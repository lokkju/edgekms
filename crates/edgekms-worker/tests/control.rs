#![cfg(target_arch = "wasm32")]
//! The hosted control plane (`edgekms_worker::control`), with a stub `GithubApi`, the
//! in-memory store in `common/memstore.rs` and `MasterAdmin::from_bytes`.
//!
//! Tests call [`control::handle`], which is [`control::serve`] minus reading the bindings.
//! Tenants created here are loaded through the data plane's tenant cache (`tenants::load`),
//! which is one `thread_local` for the whole test binary, so every test uses its own login
//! names and therefore its own tenant names.

mod common;

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;

use common::memstore::MemStore;
use common::*;
use edgekms_core::hosted::invite_request_mac_input;
use edgekms_core::keyops::{KeyOps, MacPurpose, SoftKeyOps};
use edgekms_core::tenant::TenantName;
use edgekms_core::token::{self, TokenClaims};
use edgekms_core::transit::{Id, RootKey};
use edgekms_worker::audit::Limit;
use edgekms_worker::auth::authenticate;
use edgekms_worker::control::{self, Control, Masters, Settings, SignupMode};
use edgekms_worker::github::{GithubApi, GithubError, GithubUser, LocalFuture};
use edgekms_worker::handlers::{ApiRequest, Deps, handle};
use edgekms_worker::master::{MasterAdmin, MasterUnwrap};
use edgekms_worker::store::{
    AllowRow, InviteRequestRow, InviteRow, MemberRole, MemberRow, RequestStatus, TenantStatus,
    TenantStore,
};
use edgekms_worker::tenants::{self, LoadError, NEGATIVE_MS, REVALIDATE_MS};
use edgekms_worker::vault::Reply;
use edgekms_worker::webcrypto::WebCryptoKeyOps;
use serde_json::{Value, json};
use wasm_bindgen_test::wasm_bindgen_test;
use worker::Method;

const CLIENT: &str = "Iv_hosted_test";
const M1: [u8; 32] = [0x41; 32];
const M2: [u8; 32] = [0x42; 32];
const OPERATOR: u64 = 9_000;

// ---- GitHub, stubbed ----

/// Answers token checks from a table (token to user); any other token is "not this App's".
/// Records every check and revocation.
#[derive(Default)]
struct FakeGithub {
    users: RefCell<HashMap<String, GithubUser>>,
    calls: RefCell<Vec<(String, String)>>,
    revoked: RefCell<Vec<(String, String)>>,
}

impl FakeGithub {
    /// A GitHub token for user `id` named `login`.
    fn token_for(&self, id: u64, login: &str) -> String {
        let token = format!("gho_{id}_{login}");
        self.users.borrow_mut().insert(
            token.clone(),
            GithubUser {
                id,
                login: login.to_owned(),
            },
        );
        token
    }
}

impl GithubApi for FakeGithub {
    fn check_token<'a>(
        &'a self,
        client_id: &'a str,
        token: &'a str,
    ) -> LocalFuture<'a, Result<GithubUser, GithubError>> {
        self.calls
            .borrow_mut()
            .push((client_id.to_owned(), token.to_owned()));
        let r = if client_id == CLIENT {
            self.users
                .borrow()
                .get(token)
                .cloned()
                .ok_or(GithubError::Denied("github_token_not_for_app"))
        } else {
            Err(GithubError::Denied("github_token_not_for_app"))
        };
        Box::pin(async move { r })
    }

    fn revoke_token<'a>(
        &'a self,
        client_id: &'a str,
        token: &'a str,
    ) -> LocalFuture<'a, Result<(), &'static str>> {
        self.revoked
            .borrow_mut()
            .push((client_id.to_owned(), token.to_owned()));
        Box::pin(async { Ok(()) })
    }

    /// The control API never exchanges a web-flow code; the console does (`tests/console.rs`).
    fn exchange_code<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: &'a str,
        _: &'a str,
    ) -> LocalFuture<'a, Result<zeroize::Zeroizing<String>, GithubError>> {
        Box::pin(async { Err(GithubError::Unavailable("not_in_this_test")) })
    }
}

// ---- The fixture ----

struct Fx {
    store: MemStore,
    masters: RefCell<Rc<Masters>>,
    audit: MemAudit,
    limits: MemLimits,
    gh: FakeGithub,
    settings: RefCell<Rc<Settings>>,
    /// Unix seconds.
    now: Cell<u64>,
    /// What the data plane unwraps with.
    data_unwrap: RefCell<Rc<MasterUnwrap>>,
}

fn settings() -> Settings {
    Settings {
        apex: "edge.km".into(),
        github_client_id: CLIENT.into(),
        operators: vec![OPERATOR],
        max_tenants_per_user: 5,
        previous_master: None,
        signup: SignupMode::Open,
        max_pending_invite_requests: 200,
    }
}

async fn masters(current: &str, versions: &[(&str, &[u8; 32])]) -> Masters {
    Masters::fixed(
        MasterAdmin::from_bytes(current, versions).await.unwrap(),
        MasterUnwrap::from_bytes(versions).await.unwrap(),
    )
}

async fn fx() -> Fx {
    Fx {
        store: MemStore::default(),
        masters: RefCell::new(Rc::new(masters("m1", &[("m1", &M1)]).await)),
        audit: MemAudit::default(),
        limits: MemLimits::default(),
        gh: FakeGithub::default(),
        settings: RefCell::new(Rc::new(settings())),
        now: Cell::new(NOW),
        data_unwrap: RefCell::new(Rc::new(
            MasterUnwrap::from_bytes(&[("m1", &M1), ("m2", &M2)])
                .await
                .unwrap(),
        )),
    }
}

/// A control-plane request on `api.edge.km` with the control token as a bearer token.
fn creq(method: Method, path: &str, token: Option<&str>, body: &Value) -> ApiRequest {
    craw(method, path, token, serde_json::to_vec(body).unwrap())
}

fn craw(method: Method, path: &str, token: Option<&str>, body: Vec<u8>) -> ApiRequest {
    let mut r = raw(method, path, None, body);
    r.authorization = token.map(|t| format!("Bearer {t}"));
    r.host = "api.edge.km".into();
    r.origin = "https://api.edge.km".into();
    r
}

/// A login name unique to this test run, from `base`.
fn unique(base: &str) -> String {
    thread_local!(static N: Cell<u32> = const { Cell::new(0) });
    let n = N.with(|c| {
        c.set(c.get() + 1);
        c.get()
    });
    format!("{base}{n}x")
}

impl Fx {
    async fn call(&self, req: ApiRequest) -> Reply {
        let masters = self.masters.borrow().clone();
        let settings = self.settings.borrow().clone();
        let c = Control {
            store: &self.store,
            masters: &masters,
            audit: &self.audit,
            limits: &self.limits,
            github: &self.gh,
            settings: &settings,
            now_ms: self.now.get() * 1000,
        };
        control::handle(&c, &req).await
    }

    /// Logs in as GitHub user `id` named `login`; returns the reply.
    async fn login_reply(&self, id: u64, login: &str) -> Reply {
        let gh = self.gh.token_for(id, login);
        self.call(creq(
            Method::Post,
            "/v1/login/github",
            None,
            &json!({ "token": gh }),
        ))
        .await
    }

    /// Logs in and returns the control token.
    async fn login(&self, id: u64, login: &str) -> String {
        let r = self.login_reply(id, login).await;
        data(&r)["token"].as_str().unwrap().to_owned()
    }

    /// Logs in a new user whose personal tenant is created; returns the token and the tenant.
    async fn owner(&self, id: u64, base: &str) -> (String, String) {
        let login = unique(base);
        let r = self.login_reply(id, &login).await;
        let d = data(&r);
        assert_eq!(d["created_tenant"], json!(login));
        (d["token"].as_str().unwrap().to_owned(), login)
    }

    async fn get(&self, path: &str, token: &str) -> Reply {
        self.call(creq(Method::Get, path, Some(token), &json!({})))
            .await
    }

    async fn show(&self, name: &str, token: &str) -> Reply {
        self.get(&format!("/v1/tenants/{name}"), token).await
    }

    async fn put_config(
        &self,
        name: &str,
        token: &str,
        if_match: Option<&str>,
        body: Vec<u8>,
    ) -> Reply {
        let mut r = craw(
            Method::Put,
            &format!("/v1/tenants/{name}/config"),
            Some(token),
            body,
        );
        r.if_match = if_match.map(str::to_owned);
        self.call(r).await
    }

    async fn set_member(&self, name: &str, token: &str, id: u64, role: &str) -> Reply {
        self.call(creq(
            Method::Put,
            &format!("/v1/tenants/{name}/members/{id}"),
            Some(token),
            &json!({ "role": role }),
        ))
        .await
    }

    /// `POST /v1/tenants/:name/<action>` (`accept` or `decline`).
    async fn respond(&self, name: &str, token: &str, action: &str) -> Reply {
        self.call(creq(
            Method::Post,
            &format!("/v1/tenants/{name}/{action}"),
            Some(token),
            &json!({}),
        ))
        .await
    }

    /// Invites GitHub user `id` to `name` as `role`, logs them in and accepts; returns their
    /// control token.
    async fn grant(&self, name: &str, owner: &str, id: u64, base: &str, role: &str) -> String {
        assert_eq!(
            self.set_member(name, owner, id, role).await,
            Reply::no_content()
        );
        let token = self.login(id, &unique(base)).await;
        let r = self.respond(name, &token, "accept").await;
        assert_eq!(data(&r)["role"], json!(role), "{r:?}");
        token
    }

    async fn remove_member(&self, name: &str, token: &str, id: u64) -> Reply {
        self.call(craw(
            Method::Delete,
            &format!("/v1/tenants/{name}/members/{id}"),
            Some(token),
            Vec::new(),
        ))
        .await
    }

    async fn export(&self, name: &str, token: &str) -> Reply {
        self.call(creq(
            Method::Post,
            &format!("/v1/tenants/{name}/export"),
            Some(token),
            &json!({}),
        ))
        .await
    }

    async fn create(&self, token: &str, body: &Value) -> Reply {
        self.call(creq(Method::Post, "/v1/tenants", Some(token), body))
            .await
    }

    /// The tenant `name` as the data plane loads it, `now_ms` being the load time.
    async fn load_at(&self, name: &str, now_ms: u64) -> Result<tenants::Loaded, LoadError> {
        let unwrap = self.data_unwrap.borrow().clone();
        tenants::load(
            &self.store,
            &unwrap,
            &TenantName::new(name).unwrap(),
            format!("https://{name}.edge.km"),
            CLIENT,
            now_ms,
        )
        .await
    }

    async fn load(&self, name: &str) -> Result<tenants::Loaded, LoadError> {
        self.load_at(name, self.now.get() * 1000).await
    }

    /// The tenant's current config JSON and version, as an owner or member sees them.
    async fn config(&self, name: &str, token: &str) -> (Value, u64) {
        let r = self.show(name, token).await;
        let d = data(&r);
        (d["config"].clone(), d["config_version"].as_u64().unwrap())
    }
}

/// `config` plus one more key named `second`.
fn with_second_key(config: &Value) -> Value {
    let mut c = config.clone();
    c["keys"]["second"] =
        json!({"id": "k_second", "latest_version": 1, "min_decryption_version": 1});
    c
}

/// A data-plane request through the real handlers with tenant `state`.
async fn data_plane(st: &edgekms_worker::state::State, r: ApiRequest, now: u64) -> Reply {
    let rev = MemRevocations::default();
    let jwks = FakeJwks::default();
    let audit = MemAudit::default();
    let limits = MemLimits::default();
    let deps = Deps::new(st, &rev, &jwks, &audit, &limits, now * 1000);
    handle(&deps, &r).await
}

async fn mint(ops: &impl KeyOps, role: &str, policies: &[&str], iat: u64) -> String {
    let claims = TokenClaims {
        v: 1,
        jti: token::new_jti(ops),
        role: role.into(),
        policies: policies.iter().map(|p| (*p).to_owned()).collect(),
        iat,
        exp: iat + 3600,
        long: false,
        meta: BTreeMap::new(),
    };
    token::mint(ops, &claims).await.unwrap()
}

// ---------------------------------------------------------------------------------------------
// Login, control tokens, the personal tenant

#[wasm_bindgen_test]
async fn login_returns_a_control_token_and_revokes_the_github_token() {
    let fx = fx().await;
    let login = unique("octo");
    let gh = fx.gh.token_for(501, &login);
    let r = fx
        .call(creq(
            Method::Post,
            "/v1/login/github",
            None,
            &json!({ "token": gh }),
        ))
        .await;
    let d = data(&r);
    let token = d["token"].as_str().unwrap();
    assert!(token.starts_with("ekms."), "{d}");
    assert_eq!(d["expires_in"], 1800);
    assert_eq!(d["github_id"], 501);
    assert_eq!(d["login"], json!(login));
    assert_eq!(*fx.gh.calls.borrow(), vec![(CLIENT.to_owned(), gh.clone())]);
    assert_eq!(*fx.gh.revoked.borrow(), vec![(CLIENT.to_owned(), gh)]);

    let me = fx.get("/v1/me", token).await;
    assert_eq!(data(&me)["github_id"], 501);
    assert_eq!(data(&me)["login"], json!(login));

    // The login is a durable control event (an attempt, then the outcome), and the GitHub
    // token is in neither.
    let events = fx.audit.events.borrow();
    let login_events: Vec<&String> = events
        .iter()
        .filter(|e| e.contains("control_login"))
        .collect();
    assert_eq!(login_events.len(), 2, "{events:?}");
    assert!(login_events.iter().all(|e| !e.contains("gho_")));
    let results: Vec<Value> = login_events
        .iter()
        .map(|e| serde_json::from_str::<Value>(e).unwrap())
        .collect();
    assert_eq!(results[0]["result"], "attempt");
    assert_eq!(results[1]["github_id"], 501);
    assert_eq!(results[1]["result"], "ok");
}

#[wasm_bindgen_test]
async fn first_login_creates_a_personal_tenant_named_after_the_login() {
    let fx = fx().await;
    let login = unique("Alice");
    let r = fx.login_reply(502, &login).await;
    let name = login.to_ascii_lowercase();
    assert_eq!(data(&r)["created_tenant"], json!(name));
    let token = data(&r)["token"].as_str().unwrap().to_owned();

    let me = fx.get("/v1/me", &token).await;
    assert_eq!(
        data(&me)["tenants"],
        json!([{ "name": name, "role": "owner", "status": "active" }])
    );
    // It loads in the data plane with the default config, which binds the owner.
    let loaded = fx.load(&name).await.unwrap();
    let cfg = &loaded.state.config;
    assert!(cfg.keys.contains_key("default"));
    assert_eq!(cfg.roles["owner"].github_user_ids, vec![502]);
    assert_eq!(cfg.public_origins, vec![format!("https://{name}.edge.km")]);
}

#[wasm_bindgen_test]
async fn taken_login_gets_a_suffix() {
    let fx = fx().await;
    let login = unique("dave");
    fx.login(503, &login).await;
    // Another account later holds the same login (GitHub logins can be renamed and reused).
    let r = fx.login_reply(504, &login).await;
    let created = data(&r)["created_tenant"].as_str().unwrap().to_owned();
    let suffix = created
        .strip_prefix(&format!("{login}-"))
        .unwrap_or_else(|| panic!("{created}"));
    assert_eq!(suffix.len(), 4);
    assert!(suffix.bytes().all(|b| b.is_ascii_hexdigit()));
    fx.load(&created).await.unwrap();
}

#[wasm_bindgen_test]
async fn reserved_login_gets_a_suffix() {
    let fx = fx().await;
    let r = fx.login_reply(505, "admin").await;
    let created = data(&r)["created_tenant"].as_str().unwrap();
    assert!(
        created.starts_with("u-admin-") && created.len() == 12,
        "{created}"
    );
}

#[wasm_bindgen_test]
async fn unusable_logins_still_get_a_valid_tenant_name() {
    let fx = fx().await;
    for (id, login) in [
        (506, "ab"),
        (507, "edgekms-fan"),
        (508, "a-very-long-github-login-name-of-39-chr"),
    ] {
        let r = fx.login_reply(id, login).await;
        let created = data(&r)["created_tenant"].as_str().unwrap();
        TenantName::new(created).unwrap_or_else(|e| panic!("{login}: {created}: {e}"));
    }
}

#[wasm_bindgen_test]
async fn second_login_creates_nothing() {
    let fx = fx().await;
    let (_, name) = fx.owner(509, "erin").await;
    let r = fx.login_reply(509, &name).await;
    assert!(data(&r).get("created_tenant").is_none(), "{r:?}");
    let token = data(&r)["token"].as_str().unwrap().to_owned();
    let me = fx.get("/v1/me", &token).await;
    assert_eq!(data(&me)["tenants"].as_array().unwrap().len(), 1);
}

#[wasm_bindgen_test]
async fn control_token_is_refused_by_a_tenant() {
    let fx = fx().await;
    let (token, name) = fx.owner(510, "frank").await;
    let loaded = fx.load(&name).await.unwrap();
    let mut r = req(
        Method::Get,
        "/v1/auth/token/lookup-self",
        Some(&token),
        &json!({}),
    );
    r.host = format!("{name}.edge.km");
    let rev = MemRevocations::default();
    assert!(authenticate(&r, &loaded.state, &rev, NOW).await.is_err());
    // And through the handler: 403.
    let reply = data_plane(&loaded.state, r, NOW).await;
    assert_error(&reply, 403, "permission denied");
}

#[wasm_bindgen_test]
async fn tenant_token_is_refused_by_control() {
    let fx = fx().await;
    let (_, name) = fx.owner(511, "gina").await;
    let loaded = fx.load(&name).await.unwrap();
    let tenant_token = mint(&loaded.state.ops, "owner", &["admin"], NOW).await;
    // A control-shaped claim set MACed under the tenant's root is no better.
    let forged = mint(&loaded.state.ops, "control", &[], NOW).await;
    for t in [tenant_token, forged] {
        let r = fx.get("/v1/me", &t).await;
        assert_error(&r, 403, "permission denied");
    }
}

#[wasm_bindgen_test]
async fn github_token_for_another_app_is_400() {
    let fx = fx().await;
    let r = fx
        .call(creq(
            Method::Post,
            "/v1/login/github",
            None,
            &json!({ "token": "gho_some_other_apps_token" }),
        ))
        .await;
    assert_error(&r, 400, "permission denied");
    for bad in [json!({}), json!({ "token": "" }), json!({ "token": "a b" })] {
        let r = fx
            .call(creq(Method::Post, "/v1/login/github", None, &bad))
            .await;
        assert_error(&r, 400, "permission denied");
    }
    assert!(fx.gh.revoked.borrow().is_empty());
}

#[wasm_bindgen_test]
async fn info_is_public() {
    let fx = fx().await;
    let r = fx
        .call(creq(Method::Get, "/v1/info", None, &json!({})))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(
        r.body,
        Some(json!({ "github_client_id": CLIENT, "apex": "edge.km" }))
    );
}

#[wasm_bindgen_test]
async fn routes_need_a_control_token() {
    let fx = fx().await;
    let (_, name) = fx.owner(512, "hank").await;
    for (m, p) in [
        (Method::Get, "/v1/me".to_owned()),
        (Method::Get, format!("/v1/tenants/{name}")),
        (Method::Post, "/v1/tenants".to_owned()),
        (Method::Post, format!("/v1/tenants/{name}/export")),
        (Method::Post, "/v1/ops/rewrap".to_owned()),
    ] {
        for t in [None, Some("garbage"), Some("ekms.e30.AAAA")] {
            let r = fx.call(creq(m.clone(), &p, t, &json!({}))).await;
            assert_error(&r, 403, "permission denied");
        }
    }
}

#[wasm_bindgen_test]
async fn expired_control_token_is_refused() {
    let fx = fx().await;
    let (token, _) = fx.owner(513, "ida").await;
    fx.now.set(NOW + 1799);
    assert_eq!(fx.get("/v1/me", &token).await.status, 200);
    fx.now.set(NOW + 1800);
    assert_error(&fx.get("/v1/me", &token).await, 403, "permission denied");
}

#[wasm_bindgen_test]
async fn every_request_counts_against_the_control_limit() {
    let fx = fx().await;
    let (token, _) = fx.owner(514, "jack").await;
    fx.limits.checks.borrow_mut().clear();
    fx.audit.clear();
    fx.get("/v1/me", &token).await;
    fx.call(creq(Method::Get, "/v1/info", None, &json!({})))
        .await;
    let checks = fx.limits.checks.borrow().clone();
    assert_eq!(
        checks,
        vec![
            (edgekms_worker::audit::Limit::Control, TEST_IP.to_owned()),
            (edgekms_worker::audit::Limit::Control, TEST_IP.to_owned())
        ]
    );

    // A refused request is a 429, counted as a metric and never written durably.
    fx.limits.deny_control.set(true);
    fx.audit.clear();
    let r = fx
        .call(creq(
            Method::Post,
            "/v1/tenants",
            Some(&token),
            &json!({ "name": "abcde" }),
        ))
        .await;
    assert_eq!(r.status, 429);
    let m = fx.audit.only_metric();
    assert_eq!(m["error"], "rate_limited");

    // No client IP: refused, not put in one shared bucket.
    fx.limits.deny_control.set(false);
    fx.audit.clear();
    let mut r = creq(Method::Get, "/v1/me", Some(&token), &json!({}));
    r.ip = None;
    r.limit_key = None;
    assert_error(&fx.call(r).await, 403, "permission denied");
    assert_eq!(fx.audit.only_metric()["error"], "no_client_ip");
}

#[wasm_bindgen_test]
async fn unknown_paths_are_404() {
    let fx = fx().await;
    let r = fx
        .call(creq(Method::Get, "/v1/transit/keys/x", None, &json!({})))
        .await;
    assert_eq!(r.status, 404);
}

// ---------------------------------------------------------------------------------------------
// Tenants, config and members

#[wasm_bindgen_test]
async fn owner_can_edit_config() {
    let fx = fx().await;
    let (token, name) = fx.owner(601, "kate").await;
    let (cfg, v) = fx.config(&name, &token).await;
    assert_eq!(v, 1);
    let edited = with_second_key(&cfg);
    let r = fx
        .put_config(
            &name,
            &token,
            Some("\"1\""),
            edited.to_string().into_bytes(),
        )
        .await;
    assert_eq!(data(&r)["config_version"], 2);
    let (now_cfg, v) = fx.config(&name, &token).await;
    assert_eq!((now_cfg, v), (edited, 2));

    let events = fx.audit.values();
    let ev = events.iter().find(|e| e["op"] == "tenant_config").unwrap();
    assert_eq!(ev["old_config_version"], 1);
    assert_eq!(ev["config_version"], 2);
    assert_eq!(ev["github_id"], 601);
    let sha = ev["config_sha256"].as_str().unwrap();
    assert_eq!(sha.len(), 64);
    assert!(
        sha.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
    assert!(!ev.to_string().contains("k_second"));
}

#[wasm_bindgen_test]
async fn member_cannot_edit_config() {
    let fx = fx().await;
    let (owner, name) = fx.owner(602, "liam").await;
    let member = fx.grant(&name, &owner, 603, "mia", "member").await;

    // Reads work.
    let (cfg, v) = fx.config(&name, &member).await;
    let me = fx.get("/v1/me", &member).await;
    assert!(
        data(&me)["tenants"]
            .as_array()
            .unwrap()
            .contains(&json!({ "name": name, "role": "member", "status": "active" }))
    );

    // Every owner action is 403.
    let edited = with_second_key(&cfg).to_string().into_bytes();
    let tag = format!("\"{v}\"");
    assert_error(
        &fx.put_config(&name, &member, Some(&tag), edited).await,
        403,
        "permission denied",
    );
    assert_error(
        &fx.set_member(&name, &member, 604, "member").await,
        403,
        "permission denied",
    );
    assert_error(
        &fx.set_member(&name, &member, 603, "owner").await,
        403,
        "permission denied",
    );
    assert_error(
        &fx.remove_member(&name, &member, 602).await,
        403,
        "permission denied",
    );
    assert_error(&fx.export(&name, &member).await, 403, "permission denied");
    assert_eq!(fx.config(&name, &owner).await.1, 1);
}

#[wasm_bindgen_test]
async fn non_member_gets_404() {
    let fx = fx().await;
    let (_, name) = fx.owner(605, "noah").await;
    let stranger = fx.login(606, &unique("olga")).await;
    for missing in [name.as_str(), "nosuchtenant"] {
        assert_error(&fx.show(missing, &stranger).await, 404, "tenant not found");
        assert_error(
            &fx.put_config(missing, &stranger, Some("\"1\""), b"{}".to_vec())
                .await,
            404,
            "tenant not found",
        );
        assert_error(
            &fx.set_member(missing, &stranger, 606, "owner").await,
            404,
            "tenant not found",
        );
        assert_error(
            &fx.remove_member(missing, &stranger, 605).await,
            404,
            "tenant not found",
        );
        assert_error(
            &fx.export(missing, &stranger).await,
            404,
            "tenant not found",
        );
    }
    // An invalid name is the same 404.
    assert_error(
        &fx.show("Not_A_Name", &stranger).await,
        404,
        "tenant not found",
    );
}

#[wasm_bindgen_test]
async fn stale_if_match_is_409() {
    let fx = fx().await;
    let (token, name) = fx.owner(607, "pete").await;
    let (cfg, _) = fx.config(&name, &token).await;
    let edited = with_second_key(&cfg).to_string();
    fx.put_config(&name, &token, Some("\"1\""), edited.clone().into_bytes())
        .await;
    let r = fx
        .put_config(&name, &token, Some("\"1\""), edited.into_bytes())
        .await;
    assert_eq!(r.status, 409, "{r:?}");
    assert_eq!(fx.config(&name, &token).await.1, 2);
}

#[wasm_bindgen_test]
async fn missing_if_match_is_428() {
    let fx = fx().await;
    let (token, name) = fx.owner(608, "quinn").await;
    let (cfg, _) = fx.config(&name, &token).await;
    let body = cfg.to_string().into_bytes();
    let r = fx.put_config(&name, &token, None, body.clone()).await;
    assert_eq!(r.status, 428, "{r:?}");
    for bad in ["*", "\"x\"", "W/\"1\"", "\"\""] {
        let r = fx.put_config(&name, &token, Some(bad), body.clone()).await;
        assert_eq!(r.status, 400, "{bad}: {r:?}");
    }
    // A bare number is accepted as well as the quoted form.
    let r = fx.put_config(&name, &token, Some("1"), body).await;
    assert_eq!(data(&r)["config_version"], 2);
}

/// `GET transit/keys/:name` lists every decryptable version and the data plane derives a key
/// per version, so a config with billions of them must never reach a shared isolate.
#[wasm_bindgen_test]
async fn config_with_too_many_key_versions_is_400() {
    let fx = fx().await;
    let (token, name) = fx.owner(622, "bram").await;
    let (mut cfg, _) = fx.config(&name, &token).await;
    cfg["keys"]["default"]["latest_version"] = json!(4_000_000_000_u32);
    let r = fx
        .put_config(&name, &token, Some("\"1\""), cfg.to_string().into_bytes())
        .await;
    assert_eq!(r.status, 400, "{r:?}");
    assert!(errors(&r)[0].contains("keys.default"), "{r:?}");

    cfg["keys"]["default"]["latest_version"] = json!(257);
    let r = fx
        .put_config(&name, &token, Some("\"1\""), cfg.to_string().into_bytes())
        .await;
    assert_eq!(r.status, 400, "{r:?}");
    assert!(errors(&r)[0].contains("decryptable versions"), "{r:?}");

    cfg["keys"]["default"]["latest_version"] = json!(256);
    let r = fx
        .put_config(&name, &token, Some("\"1\""), cfg.to_string().into_bytes())
        .await;
    assert_eq!(r.status, 200, "{r:?}");
}

#[wasm_bindgen_test]
async fn config_with_public_origins_is_400_naming_the_path() {
    let fx = fx().await;
    let (token, name) = fx.owner(609, "rosa").await;
    let (mut cfg, _) = fx.config(&name, &token).await;
    cfg["public_origins"] = json!(["https://evil.example"]);
    let r = fx
        .put_config(&name, &token, Some("\"1\""), cfg.to_string().into_bytes())
        .await;
    assert_eq!(r.status, 400);
    assert!(errors(&r)[0].contains("public_origins"), "{r:?}");

    // The root id is the row's; a config naming another is refused too.
    let (mut cfg, _) = fx.config(&name, &token).await;
    cfg["root_id"] = json!("r_somebody_else");
    let r = fx
        .put_config(&name, &token, Some("\"1\""), cfg.to_string().into_bytes())
        .await;
    assert_eq!(r.status, 400);
    assert!(errors(&r)[0].contains("root_id"), "{r:?}");

    // Not JSON, and JSON that isn't a config.
    for body in [&b"not json"[..], b"[1]", b"{}"] {
        let r = fx
            .put_config(&name, &token, Some("\"1\""), body.to_vec())
            .await;
        assert_eq!(r.status, 400, "{r:?}");
    }
    assert_eq!(fx.config(&name, &token).await.1, 1);
}

#[wasm_bindgen_test]
async fn oversized_config_is_413() {
    let fx = fx().await;
    let (token, name) = fx.owner(610, "sam").await;
    let (mut cfg, _) = fx.config(&name, &token).await;
    cfg["padding"] = json!("x".repeat(edgekms_core::hosted::MAX_CONFIG_BYTES));
    let r = fx
        .put_config(&name, &token, Some("\"1\""), cfg.to_string().into_bytes())
        .await;
    assert_eq!(r.status, 413, "{r:?}");
}

#[wasm_bindgen_test]
async fn edited_config_mac_verifies_in_the_cache() {
    let fx = fx().await;
    let (token, name) = fx.owner(611, "tess").await;
    let (cfg, _) = fx.config(&name, &token).await;
    let r = fx
        .put_config(
            &name,
            &token,
            Some("\"1\""),
            with_second_key(&cfg).to_string().into_bytes(),
        )
        .await;
    assert_eq!(r.status, 200, "{r:?}");
    // First load of this name in the isolate: it reads the edited row and checks its MAC.
    let loaded = fx.load(&name).await.unwrap();
    assert!(loaded.state.config.keys.contains_key("second"));
}

#[wasm_bindgen_test]
async fn config_mac_binds_the_tenant_name() {
    // There is no rename route; this pins what one would rely on: every config write MACs the
    // config under the row's current name, so the same row under another name doesn't load.
    let fx = fx().await;
    let (token, name) = fx.owner(612, "uma").await;
    let (cfg, _) = fx.config(&name, &token).await;
    fx.put_config(
        &name,
        &token,
        Some("\"1\""),
        with_second_key(&cfg).to_string().into_bytes(),
    )
    .await;
    let other = unique("renamed");
    fx.store.tamper(&name, |row| row.name.clone_from(&other));
    assert!(matches!(fx.load(&other).await, Err(LoadError::Invalid(_))));
}

#[wasm_bindgen_test]
async fn owner_adds_and_removes_members() {
    let fx = fx().await;
    let (token, name) = fx.owner(613, "vic").await;
    fx.grant(&name, &token, 614, "vin", "member").await;
    assert_eq!(
        fx.set_member(&name, &token, 615, "owner").await,
        Reply::no_content()
    );
    let r = fx.show(&name, &token).await;
    assert_eq!(
        data(&r)["members"],
        json!([
            { "github_id": 613, "role": "owner" },
            { "github_id": 614, "role": "member" },
        ])
    );
    assert_eq!(
        data(&r)["invites"],
        json!([{ "github_id": 615, "role": "owner" }])
    );
    // The pending invite is withdrawn by the same DELETE.
    assert_eq!(
        fx.remove_member(&name, &token, 615).await,
        Reply::no_content()
    );
    assert_eq!(data(&fx.show(&name, &token).await)["invites"], json!([]));
    assert_eq!(
        fx.remove_member(&name, &token, 614).await,
        Reply::no_content()
    );
    assert_error(
        &fx.remove_member(&name, &token, 614).await,
        404,
        "member not found",
    );
    for bad in [json!({ "role": "admin" }), json!({})] {
        let r = fx
            .call(creq(
                Method::Put,
                &format!("/v1/tenants/{name}/members/616"),
                Some(&token),
                &bad,
            ))
            .await;
        assert_eq!(r.status, 400, "{r:?}");
    }
    let r = fx.set_member(&name, &token, 0, "member").await;
    assert_eq!(r.status, 400, "{r:?}");
    let r = fx
        .call(creq(
            Method::Put,
            &format!("/v1/tenants/{name}/members/abc"),
            Some(&token),
            &json!({ "role": "member" }),
        ))
        .await;
    assert_eq!(r.status, 400, "{r:?}");

    let ev = fx.audit.values();
    assert!(ev.iter().any(|e| e["op"] == "member_set"
        && e["target_github_id"] == 615
        && e["meta"]["change"] == "invite"
        && e["result"] == "ok"));
    assert!(
        ev.iter()
            .any(|e| e["op"] == "member_remove" && e["target_github_id"] == 614)
    );
}

#[wasm_bindgen_test]
async fn last_owner_cannot_leave() {
    let fx = fx().await;
    let (token, name) = fx.owner(617, "wade").await;
    assert_error(
        &fx.remove_member(&name, &token, 617).await,
        400,
        "tenant needs an owner",
    );
    assert_error(
        &fx.set_member(&name, &token, 617, "member").await,
        400,
        "tenant needs an owner",
    );
    // With a second owner, the first can leave; the second then can't.
    let second = fx.grant(&name, &token, 618, "xena", "owner").await;
    assert_eq!(
        fx.remove_member(&name, &token, 617).await,
        Reply::no_content()
    );
    assert_error(
        &fx.remove_member(&name, &second, 618).await,
        400,
        "tenant needs an owner",
    );
    // The one who left is now a stranger.
    assert_error(&fx.show(&name, &token).await, 404, "tenant not found");
}

#[wasm_bindgen_test]
async fn tenant_cap_is_enforced_except_for_operators() {
    let fx = fx().await;
    let (token, login) = fx.owner(619, "yara").await;
    for i in 0..4 {
        let r = fx
            .create(&token, &json!({ "name": child(&login, &format!("yt{i}")) }))
            .await;
        assert_eq!(r.status, 200, "{r:?}");
    }
    let r = fx
        .create(&token, &json!({ "name": child(&login, "yt5") }))
        .await;
    assert_error(&r, 403, "at most 5 tenants per user");

    let op = fx.login(OPERATOR, &unique("op")).await;
    for i in 0..6 {
        let r = fx
            .create(&op, &json!({ "name": unique(&format!("ot{i}")) }))
            .await;
        assert_eq!(r.status, 200, "{r:?}");
    }
}

#[wasm_bindgen_test]
async fn created_tenant_overwrites_the_config_root_id() {
    let fx = fx().await;
    let (token, login) = fx.owner(620, "zack").await;
    let name = child(&login, "zt");
    let config = json!({
        "root_id": "r_chosen_by_client",
        "keys": { "app": { "id": "k_app", "latest_version": 1, "min_decryption_version": 1 } },
        "mounts": { "github-user": { "type": "github-user", "client_id": CLIENT } },
        "roles": { "owner": { "mount": "github-user", "github_user_ids": [620],
                              "policies": ["app"], "token_ttl_secs": 600 } },
        "policies": { "app": { "keys": { "app": ["encrypt", "decrypt"] } } }
    });
    let r = fx
        .create(&token, &json!({ "name": name, "config": config }))
        .await;
    let d = data(&r).clone();
    assert_eq!(d["name"], json!(name));
    assert_eq!(d["config_version"], 1);
    let root_id = d["root_id"].as_str().unwrap();
    assert_ne!(root_id, "r_chosen_by_client");
    assert!(d["id"].as_str().unwrap().starts_with("t_"));
    let (cfg, _) = fx.config(&name, &token).await;
    assert_eq!(cfg["root_id"], json!(root_id));
    assert!(cfg["keys"]["app"].is_object());
    let loaded = fx.load(&name).await.unwrap();
    assert_eq!(loaded.tenant_id, d["id"].as_str().unwrap());
}

#[wasm_bindgen_test]
async fn create_refuses_bad_names_configs_and_duplicates() {
    let fx = fx().await;
    let (token, login) = fx.owner(621, "abby").await;
    let existing = child(&login, "dup");
    assert_eq!(
        fx.create(&token, &json!({ "name": existing })).await.status,
        200
    );
    let r = fx.create(&token, &json!({ "name": "a--b" })).await;
    assert_error(&r, 400, "tenant name must not contain --");
    let r = fx.create(&token, &json!({ "name": "www" })).await;
    assert_error(&r, 400, "tenant name is reserved");
    let r = fx.create(&token, &json!({})).await;
    assert_eq!(r.status, 400);
    let r = fx.create(&token, &json!({ "name": existing })).await;
    assert_error(&r, 409, "tenant name already in use");
    // A config is a JSON object, not a string holding one.
    let r = fx
        .create(
            &token,
            &json!({ "name": child(&login, "ac"), "config": "{}" }),
        )
        .await;
    assert_eq!(r.status, 400, "{r:?}");
    // A config that fails the hosted rules names the path.
    let r = fx
        .create(
            &token,
            &json!({ "name": child(&login, "ac"), "config": {
                "root_id": "r_x", "public_origins": ["https://x.example"],
                "keys": {}, "mounts": {}, "roles": {}, "policies": {} } }),
        )
        .await;
    assert_eq!(r.status, 400);
    assert!(errors(&r)[0].contains("public_origins"), "{r:?}");
}

// ---------------------------------------------------------------------------------------------
// Import and export

/// A config for an imported root `r1` with key `app` (`k_app`, versions 2 and 3 live, as the
/// shared harness config) and an owner role for `owner`.
fn import_config(owner: u64) -> Value {
    json!({
        "root_id": "r1",
        "keys": { "app": { "id": "k_app", "latest_version": 3, "min_decryption_version": 2 } },
        "mounts": { "github-user": { "type": "github-user", "client_id": CLIENT } },
        "roles": { "owner": { "mount": "github-user", "github_user_ids": [owner],
                              "policies": ["app", "admin"], "token_ttl_secs": 600 } },
        "policies": {
            "app": { "keys": { "app": ["encrypt", "decrypt", "rewrap", "read"] } },
            "admin": { "admin": ["token-create", "token-revoke"] }
        }
    })
}

fn import_body(name: &str, owner: u64) -> Value {
    json!({
        "name": name,
        "config": import_config(owner),
        "import": { "root_id": "r1", "root_key": b64(&root_bytes()) }
    })
}

struct FixedRng(u8);

impl rand_core::TryRng for FixedRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(u32::from(self.0))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(u64::from(self.0))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        dst.fill(self.0);
        Ok(())
    }
}

impl rand_core::TryCryptoRng for FixedRng {}

fn soft() -> SoftKeyOps<FixedRng> {
    SoftKeyOps::new(
        RootKey::new(Id::new("r1").unwrap(), root_bytes()),
        FixedRng(9),
    )
}

/// Imports the KAT root `r1` as a new tenant owned by `owner`, logged in as `login`; returns
/// the tenant name.
async fn imported(fx: &Fx, token: &str, login: &str, owner: u64) -> String {
    let name = child(login, "imp");
    let r = fx.create(token, &import_body(&name, owner)).await;
    let d = data(&r);
    assert_eq!(d["root_id"], "r1");
    assert_eq!(d["config_version"], 1);
    name
}

#[wasm_bindgen_test]
async fn imported_tenant_decrypts_old_ciphertext() {
    let fx = fx().await;
    let (token, login) = fx.owner(701, "bea").await;
    let name = imported(&fx, &token, &login, 701).await;
    let ct = soft()
        .encrypt(&Id::new("k_app").unwrap(), 3, b"old secret")
        .await
        .unwrap();
    let loaded = fx.load(&name).await.unwrap();
    let tok = mint(&loaded.state.ops, "owner", &["app"], NOW).await;
    let r = data_plane(
        &loaded.state,
        req(
            Method::Put,
            "/v1/transit/decrypt/app",
            Some(&tok),
            &json!({ "ciphertext": ct }),
        ),
        NOW,
    )
    .await;
    assert_eq!(data(&r)["plaintext"], json!(b64(b"old secret")));
}

#[wasm_bindgen_test]
async fn imported_tenant_accepts_old_tokens() {
    let fx = fx().await;
    let (token, login) = fx.owner(702, "cal").await;
    let name = imported(&fx, &token, &login, 702).await;
    // Minted before the move, by the self-hosted instance's root.
    let old = mint(&soft(), "owner", &["app"], NOW - 60).await;
    let loaded = fx.load(&name).await.unwrap();
    let r = data_plane(
        &loaded.state,
        req(
            Method::Get,
            "/v1/auth/token/lookup-self",
            Some(&old),
            &json!({}),
        ),
        NOW,
    )
    .await;
    assert_eq!(r.status, 200, "{r:?}");
}

#[wasm_bindgen_test]
async fn import_with_mismatched_root_id_is_400() {
    let fx = fx().await;
    let (token, login) = fx.owner(703, "dina").await;
    let mut body = import_body(&child(&login, "imp"), 703);
    body["config"]["root_id"] = json!("r_other");
    let r = fx.create(&token, &body).await;
    assert_eq!(r.status, 400, "{r:?}");
    assert!(errors(&r)[0].contains("root_id"), "{r:?}");

    // No config with an import; a key that isn't base64 of 32 bytes; a bad root id.
    let mut body = import_body(&child(&login, "imp"), 703);
    body.as_object_mut().unwrap().remove("config");
    assert_eq!(fx.create(&token, &body).await.status, 400);
    let mut body = import_body(&child(&login, "imp"), 703);
    body["import"]["root_key"] = json!(b64(&[1u8; 31]));
    assert_eq!(fx.create(&token, &body).await.status, 400);
    let mut body = import_body(&child(&login, "imp"), 703);
    body["import"]["root_key"] = json!("not base64!");
    assert_eq!(fx.create(&token, &body).await.status, 400);
    let mut body = import_body(&child(&login, "imp"), 703);
    body["import"]["root_id"] = json!("R-1");
    assert_eq!(fx.create(&token, &body).await.status, 400);
}

#[wasm_bindgen_test]
async fn duplicate_root_id_is_409() {
    let fx = fx().await;
    let (token, login) = fx.owner(704, "eli").await;
    imported(&fx, &token, &login, 704).await;
    let r = fx
        .create(&token, &import_body(&child(&login, "imp"), 704))
        .await;
    assert_error(&r, 409, "root id already in use");
}

#[wasm_bindgen_test]
async fn export_returns_the_imported_bytes() {
    let fx = fx().await;
    let (token, login) = fx.owner(705, "fay").await;
    let name = imported(&fx, &token, &login, 705).await;
    let r = fx.export(&name, &token).await;
    assert_eq!(
        *data(&r),
        json!({ "root_id": "r1", "root_key": b64(&root_bytes()) })
    );
    assert!(r.headers().contains(&("Cache-Control", "no-store")));
}

#[wasm_bindgen_test]
async fn export_by_member_is_403() {
    let fx = fx().await;
    let (token, login) = fx.owner(706, "gus").await;
    let name = imported(&fx, &token, &login, 706).await;
    let member = fx.grant(&name, &token, 707, "hal", "member").await;
    assert_error(&fx.export(&name, &member).await, 403, "permission denied");
    let ev = fx.audit.values();
    let denied = ev.iter().find(|e| e["op"] == "tenant_export").unwrap();
    assert_eq!(denied["result"], "denied");
    assert_eq!(denied["github_id"], 707);
}

#[wasm_bindgen_test]
async fn export_with_stale_login_is_403() {
    let fx = fx().await;
    let (token, login) = fx.owner(708, "ivy").await;
    let name = imported(&fx, &token, &login, 708).await;
    fx.now.set(NOW + 299);
    assert_eq!(fx.export(&name, &token).await.status, 200);
    fx.now.set(NOW + 300);
    assert_error(&fx.export(&name, &token).await, 403, "fresh login required");
    // The same token still does everything else.
    assert_eq!(fx.show(&name, &token).await.status, 200);
    let fresh = fx.login(708, "ivy").await;
    assert_eq!(fx.export(&name, &fresh).await.status, 200);
}

#[wasm_bindgen_test]
async fn export_is_audited_without_the_key() {
    let fx = fx().await;
    let (token, login) = fx.owner(709, "jon").await;
    let name = imported(&fx, &token, &login, 709).await;
    fx.audit.clear();
    assert_eq!(fx.export(&name, &token).await.status, 200);
    let ev = fx.audit.values();
    assert_eq!(ev.len(), 2, "{ev:?}");
    assert_eq!(ev[0]["result"], "attempt");
    for e in &ev {
        assert_eq!(e["op"], "tenant_export");
        assert_eq!(e["github_id"], 709);
        assert!(e["tenant"].as_str().unwrap().starts_with("t_"));
    }
    assert_eq!(ev[1]["result"], "ok");
    assert!(
        fx.audit
            .events
            .borrow()
            .iter()
            .all(|raw| !raw.contains(&b64(&root_bytes())))
    );
    // The import was audited too, also without the key.
    assert!(
        fx.audit
            .metrics
            .borrow()
            .iter()
            .all(|m| !m.contains(&b64(&root_bytes())))
    );
}

// ---------------------------------------------------------------------------------------------
// Master rewrap and suspension

fn set_previous(fx: &Fx, previous: Option<&str>) {
    let mut s = (**fx.settings.borrow()).clone();
    s.previous_master = previous.map(str::to_owned);
    *fx.settings.borrow_mut() = Rc::new(s);
}

/// Moves the fixture to master `m2` with `m1` as the previous version, as a rotation does.
async fn rotate(fx: &Fx) {
    *fx.masters.borrow_mut() = Rc::new(masters("m2", &[("m2", &M2), ("m1", &M1)]).await);
    set_previous(fx, Some("m1"));
}

async fn rewrap(fx: &Fx, token: &str, limit: u64) -> Reply {
    rewrap_after(fx, token, limit, None).await
}

async fn rewrap_after(fx: &Fx, token: &str, limit: u64, after: Option<&str>) -> Reply {
    fx.call(creq(
        Method::Post,
        "/v1/ops/rewrap",
        Some(token),
        &json!({ "limit": limit, "after": after }),
    ))
    .await
}

#[wasm_bindgen_test]
async fn rewrap_moves_rows_and_reports_remaining() {
    let fx = fx().await;
    // Three tenants plus the control root, all under m1.
    let op = fx.login(OPERATOR, &unique("op")).await;
    for i in 0..2 {
        fx.create(&op, &json!({ "name": unique(&format!("rw{i}")) }))
            .await;
    }
    assert_eq!(
        fx.store.rows_wrapped_with("m1", 100).await.unwrap().len(),
        3
    );
    rotate(&fx).await;
    let r = rewrap(&fx, &op, 2).await;
    let d = data(&r);
    assert_eq!(d["rewrapped"], 2);
    assert_eq!(d["remaining"], 2);
    assert_eq!(d["failed"], json!([]));
    let next = d["next"].as_str().unwrap().to_owned();
    let r = rewrap_after(&fx, &op, 100, Some(&next)).await;
    assert_eq!(
        *data(&r),
        json!({ "rewrapped": 2, "failed": [], "next": null, "remaining": 0 })
    );
    assert_eq!(
        fx.store.rows_wrapped_with("m1", 100).await.unwrap().len(),
        0
    );
    assert_eq!(
        fx.store.rows_wrapped_with("m2", 100).await.unwrap().len(),
        3
    );
    assert_eq!(
        fx.store
            .system_key("control")
            .await
            .unwrap()
            .unwrap()
            .wrap_key,
        "m2"
    );
    let ev = fx.audit.values();
    assert!(
        ev.iter()
            .any(|e| e["op"] == "master_rewrap" && e["github_id"] == OPERATOR)
    );
}

#[wasm_bindgen_test]
async fn rewrapped_tenant_still_loads_and_decrypts() {
    let fx = fx().await;
    let op = fx.login(OPERATOR, &unique("op")).await;
    let (owner, login) = fx.owner(801, "kim").await;
    let name = imported(&fx, &owner, &login, 801).await;
    let ct = soft()
        .encrypt(&Id::new("k_app").unwrap(), 3, b"before")
        .await
        .unwrap();
    rotate(&fx).await;
    let r = rewrap(&fx, &op, 100).await;
    assert_eq!(data(&r)["remaining"], 0);

    // m1 is retired: neither the data plane nor the control plane has it any more.
    *fx.data_unwrap.borrow_mut() = Rc::new(MasterUnwrap::from_bytes(&[("m2", &M2)]).await.unwrap());
    *fx.masters.borrow_mut() = Rc::new(masters("m2", &[("m2", &M2)]).await);
    set_previous(&fx, None);
    let loaded = fx.load(&name).await.unwrap();
    let tok = mint(&loaded.state.ops, "owner", &["app"], NOW).await;
    let r = data_plane(
        &loaded.state,
        req(
            Method::Put,
            "/v1/transit/decrypt/app",
            Some(&tok),
            &json!({ "ciphertext": ct }),
        ),
        NOW,
    )
    .await;
    assert_eq!(data(&r)["plaintext"], json!(b64(b"before")));
    // Control tokens issued before the rotation still verify, through the rewrapped root.
    assert_eq!(fx.get("/v1/me", &owner).await.status, 200);
    // And the export still returns the same root.
    let fresh = fx.login(801, "kim").await;
    assert_eq!(
        data(&fx.export(&name, &fresh).await)["root_key"],
        json!(b64(&root_bytes()))
    );
}

#[wasm_bindgen_test]
async fn rewrap_is_idempotent() {
    let fx = fx().await;
    let op = fx.login(OPERATOR, &unique("op")).await;
    rotate(&fx).await;
    let done = |n: u64| json!({ "rewrapped": n, "failed": [], "next": null, "remaining": 0 });
    let first = rewrap(&fx, &op, 100).await;
    assert_eq!(*data(&first), done(2));
    let again = rewrap(&fx, &op, 100).await;
    assert_eq!(*data(&again), done(0));
    // With no rotation in progress there is nothing to do.
    set_previous(&fx, None);
    let none = rewrap(&fx, &op, 100).await;
    assert_eq!(*data(&none), done(0));
    // A limit outside 1..=100 is refused.
    for bad in [
        json!({ "limit": 0 }),
        json!({ "limit": 101 }),
        json!({ "limit": "x" }),
        json!({ "after": 7 }),
    ] {
        let r = fx
            .call(creq(Method::Post, "/v1/ops/rewrap", Some(&op), &bad))
            .await;
        assert_eq!(r.status, 400, "{bad}: {r:?}");
    }
}

#[wasm_bindgen_test]
async fn non_operator_gets_403() {
    let fx = fx().await;
    let (token, name) = fx.owner(802, "lou").await;
    rotate(&fx).await;
    assert_error(&rewrap(&fx, &token, 10).await, 403, "permission denied");
    let r = fx
        .call(creq(
            Method::Put,
            &format!("/v1/ops/tenants/{name}/status"),
            Some(&token),
            &json!({ "status": "suspended" }),
        ))
        .await;
    assert_error(&r, 403, "permission denied");
    assert_eq!(
        fx.store.rows_wrapped_with("m1", 100).await.unwrap().len(),
        1
    );
    assert!(fx.load(&name).await.is_ok());
}

#[wasm_bindgen_test]
async fn suspended_tenant_is_refused_after_revalidate() {
    let fx = fx().await;
    let op = fx.login(OPERATOR, &unique("op")).await;
    let (_, name) = fx.owner(803, "max").await;
    let t0 = NOW * 1000;
    fx.load_at(&name, t0).await.unwrap();
    let status = |s: &str| {
        creq(
            Method::Put,
            &format!("/v1/ops/tenants/{name}/status"),
            Some(&op),
            &json!({ "status": s }),
        )
    };
    assert_eq!(fx.call(status("suspended")).await, Reply::no_content());
    assert_eq!(
        fx.store
            .tenant_version(&name)
            .await
            .unwrap()
            .unwrap()
            .status,
        TenantStatus::Suspended
    );
    // Served from the cache until the next revalidation, then refused.
    assert!(fx.load_at(&name, t0 + 1).await.is_ok());
    let t1 = t0 + REVALIDATE_MS + 1;
    assert!(matches!(
        fx.load_at(&name, t1).await,
        Err(LoadError::Suspended)
    ));
    // Reactivated: served again once the negative cache entry expires.
    assert_eq!(fx.call(status("active")).await, Reply::no_content());
    assert!(fx.load_at(&name, t1 + NEGATIVE_MS + 1).await.is_ok());

    let r = fx.call(status("deleted")).await;
    assert_eq!(r.status, 400);
    let r = fx
        .call(creq(
            Method::Put,
            "/v1/ops/tenants/nosuchtenant/status",
            Some(&op),
            &json!({ "status": "active" }),
        ))
        .await;
    assert_error(&r, 404, "tenant not found");
    let ev = fx.audit.values();
    assert!(
        ev.iter()
            .any(|e| e["op"] == "tenant_status" && e["result"] == "ok")
    );
}

#[wasm_bindgen_test]
async fn serve_without_bindings_fails_closed() {
    // No HOSTED vars, no D1, no master: every route but /v1/info is a 500, never a panic.
    let r = control::serve(
        &empty_env(),
        creq(
            Method::Post,
            "/v1/login/github",
            None,
            &json!({ "token": "gho_x" }),
        ),
        NOW * 1000,
    )
    .await;
    assert_eq!(r.status, 500, "{r:?}");
}

// ---------------------------------------------------------------------------------------------
// Review of #44: invites, the atomic cap, logout, audit attempts, the rewrap cursor,
// suspension and failed logins

#[wasm_bindgen_test]
async fn invite_grants_nothing_until_accepted() {
    let fx = fx().await;
    let (owner, name) = fx.owner(901, "ann").await;
    assert_eq!(
        fx.set_member(&name, &owner, 902, "owner").await,
        Reply::no_content()
    );
    let invitee = fx.login(902, &unique("bea")).await;
    // Pending: the invitee sees the invite apart from their tenants, and nothing else.
    let me = fx.get("/v1/me", &invitee).await;
    assert_eq!(
        data(&me)["invites"],
        json!([{ "name": name, "role": "owner" }])
    );
    assert!(
        !data(&me)["tenants"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == json!(name))
    );
    assert_error(&fx.show(&name, &invitee).await, 404, "tenant not found");
    assert_error(&fx.export(&name, &invitee).await, 404, "tenant not found");
    // A pending owner doesn't count: the inviter is still the last owner.
    assert_error(
        &fx.remove_member(&name, &owner, 901).await,
        400,
        "tenant needs an owner",
    );
    // Accepted, it counts for everything.
    let r = fx.respond(&name, &invitee, "accept").await;
    assert_eq!(*data(&r), json!({ "name": name, "role": "owner" }));
    assert_eq!(fx.show(&name, &invitee).await.status, 200);
    assert_eq!(
        data(&fx.get("/v1/me", &invitee).await)["invites"],
        json!([])
    );
    assert_eq!(
        fx.remove_member(&name, &owner, 901).await,
        Reply::no_content()
    );
    // The invite is used up.
    assert_error(
        &fx.respond(&name, &invitee, "accept").await,
        404,
        "tenant not found",
    );
    let ev = fx.audit.values();
    assert!(
        ev.iter()
            .any(|e| e["op"] == "invite_accept" && e["result"] == "ok" && e["github_id"] == 902)
    );
}

#[wasm_bindgen_test]
async fn only_the_invitee_can_accept_or_decline() {
    let fx = fx().await;
    let (owner, name) = fx.owner(903, "cal").await;
    fx.set_member(&name, &owner, 904, "member").await;
    let stranger = fx.login(905, &unique("dot")).await;
    for action in ["accept", "decline"] {
        assert_error(
            &fx.respond(&name, &stranger, action).await,
            404,
            "tenant not found",
        );
        assert_error(
            &fx.respond("nosuchtenant", &stranger, action).await,
            404,
            "tenant not found",
        );
    }
    // The owner, already a member, has no invite to accept either.
    assert_error(
        &fx.respond(&name, &owner, "accept").await,
        404,
        "tenant not found",
    );
    let invitee = fx.login(904, &unique("eve")).await;
    assert_eq!(
        fx.respond(&name, &invitee, "decline").await,
        Reply::no_content()
    );
    assert_error(
        &fx.respond(&name, &invitee, "accept").await,
        404,
        "tenant not found",
    );
    assert_error(&fx.show(&name, &invitee).await, 404, "tenant not found");
}

#[wasm_bindgen_test]
async fn demoting_an_owner_applies_at_once_and_promoting_is_an_invite() {
    let fx = fx().await;
    let (owner, name) = fx.owner(906, "fay").await;
    let second = fx.grant(&name, &owner, 907, "gil", "owner").await;
    // Lowering needs no consent.
    assert_eq!(
        fx.set_member(&name, &owner, 907, "member").await,
        Reply::no_content()
    );
    assert_error(&fx.export(&name, &second).await, 403, "permission denied");
    // Raising it again is an invite, and accepting it raises the role.
    fx.set_member(&name, &owner, 907, "owner").await;
    assert_error(&fx.export(&name, &second).await, 403, "permission denied");
    let r = fx.respond(&name, &second, "accept").await;
    assert_eq!(data(&r)["role"], "owner");
    // Asking for a role already held changes nothing and invites no one.
    assert_eq!(
        fx.set_member(&name, &owner, 907, "owner").await,
        Reply::no_content()
    );
    assert_eq!(data(&fx.show(&name, &owner).await)["invites"], json!([]));
}

#[wasm_bindgen_test]
async fn concurrent_creates_at_the_cap_admit_exactly_one() {
    let fx = fx().await;
    let (token, login) = fx.owner(910, "hep").await;
    for i in 0..3 {
        let r = fx
            .create(&token, &json!({ "name": child(&login, &format!("hc{i}")) }))
            .await;
        assert_eq!(r.status, 200, "{r:?}");
    }
    // 4 of 5 created; four more race for the last slot.
    let body = |i: u32| json!({ "name": child(&login, &format!("hr{i}")) });
    let (a, b, c, d) = futures_util::future::join4(
        fx.create(&token, &body(0)),
        fx.create(&token, &body(1)),
        fx.create(&token, &body(2)),
        fx.create(&token, &body(3)),
    )
    .await;
    let replies = [a, b, c, d];
    assert_eq!(
        replies.iter().filter(|r| r.status == 200).count(),
        1,
        "{replies:?}"
    );
    for r in replies.iter().filter(|r| r.status != 200) {
        assert_error(r, 403, "at most 5 tenants per user");
    }
    assert_eq!(fx.store.count_created(910).await.unwrap(), 5);
}

#[wasm_bindgen_test]
async fn cap_counts_tenants_created_not_owned() {
    let fx = fx().await;
    let mut s = (**fx.settings.borrow()).clone();
    s.max_tenants_per_user = 2;
    *fx.settings.borrow_mut() = Rc::new(s);
    let (other, other_name) = fx.owner(911, "ida").await;
    let (token, login) = fx.owner(912, "jay").await;
    // Owning someone else's tenant uses none of the cap...
    fx.grant(&other_name, &other, 912, "jay", "owner").await;
    let r = fx
        .create(&token, &json!({ "name": child(&login, "jc") }))
        .await;
    assert_eq!(r.status, 200, "{r:?}");
    // ...and leaving a tenant you created gives none back.
    let r = fx
        .create(&token, &json!({ "name": child(&login, "jd") }))
        .await;
    assert_error(&r, 403, "at most 2 tenants per user");
    let ev = fx.audit.values();
    assert!(
        ev.iter()
            .any(|e| e["op"] == "tenant_create" && e["error"] == "tenant_cap")
    );
}

#[wasm_bindgen_test]
async fn concurrent_first_logins_create_one_personal_tenant() {
    let fx = fx().await;
    let login = unique("kai");
    let (a, b) =
        futures_util::future::join(fx.login_reply(913, &login), fx.login_reply(913, &login)).await;
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(b.status, 200, "{b:?}");
    let created = [&a, &b]
        .iter()
        .filter(|r| !data(r)["created_tenant"].is_null())
        .count();
    assert_eq!(created, 1, "{a:?} {b:?}");
    assert_eq!(fx.store.count_created(913).await.unwrap(), 1);
}

#[wasm_bindgen_test]
async fn invited_user_still_gets_a_personal_tenant() {
    let fx = fx().await;
    let (owner, name) = fx.owner(914, "lee").await;
    fx.set_member(&name, &owner, 915, "member").await;
    let login = unique("moe");
    let r = fx.login_reply(915, &login).await;
    assert_eq!(data(&r)["created_tenant"], json!(login));
}

#[wasm_bindgen_test]
async fn logout_invalidates_outstanding_tokens() {
    let fx = fx().await;
    let (first, _) = fx.owner(916, "ned").await;
    let login = unique("ned");
    let second = fx.login(916, &login).await;
    fx.now.set(NOW + 1);
    let other = fx.login(917, &unique("oak")).await;
    let r = fx
        .call(creq(Method::Post, "/v1/logout", Some(&first), &json!({})))
        .await;
    assert_eq!(r, Reply::no_content());
    for t in [&first, &second] {
        assert_error(&fx.get("/v1/me", t).await, 403, "permission denied");
    }
    // Another user's tokens are untouched.
    assert_eq!(fx.get("/v1/me", &other).await.status, 200);
    // A new login works.
    fx.now.set(NOW + 2);
    let again = fx.login(916, &login).await;
    assert_eq!(fx.get("/v1/me", &again).await.status, 200);
    let ev = fx.audit.values();
    assert!(
        ev.iter()
            .any(|e| e["op"] == "control_logout" && e["result"] == "ok")
    );
    // Reads are metrics only.
    assert!(
        fx.audit
            .metrics
            .borrow()
            .iter()
            .any(|m| m.contains("token_logged_out"))
    );
}

#[wasm_bindgen_test]
async fn state_changes_write_an_attempt_first_and_fail_closed() {
    let fx = fx().await;
    let (token, name) = fx.owner(918, "pam").await;
    let (cfg, v) = fx.config(&name, &token).await;
    let edited = with_second_key(&cfg).to_string().into_bytes();
    let tag = format!("\"{v}\"");
    fx.audit.clear();
    assert_eq!(
        fx.put_config(&name, &token, Some(&tag), edited.clone())
            .await
            .status,
        200
    );
    let ev = fx.audit.values();
    assert_eq!(ev.len(), 2, "{ev:?}");
    assert_eq!(ev[0]["result"], "attempt");
    assert_eq!(ev[0]["config_version"], v + 1);
    assert_eq!(ev[1]["result"], "ok");
    assert_eq!(ev[0]["config_sha256"], ev[1]["config_sha256"]);

    // With the durable log down, nothing changes.
    fx.audit.fail.set(true);
    let tag = format!("\"{}\"", v + 1);
    let edited = with_second_key(&json!(cfg)).to_string().into_bytes();
    assert_error(
        &fx.put_config(&name, &token, Some(&tag), edited).await,
        500,
        "audit log unavailable",
    );
    assert_error(
        &fx.create(&token, &json!({ "name": child(&name, "pc") }))
            .await,
        500,
        "audit log unavailable",
    );
    assert_error(
        &fx.set_member(&name, &token, 919, "member").await,
        500,
        "audit log unavailable",
    );
    let r = fx
        .call(creq(Method::Post, "/v1/logout", Some(&token), &json!({})))
        .await;
    assert_error(&r, 500, "audit log unavailable");
    fx.audit.fail.set(false);
    assert_eq!(fx.config(&name, &token).await.1, v + 1);
    assert_eq!(fx.store.count_created(918).await.unwrap(), 1);
    assert_eq!(data(&fx.show(&name, &token).await)["invites"], json!([]));
    assert_eq!(fx.get("/v1/me", &token).await.status, 200);
}

/// A create refused for want of its attempt event writes nothing, not even the user row it
/// refreshes for `create_tenant`.
#[wasm_bindgen_test]
async fn create_with_the_audit_log_down_writes_no_user_row() {
    let fx = fx().await;
    let (token, name) = fx.owner(623, "cora").await;
    fx.store.forge_user_login(623, "cora-before");
    fx.audit.fail.set(true);
    assert_error(
        &fx.create(&token, &json!({ "name": child(&name, "pc") }))
            .await,
        500,
        "audit log unavailable",
    );
    assert_eq!(fx.store.user_login(623).as_deref(), Some("cora-before"));
    fx.audit.fail.set(false);
    assert_eq!(
        fx.create(&token, &json!({ "name": child(&name, "pc") }))
            .await
            .status,
        200
    );
    assert_ne!(fx.store.user_login(623).as_deref(), Some("cora-before"));
}

#[wasm_bindgen_test]
async fn export_with_the_audit_log_down_withholds_the_key() {
    let fx = fx().await;
    let (token, login) = fx.owner(920, "quin").await;
    let name = imported(&fx, &token, &login, 920).await;
    fx.audit.fail.set(true);
    let r = fx.export(&name, &token).await;
    assert_error(&r, 500, "audit log unavailable");
    assert!(
        fx.audit
            .metrics
            .borrow()
            .iter()
            .all(|m| !m.contains(&b64(&root_bytes())))
    );
}

#[wasm_bindgen_test]
async fn rewrap_pages_past_a_broken_row_and_reports_it() {
    let fx = fx().await;
    let op = fx.login(OPERATOR, &unique("op")).await;
    let mut names = Vec::new();
    for i in 0..3 {
        let name = unique(&format!("rb{i}"));
        fx.create(&op, &json!({ "name": name })).await;
        names.push(name);
    }
    fx.store
        .tamper(&names[1], |row| row.wrapped_root = vec![7; 60]);
    let broken = fx
        .store
        .tenant_by_name(&names[1])
        .await
        .unwrap()
        .unwrap()
        .id;
    rotate(&fx).await;
    let mut after: Option<String> = None;
    let mut failed = Vec::new();
    let mut rewrapped = 0;
    for _ in 0..10 {
        let r = rewrap_after(&fx, &op, 1, after.as_deref()).await;
        let d = data(&r);
        rewrapped += d["rewrapped"].as_u64().unwrap();
        failed.extend(d["failed"].as_array().unwrap().iter().cloned());
        let Some(n) = d["next"].as_str() else {
            // Only the broken row is left under the old key.
            assert_eq!(d["remaining"], 1);
            break;
        };
        after = Some(n.to_owned());
    }
    assert_eq!(failed, vec![json!(broken)]);
    // Four good rows: two tenants, the operator's personal tenant and the control root.
    assert_eq!(rewrapped, 4);
}

#[wasm_bindgen_test]
async fn suspended_tenant_can_export_but_not_change() {
    let fx = fx().await;
    let op = fx.login(OPERATOR, &unique("op")).await;
    let (token, login) = fx.owner(921, "rex").await;
    let name = imported(&fx, &token, &login, 921).await;
    fx.set_member(&name, &token, 922, "member").await;
    fx.set_member(&name, &token, 923, "member").await;
    let r = fx
        .call(creq(
            Method::Put,
            &format!("/v1/ops/tenants/{name}/status"),
            Some(&op),
            &json!({ "status": "suspended" }),
        ))
        .await;
    assert_eq!(r, Reply::no_content());

    // The way out stays open.
    let r = fx.export(&name, &token).await;
    assert_eq!(data(&r)["root_key"], json!(b64(&root_bytes())));
    assert_eq!(fx.show(&name, &token).await.status, 200);

    let (cfg, v) = fx.config(&name, &token).await;
    let edited = with_second_key(&cfg).to_string().into_bytes();
    let tag = format!("\"{v}\"");
    let suspended = |r: &Reply| assert_error(r, 403, "tenant is suspended");
    suspended(&fx.put_config(&name, &token, Some(&tag), edited).await);
    suspended(&fx.set_member(&name, &token, 924, "member").await);
    suspended(&fx.remove_member(&name, &token, 922).await);
    let invitee = fx.login(922, &unique("sam")).await;
    suspended(&fx.respond(&name, &invitee, "accept").await);
    // Declining only removes a grant, so it is allowed.
    let other = fx.login(923, &unique("tia")).await;
    assert_eq!(
        fx.respond(&name, &other, "decline").await,
        Reply::no_content()
    );
    assert_eq!(fx.config(&name, &token).await.1, v);
}

#[wasm_bindgen_test]
async fn misreported_config_version_is_500() {
    let fx = fx().await;
    let (token, name) = fx.owner(925, "uma").await;
    let (cfg, v) = fx.config(&name, &token).await;
    let edited = with_second_key(&cfg).to_string().into_bytes();
    fx.store.skew_config_version(1);
    let r = fx
        .put_config(&name, &token, Some(&format!("\"{v}\"")), edited)
        .await;
    fx.store.skew_config_version(0);
    assert_eq!(r.status, 500, "{r:?}");
    let ev = fx.audit.values();
    assert!(
        ev.iter()
            .any(|e| e["op"] == "tenant_config" && e["error"] == "config_version_unexpected")
    );
}

#[wasm_bindgen_test]
async fn failed_logins_count_against_the_auth_failure_limit() {
    let fx = fx().await;
    // A good login spends nothing.
    fx.login(926, &unique("val")).await;
    assert!(
        !fx.limits
            .checks
            .borrow()
            .iter()
            .any(|(l, _)| *l == Limit::AuthFailure)
    );
    fx.limits.auth_failure_budget.set(Some(1));
    let bad = || {
        creq(
            Method::Post,
            "/v1/login/github",
            None,
            &json!({ "token": "gho_not_a_known_token_at_all" }),
        )
    };
    assert_error(&fx.call(bad()).await, 400, "permission denied");
    let r = fx.call(bad()).await;
    assert_eq!(r.status, 429, "{r:?}");
    // A bad control token counts the same way.
    let r = fx.get("/v1/me", "ekms.garbage").await;
    assert_eq!(r.status, 429, "{r:?}");
    assert!(
        fx.limits
            .checks
            .borrow()
            .iter()
            .any(|(l, _)| *l == Limit::AuthFailure)
    );
}

// ---- Membership and invite MACs: a D1 writer without the master grants nothing ----

/// Every MAC a D1 writer without the master can produce: the migration's placeholder, and
/// guesses.
fn forged_macs() -> [Vec<u8>; 3] {
    [Vec::new(), vec![0; 32], vec![0xff; 32]]
}

fn forged_owner(github_id: u64, mac: Vec<u8>) -> MemberRow {
    MemberRow {
        github_id,
        role: MemberRole::Owner,
        added_by: github_id,
        added_ms: NOW * 1000,
        mac,
    }
}

/// Everything an owner can do through the control plane, as `token` on `name`, is refused
/// exactly as for a stranger.
async fn assert_stranger(fx: &Fx, name: &str, token: &str) {
    assert_error(&fx.show(name, token).await, 404, "tenant not found");
    assert_error(&fx.export(name, token).await, 404, "tenant not found");
    let r = fx
        .put_config(name, token, Some("\"1\""), b"{}".to_vec())
        .await;
    assert_error(&r, 404, "tenant not found");
    assert_error(
        &fx.set_member(name, token, 7_999, "owner").await,
        404,
        "tenant not found",
    );
    let me = fx.get("/v1/me", token).await;
    assert!(
        data(&me)["tenants"]
            .as_array()
            .unwrap()
            .iter()
            .all(|t| t["name"] != json!(name)),
        "{me:?}"
    );
}

#[wasm_bindgen_test]
async fn forged_member_row_grants_nothing() {
    let fx = fx().await;
    let (owner, name) = fx.owner(7_101, "forgevictim").await;
    let (attacker, _) = fx.owner(7_102, "forger").await;
    for mac in forged_macs() {
        fx.store.forge_member(&name, forged_owner(7_102, mac));
        assert_stranger(&fx, &name, &attacker).await;
    }
    // The owner's view lists only rows that verify.
    assert_eq!(
        data(&fx.show(&name, &owner).await)["members"],
        json!([{ "github_id": 7_101, "role": "owner" }])
    );
}

#[wasm_bindgen_test]
async fn forged_invite_cannot_be_accepted() {
    let fx = fx().await;
    let (owner, name) = fx.owner(7_111, "invvictim").await;
    let attacker = fx.login(7_112, &unique("invforger")).await;
    for mac in forged_macs() {
        fx.store.forge_invite(
            &name,
            InviteRow {
                github_id: 7_112,
                role: MemberRole::Owner,
                invited_by: 7_111,
                invited_ms: NOW * 1000,
                mac,
            },
        );
        for action in ["accept", "decline"] {
            assert_error(
                &fx.respond(&name, &attacker, action).await,
                404,
                "tenant not found",
            );
        }
        assert_eq!(
            data(&fx.get("/v1/me", &attacker).await)["invites"],
            json!([])
        );
        assert_eq!(data(&fx.show(&name, &owner).await)["invites"], json!([]));
        assert_stranger(&fx, &name, &attacker).await;
    }
    // A real invite to someone else, rewritten to name the attacker, doesn't verify either.
    assert_eq!(
        fx.set_member(&name, &owner, 7_113, "owner").await,
        Reply::no_content()
    );
    let mut stolen = fx.store.invite_row(&name, 7_113).unwrap();
    stolen.github_id = 7_112;
    fx.store.forge_invite(&name, stolen);
    assert_error(
        &fx.respond(&name, &attacker, "accept").await,
        404,
        "tenant not found",
    );
    assert_stranger(&fx, &name, &attacker).await;
}

#[wasm_bindgen_test]
async fn member_row_with_a_swapped_role_tenant_or_user_fails() {
    let fx = fx().await;
    let (owner, name) = fx.owner(7_121, "swapvictim").await;
    let member = fx.grant(&name, &owner, 7_122, "swapmember", "member").await;
    let (other_owner, other) = fx.owner(7_123, "swapother").await;
    let real = fx.store.member_row(&name, 7_122).unwrap();

    // The member rewrites its own role to owner: the row no longer verifies at all.
    fx.store
        .tamper_member(&name, 7_122, |m| m.role = MemberRole::Owner);
    assert_stranger(&fx, &name, &member).await;

    // Its real row copied into another tenant grants nothing there.
    fx.store.forge_member(&name, real.clone());
    fx.store.forge_member(&other, real);
    assert_stranger(&fx, &other, &member).await;
    assert_eq!(
        data(&fx.show(&other, &other_owner).await)["members"],
        json!([{ "github_id": 7_123, "role": "owner" }])
    );

    // An owner's real row copied to another user grants that user nothing.
    let mut stolen = fx.store.member_row(&name, 7_121).unwrap();
    stolen.github_id = 7_123;
    fx.store.forge_member(&name, stolen);
    assert_stranger(&fx, &name, &other_owner).await;

    // The untouched real row still works.
    let r = fx.show(&name, &member).await;
    assert_eq!(r.status, 200, "{r:?}");
    assert_error(&fx.export(&name, &member).await, 403, "permission denied");
}

#[wasm_bindgen_test]
async fn last_owner_rule_ignores_forged_owners() {
    let fx = fx().await;
    let (owner, name) = fx.owner(7_131, "lonely").await;
    let (_, other) = fx.owner(7_132, "lonelyother").await;
    // Garbage owner rows, and a real owner row from another tenant (valid there, not here),
    // as itself and renamed to another user.
    for (id, mac) in [7_133, 7_134, 7_135].into_iter().zip(forged_macs()) {
        fx.store.forge_member(&name, forged_owner(id, mac));
    }
    let foreign = fx.store.member_row(&other, 7_132).unwrap();
    fx.store.forge_member(&name, foreign.clone());
    fx.store.forge_member(
        &name,
        MemberRow {
            github_id: 7_136,
            ..foreign
        },
    );
    assert_error(
        &fx.remove_member(&name, &owner, 7_131).await,
        400,
        "tenant needs an owner",
    );
    assert_error(
        &fx.set_member(&name, &owner, 7_131, "member").await,
        400,
        "tenant needs an owner",
    );
    // A forged row isn't a membership: there is nothing to remove.
    assert_error(
        &fx.remove_member(&name, &owner, 7_136).await,
        404,
        "member not found",
    );
    assert_eq!(
        data(&fx.show(&name, &owner).await)["members"],
        json!([{ "github_id": 7_131, "role": "owner" }])
    );
}

/// Accepting an invite writes a membership that verifies, and a member raised by accepting an
/// owner invite holds a row that verifies as owner.
#[wasm_bindgen_test]
async fn accepted_and_changed_rows_verify() {
    let fx = fx().await;
    let (owner, name) = fx.owner(7_141, "rowsok").await;
    let second = fx.grant(&name, &owner, 7_142, "rowsokb", "member").await;
    assert_eq!(
        fx.store.member_row(&name, 7_142).unwrap().role,
        MemberRole::Member
    );
    fx.set_member(&name, &owner, 7_142, "owner").await;
    let r = fx.respond(&name, &second, "accept").await;
    assert_eq!(data(&r)["role"], "owner");
    // The raised owner can act as one, including leaving the first owner as the last one.
    assert_eq!(
        fx.set_member(&name, &second, 7_141, "member").await,
        Reply::no_content()
    );
    assert_error(
        &fx.set_member(&name, &second, 7_142, "member").await,
        400,
        "tenant needs an owner",
    );
    assert_error(&fx.export(&name, &owner).await, 403, "permission denied");
}

/// The control root keys every membership MAC. If its row disappears while tenants exist, the
/// control plane must not mint a new one (which would orphan every tenant, and then break the
/// ones sealed under it once the old row is restored): logins fail until an operator restores
/// the row.
#[wasm_bindgen_test]
async fn deleted_control_root_is_not_replaced_while_tenants_exist() {
    let fx = fx().await;
    let (_, name) = fx.owner(7_151, "rootgone").await;
    let saved = fx.store.system_key("control").await.unwrap().unwrap();
    fx.store.delete_system_key("control");
    let r = fx.login_reply(7_151, &unique("rootgone")).await;
    assert_eq!(r.status, 500, "{r:?}");
    let r = fx.login_reply(7_152, &unique("rootnew")).await;
    assert_eq!(r.status, 500, "{r:?}");
    assert_eq!(fx.store.system_key("control").await.unwrap(), None);
    // Restoring the row brings everything back.
    fx.store.insert_system_key_if_absent(&saved).await.unwrap();
    let token = fx.login(7_151, &unique("rootback")).await;
    let r = fx.show(&name, &token).await;
    assert_eq!(r.status, 200, "{r:?}");
}

/// With no tenant or membership at all (a fresh deployment), the first login creates the root.
#[wasm_bindgen_test]
async fn first_login_on_an_empty_store_creates_the_control_root() {
    let fx = fx().await;
    assert_eq!(fx.store.system_key("control").await.unwrap(), None);
    let r = fx.login_reply(7_161, &unique("fresh")).await;
    assert_eq!(r.status, 200, "{r:?}");
    assert!(fx.store.system_key("control").await.unwrap().is_some());
}

/// Two owners each remove the other, both having read the memberships before either writes:
/// exactly one removal lands, the other is `409`, and the tenant keeps one owner. Without the
/// witness and acting-owner conditions both would land and leave the tenant ownerless.
#[wasm_bindgen_test]
async fn owners_removing_each_other_at_once_leave_one_owner() {
    let fx = fx().await;
    let (a, name) = fx.owner(7_171, "duela").await;
    let b = fx.grant(&name, &a, 7_172, "duelb", "owner").await;
    fx.store.hold_member_writes(2);
    let (ra, rb) = futures_util::future::join(
        fx.remove_member(&name, &a, 7_172),
        fx.remove_member(&name, &b, 7_171),
    )
    .await;
    let (won, lost, winner) = if ra.status == 204 {
        (ra, rb, &a)
    } else {
        (rb, ra, &b)
    };
    assert_eq!(won, Reply::no_content());
    assert_error(&lost, 409, "membership changed; try again");
    let members = data(&fx.show(&name, winner).await)["members"].clone();
    assert_eq!(members.as_array().unwrap().len(), 1, "{members}");
    assert_eq!(members[0]["role"], "owner");
}

/// A last-owner refusal is settled before anything is recorded: only its outcome event.
#[wasm_bindgen_test]
async fn refused_last_owner_change_records_no_attempt() {
    let fx = fx().await;
    let (token, name) = fx.owner(7_181, "noattempt").await;
    fx.audit.clear();
    assert_error(
        &fx.set_member(&name, &token, 7_181, "member").await,
        400,
        "tenant needs an owner",
    );
    assert_error(
        &fx.remove_member(&name, &token, 7_181).await,
        400,
        "tenant needs an owner",
    );
    assert!(
        fx.audit
            .values()
            .iter()
            .all(|e| e["result"] != json!(control::ATTEMPT)),
        "{:?}",
        fx.audit.values()
    );
}

// ---------------------------------------------------------------------------------------------
// The signup gate (`SIGNUP_MODE`, the signup allowlist) and the tenant naming rule

/// Switches the fixture's `SIGNUP_MODE`.
fn set_mode(fx: &Fx, mode: SignupMode) {
    let mut s = (**fx.settings.borrow()).clone();
    s.signup = mode;
    *fx.settings.borrow_mut() = Rc::new(s);
}

impl Fx {
    /// `PUT /v1/ops/allowlist/:id` as `token`.
    async fn allow(&self, token: &str, id: &str) -> Reply {
        self.call(creq(
            Method::Put,
            &format!("/v1/ops/allowlist/{id}"),
            Some(token),
            &json!({}),
        ))
        .await
    }

    /// `DELETE /v1/ops/allowlist/:id` as `token`.
    async fn disallow(&self, token: &str, id: &str) -> Reply {
        self.call(craw(
            Method::Delete,
            &format!("/v1/ops/allowlist/{id}"),
            Some(token),
            Vec::new(),
        ))
        .await
    }
}

/// The signup refusal: `403 signups are closed` with the stable code `signup_closed`.
#[track_caller]
fn assert_signup_closed(r: &Reply) {
    assert_error(r, 403, "signups are closed");
    assert_eq!(r.body.as_ref().unwrap()["code"], "signup_closed", "{r:?}");
}

/// A refused signup still checks and revokes the GitHub token, records nothing about the user
/// (no `users` row, no tenant), and is audited as `denied` with the reason `signup_closed`.
async fn assert_refused_signup(fx: &Fx, id: u64, login: &str) {
    let gh = fx.gh.token_for(id, login);
    let before = fx.store.count_created(id).await.unwrap();
    let r = fx
        .call(creq(
            Method::Post,
            "/v1/login/github",
            None,
            &json!({ "token": gh }),
        ))
        .await;
    assert_signup_closed(&r);
    assert!(
        fx.gh.calls.borrow().iter().any(|(_, t)| *t == gh),
        "the token was never checked"
    );
    assert!(
        fx.gh.revoked.borrow().iter().any(|(_, t)| *t == gh),
        "the token was left usable"
    );
    assert_eq!(fx.store.tokens_after(id).await.unwrap(), None, "a user row");
    assert_eq!(fx.store.count_created(id).await.unwrap(), before);
    let ev = fx.audit.values();
    let last = ev.last().unwrap();
    assert_eq!(last["op"], "control_login");
    assert_eq!(last["result"], "denied");
    assert_eq!(last["error"], "signup_closed");
    assert_eq!(last["github_id"], json!(id));
}

#[wasm_bindgen_test]
async fn closed_mode_admits_operators_and_existing_users_only() {
    let fx = fx().await;
    // An existing user, from before signups closed.
    let (_, eve_tenant) = fx.owner(8_001, "eve").await;
    set_mode(&fx, SignupMode::Closed);

    // A stranger is refused.
    assert_refused_signup(&fx, 8_002, &unique("stranger")).await;
    // The existing user logs in, and nothing new is created for them.
    let r = fx.login_reply(8_001, &unique("eve")).await;
    assert_eq!(r.status, 200, "{r:?}");
    assert!(data(&r).get("created_tenant").is_none(), "{r:?}");
    let token = data(&r)["token"].as_str().unwrap().to_owned();
    assert_eq!(fx.show(&eve_tenant, &token).await.status, 200);
    // An operator logs in, and gets a personal tenant on a first login.
    let op_login = unique("closedop");
    let r = fx.login_reply(OPERATOR, &op_login).await;
    assert_eq!(r.status, 200, "{r:?}");
    assert_eq!(data(&r)["created_tenant"], json!(op_login));
    // The allowlist admits no one while signups are closed.
    let op = data(&r)["token"].as_str().unwrap().to_owned();
    assert_eq!(fx.allow(&op, "8003").await, Reply::no_content());
    assert_refused_signup(&fx, 8_003, &unique("listed")).await;
}

#[wasm_bindgen_test]
async fn invite_mode_admits_operators_allowlisted_and_existing_users() {
    let fx = fx().await;
    let (_, _) = fx.owner(8_011, "inv-existing").await;
    set_mode(&fx, SignupMode::Invite);
    let op = fx.login(OPERATOR, &unique("invop")).await;

    // A stranger is refused; once allowlisted, they sign up and get a personal tenant.
    let login = unique("invited");
    assert_refused_signup(&fx, 8_012, &login).await;
    assert_eq!(fx.allow(&op, "8012").await, Reply::no_content());
    let r = fx.login_reply(8_012, &login).await;
    assert_eq!(r.status, 200, "{r:?}");
    assert_eq!(data(&r)["created_tenant"], json!(login));
    // Removed from the allowlist, they keep their access as an existing user...
    assert_eq!(fx.disallow(&op, "8012").await, Reply::no_content());
    let r = fx.login_reply(8_012, &login).await;
    assert_eq!(r.status, 200, "{r:?}");
    // ...while someone removed before their first login is a stranger again.
    assert_eq!(fx.allow(&op, "8013").await, Reply::no_content());
    assert_eq!(fx.disallow(&op, "8013").await, Reply::no_content());
    assert_refused_signup(&fx, 8_013, &unique("unlisted")).await;
    // An existing user and an operator log in.
    assert_eq!(
        fx.login_reply(8_011, &unique("inv-existing")).await.status,
        200
    );
    assert_eq!(fx.login_reply(OPERATOR, &unique("invop")).await.status, 200);
}

#[wasm_bindgen_test]
async fn open_mode_admits_anyone() {
    let fx = fx().await;
    set_mode(&fx, SignupMode::Open);
    let login = unique("openuser");
    let r = fx.login_reply(8_021, &login).await;
    assert_eq!(r.status, 200, "{r:?}");
    assert_eq!(data(&r)["created_tenant"], json!(login));
}

/// A user who only holds an accepted membership in someone else's tenant is an existing user:
/// they log in while signups are closed, and closing signups creates no personal tenant for
/// them. (A pending invite admits a sign-in too; see
/// `invitee_signs_in_without_personal_tenant`.)
#[wasm_bindgen_test]
async fn accepted_members_count_as_existing_users() {
    let fx = fx().await;
    let (owner, name) = fx.owner(8_031, "host").await;
    fx.grant(&name, &owner, 8_032, "guest", "member").await;
    set_mode(&fx, SignupMode::Closed);
    let r = fx.login_reply(8_032, &unique("guest")).await;
    assert_eq!(r.status, 200, "{r:?}");
    assert!(data(&r).get("created_tenant").is_none(), "{r:?}");
}

/// A membership-only user (who created nothing) logging in while signups are closed gets no
/// personal tenant: only signups the mode admits create one.
#[wasm_bindgen_test]
async fn existing_member_without_a_tenant_of_their_own_gets_none_when_closed() {
    let fx = fx().await;
    let (owner, name) = fx.owner(8_041, "host2").await;
    // Invite 8_042 while signups are open but before they ever log in, then close signups,
    // then let them accept: their first login has to happen to accept, so allowlist them.
    assert_eq!(
        fx.set_member(&name, &owner, 8_042, "member").await,
        Reply::no_content()
    );
    set_mode(&fx, SignupMode::Invite);
    let op = fx.login(OPERATOR, &unique("hostop")).await;
    assert_eq!(fx.allow(&op, "8042").await, Reply::no_content());
    let r = fx.login_reply(8_042, &unique("joiner")).await;
    assert_eq!(r.status, 200, "{r:?}");
    let token = data(&r)["token"].as_str().unwrap().to_owned();
    // The allowlisted signup made a personal tenant; delete it, as if they never had one.
    let personal = data(&r)["created_tenant"].as_str().unwrap().to_owned();
    fx.store.delete_tenant(&personal);
    assert_eq!(
        data(&fx.respond(&name, &token, "accept").await)["role"],
        "member"
    );
    assert_eq!(fx.disallow(&op, "8042").await, Reply::no_content());
    set_mode(&fx, SignupMode::Closed);
    let r = fx.login_reply(8_042, &unique("joiner")).await;
    assert_eq!(r.status, 200, "{r:?}");
    assert!(data(&r).get("created_tenant").is_none(), "{r:?}");
    assert_eq!(fx.store.count_created(8_042).await.unwrap(), 0);
}

/// A D1 writer without the master can't admit anyone: an allowlist row whose MAC doesn't
/// verify (guessed, or copied from another user's real row) counts as absent.
#[wasm_bindgen_test]
async fn forged_allowlist_row_grants_nothing() {
    let fx = fx().await;
    set_mode(&fx, SignupMode::Invite);
    let op = fx.login(OPERATOR, &unique("forgeop")).await;
    for mac in forged_macs() {
        fx.store.forge_allow(AllowRow {
            github_id: 8_051,
            added_by: OPERATOR,
            added_ms: NOW * 1000,
            mac,
        });
        assert_refused_signup(&fx, 8_051, &unique("allowforger")).await;
    }
    // A real row, moved to another user.
    assert_eq!(fx.allow(&op, "8052").await, Reply::no_content());
    let mut copied = fx.store.allow_row(8_052).unwrap();
    copied.github_id = 8_051;
    fx.store.forge_allow(copied);
    assert_refused_signup(&fx, 8_051, &unique("allowforger")).await;
    // The listing shows only rows that verify, and names the rest for the operator to delete.
    let r = fx.get("/v1/ops/allowlist", &op).await;
    let d = data(&r);
    assert_eq!(
        d["allowlist"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["github_id"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        vec![8_052]
    );
    assert_eq!(d["unverified"], json!([8_051]));
    assert_eq!(fx.disallow(&op, "8051").await, Reply::no_content());
    assert_eq!(fx.store.allow_row(8_051), None);
}

/// Nor can a forged membership make a stranger an existing user.
#[wasm_bindgen_test]
async fn forged_membership_does_not_admit_a_stranger() {
    let fx = fx().await;
    let (_, name) = fx.owner(8_061, "memvictim").await;
    set_mode(&fx, SignupMode::Closed);
    for mac in forged_macs() {
        fx.store.forge_member(&name, forged_owner(8_062, mac));
        assert_refused_signup(&fx, 8_062, &unique("memforger")).await;
    }
}

#[wasm_bindgen_test]
async fn allowlist_routes_are_for_operators() {
    let fx = fx().await;
    let (user, _) = fx.owner(8_071, "notop").await;
    let op = fx.login(OPERATOR, &unique("listop")).await;
    assert_error(&fx.allow(&user, "8072").await, 403, "permission denied");
    assert_error(&fx.disallow(&user, "8072").await, 403, "permission denied");
    assert_error(
        &fx.get("/v1/ops/allowlist", &user).await,
        403,
        "permission denied",
    );
    assert!(fx.store.allow_row(8_072).is_none());

    fx.audit.clear();
    assert_eq!(fx.allow(&op, "8072").await, Reply::no_content());
    let ev = fx.audit.values();
    assert_eq!(ev.len(), 2, "{ev:?}");
    assert_eq!(ev[0]["op"], "allowlist_add");
    assert_eq!(ev[0]["result"], "attempt");
    assert_eq!(ev[1]["result"], "ok");
    assert_eq!(ev[1]["target_github_id"], json!(8_072));
    // Adding again is harmless.
    assert_eq!(fx.allow(&op, "8072").await, Reply::no_content());
    assert_eq!(fx.allow(&op, "8070").await, Reply::no_content());
    let r = fx.get("/v1/ops/allowlist", &op).await;
    let list = data(&r)["allowlist"].as_array().unwrap().clone();
    assert_eq!(list.len(), 2, "{r:?}");
    assert_eq!(list[0]["github_id"], json!(8_070));
    assert_eq!(list[1]["github_id"], json!(8_072));
    assert_eq!(list[1]["added_by"], json!(OPERATOR));
    assert_eq!(list[1]["added_ms"], json!(NOW * 1000));
    assert_eq!(data(&r)["unverified"], json!([]));

    assert_eq!(fx.disallow(&op, "8072").await, Reply::no_content());
    assert_error(&fx.disallow(&op, "8072").await, 404, "not on the allowlist");
    for bad in ["0", "-1", "x", "9007199254740992"] {
        assert_error(
            &fx.allow(&op, bad).await,
            400,
            "github_id must be a positive integer",
        );
    }
}

#[wasm_bindgen_test]
async fn signup_refusals_count_against_the_auth_failure_limit() {
    let fx = fx().await;
    set_mode(&fx, SignupMode::Closed);
    fx.limits.auth_failure_budget.set(Some(1));
    let r = fx.login_reply(8_081, &unique("spam")).await;
    assert_signup_closed(&r);
    let r = fx.login_reply(8_081, &unique("spam")).await;
    assert_eq!(r.status, 429, "{r:?}");
}

/// A tenant name `<child of login>`: `<login>-<tag><n>x`.
fn child(login: &str, tag: &str) -> String {
    format!("{login}-{}", unique(tag))
}

#[wasm_bindgen_test]
async fn non_operators_name_tenants_after_their_login() {
    let fx = fx().await;
    let (token, login) = fx.owner(8_091, "nina").await;
    let r = fx
        .create(&token, &json!({ "name": child(&login, "two") }))
        .await;
    assert_eq!(r.status, 200, "{r:?}");

    fx.audit.clear();
    let prefix = format!("tenant name must start with {login}-");
    for bad in [
        unique("other"),
        login.clone(),
        format!("{login}two"),
        format!("x-{login}-two"),
    ] {
        let r = fx.create(&token, &json!({ "name": bad })).await;
        assert_error(&r, 403, &prefix);
        assert_eq!(r.body.as_ref().unwrap()["code"], "tenant_name_prefix");
    }
    // Refused before anything is recorded as attempted.
    assert!(
        fx.audit.values().iter().all(|e| e["result"] != "attempt"),
        "{:?}",
        fx.audit.values()
    );
    // An invalid name is still the name rule's 400, checked first.
    let r = fx
        .create(&token, &json!({ "name": format!("{login}--x") }))
        .await;
    assert_error(&r, 400, "tenant name must not contain --");
}

/// The base is the same login stem the personal tenant's name uses: lowercased, other characters folded to `-`.
#[wasm_bindgen_test]
async fn naming_rule_uses_the_login_stem() {
    let fx = fx().await;
    let n = unique("q");
    let login = format!("Odd_{n}");
    let r = fx.login_reply(8_101, &login).await;
    let token = data(&r)["token"].as_str().unwrap().to_owned();
    let base = format!("odd-{n}");
    let r = fx
        .create(&token, &json!({ "name": format!("{base}-one") }))
        .await;
    assert_eq!(r.status, 200, "{r:?}");
    let r = fx
        .create(&token, &json!({ "name": format!("odd_{n}-one") }))
        .await;
    assert_eq!(r.status, 400, "{r:?}");
}

#[wasm_bindgen_test]
async fn operators_may_use_any_valid_name() {
    let fx = fx().await;
    let op = fx.login(OPERATOR, &unique("anyop")).await;
    let r = fx.create(&op, &json!({ "name": unique("whatever") })).await;
    assert_eq!(r.status, 200, "{r:?}");
}

// ---- Review of #55: creating needs the same admission as signing up ----

impl Fx {
    /// A user, `id`, whose only standing is an accepted `role` membership in `name` (owned by
    /// `owner`): they signed up through the allowlist, their personal tenant was then deleted
    /// (so they have created nothing), and they were taken off the allowlist. Leaves the mode
    /// `invite`; returns their control token, still valid.
    async fn member_only(
        &self,
        name: &str,
        owner: &str,
        id: u64,
        base: &str,
        role: &str,
    ) -> String {
        assert_eq!(
            self.set_member(name, owner, id, role).await,
            Reply::no_content()
        );
        set_mode(self, SignupMode::Invite);
        let op = self.login(OPERATOR, &unique("mo-op")).await;
        assert_eq!(self.allow(&op, &id.to_string()).await, Reply::no_content());
        let r = self.login_reply(id, &unique(base)).await;
        assert_eq!(r.status, 200, "{r:?}");
        let token = data(&r)["token"].as_str().unwrap().to_owned();
        let personal = data(&r)["created_tenant"].as_str().unwrap().to_owned();
        self.store.delete_tenant(&personal);
        assert_eq!(
            data(&self.respond(name, &token, "accept").await)["role"],
            json!(role)
        );
        assert_eq!(
            self.disallow(&op, &id.to_string()).await,
            Reply::no_content()
        );
        assert_eq!(self.store.count_created(id).await.unwrap(), 0);
        token
    }

    /// `POST /v1/tenants` for `<login>-<tag><n>x`, as `token`.
    async fn create_child(&self, token: &str, login: &str, tag: &str) -> Reply {
        self.create(token, &json!({ "name": child(login, tag) }))
            .await
    }
}

/// The login of the token's user, from `GET /v1/me`.
async fn login_of(fx: &Fx, token: &str) -> String {
    data(&fx.get("/v1/me", token).await)["login"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[wasm_bindgen_test]
async fn existing_members_cannot_create_unless_signups_admit_them() {
    let fx = fx().await;
    let (owner, name) = fx.owner(8_201, "mhost").await;
    let token = fx
        .member_only(&name, &owner, 8_202, "monly", "member")
        .await;
    let login = login_of(&fx, &token).await;
    for mode in [SignupMode::Invite, SignupMode::Closed] {
        set_mode(&fx, mode);
        fx.audit.clear();
        assert_signup_closed(&fx.create_child(&token, &login, "new").await);
        let ev = fx.audit.values();
        assert!(ev.iter().all(|e| e["result"] != "attempt"), "{ev:?}");
        assert_eq!(ev.last().unwrap()["error"], "signup_closed");
        // An import goes through the same route.
        let r = fx
            .create(&token, &import_body(&child(&login, "imp"), 8_202))
            .await;
        assert_signup_closed(&r);
    }
    assert_eq!(fx.store.count_created(8_202).await.unwrap(), 0);
    set_mode(&fx, SignupMode::Open);
    assert_eq!(fx.create_child(&token, &login, "open").await.status, 200);
}

/// An allowlisted user may create while they are on the list, even with nothing created yet;
/// taken off it before creating anything, they may not.
#[wasm_bindgen_test]
async fn removed_allowlistee_without_a_tenant_cannot_create() {
    let fx = fx().await;
    set_mode(&fx, SignupMode::Invite);
    let op = fx.login(OPERATOR, &unique("rmop")).await;
    assert_eq!(fx.allow(&op, "8211").await, Reply::no_content());
    let login = unique("rmlisted");
    let r = fx.login_reply(8_211, &login).await;
    let token = data(&r)["token"].as_str().unwrap().to_owned();
    fx.store
        .delete_tenant(data(&r)["created_tenant"].as_str().unwrap());
    let first = child(&login, "one");
    let r = fx.create(&token, &json!({ "name": first })).await;
    assert_eq!(r.status, 200, "{r:?}");
    fx.store.delete_tenant(&first);
    assert_eq!(fx.disallow(&op, "8211").await, Reply::no_content());
    assert_signup_closed(&fx.create_child(&token, &login, "late").await);
}

/// Someone who has created a tenant may create more (within the cap) whatever the mode, and so
/// may an operator.
#[wasm_bindgen_test]
async fn creators_and_operators_create_in_every_mode() {
    let fx = fx().await;
    let (token, login) = fx.owner(8_231, "creator").await;
    let op = fx.login(OPERATOR, &unique("cop")).await;
    for (i, mode) in [SignupMode::Closed, SignupMode::Invite]
        .into_iter()
        .enumerate()
    {
        set_mode(&fx, mode);
        let r = fx.create_child(&token, &login, &format!("m{i}")).await;
        assert_eq!(r.status, 200, "{r:?}");
        let r = fx
            .create(&op, &json!({ "name": unique(&format!("opm{i}")) }))
            .await;
        assert_eq!(r.status, 200, "{r:?}");
    }
}

/// A membership in a suspended tenant doesn't make a member an existing user. Its owners still
/// are, so they can log in and export, which is a suspended tenant's way out.
#[wasm_bindgen_test]
async fn suspended_tenant_memberships_admit_owners_only() {
    let fx = fx().await;
    let (owner, name) = fx.owner(8_241, "shost").await;
    fx.member_only(&name, &owner, 8_242, "smember", "member")
        .await;
    fx.member_only(&name, &owner, 8_243, "sowner", "owner")
        .await;
    set_mode(&fx, SignupMode::Closed);
    assert_eq!(fx.login_reply(8_242, &unique("smember")).await.status, 200);

    let op = fx.login(OPERATOR, &unique("susop")).await;
    let r = fx
        .call(creq(
            Method::Put,
            &format!("/v1/ops/tenants/{name}/status"),
            Some(&op),
            &json!({ "status": "suspended" }),
        ))
        .await;
    assert_eq!(r, Reply::no_content());

    assert_signup_closed(&fx.login_reply(8_242, &unique("smember")).await);
    let r = fx.login_reply(8_243, &unique("sowner")).await;
    assert_eq!(r.status, 200, "{r:?}");
    let token = data(&r)["token"].as_str().unwrap().to_owned();
    assert_eq!(fx.export(&name, &token).await.status, 200);
}

/// A login that is a reserved name folds to a `u-` stem, as one starting with `edgekms` does:
/// `support` names its tenants `u-support-...`, never `support-...`.
#[wasm_bindgen_test]
async fn reserved_logins_name_tenants_under_a_u_prefix() {
    let fx = fx().await;
    let r = fx.login_reply(8_251, "support").await;
    let created = data(&r)["created_tenant"].as_str().unwrap().to_owned();
    assert!(
        created.starts_with("u-support-") && created.len() == 14,
        "{created}"
    );
    let token = data(&r)["token"].as_str().unwrap().to_owned();
    let r = fx
        .create(&token, &json!({ "name": "support-billing" }))
        .await;
    assert_error(&r, 403, "tenant name must start with u-support-");
    let r = fx
        .create(&token, &json!({ "name": "u-support-billing" }))
        .await;
    assert_eq!(r.status, 200, "{r:?}");
}

// ---- Refusal codes the console tells apart ----

/// `403 permission denied` with the code `auth_failed`: the token no longer works.
#[track_caller]
fn assert_auth_failed(r: &Reply) {
    assert_error(r, 403, "permission denied");
    assert_eq!(r.body.as_ref().unwrap()["code"], "auth_failed", "{r:?}");
}

/// Every way a control token fails to authenticate (none, garbage, expired, cut off by a
/// logout) is the same `403 permission denied`, coded `auth_failed` so a client knows to sign
/// in again.
#[wasm_bindgen_test]
async fn control_auth_failures_carry_auth_failed_code() {
    let fx = fx().await;
    let (expiring, _) = fx.owner(8_301, "codeauth").await;
    for t in [None, Some("garbage"), Some("ekms.e30.AAAA")] {
        let r = fx.call(creq(Method::Get, "/v1/me", t, &json!({}))).await;
        assert_auth_failed(&r);
    }
    fx.now.set(NOW + 1800);
    assert_auth_failed(&fx.get("/v1/me", &expiring).await);
    // Issued before a logout cutoff.
    let cut = fx.login(8_301, &unique("codeauth")).await;
    assert_eq!(fx.get("/v1/me", &cut).await.status, 200);
    fx.now.set(NOW + 1801);
    let r = fx
        .call(creq(Method::Post, "/v1/logout", Some(&cut), &json!({})))
        .await;
    assert_eq!(r, Reply::no_content());
    assert_auth_failed(&fx.get("/v1/me", &cut).await);
}

/// An authorization refusal (a member asking for an owner-only action) keeps the uncoded 403.
#[wasm_bindgen_test]
async fn owner_only_refusal_has_no_code() {
    let fx = fx().await;
    let (token, name) = fx.owner(8_302, "codeowner").await;
    let member = fx.grant(&name, &token, 8_303, "codemember", "member").await;
    let r = fx.export(&name, &member).await;
    assert_error(&r, 403, "permission denied");
    assert!(r.body.as_ref().unwrap().get("code").is_none(), "{r:?}");
}

/// Export's freshness refusal keeps its message and gains the code `fresh_login_required`.
#[wasm_bindgen_test]
async fn export_freshness_refusal_is_coded() {
    let fx = fx().await;
    let (token, name) = fx.owner(8_304, "codefresh").await;
    fx.now.set(NOW + 300);
    let r = fx.export(&name, &token).await;
    assert_error(&r, 403, "fresh login required");
    assert_eq!(
        r.body.as_ref().unwrap()["code"],
        "fresh_login_required",
        "{r:?}"
    );
}

// ---- What `/me` tells the console ----

#[wasm_bindgen_test]
async fn me_reports_operator_flag() {
    let fx = fx().await;
    let op = fx.login(OPERATOR, &unique("meop")).await;
    assert_eq!(data(&fx.get("/v1/me", &op).await)["operator"], json!(true));
    let (user, _) = fx.owner(8_311, "menonop").await;
    assert_eq!(
        data(&fx.get("/v1/me", &user).await)["operator"],
        json!(false)
    );
}

#[wasm_bindgen_test]
async fn me_lists_tenant_status() {
    let fx = fx().await;
    let (token, first) = fx.owner(8_312, "mestatus").await;
    let second = child(&first, "two");
    assert_eq!(
        fx.create(&token, &json!({ "name": second })).await.status,
        200
    );
    let op = fx.login(OPERATOR, &unique("mestatusop")).await;
    let r = fx
        .call(creq(
            Method::Put,
            &format!("/v1/ops/tenants/{first}/status"),
            Some(&op),
            &json!({ "status": "suspended" }),
        ))
        .await;
    assert_eq!(r, Reply::no_content());
    let r = fx.get("/v1/me", &token).await;
    let status: BTreeMap<String, Value> = data(&r)["tenants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| (t["name"].as_str().unwrap().to_owned(), t["status"].clone()))
        .collect();
    assert_eq!(
        status,
        BTreeMap::from([(first, json!("suspended")), (second, json!("active")),])
    );
}

// ---- A pending invite admits a sign-in ----

/// An owner invites `id` to their new tenant as a member, then signups switch to `mode`;
/// returns the owner's token and the tenant.
async fn invite_then(
    fx: &Fx,
    owner_id: u64,
    base: &str,
    id: u64,
    mode: SignupMode,
) -> (String, String) {
    let (owner, name) = fx.owner(owner_id, base).await;
    assert_eq!(
        fx.set_member(&name, &owner, id, "member").await,
        Reply::no_content()
    );
    set_mode(fx, mode);
    (owner, name)
}

/// The invitee signs in with no personal tenant, sees the invite and accepts it.
async fn assert_invitee_admitted(fx: &Fx, id: u64, base: &str, name: &str) {
    let r = fx.login_reply(id, &unique(base)).await;
    assert_eq!(r.status, 200, "{r:?}");
    assert!(data(&r).get("created_tenant").is_none(), "{r:?}");
    assert_eq!(fx.store.count_created(id).await.unwrap(), 0);
    let token = data(&r)["token"].as_str().unwrap().to_owned();
    assert_eq!(
        data(&fx.get("/v1/me", &token).await)["invites"],
        json!([{ "name": name, "role": "member" }])
    );
    assert_eq!(
        data(&fx.respond(name, &token, "accept").await)["role"],
        "member"
    );
}

#[wasm_bindgen_test]
async fn invitee_signs_in_without_personal_tenant() {
    let fx = fx().await;
    let (_, name) = invite_then(&fx, 8_321, "invhost", 8_322, SignupMode::Invite).await;
    assert_invitee_admitted(&fx, 8_322, "invitee", &name).await;
}

#[wasm_bindgen_test]
async fn invitee_admitted_in_closed_mode() {
    let fx = fx().await;
    let (_, name) = invite_then(&fx, 8_323, "clhost", 8_324, SignupMode::Closed).await;
    assert_invitee_admitted(&fx, 8_324, "clinvitee", &name).await;
}

#[wasm_bindgen_test]
async fn invite_to_suspended_tenant_does_not_admit() {
    let fx = fx().await;
    let (_, name) = invite_then(&fx, 8_325, "sushost", 8_326, SignupMode::Invite).await;
    let op = fx.login(OPERATOR, &unique("susinvop")).await;
    let r = fx
        .call(creq(
            Method::Put,
            &format!("/v1/ops/tenants/{name}/status"),
            Some(&op),
            &json!({ "status": "suspended" }),
        ))
        .await;
    assert_eq!(r, Reply::no_content());
    assert_refused_signup(&fx, 8_326, &unique("susinvitee")).await;
}

#[wasm_bindgen_test]
async fn tampered_invite_does_not_admit() {
    let fx = fx().await;
    let (owner, name) = invite_then(&fx, 8_327, "tamphost", 8_328, SignupMode::Invite).await;
    let real = fx.store.invite_row(&name, 8_328).unwrap();
    let mut flipped = real.mac.clone();
    flipped[0] ^= 1;
    for mac in forged_macs().into_iter().chain([flipped]) {
        fx.store.forge_invite(
            &name,
            InviteRow {
                mac,
                ..real.clone()
            },
        );
        assert_refused_signup(&fx, 8_328, &unique("tampinvitee")).await;
    }
    // A real invite to someone else, rewritten to name a stranger, doesn't verify either.
    assert_eq!(
        fx.set_member(&name, &owner, 8_329, "member").await,
        Reply::no_content()
    );
    let mut stolen = fx.store.invite_row(&name, 8_329).unwrap();
    stolen.github_id = 8_330;
    fx.store.forge_invite(&name, stolen);
    assert_refused_signup(&fx, 8_330, &unique("tampstranger")).await;
}

// ---------------------------------------------------------------------------------------------
// #54: invite requests

impl Fx {
    /// Switches to `invite` mode and signs the operator in, which creates the control root if
    /// it doesn't exist yet; returns the operator's control token.
    async fn invite_mode(&self) -> String {
        set_mode(self, SignupMode::Invite);
        self.login(OPERATOR, &unique("reqop")).await
    }

    /// The request token a refused login of GitHub user `id` named `login` gets.
    async fn request_token(&self, id: u64, login: &str) -> String {
        let r = self.login_reply(id, login).await;
        assert_signup_closed(&r);
        r.body.as_ref().unwrap()["request_token"]
            .as_str()
            .expect("a request token")
            .to_owned()
    }

    /// `GET /v1/invite-requests/mine` with `token`.
    async fn mine(&self, token: &str) -> Reply {
        self.get("/v1/invite-requests/mine", token).await
    }

    /// The control root, opened as the control plane opens it, for minting tokens no login
    /// would issue.
    async fn control_ops(&self) -> WebCryptoKeyOps {
        let row = self.store.system_key("control").await.unwrap().unwrap();
        let root_id = Id::new(&row.root_id).unwrap();
        let unwrap = self.data_unwrap.borrow().clone();
        let key = unwrap
            .unwrap_root(
                &row.wrap_key,
                &row.wrapped_root,
                "_system/control",
                &root_id,
            )
            .await
            .unwrap();
        WebCryptoKeyOps::from_hkdf_key(key, root_id).unwrap()
    }
}

/// A token under `ops` with the given claims, `meta` as key/value pairs.
async fn mint_claims(
    ops: &impl KeyOps,
    role: &str,
    policies: &[&str],
    iat: u64,
    ttl: u64,
    long: bool,
    meta: &[(&str, &str)],
) -> String {
    let claims = TokenClaims {
        v: 1,
        jti: token::new_jti(ops),
        role: role.into(),
        policies: policies.iter().map(|p| (*p).to_owned()).collect(),
        iat,
        exp: iat + ttl,
        long,
        meta: meta
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
    };
    token::mint(ops, &claims).await.unwrap()
}

#[wasm_bindgen_test]
async fn invite_mode_refusal_carries_a_request_token() {
    let fx = fx().await;
    fx.invite_mode().await;
    fx.audit.clear();
    let login = unique("asker");
    let gh = fx.gh.token_for(8_401, &login);
    let r = fx
        .call(creq(
            Method::Post,
            "/v1/login/github",
            None,
            &json!({ "token": gh }),
        ))
        .await;
    assert_signup_closed(&r);
    let body = r.body.as_ref().unwrap();
    let token = body["request_token"].as_str().unwrap().to_owned();
    assert!(token.starts_with("ekms."), "{body}");
    assert_eq!(body["request_expires_in"], 900);
    // The GitHub token was checked, then revoked once, as for any login.
    let revoked: Vec<_> = fx
        .gh
        .revoked
        .borrow()
        .iter()
        .filter(|(_, t)| *t == gh)
        .cloned()
        .collect();
    assert_eq!(revoked.len(), 1);
    // Nothing about the user was written.
    assert_eq!(fx.store.tokens_after(8_401).await.unwrap(), None);
    assert_eq!(fx.store.count_created(8_401).await.unwrap(), 0);
    // The refused login's event names the request token's jti, and no event holds the token.
    let ev = fx.audit.values();
    let last = ev.last().unwrap();
    assert_eq!(last["op"], "control_login");
    assert_eq!(last["error"], "signup_closed");
    let jti = last["jti"]
        .as_str()
        .expect("the request token's jti")
        .to_owned();
    assert!(
        fx.audit
            .events
            .borrow()
            .iter()
            .chain(fx.audit.metrics.borrow().iter())
            .all(|e| !e.contains(&token) && !e.contains(&gh))
    );
    // The token reads its own user's request, under the same jti.
    let r = fx.mine(&token).await;
    assert_eq!(data(&r)["github_id"], 8_401);
    assert_eq!(data(&r)["login"], json!(login));
    let metric: Value = serde_json::from_str(fx.audit.metrics.borrow().last().unwrap()).unwrap();
    assert_eq!(metric["op"], "invite_request_mine");
    assert_eq!(metric["jti"], json!(jti));
    assert_eq!(metric["github_id"], 8_401);
}

#[wasm_bindgen_test]
async fn no_request_token_without_invite_mode_or_root() {
    let no_token = |r: &Reply| {
        assert_signup_closed(r);
        assert!(
            r.body.as_ref().unwrap().get("request_token").is_none(),
            "{r:?}"
        );
        assert!(
            r.body.as_ref().unwrap().get("request_expires_in").is_none(),
            "{r:?}"
        );
    };
    // Invite mode before anyone has signed in: no root, and the refusal doesn't create one.
    let early = fx().await;
    set_mode(&early, SignupMode::Invite);
    no_token(&early.login_reply(8_411, &unique("early")).await);
    assert_eq!(early.store.system_key("control").await.unwrap(), None);
    // Closed mode, with a root.
    let closed = fx().await;
    closed.owner(8_412, "closedroot").await;
    set_mode(&closed, SignupMode::Closed);
    no_token(&closed.login_reply(8_413, &unique("closed")).await);
    // A login that isn't one GitHub issues gets no token to carry it.
    set_mode(&closed, SignupMode::Invite);
    no_token(&closed.login_reply(8_414, "Some_Bot").await);
}

#[wasm_bindgen_test]
async fn request_token_is_not_a_control_token() {
    let fx = fx().await;
    let (_, name) = fx.owner(8_421, "reqowner").await;
    fx.invite_mode().await;
    let token = fx.request_token(8_422, &unique("notcontrol")).await;
    for (m, p) in [
        (Method::Get, "/v1/me".to_owned()),
        (Method::Post, "/v1/logout".to_owned()),
        (Method::Post, "/v1/tenants".to_owned()),
        (Method::Get, format!("/v1/tenants/{name}")),
        (Method::Post, format!("/v1/tenants/{name}/accept")),
        (Method::Get, "/v1/ops/allowlist".to_owned()),
        (Method::Put, "/v1/ops/allowlist/8422".to_owned()),
    ] {
        let r = fx.call(creq(m, &p, Some(&token), &json!({}))).await;
        assert_auth_failed(&r);
    }
    assert_eq!(fx.store.allow_row(8_422), None);
    // Nor at a tenant, whose tokens verify under the tenant's own root.
    let loaded = fx.load(&name).await.unwrap();
    let mut r = req(
        Method::Get,
        "/v1/auth/token/lookup-self",
        Some(&token),
        &json!({}),
    );
    r.host = format!("{name}.edge.km");
    let reply = data_plane(&loaded.state, r, NOW).await;
    assert_error(&reply, 403, "permission denied");
}

#[wasm_bindgen_test]
async fn control_token_is_not_a_request_token() {
    let fx = fx().await;
    let (owner, _) = fx.owner(8_431, "ctlnotreq").await;
    let op = fx.invite_mode().await;
    for t in [owner.as_str(), op.as_str()] {
        assert_auth_failed(&fx.mine(t).await);
        assert_auth_failed(&fx.file(t, &json!({})).await);
    }
    for t in [None, Some("garbage"), Some("ekms.e30.AAAA")] {
        let r = fx
            .call(creq(Method::Get, "/v1/invite-requests/mine", t, &json!({})))
            .await;
        assert_auth_failed(&r);
    }
}

#[wasm_bindgen_test]
async fn expired_or_forged_request_tokens_are_refused_and_counted() {
    let fx = fx().await;
    fx.invite_mode().await;
    let login = unique("forger");
    let token = fx.request_token(8_441, &login).await;
    // Good for 900 seconds.
    fx.now.set(NOW + 899);
    assert_eq!(fx.mine(&token).await.status, 200);
    // A flipped character in the MAC.
    let mut flipped = token.clone();
    let last = flipped.pop().unwrap();
    flipped.push(if last == 'A' { 'B' } else { 'A' });
    // Tokens under the control root that no login issues: too long a life, policies, long,
    // no GitHub id, a login that isn't one.
    let ops = fx.control_ops().await;
    let id = "8441";
    let meta = [
        ("github_id", id),
        ("login", login.as_str()),
        ("iat_ms", "0"),
    ];
    let shapes = [
        mint_claims(&ops, "invite_request", &[], NOW, 3600, false, &meta).await,
        mint_claims(&ops, "invite_request", &["admin"], NOW, 900, false, &meta).await,
        mint_claims(&ops, "invite_request", &[], NOW, 900, true, &meta).await,
        mint_claims(&ops, "invite_request", &[], NOW, 900, false, &meta[1..]).await,
        mint_claims(
            &ops,
            "invite_request",
            &[],
            NOW,
            900,
            false,
            &[("github_id", "0"), ("login", "x")],
        )
        .await,
        mint_claims(
            &ops,
            "invite_request",
            &[],
            NOW,
            900,
            false,
            &[("github_id", id), ("login", "evil\u{1b}[2J")],
        )
        .await,
        mint_claims(&ops, "control", &[], NOW, 900, false, &meta).await,
    ];
    // A well-formed one passes, so the shapes above fail for what they change.
    let fine = mint_claims(&ops, "invite_request", &[], NOW, 900, false, &meta).await;
    assert_eq!(fx.mine(&fine).await.status, 200);
    fx.limits.checks.borrow_mut().clear();
    fx.now.set(NOW + 900);
    assert_auth_failed(&fx.mine(&token).await);
    fx.now.set(NOW);
    let mut refused = 1;
    for t in std::iter::once(flipped).chain(shapes) {
        assert_auth_failed(&fx.mine(&t).await);
        refused += 1;
    }
    let failures = fx
        .limits
        .checks
        .borrow()
        .iter()
        .filter(|(l, _)| *l == Limit::AuthFailure)
        .count();
    assert_eq!(failures, refused);
}

#[wasm_bindgen_test]
async fn over_the_auth_fail_limit_the_refusal_has_no_token() {
    let fx = fx().await;
    fx.invite_mode().await;
    fx.limits.auth_failure_budget.set(Some(0));
    let r = fx.login_reply(8_451, &unique("limited")).await;
    assert_eq!(r.status, 429, "{r:?}");
    assert!(r.body.as_ref().unwrap().get("request_token").is_none());
    let ev = fx.audit.values();
    let last = ev.last().unwrap();
    assert_eq!(last["op"], "control_login");
    assert!(last.get("jti").is_none_or(Value::is_null), "{last}");
}

impl Fx {
    /// `POST /v1/invite-requests` with `token` and `body`.
    async fn file(&self, token: &str, body: &Value) -> Reply {
        self.call(creq(Method::Post, "/v1/invite-requests", Some(token), body))
            .await
    }
}

/// `r` is `status` with the stable `code`.
#[track_caller]
fn assert_coded(r: &Reply, status: u16, code: &str) {
    assert_eq!(r.status, status, "{r:?}");
    assert_eq!(r.body.as_ref().unwrap()["code"], code, "{r:?}");
}

/// The control root's seal over an invite request row, as the control plane computes it.
async fn request_mac(fx: &Fx, row: &InviteRequestRow) -> Vec<u8> {
    let input = invite_request_mac_input(row.github_id, row.created_ms, &row.login, &row.note);
    fx.control_ops()
        .await
        .mac(MacPurpose::InviteRequest, &input)
        .await
        .unwrap()
        .to_vec()
}

#[wasm_bindgen_test]
async fn create_files_a_verified_pending_request() {
    let fx = fx().await;
    fx.invite_mode().await;
    let login = unique("filer");
    let token = fx.request_token(8_501, &login).await;
    let r = fx
        .file(
            &token,
            &json!({"note": "  CI signing\nfor a small project  "}),
        )
        .await;
    assert_eq!(r.status, 201, "{r:?}");
    let d = &r.body.as_ref().unwrap()["data"];
    assert_eq!(d["status"], "pending");
    assert_eq!(d["created_ms"], NOW * 1000);
    let row = fx.store.invite_request_row(8_501).unwrap();
    assert_eq!(row.login, login);
    assert_eq!(row.note, "CI signing\nfor a small project");
    assert_eq!(row.status, RequestStatus::Pending);
    assert_eq!(row.created_ms, NOW * 1000);
    assert_eq!(row.mac, request_mac(&fx, &row).await);
    // The requester sees it, without the note.
    let r = fx.mine(&token).await;
    let d = data(&r);
    assert_eq!(
        d["request"],
        json!({"status": "pending", "created_ms": NOW * 1000, "decided_ms": null})
    );
    assert!(!r.body.as_ref().unwrap().to_string().contains("CI signing"));
    // No body at all is an empty note.
    let token = fx.request_token(8_502, &unique("silent")).await;
    let r = fx
        .call(craw(
            Method::Post,
            "/v1/invite-requests",
            Some(&token),
            Vec::new(),
        ))
        .await;
    assert_eq!(r.status, 201, "{r:?}");
    assert_eq!(fx.store.invite_request_row(8_502).unwrap().note, "");
    let token = fx.request_token(8_503, &unique("nullnote")).await;
    assert_eq!(fx.file(&token, &json!({"note": null})).await.status, 201);
}

#[wasm_bindgen_test]
async fn second_request_is_already_requested() {
    let fx = fx().await;
    fx.invite_mode().await;
    let login = unique("twice");
    let token = fx.request_token(8_511, &login).await;
    assert_eq!(fx.file(&token, &json!({"note": "one"})).await.status, 201);
    assert_coded(
        &fx.file(&token, &json!({"note": "two"})).await,
        409,
        "already_requested",
    );
    // A fresh sign-in doesn't change that, and the first note stands.
    let again = fx.request_token(8_511, &login).await;
    assert_coded(&fx.file(&again, &json!({})).await, 409, "already_requested");
    assert_eq!(fx.store.invite_request_row(8_511).unwrap().note, "one");
}

#[wasm_bindgen_test]
async fn declined_requester_cannot_ask_again() {
    let fx = fx().await;
    let op = fx.invite_mode().await;
    let login = unique("declinee");
    let token = fx.request_token(8_521, &login).await;
    assert_eq!(fx.file(&token, &json!({})).await.status, 201);
    let row = fx.store.invite_request_row(8_521).unwrap();
    fx.store
        .decide_invite_request(8_521, &row.mac, RequestStatus::Declined, OPERATOR, 5, None)
        .await
        .unwrap();
    let r = fx.mine(&token).await;
    assert_eq!(data(&r)["request"]["status"], "declined");
    assert_eq!(data(&r)["request"]["decided_ms"], 5);
    assert_coded(&fx.file(&token, &json!({})).await, 409, "request_declined");
    // Until an operator deletes the row.
    fx.store.delete_invite_request(8_521).await.unwrap();
    assert_eq!(fx.file(&token, &json!({})).await.status, 201);
    let _ = op;
}

#[wasm_bindgen_test]
async fn admitted_user_gets_already_admitted() {
    let fx = fx().await;
    let (owner, name) = fx.owner(8_531, "admhost").await;
    let op = fx.invite_mode().await;
    // Allowlisted after the refusal.
    let token = fx.request_token(8_532, &unique("listedlater")).await;
    assert_eq!(fx.allow(&op, "8532").await, Reply::no_content());
    assert_coded(&fx.file(&token, &json!({})).await, 409, "already_admitted");
    // Invited to a tenant after the refusal.
    let token = fx.request_token(8_533, &unique("invitedlater")).await;
    assert_eq!(
        fx.set_member(&name, &owner, 8_533, "member").await,
        Reply::no_content()
    );
    assert_coded(&fx.file(&token, &json!({})).await, 409, "already_admitted");
    assert_eq!(fx.store.invite_request_row(8_532), None);
    assert_eq!(fx.store.invite_request_row(8_533), None);
    // An operator, or an existing member, holding a request token minted for them.
    let ops = fx.control_ops().await;
    for (id, login) in [(OPERATOR, "theop"), (8_531, "theowner")] {
        let id_text = id.to_string();
        let t = mint_claims(
            &ops,
            "invite_request",
            &[],
            NOW,
            900,
            false,
            &[("github_id", &id_text), ("login", login)],
        )
        .await;
        assert_coded(&fx.file(&t, &json!({})).await, 409, "already_admitted");
    }
}

#[wasm_bindgen_test]
async fn closed_mode_or_zero_cap_stops_requests() {
    let fx = fx().await;
    fx.invite_mode().await;
    let token = fx.request_token(8_541, &unique("tooslow")).await;
    // Closed after the token was issued: the token still reads, but files nothing.
    set_mode(&fx, SignupMode::Closed);
    assert_eq!(data(&fx.mine(&token).await)["accepting"], false);
    assert_coded(
        &fx.file(&token, &json!({})).await,
        403,
        "invite_requests_closed",
    );
    set_mode(&fx, SignupMode::Open);
    assert_eq!(data(&fx.mine(&token).await)["accepting"], false);
    assert_coded(
        &fx.file(&token, &json!({})).await,
        403,
        "invite_requests_closed",
    );
    // Invite mode with a cap of 0.
    set_mode(&fx, SignupMode::Invite);
    assert_eq!(data(&fx.mine(&token).await)["accepting"], true);
    set_cap(&fx, 0);
    assert_eq!(data(&fx.mine(&token).await)["accepting"], false);
    assert_coded(
        &fx.file(&token, &json!({})).await,
        403,
        "invite_requests_closed",
    );
    assert_eq!(fx.store.invite_request_row(8_541), None);
}

/// Sets the fixture's `MAX_PENDING_INVITE_REQUESTS`.
fn set_cap(fx: &Fx, cap: u64) {
    let mut s = (**fx.settings.borrow()).clone();
    s.max_pending_invite_requests = cap;
    *fx.settings.borrow_mut() = Rc::new(s);
}

#[wasm_bindgen_test]
async fn create_at_the_cap_is_full() {
    let fx = fx().await;
    fx.invite_mode().await;
    set_cap(&fx, 2);
    for id in [8_551, 8_552] {
        let t = fx.request_token(id, &unique("early")).await;
        assert_eq!(fx.file(&t, &json!({})).await.status, 201);
    }
    let t = fx.request_token(8_553, &unique("late")).await;
    assert_coded(&fx.file(&t, &json!({})).await, 503, "invite_requests_full");
    assert_eq!(fx.store.invite_request_row(8_553), None);
    // Room again once one is decided.
    let row = fx.store.invite_request_row(8_551).unwrap();
    fx.store
        .decide_invite_request(8_551, &row.mac, RequestStatus::Declined, OPERATOR, 1, None)
        .await
        .unwrap();
    assert_eq!(fx.file(&t, &json!({})).await.status, 201);
}

#[wasm_bindgen_test]
async fn unverified_row_is_replaced() {
    let fx = fx().await;
    fx.invite_mode().await;
    let login = unique("victim");
    let token = fx.request_token(8_561, &login).await;
    // A D1 writer filed a request in this user's name, with a note of their choosing, and
    // marked it declined so the real user couldn't ask.
    fx.store.forge_invite_request(InviteRequestRow {
        github_id: 8_561,
        login: "famous".into(),
        note: "planted".into(),
        created_ms: 1,
        status: RequestStatus::Declined,
        decided_by: Some(1),
        decided_ms: Some(2),
        mac: vec![0; 32],
    });
    assert_eq!(data(&fx.mine(&token).await)["request"], Value::Null);
    let r = fx.file(&token, &json!({"note": "mine"})).await;
    assert_eq!(r.status, 201, "{r:?}");
    let row = fx.store.invite_request_row(8_561).unwrap();
    assert_eq!(
        (row.login.as_str(), row.note.as_str()),
        (login.as_str(), "mine")
    );
    assert_eq!(row.status, RequestStatus::Pending);
    assert_eq!(row.decided_by, None);
    assert_eq!(row.mac, request_mac(&fx, &row).await);
}

#[wasm_bindgen_test]
async fn note_rules_are_enforced_and_trimmed() {
    let fx = fx().await;
    fx.invite_mode().await;
    let token = fx.request_token(8_571, &unique("noter")).await;
    for (note, rule) in [
        (json!("a\rb"), "control characters"),
        (json!("a\u{1b}[31mb"), "control characters"),
        (json!("a\u{202e}b"), "bidirectional"),
        (json!("x".repeat(501)), "500 characters"),
        (json!("x".repeat(2001)), "2000 bytes"),
        (json!(42), "string"),
        (json!(["a"]), "string"),
    ] {
        let r = fx.file(&token, &json!({ "note": note })).await;
        assert_coded(&r, 400, "note_invalid");
        assert!(errors(&r)[0].contains(rule), "{r:?}");
    }
    assert_eq!(fx.store.invite_request_row(8_571), None);
    let r = fx
        .file(
            &token,
            &json!({"note": format!("\n  {}  \n", "x".repeat(500))}),
        )
        .await;
    assert_eq!(r.status, 201, "{r:?}");
    assert_eq!(
        fx.store.invite_request_row(8_571).unwrap().note,
        "x".repeat(500)
    );
}

#[wasm_bindgen_test]
async fn create_audits_github_id_and_jti_but_never_the_note() {
    let fx = fx().await;
    fx.invite_mode().await;
    let token = fx.request_token(8_581, &unique("audited")).await;
    let jti = fx.audit.values().last().unwrap()["jti"]
        .as_str()
        .unwrap()
        .to_owned();
    fx.audit.clear();
    let note = "a distinctive note 7f3a";
    assert_eq!(fx.file(&token, &json!({ "note": note })).await.status, 201);
    let ev = fx.audit.values();
    assert_eq!(ev.len(), 2, "{ev:?}");
    for (e, result) in ev.iter().zip(["attempt", "ok"]) {
        assert_eq!(e["op"], "invite_request_create");
        assert_eq!(e["result"], result);
        assert_eq!(e["github_id"], 8_581);
        assert_eq!(e["jti"], json!(jti));
    }
    // A refusal is durable too, and none of it carries the note or the token.
    fx.file(&token, &json!({ "note": note })).await;
    assert_eq!(
        fx.audit.values().last().unwrap()["error"],
        "already_requested"
    );
    let bad = fx.file(&token, &json!({ "note": "bad\u{1b} 7f3a" })).await;
    assert_eq!(bad.status, 400);
    assert!(
        fx.audit
            .events
            .borrow()
            .iter()
            .chain(fx.audit.metrics.borrow().iter())
            .all(|e| !e.contains("7f3a") && !e.contains(&token))
    );
}

#[wasm_bindgen_test]
async fn mine_reports_each_state() {
    let fx = fx().await;
    fx.invite_mode().await;
    let token = fx.request_token(8_591, &unique("watcher")).await;
    let r = fx.mine(&token).await;
    assert_eq!(data(&r)["request"], Value::Null);
    assert_eq!(data(&r)["accepting"], true);
    assert_eq!(fx.file(&token, &json!({})).await.status, 201);
    assert_eq!(data(&fx.mine(&token).await)["request"]["status"], "pending");
    let row = fx.store.invite_request_row(8_591).unwrap();
    fx.store
        .decide_invite_request(8_591, &row.mac, RequestStatus::Approved, OPERATOR, 9, None)
        .await
        .unwrap();
    let r = fx.mine(&token).await;
    assert_eq!(
        data(&r)["request"],
        json!({"status": "approved", "created_ms": NOW * 1000, "decided_ms": 9})
    );
    // Reads are metrics only.
    fx.audit.clear();
    fx.mine(&token).await;
    assert_eq!(fx.audit.only_metric()["op"], "invite_request_mine");
    // A row someone else's token can't see: each token reads only its own user's row.
    let other = fx.request_token(8_592, &unique("nosy")).await;
    assert_eq!(data(&fx.mine(&other).await)["request"], Value::Null);
    assert_eq!(data(&fx.mine(&other).await)["github_id"], 8_592);
}

impl Fx {
    /// `GET /v1/ops/invite-requests` as `token`.
    async fn requests(&self, token: &str) -> Reply {
        self.get("/v1/ops/invite-requests", token).await
    }

    /// `POST /v1/ops/invite-requests/:id/<action>` (`approve` or `decline`) as `token`.
    async fn decide(&self, token: &str, id: u64, action: &str) -> Reply {
        self.call(creq(
            Method::Post,
            &format!("/v1/ops/invite-requests/{id}/{action}"),
            Some(token),
            &json!({}),
        ))
        .await
    }

    /// `DELETE /v1/ops/invite-requests/:id` as `token`.
    async fn delete_request(&self, token: &str, id: &str) -> Reply {
        self.call(craw(
            Method::Delete,
            &format!("/v1/ops/invite-requests/{id}"),
            Some(token),
            Vec::new(),
        ))
        .await
    }

    /// GitHub user `id` is refused and files a request with `note`; returns their login.
    async fn filed(&self, id: u64, base: &str, note: &str) -> String {
        let login = unique(base);
        let token = self.request_token(id, &login).await;
        let r = self.file(&token, &json!({ "note": note })).await;
        assert_eq!(r.status, 201, "{r:?}");
        login
    }
}

/// A verified invite request row as the control plane would have written it.
async fn sealed_request(
    fx: &Fx,
    id: u64,
    created_ms: u64,
    status: RequestStatus,
    decided_ms: Option<u64>,
) -> InviteRequestRow {
    let mut row = InviteRequestRow {
        github_id: id,
        login: format!("u{id}"),
        note: String::new(),
        created_ms,
        status,
        decided_by: decided_ms.map(|_| OPERATOR),
        decided_ms,
        mac: Vec::new(),
    };
    row.mac = request_mac(fx, &row).await;
    row
}

#[wasm_bindgen_test]
async fn invite_request_routes_are_for_operators() {
    let fx = fx().await;
    let (user, _) = fx.owner(8_601, "notop").await;
    fx.invite_mode().await;
    fx.filed(8_602, "pendingone", "hello").await;
    assert_error(&fx.requests(&user).await, 403, "permission denied");
    for action in ["approve", "decline"] {
        assert_error(
            &fx.decide(&user, 8_602, action).await,
            403,
            "permission denied",
        );
    }
    assert_error(
        &fx.delete_request(&user, "8602").await,
        403,
        "permission denied",
    );
    let row = fx.store.invite_request_row(8_602).unwrap();
    assert_eq!(row.status, RequestStatus::Pending);
    assert_eq!(fx.store.allow_row(8_602), None);
    // A request token is no operator either.
    let token = fx.request_token(8_603, &unique("reqnotop")).await;
    let r = fx.requests(&token).await;
    assert_eq!(r.body.as_ref().unwrap()["code"], "auth_failed", "{r:?}");
}

#[wasm_bindgen_test]
async fn list_orders_pending_then_decided_and_names_unverified() {
    let fx = fx().await;
    let op = fx.invite_mode().await;
    fx.now.set(NOW + 20);
    let late = fx.filed(8_611, "late", "second in line").await;
    fx.now.set(NOW + 10);
    let early = fx
        .filed(8_612, "early", "first in line\nwith two lines")
        .await;
    fx.now.set(NOW + 30);
    fx.filed(8_613, "decided", "").await;
    assert_eq!(fx.decide(&op, 8_613, "decline").await, Reply::no_content());
    fx.store.forge_invite_request(InviteRequestRow {
        github_id: 8_614,
        login: "planted".into(),
        note: "approve me".into(),
        created_ms: 1,
        status: RequestStatus::Pending,
        decided_by: None,
        decided_ms: None,
        mac: vec![0; 32],
    });
    let r = fx.requests(&op).await;
    let d = data(&r);
    assert_eq!(d["pending"], 2);
    assert_eq!(d["unverified"], json!([8_614]));
    let list = d["requests"].as_array().unwrap();
    assert_eq!(
        list.iter()
            .map(|r| r["github_id"].clone())
            .collect::<Vec<_>>(),
        [json!(8_612), json!(8_611), json!(8_613)]
    );
    assert_eq!(
        list[0],
        json!({
            "github_id": 8_612, "login": early, "note": "first in line\nwith two lines",
            "created_ms": (NOW + 10) * 1000, "status": "pending",
            "decided_by": null, "decided_ms": null,
        })
    );
    assert_eq!(list[1]["login"], json!(late));
    assert_eq!(list[2]["status"], "declined");
    assert_eq!(list[2]["decided_by"], OPERATOR);
    assert_eq!(list[2]["decided_ms"], (NOW + 30) * 1000);
    // A read: a metric only.
    fx.audit.clear();
    fx.requests(&op).await;
    assert_eq!(fx.audit.only_metric()["op"], "invite_request_list");
    // At most the 100 most recently decided rows follow the pending ones.
    for i in 0..105_u64 {
        let decided = (NOW + 100) * 1000 + i;
        let row = sealed_request(
            &fx,
            9_000_000 + i,
            1,
            RequestStatus::Approved,
            Some(decided),
        )
        .await;
        fx.store.forge_invite_request(row);
    }
    let r = fx.requests(&op).await;
    let list = data(&r)["requests"].as_array().unwrap().clone();
    assert_eq!(list.len(), 2 + 100);
    assert_eq!(list[2]["github_id"], 9_000_104);
    assert_eq!(list[101]["github_id"], 9_000_005);
}

#[wasm_bindgen_test]
async fn approve_allowlists_and_the_next_login_creates_the_tenant() {
    let fx = fx().await;
    let op = fx.invite_mode().await;
    let login = fx.filed(8_621, "approvee", "please").await;
    fx.now.set(NOW + 60);
    fx.audit.clear();
    assert_eq!(fx.decide(&op, 8_621, "approve").await, Reply::no_content());
    let row = fx.store.invite_request_row(8_621).unwrap();
    assert_eq!(row.status, RequestStatus::Approved);
    assert_eq!(row.decided_by, Some(OPERATOR));
    assert_eq!(row.decided_ms, Some((NOW + 60) * 1000));
    let allow = fx.store.allow_row(8_621).unwrap();
    assert_eq!(
        (allow.added_by, allow.added_ms),
        (OPERATOR, (NOW + 60) * 1000)
    );
    let ev = fx.audit.values();
    assert_eq!(ev.len(), 2, "{ev:?}");
    for (e, result) in ev.iter().zip(["attempt", "ok"]) {
        assert_eq!(e["op"], "invite_request_approve");
        assert_eq!(e["result"], result);
        assert_eq!(e["target_github_id"], 8_621);
        assert!(!e.to_string().contains("please"));
    }
    // The allowlist lists them as the allowlist PUT would.
    let r = fx.get("/v1/ops/allowlist", &op).await;
    assert!(
        data(&r)["allowlist"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["github_id"] == 8_621)
    );
    // Their next sign-in creates their personal tenant.
    let r = fx.login_reply(8_621, &login).await;
    assert_eq!(data(&r)["created_tenant"], json!(login));
}

#[wasm_bindgen_test]
async fn approving_twice_is_not_pending() {
    let fx = fx().await;
    let op = fx.invite_mode().await;
    fx.filed(8_631, "twiceapproved", "").await;
    assert_eq!(fx.decide(&op, 8_631, "approve").await, Reply::no_content());
    // Take them off the allowlist: a second approval mustn't put them back.
    assert_eq!(fx.disallow(&op, "8631").await, Reply::no_content());
    for action in ["approve", "decline"] {
        assert_coded(
            &fx.decide(&op, 8_631, action).await,
            409,
            "request_not_pending",
        );
    }
    assert_eq!(fx.store.allow_row(8_631), None);
    assert_eq!(
        fx.store.invite_request_row(8_631).unwrap().status,
        RequestStatus::Approved
    );
    assert_coded(
        &fx.decide(&op, 8_639, "approve").await,
        404,
        "request_not_found",
    );
}

#[wasm_bindgen_test]
async fn approving_an_unverified_row_is_refused_and_writes_nothing() {
    let fx = fx().await;
    let op = fx.invite_mode().await;
    // A real request, then its login rewritten in D1 to someone famous.
    fx.filed(8_641, "realone", "").await;
    let mut row = fx.store.invite_request_row(8_641).unwrap();
    row.login = "torvalds".into();
    fx.store.forge_invite_request(row);
    for action in ["approve", "decline"] {
        assert_coded(
            &fx.decide(&op, 8_641, action).await,
            409,
            "request_unverified",
        );
    }
    assert_eq!(fx.store.allow_row(8_641), None);
    assert_eq!(
        fx.store.invite_request_row(8_641).unwrap().status,
        RequestStatus::Pending
    );
}

#[wasm_bindgen_test]
async fn approve_of_a_changed_row_writes_nothing() {
    let fx = fx().await;
    let op = fx.invite_mode().await;
    // Rewritten between the read and the decision.
    fx.filed(8_651, "raced", "").await;
    fx.store.on_next_decide(|r| r.mac[0] ^= 1);
    assert_coded(
        &fx.decide(&op, 8_651, "approve").await,
        409,
        "request_not_pending",
    );
    assert_eq!(fx.store.allow_row(8_651), None);
    // Decided by another operator between the read and the decision.
    fx.filed(8_652, "raced", "").await;
    fx.store.on_next_decide(|r| {
        r.status = RequestStatus::Declined;
        r.decided_by = Some(1);
        r.decided_ms = Some(1);
    });
    assert_coded(
        &fx.decide(&op, 8_652, "approve").await,
        409,
        "request_not_pending",
    );
    assert_eq!(fx.store.allow_row(8_652), None);
    assert_eq!(
        fx.store.invite_request_row(8_652).unwrap().status,
        RequestStatus::Declined
    );
}

#[wasm_bindgen_test]
async fn decline_marks_declined_without_allowlisting() {
    let fx = fx().await;
    let op = fx.invite_mode().await;
    fx.filed(8_661, "declined", "").await;
    fx.audit.clear();
    assert_eq!(fx.decide(&op, 8_661, "decline").await, Reply::no_content());
    let row = fx.store.invite_request_row(8_661).unwrap();
    assert_eq!(row.status, RequestStatus::Declined);
    assert_eq!(row.decided_by, Some(OPERATOR));
    assert_eq!(fx.store.allow_row(8_661), None);
    let ev = fx.audit.values();
    assert_eq!(ev.last().unwrap()["op"], "invite_request_decline");
    assert_eq!(ev.last().unwrap()["target_github_id"], 8_661);
    // Their next sign-in is still refused.
    assert_signup_closed(&fx.login_reply(8_661, &unique("declined")).await);
}

#[wasm_bindgen_test]
async fn delete_removes_any_status_and_404s_after() {
    let fx = fx().await;
    let op = fx.invite_mode().await;
    fx.filed(8_671, "delpending", "").await;
    fx.filed(8_672, "delapproved", "").await;
    fx.filed(8_673, "deldeclined", "").await;
    assert_eq!(fx.decide(&op, 8_672, "approve").await, Reply::no_content());
    assert_eq!(fx.decide(&op, 8_673, "decline").await, Reply::no_content());
    fx.store.forge_invite_request(InviteRequestRow {
        github_id: 8_674,
        login: "x".into(),
        note: String::new(),
        created_ms: 1,
        status: RequestStatus::Pending,
        decided_by: None,
        decided_ms: None,
        mac: vec![1; 32],
    });
    fx.audit.clear();
    for id in [8_671, 8_672, 8_673, 8_674] {
        let r = fx.delete_request(&op, &id.to_string()).await;
        assert_eq!(r, Reply::no_content());
        assert_eq!(fx.store.invite_request_row(id), None);
    }
    assert_eq!(
        fx.audit.values().last().unwrap()["op"],
        "invite_request_delete"
    );
    assert_eq!(fx.audit.values().last().unwrap()["target_github_id"], 8_674);
    // Deleting an approved request leaves the allowlist alone.
    assert!(fx.store.allow_row(8_672).is_some());
    assert_coded(
        &fx.delete_request(&op, "8671").await,
        404,
        "request_not_found",
    );
    assert_error(
        &fx.delete_request(&op, "abc").await,
        400,
        "github_id must be a positive integer",
    );
    // A deleted declined request lets its user file again.
    let token = fx.request_token(8_673, &unique("again")).await;
    assert_eq!(fx.file(&token, &json!({})).await.status, 201);
}
