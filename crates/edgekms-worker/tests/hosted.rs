#![cfg(target_arch = "wasm32")]
#![allow(clippy::unused_async_trait_impl)] // test doubles satisfy async traits without awaiting
//! The hosted data plane: mode selection, Host dispatch and tenant isolation through the real
//! handler functions, with two tenants from different roots behind one in-memory tenant store,
//! one revocation store, one audit sink and one set of limiters.
//!
//! The binding-backed path (`fetch` reading D1, KV, R2 and the rate limiters) only runs under
//! workerd; `scripts/e2e-hosted.sh` covers it.

mod common;

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};

use common::memstore::MemStore;
use common::*;
use edgekms_core::hosted::config_mac_input;
use edgekms_core::keyops::{KeyOps, MacPurpose};
use edgekms_core::tenant::TenantName;
use edgekms_core::transit::Id;
use edgekms_worker::audit::{Limit, RateLimit};
use edgekms_worker::auth::{KvRevocations, RevocationStore, Revocations};
use edgekms_worker::github::{NoGithub, api_base};
use edgekms_worker::handlers::ApiRequest;
use edgekms_worker::master::{MasterAdmin, MasterUnwrap};
use edgekms_worker::state::{Mode, ModeVars, mode, mode_from};
use edgekms_worker::store::{TenantRow, TenantStatus, TenantStore};
use edgekms_worker::vault::Reply;
use edgekms_worker::webcrypto::WebCryptoKeyOps;
use edgekms_worker::{HostDispatch, TenantDeps, dispatch_host, serve_tenant};
use serde_json::{Value, json};
use wasm_bindgen::JsValue;
use wasm_bindgen_test::wasm_bindgen_test;
use worker::Method;

const APEX: &str = "edge.km";
const TEMPLATE: &str = "https://{tenant}.edge.km";
const CLIENT: &str = "Iv_hosted_test";
const OWNER: u64 = 4242;
const M1: [u8; 32] = [0x11; 32];

/// The per-IP limiters count a request's limit key, not its raw IP.
#[wasm_bindgen_test]
async fn per_ip_limits_count_the_limit_key() {
    let h = Harness::new().await;
    let mut login = req(Method::Put, "/v1/auth/ssh/login", None, &json!({}));
    login.limit_key = Some("cfw:zone.example|104.16.0.1".to_owned());
    h.call(login).await;
    let checks = h.limits.checks.borrow();
    assert_eq!(checks.len(), 1, "{checks:?}");
    assert_eq!(checks[0].1, "cfw:zone.example|104.16.0.1");
}

// ---- Mode and Host dispatch ----

fn hosted_vars() -> ModeVars<'static> {
    ModeVars {
        hosted_apex: Some(APEX),
        origin_template: Some(TEMPLATE),
        github_api_base: None,
        single_tenant_bound: false,
        plain_master_bound: false,
    }
}

#[wasm_bindgen_test]
fn hosted_with_root_key_is_refused() {
    let vars = ModeVars {
        single_tenant_bound: true,
        ..hosted_vars()
    };
    assert_eq!(mode_from(&vars), Err("hosted_and_single_tenant_bindings"));
}

#[wasm_bindgen_test]
fn no_apex_is_single_tenant() {
    let vars = ModeVars {
        hosted_apex: None,
        ..hosted_vars()
    };
    assert_eq!(mode_from(&vars), Ok(Mode::SingleTenant));
    // Today's deployments: EDGEKMS_CONFIG and ROOT_KEY bound, nothing hosted. A stray
    // GITHUB_API_BASE is ignored there, as it always was.
    let vars = ModeVars {
        hosted_apex: None,
        origin_template: None,
        github_api_base: Some("http://127.0.0.1:9999"),
        single_tenant_bound: true,
        plain_master_bound: false,
    };
    assert_eq!(mode_from(&vars), Ok(Mode::SingleTenant));
}

#[wasm_bindgen_test]
fn hosted_mode_names_the_apex_and_origin_template() {
    assert_eq!(
        mode_from(&hosted_vars()),
        Ok(Mode::Hosted {
            apex: APEX.to_owned(),
            origin_template: TEMPLATE.to_owned(),
        })
    );
}

#[wasm_bindgen_test]
fn hosted_without_a_usable_origin_template_is_refused() {
    for (template, want) in [
        (None, "hosted_origin_template_missing"),
        (Some("https://edge.km"), "hosted_origin_template_invalid"),
        (
            Some("https://{tenant}.{tenant}.edge.km"),
            "hosted_origin_template_invalid",
        ),
    ] {
        let vars = ModeVars {
            origin_template: template,
            ..hosted_vars()
        };
        assert_eq!(mode_from(&vars), Err(want), "{template:?}");
    }
    let vars = ModeVars {
        hosted_apex: Some(" "),
        ..hosted_vars()
    };
    assert_eq!(mode_from(&vars), Err("hosted_apex_invalid"));
}

/// An `Env` holding `vars` as plain string bindings, as `wrangler` vars and secrets arrive.
fn env_with(vars: &[(&str, &str)]) -> worker::Env {
    let env = empty_env();
    for (k, v) in vars {
        js_sys::Reflect::set(&env, &JsValue::from_str(k), &JsValue::from_str(v)).unwrap();
    }
    env
}

#[wasm_bindgen_test]
fn mode_reads_the_bindings() {
    assert_eq!(mode(&empty_env()), Ok(Mode::SingleTenant));
    assert_eq!(
        mode(&env_with(&[("EDGEKMS_CONFIG", "{}"), ("ROOT_KEY", "x")])),
        Ok(Mode::SingleTenant)
    );
    let hosted = [("HOSTED_APEX", APEX), ("HOSTED_ORIGIN_TEMPLATE", TEMPLATE)];
    assert!(matches!(mode(&env_with(&hosted)), Ok(Mode::Hosted { .. })));
    for extra in ["EDGEKMS_CONFIG", "ROOT_KEY"] {
        let mut vars = hosted.to_vec();
        vars.push((extra, "anything"));
        assert_eq!(
            mode(&env_with(&vars)),
            Err("hosted_and_single_tenant_bindings"),
            "{extra}"
        );
    }
    let mut vars = hosted.to_vec();
    vars.push(("GITHUB_API_BASE", "http://127.0.0.1:9999"));
    assert_eq!(mode(&env_with(&vars)), Err("github_api_base_refused"));
}

/// A `MASTER_KEY_M<n>` that is a plain secret or var (`wrangler secret put MASTER_KEY_M7`) would
/// add an unwrap-capable master outside the Secrets Store ceremony, so off `localhost` the
/// Worker refuses every request, as it does a stray `ROOT_KEY`.
#[wasm_bindgen_test]
fn plain_master_key_binding_is_refused_off_localhost() {
    let vars = ModeVars {
        plain_master_bound: true,
        ..hosted_vars()
    };
    assert_eq!(mode_from(&vars), Err("master_key_not_in_secrets_store"));
    let vars = ModeVars {
        hosted_apex: Some("localhost"),
        origin_template: Some("http://{tenant}.localhost:8787"),
        plain_master_bound: true,
        ..hosted_vars()
    };
    assert!(matches!(mode_from(&vars), Ok(Mode::Hosted { .. })));

    let hosted = [("HOSTED_APEX", APEX), ("HOSTED_ORIGIN_TEMPLATE", TEMPLATE)];
    let mut vars = hosted.to_vec();
    vars.push(("MASTER_KEY_M7", "AAAA"));
    assert_eq!(
        mode(&env_with(&vars)),
        Err("master_key_not_in_secrets_store")
    );
    // A Secrets Store binding (workers-rs knows one by its `Fetcher` constructor) is fine, and
    // so are the version-naming vars.
    let env = env_with(&[
        ("HOSTED_APEX", APEX),
        ("HOSTED_ORIGIN_TEMPLATE", TEMPLATE),
        ("MASTER_KEY_CURRENT", "m7"),
        ("MASTER_KEY_PREVIOUS", "m6"),
    ]);
    let store = js_sys::Function::new_with_args("", "class Fetcher {}; return new Fetcher();")
        .call0(&JsValue::NULL)
        .unwrap();
    js_sys::Reflect::set(&env, &"MASTER_KEY_M7".into(), &store).unwrap();
    assert!(matches!(mode(&env), Ok(Mode::Hosted { .. })));
    // Single-tenant Workers have no master keys to protect.
    assert_eq!(
        mode(&env_with(&[("MASTER_KEY_M7", "AAAA")])),
        Ok(Mode::SingleTenant)
    );
}

#[wasm_bindgen_test]
fn reserved_and_foreign_hosts_are_bare_404() {
    for host in [
        "www.edge.km",
        "admin.edge.km",
        "edge.km",
        "a.b.edge.km",
        "acme.edge.km.evil.com",
        "evil-edge.km",
        "xn--80ak6aa92e.edge.km",
        "",
    ] {
        assert_eq!(dispatch_host(APEX, host), HostDispatch::NotFound, "{host}");
    }
}

#[wasm_bindgen_test]
fn api_host_goes_to_control() {
    for host in [
        "api.edge.km",
        "API.EDGE.KM",
        "api.edge.km:443",
        "api.edge.km.",
    ] {
        assert_eq!(dispatch_host(APEX, host), HostDispatch::Control, "{host}");
    }
}

#[wasm_bindgen_test]
fn app_host_goes_to_the_console() {
    for host in [
        "app.edge.km",
        "APP.EDGE.KM",
        "app.edge.km:443",
        "app.edge.km.",
    ] {
        assert_eq!(dispatch_host(APEX, host), HostDispatch::Console, "{host}");
    }
    assert_eq!(
        dispatch_host("edgekms.dev", "app.edgekms.dev"),
        HostDispatch::Console
    );
    assert_eq!(
        dispatch_host("localhost", "app.localhost:8787"),
        HostDispatch::Console
    );
    // Only exactly `app.<apex>`: never a tenant's host or a deeper name.
    for host in ["app.acme.edge.km", "acme.app.edge.km", "apps.edge.km"] {
        assert_ne!(dispatch_host(APEX, host), HostDispatch::Console, "{host}");
    }
}

#[wasm_bindgen_test]
fn tenant_hosts_name_the_tenant() {
    assert_eq!(
        dispatch_host(APEX, "Acme.edge.km:443"),
        HostDispatch::Tenant(TenantName::new("acme").unwrap())
    );
    assert_eq!(
        dispatch_host("localhost", "alice.localhost:8787"),
        HostDispatch::Tenant(TenantName::new("alice").unwrap())
    );
}

#[wasm_bindgen_test]
fn github_api_base_override_needs_localhost_apex() {
    let github = "https://api.github.com";
    assert_eq!(api_base(None, None), Ok(github.to_owned()));
    assert_eq!(api_base(Some(APEX), None), Ok(github.to_owned()));
    // Single-tenant mode ignores the var, as it always has.
    assert_eq!(
        api_base(None, Some("http://127.0.0.1:9")),
        Ok(github.to_owned())
    );
    assert_eq!(
        api_base(Some("localhost"), Some("http://127.0.0.1:9/")),
        Ok("http://127.0.0.1:9".to_owned())
    );
    assert_eq!(
        api_base(Some(APEX), Some("http://127.0.0.1:9")),
        Err("github_api_base_refused")
    );
    assert_eq!(
        api_base(Some("localhost"), Some("ftp://127.0.0.1")),
        Err("github_api_base_refused")
    );
}

// ---- Tenant isolation ----

thread_local! {
    static NEXT: Cell<u64> = const { Cell::new(1) };
}

/// A fresh number, so every test's tenants have names of their own in the shared per-isolate
/// tenant cache.
fn next() -> u64 {
    NEXT.with(|n| {
        let v = n.get();
        n.set(v + 1);
        v
    })
}

/// A revocation store shared by every tenant, as the hosted Worker's one KV namespace is.
#[derive(Default)]
struct MemKv(RefCell<HashMap<String, u64>>);

impl RevocationStore for MemKv {
    async fn exists(&self, key: &str) -> worker::Result<bool> {
        Ok(self.0.borrow().contains_key(key))
    }
    async fn put(&self, key: &str, ttl_secs: u64) -> worker::Result<()> {
        self.0.borrow_mut().insert(key.to_owned(), ttl_secs);
        Ok(())
    }
}

/// Allows everything except the `(limit, key)` pairs in `deny`; records every check.
#[derive(Default)]
struct KeyedLimits {
    deny: RefCell<HashSet<(String, String)>>,
    checks: RefCell<Vec<(Limit, String)>>,
}

impl KeyedLimits {
    fn deny(&self, limit: Limit, key: &str) {
        self.deny
            .borrow_mut()
            .insert((format!("{limit:?}"), key.to_owned()));
    }
}

impl RateLimit for KeyedLimits {
    async fn allow(&self, limit: Limit, key: &str) -> bool {
        self.checks.borrow_mut().push((limit, key.to_owned()));
        !self
            .deny
            .borrow()
            .contains(&(format!("{limit:?}"), key.to_owned()))
    }
}

/// A JWKS source that is never reached: no test here logs in through a `jwks_url` mount.
struct NoJwks;

impl edgekms_worker::jwks::JwksSource for NoJwks {
    async fn jwks(&self, _: &str, _: &str, _: bool) -> worker::Result<edgekms_core::jwt::Jwks> {
        Err(worker::Error::RustError("no JWKS in these tests".into()))
    }
}

/// One hosted Worker: a tenant store, the master key, and one of each shared binding.
struct World {
    store: MemStore,
    admin: MasterAdmin,
    master: MasterUnwrap,
    kv: MemKv,
    audit: MemAudit,
    limits: KeyedLimits,
}

/// A tenant as the control plane creates one, with the test config (every mount, role and
/// policy of `common::config_json`) under a root of its own.
struct Tenant {
    name: String,
    id: String,
    ops: WebCryptoKeyOps,
}

impl World {
    async fn new() -> Self {
        let store = MemStore::default();
        store.upsert_user(OWNER, "owner", NOW * 1000).await.unwrap();
        Self {
            store,
            admin: MasterAdmin::from_bytes("m1", &[("m1", &M1)]).await.unwrap(),
            master: MasterUnwrap::from_bytes(&[("m1", &M1)]).await.unwrap(),
            kv: MemKv::default(),
            audit: MemAudit::default(),
            limits: KeyedLimits::default(),
        }
    }

    async fn tenant(&self, prefix: &str) -> Tenant {
        self.tenant_with(prefix, |_| {}).await
    }

    /// As [`World::tenant`], with `edit` applied to the config first.
    async fn tenant_with(&self, prefix: &str, edit: impl FnOnce(&mut Value)) -> Tenant {
        let n = next();
        let name = format!("{prefix}-{n}");
        let id = format!("t_{:016x}", 0xf000 + n);
        let root_id = Id::new(&format!("r_{:016x}", 0xf000 + n)).unwrap();
        let (handle, wrapped) = self.admin.new_root(&id, &root_id).await.unwrap();
        let ops = WebCryptoKeyOps::from_hkdf_key(handle, root_id.clone()).unwrap();
        let mut config = config_json();
        config["root_id"] = json!(root_id.as_str());
        edit(&mut config);
        let config = config.to_string();
        let mac = ops
            .mac(
                MacPurpose::Config,
                &config_mac_input(&id, &name, 1, &config),
            )
            .await
            .unwrap()
            .to_vec();
        self.store
            .create_tenant(
                &TenantRow {
                    id: id.clone(),
                    name: name.clone(),
                    root_id: root_id.as_str().to_owned(),
                    wrapped_root: wrapped,
                    wrap_key: "m1".into(),
                    config,
                    config_version: 1,
                    config_mac: mac,
                    status: TenantStatus::Active,
                },
                OWNER,
                NOW * 1000,
                &[0xaa; 32],
            )
            .await
            .unwrap();
        Tenant { name, id, ops }
    }

    fn deps(&self) -> TenantDeps<'_, MemStore, MemKv, NoJwks, MemAudit, KeyedLimits> {
        TenantDeps {
            store: &self.store,
            master: &self.master,
            origin_template: TEMPLATE,
            github_client_id: CLIENT,
            revoked: &self.kv,
            jwks: &NoJwks,
            audit: &self.audit,
            limits: &self.limits,
            github: &NoGithub,
            now_ms: NOW * 1000,
        }
    }

    /// Sends `req` to the tenant named `name`, as `fetch` does after routing its Host.
    async fn send(&self, name: &str, mut req: ApiRequest) -> Reply {
        req.origin = format!("https://{name}.edge.km");
        req.host = format!("{name}.edge.km");
        serve_tenant(&self.deps(), &TenantName::new(name).unwrap(), &req).await
    }

    async fn challenge(&self, t: &Tenant) -> String {
        let r = self
            .send(
                &t.name,
                req(Method::Post, "/v1/auth/ssh/challenge", None, &json!({})),
            )
            .await;
        data(&r)["challenge"].as_str().unwrap().to_owned()
    }

    async fn ssh_login(&self, at: &Tenant, challenge: &str) -> Reply {
        let signature = ssh_test_key()
            .sign("edgekms", ssh_key::HashAlg::Sha512, challenge.as_bytes())
            .unwrap()
            .to_pem(ssh_key::LineEnding::LF)
            .unwrap();
        self.send(
            &at.name,
            req(
                Method::Put,
                "/v1/auth/ssh/login",
                None,
                &json!({ "role": "op", "challenge": challenge, "signature": signature }),
            ),
        )
        .await
    }

    /// An `op` (admin) token at `t`, through a real SSH login there.
    async fn admin_token(&self, t: &Tenant) -> String {
        let c = self.challenge(t).await;
        let r = self.ssh_login(t, &c).await;
        assert_eq!(r.status, 200, "{r:?}");
        r.body.as_ref().unwrap()["auth"]["client_token"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    async fn encrypt(&self, at: &Tenant, token: &str) -> Reply {
        self.send(
            &at.name,
            req(
                Method::Put,
                "/v1/transit/encrypt/app",
                Some(token),
                &json!({ "plaintext": b64(b"tenant data") }),
            ),
        )
        .await
    }

    /// The last durable audit event.
    fn last_event(&self) -> Value {
        self.audit.values().pop().expect("an audit event")
    }
}

#[wasm_bindgen_test]
async fn token_from_tenant_a_is_refused_at_b() {
    let w = World::new().await;
    let (a, b) = (w.tenant("ta").await, w.tenant("tb").await);
    let tok = w.admin_token(&a).await;
    assert_eq!(w.encrypt(&a, &tok).await.status, 200);
    assert_eq!(w.last_event()["tenant"], json!(a.id));

    // The same role names exist at B; only the root tells the two apart.
    let r = w.encrypt(&b, &tok).await;
    assert_error(&r, 403, "permission denied");
    let ev = w.last_event();
    assert_eq!(ev["tenant"], json!(b.id));
    assert_eq!(ev["error"], "invalid_token");
}

#[wasm_bindgen_test]
async fn ssh_challenge_from_a_is_refused_at_b() {
    let w = World::new().await;
    let (a, b) = (w.tenant("ca").await, w.tenant("cb").await);
    let minted = w.challenge(&a).await;
    let reply = w.ssh_login(&b, &minted).await;
    assert_error(&reply, 400, "permission denied");
    assert_eq!(w.last_event()["tenant"], json!(b.id));
    // The same signed challenge still works where it was minted.
    assert_eq!(w.ssh_login(&a, &minted).await.status, 200);
}

#[wasm_bindgen_test]
async fn revoking_at_a_does_not_touch_b() {
    let w = World::new().await;
    let (a, b) = (w.tenant("ra").await, w.tenant("rb").await);
    let (admin_a, admin_b) = (w.admin_token(&a).await, w.admin_token(&b).await);

    // A long token created at B.
    let r = w
        .send(
            &b.name,
            req(
                Method::Post,
                "/v1/auth/token/create",
                Some(&admin_b),
                &json!({ "policies": ["app-all"], "ttl": "8760h" }),
            ),
        )
        .await;
    let created = r.body.as_ref().unwrap()["auth"].clone();
    let tok_b = created["client_token"].as_str().unwrap().to_owned();
    let accessor = created["accessor"].as_str().unwrap().to_owned();
    assert_eq!(w.encrypt(&b, &tok_b).await.status, 200);

    // A's admin revokes B's accessor: it lands in A's list only.
    let revoke = |token: &str| {
        req(
            Method::Put,
            "/v1/auth/token/revoke-accessor",
            Some(token),
            &json!({ "accessor": accessor }),
        )
    };
    assert_eq!(w.send(&a.name, revoke(&admin_a)).await.status, 204);
    assert!(
        w.kv.0
            .borrow()
            .contains_key(&format!("revoked:{}:{accessor}", a.id))
    );
    assert_eq!(
        w.encrypt(&b, &tok_b).await.status,
        200,
        "B's token survives"
    );

    // B's own admin revokes it, and then it's refused at B.
    assert_eq!(w.send(&b.name, revoke(&admin_b)).await.status, 204);
    assert_error(&w.encrypt(&b, &tok_b).await, 403, "permission denied");
    assert_eq!(w.last_event()["error"], "token_revoked");
}

#[wasm_bindgen_test]
async fn revocation_keys_are_prefixed_by_tenant() {
    let kv = MemKv::default();
    let single = KvRevocations::single_tenant(&kv);
    let a = KvRevocations::for_tenant(&kv, "t_a");
    let b = KvRevocations::for_tenant(&kv, "t_b");
    // Self-hosted deployments keep today's layout.
    assert_eq!(single.key("jti1"), "revoked:jti1");
    assert_eq!(a.key("jti1"), "revoked:t_a:jti1");

    a.revoke("jti1", 60).await.unwrap();
    assert!(a.is_revoked("jti1").await.unwrap());
    assert!(!b.is_revoked("jti1").await.unwrap());
    assert!(!single.is_revoked("jti1").await.unwrap());
}

#[wasm_bindgen_test]
async fn audit_events_carry_the_tenant() {
    let w = World::new().await;
    let a = w.tenant("aa").await;
    let tok = w.admin_token(&a).await;
    w.audit.clear();
    w.encrypt(&a, &tok).await;
    let (ev, _) = w.audit.only();
    assert_eq!(ev["tenant"], json!(a.id));
    assert_eq!(ev["op"], "encrypt");
    let metrics = w.audit.metrics.borrow();
    let metric: Value = serde_json::from_str(&metrics[0]).unwrap();
    assert_eq!(metric["tenant"], json!(a.id));
}

#[wasm_bindgen_test]
async fn tenant_limit_429_is_metric_only() {
    let w = World::new().await;
    let (a, b) = (w.tenant("la").await, w.tenant("lb").await);
    let tok_a = w.admin_token(&a).await;
    let tok_b = w.admin_token(&b).await;
    w.limits.deny(Limit::Tenant, &a.id);
    w.audit.clear();

    let r = w.encrypt(&a, &tok_a).await;
    assert_error(
        &r,
        429,
        "request path \"transit/encrypt/app\": rate limit quota exceeded",
    );
    let ev = w.audit.only_metric();
    assert_eq!(ev["error"], "rate_limited");
    assert_eq!(ev["tenant"], json!(a.id));

    // B's budget is its own.
    assert_eq!(w.encrypt(&b, &tok_b).await.status, 200);
    let checks = w.limits.checks.borrow();
    let tenant_keys: Vec<&str> = checks
        .iter()
        .filter(|(l, _)| *l == Limit::Tenant)
        .map(|(_, k)| k.as_str())
        .collect();
    assert_eq!(tenant_keys.last(), Some(&b.id.as_str()));
    assert!(tenant_keys.contains(&a.id.as_str()));
}

#[wasm_bindgen_test]
async fn tenant_limit_is_counted_once_per_request() {
    let w = World::new().await;
    let a = w.tenant("lo").await;
    let tok = w.admin_token(&a).await;
    w.limits.checks.borrow_mut().clear();
    w.encrypt(&a, &tok).await;
    let checks = w.limits.checks.borrow();
    let tenant = checks.iter().filter(|(l, _)| *l == Limit::Tenant).count();
    assert_eq!(tenant, 1, "{checks:?}");
}

#[wasm_bindgen_test]
async fn token_limit_is_keyed_by_tenant_and_jti() {
    let w = World::new().await;
    let a = w.tenant("tk").await;
    let tok = w.admin_token(&a).await;
    let jti = edgekms_core::token::check(&a.ops, &tok, NOW)
        .await
        .unwrap()
        .jti;
    w.limits.checks.borrow_mut().clear();
    w.encrypt(&a, &tok).await;
    let key = format!("{}:{jti}", a.id);
    let counted = w
        .limits
        .checks
        .borrow()
        .contains(&(Limit::Token, key.clone()));
    assert!(counted, "{:?}", w.limits.checks.borrow());
    w.limits.deny(Limit::Token, &key);
    assert_eq!(w.encrypt(&a, &tok).await.status, 429);
}

#[wasm_bindgen_test]
async fn unknown_tenant_is_a_bare_404_and_only_a_metric() {
    let w = World::new().await;
    let name = format!("nobody-{}", next());
    let r = w
        .send(&name, req(Method::Get, "/v1/sys/health", None, &json!({})))
        .await;
    assert_eq!(r, Reply::bare_404());
    let ev = w.audit.only_metric();
    assert_eq!(ev["error"], "unknown_tenant");
    assert!(ev.get("tenant").is_none());
    let checks = w.limits.checks.borrow();
    assert!(checks.is_empty(), "{checks:?}");
}

#[wasm_bindgen_test]
async fn suspended_tenant_is_refused() {
    let w = World::new().await;
    let (a, b) = (w.tenant("sa").await, w.tenant("sb").await);
    let tok = w.admin_token(&a).await;
    w.store
        .set_status(&a.id, TenantStatus::Suspended)
        .await
        .unwrap();
    w.audit.clear();
    // After one revalidation interval the cached entry is checked again.
    let mut deps = w.deps();
    deps.now_ms += edgekms_worker::tenants::REVALIDATE_MS;
    let mut r = req(
        Method::Put,
        "/v1/transit/encrypt/app",
        Some(&tok),
        &json!({ "plaintext": b64(b"x") }),
    );
    r.origin = format!("https://{}.edge.km", a.name);
    let reply = serve_tenant(&deps, &TenantName::new(&a.name).unwrap(), &r).await;
    assert_error(&reply, 403, "permission denied");
    let ev = w.audit.only_metric();
    assert_eq!(ev["error"], "tenant_suspended");
    // B is untouched.
    let tok_b = w.admin_token(&b).await;
    assert_eq!(w.encrypt(&b, &tok_b).await.status, 200);
}

#[wasm_bindgen_test]
async fn broken_tenant_is_500_and_others_keep_serving() {
    let w = World::new().await;
    let (a, b) = (w.tenant("ba").await, w.tenant("bb").await);
    w.store.tamper(&a.name, |row| row.config.push(' '));
    let r = w
        .send(
            &a.name,
            req(Method::Get, "/v1/sys/health", None, &json!({})),
        )
        .await;
    assert_error(&r, 500, "internal error");
    let tok_b = w.admin_token(&b).await;
    assert_eq!(w.encrypt(&b, &tok_b).await.status, 200);
}

#[wasm_bindgen_test]
async fn health_answers_at_a_tenant_without_counting() {
    let w = World::new().await;
    let a = w.tenant("ha").await;
    let r = w
        .send(
            &a.name,
            req(Method::Get, "/v1/sys/health", None, &json!({})),
        )
        .await;
    assert_eq!(r.status, 200);
    assert!(w.limits.checks.borrow().is_empty());
    assert!(w.audit.metrics.borrow().is_empty());
}

#[wasm_bindgen_test]
async fn jwks_url_under_the_apex_does_not_load() {
    let w = World::new().await;
    // A WHATWG parser resolves the ideographic full stop to `.`: the host is `api.edge.km`.
    let a = w
        .tenant_with("ja", |c| {
            c["mounts"]["jwt-url"]["jwks_url"] = json!("https://api.edge\u{3002}km/jwks");
        })
        .await;
    let r = w
        .send(
            &a.name,
            req(Method::Get, "/v1/sys/health", None, &json!({})),
        )
        .await;
    assert_error(&r, 500, "internal error");
}

// ---- TENANT_LIMIT is spent only past the per-IP gates ----

const ATTACKER_IP: &str = "198.51.100.66";

fn from_attacker(mut r: ApiRequest) -> ApiRequest {
    r.ip = Some(ATTACKER_IP.to_owned());
    r.limit_key = Some(ATTACKER_IP.to_owned());
    r
}

fn tenant_checks(w: &World) -> usize {
    w.limits
        .checks
        .borrow()
        .iter()
        .filter(|(l, _)| *l == Limit::Tenant)
        .count()
}

#[wasm_bindgen_test]
async fn unauthenticated_traffic_cannot_drain_the_tenant_budget() {
    let w = World::new().await;
    let a = w.tenant("dr").await;
    let tok = w.admin_token(&a).await;
    // The attacker's IP has spent its failed-authentication and login budgets.
    w.limits.deny(Limit::AuthFailure, ATTACKER_IP);
    w.limits.deny(Limit::Login, ATTACKER_IP);
    w.limits.checks.borrow_mut().clear();
    for _ in 0..50 {
        for r in [
            req(Method::Put, "/v1/transit/encrypt/app", None, &json!({})),
            req(
                Method::Put,
                "/v1/transit/encrypt/app",
                Some("ekms.forged"),
                &json!({}),
            ),
            req(Method::Get, "/v1/auth/token/lookup-self", None, &json!({})),
            req(Method::Post, "/v1/auth/ssh/challenge", None, &json!({})),
            req(Method::Put, "/v1/auth/ssh/login", None, &json!({})),
            req(Method::Put, "/v1/auth/nope/login", None, &json!({})),
        ] {
            let reply = w.send(&a.name, from_attacker(r)).await;
            assert_eq!(reply.status, 429, "{reply:?}");
        }
    }
    assert_eq!(tenant_checks(&w), 0, "{:?}", w.limits.checks.borrow());
    // The legitimate caller is served and counted once.
    assert_eq!(w.encrypt(&a, &tok).await.status, 200);
    assert_eq!(tenant_checks(&w), 1);
}

#[wasm_bindgen_test]
async fn failed_authentication_under_the_ip_limit_is_not_counted_against_the_tenant() {
    let w = World::new().await;
    let a = w.tenant("df").await;
    w.limits.checks.borrow_mut().clear();
    let r = w
        .send(
            &a.name,
            from_attacker(req(
                Method::Put,
                "/v1/transit/encrypt/app",
                Some("ekms.forged"),
                &json!({}),
            )),
        )
        .await;
    assert_error(&r, 403, "permission denied");
    assert_eq!(tenant_checks(&w), 0);
}

#[wasm_bindgen_test]
async fn login_and_challenge_are_counted_after_the_login_limit() {
    let w = World::new().await;
    let a = w.tenant("dl").await;
    w.limits.checks.borrow_mut().clear();
    w.challenge(&a).await;
    let checks = w.limits.checks.borrow().clone();
    let kinds: Vec<Limit> = checks.iter().map(|(l, _)| *l).collect();
    assert_eq!(kinds, [Limit::Login, Limit::Tenant], "{checks:?}");
}

#[wasm_bindgen_test]
async fn authenticated_request_is_counted_after_authentication() {
    let w = World::new().await;
    let a = w.tenant("dk").await;
    let tok = w.admin_token(&a).await;
    w.limits.checks.borrow_mut().clear();
    w.encrypt(&a, &tok).await;
    let kinds: Vec<Limit> = w.limits.checks.borrow().iter().map(|(l, _)| *l).collect();
    assert_eq!(kinds, [Limit::Tenant, Limit::Token]);
}

// ---- the per-isolate master handle, shared with the control plane ----

#[wasm_bindgen_test]
async fn one_master_unwrap_per_isolate() {
    // The only test in this binary that touches the isolate's handle.
    assert!(
        edgekms_worker::state::master_unwrap(&empty_env())
            .await
            .is_err(),
        "a failed build isn't cached"
    );
    let env = env_with(&[("MASTER_KEY_CURRENT", "m1")]);
    let first = edgekms_worker::state::master_unwrap(&env).await.unwrap();
    let second = edgekms_worker::state::master_unwrap(&env).await.unwrap();
    assert!(std::rc::Rc::ptr_eq(&first, &second));
}
