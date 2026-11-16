#![cfg(target_arch = "wasm32")]
//! The web console on `app.<apex>` (`edgekms_worker::console::handle`): sign-in through a
//! stubbed GitHub web flow, the session cookie, and the `/api/v1/*` proxy into the real control
//! plane, with the in-memory store, audit sink and limiters from `common/`.

mod common;

use std::cell::RefCell;
use std::collections::HashMap;

use common::memstore::MemStore;
use common::*;
use edgekms_worker::audit::Limit;
use edgekms_worker::console::cookie::{AUTH_COOKIE, REQUEST_COOKIE, SESSION_COOKIE};
use edgekms_worker::console::{self, ConsoleReply, ConsoleRequest, flow};
use edgekms_worker::control::{Control, Masters, Settings, SignupMode};
use edgekms_worker::github::{GithubApi, GithubError, GithubUser, LocalFuture};
use edgekms_worker::handlers::ApiRequest;
use edgekms_worker::master::{MasterAdmin, MasterUnwrap};
use edgekms_worker::vault::Reply;
use serde_json::{Value, json};
use wasm_bindgen_test::wasm_bindgen_test;
use worker::Method;
use zeroize::Zeroizing;

const CLIENT: &str = "Iv_console_test";
const TEMPLATE: &str = "https://{tenant}.edge.km";
const ORIGIN: &str = "https://app.edge.km";
const REDIRECT_URI: &str = "https://app.edge.km/auth/callback";
const M1: [u8; 32] = [0x51; 32];

// ---- GitHub, stubbed ----

/// One code GitHub would accept: the user it signs in, and what the exchange must prove.
struct Grant {
    user: GithubUser,
    verifier: String,
}

/// Exchanges codes from a table, each once (as GitHub does), checking the client id, redirect
/// URI and PKCE verifier; checks the user tokens it handed out and records each revocation.
#[derive(Default)]
struct FakeGithub {
    codes: RefCell<HashMap<String, Grant>>,
    tokens: RefCell<HashMap<String, GithubUser>>,
    exchanges: RefCell<u32>,
    revoked: RefCell<Vec<String>>,
}

impl FakeGithub {
    fn grant(&self, code: &str, id: u64, login: &str, verifier: &str) {
        self.codes.borrow_mut().insert(
            code.to_owned(),
            Grant {
                user: GithubUser {
                    id,
                    login: login.to_owned(),
                },
                verifier: verifier.to_owned(),
            },
        );
    }
}

impl GithubApi for FakeGithub {
    fn check_token<'a>(
        &'a self,
        client_id: &'a str,
        token: &'a str,
    ) -> LocalFuture<'a, Result<GithubUser, GithubError>> {
        let r = if client_id == CLIENT {
            self.tokens
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
        assert_eq!(client_id, CLIENT);
        self.revoked.borrow_mut().push(token.to_owned());
        Box::pin(async { Ok(()) })
    }

    fn exchange_code<'a>(
        &'a self,
        client_id: &'a str,
        code: &'a str,
        redirect_uri: &'a str,
        verifier: &'a str,
    ) -> LocalFuture<'a, Result<Zeroizing<String>, GithubError>> {
        *self.exchanges.borrow_mut() += 1;
        let grant = self.codes.borrow_mut().remove(code);
        let r = match grant {
            Some(g)
                if client_id == CLIENT
                    && redirect_uri == REDIRECT_URI
                    && g.verifier == verifier =>
            {
                let token = format!("ghu_{}_{}", g.user.id, g.user.login);
                self.tokens.borrow_mut().insert(token.clone(), g.user);
                Ok(Zeroizing::new(token))
            }
            _ => Err(GithubError::Denied("github_code_rejected")),
        };
        Box::pin(async move { r })
    }
}

// ---- The fixture ----

struct Fx {
    store: MemStore,
    masters: Masters,
    audit: MemAudit,
    limits: MemLimits,
    gh: FakeGithub,
    settings: Settings,
}

async fn fx_with(signup: SignupMode) -> Fx {
    Fx {
        store: MemStore::default(),
        masters: Masters::fixed(
            MasterAdmin::from_bytes("m1", &[("m1", &M1)]).await.unwrap(),
            MasterUnwrap::from_bytes(&[("m1", &M1)]).await.unwrap(),
        ),
        audit: MemAudit::default(),
        limits: MemLimits::default(),
        gh: FakeGithub::default(),
        settings: Settings {
            apex: "edge.km".into(),
            github_client_id: CLIENT.into(),
            operators: vec![900],
            max_tenants_per_user: 5,
            previous_master: None,
            signup,
            max_pending_invite_requests: 200,
        },
    }
}

async fn fx() -> Fx {
    fx_with(SignupMode::Open).await
}

/// A request to `app.edge.km` for `path_and_query`.
fn creq(
    method: Method,
    path_and_query: &str,
    cookie: Option<&str>,
    body: Vec<u8>,
) -> ConsoleRequest {
    let (path, query) = path_and_query
        .split_once('?')
        .unwrap_or((path_and_query, ""));
    let mut api: ApiRequest = raw(method, path, None, body);
    api.host = "app.edge.km".into();
    api.origin = ORIGIN.into();
    ConsoleRequest {
        api,
        query: query.to_owned(),
        cookie: cookie.map(str::to_owned),
        origin_header: None,
        content_type: None,
    }
}

/// A same-origin `fetch` from the SPA: `Origin` set and, with a body, a JSON content type.
fn spa(method: Method, path: &str, session: Option<&str>, body: Option<&Value>) -> ConsoleRequest {
    let cookie = session.map(|t| format!("{SESSION_COOKIE}={t}"));
    let bytes = body
        .map(|b| serde_json::to_vec(b).unwrap())
        .unwrap_or_default();
    let mut r = creq(method, path, cookie.as_deref(), bytes);
    r.origin_header = Some(ORIGIN.into());
    if body.is_some() {
        r.content_type = Some("application/json".into());
    }
    r
}

impl Fx {
    async fn call(&self, req: ConsoleRequest) -> ConsoleReply {
        let c = Control {
            store: &self.store,
            masters: &self.masters,
            audit: &self.audit,
            limits: &self.limits,
            github: &self.gh,
            settings: &self.settings,
            now_ms: NOW * 1000,
        };
        console::handle(&c, TEMPLATE, req).await
    }

    /// `GET /auth/login?<query>`: the redirect location and the auth cookie's value.
    async fn start(&self, query: &str) -> (String, String) {
        let r = self
            .call(creq(
                Method::Get,
                &format!("/auth/login?{query}"),
                None,
                vec![],
            ))
            .await;
        let (location, cookies) = redirect(&r);
        assert_eq!(cookies.len(), 1, "{cookies:?}");
        let value = cookie_value(&cookies[0], AUTH_COOKIE).expect("an auth cookie");
        (location, value)
    }

    /// The whole sign-in for GitHub user `id`: login, GitHub approves, callback. Returns the
    /// callback's reply.
    async fn sign_in_reply(&self, id: u64, login: &str, return_to: &str) -> ConsoleReply {
        let (_, auth) = self
            .start(&format!("return_to={}", flow::encode(return_to)))
            .await;
        let (state, verifier, _) = flow::unpack(&auth).unwrap();
        let code = format!("code_{id}");
        self.gh.grant(&code, id, login, &verifier);
        self.callback(&format!("code={code}&state={state}"), Some(&auth))
            .await
    }

    /// Signs in and returns the session token.
    async fn sign_in(&self, id: u64, login: &str) -> String {
        let r = self.sign_in_reply(id, login, "/").await;
        let (_, cookies) = redirect(&r);
        cookies
            .iter()
            .find_map(|c| cookie_value(c, SESSION_COOKIE).filter(|v| !v.is_empty()))
            .expect("a session cookie")
    }

    async fn callback(&self, query: &str, auth: Option<&str>) -> ConsoleReply {
        let cookie = auth.map(|a| format!("{AUTH_COOKIE}={a}"));
        self.call(creq(
            Method::Get,
            &format!("/auth/callback?{query}"),
            cookie.as_deref(),
            vec![],
        ))
        .await
    }
}

/// A redirect's location and `Set-Cookie` values.
#[track_caller]
fn redirect(r: &ConsoleReply) -> (String, Vec<String>) {
    match r {
        ConsoleReply::Redirect {
            location,
            set_cookies,
        } => (
            location.clone(),
            set_cookies.iter().map(|c| c.to_string()).collect(),
        ),
        other => panic!("not a redirect: {other:?}"),
    }
}

/// A JSON reply and its `Set-Cookie` values.
#[track_caller]
fn json_reply(r: &ConsoleReply) -> (&Reply, Vec<String>) {
    match r {
        ConsoleReply::Json { reply, set_cookies } => {
            (reply, set_cookies.iter().map(|c| c.to_string()).collect())
        }
        other => panic!("not JSON: {other:?}"),
    }
}

/// The value `set_cookie` sets for `name`.
fn cookie_value(set_cookie: &str, name: &str) -> Option<String> {
    let (pair, _) = set_cookie.split_once(';')?;
    let (n, v) = pair.split_once('=')?;
    (n == name).then(|| v.to_owned())
}

fn clears(set_cookie: &str, name: &str) -> bool {
    cookie_value(set_cookie, name).as_deref() == Some("") && set_cookie.ends_with("; Max-Age=0")
}

/// The one data point the callback wrote for a refused or failed code exchange.
#[track_caller]
fn exchange_metric(fx: &Fx) -> Value {
    let metrics: Vec<Value> = fx
        .audit
        .metrics
        .borrow()
        .iter()
        .map(|m| serde_json::from_str::<Value>(m).unwrap())
        .filter(|m| m["op"] == "console_code_exchange")
        .collect();
    assert_eq!(metrics.len(), 1, "{metrics:?}");
    assert!(
        fx.audit
            .values()
            .iter()
            .all(|e| e["op"] != "console_code_exchange"),
        "a metric only"
    );
    metrics[0].clone()
}

fn code_of(r: &Reply) -> Option<&str> {
    r.body.as_ref()?.get("code")?.as_str()
}

// ---- /auth/login ----

#[wasm_bindgen_test]
async fn login_sets_lax_auth_cookie_and_redirects() {
    let fx = fx().await;
    let r = fx
        .call(creq(
            Method::Get,
            "/auth/login?return_to=%2Ft%2Facme",
            None,
            vec![],
        ))
        .await;
    let (location, cookies) = redirect(&r);
    assert_eq!(cookies.len(), 1);
    let c = &cookies[0];
    assert!(c.starts_with("__Host-edgekms_auth="), "{c}");
    assert!(
        c.ends_with("; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=600"),
        "{c}"
    );
    let (state, verifier, return_to) =
        flow::unpack(&cookie_value(c, AUTH_COOKIE).unwrap()).unwrap();
    assert_eq!(return_to, "/t/acme");
    assert_eq!(state.len(), 43);
    let challenge = flow::challenge(&verifier).await.unwrap();
    assert_eq!(
        location,
        flow::authorize_url(CLIENT, REDIRECT_URI, &state, &challenge)
    );
    assert!(location.contains("code_challenge_method=S256"));
}

#[wasm_bindgen_test]
async fn login_sanitizes_return_to() {
    let fx = fx().await;
    for q in [
        "return_to=%2F%2Fevil.com",
        "return_to=https%3A%2F%2Fevil.com",
        "return_to=%2F%5Cevil.com",
        "return_to=%2F%252F%252Fevil.com",
        "",
    ] {
        let (_, auth) = fx.start(q).await;
        let (_, _, return_to) = flow::unpack(&auth).unwrap();
        assert_eq!(return_to, "/", "{q}");
    }
}

#[wasm_bindgen_test]
async fn every_login_gets_its_own_state() {
    let fx = fx().await;
    let (_, a) = fx.start("").await;
    let (_, b) = fx.start("").await;
    assert_ne!(flow::unpack(&a).unwrap().0, flow::unpack(&b).unwrap().0);
}

// ---- /auth/callback ----

#[wasm_bindgen_test]
async fn callback_without_cookie_is_state_error() {
    let fx = fx().await;
    let (_, auth) = fx.start("").await;
    let (state, verifier, _) = flow::unpack(&auth).unwrap();
    fx.gh.grant("c1", 101, "alice", &verifier);
    let r = fx.callback(&format!("code=c1&state={state}"), None).await;
    let (location, cookies) = redirect(&r);
    assert_eq!(location, "/signin?error=state");
    assert!(clears(&cookies[0], AUTH_COOKIE), "{cookies:?}");
    assert_eq!(
        *fx.gh.exchanges.borrow(),
        0,
        "no exchange without the cookie"
    );
}

#[wasm_bindgen_test]
async fn callback_state_mismatch_is_state_error() {
    let fx = fx().await;
    let (_, auth) = fx.start("").await;
    let (state, verifier, _) = flow::unpack(&auth).unwrap();
    fx.gh.grant("c1", 101, "alice", &verifier);
    // Another browser's state, one character off, missing, or a broken cookie.
    let mut off = state.clone().into_bytes();
    off[0] = if off[0] == b'A' { b'B' } else { b'A' };
    let off = String::from_utf8(off).unwrap();
    for (query, cookie) in [
        (format!("code=c1&state={off}"), auth.clone()),
        ("code=c1".to_owned(), auth.clone()),
        (format!("state={state}"), auth.clone()),
        (format!("code=c1&state={state}"), "garbage".to_owned()),
        (format!("code=c1&state={state}"), String::new()),
    ] {
        let r = fx.callback(&query, Some(&cookie)).await;
        let (location, cookies) = redirect(&r);
        assert_eq!(location, "/signin?error=state", "{query} {cookie}");
        assert!(clears(&cookies[0], AUTH_COOKIE));
    }
    assert_eq!(*fx.gh.exchanges.borrow(), 0);
}

#[wasm_bindgen_test]
async fn callback_replay_is_state_error() {
    let fx = fx().await;
    let (_, auth) = fx.start("").await;
    let (state, verifier, _) = flow::unpack(&auth).unwrap();
    fx.gh.grant("c1", 101, "alice", &verifier);
    let query = format!("code=c1&state={state}");
    let first = fx.callback(&query, Some(&auth)).await;
    let (location, cookies) = redirect(&first);
    assert_eq!(location, "/?signed_in=1");
    // The browser now holds the cleared cookie, so the replay arrives with it empty.
    let cleared = cookies
        .iter()
        .find(|c| clears(c, AUTH_COOKIE))
        .expect("the auth cookie is cleared");
    let empty = cookie_value(cleared, AUTH_COOKIE).unwrap();
    let r = fx.callback(&query, Some(&empty)).await;
    assert_eq!(redirect(&r).0, "/signin?error=state");
    // A replay that kept the old cookie reaches GitHub, which refuses a used code.
    let r = fx.callback(&query, Some(&auth)).await;
    assert_eq!(redirect(&r).0, "/signin?error=github_denied");
    let logins = fx
        .audit
        .values()
        .into_iter()
        .filter(|e| e["op"] == "control_login" && e["result"] == "ok")
        .count();
    assert_eq!(logins, 1, "exactly one login");
}

#[wasm_bindgen_test]
async fn callback_success_sets_strict_session_and_redirects_to_return_to() {
    let fx = fx().await;
    let r = fx.sign_in_reply(102, "bob", "/t/bob/keys").await;
    let (location, cookies) = redirect(&r);
    assert_eq!(location, "/t/bob/keys?signed_in=1");
    assert_eq!(cookies.len(), 3, "{cookies:?}");
    assert!(cookies.iter().any(|c| clears(c, AUTH_COOKIE)));
    assert!(cookies.iter().any(|c| clears(c, REQUEST_COOKIE)));
    let session = cookies
        .iter()
        .find(|c| c.starts_with("__Host-edgekms_session="))
        .unwrap();
    assert!(
        session.ends_with("; HttpOnly; Secure; Path=/; SameSite=Strict; Max-Age=1800"),
        "{session}"
    );
    let token = cookie_value(session, SESSION_COOKIE).unwrap();
    assert!(token.starts_with("ekms."), "a control token");
    // The session works through the proxy.
    let r = fx
        .call(spa(Method::Get, "/api/v1/me", Some(&token), None))
        .await;
    let (reply, cookies) = json_reply(&r);
    assert_eq!(data(reply)["github_id"], json!(102));
    assert_eq!(cookies, Vec::<String>::new());
}

#[wasm_bindgen_test]
async fn callback_success_marks_the_return_path_signed_in() {
    // The SPA reads `signed_in=1` to tell a sign-in that just happened from a stale session,
    // so a session refused right after sign-in doesn't loop back through GitHub.
    for (i, (return_to, location)) in [
        ("/", "/?signed_in=1"),
        ("/t/acme/roles?tab=x", "/t/acme/roles?tab=x&signed_in=1"),
        ("/t/acme?", "/t/acme?signed_in=1"),
        ("/t/acme?a=1&", "/t/acme?a=1&signed_in=1"),
        ("/t/acme#keys", "/t/acme?signed_in=1#keys"),
        ("/t/acme?a=1#k?x", "/t/acme?a=1&signed_in=1#k?x"),
        ("//evil.com", "/?signed_in=1"),
    ]
    .into_iter()
    .enumerate()
    {
        let fx = fx().await;
        let id = 130 + u64::try_from(i).unwrap();
        let r = fx.sign_in_reply(id, &format!("u{id}"), return_to).await;
        assert_eq!(redirect(&r).0, location, "{return_to}");
    }
}

#[wasm_bindgen_test]
async fn callback_signup_closed_maps_code() {
    let fx = fx_with(SignupMode::Invite).await;
    let r = fx.sign_in_reply(103, "carol", "/").await;
    let (location, cookies) = redirect(&r);
    assert_eq!(location, "/signin?error=signup_closed");
    assert_eq!(cookies.len(), 1);
    assert!(clears(&cookies[0], AUTH_COOKIE));
}

#[wasm_bindgen_test]
async fn callback_github_refusal_is_github_denied() {
    let fx = fx().await;
    let (_, auth) = fx.start("").await;
    let (state, _, _) = flow::unpack(&auth).unwrap();
    // A code GitHub never issued.
    let r = fx
        .callback(&format!("code=nope&state={state}"), Some(&auth))
        .await;
    assert_eq!(redirect(&r).0, "/signin?error=github_denied");
    // The user pressed Cancel on GitHub's page.
    let r = fx
        .callback(&format!("error=access_denied&state={state}"), Some(&auth))
        .await;
    assert_eq!(redirect(&r).0, "/signin?error=github_denied");
}

#[wasm_bindgen_test]
async fn callback_counts_against_control_limit() {
    let fx = fx().await;
    fx.limits.deny_control.set(true);
    let r = fx.sign_in_reply(104, "dave", "/").await;
    assert_eq!(redirect(&r).0, "/signin?error=rate_limited");
}

#[wasm_bindgen_test]
async fn callback_over_control_limit_makes_no_exchange() {
    // A script holding its own auth cookie can replay the callback; over the limit, GitHub's
    // token endpoint never hears about it.
    let fx = fx().await;
    fx.limits.deny_control.set(true);
    let r = fx.sign_in_reply(119, "sam", "/").await;
    assert_eq!(redirect(&r).0, "/signin?error=rate_limited");
    assert_eq!(*fx.gh.exchanges.borrow(), 0, "no exchange over the limit");
    assert!(fx.gh.revoked.borrow().is_empty());
    let ev = exchange_metric(&fx);
    assert_eq!(ev["result"], "denied");
    assert_eq!(ev["error"], "rate_limited");
    assert_eq!(ev["ip"], json!(TEST_IP));
}

#[wasm_bindgen_test]
async fn callback_refused_before_check_still_revokes_the_token() {
    // The callback's own control check passes but the login's is refused, before
    // `check_token` runs, so only the callback can burn the token GitHub just issued.
    let fx = fx().await;
    fx.limits.control_budget.set(Some(1));
    let r = fx.sign_in_reply(116, "pete", "/").await;
    assert_eq!(redirect(&r).0, "/signin?error=rate_limited");
    assert_eq!(*fx.gh.exchanges.borrow(), 1);
    assert_eq!(*fx.gh.revoked.borrow(), vec!["ghu_116_pete".to_owned()]);
}

#[wasm_bindgen_test]
async fn callback_success_counts_two_control_units() {
    // One for the callback's own check before the exchange, one for the login it makes.
    let fx = fx().await;
    fx.sign_in(120, "tara").await;
    let control = fx
        .limits
        .checks
        .borrow()
        .iter()
        .filter(|(l, k)| *l == Limit::Control && k == TEST_IP)
        .count();
    assert_eq!(control, 2);
}

#[wasm_bindgen_test]
async fn callback_github_refusal_counts_an_auth_failure() {
    let fx = fx().await;
    let (_, auth) = fx.start("").await;
    let (state, _, _) = flow::unpack(&auth).unwrap();
    let r = fx
        .callback(&format!("code=nope&state={state}"), Some(&auth))
        .await;
    assert_eq!(redirect(&r).0, "/signin?error=github_denied");
    let failures = fx
        .limits
        .checks
        .borrow()
        .iter()
        .filter(|(l, k)| *l == Limit::AuthFailure && k == TEST_IP)
        .count();
    assert_eq!(failures, 1);
    let ev = exchange_metric(&fx);
    assert_eq!(ev["result"], "denied");
    assert_eq!(ev["error"], "github_code_rejected");
}

#[wasm_bindgen_test]
async fn callback_github_refusal_over_auth_fail_limit_is_rate_limited() {
    let fx = fx().await;
    fx.limits.deny_auth_failure.set(true);
    let (_, auth) = fx.start("").await;
    let (state, _, _) = flow::unpack(&auth).unwrap();
    let r = fx
        .callback(&format!("code=nope&state={state}"), Some(&auth))
        .await;
    assert_eq!(redirect(&r).0, "/signin?error=rate_limited");
}

#[wasm_bindgen_test]
async fn callback_refused_after_check_revokes_and_success_revokes_once() {
    // `signup_closed` comes after `check_token`, which revoked already; the callback's second
    // revoke of the same token is harmless.
    let closed = fx_with(SignupMode::Closed).await;
    let r = closed.sign_in_reply(117, "quinn", "/").await;
    assert_eq!(redirect(&r).0, "/signin?error=signup_closed");
    assert_eq!(
        *closed.gh.revoked.borrow(),
        vec!["ghu_117_quinn".to_owned(), "ghu_117_quinn".to_owned()]
    );
    // A successful login is revoked once, by the login itself.
    let fx = fx().await;
    fx.sign_in(118, "rosa").await;
    assert_eq!(*fx.gh.revoked.borrow(), vec!["ghu_118_rosa".to_owned()]);
}

#[wasm_bindgen_test]
async fn callback_login_is_durably_audited() {
    let fx = fx().await;
    fx.sign_in(105, "erin").await;
    let events = fx.audit.values();
    let login: Vec<&Value> = events
        .iter()
        .filter(|e| e["op"] == "control_login")
        .collect();
    assert_eq!(login.len(), 2, "attempt and outcome: {events:?}");
    assert_eq!(login[1]["result"], "ok");
    assert_eq!(login[1]["github_id"], json!(105));
    assert_eq!(login[1]["ip"], json!(TEST_IP));
}

#[wasm_bindgen_test]
async fn callback_without_client_ip_is_login_failed() {
    let fx = fx().await;
    let (_, auth) = fx.start("").await;
    let (state, verifier, _) = flow::unpack(&auth).unwrap();
    fx.gh.grant("c1", 106, "frank", &verifier);
    let cookie = format!("{AUTH_COOKIE}={auth}");
    let mut req = creq(
        Method::Get,
        &format!("/auth/callback?code=c1&state={state}"),
        Some(&cookie),
        vec![],
    );
    req.api.ip = None;
    let r = fx.call(req).await;
    assert_eq!(redirect(&r).0, "/signin?error=login_failed");
    assert_eq!(
        *fx.gh.exchanges.borrow(),
        0,
        "no exchange without a client IP"
    );
    assert!(fx.gh.revoked.borrow().is_empty());
    let ev = exchange_metric(&fx);
    assert_eq!(ev["result"], "denied");
    assert_eq!(ev["error"], "no_client_ip");
}

// ---- /api/v1 ----

#[wasm_bindgen_test]
async fn api_without_cookie_is_401_no_session() {
    let fx = fx().await;
    for cookie in [None, Some("other=1"), Some("__Host-edgekms_session=")] {
        let mut req = creq(Method::Get, "/api/v1/me", cookie, vec![]);
        req.origin_header = Some(ORIGIN.into());
        let r = fx.call(req).await;
        let (reply, _) = json_reply(&r);
        assert_error(reply, 401, "sign in required");
        assert_eq!(code_of(reply), Some("no_session"));
    }
}

#[wasm_bindgen_test]
async fn api_strips_incoming_authorization() {
    let fx = fx().await;
    let alice = fx.sign_in(107, "gina").await;
    let bob = fx.sign_in(108, "hank").await;
    // A bearer token in the header never replaces the session, nor stands in for a missing one.
    let mut req = spa(Method::Get, "/api/v1/me", Some(&alice), None);
    req.api.authorization = Some(format!("Bearer {bob}"));
    req.api.vault_token = Some(bob.clone());
    let r = fx.call(req).await;
    assert_eq!(data(json_reply(&r).0)["github_id"], json!(107));
    let mut req = spa(Method::Get, "/api/v1/me", None, None);
    req.api.authorization = Some(format!("Bearer {bob}"));
    let r = fx.call(req).await;
    assert_eq!(json_reply(&r).0.status, 401);
}

#[wasm_bindgen_test]
async fn api_refuses_login_path() {
    let fx = fx().await;
    let token = fx.sign_in(109, "ivan").await;
    for path in ["/api/v1/login/github", "/api/v1/login"] {
        let r = fx
            .call(spa(
                Method::Post,
                path,
                Some(&token),
                Some(&json!({"token": "ghu_x"})),
            ))
            .await;
        assert_error(json_reply(&r).0, 404, "unsupported path");
    }
}

/// The SSH login routes are login routes: the console never reaches them, with or without a
/// session, and the control plane never sees the request.
#[wasm_bindgen_test]
async fn console_refuses_the_ssh_login_routes() {
    let fx = fx().await;
    let token = fx.sign_in(120, "sshrefuse").await;
    for path in ["/api/v1/login/ssh", "/api/v1/login/ssh/challenge"] {
        for session in [Some(token.as_str()), None] {
            fx.audit.clear();
            let r = fx
                .call(spa(Method::Post, path, session, Some(&json!({}))))
                .await;
            assert_error(json_reply(&r).0, 404, "unsupported path");
            assert!(fx.audit.metrics.borrow().is_empty(), "{path}");
        }
    }
}

/// A registration challenge fetched through the console is bound to the control origin,
/// `https://api.<apex>`, as one the CLI fetches is: the control plane's challenges name only
/// its own origin.
#[wasm_bindgen_test]
async fn registration_challenge_through_the_console_names_the_control_origin() {
    let fx = fx().await;
    let token = fx.sign_in(121, "sshorigin").await;
    let r = fx
        .call(spa(
            Method::Post,
            "/api/v1/me/ssh-keys/challenge",
            Some(&token),
            Some(&json!({})),
        ))
        .await;
    let reply = json_reply(&r).0;
    assert_eq!(reply.status, 200, "{reply:?}");
    let challenge = reply.body.as_ref().unwrap()["data"]["challenge"]
        .as_str()
        .unwrap()
        .to_owned();
    let (account, origin) = edgekms_core::ssh::register_challenge_parts(&challenge).unwrap();
    assert_eq!(origin, "https://api.edge.km");
    // And to the signed-in account (lokkju/edgekms#17).
    assert_eq!(
        (account.github_id, account.login.as_str()),
        (121, "sshorigin")
    );
    // The listing passes through under the usual rules.
    let r = fx
        .call(spa(Method::Get, "/api/v1/me/ssh-keys", Some(&token), None))
        .await;
    assert_eq!(json_reply(&r).0.status, 200);
    let mut cross = spa(
        Method::Post,
        "/api/v1/me/ssh-keys/challenge",
        Some(&token),
        Some(&json!({})),
    );
    cross.origin_header = Some("https://evil.example".into());
    assert_eq!(json_reply(&fx.call(cross).await).0.status, 403);
}

#[wasm_bindgen_test]
async fn api_post_from_foreign_origin_is_403() {
    let fx = fx().await;
    let token = fx.sign_in(110, "judy").await;
    for origin in [
        Some("https://evil.com"),
        Some("https://acme.edge.km"),
        Some("https://api.edge.km"),
        Some("http://app.edge.km"),
        Some("null"),
        None,
    ] {
        let mut req = spa(
            Method::Post,
            "/api/v1/tenants",
            Some(&token),
            Some(&json!({"name": "judy-x"})),
        );
        req.origin_header = origin.map(str::to_owned);
        let r = fx.call(req).await;
        assert_error(json_reply(&r).0, 403, "cross-origin request refused");
    }
    let mut req = spa(
        Method::Delete,
        "/api/v1/tenants/judy/members/1",
        Some(&token),
        None,
    );
    req.origin_header = Some("https://evil.com".into());
    assert_eq!(json_reply(&fx.call(req).await).0.status, 403);
}

#[wasm_bindgen_test]
async fn api_post_without_json_content_type_is_415() {
    let fx = fx().await;
    let token = fx.sign_in(111, "kate").await;
    for ct in [
        None,
        Some("text/plain"),
        Some("application/x-www-form-urlencoded"),
    ] {
        let mut req = spa(
            Method::Post,
            "/api/v1/tenants",
            Some(&token),
            Some(&json!({"name": "kate-x"})),
        );
        req.content_type = ct.map(str::to_owned);
        let r = fx.call(req).await;
        assert_eq!(json_reply(&r).0.status, 415, "{ct:?}");
    }
    // No body needs no content type.
    let r = fx
        .call(spa(
            Method::Post,
            "/api/v1/tenants/kate/decline",
            Some(&token),
            None,
        ))
        .await;
    assert_ne!(json_reply(&r).0.status, 415);
}

#[wasm_bindgen_test]
async fn api_passes_if_match() {
    let fx = fx().await;
    let token = fx.sign_in(112, "liam").await;
    let r = fx
        .call(spa(Method::Get, "/api/v1/tenants/liam", Some(&token), None))
        .await;
    let d = data(json_reply(&r).0).clone();
    let version = d["config_version"].as_u64().unwrap();
    let config = d["config"].clone();
    let put = |if_match: String| {
        let mut req = spa(
            Method::Put,
            "/api/v1/tenants/liam/config",
            Some(&token),
            Some(&config),
        );
        req.api.if_match = Some(if_match);
        req
    };
    let stale = fx.call(put(format!("\"{}\"", version + 7))).await;
    assert_eq!(json_reply(&stale).0.status, 409);
    let ok = fx.call(put(format!("\"{version}\""))).await;
    assert!(
        (200..300).contains(&json_reply(&ok).0.status),
        "{:?}",
        json_reply(&ok).0
    );
}

#[wasm_bindgen_test]
async fn api_under_another_prefix_is_404() {
    let fx = fx().await;
    let token = fx.sign_in(113, "mona").await;
    for path in ["/api/v2/me", "/api/v1", "/api", "/auth/other"] {
        let r = fx.call(spa(Method::Get, path, Some(&token), None)).await;
        assert_error(json_reply(&r).0, 404, "unsupported path");
    }
}

// ---- /auth/logout ----

#[wasm_bindgen_test]
async fn logout_clears_cookie_and_cuts_off_token() {
    let fx = fx().await;
    let token = fx.sign_in(114, "nina").await;
    let r = fx
        .call(spa(Method::Post, "/auth/logout", Some(&token), None))
        .await;
    let (reply, cookies) = json_reply(&r);
    assert_eq!(reply.status, 204);
    assert_eq!(cookies.len(), 1);
    assert!(clears(&cookies[0], SESSION_COOKIE), "{cookies:?}");
    assert!(cookies[0].contains("SameSite=Strict"));
    // The old token is cut off, and the code tells the SPA to sign in again.
    let r = fx
        .call(spa(Method::Get, "/api/v1/me", Some(&token), None))
        .await;
    let reply = json_reply(&r).0;
    assert_error(reply, 403, "permission denied");
    assert_eq!(code_of(reply), Some("auth_failed"));
}

#[wasm_bindgen_test]
async fn logout_from_foreign_origin_is_403_and_keeps_the_session() {
    let fx = fx().await;
    let token = fx.sign_in(115, "otto").await;
    let mut req = spa(Method::Post, "/auth/logout", Some(&token), None);
    req.origin_header = Some("https://evil.com".into());
    let r = fx.call(req).await;
    let (reply, cookies) = json_reply(&r);
    assert_error(reply, 403, "cross-origin request refused");
    assert_eq!(cookies, Vec::<String>::new());
    let r = fx
        .call(spa(Method::Get, "/api/v1/me", Some(&token), None))
        .await;
    assert_eq!(json_reply(&r).0.status, 200);
}

#[wasm_bindgen_test]
async fn logout_control_failure_keeps_the_session_cookie() {
    // The audit log is down, so the control logout fails and every session stays live; the
    // browser must keep its cookie and hear about the failure.
    let fx = fx().await;
    let token = fx.sign_in(121, "uma").await;
    fx.audit.fail.set(true);
    let r = fx
        .call(spa(Method::Post, "/auth/logout", Some(&token), None))
        .await;
    let (reply, cookies) = json_reply(&r);
    assert_eq!(reply.status, 500);
    assert_eq!(cookies, Vec::<String>::new(), "no cookie cleared");
    fx.audit.fail.set(false);
    let r = fx
        .call(spa(Method::Get, "/api/v1/me", Some(&token), None))
        .await;
    assert_eq!(json_reply(&r).0.status, 200, "the session still works");
}

#[wasm_bindgen_test]
async fn logout_without_session_still_clears_the_cookie() {
    let fx = fx().await;
    let r = fx.call(spa(Method::Post, "/auth/logout", None, None)).await;
    let (reply, cookies) = json_reply(&r);
    assert_eq!(reply.status, 204);
    assert!(clears(&cookies[0], SESSION_COOKIE));
}

// ---- everything else ----

#[wasm_bindgen_test]
async fn unknown_get_is_asset() {
    let fx = fx().await;
    for (method, path, asset) in [
        (Method::Get, "/", true),
        (Method::Head, "/t/x", true),
        (Method::Post, "/", false),
        (Method::Get, "/api/v1/me", false),
        (Method::Get, "/api", false),
        (Method::Get, "/auth/login", false),
        (Method::Get, "/auth/other", false),
        (Method::Get, "/authors", true),
    ] {
        // The Worker serves assets on this answer, without reading the body or the bindings.
        assert_eq!(console::is_asset(&method, path), asset, "{method:?} {path}");
        assert_eq!(
            matches!(
                fx.call(creq(method.clone(), path, None, vec![])).await,
                ConsoleReply::Asset
            ),
            asset,
            "{method:?} {path}"
        );
    }
    for path in [
        "/",
        "/index.html",
        "/assets/app-1234.js",
        "/t/acme/roles",
        "/signin",
    ] {
        assert!(
            matches!(
                fx.call(creq(Method::Get, path, None, vec![])).await,
                ConsoleReply::Asset
            ),
            "{path}"
        );
        assert!(
            matches!(
                fx.call(creq(Method::Head, path, None, vec![])).await,
                ConsoleReply::Asset
            ),
            "{path}"
        );
    }
}

#[wasm_bindgen_test]
async fn other_methods_on_assets_and_auth_routes_are_405() {
    let fx = fx().await;
    for (method, path) in [
        (Method::Post, "/"),
        (Method::Put, "/t/acme"),
        (Method::Post, "/auth/login"),
        (Method::Post, "/auth/callback"),
        (Method::Get, "/auth/logout"),
    ] {
        let mut req = creq(method.clone(), path, None, vec![]);
        req.origin_header = Some(ORIGIN.into());
        let r = fx.call(req).await;
        assert_eq!(json_reply(&r).0.status, 405, "{method:?} {path}");
    }
}

// ---- #54: the request cookie ----

/// An operator, so a sign-in creates the control root that request tokens are minted under.
const OP: u64 = 900;

/// A same-origin `fetch` from the SPA with the `Cookie` header `cookies`.
fn spa_with(method: Method, path: &str, cookies: &str, body: Option<&Value>) -> ConsoleRequest {
    let bytes = body
        .map(|b| serde_json::to_vec(b).unwrap())
        .unwrap_or_default();
    let mut r = creq(method, path, Some(cookies), bytes);
    r.origin_header = Some(ORIGIN.into());
    if body.is_some() {
        r.content_type = Some("application/json".into());
    }
    r
}

impl Fx {
    /// GitHub user `id` is refused at sign-in in invite mode, with the control root in place;
    /// returns the request cookie's value.
    async fn refused(&self, id: u64, login: &str) -> String {
        let r = self.sign_in_reply(id, login, "/").await;
        let (location, cookies) = redirect(&r);
        assert_eq!(location, "/request-invite");
        cookies
            .iter()
            .find_map(|c| cookie_value(c, REQUEST_COOKIE).filter(|v| !v.is_empty()))
            .expect("a request cookie")
    }
}

/// Invite mode with the operator signed in (so the control root exists); returns the fixture
/// and the operator's session token.
async fn invite_fx() -> (Fx, String) {
    let fx = fx_with(SignupMode::Invite).await;
    let session = fx.sign_in(OP, "boss").await;
    (fx, session)
}

#[wasm_bindgen_test]
async fn callback_refusal_with_a_token_sets_the_request_cookie() {
    let (fx, _) = invite_fx().await;
    // `return_to` is ignored: a refused sign-in has nowhere else to go.
    let r = fx.sign_in_reply(201, "rita", "/t/elsewhere").await;
    let (location, cookies) = redirect(&r);
    assert_eq!(location, "/request-invite");
    assert_eq!(cookies.len(), 3, "{cookies:?}");
    assert!(cookies.iter().any(|c| clears(c, AUTH_COOKIE)));
    // A session another account left in this browser is ended too.
    assert!(cookies.iter().any(|c| clears(c, SESSION_COOKIE)));
    let set = cookies
        .iter()
        .find(|c| c.starts_with("__Host-edgekms_request="))
        .unwrap();
    let token = cookie_value(set, REQUEST_COOKIE).unwrap();
    assert!(token.starts_with("ekms."), "{set}");
    assert_eq!(
        *set,
        format!("{REQUEST_COOKIE}={token}; HttpOnly; Secure; Path=/; SameSite=Strict; Max-Age=900")
    );
    assert!(
        !cookies
            .iter()
            .any(|c| cookie_value(c, SESSION_COOKIE).is_some_and(|v| !v.is_empty()))
    );
    // The GitHub token was burned, as for any refused sign-in.
    assert!(fx.gh.revoked.borrow().contains(&"ghu_201_rita".to_owned()));
}

#[wasm_bindgen_test]
async fn callback_refusal_without_a_token_keeps_signin_error() {
    // Closed mode, with a root: no request token, so the sign-in page explains.
    let fx = fx_with(SignupMode::Closed).await;
    fx.sign_in(OP, "boss").await;
    let r = fx.sign_in_reply(202, "sam", "/").await;
    let (location, cookies) = redirect(&r);
    assert_eq!(location, "/signin?error=signup_closed");
    assert_eq!(cookies.len(), 1);
    assert!(clears(&cookies[0], AUTH_COOKIE));
}

#[wasm_bindgen_test]
async fn successful_sign_in_clears_the_request_cookie() {
    let fx = fx().await;
    let r = fx.sign_in_reply(203, "tara", "/").await;
    let (_, cookies) = redirect(&r);
    let clear = cookies
        .iter()
        .find(|c| c.starts_with("__Host-edgekms_request="))
        .expect("the request cookie cleared");
    assert_eq!(
        *clear,
        format!("{REQUEST_COOKIE}=; HttpOnly; Secure; Path=/; SameSite=Strict; Max-Age=0")
    );
}

#[wasm_bindgen_test]
async fn proxy_picks_the_cookie_by_path() {
    let (fx, session) = invite_fx().await;
    let request = fx.refused(204, "uma").await;
    let both = format!("{SESSION_COOKIE}={session}; {REQUEST_COOKIE}={request}");
    let only_request = format!("{REQUEST_COOKIE}={request}");
    let only_session = format!("{SESSION_COOKIE}={session}");
    let get = |path: &str, cookies: &str| fx.call(spa_with(Method::Get, path, cookies, None));
    // The requester paths take the request cookie, even beside a session.
    let r = get("/api/v1/invite-requests/mine", &both).await;
    assert_eq!(data(json_reply(&r).0)["github_id"], json!(204));
    // Everything else takes the session cookie, the operator routes for requests included.
    let r = get("/api/v1/me", &both).await;
    assert_eq!(data(json_reply(&r).0)["github_id"], json!(OP));
    let r = get("/api/v1/ops/invite-requests", &both).await;
    assert_eq!(json_reply(&r).0.status, 200);
    // Without the cookie a path takes, the other one never stands in.
    for path in [
        "/api/v1/me",
        "/api/v1/ops/invite-requests",
        "/api/v1/invite-requests/mine/",
        "/api/v1/invite-requests/other",
    ] {
        let r = get(path, &only_request).await;
        let (reply, _) = json_reply(&r);
        assert_error(reply, 401, "sign in required");
        assert_eq!(code_of(reply), Some("no_session"), "{path}");
    }
    for cookies in [only_session.as_str(), "", "__Host-edgekms_request="] {
        let r = get("/api/v1/invite-requests/mine", cookies).await;
        let (reply, _) = json_reply(&r);
        assert_eq!(reply.status, 401, "{reply:?}");
        assert_eq!(code_of(reply), Some("no_request_session"));
        let r = fx
            .call(spa_with(
                Method::Post,
                "/api/v1/invite-requests",
                cookies,
                Some(&json!({})),
            ))
            .await;
        assert_eq!(code_of(json_reply(&r).0), Some("no_request_session"));
    }
    // A bearer header never stands in for the request cookie either.
    let mut r = spa_with(Method::Get, "/api/v1/invite-requests/mine", "", None);
    r.api.authorization = Some(format!("Bearer {request}"));
    assert_eq!(json_reply(&fx.call(r).await).0.status, 401);
}

#[wasm_bindgen_test]
async fn requester_post_needs_same_origin_and_json() {
    let (fx, _) = invite_fx().await;
    let request = fx.refused(205, "vera").await;
    let cookies = format!("{REQUEST_COOKIE}={request}");
    let mut r = spa_with(
        Method::Post,
        "/api/v1/invite-requests",
        &cookies,
        Some(&json!({"note": "x"})),
    );
    r.origin_header = Some("https://evil.com".into());
    assert_error(
        json_reply(&fx.call(r).await).0,
        403,
        "cross-origin request refused",
    );
    let mut r = spa_with(
        Method::Post,
        "/api/v1/invite-requests",
        &cookies,
        Some(&json!({"note": "x"})),
    );
    r.content_type = Some("text/plain".into());
    assert_eq!(json_reply(&fx.call(r).await).0.status, 415);
    assert_eq!(fx.store.invite_request_row(205), None);
}

#[wasm_bindgen_test]
async fn refused_user_files_a_request_through_the_console() {
    let (fx, session) = invite_fx().await;
    let request = fx.refused(206, "wade").await;
    let cookies = format!("{REQUEST_COOKIE}={request}");
    let r = fx
        .call(spa_with(
            Method::Get,
            "/api/v1/invite-requests/mine",
            &cookies,
            None,
        ))
        .await;
    let d = data(json_reply(&r).0).clone();
    assert_eq!(d["login"], "wade");
    assert_eq!(d["accepting"], true);
    assert_eq!(d["request"], Value::Null);
    let r = fx
        .call(spa_with(
            Method::Post,
            "/api/v1/invite-requests",
            &cookies,
            Some(&json!({"note": "signing for my project"})),
        ))
        .await;
    assert_eq!(json_reply(&r).0.status, 201, "{r:?}");
    let r = fx
        .call(spa_with(
            Method::Get,
            "/api/v1/invite-requests/mine",
            &cookies,
            None,
        ))
        .await;
    assert_eq!(data(json_reply(&r).0)["request"]["status"], "pending");
    // The operator sees it, and approving lets the next sign-in in.
    let ops = format!("{SESSION_COOKIE}={session}");
    let r = fx
        .call(spa_with(
            Method::Get,
            "/api/v1/ops/invite-requests",
            &ops,
            None,
        ))
        .await;
    let d = data(json_reply(&r).0).clone();
    assert_eq!(d["requests"][0]["note"], "signing for my project");
    let r = fx
        .call(spa_with(
            Method::Post,
            "/api/v1/ops/invite-requests/206/approve",
            &ops,
            Some(&json!({})),
        ))
        .await;
    assert_eq!(json_reply(&r).0.status, 204);
    let r = fx.sign_in_reply(206, "wade", "/").await;
    let (location, cookies) = redirect(&r);
    assert_eq!(location, "/?signed_in=1");
    assert!(cookies.iter().any(|c| clears(c, REQUEST_COOKIE)));
}
