#![cfg(target_arch = "wasm32")]
//! Request-level ordering and precedence: which token header wins, and what the login limiter
//! runs ahead of.

mod common;

use std::cell::RefCell;

use edgekms_worker::audit::Limit;
use edgekms_worker::vault::Reply;
use serde_json::json;
use wasm_bindgen_test::wasm_bindgen_test;
use worker::Method;

use common::*;

fn encrypt_req(
    vault_token: Option<&str>,
    authorization: Option<String>,
) -> edgekms_worker::handlers::ApiRequest {
    let mut r = req(
        Method::Put,
        "/v1/transit/encrypt/app",
        vault_token,
        &json!({ "plaintext": b64(b"x") }),
    );
    r.authorization = authorization;
    r
}

#[wasm_bindgen_test]
async fn x_vault_token_wins_over_authorization() {
    let h = Harness::new().await;
    let good = h.admin().await;

    // A good X-Vault-Token is used whatever Authorization holds.
    for auth in ["Bearer garbage", "Basic Zm9vOmJhcg==", ""] {
        let r = h
            .call(encrypt_req(Some(&good), Some(auth.to_owned())))
            .await;
        assert_eq!(r.status, 200, "Authorization {auth:?}: {r:?}");
    }

    // A bad X-Vault-Token is not rescued by a good bearer token: there is no fallback.
    let r = h
        .call(encrypt_req(Some("garbage"), Some(format!("Bearer {good}"))))
        .await;
    assert_error(&r, 403, "permission denied");

    // The control: the same bearer token alone is accepted.
    let r = h
        .call(encrypt_req(None, Some(format!("Bearer {good}"))))
        .await;
    assert_eq!(r.status, 200, "{r:?}");
}

#[wasm_bindgen_test]
async fn login_limiter_runs_before_the_jwks_fetch() {
    let mut h = Harness::new().await;
    let fx: serde_json::Value = serde_json::from_str(JWT_FIXTURES).unwrap();
    h.jwks = FakeJwks {
        normal: Some(fx["jwks"].clone()),
        forced: Some(fx["jwks"].clone()),
        calls: RefCell::default(),
    };
    h.limits.deny_login.set(true);
    let login = || {
        req(
            Method::Post,
            "/v1/auth/jwt-url/login",
            None,
            &json!({ "role": "ci-url", "jwt": jwt_case("valid_rs256") }),
        )
    };

    let r = h.call(login()).await;
    assert_error(
        &r,
        429,
        r#"request path "auth/jwt-url/login": rate limit quota exceeded"#,
    );
    assert!(h.jwks.calls.borrow().is_empty(), "{:?}", h.jwks.calls);
    assert_eq!(
        *h.limits.checks.borrow(),
        vec![(Limit::Login, TEST_IP.to_owned())]
    );

    // The control: with the limiter open, the same login fetches the JWKS once and succeeds.
    h.limits.deny_login.set(false);
    let r = h.call(login()).await;
    assert_eq!(r.status, 200, "{r:?}");
    assert_eq!(*h.jwks.calls.borrow(), vec![false]);
}

/// What every request refused for a missing `CF-Connecting-IP` must look like: the route's
/// ordinary refusal (`status` permission denied, never a `429` that Vault clients would retry),
/// no limiter consulted (there is no key to count it under), and a data point with
/// `no_client_ip` but nothing in the durable log.
#[track_caller]
fn assert_refused_without_ip(h: &Harness, r: &Reply, status: u16, op: &str) {
    assert_error(r, status, "permission denied");
    assert!(h.limits.checks.borrow().is_empty(), "{:?}", h.limits.checks);
    let ev = h.audit.only_metric();
    assert_eq!(ev["op"], op);
    assert_eq!(ev["result"], "denied");
    assert_eq!(ev["error"], "no_client_ip");
    assert!(ev.get("ip").is_none(), "{ev}");
}

#[wasm_bindgen_test]
async fn login_without_a_client_ip_is_refused_before_any_work() {
    let mut h = Harness::new().await;
    let fx: serde_json::Value = serde_json::from_str(JWT_FIXTURES).unwrap();
    h.jwks = FakeJwks {
        normal: Some(fx["jwks"].clone()),
        forced: Some(fx["jwks"].clone()),
        calls: RefCell::default(),
    };
    let mut login = req(
        Method::Post,
        "/v1/auth/jwt-url/login",
        None,
        &json!({ "role": "ci-url", "jwt": jwt_case("valid_rs256") }),
    );
    login.ip = None;
    let r = h.call(login).await;
    // The uniform login refusal.
    assert_refused_without_ip(&h, &r, 400, "login");
    assert!(h.jwks.calls.borrow().is_empty(), "{:?}", h.jwks.calls);
}

#[wasm_bindgen_test]
async fn login_on_an_unconfigured_mount_without_a_client_ip_is_403() {
    // As a login to a mount the config doesn't have always is.
    let h = Harness::new().await;
    let mut login = req(
        Method::Post,
        "/v1/auth/nope/login",
        None,
        &json!({ "role": "x", "jwt": "y" }),
    );
    login.ip = None;
    let r = h.call(login).await;
    assert_refused_without_ip(&h, &r, 403, "login");
}

#[wasm_bindgen_test]
async fn challenge_without_a_client_ip_is_refused() {
    let h = Harness::new().await;
    let mut challenge = req(Method::Post, "/v1/auth/ssh/challenge", None, &json!({}));
    challenge.ip = None;
    let r = h.call(challenge).await;
    assert_refused_without_ip(&h, &r, 403, "challenge");
}

#[wasm_bindgen_test]
async fn failed_authentication_without_a_client_ip_is_refused_not_shared() {
    let h = Harness::new().await;
    let mut bad = encrypt_req(Some("garbage"), None);
    bad.ip = None;
    let r = h.call(bad).await;
    assert_refused_without_ip(&h, &r, 403, "encrypt");
}

#[wasm_bindgen_test]
async fn a_valid_token_needs_no_client_ip() {
    // The token limit is keyed by token id, so an authenticated request has a key without the
    // IP and goes through.
    let h = Harness::new().await;
    let good = h.admin().await;
    let mut r = encrypt_req(Some(&good), None);
    r.ip = None;
    let reply = h.call(r).await;
    assert_eq!(reply.status, 200, "{reply:?}");
    assert_eq!(h.limits.checks.borrow().len(), 1);
    assert_eq!(h.limits.checks.borrow()[0].0, Limit::Token);
}
