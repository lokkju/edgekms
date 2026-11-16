#![cfg(target_arch = "wasm32")]
#![allow(clippy::unused_async_trait_impl)] // test doubles satisfy async traits without awaiting
//! Audit events and rate limits: what each operation records, what it never records, and that
//! a failed audit write fails the request.

mod common;

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use edgekms_core::keyops::{KeyOps, MacPurpose};
use edgekms_core::token::{self, TokenClaims};
use edgekms_worker::audit::metric_point;
use edgekms_worker::audit::{AuditEvent, Limit, object_key};
use serde_json::{Value, json};
use wasm_bindgen_test::wasm_bindgen_test;
use worker::Method;

use common::*;

const SECRET: &[u8] = b"correct horse battery staple";

async fn expected_mac(h: &Harness, ct: &str) -> String {
    URL_SAFE_NO_PAD.encode(
        h.st.ops
            .mac(MacPurpose::Audit, ct.as_bytes())
            .await
            .unwrap(),
    )
}

async fn jti_of(h: &Harness, tok: &str) -> String {
    token::check(&h.st.ops, tok, NOW).await.unwrap().jti
}

async fn decrypt(h: &Harness, tok: &str, ct: &str) -> edgekms_worker::vault::Reply {
    h.call(req(
        Method::Put,
        "/v1/transit/decrypt/app",
        Some(tok),
        &json!({ "ciphertext": ct }),
    ))
    .await
}

/// Asserts none of `secrets` occurs in the serialized event.
#[track_caller]
fn assert_absent(serialized: &str, secrets: &[&str]) {
    for s in secrets {
        assert!(s.len() >= 4, "{s:?} is too short to be a meaningful probe");
        assert!(!serialized.contains(s), "{s:?} leaked into {serialized}");
    }
}

#[wasm_bindgen_test]
async fn decrypt_emits_one_event_without_plaintext_or_ciphertext() {
    let h = Harness::new().await;
    let ct = encrypt(&h, &h.admin().await, SECRET).await;
    let tok = h.token("ci", &["app-decrypt"], 900, NOW).await;
    h.audit.clear();

    let r = decrypt(&h, &tok, &ct).await;
    assert_eq!(data(&r)["plaintext"], b64(SECRET));

    let (ev, text) = h.audit.only();
    assert_eq!(ev["op"], "decrypt");
    assert_eq!(ev["result"], "ok");
    assert_eq!(ev["key"], "app");
    assert_eq!(ev["version"], 3);
    assert_eq!(ev["role"], "ci");
    assert_eq!(ev["mount"], "jwt");
    assert_eq!(ev["jti"], jti_of(&h, &tok).await);
    assert_eq!(ev["ct_mac"], expected_mac(&h, &ct).await);
    assert_eq!(ev["ip"], TEST_IP);
    assert_eq!(ev["country"], "NZ");
    assert_eq!(ev["ts"], NOW * 1000);
    assert!(ev.get("error").is_none_or(Value::is_null), "{ev}");

    let body = ct.strip_prefix("vault:v3:").unwrap();
    let pt = std::str::from_utf8(SECRET).unwrap();
    assert_absent(&text, &[pt, &b64(SECRET), &ct, body, &tok]);
}

#[wasm_bindgen_test]
async fn encrypt_emits_one_event_without_plaintext_or_ciphertext() {
    let h = Harness::new().await;
    let tok = h.admin().await;
    let ct = encrypt(&h, &tok, SECRET).await;

    let (ev, text) = h.audit.only();
    assert_eq!(ev["op"], "encrypt");
    assert_eq!(ev["result"], "ok");
    assert_eq!(ev["key"], "app");
    assert_eq!(ev["version"], 3);
    assert_eq!(ev["role"], "op");
    assert_eq!(ev["mount"], "ssh");
    assert_eq!(ev["ct_mac"], expected_mac(&h, &ct).await);

    let body = ct.strip_prefix("vault:v3:").unwrap();
    let pt = std::str::from_utf8(SECRET).unwrap();
    assert_absent(&text, &[pt, &b64(SECRET), &ct, body, &tok]);
}

#[wasm_bindgen_test]
async fn rewrap_records_the_input_and_output_ciphertext_macs() {
    let h = Harness::new().await;
    let tok = h.admin().await;
    let ct = encrypt(&h, &tok, SECRET).await;
    h.audit.clear();
    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/rewrap/app",
            Some(&tok),
            &json!({ "ciphertext": ct }),
        ))
        .await;
    let new_ct = data(&r)["ciphertext"].as_str().unwrap().to_owned();
    let (ev, text) = h.audit.only();
    assert_eq!(ev["op"], "rewrap");
    assert_eq!(ev["result"], "ok");
    assert_eq!(ev["ct_mac"], expected_mac(&h, &ct).await);
    assert_eq!(ev["new_ct_mac"], expected_mac(&h, &new_ct).await);
    assert_absent(&text, &[&ct, &new_ct, &b64(SECRET), &tok]);
}

#[wasm_bindgen_test]
async fn ct_mac_is_base64url_of_the_audit_mac_of_a_known_ciphertext() {
    let h = Harness::new().await;
    let tok = h.admin().await;
    // Well-formed but not decryptable: the event still identifies which ciphertext was tried.
    let known = "vault:v3:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let r = decrypt(&h, &tok, known).await;
    assert_eq!(r.status, 400, "{r:?}");
    let (ev, text) = h.audit.only();
    let tag =
        h.st.ops
            .mac(MacPurpose::Audit, known.as_bytes())
            .await
            .unwrap();
    assert_eq!(ev["ct_mac"], URL_SAFE_NO_PAD.encode(tag));
    assert_eq!(ev["ct_mac"].as_str().unwrap().len(), 43);
    assert_eq!(ev["result"], "error");
    assert_absent(&text, &[known]);
}

#[wasm_bindgen_test]
async fn failed_login_is_denied_and_never_records_the_jwt() {
    let h = Harness::new().await;
    let jwt = jwt_case("wrong_issuer");
    let r = h
        .call(req(
            Method::Post,
            "/v1/auth/jwt/login",
            None,
            &json!({ "role": "ci", "jwt": jwt }),
        ))
        .await;
    assert_error(&r, 400, "permission denied");
    let (ev, text) = h.audit.only();
    assert_eq!(ev["op"], "login");
    assert_eq!(ev["result"], "denied");
    assert_eq!(ev["mount"], "jwt");
    assert_eq!(ev["role"], "ci");
    assert_eq!(ev["error"], "jwt_wrong_issuer");
    assert!(ev.get("jti").is_none_or(Value::is_null), "{ev}");
    let signature = jwt.rsplit('.').next().unwrap();
    assert_absent(&text, &[&jwt, signature]);
}

#[wasm_bindgen_test]
async fn login_failures_record_stable_codes() {
    let h = Harness::new().await;
    let cases = [
        ("ci", jwt_case("expired"), "jwt_expired"),
        ("ci", jwt_case("bad_signature"), "jwt_bad_signature"),
        ("ci", jwt_case("unknown_kid"), "jwt_unknown_kid"),
        ("ci", jwt_case("alg_none"), "jwt_unsupported_alg"),
        ("ci", "not.a.jwt".to_owned(), "jwt_malformed"),
        (
            "ci",
            jwt_case("numeric_repository_id"),
            "jwt_claims_mismatch",
        ),
        ("nope", jwt_case("valid_rs256"), "login_role_not_found"),
        // The signature is checked even for a role on another mount, so the failure is the
        // signature's, not the role's.
        ("op", jwt_case("bad_signature"), "jwt_bad_signature"),
    ];
    for (role, jwt, code) in cases {
        h.audit.clear();
        let r = h
            .call(req(
                Method::Post,
                "/v1/auth/jwt/login",
                None,
                &json!({ "role": role, "jwt": jwt }),
            ))
            .await;
        assert_error(&r, 400, "permission denied");
        let (ev, _) = h.audit.only();
        assert_eq!(ev["error"], code, "{role}: {ev}");
    }

    h.audit.clear();
    let r = h
        .call(req(
            Method::Post,
            "/v1/auth/ssh/login",
            None,
            &json!({ "role": "op", "challenge": "nope", "signature": "nope" }),
        ))
        .await;
    assert_error(&r, 400, "permission denied");
    assert_eq!(h.audit.only().0["error"], "ssh_challenge_malformed");
}

#[wasm_bindgen_test]
async fn login_for_an_unknown_role_records_no_role_name() {
    let h = Harness::new().await;
    let r = h
        .call(req(
            Method::Post,
            "/v1/auth/jwt/login",
            None,
            &json!({ "role": "no-such-role-xyzzy", "jwt": jwt_case("valid_rs256") }),
        ))
        .await;
    assert_error(&r, 400, "permission denied");
    let (ev, text) = h.audit.only();
    assert_eq!(ev["result"], "denied");
    assert_absent(&text, &["xyzzy"]);
}

#[wasm_bindgen_test]
async fn successful_login_records_the_new_accessor_and_allowlisted_claims() {
    let h = Harness::new().await;
    let jwt = jwt_case("valid_rs256");
    let r = h
        .call(req(
            Method::Post,
            "/v1/auth/jwt/login",
            None,
            &json!({ "role": "ci", "jwt": jwt }),
        ))
        .await;
    assert_eq!(r.status, 200, "{r:?}");
    let a = &r.body.as_ref().unwrap()["auth"];
    let (ev, text) = h.audit.only();
    assert_eq!(ev["op"], "login");
    assert_eq!(ev["result"], "ok");
    assert_eq!(ev["role"], "ci");
    assert_eq!(ev["mount"], "jwt");
    assert_eq!(ev["jti"], a["accessor"]);
    assert_eq!(ev["meta"]["sub"], "repo:o/r:ref:refs/heads/main");
    let client_token = a["client_token"].as_str().unwrap();
    assert_absent(&text, &[&jwt, client_token]);
}

#[wasm_bindgen_test]
async fn meta_outside_the_allowlist_is_dropped() {
    let h = Harness::new().await;
    let claims = TokenClaims {
        v: 1,
        jti: token::new_jti(&h.st.ops),
        role: "op".into(),
        policies: vec!["app-all".into()],
        iat: NOW,
        exp: NOW + 900,
        long: false,
        meta: BTreeMap::from([
            ("sub".to_owned(), "someone".to_owned()),
            ("display_name".to_owned(), "free text".to_owned()),
            ("created_by".to_owned(), "AAAAAAAAAAAAAAAAAAAAAA".to_owned()),
        ]),
    };
    let tok = token::mint(&h.st.ops, &claims).await.unwrap();
    encrypt(&h, &tok, b"x").await;
    let (ev, _) = h.audit.only();
    assert_eq!(ev["meta"], json!({ "sub": "someone" }));
}

#[wasm_bindgen_test]
async fn policy_denial_is_recorded_as_denied() {
    let h = Harness::new().await;
    let ct = encrypt(&h, &h.admin().await, SECRET).await;
    let tok = h.token("op", &["other-all"], 900, NOW).await;
    h.audit.clear();
    let r = decrypt(&h, &tok, &ct).await;
    assert_error(&r, 403, "permission denied");
    let (ev, _) = h.audit.only();
    assert_eq!(ev["op"], "decrypt");
    assert_eq!(ev["result"], "denied");
    assert_eq!(ev["jti"], jti_of(&h, &tok).await);
}

#[wasm_bindgen_test]
async fn missing_token_is_recorded_as_denied() {
    let h = Harness::new().await;
    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/encrypt/app",
            None,
            &json!({ "plaintext": b64(b"x") }),
        ))
        .await;
    assert_error(&r, 403, "permission denied");
    let (ev, _) = h.audit.only();
    assert_eq!(ev["result"], "denied");
}

#[wasm_bindgen_test]
async fn keys_read_and_token_admin_calls_are_audited() {
    let h = Harness::new().await;
    let admin = h.admin().await;
    let admin_jti = jti_of(&h, &admin).await;

    let r = h
        .call(req(
            Method::Get,
            "/v1/transit/keys/app",
            Some(&admin),
            &json!({}),
        ))
        .await;
    assert_eq!(r.status, 200);
    let (ev, _) = h.audit.only();
    assert_eq!(
        (ev["op"].as_str(), ev["key"].as_str()),
        (Some("keys_read"), Some("app"))
    );
    h.audit.clear();

    let r = h
        .call(req(
            Method::Post,
            "/v1/auth/token/create",
            Some(&admin),
            &json!({ "policies": ["app-all"], "ttl": "1h" }),
        ))
        .await;
    let created = r.body.as_ref().unwrap()["auth"]["client_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let accessor = r.body.as_ref().unwrap()["auth"]["accessor"].clone();
    let (ev, text) = h.audit.only();
    assert_eq!(ev["op"], "token_create");
    assert_eq!(ev["result"], "ok");
    assert_eq!(ev["jti"], admin_jti);
    assert_eq!(ev["target_jti"], accessor);
    assert_absent(&text, &[&created, &admin]);
    h.audit.clear();

    let r = h
        .call(req(
            Method::Post,
            "/v1/auth/token/revoke-accessor",
            Some(&admin),
            &json!({ "accessor": "AAAAAAAAAAAAAAAAAAAAAA" }),
        ))
        .await;
    assert_eq!(r.status, 204);
    let (ev, _) = h.audit.only();
    assert_eq!(ev["op"], "token_revoke");
    assert_eq!(ev["result"], "ok");
    assert_eq!(ev["target_jti"], "AAAAAAAAAAAAAAAAAAAAAA");
}

#[wasm_bindgen_test]
async fn malformed_revoke_accessor_is_not_recorded() {
    let h = Harness::new().await;
    let admin = h.admin().await;
    let r = h
        .call(req(
            Method::Post,
            "/v1/auth/token/revoke-accessor",
            Some(&admin),
            &json!({ "accessor": "not-an-accessor-xyzzy!" }),
        ))
        .await;
    assert_error(&r, 400, "invalid accessor");
    let (ev, text) = h.audit.only();
    assert!(ev.get("target_jti").is_none_or(Value::is_null), "{ev}");
    assert_absent(&text, &["xyzzy"]);
}

#[wasm_bindgen_test]
async fn revoked_token_use_records_its_id_and_role() {
    let h = Harness::new().await;
    let long = h.token("op", &["app-all"], 8_760 * 3600, NOW).await;
    let jti = jti_of(&h, &long).await;
    h.rev.0.borrow_mut().insert(jti.clone());
    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/encrypt/app",
            Some(&long),
            &json!({ "plaintext": b64(b"x") }),
        ))
        .await;
    assert_error(&r, 403, "permission denied");
    let (ev, text) = h.audit.only();
    assert_eq!(ev["result"], "denied");
    assert_eq!(ev["error"], "token_revoked");
    assert_eq!(ev["jti"], jti);
    assert_eq!(ev["role"], "op");
    assert_absent(&text, &[&long]);
}

#[wasm_bindgen_test]
async fn token_from_before_role_not_before_records_its_id_and_role() {
    let h = Harness::new().await;
    let stale = h.token("fresh", &["app-all"], 3600, NOW - 200).await;
    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/encrypt/app",
            Some(&stale),
            &json!({ "plaintext": b64(b"x") }),
        ))
        .await;
    assert_error(&r, 403, "permission denied");
    let (ev, _) = h.audit.only();
    assert_eq!(ev["result"], "denied");
    assert_eq!(ev["error"], "token_not_before");
    assert_eq!(ev["jti"], jti_of(&h, &stale).await);
    assert_eq!(ev["role"], "fresh");
}

#[wasm_bindgen_test]
async fn health_and_unknown_paths_are_not_audited() {
    let h = Harness::new().await;
    h.call(req(Method::Get, "/v1/sys/health", None, &json!({})))
        .await;
    h.call(req(Method::Get, "/v1/nope", None, &json!({}))).await;
    assert!(h.audit.events.borrow().is_empty());
}

// ---- fail closed ----

#[track_caller]
fn assert_audit_unavailable(r: &edgekms_worker::vault::Reply) {
    assert_error(r, 500, "audit log unavailable");
}

#[wasm_bindgen_test]
async fn audit_failure_is_visible_as_a_metric() {
    let h = Harness::new().await;
    let tok = h.admin().await;
    let ct = encrypt(&h, &tok, SECRET).await;
    h.audit.clear();
    h.audit.fail.set(true);
    let r = decrypt(&h, &tok, &ct).await;
    assert_audit_unavailable(&r);
    let ev = h.audit.only_metric();
    assert_eq!(ev["op"], "decrypt");
    assert_eq!(ev["result"], "error");
    assert_eq!(ev["error"], "audit_unavailable");
    assert_eq!(ev["key"], "app");
}

#[wasm_bindgen_test]
async fn denial_records_the_key_when_it_is_in_config() {
    let h = Harness::new().await;
    let ct = encrypt(&h, &h.admin().await, SECRET).await;
    h.audit.clear();
    let r = decrypt(&h, "garbage", &ct).await;
    assert_error(&r, 403, "permission denied");
    let (ev, _) = h.audit.only();
    assert_eq!(ev["result"], "denied");
    assert_eq!(ev["key"], "app");
    h.audit.clear();

    // A name that isn't in config is caller input, so it stays out of the event.
    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/decrypt/no-such-key-xyzzy",
            Some("garbage"),
            &json!({ "ciphertext": ct }),
        ))
        .await;
    assert_error(&r, 403, "permission denied");
    let (ev, text) = h.audit.only();
    assert!(ev.get("key").is_none(), "{ev}");
    assert_absent(&text, &["xyzzy"]);
}

#[wasm_bindgen_test]
async fn audit_failure_fails_closed() {
    let h = Harness::new().await;
    let tok = h.admin().await;
    let ct = encrypt(&h, &tok, SECRET).await;
    h.audit.fail.set(true);

    let r = decrypt(&h, &tok, &ct).await;
    assert_audit_unavailable(&r);
    let body = serde_json::to_string(&r.body).unwrap();
    assert!(!body.contains("plaintext"), "{body}");
    assert!(!body.contains(&b64(SECRET)), "{body}");

    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/encrypt/app",
            Some(&tok),
            &json!({ "plaintext": b64(SECRET) }),
        ))
        .await;
    assert_audit_unavailable(&r);
    assert!(!serde_json::to_string(&r.body).unwrap().contains("vault:"));

    let r = h
        .call(req(
            Method::Post,
            "/v1/auth/jwt/login",
            None,
            &json!({ "role": "ci", "jwt": jwt_case("valid_rs256") }),
        ))
        .await;
    assert_audit_unavailable(&r);
    assert!(
        !serde_json::to_string(&r.body)
            .unwrap()
            .contains("client_token")
    );

    // Failures are audited too, so an unwritable log turns them into 500 as well.
    let r = decrypt(&h, "garbage", &ct).await;
    assert_audit_unavailable(&r);
}

// ---- rate limits ----

#[wasm_bindgen_test]
async fn login_rate_limit_is_429_and_a_denied_event() {
    let h = Harness::new().await;
    h.limits.deny_login.set(true);
    let r = h
        .call(req(
            Method::Post,
            "/v1/auth/jwt/login",
            None,
            &json!({ "role": "ci", "jwt": jwt_case("valid_rs256") }),
        ))
        .await;
    assert_error(
        &r,
        429,
        r#"request path "auth/jwt/login": rate limit quota exceeded"#,
    );
    let ev = h.audit.only_metric();
    assert_eq!(ev["op"], "login");
    assert_eq!(ev["result"], "denied");
    assert_eq!(ev["error"], "rate_limited");
    assert_eq!(ev["mount"], "jwt");
    assert_eq!(
        *h.limits.checks.borrow(),
        vec![(Limit::Login, TEST_IP.to_owned())]
    );
    h.audit.clear();

    let r = h
        .call(req(
            Method::Post,
            "/v1/auth/ssh/challenge",
            None,
            &json!({}),
        ))
        .await;
    assert_error(
        &r,
        429,
        r#"request path "auth/ssh/challenge": rate limit quota exceeded"#,
    );
    assert_eq!(h.audit.only_metric()["error"], "rate_limited");
}

#[wasm_bindgen_test]
async fn token_rate_limit_is_429_keyed_by_token_id() {
    let h = Harness::new().await;
    let tok = h.admin().await;
    let ct = encrypt(&h, &tok, SECRET).await;
    h.audit.clear();
    h.limits.checks.borrow_mut().clear();
    h.limits.deny_token.set(true);

    let r = decrypt(&h, &tok, &ct).await;
    assert_error(
        &r,
        429,
        r#"request path "transit/decrypt/app": rate limit quota exceeded"#,
    );
    let jti = jti_of(&h, &tok).await;
    assert_eq!(*h.limits.checks.borrow(), vec![(Limit::Token, jti.clone())]);
    let ev = h.audit.only_metric();
    assert_eq!(ev["result"], "denied");
    assert_eq!(ev["error"], "rate_limited");
    assert_eq!(ev["jti"], jti);

    let r = h
        .call(req(
            Method::Get,
            "/v1/auth/token/lookup-self",
            Some(&tok),
            &json!({}),
        ))
        .await;
    assert_error(
        &r,
        429,
        r#"request path "auth/token/lookup-self": rate limit quota exceeded"#,
    );
}

#[wasm_bindgen_test]
async fn rate_limited_request_with_a_broken_audit_log_is_still_429() {
    // A 429 never touches the durable log, so a broken one can't turn it into a 500.
    let h = Harness::new().await;
    h.limits.deny_login.set(true);
    h.audit.fail.set(true);
    let r = h
        .call(req(
            Method::Post,
            "/v1/auth/ssh/challenge",
            None,
            &json!({}),
        ))
        .await;
    assert_error(
        &r,
        429,
        r#"request path "auth/ssh/challenge": rate limit quota exceeded"#,
    );
    assert_eq!(h.audit.only_metric()["error"], "rate_limited");
}

#[wasm_bindgen_test]
async fn rate_limit_message_quotes_the_path_as_go_does() {
    let h = Harness::new().await;
    h.limits.deny_login.set(true);
    let r = h
        .call(req(
            Method::Post,
            r#"/v1/auth/a"b\c/login"#,
            None,
            &json!({}),
        ))
        .await;
    assert_error(
        &r,
        429,
        r#"request path "auth/a\"b\\c/login": rate limit quota exceeded"#,
    );
}

#[wasm_bindgen_test]
async fn login_to_an_unconfigured_mount_is_only_a_metric() {
    let h = Harness::new().await;
    for path in ["/v1/auth/nope/login", "/v1/auth/nope/challenge"] {
        let r = h
            .call(req(
                Method::Post,
                path,
                None,
                &json!({ "role": "ci", "jwt": jwt_case("valid_rs256") }),
            ))
            .await;
        assert_error(&r, 403, "permission denied");
        let ev = h.audit.only_metric();
        assert_eq!(ev["result"], "error");
        assert_eq!(ev["error"], "not_found");
        assert!(ev.get("mount").is_none(), "{ev}");
        h.audit.clear();
    }

    // A challenge on a configured mount that isn't SSH is treated the same way.
    let r = h
        .call(req(
            Method::Post,
            "/v1/auth/jwt/challenge",
            None,
            &json!({}),
        ))
        .await;
    assert_error(&r, 403, "permission denied");
    let ev = h.audit.only_metric();
    assert_eq!(ev["error"], "not_found");
    h.audit.clear();

    // Unaffected by a broken durable log, since it never writes there.
    h.audit.fail.set(true);
    let r = h
        .call(req(Method::Post, "/v1/auth/nope/login", None, &json!({})))
        .await;
    assert_error(&r, 403, "permission denied");
}

#[wasm_bindgen_test]
async fn failed_authentication_under_the_limit_is_a_durable_record() {
    let h = Harness::new().await;
    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/encrypt/app",
            Some("garbage"),
            &json!({ "plaintext": b64(b"x") }),
        ))
        .await;
    assert_error(&r, 403, "permission denied");
    let (ev, _) = h.audit.only();
    assert_eq!(ev["result"], "denied");
    assert_ne!(ev["error"], "rate_limited");
    assert_eq!(h.audit.metrics.borrow().len(), 1);
}

#[wasm_bindgen_test]
async fn failed_authentication_is_limited_per_ip() {
    let h = Harness::new().await;
    let tok = h.admin().await;
    h.limits.auth_failure_budget.set(Some(3));
    let bad = |tok: Option<&'static str>| {
        req(
            Method::Put,
            "/v1/transit/encrypt/app",
            tok,
            &json!({ "plaintext": b64(b"x") }),
        )
    };
    for t in [Some("garbage"), None, Some("ekms.forged.token")] {
        assert_error(&h.call(bad(t)).await, 403, "permission denied");
    }
    h.audit.clear();
    let r = h.call(bad(Some("garbage"))).await;
    assert_error(
        &r,
        429,
        r#"request path "transit/encrypt/app": rate limit quota exceeded"#,
    );
    let ev = h.audit.only_metric();
    assert_eq!(ev["result"], "denied");
    assert_eq!(ev["error"], "rate_limited");
    assert!(
        h.limits
            .checks
            .borrow()
            .iter()
            .all(|c| *c == (Limit::AuthFailure, TEST_IP.to_owned()))
    );

    // A valid token is not charged against (or stopped by) the exhausted per-IP limit.
    h.limits.checks.borrow_mut().clear();
    let r = h.call(bad(None)).await;
    assert_eq!(r.status, 429);
    h.limits.checks.borrow_mut().clear();
    encrypt(&h, &tok, b"x").await;
    assert!(
        h.limits
            .checks
            .borrow()
            .iter()
            .all(|(l, _)| *l == Limit::Token)
    );
}

#[wasm_bindgen_test]
async fn unauthenticated_requests_are_charged_to_the_ip_not_a_token() {
    let h = Harness::new().await;
    h.call(req(
        Method::Put,
        "/v1/transit/encrypt/app",
        Some("garbage"),
        &json!({ "plaintext": b64(b"x") }),
    ))
    .await;
    assert_eq!(
        *h.limits.checks.borrow(),
        vec![(Limit::AuthFailure, TEST_IP.to_owned())]
    );
}

#[wasm_bindgen_test]
async fn failed_authentication_does_not_lock_the_ip_out_of_login() {
    // A client stuck with a broken token exhausts its failed-authentication budget, not the
    // login budget it needs to get a working token.
    let h = Harness::new().await;
    h.limits.deny_auth_failure.set(true);
    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/encrypt/app",
            Some("garbage"),
            &json!({ "plaintext": b64(b"x") }),
        ))
        .await;
    assert_eq!(r.status, 429);
    let r = h
        .call(req(
            Method::Post,
            "/v1/auth/jwt/login",
            None,
            &json!({ "role": "ci", "jwt": jwt_case("valid_rs256") }),
        ))
        .await;
    assert_eq!(r.status, 200, "{r:?}");
}

// ---- object keys ----

#[wasm_bindgen_test]
fn object_key_is_hourly_utc_with_the_token_id_and_a_random_suffix() {
    let ev = AuditEvent {
        ts: 2_000_000_000_123,
        jti: Some("AbCdEfGhIjKlMnOpQrStUv".into()),
        ..AuditEvent::new("decrypt")
    };
    assert_eq!(
        object_key(&ev, [0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3]),
        "audit/2033/05/18/03/2000000000123-AbCdEfGhIjKlMnOpQrStUv-deadbeef00010203.json"
    );
    let anon = AuditEvent {
        ts: 0,
        ..AuditEvent::new("login")
    };
    assert_eq!(
        object_key(&anon, [0xff; 8]),
        "audit/1970/01/01/00/0-ffffffffffffffff.json"
    );
}

#[wasm_bindgen_test]
fn audit_object_key_has_tenant_prefix() {
    let ev = AuditEvent {
        ts: 2_000_000_000_123,
        jti: Some("AbCdEfGhIjKlMnOpQrStUv".into()),
        tenant: Some("t_00000000000000ab".into()),
        ..AuditEvent::new("decrypt")
    };
    assert_eq!(
        object_key(&ev, [0; 8]),
        "audit/t_00000000000000ab/2033/05/18/03/2000000000123-AbCdEfGhIjKlMnOpQrStUv-0000000000000000.json"
    );
    // A control-plane event goes under control/, even when it acted on a tenant.
    for tenant in [None, Some("t_00000000000000ab".to_owned())] {
        let ev = AuditEvent {
            ts: 0,
            control: true,
            tenant,
            ..AuditEvent::new("tenant_export")
        };
        assert_eq!(
            object_key(&ev, [0xff; 8]),
            "control/1970/01/01/00/0-ffffffffffffffff.json"
        );
    }
}

// ---- metrics ----

#[wasm_bindgen_test]
fn single_tenant_metric_layout_is_unchanged() {
    let ev = AuditEvent {
        key: Some("app".into()),
        role: Some("ci".into()),
        mount: Some("jwt".into()),
        country: Some("NZ".into()),
        result: "denied",
        error: Some("rate_limited"),
        ..AuditEvent::new("decrypt")
    };
    let (index, blobs) = metric_point(&ev);
    assert_eq!(index, "decrypt");
    assert_eq!(
        blobs,
        [
            "decrypt",
            "denied",
            "app",
            "ci",
            "jwt",
            "NZ",
            "rate_limited"
        ]
    );
}

#[wasm_bindgen_test]
fn hosted_metric_is_indexed_and_tagged_by_tenant() {
    let ev = AuditEvent {
        result: "ok",
        tenant: Some("t_00000000000000ab".into()),
        ..AuditEvent::new("encrypt")
    };
    let (index, blobs) = metric_point(&ev);
    assert_eq!(index, "t_00000000000000ab");
    assert_eq!(
        blobs,
        ["encrypt", "ok", "", "", "", "", "", "t_00000000000000ab"]
    );
}
