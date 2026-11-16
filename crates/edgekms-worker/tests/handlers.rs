#![cfg(target_arch = "wasm32")]
#![allow(clippy::unused_async_trait_impl)] // test doubles satisfy async traits without awaiting
//! Handler tests over plain requests, using the harness in `common`.

mod common;

use edgekms_core::config::Config;
use edgekms_core::keyops::{KeyOps, MacPurpose};
use edgekms_core::token;
use edgekms_core::transit::{Ciphertext, Error, Id};
use edgekms_worker::auth::Revocations;
use edgekms_worker::github::{GithubApi, GithubError, GithubUser, LocalFuture};
use edgekms_worker::handlers::{Deps, handle};
use edgekms_worker::state::State;
use edgekms_worker::vault::Reply;
use edgekms_worker::webcrypto::WebCryptoKeyOps;
use serde_json::{Value, json};
use std::cell::RefCell;
use wasm_bindgen_test::wasm_bindgen_test;
use worker::Method;
use zeroize::Zeroizing;

use common::*;
// ---- transit ----

#[wasm_bindgen_test]
async fn encrypt_decrypt_round_trip_with_admin_token() {
    let h = Harness::new().await;
    let tok = h.admin().await;
    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/encrypt/app",
            Some(&tok),
            &json!({ "plaintext": b64(b"hello") }),
        ))
        .await;
    let d = data(&r);
    assert_eq!(d["key_version"], 3);
    let ct = d["ciphertext"].as_str().unwrap();
    assert!(ct.starts_with("vault:v3:"), "{ct}");

    let r = h
        .call(req(
            Method::Post,
            "/v1/transit/decrypt/app",
            Some(&tok),
            &json!({ "ciphertext": ct }),
        ))
        .await;
    assert_eq!(data(&r)["plaintext"], b64(b"hello"));
}

#[wasm_bindgen_test]
async fn authorization_bearer_header_is_accepted() {
    let h = Harness::new().await;
    let tok = h.admin().await;
    let mut r = req(
        Method::Put,
        "/v1/transit/encrypt/app",
        None,
        &json!({ "plaintext": b64(b"x") }),
    );
    r.authorization = Some(format!("Bearer {tok}"));
    assert_eq!(h.call(r).await.status, 200);
}

#[wasm_bindgen_test]
async fn decrypt_only_token_decrypts_but_cannot_encrypt() {
    let h = Harness::new().await;
    let ct = encrypt(&h, &h.admin().await, b"secret").await;
    let tok = h.token("ci", &["app-decrypt"], 900, NOW).await;
    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/decrypt/app",
            Some(&tok),
            &json!({ "ciphertext": ct }),
        ))
        .await;
    assert_eq!(data(&r)["plaintext"], b64(b"secret"));
    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/encrypt/app",
            Some(&tok),
            &json!({ "plaintext": b64(b"x") }),
        ))
        .await;
    assert_error(&r, 403, "permission denied");
}

#[wasm_bindgen_test]
async fn policy_for_another_key_grants_nothing_here() {
    let h = Harness::new().await;
    let ct = encrypt(&h, &h.admin().await, b"secret").await;
    let tok = h.token("op", &["other-all"], 900, NOW).await;
    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/decrypt/app",
            Some(&tok),
            &json!({ "ciphertext": ct }),
        ))
        .await;
    assert_error(&r, 403, "permission denied");
}

#[wasm_bindgen_test]
async fn encrypt_key_version_below_min_decryption_version_is_too_old() {
    let h = Harness::new().await;
    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/encrypt/app",
            Some(&h.admin().await),
            &json!({ "plaintext": b64(b"x"), "key_version": 1 }),
        ))
        .await;
    assert_error(
        &r,
        400,
        "ciphertext or signature version is disallowed by policy (too old)",
    );
}

#[wasm_bindgen_test]
async fn encrypt_key_version_above_latest_is_refused() {
    let h = Harness::new().await;
    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/encrypt/app",
            Some(&h.admin().await),
            &json!({ "plaintext": b64(b"x"), "key_version": 4 }),
        ))
        .await;
    assert_error(
        &r,
        400,
        "requested version for encryption is higher than the latest key version",
    );
}

#[wasm_bindgen_test]
async fn encrypt_with_explicit_key_version_labels_ciphertext() {
    let h = Harness::new().await;
    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/encrypt/app",
            Some(&h.admin().await),
            &json!({ "plaintext": b64(b"x"), "key_version": 2 }),
        ))
        .await;
    assert_eq!(data(&r)["key_version"], 2);
    assert!(
        data(&r)["ciphertext"]
            .as_str()
            .unwrap()
            .starts_with("vault:v2:")
    );
}

#[wasm_bindgen_test]
async fn encrypt_key_version_may_be_a_numeric_string() {
    // Vault decodes request fields weakly, so `"key_version": "2"` is version 2.
    let h = Harness::new().await;
    let tok = h.admin().await;
    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/encrypt/app",
            Some(&tok),
            &json!({ "plaintext": b64(b"x"), "key_version": "2" }),
        ))
        .await;
    assert_eq!(data(&r)["key_version"], 2);
    // Weak decoding also reads an empty string as 0, which means the latest version.
    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/encrypt/app",
            Some(&tok),
            &json!({ "plaintext": b64(b"x"), "key_version": "" }),
        ))
        .await;
    assert_eq!(data(&r)["key_version"], 3);
    for bad in [json!("two"), json!("-1"), json!("1.5"), json!(true)] {
        let r = h
            .call(req(
                Method::Put,
                "/v1/transit/encrypt/app",
                Some(&tok),
                &json!({ "plaintext": b64(b"x"), "key_version": bad }),
            ))
            .await;
        assert_error(&r, 400, "key_version must be a non-negative integer");
    }
}

/// A ciphertext labelled with `version`, made directly with the key ops so the handler's own
/// version checks are what's under test.
async fn ciphertext_at(h: &Harness, version: u32) -> String {
    h.st.ops
        .encrypt(&Id::new("k_app").unwrap(), version, b"old")
        .await
        .unwrap()
}

#[wasm_bindgen_test]
async fn decrypt_version_below_min_decryption_version_is_too_old() {
    let h = Harness::new().await;
    let ct = ciphertext_at(&h, 1).await;
    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/decrypt/app",
            Some(&h.admin().await),
            &json!({ "ciphertext": ct }),
        ))
        .await;
    assert_error(
        &r,
        400,
        "ciphertext or signature version is disallowed by policy (too old)",
    );
}

#[wasm_bindgen_test]
async fn decrypt_version_above_latest_is_too_new() {
    let h = Harness::new().await;
    let ct = ciphertext_at(&h, 4).await;
    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/decrypt/app",
            Some(&h.admin().await),
            &json!({ "ciphertext": ct }),
        ))
        .await;
    assert_error(&r, 400, "invalid ciphertext: version is too new");
}

#[wasm_bindgen_test]
async fn decrypt_malformed_ciphertext_is_400() {
    let h = Harness::new().await;
    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/decrypt/app",
            Some(&h.admin().await),
            &json!({ "ciphertext": "vault:v1:not base64!" }),
        ))
        .await;
    assert_error(&r, 400, "invalid ciphertext");
}

#[wasm_bindgen_test]
async fn decrypt_tampered_ciphertext_is_vaults_auth_failure() {
    let h = Harness::new().await;
    let ct: Ciphertext = encrypt(&h, &h.admin().await, b"secret")
        .await
        .parse()
        .unwrap();
    let mut sealed = ct.sealed().to_vec();
    sealed[0] ^= 1;
    let bad = Ciphertext::from_parts(ct.version(), ct.nonce(), &sealed)
        .unwrap()
        .to_string();
    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/decrypt/app",
            Some(&h.admin().await),
            &json!({ "ciphertext": bad }),
        ))
        .await;
    assert_error(&r, 400, "cipher: message authentication failed");
}

#[wasm_bindgen_test]
async fn ciphertext_of_another_key_does_not_decrypt() {
    let h = Harness::new().await;
    let ct =
        h.st.ops
            .encrypt(&Id::new("k_other").unwrap(), 3, b"x")
            .await
            .unwrap();
    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/decrypt/app",
            Some(&h.admin().await),
            &json!({ "ciphertext": ct }),
        ))
        .await;
    assert_error(&r, 400, "cipher: message authentication failed");
}

/// The policy is checked before the key is looked up, as Vault does, so a token learns nothing
/// about a key it has no grant on: an unknown key and a known one it can't use are the same 403.
/// A policy can only name a key in config, so no grant ever reaches a missing key.
#[wasm_bindgen_test]
async fn unknown_key_is_the_same_403_as_a_key_without_a_grant() {
    let h = Harness::new().await;
    let tok = h.admin().await;
    for op in ["encrypt", "decrypt", "rewrap"] {
        for key in ["nope", "other"] {
            let r = h
                .call(req(
                    Method::Put,
                    &format!("/v1/transit/{op}/{key}"),
                    Some(&tok),
                    &json!({ "plaintext": b64(b"x"), "ciphertext": "vault:v1:AAAA" }),
                ))
                .await;
            assert_error(&r, 403, "permission denied");
        }
    }
    for key in ["nope", "other"] {
        let r = h
            .call(req(
                Method::Get,
                &format!("/v1/transit/keys/{key}"),
                Some(&tok),
                &json!({}),
            ))
            .await;
        assert_error(&r, 403, "permission denied");
    }
    // With a grant, the key is found.
    let r = h
        .call(req(
            Method::Get,
            "/v1/transit/keys/app",
            Some(&tok),
            &json!({}),
        ))
        .await;
    assert_eq!(data(&r)["name"], "app");
}

#[wasm_bindgen_test]
async fn unsupported_transit_fields_are_400_naming_the_field() {
    let h = Harness::new().await;
    let tok = h.admin().await;
    for field in [
        "context",
        "batch_input",
        "associated_data",
        "convergent_encryption",
        "nonce",
    ] {
        for op in ["encrypt", "decrypt", "rewrap"] {
            let mut body = json!({ "plaintext": b64(b"x"), "ciphertext": "vault:v3:AAAA" });
            body[field] = json!("x");
            let r = h
                .call(req(
                    Method::Put,
                    &format!("/v1/transit/{op}/app"),
                    Some(&tok),
                    &body,
                ))
                .await;
            assert_eq!(r.status, 400, "{op} {field}");
            assert!(errors(&r)[0].contains(field), "{op} {field}: {r:?}");
        }
    }
}

#[wasm_bindgen_test]
async fn empty_unsupported_fields_are_ignored_as_vault_ignores_them() {
    // Some clients always send `"context": ""` and the like; for a key that isn't derived or
    // convergent, Vault treats an empty value as absent, and so does edgekms.
    let h = Harness::new().await;
    let tok = h.admin().await;
    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/encrypt/app",
            Some(&tok),
            &json!({
                "plaintext": b64(b"x"),
                "context": "",
                "nonce": "",
                "associated_data": "",
                "batch_input": null,
                "convergent_encryption": false,
            }),
        ))
        .await;
    let ct = data(&r)["ciphertext"].as_str().unwrap().to_owned();
    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/decrypt/app",
            Some(&tok),
            &json!({ "ciphertext": ct, "context": "" }),
        ))
        .await;
    assert_eq!(data(&r)["plaintext"], b64(b"x"));
}

#[wasm_bindgen_test]
async fn missing_or_bad_plaintext_is_400() {
    let h = Harness::new().await;
    let tok = h.admin().await;
    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/encrypt/app",
            Some(&tok),
            &json!({}),
        ))
        .await;
    assert_error(&r, 400, "missing plaintext to encrypt");
    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/encrypt/app",
            Some(&tok),
            &json!({ "plaintext": "%%%" }),
        ))
        .await;
    assert_error(&r, 400, "failed to base64-decode plaintext");
    let r = h
        .call(raw(
            Method::Put,
            "/v1/transit/encrypt/app",
            Some(&tok),
            b"not json".to_vec(),
        ))
        .await;
    assert_error(&r, 400, "failed to parse JSON input");
}

#[wasm_bindgen_test]
async fn body_over_64_kib_is_413() {
    let h = Harness::new().await;
    let r = h
        .call(raw(
            Method::Put,
            "/v1/transit/encrypt/app",
            Some(&h.admin().await),
            vec![b' '; 65_537],
        ))
        .await;
    // OpenBao's body for its own cap (Go's `http.MaxBytesReader` error).
    assert_error(&r, 413, "http: request body too large");
}

#[wasm_bindgen_test]
async fn oversized_body_outside_v1_is_still_a_bare_404() {
    let h = Harness::new().await;
    let r = h
        .call(raw(Method::Put, "/robots.txt", None, vec![b' '; 65_537]))
        .await;
    assert_eq!(r, Reply::bare_404());
}

#[wasm_bindgen_test]
fn before_body_answers_outside_v1_and_oversized_declarations() {
    use edgekms_worker::handlers::before_body;
    assert_eq!(
        before_body("/robots.txt", Some(1 << 30)),
        Some(Reply::bare_404())
    );
    assert_eq!(before_body("/", None), Some(Reply::bare_404()));
    let r = before_body("/v1/nope", Some(65_537)).unwrap();
    assert_error(&r, 413, "http: request body too large");
    assert_eq!(before_body("/v1/nope", Some(65_536)), None);
    assert_eq!(before_body("/v1/nope", None), None);
}

#[wasm_bindgen_test]
async fn rewrap_moves_ciphertext_to_latest_version() {
    let h = Harness::new().await;
    let tok = h.admin().await;
    let old = ciphertext_at(&h, 2).await;
    let r = h
        .call(req(
            Method::Post,
            "/v1/transit/rewrap/app",
            Some(&tok),
            &json!({ "ciphertext": old }),
        ))
        .await;
    let d = data(&r);
    assert_eq!(d["key_version"], 3);
    let new = d["ciphertext"].as_str().unwrap();
    assert!(new.starts_with("vault:v3:"));
    assert!(d.get("plaintext").is_none());
    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/decrypt/app",
            Some(&tok),
            &json!({ "ciphertext": new }),
        ))
        .await;
    assert_eq!(data(&r)["plaintext"], b64(b"old"));
}

#[wasm_bindgen_test]
async fn rewrap_needs_rewrap_capability() {
    let h = Harness::new().await;
    let old = ciphertext_at(&h, 2).await;
    let tok = h.token("op", &["seal"], 900, NOW).await;
    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/rewrap/app",
            Some(&tok),
            &json!({ "ciphertext": old }),
        ))
        .await;
    assert_error(&r, 403, "permission denied");
}

#[wasm_bindgen_test]
async fn key_metadata_has_vaults_shape_and_no_key_material() {
    let h = Harness::new().await;
    let r = h
        .call(req(
            Method::Get,
            "/v1/transit/keys/app",
            Some(&h.admin().await),
            &json!({}),
        ))
        .await;
    assert_eq!(
        *data(&r),
        json!({
            "name": "app",
            "type": "aes256-gcm96",
            "latest_version": 3,
            "min_decryption_version": 2,
            "min_encryption_version": 0,
            "deletion_allowed": false,
            "exportable": false,
            "supports_encryption": true,
            "supports_decryption": true,
            "supports_derivation": false,
            "keys": { "2": 0, "3": 0 }
        })
    );
}

#[wasm_bindgen_test]
async fn key_metadata_needs_read_capability() {
    let h = Harness::new().await;
    let tok = h.token("op", &["seal"], 900, NOW).await;
    let r = h
        .call(req(
            Method::Get,
            "/v1/transit/keys/app",
            Some(&tok),
            &json!({}),
        ))
        .await;
    assert_error(&r, 403, "permission denied");
}

// ---- routing ----

#[wasm_bindgen_test]
async fn wrong_method_on_known_path_is_405() {
    let h = Harness::new().await;
    let tok = h.admin().await;
    for (m, p) in [
        (Method::Get, "/v1/transit/encrypt/app"),
        (Method::Delete, "/v1/transit/decrypt/app"),
        (Method::Put, "/v1/transit/keys/app"),
    ] {
        let r = h.call(req(m, p, Some(&tok), &json!({}))).await;
        assert_error(&r, 403, "permission denied");
    }
    // OpenBao: any method but GET and HEAD on /v1/sys/health is 405 `{"errors":[]}`, with or
    // without a token.
    for (m, t) in [
        (Method::Post, Some(tok.as_str())),
        (Method::Delete, None),
        (Method::Put, None),
    ] {
        let r = h.call(req(m, "/v1/sys/health", t, &json!({}))).await;
        assert_eq!(r.status, 405, "{r:?}");
        assert_eq!(r.body, Some(json!({ "errors": [] })));
    }
}

#[wasm_bindgen_test]
async fn unknown_v1_path_is_vaults_403() {
    let h = Harness::new().await;
    for p in [
        "/v1/transit/encrypt",
        "/v1/transit/encrypt/app/extra",
        "/v1/transit/export/encryption-key/app",
        "/v1/sys/seal",
        "/v1/nope",
    ] {
        let r = h
            .call(req(Method::Put, p, Some(&h.admin().await), &json!({})))
            .await;
        assert_error(&r, 403, "permission denied");
    }
}

#[wasm_bindgen_test]
async fn paths_outside_v1_are_a_bare_404() {
    let h = Harness::new().await;
    for p in [
        "/",
        "/robots.txt",
        "/favicon.ico",
        "/transit/encrypt/app",
        "/v1",
    ] {
        let r = h.call(req(Method::Get, p, None, &json!({}))).await;
        assert_eq!(r.status, 404, "{p}: {r:?}");
        assert_eq!(r.body, None, "{p}");
        assert!(
            h.audit.events.borrow().is_empty() && h.audit.metrics.borrow().is_empty(),
            "{p}"
        );
    }
}

#[wasm_bindgen_test]
async fn health_needs_no_token() {
    let h = Harness::new().await;
    let r = h
        .call(req(Method::Get, "/v1/sys/health", None, &json!({})))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body.as_ref().unwrap()["sealed"], false);
}

#[wasm_bindgen_test]
async fn head_on_health_is_200_without_a_body() {
    // OpenBao answers HEAD /v1/sys/health with GET's status and headers, and no body.
    let h = Harness::new().await;
    let r = h
        .call(raw(Method::Head, "/v1/sys/health", None, vec![]))
        .await;
    assert_eq!(r.status, 200, "{r:?}");
    assert_eq!(r.body, None);
    assert_eq!(r.body_bytes(), None);
    assert!(r.headers().contains(&("Content-Type", "application/json")));
}

// ---- wire format ----

#[wasm_bindgen_test]
fn json_bodies_end_with_a_newline_as_gos_encoder_writes_them() {
    // Byte for byte what OpenBao 2.7 sends (`curl -s | xxd`).
    assert_eq!(
        Reply::denied().body_bytes().unwrap().as_slice(),
        b"{\"errors\":[\"permission denied\"]}\n"
    );
    assert_eq!(
        Reply::method_not_allowed().body_bytes().unwrap().as_slice(),
        b"{\"errors\":[]}\n"
    );
    assert_eq!(
        Reply::too_large().body_bytes().unwrap().as_slice(),
        b"{\"errors\":[\"http: request body too large\"]}\n"
    );
    assert_eq!(Reply::bare_404().body_bytes(), None);
    assert_eq!(Reply::no_content().body_bytes(), None);
}

#[wasm_bindgen_test]
fn json_bodies_escape_html_characters_as_gos_encoder_does() {
    let r = Reply::error(400, "a<b>&c\u{2028}\u{2029}");
    assert_eq!(
        String::from_utf8(r.body_bytes().unwrap().to_vec()).unwrap(),
        "{\"errors\":[\"a\\u003cb\\u003e\\u0026c\\u2028\\u2029\"]}\n"
    );
}

#[wasm_bindgen_test]
fn responses_carry_openbaos_headers_except_the_bare_404() {
    for r in [Reply::denied(), Reply::no_content(), Reply::data(json!({}))] {
        let headers = r.headers();
        assert!(
            headers.contains(&("Content-Type", "application/json")),
            "{r:?}"
        );
        assert!(headers.contains(&("Cache-Control", "no-store")), "{r:?}");
    }
    let bare = Reply::bare_404().headers();
    assert!(
        bare.iter().all(|(name, _)| *name != "Content-Type"),
        "{bare:?}"
    );
}

#[wasm_bindgen_test]
async fn into_response_sends_those_bytes_and_headers() {
    let mut resp = Reply::denied().into_response().unwrap();
    assert_eq!(resp.status_code(), 403);
    let h = resp.headers();
    assert_eq!(
        h.get("Content-Type").unwrap().as_deref(),
        Some("application/json")
    );
    assert_eq!(h.get("Cache-Control").unwrap().as_deref(), Some("no-store"));
    assert_eq!(
        resp.bytes().await.unwrap(),
        b"{\"errors\":[\"permission denied\"]}\n"
    );

    let mut bare = Reply::bare_404().into_response().unwrap();
    assert_eq!(bare.status_code(), 404);
    assert_eq!(bare.headers().get("Content-Type").unwrap(), None);
    assert_eq!(bare.bytes().await.unwrap(), Vec::<u8>::new());
}

// ---- authentication ----

#[wasm_bindgen_test]
async fn missing_token_is_403() {
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
}

#[wasm_bindgen_test]
async fn forged_expired_and_garbage_tokens_are_403() {
    let h = Harness::new().await;
    let good = h.admin().await;
    let mut forged = good.clone().into_bytes();
    let last = forged.len() - 1;
    forged[last] = if forged[last] == b'A' { b'B' } else { b'A' };
    let expired = h.token("op", &["app-all"], 60, NOW - 61).await;
    for tok in [
        String::from_utf8(forged).unwrap(),
        expired,
        "garbage".into(),
        String::new(),
    ] {
        let r = h
            .call(req(
                Method::Put,
                "/v1/transit/encrypt/app",
                Some(&tok),
                &json!({ "plaintext": b64(b"x") }),
            ))
            .await;
        assert_error(&r, 403, "permission denied");
    }
}

#[wasm_bindgen_test]
async fn oversized_token_is_403_before_any_mac_work() {
    // MAC calls on this backend panic, so reaching one fails the test.
    let h = Harness {
        st: State::new(
            Config::from_json(&config_json().to_string()).unwrap(),
            PanicOps,
        )
        .unwrap(),
        rev: MemRevocations::default(),
        jwks: FakeJwks::default(),
        audit: MemAudit::default(),
        limits: MemLimits::default(),
        now: NOW,
    };
    // Well-formed (payload and a 32-byte tag), so only the length check stops it before MAC.
    let tok = format!("ekms.{}.{}", "A".repeat(4048), "A".repeat(43));
    assert_eq!(tok.len(), 4097);
    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/encrypt/app",
            Some(&tok),
            &json!({ "plaintext": b64(b"x") }),
        ))
        .await;
    assert_error(&r, 403, "permission denied");
}

#[wasm_bindgen_test]
async fn token_issued_before_role_not_before_is_refused() {
    let h = Harness::new().await;
    let stale = h.token("fresh", &["app-all"], 3600, NOW - 101).await;
    let ok = h.token("fresh", &["app-all"], 3600, NOW - 100).await;
    let body = json!({ "plaintext": b64(b"x") });
    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/encrypt/app",
            Some(&stale),
            &body,
        ))
        .await;
    assert_error(&r, 403, "permission denied");
    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/encrypt/app",
            Some(&ok),
            &body,
        ))
        .await;
    assert_eq!(r.status, 200);
}

#[wasm_bindgen_test]
async fn token_for_a_role_no_longer_in_config_is_refused() {
    let h = Harness::new().await;
    let tok = h.token("gone", &["app-all"], 3600, NOW).await;
    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/encrypt/app",
            Some(&tok),
            &json!({ "plaintext": b64(b"x") }),
        ))
        .await;
    assert_error(&r, 403, "permission denied");
}

#[wasm_bindgen_test]
async fn long_token_with_unreadable_revocation_list_is_refused() {
    struct Down;
    impl Revocations for Down {
        async fn is_revoked(&self, _: &str) -> worker::Result<bool> {
            Err(worker::Error::RustError("kv down".into()))
        }
        async fn revoke(&self, _: &str, _: u64) -> worker::Result<()> {
            Err(worker::Error::RustError("kv down".into()))
        }
    }
    let h = Harness::new().await;
    let long = h.token("op", &["app-all"], 8_760 * 3600, NOW).await;
    let r = h
        .call_with(
            &Down,
            req(
                Method::Put,
                "/v1/transit/encrypt/app",
                Some(&long),
                &json!({ "plaintext": b64(b"x") }),
            ),
        )
        .await;
    assert_error(&r, 403, "permission denied");
}

// ---- backend failures ----

/// Real MACs (so tokens check) but every cipher operation fails as the backend would.
struct BrokenCipher(WebCryptoKeyOps);

impl KeyOps for BrokenCipher {
    async fn encrypt(&self, _: &Id, _: u32, _: &[u8]) -> Result<String, Error> {
        Err(Error::Backend("encrypt"))
    }
    async fn decrypt(&self, _: &Id, _: &Ciphertext) -> Result<Zeroizing<Vec<u8>>, Error> {
        Err(Error::Backend("key derivation"))
    }
    async fn mac(&self, p: MacPurpose, d: &[u8]) -> Result<[u8; 32], Error> {
        self.0.mac(p, d).await
    }
    async fn verify_mac(&self, p: MacPurpose, d: &[u8], t: &[u8]) -> Result<bool, Error> {
        self.0.verify_mac(p, d, t).await
    }
    fn random(&self, out: &mut [u8]) {
        self.0.random(out);
    }
}

/// Panics on any secret-key operation.
struct PanicOps;

impl KeyOps for PanicOps {
    async fn encrypt(&self, _: &Id, _: u32, _: &[u8]) -> Result<String, Error> {
        panic!("encrypt reached")
    }
    async fn decrypt(&self, _: &Id, _: &Ciphertext) -> Result<Zeroizing<Vec<u8>>, Error> {
        panic!("decrypt reached")
    }
    async fn mac(&self, _: MacPurpose, _: &[u8]) -> Result<[u8; 32], Error> {
        panic!("mac reached")
    }
    async fn verify_mac(&self, _: MacPurpose, _: &[u8], _: &[u8]) -> Result<bool, Error> {
        panic!("verify_mac reached")
    }
    fn random(&self, out: &mut [u8]) {
        out.fill(0);
    }
}

#[wasm_bindgen_test]
async fn backend_failure_is_500_without_detail() {
    let good = Harness::new().await;
    let tok = good.admin().await;
    let ct = encrypt(&good, &tok, b"secret").await;
    let h = Harness {
        st: State::new(
            Config::from_json(&config_json().to_string()).unwrap(),
            BrokenCipher(web_ops().await),
        )
        .unwrap(),
        rev: MemRevocations::default(),
        jwks: FakeJwks::default(),
        audit: MemAudit::default(),
        limits: MemLimits::default(),
        now: NOW,
    };
    for (op, body) in [
        ("encrypt", json!({ "plaintext": b64(b"x") })),
        ("decrypt", json!({ "ciphertext": ct })),
        ("rewrap", json!({ "ciphertext": ct })),
    ] {
        let r = h
            .call(req(
                Method::Put,
                &format!("/v1/transit/{op}/app"),
                Some(&tok),
                &body,
            ))
            .await;
        assert_error(&r, 500, "internal error");
        let events = h.audit.values();
        assert_eq!(events.last().unwrap()["error"], "key_backend", "{op}");
    }
}

/// Real MACs, but decrypt reports a key id the backend refuses (a config the loader should
/// never let through).
struct BadIdCipher(WebCryptoKeyOps);

impl KeyOps for BadIdCipher {
    async fn encrypt(&self, k: &Id, v: u32, p: &[u8]) -> Result<String, Error> {
        self.0.encrypt(k, v, p).await
    }
    async fn decrypt(&self, _: &Id, _: &Ciphertext) -> Result<Zeroizing<Vec<u8>>, Error> {
        Err(Error::InvalidId("K/1".into()))
    }
    async fn mac(&self, p: MacPurpose, d: &[u8]) -> Result<[u8; 32], Error> {
        self.0.mac(p, d).await
    }
    async fn verify_mac(&self, p: MacPurpose, d: &[u8], t: &[u8]) -> Result<bool, Error> {
        self.0.verify_mac(p, d, t).await
    }
    fn random(&self, out: &mut [u8]) {
        self.0.random(out);
    }
}

#[wasm_bindgen_test]
async fn invalid_key_id_on_decrypt_is_a_recorded_500() {
    let good = Harness::new().await;
    let tok = good.admin().await;
    let ct = encrypt(&good, &tok, b"secret").await;
    let h = Harness {
        st: State::new(
            Config::from_json(&config_json().to_string()).unwrap(),
            BadIdCipher(web_ops().await),
        )
        .unwrap(),
        rev: MemRevocations::default(),
        jwks: FakeJwks::default(),
        audit: MemAudit::default(),
        limits: MemLimits::default(),
        now: NOW,
    };
    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/decrypt/app",
            Some(&tok),
            &json!({ "ciphertext": ct }),
        ))
        .await;
    assert_error(&r, 500, "internal error");
    let (ev, text) = h.audit.only();
    assert_eq!(ev["result"], "error");
    assert_eq!(ev["error"], "key_id_invalid");
    assert!(!text.contains("K/1"), "{text}");
}

// ---- JWT login ----

fn fixture_jwks() -> Value {
    let fx: Value = serde_json::from_str(JWT_FIXTURES).unwrap();
    fx["jwks"].clone()
}

async fn jwt_login(h: &Harness, mount: &str, role: &str, jwt: &str) -> Reply {
    h.call(req(
        Method::Post,
        &format!("/v1/auth/{mount}/login"),
        None,
        &json!({ "role": role, "jwt": jwt }),
    ))
    .await
}

fn auth(r: &Reply) -> &Value {
    assert_eq!(r.status, 200, "{r:?}");
    &r.body.as_ref().unwrap()["auth"]
}

#[wasm_bindgen_test]
async fn jwt_login_with_pinned_jwks_returns_a_working_token() {
    let h = Harness::new().await;
    for case in ["valid_rs256", "valid_es256"] {
        let r = jwt_login(&h, "jwt", "ci", &jwt_case(case)).await;
        let a = auth(&r);
        let tok = a["client_token"].as_str().unwrap();
        assert!(tok.starts_with("ekms."), "{case}");
        assert_eq!(a["policies"], json!(["app-decrypt"]));
        assert_eq!(a["token_policies"], json!(["app-decrypt"]));
        assert_eq!(a["lease_duration"], 900);
        assert_eq!(a["renewable"], false);
        assert_eq!(a["metadata"], json!({ "role": "ci" }));
        assert_eq!(a["accessor"].as_str().unwrap().len(), 22);

        let claims = token::check(&h.st.ops, tok, NOW).await.unwrap();
        assert_eq!(claims.jti, a["accessor"].as_str().unwrap());
        assert_eq!(claims.role, "ci");
        assert!(!claims.long);
        assert_eq!(claims.exp, NOW + 900);
        assert_eq!(claims.meta["sub"], "repo:o/r:ref:refs/heads/main");
        assert_eq!(claims.meta["ref"], "refs/heads/main");

        let ct = encrypt(&h, &h.admin().await, b"ci").await;
        let r = h
            .call(req(
                Method::Put,
                "/v1/transit/decrypt/app",
                Some(tok),
                &json!({ "ciphertext": ct }),
            ))
            .await;
        assert_eq!(data(&r)["plaintext"], b64(b"ci"), "{case}");
    }
}

#[wasm_bindgen_test]
async fn jwt_login_failures_are_one_identical_400() {
    let h = Harness::new().await;
    let cases = [
        ("jwt", "ci", jwt_case("wrong_issuer")),
        ("jwt", "ci", jwt_case("expired")),
        ("jwt", "ci", jwt_case("bad_signature")),
        ("jwt", "ci", jwt_case("signed_by_other_key")),
        ("jwt", "ci", jwt_case("alg_none")),
        ("jwt", "ci", jwt_case("hs256_with_public_key")),
        ("jwt", "ci", jwt_case("rs256_header_ec_key")),
        ("jwt", "ci", jwt_case("unknown_kid")),
        ("jwt", "ci", jwt_case("numeric_repository_id")),
        ("jwt", "ci", "not.a.jwt".to_owned()),
        ("jwt", "nope", jwt_case("valid_rs256")),
        // A role on another mount, even one this token would satisfy.
        ("jwt", "op", jwt_case("valid_rs256")),
        ("jwt", "ci-url", jwt_case("valid_rs256")),
    ];
    for (mount, role, jwt) in cases {
        let r = jwt_login(&h, mount, role, &jwt).await;
        assert_error(&r, 400, "permission denied");
    }
}

#[wasm_bindgen_test]
async fn jwt_login_needs_role_and_jwt() {
    let h = Harness::new().await;
    let r = h
        .call(req(
            Method::Post,
            "/v1/auth/jwt/login",
            None,
            &json!({ "role": "ci" }),
        ))
        .await;
    assert_error(&r, 400, "missing jwt");
    let r = h
        .call(req(
            Method::Post,
            "/v1/auth/jwt/login",
            None,
            &json!({ "jwt": "x" }),
        ))
        .await;
    assert_error(&r, 400, "missing role");
}

#[wasm_bindgen_test]
async fn jwks_url_mount_refetches_once_on_unknown_kid() {
    let mut h = Harness::new().await;
    h.jwks = FakeJwks {
        normal: Some(json!({ "keys": [] })),
        forced: Some(fixture_jwks()),
        calls: RefCell::default(),
    };
    let r = jwt_login(&h, "jwt-url", "ci-url", &jwt_case("valid_rs256")).await;
    assert!(auth(&r)["client_token"].is_string());
    assert_eq!(*h.jwks.calls.borrow(), vec![false, true]);
}

#[wasm_bindgen_test]
async fn jwks_url_mount_still_unknown_kid_after_refetch_is_denied() {
    let mut h = Harness::new().await;
    h.jwks = FakeJwks {
        normal: Some(fixture_jwks()),
        forced: Some(fixture_jwks()),
        calls: RefCell::default(),
    };
    let r = jwt_login(&h, "jwt-url", "ci-url", &jwt_case("unknown_kid")).await;
    assert_error(&r, 400, "permission denied");
    assert_eq!(*h.jwks.calls.borrow(), vec![false, true]);
}

#[wasm_bindgen_test]
async fn jwks_url_mount_bad_signature_does_not_refetch() {
    let mut h = Harness::new().await;
    h.jwks = FakeJwks {
        normal: Some(fixture_jwks()),
        forced: Some(fixture_jwks()),
        calls: RefCell::default(),
    };
    let r = jwt_login(&h, "jwt-url", "ci-url", &jwt_case("bad_signature")).await;
    assert_error(&r, 400, "permission denied");
    assert_eq!(*h.jwks.calls.borrow(), vec![false]);
}

#[wasm_bindgen_test]
async fn unreachable_jwks_is_500() {
    let h = Harness::new().await;
    let r = jwt_login(&h, "jwt-url", "ci-url", &jwt_case("valid_rs256")).await;
    assert_error(&r, 500, "internal error");
}

#[wasm_bindgen_test]
async fn login_on_unknown_mount_and_get_are_vaults_403() {
    let h = Harness::new().await;
    let r = jwt_login(&h, "nope", "ci", &jwt_case("valid_rs256")).await;
    assert_error(&r, 403, "permission denied");
    let r = h
        .call(req(Method::Get, "/v1/auth/jwt/login", None, &json!({})))
        .await;
    assert_error(&r, 403, "permission denied");
}

#[wasm_bindgen_test]
async fn bad_pinned_jwks_fails_state_construction() {
    let mut cfg = config_json();
    cfg["mounts"]["jwt"]["jwks"] = json!({ "nokeys": true });
    let config = Config::from_json(&cfg.to_string()).unwrap();
    assert!(State::new(config, web_ops().await).is_err());
}

// ---- SSH login ----

fn ssh_sign(key: &ssh_key::PrivateKey, namespace: &str, msg: &str) -> String {
    key.sign(namespace, ssh_key::HashAlg::Sha512, msg.as_bytes())
        .unwrap()
        .to_pem(ssh_key::LineEnding::LF)
        .unwrap()
}

async fn challenge(h: &Harness) -> String {
    let r = h
        .call(req(
            Method::Post,
            "/v1/auth/ssh/challenge",
            None,
            &json!({}),
        ))
        .await;
    let d = data(&r);
    assert_eq!(d["expires_in"], 60);
    d["challenge"].as_str().unwrap().to_owned()
}

async fn ssh_login(h: &Harness, role: &str, challenge: &str, signature: &str) -> Reply {
    h.call(req(
        Method::Put,
        "/v1/auth/ssh/login",
        None,
        &json!({ "role": role, "challenge": challenge, "signature": signature }),
    ))
    .await
}

#[wasm_bindgen_test]
async fn ssh_login_with_a_signed_challenge_returns_a_token() {
    let h = Harness::new().await;
    let c = challenge(&h).await;
    let r = ssh_login(&h, "op", &c, &ssh_sign(&ssh_test_key(), "edgekms", &c)).await;
    let a = auth(&r);
    assert_eq!(a["policies"], json!(["admin", "app-all"]));
    assert_eq!(a["lease_duration"], 3600);
    let claims = token::check(&h.st.ops, a["client_token"].as_str().unwrap(), NOW)
        .await
        .unwrap();
    assert!(claims.meta["ssh_fingerprint"].starts_with("SHA256:"));
    assert_eq!(claims.role, "op");
}

#[wasm_bindgen_test]
async fn ssh_login_failures_are_one_identical_400() {
    let mut h = Harness::new().await;
    let key = ssh_test_key();
    let c = challenge(&h).await;
    let good = ssh_sign(&key, "edgekms", &c);
    let mut tampered = c.clone().into_bytes();
    let i = tampered.len() - 2;
    tampered[i] = if tampered[i] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(tampered).unwrap();
    let stranger = ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[9; 32]));
    let fixture_sig = include_str!("../../edgekms-core/tests/fixtures/ssh/ed25519.sig");

    let cases: Vec<(&str, String, String)> = vec![
        ("op", "ekmsc.garbage".into(), good.clone()),
        ("op", tampered.clone(), ssh_sign(&key, "edgekms", &tampered)),
        ("op", c.clone(), "not a signature".into()),
        ("op", c.clone(), ssh_sign(&key, "git", &c)),
        ("op", c.clone(), ssh_sign(&key, "edgekms", "other message")),
        ("op", c.clone(), ssh_sign(&stranger, "edgekms", &c)),
        ("op", c.clone(), fixture_sig.into()),
        // The key is valid, but not one this role pins.
        ("fresh", c.clone(), good.clone()),
        ("nope", c.clone(), good.clone()),
        // A JWT role named on the SSH mount.
        ("ci", c.clone(), good.clone()),
    ];
    for (role, chal, sig) in &cases {
        let r = ssh_login(&h, role, chal, sig).await;
        assert_error(&r, 400, "permission denied");
    }

    // Expired, then from the future: the same signature, the same answer.
    h.now = NOW + 61;
    assert_error(
        &ssh_login(&h, "op", &c, &good).await,
        400,
        "permission denied",
    );
    h.now = NOW - 6;
    assert_error(
        &ssh_login(&h, "op", &c, &good).await,
        400,
        "permission denied",
    );
    h.now = NOW + 60;
    assert_eq!(ssh_login(&h, "op", &c, &good).await.status, 200);
}

#[wasm_bindgen_test]
async fn ssh_login_checks_the_challenge_and_signature_before_refusing_the_role() {
    // As for JWT logins, a role that isn't on the mount is refused only after the challenge
    // and the signature have been checked, so the time a refusal takes doesn't say which role
    // names exist. The audit code shows which check refused it.
    let h = Harness::new().await;
    let key = ssh_test_key();
    let c = challenge(&h).await;
    let good = ssh_sign(&key, "edgekms", &c);
    let cases = [
        ("nope", c.clone(), good.clone(), "login_role_not_found"),
        ("ci", c.clone(), good.clone(), "login_role_not_found"),
        (
            "nope",
            "ekmsc.garbage".to_owned(),
            good.clone(),
            "ssh_challenge_malformed",
        ),
        (
            "nope",
            c.clone(),
            "not a signature".to_owned(),
            "ssh_signature_malformed",
        ),
        (
            "nope",
            c.clone(),
            ssh_sign(&key, "git", &c),
            "ssh_wrong_namespace",
        ),
        ("fresh", c.clone(), good.clone(), "ssh_key_not_allowed"),
    ];
    for (role, chal, sig, code) in cases {
        h.audit.clear();
        let r = ssh_login(&h, role, &chal, &sig).await;
        assert_error(&r, 400, "permission denied");
        let (ev, _) = h.audit.only();
        assert_eq!(ev["error"], code, "role {role}: {ev}");
    }
}

#[wasm_bindgen_test]
async fn challenge_names_the_origin_the_request_was_sent_to() {
    let h = Harness::new().await;
    let c = challenge(&h).await;
    assert_eq!(
        edgekms_core::ssh::challenge_origin(&c).unwrap(),
        TEST_ORIGIN
    );
}

#[wasm_bindgen_test]
async fn challenge_relayed_to_another_origin_is_denied() {
    // Deployment B issues a genuine challenge; the login carrying it arrives at another origin
    // the same Worker answers on. The signature is good, the origin is not.
    let h = Harness::new().await;
    let c = challenge(&h).await;
    let sig = ssh_sign(&ssh_test_key(), "edgekms", &c);
    let mut login = req(
        Method::Put,
        "/v1/auth/ssh/login",
        None,
        &json!({ "role": "op", "challenge": c, "signature": sig }),
    );
    "https://other.test".clone_into(&mut login.origin);
    assert_error(&h.call(login).await, 400, "permission denied");
    let events = h.audit.values();
    assert_eq!(
        events.last().unwrap()["error"],
        "ssh_challenge_wrong_origin"
    );
}

/// The usual harness with `public_origins` set, as a deployment reachable with a spoofable
/// Host header should be.
async fn origins_harness(origins: &[&str]) -> Harness {
    let mut cfg = config_json();
    cfg["public_origins"] = json!(origins);
    let mut h = Harness::new().await;
    h.st = State::new(
        Config::from_json(&cfg.to_string()).unwrap(),
        web_ops().await,
    )
    .unwrap();
    h
}

#[wasm_bindgen_test]
async fn configured_origins_ignore_a_spoofed_host_when_minting() {
    let h = origins_harness(&["https://kms.test"]).await;
    let mut r = req(Method::Post, "/v1/auth/ssh/challenge", None, &json!({}));
    "https://evil.test".clone_into(&mut r.origin);
    let c = data(&h.call(r).await)["challenge"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        edgekms_core::ssh::challenge_origin(&c).unwrap(),
        "https://kms.test"
    );
}

#[wasm_bindgen_test]
async fn configured_origins_refuse_a_challenge_for_a_spoofed_host() {
    // Off Cloudflare's edge a client picks the Host header, so the server could mint a
    // genuine challenge for any origin. With origins configured, only theirs log in.
    let h = origins_harness(&["https://kms.test"]).await;
    let c = edgekms_core::ssh::new_challenge(&h.st.ops, NOW, "https://evil.test")
        .await
        .unwrap();
    let sig = ssh_sign(&ssh_test_key(), "edgekms", &c);
    let mut login = req(
        Method::Put,
        "/v1/auth/ssh/login",
        None,
        &json!({ "role": "op", "challenge": c, "signature": sig }),
    );
    "https://evil.test".clone_into(&mut login.origin);
    assert_error(&h.call(login).await, 400, "permission denied");
    assert_eq!(
        h.audit.values().last().unwrap()["error"],
        "ssh_challenge_wrong_origin"
    );
}

#[wasm_bindgen_test]
async fn any_configured_origin_logs_in() {
    let h = origins_harness(&["https://kms.test", "https://alt.test"]).await;
    let mut r = req(Method::Post, "/v1/auth/ssh/challenge", None, &json!({}));
    "https://alt.test".clone_into(&mut r.origin);
    let c = data(&h.call(r).await)["challenge"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        edgekms_core::ssh::challenge_origin(&c).unwrap(),
        "https://alt.test"
    );
    let sig = ssh_sign(&ssh_test_key(), "edgekms", &c);
    let mut login = req(
        Method::Put,
        "/v1/auth/ssh/login",
        None,
        &json!({ "role": "op", "challenge": c, "signature": sig }),
    );
    "https://kms.test".clone_into(&mut login.origin);
    assert_eq!(h.call(login).await.status, 200);
}

#[wasm_bindgen_test]
async fn ssh_login_needs_all_fields() {
    let h = Harness::new().await;
    let r = h
        .call(req(
            Method::Put,
            "/v1/auth/ssh/login",
            None,
            &json!({ "role": "op", "challenge": "x" }),
        ))
        .await;
    assert_error(&r, 400, "missing signature");
}

#[wasm_bindgen_test]
async fn challenge_is_only_offered_on_ssh_mounts() {
    let h = Harness::new().await;
    for m in ["jwt", "nope"] {
        let r = h
            .call(req(
                Method::Post,
                &format!("/v1/auth/{m}/challenge"),
                None,
                &json!({}),
            ))
            .await;
        assert_error(&r, 403, "permission denied");
    }
    let r = h
        .call(req(Method::Get, "/v1/auth/ssh/challenge", None, &json!({})))
        .await;
    assert_error(&r, 403, "permission denied");
}

// ---- GitHub user login ----

/// GitHub, stubbed: answers every token check with `result` and records each call.
struct FakeGithub {
    result: Result<GithubUser, GithubError>,
    calls: RefCell<Vec<(String, String)>>,
    revoked: RefCell<Vec<(String, String)>>,
    revoke_fails: bool,
}

impl FakeGithub {
    fn answering(result: Result<GithubUser, GithubError>) -> Self {
        Self {
            result,
            calls: RefCell::default(),
            revoked: RefCell::default(),
            revoke_fails: false,
        }
    }

    fn user(id: u64) -> Self {
        Self::answering(Ok(GithubUser {
            id,
            login: "octocat".into(),
        }))
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
        let r = self.result.clone();
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
        let fails = self.revoke_fails;
        Box::pin(async move {
            if fails {
                Err("github_revoke_failed")
            } else {
                Ok(())
            }
        })
    }

    /// The data plane never exchanges a web-flow code.
    fn exchange_code<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: &'a str,
        _: &'a str,
    ) -> LocalFuture<'a, Result<Zeroizing<String>, GithubError>> {
        Box::pin(async { Err(GithubError::Unavailable("not_in_this_test")) })
    }
}

const GH_TOKEN: &str = "gho_16C7e42F292c6912E7710c838347Ae178B4a";

/// The usual harness with a `github-user` mount (OAuth App `Iv1.test`) and a role binding
/// GitHub user 583231.
async fn github_harness() -> Harness {
    let mut cfg = config_json();
    cfg["mounts"]["github-user"] = json!({ "type": "github-user", "client_id": "Iv1.test" });
    cfg["roles"]["gh-op"] = json!({
        "mount": "github-user",
        "github_user_ids": [583_231],
        "policies": ["app-all"],
        "token_ttl_secs": 3600
    });
    let mut h = Harness::new().await;
    h.st = State::new(
        Config::from_json(&cfg.to_string()).unwrap(),
        web_ops().await,
    )
    .unwrap();
    h
}

async fn github_login(h: &Harness, gh: Option<&FakeGithub>, role: &str, token: &str) -> Reply {
    let deps = Deps::new(&h.st, &h.rev, &h.jwks, &h.audit, &h.limits, h.now * 1000);
    let deps = match gh {
        Some(g) => deps.with_github(g),
        None => deps,
    };
    let r = req(
        Method::Post,
        "/v1/auth/github-user/login",
        None,
        &json!({ "role": role, "token": token }),
    );
    handle(&deps, &r).await
}

#[wasm_bindgen_test]
async fn github_login_with_a_token_of_a_bound_user_returns_a_token() {
    let h = github_harness().await;
    let gh = FakeGithub::user(583_231);
    let r = github_login(&h, Some(&gh), "gh-op", GH_TOKEN).await;
    let a = auth(&r);
    assert_eq!(a["policies"], json!(["app-all"]));
    assert_eq!(a["lease_duration"], 3600);
    let claims = token::check(&h.st.ops, a["client_token"].as_str().unwrap(), NOW)
        .await
        .unwrap();
    assert_eq!(claims.role, "gh-op");
    assert_eq!(claims.meta["sub"], "github-user:583231");
    assert_eq!(
        *gh.calls.borrow(),
        vec![("Iv1.test".to_owned(), GH_TOKEN.to_owned())]
    );
    let (ev, raw) = h.audit.only();
    assert_eq!(ev["op"], "login");
    assert_eq!(ev["mount"], "github-user");
    assert_eq!(ev["role"], "gh-op");
    assert_eq!(ev["result"], "ok");
    assert!(!raw.contains(GH_TOKEN), "{raw}");
}

#[wasm_bindgen_test]
async fn github_login_failures_are_one_identical_400() {
    let h = github_harness().await;
    let not_this_app = FakeGithub::answering(Err(GithubError::Denied("github_token_not_for_app")));
    let stranger = FakeGithub::user(1);
    let bound = FakeGithub::user(583_231);
    let cases: [(&FakeGithub, &str, &str, &str); 5] = [
        (&not_this_app, "gh-op", GH_TOKEN, "github_token_not_for_app"),
        (&stranger, "gh-op", GH_TOKEN, "github_user_not_bound"),
        (&bound, "gh-op", "not a token", "github_malformed_token"),
        (&bound, "nope", GH_TOKEN, "login_role_not_found"),
        // A role on another mount, even one that pins this caller's SSH key.
        (&bound, "op", GH_TOKEN, "login_role_not_found"),
    ];
    for (gh, role, tok, label) in cases {
        h.audit.clear();
        let r = github_login(&h, Some(gh), role, tok).await;
        assert_error(&r, 400, "permission denied");
        let (ev, raw) = h.audit.only();
        assert_eq!(ev["result"], "denied", "{label}");
        assert_eq!(ev["error"], label);
        assert!(!raw.contains(GH_TOKEN), "{raw}");
    }
    // A malformed token never reaches GitHub. An unknown role and a role on another mount do,
    // so the time a refusal takes doesn't say which role names exist on this mount.
    assert_eq!(
        *bound.calls.borrow(),
        vec![("Iv1.test".to_owned(), GH_TOKEN.to_owned()); 2]
    );
}

#[wasm_bindgen_test]
async fn github_token_is_checked_and_burned_for_an_unknown_role() {
    let h = github_harness().await;
    let bound = FakeGithub::user(583_231);
    let r = github_login(&h, Some(&bound), "nope", GH_TOKEN).await;
    assert_error(&r, 400, "permission denied");
    assert_eq!(bound.calls.borrow().len(), 1);
    assert_eq!(bound.revoked.borrow().len(), 1);
    // GitHub's refusal is reported ahead of the role's, as a JWT's signature is.
    let not_this_app = FakeGithub::answering(Err(GithubError::Denied("github_token_not_for_app")));
    h.audit.clear();
    github_login(&h, Some(&not_this_app), "nope", GH_TOKEN).await;
    assert_eq!(h.audit.only().0["error"], "github_token_not_for_app");
}

#[wasm_bindgen_test]
async fn every_checked_github_token_is_revoked_so_it_is_single_use() {
    let h = github_harness().await;
    let bound = FakeGithub::user(583_231);
    assert_eq!(
        github_login(&h, Some(&bound), "gh-op", GH_TOKEN)
            .await
            .status,
        200
    );
    assert_eq!(
        *bound.revoked.borrow(),
        vec![("Iv1.test".to_owned(), GH_TOKEN.to_owned())]
    );
    // A genuine token of an unbound user is burned too: it reached this deployment.
    let stranger = FakeGithub::user(1);
    assert_eq!(
        github_login(&h, Some(&stranger), "gh-op", GH_TOKEN)
            .await
            .status,
        400
    );
    assert_eq!(stranger.revoked.borrow().len(), 1);
    // A token GitHub didn't recognize has nothing to revoke.
    let unknown = FakeGithub::answering(Err(GithubError::Denied("github_token_not_for_app")));
    github_login(&h, Some(&unknown), "gh-op", GH_TOKEN).await;
    assert!(unknown.revoked.borrow().is_empty());
}

#[wasm_bindgen_test]
async fn failed_github_revocation_does_not_fail_the_login() {
    let h = github_harness().await;
    let mut gh = FakeGithub::user(583_231);
    gh.revoke_fails = true;
    assert_eq!(
        github_login(&h, Some(&gh), "gh-op", GH_TOKEN).await.status,
        200
    );
    assert_eq!(gh.revoked.borrow().len(), 1);
}

#[wasm_bindgen_test]
async fn github_unavailable_or_unconfigured_is_500() {
    let h = github_harness().await;
    let down = FakeGithub::answering(Err(GithubError::Unavailable("github_unreachable")));
    assert_error(
        &github_login(&h, Some(&down), "gh-op", GH_TOKEN).await,
        500,
        "internal error",
    );
    // No GITHUB_CLIENT_SECRET: the Worker never got a GitHub checker.
    assert_error(
        &github_login(&h, None, "gh-op", GH_TOKEN).await,
        500,
        "internal error",
    );
}

#[wasm_bindgen_test]
async fn github_login_needs_role_and_token_and_is_rate_limited() {
    let h = github_harness().await;
    let gh = FakeGithub::user(583_231);
    let deps =
        Deps::new(&h.st, &h.rev, &h.jwks, &h.audit, &h.limits, h.now * 1000).with_github(&gh);
    let r = handle(
        &deps,
        &req(
            Method::Post,
            "/v1/auth/github-user/login",
            None,
            &json!({ "role": "gh-op" }),
        ),
    )
    .await;
    assert_error(&r, 400, "missing token");
    h.limits.deny_login.set(true);
    assert_eq!(
        github_login(&h, Some(&gh), "gh-op", GH_TOKEN).await.status,
        429
    );
    assert!(gh.calls.borrow().is_empty());
}

#[wasm_bindgen_test]
async fn challenge_is_not_offered_on_github_user_mounts() {
    let h = github_harness().await;
    let r = h
        .call(req(
            Method::Post,
            "/v1/auth/github-user/challenge",
            None,
            &json!({}),
        ))
        .await;
    assert_error(&r, 403, "permission denied");
}

// ---- tokens ----

#[wasm_bindgen_test]
async fn lookup_self_never_returns_the_token() {
    let h = Harness::new().await;
    let r = jwt_login(&h, "jwt", "ci", &jwt_case("valid_rs256")).await;
    let tok = auth(&r)["client_token"].as_str().unwrap().to_owned();
    let accessor = auth(&r)["accessor"].as_str().unwrap().to_owned();
    let r = h
        .call(req(
            Method::Get,
            "/v1/auth/token/lookup-self",
            Some(&tok),
            &json!({}),
        ))
        .await;
    let d = data(&r);
    assert_eq!(d["id"], "<redacted>");
    assert_eq!(d["accessor"], accessor);
    assert_eq!(d["policies"], json!(["app-decrypt"]));
    assert_eq!(d["ttl"], 900);
    // NOW + 900 = 2033-05-18T03:48:20Z
    assert_eq!(d["expire_time"], "2033-05-18T03:48:20Z");
    assert_eq!(d["renewable"], false);
    assert_eq!(d["meta"]["ref"], "refs/heads/main");
    let text = serde_json::to_string(&r.body).unwrap();
    assert!(!text.contains(&tok));
    let payload = tok.split('.').nth(1).unwrap();
    assert!(!text.contains(payload));
}

#[wasm_bindgen_test]
async fn lookup_self_needs_a_token_and_get() {
    let h = Harness::new().await;
    let r = h
        .call(req(
            Method::Get,
            "/v1/auth/token/lookup-self",
            None,
            &json!({}),
        ))
        .await;
    assert_error(&r, 403, "permission denied");
    let r = h
        .call(req(
            Method::Post,
            "/v1/auth/token/lookup-self",
            Some(&h.admin().await),
            &json!({}),
        ))
        .await;
    assert_error(&r, 403, "permission denied");
}

#[wasm_bindgen_test]
async fn renew_self_is_always_refused() {
    let h = Harness::new().await;
    let r = h
        .call(req(
            Method::Put,
            "/v1/auth/token/renew-self",
            Some(&h.admin().await),
            &json!({ "increment": "1h" }),
        ))
        .await;
    assert_error(&r, 400, "token is not renewable");
    let r = h
        .call(req(
            Method::Put,
            "/v1/auth/token/renew-self",
            None,
            &json!({}),
        ))
        .await;
    assert_error(&r, 403, "permission denied");
}

async fn seal_admin(h: &Harness) -> String {
    h.token("op", &["admin", "seal"], 3600, NOW).await
}

async fn create(h: &Harness, caller: &str, body: &Value) -> Reply {
    h.call(req(
        Method::Post,
        "/v1/auth/token/create",
        Some(caller),
        body,
    ))
    .await
}

#[wasm_bindgen_test]
async fn admin_creates_a_long_seal_token() {
    let h = Harness::new().await;
    let r = create(
        &h,
        &seal_admin(&h).await,
        &json!({ "policies": ["seal"], "ttl": "8760h", "display_name": "openbao" }),
    )
    .await;
    let a = auth(&r);
    assert_eq!(a["policies"], json!(["seal"]));
    assert_eq!(a["token_policies"], json!(["seal"]));
    assert_eq!(a["lease_duration"], 8760 * 3600);
    assert_eq!(a["renewable"], false);
    let tok = a["client_token"].as_str().unwrap();
    let claims = token::check(&h.st.ops, tok, NOW).await.unwrap();
    assert!(claims.long);
    assert_eq!(claims.role, "op");
    assert_eq!(claims.exp, NOW + 8760 * 3600);
    assert_eq!(claims.meta["display_name"], "openbao");
    assert_eq!(claims.jti, a["accessor"].as_str().unwrap());
    let ct = encrypt(&h, tok, b"unseal").await;
    assert!(ct.starts_with("vault:v3:"));
}

#[wasm_bindgen_test]
async fn token_create_ttl_forms_and_bounds() {
    let h = Harness::new().await;
    let admin = seal_admin(&h).await;
    for (ttl, secs) in [
        (json!("30m"), 1800),
        (json!("45m30s"), 2730),
        (json!("1h30m"), 5400),
        (json!("60s"), 60),
        (json!("120"), 120),
        (json!(3600), 3600),
        (json!("86400s"), 86_400),
        (json!(34_560_000), 34_560_000),
        // Vault's duration parser also takes days.
        (json!("1d"), 86_400),
        (json!("365d"), 31_536_000),
        (json!("400d"), 34_560_000),
    ] {
        let r = create(&h, &admin, &json!({ "policies": ["seal"], "ttl": ttl })).await;
        assert_eq!(auth(&r)["lease_duration"], secs, "{ttl}");
        let claims = token::check(&h.st.ops, auth(&r)["client_token"].as_str().unwrap(), NOW)
            .await
            .unwrap();
        // Every created token is checked against the revocation list, whatever its TTL.
        assert!(claims.long, "{ttl}");
    }
    for ttl in [
        json!("59s"),
        json!(59),
        json!(34_560_001),
        json!("9601h"),
        json!("1.5h"),
        json!("-1h"),
        json!("401d"),
        json!("d"),
        json!("2d12h"),
        json!("h"),
        json!(""),
        json!(-5),
        json!(1.5),
        json!("99999999999999999999h"),
        json!(null),
    ] {
        let r = create(&h, &admin, &json!({ "policies": ["seal"], "ttl": ttl })).await;
        assert_eq!(r.status, 400, "{ttl}: {r:?}");
    }
    let r = create(&h, &admin, &json!({ "policies": ["seal"] })).await;
    assert_error(&r, 400, "missing ttl");
}

#[wasm_bindgen_test]
async fn token_create_policy_must_exist_and_be_held_by_the_caller() {
    let h = Harness::new().await;
    let admin = seal_admin(&h).await;
    for policies in [
        json!(["nope"]),
        json!(["app-all"]),
        json!(["seal", "app-all"]),
        json!([]),
        json!("seal"),
        json!([1]),
    ] {
        let r = create(&h, &admin, &json!({ "policies": policies, "ttl": "1h" })).await;
        assert_eq!(r.status, 400, "{policies}: {r:?}");
    }
    // A caller holding a policy name that isn't in config can't pass it on either.
    let ghost = h.token("op", &["admin", "ghost"], 3600, NOW).await;
    let r = create(&h, &ghost, &json!({ "policies": ["ghost"], "ttl": "1h" })).await;
    assert_eq!(r.status, 400);
}

#[wasm_bindgen_test]
async fn token_create_needs_token_create() {
    let h = Harness::new().await;
    let tok = h.token("op", &["seal"], 3600, NOW).await;
    let r = create(&h, &tok, &json!({ "policies": ["seal"], "ttl": "1h" })).await;
    assert_error(&r, 403, "permission denied");
    let r = create(&h, "", &json!({ "policies": ["seal"], "ttl": "1h" })).await;
    assert_error(&r, 403, "permission denied");
}

#[wasm_bindgen_test]
async fn token_create_refuses_options_it_would_ignore() {
    let h = Harness::new().await;
    let admin = seal_admin(&h).await;
    for field in ["period", "num_uses", "renewable", "explicit_max_ttl"] {
        let mut body = json!({ "policies": ["seal"], "ttl": "1h" });
        body[field] = json!("1");
        let r = create(&h, &admin, &body).await;
        assert_eq!(r.status, 400, "{field}");
        assert!(errors(&r)[0].contains(field), "{field}: {r:?}");
    }
    let r = create(
        &h,
        &admin,
        &json!({ "policies": ["seal"], "ttl": "1h", "display_name": "x".repeat(129) }),
    )
    .await;
    assert_eq!(r.status, 400);
}

async fn revoke(h: &Harness, caller: &str, accessor: &str) -> Reply {
    h.call(req(
        Method::Put,
        "/v1/auth/token/revoke-accessor",
        Some(caller),
        &json!({ "accessor": accessor }),
    ))
    .await
}

#[wasm_bindgen_test]
async fn revoked_long_token_is_refused() {
    let h = Harness::new().await;
    let admin = seal_admin(&h).await;
    let r = create(&h, &admin, &json!({ "policies": ["seal"], "ttl": "8760h" })).await;
    let tok = auth(&r)["client_token"].as_str().unwrap().to_owned();
    let accessor = auth(&r)["accessor"].as_str().unwrap().to_owned();
    encrypt(&h, &tok, b"before").await;

    let r = revoke(&h, &admin, &accessor).await;
    assert_eq!(r.status, 204, "{r:?}");
    assert!(r.body.is_none());
    assert!(h.rev.0.borrow().contains(&accessor));

    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/encrypt/app",
            Some(&tok),
            &json!({ "plaintext": b64(b"after") }),
        ))
        .await;
    assert_error(&r, 403, "permission denied");
    let r = h
        .call(req(
            Method::Get,
            "/v1/auth/token/lookup-self",
            Some(&tok),
            &json!({}),
        ))
        .await;
    assert_error(&r, 403, "permission denied");
}

#[wasm_bindgen_test]
async fn revoked_short_created_token_is_refused() {
    let h = Harness::new().await;
    let admin = seal_admin(&h).await;
    let r = create(&h, &admin, &json!({ "policies": ["seal"], "ttl": "1h" })).await;
    let tok = auth(&r)["client_token"].as_str().unwrap().to_owned();
    let accessor = auth(&r)["accessor"].as_str().unwrap().to_owned();
    encrypt(&h, &tok, b"before").await;

    let r = revoke(&h, &admin, &accessor).await;
    assert_eq!(r.status, 204, "{r:?}");
    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/encrypt/app",
            Some(&tok),
            &json!({ "plaintext": b64(b"after") }),
        ))
        .await;
    assert_error(&r, 403, "permission denied");
}

#[wasm_bindgen_test]
async fn revoke_needs_token_revoke_and_a_well_formed_accessor() {
    let h = Harness::new().await;
    let tok = h.token("op", &["seal"], 3600, NOW).await;
    let r = revoke(&h, &tok, "AAAAAAAAAAAAAAAAAAAAAA").await;
    assert_error(&r, 403, "permission denied");
    assert!(h.rev.0.borrow().is_empty());
    let admin = seal_admin(&h).await;
    for bad in [
        "",
        "short",
        "AAAAAAAAAAAAAAAAAAAAA+",
        "revoked:AAAAAAAAAAAAAA",
    ] {
        let r = revoke(&h, &admin, bad).await;
        assert_eq!(r.status, 400, "{bad}");
    }
    assert!(h.rev.0.borrow().is_empty());
}

#[wasm_bindgen_test]
async fn revoke_store_failure_is_500() {
    struct ReadOnly;
    impl Revocations for ReadOnly {
        async fn is_revoked(&self, _: &str) -> worker::Result<bool> {
            Ok(false)
        }
        async fn revoke(&self, _: &str, _: u64) -> worker::Result<()> {
            Err(worker::Error::RustError("kv down".into()))
        }
    }
    let h = Harness::new().await;
    let admin = seal_admin(&h).await;
    let r = h
        .call_with(
            &ReadOnly,
            req(
                Method::Put,
                "/v1/auth/token/revoke-accessor",
                Some(&admin),
                &json!({ "accessor": "AAAAAAAAAAAAAAAAAAAAAA" }),
            ),
        )
        .await;
    assert_error(&r, 500, "internal error");
}

// ---- token create limits (fix round 1) ----

#[wasm_bindgen_test]
async fn token_create_refuses_admin_policies() {
    let h = Harness::new().await;
    let admin = seal_admin(&h).await;
    for policies in [json!(["admin"]), json!(["admin", "seal"])] {
        let r = create(&h, &admin, &json!({ "policies": policies, "ttl": "9600h" })).await;
        assert_error(&r, 400, "token create may only grant key policies");
    }
    let r = create(&h, &admin, &json!({ "policies": ["seal"], "ttl": "8760h" })).await;
    let tok = auth(&r)["client_token"].as_str().unwrap();
    assert!(token::check(&h.st.ops, tok, NOW).await.unwrap().long);
}

#[wasm_bindgen_test]
async fn created_token_dies_with_its_creator_roles_not_before() {
    let mut h = Harness::new().await;
    let admin = seal_admin(&h).await;
    let r = create(&h, &admin, &json!({ "policies": ["seal"], "ttl": "8760h" })).await;
    let tok = auth(&r)["client_token"].as_str().unwrap().to_owned();
    encrypt(&h, &tok, b"before").await;

    let mut cfg = config_json();
    cfg["roles"]["op"]["not_before"] = json!(NOW + 1);
    h.st = State::new(
        Config::from_json(&cfg.to_string()).unwrap(),
        web_ops().await,
    )
    .unwrap();
    h.now = NOW + 10;
    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/encrypt/app",
            Some(&tok),
            &json!({ "plaintext": b64(b"after") }),
        ))
        .await;
    assert_error(&r, 403, "permission denied");
}
