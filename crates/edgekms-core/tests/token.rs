use edgekms_core::keyops::SoftKeyOps;
use edgekms_core::token::{self, TokenClaims, TokenError};
use edgekms_core::transit::{Id, RootKey};
use pollster::block_on;

fn ops(seed: u8) -> SoftKeyOps<rand::rngs::ThreadRng> {
    SoftKeyOps::new(
        RootKey::new(Id::new("r1").unwrap(), [seed; 32]),
        rand::rng(),
    )
}
fn claims(exp: u64) -> TokenClaims {
    TokenClaims {
        v: 1,
        jti: "abc".into(),
        role: "infra-ci".into(),
        policies: vec!["p".into()],
        iat: 100,
        exp,
        long: false,
        meta: std::collections::BTreeMap::default(),
    }
}

#[test]
fn mint_then_check_round_trips() {
    let o = ops(1);
    let t = block_on(token::mint(&o, &claims(200))).unwrap();
    assert!(t.starts_with("ekms."));
    assert_eq!(block_on(token::check(&o, &t, 150)).unwrap(), claims(200));
}
#[test]
fn expired_token_is_rejected() {
    let o = ops(1);
    let t = block_on(token::mint(&o, &claims(200))).unwrap();
    assert_eq!(
        block_on(token::check(&o, &t, 200)).unwrap_err(),
        TokenError::Expired
    );
}
#[test]
fn token_from_another_root_is_rejected() {
    let t = block_on(token::mint(&ops(1), &claims(200))).unwrap();
    assert_eq!(
        block_on(token::check(&ops(2), &t, 150)).unwrap_err(),
        TokenError::BadMac
    );
}
#[test]
fn edited_payload_is_rejected() {
    let o = ops(1);
    let t = block_on(token::mint(&o, &claims(200))).unwrap();
    let mut parts: Vec<String> = t
        .trim_start_matches("ekms.")
        .split('.')
        .map(String::from)
        .collect();
    let forged = claims(9_999_999_999);
    parts[0] = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        serde_json::to_vec(&forged).unwrap(),
    );
    assert_eq!(
        block_on(token::check(
            &o,
            &format!("ekms.{}.{}", parts[0], parts[1]),
            150
        ))
        .unwrap_err(),
        TokenError::BadMac
    );
}
#[test]
fn malformed_tokens_are_rejected() {
    let o = ops(1);
    // Shape errors are caught before the MAC is computed, so they are always `Malformed`.
    for bad in [
        "",
        "ekms.",
        "ekms.a",
        "ekms..AAAA",
        "ekms.a.",
        "hvs.a.b",
        "EKMS.a.AAAA",
        "ekms.a.b.c",
        "ekms.!!.!!",
        "ekms.a.!!",
        "ekms.a.b",
    ] {
        assert_eq!(
            block_on(token::check(&o, bad, 150)),
            Err(TokenError::Malformed),
            "{bad}"
        );
    }
    // Well-shaped with a decodable tag: the MAC decides, before the payload is ever parsed.
    for bad in ["ekms.a.AAAA", "ekms.!!.AAAA"] {
        assert_eq!(
            block_on(token::check(&o, bad, 150)),
            Err(TokenError::BadMac),
            "{bad}"
        );
    }
}

#[test]
fn token_with_no_policies_round_trips() {
    let o = ops(1);
    let mut c = claims(200);
    c.policies.clear();
    let t = block_on(token::mint(&o, &c)).unwrap();
    assert_eq!(block_on(token::check(&o, &t, 150)).unwrap(), c);
}
#[test]
fn jti_is_random_and_url_safe() {
    let o = ops(1);
    let (a, b) = (token::new_jti(&o), token::new_jti(&o));
    assert_ne!(a, b);
    assert_eq!(a.len(), 22);
    assert!(
        a.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    );
}

async fn sign(o: &impl edgekms_core::keyops::KeyOps, json: &[u8]) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B;
    let payload = B.encode(json);
    let tag = o
        .mac(edgekms_core::keyops::MacPurpose::Token, payload.as_bytes())
        .await
        .unwrap();
    format!("ekms.{payload}.{}", B.encode(tag))
}

#[test]
fn validly_signed_unknown_field_is_malformed() {
    let o = ops(1);
    let json = br#"{"v":1,"jti":"a","role":"r","policies":[],"iat":1,"exp":9,"long":false,"x":1}"#;
    let t = block_on(sign(&o, json));
    assert_eq!(
        block_on(token::check(&o, &t, 5)).unwrap_err(),
        TokenError::Malformed
    );
}

#[test]
fn validly_signed_wrong_version_is_unsupported() {
    let o = ops(1);
    let json = br#"{"v":2,"jti":"a","role":"r","policies":[],"iat":1,"exp":9,"long":false}"#;
    let t = block_on(sign(&o, json));
    assert_eq!(
        block_on(token::check(&o, &t, 5)).unwrap_err(),
        TokenError::UnsupportedVersion
    );
}

#[test]
fn padded_mac_is_rejected() {
    let o = ops(1);
    let t = block_on(token::mint(&o, &claims(200))).unwrap();
    assert_eq!(
        block_on(token::check(&o, &format!("{t}="), 150)).unwrap_err(),
        TokenError::Malformed
    );
}
