use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use edgekms_core::config::{ClaimMatch, Role};
use edgekms_core::jwt::{self, Alg, Jwk, Jwks, JwsVerifier, JwtError};
use edgekms_core::role::{self, RoleError};
use pollster::block_on;
use std::collections::BTreeMap;

const NOW: u64 = 2_000_000_000;

struct Ring;
#[allow(clippy::unused_async_trait_impl)]
impl JwsVerifier for Ring {
    async fn verify(&self, alg: Alg, key: &Jwk, input: &[u8], sig: &[u8]) -> bool {
        use ring::signature as s;
        let d = |v: &Option<String>| URL_SAFE_NO_PAD.decode(v.as_deref().unwrap()).unwrap();
        match alg {
            Alg::Rs256 => s::RsaPublicKeyComponents {
                n: d(&key.n),
                e: d(&key.e),
            }
            .verify(&s::RSA_PKCS1_2048_8192_SHA256, input, sig)
            .is_ok(),
            Alg::Es256 => {
                let mut pt = vec![4u8];
                pt.extend(d(&key.x));
                pt.extend(d(&key.y));
                s::UnparsedPublicKey::new(&s::ECDSA_P256_SHA256_FIXED, pt)
                    .verify(input, sig)
                    .is_ok()
            }
        }
    }
}

struct Fixtures {
    issuer: String,
    jwks: Jwks,
    cases: BTreeMap<String, String>,
}
fn fx() -> Fixtures {
    let v: serde_json::Value = serde_json::from_str(include_str!("fixtures/jwt.json")).unwrap();
    Fixtures {
        issuer: v["issuer"].as_str().unwrap().into(),
        jwks: serde_json::from_value(v["jwks"].clone()).unwrap(),
        cases: serde_json::from_value(v["cases"].clone()).unwrap(),
    }
}
fn run(case: &str) -> Result<jwt::Claims, JwtError> {
    let f = fx();
    block_on(jwt::verify(&f.cases[case], &f.jwks, &Ring, &f.issuer, NOW))
}

#[test]
fn valid_tokens_verify() {
    assert!(run("valid_rs256").is_ok());
    assert!(run("valid_es256").is_ok());
}
#[test]
fn expired_is_rejected() {
    assert_eq!(run("expired").unwrap_err(), JwtError::Expired);
}
#[test]
fn not_yet_valid_is_rejected() {
    assert_eq!(run("not_yet_valid").unwrap_err(), JwtError::NotYetValid);
}
#[test]
fn missing_exp_is_rejected() {
    assert_eq!(run("no_exp").unwrap_err(), JwtError::MissingExp);
}
#[test]
fn wrong_issuer_is_rejected() {
    assert_eq!(run("wrong_issuer").unwrap_err(), JwtError::WrongIssuer);
}
#[test]
fn unknown_kid_is_reported_for_refetch() {
    assert_eq!(
        run("unknown_kid").unwrap_err(),
        JwtError::UnknownKid("rsa2".into())
    );
}
#[test]
fn missing_kid_is_rejected() {
    assert_eq!(run("missing_kid").unwrap_err(), JwtError::MissingKid);
}
#[test]
fn bad_signatures_are_rejected() {
    assert_eq!(run("bad_signature").unwrap_err(), JwtError::BadSignature);
    assert_eq!(
        run("signed_by_other_key").unwrap_err(),
        JwtError::BadSignature
    );
}
#[test]
fn alg_key_confusion_is_rejected() {
    assert_eq!(
        run("rs256_header_ec_key").unwrap_err(),
        JwtError::KeyMismatch
    );
}
#[test]
fn none_and_hmac_algs_are_rejected() {
    assert_eq!(
        run("alg_none").unwrap_err(),
        JwtError::UnsupportedAlg("none".into())
    );
    assert_eq!(
        run("hs256_with_public_key").unwrap_err(),
        JwtError::UnsupportedAlg("HS256".into())
    );
}
#[test]
fn malformed_is_rejected() {
    assert_eq!(run("two_parts").unwrap_err(), JwtError::Malformed);
}
#[test]
fn expiry_leeway_is_sixty_seconds() {
    let f = fx();
    let t = &f.cases["expired"]; // exp = 1_000_000_100
    assert!(block_on(jwt::verify(t, &f.jwks, &Ring, &f.issuer, 1_000_000_160)).is_ok());
    assert_eq!(
        block_on(jwt::verify(t, &f.jwks, &Ring, &f.issuer, 1_000_000_161)).unwrap_err(),
        JwtError::Expired
    );
}

fn role(claims: &[(&str, ClaimMatch)], not_before: u64) -> Role {
    Role {
        mount: "github".into(),
        bound_audiences: vec!["https://kms.test".into()],
        bound_claims: claims
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect(),
        ssh_keys: vec![],
        github_user_ids: vec![],
        policies: vec!["p".into()],
        token_ttl_secs: 900,
        not_before,
    }
}

#[test]
fn role_matches_exact_and_glob_claims() {
    let c = run("valid_rs256").unwrap();
    assert!(
        role::check_jwt_role(
            &role(
                &[
                    ("repository_id", ClaimMatch::Exact("42".into())),
                    (
                        "ref",
                        ClaimMatch::Glob {
                            glob: "refs/heads/*".into()
                        }
                    )
                ],
                0
            ),
            &c
        )
        .is_ok()
    );
}
#[test]
fn role_rejects_mismatched_or_missing_claims() {
    let c = run("valid_rs256").unwrap();
    assert_eq!(
        role::check_jwt_role(
            &role(&[("repository_id", ClaimMatch::Exact("43".into()))], 0),
            &c
        )
        .unwrap_err(),
        RoleError::ClaimMismatch("repository_id".into())
    );
    assert_eq!(
        role::check_jwt_role(
            &role(&[("environment", ClaimMatch::Exact("prod".into()))], 0),
            &c
        )
        .unwrap_err(),
        RoleError::ClaimMismatch("environment".into())
    );
}
#[test]
fn role_rejects_non_string_claims() {
    let c = run("numeric_repository_id").unwrap();
    assert_eq!(
        role::check_jwt_role(
            &role(&[("repository_id", ClaimMatch::Exact("42".into()))], 0),
            &c
        )
        .unwrap_err(),
        RoleError::ClaimMismatch("repository_id".into())
    );
}
#[test]
fn role_checks_audience_string_and_list() {
    let mut r = role(&[("repository_id", ClaimMatch::Exact("42".into()))], 0);
    assert!(role::check_jwt_role(&r, &run("aud_list").unwrap()).is_ok());
    r.bound_audiences = vec!["https://other".into()];
    assert_eq!(
        role::check_jwt_role(&r, &run("valid_rs256").unwrap()).unwrap_err(),
        RoleError::AudienceMismatch
    );
}
#[test]
fn role_not_before_reads_iat_like_exp_and_nbf() {
    let r = role(
        &[("repository_id", ClaimMatch::Exact("42".into()))],
        1_000_000_000,
    );
    let claims = |iat: serde_json::Value| -> jwt::Claims {
        serde_json::from_value(serde_json::json!({
            "aud": "https://kms.test", "repository_id": "42", "iat": iat
        }))
        .unwrap()
    };
    // A fractional iat floors, as exp and nbf do.
    assert!(role::check_jwt_role(&r, &claims(serde_json::json!(1_000_000_000.5))).is_ok());
    assert_eq!(
        role::check_jwt_role(&r, &claims(serde_json::json!(999_999_999.9))).unwrap_err(),
        RoleError::IssuedBeforeNotBefore
    );
    // At or past 2^63, or negative, it fails closed.
    for bad in [
        serde_json::json!(u64::MAX),
        serde_json::json!(1u64 << 63),
        serde_json::json!(-1),
    ] {
        assert_eq!(
            role::check_jwt_role(&r, &claims(bad.clone())).unwrap_err(),
            RoleError::IssuedBeforeNotBefore,
            "{bad}"
        );
    }
}

#[test]
fn role_not_before_rejects_older_tokens() {
    let c = run("valid_rs256").unwrap(); // iat = 1_000_000_000
    assert!(
        role::check_jwt_role(
            &role(
                &[("repository_id", ClaimMatch::Exact("42".into()))],
                1_000_000_000
            ),
            &c
        )
        .is_ok()
    );
    assert_eq!(
        role::check_jwt_role(
            &role(
                &[("repository_id", ClaimMatch::Exact("42".into()))],
                1_000_000_001
            ),
            &c
        )
        .unwrap_err(),
        RoleError::IssuedBeforeNotBefore
    );
}
