//! Branch tests for `jwt::verify` using hand-built JWKS and stub verifiers (no fixtures).
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use edgekms_core::jwt::{self, Alg, Jwk, Jwks, JwsVerifier, JwtError};
use pollster::block_on;
use serde_json::{Value, json};
use std::cell::Cell;

const ISS: &str = "https://issuer.test";

struct Yes(Cell<u32>);
impl Yes {
    fn new() -> Self {
        Self(Cell::new(0))
    }
}
#[allow(clippy::unused_async_trait_impl)]
impl JwsVerifier for Yes {
    async fn verify(&self, _: Alg, _: &Jwk, _: &[u8], _: &[u8]) -> bool {
        self.0.set(self.0.get() + 1);
        true
    }
}

fn b64(v: &Value) -> String {
    URL_SAFE_NO_PAD.encode(v.to_string())
}
/// An RSA JWK whose modulus is `n_len` bytes with the top bit set, so `8 * n_len` bits.
fn rsa(n_len: usize) -> Value {
    rsa_n(&vec![0xc5u8; n_len])
}
fn rsa_n(n: &[u8]) -> Value {
    json!({"kty":"RSA","kid":"r","n":URL_SAFE_NO_PAD.encode(n),"e":"AQAB"})
}
fn ec() -> Value {
    let c = URL_SAFE_NO_PAD.encode([7u8; 32]);
    json!({"kty":"EC","kid":"e","crv":"P-256","x":c,"y":c})
}
fn jwks(keys: &[Value]) -> Jwks {
    serde_json::from_value(json!({"keys": keys})).unwrap()
}
/// A token with a 64-byte signature, the length ES256 requires.
fn tok(header: &Value, payload: &Value) -> String {
    tok_sig(header, payload, 64)
}
fn tok_sig(header: &Value, payload: &Value, sig_len: usize) -> String {
    raw_tok(&header.to_string(), &payload.to_string(), sig_len)
}
/// A token from literal JSON text, for inputs `serde_json::Value` can't represent (duplicate keys).
fn raw_tok(header: &str, payload: &str, sig_len: usize) -> String {
    format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(payload),
        URL_SAFE_NO_PAD.encode(vec![0u8; sig_len])
    )
}
fn good() -> Value {
    json!({"iss": ISS, "exp": 2_000_000_000u64})
}
fn run(k: &[Value], t: &str, now: u64) -> (Result<jwt::Claims, JwtError>, u32) {
    let v = Yes::new();
    let r = block_on(jwt::verify(t, &jwks(k), &v, ISS, now));
    (r, v.0.get())
}
fn hdr(alg: &str, kid: &str) -> Value {
    json!({"alg": alg, "kid": kid})
}

#[test]
fn stub_baseline_accepts() {
    assert!(
        run(
            &[rsa(256)],
            &tok(&hdr("RS256", "r"), &good()),
            1_900_000_000
        )
        .0
        .is_ok()
    );
}

#[test]
fn short_rsa_modulus_is_key_mismatch() {
    let (r, calls) = run(&[rsa(255)], &tok(&hdr("RS256", "r"), &good()), 1);
    assert_eq!(r.unwrap_err(), JwtError::KeyMismatch);
    assert_eq!(calls, 0);
}

/// The control for the EC mismatch tests below: the same `ec()` key under an ES256 header reaches
/// the verifier and passes, so their `KeyMismatch` comes from the one field each one changes.
#[test]
fn es256_stub_baseline_accepts() {
    let (r, calls) = run(&[ec()], &tok(&hdr("ES256", "e"), &good()), 1_900_000_000);
    assert!(r.is_ok(), "{r:?}");
    assert_eq!(calls, 1);
    let mut with_alg = ec();
    with_alg["alg"] = json!("ES256");
    let (r, calls) = run(
        &[with_alg],
        &tok(&hdr("ES256", "e"), &good()),
        1_900_000_000,
    );
    assert!(r.is_ok(), "{r:?}");
    assert_eq!(calls, 1);
}

#[test]
fn wrong_curve_is_key_mismatch() {
    let mut k = ec();
    k["crv"] = json!("P-384");
    let (r, calls) = run(&[k], &tok(&hdr("ES256", "e"), &good()), 1);
    assert_eq!(r.unwrap_err(), JwtError::KeyMismatch);
    assert_eq!(calls, 0);
}

#[test]
fn jwk_alg_must_equal_header_alg() {
    let mut k = rsa(256);
    k["alg"] = json!("RS384");
    assert_eq!(
        run(&[k], &tok(&hdr("RS256", "r"), &good()), 1)
            .0
            .unwrap_err(),
        JwtError::KeyMismatch
    );
}

#[test]
fn es256_header_with_rsa_key_is_key_mismatch() {
    let (r, calls) = run(&[rsa(256)], &tok(&hdr("ES256", "r"), &good()), 1);
    assert_eq!(r.unwrap_err(), JwtError::KeyMismatch);
    assert_eq!(calls, 0);
}

#[test]
fn incomplete_keys_are_key_mismatch() {
    let mut r = rsa(256);
    r.as_object_mut().unwrap().remove("e");
    assert_eq!(
        run(&[r], &tok(&hdr("RS256", "r"), &good()), 1)
            .0
            .unwrap_err(),
        JwtError::KeyMismatch
    );
    for missing in ["x", "y"] {
        let mut e = ec();
        e.as_object_mut().unwrap().remove(missing);
        assert_eq!(
            run(&[e], &tok(&hdr("ES256", "e"), &good()), 1)
                .0
                .unwrap_err(),
            JwtError::KeyMismatch
        );
    }
}

#[test]
fn bad_base64_and_part_counts_are_malformed() {
    let h = b64(&hdr("RS256", "r"));
    let p = b64(&good());
    let m = |t: String| run(&[rsa(256)], &t, 1).0.unwrap_err();
    assert_eq!(m(format!("{h}=.{p}.AAAA")), JwtError::Malformed);
    assert_eq!(m(format!("{h}.{p}.AA+A")), JwtError::Malformed);
    assert_eq!(m(format!("{h}.{p}.AA/A")), JwtError::Malformed);
    assert_eq!(m(format!("{h}.{p}.AAAA.AAAA")), JwtError::Malformed);
    let non_object = URL_SAFE_NO_PAD.encode("[1]");
    assert_eq!(m(format!("{non_object}.{p}.AAAA")), JwtError::Malformed);
    assert_eq!(m(format!("{h}.{non_object}.AAAA")), JwtError::Malformed);
}

#[test]
fn embedded_jwk_header_is_ignored() {
    let mut h = hdr("RS256", "attacker");
    h["jwk"] = rsa(256);
    let (r, calls) = run(&[rsa(256)], &tok(&h, &good()), 1);
    assert_eq!(r.unwrap_err(), JwtError::UnknownKid("attacker".into()));
    assert_eq!(calls, 0);
}

#[test]
fn none_and_hmac_never_reach_the_verifier() {
    for alg in ["none", "HS256", "HS512", "RS512", "PS256", "ES384"] {
        let (r, calls) = run(&[rsa(256)], &tok(&hdr(alg, "r"), &good()), 1);
        assert_eq!(r.unwrap_err(), JwtError::UnsupportedAlg(alg.into()));
        assert_eq!(calls, 0);
    }
}

#[test]
fn time_claims_are_bounded_and_fail_closed() {
    let k = [rsa(256)];
    let h = hdr("RS256", "r");
    let with = |exp: Value, now: u64| run(&k, &tok(&h, &json!({"iss": ISS, "exp": exp})), now).0;
    // Huge or negative numbers are Malformed; no arithmetic overflow.
    assert_eq!(with(json!(1e300), 1).unwrap_err(), JwtError::Malformed);
    assert_eq!(with(json!(-5), 1).unwrap_err(), JwtError::Malformed);
    // An integer exp at or past 2^63 is out of range, as the same value written as a float is.
    assert_eq!(with(json!(u64::MAX), 1).unwrap_err(), JwtError::Malformed);
    assert_eq!(with(json!(1u64 << 63), 1).unwrap_err(), JwtError::Malformed);
    assert_eq!(with(json!(9.3e18), 1).unwrap_err(), JwtError::Malformed);
    assert!(with(json!((1u64 << 63) - 1), u64::MAX >> 1).is_ok());
    // Non-numbers are MissingExp.
    assert_eq!(with(json!("123"), 1).unwrap_err(), JwtError::MissingExp);
    assert_eq!(with(json!(null), 1).unwrap_err(), JwtError::MissingExp);
    // Fractional exp floors.
    assert!(with(json!(100.9), 160).is_ok());
    assert_eq!(with(json!(100.9), 161).unwrap_err(), JwtError::Expired);
}

#[test]
fn nbf_boundary_and_non_numeric() {
    let k = [rsa(256)];
    let h = hdr("RS256", "r");
    let with = |nbf: Value, now: u64| {
        run(
            &k,
            &tok(
                &h,
                &json!({"iss": ISS, "exp": 4_000_000_000u64, "nbf": nbf}),
            ),
            now,
        )
        .0
    };
    assert!(with(json!(1000), 940).is_ok());
    assert_eq!(with(json!(1000), 939).unwrap_err(), JwtError::NotYetValid);
    assert_eq!(with(json!("1000"), 940).unwrap_err(), JwtError::Malformed);
    assert_eq!(with(json!(1e300), 940).unwrap_err(), JwtError::Malformed);
    assert_eq!(with(json!(-1), 940).unwrap_err(), JwtError::Malformed);
}

#[test]
fn es256_signature_must_be_64_raw_bytes() {
    let h = hdr("ES256", "e");
    // 70 to 72 bytes is what a DER-encoded ECDSA signature usually takes.
    for len in [0, 32, 63, 65, 71, 72] {
        let (r, calls) = run(&[ec()], &tok_sig(&h, &good(), len), 1);
        assert_eq!(r.unwrap_err(), JwtError::BadSignature, "{len}");
        assert_eq!(calls, 0, "{len}");
    }
    assert!(run(&[ec()], &tok_sig(&h, &good(), 64), 1).0.is_ok());
}

#[test]
fn crit_header_is_rejected() {
    // RFC 7515 4.1.11: a recipient must refuse a crit extension it doesn't understand, and edgekms
    // understands none. An empty list is itself invalid.
    for crit in [json!(["b64"]), json!(["exp"]), json!([]), json!("b64")] {
        let mut h = hdr("RS256", "r");
        h["crit"] = crit.clone();
        let (r, calls) = run(&[rsa(256)], &tok(&h, &good()), 1);
        assert_eq!(r.unwrap_err(), JwtError::Malformed, "{crit}");
        assert_eq!(calls, 0, "{crit}");
    }
}

#[test]
fn duplicate_json_keys_are_malformed() {
    let k = [rsa(256)];
    let h = r#"{"alg":"RS256","kid":"r"}"#;
    let p = format!(r#"{{"iss":"{ISS}","exp":2000000000}}"#);
    assert!(run(&k, &raw_tok(h, &p, 64), 1).0.is_ok());
    let dup_headers = [
        r#"{"alg":"RS256","kid":"r","kid":"r"}"#,
        r#"{"alg":"HS256","alg":"RS256","kid":"r"}"#,
        r#"{"alg":"RS256","kid":"r","x":{"a":1,"a":2}}"#,
        r#"{"alg":"RS256","kid":"r","x":[{"a":1,"a":2}]}"#,
    ];
    for dup in dup_headers {
        let (r, calls) = run(&k, &raw_tok(dup, &p, 64), 1);
        assert_eq!(r.unwrap_err(), JwtError::Malformed, "{dup}");
        assert_eq!(calls, 0, "{dup}");
    }
    let dup_payloads = [
        format!(r#"{{"iss":"https://evil.test","iss":"{ISS}","exp":2000000000}}"#),
        format!(r#"{{"iss":"{ISS}","exp":1,"exp":2000000000}}"#),
        format!(r#"{{"iss":"{ISS}","exp":2000000000,"c":{{"ref":"a","ref":"b"}}}}"#),
    ];
    for dup in &dup_payloads {
        assert_eq!(
            run(&k, &raw_tok(h, dup, 64), 1).0.unwrap_err(),
            JwtError::Malformed,
            "{dup}"
        );
    }
}

#[test]
fn attacker_strings_in_errors_are_truncated() {
    let long = "A".repeat(1000);
    let (r, _) = run(&[rsa(256)], &tok(&hdr(&long, "r"), &good()), 1);
    assert_eq!(r.unwrap_err(), JwtError::UnsupportedAlg("A".repeat(64)));
    let (r, _) = run(&[rsa(256)], &tok(&hdr("RS256", &long), &good()), 1);
    assert_eq!(r.unwrap_err(), JwtError::UnknownKid("A".repeat(64)));
    // Truncation counts characters, so it never splits a multi-byte one.
    let wide = "\u{e9}".repeat(100);
    let (r, _) = run(&[rsa(256)], &tok(&hdr("RS256", &wide), &good()), 1);
    assert_eq!(r.unwrap_err(), JwtError::UnknownKid("\u{e9}".repeat(64)));
    let (r, _) = run(&[rsa(256)], &tok(&hdr("RS256", "k2"), &good()), 1);
    assert_eq!(r.unwrap_err(), JwtError::UnknownKid("k2".into()));
}

#[test]
fn encryption_keys_are_dropped_from_a_jwks() {
    let mut enc = rsa(256);
    enc["use"] = json!("enc");
    let mut sig = rsa(256);
    sig["use"] = json!("sig");
    sig["kid"] = json!("s");
    let mut other = rsa(256);
    other["use"] = json!("x-custom");
    other["kid"] = json!("o");
    let set = jwks(&[enc.clone(), sig, other, ec()]);
    let kids: Vec<_> = set.keys.iter().map(|k| k.kid.as_deref().unwrap()).collect();
    assert_eq!(kids, ["s", "e"]);
    let (r, calls) = run(&[enc], &tok(&hdr("RS256", "r"), &good()), 1);
    assert_eq!(r.unwrap_err(), JwtError::UnknownKid("r".into()));
    assert_eq!(calls, 0);
}

#[test]
fn rsa_modulus_is_measured_in_bits() {
    let h = hdr("RS256", "r");
    let check = |n: &[u8]| run(&[rsa_n(n)], &tok(&h, &good()), 1).0;
    // 256 bytes but only 2041 bits: the top byte is 0x01.
    let mut n = vec![0x01u8];
    n.extend([0xffu8; 255]);
    assert_eq!(check(&n).unwrap_err(), JwtError::KeyMismatch);
    // The same value zero-padded to 257 bytes is still 2041 bits.
    n.insert(0, 0);
    assert_eq!(check(&n).unwrap_err(), JwtError::KeyMismatch);
    // 2047 bits fails; 2048 passes, with or without a leading zero byte.
    let mut n = vec![0x7fu8];
    n.extend([0xffu8; 255]);
    assert_eq!(check(&n).unwrap_err(), JwtError::KeyMismatch);
    let mut n = vec![0x80u8];
    n.extend([0u8; 255]);
    assert!(check(&n).is_ok());
    n.insert(0, 0);
    assert!(check(&n).is_ok());
    assert_eq!(check(&[0u8; 300]).unwrap_err(), JwtError::KeyMismatch);
}

#[test]
fn ec_coordinates_must_be_32_bytes() {
    let h = hdr("ES256", "e");
    for coord in ["x", "y"] {
        for bad in [
            URL_SAFE_NO_PAD.encode([7u8; 31]),
            URL_SAFE_NO_PAD.encode([7u8; 33]),
            URL_SAFE_NO_PAD.encode([7u8; 64]),
            "not base64!".to_string(),
        ] {
            let mut k = ec();
            k[coord] = json!(bad);
            let (r, calls) = run(&[k], &tok(&h, &good()), 1);
            assert_eq!(r.unwrap_err(), JwtError::KeyMismatch, "{coord} {bad}");
            assert_eq!(calls, 0);
        }
    }
}

#[test]
fn iat_is_checked_like_nbf() {
    let k = [rsa(256)];
    let h = hdr("RS256", "r");
    let with = |iat: Value| {
        run(
            &k,
            &tok(
                &h,
                &json!({"iss": ISS, "exp": 4_000_000_000u64, "iat": iat}),
            ),
            1,
        )
        .0
    };
    assert!(with(json!(1000)).is_ok());
    assert!(with(json!(1000.5)).is_ok());
    for bad in [
        json!("1000"),
        json!(null),
        json!(-1),
        json!(1e300),
        json!(u64::MAX),
    ] {
        assert_eq!(with(bad.clone()).unwrap_err(), JwtError::Malformed, "{bad}");
    }
}

#[test]
fn numeric_date_floors_and_bounds_every_number_alike() {
    assert_eq!(jwt::numeric_date(&json!(5)), Some(5));
    assert_eq!(jwt::numeric_date(&json!(5.9)), Some(5));
    assert_eq!(
        jwt::numeric_date(&json!((1u64 << 63) - 1)),
        Some((1u64 << 63) - 1)
    );
    assert_eq!(jwt::numeric_date(&json!(1u64 << 63)), None);
    assert_eq!(jwt::numeric_date(&json!(-1)), None);
    assert_eq!(jwt::numeric_date(&json!(-0.5)), None);
    assert_eq!(jwt::numeric_date(&json!("5")), None);
}
