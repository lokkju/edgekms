use std::collections::HashMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use edgekms_core::transit::{self, Ciphertext, DataKey, Error, Id, RootKey};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    keys: HashMap<u32, String>,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    plaintext: String,
    ciphertext: String,
}

fn openbao() -> Vectors {
    serde_json::from_str(include_str!("vectors/openbao.json")).unwrap()
}

fn data_key(b64: &str) -> DataKey {
    DataKey::from_bytes(STANDARD.decode(b64).unwrap().try_into().unwrap())
}

fn test_key() -> DataKey {
    DataKey::from_bytes([7; 32])
}

fn root(id: &str) -> RootKey {
    let bytes: [u8; 32] = std::array::from_fn(|i| u8::try_from(i).unwrap());
    RootKey::new(Id::new(id).unwrap(), bytes)
}

#[test]
fn decrypts_openbao_ciphertext_with_the_exported_key() {
    let v = openbao();
    for case in &v.cases {
        let ct: Ciphertext = case.ciphertext.parse().unwrap();
        let key = data_key(&v.keys[&ct.version()]);
        let plaintext = transit::decrypt(&key, &ct).unwrap();
        assert_eq!(
            STANDARD.encode(&*plaintext),
            case.plaintext,
            "{}",
            case.ciphertext
        );
    }
}

#[test]
fn encrypt_round_trips_and_writes_vault_prefix() {
    let ct = transit::encrypt(&test_key(), 3, b"data key", &mut rand::rng()).unwrap();
    assert!(ct.starts_with("vault:v3:"), "{ct}");
    let parsed: Ciphertext = ct.parse().unwrap();
    assert_eq!(parsed.version(), 3);
    assert_eq!(
        &*transit::decrypt(&test_key(), &parsed).unwrap(),
        b"data key"
    );
}

#[test]
fn encrypt_uses_a_fresh_nonce_each_time() {
    let a = transit::encrypt(&test_key(), 1, b"same", &mut rand::rng()).unwrap();
    let b = transit::encrypt(&test_key(), 1, b"same", &mut rand::rng()).unwrap();
    assert_ne!(a, b);
}

#[test]
fn decrypt_rejects_a_tampered_ciphertext() {
    let ct = transit::encrypt(&test_key(), 1, b"secret", &mut rand::rng()).unwrap();
    let mut payload = STANDARD
        .decode(ct.strip_prefix("vault:v1:").unwrap())
        .unwrap();
    payload[13] ^= 1;
    let tampered: Ciphertext = format!("vault:v1:{}", STANDARD.encode(payload))
        .parse()
        .unwrap();
    assert_eq!(
        transit::decrypt(&test_key(), &tampered).unwrap_err(),
        Error::Decrypt
    );
}

#[test]
fn decrypt_rejects_the_wrong_key() {
    let ct: Ciphertext = transit::encrypt(&test_key(), 1, b"secret", &mut rand::rng())
        .unwrap()
        .parse()
        .unwrap();
    let other = DataKey::from_bytes([8; 32]);
    assert_eq!(transit::decrypt(&other, &ct).unwrap_err(), Error::Decrypt);
}

#[test]
fn parse_rejects_malformed_ciphertext() {
    let short = STANDARD.encode([0u8; 27]);
    for bad in [
        String::new(),
        "vault:".into(),
        "vault:v1".into(),
        "vault:v1:".into(),
        "vault:v0:AAAA".into(),
        "vault:v01:AAAA".into(),
        "vault:vx:AAAA".into(),
        "vault:v-1:AAAA".into(),
        "vault:v1:!!!!".into(),
        "vault:v1: AAAA".into(),
        "bao:v1:AAAA".into(),
        format!("vault:v1:{short}"),
    ] {
        assert!(
            matches!(bad.parse::<Ciphertext>(), Err(Error::Malformed(_))),
            "{bad:?}"
        );
    }
}

#[test]
fn parse_and_display_round_trip() {
    for case in &openbao().cases {
        let ct: Ciphertext = case.ciphertext.parse().unwrap();
        assert_eq!(ct.to_string(), case.ciphertext);
    }
}

#[test]
fn derivation_matches_independent_hkdf_vectors() {
    // Computed with Python's `cryptography` HKDF; see docs/security-model.md#named-keys.
    let k = Id::new("k_test").unwrap();
    let cases = [
        (
            "r1",
            1,
            "f8c344d0aa08dc23f094d482c48f51c008ba7465db443e2973a62ee14fadf707",
        ),
        (
            "r1",
            2,
            "79fbe8330c2b7606e642d6f6ad801d6e94ab9ea48e454fbefe0dbc735d9d2183",
        ),
        (
            "r2",
            1,
            "1c7aa0a46b7dd2c2f72208d30422f5fb3cf788ac9b84969f6e385d57d033ff1b",
        ),
    ];
    for (root_id, version, hex) in cases {
        let derived = root(root_id).transit_key(&k, version);
        let ct = transit::encrypt(&derived, version, b"probe", &mut rand::rng()).unwrap();
        let expected = DataKey::from_bytes(decode_hex(hex));
        let parsed: Ciphertext = ct.parse().unwrap();
        assert_eq!(
            &*transit::decrypt(&expected, &parsed).unwrap(),
            b"probe",
            "{root_id} v{version}"
        );
    }
}

#[test]
fn id_accepts_only_lowercase_alphanumerics_and_underscore() {
    for good in ["k_7f3a9c1e", "r1", "a"] {
        assert!(Id::new(good).is_ok(), "{good}");
    }
    for bad in ["", "a/b", "K1", "k-1", "k 1", "k.1", "ключ"] {
        assert!(Id::new(bad).is_err(), "{bad}");
    }
}

fn decode_hex(s: &str) -> [u8; 32] {
    std::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
}

#[test]
fn from_parts_rebuilds_a_parsed_ciphertext() {
    let s = transit::encrypt(&test_key(), 4, b"x", &mut rand::rng()).unwrap();
    let ct: Ciphertext = s.parse().unwrap();
    assert_eq!(ct.sealed().len(), 1 + 16);
    let rebuilt = Ciphertext::from_parts(4, ct.nonce(), ct.sealed()).unwrap();
    assert_eq!(rebuilt, ct);
    assert_eq!(rebuilt.to_string(), s);
}

#[test]
fn from_parts_rejects_version_zero_and_a_missing_tag() {
    assert!(matches!(
        Ciphertext::from_parts(0, &[0; 12], &[0; 16]),
        Err(Error::Malformed(_))
    ));
    assert!(matches!(
        Ciphertext::from_parts(1, &[0; 12], &[0; 15]),
        Err(Error::Malformed(_))
    ));
    assert!(Ciphertext::from_parts(1, &[0; 12], &[0; 16]).is_ok());
}

#[test]
fn encrypt_rejects_version_zero() {
    // vault:v0: is a ciphertext no parser here, or in Vault, accepts back.
    assert!(matches!(
        transit::encrypt(&test_key(), 0, b"x", &mut rand::rng()),
        Err(Error::Malformed(_))
    ));
}

#[test]
fn backend_error_displays_only_its_label() {
    assert_eq!(
        Error::Backend("hmac").to_string(),
        "key backend failure: hmac"
    );
}

#[test]
fn export_transit_key_matches_hkdf_vector() {
    let k = Id::new("k_test").unwrap();
    let raw = root("r1").export_transit_key(&k, 1);
    assert_eq!(
        *raw,
        decode_hex("f8c344d0aa08dc23f094d482c48f51c008ba7465db443e2973a62ee14fadf707")
    );
}
