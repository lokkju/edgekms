use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use edgekms_cli::offline::{self, OfflineError};
use edgekms_core::config::Config;
use edgekms_core::keyops::{KeyOps, SoftKeyOps};
use edgekms_core::transit::{self, Ciphertext, DataKey, Id, RootKey};

const ROOT: [u8; 32] = [7; 32];

fn config() -> Config {
    Config::from_json(
        r#"{"root_id":"r1","keys":{"vault":{"id":"k_test","latest_version":2,"min_decryption_version":1}},
            "mounts":{},"roles":{},"policies":{}}"#,
    )
    .unwrap()
}

fn encrypt(version: u32, plaintext: &[u8]) -> String {
    let ops = SoftKeyOps::new(RootKey::new(Id::new("r1").unwrap(), ROOT), rand::rng());
    pollster::block_on(ops.encrypt(&Id::new("k_test").unwrap(), version, plaintext)).unwrap()
}

fn root_b64() -> String {
    format!("{}\n", STANDARD.encode(ROOT))
}

#[test]
fn decrypt_round_trips_a_soft_key_ops_ciphertext() {
    for v in [1, 2] {
        let ct = encrypt(v, b"hello break glass");
        let out = offline::decrypt(&config(), &ROOT, "vault", &ct).unwrap();
        assert_eq!(
            STANDARD.decode(out.plaintext.as_str()).unwrap(),
            b"hello break glass"
        );
        assert_eq!(out.notice, None);
    }
}

#[test]
fn decrypted_debug_leaves_out_the_plaintext() {
    let out =
        offline::decrypt(&config(), &ROOT, "vault", &encrypt(1, b"hello break glass")).unwrap();
    let shown = format!("{out:?}");
    assert!(!shown.contains(out.plaintext.as_str()), "{shown}");
    assert!(shown.contains("<redacted>"), "{shown}");
}

#[test]
fn decrypt_names_a_missing_key() {
    let err = offline::decrypt(&config(), &ROOT, "nope", &encrypt(1, b"x")).unwrap_err();
    assert!(matches!(err, OfflineError::UnknownKey(_)));
    assert!(err.to_string().contains("nope"), "{err}");
}

#[test]
fn decrypt_rejects_a_version_beyond_latest_and_a_wrong_root() {
    let err = offline::decrypt(&config(), &ROOT, "vault", &encrypt(3, b"x")).unwrap_err();
    assert!(matches!(err, OfflineError::BadVersion { .. }), "{err}");
    let err = offline::decrypt(&config(), &[8; 32], "vault", &encrypt(1, b"x")).unwrap_err();
    assert!(matches!(err, OfflineError::Decrypt), "{err}");
    let err = offline::decrypt(&config(), &ROOT, "vault", "not a ciphertext").unwrap_err();
    assert!(matches!(err, OfflineError::Ciphertext(_)), "{err}");
}

#[test]
fn export_matches_the_hkdf_vector_and_decrypts() {
    let b64 = offline::export(&config(), &ROOT, "vault", 1).unwrap();
    let raw: [u8; 32] = STANDARD.decode(b64.as_str()).unwrap().try_into().unwrap();
    let ct: Ciphertext = encrypt(1, b"via export").parse().unwrap();
    let out = transit::decrypt(&DataKey::from_bytes(raw), &ct).unwrap();
    assert_eq!(&*out, b"via export");

    // Core's HKDF vector: root bytes 0..32, r1 / k_test / v1.
    let kat_root: [u8; 32] = std::array::from_fn(|i| u8::try_from(i).unwrap());
    let kat = offline::export(&config(), &kat_root, "vault", 1).unwrap();
    assert_eq!(
        STANDARD.decode(kat.as_str()).unwrap(),
        [
            0xf8, 0xc3, 0x44, 0xd0, 0xaa, 0x08, 0xdc, 0x23, 0xf0, 0x94, 0xd4, 0x82, 0xc4, 0x8f,
            0x51, 0xc0, 0x08, 0xba, 0x74, 0x65, 0xdb, 0x44, 0x3e, 0x29, 0x73, 0xa6, 0x2e, 0xe1,
            0x4f, 0xad, 0xf7, 0x07
        ][..]
    );
}

#[test]
fn export_rejects_unknown_key_and_out_of_range_version() {
    assert!(matches!(
        offline::export(&config(), &ROOT, "nope", 1),
        Err(OfflineError::UnknownKey(_))
    ));
    for v in [0, 3] {
        assert!(matches!(
            offline::export(&config(), &ROOT, "vault", v),
            Err(OfflineError::BadVersion { .. })
        ));
    }
}

#[test]
fn root_key_reads_trimmed_base64_of_exactly_32_bytes() {
    let root = offline::read_root_key(root_b64().as_bytes()).unwrap();
    assert_eq!(*root, ROOT);
}

#[test]
fn bad_root_keys_fail_without_echoing_input() {
    let short = STANDARD.encode([1u8; 31]);
    let long = STANDARD.encode([1u8; 33]);
    for bad in [short.as_str(), long.as_str(), "!!!not base64!!!", ""] {
        let err = offline::read_root_key(bad.as_bytes()).unwrap_err();
        assert!(matches!(err, OfflineError::RootKey(_)), "{err}");
        assert!(!err.to_string().contains(bad) || bad.is_empty(), "{err}");
    }
}

#[test]
fn decrypt_below_min_decryption_version_works_with_a_notice() {
    let config = Config::from_json(
        r#"{"root_id":"r1","keys":{"vault":{"id":"k_test","latest_version":2,"min_decryption_version":2}},
            "mounts":{},"roles":{},"policies":{}}"#,
    )
    .unwrap();
    let out = offline::decrypt(&config, &ROOT, "vault", &encrypt(1, b"old")).unwrap();
    assert_eq!(STANDARD.decode(out.plaintext.as_str()).unwrap(), b"old");
    let notice = out
        .notice
        .expect("a notice for a version the Worker refuses");
    assert!(notice.contains("version 1"), "{notice}");
    assert!(notice.contains("min_decryption_version 2"), "{notice}");
    let out = offline::decrypt(&config, &ROOT, "vault", &encrypt(2, b"new")).unwrap();
    assert_eq!(out.notice, None);
}

#[test]
fn root_key_input_past_the_read_limit_is_refused() {
    let padded = format!("{}{}", root_b64(), " ".repeat(offline::MAX_ROOT_KEY_INPUT));
    let err = offline::read_root_key(padded.as_bytes()).unwrap_err();
    assert!(matches!(err, OfflineError::RootKey(_)), "{err}");
    // Surrounding whitespace up to the limit is still fine.
    let spaced = format!("  {}  ", root_b64());
    assert_eq!(*offline::read_root_key(spaced.as_bytes()).unwrap(), ROOT);
}
