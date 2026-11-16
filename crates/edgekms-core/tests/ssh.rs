use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use edgekms_core::keyops::SoftKeyOps;
use edgekms_core::ssh::{self, SshError};
use edgekms_core::transit::{Id, RootKey};
use pollster::block_on;
use ssh_key::SshSig;

const CHALLENGE: &str = include_str!("fixtures/ssh/challenge.txt");
fn key(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/ssh/{name}.pub",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}
fn sig(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/ssh/{name}.sig",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}
fn ops() -> SoftKeyOps<rand::rngs::ThreadRng> {
    SoftKeyOps::new(RootKey::new(Id::new("r1").unwrap(), [3; 32]), rand::rng())
}

#[test]
fn ed25519_and_ecdsa_signatures_verify() {
    for t in ["ed25519", "ecdsa"] {
        let fp = ssh::verify(&[key(t)], CHALLENGE, &sig(t)).unwrap();
        assert!(fp.starts_with("SHA256:"), "{t}: {fp}");
    }
}
#[test]
fn key_comment_is_ignored_when_matching() {
    let k = key("ed25519");
    let without_comment = k.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
    assert!(ssh::verify(&[without_comment], CHALLENGE, &sig("ed25519")).is_ok());
}
#[test]
fn rsa_is_unsupported() {
    assert_eq!(
        ssh::verify(&[key("rsa")], CHALLENGE, &sig("rsa")).unwrap_err(),
        SshError::UnsupportedKeyType
    );
}
#[test]
fn wrong_namespace_is_rejected() {
    assert_eq!(
        ssh::verify(
            &[key("ed25519")],
            CHALLENGE,
            &sig("ed25519.wrong-namespace")
        )
        .unwrap_err(),
        SshError::WrongNamespace
    );
}
#[test]
fn key_not_in_role_is_rejected() {
    assert_eq!(
        ssh::verify(&[key("other")], CHALLENGE, &sig("ed25519")).unwrap_err(),
        SshError::KeyNotAllowed
    );
}
#[test]
fn signature_over_other_message_is_rejected() {
    assert_eq!(
        ssh::verify(&[key("ed25519")], "ekmsc.other", &sig("ed25519")).unwrap_err(),
        SshError::BadSignature
    );
}
#[test]
fn garbage_signature_is_malformed() {
    assert_eq!(
        ssh::verify(&[key("ed25519")], CHALLENGE, "nope").unwrap_err(),
        SshError::MalformedSignature
    );
}

const ORIGIN: &str = "https://kms.example.com";

#[test]
fn challenge_round_trip_and_expiry() {
    let o = ops();
    let c = block_on(ssh::new_challenge(&o, 1000, ORIGIN)).unwrap();
    assert!(c.starts_with("ekmsc."));
    assert!(c.len() <= ssh::MAX_CHALLENGE_LEN);
    assert!(block_on(ssh::check_challenge(&o, &c, 1060, &[ORIGIN])).is_ok());
    assert_eq!(
        block_on(ssh::check_challenge(&o, &c, 1061, &[ORIGIN])).unwrap_err(),
        SshError::ChallengeExpired
    );
    assert_eq!(
        block_on(ssh::check_challenge(&o, &c, 994, &[ORIGIN])).unwrap_err(),
        SshError::ChallengeFromFuture
    );
}
#[test]
fn challenge_from_other_root_is_rejected() {
    let c = block_on(ssh::new_challenge(&ops(), 1000, ORIGIN)).unwrap();
    let other = SoftKeyOps::new(RootKey::new(Id::new("r1").unwrap(), [4; 32]), rand::rng());
    assert_eq!(
        block_on(ssh::check_challenge(&other, &c, 1000, &[ORIGIN])).unwrap_err(),
        SshError::BadChallengeMac
    );
}
#[test]
fn malformed_challenge_is_rejected() {
    for bad in ["ekmsc.AAAA", "nope", "ekmsc.", "ekmsc.!!!!"] {
        assert_eq!(
            block_on(ssh::check_challenge(&ops(), bad, 1000, &[ORIGIN])).unwrap_err(),
            SshError::MalformedChallenge,
            "{bad}"
        );
        assert_eq!(
            ssh::challenge_origin(bad).unwrap_err(),
            SshError::MalformedChallenge,
            "{bad}"
        );
    }
}

#[test]
fn challenge_carries_its_origin_for_the_client_to_check() {
    let c = block_on(ssh::new_challenge(&ops(), 1000, ORIGIN)).unwrap();
    assert_eq!(ssh::challenge_origin(&c).unwrap(), ORIGIN);
}

#[test]
fn challenge_for_another_origin_is_refused_by_the_server() {
    let o = ops();
    let c = block_on(ssh::new_challenge(&o, 1000, "https://a.example")).unwrap();
    assert_eq!(
        block_on(ssh::check_challenge(&o, &c, 1000, &["https://b.example"])).unwrap_err(),
        SshError::WrongOrigin
    );
}

#[test]
fn challenge_for_any_accepted_origin_passes() {
    let o = ops();
    let c = block_on(ssh::new_challenge(&o, 1000, "https://b.example")).unwrap();
    assert!(
        block_on(ssh::check_challenge(
            &o,
            &c,
            1000,
            &["https://a.example", "https://b.example"]
        ))
        .is_ok()
    );
    assert_eq!(
        block_on(ssh::check_challenge(&o, &c, 1000, &[])).unwrap_err(),
        SshError::WrongOrigin
    );
}

#[test]
fn origin_shape_is_public_for_config_validation() {
    assert!(ssh::valid_origin("https://kms.example.com"));
    assert!(ssh::valid_origin("http://[::1]:8787"));
    for bad in [
        "https://kms.example.com/",
        "kms.example.com",
        "https://a b",
        "",
    ] {
        assert!(!ssh::valid_origin(bad), "{bad:?}");
    }
}

#[test]
fn origin_is_covered_by_the_mac() {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let o = ops();
    let c = block_on(ssh::new_challenge(&o, 1000, "https://a.example")).unwrap();
    let mut raw = URL_SAFE_NO_PAD.decode(&c["ekmsc.".len()..]).unwrap();
    let n = raw.len();
    raw[n - 9..].copy_from_slice(b"b.example");
    let forged = format!("ekmsc.{}", URL_SAFE_NO_PAD.encode(raw));
    assert_eq!(ssh::challenge_origin(&forged).unwrap(), "https://b.example");
    assert_eq!(
        block_on(ssh::check_challenge(
            &o,
            &forged,
            1000,
            &["https://b.example"]
        ))
        .unwrap_err(),
        SshError::BadChallengeMac
    );
}

#[test]
fn bad_origins_are_refused_when_minting() {
    let too_long = format!("https://{}", "a".repeat(ssh::MAX_ORIGIN_LEN));
    for bad in [
        "",
        "kms.example.com",
        "https://",
        "https://a b",
        "https://k/\n",
        &too_long,
    ] {
        assert_eq!(
            block_on(ssh::new_challenge(&ops(), 1000, bad)).unwrap_err(),
            SshError::BadOrigin,
            "{bad:?}"
        );
    }
}

#[test]
fn oversized_challenge_is_malformed_before_decoding() {
    let huge = format!("ekmsc.{}", "A".repeat(ssh::MAX_CHALLENGE_LEN));
    assert_eq!(
        ssh::challenge_origin(&huge).unwrap_err(),
        SshError::MalformedChallenge
    );
}

/// The raw bytes of a fresh challenge for [`ORIGIN`]:
/// `ts (8) || random (16) || mac (32) || origin`.
fn raw_challenge(o: &SoftKeyOps<rand::rngs::ThreadRng>, now: u64) -> Vec<u8> {
    let c = block_on(ssh::new_challenge(o, now, ORIGIN)).unwrap();
    URL_SAFE_NO_PAD
        .decode(c.strip_prefix("ekmsc.").unwrap())
        .unwrap()
}
fn encode_challenge(raw: &[u8]) -> String {
    format!("ekmsc.{}", URL_SAFE_NO_PAD.encode(raw))
}

#[test]
fn challenge_with_any_flipped_bit_fails_the_mac() {
    let o = ops();
    let raw = raw_challenge(&o, 1000);
    assert_eq!(raw.len(), 56 + ORIGIN.len());
    // A bit in the timestamp, the random part and the tag, at both ends of each, and one in the
    // origin that keeps it well-formed ('k' of kms becomes 'j').
    for (byte, bit) in [(0, 0), (7, 7), (8, 0), (23, 7), (24, 0), (55, 7), (64, 0)] {
        let mut bad = raw.clone();
        bad[byte] ^= 1 << bit;
        assert_eq!(
            block_on(ssh::check_challenge(
                &o,
                &encode_challenge(&bad),
                1000,
                &[ORIGIN]
            ))
            .unwrap_err(),
            SshError::BadChallengeMac,
            "byte {byte} bit {bit}"
        );
    }
}

#[test]
fn challenge_one_byte_short_or_long_is_malformed() {
    let o = ops();
    let raw = raw_challenge(&o, 1000);
    // One byte short of the fixed part leaves no origin; a trailing NUL isn't an origin.
    let mut long = raw.clone();
    long.push(0);
    for bad in [&raw[..55], &long[..]] {
        assert_eq!(
            block_on(ssh::check_challenge(
                &o,
                &encode_challenge(bad),
                1000,
                &[ORIGIN]
            ))
            .unwrap_err(),
            SshError::MalformedChallenge,
            "{} bytes",
            bad.len()
        );
    }
}

#[test]
fn challenge_with_wrong_prefix_is_malformed() {
    let o = ops();
    let c = block_on(ssh::new_challenge(&o, 1000, ORIGIN)).unwrap();
    let body = c.strip_prefix("ekmsc.").unwrap();
    for bad in [
        body.to_owned(),
        format!("ekms.{body}"),
        format!("EKMSC.{body}"),
        format!("ekmsc-{body}"),
        format!(" ekmsc.{body}"),
    ] {
        assert_eq!(
            block_on(ssh::check_challenge(&o, &bad, 1000, &[ORIGIN])).unwrap_err(),
            SshError::MalformedChallenge,
            "{bad}"
        );
    }
    // The control: the same body under the right prefix passes.
    assert!(
        block_on(ssh::check_challenge(
            &o,
            &format!("ekmsc.{body}"),
            1000,
            &[ORIGIN]
        ))
        .is_ok()
    );
}

#[test]
fn ecdsa_signature_against_another_ecdsa_key_is_rejected() {
    assert_eq!(
        ssh::verify(&[key("other-ecdsa")], CHALLENGE, &sig("ecdsa")).unwrap_err(),
        SshError::KeyNotAllowed
    );
    // An Ed25519 allow list never matches an ECDSA signer either.
    assert_eq!(
        ssh::verify(&[key("ed25519"), key("other")], CHALLENGE, &sig("ecdsa")).unwrap_err(),
        SshError::KeyNotAllowed
    );
    assert!(
        ssh::verify(
            &[key("other-ecdsa"), key("ecdsa")],
            CHALLENGE,
            &sig("ecdsa")
        )
        .is_ok()
    );
}

#[test]
fn sha256_sshsig_verifies() {
    let s = sig("sha256");
    assert_eq!(
        SshSig::from_pem(&s).unwrap().hash_alg(),
        ssh_key::HashAlg::Sha256
    );
    let fp = ssh::verify(&[key("sha256")], CHALLENGE, &s).unwrap();
    assert!(fp.starts_with("SHA256:"), "{fp}");
    assert_eq!(
        ssh::verify(&[key("sha256")], "ekmsc.other", &s).unwrap_err(),
        SshError::BadSignature
    );
}

mod sk {
    use super::CHALLENGE;
    use ed25519_dalek::{Signer, SigningKey};
    use edgekms_core::ssh::{self, SshError};
    use sha2::{Digest, Sha256};
    use ssh_key::public::{Ed25519PublicKey, KeyData, SkEd25519};
    use ssh_key::{Algorithm, HashAlg, LineEnding, PublicKey, Signature, SshSig};

    /// A software sk-ssh-ed25519 key and its SSHSIG over `CHALLENGE` with the given flags.
    fn sk_login(flags: u8) -> (String, String) {
        let sk = SigningKey::from_bytes(&[9; 32]);
        let app = "ssh:";
        let data = KeyData::SkEd25519(SkEd25519::new(
            Ed25519PublicKey(sk.verifying_key().to_bytes()),
            app,
        ));
        let counter = 7u32.to_be_bytes();
        let signed = SshSig::signed_data("edgekms", HashAlg::Sha512, CHALLENGE.as_bytes()).unwrap();
        let mut sk_data = Sha256::digest(app).to_vec();
        sk_data.push(flags);
        sk_data.extend(counter);
        sk_data.extend(Sha256::digest(&signed));
        let mut blob = sk.sign(&sk_data).to_bytes().to_vec();
        blob.push(flags);
        blob.extend(counter);
        let sig = Signature::new(Algorithm::SkEd25519, blob).unwrap();
        let armored = SshSig::new(data.clone(), "edgekms", HashAlg::Sha512, sig)
            .unwrap()
            .to_pem(LineEnding::LF)
            .unwrap();
        (PublicKey::from(data).to_openssh().unwrap(), armored)
    }

    #[test]
    fn touched_sk_signature_verifies() {
        let (k, s) = sk_login(0x01);
        assert!(
            ssh::verify(&[k], CHALLENGE, &s)
                .unwrap()
                .starts_with("SHA256:")
        );
    }

    #[test]
    fn sk_signature_without_user_presence_is_rejected() {
        // The signature itself is valid (it signs the flags byte), so only the missing
        // user-presence bit can produce this error.
        let (k, s) = sk_login(0x00);
        assert_eq!(
            ssh::verify(&[k], CHALLENGE, &s).unwrap_err(),
            SshError::UserNotPresent
        );
    }

    #[test]
    fn sk_signature_with_other_flags_but_no_user_presence_is_rejected() {
        // 0x04 is user verification (a PIN), which doesn't stand in for a touch.
        let (k, s) = sk_login(0x04);
        assert_eq!(
            ssh::verify(&[k], CHALLENGE, &s).unwrap_err(),
            SshError::UserNotPresent
        );
    }

    #[test]
    fn tampered_flags_are_a_bad_signature_not_missing_presence() {
        // Clearing the presence bit after signing breaks the signature over the flags, and
        // the signature check comes first.
        let (k, s) = sk_login(0x01);
        let sig = SshSig::from_pem(&s).unwrap();
        let mut blob = sig.signature_bytes().to_vec();
        let flags = blob.len() - 5;
        blob[flags] = 0x00;
        let tampered = SshSig::new(
            sig.public_key().clone(),
            "edgekms",
            HashAlg::Sha512,
            Signature::new(Algorithm::SkEd25519, blob).unwrap(),
        )
        .unwrap()
        .to_pem(LineEnding::LF)
        .unwrap();
        assert_eq!(
            ssh::verify(&[k], CHALLENGE, &tampered).unwrap_err(),
            SshError::BadSignature
        );
    }
}
