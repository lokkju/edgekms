//! The control plane's use of `edgekms_core::ssh` (lokkju/edgekms#16): challenge purposes and
//! TTLs, verification against the key embedded in a signature or against a named key, and the
//! public key and key id rules.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use edgekms_core::keyops::{KeyOps, MacPurpose, SoftKeyOps};
use edgekms_core::ssh::{self, KeyError, SshError};
use edgekms_core::transit::{Id, RootKey};
use pollster::block_on;
use rand::SeedableRng as _;

const CHALLENGE: &str = include_str!("fixtures/ssh/challenge.txt");
const ORIGIN: &str = "https://api.example.com";
const ED25519_FP: &str = "SHA256:s+32EFD9PwLcLNw19M31vuVO4Kw50eoa+/VVH7zTFAA";
const ECDSA_FP: &str = "SHA256:QTGyY/iMP1GRM64kaA+RnOAFoUF7GsEvba7Ca9dMp44";

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/ssh/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}
fn ops() -> SoftKeyOps<rand::rngs::ThreadRng> {
    SoftKeyOps::new(RootKey::new(Id::new("r1").unwrap(), [3; 32]), rand::rng())
}
fn signer(seed: u8) -> ssh_key::PrivateKey {
    ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[seed; 32]))
}
fn sign(k: &ssh_key::PrivateKey, namespace: &str, msg: &str) -> String {
    k.sign(namespace, ssh_key::HashAlg::Sha512, msg.as_bytes())
        .unwrap()
        .to_pem(ssh_key::LineEnding::LF)
        .unwrap()
}
fn line(k: &ssh_key::PrivateKey) -> String {
    k.public_key().to_openssh().unwrap()
}

#[test]
fn control_challenge_purposes_do_not_cross() {
    let o = ops();
    let purposes = [
        MacPurpose::Challenge,
        MacPurpose::ControlChallenge,
        MacPurpose::SshKeyProof,
    ];
    for minted in purposes {
        let c = block_on(ssh::new_challenge_with(&o, minted, 1000, ORIGIN)).unwrap();
        for checked in purposes {
            let r = block_on(ssh::check_challenge_with(
                &o,
                checked,
                60,
                &c,
                1000,
                &[ORIGIN],
            ));
            if minted == checked {
                assert!(r.is_ok(), "{minted:?}");
            } else {
                assert_eq!(
                    r.unwrap_err(),
                    SshError::BadChallengeMac,
                    "{minted:?} as {checked:?}"
                );
            }
        }
    }
    // The data plane's check refuses a control challenge too.
    let c = block_on(ssh::new_challenge_with(
        &o,
        MacPurpose::ControlChallenge,
        1000,
        ORIGIN,
    ))
    .unwrap();
    assert_eq!(
        block_on(ssh::check_challenge(&o, &c, 1000, &[ORIGIN])).unwrap_err(),
        SshError::BadChallengeMac
    );
}

#[test]
fn mac_purpose_infos() {
    assert_eq!(
        MacPurpose::ControlChallenge.info(),
        "mac/control-challenge/v1"
    );
    assert_eq!(MacPurpose::SshKeyProof.info(), "mac/ssh-key-proof/v1");
    assert_eq!(MacPurpose::SshKey.info(), "mac/ssh-key/v1");
}

/// `new_challenge` produces the bytes it did before the purpose-taking pair existed: the vector
/// was recorded from the code before the change, with this seed.
#[test]
fn existing_challenge_bytes_are_unchanged() {
    let seeded = || {
        SoftKeyOps::new(
            RootKey::new(Id::new("r1").unwrap(), [3; 32]),
            rand::rngs::StdRng::seed_from_u64(7),
        )
    };
    let c = block_on(ssh::new_challenge(&seeded(), 1000, ORIGIN)).unwrap();
    assert_eq!(c, EXPECTED_SEED7);
    let with = block_on(ssh::new_challenge_with(
        &seeded(),
        MacPurpose::Challenge,
        1000,
        ORIGIN,
    ))
    .unwrap();
    assert_eq!(with, c);
    assert!(block_on(ssh::check_challenge(&ops(), &c, 1000, &[ORIGIN])).is_ok());
}
const EXPECTED_SEED7: &str = "ekmsc.AAAAAAAAA-i--6hq6eDCB4ZffiToNJ1OcPNXcm-m-lfxBsz4nZoJVyucvkiInnMkJy589pNJi1lodHRwczovL2FwaS5leGFtcGxlLmNvbQ";

#[test]
fn check_challenge_with_honors_its_ttl_and_returns_the_tag() {
    let o = ops();
    let c = block_on(ssh::new_challenge_with(
        &o,
        MacPurpose::SshKeyProof,
        1000,
        ORIGIN,
    ))
    .unwrap();
    let check = |now| {
        block_on(ssh::check_challenge_with(
            &o,
            MacPurpose::SshKeyProof,
            ssh::SSH_KEY_PROOF_TTL_SECS,
            &c,
            now,
            &[ORIGIN],
        ))
    };
    let ok = check(1300).unwrap();
    assert_eq!(ok.expires_at, 1300);
    let raw = URL_SAFE_NO_PAD.decode(&c["ekmsc.".len()..]).unwrap();
    assert_eq!(&ok.tag[..], &raw[24..56]);
    let mac = block_on(o.mac(MacPurpose::SshKeyProof, &[&raw[..24], &raw[56..]].concat())).unwrap();
    assert_eq!(ok.tag, mac);
    assert_eq!(check(1301).unwrap_err(), SshError::ChallengeExpired);
    assert_eq!(ssh::SSH_KEY_PROOF_TTL_SECS, 300);
}

#[test]
fn verify_embedded_accepts_each_supported_type() {
    // The fingerprints are what `ssh-keygen -lf` prints for the fixtures.
    for (t, fp, kt) in [
        ("ed25519", ED25519_FP, "ssh-ed25519"),
        ("ecdsa", ECDSA_FP, "ecdsa-sha2-nistp256"),
    ] {
        let v = ssh::verify_embedded(CHALLENGE, &fixture(&format!("{t}.sig"))).unwrap();
        assert_eq!(v.fingerprint, fp, "{t}");
        assert_eq!(v.key_type, kt, "{t}");
        let want = fixture(&format!("{t}.pub"));
        let want = want
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(v.public_key, want, "{t}");
    }
}

#[test]
fn verify_embedded_refusals() {
    assert_eq!(
        ssh::verify_embedded(CHALLENGE, &fixture("rsa.sig")).unwrap_err(),
        SshError::UnsupportedKeyType
    );
    assert_eq!(
        ssh::verify_embedded(CHALLENGE, &fixture("ed25519.wrong-namespace.sig")).unwrap_err(),
        SshError::WrongNamespace
    );
    assert_eq!(
        ssh::verify_embedded("ekmsc.other", &fixture("ed25519.sig")).unwrap_err(),
        SshError::BadSignature
    );
    assert_eq!(
        ssh::verify_embedded(CHALLENGE, "nope").unwrap_err(),
        SshError::MalformedSignature
    );
    // A registration proof never logs in.
    let k = signer(1);
    assert_eq!(
        ssh::verify_embedded(CHALLENGE, &sign(&k, ssh::REGISTER_NAMESPACE, CHALLENGE)).unwrap_err(),
        SshError::WrongNamespace
    );
    assert!(ssh::verify_embedded(CHALLENGE, &sign(&k, ssh::NAMESPACE, CHALLENGE)).is_ok());
}

#[test]
fn verify_proof_needs_the_named_key_and_namespace() {
    let k = signer(1);
    let other = signer(2);
    let proof = sign(&k, ssh::REGISTER_NAMESPACE, CHALLENGE);
    let v = ssh::verify_proof(&line(&k), CHALLENGE, &proof).unwrap();
    assert_eq!(
        v.fingerprint,
        k.public_key()
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string()
    );
    let commented = format!("{} me@laptop", line(&k));
    assert!(ssh::verify_proof(&commented, CHALLENGE, &proof).is_ok());
    assert_eq!(
        ssh::verify_proof(&line(&other), CHALLENGE, &proof).unwrap_err(),
        SshError::KeyNotAllowed
    );
    assert_eq!(
        ssh::verify_proof(&line(&k), CHALLENGE, &sign(&k, ssh::NAMESPACE, CHALLENGE)).unwrap_err(),
        SshError::WrongNamespace
    );
    assert_eq!(
        ssh::verify_proof(&line(&k), "ekmsc.other", &proof).unwrap_err(),
        SshError::BadSignature
    );
    assert_eq!(
        ssh::verify_proof("garbage", CHALLENGE, &proof).unwrap_err(),
        SshError::KeyNotAllowed
    );
}

#[test]
fn parse_public_key_rules() {
    let p = ssh::parse_public_key(&fixture("ed25519.pub")).unwrap();
    assert_eq!(p.key_type, "ssh-ed25519");
    assert_eq!(p.comment, "fixture-ed25519");
    assert_eq!(p.fingerprint, ED25519_FP);
    assert!(!p.public_key.contains("fixture"));
    assert_eq!(p.public_key.split(' ').count(), 2);
    assert_eq!(
        ssh::parse_public_key(&fixture("ecdsa.pub"))
            .unwrap()
            .key_type,
        "ecdsa-sha2-nistp256"
    );
    assert_eq!(
        ssh::parse_public_key(&fixture("rsa.pub")).unwrap_err(),
        KeyError::Unsupported
    );
    let two = format!("{}{}", fixture("ed25519.pub"), fixture("other.pub"));
    let huge = format!("ssh-ed25519 {}", "A".repeat(ssh::MAX_PUBLIC_KEY_BYTES));
    for bad in [
        "",
        "garbage",
        "ssh-ed25519 !!!!",
        two.as_str(),
        huge.as_str(),
    ] {
        assert_eq!(
            ssh::parse_public_key(bad).unwrap_err(),
            KeyError::Invalid,
            "{bad:.40}"
        );
    }
}

#[test]
fn key_id_round_trips() {
    let id = ssh::key_id(ED25519_FP).unwrap();
    assert_eq!(id, "s-32EFD9PwLcLNw19M31vuVO4Kw50eoa-_VVH7zTFAA");
    assert_eq!(id.len(), 43);
    assert_eq!(ssh::fingerprint_from_id(&id).unwrap(), ED25519_FP);
    let long = format!("{id}A");
    for bad in [
        "",
        "short",
        "s+32EFD9PwLcLNw19M31vuVO4Kw50eoa+/VVH7zTFAA",
        long.as_str(),
    ] {
        assert_eq!(ssh::fingerprint_from_id(bad), None, "{bad}");
    }
    assert_eq!(ssh::key_id("MD5:aa"), None);
    assert_eq!(ssh::key_id("SHA256:short"), None);
}

// ---- Registration challenges bound to an account (lokkju/edgekms#17) ----

fn alice() -> ssh::RegisterAccount {
    ssh::RegisterAccount {
        github_id: 42,
        login: "alice".to_owned(),
    }
}

#[test]
fn register_challenge_names_its_account_in_the_signed_text() {
    let o = ops();
    let c = block_on(ssh::new_register_challenge(&o, 1000, ORIGIN, &alice())).unwrap();
    assert!(c.starts_with("ekmsr.42.alice."), "{c}");
    assert!(c.len() <= ssh::MAX_REGISTER_CHALLENGE_LEN);
    let (account, origin) = ssh::register_challenge_parts(&c).unwrap();
    assert_eq!(account, alice());
    assert_eq!(origin, ORIGIN);
    let ok = block_on(ssh::check_register_challenge(&o, &c, 1300, &[ORIGIN], 42)).unwrap();
    assert_eq!(ok.expires_at, 1300);
    assert_eq!(
        block_on(ssh::check_register_challenge(&o, &c, 1301, &[ORIGIN], 42)).unwrap_err(),
        SshError::ChallengeExpired
    );
    assert_eq!(
        block_on(ssh::check_register_challenge(
            &o,
            &c,
            1000,
            &["https://other.example.com"],
            42
        ))
        .unwrap_err(),
        SshError::WrongOrigin
    );
}

#[test]
fn register_challenge_for_one_account_is_refused_for_another() {
    let o = ops();
    let c = block_on(ssh::new_register_challenge(&o, 1000, ORIGIN, &alice())).unwrap();
    assert_eq!(
        block_on(ssh::check_register_challenge(&o, &c, 1000, &[ORIGIN], 43)).unwrap_err(),
        SshError::WrongAccount
    );
}

#[test]
fn register_challenge_account_is_under_the_mac() {
    let o = ops();
    let c = block_on(ssh::new_register_challenge(&o, 1000, ORIGIN, &alice())).unwrap();
    for (forged, as_id) in [
        (c.replacen("ekmsr.42.", "ekmsr.43.", 1), 43),
        (c.replacen(".alice.", ".mallory.", 1), 42),
    ] {
        assert_eq!(
            block_on(ssh::check_register_challenge(
                &o,
                &forged,
                1000,
                &[ORIGIN],
                as_id
            ))
            .unwrap_err(),
            SshError::BadChallengeMac,
            "{forged}"
        );
    }
}

#[test]
fn register_challenges_and_other_challenges_do_not_cross() {
    let o = ops();
    // An old-format registration challenge (no account) no longer registers anything.
    let old = block_on(ssh::new_challenge_with(
        &o,
        MacPurpose::SshKeyProof,
        1000,
        ORIGIN,
    ))
    .unwrap();
    assert_eq!(
        block_on(ssh::check_register_challenge(&o, &old, 1000, &[ORIGIN], 42)).unwrap_err(),
        SshError::MalformedChallenge
    );
    // A registration challenge is no login challenge, under any purpose.
    let c = block_on(ssh::new_register_challenge(&o, 1000, ORIGIN, &alice())).unwrap();
    for purpose in [
        MacPurpose::Challenge,
        MacPurpose::ControlChallenge,
        MacPurpose::SshKeyProof,
    ] {
        assert_eq!(
            block_on(ssh::check_challenge_with(
                &o,
                purpose,
                300,
                &c,
                1000,
                &[ORIGIN]
            ))
            .unwrap_err(),
            SshError::MalformedChallenge,
            "{purpose:?}"
        );
    }
    assert!(ssh::challenge_origin(&c).is_err());
}

#[test]
fn register_challenge_shape_rules() {
    let o = ops();
    let long = "x".repeat(40);
    for login in ["", "a.b", "a b", "al\u{202e}ce", long.as_str()] {
        let bad = ssh::RegisterAccount {
            github_id: 1,
            login: login.to_owned(),
        };
        assert_eq!(
            block_on(ssh::new_register_challenge(&o, 1000, ORIGIN, &bad)).unwrap_err(),
            SshError::BadAccount,
            "{login:?}"
        );
    }
    let c = block_on(ssh::new_register_challenge(&o, 1000, ORIGIN, &alice())).unwrap();
    // One spelling per account: no leading zeros, no sign, nothing missing.
    for forged in [
        c.replacen("ekmsr.42.", "ekmsr.042.", 1),
        c.replacen("ekmsr.42.", "ekmsr.+42.", 1),
        c.replacen("ekmsr.42.alice.", "ekmsr.42.", 1),
        "ekmsr.42.alice".to_owned(),
        format!("{c}{}", "A".repeat(ssh::MAX_REGISTER_CHALLENGE_LEN)),
    ] {
        assert_eq!(
            ssh::register_challenge_parts(&forged).unwrap_err(),
            SshError::MalformedChallenge,
            "{forged}"
        );
    }
}

mod sk {
    use super::CHALLENGE;
    use ed25519_dalek::{Signer, SigningKey};
    use edgekms_core::ssh::{self, SshError};
    use sha2::{Digest, Sha256};
    use ssh_key::public::{Ed25519PublicKey, KeyData, SkEd25519};
    use ssh_key::{Algorithm, HashAlg, LineEnding, PublicKey, Signature, SshSig};

    /// A software sk-ssh-ed25519 key and its SSHSIG over `CHALLENGE` in `namespace` with `flags`.
    fn sk_sig(namespace: &str, flags: u8) -> (String, String) {
        let sk = SigningKey::from_bytes(&[9; 32]);
        let app = "ssh:";
        let data = KeyData::SkEd25519(SkEd25519::new(
            Ed25519PublicKey(sk.verifying_key().to_bytes()),
            app,
        ));
        let counter = 7u32.to_be_bytes();
        let signed = SshSig::signed_data(namespace, HashAlg::Sha512, CHALLENGE.as_bytes()).unwrap();
        let mut sk_data = Sha256::digest(app).to_vec();
        sk_data.push(flags);
        sk_data.extend(counter);
        sk_data.extend(Sha256::digest(&signed));
        let mut blob = sk.sign(&sk_data).to_bytes().to_vec();
        blob.push(flags);
        blob.extend(counter);
        let sig = Signature::new(Algorithm::SkEd25519, blob).unwrap();
        let armored = SshSig::new(data.clone(), namespace, HashAlg::Sha512, sig)
            .unwrap()
            .to_pem(LineEnding::LF)
            .unwrap();
        (PublicKey::from(data).to_openssh().unwrap(), armored)
    }

    #[test]
    fn embedded_and_proof_need_user_presence() {
        let (_, touched) = sk_sig(ssh::NAMESPACE, 0x01);
        let v = ssh::verify_embedded(CHALLENGE, &touched).unwrap();
        assert_eq!(v.key_type, "sk-ssh-ed25519@openssh.com");
        let (_, untouched) = sk_sig(ssh::NAMESPACE, 0x00);
        assert_eq!(
            ssh::verify_embedded(CHALLENGE, &untouched).unwrap_err(),
            SshError::UserNotPresent
        );
        let (k, touched) = sk_sig(ssh::REGISTER_NAMESPACE, 0x01);
        assert!(ssh::verify_proof(&k, CHALLENGE, &touched).is_ok());
        let (k, untouched) = sk_sig(ssh::REGISTER_NAMESPACE, 0x00);
        assert_eq!(
            ssh::verify_proof(&k, CHALLENGE, &untouched).unwrap_err(),
            SshError::UserNotPresent
        );
        assert_eq!(
            ssh::parse_public_key(&k).unwrap().key_type,
            "sk-ssh-ed25519@openssh.com"
        );
    }
}
