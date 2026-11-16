#![cfg(target_arch = "wasm32")]
use std::fmt::Write as _;

use edgekms_core::keyops::{KeyOps, MacPurpose, SoftKeyOps};
use edgekms_core::transit::{self, Ciphertext, DataKey, Id, RootKey};
use edgekms_worker::webcrypto::{MAX_CACHED_KEYS, WebCryptoKeyOps};
use wasm_bindgen_test::wasm_bindgen_test;

fn root_bytes() -> [u8; 32] {
    std::array::from_fn(|i| u8::try_from(i).unwrap())
}

async fn web() -> WebCryptoKeyOps {
    WebCryptoKeyOps::import(&root_bytes(), Id::new("r1").unwrap())
        .await
        .unwrap()
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

#[wasm_bindgen_test]
async fn mac_matches_vectors() {
    let w = web().await;
    assert_eq!(
        hex(&w.mac(MacPurpose::Token, b"probe").await.unwrap()),
        "1a0052537fb94790d605802454d8be1cb1e896411390953baa1296b18e7ee3b1"
    );
    assert_eq!(
        hex(&w.mac(MacPurpose::Challenge, b"probe").await.unwrap()),
        "ef43c64c2107cf81465d1b8e9b0fa0cf80b8c161529e38802d779dd038adfe0d"
    );
}

#[wasm_bindgen_test]
async fn webcrypto_ciphertext_decrypts_with_kat_key() {
    let ct: Ciphertext = web()
        .await
        .encrypt(&Id::new("k_test").unwrap(), 1, b"probe")
        .await
        .unwrap()
        .parse()
        .unwrap();
    let kat = DataKey::from_bytes(decode_hex(
        "f8c344d0aa08dc23f094d482c48f51c008ba7465db443e2973a62ee14fadf707",
    ));
    assert_eq!(&*transit::decrypt(&kat, &ct).unwrap(), b"probe");
}

#[wasm_bindgen_test]
async fn webcrypto_decrypts_soft_ciphertext() {
    // A fixed-seed RNG is fine here: the test checks interoperability, not nonce quality.
    let soft = SoftKeyOps::new(
        RootKey::new(Id::new("r1").unwrap(), root_bytes()),
        FixedRng(7),
    );
    let k = Id::new("k_test").unwrap();
    let ct: Ciphertext = pollster::block_on(soft.encrypt(&k, 2, b"cross"))
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(&*web().await.decrypt(&k, &ct).await.unwrap(), b"cross");
}

#[wasm_bindgen_test]
async fn verify_mac_rejects_wrong_purpose() {
    let w = web().await;
    let tag = w.mac(MacPurpose::Token, b"d").await.unwrap();
    assert!(w.verify_mac(MacPurpose::Token, b"d", &tag).await.unwrap());
    assert!(!w.verify_mac(MacPurpose::Audit, b"d", &tag).await.unwrap());
}

#[wasm_bindgen_test]
async fn verify_mac_is_false_for_a_wrong_length_tag() {
    let w = web().await;
    let tag = w.mac(MacPurpose::Token, b"d").await.unwrap();
    assert!(
        !w.verify_mac(MacPurpose::Token, b"d", &tag[..31])
            .await
            .unwrap()
    );
    assert!(!w.verify_mac(MacPurpose::Token, b"d", &[]).await.unwrap());
}

#[wasm_bindgen_test]
async fn mac_matches_soft_key_ops_for_every_purpose() {
    let soft = SoftKeyOps::new(
        RootKey::new(Id::new("r1").unwrap(), root_bytes()),
        FixedRng(7),
    );
    let w = web().await;
    for purpose in [MacPurpose::Token, MacPurpose::Challenge, MacPurpose::Audit] {
        let data = vec![0xa5; 1000];
        assert_eq!(
            w.mac(purpose, &data).await.unwrap(),
            pollster::block_on(soft.mac(purpose, &data)).unwrap(),
            "{purpose:?}"
        );
    }
}

#[wasm_bindgen_test]
async fn decrypt_rejects_a_tampered_ciphertext_and_the_wrong_key() {
    let w = web().await;
    let k = Id::new("k_test").unwrap();
    let ct: Ciphertext = w.encrypt(&k, 1, b"secret").await.unwrap().parse().unwrap();
    assert_eq!(&*w.decrypt(&k, &ct).await.unwrap(), b"secret");
    let mut sealed = ct.sealed().to_vec();
    sealed[0] ^= 1;
    let tampered = Ciphertext::from_parts(1, ct.nonce(), &sealed).unwrap();
    assert_eq!(
        w.decrypt(&k, &tampered).await.unwrap_err(),
        transit::Error::Decrypt
    );
    let other = Id::new("k_other").unwrap();
    assert_eq!(
        w.decrypt(&other, &ct).await.unwrap_err(),
        transit::Error::Decrypt
    );
}

#[wasm_bindgen_test]
async fn derived_keys_are_cached_per_key_version_and_usage() {
    let w = web().await;
    let k = Id::new("k_test").unwrap();
    assert_eq!(w.cached_keys(), 0);
    let ct1: Ciphertext = w.encrypt(&k, 1, b"a").await.unwrap().parse().unwrap();
    let ct2: Ciphertext = w.encrypt(&k, 1, b"b").await.unwrap().parse().unwrap();
    assert_eq!(w.cached_keys(), 1, "one encrypt key for k_test v1");
    assert_eq!(&*w.decrypt(&k, &ct1).await.unwrap(), b"a");
    assert_eq!(&*w.decrypt(&k, &ct2).await.unwrap(), b"b");
    assert_eq!(w.cached_keys(), 2, "plus one decrypt key");
    w.encrypt(&k, 2, b"c").await.unwrap();
    w.mac(MacPurpose::Audit, b"x").await.unwrap();
    w.mac(MacPurpose::Audit, b"y").await.unwrap();
    assert_eq!(w.cached_keys(), 4);

    // A cached key gives the same bytes as a fresh derivation would.
    let fresh = web().await;
    assert_eq!(
        w.mac(MacPurpose::Audit, b"x").await.unwrap(),
        fresh.mac(MacPurpose::Audit, b"x").await.unwrap()
    );
    assert_eq!(&*fresh.decrypt(&k, &ct1).await.unwrap(), b"a");
}

#[wasm_bindgen_test]
async fn derived_key_cache_is_bounded() {
    let w = web().await;
    let k = Id::new("k_test").unwrap();
    let max = u32::try_from(MAX_CACHED_KEYS).unwrap();
    for v in 1..=max {
        w.encrypt(&k, v, b"a").await.unwrap();
    }
    assert_eq!(w.cached_keys(), MAX_CACHED_KEYS);
    // One more starts the cache over instead of growing it.
    let ct: Ciphertext = w.encrypt(&k, max + 1, b"b").await.unwrap().parse().unwrap();
    assert!(w.cached_keys() <= MAX_CACHED_KEYS, "{}", w.cached_keys());
    assert_eq!(&*w.decrypt(&k, &ct).await.unwrap(), b"b");
}

#[wasm_bindgen_test]
async fn random_fills_buffers_past_the_getrandomvalues_limit() {
    let w = web().await;
    let mut buf = vec![0u8; 70_000];
    w.random(&mut buf);
    assert!(buf[65_536..].iter().any(|&b| b != 0));
    assert!(buf[..65_536].iter().any(|&b| b != 0));
}

/// A non-extractable HKDF handle over `root_bytes()`, imported by the test itself, as
/// `MasterUnwrap::unwrap_root` would hand one over.
async fn hkdf_handle() -> web_sys::CryptoKey {
    use wasm_bindgen::{JsCast as _, JsValue};
    let crypto: web_sys::Crypto = js_sys::Reflect::get(&js_sys::global(), &"crypto".into())
        .unwrap()
        .unchecked_into();
    let raw = js_sys::Uint8Array::from(&root_bytes()[..]);
    let usages = js_sys::Array::of1(&JsValue::from_str("deriveKey"));
    let promise = crypto
        .subtle()
        .import_key_with_str("raw", &raw, "HKDF", false, &usages)
        .unwrap();
    wasm_bindgen_futures::JsFuture::from(promise)
        .await
        .unwrap()
        .unchecked_into()
}

#[wasm_bindgen_test]
async fn from_hkdf_key_matches_import() {
    let imported = web().await;
    let handed =
        WebCryptoKeyOps::from_hkdf_key(hkdf_handle().await, Id::new("r1").unwrap()).unwrap();
    for purpose in [
        MacPurpose::Token,
        MacPurpose::Challenge,
        MacPurpose::Audit,
        MacPurpose::Config,
    ] {
        assert_eq!(
            handed.mac(purpose, b"probe").await.unwrap(),
            imported.mac(purpose, b"probe").await.unwrap(),
            "{purpose:?}"
        );
    }
    let k = Id::new("k_test").unwrap();
    let a: Ciphertext = handed
        .encrypt(&k, 1, b"one")
        .await
        .unwrap()
        .parse()
        .unwrap();
    let b: Ciphertext = imported
        .encrypt(&k, 3, b"two")
        .await
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(&*imported.decrypt(&k, &a).await.unwrap(), b"one");
    assert_eq!(&*handed.decrypt(&k, &b).await.unwrap(), b"two");
}

#[wasm_bindgen_test]
async fn config_mac_matches_vector() {
    // The config MAC vector: HKDF-SHA256(root 0..32, salt "edgekms/v1/r1", info "mac/config/v1"),
    // then HMAC-SHA256 of "probe", computed independently with Python `cryptography`.
    let handed =
        WebCryptoKeyOps::from_hkdf_key(hkdf_handle().await, Id::new("r1").unwrap()).unwrap();
    assert_eq!(
        hex(&handed.mac(MacPurpose::Config, b"probe").await.unwrap()),
        "cd5ce29599ea8bc9b4860c1125e764300708388b5faf937199874b4dee1f7d8e"
    );
}

#[wasm_bindgen_test]
async fn member_and_invite_macs_match_vectors() {
    // The vectors in edgekms-core's tests/keyops.rs, computed independently with Python
    // `cryptography`: WebCrypto's derivation for the membership and invite purposes agrees.
    let handed =
        WebCryptoKeyOps::from_hkdf_key(hkdf_handle().await, Id::new("r1").unwrap()).unwrap();
    assert_eq!(
        hex(&handed.mac(MacPurpose::Member, b"probe").await.unwrap()),
        "5ae599aed569217c770194b71a602d69f99460bc75c03a1c2cad2cd483671cb5"
    );
    assert_eq!(
        hex(&handed.mac(MacPurpose::Invite, b"probe").await.unwrap()),
        "97a2844856cc86b35dd51fd790c208f28ed3927313bb8cce9863a1a7e91e3985"
    );
    assert_eq!(
        hex(&handed.mac(MacPurpose::Allow, b"probe").await.unwrap()),
        "266e8a4f60c92e8687e283d7853c7bd3b355ad2478ef3cb7f47d3d25c4814271"
    );
    assert_eq!(
        hex(&handed
            .mac(MacPurpose::InviteRequest, b"probe")
            .await
            .unwrap()),
        "bbaae71e162fd00f01ad68dd41ffbd985d0053119c3adaff9df7982b2c6835ad"
    );
}

struct FixedRng(u8);

impl rand_core::TryRng for FixedRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(u32::from(self.0))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(u64::from(self.0))
    }
    fn try_fill_bytes(&mut self, d: &mut [u8]) -> Result<(), Self::Error> {
        d.fill(self.0);
        Ok(())
    }
}

impl rand_core::TryCryptoRng for FixedRng {}

fn decode_hex(s: &str) -> [u8; 32] {
    std::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
}
