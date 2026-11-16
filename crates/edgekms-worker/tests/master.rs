#![cfg(target_arch = "wasm32")]
//! Master-key wrap, unwrap, export and rewrap (`edgekms_worker::master`), under Node's
//! `WebCrypto`. workerd's acceptance of `unwrapKey` into `HKDF` is checked by the hosted e2e
//! (`scripts/e2e-hosted.sh`), not here.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use edgekms_core::hosted::wrap_aad;
use edgekms_core::keyops::{KeyOps, MacPurpose};
use edgekms_core::transit::{self, Ciphertext, DataKey, Id};
use edgekms_worker::master::{MasterAdmin, MasterUnwrap};
use edgekms_worker::webcrypto::WebCryptoKeyOps;
use js_sys::{Object, Reflect};
use wasm_bindgen::{JsCast as _, JsValue};
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::wasm_bindgen_test;
use web_sys::CryptoKey;

const M1: [u8; 32] = [0x11; 32];
const M2: [u8; 32] = [0x22; 32];

#[derive(serde::Deserialize)]
struct Fixture {
    master: String,
    root: String,
    tenant_id: String,
    root_id: String,
    aad: String,
    iv: String,
    wrapped: String,
    k_test_v1_data_key: String,
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!("fixtures/wrap.json")).unwrap()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn key32(s: &str) -> [u8; 32] {
    unhex(s).try_into().unwrap()
}

/// The AAD layout of `edgekms_core::hosted::wrap_aad`, spelled out independently here as a
/// cross-check against it and the fixture's `aad`.
fn aad(tenant: &str, root_id: &str) -> Vec<u8> {
    format!("edgekms/wrap/v1/{tenant}/{root_id}").into_bytes()
}

fn id(s: &str) -> Id {
    Id::new(s).unwrap()
}

fn root_bytes() -> [u8; 32] {
    std::array::from_fn(|i| u8::try_from(i).unwrap())
}

fn err_text<T>(r: worker::Result<T>) -> String {
    match r {
        Ok(_) => panic!("expected an error"),
        Err(e) => e.to_string(),
    }
}

fn ops(root: CryptoKey) -> WebCryptoKeyOps {
    WebCryptoKeyOps::from_hkdf_key(root, Id::new("r1").unwrap()).unwrap()
}

/// An `Env` holding `vars` as plain string bindings, under `HOSTED_APEX` `localhost`, the one
/// apex where a plain secret may stand in for a Secrets Store binding.
fn env_with(vars: &[(&str, &str)]) -> worker::Env {
    let obj = Object::new();
    Reflect::set(&obj, &"HOSTED_APEX".into(), &"localhost".into()).unwrap();
    for (k, v) in vars {
        Reflect::set(&obj, &JsValue::from_str(k), &JsValue::from_str(v)).unwrap();
    }
    obj.unchecked_into()
}

/// A stand-in for a Secrets Store binding: an object workers-rs recognizes as one (its
/// constructor is named `Fetcher`) whose `get()` resolves to `value`.
fn secrets_store(value: &str) -> JsValue {
    js_sys::Function::new_with_args(
        "v",
        "class Fetcher { async get() { return v; } }; return new Fetcher();",
    )
    .call1(&JsValue::NULL, &JsValue::from_str(value))
    .unwrap()
}

fn usages(key: &CryptoKey) -> Vec<String> {
    key.usages()
        .iter()
        .map(|u| u.as_string().unwrap())
        .collect()
}

#[wasm_bindgen_test]
async fn unwrap_matches_python_vector() {
    let f = fixture();
    assert_eq!(f.aad.as_bytes(), aad(&f.tenant_id, &f.root_id));
    assert_eq!(f.aad.as_bytes(), wrap_aad(&f.tenant_id, &id(&f.root_id)));
    let wrapped = unhex(&f.wrapped);
    assert_eq!(&wrapped[..12], &unhex(&f.iv)[..]);
    let master = MasterUnwrap::from_bytes(&[("m1", &key32(&f.master))])
        .await
        .unwrap();
    let root = master
        .unwrap_root("m1", &wrapped, &f.tenant_id, &id(&f.root_id))
        .await
        .unwrap();
    assert_eq!(master.unwrap_count(), 1);
    assert!(!root.extractable());
    assert_eq!(usages(&root), ["deriveKey"]);

    let ops = WebCryptoKeyOps::from_hkdf_key(root, Id::new(&f.root_id).unwrap()).unwrap();
    let ct: Ciphertext = ops
        .encrypt(&Id::new("k_test").unwrap(), 1, b"probe")
        .await
        .unwrap()
        .parse()
        .unwrap();
    let kat = DataKey::from_bytes(key32(&f.k_test_v1_data_key));
    assert_eq!(&*transit::decrypt(&kat, &ct).unwrap(), b"probe");

    // The admin handle opens the same vector to the same root bytes.
    let admin = MasterAdmin::from_bytes("m1", &[("m1", &key32(&f.master))])
        .await
        .unwrap();
    let raw = admin
        .export_root("m1", &wrapped, &f.tenant_id, &id(&f.root_id))
        .await
        .unwrap();
    assert_eq!(&raw[..], &unhex(&f.root)[..]);
}

#[wasm_bindgen_test]
async fn swapped_wrapped_root_fails_to_unwrap() {
    let f = fixture();
    let wrapped = unhex(&f.wrapped);
    let master = MasterUnwrap::from_bytes(&[("m1", &key32(&f.master))])
        .await
        .unwrap();
    // Tenant A's row copied into tenant B's: same bytes, B's tenant id in the AAD.
    let err = err_text(
        master
            .unwrap_root("m1", &wrapped, "t_other", &id("r1"))
            .await,
    );
    assert!(err.contains("unwrap_failed"), "{err}");
    // The same tenant with another root id doesn't unwrap either.
    let err = err_text(
        master
            .unwrap_root("m1", &wrapped, "t_test", &id("r2"))
            .await,
    );
    assert!(err.contains("unwrap_failed"), "{err}");
    assert_eq!(master.unwrap_count(), 0);

    // And a freshly wrapped root, swapped between two tenants of one admin.
    let admin = MasterAdmin::from_bytes("m1", &[("m1", &M1)]).await.unwrap();
    let unwrap = MasterUnwrap::from_bytes(&[("m1", &M1)]).await.unwrap();
    let (_, a_wrapped) = admin.new_root("t_a", &id("ra")).await.unwrap();
    let (_, b_wrapped) = admin.new_root("t_b", &id("rb")).await.unwrap();
    for (wrapped, tenant, root) in [(&a_wrapped, "t_b", "rb"), (&b_wrapped, "t_a", "ra")] {
        let err = err_text(unwrap.unwrap_root("m1", wrapped, tenant, &id(root)).await);
        assert!(err.contains("unwrap_failed"), "{err}");
    }
    unwrap
        .unwrap_root("m1", &a_wrapped, "t_a", &id("ra"))
        .await
        .unwrap();
}

#[wasm_bindgen_test]
async fn truncated_wrapped_root_is_malformed() {
    let wrapped = unhex(&fixture().wrapped);
    let master = MasterUnwrap::from_bytes(&[("m1", &key32(&fixture().master))])
        .await
        .unwrap();
    let a = ("t_test", id("r1"));
    for bad in [
        &wrapped[..59],
        &wrapped[..12],
        &[][..],
        &[wrapped.clone(), vec![0]].concat(),
    ] {
        let err = err_text(master.unwrap_root("m1", bad, a.0, &a.1).await);
        assert!(err.contains("wrapped_root_malformed"), "{err}");
    }
    let admin = MasterAdmin::from_bytes("m1", &[("m1", &key32(&fixture().master))])
        .await
        .unwrap();
    let err = err_text(admin.export_root("m1", &wrapped[..59], a.0, &a.1).await);
    assert!(err.contains("wrapped_root_malformed"), "{err}");
    let err = err_text(admin.rewrap("m1", &wrapped[..59], a.0, &a.1).await);
    assert!(err.contains("wrapped_root_malformed"), "{err}");

    // A flipped bit in the IV, ciphertext or tag is a failed unwrap, not a malformed one.
    for i in [0, 20, 59] {
        let mut t = wrapped.clone();
        t[i] ^= 1;
        let err = err_text(master.unwrap_root("m1", &t, a.0, &a.1).await);
        assert!(err.contains("unwrap_failed"), "{err}");
    }
}

#[wasm_bindgen_test]
async fn new_root_round_trips() {
    let admin = MasterAdmin::from_bytes("m1", &[("m1", &M1)]).await.unwrap();
    assert_eq!(admin.current(), "m1");
    let a = ("t_new", id("r1"));
    let (fresh, wrapped) = admin.new_root(a.0, &a.1).await.unwrap();
    assert_eq!(wrapped.len(), 60);
    assert!(!fresh.extractable());
    assert_eq!(usages(&fresh), ["deriveKey"]);

    let unwrap = MasterUnwrap::from_bytes(&[("m1", &M1)]).await.unwrap();
    let loaded = unwrap.unwrap_root("m1", &wrapped, a.0, &a.1).await.unwrap();
    let (fresh, loaded) = (ops(fresh), ops(loaded));
    let k = Id::new("k_test").unwrap();
    let ct: Ciphertext = fresh
        .encrypt(&k, 1, b"hello")
        .await
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(&*loaded.decrypt(&k, &ct).await.unwrap(), b"hello");
    assert_eq!(
        fresh.mac(MacPurpose::Config, b"c").await.unwrap(),
        loaded.mac(MacPurpose::Config, b"c").await.unwrap()
    );

    // Two new roots differ, and so do their IVs.
    let (_, other) = admin.new_root(a.0, &a.1).await.unwrap();
    assert_ne!(other[..12], wrapped[..12]);
    assert_ne!(
        admin.export_root("m1", &other, a.0, &a.1).await.unwrap()[..],
        admin.export_root("m1", &wrapped, a.0, &a.1).await.unwrap()[..]
    );
}

#[wasm_bindgen_test]
async fn import_then_export_returns_the_same_bytes() {
    let admin = MasterAdmin::from_bytes("m1", &[("m1", &M1)]).await.unwrap();
    let a = ("t_imp", id("r1"));
    let (handle, wrapped) = admin.import_root(&root_bytes(), a.0, &a.1).await.unwrap();
    assert!(!handle.extractable());
    assert_eq!(
        &admin.export_root("m1", &wrapped, a.0, &a.1).await.unwrap()[..],
        &root_bytes()
    );
    // The imported handle derives the KAT key.
    let ct: Ciphertext = ops(handle)
        .encrypt(&Id::new("k_test").unwrap(), 1, b"x")
        .await
        .unwrap()
        .parse()
        .unwrap();
    let kat = DataKey::from_bytes(key32(&fixture().k_test_v1_data_key));
    assert_eq!(&*transit::decrypt(&kat, &ct).unwrap(), b"x");

    // A unique random IV per wrap: the same root and AAD wrap differently every time.
    let (_, again) = admin.import_root(&root_bytes(), a.0, &a.1).await.unwrap();
    assert_ne!(again[..12], wrapped[..12]);
    assert_ne!(again, wrapped);

    // Export checks the AAD too.
    let err = err_text(admin.export_root("m1", &wrapped, "t_x", &id("r1")).await);
    assert!(err.contains("unwrap_failed"), "{err}");
}

#[wasm_bindgen_test]
async fn rewrap_moves_to_the_current_version() {
    let a = ("t_rot", id("r1"));
    let old = MasterAdmin::from_bytes("m1", &[("m1", &M1)]).await.unwrap();
    let (_, under_m1) = old.import_root(&root_bytes(), a.0, &a.1).await.unwrap();

    let admin = MasterAdmin::from_bytes("m2", &[("m1", &M1), ("m2", &M2)])
        .await
        .unwrap();
    assert_eq!(admin.current(), "m2");
    let under_m2 = admin.rewrap("m1", &under_m1, a.0, &a.1).await.unwrap();
    assert_eq!(under_m2.len(), 60);
    assert_ne!(under_m2[..12], under_m1[..12]);

    let unwrap = MasterUnwrap::from_bytes(&[("m1", &M1), ("m2", &M2)])
        .await
        .unwrap();
    unwrap
        .unwrap_root("m2", &under_m2, a.0, &a.1)
        .await
        .unwrap();
    let err = err_text(unwrap.unwrap_root("m1", &under_m2, a.0, &a.1).await);
    assert!(err.contains("unwrap_failed"), "{err}");
    assert_eq!(
        &admin.export_root("m2", &under_m2, a.0, &a.1).await.unwrap()[..],
        &root_bytes()
    );

    // Rewrap keeps the AAD binding.
    let err = err_text(admin.rewrap("m1", &under_m1, "t_x", &id("r1")).await);
    assert!(err.contains("unwrap_failed"), "{err}");
    // A version the admin wasn't given is missing.
    let err = err_text(admin.rewrap("m3", &under_m1, a.0, &a.1).await);
    assert!(err.contains("master_key_missing"), "{err}");
}

#[wasm_bindgen_test]
async fn master_and_root_handles_are_locked_down() {
    // The master handle itself is out of reach; `handle_info` reports only its properties.
    // `master::tests` checks inside the crate that it refuses `encrypt` and `exportKey`.
    let unwrap = MasterUnwrap::from_bytes(&[("m1", &M1)]).await.unwrap();
    assert_eq!(
        unwrap.handle_info("m1"),
        Some((false, vec!["unwrapKey".to_owned()]))
    );
    assert_eq!(unwrap.handle_info("m2"), None);

    // An unwrapped root can't be exported.
    let admin = MasterAdmin::from_bytes("m1", &[("m1", &M1)]).await.unwrap();
    let a = ("t_u", id("r1"));
    let (_, wrapped) = admin.new_root(a.0, &a.1).await.unwrap();
    let root = unwrap.unwrap_root("m1", &wrapped, a.0, &a.1).await.unwrap();
    let crypto: web_sys::Crypto = Reflect::get(&js_sys::global(), &"crypto".into())
        .unwrap()
        .unchecked_into();
    let exported = match crypto.subtle().export_key("raw", &root) {
        Err(_) => true,
        Ok(p) => JsFuture::from(p).await.is_err(),
    };
    assert!(exported, "an unwrapped root must not export");
}

#[wasm_bindgen_test]
async fn admin_from_bytes_needs_the_current_version() {
    let err = err_text(MasterAdmin::from_bytes("m2", &[("m1", &M1)]).await);
    assert!(err.contains("master_key_missing"), "{err}");
}

#[wasm_bindgen_test]
async fn from_env_reads_versions_and_imports_lazily() {
    let f = fixture();
    let b64 = STANDARD.encode(key32(&f.master));
    let env = env_with(&[("MASTER_KEY_CURRENT", "m1"), ("MASTER_KEY_M1", &b64)]);
    let unwrap = MasterUnwrap::from_env(&env).await.unwrap();
    assert!(unwrap.handle_info("m1").is_none(), "imported on first use");
    unwrap
        .unwrap_root("m1", &unhex(&f.wrapped), &f.tenant_id, &id(&f.root_id))
        .await
        .unwrap();
    assert!(unwrap.handle_info("m1").is_some());
    // An unbound version, and names that aren't versions, are missing.
    for v in ["m2", "M1", "m", "m0", "m01", "ROOT_KEY", "m1x", ""] {
        let err = err_text(
            unwrap
                .unwrap_root(v, &unhex(&f.wrapped), &f.tenant_id, &id(&f.root_id))
                .await,
        );
        assert!(err.contains("master_key_missing"), "{v}: {err}");
    }

    let admin = MasterAdmin::from_env(&env).await.unwrap();
    assert_eq!(admin.current(), "m1");
    let raw = admin
        .export_root("m1", &unhex(&f.wrapped), &f.tenant_id, &id(&f.root_id))
        .await
        .unwrap();
    assert_eq!(&raw[..], &unhex(&f.root)[..]);
}

#[wasm_bindgen_test]
async fn admin_from_env_imports_the_previous_version() {
    let env = env_with(&[
        ("MASTER_KEY_CURRENT", "m2"),
        ("MASTER_KEY_PREVIOUS", "m1"),
        ("MASTER_KEY_M1", &STANDARD.encode(M1)),
        ("MASTER_KEY_M2", &STANDARD.encode(M2)),
    ]);
    let a = ("t_env", id("r1"));
    let old = MasterAdmin::from_bytes("m1", &[("m1", &M1)]).await.unwrap();
    let (_, under_m1) = old.import_root(&root_bytes(), a.0, &a.1).await.unwrap();
    let admin = MasterAdmin::from_env(&env).await.unwrap();
    assert_eq!(admin.current(), "m2");
    let under_m2 = admin.rewrap("m1", &under_m1, a.0, &a.1).await.unwrap();
    let unwrap = MasterUnwrap::from_env(&env).await.unwrap();
    unwrap
        .unwrap_root("m2", &under_m2, a.0, &a.1)
        .await
        .unwrap();
}

/// `wrangler secret put MASTER_KEY_M7` must not add a master outside the Secrets Store
/// ceremony: off `localhost`, only a Secrets Store binding is a master version.
#[wasm_bindgen_test]
async fn only_a_secrets_store_binding_is_a_master_off_localhost() {
    let f = fixture();
    let b64 = STANDARD.encode(key32(&f.master));
    let env = env_with(&[("MASTER_KEY_CURRENT", "m1"), ("MASTER_KEY_M1", &b64)]);
    Reflect::set(&env, &"HOSTED_APEX".into(), &"edge.km".into()).unwrap();
    let unwrap = MasterUnwrap::from_env(&env).await.unwrap();
    let err = err_text(
        unwrap
            .unwrap_root("m1", &unhex(&f.wrapped), &f.tenant_id, &id(&f.root_id))
            .await,
    );
    assert!(err.contains("master_key_not_in_secrets_store"), "{err}");
    assert!(!err.contains(&b64), "{err}");
    let err = err_text(MasterAdmin::from_env(&env).await);
    assert!(err.contains("master_key_not_in_secrets_store"), "{err}");

    Reflect::set(&env, &"MASTER_KEY_M1".into(), &secrets_store(&b64)).unwrap();
    let unwrap = MasterUnwrap::from_env(&env).await.unwrap();
    unwrap
        .unwrap_root("m1", &unhex(&f.wrapped), &f.tenant_id, &id(&f.root_id))
        .await
        .unwrap();
    assert_eq!(MasterAdmin::from_env(&env).await.unwrap().current(), "m1");
}

#[wasm_bindgen_test]
async fn from_env_errors_are_fixed_labels() {
    let err = err_text(MasterUnwrap::from_env(&env_with(&[])).await);
    assert!(err.contains("master_key_missing"), "{err}");
    let err = err_text(MasterAdmin::from_env(&env_with(&[])).await);
    assert!(err.contains("master_key_missing"), "{err}");
    let err = err_text(MasterAdmin::from_env(&env_with(&[("MASTER_KEY_CURRENT", "m1")])).await);
    assert!(err.contains("master_key_missing"), "{err}");
    let err = err_text(
        MasterAdmin::from_env(&env_with(&[
            ("MASTER_KEY_CURRENT", "m1"),
            ("MASTER_KEY_PREVIOUS", "m9"),
            ("MASTER_KEY_M1", &STANDARD.encode(M1)),
        ]))
        .await,
    );
    assert!(err.contains("master_key_missing"), "{err}");

    let secret = STANDARD.encode([0x5a_u8; 16]);
    for value in [secret.as_str(), "not base64!"] {
        let env = env_with(&[("MASTER_KEY_CURRENT", "m1"), ("MASTER_KEY_M1", value)]);
        let err = err_text(MasterAdmin::from_env(&env).await);
        assert!(err.contains("master_key_bad_length"), "{err}");
        assert!(
            !err.contains(value),
            "the error never carries the value: {err}"
        );
        let unwrap = MasterUnwrap::from_env(&env).await.unwrap();
        let err = err_text(
            unwrap
                .unwrap_root("m1", &unhex(&fixture().wrapped), "t_x", &id("r1"))
                .await,
        );
        assert!(err.contains("master_key_bad_length"), "{err}");
    }
}
