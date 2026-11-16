//! The hosted tier's master key: AES-256-GCM over each tenant's 32-byte root key, with the
//! tenant id and root id as additional data. Every method takes the tenant id and root id and
//! builds the AAD itself with `edgekms_core::hosted::wrap_aad`, so no caller can wrap or
//! unwrap under some other binding.
//!
//! Master versions are named `m1`, `m2`, and so on. Version `mN` is the Secrets Store binding
//! `MASTER_KEY_MN`; its value is base64 of 32 bytes. Only under `HOSTED_APEX` `localhost` (the
//! local end-to-end run) may a Worker secret of the same name stand in for it; anywhere else a
//! plain `MASTER_KEY_M<n>` refuses every request ([`crate::state::mode`]) and never unwraps. The var `MASTER_KEY_CURRENT` names the version new wraps use; `MASTER_KEY_PREVIOUS`,
//! when set, names the one being rotated away from. A version name is `m` and a number without
//! a leading zero; anything else (from a tampered `wrap_key` column, say) is
//! `master_key_missing` and never becomes a binding lookup.
//!
//! Two handles, never extractable:
//! - [`MasterUnwrap`] (usage `unwrapKey`) on every host: `subtle.unwrapKey` straight into a
//!   non-extractable HKDF key, so a tenant's raw root never enters wasm memory.
//! - [`MasterAdmin`] (usages `encrypt`, `decrypt`) only while serving the control plane: new,
//!   imported, exported and rewrapped roots.
//!
//! A wrapped root is `iv[12] || ct[32] || tag[16]`, 60 bytes, with a fresh random IV from
//! `crypto.getRandomValues` for every wrap. Errors are fixed labels (`master_key_missing`,
//! `master_key_bad_length`, `master_key_import_failed`, `wrapped_root_malformed`,
//! `unwrap_failed`, `wrap_failed`), never a value.
//!
//! Retiring a master version means deleting its `MASTER_KEY_M<n>` binding: [`MasterUnwrap`]
//! unwraps under any well-formed version that is bound, whatever `MASTER_KEY_CURRENT` and
//! `MASTER_KEY_PREVIOUS` say.
//!
//! Unwrapped and new root handles get the usage `deriveKey` only, as
//! [`WebCryptoKeyOps::import`](crate::webcrypto::WebCryptoKeyOps::import) gives a self-hosted
//! root: without `deriveBits` no HKDF output can be read back into wasm memory.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use edgekms_core::hosted::wrap_aad;
use edgekms_core::transit::Id;
use js_sys::{Array, ArrayBuffer, Uint8Array};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{AesGcmParams, Crypto, CryptoKey, SubtleCrypto};
use worker::Env;
use zeroize::Zeroizing;

use crate::vault::log_internal;
use crate::webcrypto::{global_crypto, hkdf_usages, import_hkdf};

const IV_LEN: usize = 12;
const ROOT_LEN: usize = 32;
const TAG_BITS: u8 = 128;
/// `iv[12] || ct[32] || tag[16]`.
const WRAPPED_LEN: usize = IV_LEN + ROOT_LEN + 16;

const MISSING: &str = "master_key_missing";
const NOT_IN_STORE: &str = "master_key_not_in_secrets_store";
const BAD_LENGTH: &str = "master_key_bad_length";
const IMPORT_FAILED: &str = "master_key_import_failed";
const MALFORMED: &str = "wrapped_root_malformed";
const UNWRAP_FAILED: &str = "unwrap_failed";
const WRAP_FAILED: &str = "wrap_failed";

fn fail(label: &'static str) -> worker::Error {
    log_internal(label);
    worker::Error::RustError(label.into())
}

/// `MASTER_KEY_<VERSION>` for a well-formed version name (`m1`, `m2`, ...).
fn binding_name(version: &str) -> Option<String> {
    let digits = version.strip_prefix('m')?;
    let well_formed = !digits.is_empty()
        && digits.len() <= 6
        && digits.bytes().all(|b| b.is_ascii_digit())
        && !digits.starts_with('0');
    well_formed.then(|| format!("MASTER_KEY_M{digits}"))
}

/// The one `HOSTED_APEX` under which a plain Worker secret may stand in for a master version's
/// Secrets Store binding: the local end-to-end run, which adds later versions from an env file.
pub const PLAIN_MASTER_APEX: &str = "localhost";

/// Whether `env` has some `MASTER_KEY_M<n>` bound as anything but a Secrets Store binding (a
/// Worker secret or a var). workers-rs tells them apart by the binding's constructor: a Secrets
/// Store binding is a `Fetcher`, a secret or var a `String`.
#[must_use]
pub fn plain_master_bound(env: &Env) -> bool {
    js_sys::Object::keys(env.unchecked_ref::<js_sys::Object>())
        .iter()
        .filter_map(|k| k.as_string())
        .filter(|k| k.starts_with("MASTER_KEY_M"))
        .any(|k| env.secret_store(&k).is_err())
}

/// Whether `env`'s `HOSTED_APEX` is [`PLAIN_MASTER_APEX`].
fn plain_master_allowed(env: &Env) -> bool {
    env.var("HOSTED_APEX")
        .is_ok_and(|v| v.to_string().trim().eq_ignore_ascii_case(PLAIN_MASTER_APEX))
}

/// The bytes of master version `version` from `env`: a Secrets Store binding if there is one,
/// else, only under [`PLAIN_MASTER_APEX`], a Worker secret. Anywhere else a plain secret is
/// `master_key_not_in_secrets_store`, so `wrangler secret put MASTER_KEY_M7` can't add a
/// master outside the Secrets Store ceremony. The base64 text and the bytes are zeroized when
/// dropped.
async fn master_bytes(env: &Env, version: &str) -> worker::Result<Zeroizing<[u8; 32]>> {
    let binding = binding_name(version).ok_or_else(|| fail(MISSING))?;
    let text: Zeroizing<String> = if let Ok(store) = env.secret_store(&binding) {
        Zeroizing::new(
            store
                .get()
                .await
                .map_err(|_| fail(MISSING))?
                .ok_or_else(|| fail(MISSING))?,
        )
    } else {
        let secret = env.secret(&binding).map_err(|_| fail(MISSING))?;
        if !plain_master_allowed(env) {
            return Err(fail(NOT_IN_STORE));
        }
        Zeroizing::new(secret.to_string())
    };
    decode_master(text.trim())
}

/// Base64 of exactly 32 bytes; bad base64 and a wrong length are both `master_key_bad_length`.
fn decode_master(b64: &str) -> worker::Result<Zeroizing<[u8; 32]>> {
    let bytes = Zeroizing::new(STANDARD.decode(b64).map_err(|_| fail(BAD_LENGTH))?);
    let mut key = Zeroizing::new([0u8; 32]);
    if bytes.len() != key.len() {
        return Err(fail(BAD_LENGTH));
    }
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Imports `bytes` as a non-extractable AES-GCM key with `usages`, zeroing the JS copy. A
/// refusal is `master_key_import_failed`.
async fn import_master(
    subtle: &SubtleCrypto,
    bytes: &[u8; 32],
    usages: &[&str],
) -> worker::Result<CryptoKey> {
    let raw = Uint8Array::new_with_length(32);
    raw.copy_from(bytes);
    let usages: Array = usages.iter().map(|u| JsValue::from_str(u)).collect();
    let imported = async {
        let promise = subtle.import_key_with_str("raw", &raw, "AES-GCM", false, &usages)?;
        JsFuture::from(promise).await
    }
    .await;
    raw.fill(0, 0, 32);
    Ok(imported.map_err(|_| fail(IMPORT_FAILED))?.unchecked_into())
}

fn gcm_params(iv: &[u8], aad: &[u8]) -> AesGcmParams {
    let params = AesGcmParams::new_with_u8_array("AES-GCM", &Uint8Array::from(iv));
    params.set_additional_data_u8_array(&Uint8Array::from(aad));
    params.set_tag_length(TAG_BITS);
    params
}

fn check_len(wrapped: &[u8]) -> worker::Result<()> {
    if wrapped.len() == WRAPPED_LEN {
        Ok(())
    } else {
        Err(fail(MALFORMED))
    }
}

/// Unwrap-only master key handles by version, imported on first use.
pub struct MasterUnwrap {
    subtle: SubtleCrypto,
    /// Where versions not yet imported come from; `None` for [`MasterUnwrap::from_bytes`].
    env: Option<Env>,
    keys: RefCell<HashMap<String, CryptoKey>>,
    /// Successful [`MasterUnwrap::unwrap_root`] calls, for tests and metrics.
    unwraps: Cell<u64>,
}

/// The current master version's `encrypt`/`decrypt` handle, and the previous version's while a
/// rotation is in progress.
pub struct MasterAdmin {
    current: String,
    crypto: Crypto,
    subtle: SubtleCrypto,
    keys: HashMap<String, CryptoKey>,
}

impl MasterUnwrap {
    /// Reads the master bindings from `env`; each version is imported on the first
    /// [`MasterUnwrap::unwrap_root`] that names it.
    ///
    /// # Errors
    /// `master_key_missing` if `MASTER_KEY_CURRENT` is unset.
    // Async by the store contract: versions are imported lazily, so nothing awaits here yet.
    #[allow(clippy::unused_async, clippy::unused_async_trait_impl)]
    pub async fn from_env(env: &Env) -> worker::Result<Self> {
        env.var("MASTER_KEY_CURRENT").map_err(|_| fail(MISSING))?;
        Ok(Self {
            subtle: global_crypto()?.subtle(),
            env: Some(env.clone()),
            keys: RefCell::new(HashMap::new()),
            unwraps: Cell::new(0),
        })
    }

    /// For tests and e2e: unwrap handles for the given `(version, master key bytes)` pairs.
    ///
    /// # Errors
    /// `master_key_missing` for a malformed version name; `master_key_import_failed` if
    /// `WebCrypto` refuses an import.
    pub async fn from_bytes(versions: &[(&str, &[u8; 32])]) -> worker::Result<Self> {
        let subtle = global_crypto()?.subtle();
        let mut keys = HashMap::new();
        for (version, bytes) in versions {
            binding_name(version).ok_or_else(|| fail(MISSING))?;
            let key = import_master(&subtle, bytes, &["unwrapKey"]).await?;
            keys.insert((*version).to_owned(), key);
        }
        Ok(Self {
            subtle,
            env: None,
            keys: RefCell::new(keys),
            unwraps: Cell::new(0),
        })
    }

    /// The unwrap handle for `version`, imported from `env` on first use. Any well-formed
    /// version whose `MASTER_KEY_M<n>` binding exists is accepted, not only the ones
    /// `MASTER_KEY_CURRENT` and `MASTER_KEY_PREVIOUS` name, so a row still wrapped under an old
    /// version keeps loading during a rotation. Retiring a version therefore means deleting its
    /// binding; changing the two vars alone leaves it usable.
    async fn key(&self, version: &str) -> worker::Result<CryptoKey> {
        binding_name(version).ok_or_else(|| fail(MISSING))?;
        // The borrow ends with this statement, before any `.await`.
        if let Some(key) = self.keys.borrow().get(version).cloned() {
            return Ok(key);
        }
        let env = self.env.as_ref().ok_or_else(|| fail(MISSING))?;
        let bytes = master_bytes(env, version).await?;
        let key = import_master(&self.subtle, &bytes, &["unwrapKey"]).await?;
        self.keys
            .borrow_mut()
            .insert(version.to_owned(), key.clone());
        Ok(key)
    }

    /// Unwraps `wrapped` (60 bytes) under master version `wrap_key`, bound to `tenant_id` and
    /// `root_id`, into a non-extractable HKDF key with usage `deriveKey`.
    ///
    /// # Errors
    /// `wrapped_root_malformed` for a wrong length, `master_key_missing` for an unbound
    /// version, `master_key_bad_length` for a bound one that isn't base64 of 32 bytes,
    /// `master_key_import_failed` if `WebCrypto` refuses it, `unwrap_failed` for a bad tag (wrong master, wrong AAD, tampered bytes).
    pub async fn unwrap_root(
        &self,
        wrap_key: &str,
        wrapped: &[u8],
        tenant_id: &str,
        root_id: &Id,
    ) -> worker::Result<CryptoKey> {
        check_len(wrapped)?;
        let master = self.key(wrap_key).await?;
        let params = gcm_params(&wrapped[..IV_LEN], &wrap_aad(tenant_id, root_id));
        let root = async {
            let promise = self.subtle.unwrap_key_with_u8_array_and_object_and_str(
                "raw",
                &wrapped[IV_LEN..],
                &master,
                &params,
                "HKDF",
                false,
                &hkdf_usages(),
            )?;
            JsFuture::from(promise).await
        }
        .await
        .map_err(|_| fail(UNWRAP_FAILED))?;
        self.unwraps.set(self.unwraps.get() + 1);
        Ok(root.unchecked_into())
    }

    /// How many [`MasterUnwrap::unwrap_root`] calls have succeeded on this handle, so tests can
    /// show a cached tenant isn't unwrapped again.
    #[must_use]
    pub fn unwrap_count(&self) -> u64 {
        self.unwraps.get()
    }

    /// For tests: whether the master handle for `version` has been imported, and if so its
    /// `extractable` flag and usages. The handle itself never leaves this module.
    #[must_use]
    pub fn handle_info(&self, version: &str) -> Option<(bool, Vec<String>)> {
        let keys = self.keys.borrow();
        let key = keys.get(version)?;
        let usages = key.usages().iter().filter_map(|u| u.as_string()).collect();
        Some((key.extractable(), usages))
    }
}

impl MasterAdmin {
    /// Imports `MASTER_KEY_CURRENT` (and `MASTER_KEY_PREVIOUS` if set) with usages `encrypt`
    /// and `decrypt`. Only the control plane builds one.
    ///
    /// # Errors
    /// `master_key_missing`, `master_key_bad_length` or `master_key_import_failed`.
    pub async fn from_env(env: &Env) -> worker::Result<Self> {
        let current = env
            .var("MASTER_KEY_CURRENT")
            .map_err(|_| fail(MISSING))?
            .to_string();
        let mut versions = vec![current.clone()];
        if let Ok(previous) = env.var("MASTER_KEY_PREVIOUS") {
            let previous = previous.to_string();
            if previous != current {
                versions.push(previous);
            }
        }
        let crypto = global_crypto()?;
        let subtle = crypto.subtle();
        let mut keys = HashMap::new();
        for version in versions {
            let bytes = master_bytes(env, &version).await?;
            let key = import_master(&subtle, &bytes, &["encrypt", "decrypt"]).await?;
            keys.insert(version, key);
        }
        Ok(Self {
            current,
            crypto,
            subtle,
            keys,
        })
    }

    /// For tests and e2e: `current` names the version new wraps use, and `versions` holds
    /// every version's bytes (the current one and, during a rotation, the previous one).
    ///
    /// # Errors
    /// `master_key_missing` if `current` isn't among `versions` or a version name is malformed;
    /// `master_key_import_failed` if `WebCrypto` refuses an import.
    pub async fn from_bytes(current: &str, versions: &[(&str, &[u8; 32])]) -> worker::Result<Self> {
        if !versions.iter().any(|(v, _)| *v == current) {
            return Err(fail(MISSING));
        }
        let crypto = global_crypto()?;
        let subtle = crypto.subtle();
        let mut keys = HashMap::new();
        for (version, bytes) in versions {
            binding_name(version).ok_or_else(|| fail(MISSING))?;
            let key = import_master(&subtle, bytes, &["encrypt", "decrypt"]).await?;
            keys.insert((*version).to_owned(), key);
        }
        Ok(Self {
            current: current.to_owned(),
            crypto,
            subtle,
            keys,
        })
    }

    /// The master version new wraps use (`m1`).
    #[must_use]
    pub fn current(&self) -> &str {
        &self.current
    }

    fn key(&self, version: &str) -> worker::Result<&CryptoKey> {
        self.keys.get(version).ok_or_else(|| fail(MISSING))
    }

    /// A fresh random root from `crypto.getRandomValues`: its non-extractable HKDF handle, and
    /// the root wrapped under the current version, bound to `tenant_id` and `root_id`. The raw root stays in a JS buffer
    /// that is zeroed afterwards.
    ///
    /// # Errors
    /// `wrap_failed` if `WebCrypto` fails.
    pub async fn new_root(
        &self,
        tenant_id: &str,
        root_id: &Id,
    ) -> worker::Result<(CryptoKey, Vec<u8>)> {
        let raw = Uint8Array::new_with_length(32);
        if self
            .crypto
            .get_random_values_with_js_u8_array(&raw)
            .is_err()
        {
            return Err(fail(WRAP_FAILED));
        }
        let result = self
            .wrap_and_import(&raw, &wrap_aad(tenant_id, root_id))
            .await;
        raw.fill(0, 0, 32);
        result
    }

    /// As [`MasterAdmin::new_root`] from the caller's root bytes, for importing an existing
    /// root. The bytes are copied into a JS buffer that is zeroed afterwards; zeroizing `raw`
    /// itself is the caller's job.
    ///
    /// # Errors
    /// `wrap_failed` if `WebCrypto` fails.
    pub async fn import_root(
        &self,
        raw: &[u8; 32],
        tenant_id: &str,
        root_id: &Id,
    ) -> worker::Result<(CryptoKey, Vec<u8>)> {
        let buf = Uint8Array::new_with_length(32);
        buf.copy_from(raw);
        let result = self
            .wrap_and_import(&buf, &wrap_aad(tenant_id, root_id))
            .await;
        buf.fill(0, 0, 32);
        result
    }

    /// The raw root wrapped under version `wrap_key` for `tenant_id` and `root_id`, for export.
    ///
    /// # Errors
    /// `wrapped_root_malformed`, `master_key_missing` or `unwrap_failed`.
    pub async fn export_root(
        &self,
        wrap_key: &str,
        wrapped: &[u8],
        tenant_id: &str,
        root_id: &Id,
    ) -> worker::Result<Zeroizing<[u8; 32]>> {
        let plain = self
            .open(wrap_key, wrapped, &wrap_aad(tenant_id, root_id))
            .await?;
        let mut out = Zeroizing::new([0u8; 32]);
        plain.copy_to(&mut out[..]);
        plain.fill(0, 0, 32);
        Ok(out)
    }

    /// `wrapped` decrypted under version `wrap_key` and encrypted under the current version
    /// with a fresh IV, still bound to `tenant_id` and `root_id`. The plaintext root never
    /// crosses into wasm.
    ///
    /// # Errors
    /// `wrapped_root_malformed`, `master_key_missing`, `unwrap_failed` or `wrap_failed`.
    pub async fn rewrap(
        &self,
        wrap_key: &str,
        wrapped: &[u8],
        tenant_id: &str,
        root_id: &Id,
    ) -> worker::Result<Vec<u8>> {
        let aad = wrap_aad(tenant_id, root_id);
        let plain = self.open(wrap_key, wrapped, &aad).await?;
        let result = self.seal(&plain, &aad).await;
        plain.fill(0, 0, 32);
        result
    }

    /// Wraps the root in `raw` under the current version and imports it as an HKDF handle.
    /// Zeroing `raw` is the caller's job.
    async fn wrap_and_import(
        &self,
        raw: &Uint8Array,
        aad: &[u8],
    ) -> worker::Result<(CryptoKey, Vec<u8>)> {
        let wrapped = self.seal(raw, aad).await?;
        let handle = import_hkdf(&self.subtle, raw)
            .await
            .map_err(|_| fail(WRAP_FAILED))?;
        Ok((handle, wrapped))
    }

    /// `iv || AES-GCM(current master, iv, aad, plain)` with a fresh random IV.
    async fn seal(&self, plain: &Uint8Array, aad: &[u8]) -> worker::Result<Vec<u8>> {
        let mut iv = [0u8; IV_LEN];
        if self
            .crypto
            .get_random_values_with_u8_array(&mut iv)
            .is_err()
        {
            return Err(fail(WRAP_FAILED));
        }
        let master = self.key(&self.current)?;
        let params = gcm_params(&iv, aad);
        let sealed = async {
            let promise = self
                .subtle
                .encrypt_with_object_and_buffer_source(&params, master, plain)?;
            JsFuture::from(promise).await
        }
        .await
        .map_err(|_| fail(WRAP_FAILED))?;
        let sealed = Uint8Array::new(sealed.unchecked_ref::<ArrayBuffer>()).to_vec();
        if sealed.len() != WRAPPED_LEN - IV_LEN {
            return Err(fail(WRAP_FAILED));
        }
        let mut out = Vec::with_capacity(WRAPPED_LEN);
        out.extend_from_slice(&iv);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// The root under `wrapped`, decrypted into a JS buffer the caller must zero.
    async fn open(&self, wrap_key: &str, wrapped: &[u8], aad: &[u8]) -> worker::Result<Uint8Array> {
        check_len(wrapped)?;
        let master = self.key(wrap_key)?;
        let params = gcm_params(&wrapped[..IV_LEN], aad);
        let opened = async {
            let promise = self.subtle.decrypt_with_object_and_u8_array(
                &params,
                master,
                &wrapped[IV_LEN..],
            )?;
            JsFuture::from(promise).await
        }
        .await
        .map_err(|_| fail(UNWRAP_FAILED))?;
        let plain = Uint8Array::new(opened.unchecked_ref::<ArrayBuffer>());
        if plain.length() as usize != ROOT_LEN {
            plain.fill(0, 0, plain.length());
            return Err(fail(UNWRAP_FAILED));
        }
        Ok(plain)
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod tests {
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;

    async fn refused(promise: Result<js_sys::Promise, JsValue>) -> bool {
        match promise {
            Err(_) => true,
            Ok(p) => JsFuture::from(p).await.is_err(),
        }
    }

    #[wasm_bindgen_test]
    async fn unwrap_handle_cannot_encrypt_or_export() {
        let unwrap = MasterUnwrap::from_bytes(&[("m1", &[0x11; 32])])
            .await
            .unwrap();
        let key = unwrap.keys.borrow().get("m1").cloned().unwrap();
        let params = AesGcmParams::new_with_u8_array("AES-GCM", &Uint8Array::new_with_length(12));
        assert!(
            refused(
                unwrap
                    .subtle
                    .encrypt_with_object_and_u8_array(&params, &key, b"x")
            )
            .await,
            "an unwrap-only handle must not encrypt"
        );
        assert!(
            refused(unwrap.subtle.export_key("raw", &key)).await,
            "the master handle must not export"
        );
    }

    #[wasm_bindgen_test]
    async fn admin_handle_cannot_export() {
        let admin = MasterAdmin::from_bytes("m1", &[("m1", &[0x11; 32])])
            .await
            .unwrap();
        let key = admin.key("m1").unwrap();
        assert!(!key.extractable());
        assert!(refused(admin.subtle.export_key("raw", key)).await);
    }

    #[wasm_bindgen_test]
    fn version_names() {
        assert_eq!(binding_name("m1").as_deref(), Some("MASTER_KEY_M1"));
        assert_eq!(binding_name("m42").as_deref(), Some("MASTER_KEY_M42"));
        for bad in ["", "m", "m0", "m01", "M1", "m1x", "ROOT_KEY", "m1234567"] {
            assert_eq!(binding_name(bad), None, "{bad}");
        }
    }
}
