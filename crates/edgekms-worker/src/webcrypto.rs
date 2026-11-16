//! [`KeyOps`] on Workers' `WebCrypto`. The root key is imported once as a non-extractable HKDF
//! key, and every AES-GCM and HMAC key derived from it is non-extractable too, so key bytes live
//! in the runtime's native memory and never in this module's linear memory. Derivation matches
//! [`edgekms_core::keyops::SoftKeyOps`] byte for byte.
//!
//! Derived keys are cached per HKDF `info` and usage for the life of the isolate, so a request
//! costs one `deriveKey` per key the isolate hasn't used yet instead of one per operation. The
//! cache holds the same non-extractable handles, never bytes, and is bounded by the config: a
//! transit key is derived only for a key in config and a version inside its window. It is also
//! capped at [`MAX_CACHED_KEYS`] whatever the config says.

use std::cell::RefCell;
use std::collections::HashMap;

use edgekms_core::keyops::{KeyOps, MacPurpose};
use edgekms_core::transit::{Ciphertext, Error, Id};
use js_sys::{Array, ArrayBuffer, Object, Reflect, Uint8Array};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    AesDerivedKeyParams, AesGcmParams, Crypto, CryptoKey, HkdfParams, HmacImportParams,
    SubtleCrypto,
};
use zeroize::Zeroizing;

use crate::vault::log_internal;

const NONCE_LEN: usize = 12;
const MAC_LEN: usize = 32;
const GCM_TAG_BITS: u8 = 128;
/// `crypto.getRandomValues` refuses requests over 64 KiB.
const RANDOM_CHUNK: usize = 65_536;

/// The most derived keys one [`WebCryptoKeyOps`] caches. Past it the cache is cleared and
/// starts over, which costs re-derivations but never correctness. The config bounds what a
/// tenant can derive; this bounds what one tenant's cache can hold of a shared isolate's memory
/// whatever the config says.
pub const MAX_CACHED_KEYS: usize = 1024;

/// [`KeyOps`] backed by `crypto.subtle`, holding only a non-extractable handle to the root key.
pub struct WebCryptoKeyOps {
    root: CryptoKey,
    root_id: Id,
    subtle: SubtleCrypto,
    crypto: Crypto,
    /// Derived keys by `(info, usage)`.
    derived: RefCell<HashMap<(String, &'static str), CryptoKey>>,
}

impl WebCryptoKeyOps {
    /// Imports `root_key` as a non-extractable HKDF key. The bytes are copied into a JS buffer
    /// for the import and that buffer is zeroed afterwards; zeroizing `root_key` itself is the
    /// caller's job.
    ///
    /// # Errors
    /// If `globalThis.crypto` is missing or `importKey` rejects.
    pub async fn import(root_key: &[u8; 32], root_id: Id) -> worker::Result<Self> {
        let crypto = global_crypto()?;
        let raw = Uint8Array::new_with_length(32);
        raw.copy_from(root_key);
        let imported = import_hkdf(&crypto.subtle(), &raw).await;
        raw.fill(0, 0, 32);
        Ok(Self::with_crypto(imported?, root_id, crypto))
    }

    /// Wraps an already-imported non-extractable HKDF key (from
    /// `MasterUnwrap::unwrap_root` or `MasterAdmin::new_root`), so a hosted tenant's raw root
    /// never passes through wasm memory. The handle needs the `deriveKey` usage; derivation
    /// matches [`WebCryptoKeyOps::import`] of the same bytes.
    ///
    /// # Errors
    /// If `globalThis.crypto` is missing.
    pub fn from_hkdf_key(root: CryptoKey, root_id: Id) -> worker::Result<Self> {
        Ok(Self::with_crypto(root, root_id, global_crypto()?))
    }

    fn with_crypto(root: CryptoKey, root_id: Id, crypto: Crypto) -> Self {
        Self {
            root,
            root_id,
            subtle: crypto.subtle(),
            crypto,
            derived: RefCell::new(HashMap::new()),
        }
    }

    /// How many derived keys are cached.
    #[must_use]
    pub fn cached_keys(&self) -> usize {
        self.derived.borrow().len()
    }

    /// `HKDF-SHA256(root, salt = "edgekms/v1/" + root id, info)` as a non-extractable key of
    /// type `algorithm`, from the cache when this isolate has derived it before.
    async fn derive(
        &self,
        info: &str,
        algorithm: &Object,
        usage: &'static str,
    ) -> Result<CryptoKey, Error> {
        let cache_key = (info.to_owned(), usage);
        // The borrow ends with this statement, before any `.await`.
        if let Some(key) = self.derived.borrow().get(&cache_key).cloned() {
            return Ok(key);
        }
        let salt = format!("edgekms/v1/{}", self.root_id.as_str());
        let params = HkdfParams::new_with_str(
            "HKDF",
            "SHA-256",
            &Uint8Array::from(info.as_bytes()),
            &Uint8Array::from(salt.as_bytes()),
        );
        let usages = Array::of1(&JsValue::from_str(usage));
        let derived = async {
            let promise = self.subtle.derive_key_with_object_and_object(
                &params, &self.root, algorithm, false, &usages,
            )?;
            JsFuture::from(promise).await
        }
        .await
        .map_err(|_| Error::Backend("key derivation"))?;
        let key: CryptoKey = derived.unchecked_into();
        let mut derived = self.derived.borrow_mut();
        if derived.len() >= MAX_CACHED_KEYS {
            derived.clear();
        }
        derived.insert(cache_key, key.clone());
        Ok(key)
    }

    async fn transit_key(
        &self,
        key_id: &Id,
        version: u32,
        usage: &'static str,
    ) -> Result<CryptoKey, Error> {
        let info = format!("transit/{}/{version}", key_id.as_str());
        self.derive(&info, &AesDerivedKeyParams::new("AES-GCM", 256), usage)
            .await
    }

    async fn mac_key(&self, purpose: MacPurpose, usage: &'static str) -> Result<CryptoKey, Error> {
        let params = HmacImportParams::new_with_str("HMAC", "SHA-256");
        // Without an explicit length WebCrypto derives a key of the hash's block size (64
        // bytes), which would not match SoftKeyOps' 32-byte HKDF output.
        Reflect::set(&params, &JsValue::from_str("length"), &JsValue::from(256))
            .map_err(|_| Error::Backend("key derivation"))?;
        self.derive(purpose.info(), &params, usage).await
    }
}

/// `globalThis.crypto`.
///
/// # Errors
/// If it is missing or isn't a `Crypto`.
pub(crate) fn global_crypto() -> worker::Result<Crypto> {
    Reflect::get(&js_sys::global(), &JsValue::from_str("crypto"))?
        .dyn_into()
        .map_err(|_| worker::Error::RustError("globalThis.crypto is not a Crypto".into()))
}

/// The usages of every root HKDF handle, imported or unwrapped: `deriveKey` only. Without
/// `deriveBits`, no derived key's bytes can be pulled into wasm memory.
pub(crate) fn hkdf_usages() -> Array {
    Array::of1(&JsValue::from_str("deriveKey"))
}

/// Imports `raw` as a non-extractable HKDF root. Zeroing `raw` is the caller's job.
pub(crate) async fn import_hkdf(
    subtle: &SubtleCrypto,
    raw: &Uint8Array,
) -> worker::Result<CryptoKey> {
    let promise = subtle.import_key_with_str("raw", raw, "HKDF", false, &hkdf_usages())?;
    Ok(JsFuture::from(promise).await?.unchecked_into())
}

/// Copies a `WebCrypto` result out of its `ArrayBuffer`, then zeroes the buffer so the bytes
/// don't linger in JS memory until collection.
fn take_bytes(buf: &JsValue) -> Zeroizing<Vec<u8>> {
    let view = Uint8Array::new(buf.unchecked_ref::<ArrayBuffer>());
    let bytes = Zeroizing::new(view.to_vec());
    view.fill(0, 0, view.length());
    bytes
}

impl KeyOps for WebCryptoKeyOps {
    async fn encrypt(&self, key_id: &Id, version: u32, plaintext: &[u8]) -> Result<String, Error> {
        let key = self.transit_key(key_id, version, "encrypt").await?;
        let mut nonce = [0u8; NONCE_LEN];
        self.random(&mut nonce);
        let params = AesGcmParams::new_with_u8_array("AES-GCM", &Uint8Array::from(&nonce[..]));
        params.set_tag_length(GCM_TAG_BITS);
        let sealed = async {
            let promise = self
                .subtle
                .encrypt_with_object_and_u8_array(&params, &key, plaintext)?;
            JsFuture::from(promise).await
        }
        .await
        .map_err(|_| Error::Backend("encrypt"))?;
        Ok(Ciphertext::from_parts(version, &nonce, &take_bytes(&sealed))?.to_string())
    }

    async fn decrypt(&self, key_id: &Id, ct: &Ciphertext) -> Result<Zeroizing<Vec<u8>>, Error> {
        let key = self.transit_key(key_id, ct.version(), "decrypt").await?;
        let params = AesGcmParams::new_with_u8_array("AES-GCM", &Uint8Array::from(&ct.nonce()[..]));
        params.set_tag_length(GCM_TAG_BITS);
        let opened = async {
            let promise =
                self.subtle
                    .decrypt_with_object_and_u8_array(&params, &key, ct.sealed())?;
            JsFuture::from(promise).await
        }
        .await
        .map_err(|_| Error::Decrypt)?;
        Ok(take_bytes(&opened))
    }

    async fn mac(&self, purpose: MacPurpose, data: &[u8]) -> Result<[u8; 32], Error> {
        let key = self.mac_key(purpose, "sign").await?;
        let tag = async {
            let promise = self.subtle.sign_with_str_and_u8_array("HMAC", &key, data)?;
            JsFuture::from(promise).await
        }
        .await
        .map_err(|_| Error::Backend("hmac"))?;
        <[u8; 32]>::try_from(&take_bytes(&tag)[..]).map_err(|_| Error::Backend("hmac"))
    }

    async fn verify_mac(
        &self,
        purpose: MacPurpose,
        data: &[u8],
        tag: &[u8],
    ) -> Result<bool, Error> {
        if tag.len() != MAC_LEN {
            return Ok(false);
        }
        let key = self.mac_key(purpose, "verify").await?;
        let valid = async {
            let promise = self
                .subtle
                .verify_with_str_and_u8_array_and_u8_array("HMAC", &key, tag, data)?;
            JsFuture::from(promise).await
        }
        .await
        .map_err(|_| Error::Backend("hmac"))?;
        Ok(valid.as_bool() == Some(true))
    }

    /// # Panics
    /// If `crypto.getRandomValues` throws. It only throws for a buffer over 64 KiB, which the
    /// chunking rules out, or a non-integer array, which a `Uint8Array` isn't. `KeyOps::random`
    /// is infallible, and carrying on without randomness would mean a repeated nonce or token
    /// id, so a failure stops the request (the runtime answers 500) after logging why.
    fn random(&self, out: &mut [u8]) {
        for chunk in out.chunks_mut(RANDOM_CHUNK) {
            if self.crypto.get_random_values_with_u8_array(chunk).is_err() {
                log_internal("getRandomValues failed; stopping the request");
                panic!("getRandomValues failed");
            }
        }
    }
}
