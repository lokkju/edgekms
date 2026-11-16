//! [`JwsVerifier`] on `WebCrypto`: RSASSA-PKCS1-v1_5 with SHA-256 for RS256 and ECDSA P-256
//! with SHA-256 for ES256. The JWK is imported with `importKey("jwk")`, so no RSA or EC code is
//! compiled into the Worker.

use edgekms_core::jwt::{Alg, Jwk, JwsVerifier};
use js_sys::{Array, Object, Reflect};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Crypto, CryptoKey, SubtleCrypto};

/// ES256 signatures in JWS are raw `r || s`, 32 bytes each.
const ES256_SIG_LEN: usize = 64;

pub struct WebJws;

impl JwsVerifier for WebJws {
    async fn verify(&self, alg: Alg, key: &Jwk, signing_input: &[u8], signature: &[u8]) -> bool {
        if alg == Alg::Es256 && signature.len() != ES256_SIG_LEN {
            return false;
        }
        verify(alg, key, signing_input, signature)
            .await
            .unwrap_or(false)
    }
}

fn object(pairs: &[(&str, &str)]) -> Result<Object, JsValue> {
    let o = Object::new();
    for (k, v) in pairs {
        Reflect::set(&o, &JsValue::from_str(k), &JsValue::from_str(v))?;
    }
    Ok(o)
}

fn subtle() -> Result<SubtleCrypto, JsValue> {
    let crypto: Crypto = Reflect::get(&js_sys::global(), &JsValue::from_str("crypto"))?
        .dyn_into()
        .map_err(|_| JsValue::from_str("globalThis.crypto is not a Crypto"))?;
    Ok(crypto.subtle())
}

/// Only the public parameters the algorithm needs go into the imported JWK; anything else the
/// issuer published (`alg`, `use`, `key_ops`, private members) is left out.
async fn verify(alg: Alg, key: &Jwk, input: &[u8], signature: &[u8]) -> Result<bool, JsValue> {
    let missing = || JsValue::from_str("JWK lacks a parameter");
    let (jwk, import_alg, verify_alg) = match alg {
        Alg::Rs256 => (
            object(&[
                ("kty", "RSA"),
                ("n", key.n.as_deref().ok_or_else(missing)?),
                ("e", key.e.as_deref().ok_or_else(missing)?),
            ])?,
            object(&[("name", "RSASSA-PKCS1-v1_5"), ("hash", "SHA-256")])?,
            object(&[("name", "RSASSA-PKCS1-v1_5")])?,
        ),
        Alg::Es256 => (
            object(&[
                ("kty", "EC"),
                ("crv", "P-256"),
                ("x", key.x.as_deref().ok_or_else(missing)?),
                ("y", key.y.as_deref().ok_or_else(missing)?),
            ])?,
            object(&[("name", "ECDSA"), ("namedCurve", "P-256")])?,
            object(&[("name", "ECDSA"), ("hash", "SHA-256")])?,
        ),
    };
    let subtle = subtle()?;
    let usages = Array::of1(&JsValue::from_str("verify"));
    let imported: CryptoKey =
        JsFuture::from(subtle.import_key_with_object("jwk", &jwk, &import_alg, false, &usages)?)
            .await?
            .unchecked_into();
    let ok = JsFuture::from(subtle.verify_with_object_and_u8_array_and_u8_array(
        &verify_alg,
        &imported,
        signature,
        input,
    )?)
    .await?;
    Ok(ok.as_bool() == Some(true))
}
