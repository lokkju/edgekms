//! Stateless bearer tokens: `ekms.<base64url payload>.<base64url mac>`.
//!
//! The MAC covers the base64url payload string exactly as it appears in the token, so no
//! re-encoding step can diverge between mint and check. `check` verifies the MAC before it
//! parses the payload, and no error variant carries token or claim content.

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::keyops::{KeyOps, MacPurpose};
use crate::transit::Error;

pub const PREFIX: &str = "ekms.";

const VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenClaims {
    pub v: u8,
    pub jti: String,
    pub role: String,
    pub policies: Vec<String>,
    pub iat: u64,
    pub exp: u64,
    pub long: bool,
    #[serde(default)]
    pub meta: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    #[error("malformed token")]
    Malformed,
    #[error("invalid token signature")]
    BadMac,
    #[error("token expired")]
    Expired,
    #[error("unsupported token version")]
    UnsupportedVersion,
}

/// A fresh token id: 16 random bytes, base64url without padding (22 characters).
pub fn new_jti(ops: &impl KeyOps) -> String {
    let mut bytes = [0u8; 16];
    ops.random(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Serialize `claims` (struct field order, so the output is deterministic) and sign them.
///
/// # Errors
/// Fails if serialization or the MAC computation fails.
pub async fn mint(ops: &impl KeyOps, claims: &TokenClaims) -> Result<String, Error> {
    let json = serde_json::to_vec(claims).map_err(|_| Error::Malformed("token claims"))?;
    let payload = URL_SAFE_NO_PAD.encode(json);
    let tag = ops.mac(MacPurpose::Token, payload.as_bytes()).await?;
    Ok(format!("{PREFIX}{payload}.{}", URL_SAFE_NO_PAD.encode(tag)))
}

/// Check a token and return its claims. Order: shape, MAC, payload parse, version, expiry.
///
/// # Errors
/// A [`TokenError`] naming the first check that failed; never carries token content.
pub async fn check(ops: &impl KeyOps, token: &str, now: u64) -> Result<TokenClaims, TokenError> {
    let rest = token.strip_prefix(PREFIX).ok_or(TokenError::Malformed)?;
    let mut parts = rest.split('.');
    let (Some(payload), Some(tag), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(TokenError::Malformed);
    };
    if payload.is_empty() || tag.is_empty() {
        return Err(TokenError::Malformed);
    }
    let tag = URL_SAFE_NO_PAD
        .decode(tag)
        .map_err(|_| TokenError::Malformed)?;

    match ops
        .verify_mac(MacPurpose::Token, payload.as_bytes(), &tag)
        .await
    {
        Ok(true) => {}
        Ok(false) | Err(_) => return Err(TokenError::BadMac),
    }

    let json = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| TokenError::Malformed)?;
    let claims: TokenClaims = serde_json::from_slice(&json).map_err(|_| TokenError::Malformed)?;
    if claims.v != VERSION {
        return Err(TokenError::UnsupportedVersion);
    }
    if now >= claims.exp {
        return Err(TokenError::Expired);
    }
    Ok(claims)
}
