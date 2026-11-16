//! JWT parsing and claim checks. The signature itself is delegated to [`JwsVerifier`], so this
//! crate carries no signature-crypto dependency. Errors name algorithms, key ids and claim
//! names only; token contents never appear in them, and the algorithm and key id they echo are
//! cut to [`MAX_ERROR_CHARS`] characters.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::Value;

/// Signature algorithms accepted for login tokens. Nothing else is ever dispatched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alg {
    Rs256,
    Es256,
}

impl Alg {
    fn name(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Es256 => "ES256",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub kid: Option<String>,
    pub alg: Option<String>,
    pub n: Option<String>,
    pub e: Option<String>,
    pub crv: Option<String>,
    pub x: Option<String>,
    pub y: Option<String>,
}

/// A JWK Set. Deserializing keeps only signature keys: a key whose `use` is anything but `sig`
/// (an `enc` key, typically) is dropped, so a token naming its `kid` gets
/// [`JwtError::UnknownKid`]. A set built by hand is taken as given.
#[derive(Debug, Clone, Deserialize)]
pub struct Jwks {
    #[serde(deserialize_with = "signature_keys")]
    pub keys: Vec<Jwk>,
}

/// One JWKS entry with its `use`, which [`Jwk`] doesn't carry.
#[derive(Deserialize)]
struct UsedJwk {
    #[serde(rename = "use", default)]
    usage: Option<Value>,
    #[serde(flatten)]
    jwk: Jwk,
}

fn signature_keys<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Jwk>, D::Error> {
    Ok(Vec::<UsedJwk>::deserialize(d)?
        .into_iter()
        .filter(|k| k.usage.as_ref().is_none_or(|u| u == "sig"))
        .map(|k| k.jwk)
        .collect())
}

pub type Claims = serde_json::Map<String, Value>;

/// Verifies a JWS signature. ES256 signatures are the 64-byte raw `r||s` form; [`verify`] refuses
/// any other length before calling this.
#[allow(async_fn_in_trait)]
pub trait JwsVerifier {
    async fn verify(&self, alg: Alg, key: &Jwk, signing_input: &[u8], signature: &[u8]) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JwtError {
    #[error("malformed token")]
    Malformed,
    #[error("unsupported algorithm {0:?}")]
    UnsupportedAlg(String),
    #[error("token header has no kid")]
    MissingKid,
    #[error("no key with kid {0:?}")]
    UnknownKid(String),
    #[error("key does not fit the token algorithm")]
    KeyMismatch,
    #[error("bad signature")]
    BadSignature,
    #[error("wrong issuer")]
    WrongIssuer,
    #[error("token expired")]
    Expired,
    #[error("token not yet valid")]
    NotYetValid,
    #[error("token has no exp")]
    MissingExp,
}

pub const LEEWAY_SECS: u64 = 60;

/// The longest `alg` or `kid` an error echoes back; both come from the caller.
pub const MAX_ERROR_CHARS: usize = 64;

/// ES256 signatures in JWS are raw `r || s`, 32 bytes each (RFC 7518 3.4).
const ES256_SIG_LEN: usize = 64;
const P256_COORD_LEN: usize = 32;
const MIN_RSA_BITS: usize = 2048;

fn bounded(s: &str) -> String {
    s.chars().take(MAX_ERROR_CHARS).collect()
}

fn decode_part(part: &str) -> Result<Vec<u8>, JwtError> {
    URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| JwtError::Malformed)
}

/// A JSON object, refusing duplicate keys at any depth. `serde_json` keeps the last of two
/// duplicates; another parser might keep the first, so a token with them means different things
/// to different readers.
fn json_object(bytes: &[u8]) -> Result<Claims, JwtError> {
    match serde_json::from_slice::<Unique>(bytes) {
        Ok(Unique(Value::Object(m))) => Ok(m),
        _ => Err(JwtError::Malformed),
    }
}

/// A [`Value`] whose objects have no duplicate keys.
struct Unique(Value);

impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(UniqueVisitor).map(Unique)
    }
}

struct UniqueVisitor;

impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite number"))
    }

    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(Unique(v)) = seq.next_element()? {
            items.push(v);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut m = serde_json::Map::new();
        while let Some(k) = map.next_key::<String>()? {
            let Unique(v) = map.next_value()?;
            if m.contains_key(&k) {
                return Err(de::Error::custom("duplicate key"));
            }
            m.insert(k, v);
        }
        Ok(Value::Object(m))
    }
}

/// A JSON number as whole Unix seconds (RFC 7519 `NumericDate`), the one reading of `exp`,
/// `nbf` and `iat`. Fractions floor. A non-number, a negative or non-finite value, and anything at
/// or past 2^63 (integer or float alike) is `None`, so later arithmetic cannot overflow.
#[must_use]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn numeric_date(v: &Value) -> Option<u64> {
    const LIMIT: u64 = 1 << 63;
    if let Some(u) = v.as_u64() {
        return (u < LIMIT).then_some(u);
    }
    // 2^63 as f64 is exact; anything below it floors into u64 without saturating.
    match v.as_f64() {
        Some(f) if f.is_finite() && (0.0..9_223_372_036_854_775_808.0).contains(&f) => {
            Some(f.floor() as u64)
        }
        _ => None,
    }
}

/// The bit length of a big-endian unsigned integer, ignoring leading zero bytes.
fn bit_len(n: &[u8]) -> usize {
    match n.iter().position(|&b| b != 0) {
        None => 0,
        Some(i) => (n.len() - i) * 8 - n[i].leading_zeros() as usize,
    }
}

fn decoded(field: Option<&str>) -> Option<Vec<u8>> {
    field.and_then(|v| URL_SAFE_NO_PAD.decode(v).ok())
}

fn key_fits(alg: Alg, key: &Jwk) -> bool {
    if key.alg.as_deref().is_some_and(|a| a != alg.name()) {
        return false;
    }
    match alg {
        Alg::Rs256 => {
            key.kty == "RSA"
                && key.e.is_some()
                && decoded(key.n.as_deref()).is_some_and(|n| bit_len(&n) >= MIN_RSA_BITS)
        }
        Alg::Es256 => {
            key.kty == "EC"
                && key.crv.as_deref() == Some("P-256")
                && decoded(key.x.as_deref()).is_some_and(|x| x.len() == P256_COORD_LEN)
                && decoded(key.y.as_deref()).is_some_and(|y| y.len() == P256_COORD_LEN)
        }
    }
}

/// Verifies `token` against `jwks` and returns its claims.
///
/// # Errors
/// Returns the first failing rule: structure (including duplicate JSON keys and any `crit`
/// header), algorithm, key lookup, key/algorithm fit, signature (an ES256 signature must be 64
/// bytes), then issuer and time claims (checked only after the signature holds). `exp`, `nbf` and
/// `iat` are all read by [`numeric_date`]; a present `nbf` or `iat` it can't read is
/// [`JwtError::Malformed`].
pub async fn verify(
    token: &str,
    jwks: &Jwks,
    verifier: &impl JwsVerifier,
    issuer: &str,
    now: u64,
) -> Result<Claims, JwtError> {
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(JwtError::Malformed);
    };
    let header = json_object(&decode_part(h)?)?;
    let payload_bytes = decode_part(p)?;
    let signature = decode_part(s)?;

    // RFC 7515 4.1.11: a crit extension the recipient doesn't understand must be refused, and
    // edgekms understands none.
    if header.contains_key("crit") {
        return Err(JwtError::Malformed);
    }
    let alg = match header.get("alg").and_then(Value::as_str) {
        Some("RS256") => Alg::Rs256,
        Some("ES256") => Alg::Es256,
        Some(other) => return Err(JwtError::UnsupportedAlg(bounded(other))),
        None => return Err(JwtError::Malformed),
    };
    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .ok_or(JwtError::MissingKid)?;
    let key = jwks
        .keys
        .iter()
        .find(|k| k.kid.as_deref() == Some(kid))
        .ok_or_else(|| JwtError::UnknownKid(bounded(kid)))?;
    if !key_fits(alg, key) {
        return Err(JwtError::KeyMismatch);
    }
    if alg == Alg::Es256 && signature.len() != ES256_SIG_LEN {
        return Err(JwtError::BadSignature);
    }

    let signing_input = format!("{h}.{p}");
    if !verifier
        .verify(alg, key, signing_input.as_bytes(), &signature)
        .await
    {
        return Err(JwtError::BadSignature);
    }

    let claims = json_object(&payload_bytes)?;
    if claims.get("iss").and_then(Value::as_str) != Some(issuer) {
        return Err(JwtError::WrongIssuer);
    }
    // A non-number exp is MissingExp; a number numeric_date can't read is Malformed.
    let exp = match claims.get("exp") {
        Some(v) if v.is_number() => numeric_date(v).ok_or(JwtError::Malformed)?,
        _ => return Err(JwtError::MissingExp),
    };
    if now > exp.saturating_add(LEEWAY_SECS) {
        return Err(JwtError::Expired);
    }
    // A present nbf or iat that isn't a readable NumericDate is a malformed token, not an absent
    // claim.
    let date = |name: &str| {
        claims
            .get(name)
            .map(|v| numeric_date(v).ok_or(JwtError::Malformed))
    };
    if let Some(nbf) = date("nbf").transpose()?
        && now.saturating_add(LEEWAY_SECS) < nbf
    {
        return Err(JwtError::NotYetValid);
    }
    date("iat").transpose()?;
    Ok(claims)
}
