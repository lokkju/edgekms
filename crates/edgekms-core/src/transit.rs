//! Vault Transit compatible encryption: `aes256-gcm96` keys derived from a root key, and the
//! `vault:v<N>:<base64(nonce || ciphertext || tag)>` ciphertext format.

use std::fmt;
use std::str::FromStr;

use aes_gcm::aead::{Aead, Nonce};
use aes_gcm::{Aes256Gcm, KeyInit};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

const PREFIX: &str = "vault:v";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("malformed ciphertext: {0}")]
    Malformed(&'static str),
    #[error("decryption failed")]
    Decrypt,
    #[error("invalid id {0:?}: use lowercase letters, digits and underscore")]
    InvalidId(String),
    /// The key backend (`WebCrypto`) failed on valid input: a server fault, not a client error.
    /// The label names the operation and never carries key material or data.
    #[error("key backend failure: {0}")]
    Backend(&'static str),
}

/// A root or key id. Ids go into HKDF inputs joined by `/`, so they may not contain one; the
/// allowed set is narrower than that so ids stay readable in config and audit logs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(try_from = "String")]
pub struct Id(String);

impl TryFrom<String> for Id {
    type Error = Error;

    fn try_from(s: String) -> Result<Self, Error> {
        Self::new(&s)
    }
}

impl Id {
    /// # Errors
    /// [`Error::InvalidId`] unless `s` is 1 to 64 of `[a-z0-9_]`.
    pub fn new(s: &str) -> Result<Self, Error> {
        let valid = (1..=64).contains(&s.len())
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        if valid {
            Ok(Self(s.to_owned()))
        } else {
            Err(Error::InvalidId(s.to_owned()))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The root key every named key derives from. The bytes live on the heap, so moving a
/// `RootKey` never copies them.
pub struct RootKey {
    id: Id,
    key: Box<Zeroizing<[u8; 32]>>,
}

impl RootKey {
    /// Takes `key` by value; the caller's copy is its own to zeroize. Prefer
    /// [`RootKey::from_ref`] when the bytes are already in zeroizing storage.
    #[must_use]
    pub fn new(id: Id, key: [u8; 32]) -> Self {
        let mut key = key;
        let root = Self::from_ref(id, &key);
        zeroize::Zeroize::zeroize(&mut key);
        root
    }

    /// Copies `key` straight into heap storage, leaving no stack copy behind.
    #[must_use]
    pub fn from_ref(id: Id, key: &[u8; 32]) -> Self {
        let mut boxed = Box::new(Zeroizing::new([0u8; 32]));
        boxed.copy_from_slice(key);
        Self { id, key: boxed }
    }

    /// The AES-256 key for version `version` of the named key whose id is `key_id`:
    /// `HKDF-SHA256(root, salt = "edgekms/v1/" + root id, info = "transit/" + key id + "/" + version)`.
    #[must_use]
    pub fn transit_key(&self, key_id: &Id, version: u32) -> DataKey {
        DataKey(self.derive(&format!("transit/{}/{version}", key_id.as_str())))
    }

    /// The raw bytes of [`RootKey::transit_key`], for break-glass export (`edgekms export`) to
    /// another KMS. Nothing in the Worker calls this; the caller must handle the result as key
    /// material.
    #[must_use]
    pub fn export_transit_key(&self, key_id: &Id, version: u32) -> Zeroizing<[u8; 32]> {
        self.derive(&format!("transit/{}/{version}", key_id.as_str()))
    }

    /// `HKDF-SHA256(root, salt = "edgekms/v1/" + root id, info)` expanded to 32 bytes.
    ///
    /// # Panics
    /// Never: 32 bytes is within HKDF-SHA256's output limit.
    pub(crate) fn derive(&self, info: &str) -> Zeroizing<[u8; 32]> {
        let salt = format!("edgekms/v1/{}", self.id.as_str());
        let mut okm = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(Some(salt.as_bytes()), self.key.as_slice())
            .expand(info.as_bytes(), &mut *okm)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        okm
    }
}

/// One version of one named key.
pub struct DataKey(Zeroizing<[u8; 32]>);

impl DataKey {
    #[must_use]
    pub fn from_bytes(key: [u8; 32]) -> Self {
        Self(Zeroizing::new(key))
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new(&(*self.0).into())
    }
}

/// A parsed `vault:v<N>:...` ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext {
    version: u32,
    payload: Vec<u8>,
}

impl Ciphertext {
    #[must_use]
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Assembles a ciphertext from a nonce and the AEAD output `ciphertext || tag`, for
    /// [`KeyOps`](crate::keyops::KeyOps) implementations that encrypt outside this module.
    ///
    /// # Errors
    /// [`Error::Malformed`] if `version` is 0 or `sealed` is shorter than a tag.
    pub fn from_parts(version: u32, nonce: &[u8; NONCE_LEN], sealed: &[u8]) -> Result<Self, Error> {
        if version == 0 {
            return Err(Error::Malformed("version must be a positive integer"));
        }
        if sealed.len() < TAG_LEN {
            return Err(Error::Malformed("too short"));
        }
        let mut payload = Vec::with_capacity(NONCE_LEN + sealed.len());
        payload.extend_from_slice(nonce);
        payload.extend_from_slice(sealed);
        Ok(Self { version, payload })
    }

    /// The 12-byte AES-GCM nonce.
    ///
    /// # Panics
    /// Never: parsing and [`Ciphertext::from_parts`] guarantee the payload holds a nonce.
    #[must_use]
    pub fn nonce(&self) -> &[u8; NONCE_LEN] {
        self.payload[..NONCE_LEN]
            .try_into()
            .expect("payload is at least NONCE_LEN + TAG_LEN bytes")
    }

    /// The AEAD output after the nonce: `ciphertext || tag`.
    #[must_use]
    pub fn sealed(&self) -> &[u8] {
        &self.payload[NONCE_LEN..]
    }
}

impl FromStr for Ciphertext {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let rest = s
            .strip_prefix(PREFIX)
            .ok_or(Error::Malformed("missing vault:v prefix"))?;
        let (version, b64) = rest
            .split_once(':')
            .ok_or(Error::Malformed("missing version"))?;
        if version.is_empty()
            || version.starts_with('0')
            || !version.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(Error::Malformed("version must be a positive integer"));
        }
        let version = version
            .parse()
            .map_err(|_| Error::Malformed("version out of range"))?;
        let payload = STANDARD
            .decode(b64)
            .map_err(|_| Error::Malformed("invalid base64"))?;
        if payload.len() < NONCE_LEN + TAG_LEN {
            return Err(Error::Malformed("too short"));
        }
        Ok(Self { version, payload })
    }
}

impl fmt::Display for Ciphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{PREFIX}{}:{}",
            self.version,
            STANDARD.encode(&self.payload)
        )
    }
}

/// Encrypts `plaintext` under `key`, labelling the result as key version `version`.
///
/// # Errors
/// [`Error::Malformed`] if `version` is 0, which no `vault:v<N>:` parser accepts back.
///
/// # Panics
/// If `plaintext` exceeds AES-GCM's 64 GiB limit, far past any request body edgekms accepts.
pub fn encrypt(
    key: &DataKey,
    version: u32,
    plaintext: &[u8],
    rng: &mut impl rand_core::CryptoRng,
) -> Result<String, Error> {
    if version == 0 {
        return Err(Error::Malformed("version must be a positive integer"));
    }
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let sealed = key
        .cipher()
        .encrypt(&Nonce::<Aes256Gcm>::from(nonce), plaintext)
        .expect("AES-GCM encryption fails only for inputs over 64 GiB");
    Ok(Ciphertext::from_parts(version, &nonce, &sealed)?.to_string())
}

/// Decrypts `ct` with `key`. The caller picks `key` from `ct.version()`.
///
/// # Errors
/// [`Error::Decrypt`] if the key is wrong or the ciphertext was altered.
pub fn decrypt(key: &DataKey, ct: &Ciphertext) -> Result<Zeroizing<Vec<u8>>, Error> {
    let (nonce, sealed) = ct.payload.split_at(NONCE_LEN);
    let nonce = Nonce::<Aes256Gcm>::try_from(nonce).map_err(|_| Error::Malformed("bad nonce"))?;
    key.cipher()
        .decrypt(&nonce, sealed)
        .map(Zeroizing::new)
        .map_err(|_| Error::Decrypt)
}
