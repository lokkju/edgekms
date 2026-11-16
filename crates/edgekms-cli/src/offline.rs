//! Break-glass operations that run from the root key and the config alone, with no Worker.
//!
//! Versions below a key's `min_decryption_version` still work here: the operator holding the
//! root key is the authority the Worker's limit protects against. Versions above
//! `latest_version` were never issued and are refused.

use std::io::Read;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use edgekms_core::config::{Config, KeyConfig};
use edgekms_core::transit::{self, Ciphertext, RootKey};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum OfflineError {
    /// Never carries the offending input.
    #[error("root key: {0}")]
    RootKey(&'static str),
    #[error("no key named {0:?} in the config")]
    UnknownKey(String),
    #[error("version {version} of key {key:?} does not exist (latest is {latest})")]
    BadVersion {
        key: String,
        version: u32,
        latest: u32,
    },
    #[error("ciphertext: {0}")]
    Ciphertext(transit::Error),
    #[error("decryption failed: wrong root key, wrong config, or altered ciphertext")]
    Decrypt,
}

/// Most bytes [`read_root_key`] accepts: a 44-character key with generous whitespace.
pub const MAX_ROOT_KEY_INPUT: usize = 256;

/// Reads the root key from `input`: standard base64, surrounding whitespace ignored, exactly
/// 32 bytes once decoded.
///
/// The input goes into one fixed, zeroizing buffer; nothing grows or reallocates, so no copy of
/// it is left behind in freed memory.
///
/// # Errors
/// [`OfflineError::RootKey`] when `input` cannot be read, is longer than
/// [`MAX_ROOT_KEY_INPUT`], is not base64, or is not 32 bytes.
pub fn read_root_key(mut input: impl Read) -> Result<Zeroizing<[u8; 32]>, OfflineError> {
    // One spare byte tells "exactly full" from "too long".
    let mut buf = Zeroizing::new([0u8; MAX_ROOT_KEY_INPUT + 1]);
    let mut len = 0;
    loop {
        // The read error text is dropped on purpose; a label is enough.
        match input.read(&mut buf[len..]) {
            Ok(0) => break,
            Ok(n) => len += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(OfflineError::RootKey("could not read stdin")),
        }
        if len > MAX_ROOT_KEY_INPUT {
            return Err(OfflineError::RootKey("input is too long for a root key"));
        }
    }
    let text = std::str::from_utf8(&buf[..len])
        .map_err(|_| OfflineError::RootKey("could not read stdin as text"))?;
    let mut decoded = Zeroizing::new([0u8; 48]);
    let n = STANDARD
        .decode_slice(text.trim(), &mut decoded[..])
        .map_err(|_| OfflineError::RootKey("not valid standard base64"))?;
    let mut key = Zeroizing::new([0u8; 32]);
    if n != key.len() {
        return Err(OfflineError::RootKey("must decode to exactly 32 bytes"));
    }
    key.copy_from_slice(&decoded[..n]);
    Ok(key)
}

fn key_config<'c>(config: &'c Config, name: &str) -> Result<&'c KeyConfig, OfflineError> {
    config
        .key(name)
        .ok_or_else(|| OfflineError::UnknownKey(name.to_owned()))
}

fn check_version(name: &str, key: &KeyConfig, version: u32) -> Result<(), OfflineError> {
    if version == 0 || version > key.latest_version {
        return Err(OfflineError::BadVersion {
            key: name.to_owned(),
            version,
            latest: key.latest_version,
        });
    }
    Ok(())
}

/// What [`decrypt`] produced. Its `Debug` leaves out the plaintext.
#[derive(PartialEq, Eq)]
pub struct Decrypted {
    /// Standard base64.
    pub plaintext: Zeroizing<String>,
    /// Set when the ciphertext's version is below the key's `min_decryption_version`: it
    /// decrypts here, but the Worker would refuse it.
    pub notice: Option<String>,
}

impl std::fmt::Debug for Decrypted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Decrypted")
            .field("plaintext", &"<redacted>")
            .field("notice", &self.notice)
            .finish()
    }
}

/// Decrypts a `vault:v<N>:...` ciphertext under the named key.
///
/// # Errors
/// An [`OfflineError`] for an unknown key, a malformed or out-of-range ciphertext, or a failed
/// decryption.
pub fn decrypt(
    config: &Config,
    root: &[u8; 32],
    key_name: &str,
    ciphertext: &str,
) -> Result<Decrypted, OfflineError> {
    let key = key_config(config, key_name)?;
    let ct: Ciphertext = ciphertext
        .trim()
        .parse()
        .map_err(OfflineError::Ciphertext)?;
    check_version(key_name, key, ct.version())?;
    let root = RootKey::from_ref(config.root_id.clone(), root);
    let data_key = root.transit_key(&key.id, ct.version());
    let plaintext = transit::decrypt(&data_key, &ct).map_err(|_| OfflineError::Decrypt)?;
    let notice = (ct.version() < key.min_decryption_version).then(|| {
        format!(
            "ciphertext version {} of key {key_name:?} is below min_decryption_version {}; \
             it decrypts offline, but the Worker refuses it (rewrap it to keep it usable there)",
            ct.version(),
            key.min_decryption_version
        )
    });
    Ok(Decrypted {
        plaintext: Zeroizing::new(STANDARD.encode(&*plaintext)),
        notice,
    })
}

/// The raw AES-256 key for `version` of the named key, as standard base64, for import into
/// another KMS.
///
/// # Errors
/// An [`OfflineError`] for an unknown key or a version outside `1..=latest_version`.
pub fn export(
    config: &Config,
    root: &[u8; 32],
    key_name: &str,
    version: u32,
) -> Result<Zeroizing<String>, OfflineError> {
    let key = key_config(config, key_name)?;
    check_version(key_name, key, version)?;
    let root = RootKey::from_ref(config.root_id.clone(), root);
    let raw = root.export_transit_key(&key.id, version);
    Ok(Zeroizing::new(STANDARD.encode(&raw[..])))
}
