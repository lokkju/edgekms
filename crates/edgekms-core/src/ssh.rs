//! Stateless SSH login: an HMAC-authenticated challenge, and verification of an OpenSSH `SSHSIG`
//! over it against public keys pinned in a role. No state is kept between the two steps.
//!
//! A challenge names the origin (`https://host[:port]`) of the server that issued it, under the
//! MAC. The client refuses to sign a challenge whose origin isn't the server it asked, and the
//! server refuses one minted for another origin, so a deployment can't relay another's challenge
//! to an operator and log in there with the signature.
//!
//! A registration challenge (the control plane's `POST /v1/me/ssh-keys/challenge`) also names,
//! in clear text at its start and under the MAC, the account it registers a key to:
//! `ekmsr.<github_id>.<login>.<base64url(ts || random || mac || origin)>`. A signature over it
//! is a key holder's consent to that key on that account and no other, and a person asked to
//! sign one sees whose account it is in the very text they sign (lokkju/edgekms#17).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, PublicKey, SshSig};

use crate::hosted::plausible_login;
use crate::keyops::{KeyOps, MacPurpose};

/// The `ssh-keygen -Y sign -n` namespace every login signature must carry.
pub const NAMESPACE: &str = "edgekms";
/// The namespace of a registration proof (the control plane's `POST /v1/me/ssh-keys`). A
/// signature in it can't log in, and a login signature can't register a key.
pub const REGISTER_NAMESPACE: &str = "edgekms-register";
/// Seconds a challenge stays valid after it was issued.
pub const CHALLENGE_TTL_SECS: u64 = 60;
/// Seconds a registration challenge stays valid: in the console a person copies a command, runs
/// it and pastes the result.
pub const SSH_KEY_PROOF_TTL_SECS: u64 = 300;
/// Clock skew tolerated for a challenge stamped ahead of `now`.
const FUTURE_SKEW_SECS: u64 = 5;

/// Longest origin a challenge may carry, in bytes.
pub const MAX_ORIGIN_LEN: usize = 255;
/// Longest challenge string either side accepts; checked before any decoding.
pub const MAX_CHALLENGE_LEN: usize = PREFIX.len() + (FIXED_LEN + MAX_ORIGIN_LEN).div_ceil(3) * 4;

/// Longest registration challenge either side accepts: the prefix, a u64 in decimal, a
/// 39-byte login, two dots and the base64url tail. Checked before any decoding.
pub const MAX_REGISTER_CHALLENGE_LEN: usize =
    REGISTER_PREFIX.len() + 20 + 1 + 39 + 1 + (FIXED_LEN + MAX_ORIGIN_LEN).div_ceil(3) * 4;

const PREFIX: &str = "ekmsc.";
const REGISTER_PREFIX: &str = "ekmsr.";
/// `ts (8) || random (16)`, the start of the MAC input.
const STAMP_LEN: usize = 8 + 16;
const MAC_LEN: usize = 32;
/// `ts || random || mac`; the origin follows.
const FIXED_LEN: usize = STAMP_LEN + MAC_LEN;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SshError {
    #[error("malformed challenge")]
    MalformedChallenge,
    #[error("origin must be http(s)://host[:port], at most 255 bytes")]
    BadOrigin,
    #[error("challenge was issued for another origin")]
    WrongOrigin,
    /// A registration challenge asked for an account whose login isn't a GitHub login's shape.
    #[error("account login must be 1 to 39 ASCII letters, digits and hyphens")]
    BadAccount,
    /// A registration challenge names another account than the one registering the key.
    #[error("challenge was issued for another account")]
    WrongAccount,
    #[error("key backend failure")]
    Backend,
    #[error("challenge authentication failed")]
    BadChallengeMac,
    #[error("challenge expired")]
    ChallengeExpired,
    #[error("challenge is from the future")]
    ChallengeFromFuture,
    #[error("malformed signature")]
    MalformedSignature,
    #[error("wrong signature namespace")]
    WrongNamespace,
    #[error("key not allowed")]
    KeyNotAllowed,
    #[error("unsupported key type")]
    UnsupportedKeyType,
    #[error("signature verification failed")]
    BadSignature,
    /// A valid FIDO (`sk-ssh-ed25519`) signature made without a touch: the authenticator's
    /// user-presence flag is clear.
    #[error("security key signature made without user presence")]
    UserNotPresent,
}

/// Whether `origin` is the ASCII serialization of an http(s) origin: scheme, host, optional
/// port, nothing else. This is a shape check, not a URL parser.
#[must_use]
pub fn valid_origin(origin: &str) -> bool {
    let Some(authority) = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
    else {
        return false;
    };
    origin.len() <= MAX_ORIGIN_LEN
        && !authority.is_empty()
        && authority
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b))
}

/// `"ekmsc." + base64url(now_be8 || random16 || mac32 || origin)`, the MAC covering
/// `now || random || origin`. `origin` is the issuing server's, as the client addresses it.
///
/// # Errors
/// [`SshError::BadOrigin`] if `origin` isn't an http(s) origin; [`SshError::Backend`] if
/// [`KeyOps::mac`] fails.
pub async fn new_challenge(ops: &impl KeyOps, now: u64, origin: &str) -> Result<String, SshError> {
    new_challenge_with(ops, MacPurpose::Challenge, now, origin).await
}

/// [`new_challenge`] with the MAC keyed for `purpose`: the control plane mints login challenges
/// under [`MacPurpose::ControlChallenge`], so they don't verify as data-plane challenges. The
/// wire format is the same. Registration challenges, which name an account, come from
/// [`new_register_challenge`]; one minted here under [`MacPurpose::SshKeyProof`] registers
/// nothing, since [`check_register_challenge`] refuses the `ekmsc.` format.
///
/// # Errors
/// As [`new_challenge`].
pub async fn new_challenge_with(
    ops: &impl KeyOps,
    purpose: MacPurpose,
    now: u64,
    origin: &str,
) -> Result<String, SshError> {
    let raw = new_raw(ops, purpose, now, origin, &[]).await?;
    Ok(format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(raw)))
}

/// `ts || random || mac || origin` for a new challenge, the MAC covering
/// [`mac_input`]`(raw, bound)`.
async fn new_raw(
    ops: &impl KeyOps,
    purpose: MacPurpose,
    now: u64,
    origin: &str,
    bound: &[u8],
) -> Result<Vec<u8>, SshError> {
    if !valid_origin(origin) {
        return Err(SshError::BadOrigin);
    }
    let mut raw = vec![0u8; FIXED_LEN + origin.len()];
    raw[..8].copy_from_slice(&now.to_be_bytes());
    ops.random(&mut raw[8..STAMP_LEN]);
    raw[FIXED_LEN..].copy_from_slice(origin.as_bytes());
    let mac = ops
        .mac(purpose, &mac_input(&raw, bound))
        .await
        .map_err(|_| SshError::Backend)?;
    raw[STAMP_LEN..FIXED_LEN].copy_from_slice(&mac);
    Ok(raw)
}

/// `ts || random || bound || origin` from a decoded challenge. `bound` is empty for a login
/// challenge, so its bytes are what they always were, and a registration challenge's account
/// ([`account_bytes`]) otherwise.
fn mac_input(raw: &[u8], bound: &[u8]) -> Vec<u8> {
    [&raw[..STAMP_LEN], bound, &raw[FIXED_LEN..]].concat()
}

/// Decodes a challenge and checks its layout and its origin's shape, not its MAC.
fn decode(challenge: &str) -> Result<Vec<u8>, SshError> {
    if challenge.len() > MAX_CHALLENGE_LEN {
        return Err(SshError::MalformedChallenge);
    }
    let body = challenge
        .strip_prefix(PREFIX)
        .ok_or(SshError::MalformedChallenge)?;
    decode_tail(body)
}

/// The base64url `ts || random || mac || origin` of either kind of challenge, with its layout
/// and its origin's shape checked.
fn decode_tail(body: &str) -> Result<Vec<u8>, SshError> {
    let raw = URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|_| SshError::MalformedChallenge)?;
    let origin_ok = raw
        .get(FIXED_LEN..)
        .and_then(|o| std::str::from_utf8(o).ok())
        .is_some_and(valid_origin);
    if origin_ok {
        Ok(raw)
    } else {
        Err(SshError::MalformedChallenge)
    }
}

/// The origin a challenge says it was issued for, checked for shape and length only (the
/// client can't check the MAC). The CLI compares it with the server it asked before signing.
///
/// # Errors
/// [`SshError::MalformedChallenge`] if `challenge` isn't a well-formed challenge.
pub fn challenge_origin(challenge: &str) -> Result<String, SshError> {
    let mut raw = decode(challenge)?;
    let origin = raw.split_off(FIXED_LEN);
    String::from_utf8(origin).map_err(|_| SshError::MalformedChallenge)
}

/// Checks the layout, the MAC (constant time), the origin, then the age of a challenge from
/// [`new_challenge`]. `origins` are the origins this server answers on; the challenge must name
/// one of them. [`check_challenge_with`] with [`MacPurpose::Challenge`] and
/// [`CHALLENGE_TTL_SECS`].
///
/// # Errors
/// An [`SshError`] naming the first check that failed; a failing [`KeyOps`] is `BadChallengeMac`.
pub async fn check_challenge(
    ops: &impl KeyOps,
    challenge: &str,
    now: u64,
    origins: &[&str],
) -> Result<(), SshError> {
    check_challenge_with(
        ops,
        MacPurpose::Challenge,
        CHALLENGE_TTL_SECS,
        challenge,
        now,
        origins,
    )
    .await
    .map(drop)
}

/// A challenge that passed [`check_challenge_with`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checked {
    /// The challenge's MAC, which names it: the control plane records it to accept the
    /// challenge once.
    pub tag: [u8; MAC_LEN],
    /// The last second (Unix) at which the challenge is accepted: its timestamp plus the TTL.
    pub expires_at: u64,
}

/// [`check_challenge`] with the MAC keyed for `purpose` and a challenge good for `ttl` seconds
/// after its timestamp. Returns the challenge's tag and expiry.
///
/// # Errors
/// As [`check_challenge`].
pub async fn check_challenge_with(
    ops: &impl KeyOps,
    purpose: MacPurpose,
    ttl: u64,
    challenge: &str,
    now: u64,
    origins: &[&str],
) -> Result<Checked, SshError> {
    let raw = decode(challenge)?;
    let tag = check_mac_and_origin(ops, purpose, &raw, &[], origins).await?;
    check_age(&raw, tag, ttl, now)
}

/// The MAC (constant time) over [`mac_input`]`(raw, bound)`, then the origin; returns the tag.
async fn check_mac_and_origin(
    ops: &impl KeyOps,
    purpose: MacPurpose,
    raw: &[u8],
    bound: &[u8],
    origins: &[&str],
) -> Result<[u8; MAC_LEN], SshError> {
    let mut tag = [0u8; MAC_LEN];
    tag.copy_from_slice(&raw[STAMP_LEN..FIXED_LEN]);
    match ops.verify_mac(purpose, &mac_input(raw, bound), &tag).await {
        Ok(true) => {}
        _ => return Err(SshError::BadChallengeMac),
    }
    if !origins.iter().any(|o| &raw[FIXED_LEN..] == o.as_bytes()) {
        return Err(SshError::WrongOrigin);
    }
    Ok(tag)
}

/// The account a registration challenge registers a key to. Its `login` is display only (GitHub
/// logins can be renamed); `github_id` is what the control plane compares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterAccount {
    pub github_id: u64,
    /// The GitHub login when the challenge was minted, of [`plausible_login`]'s shape.
    pub login: String,
}

/// What a registration challenge's MAC binds besides the stamp and the origin:
/// `github_id (u64 big-endian) || login length (1 byte) || login`. The login is at most 39
/// bytes, so the length fits; it is there so the origin after it can't be mistaken for part of
/// the login.
fn account_bytes(account: &RegisterAccount) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + account.login.len());
    out.extend_from_slice(&account.github_id.to_be_bytes());
    out.push(u8::try_from(account.login.len()).unwrap_or(u8::MAX));
    out.extend_from_slice(account.login.as_bytes());
    out
}

/// A registration challenge for `account`, bound to `origin`, under
/// [`MacPurpose::SshKeyProof`]: `"ekmsr." + github_id + "." + login + "." +
/// base64url(now_be8 || random16 || mac32 || origin)`, the MAC covering `now || random ||`
/// [`account_bytes`] `|| origin`. The account leads the text, so it is in what the key holder
/// signs and in what they read before signing.
///
/// # Errors
/// [`SshError::BadAccount`] if the login isn't of [`plausible_login`]'s shape (it goes into a
/// shell command in the console); otherwise as [`new_challenge`].
pub async fn new_register_challenge(
    ops: &impl KeyOps,
    now: u64,
    origin: &str,
    account: &RegisterAccount,
) -> Result<String, SshError> {
    if !plausible_login(&account.login) {
        return Err(SshError::BadAccount);
    }
    let raw = new_raw(
        ops,
        MacPurpose::SshKeyProof,
        now,
        origin,
        &account_bytes(account),
    )
    .await?;
    Ok(format!(
        "{REGISTER_PREFIX}{}.{}.{}",
        account.github_id,
        account.login,
        URL_SAFE_NO_PAD.encode(raw)
    ))
}

/// Decodes a registration challenge: its account and its `ts || random || mac || origin`, with
/// the layout and shapes checked, not the MAC. The id must be spelled as `u64::to_string`
/// spells it, so each challenge has one spelling.
fn decode_register(challenge: &str) -> Result<(RegisterAccount, Vec<u8>), SshError> {
    if challenge.len() > MAX_REGISTER_CHALLENGE_LEN {
        return Err(SshError::MalformedChallenge);
    }
    let body = challenge
        .strip_prefix(REGISTER_PREFIX)
        .ok_or(SshError::MalformedChallenge)?;
    let mut parts = body.splitn(3, '.');
    let (Some(id), Some(login), Some(tail)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(SshError::MalformedChallenge);
    };
    let github_id = id
        .parse::<u64>()
        .ok()
        .filter(|n| n.to_string() == id)
        .ok_or(SshError::MalformedChallenge)?;
    if !plausible_login(login) {
        return Err(SshError::MalformedChallenge);
    }
    let raw = decode_tail(tail)?;
    let account = RegisterAccount {
        github_id,
        login: login.to_owned(),
    };
    Ok((account, raw))
}

/// The account and the origin a registration challenge names, checked for shape and length
/// only (the client can't check the MAC). The CLI compares them with the signed-in account and
/// the server it asked before signing.
///
/// # Errors
/// [`SshError::MalformedChallenge`] if `challenge` isn't a well-formed registration challenge.
pub fn register_challenge_parts(challenge: &str) -> Result<(RegisterAccount, String), SshError> {
    let (account, mut raw) = decode_register(challenge)?;
    let origin = raw.split_off(FIXED_LEN);
    let origin = String::from_utf8(origin).map_err(|_| SshError::MalformedChallenge)?;
    Ok((account, origin))
}

/// Checks a registration challenge from [`new_register_challenge`]: the layout, the MAC
/// (constant time, covering the account), the origin, that it names `github_id`, then its age
/// against [`SSH_KEY_PROOF_TTL_SECS`]. Returns the challenge's tag and expiry. A challenge
/// without an account (the `ekmsc.` format) is malformed here.
///
/// # Errors
/// An [`SshError`] naming the first check that failed: [`SshError::WrongAccount`] for a
/// challenge minted for another account.
pub async fn check_register_challenge(
    ops: &impl KeyOps,
    challenge: &str,
    now: u64,
    origins: &[&str],
    github_id: u64,
) -> Result<Checked, SshError> {
    let (account, raw) = decode_register(challenge)?;
    let tag = check_mac_and_origin(
        ops,
        MacPurpose::SshKeyProof,
        &raw,
        &account_bytes(&account),
        origins,
    )
    .await?;
    if account.github_id != github_id {
        return Err(SshError::WrongAccount);
    }
    check_age(&raw, tag, SSH_KEY_PROOF_TTL_SECS, now)
}

/// A challenge whose MAC and origin passed, checked for age: `ttl` seconds after its timestamp,
/// [`FUTURE_SKEW_SECS`] before it.
fn check_age(raw: &[u8], tag: [u8; MAC_LEN], ttl: u64, now: u64) -> Result<Checked, SshError> {
    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&raw[..8]);
    let ts = u64::from_be_bytes(ts_bytes);
    if ts > now.saturating_add(FUTURE_SKEW_SECS) {
        return Err(SshError::ChallengeFromFuture);
    }
    let expires_at = ts.saturating_add(ttl);
    if now > expires_at {
        return Err(SshError::ChallengeExpired);
    }
    Ok(Checked { tag, expires_at })
}

/// Whether edgekms accepts keys and signatures of `alg`: Ed25519, its FIDO form, ECDSA P-256.
pub(crate) fn supported(alg: &Algorithm) -> bool {
    match alg {
        Algorithm::Ed25519 | Algorithm::SkEd25519 => true,
        Algorithm::Ecdsa { curve } => *curve == EcdsaCurve::NistP256,
        _ => false,
    }
}

/// A `SkEd25519` signature blob is `ed25519 sig (64) || flags (1) || counter (4)`. ssh-key signs
/// over the flags but never tests them, so the user-presence bit (0x01, the key was touched) is
/// checked here; a blob too short to hold the trailer counts as not present.
fn user_present(blob: &[u8]) -> bool {
    const FLAG_USER_PRESENT: u8 = 0x01;
    blob.len()
        .checked_sub(5)
        .and_then(|i| blob.get(i))
        .is_some_and(|flags| flags & FLAG_USER_PRESENT != 0)
}

/// Verifies the armored `SSHSIG` over `challenge`'s bytes against `allowed_keys` (OpenSSH public
/// key lines; comments are ignored, key data is compared) and returns the signing key's SHA256
/// fingerprint. Allowed keys that do not parse are skipped, so they can never match.
///
/// # Errors
/// An [`SshError`] naming the first check that failed.
pub fn verify(
    allowed_keys: &[String],
    challenge: &str,
    armored_signature: &str,
) -> Result<String, SshError> {
    verify_sig(NAMESPACE, challenge, armored_signature, |embedded| {
        allowed_keys
            .iter()
            .filter_map(|line| PublicKey::from_openssh(line).ok())
            .find(|k| k.key_data() == embedded)
            .ok_or(SshError::KeyNotAllowed)
    })
    .map(|k| k.fingerprint)
}

/// The key a signature verified against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedKey {
    /// The algorithm name: `ssh-ed25519`, `sk-ssh-ed25519@openssh.com` or
    /// `ecdsa-sha2-nistp256`.
    pub key_type: String,
    /// `<type> <base64>`, without a comment.
    pub public_key: String,
    /// `SHA256:` and the unpadded standard base64 of the key blob's SHA-256, as
    /// `ssh-keygen -lf` prints it.
    pub fingerprint: String,
}

impl VerifiedKey {
    fn of(key: &PublicKey) -> Result<Self, SshError> {
        let bare = PublicKey::new(key.key_data().clone(), "");
        Ok(Self {
            key_type: key.algorithm().as_str().to_owned(),
            public_key: bare
                .to_openssh()
                .map_err(|_| SshError::MalformedSignature)?,
            fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
        })
    }
}

/// Verifies an armored login `SSHSIG` (namespace [`NAMESPACE`]) over `challenge`'s bytes
/// against the public key embedded in the signature itself, and returns that key. The control
/// plane finds the account by this key: anyone can put any public key in a signature, so the
/// key means nothing until this returns `Ok`.
///
/// # Errors
/// An [`SshError`] naming the first check that failed (never [`SshError::KeyNotAllowed`]).
pub fn verify_embedded(challenge: &str, armored_signature: &str) -> Result<VerifiedKey, SshError> {
    verify_sig(NAMESPACE, challenge, armored_signature, |embedded| {
        Ok(PublicKey::from(embedded.clone()))
    })
}

/// Verifies a registration proof: an armored `SSHSIG` with namespace [`REGISTER_NAMESPACE`] over
/// `challenge`'s bytes, by the key `public_key` names (an OpenSSH public key line; its comment
/// is ignored). Returns that key.
///
/// # Errors
/// [`SshError::KeyNotAllowed`] if `public_key` doesn't parse or isn't the signing key, or
/// another [`SshError`] naming the first check that failed.
pub fn verify_proof(
    public_key: &str,
    challenge: &str,
    armored_signature: &str,
) -> Result<VerifiedKey, SshError> {
    let named = PublicKey::from_openssh(public_key.trim()).ok();
    verify_sig(
        REGISTER_NAMESPACE,
        challenge,
        armored_signature,
        |embedded| {
            named
                .filter(|k| k.key_data() == embedded)
                .ok_or(SshError::KeyNotAllowed)
        },
    )
}

/// The checks every signature goes through, in order: armor, `namespace`, a supported
/// algorithm, the key `pick` chooses for the embedded key, the signature itself, and the
/// user-presence flag of a FIDO signature.
fn verify_sig(
    namespace: &str,
    challenge: &str,
    armored_signature: &str,
    pick: impl FnOnce(&KeyData) -> Result<PublicKey, SshError>,
) -> Result<VerifiedKey, SshError> {
    let sig = SshSig::from_pem(armored_signature).map_err(|_| SshError::MalformedSignature)?;
    if sig.namespace() != namespace {
        return Err(SshError::WrongNamespace);
    }
    if !supported(&sig.algorithm()) || !supported(&sig.public_key().algorithm()) {
        return Err(SshError::UnsupportedKeyType);
    }
    let key = pick(sig.public_key())?;
    key.verify(namespace, challenge.as_bytes(), &sig)
        .map_err(|_| SshError::BadSignature)?;
    if sig.algorithm() == Algorithm::SkEd25519 && !user_present(sig.signature_bytes()) {
        return Err(SshError::UserNotPresent);
    }
    VerifiedKey::of(&key)
}

/// Longest public key line [`parse_public_key`] accepts, in bytes.
pub const MAX_PUBLIC_KEY_BYTES: usize = 8192;

/// Why [`parse_public_key`] refused a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    /// Not one OpenSSH public key line of at most [`MAX_PUBLIC_KEY_BYTES`].
    #[error("not an OpenSSH public key line")]
    Invalid,
    /// A key edgekms doesn't accept: only Ed25519, `sk-ssh-ed25519` and ECDSA P-256.
    #[error("only ssh-ed25519, sk-ssh-ed25519@openssh.com and ecdsa-sha2-nistp256 keys")]
    Unsupported,
}

/// A public key as the control plane registers it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedKey {
    pub key_type: String,
    /// `<type> <base64>`, without the comment.
    pub public_key: String,
    pub fingerprint: String,
    /// The line's comment, empty when it had none.
    pub comment: String,
}

/// Parses one OpenSSH public key line (surrounding whitespace ignored, at most
/// [`MAX_PUBLIC_KEY_BYTES`]) of a supported type.
///
/// # Errors
/// [`KeyError::Invalid`] for anything but one parseable line; [`KeyError::Unsupported`] for a
/// key of another type.
pub fn parse_public_key(line: &str) -> Result<ParsedKey, KeyError> {
    if line.len() > MAX_PUBLIC_KEY_BYTES {
        return Err(KeyError::Invalid);
    }
    let line = line.trim();
    if line.is_empty() || line.contains(['\n', '\r']) {
        return Err(KeyError::Invalid);
    }
    let key = PublicKey::from_openssh(line).map_err(|_| KeyError::Invalid)?;
    if !supported(&key.algorithm()) {
        return Err(KeyError::Unsupported);
    }
    let v = VerifiedKey::of(&key).map_err(|_| KeyError::Invalid)?;
    Ok(ParsedKey {
        key_type: v.key_type,
        public_key: v.public_key,
        fingerprint: v.fingerprint,
        comment: key.comment().to_owned(),
    })
}

const FINGERPRINT_PREFIX: &str = "SHA256:";
/// The length of a SHA-256 in unpadded base64.
const KEY_ID_LEN: usize = 43;

/// The id a control-plane route names a key by: the base64 part of its `SHA256:` fingerprint in
/// base64url (`+` to `-`, `/` to `_`), since a `/` can't go in a path segment. `None` for
/// anything but a SHA-256 fingerprint.
#[must_use]
pub fn key_id(fingerprint: &str) -> Option<String> {
    let b64 = fingerprint.strip_prefix(FINGERPRINT_PREFIX)?;
    let ok = b64.len() == KEY_ID_LEN
        && b64
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/');
    ok.then(|| b64.replace('+', "-").replace('/', "_"))
}

/// The fingerprint a [`key_id`] stands for; `None` unless `id` is 43 base64url characters.
#[must_use]
pub fn fingerprint_from_id(id: &str) -> Option<String> {
    let ok = id.len() == KEY_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    ok.then(|| {
        format!(
            "{FINGERPRINT_PREFIX}{}",
            id.replace('-', "+").replace('_', "/")
        )
    })
}
