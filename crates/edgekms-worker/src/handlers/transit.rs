//! `transit/encrypt`, `transit/decrypt`, `transit/rewrap` and `transit/keys`.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use edgekms_core::config::{Capability, KeyConfig};
use edgekms_core::keyops::{KeyOps, MacPurpose};
use edgekms_core::policy;
use edgekms_core::transit::{Ciphertext, Error};
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use super::{ApiRequest, Deps, json_body};
use crate::audit::{AuditSink, RateLimit};
use crate::auth::{Logged, Revocations};
use crate::jwks::JwksSource;
use crate::vault::{Reply, log_internal};

/// Vault Transit request fields edgekms doesn't implement. Silently ignoring any of them would
/// change what the caller thinks they got, so each is a 400, unless it is empty (`null`, `""`
/// or `false`): Vault ignores an empty one for a key that is neither derived nor convergent, as
/// every edgekms key is, and some clients always send `"context": ""`.
const UNSUPPORTED: [&str; 5] = [
    "context",
    "batch_input",
    "associated_data",
    "convergent_encryption",
    "nonce",
];

const TOO_OLD: &str = "ciphertext or signature version is disallowed by policy (too old)";

#[derive(Clone, Copy)]
pub(super) enum Op {
    Encrypt,
    Decrypt,
    Rewrap,
}

impl Op {
    /// The audit event's `op`.
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Encrypt => "encrypt",
            Self::Decrypt => "decrypt",
            Self::Rewrap => "rewrap",
        }
    }

    fn capability(self) -> Capability {
        match self {
            Self::Encrypt => Capability::Encrypt,
            Self::Decrypt => Capability::Decrypt,
            Self::Rewrap => Capability::Rewrap,
        }
    }
}

/// Authenticates, checks `cap` on the key name, then finds the key. The policy comes first, as
/// in Vault, so a caller with no grant on a name gets the same 403 whether or not the key
/// exists.
async fn authorize<'s, K: KeyOps, R: Revocations, J: JwksSource, A: AuditSink, L: RateLimit>(
    deps: &Deps<'s, K, R, J, A, L>,
    req: &ApiRequest,
    name: &str,
    cap: Capability,
) -> Result<&'s KeyConfig, Reply> {
    // A name in config goes in the event before authenticating, so a denial records which
    // key it was for; a name that isn't is caller input and never does.
    let key = deps.state.config.key(name);
    if key.is_some() {
        deps.event().key = Some(name.to_owned());
    }
    let caller = deps.authenticate(req).await?;
    if !policy::allows(&deps.state.config, &caller.claims.policies, name, cap) {
        return Err(Reply::denied());
    }
    // Config validation only lets a policy name a key in config, so a grant always finds one.
    key.ok_or_else(|| Reply::error(404, "encryption key not found"))
}

pub(super) async fn transit<
    K: KeyOps,
    R: Revocations,
    J: JwksSource,
    A: AuditSink,
    L: RateLimit,
>(
    deps: &Deps<'_, K, R, J, A, L>,
    req: &ApiRequest,
    op: Op,
    name: &str,
) -> Reply {
    match run(deps, req, op, name).await {
        Ok(r) | Err(r) => r,
    }
}

async fn run<K: KeyOps, R: Revocations, J: JwksSource, A: AuditSink, L: RateLimit>(
    deps: &Deps<'_, K, R, J, A, L>,
    req: &ApiRequest,
    op: Op,
    name: &str,
) -> Result<Reply, Reply> {
    let key = authorize(deps, req, name, op.capability()).await?;
    let body = json_body(&req.body)?;
    if let Some(field) = UNSUPPORTED
        .iter()
        .find(|f| body.get(**f).is_some_and(|v| !is_empty(v)))
    {
        return Err(Reply::error(
            400,
            &format!("{field} is not supported by edgekms"),
        ));
    }
    match op {
        Op::Encrypt => {
            let plaintext = plaintext(&body)?;
            let version = encryption_version(&body, key)?;
            deps.event().version = Some(version);
            let ciphertext = seal(deps, key, version, &plaintext).await?;
            deps.event().ct_mac = Some(audit_mac(deps, &ciphertext).await?);
            Ok(Reply::data(json!({
                "ciphertext": ciphertext,
                "key_version": version,
            })))
        }
        Op::Decrypt => {
            let plaintext = open(deps, key, &body).await?;
            Ok(Reply::plaintext(&plaintext))
        }
        Op::Rewrap => {
            // `version` and `ct_mac` describe the ciphertext opened, `new_ct_mac` the new one.
            let plaintext = open(deps, key, &body).await?;
            let version = key.latest_version;
            let ciphertext = seal(deps, key, version, &plaintext).await?;
            deps.event().new_ct_mac = Some(audit_mac(deps, &ciphertext).await?);
            Ok(Reply::data(json!({
                "ciphertext": ciphertext,
                "key_version": version,
            })))
        }
    }
}

/// base64url (no padding) of the audit MAC of `ciphertext`, the `vault:vN:...` string as sent
/// or returned. A MAC failure fails the request.
async fn audit_mac<K: KeyOps, R, J, A, L>(
    deps: &Deps<'_, K, R, J, A, L>,
    ciphertext: &str,
) -> Result<String, Reply> {
    let tag = Logged(&deps.state.ops)
        .mac(MacPurpose::Audit, ciphertext.as_bytes())
        .await
        .map_err(|e| backend_failure(deps, &e))?;
    Ok(URL_SAFE_NO_PAD.encode(tag))
}

/// A key backend failure: `500 internal error`, with the cause in the audit event. `Logged`
/// already logs a backend's own label; an id the backend refused is logged here, since it
/// means a config the loader should never have accepted.
fn backend_failure<K, R, J, A, L>(deps: &Deps<'_, K, R, J, A, L>, e: &Error) -> Reply {
    if matches!(e, Error::InvalidId(_)) {
        log_internal("transit: key id refused by the backend");
        deps.fail("key_id_invalid");
    } else {
        deps.fail("key_backend");
    }
    Reply::internal()
}

/// `null`, `""` or `false`: a field sent with no meaning.
fn is_empty(v: &Value) -> bool {
    matches!(v, Value::Null | Value::Bool(false)) || v.as_str() == Some("")
}

fn plaintext(body: &Map<String, Value>) -> Result<Zeroizing<Vec<u8>>, Reply> {
    let Some(Value::String(b64)) = body.get("plaintext") else {
        return Err(Reply::error(400, "missing plaintext to encrypt"));
    };
    STANDARD
        .decode(b64)
        .map(Zeroizing::new)
        .map_err(|_| Reply::error(400, "failed to base64-decode plaintext"))
}

/// `key_version` if given (0 or absent means latest), within
/// `min_decryption_version..=latest_version`. A string of digits counts as the number, since
/// Vault decodes request fields weakly.
fn encryption_version(body: &Map<String, Value>, key: &KeyConfig) -> Result<u32, Reply> {
    let bad = || Reply::error(400, "key_version must be a non-negative integer");
    let requested = match body.get("key_version") {
        None | Some(Value::Null) => 0,
        // Vault's weak decoding reads "" as 0, the latest version.
        Some(Value::String(s)) if s.is_empty() => 0,
        Some(Value::String(s)) if s.bytes().all(|b| b.is_ascii_digit()) => {
            s.parse().map_err(|_| bad())?
        }
        Some(v) => v.as_u64().ok_or_else(bad)?,
    };
    if requested == 0 {
        return Ok(key.latest_version);
    }
    if requested > u64::from(key.latest_version) {
        return Err(Reply::error(
            400,
            "requested version for encryption is higher than the latest key version",
        ));
    }
    if requested < u64::from(key.min_decryption_version) {
        return Err(Reply::error(400, TOO_OLD));
    }
    u32::try_from(requested).map_err(|_| Reply::internal())
}

async fn seal<K: KeyOps, R, J, A, L>(
    deps: &Deps<'_, K, R, J, A, L>,
    key: &KeyConfig,
    version: u32,
    plaintext: &[u8],
) -> Result<String, Reply> {
    Logged(&deps.state.ops)
        .encrypt(&key.id, version, plaintext)
        .await
        .map_err(|e| backend_failure(deps, &e))
}

/// Parses `ciphertext`, checks its version against the key's window, and decrypts it. The
/// ciphertext's MAC goes in the audit event first, so a refused one is identified too.
async fn open<K: KeyOps, R, J, A, L>(
    deps: &Deps<'_, K, R, J, A, L>,
    key: &KeyConfig,
    body: &Map<String, Value>,
) -> Result<Zeroizing<Vec<u8>>, Reply> {
    let Some(Value::String(text)) = body.get("ciphertext") else {
        return Err(Reply::error(400, "missing ciphertext to decrypt"));
    };
    deps.event().ct_mac = Some(audit_mac(deps, text).await?);
    let ct: Ciphertext = text
        .parse()
        .map_err(|_| Reply::error(400, "invalid ciphertext"))?;
    deps.event().version = Some(ct.version());
    if ct.version() < key.min_decryption_version {
        return Err(Reply::error(400, TOO_OLD));
    }
    if ct.version() > key.latest_version {
        return Err(Reply::error(400, "invalid ciphertext: version is too new"));
    }
    Logged(&deps.state.ops)
        .decrypt(&key.id, &ct)
        .await
        .map_err(|e| match e {
            Error::Decrypt => Reply::error(400, "cipher: message authentication failed"),
            Error::Malformed(_) => Reply::error(400, "invalid ciphertext"),
            Error::Backend(_) | Error::InvalidId(_) => backend_failure(deps, &e),
        })
}

/// `GET transit/keys/:name`: Vault's key metadata shape, never key material.
pub(super) async fn keys<K: KeyOps, R: Revocations, J: JwksSource, A: AuditSink, L: RateLimit>(
    deps: &Deps<'_, K, R, J, A, L>,
    req: &ApiRequest,
    name: &str,
) -> Reply {
    let key = match authorize(deps, req, name, Capability::Read).await {
        Ok(k) => k,
        Err(r) => return r,
    };
    // Creation times aren't tracked in config yet; Vault clients only read the keys.
    let versions: Map<String, Value> = (key.min_decryption_version..=key.latest_version)
        .map(|v| (v.to_string(), json!(0)))
        .collect();
    Reply::data(json!({
        "name": name,
        "type": "aes256-gcm96",
        "latest_version": key.latest_version,
        "min_decryption_version": key.min_decryption_version,
        "min_encryption_version": 0,
        "deletion_allowed": false,
        "exportable": false,
        "supports_encryption": true,
        "supports_decryption": true,
        "supports_derivation": false,
        "keys": versions,
    }))
}
