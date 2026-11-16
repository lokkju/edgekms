//! SSH-key login to the control plane and the keys behind it (lokkju/edgekms#16).
//!
//! | Route | Who |
//! |---|---|
//! | `POST /v1/login/ssh/challenge` | anyone: a login challenge, 60 seconds, single use |
//! | `POST /v1/login/ssh` | anyone holding a registered key's private half |
//! | `GET /v1/me/ssh-keys` | any user: their keys, and the fingerprints of rows that don't verify |
//! | `POST /v1/me/ssh-keys/challenge` | any user whose login is under five minutes old |
//! | `POST /v1/me/ssh-keys` | the same, with a proof by the key over that challenge |
//! | `DELETE /v1/me/ssh-keys/:id` | the key's user, from any session |
//! | `DELETE /v1/ops/users/:github_id/ssh-keys` | operators: every key of the user, and a logout |
//!
//! A login challenge is `edgekms_core::ssh`'s format under the control root with
//! `MacPurpose::ControlChallenge`, bound to the request's origin (the control origin: the
//! console's proxy presents its requests under it too). The login body names no account: the
//! signature's embedded key does, once [`ssh::verify_embedded`] has checked the signature. That
//! check runs before anything reads the store, so someone holding only a public key learns
//! nothing, whether the key is registered or not, and every refusal is the same `400 permission
//! denied` counted against `AUTH_FAIL_LIMIT`. A challenge is accepted once: its MAC tag goes into
//! `used_ssh_challenges` after the signature verifies.
//!
//! An SSH login reaches existing accounts only, in every `SIGNUP_MODE`: an operator, a user
//! holding a membership that verifies (in an active tenant, or as owner of a suspended one), or
//! a user holding a pending invite that verifies to an active tenant. It never creates a user,
//! a personal tenant or an allowlist entry.
//!
//! Registering a key takes a fresh session and a proof: a signature by the key, in namespace
//! `edgekms-register`, over a registration challenge (`MacPurpose::SshKeyProof`, 300 seconds,
//! single use) that names the session's account (lokkju/edgekms#17). Only the key's holder can
//! therefore register it, or learn it is registered, and only to the account the text they
//! signed names: a challenge minted for one account is refused from another's session.
//! Each row carries a MAC under the control root (`Seal::ssh_key`); a row that doesn't verify
//! logs no one in and keeps no token alive.

use edgekms_core::hosted::ssh_key_label;
use edgekms_core::keyops::MacPurpose;
use edgekms_core::ssh::{
    self, CHALLENGE_TTL_SECS, KeyError, REGISTER_NAMESPACE, RegisterAccount,
    SSH_KEY_PROOF_TTL_SECS, SshError,
};
use serde_json::{Value, json};

use super::auth::{self, AuthMethod, CONTROL_TTL_SECS, User};
use super::login::{denied, existing, invited};
use super::members::Seal;
use super::ops::operator;
use super::{Control, RATE_LIMITED, attempt, coded, deny, internal};
use crate::audit::{AuditEvent, AuditSink, Limit, RateLimit};
use crate::handlers::login::ssh_label;
use crate::handlers::{ApiRequest, json_body};
use crate::store::{SshKeyRow, StoreError, TenantStore};
use crate::vault::Reply;
use crate::webcrypto::WebCryptoKeyOps;

/// The most SSH keys one account holds.
pub const MAX_SSH_KEYS_PER_USER: u64 = 10;

/// The longest armored signature either route reads; an `SSHSIG` from a supported key is well
/// under 1 KiB.
const MAX_SIGNATURE_LEN: usize = 8192;

/// How long past its last accepted second a challenge's tag stays in `used_ssh_challenges`.
/// Isolates' clocks can disagree; without the margin, a fast one could purge a tag that a slow
/// one would still accept.
const USED_MARGIN_SECS: u64 = 60;

/// The `expires_ms` a consumed challenge's tag is kept until.
fn used_until_ms(expires_at: u64) -> u64 {
    expires_at
        .saturating_add(1 + USED_MARGIN_SECS)
        .saturating_mul(1000)
}

/// `LOGIN_LIMIT` for the client: `429` (recorded as `rate_limited`) once it's spent.
async fn login_limit<S, A, L: RateLimit>(
    c: &Control<'_, S, A, L>,
    req: &ApiRequest,
    ev: &mut AuditEvent,
) -> Result<(), Reply> {
    // `handle` has already refused a request without a limit key.
    let allowed = match req.limit_key.as_deref() {
        Some(key) => c.limits.allow(Limit::Login, key).await,
        None => false,
    };
    if allowed {
        Ok(())
    } else {
        deny(ev, RATE_LIMITED);
        Err(Reply::error(429, "rate limit quota exceeded"))
    }
}

/// `POST /v1/login/ssh/challenge`: `{"challenge", "expires_in": 60}`, the same for every
/// caller.
pub async fn challenge<S: TenantStore, A, L: RateLimit>(
    c: &Control<'_, S, A, L>,
    req: &ApiRequest,
    ev: &mut AuditEvent,
) -> Reply {
    if let Err(reply) = login_limit(c, req, ev).await {
        return reply;
    }
    // No control root means no one has ever logged in, so no key is registered either.
    let root = match auth::existing_root(c, ev).await {
        Ok(Some(root)) => root,
        Ok(None) => {
            deny(ev, "control_root_missing");
            return Reply::error(400, "permission denied");
        }
        Err(reply) => return reply,
    };
    mint_challenge(
        ev,
        &root,
        MacPurpose::ControlChallenge,
        c.now(),
        &req.origin,
        json!({ "expires_in": CHALLENGE_TTL_SECS }),
    )
    .await
    .unwrap_or_else(|reply| reply)
}

/// A challenge for `purpose` bound to `origin`, as `{"challenge", ...extra}`.
async fn mint_challenge(
    ev: &mut AuditEvent,
    root: &WebCryptoKeyOps,
    purpose: MacPurpose,
    now: u64,
    origin: &str,
    mut extra: Value,
) -> Result<Reply, Reply> {
    match ssh::new_challenge_with(root, purpose, now, origin).await {
        Ok(challenge) => {
            extra["challenge"] = json!(challenge);
            Ok(Reply::data(extra))
        }
        Err(SshError::BadOrigin) => Err(internal(ev, "ssh_challenge_bad_origin")),
        Err(_) => Err(internal(ev, "ssh_challenge_mac_failed")),
    }
}

/// The `challenge` and `signature` strings of a login or registration body, the challenge
/// within `max_challenge` bytes and the signature within its cap; `None` for anything else.
fn challenge_and_signature(
    body: &serde_json::Map<String, Value>,
    max_challenge: usize,
) -> Option<(String, String)> {
    let challenge = body.get("challenge")?.as_str()?;
    let signature = body.get("signature")?.as_str()?;
    (challenge.len() <= max_challenge && signature.len() <= MAX_SIGNATURE_LEN)
        .then(|| (challenge.to_owned(), signature.to_owned()))
}

/// `POST /v1/login/ssh` with `{"challenge", "signature"}`.
pub async fn login<S: TenantStore, A: AuditSink, L: RateLimit>(
    c: &Control<'_, S, A, L>,
    req: &ApiRequest,
    ev: &mut AuditEvent,
) -> Reply {
    match run_login(c, req, ev).await {
        Ok(r) | Err(r) => r,
    }
}

async fn run_login<S: TenantStore, A: AuditSink, L: RateLimit>(
    c: &Control<'_, S, A, L>,
    req: &ApiRequest,
    ev: &mut AuditEvent,
) -> Result<Reply, Reply> {
    login_limit(c, req, ev).await?;
    let fields = json_body(&req.body)
        .ok()
        .and_then(|b| challenge_and_signature(&b, ssh::MAX_CHALLENGE_LEN));
    let Some((challenge, signature)) = fields else {
        return Err(denied(c, req, ev, "ssh_body_malformed").await);
    };
    // Without a root no challenge can verify. This reads `system_keys`, never anything about
    // a user or a key.
    let Some(root) = auth::existing_root(c, ev).await? else {
        return Err(denied(c, req, ev, "ssh_challenge_mac").await);
    };
    let checked = match ssh::check_challenge_with(
        &*root,
        MacPurpose::ControlChallenge,
        CHALLENGE_TTL_SECS,
        &challenge,
        c.now(),
        &[req.origin.as_str()],
    )
    .await
    {
        Ok(checked) => checked,
        Err(e) => return Err(denied(c, req, ev, ssh_label(&e)).await),
    };
    // The key embedded in the signature, checked against the signature itself. Nothing before
    // this point has touched the store but the control root's row.
    let key = match ssh::verify_embedded(&challenge, &signature) {
        Ok(key) => key,
        Err(e) => return Err(denied(c, req, ev, ssh_label(&e)).await),
    };
    drop(signature);
    // Only now does the key mean anything: whoever sent this holds its private half.
    ev.auth_ssh_fingerprint = Some(key.fingerprint.clone());
    match c
        .store
        .consume_challenge(&checked.tag, used_until_ms(checked.expires_at), c.now_ms)
        .await
    {
        Ok(()) => {}
        Err(StoreError::Conflict) => return Err(denied(c, req, ev, "ssh_challenge_replayed").await),
        Err(_) => return Err(internal(ev, "control_store_failed")),
    }
    let found = c
        .store
        .ssh_key(&key.fingerprint)
        .await
        .map_err(|_| internal(ev, "control_store_failed"))?;
    let Some(found) = found
        .filter(|f| f.row.fingerprint == key.fingerprint && f.row.public_key == key.public_key)
    else {
        return Err(denied(c, req, ev, "ssh_key_unknown").await);
    };
    let seal = Seal(&root);
    if !seal.ssh_key_ok(&found.row).await? {
        return Err(denied(c, req, ev, "ssh_key_mac_invalid").await);
    }
    let github_id = found.row.github_id;
    ev.github_id = Some(github_id);
    // The "existing" half of admission only, in every signup mode.
    let reachable = c.settings.is_operator(github_id)
        || existing(c, ev, &seal, github_id).await?
        || invited(c, ev, &seal, github_id).await?;
    if !reachable {
        return Err(denied(c, req, ev, "ssh_not_existing").await);
    }
    let method = AuthMethod::Ssh {
        fingerprint: key.fingerprint.clone(),
    };
    ev.auth_method = Some(method.label());
    attempt(c, ev).await?;
    c.store
        .ssh_login_used(github_id, &key.fingerprint, c.now_ms)
        .await
        .map_err(|_| internal(ev, "control_store_failed"))?;
    let ssh_keys = key_count(c, ev, &seal, github_id).await?;
    let token = auth::mint(&root, github_id, &found.login, &method, c.now_ms).await?;
    Ok(Reply::data(json!({
        "token": token.as_str(),
        "expires_in": CONTROL_TTL_SECS,
        "github_id": github_id,
        "login": found.login,
        "auth": method.label(),
        "ssh_fingerprint": key.fingerprint,
        "ssh_keys": ssh_keys,
    })))
}

/// How many keys that verify `github_id` holds: what a login reply reports, so a key added
/// behind the owner's back shows at their next login.
pub(super) async fn key_count<S: TenantStore, A, L>(
    c: &Control<'_, S, A, L>,
    ev: &mut AuditEvent,
    seal: &Seal<'_>,
    github_id: u64,
) -> Result<u64, Reply> {
    let rows = c
        .store
        .ssh_keys_for_user(github_id)
        .await
        .map_err(|_| internal(ev, "control_store_failed"))?;
    let mut n = 0;
    for row in rows.iter().filter(|r| r.github_id == github_id) {
        if seal.ssh_key_ok(row).await? {
            n += 1;
        }
    }
    Ok(n)
}

/// A key as the listing and the add reply show it.
fn key_json(row: &SshKeyRow) -> Value {
    json!({
        "id": ssh::key_id(&row.fingerprint),
        "fingerprint": row.fingerprint,
        "key_type": row.key_type,
        "public_key": row.public_key,
        "label": row.label,
        "added_ms": row.added_ms,
        "added_via": row.added_via,
        "last_used_ms": row.last_used_ms,
    })
}

/// `GET /v1/me/ssh-keys`: `{"keys": [...], "unverified": [fingerprint]}`, by `added_ms`.
pub async fn list<S: TenantStore, A, L>(
    c: &Control<'_, S, A, L>,
    ev: &mut AuditEvent,
    user: &User,
) -> Result<Reply, Reply> {
    let rows = c
        .store
        .ssh_keys_for_user(user.github_id)
        .await
        .map_err(|_| internal(ev, "control_store_failed"))?;
    let seal = Seal(&user.control_root);
    let mut keys = Vec::new();
    let mut unverified = Vec::new();
    for row in rows.iter().filter(|r| r.github_id == user.github_id) {
        if seal.ssh_key_ok(row).await? {
            keys.push(key_json(row));
        } else {
            unverified.push(json!(row.fingerprint));
        }
    }
    Ok(Reply::data(
        json!({ "keys": keys, "unverified": unverified }),
    ))
}

/// The refusal for a session too old to register a key, as export's.
fn stale(ev: &mut AuditEvent) -> Reply {
    deny(ev, "fresh_login_required");
    coded(403, "fresh login required", "fresh_login_required")
}

/// `POST /v1/me/ssh-keys/challenge`: `{"challenge", "expires_in": 300, "namespace":
/// "edgekms-register", "github_id", "login"}` for a fresh session. The challenge names the
/// session's account, which `github_id` and `login` repeat for a client that shows it.
pub async fn proof_challenge<S, A, L>(
    c: &Control<'_, S, A, L>,
    req: &ApiRequest,
    ev: &mut AuditEvent,
    user: &User,
) -> Result<Reply, Reply> {
    if !user.fresh(c.now()) {
        return Err(stale(ev));
    }
    let account = RegisterAccount {
        github_id: user.github_id,
        login: user.login.clone(),
    };
    match ssh::new_register_challenge(&*user.control_root, c.now(), &req.origin, &account).await {
        Ok(challenge) => Ok(Reply::data(json!({
            "challenge": challenge,
            "expires_in": SSH_KEY_PROOF_TTL_SECS,
            "namespace": REGISTER_NAMESPACE,
            "github_id": account.github_id,
            "login": account.login,
        }))),
        Err(SshError::BadOrigin) => Err(internal(ev, "ssh_challenge_bad_origin")),
        // GitHub logins always have the shape; a token carrying another is no session to
        // register a key from.
        Err(SshError::BadAccount) => Err(internal(ev, "ssh_challenge_bad_account")),
        Err(_) => Err(internal(ev, "ssh_challenge_mac_failed")),
    }
}

/// A failed registration proof: `400` coded `ssh_key_proof_failed`, counted against
/// `AUTH_FAIL_LIMIT` and recorded as `label`.
async fn proof_failed<S, A, L: RateLimit>(
    c: &Control<'_, S, A, L>,
    req: &ApiRequest,
    ev: &mut AuditEvent,
    label: &'static str,
) -> Reply {
    auth::failed(
        c,
        req,
        ev,
        label,
        coded(400, "ssh key proof failed", "ssh_key_proof_failed"),
    )
    .await
}

/// `POST /v1/me/ssh-keys` with `{"public_key", "label", "challenge", "signature"}`: `201` with
/// the new key. Checks, in order: a fresh session, the body, the label, the public key, the
/// challenge (its account must be the session's), the proof, then consumes the challenge and
/// inserts.
pub async fn add<S: TenantStore, A: AuditSink, L: RateLimit>(
    c: &Control<'_, S, A, L>,
    req: &ApiRequest,
    ev: &mut AuditEvent,
    user: &User,
) -> Result<Reply, Reply> {
    if !user.fresh(c.now()) {
        return Err(stale(ev));
    }
    let body = json_body(&req.body)?;
    let public_key = body.get("public_key").and_then(Value::as_str);
    let label = match body.get("label") {
        None | Some(Value::Null) => Some(""),
        Some(v) => v.as_str(),
    };
    let fields = challenge_and_signature(&body, ssh::MAX_REGISTER_CHALLENGE_LEN);
    let (Some(public_key), Some(label), Some((challenge, signature))) = (public_key, label, fields)
    else {
        return Err(Reply::error(
            400,
            "public_key, challenge and signature are required strings; label is an optional string",
        ));
    };
    let label = ssh_key_label(label).map_err(|e| coded(400, &e.to_string(), "label_invalid"))?;
    let parsed = ssh::parse_public_key(public_key).map_err(|e| match e {
        KeyError::Invalid => coded(400, &e.to_string(), "ssh_key_invalid"),
        KeyError::Unsupported => coded(400, &e.to_string(), "ssh_key_unsupported"),
    })?;
    let checked = match ssh::check_register_challenge(
        &*user.control_root,
        &challenge,
        c.now(),
        &[req.origin.as_str()],
        user.github_id,
    )
    .await
    {
        Ok(checked) => checked,
        Err(e) => return Err(proof_failed(c, req, ev, ssh_label(&e)).await),
    };
    let key = match ssh::verify_proof(&parsed.public_key, &challenge, &signature) {
        Ok(key) => key,
        Err(e) => return Err(proof_failed(c, req, ev, ssh_label(&e)).await),
    };
    drop(signature);
    ev.target_ssh_fingerprint = Some(key.fingerprint.clone());
    ev.target_ssh_key_type = Some(key.key_type.clone());
    match c
        .store
        .consume_challenge(&checked.tag, used_until_ms(checked.expires_at), c.now_ms)
        .await
    {
        Ok(()) => {}
        Err(StoreError::Conflict) => {
            return Err(proof_failed(c, req, ev, "ssh_challenge_replayed").await);
        }
        Err(_) => return Err(internal(ev, "control_store_failed")),
    }
    let added_via = match &user.auth {
        AuthMethod::Github => "github".to_owned(),
        AuthMethod::Ssh { fingerprint } => format!("ssh:{fingerprint}"),
    };
    let row = Seal(&user.control_root)
        .ssh_key(user.github_id, &key, label, &added_via, c.now_ms)
        .await?;
    attempt(c, ev).await?;
    match c.store.insert_ssh_key(&row, MAX_SSH_KEYS_PER_USER).await {
        Ok(()) => {
            let mut reply = Reply::data(key_json(&row));
            reply.status = 201;
            Ok(reply)
        }
        Err(StoreError::Conflict) => {
            Err(coded(409, "ssh key already registered", "ssh_key_in_use"))
        }
        Err(StoreError::CapReached) => Err(coded(
            409,
            &format!("an account holds at most {MAX_SSH_KEYS_PER_USER} ssh keys"),
            "ssh_key_limit",
        )),
        Err(_) => Err(internal(ev, "control_store_failed")),
    }
}

/// `DELETE /v1/me/ssh-keys/:id`: `204`, or `404 ssh key not found` when the caller holds no
/// key with that id (whether or not anyone else does). A row that doesn't verify can be
/// removed.
pub async fn remove<S: TenantStore, A: AuditSink, L>(
    c: &Control<'_, S, A, L>,
    ev: &mut AuditEvent,
    user: &User,
    id: &str,
) -> Result<Reply, Reply> {
    let fingerprint =
        ssh::fingerprint_from_id(id).ok_or_else(|| Reply::error(400, "invalid ssh key id"))?;
    ev.target_ssh_fingerprint = Some(fingerprint.clone());
    attempt(c, ev).await?;
    match c.store.delete_ssh_key(user.github_id, &fingerprint).await {
        Ok(()) => Ok(Reply::no_content()),
        Err(StoreError::NotFound) => Err(Reply::error(404, "ssh key not found")),
        Err(_) => Err(internal(ev, "control_store_failed")),
    }
}

/// `DELETE /v1/ops/users/:github_id/ssh-keys` (operators): removes every key of the user and
/// ends every control token they hold, in one transaction. `{"removed": n}`, or `404 user not
/// found`.
pub async fn revoke<S: TenantStore, A: AuditSink, L>(
    c: &Control<'_, S, A, L>,
    ev: &mut AuditEvent,
    user: &User,
    id: &str,
) -> Result<Reply, Reply> {
    operator(c, ev, user)?;
    let target = super::tenants::github_id(id)?;
    ev.target_github_id = Some(target);
    attempt(c, ev).await?;
    match c.store.revoke_user_ssh_keys(target, c.now_ms).await {
        Ok(removed) => {
            ev.ssh_keys_removed = Some(removed);
            Ok(Reply::data(json!({ "removed": removed })))
        }
        Err(StoreError::NotFound) => Err(Reply::error(404, "user not found")),
        Err(_) => Err(internal(ev, "control_store_failed")),
    }
}
