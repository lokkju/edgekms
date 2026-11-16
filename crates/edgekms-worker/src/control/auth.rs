//! Control tokens: ordinary `ekms.` tokens (`edgekms_core::token`) with MACs under the control
//! plane's own root, the `system_keys` row `control`, wrapped by the master key like a
//! tenant's root with the AAD id `_system/control`. Since that root differs from every
//! tenant's, a control token is useless at a tenant and a tenant token is useless here.
//!
//! The root is created on the first login and its handle kept per isolate.
//!
//! A control token also stops working once its user logs out: `POST /v1/logout` raises
//! `users.tokens_after_ms`, and every request refuses a token issued (`iat_ms`, in the token's
//! `meta`) at or before it.
//!
//! A request token (lokkju/edgekms#12) is the same kind of token under the same root with the
//! role [`REQUEST_ROLE`]: the `signup_closed` refusal of a login in `invite` mode carries one,
//! good for [`REQUEST_TTL_SECS`], and it proves only that GitHub vouched for its user moments
//! ago. [`authenticate`] refuses it, as every control route does, and [`requester`] refuses
//! anything else, so it reads and files its own user's invite request and nothing more. It
//! can't be cut off by a logout (its user has no `users` row); its short life bounds it.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use edgekms_core::token::{self, TokenClaims};
use edgekms_core::transit::Id;
use zeroize::Zeroizing;

use super::members::Seal;
use super::{Control, attempt, coded, deny, internal, random_id};
use crate::audit::{AuditEvent, AuditSink, Limit, RateLimit};
use crate::auth::{Logged, MAX_TOKEN_LEN};
use crate::handlers::ApiRequest;
use crate::store::{SystemKeyRow, TenantStore};
use crate::vault::{Reply, log_internal};
use crate::webcrypto::WebCryptoKeyOps;

/// The `system_keys` row of the control plane's token root.
pub const CONTROL_KEY: &str = "control";
/// The tenant id the control root's wrap is bound to (`wrap_aad`); no tenant id can be it,
/// since tenant ids are `t_<hex>`.
pub const CONTROL_AAD_ID: &str = "_system/control";
/// Every control token's role.
pub const CONTROL_ROLE: &str = "control";
/// Control token lifetime.
pub const CONTROL_TTL_SECS: u64 = 1800;
/// How recent a login export needs, in seconds.
pub const FRESH_LOGIN_SECS: u64 = 300;
/// Every request token's role.
pub const REQUEST_ROLE: &str = "invite_request";
/// Request token lifetime.
pub const REQUEST_TTL_SECS: u64 = 900;

/// How a control token was obtained: its `auth` claim, and for SSH its `ssh_fingerprint`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMethod {
    /// `POST /v1/login/github` (or a token from before the claim existed).
    Github,
    /// `POST /v1/login/ssh` with the key `fingerprint` (`SHA256:...`). The token works only
    /// while that key's row exists, verifies and belongs to the token's user.
    Ssh { fingerprint: String },
}

impl AuthMethod {
    /// The `auth` claim and the audit `auth_method`.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Github => "github",
            Self::Ssh { .. } => "ssh",
        }
    }

    /// The SSH key's fingerprint, for an SSH login.
    #[must_use]
    pub fn fingerprint(&self) -> Option<&str> {
        match self {
            Self::Github => None,
            Self::Ssh { fingerprint } => Some(fingerprint),
        }
    }
}

/// An authenticated control-plane user.
#[derive(Clone)]
pub struct User {
    pub github_id: u64,
    /// The GitHub login when the token was issued. Display only: logins can be renamed.
    pub login: String,
    /// When the control token was issued (Unix seconds), for the export and key registration
    /// freshness check. An SSH login counts exactly as a GitHub one.
    pub iat: u64,
    /// How the token was obtained.
    pub auth: AuthMethod,
    /// The control root the token verified under, which also MACs membership and invite rows
    /// (`super::members`).
    pub control_root: Rc<WebCryptoKeyOps>,
}

impl User {
    /// Whether the login behind this token is under [`FRESH_LOGIN_SECS`] old at `now`.
    pub fn fresh(&self, now: u64) -> bool {
        now.saturating_sub(self.iat) < FRESH_LOGIN_SECS
    }
}

thread_local! {
    /// The control root's handle, by the `(root_id, wrap_key)` it was opened from. A rewrap
    /// changes the wrap key, so the next request opens the rewrapped row (the root itself is
    /// the same).
    static ROOT: RefCell<Option<(String, String, Rc<WebCryptoKeyOps>)>> = const { RefCell::new(None) };
}

fn cached(row: &SystemKeyRow) -> Option<Rc<WebCryptoKeyOps>> {
    ROOT.with(|r| {
        r.borrow()
            .as_ref()
            .filter(|(id, wk, _)| *id == row.root_id && *wk == row.wrap_key)
            .map(|(_, _, ops)| ops.clone())
    })
}

fn remember(row: &SystemKeyRow, ops: Rc<WebCryptoKeyOps>) -> Rc<WebCryptoKeyOps> {
    ROOT.with(|r| {
        *r.borrow_mut() = Some((row.root_id.clone(), row.wrap_key.clone(), ops.clone()));
    });
    ops
}

/// Opens a stored control root.
async fn open<S, A, L>(
    c: &Control<'_, S, A, L>,
    row: &SystemKeyRow,
    ev: &mut AuditEvent,
) -> Result<Rc<WebCryptoKeyOps>, Reply> {
    if let Some(ops) = cached(row) {
        return Ok(ops);
    }
    let root_id = Id::new(&row.root_id).map_err(|_| internal(ev, "control_root_id_invalid"))?;
    let unwrap = c.masters.unwrap().await?;
    let handle = unwrap
        .unwrap_root(&row.wrap_key, &row.wrapped_root, CONTROL_AAD_ID, &root_id)
        .await
        .map_err(|_| internal(ev, "control_root_unwrap_failed"))?;
    let ops =
        WebCryptoKeyOps::from_hkdf_key(handle, root_id).map_err(|_| internal(ev, "webcrypto"))?;
    Ok(remember(row, Rc::new(ops)))
}

/// The control root's handle, or `None` if there is none yet (no one has ever logged in).
pub(super) async fn existing_root<S: TenantStore, A, L>(
    c: &Control<'_, S, A, L>,
    ev: &mut AuditEvent,
) -> Result<Option<Rc<WebCryptoKeyOps>>, Reply> {
    let row = c
        .store
        .system_key(CONTROL_KEY)
        .await
        .map_err(|_| internal(ev, "control_store_failed"))?;
    match row {
        Some(row) => open(c, &row, ev).await.map(Some),
        None => Ok(None),
    }
}

/// The control root's handle, creating the root if there is none and the store holds no tenant
/// or membership yet (`500`, logged as `control_root_missing`, if it does). Two isolates racing
/// to create it agree on whichever row the store kept.
pub async fn root<S: TenantStore, A, L>(
    c: &Control<'_, S, A, L>,
    ev: &mut AuditEvent,
) -> Result<Rc<WebCryptoKeyOps>, Reply> {
    if let Some(ops) = existing_root(c, ev).await? {
        return Ok(ops);
    }
    // Every membership and invite MAC is keyed from this root. With tenants in the store, a
    // missing row means the root was lost (deleted, or a partial restore), and a new one would
    // orphan every tenant, then break the ones sealed under it once the old row is restored.
    // Refuse, so an operator restores the row.
    let holds = c
        .store
        .holds_tenants()
        .await
        .map_err(|_| internal(ev, "control_store_failed"))?;
    if holds {
        return Err(internal(ev, "control_root_missing"));
    }
    let admin = c.masters.admin().await?;
    let root_id = Id::new(&random_id("r_")?).map_err(|_| Reply::internal())?;
    let (handle, wrapped) = admin
        .new_root(CONTROL_AAD_ID, &root_id)
        .await
        .map_err(|_| internal(ev, "control_root_create_failed"))?;
    let mine = SystemKeyRow {
        name: CONTROL_KEY.to_owned(),
        root_id: root_id.as_str().to_owned(),
        wrapped_root: wrapped,
        wrap_key: admin.current().to_owned(),
        created_ms: c.now_ms,
    };
    let stored = c
        .store
        .insert_system_key_if_absent(&mine)
        .await
        .map_err(|_| internal(ev, "control_store_failed"))?;
    if stored == mine {
        let ops = WebCryptoKeyOps::from_hkdf_key(handle, root_id)
            .map_err(|_| internal(ev, "webcrypto"))?;
        Ok(remember(&stored, Rc::new(ops)))
    } else {
        open(c, &stored, ev).await
    }
}

/// Mints a control token for GitHub user `github_id`, logged in by `auth`, at `now_ms` (Unix
/// milliseconds).
pub async fn mint(
    ops: &WebCryptoKeyOps,
    github_id: u64,
    login: &str,
    auth: &AuthMethod,
    now_ms: u64,
) -> Result<Zeroizing<String>, Reply> {
    let now = now_ms / 1000;
    let ops = Logged(ops);
    let mut meta = BTreeMap::from([
        ("auth".to_owned(), auth.label().to_owned()),
        ("github_id".to_owned(), github_id.to_string()),
        // Milliseconds, so a logout refuses every token issued before it, however soon.
        ("iat_ms".to_owned(), now_ms.to_string()),
        ("login".to_owned(), login.to_owned()),
    ]);
    if let Some(fp) = auth.fingerprint() {
        meta.insert("ssh_fingerprint".to_owned(), fp.to_owned());
    }
    let claims = TokenClaims {
        v: 1,
        jti: token::new_jti(&ops),
        role: CONTROL_ROLE.to_owned(),
        policies: Vec::new(),
        iat: now,
        exp: now.saturating_add(CONTROL_TTL_SECS),
        long: false,
        meta,
    };
    token::mint(&ops, &claims)
        .await
        .map(Zeroizing::new)
        .map_err(|_| Reply::internal())
}

/// Whether `login` looks like a GitHub login. A request token is issued, and accepted, only for
/// one, so the login it carries is safe to put on an operator's terminal or page.
pub use edgekms_core::hosted::plausible_login;

/// Mints a request token for GitHub user `github_id` named `login` at `now_ms` (Unix
/// milliseconds); returns it and its jti.
pub async fn mint_request(
    ops: &WebCryptoKeyOps,
    github_id: u64,
    login: &str,
    now_ms: u64,
) -> Result<(Zeroizing<String>, String), Reply> {
    let now = now_ms / 1000;
    let ops = Logged(ops);
    let jti = token::new_jti(&ops);
    let claims = TokenClaims {
        v: 1,
        jti: jti.clone(),
        role: REQUEST_ROLE.to_owned(),
        policies: Vec::new(),
        iat: now,
        exp: now.saturating_add(REQUEST_TTL_SECS),
        long: false,
        meta: BTreeMap::from([
            ("github_id".to_owned(), github_id.to_string()),
            ("iat_ms".to_owned(), now_ms.to_string()),
            ("login".to_owned(), login.to_owned()),
        ]),
    };
    let token = token::mint(&ops, &claims)
        .await
        .map(Zeroizing::new)
        .map_err(|_| Reply::internal())?;
    Ok((token, jti))
}

/// A user holding a request token: refused at login, vouched for by GitHub.
pub struct Requester {
    pub github_id: u64,
    /// The GitHub login when the token was issued.
    pub login: String,
    /// The control root the token verified under, which also MACs invite request rows.
    pub control_root: Rc<WebCryptoKeyOps>,
}

/// The bearer token from `Authorization`.
fn bearer(req: &ApiRequest) -> Option<&str> {
    let auth = req.authorization.as_deref()?.trim_start();
    let (scheme, rest) = auth.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then_some(rest.trim())
}

/// Counts a failed login or token check against the client IP's `AUTH_FAIL_LIMIT`, as the
/// data plane does, and records `label`. The refusal is `refusal`, or `429` once the IP has
/// failed too often. A request without a client IP never gets this far (`handle` refuses it).
pub async fn failed<S, A, L: RateLimit>(
    c: &Control<'_, S, A, L>,
    req: &ApiRequest,
    ev: &mut AuditEvent,
    label: &'static str,
    refusal: Reply,
) -> Reply {
    deny(ev, label);
    let allowed = match req.limit_key.as_deref() {
        Some(key) => c.limits.allow(Limit::AuthFailure, key).await,
        None => true,
    };
    if allowed {
        refusal
    } else {
        Reply::error(429, "rate limit quota exceeded")
    }
}

/// The refusal for a control token that doesn't authenticate: the uniform `403 permission
/// denied` (the CLI matches the message), coded `auth_failed` so a client can tell "sign in
/// again" from an authorization refusal, which stays uncoded. The code tells a token holder
/// only that the token no longer works, which the next call would tell them anyway.
fn auth_failed() -> Reply {
    coded(403, "permission denied", "auth_failed")
}

/// Checks the request's control token: its MAC under the control root, its expiry, that it is
/// a control token (role, no policies, a GitHub id), and that its user hasn't logged out since
/// it was issued. Every failure is [`auth_failed`] and counts against `AUTH_FAIL_LIMIT`.
pub async fn authenticate<S: TenantStore, A: AuditSink, L: RateLimit>(
    c: &Control<'_, S, A, L>,
    req: &ApiRequest,
    ev: &mut AuditEvent,
) -> Result<User, Reply> {
    let Some(presented) = bearer(req) else {
        return Err(failed(c, req, ev, "missing_token", auth_failed()).await);
    };
    if presented.is_empty() || presented.len() > MAX_TOKEN_LEN {
        return Err(failed(c, req, ev, "invalid_token", auth_failed()).await);
    }
    let Some(ops) = existing_root(c, ev).await? else {
        return Err(failed(c, req, ev, "invalid_token", auth_failed()).await);
    };
    let Ok(claims) = token::check(&Logged(&*ops), presented, c.now()).await else {
        return Err(failed(c, req, ev, "invalid_token", auth_failed()).await);
    };
    // A request token is a real token under this root, just not a control token: refused like
    // any other, without logging it as a malformed one.
    if claims.role == REQUEST_ROLE {
        return Err(failed(c, req, ev, "invalid_token", auth_failed()).await);
    }
    let meta_u64 = |k: &str| claims.meta.get(k).and_then(|v| v.parse::<u64>().ok());
    let shape = (meta_u64("github_id"), meta_u64("iat_ms"));
    let (Some(github_id), Some(iat_ms)) = shape else {
        log_internal("control token with a valid MAC but the wrong shape");
        return Err(failed(c, req, ev, "invalid_token", auth_failed()).await);
    };
    if claims.role != CONTROL_ROLE || !claims.policies.is_empty() || claims.long {
        log_internal("control token with a valid MAC but the wrong shape");
        return Err(failed(c, req, ev, "invalid_token", auth_failed()).await);
    }
    // A token without `auth` predates the claim and came from a GitHub login.
    let auth = match claims.meta.get("auth").map(String::as_str) {
        None | Some("github") => AuthMethod::Github,
        Some("ssh") => match claims.meta.get("ssh_fingerprint") {
            Some(fp) if fp.starts_with("SHA256:") => AuthMethod::Ssh {
                fingerprint: fp.clone(),
            },
            _ => {
                log_internal("control token with a valid MAC but the wrong shape");
                return Err(failed(c, req, ev, "invalid_token", auth_failed()).await);
            }
        },
        Some(_) => {
            log_internal("control token with a valid MAC but the wrong shape");
            return Err(failed(c, req, ev, "invalid_token", auth_failed()).await);
        }
    };
    ev.jti = Some(claims.jti.clone());
    ev.github_id = Some(github_id);
    ev.auth_method = Some(auth.label());
    ev.auth_ssh_fingerprint = auth.fingerprint().map(str::to_owned);
    // The logout cutoff and, for an SSH token, its key, in one read.
    let state = c
        .store
        .token_state(github_id, auth.fingerprint())
        .await
        .map_err(|_| internal(ev, "control_store_failed"))?;
    // No user row: nothing to check a logout against, so nothing to trust.
    let Some((_, key)) = state.filter(|(after, _)| iat_ms > *after) else {
        return Err(failed(c, req, ev, "token_logged_out", auth_failed()).await);
    };
    // An SSH token lives only while its key does: removed, moved to another user, or written
    // without the master, the key ends the token on this request.
    if let AuthMethod::Ssh { fingerprint } = &auth {
        let live = match key {
            // A key re-added after a removal starts a new row (`added_ms` is under the MAC), so
            // tokens the old row minted stay dead.
            Some(row)
                if row.github_id == github_id
                    && row.fingerprint == *fingerprint
                    && row.added_ms <= iat_ms =>
            {
                Seal(&ops).ssh_key_ok(&row).await?
            }
            _ => false,
        };
        if !live {
            return Err(failed(c, req, ev, "ssh_key_revoked", auth_failed()).await);
        }
    }
    Ok(User {
        github_id,
        login: claims.meta.get("login").cloned().unwrap_or_default(),
        iat: claims.iat,
        auth,
        control_root: ops,
    })
}

/// Checks the request's request token: its MAC under the control root, its expiry, that it is
/// a request token (role [`REQUEST_ROLE`], no policies, not long, a life of at most
/// [`REQUEST_TTL_SECS`]) and that it names a GitHub id and a plausible login. Every failure is
/// [`auth_failed`] and counts against `AUTH_FAIL_LIMIT`, as for a control token.
pub async fn requester<S: TenantStore, A: AuditSink, L: RateLimit>(
    c: &Control<'_, S, A, L>,
    req: &ApiRequest,
    ev: &mut AuditEvent,
) -> Result<Requester, Reply> {
    let Some(presented) = bearer(req) else {
        return Err(failed(c, req, ev, "missing_token", auth_failed()).await);
    };
    if presented.is_empty() || presented.len() > MAX_TOKEN_LEN {
        return Err(failed(c, req, ev, "invalid_token", auth_failed()).await);
    }
    let Some(ops) = existing_root(c, ev).await? else {
        return Err(failed(c, req, ev, "invalid_token", auth_failed()).await);
    };
    let Ok(claims) = token::check(&Logged(&*ops), presented, c.now()).await else {
        return Err(failed(c, req, ev, "invalid_token", auth_failed()).await);
    };
    if claims.role != REQUEST_ROLE {
        return Err(failed(c, req, ev, "invalid_token", auth_failed()).await);
    }
    let github_id = claims
        .meta
        .get("github_id")
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|id| *id > 0);
    let login = claims.meta.get("login").filter(|l| plausible_login(l));
    let lifetime_ok = claims.exp.saturating_sub(claims.iat) <= REQUEST_TTL_SECS;
    let (Some(github_id), Some(login)) = (github_id, login) else {
        log_internal("request token with a valid MAC but the wrong shape");
        return Err(failed(c, req, ev, "invalid_token", auth_failed()).await);
    };
    if !claims.policies.is_empty() || claims.long || !lifetime_ok {
        log_internal("request token with a valid MAC but the wrong shape");
        return Err(failed(c, req, ev, "invalid_token", auth_failed()).await);
    }
    // The jti links the request's events to the refused login that issued the token.
    ev.jti = Some(claims.jti.clone());
    ev.github_id = Some(github_id);
    Ok(Requester {
        github_id,
        login: login.clone(),
        control_root: ops,
    })
}

/// `POST /v1/logout`: every control token the caller holds, this one included, stops working.
/// `204`.
pub async fn logout<S: TenantStore, A: AuditSink, L>(
    c: &Control<'_, S, A, L>,
    ev: &mut AuditEvent,
    user: &User,
) -> Result<Reply, Reply> {
    attempt(c, ev).await?;
    c.store
        .set_tokens_after(user.github_id, c.now_ms)
        .await
        .map_err(|_| internal(ev, "control_store_failed"))?;
    Ok(Reply::no_content())
}
