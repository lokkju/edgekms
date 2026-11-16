//! `POST /v1/login/github`: a GitHub user token from the hosted App's device flow for a
//! control token, and on a user's first login their personal tenant.
//!
//! `SIGNUP_MODE` gates it (the signup gate). After the GitHub token is checked and revoked, and before
//! anything is written, the user must be one the mode admits: anyone in `open` mode, an
//! operator, a user on the signup allowlist whose row verifies in `invite` mode, or, in every
//! mode, an existing user (one holding at least one membership that verifies) or an invitee
//! (one holding a pending invite that verifies, to an active tenant). Anyone else gets
//! `403 signups are closed` with `"code": "signup_closed"`, counted against `AUTH_FAIL_LIMIT`
//! like any refused login. In `invite` mode, once the control root exists, the refusal also
//! carries a request token (`request_token`, good for `request_expires_in` seconds; see
//! `super::auth`) with which the refused user can file one invite request (lokkju/edgekms#12). Only a user the mode admits gets a personal tenant: an existing user
//! or invitee admitted by their memberships or invites alone (say, a member of someone else's
//! tenant while signups are closed) gets a control token and nothing more. An owner's invite
//! therefore lets someone sign in to take a seat in that tenant, never to get a tenant of
//! their own.
//!
//! The GitHub token is checked and then revoked exactly as the `github-user` mount does
//! (`crate::github`), so a token that reached the control plane can't be relayed to a tenant
//! or anywhere else afterwards.
//!
//! Every failed login counts against the client IP's `AUTH_FAIL_LIMIT`, as on the data plane,
//! so one IP can't spend the shared App's GitHub API quota on garbage tokens. The Workers rate
//! limiter can't be read without counting, so the check follows the failure: an IP over the
//! limit gets `429` in place of the refusal, and still costs one GitHub call per attempt
//! within `CONTROL_LIMIT`.

use edgekms_core::tenant::{RESERVED, TenantName};
use edgekms_core::transit::Id;
use serde_json::{Value, json};

use super::auth::{self, AuthMethod, CONTROL_TTL_SECS, REQUEST_TTL_SECS};
use super::members::Seal;
use super::tenants::{InsertError, Root, insert};
use super::{Control, SignupMode, attempt, coded, hex, internal, random_id};
use crate::audit::{AuditEvent, AuditSink, RateLimit};
use crate::github::{GithubError, GithubUser, plausible_token};
use crate::handlers::{ApiRequest, json_body};
use crate::store::{MemberRole, StoreError, TenantStatus, TenantStore};
use crate::vault::{Reply, log_internal};
use edgekms_core::hosted::default_config;

/// How many suffixed names a personal tenant tries after the plain login.
const NAME_ATTEMPTS: usize = 3;
/// The longest stem a suffixed name keeps: 32 characters less `-` and 4 hex digits.
const STEM_LEN: usize = 27;

/// The signup refusal's message; the CLI matches the code, `signup_closed`.
pub const SIGNUPS_CLOSED: &str = "signups are closed";

/// A refused login: the uniform `400 permission denied`, counted against `AUTH_FAIL_LIMIT`.
pub(super) async fn denied<S, A, L: RateLimit>(
    c: &Control<'_, S, A, L>,
    req: &ApiRequest,
    ev: &mut AuditEvent,
    label: &'static str,
) -> Reply {
    auth::failed(c, req, ev, label, Reply::error(400, "permission denied")).await
}

/// `POST /v1/login/github` with `{"token": "<GitHub user token>"}`.
pub async fn login<S: TenantStore, A: AuditSink, L: RateLimit>(
    c: &Control<'_, S, A, L>,
    req: &ApiRequest,
    ev: &mut AuditEvent,
) -> Reply {
    match run(c, req, ev).await {
        Ok(r) | Err(r) => r,
    }
}

async fn run<S: TenantStore, A: AuditSink, L: RateLimit>(
    c: &Control<'_, S, A, L>,
    req: &ApiRequest,
    ev: &mut AuditEvent,
) -> Result<Reply, Reply> {
    let body = match json_body(&req.body) {
        Ok(b) => b,
        Err(reply) => return Err(auth::failed(c, req, ev, "bad_request", reply).await),
    };
    let Some(token) = body.get("token").and_then(Value::as_str) else {
        return Err(denied(c, req, ev, "github_malformed_token").await);
    };
    if !plausible_token(token) {
        return Err(denied(c, req, ev, "github_malformed_token").await);
    }
    let client_id = c.settings.github_client_id.as_str();
    let user = match c.github.check_token(client_id, token).await {
        Ok(u) => u,
        Err(GithubError::Denied(label)) => return Err(denied(c, req, ev, label).await),
        Err(GithubError::Unavailable(label)) => return Err(internal(ev, label)),
    };
    // Burn it: single use here, and useless to anyone it is relayed to afterwards. A failure
    // is logged, not fatal, as on the `github-user` mount.
    if let Err(label) = c.github.revoke_token(client_id, token).await {
        log_internal(label);
    }
    drop(body);
    ev.github_id = Some(user.id);
    let admitted = admit(c, req, ev, &user).await?;
    // The login changes state (the user row, perhaps the control root and a personal tenant).
    attempt(c, ev).await?;
    c.store
        .upsert_user(user.id, &user.login, c.now_ms)
        .await
        .map_err(|_| internal(ev, "control_store_failed"))?;
    let ops = auth::root(c, ev).await?;
    let created = match admitted {
        Admit::Signup => personal_tenant(c, ev, &Seal(&ops), &user).await?,
        Admit::Existing => None,
    };
    let method = AuthMethod::Github;
    ev.auth_method = Some(method.label());
    let ssh_keys = super::ssh::key_count(c, ev, &Seal(&ops), user.id).await?;
    let token = auth::mint(&ops, user.id, &user.login, &method, c.now_ms).await?;
    let mut data = json!({
        "token": token.as_str(),
        "expires_in": CONTROL_TTL_SECS,
        "github_id": user.id,
        "login": user.login,
        "auth": method.label(),
        "ssh_keys": ssh_keys,
    });
    if let Some(name) = created {
        data["created_tenant"] = json!(name);
    }
    Ok(Reply::data(data))
}

/// Why [`admit`] let a user in.
enum Admit {
    /// The signup mode admits them: they get a personal tenant if they have never created one.
    Signup,
    /// Only their existing memberships or pending invites admit them.
    Existing,
}

/// Whether `SIGNUP_MODE` lets `user` log in, or the refusal. Writes nothing.
async fn admit<S: TenantStore, A, L: RateLimit>(
    c: &Control<'_, S, A, L>,
    req: &ApiRequest,
    ev: &mut AuditEvent,
    user: &GithubUser,
) -> Result<Admit, Reply> {
    if c.settings.signup == SignupMode::Open || c.settings.is_operator(user.id) {
        return Ok(Admit::Signup);
    }
    // Every allowlist and membership row is checked under the control root. With no root yet
    // nothing can verify (and nothing has been created), so no one is allowlisted or existing;
    // the root isn't created for a login that is going to be refused.
    let root = auth::existing_root(c, ev).await?;
    if let Some(root) = &root {
        let seal = Seal(root);
        if c.settings.signup == SignupMode::Invite && allowlisted(c, ev, &seal, user.id).await? {
            return Ok(Admit::Signup);
        }
        if existing(c, ev, &seal, user.id).await? || invited(c, ev, &seal, user.id).await? {
            return Ok(Admit::Existing);
        }
    }
    let mut refusal = coded(403, SIGNUPS_CLOSED, "signup_closed");
    // In invite mode the refused user may ask for an invite: the refusal carries the proof
    // GitHub just gave, as a short-lived request token. Its values are already in memory and
    // the GitHub token is already revoked. Never in closed mode, and never without a root,
    // which isn't created for a refused login.
    if c.settings.signup == SignupMode::Invite
        && let Some(root) = &root
        && auth::plausible_login(&user.login)
    {
        match auth::mint_request(root, user.id, &user.login, c.now_ms).await {
            Ok((token, jti)) => {
                if let Some(Value::Object(body)) = refusal.body.as_mut() {
                    body.insert("request_token".to_owned(), json!(token.as_str()));
                    body.insert("request_expires_in".to_owned(), json!(REQUEST_TTL_SECS));
                }
                // Links a later `invite_request_create` event to this sign-in.
                ev.jti = Some(jti);
            }
            // Refused all the same, without the means to ask.
            Err(_) => log_internal("control: request token mint failed"),
        }
    }
    let reply = auth::failed(c, req, ev, "signup_closed", refusal).await;
    if reply.status == 429 {
        // The refusal and its token were dropped; no token was issued.
        ev.jti = None;
    }
    Err(reply)
}

/// Whether `github_id` holds a signup allowlist row that verifies under `seal`.
pub(super) async fn allowlisted<S: TenantStore, A, L>(
    c: &Control<'_, S, A, L>,
    ev: &mut AuditEvent,
    seal: &Seal<'_>,
    github_id: u64,
) -> Result<bool, Reply> {
    let row = c
        .store
        .allowed_signup(github_id)
        .await
        .map_err(|_| internal(ev, "control_store_failed"))?
        .filter(|r| r.github_id == github_id);
    match row {
        Some(row) => seal.allow_ok(&row).await,
        None => Ok(false),
    }
}

/// Whether `github_id` is an existing user: holds a membership that verifies under `seal`, in
/// an active tenant, or as an owner of a suspended one. A suspended tenant's members don't
/// count, but its owners do, so they can still log in and export (the way out suspension
/// leaves open).
pub(super) async fn existing<S: TenantStore, A, L>(
    c: &Control<'_, S, A, L>,
    ev: &mut AuditEvent,
    seal: &Seal<'_>,
    github_id: u64,
) -> Result<bool, Reply> {
    let store_failed = |ev: &mut AuditEvent| internal(ev, "control_store_failed");
    let memberships = c
        .store
        .tenants_for_user(github_id)
        .await
        .map_err(|_| store_failed(ev))?;
    for m in memberships {
        if m.row.github_id != github_id || !seal.member_ok(&m.tenant_id, &m.row).await? {
            continue;
        }
        if m.row.role == MemberRole::Owner {
            return Ok(true);
        }
        let version = c
            .store
            .tenant_version(&m.name)
            .await
            .map_err(|_| store_failed(ev))?;
        if version.is_some_and(|v| v.id == m.tenant_id && v.status == TenantStatus::Active) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether `github_id` holds a pending invite that verifies under `seal` to an active tenant
/// (invitees may always sign in), so they can accept or decline it. A suspended tenant's invites don't
/// count: accepting one would make them only a member of a suspended tenant, which
/// [`existing`] wouldn't admit either.
pub(super) async fn invited<S: TenantStore, A, L>(
    c: &Control<'_, S, A, L>,
    ev: &mut AuditEvent,
    seal: &Seal<'_>,
    github_id: u64,
) -> Result<bool, Reply> {
    let store_failed = |ev: &mut AuditEvent| internal(ev, "control_store_failed");
    let invites = c
        .store
        .invites_for_user(github_id)
        .await
        .map_err(|_| store_failed(ev))?;
    for i in invites {
        if i.row.github_id != github_id || !seal.invite_ok(&i.tenant_id, &i.row).await? {
            continue;
        }
        let version = c
            .store
            .tenant_version(&i.name)
            .await
            .map_err(|_| store_failed(ev))?;
        if version.is_some_and(|v| v.id == i.tenant_id && v.status == TenantStatus::Active) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The base of a suffixed personal tenant name: the login lowercased, anything outside
/// `[a-z0-9]` as `-`, no `--` and no leading or trailing `-`, `u-` in front of a login that
/// starts with `edgekms` or is a reserved name (`support`, `admin`, ...), at most [`STEM_LEN`]
/// characters; `user` if nothing is left.
pub(super) fn stem(login: &str) -> String {
    let mut s: String = login
        .chars()
        .map(|ch| {
            let ch = ch.to_ascii_lowercase();
            if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
                ch
            } else {
                '-'
            }
        })
        .collect();
    while s.contains("--") {
        s = s.replace("--", "-");
    }
    let mut s = s.trim_matches('-').to_owned();
    if s.starts_with("edgekms") || RESERVED.contains(&s.as_str()) {
        s.insert_str(0, "u-");
    }
    s.truncate(STEM_LEN);
    let s = s.trim_end_matches('-');
    if s.is_empty() {
        "user".to_owned()
    } else {
        s.to_owned()
    }
}

/// `<stem>-<4 random hex digits>`.
fn suffixed(login: &str) -> Result<String, Reply> {
    let mut b = [0u8; 2];
    getrandom::fill(&mut b).map_err(|_| Reply::internal())?;
    Ok(format!("{}-{}", stem(login), hex(&b)))
}

/// Creates the user's personal tenant if they have never created a tenant: the login
/// lowercased if it's a valid, free name, else `<login>-<4 hex>`, tried up to three times.
/// Returns the name, or `None` when nothing was created.
///
/// The claim is atomic: the insert is conditional on the user having created no tenant
/// (`create_tenant_capped` with a cap of 1), so concurrent first logins create one tenant.
/// Tenants the user was invited into don't count.
async fn personal_tenant<S: TenantStore, A, L>(
    c: &Control<'_, S, A, L>,
    ev: &mut AuditEvent,
    seal: &Seal<'_>,
    user: &GithubUser,
) -> Result<Option<String>, Reply> {
    let store_failed = |ev: &mut AuditEvent| internal(ev, "control_store_failed");
    // A cheap read to skip the root and MAC work on every later login; the insert decides.
    match c.store.count_created(user.id).await {
        Ok(0) => {}
        Ok(_) => return Ok(None),
        Err(_) => return Err(store_failed(ev)),
    }
    let mut candidates = Vec::with_capacity(NAME_ATTEMPTS + 1);
    candidates.push(user.login.to_ascii_lowercase());
    for _ in 0..NAME_ATTEMPTS {
        candidates.push(suffixed(&user.login)?);
    }
    for candidate in candidates {
        let Ok(name) = TenantName::new(&candidate) else {
            continue;
        };
        let id = random_id("t_")?;
        let root_id = Id::new(&random_id("r_")?).map_err(|_| Reply::internal())?;
        let key_id = Id::new(&random_id("k_")?).map_err(|_| Reply::internal())?;
        let config = default_config(&root_id, &key_id, user.id, &c.settings.github_client_id);
        let made = insert(
            c,
            seal,
            &id,
            &name,
            &root_id,
            config,
            Root::New,
            user.id,
            Some(1),
        );
        match made.await {
            Ok(_) => {
                ev.tenant = Some(id);
                return Ok(Some(candidate));
            }
            // A concurrent first login claimed it.
            Err(InsertError::Store(StoreError::CapReached)) => return Ok(None),
            Err(InsertError::Store(StoreError::NameTaken)) => {}
            Err(InsertError::Store(_)) => return Err(store_failed(ev)),
            Err(InsertError::Internal) => return Err(internal(ev, "tenant_create_failed")),
        }
    }
    // Logged in all the same; the next login tries again.
    log_internal("personal_tenant_names_taken");
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stems_make_valid_suffixed_names() {
        for login in [
            "Octocat",
            "ab",
            "a",
            "admin",
            "edgekms",
            "edgekms-fan",
            "a-very-long-github-login-name-of-39-chr",
            "x-",
            "---",
            "Some_Bot[bot]",
        ] {
            let name = format!("{}-abcd", stem(login));
            assert!(TenantName::new(&name).is_ok(), "{login}: {name}");
        }
        assert_eq!(stem("Octocat"), "octocat");
        assert_eq!(stem("edgekms-fan"), "u-edgekms-fan");
        // A reserved name is folded the same way, so `support` can't name `support-billing`.
        assert_eq!(stem("admin"), "u-admin");
        assert_eq!(stem("Support"), "u-support");
        assert_eq!(stem("Security_"), "u-security");
        assert_eq!(stem("admins"), "admins");
        assert_eq!(stem("---"), "user");
    }
}
