//! Tenants, their configs and members: `GET /v1/me`, `POST /v1/tenants`,
//! `GET /v1/tenants/:name`, `PUT /v1/tenants/:name/config`,
//! `PUT`/`DELETE /v1/tenants/:name/members/:github_id` and
//! `POST /v1/tenants/:name/{accept,decline}`.
//!
//! Granting a role is an invite: `PUT .../members/:github_id` with a role the user doesn't
//! already hold records a pending invite, and nothing changes until the invitee accepts it.
//! Only lowering an owner to member applies at once (it needs no consent, and the last-owner
//! rule still holds).
//!
//! Every config write, including a tenant's first, MACs the config under the tenant's own root
//! with `config_mac_input(id, name, version, config)`: the version written and the row's
//! current name. Anything that ever changes `tenants.name` (there is no rename route) must
//! write a fresh MAC over the current config under the new name and the next version in the
//! same `UPDATE`, or the tenant stops loading at its next revalidation.
//!
//! Every membership and invite row carries a MAC under the control root, verified on every read
//! (`super::members`): authorization, listings, the last-owner rule and accepting all see only
//! rows that verify.

use edgekms_core::config::Config;
use edgekms_core::hosted::{
    HostedRules, MAX_CONFIG_BYTES, config_mac_input, default_config, validate_hosted,
};
use edgekms_core::keyops::{KeyOps, MacPurpose};
use edgekms_core::tenant::TenantName;
use edgekms_core::transit::Id;
use serde_json::{Value, json};
use web_sys::CryptoKey;
use zeroize::Zeroizing;

use super::auth::User;
use super::keys;
use super::login::{SIGNUPS_CLOSED, allowlisted, stem};
use super::members::{Seal, acting_owner, other_owner, role_text};
use super::{Control, Settings, SignupMode, attempt, coded, deny, internal, random_id};
use crate::audit::{AuditEvent, AuditSink, RateLimit};
use crate::handlers::{ApiRequest, json_body};
use crate::store::{
    InviteRow, MemberRole, MemberRow, StoreError, TenantRow, TenantStatus, TenantStore,
};
use crate::vault::{Reply, log_internal};
use crate::webcrypto::{WebCryptoKeyOps, global_crypto};

/// The largest GitHub id a member can be given: D1 integers bind as JS numbers.
const MAX_GITHUB_ID: u64 = (1 << 53) - 1;

fn not_found() -> Reply {
    Reply::error(404, "tenant not found")
}

fn status_text(s: TenantStatus) -> &'static str {
    match s {
        TenantStatus::Active => "active",
        TenantStatus::Suspended => "suspended",
    }
}

/// `GET /v1/me`. Only rows that verify are listed, each tenant with its status, so a client
/// needs no `GET /v1/tenants/:name` per tenant (each counted against `CONTROL_LIMIT`) to show
/// them. A membership whose tenant row is gone, or names another tenant id, is skipped.
pub async fn me<S: TenantStore, A, L>(
    c: &Control<'_, S, A, L>,
    user: &User,
) -> Result<Reply, Reply> {
    let seal = Seal(&user.control_root);
    let memberships = c
        .store
        .tenants_for_user(user.github_id)
        .await
        .map_err(|_| Reply::internal())?;
    let pending = c
        .store
        .invites_for_user(user.github_id)
        .await
        .map_err(|_| Reply::internal())?;
    let mut tenants = Vec::with_capacity(memberships.len());
    for m in memberships {
        if m.row.github_id != user.github_id || !seal.member_ok(&m.tenant_id, &m.row).await? {
            continue;
        }
        let version = c
            .store
            .tenant_version(&m.name)
            .await
            .map_err(|_| Reply::internal())?;
        let Some(version) = version.filter(|v| v.id == m.tenant_id) else {
            continue;
        };
        tenants.push(json!({
            "name": m.name,
            "role": role_text(m.row.role),
            "status": status_text(version.status),
        }));
    }
    let mut invites = Vec::with_capacity(pending.len());
    for i in pending {
        if i.row.github_id == user.github_id && seal.invite_ok(&i.tenant_id, &i.row).await? {
            invites.push(json!({ "name": i.name, "role": role_text(i.row.role) }));
        }
    }
    Ok(Reply::data(json!({
        "github_id": user.github_id,
        "login": user.login,
        "operator": c.settings.is_operator(user.github_id),
        "tenants": tenants,
        "invites": invites,
    })))
}

/// The tenant `name` by name, or `404 tenant not found`.
async fn tenant_named<S: TenantStore, A, L>(
    c: &Control<'_, S, A, L>,
    ev: &mut AuditEvent,
    name: &str,
) -> Result<TenantRow, Reply> {
    let Ok(name) = TenantName::new(name) else {
        return Err(not_found());
    };
    c.store
        .tenant_by_name(name.as_str())
        .await
        .map_err(|_| internal(ev, "control_store_failed"))?
        .ok_or_else(not_found)
}

/// The tenant's membership rows that verify.
async fn valid_members<S: TenantStore, A, L>(
    c: &Control<'_, S, A, L>,
    ev: &mut AuditEvent,
    seal: &Seal<'_>,
    tenant_id: &str,
) -> Result<Vec<MemberRow>, Reply> {
    let rows = c
        .store
        .members(tenant_id)
        .await
        .map_err(|_| internal(ev, "control_store_failed"))?;
    seal.valid_members(tenant_id, rows).await
}

/// The tenant's pending invite rows that verify.
async fn valid_invites<S: TenantStore, A, L>(
    c: &Control<'_, S, A, L>,
    ev: &mut AuditEvent,
    seal: &Seal<'_>,
    tenant_id: &str,
) -> Result<Vec<InviteRow>, Reply> {
    let rows = c
        .store
        .invites(tenant_id)
        .await
        .map_err(|_| internal(ev, "control_store_failed"))?;
    seal.valid_invites(tenant_id, rows).await
}

/// The tenant `name` and the caller's role on it, or `404 tenant not found` when there is no
/// such tenant or the caller has no membership that verifies: the two are indistinguishable.
pub async fn tenant_for<S: TenantStore, A, L>(
    c: &Control<'_, S, A, L>,
    ev: &mut AuditEvent,
    user: &User,
    name: &str,
) -> Result<(TenantRow, MemberRole), Reply> {
    let row = tenant_named(c, ev, name).await?;
    let member = c
        .store
        .member(&row.id, user.github_id)
        .await
        .map_err(|_| internal(ev, "control_store_failed"))?
        .filter(|m| m.github_id == user.github_id);
    let role = Seal(&user.control_root)
        .valid_member(&row.id, member)
        .await?
        .map(|m| m.role)
        .ok_or_else(not_found)?;
    ev.tenant = Some(row.id.clone());
    Ok((row, role))
}

/// As [`tenant_for`], but only for an owner: a member is `403 permission denied`.
pub async fn owned<S: TenantStore, A, L>(
    c: &Control<'_, S, A, L>,
    ev: &mut AuditEvent,
    user: &User,
    name: &str,
) -> Result<TenantRow, Reply> {
    let (row, role) = tenant_for(c, ev, user, name).await?;
    if role == MemberRole::Owner {
        Ok(row)
    } else {
        deny(ev, "not_owner");
        Err(Reply::denied())
    }
}

/// As [`owned`], but refused with `403 tenant is suspended` for a suspended tenant: its
/// config and memberships are frozen while it is suspended. Export uses [`owned`], so a
/// suspended tenant's owners keep a way out.
pub async fn owned_active<S: TenantStore, A, L>(
    c: &Control<'_, S, A, L>,
    ev: &mut AuditEvent,
    user: &User,
    name: &str,
) -> Result<TenantRow, Reply> {
    let row = owned(c, ev, user, name).await?;
    refuse_suspended(ev, &row)?;
    Ok(row)
}

fn refuse_suspended(ev: &mut AuditEvent, row: &TenantRow) -> Result<(), Reply> {
    if row.status == TenantStatus::Suspended {
        deny(ev, "tenant_suspended");
        Err(Reply::error(403, "tenant is suspended"))
    } else {
        Ok(())
    }
}

/// `GET /v1/tenants/:name`.
pub async fn show<S: TenantStore, A, L>(
    c: &Control<'_, S, A, L>,
    ev: &mut AuditEvent,
    user: &User,
    name: &str,
) -> Result<Reply, Reply> {
    let (row, _) = tenant_for(c, ev, user, name).await?;
    let config: Value =
        serde_json::from_str(&row.config).map_err(|_| internal(ev, "tenant_config_invalid"))?;
    let seal = Seal(&user.control_root);
    let mut members: Vec<(u64, MemberRole)> = valid_members(c, ev, &seal, &row.id)
        .await?
        .into_iter()
        .map(|m| (m.github_id, m.role))
        .collect();
    members.sort_by_key(|(id, _)| *id);
    let mut invites: Vec<(u64, MemberRole)> = valid_invites(c, ev, &seal, &row.id)
        .await?
        .into_iter()
        .map(|i| (i.github_id, i.role))
        .collect();
    invites.sort_by_key(|(id, _)| *id);
    let list = |v: &[(u64, MemberRole)]| {
        v.iter()
            .map(|(id, role)| json!({ "github_id": id, "role": role_text(*role) }))
            .collect::<Vec<_>>()
    };
    Ok(Reply::data(json!({
        "name": row.name,
        "id": row.id,
        "root_id": row.root_id,
        "status": status_text(row.status),
        "config": config,
        "config_version": row.config_version,
        "members": list(&members),
        "invites": list(&invites),
    })))
}

/// Checks a config for tenant root `root_id`: a JSON object at most [`MAX_CONFIG_BYTES`] long
/// once compacted, then [`Config::from_json`] and [`validate_hosted`]. Returns the compact
/// JSON that is stored and covered by the MAC. Errors name a path, never a value from the config.
pub fn check_config(value: &Value, root_id: &Id, settings: &Settings) -> Result<String, Reply> {
    if !value.is_object() {
        return Err(Reply::error(400, "config must be a JSON object"));
    }
    let text = value.to_string();
    if text.len() > MAX_CONFIG_BYTES {
        return Err(config_too_large());
    }
    let config = Config::from_json(&text).map_err(|e| Reply::error(400, &e.to_string()))?;
    let rules = HostedRules {
        root_id,
        github_client_id: &settings.github_client_id,
        apex: &settings.apex,
    };
    validate_hosted(&config, &rules).map_err(|e| Reply::error(400, &e.to_string()))?;
    Ok(text)
}

fn config_too_large() -> Reply {
    Reply::error(
        413,
        &format!("config is larger than {MAX_CONFIG_BYTES} bytes"),
    )
}

/// The config MAC of tenant `id` named `name` at `version`, under the tenant root `ops`.
async fn config_mac(
    ops: &WebCryptoKeyOps,
    id: &str,
    name: &str,
    version: u64,
    config: &str,
) -> Result<Vec<u8>, Reply> {
    ops.mac(
        MacPurpose::Config,
        &config_mac_input(id, name, version, config),
    )
    .await
    .map(|tag| tag.to_vec())
    .map_err(|_| {
        log_internal("control: config MAC failed");
        Reply::internal()
    })
}

/// Lowercase hex SHA-256 of `data`, through `WebCrypto`.
async fn sha256_hex(data: &[u8]) -> Result<String, Reply> {
    let subtle = global_crypto().map_err(|_| Reply::internal())?.subtle();
    let digest = async {
        let promise = subtle.digest_with_str_and_u8_array("SHA-256", data)?;
        wasm_bindgen_futures::JsFuture::from(promise).await
    }
    .await
    .map_err(|_| {
        log_internal("control: SHA-256 failed");
        Reply::internal()
    })?;
    Ok(super::hex(&js_sys::Uint8Array::new(&digest).to_vec()))
}

/// Why [`insert`] failed.
pub enum InsertError {
    Store(StoreError),
    /// A `WebCrypto` or master key failure, already logged.
    Internal,
}

/// Where a new tenant's root comes from.
pub enum Root<'a> {
    /// A fresh random root, never in wasm memory.
    New,
    /// An existing root brought in from elsewhere.
    Import(&'a Zeroizing<[u8; 32]>),
}

/// Wraps the root (new or imported) under the current master, MACs `config` at version 1
/// under it, and stores the tenant with `owner` as its first owner (the membership row's MAC
/// computed by `seal`). With `max_created`, only while `owner` has created fewer tenants than
/// that, checked atomically with the insert (`StoreError::CapReached` otherwise).
#[allow(clippy::too_many_arguments)]
pub async fn insert<S: TenantStore, A, L>(
    c: &Control<'_, S, A, L>,
    seal: &Seal<'_>,
    id: &str,
    name: &TenantName,
    root_id: &Id,
    config: String,
    root: Root<'_>,
    owner: u64,
    max_created: Option<u64>,
) -> Result<TenantRow, InsertError> {
    let admin = c.masters.admin().await.map_err(|_| InsertError::Internal)?;
    let wrapped: Result<(CryptoKey, Vec<u8>), _> = match root {
        Root::New => admin.new_root(id, root_id).await,
        Root::Import(raw) => admin.import_root(raw, id, root_id).await,
    };
    let (handle, wrapped) = wrapped.map_err(|_| InsertError::Internal)?;
    let ops = WebCryptoKeyOps::from_hkdf_key(handle, root_id.clone())
        .map_err(|_| InsertError::Internal)?;
    let mac = config_mac(&ops, id, name.as_str(), 1, &config)
        .await
        .map_err(|_| InsertError::Internal)?;
    let row = TenantRow {
        id: id.to_owned(),
        name: name.as_str().to_owned(),
        root_id: root_id.as_str().to_owned(),
        wrapped_root: wrapped,
        wrap_key: admin.current().to_owned(),
        config,
        config_version: 1,
        config_mac: mac,
        status: TenantStatus::Active,
    };
    let membership = seal
        .member(id, owner, MemberRole::Owner, owner, c.now_ms)
        .await
        .map_err(|_| InsertError::Internal)?;
    let stored = match max_created {
        Some(max) => {
            c.store
                .create_tenant_capped(&row, owner, c.now_ms, &membership.mac, max)
                .await
        }
        None => {
            c.store
                .create_tenant(&row, owner, c.now_ms, &membership.mac)
                .await
        }
    };
    stored.map_err(InsertError::Store)?;
    Ok(row)
}

/// `POST /v1/tenants`: `{"name", "config"?, "import"?: {"root_id", "root_key"}}`.
///
/// Without an import the server generates the root and overwrites the config's `root_id`
/// with it (or uses the default config); with one, the config is required and its `root_id`
/// must be the imported one.
pub async fn create<S: TenantStore, A: AuditSink, L: RateLimit>(
    c: &Control<'_, S, A, L>,
    req: &ApiRequest,
    ev: &mut AuditEvent,
    user: &User,
) -> Result<Reply, Reply> {
    let body = json_body(&req.body)?;
    let name = body
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| Reply::error(400, "name is required"))?;
    let name = TenantName::new(name).map_err(|e| Reply::error(400, &e.to_string()))?;
    may_create(c, ev, user).await?;
    naming_rule(c.settings, ev, user, &name)?;
    // The cap counts tenants the user created, owned or not, and the store checks it inside
    // the insert, so concurrent creates can't overshoot it. Operators are exempt.
    let max = c.settings.max_tenants_per_user;
    let cap = (!c.settings.is_operator(user.github_id)).then_some(max);
    let import = keys::parse_import(&body)?;
    let config_value = body.get("config");
    let (root_id, config) = match (&import, config_value) {
        (Some(_), None) => {
            return Err(Reply::error(
                400,
                "an import needs a config with the tenant's existing keys",
            ));
        }
        (Some(i), Some(v)) => (i.root_id.clone(), check_config(v, &i.root_id, c.settings)?),
        (None, Some(v)) => {
            let root_id = Id::new(&random_id("r_")?).map_err(|_| Reply::internal())?;
            let mut v = v.clone();
            if let Some(obj) = v.as_object_mut() {
                obj.insert("root_id".to_owned(), json!(root_id.as_str()));
            }
            let config = check_config(&v, &root_id, c.settings)?;
            (root_id, config)
        }
        (None, None) => {
            let root_id = Id::new(&random_id("r_")?).map_err(|_| Reply::internal())?;
            let key_id = Id::new(&random_id("k_")?).map_err(|_| Reply::internal())?;
            let config = default_config(
                &root_id,
                &key_id,
                user.github_id,
                &c.settings.github_client_id,
            );
            (root_id, config)
        }
    };
    let id = random_id("t_")?;
    ev.tenant = Some(id.clone());
    let root = match &import {
        Some(i) => Root::Import(&i.root_key),
        None => Root::New,
    };
    attempt(c, ev).await?;
    // `create_tenant` needs the user's row; a control token outlives nothing that removes it,
    // but a restored database might lack it. Written after the attempt event, as every other
    // write is.
    c.store
        .upsert_user(user.github_id, &user.login, c.now_ms)
        .await
        .map_err(|_| internal(ev, "control_store_failed"))?;
    let seal = Seal(&user.control_root);
    match insert(
        c,
        &seal,
        &id,
        &name,
        &root_id,
        config,
        root,
        user.github_id,
        cap,
    )
    .await
    {
        Ok(row) => Ok(Reply::data(json!({
            "name": row.name,
            "id": row.id,
            "root_id": row.root_id,
            "config_version": row.config_version,
        }))),
        Err(InsertError::Store(StoreError::NameTaken)) => {
            Err(Reply::error(409, "tenant name already in use"))
        }
        Err(InsertError::Store(StoreError::RootIdTaken)) => {
            Err(Reply::error(409, "root id already in use"))
        }
        Err(InsertError::Store(StoreError::CapReached)) => {
            deny(ev, "tenant_cap");
            Err(Reply::error(
                403,
                &format!("at most {max} tenants per user"),
            ))
        }
        Err(InsertError::Store(_)) => Err(internal(ev, "control_store_failed")),
        Err(InsertError::Internal) => Err(internal(ev, "tenant_create_failed")),
    }
}

/// The signup gate: only operators and the users signups admit get tenants. Creating (an import included)
/// needs `open` mode, an operator, a verified allowlist row in `invite` mode, or a tenant the
/// user has already created; a user who logs in on memberships alone, or was taken off the
/// allowlist before creating anything, gets `403 signups are closed` with the code
/// `signup_closed`, before anything is recorded as attempted.
///
/// `count_created` reads `tenants.created_by`, which carries no MAC: a D1 writer could point it at
/// a user who can already log in, letting them create tenants. Every tenant row so created still
/// needs the master to be any use.
async fn may_create<S: TenantStore, A, L>(
    c: &Control<'_, S, A, L>,
    ev: &mut AuditEvent,
    user: &User,
) -> Result<(), Reply> {
    let s = c.settings;
    if s.signup == SignupMode::Open || s.is_operator(user.github_id) {
        return Ok(());
    }
    let seal = Seal(&user.control_root);
    if s.signup == SignupMode::Invite && allowlisted(c, ev, &seal, user.github_id).await? {
        return Ok(());
    }
    let created = c
        .store
        .count_created(user.github_id)
        .await
        .map_err(|_| internal(ev, "control_store_failed"))?;
    if created > 0 {
        return Ok(());
    }
    deny(ev, "signup_closed");
    Err(coded(403, SIGNUPS_CLOSED, "signup_closed"))
}

/// The naming rule: a tenant a non-operator creates (the personal tenant aside, which login
/// names) is `<base>-<suffix>`, where the base is the login stem the personal tenant's name uses ([`stem`]) and the
/// whole name passes [`TenantName::new`]. Operators may use any valid name. Refused with
/// `403 tenant name must start with <base>-` and the code `tenant_name_prefix`, before anything
/// is recorded as attempted.
///
/// The login is the one in the control token, so a user who renames their GitHub account names
/// new tenants after the new login from their next login on. Two logins can fold to the same
/// stem (`Foo_Bar` and `foo-bar`); the rule keeps names tidy, it doesn't reserve a namespace.
fn naming_rule(
    settings: &Settings,
    ev: &mut AuditEvent,
    user: &User,
    name: &TenantName,
) -> Result<(), Reply> {
    if settings.is_operator(user.github_id) {
        return Ok(());
    }
    let prefix = format!("{}-", stem(&user.login));
    // A valid name never ends in `-`, so a match always has a non-empty suffix.
    if name.as_str().starts_with(&prefix) {
        return Ok(());
    }
    deny(ev, "tenant_name_prefix");
    Err(coded(
        403,
        &format!("tenant name must start with {prefix}"),
        "tenant_name_prefix",
    ))
}

/// The config version in an `If-Match` header: `"N"` (an entity tag) or a bare `N`.
fn if_match_version(header: &str) -> Option<u64> {
    let h = header.trim();
    let digits = h
        .strip_prefix('"')
        .and_then(|h| h.strip_suffix('"'))
        .unwrap_or(h);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// `PUT /v1/tenants/:name/config`: the raw config JSON, with `If-Match: "<version>"`.
pub async fn put_config<S: TenantStore, A: AuditSink, L: RateLimit>(
    c: &Control<'_, S, A, L>,
    req: &ApiRequest,
    ev: &mut AuditEvent,
    user: &User,
    name: &str,
) -> Result<Reply, Reply> {
    let row = owned_active(c, ev, user, name).await?;
    let expected = match req.if_match.as_deref() {
        None => {
            return Err(Reply::error(
                428,
                "If-Match with the config version is required",
            ));
        }
        Some(h) => if_match_version(h)
            .ok_or_else(|| Reply::error(400, "If-Match must be a config version, as \"N\""))?,
    };
    if req.body.len() > MAX_CONFIG_BYTES {
        return Err(config_too_large());
    }
    let value: Value = serde_json::from_slice(&req.body)
        .map_err(|_| Reply::error(400, "failed to parse JSON input"))?;
    let root_id = Id::new(&row.root_id).map_err(|_| internal(ev, "tenant_root_id_invalid"))?;
    let config = check_config(&value, &root_id, c.settings)?;
    if expected != row.config_version {
        return Err(stale());
    }
    let next = expected + 1;
    let unwrap = c.masters.unwrap().await?;
    let handle = unwrap
        .unwrap_root(&row.wrap_key, &row.wrapped_root, &row.id, &root_id)
        .await
        .map_err(|_| internal(ev, "tenant_unwrap_failed"))?;
    let ops =
        WebCryptoKeyOps::from_hkdf_key(handle, root_id).map_err(|_| internal(ev, "webcrypto"))?;
    let mac = config_mac(&ops, &row.id, &row.name, next, &config).await?;
    ev.old_config_version = Some(expected);
    ev.config_version = Some(next);
    ev.config_sha256 = Some(sha256_hex(config.as_bytes()).await?);
    attempt(c, ev).await?;
    let written = match c
        .store
        .update_config(&row.id, expected, &config, &mac, c.now_ms)
        .await
    {
        Ok(v) => v,
        Err(StoreError::Conflict) => return Err(stale()),
        Err(StoreError::NotFound) => return Err(not_found()),
        Err(_) => return Err(internal(ev, "control_store_failed")),
    };
    if written != next {
        // The MAC covers `next`; a store that wrote another version left a row that won't load.
        ev.config_version = Some(written);
        return Err(internal(ev, "config_version_unexpected"));
    }
    Ok(Reply::data(json!({ "config_version": written })))
}

fn stale() -> Reply {
    Reply::error(409, "config version mismatch")
}

/// A member's GitHub id from the path: a positive integer D1 can hold.
pub(super) fn github_id(segment: &str) -> Result<u64, Reply> {
    segment
        .parse::<u64>()
        .ok()
        .filter(|id| (1..=MAX_GITHUB_ID).contains(id))
        .ok_or_else(|| Reply::error(400, "github_id must be a positive integer"))
}

/// `400 tenant needs an owner`: the change would leave no owner whose row verifies.
fn last_owner() -> Reply {
    Reply::error(400, "tenant needs an owner")
}

/// `409`: a membership or invite this request read changed before its write landed.
fn membership_changed() -> Reply {
    Reply::error(409, "membership changed; try again")
}

/// `PUT /v1/tenants/:name/members/:github_id` with `{"role": "owner" | "member"}`: `204`.
///
/// For a user who isn't a member, or a member being made an owner, this records a pending
/// invite (replacing any earlier one); the invitee accepts it with `POST .../accept`. An owner
/// made a member changes at once, unless no other owner's row verifies. A user who already
/// holds the role is left as is. A membership row that doesn't verify counts as no membership.
pub async fn set_member<S: TenantStore, A: AuditSink, L: RateLimit>(
    c: &Control<'_, S, A, L>,
    req: &ApiRequest,
    ev: &mut AuditEvent,
    user: &User,
    name: &str,
    id: &str,
) -> Result<Reply, Reply> {
    let row = owned_active(c, ev, user, name).await?;
    let target = github_id(id)?;
    ev.target_github_id = Some(target);
    let body = json_body(&req.body)?;
    let role = match body.get("role").and_then(Value::as_str) {
        Some("owner") => MemberRole::Owner,
        Some("member") => MemberRole::Member,
        _ => return Err(Reply::error(400, "role must be \"owner\" or \"member\"")),
    };
    let seal = Seal(&user.control_root);
    let members = valid_members(c, ev, &seal, &row.id).await?;
    let actor = acting_owner(&members, user.github_id).ok_or_else(membership_changed)?;
    let current = members.iter().find(|m| m.github_id == target);
    let demote = match (current.map(|m| m.role), role) {
        (Some(have), want) if have == want => return Ok(Reply::no_content()),
        (Some(MemberRole::Owner), MemberRole::Member) => true,
        _ => false,
    };
    let change = if demote { "demote" } else { "invite" };
    ev.meta.insert("change".to_owned(), change.to_owned());
    ev.meta
        .insert("role".to_owned(), role_text(role).to_owned());
    let done = if let (true, Some(current)) = (demote, current) {
        // The last-owner precondition is known before anything is recorded: a refused demotion
        // writes only its outcome event, no attempt.
        let Some(witness) = other_owner(&members, target) else {
            return Err(last_owner());
        };
        let demoted = seal
            .member(&row.id, target, role, user.github_id, c.now_ms)
            .await?;
        attempt(c, ev).await?;
        c.store
            .set_member(
                &row.id,
                &demoted,
                Some(&current.mac),
                Some(witness),
                Some(actor),
            )
            .await
    } else {
        let invite = seal
            .invite(&row.id, target, role, user.github_id, c.now_ms)
            .await?;
        attempt(c, ev).await?;
        c.store.invite(&row.id, &invite).await
    };
    match done {
        Ok(()) => Ok(Reply::no_content()),
        Err(StoreError::Conflict) => Err(membership_changed()),
        Err(StoreError::NotFound) => Err(not_found()),
        Err(_) => Err(internal(ev, "control_store_failed")),
    }
}

/// `DELETE /v1/tenants/:name/members/:github_id`: removes the member, or withdraws a pending
/// invite to a user who isn't one. `204`. Removing an owner needs another owner whose row
/// verifies.
pub async fn remove_member<S: TenantStore, A: AuditSink, L: RateLimit>(
    c: &Control<'_, S, A, L>,
    ev: &mut AuditEvent,
    user: &User,
    name: &str,
    id: &str,
) -> Result<Reply, Reply> {
    let row = owned_active(c, ev, user, name).await?;
    let target = github_id(id)?;
    ev.target_github_id = Some(target);
    let seal = Seal(&user.control_root);
    let members = valid_members(c, ev, &seal, &row.id).await?;
    let actor = acting_owner(&members, user.github_id).ok_or_else(membership_changed)?;
    let member = members.iter().find(|m| m.github_id == target);
    let invite = match member {
        Some(_) => None,
        None => valid_invites(c, ev, &seal, &row.id)
            .await?
            .into_iter()
            .find(|i| i.github_id == target),
    };
    if member.is_none() && invite.is_none() {
        return Err(Reply::error(404, "member not found"));
    }
    // As for a demotion, the last-owner precondition is settled before the attempt event.
    let witness = match member.map(|m| m.role) {
        Some(MemberRole::Owner) => match other_owner(&members, target) {
            Some(w) => Some(w),
            None => return Err(last_owner()),
        },
        _ => None,
    };
    let change = if member.is_some() {
        "remove"
    } else {
        "withdraw"
    };
    ev.meta.insert("change".to_owned(), change.to_owned());
    attempt(c, ev).await?;
    let done = match (member, &invite) {
        (Some(m), _) => {
            c.store
                .remove_member(&row.id, target, &m.mac, witness, Some(actor))
                .await
        }
        (None, Some(i)) => c.store.delete_invite(&row.id, target, &i.mac).await,
        (None, None) => Err(StoreError::NotFound),
    };
    match done {
        Ok(()) => Ok(Reply::no_content()),
        Err(StoreError::Conflict) => Err(membership_changed()),
        Err(StoreError::NotFound) => Err(Reply::error(404, "member not found")),
        Err(_) => Err(internal(ev, "control_store_failed")),
    }
}

/// The tenant `name` and the caller's invite to it, or `404 tenant not found` when there is no
/// such tenant or no invite that verifies: the two are indistinguishable.
async fn invited<S: TenantStore, A, L>(
    c: &Control<'_, S, A, L>,
    ev: &mut AuditEvent,
    user: &User,
    name: &str,
) -> Result<(TenantRow, InviteRow), Reply> {
    let row = tenant_named(c, ev, name).await?;
    let invite = valid_invites(c, ev, &Seal(&user.control_root), &row.id)
        .await?
        .into_iter()
        .find(|i| i.github_id == user.github_id)
        .ok_or_else(not_found)?;
    ev.tenant = Some(row.id.clone());
    ev.meta
        .insert("role".to_owned(), role_text(invite.role).to_owned());
    Ok((row, invite))
}

/// `POST /v1/tenants/:name/accept`: the caller accepts their pending invite. Replies with the
/// role now held, which is never lower than one they already had.
pub async fn accept<S: TenantStore, A: AuditSink, L: RateLimit>(
    c: &Control<'_, S, A, L>,
    ev: &mut AuditEvent,
    user: &User,
    name: &str,
) -> Result<Reply, Reply> {
    let (row, invite) = invited(c, ev, user, name).await?;
    refuse_suspended(ev, &row)?;
    let seal = Seal(&user.control_root);
    // The row as stored, whether it verifies or not: the write replaces exactly this one.
    let stored = c
        .store
        .member(&row.id, user.github_id)
        .await
        .map_err(|_| internal(ev, "control_store_failed"))?
        .filter(|m| m.github_id == user.github_id);
    let current = stored.as_ref().map(|m| m.mac.clone());
    let held = seal.valid_member(&row.id, stored).await?.map(|m| m.role);
    let role = if invite.role == MemberRole::Owner || held == Some(MemberRole::Owner) {
        MemberRole::Owner
    } else {
        MemberRole::Member
    };
    let member = seal
        .member(&row.id, user.github_id, role, invite.invited_by, c.now_ms)
        .await?;
    attempt(c, ev).await?;
    match c
        .store
        .accept_invite(&row.id, &invite.mac, current.as_deref(), &member)
        .await
    {
        Ok(()) => Ok(Reply::data(
            json!({ "name": row.name, "role": role_text(role) }),
        )),
        Err(StoreError::NotFound) => Err(not_found()),
        Err(StoreError::Conflict) => Err(membership_changed()),
        Err(_) => Err(internal(ev, "control_store_failed")),
    }
}

/// `POST /v1/tenants/:name/decline`: the caller declines their pending invite. `204`. Allowed
/// while the tenant is suspended: it only ever removes a grant.
pub async fn decline<S: TenantStore, A: AuditSink, L: RateLimit>(
    c: &Control<'_, S, A, L>,
    ev: &mut AuditEvent,
    user: &User,
    name: &str,
) -> Result<Reply, Reply> {
    let (row, invite) = invited(c, ev, user, name).await?;
    attempt(c, ev).await?;
    match c
        .store
        .delete_invite(&row.id, user.github_id, &invite.mac)
        .await
    {
        Ok(()) => Ok(Reply::no_content()),
        Err(StoreError::NotFound) => Err(not_found()),
        Err(StoreError::Conflict) => Err(membership_changed()),
        Err(_) => Err(internal(ev, "control_store_failed")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn if_match_takes_a_quoted_or_bare_version() {
        assert_eq!(if_match_version("\"7\""), Some(7));
        assert_eq!(if_match_version(" 12 "), Some(12));
        for bad in ["*", "\"\"", "W/\"1\"", "\"1", "\"x\"", "-1", "1,2", ""] {
            assert_eq!(if_match_version(bad), None, "{bad}");
        }
    }

    #[test]
    fn member_ids_are_positive_and_fit_d1() {
        assert_eq!(github_id("583231").ok(), Some(583_231));
        for bad in ["0", "-1", "abc", "9007199254740992", ""] {
            assert!(github_id(bad).is_err(), "{bad}");
        }
    }
}
