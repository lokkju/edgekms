//! Operator routes, for the GitHub ids in `OPERATOR_GITHUB_IDS` only: `POST /v1/ops/rewrap`
//! (master-key rotation), `PUT /v1/ops/tenants/:name/status` (suspension) and the signup
//! allowlist (`PUT` and `DELETE /v1/ops/allowlist/:github_id`, `GET /v1/ops/allowlist`). Anyone
//! else gets `403 permission denied`.
//!
//! Each allowlist row carries a MAC under the control root (`mac/allow/v1`, see
//! `super::members::Seal::allow`), written on `PUT` and verified on every read, so a row written
//! straight to D1 admits no one. The listing shows only rows that verify, and names the ids of
//! the ones that don't under `unverified`, for the operator to delete.
//!
//! A rewrap pass takes up to `limit` tenant rows still wrapped under `MASTER_KEY_PREVIOUS`
//! with an id after the request's `after` cursor, then (on the last page) the control plane's
//! own root if it is, rewraps each under `MASTER_KEY_CURRENT` and stores it conditionally on
//! the old wrap key, so concurrent passes and reruns are harmless. The reply's `next` is the
//! cursor for the following pass (`null` after the last page) and `failed` lists the ids that
//! couldn't be rewrapped, so a broken row is reported and skipped instead of stalling every
//! later pass. Page until `next` is `null`; `remaining` counts what is still under the
//! previous key, failed rows included.

use edgekms_core::tenant::TenantName;
use edgekms_core::transit::Id;
use serde_json::{Value, json};

use super::auth::{CONTROL_AAD_ID, CONTROL_KEY, User};
use super::members::Seal;
use super::tenants::github_id;
use super::{Control, attempt, deny, internal};
use crate::audit::{AuditEvent, AuditSink, RateLimit};
use crate::handlers::{ApiRequest, json_body};
use crate::master::MasterAdmin;
use crate::store::{StoreError, TenantStatus, TenantStore, WrappedRoot};
use crate::vault::{Reply, log_internal};

/// The most rows one rewrap pass moves.
pub const MAX_REWRAP: u64 = 100;
/// How far `remaining` counts; a larger backlog reports this many.
const COUNT_CAP: u32 = 1000;

pub(super) fn operator<S, A, L>(
    c: &Control<'_, S, A, L>,
    ev: &mut AuditEvent,
    user: &User,
) -> Result<(), Reply> {
    if c.settings.is_operator(user.github_id) {
        Ok(())
    } else {
        deny(ev, "not_operator");
        Err(Reply::denied())
    }
}

/// What happened to one row in a rewrap pass.
enum Moved {
    Yes,
    /// Someone else's pass moved it first.
    Raced,
    /// It couldn't be rewrapped: logged, reported in `failed`, left for the operator.
    Failed,
}

/// Rewraps one tenant row.
async fn rewrap_row<S: TenantStore, A, L>(
    c: &Control<'_, S, A, L>,
    admin: &MasterAdmin,
    previous: &str,
    row: &WrappedRoot,
) -> Result<Moved, Reply> {
    let Ok(root_id) = Id::new(&row.root_id) else {
        log_internal("rewrap: tenant root id invalid");
        return Ok(Moved::Failed);
    };
    let Ok(new) = admin
        .rewrap(previous, &row.wrapped_root, &row.id, &root_id)
        .await
    else {
        log_internal("rewrap: tenant root failed to rewrap");
        return Ok(Moved::Failed);
    };
    match c
        .store
        .set_wrapped(&row.id, previous, &new, admin.current())
        .await
    {
        Ok(()) => Ok(Moved::Yes),
        Err(StoreError::Conflict | StoreError::NotFound) => Ok(Moved::Raced),
        Err(_) => Err(Reply::internal()),
    }
}

/// Rewraps the control plane's own root if it is still under `previous`; `None` if it isn't.
async fn rewrap_control_root<S: TenantStore, A, L>(
    c: &Control<'_, S, A, L>,
    admin: &MasterAdmin,
    previous: &str,
) -> Result<Option<Moved>, Reply> {
    let system = c
        .store
        .system_key(CONTROL_KEY)
        .await
        .map_err(|_| Reply::internal())?;
    let Some(sk) = system.filter(|sk| sk.wrap_key == previous) else {
        return Ok(None);
    };
    let moved = match Id::new(&sk.root_id) {
        Ok(root_id) => admin
            .rewrap(previous, &sk.wrapped_root, CONTROL_AAD_ID, &root_id)
            .await
            .ok(),
        Err(_) => None,
    };
    let Some(new) = moved else {
        log_internal("rewrap: control root failed to rewrap");
        return Ok(Some(Moved::Failed));
    };
    match c
        .store
        .set_system_wrapped(CONTROL_KEY, previous, &new, admin.current())
        .await
    {
        Ok(()) => Ok(Some(Moved::Yes)),
        Err(StoreError::Conflict | StoreError::NotFound) => Ok(Some(Moved::Raced)),
        Err(_) => Err(Reply::internal()),
    }
}

/// `POST /v1/ops/rewrap` with `{"limit": n, "after": "<cursor>"}` (limit 1 to 100, default
/// 100; no `after` to start): `{"rewrapped", "failed": [ids], "next": cursor | null,
/// "remaining"}`.
pub async fn rewrap<S: TenantStore, A: AuditSink, L: RateLimit>(
    c: &Control<'_, S, A, L>,
    req: &ApiRequest,
    ev: &mut AuditEvent,
    user: &User,
) -> Result<Reply, Reply> {
    operator(c, ev, user)?;
    let body = json_body(&req.body)?;
    let limit = match body.get("limit") {
        None => MAX_REWRAP,
        Some(v) => v
            .as_u64()
            .filter(|n| (1..=MAX_REWRAP).contains(n))
            .ok_or_else(|| Reply::error(400, &format!("limit must be 1 to {MAX_REWRAP}")))?,
    };
    let after = match body.get("after") {
        None | Some(Value::Null) => String::new(),
        Some(v) => v
            .as_str()
            .filter(|a| a.len() <= 64)
            .ok_or_else(|| Reply::error(400, "after must be a cursor from an earlier pass"))?
            .to_owned(),
    };
    let admin = c.masters.admin().await?;
    let Some(previous) = c
        .settings
        .previous_master
        .as_deref()
        .filter(|p| *p != admin.current())
    else {
        return Ok(Reply::data(json!({
            "rewrapped": 0,
            "failed": [],
            "next": null,
            "remaining": 0,
        })));
    };
    let store_failed = |ev: &mut AuditEvent| internal(ev, "control_store_failed");

    attempt(c, ev).await?;
    // `limit` is at most 100.
    let rows = c
        .store
        .rows_wrapped_after(previous, &after, u32::try_from(limit).unwrap_or(100))
        .await
        .map_err(|_| store_failed(ev))?;
    let mut rewrapped = 0u64;
    let mut failed: Vec<String> = Vec::new();
    for row in &rows {
        match rewrap_row(c, &admin, previous, row)
            .await
            .map_err(|_| store_failed(ev))?
        {
            Moved::Yes => rewrapped += 1,
            Moved::Raced => {}
            Moved::Failed => failed.push(row.id.clone()),
        }
    }
    let last_page = (rows.len() as u64) < limit;
    let next = if last_page {
        None
    } else {
        rows.last().map(|r| r.id.clone())
    };
    if last_page {
        match rewrap_control_root(c, &admin, previous)
            .await
            .map_err(|_| store_failed(ev))?
        {
            Some(Moved::Yes) => rewrapped += 1,
            Some(Moved::Failed) => failed.push(CONTROL_AAD_ID.to_owned()),
            Some(Moved::Raced) | None => {}
        }
    }

    let left = c
        .store
        .rows_wrapped_with(previous, COUNT_CAP)
        .await
        .map_err(|_| store_failed(ev))?
        .len() as u64;
    let system_left = c
        .store
        .system_key(CONTROL_KEY)
        .await
        .map_err(|_| store_failed(ev))?
        .is_some_and(|sk| sk.wrap_key == previous);
    Ok(Reply::data(json!({
        "rewrapped": rewrapped,
        "failed": failed,
        "next": next,
        "remaining": left + u64::from(system_left),
    })))
}

/// `PUT /v1/ops/tenants/:name/status` with `{"status": "active" | "suspended"}`: `204`. The
/// data plane refuses a suspended tenant within one revalidation interval.
pub async fn set_status<S: TenantStore, A: AuditSink, L: RateLimit>(
    c: &Control<'_, S, A, L>,
    req: &ApiRequest,
    ev: &mut AuditEvent,
    user: &User,
    name: &str,
) -> Result<Reply, Reply> {
    operator(c, ev, user)?;
    let body = json_body(&req.body)?;
    let status = match body.get("status").and_then(Value::as_str) {
        Some("active") => TenantStatus::Active,
        Some("suspended") => TenantStatus::Suspended,
        _ => {
            return Err(Reply::error(
                400,
                "status must be \"active\" or \"suspended\"",
            ));
        }
    };
    let not_found = || Reply::error(404, "tenant not found");
    let Ok(name) = TenantName::new(name) else {
        return Err(not_found());
    };
    let version = c
        .store
        .tenant_version(name.as_str())
        .await
        .map_err(|_| internal(ev, "control_store_failed"))?
        .ok_or_else(not_found)?;
    ev.tenant = Some(version.id.clone());
    attempt(c, ev).await?;
    match c.store.set_status(&version.id, status).await {
        Ok(()) => Ok(Reply::no_content()),
        Err(StoreError::NotFound) => Err(not_found()),
        Err(_) => Err(internal(ev, "control_store_failed")),
    }
}

/// `PUT /v1/ops/allowlist/:github_id` (any body): `204`. Puts the user on the signup allowlist,
/// replacing any row they already have with a fresh one.
pub async fn allow<S: TenantStore, A: AuditSink, L: RateLimit>(
    c: &Control<'_, S, A, L>,
    ev: &mut AuditEvent,
    user: &User,
    id: &str,
) -> Result<Reply, Reply> {
    operator(c, ev, user)?;
    let target = github_id(id)?;
    ev.target_github_id = Some(target);
    let row = Seal(&user.control_root)
        .allow(target, user.github_id, c.now_ms)
        .await?;
    attempt(c, ev).await?;
    c.store
        .allow_signup(&row)
        .await
        .map_err(|_| internal(ev, "control_store_failed"))?;
    Ok(Reply::no_content())
}

/// `DELETE /v1/ops/allowlist/:github_id`: `204`, or `404 not on the allowlist`. Removes any
/// row for the user, whether it verifies or not. A user removed after their first login keeps
/// logging in as an existing user while they hold a membership.
pub async fn disallow<S: TenantStore, A: AuditSink, L: RateLimit>(
    c: &Control<'_, S, A, L>,
    ev: &mut AuditEvent,
    user: &User,
    id: &str,
) -> Result<Reply, Reply> {
    operator(c, ev, user)?;
    let target = github_id(id)?;
    ev.target_github_id = Some(target);
    attempt(c, ev).await?;
    match c.store.disallow_signup(target).await {
        Ok(()) => Ok(Reply::no_content()),
        Err(StoreError::NotFound) => Err(Reply::error(404, "not on the allowlist")),
        Err(_) => Err(internal(ev, "control_store_failed")),
    }
}

/// `GET /v1/ops/allowlist`: `{"allowlist": [{"github_id", "added_by", "added_ms"}],
/// "unverified": [github_id]}`, both by GitHub id.
pub async fn allowlist<S: TenantStore, A, L>(
    c: &Control<'_, S, A, L>,
    ev: &mut AuditEvent,
    user: &User,
) -> Result<Reply, Reply> {
    operator(c, ev, user)?;
    let rows = c
        .store
        .allowlist()
        .await
        .map_err(|_| internal(ev, "control_store_failed"))?;
    let seal = Seal(&user.control_root);
    let mut listed = Vec::with_capacity(rows.len());
    let mut unverified = Vec::new();
    for r in rows {
        if seal.allow_ok(&r).await? {
            listed.push(json!({
                "github_id": r.github_id,
                "added_by": r.added_by,
                "added_ms": r.added_ms,
            }));
        } else {
            unverified.push(r.github_id);
        }
    }
    Ok(Reply::data(json!({
        "allowlist": listed,
        "unverified": unverified,
    })))
}
