//! Invite requests (lokkju/edgekms#12). A user refused with `signup_closed` in `invite` mode
//! holds a request token (`super::auth::requester`) for 15 minutes, with which they read their
//! request (`GET /v1/invite-requests/mine`) and file one (`POST /v1/invite-requests`).
//! Operators list, approve, decline and delete requests under `/v1/ops/invite-requests`.
//!
//! One row per GitHub id (the primary key). A row whose MAC verifies is never replaced by its
//! requester: a pending or approved one is `409 already_requested`, a declined one
//! `409 request_declined` until an operator deletes it. A row whose MAC doesn't verify
//! (written straight to D1) reads as no request and is replaced by a real one.
//!
//! Approving writes the user's signup allowlist row and marks the request approved in one D1
//! batch, the allowlist insert conditional on the status change, so an approval never
//! half-lands and two operators approving at once write one allowlist row. Admission still
//! reads only the allowlist.
//!
//! The note is checked by `edgekms_core::hosted::invite_note`, stored in the row and returned
//! only to operators; it never goes into an audit event, a metric or a log.

use edgekms_core::hosted::invite_note;
use serde_json::{Value, json};

use super::auth::{Requester, User};
use super::login::{allowlisted, existing, invited};
use super::members::Seal;
use super::ops::operator;
use super::tenants::github_id;
use super::{Control, SignupMode, attempt, coded, deny, internal};
use crate::audit::{AuditEvent, AuditSink, RateLimit};
use crate::handlers::{ApiRequest, json_body};
use crate::store::{RequestStatus, StoreError, TenantStore};
use crate::vault::Reply;

/// Whether the control plane takes new invite requests: `SIGNUP_MODE` is `invite` and
/// `MAX_PENDING_INVITE_REQUESTS` isn't 0.
fn accepting<S, A, L>(c: &Control<'_, S, A, L>) -> bool {
    c.settings.signup == SignupMode::Invite && c.settings.max_pending_invite_requests > 0
}

/// A refusal with its stable `code`, recorded as `denied` for `code`.
fn refuse(ev: &mut AuditEvent, status: u16, msg: &str, code: &'static str) -> Reply {
    deny(ev, code);
    coded(status, msg, code)
}

fn already_requested(ev: &mut AuditEvent) -> Reply {
    refuse(
        ev,
        409,
        "you have already asked for an invite",
        "already_requested",
    )
}

/// `GET /v1/invite-requests/mine`: `{"github_id", "login", "accepting", "request"}`, `request`
/// being `null` or `{"status", "created_ms", "decided_ms"}` for a row that verifies. The note
/// isn't echoed.
pub async fn mine<S: TenantStore, A, L>(
    c: &Control<'_, S, A, L>,
    ev: &mut AuditEvent,
    who: &Requester,
) -> Result<Reply, Reply> {
    let row = c
        .store
        .invite_request(who.github_id)
        .await
        .map_err(|_| internal(ev, "control_store_failed"))?
        .filter(|r| r.github_id == who.github_id);
    let request = match row {
        Some(r) if Seal(&who.control_root).invite_request_ok(&r).await? => json!({
            "status": r.status.as_str(),
            "created_ms": r.created_ms,
            "decided_ms": r.decided_ms,
        }),
        _ => Value::Null,
    };
    Ok(Reply::data(json!({
        "github_id": who.github_id,
        "login": who.login,
        "accepting": accepting(c),
        "request": request,
    })))
}

/// `POST /v1/invite-requests` with `{"note": "<text>"}` or `{}`: `201 {"status": "pending",
/// "created_ms"}`. Checks, in order: the mode and cap, that the user still isn't admitted, the
/// note, and the existing row.
pub async fn create<S: TenantStore, A: AuditSink, L: RateLimit>(
    c: &Control<'_, S, A, L>,
    req: &ApiRequest,
    ev: &mut AuditEvent,
    who: &Requester,
) -> Result<Reply, Reply> {
    if !accepting(c) {
        return Err(refuse(
            ev,
            403,
            "not taking invite requests right now",
            "invite_requests_closed",
        ));
    }
    let seal = Seal(&who.control_root);
    let id = who.github_id;
    // Admitted since the refusal (allowlisted, invited, or holding a membership): they can
    // simply sign in, and a request would only sit in front of an operator.
    if c.settings.is_operator(id)
        || allowlisted(c, ev, &seal, id).await?
        || existing(c, ev, &seal, id).await?
        || invited(c, ev, &seal, id).await?
    {
        return Err(refuse(ev, 409, "you can sign in now", "already_admitted"));
    }
    let body = json_body(&req.body)?;
    let raw = match body.get("note") {
        None | Some(Value::Null) => "",
        Some(Value::String(s)) => s.as_str(),
        Some(_) => {
            return Err(refuse(ev, 400, "the note must be a string", "note_invalid"));
        }
    };
    let note = invite_note(raw).map_err(|e| refuse(ev, 400, &e.to_string(), "note_invalid"))?;
    let current = c
        .store
        .invite_request(id)
        .await
        .map_err(|_| internal(ev, "control_store_failed"))?
        .filter(|r| r.github_id == id);
    let replaces = match current {
        Some(r) if seal.invite_request_ok(&r).await? => {
            return Err(if r.status == RequestStatus::Declined {
                refuse(ev, 409, "your request wasn't approved", "request_declined")
            } else {
                already_requested(ev)
            });
        }
        // Written without the control plane: it never counted as a request, so the real one
        // takes its place.
        Some(r) => Some(r.mac),
        None => None,
    };
    let row = seal.invite_request(id, &who.login, note, c.now_ms).await?;
    attempt(c, ev).await?;
    let cap = c.settings.max_pending_invite_requests;
    let stored = match &replaces {
        Some(old) => c.store.replace_invite_request(&row, old, cap).await,
        None => c.store.insert_invite_request(&row, cap).await,
    };
    match stored {
        Ok(()) => {
            let mut reply = Reply::data(json!({
                "status": RequestStatus::Pending.as_str(),
                "created_ms": row.created_ms,
            }));
            reply.status = 201;
            Ok(reply)
        }
        Err(StoreError::CapReached) => Err(refuse(
            ev,
            503,
            "not taking more invite requests right now; try again later",
            "invite_requests_full",
        )),
        // A concurrent request from the same user landed first.
        Err(StoreError::Conflict) => Err(already_requested(ev)),
        Err(_) => Err(internal(ev, "control_store_failed")),
    }
}

/// How many decided requests `GET /v1/ops/invite-requests` lists after the pending ones.
pub const DECIDED_LISTED: u32 = 100;

fn not_found(ev: &mut AuditEvent) -> Reply {
    refuse(
        ev,
        404,
        "no invite request from that user",
        "request_not_found",
    )
}

fn not_pending(ev: &mut AuditEvent) -> Reply {
    refuse(
        ev,
        409,
        "that request was already decided",
        "request_not_pending",
    )
}

/// `GET /v1/ops/invite-requests`: `{"requests": [{"github_id", "login", "note", "created_ms",
/// "status", "decided_by", "decided_ms"}], "unverified": [github_id], "pending": n}`. Every
/// pending request, oldest first, then the [`DECIDED_LISTED`] most recently decided. Rows whose
/// MAC doesn't verify are left out of `requests` and named in `unverified`; `pending` counts
/// the verified pending rows.
pub async fn list<S: TenantStore, A, L>(
    c: &Control<'_, S, A, L>,
    ev: &mut AuditEvent,
    user: &User,
) -> Result<Reply, Reply> {
    operator(c, ev, user)?;
    let rows = c
        .store
        .invite_requests(DECIDED_LISTED)
        .await
        .map_err(|_| internal(ev, "control_store_failed"))?;
    let seal = Seal(&user.control_root);
    let mut listed = Vec::with_capacity(rows.len());
    let mut unverified = Vec::new();
    let mut pending = 0u64;
    for r in rows {
        if !seal.invite_request_ok(&r).await? {
            unverified.push(r.github_id);
            continue;
        }
        if r.status == RequestStatus::Pending {
            pending += 1;
        }
        listed.push(json!({
            "github_id": r.github_id,
            "login": r.login,
            "note": r.note,
            "created_ms": r.created_ms,
            "status": r.status.as_str(),
            "decided_by": r.decided_by,
            "decided_ms": r.decided_ms,
        }));
    }
    Ok(Reply::data(json!({
        "requests": listed,
        "unverified": unverified,
        "pending": pending,
    })))
}

/// `POST /v1/ops/invite-requests/:github_id/approve` (`Approved`) or `/decline` (`Declined`),
/// body ignored: `204`. Refuses a missing row (`404 request_not_found`), one whose MAC doesn't
/// verify (`409 request_unverified`) and a decided one, or one that changed between this read
/// and the decision (`409 request_not_pending`). An approval writes the user's allowlist row,
/// the row `PUT /v1/ops/allowlist/:github_id` writes, in the same batch as the status.
pub async fn decide<S: TenantStore, A: AuditSink, L: RateLimit>(
    c: &Control<'_, S, A, L>,
    ev: &mut AuditEvent,
    user: &User,
    id: &str,
    status: RequestStatus,
) -> Result<Reply, Reply> {
    operator(c, ev, user)?;
    let target = github_id(id)?;
    ev.target_github_id = Some(target);
    let seal = Seal(&user.control_root);
    let row = c
        .store
        .invite_request(target)
        .await
        .map_err(|_| internal(ev, "control_store_failed"))?
        .filter(|r| r.github_id == target)
        .ok_or_else(|| not_found(ev))?;
    if !seal.invite_request_ok(&row).await? {
        return Err(refuse(
            ev,
            409,
            "that request wasn't written by the control plane; delete it",
            "request_unverified",
        ));
    }
    if row.status != RequestStatus::Pending {
        return Err(not_pending(ev));
    }
    let allow = match status {
        RequestStatus::Approved => Some(seal.allow(target, user.github_id, c.now_ms).await?),
        _ => None,
    };
    attempt(c, ev).await?;
    let decided = c
        .store
        .decide_invite_request(
            target,
            &row.mac,
            status,
            user.github_id,
            c.now_ms,
            allow.as_ref(),
        )
        .await;
    match decided {
        Ok(()) => Ok(Reply::no_content()),
        Err(StoreError::Conflict) => Err(not_pending(ev)),
        Err(_) => Err(internal(ev, "control_store_failed")),
    }
}

/// `DELETE /v1/ops/invite-requests/:github_id`: `204`, or `404 request_not_found`. Removes the
/// row whatever its status or MAC; a declined user can then file again, and an approved user
/// stays on the allowlist.
pub async fn delete<S: TenantStore, A: AuditSink, L: RateLimit>(
    c: &Control<'_, S, A, L>,
    ev: &mut AuditEvent,
    user: &User,
    id: &str,
) -> Result<Reply, Reply> {
    operator(c, ev, user)?;
    let target = github_id(id)?;
    ev.target_github_id = Some(target);
    attempt(c, ev).await?;
    match c.store.delete_invite_request(target).await {
        Ok(()) => Ok(Reply::no_content()),
        Err(StoreError::NotFound) => Err(not_found(ev)),
        Err(_) => Err(internal(ev, "control_store_failed")),
    }
}
