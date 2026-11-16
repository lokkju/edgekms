//! Root import (`POST /v1/tenants` with `import`) and export
//! (`POST /v1/tenants/:name/export`). These and master rotation are the only places a root's
//! raw bytes are handled; every buffer they pass through is zeroized.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use edgekms_core::transit::Id;
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use super::auth::User;
use super::tenants::owned;
use super::{Control, attempt, coded, deny, internal};
use crate::audit::{AuditEvent, AuditSink, RateLimit};
use crate::store::TenantStore;
use crate::vault::Reply;

/// An existing root to bring into a new tenant.
pub struct Import {
    pub root_id: Id,
    pub root_key: Zeroizing<[u8; 32]>,
}

/// The body's `import` (`{"root_id", "root_key"}`, the key base64 of 32 bytes), if any. The
/// body itself is zeroized when the caller drops it.
///
/// Accepted residue: when `root_key`'s JSON string contains `\u` escapes (or any escape),
/// `serde_json` decodes it through its own scratch buffer, which isn't zeroized, so a copy of
/// the base64 text may stay in freed wasm memory until it is reused. Plain base64 has no
/// escapes and is borrowed straight from the zeroized body. The isolate's memory is not
/// readable from outside, so this is accepted rather than worked around with a custom parser.
pub fn parse_import(body: &Map<String, Value>) -> Result<Option<Import>, Reply> {
    let Some(import) = body.get("import") else {
        return Ok(None);
    };
    let bad = |what: &str| Reply::error(400, &format!("import.{what}"));
    let import = import
        .as_object()
        .ok_or_else(|| Reply::error(400, "import must be an object"))?;
    let root_id = import
        .get("root_id")
        .and_then(Value::as_str)
        .and_then(|r| Id::new(r).ok())
        .ok_or_else(|| bad("root_id: 1 to 64 of a-z, 0-9 and _"))?;
    let text = import
        .get("root_key")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("root_key is required"))?;
    // Decoded into a zeroizing buffer large enough for any 32-byte encoding, so nothing is
    // reallocated and left behind.
    let mut decoded = Zeroizing::new([0u8; 48]);
    let mut root_key = Zeroizing::new([0u8; 32]);
    match STANDARD.decode_slice(text.trim().as_bytes(), &mut decoded[..]) {
        Ok(32) => root_key.copy_from_slice(&decoded[..32]),
        _ => return Err(bad("root_key: must be base64 of 32 bytes")),
    }
    Ok(Some(Import { root_id, root_key }))
}

/// `POST /v1/tenants/:name/export` (body `{}`): the tenant's root id and base64 root key, for
/// an owner whose control-plane login is under five minutes old.
pub async fn export<S: TenantStore, A: AuditSink, L: RateLimit>(
    c: &Control<'_, S, A, L>,
    ev: &mut AuditEvent,
    user: &User,
    name: &str,
) -> Result<Reply, Reply> {
    let row = owned(c, ev, user, name).await?;
    if !user.fresh(c.now()) {
        deny(ev, "stale_login");
        return Err(coded(403, "fresh login required", "fresh_login_required"));
    }
    let root_id = Id::new(&row.root_id).map_err(|_| internal(ev, "tenant_root_id_invalid"))?;
    let admin = c.masters.admin().await?;
    // Nothing leaves without a durable record that it was asked for; the reply is withheld
    // again if the outcome record fails (`finish`).
    attempt(c, ev).await?;
    let raw = admin
        .export_root(&row.wrap_key, &row.wrapped_root, &row.id, &root_id)
        .await
        .map_err(|_| internal(ev, "tenant_export_failed"))?;
    // Exactly 44 characters: no reallocation leaves a copy behind. The reply zeroizes its own
    // copy when dropped.
    let mut key = Zeroizing::new(String::with_capacity(44));
    STANDARD.encode_string(&raw[..], &mut key);
    Ok(Reply::data(
        json!({ "root_id": row.root_id, "root_key": key.as_str() }),
    ))
}
