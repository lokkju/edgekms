//! The hosted tier's tenant store: users, tenants (config, wrapped root key, status), members
//! and the control plane's own wrapped root, behind the [`TenantStore`] trait so the cache and
//! the control plane are tested against an in-memory store. [`D1Store`] is the D1
//! implementation (schema in `migrations/`), with prepared statements and bound
//! parameters only.
//!
//! Optimistic concurrency: a config edit names the version it read and loses (`Conflict`) if
//! someone else's edit landed first; a rewrap names the master version it read the row under.
//! Membership changes name the MAC of the row they replace, and a last-owner check names the
//! other owner row it relied on ([`Witness`]), both checked in the same statement as the
//! change; the store never verifies a MAC itself.

use std::cell::OnceCell;

use js_sys::Uint8Array;
use serde::Deserialize;
use wasm_bindgen::JsValue;
use worker::{D1DatabaseSession, D1PreparedStatement, D1Result, D1SessionConstraint};

use crate::vault::log_internal;

/// One `tenants` row as the data plane and control plane use it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRow {
    /// `t_<16 hex>`, immutable; in the wrap AAD, the config MAC input and audit keys.
    pub id: String,
    pub name: String,
    pub root_id: String,
    /// `iv[12] || ct[32] || tag[16]`.
    pub wrapped_root: Vec<u8>,
    /// The master version that wrapped it (`m1`).
    pub wrap_key: String,
    /// Compact JSON.
    pub config: String,
    pub config_version: u64,
    /// HMAC under `mac/config/v1` of `config_mac_input(id, name, config_version, config)`.
    pub config_mac: Vec<u8>,
    pub status: TenantStatus,
}

/// Whether a tenant is served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantStatus {
    Active,
    Suspended,
}

/// A member's control-plane role on a tenant. Data-plane access comes from the tenant config's
/// roles, not from this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberRole {
    /// Edits config, manages members, exports the root.
    Owner,
    /// Reads only.
    Member,
}

/// One `members` row: an accepted membership. The store never checks `mac`; the control plane
/// verifies it under its own root on every read and treats a row that fails as absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberRow {
    pub github_id: u64,
    pub role: MemberRole,
    /// Display only; not covered by the MAC.
    pub added_by: u64,
    /// When the row took its current role (Unix milliseconds).
    pub added_ms: u64,
    /// HMAC under `mac/member/v1` of `member_mac_input(tenant_id, github_id, role, added_ms)`.
    pub mac: Vec<u8>,
}

/// One `invites` row: a pending membership, which grants nothing until it is accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteRow {
    pub github_id: u64,
    pub role: MemberRole,
    pub invited_by: u64,
    /// Unix milliseconds.
    pub invited_ms: u64,
    /// HMAC under `mac/invite/v1` of
    /// `invite_mac_input(tenant_id, github_id, role, invited_by, invited_ms)`.
    pub mac: Vec<u8>,
}

/// One `signup_allowlist` row: a GitHub user an operator lets sign up while `SIGNUP_MODE` is
/// `invite`. The store never checks `mac`; the control plane verifies it under its own root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowRow {
    pub github_id: u64,
    /// The operator who added it.
    pub added_by: u64,
    /// Unix milliseconds.
    pub added_ms: u64,
    /// HMAC under `mac/allow/v1` of `allow_mac_input(github_id, added_by, added_ms)`.
    pub mac: Vec<u8>,
}

/// Where an invite request stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestStatus {
    Pending,
    Approved,
    Declined,
}

impl RequestStatus {
    /// The text the `status` column holds.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Declined => "declined",
        }
    }
}

/// One `invite_requests` row: a refused user's request for an invite (lokkju/edgekms#12). The
/// store never checks `mac`; the control plane verifies it under its own root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteRequestRow {
    pub github_id: u64,
    /// The GitHub login when the request was filed. Display only.
    pub login: String,
    /// Plain text the control plane validated (`edgekms_core::hosted::invite_note`).
    pub note: String,
    /// Unix milliseconds.
    pub created_ms: u64,
    pub status: RequestStatus,
    /// The operator who decided; `None` while pending.
    pub decided_by: Option<u64>,
    pub decided_ms: Option<u64>,
    /// HMAC under `mac/invite-request/v1` of
    /// `invite_request_mac_input(github_id, created_ms, login, note)`.
    pub mac: Vec<u8>,
}

/// One `ssh_keys` row: an SSH key that can log in to the control plane as `github_id`
/// (lokkju/edgekms#16). The store never checks `mac`; the control plane verifies it under its
/// own root and treats a row that fails as absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshKeyRow {
    /// `SHA256:` and the unpadded base64 of the key blob's SHA-256; the primary key.
    pub fingerprint: String,
    pub github_id: u64,
    /// `ssh-ed25519`, `sk-ssh-ed25519@openssh.com` or `ecdsa-sha2-nistp256`.
    pub key_type: String,
    /// `<type> <base64>`, without a comment.
    pub public_key: String,
    pub label: String,
    /// Unix milliseconds.
    pub added_ms: u64,
    /// `github`, or `ssh:<fingerprint>` naming the key behind the session that added it.
    pub added_via: String,
    /// The last SSH login with this key (Unix milliseconds). Display only; not MAC'd.
    pub last_used_ms: Option<u64>,
    /// HMAC under `mac/ssh-key/v1` of
    /// `ssh_key_mac_input(github_id, added_ms, fingerprint, public_key, label, added_via)`.
    pub mac: Vec<u8>,
}

/// [`TenantStore::ssh_key`]'s answer: the row and its user's stored GitHub login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshKeyLookup {
    pub row: SshKeyRow,
    /// `users.login`, display only.
    pub login: String,
}

/// A membership or invite row with the tenant it belongs to, for the listings by user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRow<T> {
    pub tenant_id: String,
    pub name: String,
    pub row: T,
}

/// The other owner a last-owner check relied on, as the control plane read and verified it.
/// A demotion or removal guarded by a witness applies only while that exact owner row (same
/// user, `added_ms` and MAC, role `owner`) is still stored, checked in the same statement as
/// the change, so the rule counts only owner rows that verify even under concurrent changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Witness<'a> {
    pub github_id: u64,
    pub added_ms: u64,
    pub mac: &'a [u8],
}

/// The cheap read the tenant cache revalidates with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantVersion {
    pub id: String,
    pub config_version: u64,
    pub status: TenantStatus,
    pub wrap_key: String,
}

/// A row a master rewrap pass moves: enough to rebuild its AAD and rewrap it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedRoot {
    /// The tenant id.
    pub id: String,
    pub root_id: String,
    pub wrapped_root: Vec<u8>,
}

/// One `system_keys` row: a root the service itself uses (`control`, the control plane's token
/// root), wrapped like a tenant's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemKeyRow {
    pub name: String,
    pub root_id: String,
    pub wrapped_root: Vec<u8>,
    pub wrap_key: String,
    pub created_ms: u64,
}

/// Why a store call failed. `Backend` carries a fixed label, never a value or a SQL error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    #[error("not found")]
    NotFound,
    /// An optimistic-concurrency check failed (`config_version`, `wrap_key`, a membership or
    /// invite row's MAC, a [`Witness`]).
    #[error("conflict")]
    Conflict,
    #[error("tenant name already in use")]
    NameTaken,
    #[error("root id already in use")]
    RootIdTaken,
    /// [`TenantStore::create_tenant_capped`]: the user has already created as many tenants
    /// as the cap allows.
    #[error("tenant cap reached")]
    CapReached,
    #[error("tenant store: {0}")]
    Backend(&'static str),
}

/// Everything the hosted data plane and control plane read and write. The in-memory store in
/// `tests/common/memstore.rs` is the reference for each method's contract.
#[allow(async_fn_in_trait)]
pub trait TenantStore {
    /// The revalidation read: id, config version, status and wrap key, or `None` for an
    /// unknown name.
    async fn tenant_version(&self, name: &str) -> Result<Option<TenantVersion>, StoreError>;

    async fn tenant_by_name(&self, name: &str) -> Result<Option<TenantRow>, StoreError>;

    /// The tenant plus `owner`'s owner membership in one transaction (`created_by` is `owner`).
    /// The membership row is `owner`, added by `owner` at `now_ms`, with `owner_mac`.
    /// `NameTaken` / `RootIdTaken` from the unique constraints.
    async fn create_tenant(
        &self,
        row: &TenantRow,
        owner: u64,
        now_ms: u64,
        owner_mac: &[u8],
    ) -> Result<(), StoreError>;

    /// [`TenantStore::create_tenant`], but only while `owner` has created fewer than
    /// `max_created` tenants (`created_by`), checked in the same transaction as the insert so
    /// concurrent creates can't overshoot; `CapReached` otherwise. A `max_created` of 1 claims
    /// a user's personal tenant exactly once.
    async fn create_tenant_capped(
        &self,
        row: &TenantRow,
        owner: u64,
        now_ms: u64,
        owner_mac: &[u8],
        max_created: u64,
    ) -> Result<(), StoreError>;

    /// The user's `tokens_after_ms` (control tokens issued before it are refused), or `None`
    /// for an unknown user.
    async fn tokens_after(&self, github_id: u64) -> Result<Option<u64>, StoreError>;

    /// Raises the user's `tokens_after_ms` to `ms` (never lowers it). `NotFound` for an
    /// unknown user.
    async fn set_tokens_after(&self, github_id: u64, ms: u64) -> Result<(), StoreError>;

    /// Creates or replaces the pending invite `row` (for `row.github_id`) to `tenant_id`.
    /// `NotFound` for an unknown tenant. An invite grants nothing until it is accepted.
    async fn invite(&self, tenant_id: &str, row: &InviteRow) -> Result<(), StoreError>;

    /// A tenant's pending invites, by GitHub id.
    async fn invites(&self, tenant_id: &str) -> Result<Vec<InviteRow>, StoreError>;

    /// The pending invites to a user, with each tenant's id and name, by name.
    async fn invites_for_user(&self, github_id: u64)
    -> Result<Vec<UserRow<InviteRow>>, StoreError>;

    /// Accepts an invite in one transaction: stores `member` (for `member.github_id`) as the
    /// user's membership, replacing any existing one, and removes the invite. Applies only
    /// while the invite's MAC is still `invite_mac` and the user's current membership row's
    /// MAC is still `current` (`None`: no membership row). `NotFound` if no invite is stored;
    /// `Conflict` if it was replaced or the membership changed.
    async fn accept_invite(
        &self,
        tenant_id: &str,
        invite_mac: &[u8],
        current: Option<&[u8]>,
        member: &MemberRow,
    ) -> Result<(), StoreError>;

    /// Removes a pending invite (declined or withdrawn) while its MAC is still `mac`.
    /// `NotFound` for no such invite; `Conflict` if it was replaced.
    async fn delete_invite(
        &self,
        tenant_id: &str,
        github_id: u64,
        mac: &[u8],
    ) -> Result<(), StoreError>;

    /// Up to `limit` tenants wrapped under `wrap_key` with an id after `after_id` (`""` for
    /// the start), in id order, so a rewrap pass pages past rows it couldn't move.
    async fn rows_wrapped_after(
        &self,
        wrap_key: &str,
        after_id: &str,
        limit: u32,
    ) -> Result<Vec<WrappedRoot>, StoreError>;

    /// Replaces the config if its version is still `expected_version`; returns the new
    /// version. `Conflict` if it isn't.
    async fn update_config(
        &self,
        id: &str,
        expected_version: u64,
        config: &str,
        mac: &[u8],
        now_ms: u64,
    ) -> Result<u64, StoreError>;

    async fn upsert_user(&self, github_id: u64, login: &str, now_ms: u64)
    -> Result<(), StoreError>;

    /// The user's membership rows, with each tenant's id and name, by name.
    async fn tenants_for_user(&self, github_id: u64)
    -> Result<Vec<UserRow<MemberRow>>, StoreError>;

    /// Tenants created by the user (`created_by`), whether or not they still own them; the
    /// personal tenant is created only while this is 0.
    async fn count_created(&self, github_id: u64) -> Result<u64, StoreError>;

    /// A tenant's membership rows, by GitHub id.
    async fn members(&self, tenant_id: &str) -> Result<Vec<MemberRow>, StoreError>;

    /// The user's membership row on the tenant, if any.
    async fn member(
        &self,
        tenant_id: &str,
        github_id: u64,
    ) -> Result<Option<MemberRow>, StoreError>;

    /// Stores `row` as `row.github_id`'s membership, adding or replacing it, while the current
    /// row's MAC is still `current` (`None`: no row); with a `witness`, while that owner row
    /// other than `row.github_id` is still stored unchanged; and with an `actor`, while the
    /// acting owner's own row is still stored unchanged, so an owner removed or demoted
    /// mid-request can't complete the write. `NotFound` for an unknown tenant; `Conflict` if a
    /// condition failed.
    async fn set_member(
        &self,
        tenant_id: &str,
        row: &MemberRow,
        current: Option<&[u8]>,
        witness: Option<Witness<'_>>,
        actor: Option<Witness<'_>>,
    ) -> Result<(), StoreError>;

    /// Removes the membership while its MAC is still `mac`, with the same `witness` and `actor`
    /// conditions as [`TenantStore::set_member`]. `NotFound` for no such membership;
    /// `Conflict` if a condition failed.
    async fn remove_member(
        &self,
        tenant_id: &str,
        github_id: u64,
        mac: &[u8],
        witness: Option<Witness<'_>>,
        actor: Option<Witness<'_>>,
    ) -> Result<(), StoreError>;

    /// Up to `limit` tenants whose root is wrapped under `wrap_key`.
    async fn rows_wrapped_with(
        &self,
        wrap_key: &str,
        limit: u32,
    ) -> Result<Vec<WrappedRoot>, StoreError>;

    /// Stores a rewrapped root if the row is still wrapped under `old_wrap_key`; `Conflict` if
    /// it isn't.
    async fn set_wrapped(
        &self,
        id: &str,
        old_wrap_key: &str,
        new_wrapped: &[u8],
        new_wrap_key: &str,
    ) -> Result<(), StoreError>;

    async fn set_status(&self, id: &str, status: TenantStatus) -> Result<(), StoreError>;

    async fn system_key(&self, name: &str) -> Result<Option<SystemKeyRow>, StoreError>;

    /// Whether any `tenants`, `members`, `signup_allowlist`, `invite_requests` or `ssh_keys` row
    /// exists. The control plane
    /// creates its root only while this is false: once rows are sealed under a root, a missing
    /// root row means it was lost, not that none was ever made.
    async fn holds_tenants(&self) -> Result<bool, StoreError>;

    /// Adds `row` to the signup allowlist, replacing any row for the same GitHub id.
    async fn allow_signup(&self, row: &AllowRow) -> Result<(), StoreError>;

    /// The signup allowlist row for `github_id`, if any. A row that doesn't parse is absent.
    async fn allowed_signup(&self, github_id: u64) -> Result<Option<AllowRow>, StoreError>;

    /// Every signup allowlist row, by GitHub id. Rows that don't parse are skipped.
    async fn allowlist(&self) -> Result<Vec<AllowRow>, StoreError>;

    /// Removes `github_id` from the signup allowlist; `NotFound` if it holds no row.
    async fn disallow_signup(&self, github_id: u64) -> Result<(), StoreError>;

    /// The invite request of `github_id`, if any. A row that doesn't parse is absent.
    async fn invite_request(&self, github_id: u64) -> Result<Option<InviteRequestRow>, StoreError>;

    /// Stores `row` as a pending request if fewer than `max_pending` requests are pending, the
    /// count and the insert being one statement, so concurrent requests can't overshoot.
    /// `CapReached` when the cap stopped it; `Conflict` if `row.github_id` already has a row.
    async fn insert_invite_request(
        &self,
        row: &InviteRequestRow,
        max_pending: u64,
    ) -> Result<(), StoreError>;

    /// Replaces the request of `row.github_id` with `row`, pending and undecided, only while
    /// its stored MAC is `old_mac` and fewer than `max_pending` other requests are pending.
    /// `Conflict` if the row is gone or its MAC changed; `CapReached` if only the cap stopped it.
    async fn replace_invite_request(
        &self,
        row: &InviteRequestRow,
        old_mac: &[u8],
        max_pending: u64,
    ) -> Result<(), StoreError>;

    /// Every pending request by `created_ms`, then up to `decided_limit` decided ones, the most
    /// recently decided first. Rows that don't parse are skipped.
    async fn invite_requests(
        &self,
        decided_limit: u32,
    ) -> Result<Vec<InviteRequestRow>, StoreError>;

    /// Decides the pending request of `github_id` whose MAC is `expected_mac` as `status`
    /// (`Approved` or `Declined`), by operator `decided_by` at `decided_ms`; with `allow`, in
    /// the same transaction, upserts that signup allowlist row, conditional on the decision
    /// having landed. `Conflict` (and nothing written) if no pending row with that MAC exists.
    async fn decide_invite_request(
        &self,
        github_id: u64,
        expected_mac: &[u8],
        status: RequestStatus,
        decided_by: u64,
        decided_ms: u64,
        allow: Option<&AllowRow>,
    ) -> Result<(), StoreError>;

    /// Removes the request of `github_id`, whatever its status; `NotFound` if there is none.
    async fn delete_invite_request(&self, github_id: u64) -> Result<(), StoreError>;

    /// Inserts `row` unless a row with its name exists (`INSERT OR IGNORE`), then returns the
    /// stored row, so two isolates racing to create one agree on it.
    async fn insert_system_key_if_absent(
        &self,
        row: &SystemKeyRow,
    ) -> Result<SystemKeyRow, StoreError>;

    /// [`TenantStore::set_wrapped`] for a `system_keys` row.
    async fn set_system_wrapped(
        &self,
        name: &str,
        old_wrap_key: &str,
        new_wrapped: &[u8],
        new_wrap_key: &str,
    ) -> Result<(), StoreError>;

    /// The SSH key row with `fingerprint` and its user's login, if any. A row that doesn't
    /// parse is absent.
    async fn ssh_key(&self, fingerprint: &str) -> Result<Option<SshKeyLookup>, StoreError>;

    /// Every SSH key row of `github_id`, by `added_ms`. Rows that don't parse are skipped.
    async fn ssh_keys_for_user(&self, github_id: u64) -> Result<Vec<SshKeyRow>, StoreError>;

    /// Stores `row` if its user holds fewer than `max` keys, the count and the insert being one
    /// statement. `Conflict` if the fingerprint is stored already (for anyone); `CapReached`
    /// when the cap stopped it; a backend error for a user with no `users` row.
    async fn insert_ssh_key(&self, row: &SshKeyRow, max: u64) -> Result<(), StoreError>;

    /// Removes the key `fingerprint` of `github_id`; `NotFound` if that user holds no such key
    /// (another user's key with that fingerprint stays).
    async fn delete_ssh_key(&self, github_id: u64, fingerprint: &str) -> Result<(), StoreError>;

    /// In one transaction, removes every SSH key of `github_id` and raises their
    /// `tokens_after_ms` to `now_ms` (never lowers it). Returns how many keys went; `NotFound`
    /// for an unknown user.
    async fn revoke_user_ssh_keys(&self, github_id: u64, now_ms: u64) -> Result<u64, StoreError>;

    /// Records the challenge `tag` as used until `expires_ms`, purging rows that expired before
    /// `now_ms` in the same transaction. `Conflict` if the tag is recorded already: a replay.
    async fn consume_challenge(
        &self,
        tag: &[u8],
        expires_ms: u64,
        now_ms: u64,
    ) -> Result<(), StoreError>;

    /// After an SSH login: the user's `last_login_ms` and the key's `last_used_ms` (only if
    /// the key is that user's) become `now_ms`.
    async fn ssh_login_used(
        &self,
        github_id: u64,
        fingerprint: &str,
        now_ms: u64,
    ) -> Result<(), StoreError>;

    /// What a control token check needs in one read: the user's `tokens_after_ms` and, with a
    /// `fingerprint`, that user's key row with it (`None` if they hold no such key). `None` for
    /// an unknown user.
    async fn token_state(
        &self,
        github_id: u64,
        fingerprint: Option<&str>,
    ) -> Result<Option<(u64, Option<SshKeyRow>)>, StoreError>;
}

/// [`TenantStore`] on the `TENANTS` D1 binding.
///
/// Every statement is prepared with bound parameters. BLOBs bind as `Uint8Array` (D1 takes an
/// `ArrayBuffer` or a view; workers-rs's `D1Type::Blob` would bind a plain JS Array, which D1
/// doesn't list) and read back as an Array of numbers. Integers bind as JS numbers, so every
/// one must be at most 2^53 - 1; anything larger is refused before it reaches D1.
///
/// The two data-plane reads ([`TenantStore::tenant_version`] and
/// [`TenantStore::tenant_by_name`]) go through one `first-unconstrained` session, opened on the
/// first of them and kept for the store's life, so a read replica can answer them and the row
/// read sees at least what the version read saw. Build one `D1Store` per request: a store kept
/// across requests would pin its session's view of the database. Everything else goes to the
/// primary. [`D1Store::primary`] sends those two reads to the primary as well, for the
/// control plane, which must read its own writes.
pub struct D1Store {
    db: worker::D1Database,
    /// The data-plane read session; `Some(None)` if the runtime has no sessions.
    replica: OnceCell<Option<D1DatabaseSession>>,
    /// Never use the replica session.
    primary_only: bool,
}

/// The largest integer a JS number holds exactly.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

fn backend(label: &'static str) -> StoreError {
    log_internal(label);
    StoreError::Backend(label)
}

/// The error text D1 returned, for matching constraint names. Never logged or returned.
fn error_text(e: &worker::Error) -> String {
    match e {
        worker::Error::D1(d1) => {
            let js: &js_sys::Error = d1.as_ref();
            format!("{} {}", String::from(js.message()), d1.cause())
        }
        other => other.to_string(),
    }
}

/// A D1 failure we didn't anticipate, logged as `label`.
fn failed(label: &'static str) -> impl FnOnce(worker::Error) -> StoreError {
    move |_| backend(label)
}

fn text(s: &str) -> JsValue {
    JsValue::from_str(s)
}

fn blob(b: &[u8]) -> JsValue {
    Uint8Array::from(b).into()
}

fn int(n: u64) -> Result<JsValue, StoreError> {
    if n > MAX_SAFE_INTEGER {
        return Err(backend("d1_integer_out_of_range"));
    }
    // Exact: `n` fits in an f64's 53-bit mantissa.
    #[allow(clippy::cast_precision_loss)]
    Ok(JsValue::from_f64(n as f64))
}

fn status_text(s: TenantStatus) -> &'static str {
    match s {
        TenantStatus::Active => "active",
        TenantStatus::Suspended => "suspended",
    }
}

fn parse_status(s: &str) -> Result<TenantStatus, StoreError> {
    match s {
        "active" => Ok(TenantStatus::Active),
        "suspended" => Ok(TenantStatus::Suspended),
        _ => Err(backend("d1_bad_status")),
    }
}

fn parse_request_status(s: &str) -> Result<RequestStatus, StoreError> {
    match s {
        "pending" => Ok(RequestStatus::Pending),
        "approved" => Ok(RequestStatus::Approved),
        "declined" => Ok(RequestStatus::Declined),
        _ => Err(StoreError::Backend("d1_bad_request_status")),
    }
}

fn role_text(r: MemberRole) -> &'static str {
    match r {
        MemberRole::Owner => "owner",
        MemberRole::Member => "member",
    }
}

fn parse_role(s: &str) -> Result<MemberRole, StoreError> {
    match s {
        "owner" => Ok(MemberRole::Owner),
        "member" => Ok(MemberRole::Member),
        _ => Err(backend("d1_bad_role")),
    }
}

/// A BLOB column: D1 returns an Array of numbers; an `ArrayBuffer` or `Uint8Array` is accepted
/// too, in case a runtime returns one.
#[derive(Debug)]
struct Bytes(Vec<u8>);

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Bytes;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a BLOB")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Bytes, E> {
                Ok(Bytes(v.to_vec()))
            }
            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Bytes, E> {
                Ok(Bytes(v))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Bytes, A::Error> {
                let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                while let Some(b) = seq.next_element::<u8>()? {
                    out.push(b);
                }
                Ok(Bytes(out))
            }
        }
        d.deserialize_byte_buf(V)
    }
}

#[derive(Deserialize)]
struct VersionCols {
    id: String,
    config_version: u64,
    status: String,
    wrap_key: String,
}

#[derive(Deserialize)]
struct TenantCols {
    id: String,
    name: String,
    root_id: String,
    wrapped_root: Bytes,
    wrap_key: String,
    config: String,
    config_version: u64,
    config_mac: Bytes,
    status: String,
}

#[derive(Deserialize)]
struct MemberCols {
    github_id: u64,
    role: String,
    added_by: u64,
    added_ms: u64,
    mac: Bytes,
}

impl MemberCols {
    fn row(self) -> Result<MemberRow, StoreError> {
        Ok(MemberRow {
            github_id: self.github_id,
            role: parse_role(&self.role)?,
            added_by: self.added_by,
            added_ms: self.added_ms,
            mac: self.mac.0,
        })
    }
}

#[derive(Deserialize)]
struct InviteCols {
    github_id: u64,
    role: String,
    invited_by: u64,
    invited_ms: u64,
    mac: Bytes,
}

impl InviteCols {
    fn row(self) -> Result<InviteRow, StoreError> {
        Ok(InviteRow {
            github_id: self.github_id,
            role: parse_role(&self.role)?,
            invited_by: self.invited_by,
            invited_ms: self.invited_ms,
            mac: self.mac.0,
        })
    }
}

const ALLOW_COLS: &str = "github_id, added_by, added_ms, mac";

#[derive(Deserialize)]
struct AllowCols {
    github_id: u64,
    added_by: u64,
    added_ms: u64,
    mac: Bytes,
}

impl AllowCols {
    // A `Result` to fit `D1Store::rows`; every column already parsed.
    #[allow(clippy::unnecessary_wraps)]
    fn row(self) -> Result<AllowRow, StoreError> {
        Ok(AllowRow {
            github_id: self.github_id,
            added_by: self.added_by,
            added_ms: self.added_ms,
            mac: self.mac.0,
        })
    }
}

const REQUEST_COLS: &str =
    "github_id, login, note, created_ms, status, decided_by, decided_ms, mac";

#[derive(Deserialize)]
struct RequestCols {
    github_id: u64,
    login: String,
    note: String,
    created_ms: u64,
    status: String,
    decided_by: Option<u64>,
    decided_ms: Option<u64>,
    mac: Bytes,
}

impl RequestCols {
    fn row(self) -> Result<InviteRequestRow, StoreError> {
        Ok(InviteRequestRow {
            github_id: self.github_id,
            login: self.login,
            note: self.note,
            created_ms: self.created_ms,
            status: parse_request_status(&self.status)?,
            decided_by: self.decided_by,
            decided_ms: self.decided_ms,
            mac: self.mac.0,
        })
    }
}

const SSH_KEY_COLS: &str =
    "fingerprint, github_id, key_type, public_key, label, added_ms, added_via, last_used_ms, mac";

#[derive(Deserialize)]
struct SshKeyCols {
    fingerprint: String,
    github_id: u64,
    key_type: String,
    public_key: String,
    label: String,
    added_ms: u64,
    added_via: String,
    last_used_ms: Option<u64>,
    mac: Bytes,
}

impl SshKeyCols {
    // A `Result` to fit `D1Store::rows`; every column already parsed.
    #[allow(clippy::unnecessary_wraps)]
    fn row(self) -> Result<SshKeyRow, StoreError> {
        Ok(SshKeyRow {
            fingerprint: self.fingerprint,
            github_id: self.github_id,
            key_type: self.key_type,
            public_key: self.public_key,
            label: self.label,
            added_ms: self.added_ms,
            added_via: self.added_via,
            last_used_ms: self.last_used_ms,
            mac: self.mac.0,
        })
    }
}

/// [`SshKeyCols`] and the user's login, for [`TenantStore::ssh_key`].
#[derive(Deserialize)]
struct SshKeyLoginCols {
    fingerprint: String,
    github_id: u64,
    key_type: String,
    public_key: String,
    label: String,
    added_ms: u64,
    added_via: String,
    last_used_ms: Option<u64>,
    mac: Bytes,
    login: String,
}

impl SshKeyLoginCols {
    fn row(self) -> Result<SshKeyLookup, StoreError> {
        Ok(SshKeyLookup {
            login: self.login,
            row: SshKeyCols {
                fingerprint: self.fingerprint,
                github_id: self.github_id,
                key_type: self.key_type,
                public_key: self.public_key,
                label: self.label,
                added_ms: self.added_ms,
                added_via: self.added_via,
                last_used_ms: self.last_used_ms,
                mac: self.mac,
            }
            .row()?,
        })
    }
}

/// [`TenantStore::token_state`]'s row: the user's cutoff, and the key's columns, all `NULL`
/// when no key joined.
#[derive(Deserialize)]
struct TokenStateCols {
    tokens_after_ms: u64,
    fingerprint: Option<String>,
}

/// A by-user membership listing row: the tenant's id and name, then the membership columns.
/// (Spelled out, not `#[serde(flatten)]`, which would buffer D1's JS numbers through serde's
/// untyped content.)
#[derive(Deserialize)]
struct UserMemberCols {
    tenant_id: String,
    name: String,
    github_id: u64,
    role: String,
    added_by: u64,
    added_ms: u64,
    mac: Bytes,
}

impl UserMemberCols {
    fn row(self) -> Result<UserRow<MemberRow>, StoreError> {
        Ok(UserRow {
            tenant_id: self.tenant_id,
            name: self.name,
            row: MemberCols {
                github_id: self.github_id,
                role: self.role,
                added_by: self.added_by,
                added_ms: self.added_ms,
                mac: self.mac,
            }
            .row()?,
        })
    }
}

/// [`UserMemberCols`] for invites.
#[derive(Deserialize)]
struct UserInviteCols {
    tenant_id: String,
    name: String,
    github_id: u64,
    role: String,
    invited_by: u64,
    invited_ms: u64,
    mac: Bytes,
}

impl UserInviteCols {
    fn row(self) -> Result<UserRow<InviteRow>, StoreError> {
        Ok(UserRow {
            tenant_id: self.tenant_id,
            name: self.name,
            row: InviteCols {
                github_id: self.github_id,
                role: self.role,
                invited_by: self.invited_by,
                invited_ms: self.invited_ms,
                mac: self.mac,
            }
            .row()?,
        })
    }
}

const MEMBER_COLS: &str = "github_id, role, added_by, added_ms, mac";
const INVITE_COLS: &str = "github_id, role, invited_by, invited_ms, mac";

#[derive(Deserialize)]
struct WrappedCols {
    id: String,
    root_id: String,
    wrapped_root: Bytes,
}

#[derive(Deserialize)]
struct SystemKeyCols {
    name: String,
    root_id: String,
    wrapped_root: Bytes,
    wrap_key: String,
    created_ms: u64,
}

impl From<SystemKeyCols> for SystemKeyRow {
    fn from(c: SystemKeyCols) -> Self {
        Self {
            name: c.name,
            root_id: c.root_id,
            wrapped_root: c.wrapped_root.0,
            wrap_key: c.wrap_key,
            created_ms: c.created_ms,
        }
    }
}

#[derive(Deserialize)]
struct Count {
    n: u64,
}

impl D1Store {
    /// `sql` with `args` bound, on the primary.
    /// A store on `db`, the `TENANTS` binding. One per request.
    #[must_use]
    pub fn new(db: worker::D1Database) -> Self {
        Self {
            db,
            replica: OnceCell::new(),
            primary_only: false,
        }
    }

    /// A store whose every read goes to the primary: the control plane's, which must read its
    /// own writes. One per request.
    #[must_use]
    pub fn primary(db: worker::D1Database) -> Self {
        Self {
            db,
            replica: OnceCell::new(),
            primary_only: true,
        }
    }

    /// Whether this store reads only from the primary.
    #[must_use]
    pub fn is_primary_only(&self) -> bool {
        self.primary_only
    }

    fn stmt(&self, sql: &str, args: &[JsValue]) -> Result<D1PreparedStatement, StoreError> {
        self.db
            .prepare(sql)
            .bind(args)
            .map_err(failed("d1_bind_failed"))
    }

    /// `sql` with `args` bound, in this store's `first-unconstrained` session (nearest replica).
    /// Falls back to the primary if the runtime has no sessions.
    fn replica_stmt(&self, sql: &str, args: &[JsValue]) -> Result<D1PreparedStatement, StoreError> {
        if self.primary_only {
            return self.stmt(sql, args);
        }
        let session = self.replica.get_or_init(|| {
            self.db
                .with_session_constraint(D1SessionConstraint::FirstUnconstrained)
                .ok()
        });
        match session {
            Some(session) => session
                .prepare(sql)
                .bind(args)
                .map_err(failed("d1_bind_failed")),
            None => self.stmt(sql, args),
        }
    }

    async fn first<T: for<'a> Deserialize<'a>>(
        stmt: D1PreparedStatement,
    ) -> Result<Option<T>, StoreError> {
        stmt.first(None).await.map_err(failed("d1_read_failed"))
    }

    /// The rows of a membership or invite read, each parsed and converted on its own: a row
    /// that doesn't parse is skipped and logged as `label`, so one bad row (a negative
    /// integer, a mac that isn't a BLOB, an unknown role) counts as absent, as a row that
    /// doesn't verify does, instead of failing the whole read.
    async fn rows<C: for<'a> Deserialize<'a>, T>(
        stmt: D1PreparedStatement,
        label: &'static str,
        convert: impl Fn(C) -> Result<T, StoreError>,
    ) -> Result<Vec<T>, StoreError> {
        let raw: Vec<serde_json::Value> = Self::all(stmt).await?;
        Ok(raw
            .into_iter()
            .filter_map(|v| {
                let row = serde_json::from_value::<C>(v)
                    .map_err(|_| StoreError::Backend(label))
                    .and_then(&convert);
                if row.is_err() {
                    log_internal(label);
                }
                row.ok()
            })
            .collect())
    }

    async fn all<T: for<'a> Deserialize<'a>>(
        stmt: D1PreparedStatement,
    ) -> Result<Vec<T>, StoreError> {
        stmt.all()
            .await
            .map_err(failed("d1_read_failed"))?
            .results()
            .map_err(failed("d1_read_failed"))
    }

    /// Runs a write and returns how many rows it changed.
    async fn changes(
        stmt: D1PreparedStatement,
        on_err: impl FnOnce(&worker::Error) -> StoreError,
    ) -> Result<usize, StoreError> {
        let result = stmt.run().await.map_err(|e| on_err(&e))?;
        changes_of(&result)
    }

    async fn tenant_exists(&self, id: &str) -> Result<bool, StoreError> {
        let stmt = self.stmt("SELECT 1 AS n FROM tenants WHERE id = ?1", &[text(id)])?;
        Ok(Self::first::<Count>(stmt).await?.is_some())
    }

    async fn system_key_exists(&self, name: &str) -> Result<bool, StoreError> {
        let stmt = self.stmt(
            "SELECT 1 AS n FROM system_keys WHERE name = ?1",
            &[text(name)],
        )?;
        Ok(Self::first::<Count>(stmt).await?.is_some())
    }

    /// The tenant and its owner's membership in one batch, which D1 runs as one transaction.
    /// With `max_created`, both inserts are conditional: the tenant on `owner`'s `created_by`
    /// count being under the cap, the membership on the tenant row existing. The cap check and
    /// the write are therefore atomic, and a skipped insert is `CapReached`.
    async fn insert_tenant(
        &self,
        row: &TenantRow,
        owner: u64,
        now_ms: u64,
        owner_mac: &[u8],
        max_created: Option<u64>,
    ) -> Result<(), StoreError> {
        let mut args = vec![
            text(&row.id),
            text(&row.name),
            text(&row.root_id),
            blob(&row.wrapped_root),
            text(&row.wrap_key),
            text(&row.config),
            int(row.config_version)?,
            blob(&row.config_mac),
            text(status_text(row.status)),
            int(owner)?,
            int(now_ms)?,
        ];
        let tenant_sql = if let Some(max) = max_created {
            args.push(int(max)?);
            "INSERT INTO tenants (id, name, root_id, wrapped_root, wrap_key, config, \
             config_version, config_mac, status, created_by, created_ms, updated_ms) \
             SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11 \
             WHERE (SELECT count(*) FROM tenants WHERE created_by = ?10) < ?12"
        } else {
            "INSERT INTO tenants (id, name, root_id, wrapped_root, wrap_key, config, \
             config_version, config_mac, status, created_by, created_ms, updated_ms) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11)"
        };
        let tenant = self.stmt(tenant_sql, &args)?;
        let member = self.stmt(
            "INSERT INTO members (tenant_id, github_id, role, added_by, added_ms, mac) \
             SELECT ?1, ?2, 'owner', ?2, ?3, ?4 \
             WHERE EXISTS (SELECT 1 FROM tenants WHERE id = ?1)",
            &[text(&row.id), int(owner)?, int(now_ms)?, blob(owner_mac)],
        )?;
        match self.db.batch(vec![tenant, member]).await {
            Ok(results) => {
                let inserted = match results.first() {
                    Some(r) => changes_of(r)?,
                    None => return Err(backend("d1_meta_missing")),
                };
                if inserted == 1 {
                    Ok(())
                } else {
                    Err(StoreError::CapReached)
                }
            }
            Err(e) => {
                let msg = error_text(&e);
                Err(if msg.contains("tenants.name") {
                    StoreError::NameTaken
                } else if msg.contains("tenants.root_id") {
                    StoreError::RootIdTaken
                } else if msg.contains("tenants.id") {
                    StoreError::Conflict
                } else if msg.contains("FOREIGN KEY") {
                    StoreError::Backend("unknown_user")
                } else {
                    backend("d1_write_failed")
                })
            }
        }
    }

    async fn count(&self, sql: &str, github_id: u64) -> Result<u64, StoreError> {
        let stmt = self.stmt(sql, &[int(github_id)?])?;
        Ok(Self::first::<Count>(stmt).await?.map_or(0, |c| c.n))
    }

    /// Why a write conditional on an invite's MAC didn't apply: `Conflict` if an invite for
    /// the user is still stored (replaced, or the other conditions failed), else `NotFound`.
    async fn invite_gone_or_replaced(
        &self,
        tenant_id: &str,
        github_id: u64,
    ) -> Result<StoreError, StoreError> {
        let stored = self
            .exists(
                "SELECT 1 AS n FROM invites WHERE tenant_id = ?1 AND github_id = ?2",
                &[text(tenant_id), int(github_id)?],
            )
            .await?;
        Ok(if stored {
            StoreError::Conflict
        } else {
            StoreError::NotFound
        })
    }

    async fn exists(&self, sql: &str, args: &[JsValue]) -> Result<bool, StoreError> {
        let stmt = self.stmt(sql, args)?;
        Ok(Self::first::<Count>(stmt).await?.is_some())
    }
}

/// An optional BLOB: SQL `NULL` for `None`.
fn opt_blob(b: Option<&[u8]>) -> JsValue {
    b.map_or(JsValue::NULL, blob)
}

/// A [`Witness`]'s three bound values; all `NULL` for none, which the guarded statements read
/// as "no other owner needed".
fn witness_args(w: Option<Witness<'_>>) -> Result<[JsValue; 3], StoreError> {
    Ok(match w {
        Some(w) => [int(w.github_id)?, int(w.added_ms)?, blob(w.mac)],
        None => [JsValue::NULL, JsValue::NULL, JsValue::NULL],
    })
}

/// A [`Witness`] condition on parameters `?w`, `?w+1`, `?w+2` (github id, `added_ms`, MAC):
/// none given, or that exact owner row is still stored. With `other`, the row must also be a
/// user other than the target at `?2` (the last-owner witness); without, it may be the target
/// (the acting owner, who may be changing their own row).
fn witness_sql(w: usize, other: bool) -> String {
    let not_target = if other { "AND o.github_id != ?2 " } else { "" };
    format!(
        "(?{w} IS NULL OR EXISTS (SELECT 1 FROM members o WHERE o.tenant_id = ?1 \
         AND o.github_id = ?{w} {not_target}AND o.role = 'owner' \
         AND o.added_ms = ?{a} AND o.mac = ?{m}))",
        a = w + 1,
        m = w + 2
    )
}

fn changes_of(result: &D1Result) -> Result<usize, StoreError> {
    result
        .meta()
        .map_err(failed("d1_meta_missing"))?
        .and_then(|m| m.changes)
        .ok_or_else(|| backend("d1_meta_missing"))
}

/// A write failure we don't map to a contract error.
fn write_failed(_: &worker::Error) -> StoreError {
    backend("d1_write_failed")
}

const TENANT_COLS: &str = "id, name, root_id, wrapped_root, wrap_key, config, config_version, \
                           config_mac, status";

impl TenantStore for D1Store {
    async fn tenant_version(&self, name: &str) -> Result<Option<TenantVersion>, StoreError> {
        let stmt = self.replica_stmt(
            "SELECT id, config_version, status, wrap_key FROM tenants WHERE name = ?1",
            &[text(name)],
        )?;
        Self::first::<VersionCols>(stmt)
            .await?
            .map(|c| {
                Ok(TenantVersion {
                    id: c.id,
                    config_version: c.config_version,
                    status: parse_status(&c.status)?,
                    wrap_key: c.wrap_key,
                })
            })
            .transpose()
    }

    async fn tenant_by_name(&self, name: &str) -> Result<Option<TenantRow>, StoreError> {
        let stmt = self.replica_stmt(
            &format!("SELECT {TENANT_COLS} FROM tenants WHERE name = ?1"),
            &[text(name)],
        )?;
        Self::first::<TenantCols>(stmt)
            .await?
            .map(|c| {
                Ok(TenantRow {
                    id: c.id,
                    name: c.name,
                    root_id: c.root_id,
                    wrapped_root: c.wrapped_root.0,
                    wrap_key: c.wrap_key,
                    config: c.config,
                    config_version: c.config_version,
                    config_mac: c.config_mac.0,
                    status: parse_status(&c.status)?,
                })
            })
            .transpose()
    }

    async fn create_tenant(
        &self,
        row: &TenantRow,
        owner: u64,
        now_ms: u64,
        owner_mac: &[u8],
    ) -> Result<(), StoreError> {
        self.insert_tenant(row, owner, now_ms, owner_mac, None)
            .await
    }

    async fn create_tenant_capped(
        &self,
        row: &TenantRow,
        owner: u64,
        now_ms: u64,
        owner_mac: &[u8],
        max_created: u64,
    ) -> Result<(), StoreError> {
        self.insert_tenant(row, owner, now_ms, owner_mac, Some(max_created))
            .await
    }

    async fn tokens_after(&self, github_id: u64) -> Result<Option<u64>, StoreError> {
        let stmt = self.stmt(
            "SELECT tokens_after_ms AS n FROM users WHERE github_id = ?1",
            &[int(github_id)?],
        )?;
        Ok(Self::first::<Count>(stmt).await?.map(|c| c.n))
    }

    async fn set_tokens_after(&self, github_id: u64, ms: u64) -> Result<(), StoreError> {
        let stmt = self.stmt(
            "UPDATE users SET tokens_after_ms = max(tokens_after_ms, ?2) WHERE github_id = ?1",
            &[int(github_id)?, int(ms)?],
        )?;
        if Self::changes(stmt, write_failed).await? == 1 {
            Ok(())
        } else {
            Err(StoreError::NotFound)
        }
    }

    async fn invite(&self, tenant_id: &str, row: &InviteRow) -> Result<(), StoreError> {
        let stmt = self.stmt(
            "INSERT INTO invites (tenant_id, github_id, role, invited_by, invited_ms, mac) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
             ON CONFLICT (tenant_id, github_id) DO UPDATE SET role = excluded.role, \
             invited_by = excluded.invited_by, invited_ms = excluded.invited_ms, \
             mac = excluded.mac",
            &[
                text(tenant_id),
                int(row.github_id)?,
                text(role_text(row.role)),
                int(row.invited_by)?,
                int(row.invited_ms)?,
                blob(&row.mac),
            ],
        )?;
        Self::changes(stmt, |e| {
            if error_text(e).contains("FOREIGN KEY") {
                StoreError::NotFound
            } else {
                write_failed(e)
            }
        })
        .await
        .map(|_| ())
    }

    async fn invites(&self, tenant_id: &str) -> Result<Vec<InviteRow>, StoreError> {
        let stmt = self.stmt(
            &format!("SELECT {INVITE_COLS} FROM invites WHERE tenant_id = ?1 ORDER BY github_id"),
            &[text(tenant_id)],
        )?;
        Self::rows(stmt, "d1_bad_invite_row", InviteCols::row).await
    }

    async fn invites_for_user(
        &self,
        github_id: u64,
    ) -> Result<Vec<UserRow<InviteRow>>, StoreError> {
        let stmt = self.stmt(
            "SELECT i.tenant_id AS tenant_id, t.name AS name, i.github_id AS github_id, \
             i.role AS role, i.invited_by AS invited_by, i.invited_ms AS invited_ms, \
             i.mac AS mac FROM invites i JOIN tenants t ON t.id = i.tenant_id \
             WHERE i.github_id = ?1 ORDER BY t.name",
            &[int(github_id)?],
        )?;
        Self::rows(stmt, "d1_bad_invite_row", UserInviteCols::row).await
    }

    async fn accept_invite(
        &self,
        tenant_id: &str,
        invite_mac: &[u8],
        current: Option<&[u8]>,
        member: &MemberRow,
    ) -> Result<(), StoreError> {
        // Both statements are conditional and run as one transaction. The upsert applies only
        // while the invite is the one read and the membership is the one read (`IS` matches
        // `NULL`, no row, too); the `SELECT`'s `WHERE` is also what lets SQLite parse the
        // upsert clause after it. The delete applies only if the upsert left the new row.
        let add = self.stmt(
            "INSERT INTO members (tenant_id, github_id, role, added_by, added_ms, mac) \
             SELECT ?1, ?2, ?3, ?4, ?5, ?6 \
             WHERE EXISTS (SELECT 1 FROM invites WHERE tenant_id = ?1 AND github_id = ?2 \
               AND mac = ?7) \
             AND (SELECT mac FROM members WHERE tenant_id = ?1 AND github_id = ?2) IS ?8 \
             ON CONFLICT (tenant_id, github_id) DO UPDATE SET role = excluded.role, \
             added_by = excluded.added_by, added_ms = excluded.added_ms, mac = excluded.mac",
            &[
                text(tenant_id),
                int(member.github_id)?,
                text(role_text(member.role)),
                int(member.added_by)?,
                int(member.added_ms)?,
                blob(&member.mac),
                blob(invite_mac),
                opt_blob(current),
            ],
        )?;
        let remove = self.stmt(
            "DELETE FROM invites WHERE tenant_id = ?1 AND github_id = ?2 AND mac = ?3 \
             AND EXISTS (SELECT 1 FROM members WHERE tenant_id = ?1 AND github_id = ?2 \
               AND mac = ?4)",
            &[
                text(tenant_id),
                int(member.github_id)?,
                blob(invite_mac),
                blob(&member.mac),
            ],
        )?;
        let results = self
            .db
            .batch(vec![add, remove])
            .await
            .map_err(failed("d1_write_failed"))?;
        let removed = match results.get(1) {
            Some(r) => changes_of(r)?,
            None => return Err(backend("d1_meta_missing")),
        };
        if removed == 1 {
            return Ok(());
        }
        Err(self
            .invite_gone_or_replaced(tenant_id, member.github_id)
            .await?)
    }

    async fn delete_invite(
        &self,
        tenant_id: &str,
        github_id: u64,
        mac: &[u8],
    ) -> Result<(), StoreError> {
        let stmt = self.stmt(
            "DELETE FROM invites WHERE tenant_id = ?1 AND github_id = ?2 AND mac = ?3",
            &[text(tenant_id), int(github_id)?, blob(mac)],
        )?;
        if Self::changes(stmt, write_failed).await? == 1 {
            return Ok(());
        }
        Err(self.invite_gone_or_replaced(tenant_id, github_id).await?)
    }

    async fn rows_wrapped_after(
        &self,
        wrap_key: &str,
        after_id: &str,
        limit: u32,
    ) -> Result<Vec<WrappedRoot>, StoreError> {
        let stmt = self.stmt(
            "SELECT id, root_id, wrapped_root FROM tenants WHERE wrap_key = ?1 AND id > ?2 \
             ORDER BY id LIMIT ?3",
            &[text(wrap_key), text(after_id), int(u64::from(limit))?],
        )?;
        Ok(Self::all::<WrappedCols>(stmt)
            .await?
            .into_iter()
            .map(|w| WrappedRoot {
                id: w.id,
                root_id: w.root_id,
                wrapped_root: w.wrapped_root.0,
            })
            .collect())
    }

    async fn update_config(
        &self,
        id: &str,
        expected_version: u64,
        config: &str,
        mac: &[u8],
        now_ms: u64,
    ) -> Result<u64, StoreError> {
        let next = expected_version
            .checked_add(1)
            .ok_or_else(|| backend("d1_integer_out_of_range"))?;
        let stmt = self.stmt(
            "UPDATE tenants SET config = ?1, config_mac = ?2, config_version = ?3, \
             updated_ms = ?4 WHERE id = ?5 AND config_version = ?6",
            &[
                text(config),
                blob(mac),
                int(next)?,
                int(now_ms)?,
                text(id),
                int(expected_version)?,
            ],
        )?;
        if Self::changes(stmt, write_failed).await? == 1 {
            return Ok(next);
        }
        Err(if self.tenant_exists(id).await? {
            StoreError::Conflict
        } else {
            StoreError::NotFound
        })
    }

    async fn upsert_user(
        &self,
        github_id: u64,
        login: &str,
        now_ms: u64,
    ) -> Result<(), StoreError> {
        let stmt = self.stmt(
            "INSERT INTO users (github_id, login, created_ms, last_login_ms) \
             VALUES (?1, ?2, ?3, ?3) \
             ON CONFLICT (github_id) DO UPDATE SET login = excluded.login, \
             last_login_ms = excluded.last_login_ms",
            &[int(github_id)?, text(login), int(now_ms)?],
        )?;
        Self::changes(stmt, write_failed).await.map(|_| ())
    }

    async fn tenants_for_user(
        &self,
        github_id: u64,
    ) -> Result<Vec<UserRow<MemberRow>>, StoreError> {
        let stmt = self.stmt(
            "SELECT m.tenant_id AS tenant_id, t.name AS name, m.github_id AS github_id, \
             m.role AS role, m.added_by AS added_by, m.added_ms AS added_ms, m.mac AS mac \
             FROM members m JOIN tenants t ON t.id = m.tenant_id \
             WHERE m.github_id = ?1 ORDER BY t.name",
            &[int(github_id)?],
        )?;
        Self::rows(stmt, "d1_bad_member_row", UserMemberCols::row).await
    }

    async fn count_created(&self, github_id: u64) -> Result<u64, StoreError> {
        self.count(
            "SELECT count(*) AS n FROM tenants WHERE created_by = ?1",
            github_id,
        )
        .await
    }

    async fn members(&self, tenant_id: &str) -> Result<Vec<MemberRow>, StoreError> {
        let stmt = self.stmt(
            &format!("SELECT {MEMBER_COLS} FROM members WHERE tenant_id = ?1 ORDER BY github_id"),
            &[text(tenant_id)],
        )?;
        Self::rows(stmt, "d1_bad_member_row", MemberCols::row).await
    }

    async fn member(
        &self,
        tenant_id: &str,
        github_id: u64,
    ) -> Result<Option<MemberRow>, StoreError> {
        let stmt = self.stmt(
            &format!("SELECT {MEMBER_COLS} FROM members WHERE tenant_id = ?1 AND github_id = ?2"),
            &[text(tenant_id), int(github_id)?],
        )?;
        // Through `rows`, so a malformed row is absent here too.
        Ok(Self::rows(stmt, "d1_bad_member_row", MemberCols::row)
            .await?
            .into_iter()
            .next())
    }

    async fn set_member(
        &self,
        tenant_id: &str,
        row: &MemberRow,
        current: Option<&[u8]>,
        witness: Option<Witness<'_>>,
        actor: Option<Witness<'_>>,
    ) -> Result<(), StoreError> {
        // One statement, so the checks and the write are atomic: the row replaced is the one
        // the caller read (`IS` matches `NULL`, no row, too), and the witness and actor owner
        // rows are still there unchanged.
        let sql = format!(
            "INSERT INTO members (tenant_id, github_id, role, added_by, added_ms, mac) \
             SELECT ?1, ?2, ?3, ?4, ?5, ?6 \
             WHERE EXISTS (SELECT 1 FROM tenants WHERE id = ?1) \
             AND (SELECT mac FROM members WHERE tenant_id = ?1 AND github_id = ?2) IS ?7 \
             AND {} AND {} \
             ON CONFLICT (tenant_id, github_id) DO UPDATE SET role = excluded.role, \
             added_by = excluded.added_by, added_ms = excluded.added_ms, mac = excluded.mac",
            witness_sql(8, true),
            witness_sql(11, false)
        );
        let [w_id, w_ms, w_mac] = witness_args(witness)?;
        let [a_id, a_ms, a_mac] = witness_args(actor)?;
        let stmt = self.stmt(
            &sql,
            &[
                text(tenant_id),
                int(row.github_id)?,
                text(role_text(row.role)),
                int(row.added_by)?,
                int(row.added_ms)?,
                blob(&row.mac),
                opt_blob(current),
                w_id,
                w_ms,
                w_mac,
                a_id,
                a_ms,
                a_mac,
            ],
        )?;
        if Self::changes(stmt, write_failed).await? == 1 {
            return Ok(());
        }
        Err(if self.tenant_exists(tenant_id).await? {
            StoreError::Conflict
        } else {
            StoreError::NotFound
        })
    }

    async fn remove_member(
        &self,
        tenant_id: &str,
        github_id: u64,
        mac: &[u8],
        witness: Option<Witness<'_>>,
        actor: Option<Witness<'_>>,
    ) -> Result<(), StoreError> {
        let sql = format!(
            "DELETE FROM members WHERE tenant_id = ?1 AND github_id = ?2 AND mac = ?3 \
             AND {} AND {}",
            witness_sql(4, true),
            witness_sql(7, false)
        );
        let [w_id, w_ms, w_mac] = witness_args(witness)?;
        let [a_id, a_ms, a_mac] = witness_args(actor)?;
        let stmt = self.stmt(
            &sql,
            &[
                text(tenant_id),
                int(github_id)?,
                blob(mac),
                w_id,
                w_ms,
                w_mac,
                a_id,
                a_ms,
                a_mac,
            ],
        )?;
        if Self::changes(stmt, write_failed).await? == 1 {
            return Ok(());
        }
        Err(if self.member(tenant_id, github_id).await?.is_some() {
            StoreError::Conflict
        } else {
            StoreError::NotFound
        })
    }

    async fn rows_wrapped_with(
        &self,
        wrap_key: &str,
        limit: u32,
    ) -> Result<Vec<WrappedRoot>, StoreError> {
        let stmt = self.stmt(
            "SELECT id, root_id, wrapped_root FROM tenants WHERE wrap_key = ?1 \
             ORDER BY id LIMIT ?2",
            &[text(wrap_key), int(u64::from(limit))?],
        )?;
        Ok(Self::all::<WrappedCols>(stmt)
            .await?
            .into_iter()
            .map(|w| WrappedRoot {
                id: w.id,
                root_id: w.root_id,
                wrapped_root: w.wrapped_root.0,
            })
            .collect())
    }

    async fn set_wrapped(
        &self,
        id: &str,
        old_wrap_key: &str,
        new_wrapped: &[u8],
        new_wrap_key: &str,
    ) -> Result<(), StoreError> {
        let stmt = self.stmt(
            "UPDATE tenants SET wrapped_root = ?1, wrap_key = ?2 WHERE id = ?3 AND wrap_key = ?4",
            &[
                blob(new_wrapped),
                text(new_wrap_key),
                text(id),
                text(old_wrap_key),
            ],
        )?;
        if Self::changes(stmt, write_failed).await? == 1 {
            return Ok(());
        }
        Err(if self.tenant_exists(id).await? {
            StoreError::Conflict
        } else {
            StoreError::NotFound
        })
    }

    async fn set_status(&self, id: &str, status: TenantStatus) -> Result<(), StoreError> {
        let stmt = self.stmt(
            "UPDATE tenants SET status = ?1 WHERE id = ?2",
            &[text(status_text(status)), text(id)],
        )?;
        if Self::changes(stmt, write_failed).await? == 1 {
            Ok(())
        } else {
            Err(StoreError::NotFound)
        }
    }

    async fn holds_tenants(&self) -> Result<bool, StoreError> {
        self.exists(
            "SELECT 1 AS n FROM tenants UNION ALL SELECT 1 AS n FROM members \
             UNION ALL SELECT 1 AS n FROM signup_allowlist \
             UNION ALL SELECT 1 AS n FROM invite_requests \
             UNION ALL SELECT 1 AS n FROM ssh_keys LIMIT 1",
            &[],
        )
        .await
    }

    async fn allow_signup(&self, row: &AllowRow) -> Result<(), StoreError> {
        let stmt = self.stmt(
            "INSERT INTO signup_allowlist (github_id, added_by, added_ms, mac) \
             VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT (github_id) DO UPDATE SET added_by = excluded.added_by, \
             added_ms = excluded.added_ms, mac = excluded.mac",
            &[
                int(row.github_id)?,
                int(row.added_by)?,
                int(row.added_ms)?,
                blob(&row.mac),
            ],
        )?;
        Self::changes(stmt, write_failed).await.map(|_| ())
    }

    async fn allowed_signup(&self, github_id: u64) -> Result<Option<AllowRow>, StoreError> {
        let stmt = self.stmt(
            &format!("SELECT {ALLOW_COLS} FROM signup_allowlist WHERE github_id = ?1"),
            &[int(github_id)?],
        )?;
        // Through `rows`, so a malformed row is absent here too.
        Ok(Self::rows(stmt, "d1_bad_allow_row", AllowCols::row)
            .await?
            .into_iter()
            .next())
    }

    async fn allowlist(&self) -> Result<Vec<AllowRow>, StoreError> {
        let stmt = self.stmt(
            &format!("SELECT {ALLOW_COLS} FROM signup_allowlist ORDER BY github_id"),
            &[],
        )?;
        Self::rows(stmt, "d1_bad_allow_row", AllowCols::row).await
    }

    async fn disallow_signup(&self, github_id: u64) -> Result<(), StoreError> {
        let stmt = self.stmt(
            "DELETE FROM signup_allowlist WHERE github_id = ?1",
            &[int(github_id)?],
        )?;
        if Self::changes(stmt, write_failed).await? == 1 {
            Ok(())
        } else {
            Err(StoreError::NotFound)
        }
    }

    async fn invite_request(&self, github_id: u64) -> Result<Option<InviteRequestRow>, StoreError> {
        let stmt = self.stmt(
            &format!("SELECT {REQUEST_COLS} FROM invite_requests WHERE github_id = ?1"),
            &[int(github_id)?],
        )?;
        // Through `rows`, so a malformed row is absent here too.
        Ok(Self::rows(stmt, "d1_bad_request_row", RequestCols::row)
            .await?
            .into_iter()
            .next())
    }

    async fn insert_invite_request(
        &self,
        row: &InviteRequestRow,
        max_pending: u64,
    ) -> Result<(), StoreError> {
        // One statement: the pending count and the insert can't be split by a concurrent
        // request. A `SELECT` that yields no row inserts nothing and raises no constraint.
        let stmt = self.stmt(
            "INSERT INTO invite_requests (github_id, login, note, created_ms, status, mac) \
             SELECT ?1, ?2, ?3, ?4, 'pending', ?5 \
             WHERE (SELECT count(*) FROM invite_requests WHERE status = 'pending') < ?6",
            &[
                int(row.github_id)?,
                text(&row.login),
                text(&row.note),
                int(row.created_ms)?,
                blob(&row.mac),
                int(max_pending)?,
            ],
        )?;
        let changed = Self::changes(stmt, |e| {
            if error_text(e).contains("invite_requests.github_id") {
                StoreError::Conflict
            } else {
                backend("d1_write_failed")
            }
        })
        .await?;
        if changed == 1 {
            Ok(())
        } else {
            Err(StoreError::CapReached)
        }
    }

    async fn replace_invite_request(
        &self,
        row: &InviteRequestRow,
        old_mac: &[u8],
        max_pending: u64,
    ) -> Result<(), StoreError> {
        // The row being replaced doesn't count against the cap: replacing it adds no request.
        let stmt = self.stmt(
            "UPDATE invite_requests SET login = ?2, note = ?3, created_ms = ?4, \
             status = 'pending', decided_by = NULL, decided_ms = NULL, mac = ?5 \
             WHERE github_id = ?1 AND mac = ?6 \
             AND (SELECT count(*) FROM invite_requests WHERE status = 'pending' \
               AND github_id != ?1) < ?7",
            &[
                int(row.github_id)?,
                text(&row.login),
                text(&row.note),
                int(row.created_ms)?,
                blob(&row.mac),
                blob(old_mac),
                int(max_pending)?,
            ],
        )?;
        if Self::changes(stmt, write_failed).await? == 1 {
            return Ok(());
        }
        let still = self
            .exists(
                "SELECT 1 AS n FROM invite_requests WHERE github_id = ?1 AND mac = ?2",
                &[int(row.github_id)?, blob(old_mac)],
            )
            .await?;
        Err(if still {
            StoreError::CapReached
        } else {
            StoreError::Conflict
        })
    }

    async fn invite_requests(
        &self,
        decided_limit: u32,
    ) -> Result<Vec<InviteRequestRow>, StoreError> {
        let pending = self.stmt(
            &format!(
                "SELECT {REQUEST_COLS} FROM invite_requests WHERE status = 'pending' \
                 ORDER BY created_ms, github_id"
            ),
            &[],
        )?;
        let decided = self.stmt(
            &format!(
                "SELECT {REQUEST_COLS} FROM invite_requests WHERE status != 'pending' \
                 ORDER BY decided_ms DESC, github_id LIMIT ?1"
            ),
            &[int(u64::from(decided_limit))?],
        )?;
        let mut rows = Self::rows(pending, "d1_bad_request_row", RequestCols::row).await?;
        rows.extend(Self::rows(decided, "d1_bad_request_row", RequestCols::row).await?);
        Ok(rows)
    }

    async fn decide_invite_request(
        &self,
        github_id: u64,
        expected_mac: &[u8],
        status: RequestStatus,
        decided_by: u64,
        decided_ms: u64,
        allow: Option<&AllowRow>,
    ) -> Result<(), StoreError> {
        if status == RequestStatus::Pending {
            return Err(backend("decide_to_pending"));
        }
        let decide = self.stmt(
            "UPDATE invite_requests SET status = ?2, decided_by = ?3, decided_ms = ?4 \
             WHERE github_id = ?1 AND status = 'pending' AND mac = ?5",
            &[
                int(github_id)?,
                text(status.as_str()),
                int(decided_by)?,
                int(decided_ms)?,
                blob(expected_mac),
            ],
        )?;
        let mut stmts = vec![decide];
        if let Some(a) = allow {
            // Lands only if the decision above did, in the same transaction: an approval that
            // lost its race (decided already, deleted, or changed since the read) writes no
            // allowlist row. The `WHERE` is also what lets SQLite parse the upsert clause.
            stmts.push(self.stmt(
                "INSERT INTO signup_allowlist (github_id, added_by, added_ms, mac) \
                 SELECT ?1, ?2, ?3, ?4 \
                 WHERE EXISTS (SELECT 1 FROM invite_requests WHERE github_id = ?1 \
                   AND status = 'approved' AND decided_by = ?5 AND decided_ms = ?6) \
                 ON CONFLICT (github_id) DO UPDATE SET added_by = excluded.added_by, \
                 added_ms = excluded.added_ms, mac = excluded.mac",
                &[
                    int(a.github_id)?,
                    int(a.added_by)?,
                    int(a.added_ms)?,
                    blob(&a.mac),
                    int(decided_by)?,
                    int(decided_ms)?,
                ],
            )?);
        }
        let results = self
            .db
            .batch(stmts)
            .await
            .map_err(failed("d1_write_failed"))?;
        let decided = match results.first() {
            Some(r) => changes_of(r)?,
            None => return Err(backend("d1_meta_missing")),
        };
        if decided == 1 {
            Ok(())
        } else {
            Err(StoreError::Conflict)
        }
    }

    async fn delete_invite_request(&self, github_id: u64) -> Result<(), StoreError> {
        let stmt = self.stmt(
            "DELETE FROM invite_requests WHERE github_id = ?1",
            &[int(github_id)?],
        )?;
        if Self::changes(stmt, write_failed).await? == 1 {
            Ok(())
        } else {
            Err(StoreError::NotFound)
        }
    }

    async fn system_key(&self, name: &str) -> Result<Option<SystemKeyRow>, StoreError> {
        let stmt = self.stmt(
            "SELECT name, root_id, wrapped_root, wrap_key, created_ms FROM system_keys \
             WHERE name = ?1",
            &[text(name)],
        )?;
        Ok(Self::first::<SystemKeyCols>(stmt).await?.map(Into::into))
    }

    async fn insert_system_key_if_absent(
        &self,
        row: &SystemKeyRow,
    ) -> Result<SystemKeyRow, StoreError> {
        let stmt = self.stmt(
            "INSERT OR IGNORE INTO system_keys (name, root_id, wrapped_root, wrap_key, \
             created_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                text(&row.name),
                text(&row.root_id),
                blob(&row.wrapped_root),
                text(&row.wrap_key),
                int(row.created_ms)?,
            ],
        )?;
        Self::changes(stmt, write_failed).await?;
        // Ignored for the name (another isolate won: return its row) or for the root id
        // (no row by this name: `RootIdTaken`).
        self.system_key(&row.name)
            .await?
            .ok_or(StoreError::RootIdTaken)
    }

    async fn set_system_wrapped(
        &self,
        name: &str,
        old_wrap_key: &str,
        new_wrapped: &[u8],
        new_wrap_key: &str,
    ) -> Result<(), StoreError> {
        let stmt = self.stmt(
            "UPDATE system_keys SET wrapped_root = ?1, wrap_key = ?2 \
             WHERE name = ?3 AND wrap_key = ?4",
            &[
                blob(new_wrapped),
                text(new_wrap_key),
                text(name),
                text(old_wrap_key),
            ],
        )?;
        if Self::changes(stmt, write_failed).await? == 1 {
            return Ok(());
        }
        Err(if self.system_key_exists(name).await? {
            StoreError::Conflict
        } else {
            StoreError::NotFound
        })
    }

    async fn ssh_key(&self, fingerprint: &str) -> Result<Option<SshKeyLookup>, StoreError> {
        let stmt = self.stmt(
            "SELECT k.fingerprint, k.github_id, k.key_type, k.public_key, k.label, k.added_ms, \
             k.added_via, k.last_used_ms, k.mac, u.login \
             FROM ssh_keys k JOIN users u ON u.github_id = k.github_id \
             WHERE k.fingerprint = ?1",
            &[text(fingerprint)],
        )?;
        // Through `rows`, so a malformed row is absent here too.
        Ok(Self::rows(stmt, "d1_bad_ssh_key_row", SshKeyLoginCols::row)
            .await?
            .into_iter()
            .next())
    }

    async fn ssh_keys_for_user(&self, github_id: u64) -> Result<Vec<SshKeyRow>, StoreError> {
        let stmt = self.stmt(
            &format!(
                "SELECT {SSH_KEY_COLS} FROM ssh_keys WHERE github_id = ?1 \
                 ORDER BY added_ms, fingerprint"
            ),
            &[int(github_id)?],
        )?;
        Self::rows(stmt, "d1_bad_ssh_key_row", SshKeyCols::row).await
    }

    async fn insert_ssh_key(&self, row: &SshKeyRow, max: u64) -> Result<(), StoreError> {
        // One statement: the user's key count and the insert can't be split by a concurrent
        // registration. A `SELECT` that yields no row inserts nothing and raises no constraint.
        let stmt = self.stmt(
            "INSERT INTO ssh_keys (fingerprint, github_id, key_type, public_key, label, \
             added_ms, added_via, mac) \
             SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8 \
             WHERE (SELECT count(*) FROM ssh_keys WHERE github_id = ?2) < ?9",
            &[
                text(&row.fingerprint),
                int(row.github_id)?,
                text(&row.key_type),
                text(&row.public_key),
                text(&row.label),
                int(row.added_ms)?,
                text(&row.added_via),
                blob(&row.mac),
                int(max)?,
            ],
        )?;
        let changed = Self::changes(stmt, |e| {
            let msg = error_text(e);
            if msg.contains("ssh_keys.fingerprint") {
                StoreError::Conflict
            } else if msg.contains("FOREIGN KEY") {
                StoreError::Backend("unknown_user")
            } else {
                backend("d1_write_failed")
            }
        })
        .await?;
        if changed == 1 {
            Ok(())
        } else {
            Err(StoreError::CapReached)
        }
    }

    async fn delete_ssh_key(&self, github_id: u64, fingerprint: &str) -> Result<(), StoreError> {
        let stmt = self.stmt(
            "DELETE FROM ssh_keys WHERE fingerprint = ?1 AND github_id = ?2",
            &[text(fingerprint), int(github_id)?],
        )?;
        if Self::changes(stmt, write_failed).await? == 1 {
            Ok(())
        } else {
            Err(StoreError::NotFound)
        }
    }

    async fn revoke_user_ssh_keys(&self, github_id: u64, now_ms: u64) -> Result<u64, StoreError> {
        let delete = self.stmt(
            "DELETE FROM ssh_keys WHERE github_id = ?1",
            &[int(github_id)?],
        )?;
        let cutoff = self.stmt(
            "UPDATE users SET tokens_after_ms = max(tokens_after_ms, ?2) WHERE github_id = ?1",
            &[int(github_id)?, int(now_ms)?],
        )?;
        let results = self
            .db
            .batch(vec![delete, cutoff])
            .await
            .map_err(failed("d1_write_failed"))?;
        let (Some(deleted), Some(updated)) = (results.first(), results.get(1)) else {
            return Err(backend("d1_meta_missing"));
        };
        if changes_of(updated)? != 1 {
            return Err(StoreError::NotFound);
        }
        u64::try_from(changes_of(deleted)?).map_err(|_| backend("d1_meta_missing"))
    }

    async fn consume_challenge(
        &self,
        tag: &[u8],
        expires_ms: u64,
        now_ms: u64,
    ) -> Result<(), StoreError> {
        let purge = self.stmt(
            "DELETE FROM used_ssh_challenges WHERE expires_ms < ?1",
            &[int(now_ms)?],
        )?;
        let insert = self.stmt(
            "INSERT INTO used_ssh_challenges (tag, expires_ms) VALUES (?1, ?2)",
            &[blob(tag), int(expires_ms)?],
        )?;
        match self.db.batch(vec![purge, insert]).await {
            Ok(_) => Ok(()),
            Err(e) if error_text(&e).contains("used_ssh_challenges.tag") => {
                Err(StoreError::Conflict)
            }
            Err(_) => Err(backend("d1_write_failed")),
        }
    }

    async fn ssh_login_used(
        &self,
        github_id: u64,
        fingerprint: &str,
        now_ms: u64,
    ) -> Result<(), StoreError> {
        let user = self.stmt(
            "UPDATE users SET last_login_ms = ?2 WHERE github_id = ?1",
            &[int(github_id)?, int(now_ms)?],
        )?;
        let key = self.stmt(
            "UPDATE ssh_keys SET last_used_ms = ?3 WHERE github_id = ?1 AND fingerprint = ?2",
            &[int(github_id)?, text(fingerprint), int(now_ms)?],
        )?;
        self.db
            .batch(vec![user, key])
            .await
            .map(drop)
            .map_err(failed("d1_write_failed"))
    }

    async fn token_state(
        &self,
        github_id: u64,
        fingerprint: Option<&str>,
    ) -> Result<Option<(u64, Option<SshKeyRow>)>, StoreError> {
        // `k.fingerprint = NULL` is never true, so without a fingerprint no key joins.
        let stmt = self.stmt(
            "SELECT u.tokens_after_ms AS tokens_after_ms, k.fingerprint, k.github_id, \
             k.key_type, k.public_key, k.label, k.added_ms, k.added_via, k.last_used_ms, k.mac \
             FROM users u LEFT JOIN ssh_keys k \
             ON k.github_id = u.github_id AND k.fingerprint = ?2 \
             WHERE u.github_id = ?1",
            &[int(github_id)?, fingerprint.map_or(JsValue::NULL, text)],
        )?;
        let Some(raw) = Self::first::<serde_json::Value>(stmt).await? else {
            return Ok(None);
        };
        let state: TokenStateCols =
            serde_json::from_value(raw.clone()).map_err(|_| backend("d1_bad_user_row"))?;
        let key = if state.fingerprint.is_some() {
            // A key row that doesn't parse is absent, as everywhere else.
            if let Ok(cols) = serde_json::from_value::<SshKeyCols>(raw) {
                Some(cols.row()?)
            } else {
                log_internal("d1_bad_ssh_key_row");
                None
            }
        } else {
            None
        };
        Ok(Some((state.tokens_after_ms, key)))
    }
}
