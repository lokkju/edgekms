//! An in-memory [`TenantStore`] for the tenant cache, hosted data plane and control plane
//! tests. Its behaviour is the trait's contract: `D1Store` must match it, and
//! `tests/tenants.rs` runs the same contract tests against both (`D1Store` over Node's
//! `node:sqlite` with the real migration).
//!
//! The worker's tenant, control-plane and hosted tests share it. Besides the trait it offers
//! [`MemStore::calls`] (every trait call counts one, so a test can show a cached load touched
//! nothing) and [`MemStore::tamper`], [`MemStore::tamper_member`], [`MemStore::forge_member`]
//! [`MemStore::forge_invite`] and [`MemStore::forge_invite_request`] (write stored rows directly,
//! as a leaked D1 credential could).

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use edgekms_worker::store::{
    AllowRow, InviteRequestRow, InviteRow, MemberRole, MemberRow, RequestStatus, SshKeyLookup,
    SshKeyRow, StoreError, SystemKeyRow, TenantRow, TenantStatus, TenantStore, TenantVersion,
    UserRow, Witness, WrappedRoot,
};

/// What D1 reports when `created_by` names no `users` row (a foreign key failure).
pub const UNKNOWN_USER: StoreError = StoreError::Backend("unknown_user");

struct Stored {
    row: TenantRow,
    created_by: u64,
}

#[derive(Default)]
struct Inner {
    /// `github_id` to login.
    users: BTreeMap<u64, String>,
    /// By tenant id.
    tenants: BTreeMap<String, Stored>,
    /// By `(tenant id, github id)`: accepted memberships only.
    members: BTreeMap<(String, u64), MemberRow>,
    /// Pending invites, by `(tenant id, github id)`.
    invites: BTreeMap<(String, u64), InviteRow>,
    /// `users.tokens_after_ms`.
    tokens_after: BTreeMap<u64, u64>,
    system_keys: BTreeMap<String, SystemKeyRow>,
    /// The signup allowlist, by GitHub id.
    allowlist: BTreeMap<u64, AllowRow>,
    /// Invite requests, by GitHub id.
    requests: BTreeMap<u64, InviteRequestRow>,
    /// SSH keys, by fingerprint.
    ssh_keys: BTreeMap<String, SshKeyRow>,
    /// `used_ssh_challenges`: tag to `expires_ms`.
    used_challenges: BTreeMap<Vec<u8>, u64>,
}

impl Inner {
    /// How many requests are pending, `except` one GitHub id.
    fn pending_except(&self, except: Option<u64>) -> u64 {
        self.requests
            .values()
            .filter(|r| r.status == RequestStatus::Pending && Some(r.github_id) != except)
            .count() as u64
    }
}

impl Inner {
    fn by_name(&self, name: &str) -> Option<&Stored> {
        self.tenants.values().find(|t| t.row.name == name)
    }

    fn id_of(&self, name: &str) -> String {
        self.by_name(name).expect("no such tenant").row.id.clone()
    }

    /// The membership MAC stored for `(tenant_id, github_id)`, if any.
    fn member_mac(&self, tenant_id: &str, github_id: u64) -> Option<&[u8]> {
        self.members
            .get(&(tenant_id.to_owned(), github_id))
            .map(|m| m.mac.as_slice())
    }

    /// Whether `witness` (if any) is still stored exactly as an owner, and, with `other`, is a
    /// user other than `github_id`.
    fn witness_holds(
        &self,
        tenant_id: &str,
        github_id: u64,
        witness: Option<Witness<'_>>,
        other: bool,
    ) -> bool {
        witness.is_none_or(|w| {
            (!other || w.github_id != github_id)
                && self
                    .members
                    .get(&(tenant_id.to_owned(), w.github_id))
                    .is_some_and(|m| {
                        m.role == MemberRole::Owner && m.added_ms == w.added_ms && m.mac == w.mac
                    })
        })
    }
}

/// The reference [`TenantStore`].
#[derive(Default)]
pub struct MemStore {
    inner: RefCell<Inner>,
    calls: Cell<u64>,
    fail: Cell<Option<StoreError>>,
    /// Added to the version `update_config` reports, to fake a store that misreports it.
    config_skew: Cell<u64>,
    gate: Gate,
    /// Run once at the start of the next `decide_invite_request`, on the stored row.
    on_decide: RefCell<Option<RowHook>>,
}

/// [`MemStore::on_next_decide`]'s hook.
type RowHook = Box<dyn FnOnce(&mut InviteRequestRow)>;

/// [`MemStore::hold_member_writes`]'s state.
#[derive(Default)]
struct Gate {
    needed: Cell<usize>,
    waiting: Cell<usize>,
    wakers: RefCell<Vec<std::task::Waker>>,
}

impl MemStore {
    /// From now on `set_member` and `remove_member` each wait until `n` of them are waiting,
    /// then all proceed (the last to arrive first), so a test can have concurrent requests all
    /// read before any writes. Applies to the next `n` writes only.
    pub fn hold_member_writes(&self, n: usize) {
        self.gate.needed.set(n);
        self.gate.waiting.set(0);
    }

    /// Waits at the write gate, if one is set ([`MemStore::hold_member_writes`]).
    async fn gate(&self) {
        let g = &self.gate;
        if g.needed.get() == 0 {
            return;
        }
        g.waiting.set(g.waiting.get() + 1);
        if g.waiting.get() >= g.needed.get() {
            g.needed.set(0);
            for w in g.wakers.borrow_mut().drain(..) {
                w.wake();
            }
            return;
        }
        std::future::poll_fn(|cx| {
            if g.needed.get() == 0 {
                std::task::Poll::Ready(())
            } else {
                g.wakers.borrow_mut().push(cx.waker().clone());
                std::task::Poll::Pending
            }
        })
        .await;
    }

    /// Trait calls made so far.
    pub fn calls(&self) -> u64 {
        self.calls.get()
    }

    /// Rewrites the stored row of tenant `name` in place, bypassing every check (a direct D1
    /// write). Panics if there's no such tenant.
    pub fn tamper(&self, name: &str, f: impl FnOnce(&mut TenantRow)) {
        let mut inner = self.inner.borrow_mut();
        let stored = inner
            .tenants
            .values_mut()
            .find(|t| t.row.name == name)
            .expect("no such tenant");
        f(&mut stored.row);
    }

    /// Rewrites the stored membership of `github_id` on tenant `name` in place, bypassing every
    /// check. Panics if there's no such membership.
    pub fn tamper_member(&self, name: &str, github_id: u64, f: impl FnOnce(&mut MemberRow)) {
        let mut inner = self.inner.borrow_mut();
        let id = inner.id_of(name);
        f(inner
            .members
            .get_mut(&(id, github_id))
            .expect("no such membership"));
    }

    /// The stored membership of `github_id` on tenant `name`, as a D1 reader sees it.
    pub fn member_row(&self, name: &str, github_id: u64) -> Option<MemberRow> {
        let inner = self.inner.borrow();
        let id = inner.id_of(name);
        inner.members.get(&(id, github_id)).cloned()
    }

    /// Writes `row` as a membership on tenant `name` directly, replacing any, as a D1 writer
    /// without the master could.
    pub fn forge_member(&self, name: &str, row: MemberRow) {
        let mut inner = self.inner.borrow_mut();
        let id = inner.id_of(name);
        inner.members.insert((id, row.github_id), row);
    }

    /// Writes `row` to the signup allowlist directly, replacing any, as a D1 writer without the
    /// master could.
    pub fn forge_allow(&self, row: AllowRow) {
        self.inner.borrow_mut().allowlist.insert(row.github_id, row);
    }

    /// Writes `row` as an invite request directly, replacing any, as a D1 writer without the
    /// master could.
    pub fn forge_invite_request(&self, row: InviteRequestRow) {
        self.inner.borrow_mut().requests.insert(row.github_id, row);
    }

    /// The stored invite request of `github_id`, as a D1 reader sees it.
    pub fn invite_request_row(&self, github_id: u64) -> Option<InviteRequestRow> {
        self.inner.borrow().requests.get(&github_id).cloned()
    }

    /// The next `decide_invite_request` first runs `f` on the stored row (if there is one), as a
    /// concurrent writer landing between the control plane's read and its decision would.
    pub fn on_next_decide(&self, f: impl FnOnce(&mut InviteRequestRow) + 'static) {
        *self.on_decide.borrow_mut() = Some(Box::new(f));
    }

    /// The stored allowlist row for `github_id`, as a D1 reader sees it.
    pub fn allow_row(&self, github_id: u64) -> Option<AllowRow> {
        self.inner.borrow().allowlist.get(&github_id).cloned()
    }

    /// The stored login of user `github_id`, as a D1 reader sees it.
    pub fn user_login(&self, github_id: u64) -> Option<String> {
        self.inner.borrow().users.get(&github_id).cloned()
    }

    /// Rewrites the stored login of user `github_id` directly, as a D1 writer could.
    pub fn forge_user_login(&self, github_id: u64, login: &str) {
        self.inner
            .borrow_mut()
            .users
            .insert(github_id, login.to_owned());
    }

    /// Writes `row` as an SSH key directly, replacing any with its fingerprint, as a D1 writer
    /// without the master could.
    pub fn forge_ssh_key(&self, row: SshKeyRow) {
        self.inner
            .borrow_mut()
            .ssh_keys
            .insert(row.fingerprint.clone(), row);
    }

    /// Rewrites the stored SSH key `fingerprint` in place, bypassing every check. Panics if
    /// there's no such key.
    pub fn tamper_ssh_key(&self, fingerprint: &str, f: impl FnOnce(&mut SshKeyRow)) {
        f(self
            .inner
            .borrow_mut()
            .ssh_keys
            .get_mut(fingerprint)
            .expect("no such ssh key"));
    }

    /// The stored SSH key `fingerprint`, as a D1 reader sees it.
    pub fn ssh_key_row(&self, fingerprint: &str) -> Option<SshKeyRow> {
        self.inner.borrow().ssh_keys.get(fingerprint).cloned()
    }

    /// Deletes every recorded used challenge, as a D1 writer could.
    pub fn forget_used_challenges(&self) {
        self.inner.borrow_mut().used_challenges.clear();
    }

    /// Deletes the `system_keys` row `name` directly, as a D1 writer could.
    pub fn delete_system_key(&self, name: &str) {
        self.inner.borrow_mut().system_keys.remove(name);
    }

    /// The stored invite of `github_id` to tenant `name`, as a D1 reader sees it.
    pub fn invite_row(&self, name: &str, github_id: u64) -> Option<InviteRow> {
        let inner = self.inner.borrow();
        let id = inner.id_of(name);
        inner.invites.get(&(id, github_id)).cloned()
    }

    /// Writes `row` as a pending invite to tenant `name` directly, replacing any.
    pub fn forge_invite(&self, name: &str, row: InviteRow) {
        let mut inner = self.inner.borrow_mut();
        let id = inner.id_of(name);
        inner.invites.insert((id, row.github_id), row);
    }

    /// From now on `update_config` reports `skew` more than the version it wrote, as a broken
    /// store could; 0 to stop.
    pub fn skew_config_version(&self, skew: u64) {
        self.config_skew.set(skew);
    }

    /// From now on every trait call fails with `err` (a D1 outage), or works again for `None`.
    pub fn fail_with(&self, err: Option<StoreError>) {
        self.fail.set(err);
    }

    /// Deletes tenant `name` and its memberships, as an operator's direct D1 delete would.
    /// Panics if there's no such tenant.
    pub fn delete_tenant(&self, name: &str) {
        let mut inner = self.inner.borrow_mut();
        let id = inner.by_name(name).expect("no such tenant").row.id.clone();
        inner.tenants.remove(&id);
        inner.members.retain(|(t, _), _| *t != id);
        inner.invites.retain(|(t, _), _| *t != id);
    }

    /// The shared body of `create_tenant` and `create_tenant_capped`. Synchronous, so the cap
    /// check and the insert are atomic, as D1's batch makes them.
    fn insert(
        &self,
        row: &TenantRow,
        owner: u64,
        now_ms: u64,
        owner_mac: &[u8],
        max_created: Option<u64>,
    ) -> Result<(), StoreError> {
        let mut inner = self.tick()?;
        if inner.tenants.contains_key(&row.id) {
            return Err(StoreError::Conflict);
        }
        if let Some(max) = max_created {
            let created = inner
                .tenants
                .values()
                .filter(|t| t.created_by == owner)
                .count() as u64;
            if created >= max {
                return Err(StoreError::CapReached);
            }
        }
        if inner.tenants.values().any(|t| t.row.name == row.name) {
            return Err(StoreError::NameTaken);
        }
        if inner.tenants.values().any(|t| t.row.root_id == row.root_id) {
            return Err(StoreError::RootIdTaken);
        }
        if !inner.users.contains_key(&owner) {
            return Err(UNKNOWN_USER);
        }
        inner.tenants.insert(
            row.id.clone(),
            Stored {
                row: row.clone(),
                created_by: owner,
            },
        );
        inner.members.insert(
            (row.id.clone(), owner),
            MemberRow {
                github_id: owner,
                role: MemberRole::Owner,
                added_by: owner,
                added_ms: now_ms,
                mac: owner_mac.to_vec(),
            },
        );
        Ok(())
    }

    fn tick(&self) -> Result<std::cell::RefMut<'_, Inner>, StoreError> {
        self.calls.set(self.calls.get() + 1);
        match self.fail.get() {
            Some(err) => Err(err),
            None => Ok(self.inner.borrow_mut()),
        }
    }
}

impl TenantStore for MemStore {
    async fn tenant_version(&self, name: &str) -> Result<Option<TenantVersion>, StoreError> {
        Ok(self.tick()?.by_name(name).map(|t| TenantVersion {
            id: t.row.id.clone(),
            config_version: t.row.config_version,
            status: t.row.status,
            wrap_key: t.row.wrap_key.clone(),
        }))
    }

    async fn tenant_by_name(&self, name: &str) -> Result<Option<TenantRow>, StoreError> {
        Ok(self.tick()?.by_name(name).map(|t| t.row.clone()))
    }

    async fn create_tenant(
        &self,
        row: &TenantRow,
        owner: u64,
        now_ms: u64,
        owner_mac: &[u8],
    ) -> Result<(), StoreError> {
        self.insert(row, owner, now_ms, owner_mac, None)
    }

    async fn create_tenant_capped(
        &self,
        row: &TenantRow,
        owner: u64,
        now_ms: u64,
        owner_mac: &[u8],
        max_created: u64,
    ) -> Result<(), StoreError> {
        self.insert(row, owner, now_ms, owner_mac, Some(max_created))
    }

    async fn tokens_after(&self, github_id: u64) -> Result<Option<u64>, StoreError> {
        let inner = self.tick()?;
        Ok(inner
            .users
            .contains_key(&github_id)
            .then(|| inner.tokens_after.get(&github_id).copied().unwrap_or(0)))
    }

    async fn set_tokens_after(&self, github_id: u64, ms: u64) -> Result<(), StoreError> {
        let mut inner = self.tick()?;
        if !inner.users.contains_key(&github_id) {
            return Err(StoreError::NotFound);
        }
        let t = inner.tokens_after.entry(github_id).or_insert(0);
        *t = (*t).max(ms);
        Ok(())
    }

    async fn invite(&self, tenant_id: &str, row: &InviteRow) -> Result<(), StoreError> {
        let mut inner = self.tick()?;
        if !inner.tenants.contains_key(tenant_id) {
            return Err(StoreError::NotFound);
        }
        inner
            .invites
            .insert((tenant_id.to_owned(), row.github_id), row.clone());
        Ok(())
    }

    async fn invites(&self, tenant_id: &str) -> Result<Vec<InviteRow>, StoreError> {
        let inner = self.tick()?;
        Ok(inner
            .invites
            .iter()
            .filter(|((t, _), _)| t == tenant_id)
            .map(|(_, r)| r.clone())
            .collect())
    }

    async fn invites_for_user(
        &self,
        github_id: u64,
    ) -> Result<Vec<UserRow<InviteRow>>, StoreError> {
        let inner = self.tick()?;
        let mut out: Vec<UserRow<InviteRow>> = inner
            .invites
            .iter()
            .filter(|((_, g), _)| *g == github_id)
            .filter_map(|((t, _), r)| {
                inner.tenants.get(t).map(|s| UserRow {
                    tenant_id: t.clone(),
                    name: s.row.name.clone(),
                    row: r.clone(),
                })
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    async fn accept_invite(
        &self,
        tenant_id: &str,
        invite_mac: &[u8],
        current: Option<&[u8]>,
        member: &MemberRow,
    ) -> Result<(), StoreError> {
        let mut inner = self.tick()?;
        let key = (tenant_id.to_owned(), member.github_id);
        let invite = inner.invites.get(&key).ok_or(StoreError::NotFound)?;
        if invite.mac != invite_mac || inner.member_mac(tenant_id, member.github_id) != current {
            return Err(StoreError::Conflict);
        }
        inner.invites.remove(&key);
        inner.members.insert(key, member.clone());
        Ok(())
    }

    async fn delete_invite(
        &self,
        tenant_id: &str,
        github_id: u64,
        mac: &[u8],
    ) -> Result<(), StoreError> {
        let mut inner = self.tick()?;
        let key = (tenant_id.to_owned(), github_id);
        match inner.invites.get(&key) {
            None => Err(StoreError::NotFound),
            Some(i) if i.mac != mac => Err(StoreError::Conflict),
            Some(_) => {
                inner.invites.remove(&key);
                Ok(())
            }
        }
    }

    async fn rows_wrapped_after(
        &self,
        wrap_key: &str,
        after_id: &str,
        limit: u32,
    ) -> Result<Vec<WrappedRoot>, StoreError> {
        let inner = self.tick()?;
        // `tenants` is a BTreeMap by id, so this is id order, as D1's `ORDER BY id`.
        Ok(inner
            .tenants
            .values()
            .filter(|t| t.row.wrap_key == wrap_key && t.row.id.as_str() > after_id)
            .take(limit as usize)
            .map(|t| WrappedRoot {
                id: t.row.id.clone(),
                root_id: t.row.root_id.clone(),
                wrapped_root: t.row.wrapped_root.clone(),
            })
            .collect())
    }

    async fn update_config(
        &self,
        id: &str,
        expected_version: u64,
        config: &str,
        mac: &[u8],
        _now_ms: u64,
    ) -> Result<u64, StoreError> {
        let mut inner = self.tick()?;
        let stored = inner.tenants.get_mut(id).ok_or(StoreError::NotFound)?;
        if stored.row.config_version != expected_version {
            return Err(StoreError::Conflict);
        }
        config.clone_into(&mut stored.row.config);
        stored.row.config_mac = mac.to_vec();
        stored.row.config_version = expected_version + 1;
        Ok(stored.row.config_version + self.config_skew.get())
    }

    async fn upsert_user(
        &self,
        github_id: u64,
        login: &str,
        _now_ms: u64,
    ) -> Result<(), StoreError> {
        self.tick()?.users.insert(github_id, login.to_owned());
        Ok(())
    }

    async fn tenants_for_user(
        &self,
        github_id: u64,
    ) -> Result<Vec<UserRow<MemberRow>>, StoreError> {
        let inner = self.tick()?;
        let mut out: Vec<UserRow<MemberRow>> = inner
            .members
            .iter()
            .filter(|((_, g), _)| *g == github_id)
            .filter_map(|((t, _), m)| {
                inner.tenants.get(t).map(|s| UserRow {
                    tenant_id: t.clone(),
                    name: s.row.name.clone(),
                    row: m.clone(),
                })
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    async fn count_created(&self, github_id: u64) -> Result<u64, StoreError> {
        let inner = self.tick()?;
        Ok(inner
            .tenants
            .values()
            .filter(|t| t.created_by == github_id)
            .count() as u64)
    }

    async fn members(&self, tenant_id: &str) -> Result<Vec<MemberRow>, StoreError> {
        let inner = self.tick()?;
        Ok(inner
            .members
            .iter()
            .filter(|((t, _), _)| t == tenant_id)
            .map(|(_, m)| m.clone())
            .collect())
    }

    async fn member(
        &self,
        tenant_id: &str,
        github_id: u64,
    ) -> Result<Option<MemberRow>, StoreError> {
        let inner = self.tick()?;
        Ok(inner
            .members
            .get(&(tenant_id.to_owned(), github_id))
            .cloned())
    }

    async fn set_member(
        &self,
        tenant_id: &str,
        row: &MemberRow,
        current: Option<&[u8]>,
        witness: Option<Witness<'_>>,
        actor: Option<Witness<'_>>,
    ) -> Result<(), StoreError> {
        self.gate().await;
        let mut inner = self.tick()?;
        if !inner.tenants.contains_key(tenant_id) {
            return Err(StoreError::NotFound);
        }
        if inner.member_mac(tenant_id, row.github_id) != current
            || !inner.witness_holds(tenant_id, row.github_id, witness, true)
            || !inner.witness_holds(tenant_id, row.github_id, actor, false)
        {
            return Err(StoreError::Conflict);
        }
        inner
            .members
            .insert((tenant_id.to_owned(), row.github_id), row.clone());
        Ok(())
    }

    async fn remove_member(
        &self,
        tenant_id: &str,
        github_id: u64,
        mac: &[u8],
        witness: Option<Witness<'_>>,
        actor: Option<Witness<'_>>,
    ) -> Result<(), StoreError> {
        self.gate().await;
        let mut inner = self.tick()?;
        let stored = inner
            .member_mac(tenant_id, github_id)
            .ok_or(StoreError::NotFound)?;
        if stored != mac
            || !inner.witness_holds(tenant_id, github_id, witness, true)
            || !inner.witness_holds(tenant_id, github_id, actor, false)
        {
            return Err(StoreError::Conflict);
        }
        inner.members.remove(&(tenant_id.to_owned(), github_id));
        Ok(())
    }

    async fn rows_wrapped_with(
        &self,
        wrap_key: &str,
        limit: u32,
    ) -> Result<Vec<WrappedRoot>, StoreError> {
        let inner = self.tick()?;
        Ok(inner
            .tenants
            .values()
            .filter(|t| t.row.wrap_key == wrap_key)
            .take(limit as usize)
            .map(|t| WrappedRoot {
                id: t.row.id.clone(),
                root_id: t.row.root_id.clone(),
                wrapped_root: t.row.wrapped_root.clone(),
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
        let mut inner = self.tick()?;
        let stored = inner.tenants.get_mut(id).ok_or(StoreError::NotFound)?;
        if stored.row.wrap_key != old_wrap_key {
            return Err(StoreError::Conflict);
        }
        stored.row.wrapped_root = new_wrapped.to_vec();
        new_wrap_key.clone_into(&mut stored.row.wrap_key);
        Ok(())
    }

    async fn set_status(&self, id: &str, status: TenantStatus) -> Result<(), StoreError> {
        let mut inner = self.tick()?;
        inner
            .tenants
            .get_mut(id)
            .ok_or(StoreError::NotFound)?
            .row
            .status = status;
        Ok(())
    }

    async fn holds_tenants(&self) -> Result<bool, StoreError> {
        let inner = self.tick()?;
        Ok(!inner.tenants.is_empty()
            || !inner.members.is_empty()
            || !inner.allowlist.is_empty()
            || !inner.requests.is_empty()
            || !inner.ssh_keys.is_empty())
    }

    async fn allow_signup(&self, row: &AllowRow) -> Result<(), StoreError> {
        self.tick()?.allowlist.insert(row.github_id, row.clone());
        Ok(())
    }

    async fn allowed_signup(&self, github_id: u64) -> Result<Option<AllowRow>, StoreError> {
        Ok(self.tick()?.allowlist.get(&github_id).cloned())
    }

    async fn allowlist(&self) -> Result<Vec<AllowRow>, StoreError> {
        Ok(self.tick()?.allowlist.values().cloned().collect())
    }

    async fn disallow_signup(&self, github_id: u64) -> Result<(), StoreError> {
        self.tick()?
            .allowlist
            .remove(&github_id)
            .map(drop)
            .ok_or(StoreError::NotFound)
    }

    async fn invite_request(&self, github_id: u64) -> Result<Option<InviteRequestRow>, StoreError> {
        Ok(self.tick()?.requests.get(&github_id).cloned())
    }

    async fn insert_invite_request(
        &self,
        row: &InviteRequestRow,
        max_pending: u64,
    ) -> Result<(), StoreError> {
        let mut inner = self.tick()?;
        // As in SQL: the cap's `WHERE` decides first, and a skipped insert raises nothing.
        if inner.pending_except(None) >= max_pending {
            return Err(StoreError::CapReached);
        }
        if inner.requests.contains_key(&row.github_id) {
            return Err(StoreError::Conflict);
        }
        let mut stored = row.clone();
        stored.status = RequestStatus::Pending;
        stored.decided_by = None;
        stored.decided_ms = None;
        inner.requests.insert(row.github_id, stored);
        Ok(())
    }

    async fn replace_invite_request(
        &self,
        row: &InviteRequestRow,
        old_mac: &[u8],
        max_pending: u64,
    ) -> Result<(), StoreError> {
        let mut inner = self.tick()?;
        let current = inner
            .requests
            .get(&row.github_id)
            .filter(|r| r.mac == old_mac);
        if current.is_none() {
            return Err(StoreError::Conflict);
        }
        if inner.pending_except(Some(row.github_id)) >= max_pending {
            return Err(StoreError::CapReached);
        }
        let mut stored = row.clone();
        stored.status = RequestStatus::Pending;
        stored.decided_by = None;
        stored.decided_ms = None;
        inner.requests.insert(row.github_id, stored);
        Ok(())
    }

    async fn invite_requests(
        &self,
        decided_limit: u32,
    ) -> Result<Vec<InviteRequestRow>, StoreError> {
        let inner = self.tick()?;
        let mut pending: Vec<InviteRequestRow> = inner
            .requests
            .values()
            .filter(|r| r.status == RequestStatus::Pending)
            .cloned()
            .collect();
        pending.sort_by_key(|r| (r.created_ms, r.github_id));
        let mut decided: Vec<InviteRequestRow> = inner
            .requests
            .values()
            .filter(|r| r.status != RequestStatus::Pending)
            .cloned()
            .collect();
        decided.sort_by_key(|r| (std::cmp::Reverse(r.decided_ms), r.github_id));
        decided.truncate(decided_limit as usize);
        pending.extend(decided);
        Ok(pending)
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
        assert_ne!(
            status,
            RequestStatus::Pending,
            "a decision is never pending"
        );
        let mut inner = self.tick()?;
        if let Some(f) = self.on_decide.borrow_mut().take()
            && let Some(r) = inner.requests.get_mut(&github_id)
        {
            f(r);
        }
        let Some(r) = inner
            .requests
            .get_mut(&github_id)
            .filter(|r| r.status == RequestStatus::Pending && r.mac == expected_mac)
        else {
            return Err(StoreError::Conflict);
        };
        r.status = status;
        r.decided_by = Some(decided_by);
        r.decided_ms = Some(decided_ms);
        if let Some(a) = allow
            && status == RequestStatus::Approved
        {
            inner.allowlist.insert(a.github_id, a.clone());
        }
        Ok(())
    }

    async fn delete_invite_request(&self, github_id: u64) -> Result<(), StoreError> {
        self.tick()?
            .requests
            .remove(&github_id)
            .map(drop)
            .ok_or(StoreError::NotFound)
    }

    async fn system_key(&self, name: &str) -> Result<Option<SystemKeyRow>, StoreError> {
        Ok(self.tick()?.system_keys.get(name).cloned())
    }

    async fn insert_system_key_if_absent(
        &self,
        row: &SystemKeyRow,
    ) -> Result<SystemKeyRow, StoreError> {
        let mut inner = self.tick()?;
        if let Some(existing) = inner.system_keys.get(&row.name) {
            return Ok(existing.clone());
        }
        if inner.system_keys.values().any(|k| k.root_id == row.root_id) {
            return Err(StoreError::RootIdTaken);
        }
        inner.system_keys.insert(row.name.clone(), row.clone());
        Ok(row.clone())
    }

    async fn set_system_wrapped(
        &self,
        name: &str,
        old_wrap_key: &str,
        new_wrapped: &[u8],
        new_wrap_key: &str,
    ) -> Result<(), StoreError> {
        let mut inner = self.tick()?;
        let row = inner
            .system_keys
            .get_mut(name)
            .ok_or(StoreError::NotFound)?;
        if row.wrap_key != old_wrap_key {
            return Err(StoreError::Conflict);
        }
        row.wrapped_root = new_wrapped.to_vec();
        new_wrap_key.clone_into(&mut row.wrap_key);
        Ok(())
    }

    async fn ssh_key(&self, fingerprint: &str) -> Result<Option<SshKeyLookup>, StoreError> {
        let inner = self.tick()?;
        Ok(inner.ssh_keys.get(fingerprint).and_then(|row| {
            inner.users.get(&row.github_id).map(|login| SshKeyLookup {
                row: row.clone(),
                login: login.clone(),
            })
        }))
    }

    async fn ssh_keys_for_user(&self, github_id: u64) -> Result<Vec<SshKeyRow>, StoreError> {
        let inner = self.tick()?;
        let mut out: Vec<SshKeyRow> = inner
            .ssh_keys
            .values()
            .filter(|k| k.github_id == github_id)
            .cloned()
            .collect();
        out.sort_by(|a, b| (a.added_ms, &a.fingerprint).cmp(&(b.added_ms, &b.fingerprint)));
        Ok(out)
    }

    async fn insert_ssh_key(&self, row: &SshKeyRow, max: u64) -> Result<(), StoreError> {
        let mut inner = self.tick()?;
        let held = inner
            .ssh_keys
            .values()
            .filter(|k| k.github_id == row.github_id)
            .count() as u64;
        // The table's CHECK on the fingerprint's shape.
        if !(row.fingerprint.starts_with("SHA256:") && row.fingerprint.len() == 50) {
            return Err(StoreError::Backend("d1_write_failed"));
        }
        if held >= max {
            return Err(StoreError::CapReached);
        }
        if inner.ssh_keys.contains_key(&row.fingerprint) {
            return Err(StoreError::Conflict);
        }
        if !inner.users.contains_key(&row.github_id) {
            return Err(UNKNOWN_USER);
        }
        let mut stored = row.clone();
        // The insert never writes `last_used_ms`.
        stored.last_used_ms = None;
        inner.ssh_keys.insert(row.fingerprint.clone(), stored);
        Ok(())
    }

    async fn delete_ssh_key(&self, github_id: u64, fingerprint: &str) -> Result<(), StoreError> {
        let mut inner = self.tick()?;
        if inner
            .ssh_keys
            .get(fingerprint)
            .is_some_and(|k| k.github_id == github_id)
        {
            inner.ssh_keys.remove(fingerprint);
            Ok(())
        } else {
            Err(StoreError::NotFound)
        }
    }

    async fn revoke_user_ssh_keys(&self, github_id: u64, now_ms: u64) -> Result<u64, StoreError> {
        let mut inner = self.tick()?;
        if !inner.users.contains_key(&github_id) {
            return Err(StoreError::NotFound);
        }
        let before = inner.ssh_keys.len();
        inner.ssh_keys.retain(|_, k| k.github_id != github_id);
        let removed = (before - inner.ssh_keys.len()) as u64;
        let t = inner.tokens_after.entry(github_id).or_insert(0);
        *t = (*t).max(now_ms);
        Ok(removed)
    }

    async fn consume_challenge(
        &self,
        tag: &[u8],
        expires_ms: u64,
        now_ms: u64,
    ) -> Result<(), StoreError> {
        let mut inner = self.tick()?;
        inner.used_challenges.retain(|_, exp| *exp >= now_ms);
        if inner.used_challenges.contains_key(tag) {
            return Err(StoreError::Conflict);
        }
        inner.used_challenges.insert(tag.to_vec(), expires_ms);
        Ok(())
    }

    async fn ssh_login_used(
        &self,
        github_id: u64,
        fingerprint: &str,
        now_ms: u64,
    ) -> Result<(), StoreError> {
        let mut inner = self.tick()?;
        if let Some(k) = inner
            .ssh_keys
            .get_mut(fingerprint)
            .filter(|k| k.github_id == github_id)
        {
            k.last_used_ms = Some(now_ms);
        }
        Ok(())
    }

    async fn token_state(
        &self,
        github_id: u64,
        fingerprint: Option<&str>,
    ) -> Result<Option<(u64, Option<SshKeyRow>)>, StoreError> {
        let inner = self.tick()?;
        if !inner.users.contains_key(&github_id) {
            return Ok(None);
        }
        let after = inner.tokens_after.get(&github_id).copied().unwrap_or(0);
        let key = fingerprint
            .and_then(|f| inner.ssh_keys.get(f))
            .filter(|k| k.github_id == github_id)
            .cloned();
        Ok(Some((after, key)))
    }
}
