//! Membership and invite row MACs: every `members` and `invites` row carries an HMAC under a
//! key derived from the control plane's own root (`mac/member/v1`, `mac/invite/v1`), over
//! `member_mac_input` and `invite_mac_input`. The control plane writes one with every row it
//! creates or changes and verifies it on every read; a row that doesn't verify is treated as
//! absent and logged as `member_mac_invalid` or `invite_mac_invalid`. A D1 writer without the
//! master therefore can't grant anyone anything.
//!
//! The control root is used rather than each tenant's own: one root is already open for the
//! token check on every request, so verifying costs no unwrap per tenant (`GET /v1/me` lists
//! many), and an owner who has exported their tenant's root (or imported it, and so held it all
//! along) can't forge memberships with it.
//!
//! Writes that rely on what was read name it: a change replaces a membership only while its
//! MAC is the one read, and the last-owner rule names the other verified owner row it relied on
//! ([`Witness`]), which the store checks in the same statement as the change.

use edgekms_core::hosted::{
    allow_mac_input, invite_mac_input, invite_request_mac_input, member_mac_input,
    ssh_key_mac_input,
};
use edgekms_core::keyops::{KeyOps, MacPurpose};

use crate::store::{
    AllowRow, InviteRequestRow, InviteRow, MemberRole, MemberRow, RequestStatus, SshKeyRow, Witness,
};
use crate::vault::{Reply, log_internal};
use crate::webcrypto::WebCryptoKeyOps;

/// The text a role is stored as, and the MAC input covers.
pub fn role_text(r: MemberRole) -> &'static str {
    match r {
        MemberRole::Owner => "owner",
        MemberRole::Member => "member",
    }
}

/// MACs and verifies membership and invite rows under the control root.
pub struct Seal<'a>(pub &'a WebCryptoKeyOps);

fn mac_failed() -> Reply {
    log_internal("control: membership MAC failed");
    Reply::internal()
}

impl Seal<'_> {
    async fn mac(&self, purpose: MacPurpose, input: &[u8]) -> Result<Vec<u8>, Reply> {
        self.0
            .mac(purpose, input)
            .await
            .map(|t| t.to_vec())
            .map_err(|_| mac_failed())
    }

    async fn verify(&self, purpose: MacPurpose, input: &[u8], tag: &[u8]) -> Result<bool, Reply> {
        self.0
            .verify_mac(purpose, input, tag)
            .await
            .map_err(|_| mac_failed())
    }

    /// A new membership row for `github_id` on `tenant_id`, taking `role` at `now_ms`.
    pub async fn member(
        &self,
        tenant_id: &str,
        github_id: u64,
        role: MemberRole,
        added_by: u64,
        now_ms: u64,
    ) -> Result<MemberRow, Reply> {
        let input = member_mac_input(tenant_id, github_id, role_text(role), now_ms);
        Ok(MemberRow {
            github_id,
            role,
            added_by,
            added_ms: now_ms,
            mac: self.mac(MacPurpose::Member, &input).await?,
        })
    }

    /// A new invite row for `github_id` to `tenant_id` as `role`.
    pub async fn invite(
        &self,
        tenant_id: &str,
        github_id: u64,
        role: MemberRole,
        invited_by: u64,
        now_ms: u64,
    ) -> Result<InviteRow, Reply> {
        let input = invite_mac_input(tenant_id, github_id, role_text(role), invited_by, now_ms);
        Ok(InviteRow {
            github_id,
            role,
            invited_by,
            invited_ms: now_ms,
            mac: self.mac(MacPurpose::Invite, &input).await?,
        })
    }

    /// A new signup allowlist row for `github_id`, added by operator `added_by` at `now_ms`.
    pub async fn allow(
        &self,
        github_id: u64,
        added_by: u64,
        now_ms: u64,
    ) -> Result<AllowRow, Reply> {
        let input = allow_mac_input(github_id, added_by, now_ms);
        Ok(AllowRow {
            github_id,
            added_by,
            added_ms: now_ms,
            mac: self.mac(MacPurpose::Allow, &input).await?,
        })
    }

    /// Whether `row` is a signup allowlist row the control plane wrote; logged if not.
    pub async fn allow_ok(&self, row: &AllowRow) -> Result<bool, Reply> {
        let input = allow_mac_input(row.github_id, row.added_by, row.added_ms);
        let ok = self.verify(MacPurpose::Allow, &input, &row.mac).await?;
        if !ok {
            log_internal("allow_mac_invalid");
        }
        Ok(ok)
    }

    /// A new pending invite request from `github_id`, named `login` on GitHub, with `note`
    /// (already checked), filed at `now_ms`.
    pub async fn invite_request(
        &self,
        github_id: u64,
        login: &str,
        note: &str,
        now_ms: u64,
    ) -> Result<InviteRequestRow, Reply> {
        let input = invite_request_mac_input(github_id, now_ms, login, note);
        Ok(InviteRequestRow {
            github_id,
            login: login.to_owned(),
            note: note.to_owned(),
            created_ms: now_ms,
            status: RequestStatus::Pending,
            decided_by: None,
            decided_ms: None,
            mac: self.mac(MacPurpose::InviteRequest, &input).await?,
        })
    }

    /// Whether `row` is an invite request the control plane wrote; logged if not. The decision
    /// columns aren't covered.
    pub async fn invite_request_ok(&self, row: &InviteRequestRow) -> Result<bool, Reply> {
        let input = invite_request_mac_input(row.github_id, row.created_ms, &row.login, &row.note);
        let ok = self
            .verify(MacPurpose::InviteRequest, &input, &row.mac)
            .await?;
        if !ok {
            log_internal("invite_request_mac_invalid");
        }
        Ok(ok)
    }

    /// A new SSH key row: `key` (already parsed and proven) for `github_id`, labelled `label`
    /// (already checked), added at `now_ms` by a session whose login was `added_via`.
    pub async fn ssh_key(
        &self,
        github_id: u64,
        key: &edgekms_core::ssh::VerifiedKey,
        label: &str,
        added_via: &str,
        now_ms: u64,
    ) -> Result<SshKeyRow, Reply> {
        let input = ssh_key_mac_input(
            github_id,
            now_ms,
            &key.fingerprint,
            &key.public_key,
            label,
            added_via,
        );
        Ok(SshKeyRow {
            fingerprint: key.fingerprint.clone(),
            github_id,
            key_type: key.key_type.clone(),
            public_key: key.public_key.clone(),
            label: label.to_owned(),
            added_ms: now_ms,
            added_via: added_via.to_owned(),
            last_used_ms: None,
            mac: self.mac(MacPurpose::SshKey, &input).await?,
        })
    }

    /// Whether `row` is an SSH key row the control plane wrote; logged if not. `last_used_ms`
    /// isn't covered; `key_type` isn't either, but must name the public key's own type.
    pub async fn ssh_key_ok(&self, row: &SshKeyRow) -> Result<bool, Reply> {
        let input = ssh_key_mac_input(
            row.github_id,
            row.added_ms,
            &row.fingerprint,
            &row.public_key,
            &row.label,
            &row.added_via,
        );
        let typed = row
            .public_key
            .strip_prefix(row.key_type.as_str())
            .is_some_and(|rest| rest.starts_with(' '));
        let ok = typed && self.verify(MacPurpose::SshKey, &input, &row.mac).await?;
        if !ok {
            log_internal("ssh_key_mac_invalid");
        }
        Ok(ok)
    }

    /// Whether `row` is a membership on `tenant_id` the control plane wrote; logged if not.
    pub async fn member_ok(&self, tenant_id: &str, row: &MemberRow) -> Result<bool, Reply> {
        let input = member_mac_input(tenant_id, row.github_id, role_text(row.role), row.added_ms);
        let ok = self.verify(MacPurpose::Member, &input, &row.mac).await?;
        if !ok {
            log_internal("member_mac_invalid");
        }
        Ok(ok)
    }

    /// Whether `row` is an invite to `tenant_id` the control plane wrote; logged if not.
    pub async fn invite_ok(&self, tenant_id: &str, row: &InviteRow) -> Result<bool, Reply> {
        let input = invite_mac_input(
            tenant_id,
            row.github_id,
            role_text(row.role),
            row.invited_by,
            row.invited_ms,
        );
        let ok = self.verify(MacPurpose::Invite, &input, &row.mac).await?;
        if !ok {
            log_internal("invite_mac_invalid");
        }
        Ok(ok)
    }

    /// `row` if it verifies, else `None`.
    pub async fn valid_member(
        &self,
        tenant_id: &str,
        row: Option<MemberRow>,
    ) -> Result<Option<MemberRow>, Reply> {
        match row {
            Some(r) if self.member_ok(tenant_id, &r).await? => Ok(Some(r)),
            _ => Ok(None),
        }
    }

    /// The rows of `rows` that verify, in order.
    pub async fn valid_members(
        &self,
        tenant_id: &str,
        rows: Vec<MemberRow>,
    ) -> Result<Vec<MemberRow>, Reply> {
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            if self.member_ok(tenant_id, &r).await? {
                out.push(r);
            }
        }
        Ok(out)
    }

    /// The rows of `rows` that verify, in order.
    pub async fn valid_invites(
        &self,
        tenant_id: &str,
        rows: Vec<InviteRow>,
    ) -> Result<Vec<InviteRow>, Reply> {
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            if self.invite_ok(tenant_id, &r).await? {
                out.push(r);
            }
        }
        Ok(out)
    }
}

fn as_witness(m: &MemberRow) -> Witness<'_> {
    Witness {
        github_id: m.github_id,
        added_ms: m.added_ms,
        mac: &m.mac,
    }
}

/// The acting owner's own row among `verified`, as the [`Witness`] a membership change it makes
/// relies on, so the change doesn't land if that owner was removed or demoted meanwhile.
/// `None` if `github_id` holds no verified owner row (it changed since the role check).
pub fn acting_owner(verified: &[MemberRow], github_id: u64) -> Option<Witness<'_>> {
    verified
        .iter()
        .find(|m| m.role == MemberRole::Owner && m.github_id == github_id)
        .map(as_witness)
}

/// An owner among `verified` other than `github_id`, as the [`Witness`] a demotion or removal
/// of `github_id` relies on; `None` means `github_id` is the last owner. `verified` must hold
/// only rows that verified.
pub fn other_owner(verified: &[MemberRow], github_id: u64) -> Option<Witness<'_>> {
    verified
        .iter()
        .find(|m| m.role == MemberRole::Owner && m.github_id != github_id)
        .map(as_witness)
}
