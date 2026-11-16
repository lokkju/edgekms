-- Membership and invite MACs.
--
-- Each `members` row carries an HMAC under `mac/member/v1` of
-- `member_mac_input(tenant_id, github_id, role, added_ms)`, and each `invites` row one under
-- `mac/invite/v1` of `invite_mac_input(tenant_id, github_id, role, invited_by, invited_ms)`,
-- both keyed from the control plane's own root (the `system_keys` row `control`). The control
-- plane treats a row whose MAC doesn't verify as absent, so a row written straight to D1
-- without the master grants nothing.
--
-- SQLite needs a default to add a NOT NULL column. The empty BLOB never verifies (a MAC is 32
-- bytes), so any row written before this migration fails closed. A tenant created before it has
-- no owner whose row verifies, so it is orphaned: no one can manage it through the control
-- plane, and only re-sealing its rows with the master could recover it. The hosted tier hasn't
-- been deployed, so no such tenant exists and no re-seal task is needed.
ALTER TABLE members ADD COLUMN mac BLOB NOT NULL DEFAULT x'';
ALTER TABLE invites ADD COLUMN mac BLOB NOT NULL DEFAULT x'';
