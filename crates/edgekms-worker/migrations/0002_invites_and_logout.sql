-- From the security review of the hosted control plane.
--
-- Pending memberships: an owner's grant is an invite until the invitee accepts it. `members`
-- holds accepted memberships only, so every existing query (authorization, the last-owner
-- check, a user's tenants) counts accepted memberships and nothing else. Accepting moves the
-- row into `members`; it can raise an existing member to owner but never lowers a role.
CREATE TABLE invites (
  tenant_id  TEXT    NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  github_id  INTEGER NOT NULL,
  role       TEXT    NOT NULL CHECK (role IN ('owner', 'member')),
  invited_by INTEGER NOT NULL,
  invited_ms INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, github_id)
);
CREATE INDEX invites_by_user ON invites(github_id);

-- Control tokens issued (iat, in ms) before this are refused; `POST /v1/logout` raises it.
ALTER TABLE users ADD COLUMN tokens_after_ms INTEGER NOT NULL DEFAULT 0;
