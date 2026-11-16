-- The hosted tier's tenant store (edgekms_worker::store::D1Store). Applied with
-- `wrangler d1 migrations apply edgekms-tenants`; D1 enforces the foreign keys below.

CREATE TABLE users (
  github_id     INTEGER PRIMARY KEY,
  login         TEXT    NOT NULL,      -- display only; logins can be renamed
  created_ms    INTEGER NOT NULL,
  last_login_ms INTEGER NOT NULL
);

CREATE TABLE tenants (
  id             TEXT    PRIMARY KEY,  -- t_<16 hex>, immutable, in AAD, MAC input and audit keys
  name           TEXT    NOT NULL UNIQUE,
  root_id        TEXT    NOT NULL UNIQUE,
  wrapped_root   BLOB    NOT NULL,     -- iv[12] || ct[32] || tag[16]
  wrap_key       TEXT    NOT NULL,     -- master version, e.g. 'm1'
  config         TEXT    NOT NULL,     -- compact JSON, validated by Config::from_json and validate_hosted
  config_version INTEGER NOT NULL,
  config_mac     BLOB    NOT NULL,     -- HMAC under mac/config/v1 of config_mac_input
  status         TEXT    NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  created_by     INTEGER NOT NULL REFERENCES users(github_id),
  created_ms     INTEGER NOT NULL,
  updated_ms     INTEGER NOT NULL
);
CREATE INDEX tenants_by_wrap_key ON tenants(wrap_key);
CREATE INDEX tenants_by_creator ON tenants(created_by);

CREATE TABLE members (
  tenant_id TEXT    NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  github_id INTEGER NOT NULL,
  role      TEXT    NOT NULL CHECK (role IN ('owner', 'member')),
  added_by  INTEGER NOT NULL,
  added_ms  INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, github_id)
);
CREATE INDEX members_by_user ON members(github_id);

CREATE TABLE system_keys (            -- the control plane's own token root, wrapped like a tenant's
  name         TEXT    PRIMARY KEY,   -- 'control'
  root_id      TEXT    NOT NULL UNIQUE,
  wrapped_root BLOB    NOT NULL,
  wrap_key     TEXT    NOT NULL,
  created_ms   INTEGER NOT NULL
);
