-- SSH keys that can log in to the control plane (lokkju/edgekms#16).
--
-- A user registers a key from a control session under five minutes old, proving they hold it
-- (`POST /v1/me/ssh-keys`), and logs in with `POST /v1/login/ssh`. A key belongs to at most
-- one account: the fingerprint is the primary key.
--
-- Each row carries an HMAC under `mac/ssh-key/v1` of
-- `ssh_key_mac_input(github_id, added_ms, fingerprint, public_key, label, added_via)`, keyed
-- from the control plane's own root (the `system_keys` row `control`) like the member, invite
-- and allowlist MACs. A row whose MAC doesn't verify is treated as absent: it logs no one in,
-- keeps no token alive, and is listed apart for its owner to delete. `last_used_ms` is outside
-- the MAC; it is display only.
CREATE TABLE ssh_keys (
  fingerprint  TEXT    PRIMARY KEY    -- 'SHA256:' + unpadded base64 of the key blob's SHA-256
               CHECK (fingerprint GLOB 'SHA256:*' AND length(fingerprint) = 50),
  github_id    INTEGER NOT NULL REFERENCES users(github_id) ON DELETE CASCADE,
  key_type     TEXT    NOT NULL CHECK (key_type IN
                 ('ssh-ed25519', 'sk-ssh-ed25519@openssh.com', 'ecdsa-sha2-nistp256')),
  public_key   TEXT    NOT NULL,      -- '<type> <base64>', no comment
  label        TEXT    NOT NULL DEFAULT '',
  added_ms     INTEGER NOT NULL,
  added_via    TEXT    NOT NULL,      -- 'github' or 'ssh:<fingerprint>'
  last_used_ms INTEGER,               -- last SSH login with it; not MACed
  mac          BLOB    NOT NULL
);
CREATE INDEX ssh_keys_by_user ON ssh_keys(github_id);

-- Login and registration challenges already accepted, so each is accepted once. `tag` is the
-- challenge's 32-byte MAC; rows past `expires_ms` are deleted on each insert.
CREATE TABLE used_ssh_challenges (
  tag        BLOB    PRIMARY KEY,
  expires_ms INTEGER NOT NULL
);
