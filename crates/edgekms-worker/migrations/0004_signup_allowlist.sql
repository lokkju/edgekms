-- The signup allowlist, which the signup gate reads.
--
-- With `SIGNUP_MODE` `invite`, the control plane lets a GitHub user log in for the first time
-- only if they are an operator or hold a row here. Operators manage it with
-- `PUT` and `DELETE /v1/ops/allowlist/:github_id` and `GET /v1/ops/allowlist`.
--
-- Each row carries an HMAC under `mac/allow/v1` of
-- `allow_mac_input(github_id, added_by, added_ms)`, keyed from the control plane's own root (the
-- `system_keys` row `control`), like the `members` and `invites` MACs. The control plane treats
-- a row whose MAC doesn't verify as absent, so a row written straight to D1 without the master
-- admits no one.
CREATE TABLE signup_allowlist (
  github_id INTEGER PRIMARY KEY,
  added_by  INTEGER NOT NULL,    -- the operator who added it
  added_ms  INTEGER NOT NULL,
  mac       BLOB    NOT NULL
);
