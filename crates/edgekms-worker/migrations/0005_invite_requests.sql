-- Invite requests (lokkju/edgekms#12).
--
-- A GitHub user refused with `signup_closed` in `invite` mode files at most one request
-- (`POST /v1/invite-requests`, with the request token the refusal carried). Operators approve
-- (which also writes a `signup_allowlist` row), decline or delete it under
-- `/v1/ops/invite-requests`. A declined row stays until an operator deletes it, and while it
-- stays its user can't file again.
--
-- Each row carries an HMAC under `mac/invite-request/v1` of
-- `invite_request_mac_input(github_id, created_ms, login, note)`, keyed from the control
-- plane's own root like the allowlist, member and invite MACs. A row whose MAC doesn't verify
-- is listed apart for an operator to delete and can't be approved, so a row written straight
-- to D1 can't put a misleading login beside someone else's GitHub id. The decision columns are
-- outside the MAC: admission reads only `signup_allowlist`, so a forged status grants nothing.
--
-- No foreign key to `users`: a requester has never logged in, so has no `users` row.
CREATE TABLE invite_requests (
  github_id  INTEGER PRIMARY KEY,
  login      TEXT    NOT NULL,            -- from GitHub at request time; display only
  note       TEXT    NOT NULL DEFAULT '', -- plain text, validated by the control plane
  created_ms INTEGER NOT NULL,
  status     TEXT    NOT NULL DEFAULT 'pending'
             CHECK (status IN ('pending', 'approved', 'declined')),
  decided_by INTEGER,                     -- the operator; NULL while pending
  decided_ms INTEGER,
  mac        BLOB    NOT NULL,
  CHECK ((status = 'pending') = (decided_by IS NULL)),
  CHECK ((decided_by IS NULL) = (decided_ms IS NULL))
);
CREATE INDEX invite_requests_by_status ON invite_requests(status, created_ms);
