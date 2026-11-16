# Invite-request flow design (#54)

Issue: [edgekms#12](https://github.com/lokkju/edgekms/issues/12). Signups are invite-only. The signup gate (`SIGNUP_MODE`, `control/login.rs` `admit`) and the web console ([edgekms#13](https://github.com/lokkju/edgekms/issues/13), `docs/specs/2026-11-10-web-console-design.md`) have both landed, so this design builds on them as they are in the code, not as the issue imagined them before they existed.

## Intent

Today a GitHub user who isn't allowlisted, a member, an invitee or an operator gets `signup_closed` and a dead end: the console says edgekms is invite-only, and the CLI points at `https://edgekms.dev/invite`, a placeholder that doesn't exist. The only way in is to know an operator and ask them out of band.

This adds the missing step. A refused user can ask for an invite in the same session that refused them, with one optional sentence on what they'll use it for. Operators see the queue on the console's Ops page and with `edgekms ops invite-requests`, and approve or decline each request. Approving puts the user on the signup allowlist, so their next sign-in creates their personal tenant exactly as it does for anyone an operator allowlists by hand.

## Goals

- A user refused with `signup_closed` in `invite` mode can file one invite request, from the console or the CLI, without signing in a second time.
- The request is bound to a GitHub identity the control plane verified; no anonymous requests.
- One request per GitHub id, a cap on how many can be pending at once, and the control plane's existing rate limits and audit trail.
- Operators list, approve, decline and delete requests from the console's Ops page and the CLI. Approve adds the user to the allowlist and marks the request approved in one atomic write.
- A requester who comes back sees the request's date and status.
- No new origin, CSP change, Worker, binding or GitHub App permission.

## Non-goals

- Email, or any other channel to the requester. edgekms holds no email address and this design doesn't start collecting one. The requester checks back by signing in.
- Notifying operators when a request arrives (Discord, ntfy, email); owner decision D-B (below).
- Auto-approval rules (account age, waitlist position); owner decision D-D (below). The Ops page shows the account's age so an operator can apply their own rule by hand.
- A page on the marketing site that does the request itself. The site links to the console's page; it hosts no form.
- Editing a request after filing it. A requester who wants to change their note asks an operator to delete the request, then files again.
- A queue position or an estimate of when they'll be reviewed.

## Anti-goals

These would make it a failure even if it works:

- Anything a refused user can hold that works as a control token, reaches a tenant, or creates a `users` row or a tenant.
- A refused user's GitHub token staying unrevoked for longer than it does today, or being kept anywhere so it can be used again later.
- A new credential readable by JavaScript.
- A way for one GitHub account to file more than one request, or for anyone to read another user's request.
- Requester-supplied text that reaches a terminal or a page as anything other than inert plain text.
- An approval that adds the allowlist row and fails to mark the request, or the reverse.

## Architecture

### The proof of identity: a request token issued by the refused login

The login already does everything the proof needs. `login::run` checks the GitHub token against the hosted App (`check_token`), revokes it, and only then calls `admit`, which refuses with `signup_closed`. At that point the control plane knows the user's GitHub id and login and nothing more is needed from GitHub.

So the refusal itself carries the proof. When `admit` refuses a user, `SIGNUP_MODE` is `invite`, and the control root exists, the `403 signup_closed` reply gains two fields beside `code`:

```json
{
  "errors": ["signups are closed"],
  "code": "signup_closed",
  "request_token": "ekms.…",
  "request_expires_in": 900
}
```

The request token is an ordinary `ekms.` token minted with `edgekms_core::token::mint` under the control root, like a control token, with:

- `role`: `"invite_request"` (a new constant `REQUEST_ROLE` in `control/auth.rs`)
- `policies`: empty; `long`: false
- `iat` now, `exp` now + `REQUEST_TTL_SECS` (900)
- `meta`: `github_id`, `login` (both from `check_token`), `iat_ms`

A new `auth::requester(c, req, ev)` checks it: MAC under the control root, expiry, `role == REQUEST_ROLE`, no policies, not long, `github_id` and `login` present and well formed. Every failure is the same `coded(403, "permission denied", "auth_failed")` that `authenticate` returns, counted against `AUTH_FAIL_LIMIT` through `auth::failed`. It returns a `Requester { github_id, login, jti }`.

`authenticate` already refuses any token whose role isn't `control`, so a request token is useless on every existing route without a change there. A test pins that. It's also useless on every tenant, since tenant tokens verify under the tenant's own root and the control root is no tenant's.

In `closed` mode, in `open` mode (where no one is refused), and before the control root exists, the refusal has no request token. `closed` therefore doubles as the switch that stops new requests, and the root is still never created for a refused login.

The refused login's durable `control_login` audit event (result `denied`, error `signup_closed`) gets `jti` set to the request token's jti, so a later `invite_request_create` event links back to the sign-in that issued it.

**The alternative, and why not.** A separate `POST /v1/invite-requests` that takes a fresh GitHub token would mean either keeping the console user's GitHub token unrevoked until they finish typing (an anti-goal), or sending them through GitHub a second time after they type their note, and running the device flow twice in the CLI. It would also spend a second `check_token` call on the shared App's GitHub quota. The request token costs one MAC and nothing at GitHub, and the GitHub token is still revoked in the same place and at the same moment as today.

### Console: a third cookie and two proxied paths

`console/cookie.rs` gets `REQUEST_COOKIE = "__Host-edgekms_request"`: HttpOnly, Secure, `Path=/`, `SameSite=Strict`, `Max-Age` = `request_expires_in` from the reply (900 if absent or unparseable).

`/auth/callback` changes in one place, the `403 signup_closed` arm:

- If the reply has a `request_token` that `cookie::valid_value` accepts: clear the auth cookie, set the request cookie, and `302` to `/request-invite`. `return_to` is ignored; a refused sign-in has nowhere else to go.
- Otherwise (closed mode, no root): `/signin?error=signup_closed` as today.

On a successful sign-in (`200`), the callback also clears the request cookie, so a user approved between two sign-ins doesn't carry a stale one.

The proxy (`console::proxy`) picks the bearer token by path, with exact matches on `rest`:

| `rest` | Bearer | Missing cookie |
|---|---|---|
| `invite-requests` | request cookie | `401 {"code": "no_request_session"}` |
| `invite-requests/mine` | request cookie | `401 {"code": "no_request_session"}` |
| anything else | session cookie (unchanged) | `401 {"code": "no_session"}` (unchanged) |

The session cookie is never sent for the two requester paths, and the request cookie never for anything else. The Origin check, the JSON content-type rule and the `Authorization`/`X-Vault-Token` strip apply to both exactly as today, because they run before the token is chosen. `ops/invite-requests/...` doesn't match the requester rows, so it takes the session cookie like every other operator route.

`/request-invite` is a new SPA route, public in the same way `/signin` is: `App.svelte`'s effect that loads `/me` for every route except `signin` must also skip `request-invite`, or the page would send a refused user straight back through GitHub.

### CLI: same token, no browser needed

`edgekms account login` against the hosted API already reads the `signup_closed` code (`refused_with(&reply, SIGNUP_CLOSED_CODE)`). It now prints:

```
edgekms.dev is invite-only. Run `edgekms account request-invite` to ask for an invite,
or open https://app.edgekms.dev/request-invite.
```

`INVITE_URL` in `edgekms-cli/src/control.rs` becomes `https://app.edgekms.dev/request-invite`.

`edgekms account request-invite [--note <text>]` runs the device flow and the login exactly as `account login` does. Then:

- `200` (already admitted): it says so and prints nothing else; the user should run `account login`. The control token in the reply is zeroized and dropped, not printed.
- `403 signup_closed` with a `request_token`: `GET /v1/invite-requests/mine`. If a request exists, it prints its status and date. If not, it reads the note (`--note`, or a single-line prompt when stdin is a terminal, empty allowed), `POST /v1/invite-requests`, and prints the result.
- `403 signup_closed` without a token: "edgekms.dev isn't taking invite requests right now."

The request token is held in a `Zeroizing<String>` and never printed or written to disk.

### Operators

New operator routes under `/v1/ops/invite-requests` (below), the Ops page section, and `edgekms ops invite-requests list | approve <github_id> | decline <github_id> | delete <github_id>`. The CLI names them `invite-requests`, not `invites` as the issue suggested, because `invites` already means pending tenant memberships (the `invites` table, `POST /v1/tenants/:name/accept`).

### Where the page lives, and how the website links to it

The page is `https://app.edgekms.dev/request-invite`, in the console, not on the apex. The flow needs the GitHub web flow's callback, the `__Host-` cookies and the in-process control plane, all of which exist only on `app.<apex>`. A page on the apex would need its own callback URL on the App, its own cookies and either CORS on the control plane or a second copy of the proxy. The website carries a plain link, "Request an invite", to `https://app.edgekms.dev/request-invite`. It needs no script, no form and no CSP entry for it.

## Data model

Migration `crates/edgekms-worker/migrations/0005_invite_requests.sql`:

```sql
-- Invite requests (lokkju/edgekms#12).
--
-- A GitHub user refused with `signup_closed` in `invite` mode files at most one request
-- (`POST /v1/invite-requests`, with the request token the refusal carried). Operators approve
-- (which also writes a `signup_allowlist` row), decline or delete it under
-- `/v1/ops/invite-requests`.
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
```

**MAC.** `edgekms_core::keyops::MacPurpose::InviteRequest`, info `mac/invite-request/v1`. `edgekms_core::hosted::invite_request_mac_input(github_id: u64, created_ms: u64, login: &str, note: &str) -> Vec<u8>`: `github_id` u64 BE ‖ `created_ms` u64 BE ‖ `len(login)` u32 BE ‖ login bytes ‖ `len(note)` u32 BE ‖ note bytes. The length prefixes keep the two variable fields unambiguous. `Seal` gains `invite_request(...)` and `invite_request_ok(&row)`, logging `invite_request_mac_invalid` on a mismatch, like the other rows.

**Store** (`TenantStore`, with D1 and in-memory implementations):

| Method | SQL shape | Errors |
|---|---|---|
| `invite_request(github_id) -> Option<InviteRequestRow>` | `SELECT … WHERE github_id = ?1` | |
| `insert_invite_request(row, max_pending)` | `INSERT … SELECT … WHERE (SELECT count(*) FROM invite_requests WHERE status = 'pending') < ?n`, so the cap check and the insert are one statement, as `insert_tenant` does with its cap | `Conflict` on the primary key; `CapReached` when no row was inserted |
| `replace_invite_request(row, old_mac, max_pending)` | `UPDATE … SET login, note, created_ms, status = 'pending', decided_by = NULL, decided_ms = NULL, mac WHERE github_id = ?1 AND mac = ?old AND (pending count) < ?n` | `Conflict` when nothing changed |
| `invite_requests(decided_limit) -> Vec<InviteRequestRow>` | every `pending` row by `created_ms` ascending, then up to `decided_limit` decided rows by `decided_ms` descending | |
| `decide_invite_request(github_id, expected_mac, status, decided_by, decided_ms, allow: Option<&AllowRow>)` | one D1 batch: `UPDATE invite_requests SET status, decided_by, decided_ms WHERE github_id = ?1 AND status = 'pending' AND mac = ?expected`; with `allow`, then the allowlist upsert as `allow_signup` writes it, as `INSERT … SELECT … WHERE EXISTS (SELECT 1 FROM invite_requests WHERE github_id = ?1 AND status = 'approved' AND decided_ms = ?ms AND decided_by = ?by)` | `Conflict` when the first statement changed no row |
| `delete_invite_request(github_id)` | `DELETE … WHERE github_id = ?1` | `NotFound` |

`replace_invite_request` exists only for a row whose MAC doesn't verify (below); a verified row is never replaced by its requester.

**Settings.** A new var `MAX_PENDING_INVITE_REQUESTS`, parsed like `MAX_TENANTS_PER_USER` (malformed fails closed), default 200. `0` means take no requests while still issuing request tokens, so a requester sees "not taking requests right now" in place of a form. `Settings::from_vars` gains a seventh parameter; its existing callers and tests change with it.

**Note rules** (checked by the control plane; the SPA and CLI mirror them for early feedback only):

- Optional. Absent, `null` and `""` all store `""`.
- Leading and trailing whitespace trimmed before every other check and before storing.
- At most 500 Unicode scalar values and 2000 bytes after trimming.
- No control characters other than `\n` (so no `\r`, tab, ESC, NUL, DEL or C1), no bidirectional formatting characters (U+202A to U+202E, U+2066 to U+2069, and the marks U+061C, U+200E, U+200F), and no invisible characters (U+00AD, U+200B, U+2060, U+2028, U+2029, U+FEFF, U+E0000 to U+E007F; zero-width joiners stay). That keeps the text inert in a terminal (`edgekms ops invite-requests list` prints it) and stops it reordering what an operator sees.
- Any violation is `400 {"code": "note_invalid"}` with a message naming the rule.

The note never goes into an audit event or a metric, only into the row.

## API

All bodies use the existing envelope. Requester routes take `Authorization: Bearer <request token>`; operator routes take a control token from an operator. Every request counts one `CONTROL_LIMIT` unit per client IP and refuses a request without one, as `control::handle` already does for every route. The control plane sees no query strings (`ApiRequest.path` is the URL path, and the console forwards only the path), so no route takes one.

### Requester

**`GET /v1/invite-requests/mine`** (audit op `invite_request_mine`, metric only)

`200`:

```json
{"data": {
  "github_id": 123,
  "login": "octocat",
  "accepting": true,
  "request": null
}}
```

`request`, when the user has a row that verifies: `{"status": "pending" | "approved" | "declined", "created_ms": 1762819200000, "decided_ms": null | <ms>}`. A row that doesn't verify reads as `null`. `accepting` is false when `SIGNUP_MODE` is no longer `invite` or `MAX_PENDING_INVITE_REQUESTS` is `0`; the page then shows no form. The note isn't echoed (the requester wrote it, and leaving it out keeps the reply small and the console from rendering it anywhere but the Ops page).

Errors: `403 auth_failed` (missing, expired or forged request token, or a control token).

**`POST /v1/invite-requests`** (audit op `invite_request_create`, durable)

Body: `{"note": "<text>"}`, or `{}`.

Checks, in order:

1. `auth::requester` → `403 auth_failed`.
2. `SIGNUP_MODE` is still `invite` and `MAX_PENDING_INVITE_REQUESTS` > 0 → else `403 {"code": "invite_requests_closed"}`.
3. The user still isn't admitted: not an operator, not allowlisted, no verified membership or invite (the predicates `admit` uses, `allowlisted`, `existing` and `invited`, made `pub(super)`) → else `409 {"code": "already_admitted"}` ("you can sign in now").
4. Note rules → `400 note_invalid`.
5. The existing row, if any: verified `pending` or `approved` → `409 {"code": "already_requested"}`; verified `declined` → `409 {"code": "request_declined"}`; unverified → replaced through `replace_invite_request`.
6. `attempt`, then the insert (or replace).

`201 {"data": {"status": "pending", "created_ms": <ms>}}`.

Store outcomes: `CapReached` → `503 {"code": "invite_requests_full"}` ("not taking more requests right now; try again later"); `Conflict` (a concurrent request by the same user) → `409 already_requested`.

The event carries `github_id` and the request token's `jti`.

### Operator

All four call `ops::operator` first (`403 permission denied` for anyone else, as today) and set `ev.target_github_id` on the routes that name one.

**`GET /v1/ops/invite-requests`** (`invite_request_list`, metric only)

`200`:

```json
{"data": {
  "requests": [
    {"github_id": 123, "login": "octocat", "note": "CI signing for a small OSS project",
     "created_ms": 1762819200000, "status": "pending", "decided_by": null, "decided_ms": null}
  ],
  "unverified": [456],
  "pending": 1
}}
```

Every pending row, oldest first, then the 100 most recently decided. Rows that don't verify are left out of `requests` and named in `unverified`. `pending` counts verified pending rows.

**`POST /v1/ops/invite-requests/:github_id/approve`** (`invite_request_approve`, durable)

Body ignored (send `{}`). Reads the row; `404 {"code": "request_not_found"}` if none, `409 {"code": "request_unverified"}` if its MAC doesn't verify, `409 {"code": "request_not_pending"}` if it's decided. Builds the allowlist row with `Seal::allow(github_id, operator, now)`, `attempt`, then `decide_invite_request(..., Approved, ..., Some(&allow))`. A `Conflict` (decided or changed since the read) is `409 request_not_pending`. `204`.

The allowlist write is the same row `PUT /v1/ops/allowlist/:github_id` writes, so removing an approved user later is the existing `DELETE /v1/ops/allowlist/:github_id`. The request stays `approved`.

**`POST /v1/ops/invite-requests/:github_id/decline`** (`invite_request_decline`, durable)

As approve, with `Declined` and no allowlist row. `204`.

**`DELETE /v1/ops/invite-requests/:github_id`** (`invite_request_delete`, durable)

Removes the row whatever its status or MAC. `204`, or `404 request_not_found`. Deleting a declined row lets that user file again; deleting an approved row doesn't touch the allowlist.

### Routing

`control/mod.rs` `Route` gains `RequestMine`, `RequestCreate`, `RequestList`, `RequestApprove(id)`, `RequestDecline(id)`, `RequestDelete(id)`, matched as:

```
(Get,    ["invite-requests", "mine"])                  => RequestMine
(Post,   ["invite-requests"])                          => RequestCreate
(Get,    ["ops", "invite-requests"])                   => RequestList
(Post,   ["ops", "invite-requests", id, "approve"])    => RequestApprove(id)
(Post,   ["ops", "invite-requests", id, "decline"])    => RequestDecline(id)
(Delete, ["ops", "invite-requests", id])               => RequestDelete(id)
```

`dispatch` answers `RequestMine` and `RequestCreate` before `auth::authenticate`, the way it answers `Login`, and runs `auth::requester` for them instead. `durable()` is false for `RequestMine` and `RequestList`. The table in the module doc comment gets the six rows.

## Security argument

**Identity.** A request token exists only after `check_token` verified a GitHub user token issued to the hosted App, the same check every login makes. Its MAC is under the control root, which only the master unwraps; a D1 writer or anyone without the master can't mint one. Its `github_id` and `login` come from GitHub, not from the client.

**No tenant, no control token.** The token's role is `invite_request`. `authenticate` requires `control`, so every existing control route refuses it with `auth_failed`; `requester` requires `invite_request`, so a control token can't file requests either. It grants exactly two things: reading its own user's request and filing one. The refused login still writes no `users` row and creates no tenant and no control root, as today.

**The GitHub token is still revoked.** The token is minted after `revoke_token` ran, from values already in memory. The console callback's extra revoke on any non-`200` reply is unchanged.

**No revocation of the request token, bounded by its lifetime.** A requester has no `users` row, so `tokens_after_ms` can't cut it off. It lives 15 minutes, sits in an HttpOnly cookie on the console or in zeroized memory in the CLI, and a thief who got one could at most file the victim's one request with a note of their choosing or read its status. That files nothing the victim couldn't undo by asking an operator, and grants no access.

**Cookie and CSRF.** `__Host-` means only `app.<apex>` over HTTPS can set it; HttpOnly keeps it from JavaScript; `SameSite=Strict` keeps it off cross-site requests. `POST /api/v1/invite-requests` is a state change, so the proxy's Origin check and the JSON content-type rule apply. The proxy uses the request cookie for exactly two paths and never forwards it anywhere else.

**One request per GitHub id.** The primary key is the GitHub id. A verified row can't be replaced by its requester; only an operator's delete clears it.

**Volume.** Each request needs a distinct GitHub account that authorizes the App. `MAX_PENDING_INVITE_REQUESTS` (200) caps the pending queue atomically in the insert, so a sybil with many accounts fills the queue and stops there; it can't grow D1 without bound or bury the operator. Per IP: each request costs at least one refused login, which counts against `AUTH_FAIL_LIMIT`, plus `CONTROL_LIMIT` units for the login, the read and the write (and two for the console's code exchange and login). Declined rows aren't capped, but each one is an operator's deliberate action on a distinct account.

**Plain text.** The note rules exclude every control character but newline and every bidi control, so the CLI can print it raw without escape-sequence injection. The console renders it with Svelte text interpolation (`{note}`), never `{@html}`, inside an element with `white-space: pre-wrap` and `overflow-wrap: anywhere`. The note isn't logged.

**Tampering.** The MAC covers the fields an operator decides on: id, login, note and time. Without it, a D1 writer could put a famous login beside their own GitHub id and wait for an approval. With it, such a row is listed under `unverified` and can't be approved. The approval writes a fresh allowlist MAC under the operator's request, and admission keeps reading only the allowlist. The status columns are outside the MAC because nothing grants anything on them: a forged `approved` admits no one, and a forged `pending` only puts a row back in front of an operator.

**Atomic approval.** The status change and the allowlist row are one D1 batch, and the allowlist insert is conditional on the status change having happened, so an approval can't half-land and two operators approving at once write one allowlist row.

**Enumeration and privacy.** A requester reads only the row for their own token's GitHub id. The list is operator-only. The row holds the GitHub id, login, note and timestamps; no email and no IP (the IP is in the audit events, as for every control request).

**Mode changes.** `POST` re-checks `SIGNUP_MODE` and the cap, so switching to `closed` (or the cap to `0`) stops new requests at once, including from tokens issued before the switch.

## UI

### `/request-invite` (new, public)

On load, `GET /api/v1/invite-requests/mine`:

- **`401 no_request_session` or `403 auth_failed`**: "edgekms.dev is invite-only. Sign in with GitHub to request an invite." with a **Sign in with GitHub** button to `/auth/login?return_to=%2F`, and a line "Already have access? You'll go straight to your tenants." A user who is admitted signs in normally and lands on `/`; one who isn't comes back here with a request cookie.
- **`200`, `request: null`, `accepting: true`**: "Signed in with GitHub as **octocat**." A textarea labelled "What will you use edgekms for? (optional)", with a live count to 500, and **Request an invite**. On submit, `POST /api/v1/invite-requests`; on `201`, the pending view below. `400 note_invalid` shows the message under the field; `409 already_admitted` shows "You can sign in now" with a sign-in button; `503 invite_requests_full` and `403 invite_requests_closed` show "We're not taking more requests right now. Try again later."; `401`/`403 auth_failed` (the 15 minutes ran out while typing) shows "Your sign-in for this request expired. Copy your note, then sign in again." with the sign-in button. The note stays in the textarea until the user leaves, but the GitHub round trip reloads the page, so it doesn't survive the second sign-in.
- **`200`, `request: null`, `accepting: false`**: "We're not taking invite requests right now."
- **`pending`**: "You asked for an invite on 2026-11-11. An operator will review it. edgekms doesn't email you: sign in again later, and once you're approved, signing in takes you straight to your new tenant."
- **`approved`**: "Your request was approved. Sign in to get started." with the sign-in button. (Seen only if an operator removed the user from the allowlist after approving.)
- **`declined`**: "Your request on 2026-11-11 wasn't approved." (D-A).

Dates as `YYYY-MM-DD` in UTC, as the Ops page already formats them.

### `/signin`

The `signup_closed` message stays for the no-token case (closed mode), reworded: "edgekms isn't taking new signups right now. If someone invited you to a tenant, sign in again after they send the invite." In invite mode a refused user never reaches it.

### Ops page

A new **Invite requests** section above **Signup allowlist**, loaded with `GET /api/v1/ops/invite-requests`:

- Header: "Invite requests (N pending)".
- One row per pending request: stored login, GitHub id, requested date, the note (plain text, wrapped), and from GitHub (below) the current login if it differs ("now @newname"), the account's creation date and age in days, and public repo count. **Approve** and **Decline** buttons, each behind `confirm()` naming the login. After either, reload the section and the allowlist.
- A **Show decided** toggle for the decided rows, with status, decider id and date, and a **Delete** button (confirm: "Delete this request? A declined user can then request again.").
- `unverified` ids in a warning notice, each with **Delete**, as the allowlist shows its unverified rows.

GitHub details come from an unauthenticated browser `GET https://api.github.com/user/<id>`, the same pattern and the same CSP entry (`connect-src https://api.github.com`) the console already uses to resolve logins. At most 30 lookups per page view (the first 30 pending rows), since the unauthenticated limit is 60 an hour per IP; a failed or skipped lookup shows the row without those fields. `lib/github.ts` gains `accountById(id)`.

`lib/api.ts` gains the `InviteRequest` and `InviteRequestList` types and nothing else; calls go through the existing `request`.

### CLI

`edgekms ops invite-requests list` prints one block per request: `<github_id>  <login>  <status>  <date>` and the note indented underneath, pending first, then a warning for unverified ids, as `ops allowlist list` warns. `approve`, `decline` and `delete` take a GitHub id and print one line each. `edgekms account request-invite` as above.

### Docs

`docs/console.md` gets a "Requesting an invite" section and the Ops section's new part; the CLI reference gets the new commands; `docs/design.md`'s control-plane section gets the routes and the request token. These ship with the code, not with this spec.

## Testing

**Core.** `invite_request_mac_input` layout test with a fixed vector, and that two inputs differing only in where the login ends and the note begins encode differently. `MacPurpose::InviteRequest.info()`.

**Worker, `tests/control.rs`** (in-memory store, stub GitHub, fake limiter, as the existing control tests):

- `signup_closed` in `invite` mode carries a `request_token` and `request_expires_in: 900`; in `closed` mode, and with no control root, it doesn't; the GitHub token is revoked in every case; no `users` row is written.
- A request token is refused (`auth_failed`) by `GET /v1/me` and every other control route; a control token is refused by both requester routes; an expired request token and one with a flipped byte are refused and counted against `AUTH_FAIL_LIMIT`.
- `POST /v1/invite-requests`: creates a pending row whose MAC verifies; a second `POST` is `409 already_requested`; after a decline, `409 request_declined`; after an allowlisting, `409 already_admitted`; in `closed` mode, `403 invite_requests_closed`; at the cap, `503 invite_requests_full`; an unverified existing row is replaced; each note rule rejects (`\r`, ESC, U+202E, 501 scalars, 2001 bytes) and trimming applies; the durable `attempt` and outcome events carry `github_id` and the jti and never the note.
- `GET /v1/invite-requests/mine` for no row, each status, an unverified row (`null`), and `accepting` in each mode.
- Ops: non-operators get `403`; list ordering, the decided limit, `unverified`; approve writes an allowlist row that `allowlisted` accepts and the next login of that user creates their personal tenant; approving twice is `409 request_not_pending`; approving an unverified row is `409 request_unverified` and writes no allowlist row; decline; delete of each status; an approval whose row changed between the read and the batch writes nothing.
- The D1 store's SQL, through the existing D1 test path if one exists for the allowlist; otherwise the in-memory store must mirror the conditional semantics, and the D1 statements get a review against SQLite's `INSERT … SELECT … WHERE` and `ON CONFLICT` rules.

**Worker, `tests/console.rs`:** the callback sets the request cookie with every attribute and redirects to `/request-invite` on `signup_closed` with a token, keeps `/signin?error=signup_closed` without one, and clears the request cookie on a `200` sign-in; the proxy sends the request cookie for exactly the two paths, the session cookie for `ops/invite-requests`, refuses with `no_request_session` without the cookie, and applies the Origin and content-type checks to `POST /api/v1/invite-requests`.

**Console.** Vitest for the client-side note check (same cases as the server). Playwright with `/api/*` mocked: each `/request-invite` state, a submit, an expired token mid-form, and the Ops section's approve, decline, delete and unverified notice, with `api.github.com` mocked through `page.route`. The screenshot generator gets `request-invite.png` and an updated `ops.png`.

**CLI.** `tests/control.rs` with the existing fake server: `account login`'s new message, `account request-invite` for each branch (admitted, existing request, new request with `--note`, no token), and the four `ops invite-requests` commands.

**Manual, after deploy.** With a second GitHub account that isn't allowlisted: sign in on app.edgekms.dev, file a request, see it on Ops, approve it, sign in again and land on the new personal tenant. Then delete the test tenant and request.

**Review.** The independent security review the control plane gets, before the PR opens, on the request token, `auth::requester`, the proxy's cookie selection and the approve batch.

## Owner decisions

Decided by the owner on 2026-11-11, each with the recommendation below.

- **D-A. What a declined requester sees, and whether they can ask again.** Decided: the page says "Your request on <date> wasn't approved.", and the requester can't file again until an operator deletes the row. An operator who changes their mind deletes it.
- **D-B. Operator notification of new requests.** Decided: none in this change. Operators check the Ops page, whose header shows the pending count, or `edgekms ops invite-requests list`. A notification channel (ntfy, Discord, email) needs a secret and an outbound call on a requester's action, and gets its own review if the queue turns out to need watching.
- **D-C. Collecting an email for "you're in".** Decided: no. edgekms holds no personal data beyond GitHub id and login, and the requester signs in again to check.
- **D-D. Auto-approval.** Decided: none. The Ops page shows the GitHub account's age so an operator can apply that rule by hand.
- **D-E. The pending cap's default.** Decided: 200, as the var `MAX_PENDING_INVITE_REQUESTS`, changeable without a code deploy.
- **D-F. Retention of decided requests.** Decided: kept until an operator deletes them. Declined rows are what stop a re-request under D-A. Revisit if the table grows past a few thousand rows.

## Calls made (builder's, the owner can override)

- The proof of identity is a 15-minute request token carried by the `signup_closed` refusal, not a second endpoint taking a fresh GitHub token, so the GitHub token is revoked once, at the same point as today, and the shared App's quota isn't spent twice.
- Request tokens are issued only in `invite` mode, which makes `closed` the switch that stops requests, with `MAX_PENDING_INVITE_REQUESTS=0` as a softer one.
- The page lives in the console at `app.edgekms.dev/request-invite`, and the website links to it; the issue's apex page would need a second callback, cookies and CORS.
- Approve is one control route that writes the allowlist row and the status in one batch, not the starting proposal's two calls from the client (allowlist `PUT`, then a status change), which could half-land.
- Rows are MAC'd over id, login, note and time; status and decision columns aren't.
- The CLI names the commands `ops invite-requests`, not `ops invites`, because tenant invites already own the word.
- `edgekms account request-invite` gives CLI users the whole flow without a browser.
- The list route takes no query string (the control plane never sees one): it returns every pending row plus the 100 most recently decided.
- The note is 500 characters, plain text, with control and bidi characters refused rather than stripped, so what the operator reads is exactly what the requester sent.
- The requester's `GET` doesn't echo the note back.
- GitHub account details on the Ops page come from the browser against `api.github.com`, the pattern the console already uses, with no server route.
