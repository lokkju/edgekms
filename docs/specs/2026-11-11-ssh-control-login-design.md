# SSH-key control-plane login design (#66)

Issue: [edgekms#16](https://github.com/lokkju/edgekms/issues/16). The shape (keys registered only from a signed-in session, list and revoke, existing accounts only, the fingerprint in the audit log, agent signing, a control token on stdout) was agreed with the operator after a break-glass attempt that needed it (below). This spec decides the rest against the code as it is on `main` at `d60be10`.

## Intent

GitHub is the only way into the hosted control plane. `POST /v1/login/github` takes a device-flow token, checks it against GitHub and revokes it. If the GitHub account is lost, or GitHub's device flow or API is down, an owner can't run `edgekms tenant export` or `edgekms tenant config get`, which is exactly when break-glass matters. An operator backing up a tenant's config hit this: they had a forwarded ssh-agent and no way to turn it into a control token.

This adds a second login method. A signed-in user registers SSH public keys on their account. Later, `edgekms account login --ssh` asks the control plane for a challenge, has ssh-agent sign it, and gets an ordinary control token on stdout. The login never calls GitHub.

## Goals

- `POST /v1/login/ssh/challenge` and `POST /v1/login/ssh`: challenge-response with the data plane's challenge format, under the control root, bound to the control origin, single-use.
- Registered keys per user, in a D1 table with a row MAC under the control root like `members`, `invites` and `signup_allowlist`. One key belongs to at most one account.
- Register, list and remove keys from the CLI (`edgekms account ssh-keys ...`) and from a new Account page in the console.
- Registration only from an authenticated control session whose login is under five minutes old (GitHub or SSH), with proof that the registrant holds the private key.
- An SSH login reaches existing accounts only. It never creates a user, a personal tenant or a signup.
- Every control-plane audit event made under an SSH-minted token names the key's fingerprint.
- Removing a key ends every control token that key minted, on the next request.
- `edgekms account login --ssh` keeps the token contract of `account login`: the token alone on stdout, everything else on stderr, nothing written to disk.

## Non-goals

- SSH login in the console. A browser has no ssh-agent; the console keeps signing in with GitHub only. Its proxy already refuses `/api/v1/login/*`, and that stays.
- Signing up, or getting off the allowlist, with an SSH key. `SIGNUP_MODE`, the allowlist and personal tenants stay GitHub-only.
- Other key types. The data plane accepts Ed25519, `sk-ssh-ed25519@openssh.com` and ECDSA P-256; so does this. RSA and `sk-ecdsa-sha2-nistp256@openssh.com` stay out.
- SSH certificates and CA-signed keys.
- Renaming a key's label. Remove and add again.
- Changing the data plane's SSH login (its challenge replay window stays as `docs/design.md` describes it).

## Anti-goals

These would make it a failure even if it works:

- The CLI reading a private key. Signing goes through `ssh-keygen -Y sign`, which asks ssh-agent, exactly as `login ssh` does.
- An unknown key, a key that belongs to someone else, or an account with no keys being distinguishable from a bad signature, by response or by timing, to anyone who doesn't hold the private key.
- A row written straight to D1, without the master, letting any key log in to any account.
- A way to create an account, or to bypass `SIGNUP_MODE`, through SSH.
- A control token that outlives the removal of the key that minted it.
- Any change to the console's CSP or session rules.

## Architecture

### The challenge

The control plane reuses `edgekms_core::ssh`'s challenge format unchanged on the wire: `"ekmsc." + base64url(ts_be8 || random16 || mac32 || origin)`, the MAC over `ts || random || origin`. Three things differ from the data plane's use of it.

**Root and purpose.** The MAC key is derived from the control root (the `system_keys` row `control`) with a new purpose, `MacPurpose::ControlChallenge`, info `mac/control-challenge/v1`. A second new purpose, `MacPurpose::SshKeyProof`, info `mac/ssh-key-proof/v1`, MACs the registration challenges described below. The control root alone already stops a tenant's challenge from verifying here, since no tenant root equals it. The separate purposes make the domain explicit in the key derivation and keep login and registration challenges apart from each other under the one root, and from anything else the control root may MAC as a challenge later. The cost is two enum variants. `ssh::new_challenge` and `ssh::check_challenge` gain a sibling pair taking a purpose and a TTL (`new_challenge_with(ops, purpose, now, origin)`, `check_challenge_with(ops, purpose, ttl, challenge, now, origins)`); the existing functions become calls to them with `MacPurpose::Challenge` and `CHALLENGE_TTL_SECS`, and their bytes don't change.

**Origin.** The bound origin is the request's origin. `dispatch_host` has already pinned its host to `api.<apex>` before `control::serve` runs, and in production Cloudflare's routing makes it `https://api.edgekms.dev`; in `scripts/e2e-hosted` it is `http://api.localhost:8787`. The CLI refuses to sign a challenge whose origin isn't the origin of its `--api`, with the existing `challenge_origin` check. A challenge from the control plane therefore can't be signed by a CLI pointed at a tenant or a hostile self-hosted Worker, and a challenge from either can't be signed by a CLI pointed at the control plane.

**Single use.** A login challenge is accepted once. After the signature verifies, the control plane inserts the challenge's 32-byte MAC tag into `used_ssh_challenges` with its expiry; a primary-key conflict is a replay and is refused. The data plane can't afford this (it reads D1 replicas and keeps no per-login state), which is why `docs/design.md` accepts a 60-second replay window there. The control plane already reads and writes the D1 primary and already writes `users.last_login_ms` on every login, so one more insert per successful signature is cheap. Expired rows are deleted by the same batch (`DELETE ... WHERE expires_ms < now`), which the login rate limit bounds. Registration challenges are consumed the same way.

**Registration challenges name their account** ([edgekms#17](https://github.com/lokkju/edgekms/issues/17)). A registration challenge isn't the format above. It is `ekmsr.<github_id>.<login>.<base64url(ts || random || mac || origin)>`: the account it was minted for leads the text in the clear, and the MAC (purpose `SshKeyProof`) covers `ts || random || github_id (u64 big-endian) || login length (1 byte) || login || origin`. The login must have a GitHub login's shape (1 to 39 letters, digits and hyphens), so it is safe in a shell command, and the id must be spelled without leading zeros, so a challenge has one spelling. Core mints it with `ssh::new_register_challenge(ops, now, origin, account)` and checks it with `ssh::check_register_challenge(ops, challenge, now, origins, github_id)`: layout, MAC, origin, then that it names `github_id` (`SshError::WrongAccount` otherwise), then age. `ssh::register_challenge_parts` reads the account and origin without the MAC, for clients. A login challenge and a registration challenge never parse as each other, and an `ekmsc.` challenge is malformed at registration. Login challenges are unchanged.

TTLs: a login challenge lasts 60 seconds (`CHALLENGE_TTL_SECS`, as on the data plane). A registration challenge lasts 300 seconds (`SSH_KEY_PROOF_TTL_SECS`), because in the console a person copies a command, runs it and pastes the result.

### Login: the server finds the account by key

`POST /v1/login/ssh` takes `{"challenge", "signature"}` and nothing else. There is no `github_id` field: with one key belonging to at most one account, the verified signature's key names the account, and a body without an account id gives no oracle for "does user N exist" or "does user N have keys". It also means `edgekms account login --ssh` works on a host that doesn't know its owner's GitHub id.

The checks run in this order, and the order is the enumeration argument:

1. `LOGIN_LIMIT` per client IP (after `CONTROL_LIMIT`, which `handle` already counts for every request).
2. The challenge: length, layout, MAC under `ControlChallenge` (constant time), origin, age.
3. The signature: armored `SSHSIG`, namespace `edgekms`, a supported algorithm, verified against the public key embedded in the signature itself, and for `sk-ssh-ed25519` the user-presence flag. This is a new core function, `ssh::verify_embedded(challenge, armored) -> Result<VerifiedKey, SshError>`, returning the key and its SHA256 fingerprint; `ssh::verify` keeps its pinned-key behavior for the data plane and shares the code.
4. Consume the challenge (`used_ssh_challenges`).
5. Look up the key by fingerprint, verify the row's MAC, and compare the stored public key's bytes with the signature's key.
6. Check the account is one an SSH login may reach (below).
7. `attempt`, update `users.last_login_ms` and the key's `last_used_ms`, mint.

Nothing touches D1 before step 4, and step 4 needs a valid signature. Someone holding only a public key (every GitHub user's keys are public at `github.com/<login>.keys`) fails at step 3 whether or not that key is registered, in the same time, with the same response. Someone holding the private key learns at step 5 whether their own key is registered, which they could learn anyway by trying to log in. Every refusal from step 2 onward is the uniform `400 permission denied`, counted against `AUTH_FAIL_LIMIT`, with a distinct audit label.

### Who an SSH login reaches

An SSH login is for an existing account, so it applies the "existing" half of `admit` and never the "signup" half, in every `SIGNUP_MODE`: the user must be an operator, or hold a membership that verifies (in an active tenant, or as owner of a suspended one), or hold a pending invite that verifies to an active tenant. This is `login::existing` and `login::invited` as they are, factored out for reuse. The `users` row must exist (the key table references it). Anyone else, including a user with a registered key who has since been removed from every tenant, gets the same `400 permission denied` as a bad signature, labelled `ssh_not_existing` in the audit event. It isn't `403 signup_closed`: that code would tell a key holder their key is registered but their account is empty, and it would point them at an invite flow SSH can't use. An SSH login never creates a personal tenant, even in `open` mode.

A suspended tenant's owner can log in with SSH and export, the same way out suspension leaves open for GitHub logins.

### Tokens

An SSH login mints an ordinary control token with two more `meta` entries: `auth: "ssh"` and `ssh_fingerprint: "SHA256:..."`. `login` is the user's stored GitHub login (`users.login`, display only, as today). A GitHub login now also writes `auth: "github"`; a token without `auth` is treated as GitHub, for tokens minted before the change (they expire within 30 minutes of the deploy anyway).

`auth::User` gains `auth: AuthMethod`, `Github` or `Ssh { fingerprint }`. `authenticate` copies it into the audit event on every request (`auth_method`, `auth_ssh_fingerprint`, below).

**Revocation.** For a token with `auth: "ssh"`, `authenticate` also requires the key's row to exist, to verify, and to belong to the token's `github_id`. The store answers this together with the logout cutoff in one query, `token_state(github_id, Some(fingerprint))`, a `users` read with a `LEFT JOIN` on the key, so an SSH token costs the same one D1 round trip a GitHub token does, plus one HMAC under the already-open control root. A key that is gone or doesn't verify fails the token as `auth_failed`, labelled `ssh_key_revoked`. Removing a key therefore ends every token it minted on the next request, without logging out the user's other sessions. `POST /v1/logout` keeps ending every control token the user holds, of both kinds.

**Freshness.** An SSH login is a login: its token's `iat` is the login time, and `User::fresh` counts it for export and for registering keys exactly as a GitHub login. Owner decision D-A (decided: yes, every key type) covers this.

### Registering a key

Registration takes three things: a fresh session, the public key, and a signature by that key over a registration challenge.

**Fresh session.** `POST /v1/me/ssh-keys/challenge` and `POST /v1/me/ssh-keys` both require `User::fresh` (`403 fresh login required`, code `fresh_login_required`, as export). A stolen control token (30-minute TTL) can add a key only in the first five minutes after its victim logged in. This applies to SSH sessions too; the operator asked for registration from SSH sessions to be allowed, and it is.

**Proof of possession.** The registrant signs a registration challenge (purpose `SshKeyProof`, 300 seconds, single use, bound to the control origin) with the namespace **`edgekms-register`**, never `edgekms`. Three reasons:

- Without it, a signed-in user could register someone else's public key (from `github.com/<login>.keys`) to squat it, and the uniqueness refusal (`409 ssh_key_in_use`) would tell any signed-in user whether a given public key is registered to some edgekms account. With it, only the key's holder ever reaches the uniqueness check.
- It tests the break-glass path at registration time. A key that can't produce an agent signature fails now, when the owner can fix it, and not during an outage.
- The distinct namespace keeps the console's hand-run signing command from becoming a phishing pattern. The console asks people to run `ssh-keygen -Y sign -n edgekms-register`. A login needs `-n edgekms`. A page that gets someone to sign a stolen login challenge with the registration command gets a signature that can't log in, and the CLI never signs anything with `edgekms-register` except a registration challenge whose origin it has checked.

**Bound to the account** ([edgekms#17](https://github.com/lokkju/edgekms/issues/17)). Before the fix, the registration challenge didn't name an account, so a registration signature was useful to whoever presented it first, within 300 seconds, from a fresh session, for a key not yet registered: someone who intercepted it, or who talked the key's holder into signing their own challenge (registration phishing). They registered the victim's key to their own account. That gave them no access, but the victim couldn't register the key themselves (`409 ssh_key_in_use`), and a later `edgekms account login --ssh` with it signed the victim in to the attacker's account, where anything they created or imported landed.

The challenge now names the account in the text that's signed (see **The challenge**), and the server refuses a challenge naming any account but the session's. That leaves one way to put a key on an account: a signature by the key over text that names that account. The server check stops a signature made for one account from registering the key to another; what stops phishing is that the person asked to sign sees whose account it is. `edgekms account ssh-keys add` prints `Registering SSH key SHA256:... to GitHub account <login> (<id>).` before it signs, and refuses (without signing) a challenge naming any account but the one the control token's claims name, or the one `--expect-github-id` names. The console never shows a signing command for a challenge naming anyone but the signed-in user, names the account above the command and in the confirmation, and the command itself first prints `Registering this key to GitHub account <login> (<id>)` on stderr. A phishing page can still hand someone a command for the attacker's challenge, but the attacker's login is then in the command, in what it prints, and in the text being signed. Registration challenges in flight when this shipped (old format) fail as malformed; they lived 300 seconds.

A phished login signature (namespace `edgekms`) is a separate matter: the namespace split above keeps a registration command from producing one. The CLI's stderr names the account an SSH login lands in (`Logged in ... as <login> (GitHub id N)`), and the key count tells a victim with no keys of their own that something is off.

**Cap.** At most `MAX_SSH_KEYS_PER_USER` (10) keys per account, checked in the insert statement (`409 ssh_key_limit`).

**Lineage.** Each row records `added_via`: `github`, or `ssh:<fingerprint>` naming the key behind the session that added it. Removing a key doesn't remove the keys it added; the console shows them and offers to (see Console). The audit event records the same.

**Summary on login.** Both login replies carry `ssh_keys`, the number of keys registered to the account, and the CLI prints it on stderr after every `account login` ("2 SSH keys can log in to this account; see `edgekms account ssh-keys list`"). An owner recovering a GitHub account, or noticing a key they didn't add, sees it at the next login.

### Removing keys

`DELETE /v1/me/ssh-keys/:id` removes one of the caller's keys, from any session, fresh or not. Removal is the incident-response action, and it must stay easy. A stolen session can remove the owner's keys, which is a denial of service against SSH login only; the owner's GitHub login is untouched.

Operators get `DELETE /v1/ops/users/:github_id/ssh-keys`: remove every key the user holds and raise their `tokens_after_ms` to now, in one batch. It is the account-level kill switch for a compromised user who can't act themselves (owner decision D-E). There is no separate "SSH disabled" flag on the account: an account with no keys can't log in with SSH, and only a fresh session can add one.

An operator's own SSH session can call operator routes, since operator status is the `github_id`'s. That is the operator's break-glass for the control plane itself when GitHub is unavailable.

## Data model

Migration `crates/edgekms-worker/migrations/0006_ssh_keys.sql`. The invite-requests change claims `0005_invite_requests.sql`; whichever of the two merges second takes the higher number.

```sql
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
  fingerprint  TEXT    PRIMARY KEY,   -- 'SHA256:' + unpadded base64 of the key blob's SHA-256
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
```

**MAC.** `MacPurpose::SshKey`, info `mac/ssh-key/v1`. `edgekms_core::hosted::ssh_key_mac_input(github_id: u64, added_ms: u64, fingerprint: &str, public_key: &str, label: &str, added_via: &str) -> Vec<u8>`: `github_id` u64 BE, `added_ms` u64 BE, then each string as `len` u32 BE followed by its bytes. The MAC binds the key to its account (a real row moved to another `github_id` fails), and covers the label and lineage, so a D1 writer can't relabel an attacker's key "laptop" or hide where it came from. `Seal` gains `ssh_key(...)` and `ssh_key_ok(&row)`, logging `ssh_key_mac_invalid`.

**Key id.** Routes name a key by its id: the fingerprint's base64 part in base64url (`+` to `-`, `/` to `_`), 43 characters, since a fingerprint's `/` can't go in a path segment. The CLI accepts either form and converts.

**Label rules** (checked by the control plane; the CLI and console mirror them for early feedback only): optional; trimmed; at most 64 Unicode scalar values; no control characters and no bidirectional formatting characters (U+202A to U+202E, U+2066 to U+2069). Violations are `400` with code `label_invalid`. The CLI defaults the label to the key's comment when that comment passes the rules.

**Public key rules:** one OpenSSH public key line, at most 8 KiB, parsed with `ssh_key::PublicKey::from_openssh`, a supported algorithm, stored without its comment. Anything else is `400` with code `ssh_key_invalid` (unparseable) or `ssh_key_unsupported` (a type outside the three).

**Store** (`TenantStore`, D1 and in-memory):

| Method | SQL shape | Errors |
|---|---|---|
| `ssh_key(fingerprint) -> Option<SshKeyRow>` | `SELECT ... WHERE fingerprint = ?1` | |
| `ssh_keys_for_user(github_id) -> Vec<SshKeyRow>` | `SELECT ... WHERE github_id = ?1 ORDER BY added_ms` | |
| `insert_ssh_key(row, max)` | `INSERT ... SELECT ... WHERE (SELECT count(*) FROM ssh_keys WHERE github_id = ?) < ?max` | `Conflict` on the primary key, `CapReached` when no row was inserted |
| `delete_ssh_key(github_id, fingerprint)` | `DELETE ... WHERE fingerprint = ?1 AND github_id = ?2` | `NotFound` |
| `revoke_user_ssh_keys(github_id, now_ms)` | one batch: `DELETE FROM ssh_keys WHERE github_id = ?1`, then `UPDATE users SET tokens_after_ms = max(tokens_after_ms, ?2)` | `NotFound` for an unknown user |
| `consume_challenge(tag, expires_ms, now_ms)` | one batch: `DELETE FROM used_ssh_challenges WHERE expires_ms < ?now`, then `INSERT INTO used_ssh_challenges ...` | `Conflict` on the primary key (a replay) |
| `ssh_login_used(github_id, fingerprint, now_ms)` | one batch: `UPDATE users SET last_login_ms`, `UPDATE ssh_keys SET last_used_ms` | |
| `token_state(github_id, fingerprint: Option<&str>) -> Option<(u64, Option<SshKeyRow>)>` | `SELECT u.tokens_after_ms, k.* FROM users u LEFT JOIN ssh_keys k ON k.github_id = u.github_id AND k.fingerprint = ?2 WHERE u.github_id = ?1`; replaces `tokens_after` in `authenticate` | |

The delete is conditional on `github_id`, so a user can't remove another's key by id, and a removal racing a re-registration by the same user removes only what it names.

## API

Bodies use the existing envelope. Every request counts one `CONTROL_LIMIT` unit per limit key and is refused without a client IP, as `control::handle` does today. The control plane sees no query strings, so no route takes one.

| Route | Who | Audit op | Durable |
|---|---|---|---|
| `POST /v1/login/ssh/challenge` | anyone | `control_ssh_challenge` | metric only |
| `POST /v1/login/ssh` | anyone with a registered key | `control_login_ssh` | yes |
| `GET /v1/me/ssh-keys` | any user | `ssh_key_list` | metric only |
| `POST /v1/me/ssh-keys/challenge` | any user, fresh | `ssh_key_challenge` | metric only |
| `POST /v1/me/ssh-keys` | any user, fresh | `ssh_key_add` | yes |
| `DELETE /v1/me/ssh-keys/:id` | the key's user | `ssh_key_remove` | yes |
| `DELETE /v1/ops/users/:github_id/ssh-keys` | operators | `ssh_keys_revoke` | yes |

### `POST /v1/login/ssh/challenge`

Body `{}` (or empty). Counts against `LOGIN_LIMIT` per IP. `200`:

```json
{"data": {"challenge": "ekmsc.AAAA...", "expires_in": 60}}
```

`429` over a limit. No other outcome depends on the caller; the reply is the same for everyone.

### `POST /v1/login/ssh`

```json
{"challenge": "ekmsc.AAAA...", "signature": "-----BEGIN SSH SIGNATURE-----\n...\n-----END SSH SIGNATURE-----\n"}
```

Counts against `LOGIN_LIMIT` per IP before anything else. `200`:

```json
{"data": {
  "token": "ekms.…",
  "expires_in": 1800,
  "github_id": 583231,
  "login": "octocat",
  "auth": "ssh",
  "ssh_fingerprint": "SHA256:…",
  "ssh_keys": 2
}}
```

Refusals:

| Status | Body | When |
|---|---|---|
| `400` | `permission denied` | every credential failure: malformed body or fields, a bad, expired, future or foreign-origin challenge, a malformed, wrong-namespace, unsupported or invalid signature, no user presence, a replayed challenge, an unregistered key, a row that doesn't verify, an account SSH can't reach |
| `429` | `rate limit quota exceeded` | over `LOGIN_LIMIT`, or over `AUTH_FAIL_LIMIT` in place of a `400` |
| `500` | `internal error` / `audit log unavailable` | store, root or audit failure |

Audit labels, one per cause: `ssh_challenge_malformed`, `ssh_challenge_mac`, `ssh_challenge_wrong_origin`, `ssh_challenge_expired`, `ssh_challenge_from_future`, `ssh_signature_malformed`, `ssh_wrong_namespace`, `ssh_unsupported_key_type`, `ssh_bad_signature`, `ssh_user_not_present`, `ssh_challenge_replayed`, `ssh_key_unknown`, `ssh_key_mac_invalid`, `ssh_not_existing`. The event names the key (`auth_ssh_fingerprint`) only once the signature has verified; before that, the key in the signature is whatever the sender put there, and recording it would let anyone write a victim's fingerprint into the log beside a failure.

### `GET /v1/me/ssh-keys`

`200`:

```json
{"data": {
  "keys": [{
    "id": "q3Ji…",
    "fingerprint": "SHA256:q3Ji…",
    "key_type": "sk-ssh-ed25519@openssh.com",
    "public_key": "sk-ssh-ed25519@openssh.com AAAA…",
    "label": "yubikey-5c",
    "added_ms": 1762900000000,
    "added_via": "github",
    "last_used_ms": 1762900500000
  }],
  "unverified": ["SHA256:…"]
}}
```

`unverified` lists the fingerprints of the caller's rows whose MAC doesn't verify, for the caller to delete, as the allowlist listing does.

### `POST /v1/me/ssh-keys/challenge`

Body `{}`. `403 fresh login required` (code `fresh_login_required`) for a stale session. `200`:

```json
{"data": {"challenge": "ekmsr.583231.octocat.AAAA...", "expires_in": 300, "namespace": "edgekms-register", "github_id": 583231, "login": "octocat"}}
```

The challenge names the session's account (the token's `github_id` and `login`); `github_id` and `login` repeat it for a client that shows it, though the console and the CLI read it from the challenge, which is what gets signed. A token whose login doesn't have a GitHub login's shape gets a `500`; GitHub never issues one.

### `POST /v1/me/ssh-keys`

```json
{
  "public_key": "ssh-ed25519 AAAAC3Nza… nick@laptop",
  "label": "laptop",
  "challenge": "ekmsr.583231.octocat.AAAA...",
  "signature": "-----BEGIN SSH SIGNATURE-----\n...\n-----END SSH SIGNATURE-----\n"
}
```

The signature must verify against `public_key` (not merely against the key embedded in it), over `challenge`, with namespace `edgekms-register`, and with user presence for a security key. Checks run in order: fresh session, body shape, label, public key, challenge (which must name the session's `github_id`), signature, consume the challenge, insert. `201` with the new key object as in the listing.

| Status | Code | When |
|---|---|---|
| `400` | `label_invalid`, `ssh_key_invalid`, `ssh_key_unsupported` | the field named |
| `400` | `ssh_key_proof_failed` | the challenge or signature doesn't check out, the challenge names another account (audit label `ssh_challenge_wrong_account`), or the challenge was already used; counted against `AUTH_FAIL_LIMIT`, audit label naming the cause as on login |
| `403` | `fresh_login_required` | the session's login is five minutes old or more |
| `409` | `ssh_key_in_use` | the key is registered already, to this account or another |
| `409` | `ssh_key_limit` | the account holds `MAX_SSH_KEYS_PER_USER` keys |

`ssh_key_in_use` doesn't say which account. With proof of possession only the key's holder can reach it, and they could find out the same thing by logging in.

The audit event records `target_ssh_fingerprint` and `target_ssh_key_type` for the new key, and the caller's `auth_method` and `auth_ssh_fingerprint`.

### `DELETE /v1/me/ssh-keys/:id`

`204`. `404 ssh key not found` when the caller holds no key with that id (whether or not anyone else does). `400` for an id that isn't 43 base64url characters. Rows that don't verify can be deleted. The audit event records `target_ssh_fingerprint`.

### `DELETE /v1/ops/users/:github_id/ssh-keys`

Operators only (`403 permission denied` otherwise). Removes every key of the user and raises their `tokens_after_ms` to now. `200 {"data": {"removed": n}}`; `404` for an unknown user. The audit event records `target_github_id` and `removed`.

### Routing and console proxy

`control::Route` gains `LoginSsh`, `LoginSshChallenge`, `SshKeys`, `SshKeyChallenge`, `SshKeyAdd`, `SshKeyRemove(&str)` and `OpsRevokeSshKeys(&str)`. `dispatch` answers the two login routes before `authenticate`, as it does `POST /v1/login/github`. The console's proxy already refuses any `/api/v1/login*` path, which covers both new login routes; `/api/v1/me/ssh-keys*` passes through it under the usual same-origin, `SameSite=Strict` and JSON content-type rules.

### Audit event fields

`AuditEvent` gains four optional typed fields, for control events only:

- `auth_method`: `github` or `ssh`, on every event made under a control token, and on a successful login.
- `auth_ssh_fingerprint`: the key behind the caller's token, on every event made under an SSH-minted token (an export, a config edit, a member change), and the authenticating key on `control_login_ssh`.
- `target_ssh_fingerprint`, `target_ssh_key_type`: the key added or removed.

Typed fields, since `meta` is the data plane's token metadata with its own allowlist.

### Rate limits

| Route | `CONTROL_LIMIT` | `LOGIN_LIMIT` | `AUTH_FAIL_LIMIT` |
|---|---|---|---|
| `POST /v1/login/ssh/challenge` | yes | yes | no |
| `POST /v1/login/ssh` | yes | yes | on every refusal |
| `POST /v1/me/ssh-keys` | yes | no | on `ssh_key_proof_failed`, and on a bad token as every authenticated route |
| other new routes | yes | no | on a bad token |

`LOGIN_LIMIT` is bound in the hosted Worker already (30 a minute per IP) and unused by the control plane until now. An SSH login costs two `CONTROL_LIMIT` and two `LOGIN_LIMIT` units.

## Security argument

### What an SSH login is worth

A control token from an SSH login has the full power of one from a GitHub login: config edits, member changes, and, while fresh, export of every root its user owns and registration of more keys. A registered key is therefore as strong as the GitHub account it sits beside. Everything below follows from treating it that way.

### Threat: a stolen or borrowed ssh-agent

Someone with access to the user's agent socket (a forwarded agent on a compromised host, a malicious process on the workstation) can sign while that access lasts. With it they can log in, export every root the user owns, and, since their own login is fresh, register a key of their own and keep access after the agent goes away.

What limits it:

- Only registered keys work. A forwarded agent full of deploy keys gives nothing unless one of them is registered.
- A `sk-ssh-ed25519` key signs only with a touch: core refuses a signature without the user-presence flag, on the control plane as on the data plane. An agent key added with `ssh-add -c` asks for confirmation on each signature. The docs recommend registering only such keys (D-B decided not to require it).
- Every login, export and registration names the key's fingerprint in the audit log.
- The backdoor key is visible: `account login` prints the key count at every login, the console lists every key with its `added_via`, and a key added from an SSH session names the key that added it.
- Removing the stolen key ends every token it minted on the next request. The console offers to remove the keys it added in the same step.

What it doesn't limit: an export made while the attacker had the agent can't be taken back. That is the same exposure as a stolen GitHub session within its first five minutes, and the reason D-B exists.

### Threat: a stolen control token

From `EDGEKMS_CONTROL_TOKEN` in a shell, a CI log, or a process environment (the console's cookie is `HttpOnly`, and JavaScript never holds a token).

- It can't register a key unless it is under five minutes old, the same bar as export. A token stolen later than that can't turn 30 minutes of access into permanent access.
- It can remove the owner's keys (a denial of service against SSH login; GitHub login still works) and do everything else a control token does until it expires or is cut off.
- `POST /v1/logout` ends it, of either kind. If it was minted by SSH, removing its key ends it too.
- A stolen login challenge and signature pair (from a debug log, say) is refused once the real login has used it, and expires in 60 seconds regardless.

### Threat: a D1 writer without the master

A leaked D1 credential can write any row but can't compute a MAC under the control root.

- It can't add a key: the row won't verify, so it logs no one in.
- It can't move a real key to another account or rewrite its label or lineage: `github_id`, `label` and `added_via` are under the MAC.
- It can't keep a revoked key's tokens alive by editing `ssh_keys` other than by restoring the deleted row itself (next point).
- It can **replay** a removed key's row from a backup or D1 Time Travel, which revives that key, exactly as it can replay a removed membership. That matters only with the key's private half as well, which is the combination the removal was meant to stop. The MAC binds a row's contents, not that it is current; fixing that for every MAC'd table is a separate change (a per-user epoch under the MAC), noted in the threat model and not taken here.
- It can delete `used_ssh_challenges` rows, which reopens replay of a captured login signature for the rest of that challenge's 60 seconds.
- It can delete key rows (a denial of service against SSH login), lower `tokens_after_ms` (as today), or change `last_used_ms` (display only).

None of this produces a control token without a private key that was registered at some point.

### Threat: a malicious tenant owner, or a hostile server

- Keys belong to users, not tenants. An owner can't list, add or remove a member's keys, and nothing about a tenant's roles or SSH mounts touches control-plane keys.
- An owner can't squat a member's public key on their own account: registration needs a signature by that key over a challenge naming the owner's account, which the member sees before signing ([edgekms#17](https://github.com/lokkju/edgekms/issues/17)).
- A tenant's data-plane challenge can't log in here: it is MAC'd under the tenant's root with `mac/challenge/v1`, and bound to `https://<name>.<apex>`. `api` is a reserved tenant name, so no tenant answers on the control origin.
- A hostile Worker (a tenant's custom code, or a self-hosted deployment) that fetches a control challenge and asks a user to sign it through `edgekms login ssh --addr https://evil.example` fails at the CLI's origin check. Through a page asking them to run a signing command by hand, it fails at the namespace: the console only ever asks for `-n edgekms-register`, and a login needs `-n edgekms`.

### Enumeration and timing

- The login body names no account. An unknown key, a known key with a bad signature, and a key whose account SSH can't reach all return `400 permission denied` after the same checks, and D1 is consulted only after a signature verifies, so only the private key's holder can observe the lookup.
- The challenge endpoint's reply doesn't depend on anything about the caller.
- `409 ssh_key_in_use` is reachable only with a valid proof by that key.
- Key ids in `DELETE /v1/me/ssh-keys/:id` return `404` alike for "someone else's" and "nobody's".

### Accounts, suspension and the kill switch

- Signup stays GitHub-only: an SSH login never creates a `users` row, a personal tenant or an allowlist entry, and ignores `SIGNUP_MODE`, letting in only users the "existing" rule admits.
- A user removed from every tenant can't log in with SSH, though their keys stay listed for when they come back.
- A suspended tenant's owners can still log in with SSH and export; its members can't log in on its account alone, as with GitHub.
- The kill switch for a user is `DELETE /v1/ops/users/:github_id/ssh-keys`, which also logs them out. For an operator's own account, GitHub login or another operator.

## CLI

### `edgekms account login --ssh [--key <file.pub>] [--api <url>]`

1. Pick the key (below).
2. `POST <api>/v1/login/ssh/challenge`.
3. Refuse to sign unless `challenge_origin(challenge)` equals the origin of `--api` (`LoginError::WrongOrigin`, as `login ssh`).
4. `ssh-keygen -Y sign -n edgekms -f <key.pub>` with the challenge on stdin and no trailing newline (the existing `SshKeygen` signer).
5. `POST <api>/v1/login/ssh`; print the token alone on stdout.

stderr: `Logged in as octocat (GitHub id 583231) with SSH key SHA256:…`, the token's lifetime and the five-minute export window, the key count, and the `export EDGEKMS_CONTROL_TOKEN=...` hint `account login` prints today. A `400 permission denied` adds: "the key isn't registered to an edgekms account that can log in, or the signature was refused; register keys with `edgekms account ssh-keys add` from a GitHub login". `--ssh` and `--client-id` conflict. The hosted-App host restriction (`HOSTED_API_HOSTS`) applies only to GitHub tokens and doesn't apply here; the origin check does that job for challenges.

**Key selection.** `--key` must be a `.pub` file, as for `login ssh`; ssh-keygen finds its private half in ssh-agent, or falls back to the private key file beside it. Without `--key`, the CLI runs `ssh-add -L` and keeps the keys of supported types. Exactly one: it writes that public key to a file in a fresh temporary directory (a public key, nothing secret), signs with it and removes the directory. None: an error saying the agent holds no Ed25519, `sk-ssh-ed25519` or ECDSA P-256 key and to pass `--key`. Several: an error listing each one's fingerprint and comment and asking for `--key`. The CLI doesn't try keys in turn: each failure counts against `AUTH_FAIL_LIMIT`, and each security key would ask for a touch.

### `edgekms account ssh-keys list|add|remove`

All read `EDGEKMS_CONTROL_TOKEN` and take `--api`.

- `list`: one line per key, `id<TAB>fingerprint<TAB>key_type<TAB>label<TAB>added_ms<TAB>added_via<TAB>last_used_ms` (empty when never used), then `unverified<TAB><fingerprint>` lines for rows that don't verify.
- `add [--key <file.pub>] [--label <text>] [--expect-github-id <id>]`: the same key selection as login; the label defaults to the key's comment if it passes the label rules. Fetches `/v1/me/ssh-keys/challenge`, checks its origin and that it names the expected account (`--expect-github-id`, else the `github_id` in the control token's claims, read without the MAC; a token without one needs the flag), prints `Registering SSH key SHA256:... to GitHub account <login> (<id>).`, signs with `ssh-keygen -Y sign -n edgekms-register`, posts. A challenge for another account is never signed. `fresh_login_required` prints "run `edgekms account login` (GitHub or `--ssh`) again; adding a key needs a login under five minutes old". Prints the new key's id and fingerprint on stderr; nothing on stdout.
- `remove <id or fingerprint>`: accepts the 43-character id or `SHA256:...`, converts, deletes. `404` prints "no such key on this account".

The `Signer` trait gains a namespace argument; `login ssh` passes `edgekms`.

## Console

A new route `/account` ("Account" in the header beside the user's login) with one section, **SSH keys**. No CSP, header or cookie change, and no new Worker route: everything goes through `/api/v1/me/ssh-keys*`.

**List.** A table of label, type, fingerprint (monospace, with a copy button), added (date and `added_via`, with a key's lineage shown as "added from SSH key `<label or short fingerprint>`"), last used. Rows under `unverified` show in a separate warning box with a Delete button and the line "This key's record failed its integrity check and can't log in."

**Add.** A form in three steps on one panel:

1. Paste a public key; optional label (defaulting to the pasted key's comment). The SPA parses the type and shows the fingerprint it will register, computed in the browser with `crypto.subtle.digest`, so the person can check it against `ssh-keygen -lf`.
2. "Get a signing command" calls `POST /api/v1/me/ssh-keys/challenge`. On `fresh_login_required` the SPA keeps the pasted key in `sessionStorage` (a public key, nothing secret), sends the person through `/auth/login?return_to=/account` as the Export page does, and restores the form afterwards. On success it shows, with a copy button and a five-minute countdown:

   ```
   printf '%s\n' 'Registering this key to GitHub account octocat (583231)' >&2; printf '%s' 'ekmsr.583231.octocat.AAAA…' | ssh-keygen -Y sign -n edgekms-register -f ~/.ssh/<your key>.pub
   ```

   The account comes from the challenge, and the page refuses one naming anyone but the signed-in user ([edgekms#17](https://github.com/lokkju/edgekms/issues/17)); it is shown above the command too, and the confirmation after **Add key** names it. The preamble is a command, not a `#` comment, because zsh takes a `#` line typed at its prompt for a command unless `interactive_comments` is set.

   with the note that `printf '%s'` (not `echo` or `<<<`) matters, since a trailing newline changes what is signed, and that the CLI's `edgekms account ssh-keys add` does all of this in one step.
3. Paste the `-----BEGIN SSH SIGNATURE-----` block; "Add key" posts. Errors map to their codes: `ssh_key_proof_failed` says the signature didn't match this key and challenge (get a new command and try again), `ssh_key_in_use`, `ssh_key_limit`, `label_invalid`, `ssh_key_invalid`, `ssh_key_unsupported` each get one sentence.

**Remove.** A Delete button per key with a confirmation naming its label and fingerprint. If other keys list this key in `added_via`, the confirmation lists them too, checked by default ("Also remove keys this key added"), and the SPA issues one `DELETE` per checked key. A console session is always a GitHub login, so removing a key never ends the console's own session.

**Home and sign-in.** No change. The console never offers SSH sign-in.

## Docs

- `docs/design.md`: the login-and-tokens paragraph, the route table, the audit paragraph (new ops and fields), the threat model (an SSH key's power, single-use control challenges beside the data plane's unchanged replay window, the replayed-key-row case under the D1 writer), and the data model paragraph.
- The CLI guide: `account login --ssh` and `account ssh-keys`, with the advice to register `sk-ssh-ed25519` keys or `ssh-add -c` keys and to use agent destination constraints (`ssh-add -h`) when forwarding.
- The console guide: the Account page, with a screenshot generated the way the existing ones are.

## Testing

**edgekms-core**

- `ControlChallenge` and `SshKeyProof` tags don't verify under `Challenge` or each other, under the same root; the existing `new_challenge` and `check_challenge` produce byte-identical output to before (a fixed-vector test).
- `check_challenge_with` honors its TTL; 300-second registration challenges expire at 301.
- `verify_embedded`: accepts each supported type, refuses RSA and `sk-ecdsa`, wrong namespace, a tampered signature, and an `sk-ssh-ed25519` signature with the presence flag clear; returns the fingerprint `ssh-keygen -lf` prints.
- `ssh_key_mac_input` length prefixes: two inputs that differ only in where a string boundary falls produce different bytes.
- Registration challenges ([edgekms#17](https://github.com/lokkju/edgekms/issues/17)): the account leads the text; a challenge for one account is refused (`WrongAccount`) when checked for another; a rewritten id or login fails the MAC; an `ekmsc.` challenge is malformed at registration and an `ekmsr.` one at login; logins of the wrong shape aren't minted, and non-canonical ids don't parse.

**edgekms-worker** (`tests/hosted.rs`, in-memory store, stub GitHub)

- Login happy path for each key type; the token carries `auth` and `ssh_fingerprint`; the reply's `ssh_keys` count.
- Every refusal is the same `400 permission denied` body, with the right audit label, counted against `AUTH_FAIL_LIMIT`; an unknown key and a known key with a bad signature make zero store calls (the in-memory store counts calls).
- Replay: the same challenge and signature succeed once and are refused (`ssh_challenge_replayed`) the second time.
- A tenant's data-plane challenge, and a registration challenge, are refused at login; a login challenge is refused at registration.
- Wrong origin, expired, from the future.
- A user with no verified memberships or invites is refused (`ssh_not_existing`); an operator with none is admitted; a suspended tenant's owner logs in and exports; its member doesn't log in on that membership. No personal tenant is created in `open` mode.
- Removing a key fails its tokens (`ssh_key_revoked`) and leaves the user's GitHub token working; `POST /v1/logout` fails SSH tokens; the ops revoke removes all keys and fails all tokens.
- A row whose `github_id`, `label` or `added_via` was rewritten in the store doesn't log in, doesn't keep a token alive, and is listed under `unverified`.
- Registration bound to its account: a challenge minted for one user, signed by a key, is refused from another user's session (`ssh_challenge_wrong_account`) and the key stays unregistered; a challenge with its account rewritten fails the MAC; an old-format challenge is refused; the reply names the account.
- Registration: needs fresh (a token at 299 seconds passes, at 300 fails); a proof by a different key than `public_key` fails; `-n edgekms` signatures are refused; the cap; `409 ssh_key_in_use` across accounts; `added_via` from a GitHub and from an SSH session.
- `DELETE` of another user's key is `404` and leaves it in place.
- Audit: the attempt-then-outcome pair for login, add, remove and ops revoke; `auth_ssh_fingerprint` on an export made under an SSH token; a failed login before signature verification records no fingerprint; an audit store failure withholds the token.
- Rate limits: both login routes count `LOGIN_LIMIT`; the console proxy refuses `/api/v1/login/ssh` and `/api/v1/login/ssh/challenge`.
- The D1 SQL for `insert_ssh_key`, `consume_challenge`, `token_state` and `revoke_user_ssh_keys` gets the same review against SQLite semantics the existing conditional statements had, and the in-memory store mirrors them.

**edgekms-cli**

- Fake transport and signer: the origin check refuses to sign a foreign challenge; the token alone goes to stdout; the namespace passed to the signer is `edgekms` for login and `edgekms-register` for add.
- Key selection with a stubbed `ssh-add -L`: one key, none, several, unsupported types filtered; the temporary directory is removed on success and failure.
- `remove` accepts both id and fingerprint forms.
- `add` announces the challenge's account before signing and never signs a challenge for another account or in the old format; the binary needs `--expect-github-id` when the token names no account, and refuses a mismatch after fetching only the challenge.

**Console** (vitest)

- The fingerprint computed in the browser matches `ssh-keygen -lf` for fixture keys; the signing command quotes the challenge safely, uses `printf '%s'`, and prints the challenge's account on stderr first; the account is read from the challenge and anything else is refused; the page refuses (Playwright) a challenge naming another account and names the account above the command and in the confirmation; the id and fingerprint conversion; the lineage grouping for removal.

**End to end** (`scripts/e2e-hosted.sh`, real `ssh-agent` and `ssh-keygen`)

- Log in through the GitHub stub, `account ssh-keys add` an Ed25519 key from a temporary agent, `account login --ssh` with no `--key`, `tenant export` with the SSH token, `ssh-keys remove`, and the SSH token then refused.

## Owner decisions

Decided 2026-11-11: the owner accepted every recommendation below. SSH logins count as fresh for export (D-A, option 1); security keys are encouraged in the docs and console, not required (D-B, option 1); registration needs proof of possession with namespace `edgekms-register` and a login under five minutes old (D-C, option 1); removing a key ends its tokens on the next request (D-D, option 1); operators get the kill-switch route (D-E, option 1); 10 keys per account as a constant (D-F); single-use login challenges stored in D1 (D-G, option 1). The options and reasoning stay below for the record.

- **D-A. Do SSH logins count as fresh for export?** Options: (1) yes, every supported key type; (2) only `sk-ssh-ed25519` logins count as fresh; (3) never, export stays GitHub-only. Recommendation: (1). Break-glass export when GitHub is unavailable is the reason the issue exists, and (3) defeats it. (2) is the stronger choice if the operator's break-glass keys are, or will be, security keys; it costs nothing in code beyond one check in `fresh`.
- **D-B. Require security keys?** Options: (1) any supported key can be registered; (2) only `sk-ssh-ed25519` keys can be registered for the control plane. Recommendation: (1), with the docs recommending security keys or `ssh-add -c` and the console marking non-touch keys "no touch required". The operator's stated use is a forwarded agent whose key type this spec doesn't know, and (2) would block it. Revisit when the operator's keys are known.
- **D-C. Proof of possession at registration.** Options: (1) a signature by the key, with namespace `edgekms-register`, required everywhere, which makes the console's add flow paste-key, run-a-command, paste-signature; (2) paste a public key only, as the issue first imagined for the console. Recommendation: (1). (2) lets any signed-in user squat someone else's public key and ask "is this public key on edgekms?" through the `409`, and lets an untested key sit registered until the outage it was meant for.
- **D-D. What removing a key does to its tokens.** Options: (1) ends tokens it minted on the next request (one `LEFT JOIN` in the existing per-request read); (2) nothing, they expire within 30 minutes; (3) logs the user out everywhere. Recommendation: (1). (2) leaves an attacker 30 minutes after the owner reacts; (3) logs out the owner's own session doing the removal.
- **D-E. Operator kill switch.** Options: (1) `DELETE /v1/ops/users/:github_id/ssh-keys`, which also logs the user out; (2) none, operators use D1 directly. Recommendation: (1). Deleting rows by hand in D1 is the operator acting as the D1 writer of the threat model, unaudited.
- **D-F. Keys per account.** Recommendation: 10, a constant (`MAX_SSH_KEYS_PER_USER`), not a var. No one needs more for break-glass, and a var invites tuning that never happens.
- **D-G. Single-use login challenges.** Options: (1) a D1 table of used challenge tags; (2) stateless, with the data plane's 60-second replay window. Recommendation: (1). The control plane already writes the D1 primary on every login, and a replayed control login can mint a token fresh enough to export.

## Calls made (builder's, the owner can override)

- The login body carries no `github_id`; the key names the account, enforced by the fingerprint being the table's primary key.
- D1 is consulted only after a signature verifies, which is the whole enumeration and timing argument.
- SSH logins reach exactly the users `admit` calls "existing" (operator, verified membership, verified pending invite), in every `SIGNUP_MODE`, and are refused with the uniform `400`, never `signup_closed`.
- Login challenges use namespace `edgekms` like the data plane; registration proofs use `edgekms-register`.
- Two new MAC purposes for challenges (`mac/control-challenge/v1`, `mac/ssh-key-proof/v1`) and one for rows (`mac/ssh-key/v1`), with the wire format of challenges unchanged.
- The bound origin is the request's origin, already pinned to `api.<apex>` by `dispatch_host`, which keeps `scripts/e2e-hosted`'s `http://api.localhost:8787` working without a new var.
- Registration requires a fresh login from either method, as the operator allowed registration from SSH sessions; removal requires any session.
- Removing a key doesn't cascade to keys it added; the console offers to remove them in the same step, checked by default.
- Labels are under the row MAC; `last_used_ms` isn't.
- The audit log gets typed fields (`auth_method`, `auth_ssh_fingerprint`, `target_ssh_fingerprint`, `target_ssh_key_type`), not `meta` entries.
- A failed login records the key's fingerprint only after the signature verified.
- Without `--key`, the CLI uses the agent's single supported key and refuses to guess among several.
- Both login replies report the account's key count, and the CLI prints it, so a key added behind the owner's back shows at their next login.
- No per-account "SSH disabled" flag: no keys means no SSH login.
- The migration is `0006`, behind the invite-requests change's `0005`; whichever merges second renumbers.
