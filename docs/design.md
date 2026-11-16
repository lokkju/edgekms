# edgekms design

Status: draft for review.

## What it is

A Cloudflare Worker that implements the part of Vault's API that encryption clients use: Transit
encrypt and decrypt, JWT-style login, and token self-service. Clients that already speak Vault
work against it by setting `VAULT_ADDR` and `VAULT_TOKEN`; nothing is patched or forked.

The first two consumers:

- **Pulumi stacks in CI.** `pulumi stack init --secrets-provider hashivault://<key>` wraps the
  stack's data key under an edgekms key. Pulumi decrypts it once per command, so traffic is one
  decrypt per `preview` or `up`.
- **OpenBao auto-unseal.** OpenBao's `seal "transit"` stanza points at edgekms, so an OpenBao
  cluster unseals itself after a restart with no operator holding unseal shares.

## Client surface

The endpoints, request and response shapes, errors and unsupported features are in
[api.md](api.md), which is published. I read both first clients (gocloud.dev's `hashivault`
for Pulumi, and OpenBao's transit seal) to pin down exactly what they call; api.md records the
result.

## Keys

The root key, named-key derivation, the ciphertext format and the exit path are in
[security-model.md](security-model.md#keys), which is published.

## Authentication

Mounts, roles and policies (the tenant config's login side) are in
[api.md](api.md#the-tenant-config), and the CLI's three login methods, with what each binds to,
in [security-model.md](security-model.md#cli-logins). Both are published.

## Tokens

Token format, lifetimes, created tokens and revocation are in
[security-model.md](security-model.md#tokens).

## Audit

The audit event fields, where events go and the "no audit, no operation" rule are in
[security-model.md](security-model.md#audit).

## Abuse limits

The rate limiters and body caps are in
[security-model.md](security-model.md#abuse-limits).

## Deployment

Cloudflare-native, no Pulumi. `wrangler.jsonc` declares the Worker and every binding:

- `r2_buckets`: the audit bucket
- `analytics_engine_datasets`: the audit dataset (created on first write)
- `kv_namespaces`: the revocation list for created tokens
- `ratelimits`: the three limiters
- `routes`: the Worker's custom domain (`kms.example.com` in the example instance), with
  `workers_dev` and `preview_urls` off so it has no other origin

Cloudflare's `cf` CLI (open beta since 2026-09-28) supersedes wrangler and moves configuration to
`cloudflare.config.ts`, but it still delegates Rust and Python Workers to wrangler, and it can't
yet declare Access applications or other account resources. So `wrangler.jsonc` stays the deploy
config, and the few things neither tool can declare are a one-time bootstrap, by hand or as a
mise task in the instance directory:

1. Generate the root key locally, set it as the Worker secret `ROOT_KEY` (`wrangler secret put`), and
   write an offline copy encrypted to a key the operator holds (age or SOPS). The plaintext key
   never touches disk, and the copy is written before the key goes to Cloudflare.
2. Create the R2 bucket with its lock rule, and the KV namespace.

An instance with a `github-user` mount also needs a GitHub App with device flow enabled and no
permissions (GitHub, Settings, Developer settings, GitHub Apps; no callback URL or webhook, and it
never needs installing). An OAuth App works too, but its user tokens never expire. Its client ID goes
in the mount (`{"type": "github-user", "client_id": "..."}`) and is what operators pass to
`edgekms login github --client-id`; its client secret becomes the Worker secret
`GITHUB_CLIENT_SECRET`, piped on stdin the same way as `ROOT_KEY`
(`... | wrangler secret put GITHUB_CLIENT_SECRET`), never in argv or the repo. Without the secret,
every login on that mount is a `500`.

Instance configuration (keys, roles, policies, mounts) is a JSON object the Worker reads from its
`EDGEKMS_CONFIG` binding at startup, never compiled in. Self-hosted, it lives in
`deploy/<instance>/config.json`; the instance's deploy task (`mise -C deploy/<instance> run
deploy`) validates it with the same code the Worker uses and passes the compacted JSON to
`wrangler deploy` as `--var EDGEKMS_CONFIG:<json>`, so a policy change is a reviewed commit and a
deploy. The hosted tier doesn't deploy per tenant: one Worker serves every tenant, and a tenant's
config lives in D1 and changes through the control plane with no deploy (see
[Hosted tier](#hosted-tier)).

Self-hosters start from `deploy/example/`, a single-tenant instance: a `wrangler.jsonc` with
placeholders for the account, domain and resource ids, a `config.json`, and a README that walks
through the bootstrap and the first deploy. `deploy/example-hosted/` is the same for hosted mode,
with mise tasks to build, deploy, apply the D1 migrations and check the config against the
hosted-mode rules. An operator's real instance directories can live in a deployment repo of their
own, pointing the tasks at an edgekms checkout with `EDGEKMS_SRC`.

The Worker reads `ROOT_KEY` from a Secrets Store binding if it has one, and from a plain Worker
secret otherwise. The example instance uses the Worker secret: an API token for an account shared
with other projects often doesn't have Secrets Store scope, and a Worker secret is bound to that one Worker, while any
Worker in a Cloudflare account can bind any Secrets Store secret (so everyone who can deploy
Workers to the account could read a root key kept there). Production instances belong in a
dedicated account with few members, hardware-key 2FA and narrowly scoped tokens; there the root key
can move to Secrets Store.

A self-hosted instance deploys from the operator's machine. CI deploys need a Cloudflare token in
CI, which an OIDC credential broker (short-lived, scoped API credentials for CI, with no stored
token) would remove; such a broker could share edgekms's auth layer. The hosted service deploys
from GitHub Actions with an IP-restricted token behind an environment that needs the owner's
approval.

## Testing

- Unit tests for the ciphertext format, key derivation, JWT verification (expired, wrong `aud`,
  wrong `iss`, `alg: none`, unknown `kid`, HS256 with the public key as secret) and policy
  matching.
- Cross-compatibility: `scripts/openbao-vectors.sh` runs a throwaway OpenBao dev server with an
  exportable `aes256-gcm96` key at version 2 and records OpenBao's ciphertexts and the exported
  raw key versions as vectors that both `KeyOps` implementations must decrypt; it also checks that
  OpenBao decrypts what edgekms writes under each exported version. Nothing yet tests importing a
  CLI-exported key through BYOK.
- End to end, `scripts/e2e.sh` against `wrangler dev`: the CLI's SSH login, a JWT login,
  `pulumi stack init --secrets-provider hashivault://...` with a local backend and a secret
  round-trip, an OpenBao container with `seal "transit"` that unseals after init and after a
  restart, stays sealed once its seal token is revoked, and finally the audit log in the local R2
  bucket.
- The hosted Worker end to end, `scripts/e2e-hosted.sh` against `wrangler dev` with local D1, KV,
  R2, rate limiters, a local Secrets Store master and a GitHub stub: the CLI's `account login`
  and every `tenant` command, data-plane logins and transit at `http://<tenant>.localhost`,
  import and export (fresh, and refused past 300 seconds), tenant isolation, a config tampered
  in D1, suspension, rate-limit keying, master rotation through `ops/rewrap`, and sops against a
  tenant.

## Implementation

Rust, as a Cargo workspace:

- **edgekms-core:** ciphertext format, config model, JWT claim checks, SSH signature checks, role
  matching, policy, token format. No I/O; time, randomness and key material are parameters.
  Builds for `wasm32-unknown-unknown` with no `getrandom` dependency, and is tested natively.
- **edgekms-worker:** workers-rs routing, bindings, JWKS fetch and cache, audit writes. Randomness comes from `crypto.getRandomValues` through `getrandom`'s `wasm_js` backend.
  Request bodies, parsed request fields and replies (plaintext, JWTs, tokens) are zeroized when
  they are dropped, as is every buffer edgekms grows them in. What is left on the Rust side is
  serde_json's scratch buffer for a JSON string with escapes in it and the `Vec` workers-rs frees
  after copying a response body into JavaScript; the JavaScript and WebCrypto copies are out of
  Rust's reach.
- **edgekms-cli:** `login ssh`, `login github`, `login oidc`, offline `decrypt`, offline
  `export` for BYOK import, and for the hosted tier `account` (control-plane login and logout)
  and `tenant` (tenants, config, members and invitations, export). The bootstrap ceremony isn't a
  CLI command; it's a mise task in each instance directory.

Secret-key operations go through a `KeyOps` trait in core with two implementations that must
produce identical bytes:

- **`SoftKeyOps`** (core, RustCrypto: `aes-gcm`, `hkdf`, `hmac`, `sha2`), used by the CLI and the
  native tests.
- **`WebCryptoKeyOps`** (worker): the root key is imported into Workers' WebCrypto as a
  non-extractable HKDF key, and every derived AES-GCM and HMAC key is non-extractable too. Key
  bytes then live in the runtime's native memory, not the wasm module's linear memory, so a
  memory-disclosure bug in edgekms's own code can't read them. It's the same process, not
  hardware isolation. Derived key handles are cached per isolate, so each key is derived once
  per isolate rather than once per operation.

Both implementations pass the same OpenBao and HKDF vectors (the WebCrypto one through
`wasm-bindgen-test` under Node), so the break-glass CLI and the Worker can't drift apart.

JWT signature checks work the same way: core does parsing, the algorithm allowlist and claim
checks, generic over a `JwsVerifier` trait. The Worker verifies RS256 and ES256 with WebCrypto;
native tests use RustCrypto `rsa`/`p256` as dev-dependencies only, so the deployed Worker carries
no `rsa` crate (its stable line has the Marvin timing advisory, and its next line is still a
release candidate). SSH signatures are checked in core with `ssh-key`, limited to Ed25519,
`sk-ssh-ed25519` and ECDSA P-256 keys.

release-plz versions and tags the CLI (SemVer) and writes changelogs. The Worker is deployed, not
released.

## Hosted tier

The hosted tier is edgekms run as a service at `edgekms.dev`, for anyone with a GitHub account:
one shared Worker for every tenant, GitHub login, and a pricing target of free or about $1 a month.
That design replaced an earlier plan built on a Worker per tenant on Workers for Platforms with
Clerk for identity. `deploy/example-hosted/` shows how to run hosted mode yourself. A user-facing
walkthrough is [docs/hosted-quickstart.md](hosted-quickstart.md).

### Self-hosted and hosted mode

One Worker build serves both. The `HOSTED_APEX` var picks the mode:

- **No `HOSTED_APEX`:** single-tenant, exactly as the rest of this document describes. The Worker
  reads `EDGEKMS_CONFIG` and `ROOT_KEY` and serves one deployment at its own origin. Nothing in
  this section applies, and limiter keys are the plain client IP as before.
- **`HOSTED_APEX` set** (`edgekms.dev` in production, `localhost` under `wrangler dev`): multi-tenant.
  The Worker also needs `HOSTED_ORIGIN_TEMPLATE` (`https://{tenant}.edgekms.dev`, with exactly one
  `{tenant}`), `GITHUB_CLIENT_ID`, `SIGNUP_MODE`, the D1 binding `TENANTS`, the KV binding `REVOKED`,
  `MASTER_KEY_CURRENT` and a `MASTER_KEY_M<n>` binding for each master version in use. A missing
  or malformed one is a `500` with a fixed log label.

A Worker with `HOSTED_APEX` and also `EDGEKMS_CONFIG` or `ROOT_KEY` bound, under any kind of
binding, refuses every request with `500` and logs `hosted_and_single_tenant_bindings`. An
ambiguous configuration fails closed, never into one mode or the other. `GITHUB_API_BASE`, which
points the GitHub checks at a stub for the hosted end-to-end run, is honoured only when the apex
is `localhost`; any other value with any other apex refuses every request.

### Users and tenants

A **user** is a GitHub identity. Everyone logs in through one public GitHub App, `edgekms`
(device flow, no permissions, never installed), so signing up is logging in once, when
`SIGNUP_MODE` lets you in (below). There are no passwords and no other identity provider.

A **tenant** owns keys, roles and policies: one config of exactly the shape a self-hosted
`config.json` has, and its own root key. Each tenant is `https://<tenant>.edgekms.dev`. Every Vault
client works with `VAULT_ADDR` alone, origin-bound SSH challenges isolate tenants with no change
(each tenant is its own origin), and Universal SSL's `*.edgekms.dev` certificate covers every tenant
without putting tenant names in certificate-transparency logs.

Tenant names are 3 to 32 characters of `[a-z0-9-]`, start and end with a letter or digit, never
contain `--` (which also rules out `xn--` punycode labels, and so homographs), don't start with
`edgekms`, and aren't on a reserved list (`api`, `www`, `docs`, `app`, `admin`, `vault` and
about sixty others kept for the service). Uppercase is refused, not folded. The Host header
picks the route: `api.edgekms.dev` is the control plane, a valid tenant name is a tenant, and
anything else (a reserved name, a deeper label such as `a.b.edgekms.dev`, a host outside the apex)
is a bare `404`, answered before the body is read.

Users reach tenants two ways, and the two don't mix:

- **Control-plane membership** (owners and members) decides who can read and change a tenant
  through `api.edgekms.dev`. Owners edit the config, manage members and export the root key; members
  can only read the tenant, its config and its member list.
- **Data-plane access** comes from the tenant config's roles, exactly as self-hosted. A CI job
  binds a GitHub OIDC role, an operator an SSH key, a GitHub user id or an OIDC subject. Being an
  owner grants no data-plane access by itself; the default config binds the owner's GitHub id to
  an `owner` role, which is why logging in right after signup works.

The first control-plane login creates the user's **personal tenant**, named after the GitHub
login lowercased if that's a valid, free name, otherwise the login folded to a valid stem plus
`-` and 4 random hex digits. It gets a fresh root, one key `default`, a `github-user` mount on
the hosted App, and an `owner` role binding the user's GitHub id to the policies `admin` (token
create and revoke) and `default-all` (encrypt, decrypt, rewrap and read on `default`), with a
one-hour token TTL. Tenants the user was only invited into don't count: an invited user still
gets a personal tenant at first login.

**Who can sign up** is the signup gate. The required var `SIGNUP_MODE`
is `closed`, `invite` or `open`; a missing or unknown value fails the control plane's settings, so
every control request is a `500` rather than a guess at a mode. Two kinds of user can always log
in, in every mode: operators, and existing users, meaning anyone holding at least one membership
whose MAC verifies, so closing signups never locks anyone out of their own tenants. A membership
in a suspended tenant counts only for its owners, who keep the export that suspension leaves
open; its members don't count. `invite` also
admits the GitHub ids on the **signup allowlist**, which operators manage with
`PUT` and `DELETE /v1/ops/allowlist/:github_id` and `GET /v1/ops/allowlist`
(`edgekms ops allowlist add|remove|list`), and `open` admits anyone. Everyone else gets
`403 signups are closed`, with `"code": "signup_closed"` for the CLI, after the GitHub token has
been checked and revoked as for any login, and the refusal counts against `AUTH_FAIL_LIMIT`. Only
a login the mode admits creates a personal tenant: an existing user let in by their memberships
alone (a member of someone else's tenant while signups are closed) gets a control token and
nothing else. A pending invitation whose MAC verifies, to an active tenant, also lets its
invitee log in, in every mode (decided with the web console,
[lokkju/edgekms#13](https://github.com/lokkju/edgekms/issues/13)), so they can accept or decline
it; like a member let in by memberships alone, they get a control token and no personal tenant,
so an owner can offer a seat in their tenant but can't open signups to whoever they invite.
Production runs `invite`, which with an empty
allowlist admits exactly what `closed` does and lets an operator add people one at a time.

**Invite requests** ([lokkju/edgekms#12](https://github.com/lokkju/edgekms/issues/12)) give
someone refused in `invite` mode a way to ask. The refusal itself carries the proof of identity:
once the control root exists, a `signup_closed` refusal in `invite` mode adds a **request token**
(`request_token`, good for `request_expires_in`, 900 seconds), an ordinary `ekms.` token under
the control root with role `invite_request`, no policies, and the GitHub id and login
`check_token` just returned. It's minted after the GitHub token was revoked, from values already
in memory, so the GitHub token is revoked once, where it always was, and GitHub isn't asked
twice. The refused login's audit event records the request token's jti, which the request's own
events carry too. With it the user reads their request (`GET /v1/invite-requests/mine`) and files
one (`POST /v1/invite-requests`, an optional note of at most 500 characters with no control
character but a newline and no bidirectional formatting). Every control route refuses a request
token, since they require role `control`, and the requester routes refuse a control token, so it
grants exactly those two things; it's useless at a tenant like any control-root token. Without a
`users` row a logout can't cut it off; its 15 minutes bound it. The web console keeps it in its
own `HttpOnly`, `SameSite=Strict` cookie (`__Host-edgekms_request`) and sends it on the two
requester paths only, never the session cookie there, and the CLI's `edgekms account
request-invite` holds it in memory. In `closed` mode no request token
is issued, and `POST` rechecks the mode, so closing signups stops requests at once;
`MAX_PENDING_INVITE_REQUESTS` (default 200) caps the pending queue inside the insert statement,
and `0` stops new requests while the page still says why. One request per GitHub id: a pending or
approved request answers `409 already_requested`, a declined one `409 request_declined` until an
operator deletes it, and a user admitted since the refusal `409 already_admitted`. Operators list
(`GET /v1/ops/invite-requests`: every pending request, then the 100 most recently decided),
approve, decline and delete (`edgekms ops invite-requests`). Approving writes the user's allowlist
row and marks the request approved in one D1 batch, the allowlist insert conditional on the status
change having landed, so an approval never half-lands and two operators approving at once write
one allowlist row. Admission still reads only the allowlist. There's no notification, email or
automatic approval: the Ops page shows the pending count and each
account's age, looked up on GitHub from the operator's browser.

Creating a tenant takes the same admission as signing up, since the signup gate's intent is that only
operators and invited users get tenants: `POST /v1/tenants`, imports included, needs `open`
mode, an operator, a verified allowlist row in `invite` mode, or a tenant the user has already
created. Anyone else, such as a member logging in on memberships alone or a user taken off the
allowlist before creating anything, gets the same `403 signups are closed`. The last condition
reads `tenants.created_by`, which carries no MAC, so a D1 writer could let a user who can
already log in create tenants; those tenants are worth nothing without the master. The check
and the write aren't atomic with allowlist changes: a user taken off the allowlist while a
login or create of theirs is in flight can still finish it. I accepted that race; the window is
one request, and removal never revokes what a user already has.

A user can create at most five tenants (`MAX_TENANTS_PER_USER`), the personal tenant included.
The cap counts tenants the user created, not ones they own, so an invitation never uses it up,
and it's checked inside the insert, so concurrent creates can't overshoot it. **Operators**, the
numeric GitHub ids in `OPERATOR_GITHUB_IDS`, are exempt; they're also the only ones who can run
the master rewrap, suspend or reactivate a tenant, and manage the signup allowlist.

Beyond the personal tenant, a tenant a non-operator creates must be named
`<base>-<suffix>` (the naming rule), where the base is the same login stem the personal tenant's suffixed
name uses (the login lowercased, other characters folded to `-`, `u-` in front of a login starting
with `edgekms` or equal to a reserved name, so `support` names tenants `u-support-...`, at most
27 characters) and the whole name follows the usual rules. Anything else is
`403 tenant name must start with <base>-`, with `"code": "tenant_name_prefix"`. Operators may use
any valid name. The prefix is a namespace hint, not a reservation. It overlaps other users'
hyphenated logins: `acme` can create `acme-corp-prod`, which looks like it belongs to the user
`acme-corp`. Two logins can fold to the same base (`Foo_Bar` and `foo-bar`). And the base moves
with GitHub renames: it comes from the login in the control token, so a renamed account names new
tenants after its new login from its next login on, and its old base is free for whoever takes
the old login. The rule keeps names attributable at a glance; ownership is the membership, never
the name.

**Granting a role is an invitation.** An owner invites a GitHub user by numeric id (they needn't
have logged in yet), and nothing changes until the invitee accepts. That means no one can be made
a member without consent, and in particular no one can be made an owner, and so possibly the last
owner who can't leave, against their will. Accepting can raise a member to owner but never lowers
a role. Demoting an owner to member applies at once; the other changes are invitations. An owner
can withdraw an invitation or remove a member, but never the last owner (`400 tenant needs an
owner`). A tenant the caller isn't a member of answers `404 tenant not found`, exactly as one that
doesn't exist, so membership can't be probed.

**Membership and invite MACs.** Every `members` row carries an HMAC-SHA256 under a key derived
from the control plane's root (the `system_keys` row `control`, the same root control tokens use)
with `info = "mac/member/v1"`, over `tenant id || 0x00 || GitHub id (u64 big-endian) || role ||
0x00 || added_ms (u64 big-endian)`, where `added_ms` is when the row took its current role. Every
`invites` row carries one with `info = "mac/invite/v1"` over `tenant id || 0x00 || GitHub id ||
role || 0x00 || invited_by || invited_ms` (integers u64 big-endian). The control plane writes the
MAC with every row it creates or changes (a tenant's first owner, the personal tenant, an import,
an invitation, accepting, a demotion) and verifies it on every read; a row that fails is treated
as absent and logged as `member_mac_invalid` or `invite_mac_invalid`. Signup allowlist rows get
the same treatment with `info = "mac/allow/v1"` over `GitHub id || added_by || added_ms` (each u64
big-endian), logged as `allow_mac_invalid`; the allowlist listing shows the ids of rows that fail
under `unverified`, so an operator can delete them. Invite request rows carry one with
`info = "mac/invite-request/v1"` over `GitHub id || created_ms` (u64 big-endian) and the login and
note, each as a u32 big-endian length and its bytes, logged as `invite_request_mac_invalid`. A
request that fails reads as none to its requester, who may replace it, and as `unverified` to
operators, who can't approve it; so a D1 writer can't put a famous login beside its own GitHub id
and wait for an approval. The decision columns are outside that MAC: nothing is granted on them. Rows written before
migration `0003` hold an empty placeholder MAC, which never verifies. I used the control root
rather than each tenant's: it is already open for the token check on every request, so listing a
user's tenants costs no unwrap per tenant, and an owner who has exported a tenant's root (or
imported it) can't forge memberships with it. The last-owner rule counts only owners whose rows
verify, and because SQL can't check a MAC, the control plane picks a verified other owner and the
demotion or removal applies only while that exact row is still stored, in the same statement;
every membership write likewise applies only while the row it replaces, the invite it accepts
or deletes, and the acting owner's own row are the ones it read (otherwise `409 membership
changed; try again`). A row that doesn't parse (a negative integer, a mac that isn't a BLOB) is
skipped and logged like one that doesn't verify. Because every MAC hangs off the one control
root, that root is created only while the store holds no tenant, membership, allowlist or invite
request row.

### Tenant store

Tenants live in one D1 database, `edgekms-tenants` (schema in `crates/edgekms-worker/migrations/`):
`users` (GitHub id, login for display, and `tokens_after_ms` for logout), `tenants` (immutable id
`t_<16 hex>`, unique name, unique root id, the wrapped root and the master version that wrapped it,
the config JSON, its version and MAC, an `active` or `suspended` status, and who created it),
`members` (accepted memberships only), `invites` (pending ones), `signup_allowlist` (the GitHub
ids an operator lets sign up in `invite` mode, each with its MAC), `invite_requests` (one per
GitHub id: login, note, date, status and the deciding operator, with its MAC; migration `0005`),
`ssh_keys` (SSH public keys that can log in to the control plane, keyed by fingerprint so a key
belongs to one account, each with its label, lineage and MAC; migration `0006`),
`used_ssh_challenges` (the MAC tags of control-plane SSH challenges already accepted, until they
expire), and `system_keys` (the control plane's own token root, wrapped like a tenant's).

I picked D1 over KV because the control plane needs unique names and root ids, a tenant and its
owner created in one transaction, optimistic concurrency on `config_version` (two concurrent
edits mustn't silently lose one), and a resumable rewrap pass keyed by master version. KV gives
none of those, and its up-to-a-minute propagation would let a removed member linger unevenly
across locations. KV stays for the created-token revocation list, where its global read cache
fits.

The data plane reads D1 rarely. Each isolate caches up to 256 tenants it has served, each with
its unwrapped root handle and parsed config, and revalidates an entry with one indexed read of its
config version, status and master version at most every 30 seconds, through a
`first-unconstrained` D1 session (nearest replica). An unchanged version costs nothing more; a
changed one reloads the row, and a config edit doesn't unwrap the root again unless the root id or
master version changed. An unknown or suspended name is negative-cached for 10 seconds (up to
1024 names), so a scan of random subdomains costs one D1 read per name per isolate. A row that
fails to load (bad MAC, invalid config, unwrap failure) leaves the previous entry serving for at
most one more interval, so a bad write can't take a working tenant down instantly, and a broken
row never loads. The control plane reads and writes D1's primary only, so an owner sees their own
edit on the next request.

### Keys and wrapping

Per-tenant roots, master-key wrapping, the config MAC and the hosted config rules are in
[security-model.md](security-model.md#tenants-roots-and-the-master-key).

### Control plane

The control plane is part of the same Worker, under `src/control/`, and answers only on
`api.edgekms.dev`. Bodies use Vault's envelope (`{"data": ...}`, `{"errors": [...]}`).

The routes, and who may call each, are in [api.md](api.md#the-control-api).

**Login and control tokens.** `POST /v1/login/github` takes a GitHub user token from the device
flow, checks it was issued to the hosted App (the same `POST /applications/{client_id}/token`
check the `github-user` mount makes), revokes it, checks `SIGNUP_MODE` admits the user (before
anything is written), records the user, creates the personal tenant on a first login the mode
admits, and returns a control token. Control tokens are ordinary `ekms.` tokens MACed
under the control plane's own root (the `system_keys` row `control`, wrapped by the master like a
tenant's), with role `control`, no policies and a TTL of 1800 seconds. Because that root differs
from every tenant's, a control token is useless at a tenant and a tenant token is useless at the
control plane. The CLI prints the token for `EDGEKMS_CONTROL_TOKEN` and saves nothing.

`POST /v1/logout` sets the user's `tokens_after_ms` to now, and every request refuses a control
token issued at or before it (one primary read alongside the membership read), so logout ends
every control token the user holds, not just the one presented.

**SSH-key login** (lokkju/edgekms#16) is the way in when GitHub isn't: a lost account, or GitHub's
device flow or API down. A signed-in user registers SSH public keys on their account (at most 10;
Ed25519, `sk-ssh-ed25519` or ECDSA P-256), and `edgekms account login --ssh` later asks
`POST /v1/login/ssh/challenge` for a challenge, has ssh-agent sign it (namespace `edgekms`), and
posts it to `POST /v1/login/ssh` for an ordinary control token. The challenge is the data plane's
format, MACed under the control root with its own purpose (`mac/control-challenge/v1`), bound to
the control origin, good for 60 seconds and accepted once: its tag goes into
`used_ssh_challenges` after the signature verifies. The login body names no account. The
signature is verified against the public key embedded in it before anything reads D1, and only
then does that key's fingerprint pick the account, so someone holding only a public key (every
GitHub user's are at `github.com/<login>.keys`) gets the same `400 permission denied`, in the same
time, whether the key is registered or not. An SSH login reaches existing accounts only, in every
`SIGNUP_MODE`: an operator, or a user whose membership or pending invite admits them as on a
GitHub login. It never creates a user, a personal tenant or an allowlist entry. Its token carries
`auth: ssh` and the key's fingerprint, counts as fresh for export like any login, and works
only while that key's row exists, verifies and belongs to its user: `authenticate` reads the
logout cutoff and the key in one query, so removing a key ends every token it minted on the next
request without logging the user's other sessions out.

Registering a key takes a login under five minutes old (GitHub or SSH) and a proof of possession:
a signature by the key, in namespace `edgekms-register`, over a registration challenge
(`mac/ssh-key-proof/v1`, 300 seconds, single use) that names the session's account,
`ekmsr.<github_id>.<login>.<...>`, under its MAC. The control plane refuses a challenge naming any
other account, so a signature registers the key to the account its text names and no other, and
the CLI and the console show that account before anything is signed. Without the proof, any signed-in user could squat
someone else's public key, and the `409 ssh_key_in_use` refusal would tell them whether a given
key is registered anywhere. The separate namespace keeps the console's hand-run signing command
from producing anything that can log in. Each `ssh_keys` row carries a MAC under the control root
(`mac/ssh-key/v1`) over the user, the fingerprint, the public key, the label and `added_via`
(`github`, or `ssh:<fingerprint>` naming the key behind the session that added it). Removal needs
any session. Operators have a kill switch, `DELETE /v1/ops/users/:github_id/ssh-keys`, which
removes every key of the user and logs them out in one transaction. Both login replies report how
many keys can log in to the account, and the CLI prints it, so a key added behind an owner's back
shows at their next login. The console has no SSH sign-in (a browser has no ssh-agent); its
Account page lists, adds and removes keys.

**Config edits** require `If-Match` with the version being replaced (`428` without it, `409` when
stale). The new config is size-checked, parsed, checked against the hosted rules (a `400` names
the failing path, never a secret), MACed under the tenant's root through the unwrap-only master
handle, and written with a version-conditional `UPDATE`. The audit event records the old and new
version and the SHA-256 of the new config, not its contents. No redeploy is involved.

**Suspension** (operators only) freezes a tenant: the data plane refuses it, and its config,
members, invitations and accepting are `403 tenant is suspended`. Export and declining stay open.

**Audit.** Every control-plane state change (login, create, config, members, invitations,
export, rewrap, status, allowlist changes, invite requests and their decisions, SSH key
additions, removals and revokes) writes two events under `control/YYYY/MM/DD/HH/` in R2: an `attempt` after
every check and immediately before the D1 change, and the outcome after it. If the attempt can't
be stored the change doesn't happen, and if the outcome can't be stored the reply is `500 audit
log unavailable`, with export still withholding the key. Reads (`info`, `me`, `show`) are metrics
only, as are the allowlist and invite request listings and a requester's read. A refused signup
is a `denied` login event with the reason `signup_closed`. An invite request's note never goes
into an event. Every event made under a control token records `auth_method` (`github` or `ssh`)
and, for an SSH-minted token, `auth_ssh_fingerprint`; key changes record
`target_ssh_fingerprint` and `target_ssh_key_type`, and an operator's revoke `ssh_keys_removed`.
A failed SSH login names the key only once its signature has verified, since before that the
key in it is whatever the sender put there. Data-plane events for a tenant go under `audit/<tenant id>/YYYY/...`, and Analytics Engine
data points in hosted mode are indexed by tenant id.

### Import and export: you can always leave

Import and export are in [security-model.md](security-model.md#import-and-export).

### Rate limits and `CF-Worker`

The per-IP limiters (`LOGIN_LIMIT`, `AUTH_FAIL_LIMIT`, and the control plane's `CONTROL_LIMIT`)
key on `CF-Connecting-IP`. A `fetch` from any Worker to a zone it isn't on arrives with
Cloudflare's shared Worker egress address in that header, plus a `CF-Worker` header naming the
calling zone. Keyed on the IP alone, every such call, from our own Workers, from tenants calling
edgekms from a Worker, and from every other Cloudflare customer, would share one bucket. In
hosted mode the key is:

- no `CF-Connecting-IP`: no key, and the request is refused, as self-hosted;
- `CF-Worker` present (at most 253 bytes) and the IP inside Cloudflare's published ranges,
  compiled in and refreshed with `scripts/cloudflare-ranges.sh`: `cfw:<CF-Worker>|<ip>`;
- otherwise the IP alone, and a `CF-Worker` header is ignored.

The range check stops a client outside Cloudflare from inventing a zone name per request to get a
fresh bucket each time. Whether Cloudflare strips a client-supplied `CF-Worker` from direct
requests, and whether a client behind WARP (whose requests can come from Cloudflare's ranges) can
pass one through, is checked during production bring-up; if it can, the key must take the zone
from the request's `cf` object or drop it.

`TOKEN_LIMIT` is keyed `<tenant id>:<jti>`. `TENANT_LIMIT`, keyed by tenant id, bounds one
tenant's R2 writes and D1 reads, since the per-IP limits are global. It counts a request only
after a per-IP gate has passed (after authentication succeeds, or after `LOGIN_LIMIT` on login
and challenge), so one IP sending garbage can't drain a tenant's budget for its other callers.
`sys/health` isn't counted. Failed control-plane logins and bad control tokens also count against
`AUTH_FAIL_LIMIT`.

### Threat model

The hosted threat model is in [security-model.md](security-model.md#threat-model). The shared-Worker
design accepts one isolate holding many tenants; a dedicated Worker per tenant stays a possible premium
isolation tier.

### Deferred

Out of the MVP, each with its own later plan:

- **Billing and pricing.** The target is free or about $1 a month; metering would come from the Analytics Engine
  dataset, now indexed by tenant.
- **Custom domains** (`kms.example.com`) through Cloudflare for SaaS custom hostnames, as a paid
  add-on. That needs a per-tenant origin list beyond the template and a hostname-to-tenant table.
- **`X-Vault-Namespace` on the apex** `edgekms.dev`, for clients that send `VAULT_NAMESPACE`. The
  apex would serve every tenant from one origin, so the namespace would have to be bound into SSH
  challenges.
- **`edge.km` as an alias apex.** The service went live on `edgekms.dev` because the `.km`
  registry hadn't applied `edge.km`'s nameserver change. Adding `edge.km` later as a second apex
  means routing two apexes in the Worker (`HOSTED_APEX` is one value today), a second origin per
  tenant that its roles' `bound_audiences` would have to list, `jwks_url` refusing both apexes,
  and `api.edge.km` in the CLI's `HOSTED_API_HOSTS`.
- **Clerk** isn't planned. It stays possible as a second identity provider for organizations that
  don't use GitHub, as one more JWT issuer for the control plane.
- Single-use SSH challenges (a Durable Object per tenant), a bring-your-own-root mode outside the
  shared wrap, Workers for Platforms as a premium isolation tier, tenant deletion and rename,
  tenants reading their own audit log, the website at `edgekms.dev` and `www`, and replacing the
  CI deploy token with an OIDC credential broker.

## Open questions

- An outside review before the hosted service holds anything that matters.
