# Security model

What edgekms does with keys, tokens and audit records, and what each party could do if it were
compromised. It describes the hosted service at `edgekms.dev`; a self-hosted Worker is the same
code with one tenant, its own root key and no master key. Exporting your root key and leaving is
always possible, and [Import and export](#import-and-export) says how.

## Keys

### Root key

Every deployment has one 256-bit root key, and in the hosted service every tenant has its own. A
self-hosted Worker reads its root through a binding: a Secrets Store secret, or a plain Worker
secret named `ROOT_KEY`. The bootstrap ceremony, a mise task in the instance directory, generates
it and writes an offline copy at the same moment (a SOPS file in the operator's infra repo); after
that it never leaves Cloudflare. A hosted tenant's root is generated inside the Worker and stored
wrapped ([below](#tenants-roots-and-the-master-key)); its owners can [export](#import-and-export)
it.

### Named keys

Each named key is a config entry, not stored material:

```jsonc
"keys": {
  "infra-prod": { "id": "k_7f3a9c1e", "latest_version": 2, "min_decryption_version": 1 },
  "openbao-unseal": { "id": "k_02be44d0", "latest_version": 1, "min_decryption_version": 1 }
}
```

The AES-256 key for name `N`, version `v` is
`HKDF-SHA256(ikm = root, salt = "edgekms/v1/" + root_id, info = "transit/" + id + "/" + v)`.

`id` is random and set when the key is created. Deriving from the name alone would mean deleting
`infra-prod` and creating it again silently brings back the old key, which Vault never does; the
id makes a re-created key a different key.

Rotation bumps `latest_version`. Old versions stay derivable, so old ciphertext still decrypts
until `min_decryption_version` is raised past it. `rewrap` moves ciphertext forward.

### Ciphertext format

Byte-for-byte Vault's `aes256-gcm96` format: `vault:v<version>:` followed by
`base64(nonce[12] || ciphertext || tag[16])`, with a random 96-bit nonce per encryption. Matching
it means ciphertext moves between edgekms and Vault or OpenBao in either direction.

### Exit and break-glass

Because every key is derived, the offline root copy reproduces every key version. Kept as a SOPS file with one key, `root_key`
(the bootstrap ceremony writes one; the [quickstart](hosted-quickstart.md#7-export-you-can-always-leave)
shows how to write one from a hosted export), `sops decrypt --extract '["root_key"]' <file>`
produces the base64 root key to pipe into the CLI. The CLI does two things with it, both offline:

- decrypt any edgekms ciphertext directly, with no Worker and no network;
- export one version of a named key as its raw bytes in base64, the input Transit's BYOK import
  (`transit/keys/:name/import`, `import_version`) wraps and uploads, so a key can move into a
  self-hosted OpenBao and existing ciphertext keeps working.

Root key rotation (re-deriving everything under a new root) is out of scope for v1. The root id
goes into the HKDF salt from the start so that a second root can coexist later without a format
change.

## CLI logins

Operators log in through the CLI, which prints a token to export as `VAULT_TOKEN`. Every method
prints only the edgekms token; the credential it swaps (signature, GitHub token, ID token) is
never printed. The CLI's HTTP client follows no redirects and gives every exchange 30 seconds.

- **`edgekms login ssh`** asks for a challenge, signs it through ssh-agent with namespace
  `edgekms`, and swaps the signature for a token. The challenge is stateless: a timestamp, 16
  random bytes, the deployment's origin (`https://host[:port]`) and an HMAC over all three under
  a key derived from the root, valid for 60 seconds. The CLI signs a challenge only when its
  origin is the server it asked (`--addr`), and the Worker refuses a challenge minted for an
  origin it doesn't answer on, so a hostile deployment can't fetch another deployment's
  challenge, have an operator who uses the same key sign it, and log in there
  ([lokkju/edgekms#1](https://github.com/lokkju/edgekms/issues/1)). The origins come from the
  config's `public_origins` (for example `["https://kms.example.com"]`). When that
  is unset, the Worker uses the request URL's origin, and that fallback is only as good as
  Cloudflare's routing: on a custom domain with `workers_dev` and preview URLs off, the URL can't
  name another host, but under `workerd`, `wrangler dev` or a proxy that passes the Host header
  through, a client picks the origin, so such deployments must set `public_origins`. It works
  headless and through agent forwarding, and a FIDO key turns every login into a hardware touch.
  If ssh-agent doesn't hold the key, `ssh-keygen -Y sign -f x.pub` falls back to the private key
  file `x` and may prompt for its passphrase.
  A signature captured in transit could be replayed inside its 60 seconds; making challenges
  single-use needs a Durable Object, which neither mode has yet.
- **`edgekms login github --client-id <id>`** runs GitHub's OAuth device flow with the
  deployment's OAuth App (the operator enters a code at github.com from any browser, so no
  agent is needed on the machine) and sends the user token to the `github-user` mount as
  `{"role", "token"}`. The Worker confirms the token was issued to that OAuth App with
  `POST /applications/{client_id}/token`, authenticated with the App's client secret (the Worker
  secret `GITHUB_CLIENT_SECRET`), so a GitHub token held by some other app can't be replayed
  here. That reply names the token's user, and the Worker matches its numeric id against the
  role's `github_user_ids`; a separate `GET /user` would only repeat it. As with a JWT's
  signature, GitHub checks any well-shaped token whether or not the role exists on the mount, so
  the time a refusal takes doesn't say which role names do. A token GitHub doesn't
  recognize for the App is the usual `400 permission denied`; GitHub unreachable, or refusing
  the App's own credentials, is a `500`. After a successful check the Worker revokes the token
  (`DELETE /applications/{client_id}/token`, same credentials), so each GitHub token logs in
  once and can't be relayed to another deployment afterwards; a failed revocation is logged and
  doesn't fail the login. Before that revocation, a hostile deployment that shares the OAuth App
  could still replay a token it was handed, so **each deployment needs its own OAuth App**.
  One `GITHUB_CLIENT_SECRET` serves the Worker, so every `github-user` mount in a config must
  name the same `client_id`.
- **`edgekms login oidc --mount <name> --issuer <url> --client-id <id>`** fetches the issuer's
  discovery document (which must name exactly that issuer), runs the authorization code flow
  with PKCE (S256), `state` and `nonce` through a loopback redirect on
  `http://127.0.0.1:8250/oidc/callback` (`--port` changes it; 0 takes any free port), and sends
  the ID token to that JWT mount as `{"role", "jwt"}`. A reply with the wrong `state`, or an ID
  token whose `nonce` isn't this login's, ends the login before anything reaches the Worker. The
  Worker verifies the ID token like any other JWT. A client secret, for providers that issue one
  to desktop clients (Google), comes from `EDGEKMS_OIDC_CLIENT_SECRET`, never argv. An ID token
  is a bearer credential for every deployment whose role trusts its issuer and audience, and it
  stays valid until its `exp`, so **each deployment needs its own OIDC client ID** (its own
  `aud`); a deployment that shares one can replay an operator's ID token at another.

A worked OIDC example, with Google as the provider. Create an OAuth client of type "Desktop app"
in the Google Cloud console (desktop clients accept any loopback port), then add a JWT mount and
a role that binds the operator's Google account:

```jsonc
"mounts": {
  "google": {
    "type": "jwt",
    "issuer": "https://accounts.google.com",
    "jwks_url": "https://www.googleapis.com/oauth2/v3/certs"
  }
},
"roles": {
  "operator-google": {
    "mount": "google",
    "bound_audiences": ["1234-abcd.apps.googleusercontent.com"],
    "bound_claims": { "sub": "110169484474386276334" },
    "policies": ["admin", "openbao-seal"],
    "token_ttl_secs": 3600
  }
}
```

```sh
export EDGEKMS_OIDC_CLIENT_SECRET=...   # Google issues one to desktop clients
VAULT_TOKEN="$(edgekms login oidc --addr https://kms.example.com --mount google \
  --role operator-google --issuer https://accounts.google.com \
  --client-id 1234-abcd.apps.googleusercontent.com --port 0)"
```

The role binds `sub`, Google's stable account id; an email address can change hands.

Cloudflare Access isn't used. It remains possible as one more JWT issuer.

## Tokens

Tokens are stateless: `ekms.` followed by a base64url payload (token id, role, policies, issued
and expiry times, and a few audit fields copied from the login claims) and an HMAC-SHA256 tag
under a token key derived from the root (`info = "mac/token/v1"`). Checking a login token with a
TTL of a day or less needs no storage read.

Login tokens (CI, operators) last their role's `token_ttl_secs` (900 seconds for a typical CI
role, an hour for an operator) and aren't revocable individually. The exception is a role whose
TTL is over a day: its login tokens are checked against the revocation list below. Each role also
has a `not_before` timestamp in config, and raising it invalidates every token the role has
issued.

Created tokens exist for one case in practice: the OpenBao seal, which holds a static token. An
admin mints one through `auth/token/create` with the seal policy and a TTL from 60 seconds to 9600
hours. Every created token is revocable, whatever its TTL: `revoke-accessor` puts its id into a KV
revocation list (each entry outlives the longest possible token), and every request that presents
a created token checks that list. KV's propagation time (up to about a minute) is the revocation
latency. `renew-self` returns an error for every token, since a stateless token's expiry can't be
extended in place; the seal client logs that once and runs without renewal, which is the behaviour
it already has for non-renewable tokens. A stolen seal token can unseal that one OpenBao and do
nothing else.

`auth/token/create` grants only policies the caller holds, and only key policies, never one with
admin capabilities, so a stolen operator token can't mint itself a long-lived admin token. That
means the operator role holds the seal policy in order to mint the seal token, so the operator's
own token can also encrypt and decrypt with the unseal key. A created token carries its creator's
role, so raising that role's `not_before` also invalidates every seal token it minted, and those
need re-minting.

## Audit

Every routed request except `sys/health` produces one audit event: logins and challenges,
encrypt, decrypt, rewrap, key reads, and the token calls. Its fields are:

- `ts` (Unix milliseconds) and `op`;
- `key` and `version` (the key also on a denial, when its name is in config);
- `mount` and `role`, only when they name something in config (never caller input);
- `jti`, the caller's token id, or the new token's for a login;
- `target_jti`, the token id a `token_create` minted or a `token_revoke` revoked;
- `meta`, allowlisted token and login metadata: `sub`, `repository`, `ref`, `workflow`,
  `job_workflow_ref` and `ssh_fingerprint`. A JWT whose copied claim is over 256 bytes (JSON-escaped)
  is refused with a `400` naming the claim, not truncated, so two identities can't look alike here;
- `ip` and `country` from the request;
- `result` (`ok`, `denied` or `error`) and `error`, a stable reason code (`jwt_expired`,
  `token_revoked`, `rate_limited`);
- `ct_mac`, the ciphertext received (decrypt, rewrap) or produced (encrypt), and `new_ct_mac`, the
  ciphertext a rewrap produced.

Plaintext, ciphertext and tokens are never logged. Ciphertext is recorded as an HMAC (base64url,
under a key derived with `info = "mac/audit/v1"`) so that an investigator holding the root key can
match events to a specific value.

- **R2:** one JSON object per event under
  `audit/YYYY/MM/DD/HH/<ts_ms>-<jti>-<16hex>.json` (UTC hour; the `<jti>-` part is absent when
  there's no token id; 16 random hex digits keep two events in one millisecond apart), with a
  bucket lock rule for retention. Writes happen before the response returns, and a failed write
  fails the request with `500 audit log unavailable` (Vault's rule: no audit, no operation) and
  is counted as a data point with `error = "audit_unavailable"`, so an audit outage shows up in
  Analytics Engine. A revocation already written stands even when its audit write fails.
- **Analytics Engine:** one data point per event for counts, dashboards and alert queries: index
  `op`; blobs `op`, `result`, `key`, `role`, `mount`, `country` and `error`; doubles a count of 1
  and the latency. Best effort; losing a data point is acceptable because R2 is the record.

Two kinds of request go to Analytics Engine only, never R2: rate-limited requests (every 429) and
logins on a mount the config doesn't have, and challenges on any mount that isn't SSH. Neither
performs an operation, so no
audit, no operation still holds, and R2 writes stay bounded by the rate limits. A 429 is visible
only as a data point with `error = "rate_limited"`. A request refused for having no client IP
(next section) is likewise only a data point, with `error = "no_client_ip"`.

## Abuse limits

Workers rate limiting bindings: per client IP on login and challenge endpoints (`LOGIN_LIMIT`),
per client IP on every failed authentication (`AUTH_FAIL_LIMIT`), and per token id on every
authenticated endpoint (`TOKEN_LIMIT`). Failed authentication has its own limiter so a client
retrying with a broken token can't lock its IP, and everyone behind the same NAT, out of logging
in; a Worker deployed without `AUTH_FAIL_LIMIT` counts failures against `LOGIN_LIMIT`. The
per-IP limits key on `CF-Connecting-IP`, which Cloudflare's edge and `wrangler dev` both set, so
a request without it reached the Worker some other way (a service binding); a login, challenge or
failed authentication without it is refused, since a shared bucket for all of them would let one
client lock out the rest. The refusal is the route's ordinary one (`400 permission denied` for a
login on a configured mount, `403 permission denied` otherwise), not a `429`, which Vault's Go
clients would retry. An authenticated request doesn't need it: its limit
is per token id. Request bodies are capped (Transit plaintext is a data key or an unseal key, so 64 KiB is generous).

## Tenants, roots and the master key

Each tenant has its own random 32-byte root key and root id `r_<16 hex>`. Below the root nothing
differs from self-hosting: the HKDF salt `edgekms/v1/<root_id>`, the `transit/<key id>/<version>`
derivation, the token, challenge and audit MACs and the `vault:vN:` ciphertext format are the same
code. That's what makes import and export work.

Roots are stored wrapped by a **master key** with AES-256-GCM: `iv[12] || ciphertext[32] ||
tag[16]`, with additional data `edgekms/wrap/v1/<tenant id>/<root id>`. Binding the tenant id and
root id there means a wrapped root copied into another tenant's row doesn't unwrap. AES-KW would
have worked with WebCrypto's `unwrapKey` too, but it takes no additional data.

Master versions are named `m1`, `m2` and so on. Version `mN` is the Secrets Store secret
`edgekms-master-mN`, bound as `MASTER_KEY_MN`; `MASTER_KEY_CURRENT` names the version new wraps
use, and during a rotation `MASTER_KEY_PREVIOUS` names the one being retired. The master key
ceremony writes an offline SOPS copy before the value reaches Cloudflare. A `MASTER_KEY_M<n>` bound
as a plain Worker secret or var (`wrangler secret put MASTER_KEY_M7`) would add a master outside
that ceremony, so the Worker refuses every request with `500` and logs
`master_key_not_in_secrets_store`, as it does a stray `ROOT_KEY`, and never unwraps under one. The
local end-to-end run, under `HOSTED_APEX` `localhost`, is the one exception. Each isolate imports a
master version at most twice, both non-extractable: an unwrap-only handle on every host, and an
encrypt/decrypt handle only while serving `api.edgekms.dev`.

In the data plane a tenant's raw root never enters wasm memory. A new root comes from
`crypto.getRandomValues` into a JavaScript buffer that is encrypted, imported as a
non-extractable HKDF key and zeroed; every load is `subtle.unwrapKey` straight into a
non-extractable HKDF key. Only import, export and master rewrap handle raw root bytes, and they
zero every buffer they use.

Each config row carries a **config MAC**: HMAC-SHA256 under a key derived from the tenant's own
root with `info = "mac/config/v1"`, over `tenant id || 0x00 || name || 0x00 || config version (u64
big-endian) || config JSON`. A config loads only if its MAC verifies against the name it was
requested under. What it covers and what it doesn't is in the threat model below.

Hosted configs follow a few rules beyond the self-hosted ones: the `root_id` is the service's
(on create, the server overwrites whatever the config says), `public_origins` must be empty
because the Worker sets the tenant's origin itself, every `github-user` mount names the hosted
App's client id, a config holds at most 64 keys, 32 mounts, 128 roles and 128 policies and 60 KiB,
a key's `latest_version` is at most 1,000,000 with at most 256 versions decryptable
(`latest_version - min_decryption_version + 1`), and no `jwks_url` may point at `edgekms.dev` or
under it. The version caps exist because `GET /v1/transit/keys/:key` lists every decryptable
version and the data plane caches a derived key per version it uses; one tenant's config must not
be able to exhaust an isolate other tenants share. The derived-key cache is also capped at 1024
entries per tenant, cleared when full.

## Import and export

**Import.** `POST /v1/tenants` with `import: {"root_id", "root_key"}` (base64 of 32 bytes) and a
config whose `root_id` equals the imported one creates a tenant from an existing root. The config
is required, because its key ids are what make old ciphertext decrypt. A root id already in use is
`409`. A self-hosted deployment moves in this way with every ciphertext, login token and created
token it ever issued still valid.

**Export.** `POST /v1/tenants/:name/export` returns `{"root_id", "root_key"}` to an owner whose
control token is under 300 seconds old; an older one is `403 fresh login required`. The reply
carries `Cache-Control: no-store`, and the audit event names the caller but never the key. Export
works on a suspended tenant too. The exported root is everything the break-glass CLI needs:
offline decrypt, BYOK export of a key version into OpenBao, or a self-hosted Worker with the same
root and config.

## Threat model

- **Ciphertexts are assumed exposed.** Pulumi stack files live in git, OpenBao seal blobs on
  disk, and both end up in backups. Their safety is the tenant root's safety.
- **Master key plus wrapped-key store.** If the master key and the D1 `tenants` table both leak,
  every tenant's ciphertexts can be decrypted offline and tokens minted for any tenant. The master
  is non-extractable inside the Worker, so getting it takes code execution in the Worker (a
  malicious deploy, a supply-chain compromise of a dependency), a breach of Cloudflare, or the
  offline SOPS copy, which is why that copy's age recipient should be a hardware key. Master
  rotation bounds how long a leaked old master stays useful against current rows, not against D1
  backups taken before the rotation (D1 Time Travel keeps 30 days).
- **The deploy credential is the master key.** Anyone who can upload a Worker script to the
  edgekms account can bind the master secret and unwrap everything. The CI token is held to that
  standard: a GitHub environment with a required reviewer, one self-hosted runner only, and a
  Cloudflare IP condition on the token.
- **One isolate holds many tenants.** Root handles are non-extractable and live in the runtime's
  native memory, not wasm memory, but a code-execution bug in the Worker reaches every tenant
  cached in that isolate. The hosted design accepts this; a dedicated Worker per tenant stays a possible premium
  isolation tier.
- **D1 write access without the master.** A leaked D1 credential (the CI deploy token has D1
  write) can't decrypt anything or take a tenant over; that takes the master as well. The config
  MAC stops it rewriting a tenant's config, for example to add a role it controls: computing a
  valid MAC needs the tenant's root, and so the master. Because the MAC binds the tenant id and
  name, swapping two rows' names makes both fail to load, never serves one tenant's keys at the
  other's hostname, and the wrap's additional data does the same for swapped wrapped roots. The
  membership and invite MACs stop it making itself an owner or a member: a `members` or
  `invites` row it writes doesn't verify under the control root, so the control plane treats it
  as absent, and it grants no show, config edit, member change or export, doesn't appear in
  `GET /v1/me` or a tenant's member list, can't be accepted, and doesn't count toward the
  last-owner rule. A real row copied to another tenant or user, or with its role rewritten,
  fails the same way. The allowlist MAC does the same for signups: a `signup_allowlist` row it
  writes, or a real one moved to another GitHub id, admits no one. What a D1 writer can still do:
  - **roll back** a config to an older version that still has a valid MAC (an isolate that has
    already served a newer version ignores the older one, but a fresh isolate loads it), and
    likewise **replay** any membership or invite row that once existed, from a backup or D1 Time
    Travel: a removed member comes back with the role they had, a demoted owner as owner, a
    withdrawn invite as pending again (and a replayed owner invite can then be accepted). The
    MACs bind a row's contents, not that it is current, so this restores past grants but never
    grants a user a role they weren't once given or offered. A replayed allowlist row likewise
    lets a user an operator once allowlisted, and later removed, sign up;
  - **delete** rows (lock owners out, hide invites, drop a tenant, take a user off the
    allowlist before they sign up), or change `status`, which
    isn't MACed: un-suspend a suspended tenant, or suspend an active one;
  - **delete the `system_keys` row `control`**, which locks every tenant out at once: that one
    root keys every membership and invite MAC, so no row verifies without it. The control plane
    won't mint a replacement while any tenant or membership exists (logins fail with `500`,
    logged as `control_root_missing`), because tenants sealed under a new root would break when
    the old row came back; the only recovery is restoring that row. Likewise, a future rotation
    of the control root that changes its bytes, rather than rewrapping the same root under a new
    master, has to re-seal every membership and invite row under the new root;
  - lower a user's `tokens_after_ms`, which isn't MACed, reviving control tokens issued before
    their last logout until those expire (at most 30 minutes), which helps only someone already
    holding such a token;
  - point `created_by` at a victim, which uses up their creation cap: they can't create
    tenants, and a user with none yet doesn't get a personal tenant (a denial of service);
  - delete a `users` row, which refuses every control token that user holds (there is no
    logout time to check them against) until they log in again, which recreates the row (a
    denial of service; `POST /v1/tenants` itself recreates the row before inserting, so creation
    as such isn't blocked);
  - change `added_by` or a user's `login`, which are display only;
  - **replay** a removed `ssh_keys` row from a backup, which revives that key (and its tokens'
    eligibility), exactly as a replayed membership revives a seat. It matters only together with
    the key's private half, which is the combination the removal was meant to stop. A forged
    row, or a real one moved to another user, relabelled or with its lineage rewritten, logs no
    one in and keeps no token alive;
  - delete `used_ssh_challenges` rows, which reopens replay of a captured control-plane login
    signature for the rest of its challenge's 60 seconds, or delete `ssh_keys` rows (a denial of
    service against SSH login), or change `last_used_ms`, which is display only.
- **Propagation bound.** A config edit, a suspension or a reactivation reaches every isolate
  within 30 seconds plus D1 replica lag, since the data plane revalidates through the nearest
  replica; a reactivation can take 10 seconds more, because a suspended name sits in the negative
  cache that long. With D1 read replication off, the lag term is zero. A member removal is
  immediate at the control plane, which reads the primary. Created-token revocation keeps KV's
  propagation, up to about a minute.
- **Tenant names are not secret.** The wildcard certificate keeps them out of CT logs, and
  wildcard DNS answers for every label, but the Worker answers an unknown tenant differently from
  a known one, so names can be enumerated over HTTP. Nothing depends on them being secret.
- **Tenant JWKS URLs are outbound fetches on a tenant's behalf.** Any tenant can make the Worker
  fetch an `https://` URL of its choosing. The existing caps bound that (256 KiB, a ten-minute
  cache, at most one forced refetch per URL per minute, at most 64 keys per set, the login rate
  limits), the cache is keyed by URL so tenants can't poison each other's entries, and no
  `jwks_url` may point back into `edgekms.dev`. The fetch follows no redirects (a 3xx is a failed
  fetch), so an allowed host can't bounce it back into `edgekms.dev` either.
- **One GitHub App for everyone.** The control plane and every tenant's `github-user` mount share
  the hosted App and its client secret. The Worker revokes each GitHub token after its single
  check, so a token handed to one tenant can't be relayed to another afterwards. Across operators,
  "each deployment needs its own OAuth App" still holds: a hostile self-hosted deployment could
  replay a token it was handed to `edgekms.dev` before the Worker revokes it, so the CLI sends the
  hosted App's id only to `api.edgekms.dev` (its `HOSTED_API_HOSTS` list) unless `--client-id` is
  given explicitly.
- **Owners are GitHub accounts, and the SSH keys beside them.** A tenant owner's GitHub account
  controls that tenant's config, and through it its keys. Export needs a control-plane login under
  five minutes old, and logout cuts off every outstanding control token. A registered SSH key is
  exactly as strong: a token from an SSH login can do everything a GitHub one can, export and key
  registration included while fresh. Someone with the user's ssh-agent (a forwarded agent on a
  compromised host) can log in while that access lasts and, since their login is fresh, register a
  key of their own. Only registered keys work; a `sk-ssh-ed25519` key signs only with a touch, and
  an `ssh-add -c` key asks each time, which is why the docs recommend them; every login and export names the key; the key count at each login and
  `added_via` in the listing show a backdoor key; and removing the stolen key ends its tokens at
  once. An export made meanwhile can't be taken back, the same exposure as a GitHub session
  stolen in its first five minutes. Someone who talks a user into signing their registration
  challenge (`-n edgekms-register`) gets a signature over text that names their own account in
  the clear (`ekmsr.<their id>.<their login>.`), which the console's command prints before it
  signs and which `edgekms account ssh-keys add` refuses to sign unless it names the signed-in
  account (or `--expect-github-id`). The control plane refuses a challenge naming any account but
  the session's, so a signature made for one account can't register the key to another
  ([edgekms#17](https://github.com/lokkju/edgekms/issues/17)). A user who signs it anyway, having
  been shown the other account, registers their key there; it grants the other account nothing,
  and an SSH login with it lands in that account, which the CLI's login line names.
- **SSH challenge replay** inside its 60 seconds remains possible on the data plane, as
  self-hosted. The control plane's SSH challenges are single use.
