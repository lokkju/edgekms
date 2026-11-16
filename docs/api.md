# API

Each edgekms tenant, `https://<tenant>.edgekms.dev`, answers the part of Vault's HTTP API that
encryption clients use: Transit encrypt, decrypt and rewrap, key metadata, logins, and token
self-service. A client that already speaks Vault works with `VAULT_ADDR` and a token; nothing is
patched or forked. A self-hosted Worker answers the same API at its own origin. This page lists
what a tenant answers and how. The [security model](security-model.md) covers what happens to
keys and tokens behind it, and the [control API](#the-control-api) at the end manages tenants.

## The clients it was built for

These are the calls the first two clients make, read from their source.

`gocloud.dev/secrets/hashivault` (Pulumi's provider) uses `Logical().Write`, which sends **PUT**:

- `PUT /v1/transit/encrypt/<key>` with `{"plaintext": "<base64>"}`, reads `data.ciphertext`
- `PUT /v1/transit/decrypt/<key>` with `{"ciphertext": "vault:v1:..."}`, reads `data.plaintext`
  (base64)

OpenBao's transit seal (`openbao/go-kms-wrapping/wrappers/transit/transit_client.go`) makes the
same two calls under a configurable mount path, plus `PUT /v1/auth/token/renew-self` at startup.
If renewal fails it logs that and carries on without renewing.

edgekms accepts both PUT and POST on every write endpoint, as Vault does.

## Endpoints

| Endpoint | Purpose |
|---|---|
| `PUT/POST /v1/transit/encrypt/:key` | Encrypt. `plaintext` (base64) and optional `key_version` |
| `PUT/POST /v1/transit/decrypt/:key` | Decrypt |
| `PUT/POST /v1/transit/rewrap/:key` | Re-encrypt under the latest key version without exposing plaintext |
| `GET /v1/transit/keys/:key` | Key metadata (versions, `min_decryption_version`); never key material |
| `PUT/POST /v1/auth/:mount/login` | Swap a credential for an edgekms token. JWT mounts take `{"role", "jwt"}` |
| `PUT/POST /v1/auth/:mount/challenge` | A signed, 60-second login challenge, for SSH mounts |
| `GET /v1/auth/token/lookup-self` | Token introspection |
| `PUT/POST /v1/auth/token/renew-self` | Always an error; see [Tokens](security-model.md#tokens) |
| `PUT/POST /v1/auth/token/create` | Admin only: mint a revocable token (the OpenBao seal token) |
| `PUT/POST /v1/auth/token/revoke-accessor` | Admin only: revoke a created token by its accessor |
| `GET /v1/sys/health` | Liveness, for clients that probe it |

## Requests, responses and errors

The token travels in `X-Vault-Token` (or `Authorization: Bearer`). Responses use Vault's envelope
(`{"data": {...}}` or `{"auth": {...}}`); errors are `{"errors": ["..."]}` with Vault's status
codes (400, 403, 404, 429). Requests that use features edgekms doesn't implement (`context`,
convergent encryption, `batch_input`, `associated_data`) get a 400 naming the feature, never a
silent success; an empty value (`"context": ""`, which some clients always send) counts as absent,
as it does in Vault. As in Vault, `key_version` may be a numeric string and a TTL may use days
(`365d`).

Unknown paths under `/v1/`, and a known path with the wrong method, answer as OpenBao does for a
request with no token: `403 {"errors":["permission denied"]}`. `DELETE /v1/sys/health` is the one
exception, `405 {"errors":[]}`, as in OpenBao. A login to an auth mount the config doesn't have gets
the same 403. A transit request checks the token's policy before looking the key up, as Vault does,
so a key the token has no grant on and a key that doesn't exist are the same 403. Anything outside `/v1/` (`/`, `/robots.txt`) is a bare `404` with no body, answered
before any of the request body is read, and is neither audited nor counted. None of these bodies
names edgekms. Bodies are written as Go's JSON encoder writes them (HTML characters escaped, a
trailing newline) with OpenBao's `Cache-Control` and HSTS headers, and a refused rate limit is
OpenBao's `429 request path "...": rate limit quota exceeded`.

## The tenant config

A tenant's config (a self-hosted Worker's `config.json`) holds its keys, mounts, roles and
policies. The [console](console.md#editing-a-config) edits it with forms; `edgekms tenant config
get` and `set` read and replace it as JSON.

### Mounts and issuers

A mount is one way to log in. There are three kinds:

- **JWT mounts** (`"type": "jwt"`), one per issuer, as with Vault's `jwt` auth method. The caller
  sends a JWT and the Worker verifies it against the issuer's keys, fetched from `jwks_url` or
  pinned in the mount as `jwks`.
- **SSH mounts** (`"type": "ssh"`): the caller signs a server challenge with an SSH key (OpenSSH
  `SSHSIG`, namespace `edgekms`), and the Worker checks it against public keys pinned in the role.
- **GitHub user mounts** (`"type": "github-user"`, with the `client_id` of the deployment's GitHub
  OAuth App): the caller sends a GitHub user access token from the OAuth device flow, and the
  role binds numeric GitHub user ids (`github_user_ids`).

Mount names are configurable; the defaults keep existing client tooling working:

| Mount | Kind | Issuer or source | Used by |
|---|---|---|---|
| `jwt` / `github` | JWT | `https://token.actions.githubusercontent.com`, JWKS fetched and cached | `hashicorp/vault-action`, a `curl` step |
| `ssh` | SSH | Public keys in each role | Operators: `edgekms login ssh` through ssh-agent, including FIDO `sk-ssh-ed25519` keys |
| `github-user` | GitHub user | `api.github.com` | Operators without their agent: `edgekms login github` |
| `oidc` (any name) | JWT | Any OIDC issuer's JWKS (Google, Clerk, Cloudflare Access) | Operators through a browser: `edgekms login oidc` |
| `kubernetes` | JWT | k3s's service-account issuer, public keys pinned in config | Vault Agent, External Secrets, plain pods |

k3s's issuer isn't reachable from the internet, so its public keys are exported once from
`/openid/v1/jwks` and pinned in config (Vault's `jwt_validation_pubkeys`). They change only when
the cluster's service-account signing key rotates. Verification is offline, so edgekms can't see
that a pod or service account was deleted; roles for this mount should require projected tokens
with a short `exp` and an `aud` of edgekms.

Verification rules, all JWT mounts: algorithm allowlist (RS256, ES256; never `none`, never HS*), `iss`
exact match, `aud` must contain one of the role's `bound_audiences`, `exp` and `nbf` checked with
60 seconds of leeway, `kid` required. `iat` isn't leeway-checked; it's compared to the role's
`not_before`, and a token issued before it is refused. A fetched JWKS is cached for ten minutes,
and an unknown `kid` triggers at most one refetch per mount per minute. A failed fetch is retried
no sooner than a minute later, and meanwhile the cached set keeps serving, but never more than an
hour after its last successful fetch; a JWKS document over 256 KiB is refused without reading
the rest. A refetch forced by an unknown `kid` logs `edgekms: JWKS refetched for an unknown kid`
when it succeeds, and every failed fetch is logged as an error.

### Roles

A role binds claims on one mount to policies:

```jsonc
"mounts": {
  "github": {
    "type": "jwt",
    "issuer": "https://token.actions.githubusercontent.com",
    "jwks_url": "https://token.actions.githubusercontent.com/.well-known/jwks"
  },
  "ssh": { "type": "ssh" }
},
"roles": {
  "infra-ci": {
    "mount": "github",
    "bound_audiences": ["https://kms.example.com"],
    "bound_claims": {
      "repository_id": "812345678",
      "repository_owner_id": "1234567",
      "ref": "refs/heads/main",
      "environment": "prod"
    },
    "policies": ["infra-prod-decrypt"],
    "token_ttl_secs": 900
  },
  "operator": {
    "mount": "ssh",
    "ssh_keys": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJE0GVkXJCpxL5JWYnwGJv8f4VpNFckoFtC/6rejoXzs op"],
    "policies": ["admin", "openbao-seal"],
    "token_ttl_secs": 3600
  }
}
```

`token_ttl_secs` is an integer from 60 to 34,560,000 (9600 hours). A role may also set
`not_before` (Unix seconds; see [Tokens](#tokens)). An SSH role lists OpenSSH public key lines,
each parsed when the config loads; anything but Ed25519, `sk-ssh-ed25519` and ECDSA P-256 is
refused.

GitHub roles bind `repository_id` and `repository_owner_id`, not names. A deleted repo or org name
can be registered by someone else, and a name-bound role would trust them.

`bound_claims` values are exact matches. Globs are allowed only where a value is explicitly
written as a glob (`"ref": {"glob": "refs/tags/v*"}`), so a stray `*` in an exact value is never
a wildcard.

### Policies

```jsonc
"policies": {
  "infra-prod-decrypt": { "keys": { "infra-prod": ["decrypt"] } },
  "infra-prod-admin":   { "keys": { "infra-prod": ["encrypt", "decrypt", "rewrap"] } },
  "openbao-seal":       { "keys": { "openbao-unseal": ["encrypt", "decrypt"] } },
  "admin":              { "admin": ["token-create", "token-revoke"] }
}
```

Default deny. A token's capabilities are the union of its policies. Key capabilities are
`encrypt`, `decrypt`, `rewrap` and `read` (key metadata); admin capabilities are `token-create`
and `token-revoke`.

## Logging in

Every login is `PUT` or `POST /v1/auth/<mount>/login`, where the mount is one of the tenant
config's `mounts` and the body names one of its `roles`. The reply is Vault's `auth` envelope:
`client_token` (the token), `accessor` (the token's id, for revocation), `policies` and
`lease_duration` in seconds.

| Mount type | Body | Notes |
|---|---|---|
| `jwt` | `{"role", "jwt"}` | Any OIDC issuer: GitHub Actions, Google, Kubernetes service accounts. The JWT is verified against the mount's `jwks_url` or pinned `jwks`; the role's `bound_audiences` and `bound_claims` must match. |
| `ssh` | `{"role", "challenge", "signature"}` | Get a challenge first from `/v1/auth/<mount>/challenge` (good for 60 seconds), sign it with `ssh-keygen -Y sign -n edgekms`, and send both. `edgekms login ssh` does all three. |
| `github-user` | `{"role", "token"}` | A GitHub user access token from the device flow of the deployment's GitHub App. The Worker checks it with GitHub, matches the user's numeric id against the role's `github_user_ids`, and revokes it. `edgekms login github` runs the flow. |

A refused login on a configured mount is `400 permission denied`, whatever the reason, so a refusal doesn't say which
roles exist. JWTs must be RS256 or ES256 with a `kid`; `exp` and `nbf` get 60 seconds of leeway,
and a token issued before the role's `not_before` is refused.

## Tokens

`GET /v1/auth/token/lookup-self` returns the token's `accessor`, `policies`, remaining `ttl`,
`expire_time` and `meta` (the audit fields copied from its login), with `renewable` always false.
`renew-self` is always an error: tokens are stateless and their expiry can't be extended. Log in
again instead.

`PUT` or `POST /v1/auth/token/create` (needs `token-create`) mints a revocable token, the one
OpenBao's transit seal holds. The body takes `policies` (key policies the caller holds; never an
admin policy), `ttl` (seconds, or a duration such as `8760h` or `365d`, from 60 seconds to 9600
hours) and an optional `display_name`. `period`, `num_uses`, `renewable` and `explicit_max_ttl`
are refused with a 400 naming the field. `PUT` or `POST /v1/auth/token/revoke-accessor` with
`{"accessor"}` (needs `token-revoke`) revokes a created token within about a minute.

## The control API

`https://api.edgekms.dev` manages hosted tenants: their configs, members, invitations and export.
The `edgekms` CLI's `account`, `tenant` and `ops` commands and the [web console](console.md) are
its clients; the [CLI reference](cli-install.md) and the console guide describe what each action
does, and this table is the map underneath. Bodies use Vault's envelope (`{"data": ...}`,
`{"errors": [...]}`); some refusals add a `code` the clients match on. A control token, from
`edgekms account login` or the console's sign-in, goes in `Authorization: Bearer` and lasts 30
minutes. It works only here, never at a tenant.

| Route | Who |
|---|---|
| `GET /v1/info` | anyone: `{"github_client_id", "apex"}`, not wrapped in `data` |
| `POST /v1/login/github` | anyone with a GitHub user token for the hosted App whom `SIGNUP_MODE` admits |
| `POST /v1/login/ssh/challenge`, `POST /v1/login/ssh` | anyone holding a registered SSH key whose account SSH can reach |
| `POST /v1/logout` | any user |
| `GET /v1/me/ssh-keys`, `DELETE /v1/me/ssh-keys/:id` | any user, for their own keys |
| `POST /v1/me/ssh-keys/challenge`, `POST /v1/me/ssh-keys` | any user, with a login under five minutes old |
| `DELETE /v1/ops/users/:github_id/ssh-keys` | operators |
| `GET /v1/me` | any user: accepted tenants and pending invitations, listed apart |
| `POST /v1/tenants` | any user, within the cap and the naming rule |
| `GET /v1/tenants/:name` | owners and members |
| `PUT /v1/tenants/:name/config` | owners, with `If-Match: "<version>"` |
| `PUT` and `DELETE /v1/tenants/:name/members/:github_id` | owners |
| `POST /v1/tenants/:name/accept`, `.../decline` | the invitee |
| `POST /v1/tenants/:name/export` | owners, with a login under five minutes old |
| `POST /v1/ops/rewrap`, `PUT /v1/ops/tenants/:name/status` | operators |
| `PUT` and `DELETE /v1/ops/allowlist/:github_id`, `GET /v1/ops/allowlist` | operators |
| `GET /v1/invite-requests/mine`, `POST /v1/invite-requests` | a request token's user |
| `GET /v1/ops/invite-requests` | operators |
| `POST /v1/ops/invite-requests/:github_id/approve`, `.../decline`, `DELETE /v1/ops/invite-requests/:github_id` | operators |

Owners are the only ones who can change a tenant; members can read it. A tenant the caller doesn't
belong to answers `404 tenant not found`, exactly as one that doesn't exist. A config edit needs
`If-Match: "<version>"` with the version it replaces (`428` without it, `409` when someone else
saved first).
