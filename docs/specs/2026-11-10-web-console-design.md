# Web console design (#56)

Issue: [edgekms#13](https://github.com/lokkju/edgekms/issues/13). The console is built after the hosted service is live and before signups open beyond invite. The hosted service went live on 2026-11-10.

## Intent

Everything on the hosted service today is the CLI plus whole-file JSON edits (`edgekms tenant config get`, edit, `set`). That works for the operator and is a barrier for anyone else. The console at `https://app.edgekms.dev` gives a signed-in GitHub user the same control-plane powers in a browser: their tenants, each tenant's keys, roles and policies, members and invites, and export. Operators also get the signup allowlist and tenant suspend.

The console holds control-plane power, so it gets the control plane's review bar.

## Goals

- Sign in with GitHub through the public `edgekms` App's web flow (one click for a user who has already authorized it).
- See your tenants and pending invites; create a tenant; accept or decline an invite.
- Tenant detail with a structured editor for keys, roles and policies, saved through the existing `PUT /v1/tenants/<name>/config` with `If-Match`. A raw-JSON tab is the escape hatch for anything the structured editor doesn't cover.
- Members and invites: invite by GitHub login, change roles, remove members, withdraw invites.
- Export the tenant root key behind the fresh-login rule, with a deliberate confirmation, shown once.
- Operators: list, add and remove signup-allowlist entries; suspend and resume a tenant.

## Non-goals (v1)

- Invite requests ([#54](https://github.com/lokkju/edgekms/issues/12)): the page and its storage don't exist yet. The operator view gets a slot for them when #54 lands.
- Audit log view, usage metrics (Analytics Engine), billing.
- Key version history and rotation UI (the config has no rotate operation yet).
- Master-key rewrap (`POST /v1/ops/rewrap`) stays CLI-only.
- The marketing site and docs.
- Self-hosted (single-tenant) Workers: the console serves only in hosted mode.

## Anti-goals

These would make it a failure even if it works:

- A control token anywhere JavaScript can read it (localStorage, sessionStorage, a readable cookie, a JS variable).
- Any CSP relaxation: no `unsafe-inline`, no `unsafe-eval`, no third-party script or style origin.
- A second authorization model. The console is a client of the control API; every permission decision stays in `control/`.
- Console static assets served on any host other than `app.<apex>` (a tenant host serving console HTML would put control UI on a tenant origin).

## Architecture

**One Worker.** The hosted Worker `edgekms-hosted` serves the console on the reserved host `app.<apex>`. Today `dispatch_host` sends reserved names to a bare 404; `app` becomes a third dispatch target, `HostDispatch::Console`. No new Worker, route or binding beyond static assets, and the console's API calls go to its own origin, so the control plane needs no CORS.

**Static assets.** The hosted deploy's `wrangler.jsonc` gets an `assets` block (`directory` = the console build output, `binding: "ASSETS"`, `run_worker_first: true`, `not_found_handling: "single-page-application"`). `run_worker_first: true` is required: without it, Cloudflare would answer asset paths on every host the route covers, tenants included. The Worker passes a request to `ASSETS` only when the host is `app.<apex>` and the path isn't `/auth/*` or `/api/*`.

**Routes on `app.<apex>`** (new, in a `console` module of `edgekms-worker`):

| Route | What it does |
|---|---|
| `GET /auth/login?return_to=<path>` | Starts the GitHub web flow (below). |
| `GET /auth/callback?code&state` | Finishes it, sets the session cookie, redirects to `return_to`. |
| `POST /auth/logout` | Calls the control logout, clears the cookie. On a control-plane `5xx` the cookie stays and the `5xx` is passed on; the SPA then says the sessions are still active instead of leaving for `/signin`. |
| `* /api/v1/<rest>` | The control API, in process: the session cookie becomes `Authorization: Bearer`, and the request goes through `control::serve` as `/v1/<rest>`. |
| anything else | Static assets (the SPA). |

The proxy refuses `/api/v1/login/*` (the console logs in only through `/auth/callback`) and strips any incoming `Authorization` header. Control rate limits, audit events and IP keys apply unchanged, because the request goes through the same `control::serve`.

## Sign-in and session

**Web flow with PKCE.** The `edgekms` App already has a client secret in the Worker (`GITHUB_CLIENT_SECRET`) and device flow on. The web flow needs the callback URL `https://app.edgekms.dev/auth/callback` added to the App (owner action).

1. `GET /auth/login`: generate `state` (32 random bytes) and a PKCE `code_verifier` (S256). Set cookie `__Host-edgekms_auth` = `state.verifier.return_to` (HttpOnly, Secure, Path=/, SameSite=Lax, Max-Age=600), then 302 to `https://github.com/login/oauth/authorize?client_id=…&redirect_uri=…&state=…&code_challenge=…&code_challenge_method=S256`. `return_to` must be a same-origin path (starts with `/`, not `//`, no scheme); anything else becomes `/`.
2. `GET /auth/callback`: require the auth cookie, compare `state` in constant time, clear the cookie whatever happens. POST `https://github.com/login/oauth/access_token` with the client id, secret, `code`, `redirect_uri` and `code_verifier` (fetch with `redirect: "manual"`, per the #29 workerd lesson). The user token then goes through the existing login path: the same user check, token revocation, `SIGNUP_MODE` gate, personal-tenant creation and `AUTH_FAIL_LIMIT` counting as `POST /v1/login/github`. The resulting control token goes into the session cookie. (As built, there is no `login_with_token` refactor: the callback synthesizes a `POST /v1/login/github` request with body `{"token": <token>}` on behalf of the browser's client, same IP, limit key and country, and sends it through `control::handle`, which already applies `CONTROL_LIMIT` and writes the durable `control_login` audit record. A refusal before the login's own `check_token` ran, such as the control limit, would leave the token unrevoked, so the callback also revokes it at GitHub whenever the login reply isn't `200`. The code exchange itself is metered before it reaches GitHub, since a script holding its own auth cookie could otherwise replay the callback and spend the App's secret on GitHub's token endpoint without limit: no client IP refuses it (`login_failed`), it counts one `CONTROL_LIMIT` unit (`rate_limited` when over), a rejected code counts against `AUTH_FAIL_LIMIT` (`rate_limited` once over), and each refusal or failure is a `console_code_exchange` metric. A successful sign-in therefore costs two `CONTROL_LIMIT` units.)
3. Failures (bad state, GitHub refusal, `signup_closed`) redirect to `/signin?error=<code>` with a fixed set of codes; the SPA shows a message per code (for `signup_closed`: signups are invite-only, with a pointer to #54's page once it exists).

The auth cookie is SameSite=Lax because the callback is a top-level navigation from github.com, which never carries Strict cookies.

**Session cookie.** `__Host-edgekms_session` = the control token itself: HttpOnly, Secure, Path=/, SameSite=Strict, Max-Age = the token's remaining lifetime (`CONTROL_TTL_SECS`, 1800). The control token is already MAC'd, user-bound and revocable through the per-user `tokens_after_ms` cutoff, so a server-side session store would add state without adding a property. There is no refresh: when the token is missing, expired or cut off, the SPA sends the user through `/auth/login?return_to=<current path>`, which is one redirect round trip for an authorized user. Logout keeps today's semantics: it writes the user's cutoff, which also ends their CLI control sessions. The sign-out button says so.

**CSRF.** For every `/api/*` request with a method other than GET or HEAD, and for `/auth/logout`, the Worker requires `Origin` to equal `https://app.<apex>` and refuses otherwise (403), in addition to SameSite=Strict. State-changing calls must send `Content-Type: application/json` (or no body), which keeps them out of the simple-request set that browsers send cross-site without a preflight.

**Fresh login for export.** Export requires a login under 5 minutes old. The server's 403 "fresh login required" becomes `coded(403, …, "fresh_login_required")` so clients can match it. The SPA meets it by sending the user through `/auth/login?return_to=/t/<name>/export`, then retrying.

**Telling "sign in again" from "not allowed".** Today every bad control token (expired, cut off by logout, forged) gets the same uncoded `403 permission denied` as a member attempting an owner-only action. Two signals fix that:

- The proxy answers `401` with `"code": "no_session"` itself when the request has no session cookie.
- `control::auth::authenticate` failures become `coded(403, "permission denied", "auth_failed")`. The message stays the same, so the CLI's message matching is unaffected (the plan checks `edgekms-cli/src/control.rs` for any match on the uncoded body). An authorization refusal keeps its uncoded 403. The code tells a token holder only that the token no longer works, which they learn anyway on the next call.

The SPA re-authenticates on `no_session` or `auth_failed`, and shows "you don't have permission" on any other 403. A login that fails deterministically after sign-in would loop through GitHub, so the callback adds `signed_in=1` to the return path's query; the SPA notes the time in memory, strips the mark with `history.replaceState` before the router reads the address, and turns a `no_session` or `auth_failed` within 10 seconds of it into `/signin?error=login_failed` instead of another sign-in.

## Control-plane changes

The console needs these small changes in `control/`, each with tests, and they go through the same security review:

- ~~`login::run` split so a `login_with_token(c, req, ev, token)` holds everything after body parsing.~~ Replaced in the build: `/auth/callback` synthesizes `POST /v1/login/github` and calls `control::handle`, so it gets the `CONTROL_LIMIT` check on the client IP and the durable `control_login` audit outcome without a new entry point, and `login.rs` is unchanged by the console.
- `GET /v1/me` gains `"operator": bool` and a `status` for each tenant. Without the status the tenant list would need one `GET /v1/tenants/<name>` per tenant, each counted against `CONTROL_LIMIT`.
- The `auth_failed` and `fresh_login_required` codes above.

**Dispatch order in `hosted()`.** `read_request` turns away any path outside `/v1/` with a 404 before it reads the body, so the console branch for `app.<apex>` runs before `read_request`. `/api/v1/<rest>` requests are rewritten to `/v1/<rest>` before they're read.

## Response headers on `app.<apex>`

Every response (assets, auth, API):

- `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self' https://api.github.com; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
- `Strict-Transport-Security: max-age=63072000; includeSubDomains`
- `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`, `Permissions-Policy` denying everything.
- `/api/*` and `/auth/*`: `Cache-Control: no-store`. Hashed assets: long-lived immutable cache. `index.html`: `no-cache`.

`connect-src https://api.github.com` is for login-to-id lookup (below). `data:` in `img-src` is for inline SVG icons only.

## Frontend

**Stack (builder's defaults; see "Calls made").** Svelte 5 with Vite as a plain single-page app (no SvelteKit), Tailwind v4 with its CSS-first `@theme`, TypeScript. Everything is bundled and self-hosted; no CDN, no web fonts from a third party (system font stack). The build must emit no inline `<script>` or `<style>` and no `style=""` attributes, so the CSP above holds. The source lives in `console/` at the repo root (it's product code, so it lives beside the Worker); pnpm is pinned in `.mise/config.toml`.

**Screens:**

- `/signin`: one button, "Sign in with GitHub", and the error message when there's one.
- `/`: your tenants (name, your role, status, from `/me`) and pending invites with Accept and Decline. "New tenant" (name field with the `<login>-` rule explained, optional root import left to the CLI).
- `/t/<name>`: tabs.
  - **Keys:** list keys by name with id, `latest_version` and `min_decryption_version`; add a key (a name; the SPA generates the id as `k_` plus 16 random hex digits from `crypto.getRandomValues`, with both versions at 1). The structured editor never removes a key: a key's material is derived from the tenant root and its id, so a removed key leaves every ciphertext under it undecryptable until someone re-adds it with the same id. Removal stays possible through the raw-JSON tab.
  - **Roles:** a Mounts section, then roles grouped by mount.
    - Mounts: add, rename or remove `ssh` and `jwt` mounts. A `jwt` mount has two presets: "GitHub Actions" (issuer `https://token.actions.githubusercontent.com`, its `jwks_url`) and "Other OIDC" (issuer plus `jwks_url` or inline `jwks`). The hosted `github-user` mount is shown read-only, since its client id must be the hosted App's.
    - Roles: add, edit and remove roles; the form fields follow the mount type (`ssh_keys` for ssh; `bound_audiences` and `bound_claims` for jwt, with claim matchers as exact or glob rows; `github_user_ids`, entered by login, for github-user), plus `policies`, `token_ttl_secs` and `not_before`.
    - Whatever the hosted rules refuse (for example a JWKS they require pinned) comes back as the server's 400 message.
  - **Policies:** list policies; edit per-key capabilities as a checkbox grid (key × capability).
  - **Raw JSON:** the whole config in a textarea, with Save.
  - **Members:** members and invites with roles; invite by GitHub login; change role; remove or withdraw.
  - **Export** (owners): an explanation of what export means, a typed confirmation (the tenant name), the fresh-login step, then the root key and `root_id` shown once with a copy button. It's never stored in component state after the user leaves the view.
- `/ops` (operators; shown when `/me` says `operator: true`): the signup allowlist (list, add by GitHub login, remove), and suspend or resume a tenant by name through `PUT /v1/ops/tenants/<name>/status`. Operators can't read tenants they don't belong to, and v1 adds no operator read or list route, so the form takes a typed name.

**Saving config.** Every editor works on a local copy of `config` from `GET /v1/tenants/<name>` and saves the whole document with `If-Match: "<config_version>"`. A 409 shows "changed elsewhere", reloads, and keeps the user's edits visible for re-entry. A 400 shows the server's message at the top of the editor. Field-level mapping of server errors is a later improvement.

**Login to GitHub id.** Members and the allowlist are keyed by GitHub id. The SPA resolves a login with an unauthenticated `GET https://api.github.com/users/<login>` from the browser (60 requests per hour per user IP is plenty for a human), shows the resolved account (login and id) for confirmation, then sends the id. No server route and no shared rate-limit pool.

## Build and deploy

- `console/` builds with `pnpm build` into `console/dist`.
- The hosted deploy's `deploy` task builds the console before `wrangler deploy`; the wrangler `assets.directory` points at `console/dist`.
- CI (`ci.yml`) adds a console job: install, typecheck, lint, unit tests, build, and a check that `dist/index.html` has no inline script or style.
- The control-plane changes ship in the same deploy.

## Testing

- **Rust (worker):** host dispatch for `app`; `/auth/login` cookie attributes and the redirect; `return_to` sanitizing; callback state mismatch, a missing cookie, a GitHub refusal and success (with the existing fake GitHub checker plus a fake token exchange); the proxy's `Authorization` strip, login-route refusal and Origin check; the headers on every response type; and assets never served on a tenant host.
- **Console:** Vitest for config-editing logic (pure functions over the config JSON: add a key, edit a role, the capability grid round-trip). Playwright against the built SPA with `/api/*` mocked through `page.route`, for the main flows: sign-in redirect, tenant list, a role edit and save, a 409, invite by login and export.
- **Manual, after deploy:** a real sign-in on app.edgekms.dev, a no-op config save on a tenant you own, and a CSP-violation check in the browser console.
- **Review:** an independent security review of the `console` module, the login refactor and the invitee admission change (below) before the PR is opened, as for the control plane, run on Fable (`claude-fable-5-1`). A Fable review of the whole codebase follows at the end of the epic.

## Can an invitee sign in? (decided (b), 2026-11-10)

In `SIGNUP_MODE=invite`, `admit` (`control/login.rs`) refuses anyone who isn't an operator, on the signup allowlist, or already a member. A pending invite deliberately doesn't count. So an owner who invites a collaborator from the Members tab sends them to a `signup_closed` page, and they never reach Accept unless an operator also allowlists them.

- **(a) Keep the rule.** The Members tab says the invitee also needs an operator's allowlisting, and the `signup_closed` page says to ask the person who invited you.
- **(b) A pending invite admits a sign-in with no personal tenant.** The user gets a control token and can accept or decline, exactly like an existing member admitted by memberships alone. An owner can't hand anyone a tenant of their own this way, only a seat in theirs. This changes control-plane authorization, so it's reviewed with the rest.

The owner chose (b): (a) makes the Members tab useless in invite mode, which is the mode the console launches in. Only an invite whose MAC verifies admits a sign-in, and the user still gets no personal tenant until the mode admits them by its own rules.

## Owner actions

- Add `https://app.edgekms.dev/auth/callback` as a callback URL on the `edgekms` GitHub App. Needed before the first production sign-in, not before building.

## Calls made (builder's, the owner can override)

- One Worker serves the console on `app.<apex>`; no separate console Worker.
- The session cookie holds the control token; no server-side session store.
- Svelte 5 plus Vite, no SvelteKit; pnpm.
- Login-to-id lookup in the browser against api.github.com.
- No key removal in the structured editor (raw JSON only).
- Root import on tenant create stays CLI-only.
- Logout keeps its all-sessions semantics.
- Operator suspend and resume by typed name on `/ops`; no operator tenant read or list route in v1.
- `auth_failed` as a code on the existing uniform 403, not a new status.
- The Roles tab manages `ssh` and `jwt` mounts, with a GitHub Actions preset.
