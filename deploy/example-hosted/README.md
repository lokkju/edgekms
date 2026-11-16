# example-hosted

A hosted-mode edgekms in your own Cloudflare account: one Worker serving every tenant at
`https://<tenant>.<apex>`, the control plane at `https://api.<apex>` and the web console at
`https://app.<apex>`, the same build edgekms.dev runs. People sign in with GitHub, get tenants,
and manage them from the CLI or the console. If you only need one set of keys for yourself, the
single-tenant example in [deploy/example/](../example/README.md) is simpler.

Copy this directory (to `deploy/<yours>/` or into a repo of your own), fill in the
placeholders, and run the tasks below. None of the values in `wrangler.jsonc` is secret.

| File | What it is |
| --- | --- |
| `wrangler.jsonc` | Worker, bindings and vars, with `REPLACE_WITH` placeholders for your ids. |
| `hosted.env` (optional, yours) | Pins the account, Worker name and D1 name the tasks check against, forbids other accounts, and can refuse routes; see the top of `.mise/lib/hosted.sh`. |
| `.mise/tasks/build` | The console and Worker builds, with no Cloudflare token in their environment. |
| `.mise/tasks/deploy` | Config checks, the `build` task (unless `--prebuilt`), `wrangler d1 migrations apply --remote`, `wrangler deploy`. |
| `.mise/tasks/migrate` | The D1 migrations alone, for a first run before the Worker can deploy. |
| `.mise/tasks/test-config` | Proves the wrangler.jsonc rules refuse a config missing each required binding or var. No token needed; CI runs it against this file. |
| `.mise/lib/hosted.sh` | The credential and account check and the wrangler.jsonc rules the tasks share. |
| `.mise/lib/jsonc.mjs` | Turns `wrangler.jsonc` into plain JSON so the tasks can check it with `jq`. |

The tasks find the edgekms checkout from their own location. A copy outside this repo sets
`EDGEKMS_SRC` to an edgekms checkout and runs the tasks from it with `HOSTED_DIR` naming the copy:

```sh
HOSTED_DIR=$PWD/my-deploy EDGEKMS_SRC=$PWD/edgekms \
  edgekms/deploy/example-hosted/.mise/tasks/deploy
```

## Prerequisites

Run `mise install` in the repo root (wrangler, node, pnpm, Rust, worker-build), and have `openssl`
and `jq` on PATH. You need:

- a Cloudflare account, ideally one that holds nothing else, with few members and hardware-key
  2FA: everyone who can deploy Workers to it can bind the master key;
- a zone for your apex (`example.com` below) in that account, with a proxied wildcard DNS record
  `*.example.com` (an `AAAA` to `100::` is the usual placeholder target);
- a GitHub App with device flow enabled and no permissions (GitHub, Settings, Developer settings,
  GitHub Apps; no callback URL or webhook, and it never needs installing). Its client id goes in
  `vars.GITHUB_CLIENT_ID`; its client secret becomes the Worker secret `GITHUB_CLIENT_SECRET`.

## Credentials

Every task runs wrangler with one account's token and nothing else. Your shell's
`CLOUDFLARE_API_TOKEN` is ignored and unset outside CI, because it is so often a token for some
other account. Export the deploy token as `EDGEKMS_CLOUDFLARE_API_TOKEN`; the tasks copy it into
`CLOUDFLARE_API_TOKEN` for wrangler only, set `CLOUDFLARE_ACCOUNT_ID`, and refuse to go on unless
`wrangler whoami --json` lists exactly one account, the one in `wrangler.jsonc` (or
`HOSTED_ACCOUNT_ID` in `hosted.env`).

Make it an account API token in that account with Workers Scripts Edit, D1 Edit, Account Settings
Read (for the account check), Secrets Store Edit (for the master key), and Zone Read plus Workers
Routes Edit on the zone if `wrangler.jsonc` keeps its route. In GitHub Actions
(`GITHUB_ACTIONS=true`) the tasks take `CLOUDFLARE_API_TOKEN` from the job's environment as it is;
keep it in an environment with a required reviewer and a `main`-only branch policy, and run the
build in an earlier step that doesn't have it.

## Resource ids

Create the resources once, by hand or from your own infrastructure code, and paste the ids in:

```sh
wrangler d1 create edgekms-tenants                # -> d1_databases[0].database_id
wrangler kv namespace create edgekms-revoked      # -> kv_namespaces[0].id
wrangler r2 bucket create edgekms-audit           # r2_buckets[0].bucket_name
wrangler secrets-store store create edgekms --remote   # -> store_id
```

| Placeholder | Where it goes |
| --- | --- |
| `REPLACE_WITH_ACCOUNT_ID` | `account_id` |
| `REPLACE_WITH_APEX` | the route, `vars.HOSTED_APEX` and `vars.HOSTED_ORIGIN_TEMPLATE` |
| `REPLACE_WITH_GITHUB_APP_CLIENT_ID` | `vars.GITHUB_CLIENT_ID` |
| `REPLACE_WITH_YOUR_GITHUB_USER_ID` | `vars.OPERATOR_GITHUB_IDS` (`gh api user --jq .id`) |
| `REPLACE_WITH_D1_TENANTS_ID` | `d1_databases[0].database_id` |
| `REPLACE_WITH_KV_NAMESPACE_ID` | `kv_namespaces[0].id` |
| `REPLACE_WITH_SECRETS_STORE_ID` | `store_id` of every `secrets_store_secrets` entry |

Give the audit bucket a lock rule so audit objects can't be deleted or overwritten
(`wrangler r2 bucket lock add edgekms-audit audit-retention "" --retention-days 365`, or
longer); it is
permanent for each object, so choose the period before the first write.

`deploy` refuses to run while any `REPLACE_WITH` placeholder remains; `migrate` needs only the D1
id.

## First bring-up

1. Fill in the resource ids, the apex and the App's client id.
2. Apply the schema: `EDGEKMS_CLOUDFLARE_API_TOKEN=... mise -C deploy/example-hosted run migrate`.
3. Create the master key, version `m1`. It wraps every tenant's root key, so keep an offline copy
   (encrypted to a hardware-backed key) before Cloudflare holds it, and never put it in argv, the
   environment or a plaintext file:

   ```sh
   master=$(openssl rand -base64 32)
   printf '%s' "$master" | age -r <your recipient> -o edgekms-master-m1.age
   printf '%s' "$master" | wrangler secrets-store secret create <store id> \
     --name edgekms-master-m1 --scopes workers --remote
   unset master
   ```

   The binding `MASTER_KEY_M1` -> `edgekms-master-m1` is in `wrangler.jsonc` already. The offline
   copy plus a copy of the `tenants` table decrypts every tenant's ciphertexts, so guard it like
   that.
4. Set the App's client secret, piped on stdin:
   `printf '%s' "$secret" | wrangler secret put GITHUB_CLIENT_SECRET --name edgekms`. If the
   Worker doesn't exist yet, this creates it as an empty placeholder, and the first deploy
   replaces it and keeps the secret.
5. Deploy: `EDGEKMS_CLOUDFLARE_API_TOKEN=... mise -C deploy/example-hosted run deploy`.
6. Log in: `edgekms account login --api https://api.example.com --client-id <App client id>`,
   then `edgekms tenant create <name>`. The [hosted quickstart](../../docs/hosted-quickstart.md)
   walks through the rest with `api.edgekms.dev`; pass `--api` for yours.

## Deploy

```sh
mise -C deploy/example-hosted run build
EDGEKMS_CLOUDFLARE_API_TOKEN=... mise -C deploy/example-hosted run deploy --prebuilt
```

Before touching Cloudflare, `deploy` refuses placeholders and checks `wrangler.jsonc` against the
rules in `.mise/lib/hosted.sh`: name and account, no `build` block, `run_worker_first`, every
binding the Worker needs (a missing rate limiter would let requests through unlimited), and
master key bindings that match `MASTER_KEY_CURRENT` and `MASTER_KEY_PREVIOUS`. It applies the D1
migrations before the Worker, so a migration has to keep working with the version already
deployed, and refuses to deploy a config that drops the binding of a master version rows in D1
are still wrapped under.

## Master key rotation

From `m1` to `m2`:

1. Create `edgekms-master-m2` as in step 3 of the bring-up.
2. In `wrangler.jsonc`, add the `MASTER_KEY_M2` binding next to `MASTER_KEY_M1`, set
   `"MASTER_KEY_CURRENT": "m2"` and add `"MASTER_KEY_PREVIOUS": "m1"`. Deploy. New tenants are now
   wrapped under `m2`, and both versions unwrap.
3. Rewrap every row, as an operator (a GitHub id in `OPERATOR_GITHUB_IDS`), with
   `POST https://api.example.com/v1/ops/rewrap` and a control token from `edgekms account login`.
   Each call does up to `limit` rows (1 to 100) and replies
   `{"rewrapped", "failed", "next", "remaining"}`; pass `next` back as `after` until it's `null`,
   and repeat until `remaining` is 0.
4. Retire `m1`: delete the `MASTER_KEY_M1` entry and the `MASTER_KEY_PREVIOUS` var, and deploy.
   `deploy` counts the rows per master version in D1 first and refuses while any row is still
   wrapped under a version the config no longer binds.

[docs/design.md](../../docs/design.md#hosted-tier) has the design.
