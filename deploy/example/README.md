# example

A single-tenant edgekms in your own Cloudflare account: one Worker serving one custom domain,
with your own root key and a `config.json` of keys, mounts, roles and policies. A policy change is
a commit and a deploy. For a multi-tenant deployment with sign-in, a control plane and the web
console, see [deploy/example-hosted/](../example-hosted/README.md).

Copy this directory to `deploy/<instance>/` (or a repo of your own, with `EDGEKMS_SRC` pointing at
an edgekms checkout), then fill in the placeholders.

| File | What it is |
| --- | --- |
| `wrangler.jsonc` | Worker and bindings. `account_id`, the KV `id` and the custom domain are yours to fill in. |
| `config.json` | Keys, mounts, roles and policies, deployed as the `EDGEKMS_CONFIG` var. The example holds a CI smoke key, a Pulumi key (`examples/pulumi-smoke/`) and an OpenBao auto-unseal key. |
| `.mise/tasks/deploy` | Placeholder check, account check, config validation with the Worker's own code, `wrangler deploy`. |

## Fill in

- `wrangler.jsonc`: your account id, and your domain in place of `kms.example.com`. The zone must
  be in the same account.
- `config.json`: the same domain in `public_origins` and every `bound_audiences`; a fresh random
  `root_id` and key `id`s (`printf 'r_%s\n' "$(openssl rand -hex 8)"`, and `k_` for keys); your
  GitHub repository's numeric `repository_id` and `repository_owner_id`
  (`gh api repos/<owner>/<repo> --jq '.id, .owner.id'`); your SSH public key in the `operator`
  role. Ids are random and not secret; once anything is encrypted, never change them, because a
  changed `root_id` or key `id` makes every existing ciphertext undecryptable.

[docs/design.md](../../docs/design.md) explains the config format, the mounts (GitHub Actions and
other OIDC issuers, SSH keys, GitHub users) and the policy model.

## Credentials

Export a Cloudflare API token as `CLOUDFLARE_API_TOKEN`. It must reach this account and no other
(the deploy task checks), and needs Workers Scripts Edit, Workers KV Storage Edit and R2 Edit,
plus Zone Read and Workers Routes Edit on the zone.

## Root key and resources

Once, before the first deploy:

```sh
wrangler kv namespace create edgekms-revoked     # paste the id over REPLACE_WITH_KV_NAMESPACE_ID
wrangler r2 bucket create edgekms-audit
wrangler r2 bucket lock add edgekms-audit audit-retention "" --retention-days 365
```

The lock keeps audit objects from being deleted or overwritten for the retention period; it is
permanent for each object, so pick the period before the first write.

The root key is 32 random bytes, set as the Worker secret `ROOT_KEY`. Keep an offline copy first,
encrypted to a key you control (age or SOPS), and keep the plaintext out of argv, the environment
and the disk:

```sh
root=$(openssl rand -base64 32)
printf '%s' "$root" | age -r <your recipient> -o edgekms-root.age
printf '%s' "$root" | wrangler secret put ROOT_KEY --name edgekms
unset root
```

If the Worker doesn't exist yet, `wrangler secret put` creates it as an empty placeholder, and the
first deploy replaces it and keeps the secret. A deploy before the secret exists fails closed:
every request returns a 500 until `ROOT_KEY` is set. With the offline copy, any ciphertext can be
decrypted without the Worker (`edgekms decrypt`).

## Deploy

```sh
CLOUDFLARE_API_TOKEN=... mise -C deploy/example run deploy
```

Then log in, for example with the operator's SSH key:

```sh
edgekms login ssh --addr https://kms.example.com --role operator --key ~/.ssh/id_ed25519.pub
```

A GitHub Actions job logs in with its OIDC token on the `github` mount and gets a token limited to
its role's policies; `examples/pulumi-smoke/` and the [README](../../README.md) show the shape.
