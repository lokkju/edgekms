# Self-hosting

The Worker behind `edgekms.dev` also runs single-tenant in your own Cloudflare account, with your
own root key and a `config.json` of the same shape a hosted tenant's config has. Your account then
holds the root key, and a config change is a commit and a deploy instead of a call to the control
plane. The hosted service is the same code with a `HOSTED_APEX` set; leave it unset and the Worker
serves one deployment at its own origin.

## What you need

- A Cloudflare account, ideally one used for nothing else, with few members and hardware-key
  2FA: anyone who can upload a Worker script to it can read the root key.
- A custom domain on that account for the Worker (`kms.example.com`), with `workers_dev` and
  preview URLs off so it has no other origin.
- An API token that reaches that account and no other, with Workers Scripts, Workers KV Storage
  and R2 edit, plus Zone read and Workers Routes edit on the domain's zone.
- A clone of the [edgekms repository](https://github.com/lokkju/edgekms) with `mise install` run
  in it (Rust, worker-build, wrangler, age), and `openssl` and `jq`.
- Somewhere to keep the root key's offline copy, encrypted to a key you hold (age or SOPS).

## The instance directory

An instance is a directory under `deploy/`: `wrangler.jsonc` (the Worker and its bindings),
`config.json` (keys, mounts, roles and policies) and a mise `deploy` task.
[`deploy/example`](https://github.com/lokkju/edgekms/tree/main/deploy/example) is the template:
copy it, fill in the account id, the domain and your repository's ids, and generate fresh random
`root_id` and key ids for `config.json`. Its README walks through each step.

- **The bootstrap** runs once, by hand, as the example's README shows. It generates the root key
  and pipes it to two places: the offline copy first (age or SOPS), then
  `wrangler secret put ROOT_KEY`, which stores it as a Worker secret. The plaintext never touches
  disk. It also creates the audit bucket, with an object lock for the retention you pick, and the
  KV namespace for token revocation.
- **`deploy`** refuses leftover placeholders, checks the token reaches exactly your account,
  validates `config.json` with the same code the Worker uses, then runs `wrangler deploy` with the
  config as the `EDGEKMS_CONFIG` var.

To run hosted mode yourself (many tenants, GitHub sign-in, the control plane and the web console),
start from [`deploy/example-hosted`](https://github.com/lokkju/edgekms/tree/main/deploy/example-hosted)
instead.

Logins work as on a hosted tenant, with your origin as `--addr`. Set `public_origins` in the config
to the Worker's origin, so SSH challenges are bound to it. A `github-user` mount needs a GitHub App
of your own with device flow enabled, its client secret set as the Worker secret
`GITHUB_CLIENT_SECRET`; each deployment needs its own App, as the
[security model](security-model.md#cli-logins) explains.

## Moving between hosted and self-hosted

Both directions keep every ciphertext and token valid, because both sides derive keys from the
same root and key ids:

- **Hosted to self-hosted:** export the tenant's root key and config (the
  [quickstart](hosted-quickstart.md#7-export-you-can-always-leave) shows how), put the root key in
  as `ROOT_KEY` the way `bootstrap` does, and deploy the config with `public_origins` added and
  `bound_audiences` updated for the new origin.
- **Self-hosted to hosted:** create a tenant from the root key with
  `edgekms tenant create <name> --import-root-id <root id> --config config.json`, the root key on
  stdin, as the [quickstart](hosted-quickstart.md#6-bring-a-self-hosted-instance-in) describes.
