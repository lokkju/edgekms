# Hosted quickstart

edgekms runs as a hosted service at `edgekms.dev`. You log in with your GitHub account, and your first
login gives you a tenant, `https://<you>.edgekms.dev`, that any Vault Transit client can use by
setting `VAULT_ADDR`. This page walks through the CLI from first login to export. [How it works](how-it-works.md)
explains the service, and the [security model](security-model.md) its threat model.

You need the `edgekms` CLI on your PATH ([install it](cli-install.md)), and `curl` and
`jq` for a couple of the steps below.

`edgekms.dev` is invite-only for now. Your first login works once an operator has put your
numeric GitHub id on the signup allowlist; until then `edgekms account login` stops with
"edgekms.dev is invite-only. Run `edgekms account request-invite` to ask for an invite, or open
https://app.edgekms.dev/request-invite." Either one asks an operator for an invite, with an
optional note on what you'll use edgekms for:

```sh
edgekms account request-invite --note "signing CI artifacts for a small project"
```

It runs the same GitHub device flow, then files the request, or, if you've asked before, says how
it stands. edgekms doesn't email you; run `edgekms account login` later, and once you're approved
it creates your tenant. Once you have a tenant, or belong to someone else's, you can always log
in, whatever happens to signups later.

## The web console

Everything below also works in a browser at [app.edgekms.dev](https://app.edgekms.dev). The
[console guide](console.md) covers it, including which CLI command each console action matches.
Signing out of the console is `edgekms account logout`: it ends your CLI control tokens too.

## 1. Log in to the control plane

```sh
export EDGEKMS_CONTROL_TOKEN="$(edgekms account login)"
```

This runs GitHub's device flow with the public `edgekms` GitHub App: the CLI prints a URL and a
code on stderr, you enter the code at github.com in any browser, and the CLI prints a control
token on stdout. Nothing is saved to disk; every `edgekms tenant` command reads the token from
`EDGEKMS_CONTROL_TOKEN`, never from a flag. The App asks for no permissions and is never
installed on your account.

Your first login creates your personal tenant, named after your GitHub login in lowercase (or the
login plus `-` and four hex digits, if that name is taken or not allowed). The CLI's summary on
stderr names it. A pending invite into someone else's tenant also lets you log in, whatever the
signup mode, so you can accept it; it doesn't give you a personal tenant of your own.

A control token lasts 30 minutes. When it runs out, log in again. To end every control token you
hold, not just the current one:

```sh
edgekms account logout
```

## 2. See your tenants

```sh
edgekms tenant list           # name and your role in each, tab-separated
edgekms tenant show <name>    # id, root id, status, config, members and pending invitations, as JSON
```

## 3. Use your tenant with a Vault client

A new tenant's config has one key, `default`, and an `owner` role that lets your GitHub account
encrypt, decrypt, rewrap and read `default`, and mint tokens. Log in to the tenant itself with
GitHub (this is the data plane, separate from the control-plane login above):

```sh
export VAULT_ADDR=https://<you>.edgekms.dev
export EDGEKMS_GITHUB_CLIENT_ID="$(curl -fsS https://api.edgekms.dev/v1/info | jq -r .github_client_id)"
export VAULT_TOKEN="$(edgekms login github --addr "$VAULT_ADDR" --role owner)"
```

`EDGEKMS_GITHUB_CLIENT_ID` is the hosted App's client id, which every tenant's `github-user`
mount uses; `--client-id` works too. The token lasts an hour.

With `VAULT_ADDR` and `VAULT_TOKEN` set, clients work unchanged:

- **Vault or OpenBao CLI:**

  ```sh
  vault write transit/encrypt/default plaintext="$(printf 'hello' | base64)"
  vault write transit/decrypt/default ciphertext=vault:v1:...
  ```

  `bao` takes the same arguments, with `BAO_ADDR` and `BAO_TOKEN`.

- **Pulumi:**

  ```sh
  pulumi stack init dev --secrets-provider hashivault://default
  ```

  Pulumi wraps the stack's data key under `default` and decrypts it once per command. The
  [Pulumi guide](guides/pulumi.md) covers a dedicated key and CI.

- **sops:**

  ```sh
  sops encrypt --hc-vault-transit "$VAULT_ADDR/v1/transit/keys/default" secrets.yaml > secrets.sops.yaml
  ```

  The [SOPS guide](guides/sops.md) sets it up for a repository.

- **OpenBao auto-unseal:** OpenBao's seal holds a static token, so mint a revocable one that can
  only use the key. Created tokens may carry key policies you hold, never `admin`:

  ```sh
  curl -fsS -X POST "$VAULT_ADDR/v1/auth/token/create" \
    -H @<(printf 'X-Vault-Token: %s\n' "$VAULT_TOKEN") \
    -d '{"policies": ["default-all"], "ttl": "8760h", "display_name": "openbao-seal"}' |
    jq -r .auth.client_token
  ```

  `-H @<(printf ...)` hands curl the header through a file descriptor, so the token stays out of
  curl's command line, which other users on the machine can read in `ps`.

  and point the seal at your tenant:

  ```hcl
  seal "transit" {
    address    = "https://<you>.edgekms.dev"
    token      = "<the token above>"
    key_name   = "default"
    mount_path = "transit/"
  }
  ```

  A real deployment would add a dedicated key and policy for the seal (step 4) instead of
  handing OpenBao `default-all`. `POST /v1/auth/token/revoke-accessor` with the token's accessor
  revokes it, within about a minute. The [OpenBao guide](guides/openbao.md) does it that way.

## 4. Change the config

The tenant config is the same JSON a self-hosted edgekms reads: keys, mounts, roles and policies,
described in the [API reference](api.md#the-tenant-config). A few rules are the service's: leave `root_id` as it is,
leave out `public_origins` (the service sets your origin), and any `github-user` mount uses the
hosted App's client id.

```sh
edgekms tenant config get <name> > config.json    # the version goes to stderr
# edit config.json
edgekms tenant config set <name> config.json
```

`config set` checks the file locally first, then replaces the version it just read, and says so
on stderr. Pass `--if-version <n>` to replace a specific version instead; if someone else changed
it in the meantime, the set fails rather than overwriting their edit. Every isolate picks up the
new config within about 30 seconds, with no deploy.

For example, to let a GitHub Actions workflow on `main` in one repository decrypt with a key
`infra-prod`, add a JWT mount for GitHub's OIDC issuer, a role bound to that repository by its
numeric ids, the key and a policy:

```json
{
  "mounts": {
    "github": {
      "type": "jwt",
      "issuer": "https://token.actions.githubusercontent.com",
      "jwks_url": "https://token.actions.githubusercontent.com/.well-known/jwks"
    }
  },
  "roles": {
    "infra-ci": {
      "mount": "github",
      "bound_audiences": ["https://you.edgekms.dev"],
      "bound_claims": { "repository_id": "812345678", "repository_owner_id": "1234567", "ref": "refs/heads/main" },
      "policies": ["infra-prod-decrypt"],
      "token_ttl_secs": 900
    }
  },
  "keys": { "infra-prod": { "id": "k_7f3a9c1e", "latest_version": 1, "min_decryption_version": 1 } },
  "policies": { "infra-prod-decrypt": { "keys": { "infra-prod": ["decrypt"] } } }
}
```

(with your tenant's name for `you`, merged into the existing objects, not replacing them; a key id is any fresh random id, and
changing it later makes a different key). The workflow requests an OIDC token with audience
`https://<you>.edgekms.dev` and swaps it for an edgekms token at `POST /v1/auth/github/login` with
`{"role": "infra-ci", "jwt": "<token>"}`, or through `hashicorp/vault-action` with method `jwt`
and path `github`. The [GitHub Actions guide](guides/github-actions.md) has the whole workflow.

## 5. Share a tenant

Owners invite people by numeric GitHub id (`curl -fsS https://api.github.com/users/<login> | jq
.id` finds it). They needn't have logged in yet.

```sh
edgekms tenant member add <name> --github-id 1234567           # invite as a member (read-only)
edgekms tenant member add <name> --github-id 1234567 --owner   # invite as an owner
edgekms tenant member remove <name> --github-id 1234567        # remove, or withdraw the invitation
```

An invitation grants nothing until it's accepted. The invitee sees and answers it with:

```sh
edgekms tenant invites
edgekms tenant accept <name>
edgekms tenant decline <name>
```

Owners edit the config, manage members and export the root key; members can read the tenant and
its config. A tenant always keeps at least one owner. Membership is about the control plane only:
to let someone use the tenant's keys, give them a role in its config.

You can create up to five tenants of your own, your personal tenant included. While signups are
invite-only, that needs a place on the allowlist or a tenant you created; belonging to someone
else's tenant isn't enough.

```sh
edgekms tenant create <name>                         # a fresh root and the default config
edgekms tenant create <name> --config config.json    # a fresh root and your config
```

Names are 3 to 32 characters of lowercase letters, digits and single hyphens, and start with your
GitHub login and a hyphen: if you log in as `Alice`, `alice-staging` and `alice-ci` work and
`staging` doesn't. The base is your login folded the same way your personal tenant's name is
(lowercase, other characters as `-`), and a refusal names it.

## 6. Bring a self-hosted instance in

A tenant can start from an existing root key, so every ciphertext and token a self-hosted edgekms
issued keeps working. The config must be the instance's config with `public_origins` removed,
its `root_id` unchanged, and any `bound_audiences` and `github-user` mounts updated for
`https://<name>.edgekms.dev`. The root key comes from stdin, never a terminal or a flag:

```sh
sops decrypt --extract '["root_key"]' root.sops.yaml |
  edgekms tenant create <name> --import-root-id <root id> --config config.json
```

## 7. Export: you can always leave

An owner can export the tenant's root key. It needs a control-plane login under five minutes old,
so log in again first:

```sh
export EDGEKMS_CONTROL_TOKEN="$(edgekms account login)"
edgekms tenant export <name> | jq -Rn '{root_key: input}' |
  sops encrypt --filename-override root.sops.yaml --input-type json --output-type yaml \
    /dev/stdin > root.sops.yaml
```

That writes a SOPS file with one key, `root_key`, under your `.sops.yaml` creation rules, and the
plaintext key never touches disk. The root id goes to stderr and the base64 root key alone to
stdout, so pipe it straight into an encrypted store; anyone holding it can decrypt everything the tenant has encrypted and mint tokens
for it. With the root key and your config, the CLI decrypts offline (`edgekms decrypt`), exports
a key version for OpenBao's BYOK import (`edgekms export`), or a self-hosted edgekms Worker serves
the same keys; see the [security model](security-model.md#exit-and-break-glass).

## 8. Break-glass: log in with an SSH key when GitHub isn't there

GitHub is the usual way in. If you lose the GitHub account, or GitHub's device flow or API is
down, you can still log in, export and read your configs with an SSH key you registered
beforehand. Register one now, while GitHub works; it only takes a login under five minutes old:

```sh
export EDGEKMS_CONTROL_TOKEN="$(edgekms account login)"
edgekms account ssh-keys add --label yubikey
```

Without `--key`, the CLI uses the one Ed25519, `sk-ssh-ed25519` or ECDSA P-256 key your ssh-agent
holds, and refuses to guess if it holds several; pass `--key ~/.ssh/<key>.pub` then. It never
reads a private key: `ssh-keygen -Y sign` asks ssh-agent to sign a registration challenge
(namespace `edgekms-register`), which proves you hold the key. The challenge names the GitHub
account the key goes to, and the CLI prints it (`Registering SSH key SHA256:... to GitHub account
<login> (<id>).`) and refuses to sign one naming any account but the one you logged in as; pass
`--expect-github-id <id>` to pin it yourself. The label defaults to the key's comment.

Then, when you need it:

```sh
export EDGEKMS_CONTROL_TOKEN="$(edgekms account login --ssh)"
edgekms tenant export <name> | ...
```

The token is an ordinary control token: 30 minutes, fresh enough to export for its first five,
the token alone on stdout. An SSH login only reaches an account that already exists (you hold a
membership or a pending invite, or you're an operator); it never signs anyone up.

A registered key is as strong as your GitHub account, so pick it with care:

- Prefer a security key (`sk-ssh-ed25519`, `ssh-keygen -t ed25519-sk`), which signs only when
  touched, or a key added with `ssh-add -c`, which asks before every signature.
- When you forward your agent to another host, add the key with a destination constraint
  (`ssh-add -h`), so that host can't use it for edgekms.
- Every login names its key: `edgekms account login` prints how many keys can log in to your
  account, and `edgekms account ssh-keys list` shows each one with the login that added it
  (`github`, or `ssh:<fingerprint>` for a key added from an SSH session).

`edgekms account ssh-keys remove <id or fingerprint>` removes a key from any session, fresh or
not, and every control token that key minted stops working on its next request. The console's
Account page does the same; see the [console guide](console.md).
