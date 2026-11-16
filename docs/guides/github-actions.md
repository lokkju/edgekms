# GitHub Actions

A workflow can log in to an edgekms tenant with the OIDC token GitHub issues to every job, so no
Vault token, Cloudflare credential or other long-lived secret is stored in the repository. The
tenant's config decides which repositories, branches, tags or environments may log in, and which
keys their token may use.

The examples use the tenant `acme` (`https://acme.edgekms.dev`), a key `infra-prod` and the
repository `acme/app`. Swap in your own.

## 1. Find the repository's numeric ids

Roles bind GitHub's numeric `repository_id` and `repository_owner_id`, not the names. A deleted
repository's or organization's name can be registered again by someone else, and a role bound to
the name would trust them.

```sh
gh api repos/acme/app --jq '{id, owner_id: .owner.id}'
```

The console's role form looks the ids up for you for a public repository; see its
[GitHub Actions recipe](../console.md#github-actions-for-a-repository-or-branch).

## 2. Add a mount, a role, a key and a policy

Fetch the config, merge these into its `keys`, `mounts`, `roles` and `policies` objects, and set
it back:

```sh
export EDGEKMS_CONTROL_TOKEN="$(edgekms account login)"
edgekms tenant config get acme > config.json
# edit config.json
edgekms tenant config set acme config.json
```

```json
{
  "keys": {
    "infra-prod": { "id": "k_3f9a1c7e5b2d4086", "latest_version": 1, "min_decryption_version": 1 }
  },
  "mounts": {
    "actions": {
      "type": "jwt",
      "issuer": "https://token.actions.githubusercontent.com",
      "jwks_url": "https://token.actions.githubusercontent.com/.well-known/jwks"
    }
  },
  "roles": {
    "deploy-main": {
      "mount": "actions",
      "bound_audiences": ["https://acme.edgekms.dev"],
      "bound_claims": {
        "repository_id": "812345678",
        "repository_owner_id": "1234567",
        "ref": "refs/heads/main"
      },
      "policies": ["infra-prod-decrypt"],
      "token_ttl_secs": 900
    }
  },
  "policies": {
    "infra-prod-decrypt": { "keys": { "infra-prod": ["decrypt"] } }
  }
}
```

A key id is any fresh value of lowercase letters, digits and `_`; it's where the key's material
comes from, so changing it later makes a different key. The new config reaches every edge location
within about 30 seconds.

Every bound claim must match exactly, and the token's `aud` must be one of `bound_audiences`. The
audience is your tenant's URL, so a GitHub token minted for some other service isn't accepted
here. For more than one branch or tag, write the value as a glob, where `*` matches any run of
characters, slashes included:

```json
{
  "roles": {
    "release": {
      "mount": "actions",
      "bound_audiences": ["https://acme.edgekms.dev"],
      "bound_claims": {
        "repository_id": "812345678",
        "repository_owner_id": "1234567",
        "ref": { "glob": "refs/tags/v*" }
      },
      "policies": ["infra-prod-decrypt"],
      "token_ttl_secs": 900
    }
  }
}
```

A glob without a `*` is refused, and a `*` in a plain string is just a character. To hold a role
to one deployment environment's jobs, add `"environment": "prod"`; leave `ref` out to admit every
branch and tag. GitHub's claims are listed in
[About security hardening with OpenID Connect](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect).

## 3. Log in from the workflow

Give the job `id-token: write`, ask GitHub for a token with your tenant as the audience, and swap
it at the mount's login path, `/v1/auth/actions/login`:

```yaml
permissions:
  id-token: write
  contents: read

steps:
  - name: Log in to edgekms
    run: |
      jwt=$(curl -fsS -H @<(printf 'Authorization: Bearer %s\n' "$ACTIONS_ID_TOKEN_REQUEST_TOKEN") \
        "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=https://acme.edgekms.dev" | jq -r .value)
      token=$(jq -n --arg jwt "$jwt" '{role: "deploy-main", jwt: $jwt}' |
        curl -fsS -X POST -H 'Content-Type: application/json' -d @- \
          https://acme.edgekms.dev/v1/auth/actions/login | jq -r .auth.client_token)
      echo "::add-mask::$token"
      echo "VAULT_ADDR=https://acme.edgekms.dev" >> "$GITHUB_ENV"
      echo "VAULT_TOKEN=$token" >> "$GITHUB_ENV"
```

`-H @<(printf ...)` hands curl the header through a file descriptor, which keeps the request token
off curl's command line. The edgekms token lasts the role's `token_ttl_secs`, 15 minutes here.

`hashicorp/vault-action` does the same with `method: jwt`, `path: actions`, `role: deploy-main`
and `jwtGithubAudience: https://acme.edgekms.dev`.

Every later step sees `VAULT_ADDR` and `VAULT_TOKEN`, which is all [Pulumi](pulumi.md),
[SOPS](sops.md) and the `vault` CLI need.

## When a login is refused

A refusal is `400 permission denied` whatever the reason, so it doesn't say which roles exist.
Check, in order: the audience in the token request is exactly the URL in `bound_audiences`; the
ids are the repository's and its owner's, as strings; `ref` matches the event (`refs/heads/main`
for a push, `refs/pull/<n>/merge` for a pull request, `refs/tags/<tag>` for a tag); and the mount
name in the login path is the one in the config.
