# Pulumi

Pulumi's `hashivault://` secrets provider wraps a stack's data key under a Vault Transit key. Point
it at an edgekms tenant and the stack's secrets are encrypted with a key that lives in edgekms,
with no passphrase to share and no Pulumi Cloud account needed. Pulumi decrypts the data key once
per command, so a `preview` or an `up` costs one decrypt.

## 1. A key and a policy

The default config already has a key, `default`, and your `owner` role can use it, which is
enough to try this. For a real stack, give it its own key and a policy that can encrypt and
decrypt with it (`edgekms tenant config get`, edit, `edgekms tenant config set`, or the console's
**Keys** and **Policies** tabs):

```json
{
  "keys": {
    "pulumi-infra": { "id": "k_9d41c07a2e6b3f58", "latest_version": 1, "min_decryption_version": 1 }
  },
  "policies": {
    "pulumi-infra": { "keys": { "pulumi-infra": ["encrypt", "decrypt"] } }
  }
}
```

Then grant the policy to whoever runs Pulumi: your own role for a laptop, and a
[GitHub Actions role](github-actions.md) for CI.

## 2. Log in

Pulumi reads `VAULT_ADDR` and `VAULT_TOKEN` like any Vault client. From a terminal:

```sh
export VAULT_ADDR=https://acme.edgekms.dev
export EDGEKMS_GITHUB_CLIENT_ID="$(curl -fsS https://api.edgekms.dev/v1/info | jq -r .github_client_id)"
export VAULT_TOKEN="$(edgekms login github --addr "$VAULT_ADDR" --role owner)"
```

In a workflow, the [GitHub Actions](github-actions.md#3-log-in-from-the-workflow) login step sets
both.

## 3. Use the key for a stack

A new stack:

```sh
pulumi stack init prod --secrets-provider hashivault://pulumi-infra
```

An existing stack, moved off its passphrase or Pulumi Cloud encryption:

```sh
pulumi stack change-secrets-provider hashivault://pulumi-infra
```

The stack file then holds `secretsprovider: hashivault://pulumi-infra` and an `encryptedkey`,
the data key as a `vault:v1:` ciphertext (base64-encoded by Pulumi). Secrets you set with
`pulumi config set --secret` are encrypted under that data key, as before. Commit the stack file;
the ciphertext is safe to keep in git, and nothing decrypts it without a token that can use the key.

## Rotation and leaving

Rotating `pulumi-infra` (the console's **Rotate**, or raising `latest_version`) changes nothing
for existing stacks: their data key stays decryptable under its old version until you raise the
key's `min_decryption_version` past it. The stack keeps working through an export, too: with the
tenant's root key and config, `edgekms decrypt` unwraps the data key offline, and
`edgekms export` hands the key version to OpenBao's BYOK import, so the same stack file works
against an OpenBao Transit engine. The [security model](../security-model.md#exit-and-break-glass)
has the details.
