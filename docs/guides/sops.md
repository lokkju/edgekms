# SOPS

SOPS encrypts the values in a YAML, JSON, ENV or INI file and wraps its data key with one or more
key services, Vault Transit among them. With an edgekms tenant as the Transit server, a team can
keep secrets files in git and decrypt them with an edgekms token, in a terminal or in CI.

## 1. A key and a policy

The default config's `default` key works for a first try. For real use, give SOPS its own key, and
a policy for each kind of caller: people who write secrets need `encrypt` and `decrypt`, and a CI
job that only reads them needs `decrypt` alone.

```json
{
  "keys": {
    "sops": { "id": "k_51e8a3d0b7c24f96", "latest_version": 1, "min_decryption_version": 1 }
  },
  "policies": {
    "sops-edit": { "keys": { "sops": ["encrypt", "decrypt"] } },
    "sops-read": { "keys": { "sops": ["decrypt"] } }
  }
}
```

Grant `sops-edit` to the roles your team logs in with and `sops-read` to a
[GitHub Actions role](github-actions.md).

## 2. Point SOPS at the key

A `.sops.yaml` at the top of the repository makes every `sops encrypt` below it use the key:

```yaml
creation_rules:
  - path_regex: \.sops\.ya?ml$
    hc_vault_transit_uri: https://acme.edgekms.dev/v1/transit/keys/sops
```

The URI is the tenant's address, `/v1/`, the Transit mount (`transit`), `keys`, and the key name.
For a one-off file, `--hc-vault-transit` takes the same URI.

## 3. Encrypt and decrypt

SOPS reads the token from `VAULT_TOKEN`. Log in to the tenant (`edgekms login`, or the
[GitHub Actions](github-actions.md#3-log-in-from-the-workflow) step in CI), then:

```sh
sops encrypt secrets.yaml > secrets.sops.yaml
sops decrypt secrets.sops.yaml
sops edit secrets.sops.yaml
```

The encrypted file records the URI, so decrypting needs only the token. Its `sops.hc_vault`
section holds the data key as a `vault:v1:` ciphertext; the values are encrypted under that data
key with AES-GCM by SOPS itself, and edgekms only ever sees the data key.

A file can name more than one key service, an age recipient beside edgekms say, so that it still
decrypts if edgekms isn't reachable. `sops updatekeys` adds one to existing files after you change
`.sops.yaml`.

## Rotating the key

Raising the key's `latest_version` makes new files use the new version; existing files keep
decrypting until `min_decryption_version` passes their version. `sops rotate --in-place` gives a
file a fresh data key wrapped under the latest version.
