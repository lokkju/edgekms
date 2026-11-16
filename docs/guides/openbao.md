# OpenBao auto-unseal

OpenBao's `seal "transit"` stanza unseals OpenBao with a Transit key on another server. Point it at
an edgekms tenant and an OpenBao that restarts unseals itself, with no one holding unseal shares
and no cloud KMS. OpenBao has edgekms encrypt the key that protects its storage once, at
initialization, and decrypt it at every start.

The seal holds a static token, so this guide mints a revocable token that can use one key and do
nothing else.

## 1. A key, a policy, and the right to mint tokens for it

Add a key for the seal and a policy that can encrypt and decrypt with it. A minted token can only
carry policies its minter holds, so the role you mint from (here the default `owner` role, which
also holds `admin` and so `token-create`) needs the seal policy as well:

```json
{
  "keys": {
    "openbao-seal": { "id": "k_c27f05e9a14d3b68", "latest_version": 1, "min_decryption_version": 1 }
  },
  "roles": {
    "owner": {
      "mount": "github-user",
      "github_user_ids": [1234567],
      "policies": ["admin", "default-all", "openbao-seal"],
      "token_ttl_secs": 3600
    }
  },
  "policies": {
    "openbao-seal": { "keys": { "openbao-seal": ["encrypt", "decrypt"] } }
  }
}
```

Keep your own GitHub id in `github_user_ids`; `edgekms tenant config get` shows it. The owner's
own tokens can then also encrypt and decrypt with the seal key, which is the cost of minting from
that role. A role made only for minting, with `admin` and `openbao-seal` and nothing else, avoids
it.

## 2. Mint the seal token

Log in to the tenant, then call `auth/token/create`:

```sh
export VAULT_ADDR=https://acme.edgekms.dev
export EDGEKMS_GITHUB_CLIENT_ID="$(curl -fsS https://api.edgekms.dev/v1/info | jq -r .github_client_id)"
export VAULT_TOKEN="$(edgekms login github --addr "$VAULT_ADDR" --role owner)"

curl -fsS -X POST "$VAULT_ADDR/v1/auth/token/create" \
  -H @<(printf 'X-Vault-Token: %s\n' "$VAULT_TOKEN") \
  -d '{"policies": ["openbao-seal"], "ttl": "8760h", "display_name": "openbao-seal"}' |
  jq '{token: .auth.client_token, accessor: .auth.accessor}'
```

Keep the accessor; it's how you revoke the token. A minted token never carries `admin`, whatever
its minter holds, so a stolen seal token can unseal that one OpenBao and do nothing else.

The longest TTL is 9600 hours (400 days). The token can't be renewed: OpenBao's seal calls
`renew-self` at startup, logs the error once and carries on, as it does for any non-renewable
token. Mint a new token and swap it into the config before the old one expires, or OpenBao won't
unseal after its next restart.

## 3. Configure the seal

```hcl
seal "transit" {
  address    = "https://acme.edgekms.dev"
  token      = "<the token above>"
  key_name   = "openbao-seal"
  mount_path = "transit/"
}
```

Initialize a new OpenBao with recovery keys instead of unseal keys
(`bao operator init -recovery-shares=1 -recovery-threshold=1`, or more shares as your policy
needs); an existing Shamir-sealed OpenBao moves to the transit seal with
`bao operator unseal -migrate`. From then on it unseals on every start.

## Revoking and rotating

To cut the seal off, revoke the token by its accessor. Every edge location refuses it within
about a minute, and OpenBao stays sealed at its next restart:

```sh
curl -fsS -X POST "$VAULT_ADDR/v1/auth/token/revoke-accessor" \
  -H @<(printf 'X-Vault-Token: %s\n' "$VAULT_TOKEN") \
  -d '{"accessor": "<accessor>"}'
```

A minted token carries its minter's role, so raising that role's `not_before` also invalidates
every seal token it minted; mint new ones afterwards.

Rotating `openbao-seal` (raising `latest_version`) is safe: what OpenBao stored stays decryptable
under its old version until you raise `min_decryption_version` past it. Don't raise it until
OpenBao has rewritten its sealed key under the new version.
