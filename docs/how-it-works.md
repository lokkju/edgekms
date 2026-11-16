# How edgekms works

edgekms is a key management service that runs on Cloudflare Workers and speaks the part of
HashiCorp Vault's API that encryption clients use. It exists for one job: holding the keys that
wrap other keys (a Pulumi stack's data key, an OpenBao root key, a SOPS file's data key) without a
server to run, and without a long-lived credential stored in CI.

## Vault Transit, without Vault

Each tenant, `https://<tenant>.edgekms.dev`, answers Transit's encrypt, decrypt, rewrap and key
metadata calls, plus logins and token self-service. Clients that already speak Vault use it by
setting `VAULT_ADDR` and `VAULT_TOKEN`: Pulumi's `hashivault://` secrets provider, OpenBao's
`seal "transit"`, SOPS's `hc_vault_transit_uri`, the `vault` and `bao` CLIs, and
`hashicorp/vault-action`. Nothing is patched or forked.

Ciphertext is byte for byte Vault's `aes256-gcm96` format, `vault:v1:...`, so it moves between
edgekms, Vault and OpenBao in either direction. What edgekms doesn't implement (`context`,
convergent encryption, `batch_input`, `associated_data`) is refused with an error naming the
feature, never a silent success. The [API reference](api.md) lists every endpoint.

## Logins with no stored secret

A caller swaps a credential it already has for a short-lived edgekms token:

- a **GitHub Actions** job, its OIDC token, bound to a repository and branch by their numeric
  ids ([guide](guides/github-actions.md));
- a person at a terminal, an **SSH key** in ssh-agent (a FIDO key makes every login a touch), a
  **GitHub account** through the device flow, or any **OIDC provider** through a browser;
- a Kubernetes pod, its service-account token.

The tenant's config says which identities may log in on which mount, and which keys their token
may use. Everything is denied unless a policy grants it. Tokens last minutes to hours; the one
long-lived exception is a revocable token minted for an OpenBao seal.

## Tenants on the edge

Every tenant has its own root key, its own config of keys, mounts, roles and policies, and its
own origin. Your first GitHub sign-in once you're admitted, from the [console](console.md) or the
CLI, creates a personal tenant; you can create a few more and invite people to manage them. A config change takes effect
at every Cloudflare location within about 30 seconds, with no deploy.

Keys aren't stored. Each key version is derived from the tenant's root key and the key's random
id with HKDF, so a key costs nothing to keep and rotation is a config change.

## How the root key is kept

A tenant's root key is generated inside the Worker and stored in Cloudflare D1 only wrapped,
with AES-256-GCM, under a master key held in Cloudflare Secrets Store. The wrap is bound to the
tenant, so a wrapped root copied to another tenant doesn't unwrap. Inside the Worker every key is
a non-extractable WebCrypto key, outside the WebAssembly module's memory. Each config carries a
MAC under the tenant's own root, and each membership one under the control plane's, so someone
who could write to the database still couldn't add themselves to a tenant or rewrite its roles.
The [security model](security-model.md) goes through what each kind of compromise would and
wouldn't reach.

Every encrypt, decrypt, login and token call writes an audit event to R2 before it returns; if the
event can't be written, the call fails. Plaintext, ciphertext and tokens are never logged.

## You can always leave

An owner can export a tenant's root key at any time, including while the tenant is suspended.
With the root key and the tenant's config:

- `edgekms decrypt` decrypts any of the tenant's ciphertext on your own machine, with no network;
- `edgekms export` prints a key version's raw bytes for OpenBao's or Vault's BYOK import, so
  existing ciphertext keeps working there;
- a [self-hosted](self-hosting.md) edgekms Worker in your own Cloudflare account serves the same
  keys, with every ciphertext and token still valid.

The CLI and the Worker are both published in the
[edgekms repository](https://github.com/lokkju/edgekms), and the CLI's offline commands need
nothing from the service. The [quickstart](hosted-quickstart.md#7-export-you-can-always-leave) shows the
export.

## Who it's for

Small teams and homelabs that want Pulumi, SOPS or OpenBao keys held somewhere other than CI and
a laptop, and don't want to run Vault for it. `edgekms.dev` is invite-only for now; the
[quickstart](hosted-quickstart.md) starts with asking for an invite.
