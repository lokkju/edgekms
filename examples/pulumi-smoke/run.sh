#!/usr/bin/env bash
# Creates the pulumi-smoke stack from nothing, runs it once and throws it away.
#
# The stack lives in a mktemp directory with a local file backend (no Pulumi Cloud) and the
# hashivault secrets provider, so `stack init` wraps a fresh data key under the Transit key and
# every later command unwraps it through VAULT_ADDR. The config secret is `<nonce>.<random>`,
# made here; the program exports the nonce part as a plain output, and the run passes only if it
# comes back, which needs a working decrypt. Nothing is written into the repo, and neither the
# random part nor the token is printed.
#
# Needs VAULT_ADDR and VAULT_TOKEN (a token whose policy grants encrypt and decrypt on the key),
# pulumi (or PULUMI), openssl and base64. SMOKE_KEY names the Transit key (default
# pulumi-smoke).
set -euo pipefail

: "${VAULT_ADDR:?set VAULT_ADDR}"
: "${VAULT_TOKEN:?set VAULT_TOKEN}"
key="${SMOKE_KEY:-pulumi-smoke}"
pulumi="${PULUMI:-$(command -v pulumi || true)}"
[ -x "$pulumi" ] || { echo "pulumi not found (set PULUMI)" >&2; exit 1; }
here="$(cd "$(dirname "$0")" && pwd)"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/edgekms-pulumi-smoke.XXXXXX")"
chmod 700 "$tmp"
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/project" "$tmp/state" "$tmp/home"
cp "$here/Pulumi.yaml" "$tmp/project/"

p() {
  env -u PULUMI_CONFIG_PASSPHRASE -u PULUMI_CONFIG_PASSPHRASE_FILE -u PULUMI_ACCESS_TOKEN \
    PULUMI_HOME="$tmp/home" PULUMI_BACKEND_URL="file://$tmp/state" \
    PULUMI_SKIP_UPDATE_CHECK=true PULUMI_DIY_BACKEND_NO_LEGACY_WARNING=true \
    "$pulumi" --cwd "$tmp/project" --non-interactive "$@"
}

echo "pulumi $("$pulumi" version), Transit key $key at $VAULT_ADDR"

p stack init smoke --secrets-provider "hashivault://$key" >/dev/null
stack_file="$tmp/project/Pulumi.smoke.yaml"
# Pulumi stores the provider's output base64-encoded; inside is the Transit ciphertext.
wrapped="$(sed -n 's/^encryptedkey: *//p' "$stack_file" | base64 -d 2>/dev/null || true)"
[[ $wrapped == vault:v* ]] || { echo "encryptedkey is not a Transit ciphertext" >&2; exit 1; }
echo "stack initialised; data key wrapped as ${wrapped%%:*}:$(cut -d: -f2 <<<"$wrapped"):..."

nonce="$(openssl rand -hex 8)"
secret="$nonce.$(openssl rand -hex 24)"
# Through stdin, so the value is never in argv.
printf '%s' "$secret" | p config set --secret smokeSecret >/dev/null
if grep -qF "$secret" "$stack_file"; then
  echo "the stack file holds the secret in plaintext" >&2
  exit 1
fi
echo "config secret set (encrypted in the stack file)"

p up --yes --skip-preview --suppress-progress >/dev/null
got="$(p stack output smokeNonce)"
if [ "$got" != "$nonce" ]; then
  echo "smokeNonce doesn't match the nonce in the config secret" >&2
  exit 1
fi
echo "pulumi up decrypted the config secret: smokeNonce = $got"

p stack rm --yes --force smoke >/dev/null
echo "pulumi-smoke OK"
