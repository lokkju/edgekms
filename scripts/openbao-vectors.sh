#!/usr/bin/env bash
# Regenerates crates/edgekms-core/tests/vectors/openbao.json from a throwaway OpenBao dev
# server: an exportable aes256-gcm96 Transit key at version 2, OpenBao's ciphertexts for a
# few plaintexts under each version, and the exported raw key versions. It also checks the
# other direction: OpenBao decrypts ciphertext edgekms writes under each exported version.
set -euo pipefail
image="${OPENBAO_IMAGE:-quay.io/openbao/openbao:2}"
out="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)/crates/edgekms-core/tests/vectors/openbao.json"
name="edgekms-vectors-$$"
docker run --rm -d --name "$name" -p 127.0.0.1::8200 -e BAO_DEV_ROOT_TOKEN_ID=root "$image" server -dev >/dev/null
trap 'docker rm -f "$name" >/dev/null' EXIT
port="$(docker port "$name" 8200/tcp | head -1 | cut -d: -f2)"
addr="http://127.0.0.1:$port"
bao() { curl -sf -H 'X-Vault-Token: root' -X "$1" "$addr/v1/$2" ${3:+-d "$3"}; }
for _ in $(seq 30); do curl -sf "$addr/v1/sys/health" >/dev/null && break; sleep 1; done
bao POST sys/mounts/transit '{"type":"transit"}' >/dev/null
bao POST transit/keys/vec '{"type":"aes256-gcm96","exportable":true}' >/dev/null
version="$(bao GET transit/openbao-version 2>/dev/null || docker exec "$name" bao version)"
cases='[]'
for v in 1 2; do
  [ "$v" = 2 ] && bao POST transit/keys/vec/rotate >/dev/null
  for pt in "" "a" "edgekms" "$(head -c 32 /dev/urandom | base64 -w0)"; do
    b64="$(printf %s "$pt" | base64 -w0)"
    ct="$(bao POST transit/encrypt/vec "{\"plaintext\":\"$b64\"}" | jq -r .data.ciphertext)"
    cases="$(jq -c --arg p "$b64" --arg c "$ct" '. + [{plaintext: $p, ciphertext: $c}]' <<<"$cases")"
  done
done
keys="$(bao GET transit/export/encryption-key/vec | jq -c .data.keys)"
# The other direction: OpenBao must decrypt what edgekms writes under each exported version.
root="$(dirname "$out")/../../../.."
for v in 1 2; do
  b64key="$(jq -r --arg v "$v" '.[$v]' <<<"$keys")"
  pt="$(head -c 48 /dev/urandom | base64 -w0)"
  ct="$(printf %s "$pt" | base64 -d | cargo run -q --manifest-path "$root/Cargo.toml" -p edgekms-core --example vault_encrypt -- "$b64key" "$v")"
  back="$(bao POST transit/decrypt/vec "{\"ciphertext\":\"$ct\"}" | jq -r .data.plaintext)"
  [ "$back" = "$pt" ] || { echo "OpenBao failed to decrypt edgekms v$v ciphertext" >&2; exit 1; }
  echo "OpenBao decrypted edgekms ciphertext under v$v"
done
jq -n --arg v "$version" --argjson k "$keys" --argjson c "$cases" \
  '{generator: $v, keys: $k, cases: $c}' >"$out"
echo "wrote $out"
