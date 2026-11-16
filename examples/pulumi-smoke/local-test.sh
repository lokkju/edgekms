#!/usr/bin/env bash
# Runs run.sh against a local `wrangler dev`, with the keys and policies of the single-tenant
# example (deploy/example/config.json) and a throwaway root key, so the pulumi-smoke policy and
# stack are proven before a deploy. Only the GitHub mount and the two smoke roles' bindings
# change, and the operator role (its SSH key is a placeholder) is dropped: the mount trusts the
# JWT test fixture's issuer and pinned JWKS, and the roles bind the fixture's audience and claims.
# Their policies stay as committed.
#
# Then it checks the token is limited to that key: encrypt on `smoke` must be refused.
#
# Needs the repo's mise toolchain (Rust, worker-build, wrangler, pulumi), jq, curl and openssl.
# Everything throwaway lives in a mktemp directory that the EXIT trap removes.
set -euo pipefail

root="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
worker_dir="$root/crates/edgekms-worker"
fixture="$root/crates/edgekms-core/tests/fixtures/jwt.json"
role=edgekms-pulumi-smoke

tmp="$(mktemp -d "${TMPDIR:-/tmp}/edgekms-pulumi-smoke-local.XXXXXX")"
chmod 700 "$tmp"
wrangler_pid=""
cleanup() {
  local rc=$?
  set +e
  if [ -n "$wrangler_pid" ]; then
    kill -TERM -- "-$wrangler_pid" 2>/dev/null
    for _ in $(seq 20); do kill -0 "$wrangler_pid" 2>/dev/null || break; sleep 0.25; done
    kill -KILL -- "-$wrangler_pid" 2>/dev/null
  fi
  rm -rf "$tmp"
  if [ "$rc" -eq 0 ]; then echo "local-test: PASS"; else echo "local-test: FAIL (exit $rc)" >&2; fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

die() {
  echo "FAIL: $*" >&2
  [ -s "$tmp/wrangler.log" ] && tail -40 "$tmp/wrangler.log" >&2
  exit 1
}

wrangler_bin="$(mise -C "$root" which wrangler)"
pulumi_bin="$(mise -C "$root" which pulumi)"

umask 077
jq -c --slurpfile fx "$fixture" '
  .mounts.github = {type: "jwt", issuer: $fx[0].issuer, jwks: $fx[0].jwks}
  | reduce ("edgekms-pulumi-smoke", "edgekms-smoke") as $r (.;
      .roles[$r].bound_audiences = ["https://kms.test"]
      | .roles[$r].bound_claims = {repository_id: "42", ref: "refs/heads/main"})
  | del(.roles.operator)
' "$root/deploy/example/config.json" >"$tmp/config.json"
{
  printf 'ROOT_KEY=%s\n' "$(head -c 32 /dev/urandom | base64 -w0)"
  printf "EDGEKMS_CONFIG='%s'\n" "$(cat "$tmp/config.json")"
} >"$tmp/worker.env"

port=""
for p in $(shuf -i 20000-40000 -n 100); do
  if ! (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then port="$p"; break; fi
done
[ -n "$port" ] || die "no free port"
addr="http://127.0.0.1:$port"

echo "==> wrangler dev on $addr"
(
  cd "$worker_dir"
  export WRANGLER_SEND_METRICS=false CI=1
  exec setsid mise exec -- "$wrangler_bin" dev --ip 127.0.0.1 --port "$port" \
    --env-file "$tmp/worker.env" --persist-to "$tmp/state" --log-level info
) >"$tmp/wrangler.log" 2>&1 &
wrangler_pid=$!
for i in $(seq 600); do
  curl -sf "$addr/v1/sys/health" >/dev/null 2>&1 && break
  kill -0 "$wrangler_pid" 2>/dev/null || die "wrangler dev exited"
  [ "$i" = 600 ] && die "wrangler dev did not answer in 300 s"
  sleep 0.5
done

jwt="$(jq -r .cases.valid_rs256 "$fixture")"
login() {
  jq -nc --arg r "$1" --arg j "$jwt" '{role: $r, jwt: $j}' |
    curl -fsS -X POST -H 'Content-Type: application/json' --data-binary @- \
      "$addr/v1/auth/github/login" | jq -r .auth.client_token
}
echo "==> JWT login as $role with the fixture token"
token="$(login "$role")"
[[ $token == ekms.* ]] || die "login returned no token"

echo "==> run.sh"
VAULT_ADDR="$addr" VAULT_TOKEN="$token" PULUMI="$pulumi_bin" "$root/examples/pulumi-smoke/run.sh" ||
  die "run.sh failed"

echo "==> the token is refused on the smoke key"
# The token reaches curl through a file descriptor, not its argv.
status="$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H @<(printf 'X-Vault-Token: %s\n' "$token") \
  -H 'Content-Type: application/json' -d '{"plaintext": "AA=="}' "$addr/v1/transit/encrypt/smoke")"
[ "$status" = 403 ] || die "encrypt on smoke with the pulumi-smoke token: want 403, got $status"
echo "    403 on transit/encrypt/smoke"

echo "==> run.sh with an edgekms-smoke token (no grant on pulumi-smoke) must fail"
other="$(login edgekms-smoke)"
[[ $other == ekms.* ]] || die "edgekms-smoke login returned no token"
if VAULT_ADDR="$addr" VAULT_TOKEN="$other" PULUMI="$pulumi_bin" \
  "$root/examples/pulumi-smoke/run.sh" >"$tmp/neg.log" 2>&1; then
  die "run.sh passed with a token that has no grant on pulumi-smoke"
fi
grep -q 'permission denied\|403' "$tmp/neg.log" || die "run.sh failed for another reason: $(tail -5 "$tmp/neg.log")"
echo "    stack init refused: edgekms denied the encrypt"
