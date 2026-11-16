#!/usr/bin/env bash
# End-to-end run of edgekms under `wrangler dev` against real clients: the CLI's SSH login, a
# JWT login, Pulumi's unmodified hashivault:// secrets provider, and an unmodified OpenBao that
# auto-unseals through `seal "transit"`, then seal-token revocation and the audit log.
#
# Everything throwaway (root key, SSH key, Pulumi state, OpenBao storage, wrangler's local
# state) lives in a mktemp directory outside the repo, or in a Docker volume, and the EXIT trap
# removes it all. Needs: mise (the repo's Rust toolchain and worker-build), wrangler, Docker,
# the OpenBao image, Pulumi (the version .mise/config.toml pins, unless PULUMI is set), jq,
# curl, ssh-keygen and ssh-agent.
#
# Step 9, the FIDO login, needs a hardware key touch, so a plain run only prints the command
# for it: `scripts/e2e.sh --fido ~/.ssh/id_ed25519_sk.pub` adds that key to the op role and
# logs in with it through your own ssh-agent at the end.
set -euo pipefail

fido_key=""
case "${1:-}" in
  "") ;;
  --fido) fido_key="${2:?--fido needs the public key file}"; [ -r "$fido_key" ] || {
    echo "cannot read $fido_key" >&2; exit 2; } ;;
  *) echo "usage: $0 [--fido <key.pub>]" >&2; exit 2 ;;
esac

root="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
worker_dir="$root/crates/edgekms-worker"
fixture="$root/crates/edgekms-core/tests/fixtures/jwt.json"
image="${OPENBAO_IMAGE:-quay.io/openbao/openbao:2}"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/edgekms-e2e.XXXXXX")"
chmod 700 "$tmp"
# An AF_UNIX path is at most 107 bytes; under a long TMPDIR the agent socket goes in a short
# directory of its own.
sock_dir="$tmp"
if [ "${#tmp}" -gt 80 ]; then
  sock_dir="$(mktemp -d /tmp/ekms.XXXXXX)"
  chmod 700 "$sock_dir"
fi
bao_name="edgekms-e2e-bao-$$"
bao_vol="edgekms-e2e-bao-$$"
wrangler_pid=""
agent_pid=""

cleanup() {
  local rc=$?
  set +e
  if [ -n "$wrangler_pid" ]; then
    # wrangler runs in its own session; take workerd and esbuild down with it.
    kill -TERM -- "-$wrangler_pid" 2>/dev/null
    for _ in $(seq 20); do kill -0 "$wrangler_pid" 2>/dev/null || break; sleep 0.25; done
    kill -KILL -- "-$wrangler_pid" 2>/dev/null
  fi
  docker rm -f "$bao_name" >/dev/null 2>&1
  docker volume rm -f "$bao_vol" >/dev/null 2>&1
  [ -n "$agent_pid" ] && kill "$agent_pid" 2>/dev/null
  [ "$sock_dir" != "$tmp" ] && rm -rf "$sock_dir"
  rm -rf "$tmp"
  if [ "$rc" -eq 0 ]; then echo "e2e: PASS"; else echo "e2e: FAIL (exit $rc)" >&2; fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# Lines of wrangler.log written before the current step began; `die` shows only what came after.
log_mark=0
step() {
  printf '\n==> %s\n' "$*"
  log_mark=0
  if [ -f "$tmp/wrangler.log" ]; then log_mark="$(wc -l <"$tmp/wrangler.log")"; fi
}
ok() { printf '    ok: %s\n' "$*"; }
die() {
  printf '    FAIL: %s\n' "$*" >&2
  if [ -n "$wrangler_pid" ] && [ -s "$tmp/wrangler.log" ]; then
    tail -n "+$((log_mark + 1))" "$tmp/wrangler.log" | tail -40 >"$tmp/wrangler.tail"
    if [ -s "$tmp/wrangler.tail" ]; then
      echo "---- wrangler dev output during this step (at most 40 lines) ----" >&2
      cat "$tmp/wrangler.tail" >&2
    fi
  fi
  exit 1
}

# api METHOD PATH TOKEN [BODY]: response body to $tmp/resp, status to $status. The token goes
# to curl in a header file and the body on stdin, so neither is in curl's argv.
status=""
api() {
  local args=(-s -o "$tmp/resp" -w '%{http_code}' -X "$1" "$addr/v1/$2")
  if [ -n "$3" ]; then
    printf 'X-Vault-Token: %s\n' "$3" >"$tmp/token.header"
    args+=(-H "@$tmp/token.header")
  fi
  [ -n "${4:-}" ] && args+=(-H 'Content-Type: application/json' --data-binary @-)
  status="$(printf '%s' "${4:-}" | curl "${args[@]}")"
  rm -f "$tmp/token.header"
}

# Every audit event so far, one JSON object per line in $tmp/audit.jsonl. Miniflare keeps each
# R2 object body as a file under <persist>/v3/r2/<bucket>/blobs/; the Worker writes the event
# before it answers, so a request's event is there once its response is.
audit_load() {
  : >"$tmp/audit.jsonl"
  [ -d "$tmp/state/v3/r2" ] || return 0
  find "$tmp/state/v3/r2" -mindepth 3 -maxdepth 3 -path "$tmp/state/v3/r2/*/blobs/*" -type f \
    -exec cat {} + | jq -c . >"$tmp/audit.jsonl" || die "an audit object is not JSON"
}
count() { jq -s "[.[] | select($1)] | length" "$tmp/audit.jsonl"; }

# free_port [TAKEN...]: a port nothing on 127.0.0.1 answers on, other than the ones given.
free_port() {
  local p
  for p in $(shuf -i 20000-40000 -n 100); do
    [[ " $* " == *" $p "* ]] && continue
    if ! (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then echo "$p"; return; fi
  done
  die "no free port"
}

for tool in mise wrangler docker jq curl ssh-keygen ssh-agent ssh-add shuf; do
  command -v "$tool" >/dev/null || die "$tool not on PATH"
done
wrangler_bin="$(command -v wrangler)" # resolved here: the repo's mise config pins no wrangler
pulumi="${PULUMI:-$(mise -C "$root" which pulumi 2>/dev/null || command -v pulumi || true)}"
[ -x "$pulumi" ] || die "pulumi not found (run mise install, or set PULUMI)"
docker image inspect "$image" >/dev/null 2>&1 || die "OpenBao image $image is not pulled"

# Sweep containers and volumes an earlier run left behind (SIGKILL skips the trap). Each is
# labelled with its run's pid; only those whose run is gone are removed, so a concurrent run
# keeps its own. A bare `kill -0` would call another user's live run gone (EPERM), so EPERM
# counts as alive, as does a visible /proc entry; a malformed label is left alone.
pid_alive() {
  local err
  [ -d "/proc/$1" ] && return 0
  err="$(LC_ALL=C kill -0 "$1" 2>&1)" && return 0
  [[ "$err" == *"not permitted"* ]]
}
for kind in container volume; do
  if [ "$kind" = container ]; then
    docker ps -a --filter label=edgekms.e2e.pid --format '{{.Label "edgekms.e2e.pid"}} {{.Names}}'
  else
    docker volume ls --filter label=edgekms.e2e.pid --format '{{.Label "edgekms.e2e.pid"}} {{.Name}}'
  fi >"$tmp/sweep" 2>/dev/null || true
  while read -r pid name; do
    [ -n "$name" ] && [[ "$pid" =~ ^[1-9][0-9]*$ ]] && ! pid_alive "$pid" || continue
    docker "$kind" rm -f "$name" >/dev/null 2>&1 && echo "    swept stale $kind $name"
  done <"$tmp/sweep"
done

# ---------------------------------------------------------------------------------------------
step "1. throwaway root key, SSH key in a private ssh-agent, and the instance config"
umask 077
ssh-keygen -q -t ed25519 -N '' -C edgekms-e2e -f "$tmp/id_e2e"
operator_sock="${SSH_AUTH_SOCK:-}"
eval "$(ssh-agent -s -a "$sock_dir/agent.sock")" >/dev/null
agent_pid="$SSH_AGENT_PID"
ssh-add -q "$tmp/id_e2e"
ok "ssh-agent at $SSH_AUTH_SOCK holds $(ssh-keygen -lf "$tmp/id_e2e.pub" | cut -d' ' -f2)"

root_key="$(head -c 32 /dev/urandom | base64 -w0)"
jwt="$(jq -r .cases.valid_rs256 "$fixture")"
ssh_keys="$(cat "$tmp/id_e2e.pub" ${fido_key:+"$fido_key"} | jq -R . | jq -sc .)"
jq -c --slurpfile fx "$fixture" --argjson ssh "$ssh_keys" '
  .mounts.jwt.jwks = $fx[0].jwks | .roles.op.ssh_keys = $ssh
' "$root/scripts/e2e/config.json" >"$tmp/config.json"
# wrangler reads both bindings from this file, so neither the root key nor the config is in
# argv or in the repo.
{
  printf 'ROOT_KEY=%s\n' "$root_key"
  printf "EDGEKMS_CONFIG='%s'\n" "$(cat "$tmp/config.json")"
} >"$tmp/worker.env"
ok "config: $(jq -c '{keys: (.keys|keys), mounts: (.mounts|keys), roles: (.roles|keys)}' "$tmp/config.json")"

step "   building the CLI"
mise -C "$root" exec -- cargo build -q -p edgekms-cli
edgekms="$root/target/debug/edgekms"
[ -x "$edgekms" ] || die "CLI binary missing at $edgekms"
ok "$("$edgekms" --version)"

# ---------------------------------------------------------------------------------------------
port="$(free_port)"
addr="http://127.0.0.1:$port"
step "2. wrangler dev on 127.0.0.1:$port (OpenBao shares the host network to reach it)"
(
  cd "$worker_dir"
  export WRANGLER_SEND_METRICS=false CI=1
  exec setsid mise exec -- "$wrangler_bin" dev --ip 127.0.0.1 --port "$port" \
    --env-file "$tmp/worker.env" --persist-to "$tmp/state" --log-level info
) >"$tmp/wrangler.log" 2>&1 &
wrangler_pid=$!
for i in $(seq 600); do
  if curl -sf "$addr/v1/sys/health" >"$tmp/resp" 2>/dev/null; then break; fi
  kill -0 "$wrangler_pid" 2>/dev/null || die "wrangler dev exited"
  [ "$i" = 600 ] && die "wrangler dev did not answer /v1/sys/health in 300 s"
  sleep 0.5
done
[ "$(jq -r .sealed "$tmp/resp")" = false ] || die "health: $(cat "$tmp/resp")"
ok "health: $(jq -c . "$tmp/resp")"

# ---------------------------------------------------------------------------------------------
step "3. SSH login through the CLI (role op)"
# The op role's tokens last 900 s and steps 5 to 7 can take minutes, so each admin step logs in
# afresh. Every token minted goes in admin_tokens for the leak check in step 8.
admin_tokens=()
admin_login() {
  admin_token="$("$edgekms" login ssh --addr "$addr" --role op --key "$tmp/id_e2e.pub")" ||
    die "edgekms login ssh failed"
  [[ "$admin_token" == ekms.* ]] || die "login ssh printed something other than a token"
  admin_tokens+=("$admin_token")
}
admin_login
api GET auth/token/lookup-self "$admin_token"
[ "$status" = 200 ] || die "lookup-self as op: $status $(cat "$tmp/resp")"
[ "$(jq -c '.data.policies|sort' "$tmp/resp")" = '["admin","seal"]' ] ||
  die "op token policies: $(jq -c .data.policies "$tmp/resp")"
ok "admin token, policies $(jq -c .data.policies "$tmp/resp"), ttl $(jq .data.ttl "$tmp/resp")"

# ---------------------------------------------------------------------------------------------
step "4. JWT login with the fixture valid_rs256 token (role ci)"
api POST auth/jwt/login "" "$(jq -nc --arg j "$jwt" '{role: "ci", jwt: $j}')"
[ "$status" = 200 ] || die "jwt login: $status $(cat "$tmp/resp")"
ci_token="$(jq -r .auth.client_token "$tmp/resp")"
[[ "$ci_token" == ekms.* ]] || die "jwt login returned no token"
[ "$(jq -c .auth.policies "$tmp/resp")" = '["pulumi"]' ] ||
  die "ci token policies: $(jq -c .auth.policies "$tmp/resp")"
ok "ci token, policies [\"pulumi\"], lease $(jq .auth.lease_duration "$tmp/resp") s"

api POST auth/jwt/login "" "$(jq -nc --arg j "$jwt" '{role: "op", jwt: $j}')"
[ "$status" = 400 ] && [ "$(jq -r '.errors[0]' "$tmp/resp")" = "permission denied" ] ||
  die "jwt login with an SSH role: want 400 permission denied, got $status $(cat "$tmp/resp")"
ok "an SSH role on the JWT mount is refused (400 permission denied)"

step "4b. fetched JWKS: GitHub's real JWKS does not know the fixture's kid"
# The probe only tells whether this host reaches GitHub; it proves nothing about workerd's own
# fetch. The audit code does: with no cached set (fresh isolate), a failed fetch is a 500
# audited as jwks_unavailable, while jwt_unknown_kid needs a JWKS that was fetched and parsed.
# The unknown kid then forces a refetch, and the Worker logs that line only when the refetch
# succeeded (a failed one falls back to the cached set, so the audit can't tell them apart).
if curl -sf -m 10 -o /dev/null https://token.actions.githubusercontent.com/.well-known/jwks; then
  github_unknown_kid='.op == "login" and .mount == "github" and .result == "denied" and .error == "jwt_unknown_kid"'
  forced_refetch_log="edgekms: JWKS refetched for an unknown kid"
  audit_load
  unknown_kid_before="$(count "$github_unknown_kid")"
  api POST auth/github/login "" "$(jq -nc --arg j "$jwt" '{role: "gh", jwt: $j}')"
  [ "$status" = 400 ] && [ "$(jq -r '.errors[0]' "$tmp/resp")" = "permission denied" ] ||
    die "github mount login: want 400 permission denied, got $status $(cat "$tmp/resp")"
  audit_load
  # One login, one event: compared with the count before it, not with a fixed total.
  [ "$(count "$github_unknown_kid")" -eq $((unknown_kid_before + 1)) ] ||
    die "github login audit: $(jq -c 'select(.mount == "github")' "$tmp/audit.jsonl")"
  ok "400 permission denied, audited as jwt_unknown_kid: the Worker fetched GitHub's JWKS"
  # wrangler may print the Worker's log line a moment after the response.
  refetch_logged=0
  for _ in $(seq 20); do
    if tail -n "+$((log_mark + 1))" "$tmp/wrangler.log" | grep -qF "$forced_refetch_log"; then
      refetch_logged=1
      break
    fi
    sleep 0.25
  done
  [ "$refetch_logged" = 1 ] || die "no \"$forced_refetch_log\" line in wrangler's output"
  ok "the unknown kid forced a second fetch of GitHub's JWKS, and it succeeded"
  fetched_jwks=1
else
  echo "    NOTICE: no route to token.actions.githubusercontent.com; skipping the fetched-JWKS check"
  fetched_jwks=0
fi

# ---------------------------------------------------------------------------------------------
step "5. Pulumi hashivault:// secrets provider with the ci token"
secret="e2e-$(head -c 18 /dev/urandom | base64 -w0 | tr '+/' '-_')"
mkdir -p "$tmp/pulumi/project" "$tmp/pulumi/state" "$tmp/pulumi/home"
cat >"$tmp/pulumi/project/Pulumi.yaml" <<'EOF'
name: edgekms-e2e
runtime: yaml
description: edgekms end-to-end secrets provider check
EOF
# VAULT_TOKEN is a prefix assignment, so it reaches env(1) in its environment, not its argv.
pulumi_run() {
  VAULT_ADDR="$addr" VAULT_TOKEN="$ci_token" \
    env -u PULUMI_CONFIG_PASSPHRASE -u PULUMI_CONFIG_PASSPHRASE_FILE -u PULUMI_ACCESS_TOKEN \
    PULUMI_HOME="$tmp/pulumi/home" PULUMI_BACKEND_URL="file://$tmp/pulumi/state" \
    PULUMI_SKIP_UPDATE_CHECK=true PULUMI_DIY_BACKEND_NO_LEGACY_WARNING=true \
    "$pulumi" --cwd "$tmp/pulumi/project" --non-interactive "$@"
}
pulumi_run stack init e2e --secrets-provider hashivault://pulumi >/dev/null ||
  die "pulumi stack init"
ok "stack e2e initialised with hashivault://pulumi"
# The value on stdin, not in argv.
printf '%s' "$secret" | pulumi_run config set --secret x || die "pulumi config set --secret"
got="$(pulumi_run config get x)" || die "pulumi config get"
[ "$got" = "$secret" ] || die "pulumi config get x returned a different value"
ok "config get x round-trips the secret in a fresh process"
stack_file="$tmp/pulumi/project/Pulumi.e2e.yaml"
grep -qF "$secret" "$stack_file" && die "the stack file holds the secret in plaintext"
# Pulumi stores the keeper's output base64-encoded; inside is the Transit ciphertext.
wrapped="$(sed -n 's/^encryptedkey: *//p' "$stack_file" | base64 -d 2>/dev/null || true)"
[[ "$wrapped" == vault:v1:* ]] || die "Pulumi.e2e.yaml's encryptedkey is not base64 of vault:v1:..."
ok "encryptedkey is an edgekms ciphertext (${wrapped:0:16}...)"
# Proves the Worker ran on this run's root key (not one from a stray .dev.vars) and that the
# break-glass path opens what the Worker wrote.
# The plaintext is Pulumi's data key, the one secret here that edgekms itself handles; step 8
# looks for it in the audit log and the local state.
data_key_b64="$(printf '%s' "$root_key" | "$edgekms" decrypt --config "$tmp/config.json" \
  --key pulumi "$wrapped")" || die "edgekms decrypt (offline, this run's root key) cannot open the encryptedkey"
data_key_hex="$(printf '%s' "$data_key_b64" | base64 -d | od -An -v -tx1 | tr -d ' \n')"
[ "${#data_key_hex}" -ge 32 ] || die "the data key is shorter than 16 bytes"
ok "offline edgekms decrypt with this run's root key opens it ($(( ${#data_key_hex} / 2 ))-byte data key)"

# ---------------------------------------------------------------------------------------------
step "6. OpenBao auto-unseal through seal \"transit\""
admin_login
api POST auth/token/create "$admin_token" \
  '{"policies": ["seal"], "ttl": "8760h", "display_name": "e2e-openbao-seal"}'
[ "$status" = 200 ] || die "token create: $status $(cat "$tmp/resp")"
seal_token="$(jq -r .auth.client_token "$tmp/resp")"
seal_accessor="$(jq -r .auth.accessor "$tmp/resp")"
[ "$(jq .auth.lease_duration "$tmp/resp")" = 31536000 ] || die "seal token lease is not 8760h"
ok "seal token minted, accessor $seal_accessor"
api POST auth/token/create "$admin_token" '{"policies": ["admin"], "ttl": "8760h"}'
[ "$status" = 400 ] || die "token create granted an admin policy: $status"
ok "token create refuses to grant the admin policy (400)"

# OpenBao runs on the host network, so it reaches wrangler on 127.0.0.1 and its own listeners
# stay on loopback, on ports picked like wrangler's.
bao_port="$(free_port "$port")"
bao_cluster_port="$(free_port "$port" "$bao_port")"
# Filled in with bash substitution, not sed, so the seal token is in no process's argv. Quoted
# replacements stay literal under bash 5.2's patsub_replacement.
hcl="$(<"$root/scripts/e2e/openbao.hcl")"
hcl="${hcl//@EDGEKMS_ADDR@/"$addr"}"
hcl="${hcl//@BAO_PORT@/"$bao_port"}"
hcl="${hcl//@BAO_CLUSTER_PORT@/"$bao_cluster_port"}"
hcl="${hcl//@SEAL_TOKEN@/"$seal_token"}"
printf '%s\n' "$hcl" >"$tmp/openbao.hcl"
unset hcl
chmod 644 "$tmp/openbao.hcl" # read by the container's openbao user; $tmp itself stays 0700
docker volume create --label "edgekms.e2e.pid=$$" "$bao_vol" >/dev/null
docker run -d --name "$bao_name" --label "edgekms.e2e.pid=$$" --network host \
  -v "$bao_vol:/openbao/file" -v "$tmp/openbao.hcl:/openbao/config/e2e.hcl:ro" \
  "$image" server >/dev/null # the entrypoint adds -config=/openbao/config
bao() { docker exec -e "BAO_ADDR=http://127.0.0.1:$bao_port" "$bao_name" bao "$@"; }
# bao status: 0 unsealed, 2 sealed, 1 error. Echoes the JSON when it answers.
bao_status() { bao status -format=json 2>/dev/null; }
wait_answering() {
  for _ in $(seq 60); do
    local rc=0
    bao_status >"$tmp/bao-status" || rc=$?
    [ "$rc" = 0 ] || [ "$rc" = 2 ] && return 0
    [ "$(docker inspect -f '{{.State.Running}}' "$bao_name")" = true ] ||
      die "OpenBao exited: $(docker logs --tail 20 "$bao_name" 2>&1)"
    sleep 1
  done
  die "OpenBao did not answer in 60 s: $(docker logs --tail 20 "$bao_name" 2>&1)"
}
wait_answering
bao operator init -recovery-shares=1 -recovery-threshold=1 -format=json >"$tmp/bao-init.json" ||
  die "bao operator init: $(docker logs --tail 20 "$bao_name" 2>&1)"
[ "$(jq '.recovery_keys_b64|length' "$tmp/bao-init.json")" = 1 ] || die "init gave no recovery key"
ok "initialised with 1 recovery share"
unsealed_within() {
  for _ in $(seq "$1"); do
    bao_status >"$tmp/bao-status" && [ "$(jq -r .sealed "$tmp/bao-status")" = false ] && return 0
    sleep 1
  done
  return 1
}
unsealed_within 30 || die "not unsealed after init: $(cat "$tmp/bao-status")"
ok "unsealed after init"
docker restart "$bao_name" >/dev/null
wait_answering
unsealed_within 30 || die "still sealed after restart: $(docker logs --tail 20 "$bao_name" 2>&1)"
ok "restarted: $(jq -c '{type, sealed, initialized}' "$tmp/bao-status") with no unseal command"

# ---------------------------------------------------------------------------------------------
step "7. revoke the seal token; OpenBao stays sealed after a restart"
admin_login
api POST auth/token/revoke-accessor "$admin_token" "$(jq -nc --arg a "$seal_accessor" '{accessor: $a}')"
[ "$status" = 204 ] || die "revoke-accessor: $status $(cat "$tmp/resp")"
ok "revoke-accessor 204"
api POST transit/encrypt/seal "$seal_token" '{"plaintext": "AA=="}'
[ "$status" = 403 ] || die "revoked seal token still encrypts: $status"
ok "the revoked seal token gets 403 on transit/encrypt/seal"
# Local KV is read on every request that presents a long token and there is no revocation cache
# in between, which the immediate 403 above shows; hence no wait for KV's ~60 s propagation,
# which only matters on Cloudflare's edge.
seal_denied='.jti == "'"$seal_accessor"'" and .result == "denied"'
audit_load
denied_before="$(count "$seal_denied")"
# OpenBao's transit seal test-encrypts at startup; with the token refused it exits rather than
# serving sealed. Either outcome passes once edgekms has audited a new refusal of the seal
# token; answering unsealed at any point fails.
docker restart "$bao_name" >/dev/null
for _ in $(seq 20); do
  if [ "$(docker inspect -f '{{.State.Running}}' "$bao_name")" != true ]; then break; fi
  if bao_status >"$tmp/bao-status"; then die "OpenBao unsealed with a revoked seal token"; fi
  sleep 1
done
if [ "$(docker inspect -f '{{.State.Running}}' "$bao_name")" = true ]; then
  [ "$(jq -r .sealed "$tmp/bao-status")" = true ] || die "OpenBao state: $(cat "$tmp/bao-status")"
  ok "OpenBao is up and sealed 20 s after restart"
else
  docker logs --tail 10 "$bao_name" >"$tmp/bao-log" 2>&1
  grep -qF 'Error configuring seal "transit"' "$tmp/bao-log" && grep -qF 'Code: 403' "$tmp/bao-log" ||
    die "OpenBao exited for another reason: $(cat "$tmp/bao-log")"
  ok "OpenBao refused to start: seal \"transit\" got 403 from edgekms, so it never unsealed"
fi
audit_load
denied_after="$(count "$seal_denied")"
[ "$denied_after" -gt "$denied_before" ] ||
  die "no new audited refusal of the seal token after the restart ($denied_before -> $denied_after)"
ok "edgekms audited $((denied_after - denied_before)) refusal(s) of the revoked seal token after the restart"

# ---------------------------------------------------------------------------------------------
step "8. audit log in the local R2 bucket"
audit_load
[ -s "$tmp/audit.jsonl" ] || die "no R2 audit objects under $tmp/state/v3/r2"
echo "    $(wc -l <"$tmp/audit.jsonl") events:"
jq -r '[.op, .result, (.mount // "-"), (.role // "-"), (.key // "-"), (.error // "")] | @tsv' \
  "$tmp/audit.jsonl" | sort | uniq -c | sed 's/^/     /'
need() {
  local n
  n="$(count "$1")"
  [ "$n" -ge 1 ] || die "no audit event for: $2 ($1)"
  ok "$2: $n"
}
need '.op == "challenge" and .mount == "ssh" and .result == "ok"' "ssh challenge"
need '.op == "login" and .mount == "ssh" and .role == "op" and .result == "ok"' "ssh login"
need '.op == "login" and .mount == "jwt" and .role == "ci" and .result == "ok"' "jwt login"
need '.op == "login" and .mount == "jwt" and .result == "denied" and .error == "login_role_not_found"' \
  "jwt login with the SSH role op denied (role not on this mount)"
[ "$fetched_jwks" = 1 ] &&
  need '.op == "login" and .mount == "github" and .error == "jwt_unknown_kid"' \
    "fetched-JWKS login denied for an unknown kid"
need '.op == "token_lookup" and .result == "ok"' "token lookup"
need '.op == "encrypt" and .key == "pulumi" and .result == "ok"' "pulumi encrypt"
need '.op == "decrypt" and .key == "pulumi" and .result == "ok"' "pulumi decrypt"
need ".op == \"token_create\" and .target_jti == \"$seal_accessor\" and .result == \"ok\"" "seal token create"
need '.op == "token_create" and .result != "ok"' "refused admin token create"
need '.op == "encrypt" and .key == "seal" and .result == "ok"' "seal encrypt"
need '.op == "decrypt" and .key == "seal" and .result == "ok"' "seal decrypt (unseal)"
need ".op == \"token_revoke\" and .target_jti == \"$seal_accessor\" and .result == \"ok\"" "seal token revoke"
need ".jti == \"$seal_accessor\" and .result == \"denied\"" "denied use of the revoked seal token"
# Text forms with grep -a (the state includes sqlite). The Pulumi config value never reaches
# edgekms (Pulumi encrypts it locally under the data key); it is checked anyway, cheaply.
recovery_key="$(jq -r '.recovery_keys_b64[0]' "$tmp/bao-init.json")"
bao_root_token="$(jq -r '.root_token' "$tmp/bao-init.json")"
# wrangler.log is wrangler dev's and the Worker's console output: a secret logged there is as
# much a leak as one written to state.
leak_dirs=("$tmp/state" "$worker_dir/.wrangler" "$worker_dir/build" "$tmp/wrangler.log")
pairs=("Pulumi data key (base64):$data_key_b64" "JWT:$jwt" "root key:$root_key"
  "ci token:$ci_token" "seal token:$seal_token" "OpenBao recovery key:$recovery_key"
  "OpenBao root token:$bao_root_token" "Pulumi config value:$secret")
for t in "${admin_tokens[@]}"; do pairs+=("admin token:$t"); done
for pair in "${pairs[@]}"; do
  # The needle goes to grep in a file (-f), so no secret is in grep's argv.
  printf '%s\n' "${pair#*:}" >"$tmp/needle"
  for dir in "${leak_dirs[@]}"; do
    [ -e "$dir" ] || continue
    if grep -rqaF -f "$tmp/needle" "$dir"; then die "the ${pair%%:*} appears under $dir"; fi
  done
done
rm -f "$tmp/needle"
# The raw data key bytes, matched in each file's hex dump (an odd-offset hex match could only
# cause a false failure, never a false pass).
while IFS= read -r -d '' f; do
  # Through a file: under pipefail, grep -q closing the pipe early would turn a match into a
  # failed pipeline.
  od -An -v -tx1 "$f" | tr -d ' \n' >"$tmp/hex"
  if grep -qF "$data_key_hex" "$tmp/hex"; then
    die "the raw Pulumi data key appears in $f"
  fi
done < <(for dir in "${leak_dirs[@]}"; do [ -e "$dir" ] && find "$dir" -type f -print0; done)
ok "no Pulumi data key (base64 or raw), JWT, root key, token or OpenBao recovery material in the local state (R2, KV, metrics), wrangler.log or the repo's .wrangler/ and build/"

# ---------------------------------------------------------------------------------------------
step "9. FIDO login with the operator's hardware key"
if [ -n "$fido_key" ]; then
  echo "    touch the key when it blinks"
  fido_token="$(SSH_AUTH_SOCK="$operator_sock" "$edgekms" login ssh --addr "$addr" --role op \
    --key "$fido_key")" || die "FIDO login failed"
  [[ "$fido_token" == ekms.* ]] || die "FIDO login printed something other than a token"
  ok "FIDO login returned a token"
else
  cat <<EOF
    manual, once: re-run with your FIDO key in the op role and touch it when asked:
      $root/scripts/e2e.sh --fido ~/.ssh/id_ed25519_sk.pub
    and record the result in the PR.
EOF
fi
