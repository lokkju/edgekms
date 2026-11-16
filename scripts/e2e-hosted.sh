#!/usr/bin/env bash
# End-to-end run of the hosted edgekms Worker under `wrangler dev` (workerd), with local D1
# (migrations 0001 to 0006), KV, R2, rate limiters, a local Secrets Store master key and a stub
# GitHub (scripts/e2e-hosted/github-stub.py) for both the CLI's device flow and the Worker's
# token check and revoke. The real CLI drives the control plane at http://api.localhost:<port>;
# tenants are http://<name>.localhost:<port>.
#
# Each step asserts its result; the first failure stops the run. Lines tagged [workerd] are the
# checks only workerd can confirm (the unit tests run under Node); the summary at the end lists
# them.
#
# Everything throwaway (master keys, root keys, SSH key, wrangler's local state) lives in a
# mktemp directory, and the EXIT trap removes it. Needs: mise (the repo's toolchain: Rust,
# worker-build, wrangler, node, pnpm, sops, age), uv, jq, curl, ssh-keygen, python3, sha256sum, shuf.
#
# The run takes about ten minutes: it waits out the tenant cache's 30-second revalidation
# several times and the 300-second export freshness window once, and restarts wrangler three
# times. `--keep` leaves the temporary directory in place for inspection.
set -euo pipefail

keep=0
case "${1:-}" in
  "") ;;
  --keep) keep=1 ;;
  *) echo "usage: $0 [--keep]" >&2; exit 2 ;;
esac

root="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
dev_dir="$root/scripts/e2e-hosted"
fixture="$root/crates/edgekms-core/tests/fixtures/jwt.json"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/edgekms-e2e-hosted.XXXXXX")"
chmod 700 "$tmp"
wrangler_pid=""
stub_pid=""
agent_pid=""

cleanup() {
  local rc=$?
  set +e
  stop_wrangler
  [ -n "$agent_pid" ] && kill "$agent_pid" 2>/dev/null
  if [ -n "$stub_pid" ]; then
    kill -TERM -- "-$stub_pid" 2>/dev/null
    kill -TERM "$stub_pid" 2>/dev/null
  fi
  if [ "$keep" = 1 ]; then echo "kept $tmp"; else rm -rf "$tmp"; fi
  if [ "$rc" -eq 0 ]; then echo "e2e-hosted: PASS"; else echo "e2e-hosted: FAIL (exit $rc)" >&2; fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

log_mark=0
step() {
  printf '\n==> %s\n' "$*"
  log_mark=0
  if [ -f "$tmp/wrangler.log" ]; then log_mark="$(wc -l <"$tmp/wrangler.log")"; fi
}
ok() { printf '    ok: %s\n' "$*"; }
workerd=()
# confirmed ITEM DETAIL: one of the plan's workerd-only checks, passed.
confirmed() {
  printf '    ok [workerd]: %s: %s\n' "$1" "$2"
  workerd+=("PASS  $1: $2")
}
die() {
  printf '    FAIL: %s\n' "$*" >&2
  if [ -s "$tmp/wrangler.log" ]; then
    tail -n "+$((log_mark + 1))" "$tmp/wrangler.log" | tail -40 >"$tmp/wrangler.tail"
    if [ -s "$tmp/wrangler.tail" ]; then
      echo "---- wrangler dev output during this step (at most 40 lines) ----" >&2
      cat "$tmp/wrangler.tail" >&2
    fi
  fi
  exit 1
}

free_port() {
  local p
  for p in $(shuf -i 20000-40000 -n 100); do
    [[ " $* " == *" $p "* ]] && continue
    if ! (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then echo "$p"; return; fi
  done
  die "no free port"
}

for tool in mise uv jq curl ssh-keygen python3 sha256sum shuf; do
  command -v "$tool" >/dev/null || die "$tool not on PATH"
done
mx() { mise -C "$root" exec -- "$@"; }

port="$(free_port)"
stub_port="$(free_port "$port")"
stub="http://127.0.0.1:$stub_port"
api_url="http://api.localhost:$port"
tenant_url() { printf 'http://%s.localhost:%s' "$1" "$port"; }
client_id="Iv_hosted_test" # GITHUB_CLIENT_ID in scripts/e2e-hosted/wrangler.jsonc

# http METHOD URL [BODY] [CURL ARGS...]: body to $tmp/resp, status to $status. A token goes in
# $bearer (control plane, Authorization) or $vtoken (data plane, X-Vault-Token), through a
# header file, so it is in no argv. curl maps every *.localhost name to loopback itself.
status=""
bearer=""
vtoken=""
http() {
  local method="$1" url="$2" body="${3:-}"
  shift 2
  [ $# -gt 0 ] && shift
  local args=(-s -o "$tmp/resp" -w '%{http_code}' -X "$method" "$url")
  : >"$tmp/auth.header"
  [ -n "$bearer" ] && printf 'Authorization: Bearer %s\n' "$bearer" >>"$tmp/auth.header"
  [ -n "$vtoken" ] && printf 'X-Vault-Token: %s\n' "$vtoken" >>"$tmp/auth.header"
  args+=(-H "@$tmp/auth.header")
  [ -n "$body" ] && args+=(-H 'Content-Type: application/json' --data-binary @-)
  status="$(printf '%s' "$body" | curl "${args[@]}" "$@")"
  rm -f "$tmp/auth.header"
}
# want CODE WHAT: the last http status must be CODE.
want() { [ "$status" = "$1" ] || die "$2: want $1, got $status $(head -c 400 "$tmp/resp")"; }
err0() { jq -r '.errors[0] // empty' "$tmp/resp" 2>/dev/null; }

# ek ARGS...: the CLI, with its device flow pointed at the stub. Stdout to $tmp/ek.out, stderr
# to $tmp/ek.err; returns the CLI's exit status.
ek() {
  EDGEKMS_GITHUB_OAUTH_BASE="$stub" EDGEKMS_GITHUB_CLIENT_ID="$client_id" SSH_AUTH_SOCK= \
    "$edgekms" "$@" >"$tmp/ek.out" 2>"$tmp/ek.err"
}
# ek_ok WHAT ARGS...: the CLI must succeed.
ek_ok() {
  local what="$1"
  shift
  ek "$@" || die "$what: edgekms $1 $2 failed: $(cat "$tmp/ek.err")"
}
# tenant_cmd TOKEN ARGS...: `edgekms tenant --api <api> ARGS` with the control token in the env.
tenant_cmd() {
  local tok="$1"
  shift
  EDGEKMS_CONTROL_TOKEN="$tok" ek tenant --api "$api_url" "$@"
}

# next_user ID LOGIN: the stub's next device-flow approval is this GitHub user.
next_user() {
  curl -fsS -o /dev/null -X POST "$stub/_stub/next-user" -d "{\"id\": $1, \"login\": \"$2\"}" ||
    die "github stub: next-user"
}
secrets_seen=() # every credential the run handles, for the leak check at the end
# control_login ID LOGIN: `edgekms account login` as that stub user; the token in $ctl.
control_login() {
  next_user "$1" "$2"
  ek_ok "account login as $2" account login --api "$api_url" --client-id "$client_id"
  ctl="$(cat "$tmp/ek.out")"
  [[ "$ctl" == ekms.* ]] || die "account login printed something other than a token"
  secrets_seen+=("control token:$ctl")
}
# data_login ID LOGIN TENANT ROLE: `edgekms login github` at a tenant; the token in $dtok.
data_login() {
  next_user "$1" "$2"
  ek_ok "login github as $2 at $3" login github --addr "$(tenant_url "$3")" --role "$4"
  dtok="$(cat "$tmp/ek.out")"
  [[ "$dtok" == ekms.* ]] || die "login github printed something other than a token"
  secrets_seen+=("data token:$dtok")
}

# d1 SQL: runs SQL on the local D1 database; the JSON result rows to stdout.
d1() {
  WRANGLER_SEND_METRICS=false CI=1 mx wrangler d1 execute edgekms-tenants --local --json \
    --cwd "$dev_dir" --config wrangler.jsonc --persist-to "$tmp/state" --command "$1" \
    2>"$tmp/d1.err" | jq -c '.[0].results' || die "d1 execute: $(cat "$tmp/d1.err")"
}

# encrypt TENANT KEY PLAINTEXT_B64 -> ciphertext on stdout (with $vtoken).
encrypt() {
  http POST "$(tenant_url "$1")/v1/transit/encrypt/$2" "{\"plaintext\": \"$3\"}"
  want 200 "encrypt under $2 at $1"
  jq -r .data.ciphertext "$tmp/resp"
}
# decrypt TENANT KEY CIPHERTEXT -> plaintext base64 on stdout.
decrypt() {
  http POST "$(tenant_url "$1")/v1/transit/decrypt/$2" "{\"ciphertext\": \"$3\"}"
  want 200 "decrypt under $2 at $1"
  jq -r .data.plaintext "$tmp/resp"
}

# until_ok SECONDS WHAT CMD...: retries CMD every second until it succeeds or time runs out.
until_ok() {
  local secs="$1" what="$2" i
  shift 2
  for ((i = 0; i < secs; i++)); do
    if "$@"; then return 0; fi
    sleep 1
  done
  die "$what: not within $secs s"
}

# R2 audit objects: miniflare keeps the keys in a sqlite index and each body as a blob file.
audit_keys() {
  python3 -I - "$tmp/state/v3/r2" <<'EOF'
import glob, sqlite3, sys
for db in glob.glob(sys.argv[1] + "/miniflare-R2BucketObject/*.sqlite"):
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    for (t,) in con.execute("SELECT name FROM sqlite_master WHERE type = 'table'"):
        cols = [r[1] for r in con.execute(f"PRAGMA table_info({t})")]
        if "key" in cols:
            for (k,) in con.execute(f"SELECT key FROM {t}"):
                print(k)
EOF
}
audit_load() {
  : >"$tmp/audit.jsonl"
  [ -d "$tmp/state/v3/r2" ] || return 0
  find "$tmp/state/v3/r2" -path '*/blobs/*' -type f -exec cat {} + | jq -c . >"$tmp/audit.jsonl" ||
    die "an audit object is not JSON"
}
count() { jq -s "[.[] | select($1)] | length" "$tmp/audit.jsonl"; }

# start_wrangler ENV_FILE: wrangler dev on 127.0.0.1:$port with that env file (secrets and var
# overrides), until /v1/info answers on the control host.
start_wrangler() {
  (
    export WRANGLER_SEND_METRICS=false CI=1
    exec setsid mise -C "$root" exec -- wrangler dev --cwd "$dev_dir" --config wrangler.jsonc \
      --ip 127.0.0.1 --port "$port" --env-file "$1" --persist-to "$tmp/state" --log-level info
  ) >>"$tmp/wrangler.log" 2>&1 &
  wrangler_pid=$!
  local i
  for i in $(seq 600); do
    if curl -sf -o /dev/null "$api_url/v1/info" 2>/dev/null; then return 0; fi
    # Hosted mode with single-tenant bindings answers 500 everywhere, which is still an answer.
    [ "$(curl -s -o /dev/null -w '%{http_code}' "$api_url/v1/info" 2>/dev/null)" = 500 ] &&
      return 0
    kill -0 "$wrangler_pid" 2>/dev/null || die "wrangler dev exited"
    [ "$i" = 600 ] && die "wrangler dev did not answer in 300 s"
    sleep 0.5
  done
}
stop_wrangler() {
  [ -n "$wrangler_pid" ] || return 0
  # Under set -e: killing a group that already exited fails, and that is fine.
  kill -TERM -- "-$wrangler_pid" 2>/dev/null || true
  for _ in $(seq 40); do kill -0 "$wrangler_pid" 2>/dev/null || break; sleep 0.25; done
  kill -KILL -- "-$wrangler_pid" 2>/dev/null || true
  wait "$wrangler_pid" 2>/dev/null || true
  wrangler_pid=""
  for _ in $(seq 40); do (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null || return 0; sleep 0.25; done
}

# Stub users. 1003 is the operator (OPERATOR_GITHUB_IDS below); 1004's login is reserved.
# 1006 to 1008 first log in after signups stop being open (step 14).
alice=1001
bob=1002
ops=1003
admin=1004
carol=1005
dave=1006
erin=1007
frank=1008

# ---------------------------------------------------------------------------------------------
step "1. throwaway master keys, GitHub stub, local Secrets Store, D1 migrations, wrangler dev"
umask 077
m1="$(head -c 32 /dev/urandom | base64 -w0)"
m2="$(head -c 32 /dev/urandom | base64 -w0)"
gh_secret="$(head -c 18 /dev/urandom | base64 -w0 | tr '+/' '-_')"
secrets_seen+=("master m1:$m1" "master m2:$m2" "GitHub client secret:$gh_secret")
ssh-keygen -q -t ed25519 -N '' -C edgekms-e2e-hosted -f "$tmp/id_e2e"
ssh_pub="$(cat "$tmp/id_e2e.pub")"

mx cargo build -q -p edgekms-cli || die "building the CLI"
# The console's static assets (the ASSETS binding in scripts/e2e-hosted/wrangler.jsonc), which
# wrangler needs on disk before it starts.
mx pnpm -C "$root/console" install --frozen-lockfile >"$tmp/console.log" 2>&1 &&
  mx pnpm -C "$root/console" build >>"$tmp/console.log" 2>&1 ||
  die "building the console: $(tail -20 "$tmp/console.log")"
[ -f "$root/console/dist/index.html" ] || die "the console build left no console/dist/index.html"
ok "console built into console/dist"
edgekms="$root/target/debug/edgekms"
ok "$("$edgekms" --version)"

(
  export STUB_CLIENT_SECRET="$gh_secret"
  exec setsid uv run -q --script "$dev_dir/github-stub.py" "$stub_port"
) >"$tmp/stub.log" 2>&1 &
stub_pid=$!
until_ok 60 "the GitHub stub answering" curl -sf -o /dev/null "$stub/_stub/calls"
ok "GitHub stub on $stub"

# The m1 master goes into wrangler's local Secrets Store from stdin, not argv; the Worker reads
# it through the MASTER_KEY_M1 Secrets Store binding in scripts/e2e-hosted/wrangler.jsonc.
printf '%s' "$m1" | WRANGLER_SEND_METRICS=false CI=1 mx wrangler secrets-store secret create \
  local-e2e-store --name edgekms-master-m1 --scopes workers --cwd "$dev_dir" \
  --config wrangler.jsonc --persist-to "$tmp/state" >"$tmp/ss.log" 2>&1 ||
  die "secrets-store secret create: $(cat "$tmp/ss.log")"
m1_secret_id="$(grep -o 'ID: [0-9a-f]\{32\}' "$tmp/ss.log" | head -1 | cut -d' ' -f2)"
ok "master m1 in the local Secrets Store (secret $m1_secret_id)"

WRANGLER_SEND_METRICS=false CI=1 mx wrangler d1 migrations apply edgekms-tenants --local \
  --cwd "$dev_dir" --config wrangler.jsonc --persist-to "$tmp/state" >"$tmp/migrate.log" 2>&1 ||
  die "d1 migrations apply: $(cat "$tmp/migrate.log")"
for m in 0001_tenants 0002_invites_and_logout 0003_member_macs 0004_signup_allowlist 0005_invite_requests 0006_ssh_keys; do
  grep -q "$m" "$tmp/migrate.log" || die "migration $m not applied: $(cat "$tmp/migrate.log")"
done
ok "migrations 0001 to 0006 applied to the local D1"

# Signups are open until step 14, which switches to invite and then closed.
signup_mode=open
base_env() {
  printf 'SIGNUP_MODE=%s\n' "$signup_mode"
  printf 'GITHUB_CLIENT_SECRET=%s\n' "$gh_secret"
  printf 'GITHUB_API_BASE=%s\n' "$stub"
  printf 'HOSTED_ORIGIN_TEMPLATE=http://{tenant}.localhost:%s\n' "$port"
  printf 'OPERATOR_GITHUB_IDS=%s\n' "$ops"
  printf 'MAX_TENANTS_PER_USER=3\n'
}
base_env >"$tmp/worker.env"
start_wrangler "$tmp/worker.env"
http GET "$api_url/v1/info"
want 200 "GET /v1/info"
[ "$(jq -c . "$tmp/resp")" = "{\"apex\":\"localhost\",\"github_client_id\":\"$client_id\"}" ] ||
  die "/v1/info: $(cat "$tmp/resp")"
ok "control plane at $api_url: $(jq -c . "$tmp/resp")"

# ---------------------------------------------------------------------------------------------
step "2. account login (device flow at the stub) creates the personal tenant"
t0="$(date +%s)"
control_login "$alice" alice
alice_ctl_early="$ctl" # aged past 300 s for the stale-export check in step 12
grep -q "Created your tenant alice" "$tmp/ek.err" || die "login summary: $(cat "$tmp/ek.err")"
ok "$(grep 'Logged in' "$tmp/ek.err")"
curl -fsS "$stub/_stub/calls" >"$tmp/calls.json"
ctl_gh_token="$(jq -r '[.[] | select(.method == "POST")][-1].token' "$tmp/calls.json")"
secrets_seen+=("GitHub token:$ctl_gh_token")
jq -e --arg t "$ctl_gh_token" --arg c "$client_id" '
  ([.[] | select(.token == $t and .method == "POST" and .status == 200 and .client_id == $c)] | length) == 1 and
  ([.[] | select(.token == $t and .method == "DELETE" and .status == 204)] | length) == 1' \
  "$tmp/calls.json" >/dev/null || die "stub calls: $(cat "$tmp/calls.json")"
confirmed "FetchGithub check and revoke from api.<apex>" "one POST /applications/$client_id/token (200) and one DELETE (204) for the login's token"
ctl_alice="$ctl"
tenant_cmd "$ctl_alice" list || die "tenant list: $(cat "$tmp/ek.err")"
[ "$(cat "$tmp/ek.out")" = "$(printf 'alice\towner')" ] || die "tenant list: $(cat "$tmp/ek.out")"
ok "tenant list: alice owner"
tenant_cmd "$ctl_alice" show alice || die "tenant show: $(cat "$tmp/ek.err")"
alice_id="$(jq -r .id "$tmp/ek.out")"
alice_root="$(jq -r .root_id "$tmp/ek.out")"
[[ "$alice_id" =~ ^t_[0-9a-f]{16}$ ]] && [[ "$alice_root" =~ ^r_[0-9a-f]{16}$ ]] ||
  die "tenant ids: $alice_id $alice_root"
ok "alice is $alice_id, root $alice_root"
[ "$(d1 "SELECT count(*) AS n FROM system_keys WHERE name = 'control'" | jq '.[0].n')" = 1 ] ||
  die "no control root row"
ok "the control root was created on first use (INSERT OR IGNORE, then re-read)"
confirmed "D1 BLOB binding (Uint8Array)" "tenant and control-root rows written with BLOB columns and read back (the login and show succeeded)"

# A second login creates nothing.
control_login "$alice" alice
grep -q "Created your tenant" "$tmp/ek.err" && die "a second login created a tenant"
ctl_alice="$ctl"
ok "second login: no new tenant"

# A reserved login gets a `u-` stem and a suffix (u-admin-<4 hex>); the suffix comes from getrandom.
control_login "$admin" admin
admin_tenant="$(sed -n 's/.*Created your tenant \([a-z0-9-]*\)\..*/\1/p' "$tmp/ek.err")"
[[ "$admin_tenant" =~ ^u-admin-[0-9a-f]{4}$ ]] || die "reserved login's tenant: $(cat "$tmp/ek.err")"
confirmed "getrandom" "random tenant and root ids, and the reserved login admin got $admin_tenant"

# A token issued for another App is refused.
curl -fsS -X POST "$stub/_stub/mint" -d "{\"id\": $carol, \"login\": \"carol\", \"client_id\": \"Iv_other\"}" >"$tmp/mint.json"
other_token="$(jq -r .token "$tmp/mint.json")"
secrets_seen+=("GitHub token:$other_token")
bearer=""
http POST "$api_url/v1/login/github" "{\"token\": \"$other_token\"}"
want 400 "control login with another App's token"
ok "another App's token: 400 $(err0)"

# ---------------------------------------------------------------------------------------------
step "3. data plane: GitHub login at the personal tenant, transit encrypt, decrypt, rewrap"
http GET "$(tenant_url alice)/v1/sys/health"
want 200 "health at alice"
data_login "$alice" alice alice owner
vtoken="$dtok"
alice_dtok="$dtok"
pt="$(head -c 24 /dev/urandom | base64 -w0)"
secrets_seen+=("plaintext:$pt")
ct_alice="$(encrypt alice default "$pt")"
[[ "$ct_alice" == vault:v1:* ]] || die "ciphertext: $ct_alice"
[ "$(decrypt alice default "$ct_alice")" = "$pt" ] || die "decrypt returned another plaintext"
http POST "$(tenant_url alice)/v1/transit/rewrap/default" "{\"ciphertext\": \"$ct_alice\"}"
want 200 "rewrap at alice"
[ "$(decrypt alice default "$(jq -r .data.ciphertext "$tmp/resp")")" = "$pt" ] || die "rewrapped ciphertext"
ok "encrypt, decrypt and rewrap under default"
confirmed "unwrapKey (AES-GCM) into a non-extractable HKDF key" "the tenant root, wrapped under the Secrets Store master, unwrapped and derived the transit key"
confirmed "AES-GCM additionalData and tagLength 128" "the wrap AAD binds tenant and root id; unwrapping with it succeeded"
confirmed "Secrets Store binding via a held Env" "MASTER_KEY_M1 read from the local Secrets Store binding, lazily, through the Env the isolate kept"
confirmed "D1 sessions (withSession first-unconstrained) on local D1" "the data plane's version and row reads went through the session"
vtoken=""

# ---------------------------------------------------------------------------------------------
step "4. host routing: unknown, reserved and nested names are bare 404s"
for host in nobody www api2-x.b; do
  http GET "http://$host.localhost:$port/v1/sys/health"
  want 404 "GET /v1/sys/health at $host.localhost"
  [ -s "$tmp/resp" ] && die "$host.localhost: the 404 has a body: $(cat "$tmp/resp")"
done
ok "nobody (unknown), www (reserved), api2-x.b (nested): bare 404"
http GET "$api_url/v1/nothing"
want 404 "unrouted control path"
ok "an unrouted control path: 404 $(err0)"

# ---------------------------------------------------------------------------------------------
step "5. import: tenant 'alice-imported' from an existing root key, with SSH and JWT roles"
imp_root_id="r_e2e$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
imp_root_key="$(head -c 32 /dev/urandom | base64 -w0)"
secrets_seen+=("imported root key:$imp_root_key")
jq -c --arg root "$imp_root_id" --slurpfile fx "$fixture" --arg ssh "$ssh_pub" '
  .root_id = $root
  | .mounts.jwt.jwks = $fx[0].jwks
  | del(.mounts.github) | del(.roles.gh)
  | .roles.op.ssh_keys = [$ssh]
' "$root/scripts/e2e/config.json" >"$tmp/imported.json"
printf '%s' "$imp_root_key" | base64 -d | EDGEKMS_CONTROL_TOKEN="$ctl_alice" \
  EDGEKMS_GITHUB_OAUTH_BASE="$stub" "$edgekms" tenant --api "$api_url" create alice-imported \
  --import-root-id "$imp_root_id" --config "$tmp/imported.json" >"$tmp/ek.out" 2>"$tmp/ek.err" &&
  die "create read a raw key from stdin; it wants base64"
printf '%s' "$imp_root_key" | EDGEKMS_CONTROL_TOKEN="$ctl_alice" EDGEKMS_GITHUB_OAUTH_BASE="$stub" \
  "$edgekms" tenant --api "$api_url" create alice-imported --import-root-id "$imp_root_id" \
  --config "$tmp/imported.json" >"$tmp/ek.out" 2>"$tmp/ek.err" ||
  die "tenant create --import-root-id: $(cat "$tmp/ek.err")"
ok "$(cat "$tmp/ek.err")"
admin_login() {
  ek_ok "login ssh at $1" login ssh --addr "$(tenant_url "$1")" --role op --key "$tmp/id_e2e.pub"
  dtok="$(cat "$tmp/ek.out")"
  secrets_seen+=("data token:$dtok")
}
admin_login alice-imported
imp_op="$dtok"
vtoken="$imp_op"
pt2="$(head -c 24 /dev/urandom | base64 -w0)"
secrets_seen+=("plaintext:$pt2")
ct_imp="$(encrypt alice-imported seal "$pt2")"
vtoken=""
got="$(printf '%s' "$imp_root_key" | "$edgekms" decrypt --config "$tmp/imported.json" --key seal "$ct_imp")" ||
  die "offline decrypt of the imported tenant's ciphertext"
[ "$got" = "$pt2" ] || die "offline decrypt returned another plaintext"
ok "SSH login at imported; its ciphertext opens offline with the imported root key"
jwt="$(jq -r .cases.valid_rs256 "$fixture")"
secrets_seen+=("JWT:$jwt")
http POST "$(tenant_url alice-imported)/v1/auth/jwt/login" "$(jq -nc --arg j "$jwt" '{role: "ci", jwt: $j}')"
want 200 "JWT login (pinned JWKS) at imported"
imp_ci="$(jq -r .auth.client_token "$tmp/resp")"
secrets_seen+=("data token:$imp_ci")
ok "JWT login with the pinned JWKS at imported: policies $(jq -c .auth.policies "$tmp/resp")"

# Constraint errors as workerd's D1 words them.
printf '%s' "$imp_root_key" | EDGEKMS_CONTROL_TOKEN="$ctl_alice" EDGEKMS_GITHUB_OAUTH_BASE="$stub" \
  "$edgekms" tenant --api "$api_url" create alice-imported2 --import-root-id "$imp_root_id" \
  --config "$tmp/imported.json" >"$tmp/ek.out" 2>"$tmp/ek.err" && die "a duplicate root id was imported"
grep -q "HTTP 409): root id already in use" "$tmp/ek.err" || die "duplicate root id: $(cat "$tmp/ek.err")"
tenant_cmd "$ctl_alice" create alice-imported && die "a duplicate name was created"
grep -q "HTTP 409): tenant name already in use" "$tmp/ek.err" || die "duplicate name: $(cat "$tmp/ek.err")"
tenant_cmd "$ctl_alice" create bob-thing && die "alice created a tenant outside her login's prefix"
grep -q "tenant name must start with alice-" "$tmp/ek.err" &&
  grep -q "personal tenant" "$tmp/ek.err" || die "naming rule: $(cat "$tmp/ek.err")"
ok "naming rule: alice can't create bob-thing ($(head -c 120 "$tmp/ek.err"))"
confirmed "D1 constraint error wording" "a duplicate name is 409 'tenant name already in use' and a duplicate root id 409 'root id already in use' (tenants.name and tenants.root_id matched)"

# ---------------------------------------------------------------------------------------------
step "6. tenant cap: three concurrent creates with one slot left admit exactly one"
# alice created alice (personal) and imported; MAX_TENANTS_PER_USER is 3.
jobs_=()
for n in two three four; do
  (
    printf 'Authorization: Bearer %s\n' "$ctl_alice" >"$tmp/cap-$n.header"
    curl -s -o "$tmp/cap-$n.json" -w '%{http_code}' -X POST "$api_url/v1/tenants" \
      -H "@$tmp/cap-$n.header" -H 'Content-Type: application/json' \
      --data-binary "{\"name\": \"alice-$n\"}" >"$tmp/cap-$n.status"
    rm -f "$tmp/cap-$n.header"
  ) &
  jobs_+=($!)
done
wait "${jobs_[@]}" # only these: a bare wait would wait for wrangler and the stub too
created=0
for n in two three four; do
  s="$(cat "$tmp/cap-$n.status")"
  case "$s" in
    200) created=$((created + 1)); cap_name="alice-$n" ;;
    403) jq -e '.errors[0] == "at most 3 tenants per user"' "$tmp/cap-$n.json" >/dev/null ||
      die "cap refusal: $(cat "$tmp/cap-$n.json")" ;;
    *) die "create alice-$n: $s $(cat "$tmp/cap-$n.json")" ;;
  esac
done
[ "$created" = 1 ] || die "$created of three concurrent creates succeeded at the cap"
confirmed "conditional INSERT ... SELECT count cap" "three concurrent creates at 2 of 3: exactly one ($cap_name) succeeded, the others 403 'at most 3 tenants per user'"
bearer=""

# ---------------------------------------------------------------------------------------------
step "7. config: get, set (SSH and JWT roles), If-Match, and the edit reaching the data plane"
tenant_cmd "$ctl_alice" config get alice || die "config get: $(cat "$tmp/ek.err")"
grep -q "config version 1" "$tmp/ek.err" || die "config get version: $(cat "$tmp/ek.err")"
jq --slurpfile fx "$fixture" --arg ssh "$ssh_pub" '
  .mounts.ssh = {type: "ssh"}
  | .mounts.jwt = {type: "jwt", issuer: "https://issuer.test", jwks: $fx[0].jwks}
  | .roles.op = {mount: "ssh", ssh_keys: [$ssh], policies: ["admin", "default-all"], token_ttl_secs: 900}
  | .roles.ci = {mount: "jwt", bound_audiences: ["https://kms.test"], bound_claims: {repository_id: "42"},
                 policies: ["default-all"], token_ttl_secs: 900}
' "$tmp/ek.out" >"$tmp/alice-v2.json"
tenant_cmd "$ctl_alice" config set alice "$tmp/alice-v2.json" ||
  die "config set: $(cat "$tmp/ek.err")"
grep -q "alice is now at config version 2" "$tmp/ek.err" || die "config set: $(cat "$tmp/ek.err")"
ok "config set: SSH role op and JWT role ci added, version 2"
tenant_cmd "$ctl_alice" config get alice || die "config get: $(cat "$tmp/ek.err")"
grep -q "config version 2" "$tmp/ek.err" || die "read after write saw $(cat "$tmp/ek.err")"
confirmed "D1Store::primary in the control plane" "the edit is visible on the very next control request (local D1 has no replicas, so replica lag isn't exercised)"
audit_load
[ -n "$(d1 "SELECT config FROM tenants WHERE name = 'alice'" | jq -r '.[0].config')" ] || die "no config"
stored_sha="$(d1 "SELECT config FROM tenants WHERE name = 'alice'" | jq -j '.[0].config' | sha256sum | cut -d' ' -f1)"
jq -e --arg s "$stored_sha" 'select(.config_version == 2 and .result == "ok") | .config_sha256 == $s' \
  "$tmp/audit.jsonl" | grep -q true || die "config_sha256: $(jq -c 'select(.config_version)' "$tmp/audit.jsonl")"
confirmed "crypto.subtle.digest SHA-256" "the config edit's audit event has config_sha256 = sha256 of the stored config"

# Polled with curl from an address of its own: every challenge counts against LOGIN_LIMIT (30
# a minute per IP), and the CLI's logins all come from 127.0.0.1.
edit_reached() {
  http POST "$(tenant_url alice)/v1/auth/ssh/challenge" '{"role": "op"}' \
    -H 'CF-Connecting-IP: 198.51.100.50'
  [ "$status" = 200 ]
}
until_ok 45 "the SSH role op at alice after the config edit" edit_reached
ek_ok "SSH login at alice" login ssh --addr "$(tenant_url alice)" --role op --key "$tmp/id_e2e.pub"
alice_op="$(cat "$tmp/ek.out")"
secrets_seen+=("data token:$alice_op")
ok "the new SSH role works at alice within one revalidation interval, no restart"
http POST "$(tenant_url alice)/v1/auth/jwt/login" "$(jq -nc --arg j "$jwt" '{role: "ci", jwt: $j}')"
want 200 "JWT login at alice"
ok "JWT role ci works at alice"

# If-Match: stale through the CLI, missing and malformed through curl, and a race.
tenant_cmd "$ctl_alice" config set alice "$tmp/alice-v2.json" --if-version 1 &&
  die "a stale --if-version was accepted"
grep -q "changed after version 1" "$tmp/ek.err" || die "stale set: $(cat "$tmp/ek.err")"
bearer="$ctl_alice"
http PUT "$api_url/v1/tenants/alice/config" "$(jq -c . "$tmp/alice-v2.json")"
want 428 "config PUT without If-Match"
http PUT "$api_url/v1/tenants/alice/config" "$(jq -c . "$tmp/alice-v2.json")" -H 'If-Match: "v2"'
want 400 "config PUT with a malformed If-Match"
confirmed "If-Match delivery through read_request" "stale 409, missing 428, malformed 400"
jobs_=()
for n in a b; do
  (
    printf 'Authorization: Bearer %s\n' "$ctl_alice" >"$tmp/race-$n.header"
    jq -c ".keys.race_$n = {id: \"k_race_$n\", latest_version: 1, min_decryption_version: 1}" \
      "$tmp/alice-v2.json" | curl -s -o "$tmp/race-$n.json" -w '%{http_code}' -X PUT \
      "$api_url/v1/tenants/alice/config" -H "@$tmp/race-$n.header" -H 'If-Match: "2"' \
      -H 'Content-Type: application/json' --data-binary @- >"$tmp/race-$n.status"
    rm -f "$tmp/race-$n.header"
  ) &
  jobs_+=($!)
done
wait "${jobs_[@]}"
race="$(cat "$tmp/race-a.status") $(cat "$tmp/race-b.status")"
[ "$race" = "200 409" ] || [ "$race" = "409 200" ] || die "two PUTs at version 2: $race"
confirmed "meta.changes on a conditional UPDATE" "two concurrent config PUTs at If-Match 2: one 200, one 409 ($race)"
bearer=""
ok "jwks_url under the apex is refused by the control plane:"
bearer="$ctl_alice"
http PUT "$api_url/v1/tenants/alice/config" \
  "$(jq -c '.mounts.loop = {type: "jwt", issuer: "https://i.test", jwks_url: "https://x.localhost/jwks"}' "$tmp/alice-v2.json")" \
  -H 'If-Match: "3"'
want 400 "jwks_url under the apex"
ok "  400 $(err0)"
bearer=""
tenant_cmd "$ctl_alice" config get alice || die "config get: $(cat "$tmp/ek.err")"
jq '.keys.extra = {id: "k_e2e_extra", latest_version: 1, min_decryption_version: 1}
    | .policies["default-all"].keys.extra = ["encrypt", "decrypt"]' "$tmp/ek.out" >"$tmp/alice-v4.json"
tenant_cmd "$ctl_alice" config set alice "$tmp/alice-v4.json" || die "config set: $(cat "$tmp/ek.err")"
vtoken="$alice_dtok"
new_key_works() {
  http POST "$(tenant_url alice)/v1/transit/encrypt/extra" "{\"plaintext\": \"$pt\"}" -H "CF-Connecting-IP: 198.51.100.51"
  [ "$status" = 200 ]
}
# The owner token's policies come from the config at login; log in again to pick up the key.
data_login "$alice" alice alice owner
vtoken="$dtok"
alice_dtok="$dtok"
until_ok 45 "the new key extra encrypting at alice" new_key_works
ok "key extra, added by config set, encrypts within one revalidation interval"
vtoken=""

# ---------------------------------------------------------------------------------------------
step "8. tenant isolation"
vtoken="$alice_dtok"
http POST "$(tenant_url alice-imported)/v1/transit/encrypt/seal" "{\"plaintext\": \"$pt\"}"
want 403 "alice's token at imported"
http GET "$(tenant_url alice-imported)/v1/auth/token/lookup-self"
want 403 "alice's token lookup-self at imported"
vtoken=""
ok "alice's token is refused at imported (403)"
http POST "$(tenant_url alice-imported)/v1/auth/ssh/challenge" '{"role": "op"}'
want 200 "SSH challenge at imported"
challenge="$(jq -r .data.challenge "$tmp/resp")"
printf '%s' "$challenge" | SSH_AUTH_SOCK= ssh-keygen -q -Y sign -n edgekms -f "$tmp/id_e2e" >"$tmp/sig" 2>/dev/null ||
  die "ssh-keygen sign"
http POST "$(tenant_url alice)/v1/auth/ssh/login" \
  "$(jq -nc --arg c "$challenge" --rawfile s "$tmp/sig" '{role: "op", challenge: $c, signature: $s}')"
want 400 "imported's SSH challenge at alice"
[ "$(err0)" = "permission denied" ] || die "challenge replay: $(cat "$tmp/resp")"
http POST "$(tenant_url alice-imported)/v1/auth/ssh/login" \
  "$(jq -nc --arg c "$challenge" --rawfile s "$tmp/sig" '{role: "op", challenge: $c, signature: $s}')"
want 200 "the same signed challenge at imported"
secrets_seen+=("data token:$(jq -r .auth.client_token "$tmp/resp")")
ok "an SSH challenge signed for imported is refused at alice (400) and accepted at imported"
vtoken="$alice_op"
http POST "$(tenant_url alice)/v1/auth/token/create" '{"policies": ["default-all"], "ttl": "1h"}'
want 200 "token create at alice"
a_created="$(jq -r .auth.client_token "$tmp/resp")"
a_acc="$(jq -r .auth.accessor "$tmp/resp")"
http POST "$(tenant_url alice)/v1/auth/token/revoke-accessor" "{\"accessor\": \"$a_acc\"}"
want 204 "revoke-accessor at alice"
vtoken="$imp_op"
http POST "$(tenant_url alice-imported)/v1/auth/token/create" '{"policies": ["seal"], "ttl": "1h"}'
want 200 "token create at imported"
b_created="$(jq -r .auth.client_token "$tmp/resp")"
secrets_seen+=("created token:$a_created" "created token:$b_created")
vtoken="$a_created"
http POST "$(tenant_url alice)/v1/transit/encrypt/default" "{\"plaintext\": \"$pt\"}"
want 403 "the revoked token at alice"
vtoken="$b_created"
http POST "$(tenant_url alice-imported)/v1/transit/encrypt/seal" "{\"plaintext\": \"$pt\"}"
want 200 "imported's created token after alice's revocation"
vtoken=""
[ -n "$(find "$tmp/state/v3/kv" -type f -print -quit)" ] || die "no local KV state"
ok "a token created and revoked at alice is refused there; imported's created token works"

# ---------------------------------------------------------------------------------------------
step "9. members: invite, invites, accept, decline, remove, last owner"
tenant_cmd "$ctl_alice" member add alice --github-id "$bob" || die "member add: $(cat "$tmp/ek.err")"
grep -q "Invited GitHub id $bob to be a member of alice" "$tmp/ek.err" || die "member add: $(cat "$tmp/ek.err")"
tenant_cmd "$ctl_alice" member add alice --github-id "$carol" --owner || die "member add: $(cat "$tmp/ek.err")"
control_login "$bob" bob
ctl_bob="$ctl"
tenant_cmd "$ctl_bob" invites || die "invites: $(cat "$tmp/ek.err")"
[ "$(cat "$tmp/ek.out")" = "$(printf 'alice\tmember')" ] || die "bob's invites: $(cat "$tmp/ek.out")"
tenant_cmd "$ctl_bob" show alice && die "an invite granted read access before it was accepted"
grep -q "HTTP 404" "$tmp/ek.err" || die "show before accept: $(cat "$tmp/ek.err")"
tenant_cmd "$ctl_bob" accept alice || die "accept: $(cat "$tmp/ek.err")"
grep -q "You are now a member of alice" "$tmp/ek.err" || die "accept: $(cat "$tmp/ek.err")"
tenant_cmd "$ctl_bob" show alice || die "show as member: $(cat "$tmp/ek.err")"
tenant_cmd "$ctl_bob" export alice && die "a member exported"
grep -q "HTTP 403" "$tmp/ek.err" || die "member export: $(cat "$tmp/ek.err")"
tenant_cmd "$ctl_bob" config set alice "$tmp/alice-v4.json" && die "a member edited the config"
grep -q "HTTP 403" "$tmp/ek.err" || die "member config set: $(cat "$tmp/ek.err")"
ok "bob: invites lists alice, accept makes him a member, export and config set are 403"
# Offering the owner role to a member, then accepting, raises the existing row.
tenant_cmd "$ctl_alice" member add alice --github-id "$bob" --owner || die "member add --owner: $(cat "$tmp/ek.err")"
grep -q "Invited" "$tmp/ek.err" || die "owner offer: $(cat "$tmp/ek.err")"
tenant_cmd "$ctl_bob" accept alice || die "accept owner: $(cat "$tmp/ek.err")"
grep -q "You are now an owner of alice" "$tmp/ek.err" || die "accept owner: $(cat "$tmp/ek.err")"
tenant_cmd "$ctl_alice" show alice || die "show: $(cat "$tmp/ek.err")"
jq -e --argjson b "$bob" '[.members[] | select(.github_id == $b and .role == "owner")] | length == 1' \
  "$tmp/ek.out" >/dev/null || die "members after the raise: $(jq -c .members "$tmp/ek.out")"
confirmed "INSERT ... ON CONFLICT DO UPDATE ... WHERE in accept" "bob, already a member, accepted an owner offer and his one row became owner"
control_login "$carol" carol
ctl_carol="$ctl"
tenant_cmd "$ctl_carol" decline alice || die "decline: $(cat "$tmp/ek.err")"
tenant_cmd "$ctl_carol" invites || die "invites: $(cat "$tmp/ek.err")"
grep -q "No pending invites" "$tmp/ek.err" || die "carol still has invites"
tenant_cmd "$ctl_carol" accept alice && die "accepted a declined invite"
grep -q "HTTP 404" "$tmp/ek.err" || die "accept after decline: $(cat "$tmp/ek.err")"
ok "carol declines; accepting afterwards is 404"
tenant_cmd "$ctl_alice" member remove alice --github-id "$bob" || die "member remove: $(cat "$tmp/ek.err")"
tenant_cmd "$ctl_alice" member remove alice --github-id "$bob" && die "removed a missing member"
grep -q "HTTP 404): member not found" "$tmp/ek.err" || die "second remove: $(cat "$tmp/ek.err")"
tenant_cmd "$ctl_alice" member remove alice --github-id "$alice" && die "removed the last owner"
grep -q "HTTP 400): tenant needs an owner" "$tmp/ek.err" || die "last owner: $(cat "$tmp/ek.err")"
confirmed "meta.changes on DELETE" "removing bob is 204, removing him again 404 member not found"
ok "the last owner can't be removed (400 tenant needs an owner)"

# ---------------------------------------------------------------------------------------------
step "10. tamper: a config rewritten in D1 without a MAC stops loading; config set restores it"
# The version goes up too, as a D1 writer's would: the cache only rereads a row whose version
# or wrap key changed, so a rewrite in place goes unnoticed until the isolate reloads.
d1 "UPDATE tenants SET config = replace(config, 'k_e2e_extra', 'k_tampered'),
  config_version = config_version + 1 WHERE name = 'alice'" >/dev/null
vtoken="$alice_dtok"
tampered() { http POST "$(tenant_url alice)/v1/transit/encrypt/default" "{\"plaintext\": \"$pt\"}" -H "CF-Connecting-IP: 198.51.100.51"; [ "$status" = 500 ]; }
# A row that fails its MAC keeps the previous entry serving for one more interval, so this
# takes up to two.
until_ok 75 "alice answering 500 after the tamper" tampered
grep -q tenant_config_mac_bad "$tmp/wrangler.log" || die "no tenant_config_mac_bad log line"
ok "alice answers 500 once the previous entry runs out, logged tenant_config_mac_bad"
tenant_cmd "$ctl_alice" config set alice "$tmp/alice-v4.json" || die "restoring config set: $(cat "$tmp/ek.err")"
restored() { http POST "$(tenant_url alice)/v1/transit/encrypt/default" "{\"plaintext\": \"$pt\"}" -H "CF-Connecting-IP: 198.51.100.51"; [ "$status" = 200 ]; }
until_ok 45 "alice serving after the restore" restored
[ "$(decrypt alice default "$ct_alice")" = "$pt" ] || die "old ciphertext after the restore"
ok "config set wrote a fresh MAC; alice serves and decrypts its old ciphertext again"
vtoken=""

# ---------------------------------------------------------------------------------------------
step "11. suspension through the operator route"
bearer="$ctl_alice"
http PUT "$api_url/v1/ops/tenants/alice-imported/status" '{"status": "suspended"}'
want 403 "a non-operator's status change"
control_login "$ops" ops
ctl_ops="$ctl"
bearer="$ctl_ops"
http PUT "$api_url/v1/ops/tenants/alice-imported/status" '{"status": "suspended"}'
want 204 "suspend imported"
bearer=""
vtoken="$b_created"
suspended() { http POST "$(tenant_url alice-imported)/v1/transit/encrypt/seal" "{\"plaintext\": \"$pt\"}" -H "CF-Connecting-IP: 198.51.100.51"; [ "$status" = 403 ]; }
until_ok 45 "imported refused after suspension" suspended
ok "imported is refused (403) within one revalidation interval"
tenant_cmd "$ctl_alice" config set alice-imported "$tmp/imported.json" && die "config set on a suspended tenant"
grep -q "tenant is suspended" "$tmp/ek.err" || die "suspended config set: $(cat "$tmp/ek.err")"
ok "the control plane freezes its config (403 tenant is suspended)"
bearer="$ctl_ops"
http PUT "$api_url/v1/ops/tenants/alice-imported/status" '{"status": "active"}'
want 204 "reactivate imported"
bearer=""
active() { http POST "$(tenant_url alice-imported)/v1/transit/encrypt/seal" "{\"plaintext\": \"$pt\"}" -H "CF-Connecting-IP: 198.51.100.51"; [ "$status" = 200 ]; }
until_ok 50 "imported serving after reactivation" active
ok "reactivated: imported serves again"
vtoken=""

# ---------------------------------------------------------------------------------------------
step "12. export: fresh login, then a login older than 300 s"
control_login "$alice" alice
ctl_alice="$ctl"
tenant_cmd "$ctl_alice" export alice-imported || die "fresh export: $(cat "$tmp/ek.err")"
[ "$(cat "$tmp/ek.out")" = "$imp_root_key" ] || die "export returned another key"
grep -q "root id: $imp_root_id" "$tmp/ek.err" || die "export stderr: $(cat "$tmp/ek.err")"
ok "tenant export alice-imported prints the imported root key alone on stdout, the root id on stderr"
age=$(($(date +%s) - t0))
if [ "$age" -lt 305 ]; then
  echo "    waiting $((305 - age)) s for step 2's control token to pass 300 s"
  sleep $((305 - age))
fi
tenant_cmd "$alice_ctl_early" export alice-imported && die "export with a login older than 300 s"
grep -q "export needs a login less than five minutes old" "$tmp/ek.err" ||
  die "stale export: $(cat "$tmp/ek.err")"
bearer="$alice_ctl_early"
http POST "$api_url/v1/tenants/alice-imported/export" '{}'
want 403 "stale export"
[ "$(err0)" = "fresh login required" ] || die "stale export: $(cat "$tmp/resp")"
bearer=""
ok "a control token older than 300 s gets 403 fresh login required"

# ---------------------------------------------------------------------------------------------
step "12b. SSH-key control login: register a key from ssh-agent, log in with it, export, remove"
# A throwaway agent holding one fresh Ed25519 key. `ek` empties SSH_AUTH_SOCK, so these calls
# run the CLI directly with the agent's socket.
ssh-keygen -q -t ed25519 -N '' -C e2e-control -f "$tmp/id_control"
ssh-agent -a "$tmp/agent.sock" >"$tmp/agent.env"
agent_pid="$(sed -n 's/^SSH_AGENT_PID=\([0-9]*\);.*/\1/p' "$tmp/agent.env")"
SSH_AUTH_SOCK="$tmp/agent.sock" ssh-add -q "$tmp/id_control" 2>/dev/null || die "ssh-add"
rm -f "$tmp/id_control"
eka() { # eka ARGS...: the CLI with the throwaway agent; stdout and stderr as for ek
  SSH_AUTH_SOCK="$tmp/agent.sock" "$edgekms" "$@" >"$tmp/ek.out" 2>"$tmp/ek.err"
}
control_login "$alice" alice
ctl_alice="$ctl"
fp="$(ssh-keygen -lf "$tmp/id_control.pub" | awk '{print $2}')"
# The registration challenge names alice's account (#72): pinned to anyone else, nothing is
# signed or registered.
if EDGEKMS_CONTROL_TOKEN="$ctl_alice" eka account ssh-keys add --api "$api_url" \
  --expect-github-id 4242; then
  die "ssh-keys add signed a challenge for alice while expecting GitHub id 4242"
fi
grep -qF "GitHub account alice ($alice)" "$tmp/ek.err" ||
  die "ssh-keys add mismatch didn't name alice: $(cat "$tmp/ek.err")"
ok "ssh-keys add refuses a challenge for alice ($alice) when told to expect GitHub id 4242"
EDGEKMS_CONTROL_TOKEN="$ctl_alice" eka account ssh-keys add --api "$api_url" --label e2e ||
  die "ssh-keys add: $(cat "$tmp/ek.err")"
[ ! -s "$tmp/ek.out" ] || die "ssh-keys add wrote to stdout"
grep -qF "$fp" "$tmp/ek.err" || die "ssh-keys add didn't name $fp: $(cat "$tmp/ek.err")"
grep -qF "Registering SSH key $fp to GitHub account alice ($alice)." "$tmp/ek.err" ||
  die "ssh-keys add didn't name the account before signing: $(cat "$tmp/ek.err")"
EDGEKMS_CONTROL_TOKEN="$ctl_alice" eka account ssh-keys list --api "$api_url" ||
  die "ssh-keys list: $(cat "$tmp/ek.err")"
key_id="$(awk -F'\t' -v fp="$fp" '$2 == fp && $4 == "e2e" && $6 == "github" {print $1}' "$tmp/ek.out")"
[ -n "$key_id" ] || die "ssh-keys list: $(cat "$tmp/ek.out")"
ok "ssh-keys add proved and registered $fp from the agent; list shows it, added via github"
eka account login --ssh --api "$api_url" || die "account login --ssh: $(cat "$tmp/ek.err")"
ctl_ssh="$(cat "$tmp/ek.out")"
[[ "$ctl_ssh" == ekms.* ]] || die "account login --ssh printed something other than a token"
secrets_seen+=("control token:$ctl_ssh")
grep -qF "$fp" "$tmp/ek.err" || die "login --ssh stderr: $(cat "$tmp/ek.err")"
grep -q "1 SSH key can log in" "$tmp/ek.err" || die "login --ssh key count: $(cat "$tmp/ek.err")"
tenant_cmd "$ctl_ssh" export alice-imported || die "export with the SSH token: $(cat "$tmp/ek.err")"
[ "$(cat "$tmp/ek.out")" = "$imp_root_key" ] || die "SSH export returned another key"
ok "account login --ssh (no --key: the agent's one key) gives a token that exports alice-imported"
EDGEKMS_CONTROL_TOKEN="$ctl_alice" eka account ssh-keys remove --api "$api_url" "$fp" ||
  die "ssh-keys remove: $(cat "$tmp/ek.err")"
tenant_cmd "$ctl_ssh" list && die "the SSH token outlived its key"
grep -q "HTTP 403" "$tmp/ek.err" || die "after removal: $(cat "$tmp/ek.err")"
tenant_cmd "$ctl_alice" list || die "removing the key ended the GitHub session: $(cat "$tmp/ek.err")"
eka account login --ssh --api "$api_url" && die "a removed key logged in"
grep -q "isn't registered" "$tmp/ek.err" || die "removed key login: $(cat "$tmp/ek.err")"
kill "$agent_pid" 2>/dev/null || true
ok "ssh-keys remove ends the SSH token on its next request; the GitHub token keeps working"

# ---------------------------------------------------------------------------------------------
step "13. rate limits: CONTROL_LIMIT, LOGIN_LIMIT, and CF-Worker keying"
codes() { # codes N URL [CURL ARGS...]: the statuses of N GETs, space-separated
  local n="$1" url="$2" i
  shift 2
  for ((i = 0; i < n; i++)); do curl -s -o /dev/null -w '%{http_code} ' "$url" "$@"; done
}
c="$(codes 61 "$api_url/v1/info" -H 'CF-Connecting-IP: 198.51.100.7')"
[[ "$c" == *"429 " ]] && [[ "$(echo "$c" | tr ' ' '\n' | grep -c 200)" = 60 ]] ||
  die "61 control requests from one IP: $c"
confirmed "CONTROL_LIMIT binding" "60 requests from one IP pass, the 61st is 429"
c="$(codes 1 "$api_url/v1/info" -H 'CF-Connecting-IP: 198.51.100.7' -H 'CF-Worker: forged.example')"
[ "$c" = "429 " ] || die "a forged CF-Worker from outside Cloudflare's ranges got a fresh bucket: $c"
ok "CF-Worker from 198.51.100.7 (outside Cloudflare's ranges) is ignored: still 429"
codes 61 "$api_url/v1/info" -H 'CF-Connecting-IP: 104.16.0.1' >/dev/null
c="$(codes 1 "$api_url/v1/info" -H 'CF-Connecting-IP: 104.16.0.1')"
[ "$c" = "429 " ] || die "104.16.0.1 should be over the limit: $c"
c="$(codes 1 "$api_url/v1/info" -H 'CF-Connecting-IP: 104.16.0.1' -H 'CF-Worker: zone-a.example')"
[ "$c" = "200 " ] || die "CF-Worker from a Cloudflare address should have its own bucket: $c"
confirmed "rate limiter keys containing ':' and '|'" "cfw:zone-a.example|104.16.0.1 is its own bucket while 104.16.0.1 is at 429; tenant:jti TOKEN_LIMIT keys served every authenticated request above"
c=""
for ((i = 0; i < 31; i++)); do
  http POST "$(tenant_url alice)/v1/auth/github-user/login" '{"role": "owner", "token": "gho_not_a_real_token"}' \
    -H 'CF-Connecting-IP: 198.51.100.20'
  c+="$status "
done
[[ "$c" == *"429 " ]] && [[ "$c" != *"429 "*"400 "* ]] || die "31 logins from one IP: $c"
ok "31 failed logins from one IP: the last is 429 ($(echo "$c" | tr ' ' '\n' | sort | uniq -c | tr -s ' \n' ' '))"

# ---------------------------------------------------------------------------------------------
step "14. master rotation: m2 current, rewrap paged through ops/rewrap, then m1 retired"
stop_wrangler
signup_mode=invite
{ base_env; printf 'MASTER_KEY_M2=%s\nMASTER_KEY_CURRENT=m2\nMASTER_KEY_PREVIOUS=m1\n' "$m2"; } >"$tmp/worker.env"
start_wrangler "$tmp/worker.env"
# The isolate's first request is an unknown tenant, so the MasterUnwrap it builds holds that
# request's Env; m1 is read from the Secrets Store binding later, on the first unwrap.
http GET "$(tenant_url nobody)/v1/sys/health"
want 404 "unknown tenant after restart"
vtoken="$b_created"
[ "$(decrypt alice-imported seal "$ct_imp")" = "$pt2" ] || die "decrypt at imported before the rewrap"
vtoken=""
ok "after the restart, a tenant on m1 still loads (m1 imported lazily through the held Env)"
total="$(d1 "SELECT count(*) AS n FROM tenants" | jq '.[0].n')"
control_login "$ops" ops
bearer="$ctl_ops"
after=""
pages=0
rewrapped=0
while :; do
  if [ -z "$after" ]; then body='{"limit": 2}'; else body="{\"limit\": 2, \"after\": \"$after\"}"; fi
  http POST "$api_url/v1/ops/rewrap" "$body"
  want 200 "ops/rewrap page $((pages + 1))"
  pages=$((pages + 1))
  rewrapped=$((rewrapped + $(jq .data.rewrapped "$tmp/resp")))
  [ "$(jq '.data.failed | length' "$tmp/resp")" = 0 ] || die "rewrap failures: $(cat "$tmp/resp")"
  after="$(jq -r '.data.next // empty' "$tmp/resp")"
  [ -z "$after" ] && break
  [ "$pages" -gt 50 ] && die "rewrap did not finish in 50 pages"
done
[ "$(jq .data.remaining "$tmp/resp")" = 0 ] || die "rewrap remaining: $(cat "$tmp/resp")"
bearer=""
[ "$rewrapped" = $((total + 1)) ] || die "rewrapped $rewrapped rows, want $total tenants and the control root"
[ "$(d1 "SELECT count(*) AS n FROM tenants WHERE wrap_key = 'm1'" | jq '.[0].n')" = 0 ] ||
  die "tenants still wrapped under m1"
[ "$(d1 "SELECT count(*) AS n FROM system_keys WHERE wrap_key = 'm1'" | jq '.[0].n')" = 0 ] ||
  die "the control root is still wrapped under m1"
ok "ops/rewrap: $rewrapped rows ($total tenants and the control root) in $pages pages of at most 2; none left on m1"
confirmed "meta.changes on the conditional set_wrapped" "every row moved to m2 with the compare-and-swap on wrap_key"

# SIGNUP_MODE=invite since the restart: a stranger is refused until an operator allowlists them.
# refused_login ID LOGIN: `edgekms account login` must fail with the invite-only message.
refused_login() {
  next_user "$1" "$2"
  ek account login --api "$api_url" --client-id "$client_id" && die "$2 logged in; signups should be refused"
  grep -qF 'invite-only. Run `edgekms account request-invite` to ask for an invite' "$tmp/ek.err" || die "$2's refusal: $(cat "$tmp/ek.err")"
}
ops_cmd() { EDGEKMS_CONTROL_TOKEN="$ctl_ops" ek ops --api "$api_url" "$@"; }
refused_login "$dave" dave
ok "invite mode: dave, a stranger, is refused: $(tail -n 1 "$tmp/ek.err")"
ops_cmd allowlist add "$dave" || die "ops allowlist add: $(cat "$tmp/ek.err")"
control_login "$dave" dave
grep -q "Created your tenant dave" "$tmp/ek.err" || die "dave's signup: $(cat "$tmp/ek.err")"
ok "allowlisted by the operator, dave signs up and gets his personal tenant"
# A row written straight to D1, without the control root's MAC, admits no one.
d1 "INSERT INTO signup_allowlist (github_id, added_by, added_ms, mac) VALUES ($erin, $ops, 0, x'00')" >/dev/null
refused_login "$erin" erin
ops_cmd allowlist list || die "ops allowlist list: $(cat "$tmp/ek.err")"
[ "$(cut -f1 "$tmp/ek.out")" = "$dave" ] || die "allowlist: $(cat "$tmp/ek.out")"
grep -q "$erin" "$tmp/ek.err" || die "the forged row isn't reported: $(cat "$tmp/ek.err")"
ops_cmd allowlist remove "$erin" || die "ops allowlist remove erin: $(cat "$tmp/ek.err")"
ops_cmd allowlist remove "$dave" || die "ops allowlist remove dave: $(cat "$tmp/ek.err")"
confirmed "signup allowlist MACs (mac/allow/v1) on D1" "a forged row for erin admits no one and is listed as unverified; dave's real row admitted him"
control_login "$alice" alice
ok "invite mode: alice, an existing user, still logs in"

step "14b. hosted mode with a single-tenant binding refuses every request"
stop_wrangler
{ base_env; printf 'MASTER_KEY_M2=%s\nMASTER_KEY_CURRENT=m2\nROOT_KEY=%s\n' "$m2" "$m1"; } >"$tmp/worker.env"
start_wrangler "$tmp/worker.env"
http GET "$api_url/v1/info"
want 500 "control plane with ROOT_KEY bound"
http GET "$(tenant_url alice)/v1/sys/health"
want 500 "tenant with ROOT_KEY bound"
# wrangler prints the Worker's log lines a moment after the response.
until_ok 15 "a hosted_and_single_tenant_bindings log line" \
  grep -q hosted_and_single_tenant_bindings "$tmp/wrangler.log"
confirmed "binding detection through Reflect::get on a real env" "ROOT_KEY bound as a secret next to HOSTED_APEX: 500 on every host, logged hosted_and_single_tenant_bindings"

step "14c. m1 retired: its secret deleted from the Secrets Store; both tenants still decrypt"
stop_wrangler
WRANGLER_SEND_METRICS=false CI=1 mx wrangler secrets-store secret delete local-e2e-store \
  --secret-id "$m1_secret_id" --cwd "$dev_dir" --config wrangler.jsonc --persist-to "$tmp/state" \
  >"$tmp/ss.log" 2>&1 || die "secrets-store secret delete: $(cat "$tmp/ss.log")"
signup_mode=closed
{ base_env; printf 'MASTER_KEY_M2=%s\nMASTER_KEY_CURRENT=m2\n' "$m2"; } >"$tmp/worker.env"
start_wrangler "$tmp/worker.env"
vtoken="$alice_dtok"
[ "$(decrypt alice default "$ct_alice")" = "$pt" ] || die "alice after m1's retirement"
vtoken="$b_created"
[ "$(decrypt alice-imported seal "$ct_imp")" = "$pt2" ] || die "imported after m1's retirement"
vtoken=""
control_login "$alice" alice
ctl_alice="$ctl"
tenant_cmd "$ctl_alice" list || die "tenant list after rotation: $(cat "$tmp/ek.err")"
ok "with only m2 bound, alice and imported decrypt their old ciphertexts and the control plane logs in"
# SIGNUP_MODE=closed since the restart: dave (off the allowlist, but holding his tenant) logs in
# and gets nothing new; frank, a stranger, is refused.
control_login "$dave" dave
grep -q "Created your tenant" "$tmp/ek.err" && die "a login while signups are closed created a tenant"
refused_login "$frank" frank
ok "closed mode: alice and dave, existing users, log in; frank is refused"

# ---------------------------------------------------------------------------------------------
step "15. sops against the tenant, and the export-into-sops pipe"
# The binaries are resolved once and run directly: `mise -C` would change the working
# directory, and sops finds .sops.yaml from its working directory, as the quickstart relies on.
sops_bin="$(mise -C "$root" which sops 2>/dev/null || true)"
age_keygen="$(mise -C "$root" which age-keygen 2>/dev/null || true)"
if [ -x "$sops_bin" ] && [ -x "$age_keygen" ]; then
  mkdir -p "$tmp/sops"
  printf 'db_password: hunter2-%s\n' "$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')" >"$tmp/sops/secrets.yaml"
  secrets_seen+=("sops value:$(sed -n 's/^db_password: //p' "$tmp/sops/secrets.yaml")")
  addr="$(tenant_url alice)"
  ( cd "$tmp/sops" && VAULT_ADDR="$addr" VAULT_TOKEN="$alice_dtok" "$sops_bin" encrypt \
      --hc-vault-transit "$addr/v1/transit/keys/default" secrets.yaml ) >"$tmp/sops/secrets.sops.yaml" \
    2>"$tmp/sops/err" || die "sops encrypt --hc-vault-transit: $(cat "$tmp/sops/err")"
  grep -q 'vault:v1:' "$tmp/sops/secrets.sops.yaml" || die "the sops file has no vault ciphertext"
  ( cd "$tmp/sops" && VAULT_ADDR="$addr" VAULT_TOKEN="$alice_dtok" "$sops_bin" decrypt secrets.sops.yaml ) \
    >"$tmp/sops/out.yaml" 2>"$tmp/sops/err" || die "sops decrypt: $(cat "$tmp/sops/err")"
  cmp -s "$tmp/sops/out.yaml" "$tmp/sops/secrets.yaml" || die "sops round trip differs"
  ok "quickstart step 3: sops encrypt --hc-vault-transit and decrypt round-trip through alice"
  "$age_keygen" -o "$tmp/sops/age.key" 2>/dev/null
  printf 'creation_rules:\n  - age: %s\n' "$("$age_keygen" -y "$tmp/sops/age.key")" >"$tmp/sops/.sops.yaml"
  ( cd "$tmp/sops" && EDGEKMS_CONTROL_TOKEN="$ctl_alice" "$edgekms" tenant --api "$api_url" export alice-imported 2>/dev/null |
      jq -Rn '{root_key: input}' |
      "$sops_bin" encrypt --filename-override root.sops.yaml --input-type json --output-type yaml /dev/stdin \
        >root.sops.yaml ) 2>"$tmp/sops/err" || die "export into sops: $(cat "$tmp/sops/err")"
  got="$(cd "$tmp/sops" && SOPS_AGE_KEY_FILE="$tmp/sops/age.key" "$sops_bin" decrypt --extract '["root_key"]' root.sops.yaml)"
  [ "$got" = "$imp_root_key" ] || die "the sops file holds another root key"
  grep -qF "$imp_root_key" "$tmp/sops/root.sops.yaml" && die "root.sops.yaml holds the key in plaintext"
  ok "quickstart step 7: tenant export | jq | sops encrypt writes root.sops.yaml, which decrypts to the root key"
  sops_result="sops: --hc-vault-transit encrypt and decrypt against alice PASS; export-into-sops pipe PASS"
else
  sops_result="sops: not available through mise; skipped"
  echo "    NOTICE: $sops_result"
fi

# ---------------------------------------------------------------------------------------------
step "16. logout: every control token stops working"
EDGEKMS_CONTROL_TOKEN="$ctl_alice" ek account logout --api "$api_url" ||
  die "account logout: $(cat "$tmp/ek.err")"
tenant_cmd "$ctl_alice" list && die "a logged-out token still works"
grep -q "HTTP 403" "$tmp/ek.err" || die "after logout: $(cat "$tmp/ek.err")"
ok "after account logout the token gets 403"

# ---------------------------------------------------------------------------------------------
step "17. audit log in the local R2 bucket"
audit_keys >"$tmp/keys.txt"
grep -q "^audit/$alice_id/" "$tmp/keys.txt" || die "no audit/<alice id>/ objects: $(head "$tmp/keys.txt")"
grep -q "^control/" "$tmp/keys.txt" || die "no control/ objects"
ok "$(grep -c '^audit/' "$tmp/keys.txt") tenant objects under audit/<tenant id>/, $(grep -c '^control/' "$tmp/keys.txt") under control/"
audit_load
for op in tenant_export login; do
  [ "$(count ".op == \"$op\"")" -ge 1 ] || die "no $op event"
done
curl -fsS "$stub/_stub/calls" >"$tmp/calls.json"
while read -r t; do secrets_seen+=("GitHub token:$t"); done < <(jq -r '.[].token' "$tmp/calls.json" | sort -u)
for pair in "${secrets_seen[@]}"; do
  printf '%s\n' "${pair#*:}" >"$tmp/needle"
  [ -s "$tmp/needle" ] || continue
  # wrangler.log, wrangler dev's and the Worker's console output, counts as much as the state.
  for dir in "$tmp/state" "$root/crates/edgekms-worker/.wrangler" "$dev_dir/.wrangler" "$tmp/wrangler.log"; do
    [ -e "$dir" ] || continue
    # The local Secrets Store holds m1 by design; it is the master's home, not a leak.
    if grep -rqaF --exclude-dir=secrets-store -f "$tmp/needle" "$dir"; then die "the ${pair%%:*} appears under $dir"; fi
  done
done
rm -f "$tmp/needle"
ok "no master key, root key, token, GitHub token, JWT or plaintext in the local state (D1, KV, R2, cache) or wrangler.log"

printf '\nworkerd confirmations (%d):\n' "${#workerd[@]}"
printf '  %s\n' "${workerd[@]}"
printf '%s\n' "$sops_result"
