# shellcheck shell=bash
# Shared by the hosted-mode deploy tasks (build, deploy, migrate, test-config, and any an operator
# adds): the Cloudflare credential, the account check and the wrangler.jsonc rules. Source it; the
# caller defines die() and sets dir to its deploy directory, the one holding wrangler.jsonc.
#
# A deploy directory may hold a hosted.env, sourced here first, that pins what this file would
# otherwise read from wrangler.jsonc or leave unchecked:
#
#   HOSTED_ACCOUNT_ID             the one Cloudflare account the token may reach (default: the
#                                 config's account_id)
#   HOSTED_WORKER                 the Worker name the config must use (default: the config's name)
#   HOSTED_D1                     the D1 database's name (default: edgekms-tenants)
#   HOSTED_FORBIDDEN_ACCOUNT_IDS  space-separated accounts the token must not reach, such as a
#                                 personal account that holds other things
#   HOSTED_NO_ROUTES              when set, the config may have no routes; the value says who owns
#                                 them instead (an infrastructure stack, say), and is the message
#   HOSTED_README                 where the error messages send the reader (default: the deploy
#                                 directory's README.md)
# shellcheck disable=SC2154 # dir is the caller's

hosted_lib_dir=$(dirname "${BASH_SOURCE[0]}")
# The edgekms checkout the Worker, the console and the migrations come from. Defaults to the one
# this file is in; an operator repo that pins edgekms somewhere else sets EDGEKMS_SRC.
edgekms_src=$(realpath "${EDGEKMS_SRC:-$hosted_lib_dir/../../../..}")

if [[ -f $dir/hosted.env ]]; then
  # shellcheck disable=SC1091
  source "$dir/hosted.env"
fi
HOSTED_README=${HOSTED_README:-$dir/README.md}
# shellcheck disable=SC2034 # used by the tasks that source this file
HOSTED_D1=${HOSTED_D1:-edgekms-tenants}
HOSTED_FORBIDDEN_ACCOUNT_IDS=${HOSTED_FORBIDDEN_ACCOUNT_IDS:-}
HOSTED_NO_ROUTES=${HOSTED_NO_ROUTES:-}

# hosted_defaults: fills HOSTED_ACCOUNT_ID and HOSTED_WORKER from wrangler.jsonc when hosted.env
# didn't pin them.
hosted_defaults() {
  local cfg
  if [[ -z ${HOSTED_ACCOUNT_ID:-} || -z ${HOSTED_WORKER:-} ]]; then
    cfg=$(hosted_config)
    HOSTED_ACCOUNT_ID=${HOSTED_ACCOUNT_ID:-$(jq -r '.account_id // empty' <<<"$cfg")}
    HOSTED_WORKER=${HOSTED_WORKER:-$(jq -r '.name // empty' <<<"$cfg")}
  fi
  [[ -n $HOSTED_ACCOUNT_ID ]] || die "wrangler.jsonc has no account_id"
  [[ -n $HOSTED_WORKER ]] || die "wrangler.jsonc has no name"
}

# hosted_auth: points wrangler at the deploy account's token and nothing else.
#
# An operator's CLOUDFLARE_API_TOKEN is never used outside CI: it is often a token for some other
# account, loaded by whatever environment the operator's shell sits in. The deploy token comes
# from EDGEKMS_CLOUDFLARE_API_TOKEN. In GitHub Actions only, the CLOUDFLARE_API_TOKEN that the
# job's environment supplies is used as it is.
#
# Then `wrangler whoami --json` must list exactly one account, HOSTED_ACCOUNT_ID. An account token
# made in that account passes; a user token that also reaches another account doesn't.
hosted_auth() {
  local who accounts forbidden
  hosted_defaults
  unset CLOUDFLARE_API_KEY CLOUDFLARE_EMAIL
  if [[ -n ${EDGEKMS_CLOUDFLARE_API_TOKEN:-} ]]; then
    export CLOUDFLARE_API_TOKEN=$EDGEKMS_CLOUDFLARE_API_TOKEN
  elif [[ ${GITHUB_ACTIONS:-} == true && -n ${CLOUDFLARE_API_TOKEN:-} ]]; then
    : # the CI environment's secret
  else
    unset CLOUDFLARE_API_TOKEN
    die "set EDGEKMS_CLOUDFLARE_API_TOKEN to a token made in account $HOSTED_ACCOUNT_ID ($HOSTED_README, \"Credentials\"); CLOUDFLARE_API_TOKEN is ignored outside CI"
  fi
  export CLOUDFLARE_ACCOUNT_ID=$HOSTED_ACCOUNT_ID
  who=$(wrangler whoami --json 2>/dev/null) || die "wrangler whoami failed; the token is missing, expired or lacks Account Settings Read"
  accounts=$(jq -r '[.accounts[]?.id] | sort | join(",")' <<<"$who") ||
    die "couldn't parse the output of wrangler whoami --json"
  for forbidden in $HOSTED_FORBIDDEN_ACCOUNT_IDS; do
    [[ $accounts != *"$forbidden"* ]] ||
      die "the token reaches the account $forbidden, which it must not; use a token made in $HOSTED_ACCOUNT_ID"
  done
  [[ $accounts == "$HOSTED_ACCOUNT_ID" ]] ||
    die "the token must reach exactly the account $HOSTED_ACCOUNT_ID; it reaches: ${accounts:-none}"
}

# hosted_config: prints wrangler.jsonc as compact JSON.
hosted_config() {
  node "$hosted_lib_dir/jsonc.mjs" "$dir/wrangler.jsonc" || die "couldn't parse $dir/wrangler.jsonc"
}

# hosted_placeholders [PATTERN]: dies listing every line of wrangler.jsonc that still holds a
# REPLACE_WITH placeholder (or, given PATTERN, only the ones matching it).
hosted_placeholders() {
  local pattern=${1:-REPLACE_WITH} hits rc=0
  hits=$(grep -n -- "$pattern" "$dir/wrangler.jsonc") || rc=$?
  if [[ $rc -eq 0 ]]; then
    echo "$hits" >&2
    die "placeholders remain in wrangler.jsonc (lines above); fill them in first ($HOSTED_README, \"Resource ids\")"
  elif [[ $rc -ne 1 ]]; then
    die "couldn't read wrangler.jsonc (grep exit $rc)"
  fi
}

# hosted_check_config JSON: the rules a deployable wrangler.jsonc follows. Each failure names the
# rule; the config is the compact JSON from hosted_config.
hosted_check_config() {
  local cfg=$1 problems
  hosted_defaults
  problems=$(jq -r --arg acct "$HOSTED_ACCOUNT_ID" --arg name "$HOSTED_WORKER" --arg d1 "$HOSTED_D1" \
    --arg no_routes "$HOSTED_NO_ROUTES" '
    def bound($v): ("MASTER_KEY_" + ($v | ascii_upcase)) as $b
      | any(.secrets_store_secrets[]?; .binding == $b);
    [
      (if .name != $name then "name must be \($name)" else empty end),
      (if .account_id != $acct then "account_id must be \($acct)" else empty end),
      (if $no_routes != "" and ((.routes // [] | length) > 0 or has("route")) then "no routes: \($no_routes)" else empty end),
      (if .workers_dev != false then "workers_dev must be false" else empty end),
      (if .preview_urls != false then "preview_urls must be false" else empty end),
      (if has("build") then "no build block: wrangler would run it with the deploy token in its environment; the build task builds without it" else empty end),
      (if .assets.run_worker_first != true then "assets.run_worker_first must be true: without it tenant hosts serve console assets" else empty end),
      (if .assets.binding != "ASSETS" then "assets.binding must be ASSETS" else empty end),
      (if (.vars.HOSTED_APEX // "") == "" then "vars.HOSTED_APEX must be set" else empty end),
      (.vars.HOSTED_ORIGIN_TEMPLATE // "" | if contains("{tenant}") | not then "vars.HOSTED_ORIGIN_TEMPLATE must be set and contain {tenant}" else empty end),
      (if (.vars.GITHUB_CLIENT_ID // "") == "" then "vars.GITHUB_CLIENT_ID must be set" else empty end),
      (if (.vars.OPERATOR_GITHUB_IDS // "") == "" then "vars.OPERATOR_GITHUB_IDS must be set" else empty end),
      (if (.vars | has("EDGEKMS_CONFIG")) or (.vars | has("ROOT_KEY")) then "EDGEKMS_CONFIG and ROOT_KEY must not be bound in hosted mode" else empty end),
      (if any(.secrets_store_secrets[]?; .binding == "ROOT_KEY") then "ROOT_KEY must not be bound in hosted mode" else empty end),
      (if .vars.SIGNUP_MODE | IN("closed", "invite", "open") | not then "vars.SIGNUP_MODE must be closed, invite or open" else empty end),
      (if (.vars | has("MAX_PENDING_INVITE_REQUESTS")) and (.vars.MAX_PENDING_INVITE_REQUESTS | tostring | test("^ *[0-9]+ *$") | not) then "vars.MAX_PENDING_INVITE_REQUESTS must be a whole number" else empty end),
      (.vars.MASTER_KEY_CURRENT // "" | if test("^m[1-9][0-9]*$") | not then "vars.MASTER_KEY_CURRENT must be m<n>" else empty end),
      (if (.vars.MASTER_KEY_CURRENT // "") as $c | $c != "" and (bound($c) | not) then "vars.MASTER_KEY_CURRENT (\(.vars.MASTER_KEY_CURRENT)) has no MASTER_KEY binding" else empty end),
      (if .vars | has("MASTER_KEY_PREVIOUS") then
         (.vars.MASTER_KEY_PREVIOUS | if test("^m[1-9][0-9]*$") | not then "vars.MASTER_KEY_PREVIOUS must be m<n>" else empty end),
         (if bound(.vars.MASTER_KEY_PREVIOUS) | not then "vars.MASTER_KEY_PREVIOUS (\(.vars.MASTER_KEY_PREVIOUS)) has no MASTER_KEY binding" else empty end),
         (if .vars.MASTER_KEY_PREVIOUS == .vars.MASTER_KEY_CURRENT then "MASTER_KEY_PREVIOUS equals MASTER_KEY_CURRENT" else empty end)
       else empty end),
      (.secrets_store_secrets[]? | select(.binding | startswith("MASTER_KEY_"))
        | (.binding | ltrimstr("MASTER_KEY_") | ascii_downcase) as $v
        | if ($v | test("^m[1-9][0-9]*$") | not) then "binding \(.binding) is not MASTER_KEY_M<n>"
          elif .secret_name != "edgekms-master-\($v)" then "binding \(.binding) must name the secret edgekms-master-\($v)"
          else empty end),
      (if ([.secrets_store_secrets[]?.store_id] | unique | length) > 1 then "every secrets_store_secrets entry must use the one store" else empty end),
      (if any(.d1_databases[]?; .binding == "TENANTS" and .database_name == $d1) | not then "d1_databases needs TENANTS -> \($d1)" else empty end),
      (if any(.kv_namespaces[]?; .binding == "REVOKED" and (.id // "") != "") | not then "kv_namespaces needs REVOKED with an id" else empty end),
      (if any(.r2_buckets[]?; .binding == "AUDIT" and (.bucket_name // "") != "") | not then "r2_buckets needs AUDIT with a bucket_name" else empty end),
      # The Worker allows a request when its limiter binding is missing, so the deploy refuses
      # a config without all five.
      ("LOGIN_LIMIT", "TOKEN_LIMIT", "AUTH_FAIL_LIMIT", "TENANT_LIMIT", "CONTROL_LIMIT") as $l
        | (if any(.ratelimits[]?; .name == $l and (.namespace_id // "") != "") | not then "ratelimits needs \($l) with a namespace_id" else empty end)
    ] | .[]' <<<"$cfg") || die "couldn't check wrangler.jsonc"
  if [[ -n $problems ]]; then
    printf '  %s\n' "${problems//$'\n'/$'\n'  }" >&2
    die "wrangler.jsonc breaks the rules above"
  fi
}

# The rows per master version in D1, as `wrangler d1 execute --json` returns them for
# hosted_check_wrap_keys: the rotation's "every row is rewrapped" check, for every version.
# shellcheck disable=SC2034 # used by the deploy task
HOSTED_WRAP_KEY_QUERY="SELECT wrap_key, count(*) AS n FROM (SELECT wrap_key FROM tenants UNION ALL SELECT wrap_key FROM system_keys) GROUP BY wrap_key"

# hosted_check_wrap_keys CONFIG_JSON D1_JSON: dies if a master version that rows in D1 are still
# wrapped under has no MASTER_KEY_M<n> binding in the config. The Worker imports only bound
# versions, so deploying without one makes every such row fail to load; that's what retiring a
# version before its rows are rewrapped does. D1_JSON is the output of
# `wrangler d1 execute --json --command "$HOSTED_WRAP_KEY_QUERY"`.
hosted_check_wrap_keys() {
  local cfg=$1 rows=$2 problems
  problems=$(jq -r --argjson cfg "$cfg" '
    ([$cfg.secrets_store_secrets[]?.binding]) as $bound
    | if (type != "array") or (.[0].results | type != "array") then error("unexpected d1 execute output") else . end
    | .[0].results[]
    | select(("MASTER_KEY_" + (.wrap_key | tostring | ascii_upcase)) as $b | $bound | index($b) | not)
    | "\(.n) row(s) in D1 are wrapped under \(.wrap_key | tojson), which has no MASTER_KEY binding in wrangler.jsonc"
  ' <<<"$rows") || die "couldn't read the wrap_key counts from D1"
  if [[ -n $problems ]]; then
    printf '  %s\n' "${problems//$'\n'/$'\n'  }" >&2
    die "deploying would leave those rows unable to unwrap; rewrap them first ($HOSTED_README, \"Master key rotation\")"
  fi
}

# hosted_migrations_present: the D1 migrations directory exists and holds at least one .sql file.
hosted_migrations_present() {
  local mdir=$edgekms_src/crates/edgekms-worker/migrations f
  for f in "$mdir"/*.sql; do
    [[ -f $f ]] && return 0
  done
  die "no D1 migrations in $mdir; nothing to apply"
}
