#!/usr/bin/env bash
# Smoke probe for a deployment that must run the strict read privacy profile.
#
# Proves, against the RUNNING deployment, that:
#   1. the proxy reports PRIVACY_READ_PROFILE=strict and the org-admin audit
#      view as off (GET /api/v1/admin/system/read-profile);
#   2. a viewer who is NOT a participant of a known transaction — typically an
#      administrator of the contract the transaction called — receives no
#      transaction, receipt or trace for it over JSON-RPC;
#   3. optionally, the proxy-mode Explorer Data API hides it from that viewer.
#
# Run it from a host on the private network that can reach the proxy's admin
# and RPC endpoints (and, for step 3, the Explorer Data API).
#
# Required environment:
#   PROXY_URL      base URL of the proxy, e.g. http://privacy-proxy:8080
#   ADMIN_AUTH     value for the admin read: "X-Admin-Token: <token>" or
#                  "Authorization: Bearer <tier-2 admin JWT>"
#   VIEWER_JWT     access token of the non-participant viewer
#   TX_HASH        a transaction the viewer did not send and did not receive
# Optional:
#   RPC_PATH       JSON-RPC path, default /rpc (use /rpc/<org_id> if needed)
#   EXPLORER_URL   base URL of the Explorer Data API; enables step 3
#
# Exit status: 0 when every check passes, 1 otherwise. Tokens are never printed
# and never passed on a command line (curl reads them from private header files,
# so they do not show in the process list).

set -Eeuo pipefail

: "${PROXY_URL:?set PROXY_URL}"
: "${ADMIN_AUTH:?set ADMIN_AUTH}"
: "${VIEWER_JWT:?set VIEWER_JWT}"
: "${TX_HASH:?set TX_HASH}"
RPC_PATH="${RPC_PATH:-/rpc}"

failures=0
pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; failures=$((failures + 1)); }

# json_get FILE KEY — print the JSON encoding of the top-level KEY of the JSON
# body in FILE, "__absent__" when the key is missing, "__unparseable__" when the
# body is not a JSON object.
json_get() {
  python3 - "$1" "$2" <<'PY'
import json, sys
try:
    with open(sys.argv[1]) as fh:
        doc = json.load(fh)
    if not isinstance(doc, dict):
        raise ValueError
    print(json.dumps(doc[sys.argv[2]]) if sys.argv[2] in doc else "__absent__")
except Exception:
    print("__unparseable__")
PY
}

umask 077
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
# printf is a shell builtin: the tokens never appear in a process's arguments.
printf '%s\n' "$ADMIN_AUTH" >"$tmp/admin.hdr"
printf 'Authorization: Bearer %s\n' "$VIEWER_JWT" >"$tmp/viewer.hdr"

# 1. Effective profile.
code="$(curl -sS -o "$tmp/profile.json" -w '%{http_code}' -H @"$tmp/admin.hdr" "$PROXY_URL/api/v1/admin/system/read-profile")"
if [[ "$code" == "200" && "$(json_get "$tmp/profile.json" profile)" == '"strict"' ]]; then
  pass "proxy reports profile=strict"
else
  fail "proxy does not report profile=strict (HTTP $code)"
fi
if [[ "$(json_get "$tmp/profile.json" org_admin_view_user_txs)" == "false" ]]; then
  pass "org-admin audit view is off"
else
  fail "org-admin audit view is not reported as off"
fi

# 2. JSON-RPC: nothing about TX_HASH reaches the non-participant viewer.
rpc() {
  local method="$1" params="$2" out="$3"
  curl -sS -o "$out" -w '%{http_code}' -X POST \
    -H @"$tmp/viewer.hdr" -H 'Content-Type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}" \
    "$PROXY_URL$RPC_PATH"
}
for method in eth_getTransactionByHash eth_getTransactionReceipt; do
  rpc "$method" "[\"$TX_HASH\"]" "$tmp/$method.json" >/dev/null
  if [[ "$(json_get "$tmp/$method.json" result)" == "null" ]]; then
    pass "$method returns null to the non-participant"
  else
    fail "$method returned data (or an unexpected shape) to the non-participant"
  fi
done
rpc debug_traceTransaction "[\"$TX_HASH\"]" "$tmp/trace.json" >/dev/null
trace_result="$(json_get "$tmp/trace.json" result)"
if [[ "$trace_result" == "__absent__" || "$trace_result" == "null" ]]; then
  pass "debug_traceTransaction returns no trace to the non-participant"
else
  fail "debug_traceTransaction returned a trace to the non-participant"
fi

# 3. Explorer Data API (proxy mode), when reachable.
if [[ -n "${EXPLORER_URL:-}" ]]; then
  code="$(curl -sS -o "$tmp/explorer.json" -w '%{http_code}' -H @"$tmp/viewer.hdr" \
    "$EXPLORER_URL/api/v1/explorer/transactions/$TX_HASH")"
  if [[ "$code" == "404" ]]; then
    pass "explorer hides the transaction from the non-participant"
  else
    fail "explorer answered HTTP $code for the non-participant (expected 404)"
  fi
fi

if (( failures > 0 )); then
  printf '%d check(s) failed: the strict read profile is NOT in effect.\n' "$failures"
  exit 1
fi
printf 'All checks passed: the strict read profile is in effect.\n'
