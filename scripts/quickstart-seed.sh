#!/usr/bin/env bash
# Seeds (and verifies) the quickstart demo scenario against a running
# quickstart stack. Invoked by scripts/quickstart.sh; safe to re-run:
#
#   scripts/quickstart.sh --seed-only
#
# THE SCENARIO — two banks and a regulator share one chain:
#
#   Meridian Bank ─ Alice (operations, deploy claim)
#                 ├ Carol (analyst, query-only method allowlist,
#                 │        balanceOf restricted to self by a parameter rule)
#                 └ Mia   (org admin — unlocks the /admin dashboard)
#   Volta Bank    ─ Bob   (trader; no access to Meridian's contracts)
#   Regulator     ─ Rita  (no bank membership; sees Alice's activity only
#                          through an approved, audited disclosure grant)
#
#   Alice deploys the DEMO token through the proxy and pays Carol.
#   Carol can check her own balance but nobody else's (parameter-level rule).
#   Bob's bank cannot read Meridian's contract at all (cross-org isolation).
#   Rita requested access, Alice consented — every disclosed access is logged.
#
# All identities are mock-auth ("mock.<did>" tokens) with well-known anvil
# dev accounts. Nothing here is a real credential.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PROXY_URL="${PROXY_URL:-http://localhost:${HOST_PORT_PROXY:-8080}}"
ADMIN_API="${PROXY_URL}/api/v1/admin"
STATE_FILE=".quickstart-demo.json"
DEFAULT_ORG_ID="00000000-0000-0000-0000-000000000001"

color() { printf '\033[%sm%s\033[0m' "$1" "$2"; }
bold()  { color "1"    "$1"; }
green() { color "0;32" "$1"; }
yellow(){ color "0;33" "$1"; }
red()   { color "0;31" "$1"; }
blue()  { color "0;34" "$1"; }

if [[ -z "${ADMIN_API_TOKEN:-}" ]]; then
  for f in .env .env.quickstart; do
    if [[ -e "$f" ]] && grep -qE '^ADMIN_API_TOKEN=.+' "$f"; then
      ADMIN_API_TOKEN="$(grep -E '^ADMIN_API_TOKEN=' "$f" | tail -1 | cut -d= -f2-)"
      break
    fi
  done
fi
if [[ -z "${ADMIN_API_TOKEN:-}" ]]; then
  echo "$(red 'ERROR: ADMIN_API_TOKEN not set and not found in .env/.env.quickstart')" >&2
  exit 1
fi

# --- Personas (well-known anvil dev accounts — not real secrets) -------------
# The did:test: prefix matters twice: mock login skips the dev-admin
# auto-provisioning for it (personas keep exactly the org the story says),
# and the login page's dev identity picker lists did:test: users as
# one-click buttons.
ALICE_DID="did:test:alice"  ALICE_ADDR="0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
CAROL_DID="did:test:carol"  CAROL_ADDR="0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
BOB_DID="did:test:bob"      BOB_ADDR="0x90F79bf6EB2c4f870365E785982E1f101E93b906"
RITA_DID="did:test:rita"    RITA_ADDR="0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"
MIA_DID="did:test:mia"      MIA_ADDR="0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc"
MOCK_SIG="0xabababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab"

# --- HTTP helpers ------------------------------------------------------------
admin() { # admin <method> <path> [json-body]
  local method="$1" path="$2" body="${3:-}"
  if [[ -n "$body" ]]; then
    curl -sS -X "$method" "${ADMIN_API}${path}" \
      -H "X-Admin-Token: ${ADMIN_API_TOKEN}" -H "Content-Type: application/json" -d "$body"
  else
    curl -sS -X "$method" "${ADMIN_API}${path}" -H "X-Admin-Token: ${ADMIN_API_TOKEN}"
  fi
}

as_user() { # as_user <token> <method> <path> [json-body]
  local token="$1" method="$2" path="$3" body="${4:-}"
  if [[ -n "$body" ]]; then
    curl -sS -X "$method" "${PROXY_URL}${path}" \
      -H "Authorization: Bearer ${token}" -H "Content-Type: application/json" -d "$body"
  else
    curl -sS -X "$method" "${PROXY_URL}${path}" -H "Authorization: Bearer ${token}"
  fi
}

rpc() { # rpc <token> <method> <params-json> [org-id]  → full JSON-RPC response
  # With an org id the request goes to /rpc/<org_id>: required for requests
  # with no target contract (e.g. deploys) when the user belongs to more than
  # one org — mock logins always re-add the dev-admin org, so that is the norm
  # here. Target-addressed calls resolve their org from the contract instead.
  local path="/"
  [[ -n "${4:-}" ]] && path="/rpc/$4"
  curl -sS -X POST "${PROXY_URL}${path}" \
    -H "Authorization: Bearer $1" -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"$2\",\"params\":$3,\"id\":1}"
}

mint_token() { # mint_token <did> → JWT (mock login; creates the user on first use)
  local sid tok
  sid="$(curl -sS -X POST "${PROXY_URL}/auth/request" -H "Content-Type: application/json" | jq -r '.session_id // empty')"
  [[ -n "$sid" ]] || { echo "$(red "ERROR: /auth/request gave no session (is the stack up?)")" >&2; exit 1; }
  tok="$(curl -sS -X POST "${PROXY_URL}/auth/verify" -H "Content-Type: application/json" \
    -d "{\"session_id\":\"${sid}\",\"jwz_token\":\"mock.$1\"}" | jq -r '.access_token // empty')"
  [[ -n "$tok" ]] || { echo "$(red "ERROR: mock login failed for $1 (ALLOW_MOCK_LOGIN off?)")" >&2; exit 1; }
  printf '%s' "$tok"
}

# --- Setup helpers (idempotent: look up by slug/DID first) --------------------
ensure_org() { # ensure_org <slug> <name> → org id
  local slug="$1" name="$2" id
  id="$(admin GET "/orgs?limit=100" | jq -r --arg s "$slug" '(if type=="array" then . else (.data // []) end) | .[]? | select(.slug == $s) | .id' | head -1)"
  if [[ -z "$id" ]]; then
    id="$(admin POST "/orgs" "{\"slug\":\"${slug}\",\"name\":\"${name}\"}" | jq -r '.id // empty')"
  fi
  [[ -n "$id" ]] || { echo "$(red "ERROR: could not create org ${slug}")" >&2; exit 1; }
  printf '%s' "$id"
}

ensure_group() { # ensure_group <org-id> <slug> <name> <access-json> [create-extra-json] → group id
  # create-extra-json: extra top-level fields for the create body, e.g.
  # '"is_org_admin":true' (super-admin-only escalation — we hold X-Admin-Token).
  local org="$1" slug="$2" name="$3" access="$4" extra="${5:-}" id
  id="$(admin GET "/orgs/${org}/groups" | jq -r --arg s "$slug" '(if type=="array" then . else (.data // []) end) | .[]? | (.group // .) | select(.slug == $s) | .id' | head -1)"
  if [[ -z "$id" ]]; then
    id="$(admin POST "/orgs/${org}/groups" "{\"slug\":\"${slug}\",\"name\":\"${name}\"${extra:+,${extra}}}" | jq -r '.id // empty')"
  fi
  [[ -n "$id" ]] || { echo "$(red "ERROR: could not create group ${slug}")" >&2; exit 1; }
  admin PUT "/orgs/${org}/groups/${id}/access" "$access" >/dev/null
  printf '%s' "$id"
}

user_id_by_did() { # user_id_by_did <did> → user id
  admin GET "/users?search=$(printf '%s' "$1" | jq -sRr @uri)" \
    | jq -r --arg d "$1" '(if type=="array" then . else (.data // []) end) | .[]? | select(.external_id == $d) | .id' | head -1
}

setup_user() { # setup_user <did> <eth-addr> <group-id-or-""> <display-name>  → user id
  local did="$1" addr="$2" group="$3" name="$4" tok uid memberships
  tok="$(mint_token "$did")"
  uid="$(user_id_by_did "$did")"
  [[ -n "$uid" ]] || { echo "$(red "ERROR: user ${did} not found after login")" >&2; exit 1; }
  # note doubles as the display name in the login page's identity picker
  admin PUT "/users/${uid}" "{\"kyc\": true, \"note\": \"${name}\"}" >/dev/null

  # Personas belong to exactly the org the story says (or none, for the
  # regulator): drop the auto-assigned dev-admin/default-org memberships —
  # mock users get admin-level access through them in dev, and a second org
  # would leave the RPC org context ambiguous — then add the intended group.
  memberships="$(admin GET "/users/${uid}/memberships")"
  local def_mid
  for def_mid in $(printf '%s' "$memberships" | jq -r --arg o "$DEFAULT_ORG_ID" \
      '.[]? | select(.group.org_id == $o or .group.slug == "dev-admin-group") | .membership.id // empty'); do
    admin DELETE "/users/${uid}/memberships/${def_mid}" >/dev/null
  done
  if [[ -n "$group" ]]; then
    if ! printf '%s' "$memberships" | jq -e --arg g "$group" '.[]? | select(.group.id == $g)' >/dev/null; then
      admin POST "/users/${uid}/memberships" "{\"group_id\":\"${group}\"}" >/dev/null
    fi
  fi

  # Link the wallet (mock signature). Skip when this address is already linked.
  if ! admin GET "/users/${uid}/linked-addresses" | jq -e --arg a "$(printf '%s' "$addr" | tr '[:upper:]' '[:lower:]')" \
      '(.addresses // .data // []) | .[]? | select((.address // . | ascii_downcase) == $a)' >/dev/null 2>&1; then
    tok="$(mint_token "$did")" # re-mint after membership changes
    local nonce
    nonce="$(as_user "$tok" POST "/api/v1/eth/link/challenge" | jq -r '.nonce // empty')"
    if [[ -n "$nonce" ]]; then
      as_user "$tok" POST "/api/v1/eth/link/verify" \
        "{\"nonce\":\"${nonce}\",\"address\":\"${addr}\",\"signature\":\"${MOCK_SIG}\"}" >/dev/null
    fi
  fi
  printf '%s' "$uid"
}

wait_receipt() { # wait_receipt <token> <tx-hash> [org-id] → receipt JSON (or empty)
  local i resp
  for i in $(seq 1 15); do
    resp="$(rpc "$1" eth_getTransactionReceipt "[\"$2\"]" "${3:-}")"
    if [[ "$(printf '%s' "$resp" | jq -r '.result // empty')" != "" ]]; then
      printf '%s' "$resp" | jq -c '.result'
      return 0
    fi
    sleep 2
  done
  return 1
}

pad_addr() { printf '%064s' "$(printf '%s' "${1#0x}" | tr '[:upper:]' '[:lower:]')" | tr ' ' '0'; }

# =============================================================================
echo ""
echo "$(bold '==> Seeding the demo scenario: two banks + a regulator')"

if ! curl -sf "${PROXY_URL}/health" >/dev/null; then
  echo "$(red "ERROR: proxy not reachable at ${PROXY_URL} — run 'make quickstart' first")" >&2
  exit 1
fi

# --- Orgs + groups -----------------------------------------------------------
MERIDIAN_ID="$(ensure_org meridian-bank "Meridian Bank")"
VOLTA_ID="$(ensure_org volta-bank "Volta Bank")"

# Authorization model (RD-821/RD-853): the per-group METHOD ALLOWLIST decides
# what a group may call; contract grants decide what it may see. The only
# operational claims are deploy/upgrade/admin — there are no read/write claims.
OPS_GROUP="$(ensure_group "$MERIDIAN_ID" operations "Payment Operations" \
  '{"claims":["deploy"],"allowed_methods":["*"]}')"
ANALYSTS_GROUP="$(ensure_group "$MERIDIAN_ID" analysts "Compliance Analysts" \
  '{"claims":[],"allowed_methods":["eth_call","eth_blockNumber","eth_chainId","eth_getBalance","net_version"]}')"
TRADERS_GROUP="$(ensure_group "$VOLTA_ID" traders "Trading Desk" \
  '{"claims":[],"allowed_methods":["eth_call","eth_sendTransaction","eth_getBalance","eth_blockNumber","eth_chainId","eth_getTransactionReceipt","eth_getTransactionByHash","net_version"]}')"
# Org-admin group (unlocks the /admin dashboard for Mia). Invariants: claims
# must be empty (org admins get all claims automatically) and the method
# allowlist must be non-empty; creating it requires the super-admin token.
ADMINS_GROUP="$(ensure_group "$MERIDIAN_ID" administrators "Bank Administrators" \
  '{"claims":[],"allowed_methods":["eth_call","eth_getBalance","eth_blockNumber","eth_chainId","net_version"]}' \
  '"is_org_admin":true')"

echo "    $(green '✓') Meridian Bank ($MERIDIAN_ID)"
echo "    $(green '✓') Volta Bank    ($VOLTA_ID)"

# --- Users --------------------------------------------------------------------
ALICE_ID="$(setup_user "$ALICE_DID" "$ALICE_ADDR" "$OPS_GROUP" "Alice — Meridian operations")"
CAROL_ID="$(setup_user "$CAROL_DID" "$CAROL_ADDR" "$ANALYSTS_GROUP" "Carol — Meridian analyst")"
BOB_ID="$(setup_user "$BOB_DID" "$BOB_ADDR" "$TRADERS_GROUP" "Bob — Volta trader")"
RITA_ID="$(setup_user "$RITA_DID" "$RITA_ADDR" "" "Rita — Regulator")"
MIA_ID="$(setup_user "$MIA_DID" "$MIA_ADDR" "$ADMINS_GROUP" "Mia — Meridian admin")"
echo "    $(green '✓') Alice (Meridian operations), Carol (Meridian analyst), Bob (Volta trader), Rita (regulator), Mia (Meridian admin)"

ALICE_TOKEN="$(mint_token "$ALICE_DID")"
CAROL_TOKEN="$(mint_token "$CAROL_DID")"
BOB_TOKEN="$(mint_token "$BOB_DID")"
RITA_TOKEN="$(mint_token "$RITA_DID")"
MIA_TOKEN="$(mint_token "$MIA_DID")"

# --- Demo token contract -------------------------------------------------------
TOKEN_ADDR=""
if [[ -f "$STATE_FILE" ]]; then
  TOKEN_ADDR="$(jq -r '.token_address // empty' "$STATE_FILE")"
  if [[ -n "$TOKEN_ADDR" ]]; then
    # Reuse only if it is still registered to Meridian (i.e. same DB volume).
    if ! admin GET "/orgs/${MERIDIAN_ID}/contracts" | jq -e --arg a "$(printf '%s' "$TOKEN_ADDR" | tr '[:upper:]' '[:lower:]')" \
        '(if type=="array" then . else (.data // []) end) | .[]? | select(.address == $a)' >/dev/null; then
      TOKEN_ADDR=""
    fi
  fi
  if [[ -n "$TOKEN_ADDR" ]]; then
    # ... and only if the contract still has code on chain. The DB survives a
    # stack restart (postgres volume) but the dev chain does not (anvil is
    # in-memory) — a registered address with no code means the chain was
    # wiped, so deploy fresh instead of verifying against a ghost contract.
    if ! rpc "$ALICE_TOKEN" eth_getCode "[\"${TOKEN_ADDR}\",\"latest\"]" \
        | jq -e '.result and .result != "0x"' >/dev/null; then
      TOKEN_ADDR=""
    fi
  fi
fi

if [[ -z "$TOKEN_ADDR" ]]; then
  echo "    Deploying the DEMO token through the proxy (as Alice)…"
  BYTECODE="$(cat "$REPO_ROOT/scripts/quickstart-demo-erc20.bin")"
  DEPLOY_RESP="$(rpc "$ALICE_TOKEN" eth_sendTransaction \
    "[{\"from\":\"${ALICE_ADDR}\",\"data\":\"${BYTECODE}\",\"gas\":\"0x200000\"}]" "$MERIDIAN_ID")"
  TX_HASH="$(printf '%s' "$DEPLOY_RESP" | jq -r '.result // empty')"
  if [[ -z "$TX_HASH" ]]; then
    echo "$(red 'ERROR: token deployment was rejected:')" >&2
    printf '%s\n' "$DEPLOY_RESP" | jq . >&2
    exit 1
  fi
  RECEIPT="$(wait_receipt "$ALICE_TOKEN" "$TX_HASH" "$MERIDIAN_ID")" || { echo "$(red 'ERROR: no deploy receipt after 30s')" >&2; exit 1; }
  TOKEN_ADDR="$(printf '%s' "$RECEIPT" | jq -r '.contractAddress')"

  admin POST "/orgs/${MERIDIAN_ID}/contracts" "{\"address\":\"${TOKEN_ADDR}\",\"name\":\"DemoToken\"}" >/dev/null
  admin PUT "/orgs/${MERIDIAN_ID}/contracts/${TOKEN_ADDR}/abi" \
    "$(jq -n --rawfile abi "$REPO_ROOT/scripts/quickstart-demo-erc20.abi.json" '{abi: $abi}')" >/dev/null

  # Analysts may query balances — but only their own (parameter-level rule).
  admin POST "/orgs/${MERIDIAN_ID}/contracts/${TOKEN_ADDR}/grants" \
    "{\"group_id\":\"${ANALYSTS_GROUP}\",\"functions\":[{\"selector\":\"0x70a08231\",\"param_rules\":[{\"index\":0,\"must_be\":\"self\"}]}]}" >/dev/null

  # Alice pays Carol 1,000 DEMO through the proxy.
  TRANSFER_DATA="0xa9059cbb$(pad_addr "$CAROL_ADDR")00000000000000000000000000000000000000000000003635c9adc5dea00000"
  PAY_RESP="$(rpc "$ALICE_TOKEN" eth_sendTransaction \
    "[{\"from\":\"${ALICE_ADDR}\",\"to\":\"${TOKEN_ADDR}\",\"data\":\"${TRANSFER_DATA}\",\"gas\":\"0x30000\"}]" "$MERIDIAN_ID")"
  PAY_TX="$(printf '%s' "$PAY_RESP" | jq -r '.result // empty')"
  [[ -n "$PAY_TX" ]] && wait_receipt "$ALICE_TOKEN" "$PAY_TX" "$MERIDIAN_ID" >/dev/null || true
  echo "    $(green '✓') DemoToken at ${TOKEN_ADDR}; Alice paid Carol 1,000 DEMO"
else
  echo "    $(green '✓') Reusing DemoToken at ${TOKEN_ADDR}"
fi

# --- Disclosure: the regulator sees Alice only with Alice's consent -----------
GRANTS="$(admin GET "/disclosure/grants")"
if ! printf '%s' "$GRANTS" | jq -e --arg d "$RITA_DID" '(.grants // [])[]? | select(.request.requester_did == $d)' >/dev/null; then
  REQ_RESP="$(admin POST "/disclosure/requests" "{
      \"requester_did\": \"${RITA_DID}\",
      \"requester_user_id\": \"${RITA_ID}\",
      \"target_user_id\": \"${ALICE_ID}\",
      \"scope\": {\"disclosure_level\": \"full\"},
      \"reason\": \"Quarterly AML review of payment operations\",
      \"legal_basis\": \"Supervisory authority under the applicable AML framework\",
      \"expires_in_hours\": 720
    }")"
  REQ_ID="$(printf '%s' "$REQ_RESP" | jq -r '.id // empty')"
  if [[ -n "$REQ_ID" ]]; then
    as_user "$ALICE_TOKEN" POST "/api/v1/me/disclosure/requests/${REQ_ID}/approve" >/dev/null
    echo "    $(green '✓') Rita requested disclosure of Alice's activity — Alice approved (expires in 30 days)"
  else
    echo "    $(yellow '⚠') Could not create disclosure request:"; printf '%s\n' "$REQ_RESP" | jq . || true
  fi
else
  echo "    $(green '✓') Regulator disclosure grant already active"
fi

# =============================================================================
echo ""
echo "$(bold '==> Verifying the privacy story (live checks)')"
FAILURES=0
check() { # check <label> <pass|fail-expr result>
  if [[ "$2" == "pass" ]]; then
    echo "    $(green '✓') $1"
  else
    echo "    $(red '✗') $1"
    FAILURES=$((FAILURES + 1))
  fi
}

# 1. Alice reads her own balance through the proxy.
CALL_ALICE="$(rpc "$ALICE_TOKEN" eth_call "[{\"to\":\"${TOKEN_ADDR}\",\"data\":\"0x70a08231$(pad_addr "$ALICE_ADDR")\"},\"latest\"]")"
R="$(printf '%s' "$CALL_ALICE" | jq -r '.result // empty')"
if [[ -n "$R" && -n "$(printf '%s' "${R#0x}" | tr -d '0')" ]]; then V=pass; else V=fail; fi
check "Alice (deployer) reads her own DEMO balance → allowed" "$V"

# 2. Carol reads her own balance (grant allows balanceOf(self)).
CALL_CAROL="$(rpc "$CAROL_TOKEN" eth_call "[{\"to\":\"${TOKEN_ADDR}\",\"data\":\"0x70a08231$(pad_addr "$CAROL_ADDR")\"},\"latest\"]")"
R="$(printf '%s' "$CALL_CAROL" | jq -r '.result // empty')"
if [[ -n "$R" && -n "$(printf '%s' "${R#0x}" | tr -d '0')" ]]; then V=pass; else V=fail; fi
check "Carol (analyst) reads her OWN balance → allowed" "$V"

# 3. Carol tries Alice's balance — parameter rule must deny it.
CALL_CAROL_ALICE="$(rpc "$CAROL_TOKEN" eth_call "[{\"to\":\"${TOKEN_ADDR}\",\"data\":\"0x70a08231$(pad_addr "$ALICE_ADDR")\"},\"latest\"]")"
if printf '%s' "$CALL_CAROL_ALICE" | jq -e '.error' >/dev/null && ! printf '%s' "$CALL_CAROL_ALICE" | jq -e '.result' >/dev/null; then V=pass; else V=fail; fi
check "Carol tries ALICE's balance → denied (parameter-level rule)" "$V"

# 4. Bob (Volta Bank) cannot read Meridian's contract at all.
CALL_BOB="$(rpc "$BOB_TOKEN" eth_call "[{\"to\":\"${TOKEN_ADDR}\",\"data\":\"0x70a08231$(pad_addr "$BOB_ADDR")\"},\"latest\"]")"
if printf '%s' "$CALL_BOB" | jq -e '.error' >/dev/null && ! printf '%s' "$CALL_BOB" | jq -e '.result' >/dev/null; then V=pass; else V=fail; fi
check "Bob (Volta Bank) queries Meridian's token → denied (cross-org isolation)" "$V"

# 5. The disclosure grant for the regulator is active.
if admin GET "/disclosure/grants" | jq -e --arg d "$RITA_DID" '(.grants // [])[]? | select(.request.requester_did == $d)' >/dev/null; then V=pass; else V=fail; fi
check "Regulator's disclosure grant (Rita → Alice) is active" "$V"

# 6. Mia can open the admin dashboard: org admin of Meridian (and only Meridian).
if as_user "$MIA_TOKEN" GET "/api/v1/me/admin-status" \
    | jq -e --arg m "$MERIDIAN_ID" '.is_admin == true and (.admin_org_ids == [$m])' >/dev/null; then V=pass; else V=fail; fi
check "Mia (bank admin) unlocks the admin dashboard — org admin of Meridian only" "$V"

# 7. Explorer API serves data (only when the chain-indexer profile is up).
if [[ "${QUICKSTART_WITH_EXPLORER:-1}" == "1" ]]; then
  if curl -sS -H "X-Admin-Token: ${ADMIN_API_TOKEN}" "${PROXY_URL}/api/v1/explorer/blocks?limit=1" | jq -e '(if type=="array" then . else (.data // []) end) | .[]?' >/dev/null 2>&1; then V=pass; else V=fail; fi
  check "Explorer API serves indexed blocks" "$V"
fi

# --- Persist state for tooling (gitignored) -----------------------------------
jq -n \
  --arg proxy_url "$PROXY_URL" \
  --arg token_address "$TOKEN_ADDR" \
  --arg meridian_id "$MERIDIAN_ID" --arg volta_id "$VOLTA_ID" \
  --arg alice_id "$ALICE_ID" --arg carol_id "$CAROL_ID" --arg bob_id "$BOB_ID" --arg rita_id "$RITA_ID" --arg mia_id "$MIA_ID" \
  --arg alice_token "$ALICE_TOKEN" --arg carol_token "$CAROL_TOKEN" --arg bob_token "$BOB_TOKEN" --arg rita_token "$RITA_TOKEN" --arg mia_token "$MIA_TOKEN" \
  '{proxy_url: $proxy_url, token_address: $token_address,
    orgs: {meridian: $meridian_id, volta: $volta_id},
    users: {alice: $alice_id, carol: $carol_id, bob: $bob_id, rita: $rita_id, mia: $mia_id},
    tokens: {alice: $alice_token, carol: $carol_token, bob: $bob_token, rita: $rita_token, mia: $mia_token}}' \
  > "$STATE_FILE"

# =============================================================================
cat <<EOF

$(bold '================================================================')
$(bold ' Open Privacy Suite demo is up — two banks + a regulator, mock auth')
$(bold '================================================================')

  DEMO token:        ${TOKEN_ADDR}   (deployed by Meridian Bank)

$(bold 'Personas') — the login page lists them as one-click buttons:
  Alice  ${ALICE_DID}   Meridian ops     wallet ${ALICE_ADDR}
  Carol  ${CAROL_DID}   Meridian analyst wallet ${CAROL_ADDR}
  Bob    ${BOB_DID}     Volta trader     wallet ${BOB_ADDR}
  Rita   ${RITA_DID}    regulator        wallet ${RITA_ADDR}
  Mia    ${MIA_DID}     Meridian ADMIN   wallet ${MIA_ADDR}

Log in as Mia for the admin dashboard (org admin of Meridian — she sees only
her own bank): the user page shows an "Admin dashboard" button for accounts
that have access. The other personas are regular users — no button, and
/admin denies them with a link back to their own dashboard.

$(bold 'Fresh JWTs') (also in ${STATE_FILE}; re-mint any time with
'scripts/quickstart.sh --seed-only'):
  ALICE_JWT=${ALICE_TOKEN}
  CAROL_JWT=${CAROL_TOKEN}
  BOB_JWT=${BOB_TOKEN}
  RITA_JWT=${RITA_TOKEN}
  MIA_JWT=${MIA_TOKEN}

$(bold 'Try it — the same question, three viewers, three answers:')

  $(blue "# Carol checks her own balance (allowed):")
  curl -s ${PROXY_URL}/ -H "Authorization: Bearer \$CAROL_JWT" -H 'Content-Type: application/json' \\
    -d '{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"${TOKEN_ADDR}","data":"0x70a08231$(pad_addr "$CAROL_ADDR")"},"latest"],"id":1}'

  $(blue "# Carol tries ALICE's balance (denied — parameter rule):")
  curl -s ${PROXY_URL}/ -H "Authorization: Bearer \$CAROL_JWT" -H 'Content-Type: application/json' \\
    -d '{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"${TOKEN_ADDR}","data":"0x70a08231$(pad_addr "$ALICE_ADDR")"},"latest"],"id":1}'

  $(blue "# Bob, from the other bank, tries the same contract (denied — cross-org):")
  curl -s ${PROXY_URL}/ -H "Authorization: Bearer \$BOB_JWT" -H 'Content-Type: application/json' \\
    -d '{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"${TOKEN_ADDR}","data":"0x70a08231$(pad_addr "$BOB_ADDR")"},"latest"],"id":1}'

$(bold 'Drive it from an AI agent (MCP):') copy .mcp.json.example to .mcp.json,
set PRIVACY_ADMIN_TOKEN to the value of ADMIN_API_TOKEN in .env.quickstart,
then open this repo in Claude Code / Cursor and ask things like:
  "List the organizations and their groups"
  "Who can see the DemoToken contract, and why?"
  "Show the disclosure grants and their audit logs"

More: ONBOARDING.md (guided tour) · docs/mcp.md (all MCP tools)

$(bold 'Open these:')
  Web UI:            http://localhost:${HOST_PORT_UI:-5173}
  Proxy RPC + API:   ${PROXY_URL}
EOF

if [[ "$FAILURES" -gt 0 ]]; then
  echo "$(red "WARNING: ${FAILURES} verification check(s) failed — the demo may not behave as described above.")"
  exit 1
fi
