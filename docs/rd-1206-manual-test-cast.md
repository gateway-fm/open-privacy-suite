# RD-1206 — manual test with `cast` (rules 70 / 71 / 72)

Send real RPC through the proxy **as each persona** and watch the per-record gate:
the record's parties can read it, everyone else is denied — on the getter (rule 70),
the event logs (rule 71) and the transaction (rule 72).

The proxy authenticates with a **Bearer JWT**, so every call carries
`--rpc-headers "Authorization: Bearer <token>"`. Auth itself is not JSON-RPC, so the
token is minted with `curl` (two-step mock login).

## 0. Setup

```bash
export PROXY=http://localhost:8280
export ORG=11111111-1206-4000-8000-000000000001
export RPC=$PROXY/rpc/$ORG
export CONTRACT=0x5fbdb2315678afecb367f032d93f642f64180aa3
# completePayment("PAY-1") tx, used for rule 72:
export TXHASH=0x746f349f2232e265e7d954618063d7cf3c90ca8aa549da282ab50af2b4774af2

# eth_call is shape-validated here (see §2), so pre-encode the getter calldata
# once and reuse it:
export P1=$(cast calldata "getPaymentInfo(string)" "PAY-1")
export P2=$(cast calldata "getPaymentInfo(string)" "PAY-2")

# Mint a JWT for a DID via the mock-login flow. Usage: TOKEN=$(mint did:test:alice)
mint() {
  local sid tok
  sid=$(curl -s -X POST "$PROXY/auth/request" -H 'Content-Type: application/json' \
        | python3 -c 'import sys,json;print(json.load(sys.stdin)["session_id"])')
  tok=$(curl -s -X POST "$PROXY/auth/verify" -H 'Content-Type: application/json' \
        -d "{\"session_id\":\"$sid\",\"jwz_token\":\"mock.$1\"}" \
        | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
  printf '%s' "$tok"
}
```

The parties of **PAY-1**: `did:test:alice` (payer), `did:test:bob` (payee),
`did:test:charlie` (settlement, via `visibleTo`). `did:test:diana` holds the *same
contract grant* but is **not** a PAY-1 party (she's the PAY-2 payer). `did:test:erin`
has no grant at all.

## 1. Pick a persona

```bash
export TOKEN=$(mint did:test:alice)        # alice | bob | charlie | diana | erin
export AUTH="Authorization: Bearer $TOKEN"
```

## 2. Rule 70 — the getter (`getPaymentInfo`)

> Use `cast rpc eth_call`, **not** `cast call`. This deployment runs eth_call
> runtime tracing, whose validator requires exactly `[{to,data}, block]` with no
> `from`. `cast call` injects a default `from`, so it is rejected with
> `400 "call denied: invalid request shape"`.

```bash
cast rpc eth_call "{\"to\":\"$CONTRACT\",\"data\":\"$P1\"}" latest \
  --rpc-url "$RPC" --rpc-headers "$AUTH"
```

* **Party** (alice/bob/charlie) → returns the record's ABI-encoded data (hex). Decode with
  e.g. `cast abi-decode "x()(uint256,uint256,address,address,uint256)" <hex>`.
* **Non-party** (diana/erin) → **errors** (`-32000 "not authorized to read this record"`;
  erin, with no grant, gets an opaque "method not found"). Neither leaks that PAY-1 exists.

Parameter-bound — a PAY-1 party is still denied a *different* record:

```bash
cast rpc eth_call "{\"to\":\"$CONTRACT\",\"data\":\"$P2\"}" latest \
  --rpc-url "$RPC" --rpc-headers "$AUTH"     # alice → error; diana (PAY-2 payer) → data
```

## 3. Rule 71 — the event logs (`eth_getLogs`)

```bash
cast rpc eth_getLogs \
  '{"address":"'"$CONTRACT"'","fromBlock":"0x0","toBlock":"latest"}' \
  --rpc-url "$RPC" --rpc-headers "$AUTH"
```

* **Party** → both PAY-1 logs (`PaymentCreated`, `PaymentCompleted`).
* **diana** → only her *own* PAY-2 log — **not** PAY-1's (same grant, disjoint record view).
* **erin** → denied.

## 4. Rule 72 — the transaction (`eth_getTransactionByHash`)

```bash
cast rpc eth_getTransactionByHash "$TXHASH" \
  --rpc-url "$RPC" --rpc-headers "$AUTH"
```

* **Party** → the transaction object.
* **diana / erin** → `null` (not disclosed).

## 5. All personas in one pass

```bash
for DID in did:test:alice did:test:bob did:test:charlie did:test:diana did:test:erin; do
  TOKEN=$(mint "$DID"); AUTH="Authorization: Bearer $TOKEN"
  echo "== $DID =="
  printf '  getPaymentInfo(PAY-1): '
  cast rpc eth_call "{\"to\":\"$CONTRACT\",\"data\":\"$P1\"}" latest --rpc-url "$RPC" --rpc-headers "$AUTH" 2>&1 \
    | head -c 80 | tr '\n' ' '; echo
  printf '  eth_getLogs:           '
  cast rpc eth_getLogs '{"address":"'"$CONTRACT"'","fromBlock":"0x0","toBlock":"latest"}' \
    --rpc-url "$RPC" --rpc-headers "$AUTH" 2>&1 \
    | python3 -c 'import sys,json
try:
    d=json.load(sys.stdin); print(len(d), "log(s)")
except Exception: print("denied/error")'
  printf '  getTransactionByHash:  '
  cast rpc eth_getTransactionByHash "$TXHASH" --rpc-url "$RPC" --rpc-headers "$AUTH" 2>&1 \
    | python3 -c 'import sys,json
try:
    d=json.load(sys.stdin); print("tx" if d else "null")
except Exception: print("null/denied")'
done
```

## Expected

| Persona | getPaymentInfo(PAY-1) | eth_getLogs | getTx(PAY-1) | why |
|---|---|---|---|---|
| alice   | ✅ data | ✅ 2 logs | ✅ tx | payer (party) |
| bob     | ✅ data | ✅ 2 logs | ✅ tx | payee (party) |
| charlie | ✅ data | ✅ 2 logs | ✅ tx | settlement, via `visibleTo` |
| diana   | ❌ error | ✅ **1** log (her PAY-2 only) | ❌ null | same grant, **not** a PAY-1 party |
| erin    | ❌ error | ❌ denied | ❌ null | no grant |

The point: **alice/bob/charlie and diana hold the same contract grant, yet see disjoint
data** — the gate is per-record, not per-contract.
