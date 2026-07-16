# Method Access Policy — Generic Extension (draft)

Extends `visibleto-contract-call-spec.md`. Same core idea — **access to a
method call is bound to a specific record (parameter), not to the method as a
whole** — generalized so that the *parameters, the sender, and the `visibleTo`
DIDs of one method call can be mapped, in an arbitrary way, onto calls of
other method(s)*. The return-based check from the original spec stays in as
one of the resolvers.

## Model

Two policy halves, both attached to a contract and expressed against its
registered ABI:

1. **Capture** (on writer methods): when a transaction calling this method
   passes the proxy, remember selected values under a **record key** taken
   from one of its parameters. Value sources:
   - `param(i)` — decoded calldata parameter;
   - `sender` — authenticated sender (DID; matches later via linked
     addresses);
   - `visibleTo` — the resolved DID list of that transaction.
2. **Access** (on reader methods): when an `eth_call` to this method arrives,
   extract the record key from *its* calldata, look up the captured record,
   and evaluate the rules. Rule sources: captured fields, and optionally
   address fields decoded from the call's **return** (the original spec's
   resolver). Outcome: **allow / deny** (field-level redaction of the
   response is a natural later extension of the same evaluation).

A policy never *widens* access: group grant + allowed methods are checked
first, exactly as today; the policy only narrows within them.

## Policy draft (JSON; the UI form compiles to this)

```json
{
  "records": {
    "payment": {
      "capture": [
        {
          "method": "createPayment(string,address,uint256)",
          "key": { "source": "param", "index": 0 },
          "remember": {
            "payer":    { "source": "sender",           "merge": "set-once" },
            "payee":    { "source": "param", "index": 1, "merge": "set-once" },
            "audience": { "source": "visibleTo",         "merge": "union" }
          }
        },
        {
          "method": "completePayment(string)",
          "key": { "source": "param", "index": 0 },
          "remember": {
            "audience": { "source": "visibleTo", "merge": "union" }
          }
        }
      ],
      "access": [
        {
          "method": "getPaymentInfo(string)",
          "key": { "source": "param", "index": 0 },
          "allow": [
            { "callerIn": ["payer", "payee", "audience"] },
            { "callerIn": { "source": "return",
                            "paths": ["payer", "payee"], "kind": "address" } }
          ],
          "onNoRecord": "deny",
          "else": "deny"
        }
      ]
    }
  }
}
```

Semantics:

- `key` correlates writer and reader calls: `createPayment("payment-123", …)`
  ↔ `getPaymentInfo("payment-123")`.
- `remember` fields are typed by their source (address, DID list, scalar).
  `merge` controls repeated captures for the same key: `set-once` (first
  write wins — identity fields cannot be rewritten later), `union` (audience
  accumulates), `overwrite`.
- `callerIn` matches the **authenticated** caller: their DID against DID
  values, their linked ETH addresses against address values. The `from` field
  of `eth_call` is ignored for authorization.
- The second `allow` rule is the original spec's resolver, kept as an
  additional source — payer/payee resolve from the record's return even if a
  capture row is missing for some reason.
- Everything fails closed: no capture row → `onNoRecord`; ABI missing, key
  not decodable, lookup error, return shape mismatch → deny. A record created
  *before* the policy was configured is simply not visible through the gated
  method (history is immutable; if needed, capture rows can be backfilled
  from the indexer).

## How it works

### Write path — `eth_sendRawTransaction` → `createPayment("payment-123", 0xBb…, 1001)`

```text
RBAC as today (group, method, grant, claims)      -> pass or deny, unchanged
tx accepted by node -> tx hash known
async reconciler (same one that lands visibleTo):
  decode calldata via registered ABI
  key       = "payment-123"
  payer     = sender DID        (did:partior:debtor)
  payee     = param(1)          (0xBb…)
  audience  = visibleTo DIDs    ([did:partior:settlement])
  upsert record row (contract, "payment", "payment-123")
```

`completePayment("payment-123")` later unions its `visibleTo` into
`audience` — parties can be added per payment, identity fields cannot be
rewritten (`set-once`).

### Read path — `eth_call` → `getPaymentInfo("payment-123")`

```text
RBAC as today                                      -> pass or deny, unchanged
policy matched by (contract, selector)
key = decode param(0) = "payment-123"
lookup record row; forward the eth_call upstream ONCE
evaluate:
  caller ∈ {payer} ∪ {payee} ∪ audience            -> allow
  else caller ∈ addresses decoded from the return   -> allow
  else                                              -> deny (opaque -32000)
allow  -> pass the node's response through unchanged
```

One upstream call total (the response is gated, not pre-flighted), plus one
local DB lookup.

## Examples

### Example 1 — Partior `getPaymentInfo` (the policy above)

The debtor creates the payment; the settlement bank is listed per payment:

```json
{
  "jsonrpc": "2.0",
  "method": "eth_sendRawTransaction",
  "params": ["0x<SIGNED_RAW_TX createPayment(\"payment-123\", 0xBb…, 1001)>"],
  "visibleTo": ["did:partior:settlement"],
  "id": 1
}
```

Captured row after the reconciler pass:

```text
(PaymentRegistry, "payment", "payment-123") ->
  payer    = did:partior:debtor        (sender)
  payee    = 0xBb…                     (param 1)
  audience = [did:partior:settlement]  (visibleTo)
```

Reads — all as `eth_call { to: PaymentRegistry, data: getPaymentInfo("payment-123") }`,
caller = the authenticated JWT identity:

| Caller | Matched by | Result |
| --- | --- | --- |
| debtor | captured `payer` (and return `payer`) | allow — full response |
| creditor | captured `payee` (and return `payee`) | allow — full response |
| settlement bank | captured `audience` — **not expressible from the return alone** | allow — full response |
| unrelated (same group, knows the id) | nothing | deny |

Deny is opaque and parameter-bound:

```json
{ "jsonrpc": "2.0", "id": 1,
  "error": { "code": -32000, "message": "not visible for getPaymentInfo(payment-123)" } }
```

and the debtor calling `getPaymentInfo("payment-456")` (someone else's
payment) is denied the same way — visibility for `payment-123` grants nothing
for `payment-456`.

### Example 2 — getter whose return contains no addresses

```solidity
function openTrade(string tradeId, address counterparty, uint256 amount) external;
function getTradeStatus(string tradeId) external view returns (uint8 status, uint256 filled);
```

The return-based resolver has nothing to compare against — but capture does:

```json
{
  "records": {
    "trade": {
      "capture": [{
        "method": "openTrade(string,address,uint256)",
        "key": { "source": "param", "index": 0 },
        "remember": {
          "initiator":    { "source": "sender",           "merge": "set-once" },
          "counterparty": { "source": "param", "index": 1, "merge": "set-once" },
          "audience":     { "source": "visibleTo",         "merge": "union" }
        }
      }],
      "access": [{
        "method": "getTradeStatus(string)",
        "key": { "source": "param", "index": 0 },
        "allow": [ { "callerIn": ["initiator", "counterparty", "audience"] } ],
        "onNoRecord": "deny", "else": "deny"
      }]
    }
  }
}
```

### Example 3 — one writer mapped onto several readers

Captured once from `registerInvoice`, applied to three different getters —
*the parameters + sender + visibleTo DIDs of one method mapped onto calls of
other methods*:

```json
{
  "records": {
    "invoice": {
      "capture": [{
        "method": "registerInvoice(bytes32,address)",
        "key": { "source": "param", "index": 0 },
        "remember": {
          "issuer":   { "source": "sender",           "merge": "set-once" },
          "debtor":   { "source": "param", "index": 1, "merge": "set-once" },
          "audience": { "source": "visibleTo",         "merge": "union" }
        }
      }],
      "access": [
        { "method": "getInvoice(bytes32)",
          "key": { "source": "param", "index": 0 },
          "allow": [ { "callerIn": ["issuer", "debtor", "audience"] } ],
          "onNoRecord": "deny", "else": "deny" },
        { "method": "getInvoiceHistory(bytes32)",
          "key": { "source": "param", "index": 0 },
          "allow": [ { "callerIn": ["issuer", "debtor"] } ],
          "onNoRecord": "deny", "else": "deny" },
        { "method": "getSettlementDetails(bytes32)",
          "key": { "source": "param", "index": 0 },
          "allow": [ { "callerIn": ["audience"] } ],
          "onNoRecord": "deny", "else": "deny" }
      ]
    }
  }
}
```

Note the per-getter granularity: the parties read the invoice and its
history; the settlement audience reads the invoice and the settlement
details, but not the history.

### Example 4 (later phase) — non-address captured values in conditions

Captured scalars can participate in rules, e.g. a compliance DID may read
only large payments:

```json
{
  "method": "getPaymentInfo(string)",
  "key": { "source": "param", "index": 0 },
  "allow": [
    { "callerIn": ["payer", "payee", "audience"] },
    { "callerIn": ["compliance-desk"],
      "where": { "field": "amount", "op": "gte", "value": "1000000" } }
  ],
  "onNoRecord": "deny", "else": "deny"
}
```

(`amount` here is `remember`-ed from `createPayment` param 2; syntax sketch —
this is the phase where the capture engine starts paying for itself beyond
identity checks.)

Authorization in every example is parameter-bound: each decision is made
against the one record the key resolves to.

## Configuration & operations

- Stored per contract next to the existing per-contract settings; set via
  `PUT /api/v1/admin/orgs/{org}/contracts/{address}/method-policies`
  (validated against the registered ABI: methods exist, param indexes and
  types match), read back via GET; UI form later — the form compiles to this
  JSON.
- Order of operations: configure the policy before first traffic (or backfill
  capture rows from the indexer).
- Denials are logged to the access log as today; the deny is opaque
  (indistinguishable from "no such record").

## Rollout

1. **Phase 1** — policy engine + the return resolver only (= the original
   spec; closes the Partior `getPaymentInfo` case).
2. **Phase 2** — capture engine (params / sender / visibleTo, merge rules,
   reconciler write path, indexer backfill) → third parties, address-less
   returns, arbitrary parameters.
3. **Later** — field-level redaction as an `access` outcome; capture from
   call traces for records created by contract-to-contract calls.

## Open questions (mostly UX — to settle before implementation)

- How the UI presents capture→access mapping so it is configurable without
  reading this document (this is the hard part).
- Merge-rule defaults (`set-once` vs `union`) per field type.
- Whether `audience` from a *later* writer call (e.g. `completePayment`)
  should retroactively widen read access to the whole record — current draft:
  yes (union), matching how `visibleTo` already behaves for that tx's logs.
- Limits: max remembered fields per record, max audience size (reuse the
  existing visibleTo cap), record-row retention.

## Implementation notes (as shipped — RD-1206)

Where the shipped implementation refines this draft:

- **Merge modes.** Only `set-once` and `union` are implemented; `overwrite` is
  intentionally omitted (a silent identity rewrite is exactly what `set-once`
  guards against — nothing needed it). `set-once` is enforced as *deny-on-conflict*:
  if two **distinct** values ever land for one (record, field), the key is treated
  as poisoned and all reads of it are denied (fail-safe against a front-running
  writer), rather than "first write silently wins".
- **Literal principals.** A `callerIn` entry that is not a captured field name
  must be a real principal — a DID (`did:…`) or an ETH address (`0x…`). The bare
  label `"compliance-desk"` in Example 4 is illustrative only; use a concrete
  principal such as `did:example:compliance-desk`. A non-field, non-principal
  entry is rejected at write time (a typo can't degrade into an inert literal).
- **Deny path / timing.** The reader's `eth_call` is always forwarded **once**,
  then the response is gated: allow passes it through unchanged, deny discards it
  and returns the opaque error. Allow and deny therefore share the same timing
  profile (no upstream-call oracle), and this includes the capture-only case.
- **Trace twin.** `debug_traceCall` executes the same getter, so it is gated by
  the same policy; the return-address resolver is neutralized when the call
  carries a state override (a forgeable return).
- **Limits (chosen).** 32 KiB per policy document · 16 gated methods · 8
  remembered fields/capture · 256 audience DIDs per writer call · 1024-byte
  record key. The capture outbox retries an unmined tx without counting it
  toward a dead-letter cap and reaps rows that never mine (24h) — a slow-to-mine
  tx is never abandoned before it lands.
- **Admin tier.** Configured by a **tier-2 org admin** (the operator token is
  rejected), same tier as the contract's grants / ABI / visibleTo-unlock. An ABI
  edit that would break a configured policy is rejected, so the gate cannot be
  silently disabled.
