# Method-policy event gating — design (capture-fed, no upstream calls)

Status: DRAFT for review. Extends RD-1206 (method access policies). Client-agnostic;
Partior WorkflowCore is the motivating example only. Grounded in
`docs/partior-workflow-policy-resolver-handoff.md` + the Darwin CSV rules 71/72.

## 1. Problem & chosen approach

RD-1206 gates `eth_call` readers by a per-record captured audience. It does **not**
gate the record's **event logs** (or its transactions/receipts) — RD-1206 itself
lists this as a limitation, and `REDACTION_SPEC` §9 states a method policy gates the
getter only. So a workflow's events (`processPayment(msgId)` emitting logs) are today
gated only by event rules + per-tx `visibleTo`, which forces every writer to re-list
the audience on every transaction.

**Chosen mechanism (explicitly NOT the handoff's "policy-managed resolver"):** the
proxy makes **no extra upstream calls**. The audience is already captured locally at
write time (RD-1206 captures `visibleTo`/params/sender under a record key). We extend
the policy with an `events` section so that, on `eth_getLogs`, we:

1. decode the record key from the log (e.g. `msgId`),
2. look it up in the local `contract_record_captures` table,
3. admit the log only if the caller's DID / linked address is in that record's
   captured audience.

One client request still equals one node request; the only added work is a local,
batched DB lookup keyed by the record id already present in the log. This is generic:
"capture an audience under a record key; gate any event bearing that key to it" — no
`getParticipants`, no contract-specific names.

The on-chain resolver mode from the handoff (proxy calls `getParticipants(id)` itself)
is **rejected**: amplification, proxy load, timing-oracle re-analysis, and it drifts
toward client-specific. Capture-fed is also *more* correct for history: it uses the
audience as-of the record, not current on-chain membership.

## 2a. LOCKED schema (implementation contract)

No DB migration: events/transactions gating is **read-side only** against the existing
`contract_record_captures` table (the audience captured by the `capture` half). New Go
types in `internal/rbac/method_policy.go`:

```go
type RecordPolicy struct {
    Capture      []CaptureSpec     `json:"capture"`
    Access       []AccessSpec      `json:"access"`
    Events       []EventSpec       `json:"events,omitempty"`        // NEW — additive
    Transactions []TransactionSpec `json:"transactions,omitempty"`  // NEW — additive
}
type EventSpec struct {                 // gate a contract's event LOGS
    Event string      `json:"event"`    // canonical event sig "Name(t1,t2)"
    Key   KeySpec      `json:"key"`      // source "eventParam" (phase 1)
    Allow []AllowRule  `json:"allow"`    // captured-field / literal audience; no Return; where ok
}
type TransactionSpec struct {           // gate a tx (and its receipt envelope)
    Method string     `json:"method"`   // writer signature "processPayment(string,uint8)"
    Key    KeySpec     `json:"key"`      // source "param" (of the tx's own calldata)
    Allow  []AllowRule `json:"allow"`    // as above
}
```

`KeySpec` is reused; source is validated per context (`param` for capture/access/tx,
`eventParam` for events). Events/transactions have **no `onNoRecord`/`else`** — they are
additive (admit-or-abstain), and the strict parser rejects those fields if present.

Validation (extends `Validate`): event/method must exist in the ABI; the key param index
+ type must be canonicalizable AND **agree with the record's key type** (capture/access
already pin it — so an event's decoded key produces the exact `record_key` string capture
stored: the parity that makes the DB lookup hit); reject an **indexed dynamic** event key
param (unrecoverable from a topic — clear error at write time); extend the selector-owner
uniqueness check to event topic0s and tx selectors (one subject → one record type).

Example (Partior, generic fixture in tests):

```json
{ "records": { "payment": {
  "capture": [ {"method":"initiatePayment(string,(address,uint8)[],uint256)","key":{"source":"param","index":0},
                "remember":{"audience":{"source":"visibleTo","merge":"union"}}} ],
  "access":  [ {"method":"getPaymentInfo(string)","key":{"source":"param","index":0},
                "allow":[{"callerIn":["audience"]}],"onNoRecord":"deny","else":"deny"} ],
  "events":  [ {"event":"PaymentProcessed(string,uint8)","key":{"source":"eventParam","index":0},
                "allow":[{"callerIn":["audience"]}]} ],
  "transactions": [ {"method":"processPayment(string,uint8)","key":{"source":"param","index":0},
                "allow":[{"callerIn":["audience"]}]} ]
}}}
```

Shared decision (anti-drift): one `MethodPolicyDocument.EventAudienceAdmits(...)` in
`internal/rbac`, called identically by the RPC filter (via a `RecordAudienceGate` on
`TxVisibilityContext`) and the explorer (`CapturedAudienceResolver` wired at
`wireExplorerRedactor`); both server-side impls delegate to one helper so they cannot
diverge. `canonicalizeArg`'s per-value logic is extracted to `canonicalizeValue` so the
event-decoded key and the captured key canonicalize by the identical code.

## 2. Schema extension (narrative)

Add `events` to `RecordPolicy` (`internal/rbac/method_policy.go`, alongside
`Capture []CaptureSpec` and `Access []AccessSpec`):

```json
{
  "records": {
    "payment": {
      "capture": [ { "method": "initiatePayment(string,...)", "key": {"source":"param","index":0},
                     "remember": { "audience": {"source":"visibleTo","merge":"union"} } } ],
      "access":  [ { "method": "getPaymentInfo(string)", "key": {"source":"param","index":0},
                     "allow": [ {"callerIn":["audience"]} ], "onNoRecord":"deny","else":"deny" } ],
      "events":  [ { "event": "PaymentProcessed(string,uint8)",
                     "key": { "source": "eventParam", "index": 0 },
                     "allow": [ {"callerIn":["audience"]} ],
                     "onNoRecord": "deny", "else": "deny" } ]
    }
  }
}
```

- `event`: canonical event signature; resolved to topic0 (`findEventByTopic0`).
- `key.source`: `eventParam` (decode from the log) or `txInput` (decode from the parent
  tx calldata — the fallback for an **indexed dynamic** key, see §4).
- `allow`: **captured-field membership only** — logs have no "return", so no return
  resolver here. Reuses the shipped `matchCaptureSide()` matcher.
- Validation (extend `Validate()`): event must exist in the ABI; the key param
  index/type must exist and be canonicalizable; the event key type **must agree with
  the record's capture/access key type** (so the log's decoded key canonicalizes to the
  exact `record_key` string that capture stored — this parity is load-bearing); reject
  an indexed dynamic key param unless `source: txInput` is used.

## 3. Evaluation flow & insertion points

**RPC (`eth_getLogs`)** — `rbac.FilterEventLogs` (`internal/rbac/event_filter.go`).
The record-audience check is an **additive admit branch** (see §5): a log that the
existing paths already admit stays admitted. For a log the baseline would drop, when the
contract has an `events` rule matching the log's topic0 and the caller is contract-grant
eligible:
1. decode + canonicalize the record key (`canonicalizeArg`, same fn as capture);
2. `GetRecordCaptures(org, contract, recordType, recordKey)` → audience;
3. **admit** the log iff caller DID/linked-addr ∈ audience. A decode/lookup failure or an
   empty audience simply means "this branch does not admit" — the log falls through to the
   normal deny-by-default (it is never *un*-admitted, and never admitted on error).

**Receipt logs** — `FilterReceiptLogsWithEventRules` already delegates to
`FilterEventLogs`, so it inherits the gate for free.

**Explorer parity** — the same decision must run in `RedactionEngine.RedactLogs`
(`internal/explorer/redactor.go`). Wire ONE new resolver at the single wiring point
`wireExplorerRedactor` (`internal/server/explorer_event_rule_resolver.go`): a
`CapturedAudienceResolver` interface + `SetCapturedAudienceResolver`, mirrored into
`rbac.FilterEventLogs` via `TxVisibilityContext`, so RPC and explorer can't drift.
`TestExplorerRedactorWiring_FullStack` enforces every `Set*Resolver` is wired (reflection),
so it will fail until the new resolver is added to its expected list + a behavior case.

**Transactions/receipts (rule 72)** — bigger surface: `FilterTransactionByHash`,
`FilterBlockTransactions`, `FilterBlockReceipts` are today **address-only** (no ABI),
and the explorer tx lists go through `RedactTransactions`/`GetBatchVisibility`. Gating
those by record key is a separate, later phase (§7).

## 4. The load-bearing nuance: getting the key out of a log

- **Non-indexed key in event data** (Partior's `msgId` is in the event data): decode
  directly from `log.data` via the event ABI. **No extra call.** This is the clean path.
- **Indexed dynamic key** (`indexed string`/`bytes`): the topic holds only
  `keccak256(value)`, not the value — unrecoverable from the log. Options: (a) store the
  key's hash at capture and match hash-to-hash; (b) `source: txInput` fallback — decode
  the key from the parent transaction's calldata (the log carries `transactionHash`; the
  explorer log endpoint already has the parent tx's from/to, but the calldata needs a
  fetch). We reject silently-wrong behavior: if the key can't be recovered, **deny**.
- **Indexed static key** (`address`, `uint256`, `bytes32`): recoverable from the topic
  directly.

## 5. Precedence — the policy is ADDITIVE on the write-side surfaces

The write-side subjects (events, transactions, receipts) are **deny-by-default**: today
a log is seen only by the tx sender/receiver (RD-1162), the per-tx `visibleTo` parties
(RD-874), contract-grant + event-rule matches, and admins — everyone else is dropped.

So the record policy is an **additive admit path**, NOT a narrowing override (this is
the opposite of the `eth_call` reader gate, because the reader baseline is *permissive*
and must be narrowed, whereas the event baseline is *restrictive* and must be widened —
both converge on "the record's audience sees the record's data").

**Model:** admit a log if ANY existing path admits it (admin / `visibleTo`-unlock /
RD-1162 sender-participant / event rules) **OR** the caller is in the log's captured
record audience — with the record-audience branch **bounded by contract eligibility**
(the caller must already hold the contract grant, exactly like RD-874's "eligible listed
viewer"). The policy therefore:

- never removes a viewer the baseline already admits (sender/receiver/`visibleTo`/admin
  keep seeing);
- never admits anyone without contract eligibility (it cannot widen past the grant);
- only *adds* the record's own declared audience (captured from the initiating call).

It is a new OR-branch in `FilterEventLogs` / `RedactLogs`, positioned alongside the other
admit paths — no override of RD-1162 or `visibleTo`-unlock is needed, and admin bypass is
untouched. Non-policied contracts are completely unchanged.

**Dependency for rule 71:** additive-over-deny-by-default delivers "only participants see"
*because* the contract's event baseline is configured deny-by-default (Partior's config —
the coarse group establishes eligibility, not per-payment visibility). The policy adds the
record audience; it does **not** restrict an already-permissive event rule. If a client
wanted the policy to also *remove* baseline viewers, that would be a separate narrowing
mode — not required for rules 71/72.

## 6. Rule 71 / 72 verdict (against the Darwin CSV)

- **Rule 71 (events per workflowId): FULLY resolved** by this design, conditional on:
  (a) the key is non-indexed / recoverable, else hash-at-capture (§4); (b) the contract's
  event baseline is deny-by-default so the additive policy is the thing that admits the
  record audience (§5) — Partior's config; (c) explorer symmetry wired (§3). Partior's
  `msgId`-in-event-data hits the clean non-indexed path. Caveat vs the CSV's literal
  wording: we use the **captured** audience, not a live `getParticipants` call — equivalent
  when the declared audience mirrors the participant set, and strictly better for
  historical events. Flag for the client: a participant set that changes on-chain *after*
  the record is captured is not reflected (which is the correct historical behavior).
  Note the two modes are orthogonal and both supported: a client may instead call the
  gated `getParticipants` and repeat the DIDs in `visibleTo` (client-managed); this design
  adds the rules-managed way (link a prior call's captured audience to later events) so no
  `visibleTo` is needed on the later calls. The proxy never calls `getParticipants` itself.
- **Rule 72 (transactions per workflowId): resolvable, larger scope.** Needs record-key
  extraction from tx calldata applied to `getTransactionByHash`, `getBlockBy*`,
  `getBlockReceipts`, and the explorer tx lists — several of which are address-only today.
  Delivered in phases 3–4; must not be claimed "done" until block/list endpoints and the
  explorer agree (no hidden tx reintroduced).
- **Rule 20 (restrictive `privateFor`):** separate opt-in intersect mode, out of scope
  here (handoff phase 5); our closed-by-default model already satisfies the invariant.

## 7. Plan (rules 71 + 72 ship together, layered)

Decision: 71 and 72 land as one coherent delivery across RPC + explorer (a rule is not
"done" until every surface that exposes the subject agrees). Layers, in order:

1. **Schema + validation + engine (subject-agnostic core).** Add `Events []EventSpec`
   (and the tx/receipt key-extraction spec) to `RecordPolicy`; ABI validation (event/method
   lookup, key-type agreement with the record's capture key, indexed-dynamic handling); the
   additive capture-audience decision fn, keyed by a record id from a subject. Unit-tested,
   no server. Includes hash-at-capture storage for indexed-dynamic keys.
2. **RPC event surface (rule 71):** additive branch in `FilterEventLogs` (`eth_getLogs`) +
   receipt logs (inherits via `FilterReceiptLogsWithEventRules`). Bounded by contract
   eligibility; admit-only, fail-safe (§3/§5). No-anvil integration test: A/B/C see `pay1`
   events, D denied, non-policied contracts unchanged.
3. **RPC transaction/receipt surface (rule 72):** key from tx calldata → additive admit on
   `getTransactionByHash`, `getBlockBy*`, `getBlockReceipts` (these are address-only today,
   the bigger lift). Block/list endpoints must not reintroduce a hidden tx.
4. **Explorer parity (both rules):** one `CapturedAudienceResolver` + `SetCapturedAudienceResolver`,
   wired at `wireExplorerRedactor`, mirrored into the RPC path via `TxVisibilityContext`;
   extend `TestExplorerRedactorWiring_FullStack` (expected-setters + behavior) and add an
   RPC↔explorer parity case so they can't drift. Covers explorer log + tx/list surfaces.
5. **UI / simulator:** represent the `events`/tx sections + simulate a subject decision —
   after the backend schema + semantics are stable.

Rules 71 AND 72 are only claimed complete after layer 4 (RPC + explorer coherent). Each
layer: plan → adversarial audit → TDD → adversarial audit (RD-1206 rigor).

Out of scope (separate, optional): restrictive `privateFor` intersect mode (rule 20 literal
Tessera semantics); capturing the audience from a struct-array param like `Participant[]`
(a scalar/`visibleTo` capture covers Partior today — added only if a client wants the
audience straight from an on-chain array).

## 8. Security / correctness invariants

- **Fail closed:** undecodable key, missing/short data, canonicalization mismatch, lookup
  error, empty audience → **deny/drop the log**, never admit.
- **No upstream calls:** the gate reads only the local captures table + the log already
  fetched. Batch/dedup the lookup across logs sharing a key within one request.
- **Opaque:** a dropped log is indistinguishable from "no such log"; no record-existence
  or membership oracle beyond what the protected surface already reveals.
- **Never widens:** baseline group/method/grant/selector/KYC/tracing run first; the record
  gate only narrows. Admin/org-isolation boundaries enforced before the lookup (audience
  is org+contract scoped in the table key).
- **Canonicalization parity:** the event-decoded key MUST use the same `canonicalizeArg`
  path as capture, or the lookup silently misses → we treat a miss as deny, but validation
  should also enforce key-type agreement so misses aren't the norm.
- **Symmetry:** `TestExplorerRedactorWiring_FullStack` + a new RPC↔explorer parity case on
  a captured-audience log.

## 9. Decisions (resolved 2026-07-16)

1. **Precedence — RESOLVED: additive, not override.** The policy is an extra ADMIT path on
   the deny-by-default write surfaces (§5); sender/receiver/`visibleTo`/admin all keep
   admitting. Rule 71 is enforced because the event baseline is deny-by-default and the
   policy adds the record audience on top (bounded by contract eligibility).
2. **Indexed key — RESOLVED.** Non-indexed event-data keys and tx-calldata keys are
   first-class (no extra call). Indexed-dynamic keys on bare `eth_getLogs` use
   hash-at-capture (store `keccak(key)` at write time, match the topic) — folded into layer 1;
   no upstream call, no security regression. On any unrecoverable key: the additive branch
   simply doesn't admit (falls through to deny-by-default).
3. **Scope — RESOLVED: 71 + 72 ship together**, across RPC + explorer (§7).
4. **Audience source — RESOLVED: general param-linking.** Capture from a prior call's
   params / sender / `visibleTo` / return value and link to later subjects; no `visibleTo`
   on the later calls. Works today for scalar params + sender + `visibleTo`. Capturing from a
   struct-array param (`Participant[]`) is an optional additive extension (out of scope
   unless a client needs the audience straight from an on-chain array).

Orthogonality: the client-managed `getParticipants` + `visibleTo` path stays fully
supported and is independent of this feature; the proxy never invokes `getParticipants`
itself (the on-chain resolver mode from the handoff is rejected — load/amplification).
