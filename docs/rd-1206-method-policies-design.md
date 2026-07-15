# RD-1206 — Method Access Policies: per-record gating of record-reader calls

Design + implementation plan. Companion to `method-policy-generic-draft.md`
(repo root — the product-level draft with examples); this document pins the
implementable subset, the decision rationale against prior art, and the
security posture. Scope = **phase 1 + phase 2 of the draft** (return resolver +
capture resolver); field-level redaction outcomes and trace-derived capture are
deferred.

Revision 2 folds in the independent plan security audit (findings C1–C2,
H1–H3, M1–M4, L1–L3); the "Plan audit resolutions" section at the end records
each with its resolution.

## Why (decision trail)

- Contract grants authorize functions all-or-nothing (`ContractAccess.Functions`,
  three-state, `internal/rbac/access.go:1130-1195`); nothing binds a call to a
  *record*. Partior S5-T4 is the concrete case: any `payment` group member may
  read any `getPaymentInfo(paymentId)`.
- RD-1144 tried to protect returns with address-visibility field redaction →
  RD-1188 measured it blanking the record for its own payer/payee (S5-T2/T3
  regression) → **PR #391 reverted it "pending per-contract/method design"**.
  On main today, `eth_call` responses pass through unfiltered
  (`applyResponseFilter` has no eth_call case, `jsonrpc_processor.go:1014-1159`).
  This feature is that design; it ships with an RD-1188 regression test.
- Two resolvers unified (the negotiated middle): **capture** (remember
  `param(i)` / `sender` / `visibleTo` of writer calls under a record key;
  admits third parties like a per-payment settlement bank; works for readers
  whose returns carry no addresses) and **return** (decode the reader's own
  return, match caller against address outputs; works for records not created
  through captured flows). Union: either admits.
- RD-874 (CTO decision, 2026-05-04) is the precedent this composes with: *"bare
  visibleTo with no group membership ≠ access"*. Method policies **only
  narrow** — the method allowlist, contract grant, claims, function-selector
  list, and RD-915 tracing all run unchanged and first; a policy can never
  admit a caller those gates rejected, and its worst-case misconfiguration
  degrades to "no policy" = the grant's own coarse access, never more.

## Evaluation model

Per contract, one JSONB policy document, validated against the registered ABI
on write. Runtime evaluation for an authenticated `eth_call`, **after**
`CheckAccess` has already bound the caller to the contract's owning org
(grant resolution is per-org) and passed the method/grant/claim/function-selector
gates and RD-915 tracing:

```
policy load for (target contract)
  ├─ load error (DB/unmarshal)                      → DENY (fail closed)   [M1]
  ├─ no policy configured (NULL)                    → passthrough (unchanged)
  └─ policy present:
     match gated reader by function selector        [no match → passthrough]
     ownerOrg = GetContractOwnerOrgID(contract)
       └─ ownerOrg != request's resolved org        → DENY (fail closed)   [C1]
     decode record key from calldata (typed, canonical) [fail → DENY]
     resolve caller identity set = {caller DID} ∪ GetLinkedEthAddresses
       (lowercased; drop empty/zero values)                                [L3]

     CAPTURE stage (local, no upstream):
       rows = SELECT ... WHERE org_id=ownerOrg AND contract=... AND
              record_type=... AND record_key=key                          [C1]
       poison check: a set-once field with ≥2 distinct values → DENY      [H3]
       caller identity ∩ (captured DID/address values per allow rules)?
         → ALLOWED (still must forward to serve the real data)
     if ALLOWED or policy has NO return source:
         if ALLOWED → forward caller's own eth_call once, return response
         else       → opaque DENY, no upstream call
     else (not allowed, policy HAS a return source):
         forward the caller's own eth_call once  (never a synthesized call) [C2]
         decode the response's output tuple once, select the declared      [H2]
           address paths (bounded ≤128 KiB before unpack; hostile/oversize/
           wrong-typed return errors cleanly → DENY, no panic/OOM)
         caller identity ∩ decoded non-zero addresses? → return response
         else → opaque DENY
```

- **Opaque deny** = the standard error shape (`-32000`), no record-existence
  oracle: a denied real record and a nonexistent record answer identically.
- **Fail closed, every branch:** policy load error, owner-org mismatch, missing
  ABI, selector/key decode failure, capture-store error, oversize/failed return
  decode, set-once poison → deny. "No policy configured" (NULL) is the *only*
  passthrough; a load *error* is deny (M1 — the two are distinguished at the
  store layer: `(nil,nil)` vs `(_,err)`).
- **Zero/empty guard** (L3): `0x0…0`, empty DID, all-zero key/value never match
  a caller — neither in captured values nor decoded return fields.

### Timing — no per-record existence oracle (C2)

The threat: distinguishing "record exists, you're not on it" from "record
doesn't exist" by latency. Resolution, per policy shape:

- **Capture-only policy** (no return source): the decision is a single indexed
  DB lookup whose timing is independent of whether the record exists on chain
  or whether other rows exist for the key — a non-party's lookup returns zero
  matching rows identically in both cases. Deny short-circuits with no upstream
  call. No oracle. **This is the recommended default configuration.**
- **Policy with a return source:** every outcome — capture-hit allow, and both
  flavors of capture-miss (exists-but-not-party, doesn't-exist) — **forwards
  the caller's own eth_call exactly once** and then decides. Allow and deny
  therefore have the same observable profile (one forward, one decode). No
  per-record oracle.
- The remaining difference — capture-only (fast local deny) vs return-source
  (always forwards) — is a property of the **admin's fixed per-contract
  configuration**, not of any record or caller, so it is not a per-record
  existence oracle. Documented and test-locked (a companion timing/upstream-call
  test to the "zero upstream calls on capture-only deny" test).

**We forward the caller's own call, never a second one.** The return resolver
decodes the single response the node already produced for the caller's
`eth_call`; it does not synthesize an extra getter call. For a `view` getter
that means no on-chain side effect and no state exposure beyond what the node
computed anyway — we only gate whether that result reaches the caller. This is
also why same-org, intra-org, per-record isolation rests on **this resolver**,
not on RD-915: RD-915 only gates cross-org internal frames (same-org frames
pass without a grant unless `RUNTIME_TRACING_INTRA_ORG_GRANTS_ENABLED`), so the
return decode's fail-closed behavior is load-bearing (H2).

## Storage

- **Policy:** `contracts.method_policies JSONB NULL` — migration `070`
  (expand-only ADD COLUMN; `contracts` already carries app-role CRUD from `058`).
  NULL → feature off for the contract.
- **Captures:** operational table, migration `070`:

  ```sql
  contract_record_captures (
    id BIGSERIAL PRIMARY KEY,
    org_id UUID NOT NULL,                     -- in the key tuple, not just stored [C1]
    contract_address VARCHAR(42) NOT NULL,    -- lowercase 0x
    record_type TEXT NOT NULL,
    record_key TEXT NOT NULL,                 -- canonical typed string
    field TEXT NOT NULL,
    value TEXT NOT NULL,                      -- DID | lowercase 0x | scalar
    merge_mode TEXT NOT NULL,                 -- 'union' | 'set_once'
    source_tx_hash VARCHAR(66) NOT NULL,
    sender_did TEXT NOT NULL,                 -- for set-once poison detection [H3]
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, contract_address, record_type, record_key, field, value)
  );
  CREATE INDEX idx_crc_lookup ON contract_record_captures
    (org_id, contract_address, record_type, record_key);
  GRANT SELECT, INSERT, UPDATE, DELETE ON contract_record_captures TO privacy_proxy_app;
  GRANT USAGE, UPDATE ON SEQUENCE contract_record_captures_id_seq TO privacy_proxy_app;
  ```

- **Capture outbox:** `pending_record_captures`, migration `070`, mirroring
  `pending_tx_visibility` bookkeeping (attempt_count / last_attempt_at /
  last_error) but carrying the **pre-decoded** capture payload (JSONB
  field→values + merge modes + sender), since calldata is persisted nowhere
  today. **Its own GRANT block is required** (M3):

  ```sql
  GRANT SELECT, INSERT, UPDATE, DELETE ON pending_record_captures TO privacy_proxy_app;
  GRANT USAGE, UPDATE ON SEQUENCE pending_record_captures_id_seq TO privacy_proxy_app;
  ```

  Both tables are operational (full CRUD); both GRANT + sequence-grant blocks
  live **in migration 070 itself**, per the `058` new-table checklist. Migration
  header documents WHAT/WHY/ticket per the data-migration convention.

- **Merge semantics** (writer): `union` = `ON CONFLICT DO NOTHING` upsert;
  `set_once` = insert only when no row exists for `(org, contract, type, key,
  field)`; set-once reads resolve first-written (`ORDER BY id LIMIT 1`).
- **Set-once poison detection** (H3): if a `(org, contract, type, key, field)`
  ever holds **≥2 distinct set-once values from different senders**, the record
  key is treated as poisoned → **deny all reads for that key** (fail closed, not
  "trust first writer"). See the set-once trust model below.
- **Capture promotion is receipt-confirmed:** the reconciler promotes a pending
  capture only after the tx receipt exists with `status == 0x1` (batched
  upstream receipt lookup, RD-1162 style); reverted txs dropped with a logged
  reason, unmined retried via attempt bookkeeping. A *failed* `createPayment`
  must not plant set-once rows. (The plain visibleTo promoter is unchanged; this
  check is specific to capture.)

### Set-once trust model (H3)

Set-once identity capture (`payer := sender`, `payee := param`) is only sound
when the writer method **enforces one-creator-per-key on-chain** (reverts on
duplicate/foreign-key creation). If it does not, a same-org member who can call
the writer selector (they pass the coarse function grant — the very gap this
feature closes) could pre-create a record under a victim's key with
attacker-chosen identities. Three layers close this:

1. **High-entropy keys** (the identifier-as-capability model this feature
   serves): a record key is an unguessable secret. An attacker cannot
   front-run a key they cannot predict — the same property that makes reads
   safe makes poisoning infeasible. **Predictable/sequential keys are out of
   scope and must not be used** (documented operator precondition, same as the
   read side).
2. **Poison detection** (above): conflicting set-once writes → deny-all for
   that key. Worst case for a *predictable* key is denial-of-service on that one
   record, never disclosure.
3. **Return resolver is the recommended default for identity.** It reads live
   contract state (`getPaymentInfo` returns the actual on-chain payer/payee),
   so it is immune to capture poisoning. Capture set-once is opt-in, intended
   for the third-party/address-less-return case (settlement audience via
   `visibleTo`), where the return resolver cannot help.

## Policy schema (implementable subset)

As in the draft's "Policy draft": `records.<type>` with `capture[]` (method,
`key = {source: param, index}`, `remember` fields sourced `param(i)` |
`sender` | `visibleTo`, merge `set_once` | `union`) and `access[]` (method,
key, `allow[]` rules of `callerIn` over captured field names, literal
DID/address principals, and/or `{source:"return", paths, kind:"address"}`, an
optional `where` scalar condition per callerIn rule, `onNoRecord`, `else`). See
the addendum below for `where` and the simulator. Still deferred: field-level
redact outcomes and non-address return kinds.

**Validation at PUT** (reject-on-write; never at read):
- ABI registered; every method resolves to an ABI selector.
- Key param index in range and a canonicalizable type; **capture-side and
  access-side key types MUST match for a record type** (M2).
- Return `paths` name address-typed outputs (by name, or positional `"0"`/`"1"`).
- Every `callerIn` field name is declared by a capture entry of the same record
  type, or is a return source.
- Caps: policy ≤ 32 KiB; ≤ 16 gated methods/contract; ≤ 8 remembered
  fields/capture; captured audience ≤ 256 values/record (writer skips beyond
  cap + logs).

**Key canonicalization** operates on the **decoded typed value**, never the raw
calldata hex slice (M2): `string` verbatim; `address`/`bytes32` lowercase 0x;
`uintN`/`intN` decimal of the decoded big.Int (no leading-zero / hex-form
ambiguity). Because capture and access key types are validated equal, a
`string "0x01"` can never collide with a `bytes32 0x01`.

## Admin API & authorization (H1)

`PUT /api/v1/admin/orgs/{org_id}/contracts/{address}/method-policies`
(body `{"method_policies": {...}}` or `null` to clear); value returned in
`GET .../contracts/{address}`.

**Gated behind `requireSuperAdmin`** — matching `events-allow-dynamic-payload`,
**not** the tier-2 `denyOperatorOrgScoped` used by `visibleto-unlock` /
`createContractGrant`. Rationale: a method policy is the whole per-record
enforcement surface for a contract's reads; a malformed policy silently changes
the privacy posture for every caller and gives false confidence. This is the
same "affects every viewer, contract-wide privacy semantics, not a per-grant
decision" test that put `events-allow-dynamic-payload` behind super-admin. (A
policy can only *narrow*, so this is conservative rather than strictly
necessary for escalation-prevention — but the conservative default is correct
here, and provisioning already uses the super-admin token via
`provision-rbac.sh`. Relaxing to tier-2 would be a separate, explicit product
decision.)

Every mutation is **audit-logged with the full before/after policy JSON** at
`ResourceTypeContract` (change-management artifact), as
`events-allow-dynamic-payload` logs its flip. Swaggo-annotated following the
`.../visibleto-unlock` block; `make api-spec` regenerated byte-identically
(RD-1190 guard); openapi coverage gate stays green.

## Caller identity

Authenticated identity only: caller DID + `GetLinkedEthAddresses` (lowercased,
empty/zero dropped). `eth_call`'s `from` plays no role (RD-915 already rejects
spoofed `from`). A capture/audience match is evaluated **only for a caller who
has already passed `CheckAccess` on this contract this request** (L2) — a
captured-audience row is never the sole basis for access, mirroring RD-874's
load-bearing "grant link required" gate. Grant revoked but still in a stale
audience row → deny (CheckAccess fails first).

## What this deliberately does not change / surface asymmetry (L1)

- Method policies gate **only the `eth_call` getter**. The *same record's data
  reachable by other means* — the writer tx's emitted **event logs**
  (`eth_getLogs`, receipt logs), redacted per the existing event-rule engine —
  is **not** gated by the method policy. An operator who locks `getPaymentInfo`
  but whose `createPayment` emits a stakeholder-bearing event must gate that
  event separately (param rules / visibleTo). The REDACTION_SPEC section states
  this explicitly so a policy does not create false confidence.
- Explorer surfaces: `eth_call` has no explorer counterpart, so the RPC/explorer
  "must agree" invariant is unaffected (policies narrow an RPC-only surface,
  never touch `GetBatchVisibility`).
- RD-874 visibleTo event semantics: untouched. Capture *reads* the same per-tx
  audience at send time but stores its own rows; log filtering is not modified.
- RD-1183/#394 (receipt envelope): different code path; rebase-level conflicts
  only.

## Test plan (TDD order)

1. **Policy model + validation** (`internal/rbac`): valid draft example;
   unknown method; bad param index; non-address return path; oversize;
   unknown `callerIn`; **capture/access key-type mismatch → reject** (M2); key
   canonicalization per type incl. uint leading-zero + string-vs-bytes32
   non-collision (M2).
2. **Capture decode** (unit): calldata → fields for create/complete (param /
   sender / visibleTo); non-matching selector no-op; malformed calldata → error
   (enqueue skipped, logged).
3. **Capture store** (integration, real DB): union vs set_once; first-write;
   **org-scoped lookup + cross-org non-match** (C1); cap enforcement;
   **set-once poison (two senders, same key/field) → deny-all** (H3).
4. **Reconciler promotion** (integration): promotes on receipt status 1;
   retries while unmined; **drops on revert** (H3); attempt bookkeeping.
5. **Evaluation** (unit, table-driven): full outcome matrix — payer via
   capture-sender; payee via capture-param; settlement DID via
   capture-visibleTo; unrelated denied; cross-record denied (parameter-bound);
   **zero/empty guard** (L3); no-policy passthrough; **policy-load-error → deny**
   (M1); no-capture-rows + return resolver admits payer/payee; no-rows +
   no-return-source → deny **without forward (assert zero upstream calls)**;
   **return-source deny forwards exactly once, same profile as allow** (C2);
   **grant-revoked-but-in-audience → deny** (L2); ABI/decode errors deny;
   **oversized/hostile dynamic return → deny + bounded work** (H2).
6. **Processor e2e** (mockauth/e2e harness, real server path): Partior shape —
   provision policy via admin API (super-admin), send create/complete with
   visibleTo through the proxy, assert the S5 matrix incl. **S5-T2/T3 regression
   (parties read own record unredacted, RD-1188)** and **S5-T4 (unrelated with a
   known id denied)**; admin PUT validation errors; **tier-2 token rejected on
   the policy PUT** (H1).
7. **Coverage gates:** openapi coverage green; spec regen byte-identical.

## Rollout / ops

Policy configured before first traffic (or captures backfilled from indexed
history — operator note, no tooling here). High-entropy record keys required
(reads and set-once poisoning both). Docs site: one operator-focused page
(what to configure, expected behavior, the surface-asymmetry caveat — no engine
internals), same PR.

## Plan audit resolutions

- **C1 (cross-org key tuple):** `org_id` added to the capture UNIQUE constraint,
  the lookup index, and every `WHERE`; owner-org resolved via
  `GetContractOwnerOrgID` and **denied on mismatch** — self-enforcing, no longer
  reliant on the migration-035 single-owner invariant.
- **C2 (return-resolver timing oracle / RD-915 backstop):** forward the caller's
  own call exactly once; allow and deny share the profile; capture-only deny is
  oracle-free (DB-timing independent of chain state); same-org per-record
  isolation is this resolver's job, made load-bearing with H2.
- **H1 (admin tier):** raised to `requireSuperAdmin` + full before/after
  audit-log, rationale recorded.
- **H2 (hostile return decode):** input bounded ≤128 KiB *before* unpack;
  decode the output tuple once and select only the declared address paths; a
  hostile length-prefix, oversize, or wrong-typed slot errors cleanly (deny,
  no panic/OOM), verified by test. The guarantee is "bounded to the cap,
  fail-closed", not "one address per path".
- **H3 (set-once front-running):** high-entropy-key precondition + poison
  detection (deny-all on conflicting set-once) + return resolver as the
  recommended identity default; receipt-status-1 promotion already blocks failed
  txs.
- **M1 (load error vs no policy):** store distinguishes `(nil,nil)` from
  `(_,err)`; error → deny, only NULL → passthrough.
- **M2 (key collisions):** capture/access key types must match; canonicalize
  decoded typed value; collision tests.
- **M3 (GRANT compliance):** explicit GRANT + sequence grant for **both** new
  tables, in migration 070.
- **M4 (rate-limit/upstream):** single forwarded response decoded inside the
  existing concurrency window; never a second forward; reconciler receipt
  lookups reuse the bounded-batch pattern.
- **L1 (surface asymmetry):** documented in REDACTION_SPEC — policy gates the
  getter only, not the record's event logs.
- **L2 (audience vs revoked grant):** audience match only after CheckAccess;
  regression test.
- **L3 (zero/empty guard):** extended beyond zero-address to empty DID / zero
  key/value.

### Post-implementation audit (engine) — resolved

An independent adversarial review of the committed engine confirmed **no path
returns Allow=true when it shouldn't** (no disclosure/escalation); the gaps
were fail-closed/correctness in `Validate` plus one nil-receiver panic. Fixed:

- **C-1** — nil `*MethodPolicyDocument` now denies (no panic) in both
  `GatedReader` and `EvaluateAccess`.
- **H-1** — `Validate` rejects key/param types the runtime cannot
  canonicalize; `canonicalizeArg` now handles native `uintN`/`intN` (<256) and
  `bytesN`, so a common `uint64` key round-trips instead of silently bricking
  the record.
- **H-2** — `Validate` rejects a selector claimed by more than one record
  type (was a nondeterministic map-order authorization decision).
- **M-2** — read-side `decodeRecordKey` rejects an empty key, mirroring the
  writer.
- **L-1** — `AllowRule` unmarshaling rejects unknown fields inside/alongside
  `callerIn` (keeps the strict-parse posture).
- **L-2** — dead test helpers removed from the production file.

**Operator note (identity fields):** identity fields (payer/payee) MUST be
`set_once` and audience fields `union`. Marking an identity field `union`
disables the set-once poison protection for it — the operator docs state this;
Validate does not force it because `union` is legitimate for audience.

## Addendum — full-schema completion (where-conditions, invariants, simulator)

Scope decision (2026-07-15, Ivan): implement **everything in the generic
draft**, not just phases 1–2 — including Example 4 (`where` conditions) and
structured multi-capture/multi-reader authoring — and make correctness
guaranteeable for **any** authoring path (structured form OR raw JSON), because
raw JSON can otherwise express a schema-valid-but-unsafe policy the wizard would
block. Chosen approach: **extend our domain DSL** (not adopt OPA/Cedar — a
general engine adds expressivity = more ways to leak, and neither models our
capture-from-tx / return-resolver domain) + **all invariants in the backend
validator** + **a policy simulator**.

### Correctness model (the four levels)

1. Syntactic (valid JSON) — parser.
2. Structural (methods/params/returns resolve against the ABI) — `Validate`.
3. **Safety invariants** (deny-only outcomes; `callerIn` ⊆ captured∪return;
   `visibleTo`⇒`union`; unique field names; key = record id; `where` field is a
   captured scalar) — **must all live in `Validate`**, so raw JSON == wizard
   safety. Previously some lived only in the wizard (`validateWizard`); P1 moves
   them to the backend. The wizard keeps a mirror for instant feedback, but the
   backend is authoritative.
4. **Intent** (right people, no under/over-exposure) — *unprovable by any
   validator, for any authoring method*. Answered by **simulation**, mirroring
   mature authz practice (AWS IAM Policy Simulator, Cedar "validate + test",
   OPA coverage). This is why raw JSON is made safe not by forbidding it but by
   (a) full backend invariants and (b) a simulator run before trusting a policy.

Architectural floor that bounds the raw-JSON risk: the gate runs **after**
`CheckAccess` and can only turn an allowed response into a deny — so no policy
(however authored) can widen past the grant/allowlist or touch event rules. The
only residual risk is *wrong narrowing* (deny real parties / admit an
unintended captured field or return path) — exactly what the simulator surfaces.

### where-conditions (Example 4)

`AllowRule` gains an optional `where`:

```json
{ "callerIn": ["compliance-desk"],
  "where": { "field": "amount", "op": "gte", "value": "1000000" } }
```

- Semantics: the rule admits the caller only if `callerIn` matches **AND** the
  record's captured `field` satisfies `op value`. AND within a rule; rules are
  still OR'd.
- `field` MUST be a `remember`-ed field of the same record type (validated), and
  its captured value is compared as its canonical type. Numeric ops
  (`eq,neq,lt,lte,gt,gte`) compare as `*big.Int` (never lexical); `eq/neq` also
  work for string/address/bytes/bool by canonical-string equality.
- Fail-closed: field not captured for this record, value unparsable, or type/op
  mismatch → the rule does not admit (deny). `where` can only **further
  restrict** a rule, never widen it.
- Validate: `field` declared by a capture of the record; `op` in the allowed
  set; `value` parses for the field's inferred type; numeric op ⇒ numeric field.

### Simulator

Admin dry-run answering "who can read this record, and would caller X be
allowed?" — the intent check.

- `POST /api/v1/admin/orgs/{org}/contracts/{address}/method-policies/simulate`
  body `{record_type?, record_key, method, caller:{did, addresses[]}}`.
- Evaluates the **capture side** deterministically against stored rows +
  `where`; returns `{allow, matched_rule, captured:{field:[values]},
  return_resolver_note}`. The **return resolver is NOT simulated** (it depends
  on live contract state) — stated explicitly in the response so the operator
  knows a getter-returned address could additionally admit.
- Also returns the full captured admit-set for the record (payer/payee/audience
  values) so over/under-exposure is visible at a glance.
- Tier: `denyOperatorTenantRead` (same as the GET — reveals the org's own policy
  behavior + captured rows, not cross-org; not a mutation). No node call, so no
  eth_call side effect. Opaque on missing record (no cross-org existence probe).

### Structured multi-capture / multi-reader UI

The wizard becomes arrays: N capture specs (each: writer method + key + remember
rows) and N reader specs (each: reader method + key + allow rules incl.
optional `where`). This makes Examples 1 (both captures), 2, 3, 4 all
structured-form-authorable. Raw JSON is demoted to an optional advanced view
that is validated by the same backend `Validate` and can be simulated before
save. Everything compiles to the identical document schema.

### Out of scope (still deferred, per the draft's "Later")

- Field-level **redaction** as an access outcome (vs allow/deny).
- Capture from contract-to-contract **call traces**.
These remain the documented next phase; everything else in the draft is in.

### Future improvement — effective-dated / soft-deactivated policies (not yet scoped)

**Problem.** A policy today is a single mutable JSONB column; clearing it is a
hard removal. Because reader gates are evaluated **live** (no "as of block N"),
removing a *narrowing* policy silently **widens access to every historical
record at once** — records that were visible only to their parties become
readable by any member of a granted group the instant the policy is cleared.
That is a mass re-exposure of historical private data and a change-management /
audit concern (ISO 27001). Symmetrically, *adding* a policy narrows old records
(capture rows only exist from write-time forward; pre-policy records fall back
to the return resolver or become invisible).

**Idea (operator's request).** Don't delete policies — **deactivate** them, and
keep enforcing the version that was in force when a record was created, so
history reads exactly as it did. Optionally give policies a `effective_from` /
`effective_to` window (time-boxed access — e.g. a compliance DID that may read
only during an audit window, pairing with `where`).

**What it would take (per-record binding).** Reads are live, so "preserve
history exactly" requires versioning, not just dates:
- Store policy **versions** (new table, each with a stable id + `effective_from`
  / `effective_to`), instead of overwriting one column.
- Stamp each promoted capture row with the **policy version id** in force at
  capture time.
- On read, evaluate a record under the version bound to *its* capture rows, not
  the current document.

**Design tensions to settle first.**
- "Freeze history" cuts both ways: sometimes the operator *wants* a stricter new
  policy applied retroactively (tighten old records after a leak). The design
  should offer **retroactive vs forward-only** as an explicit choice, with the
  safe (more-restrictive) default.
- The **return resolver reads live chain state**, so effective-dating only fully
  governs the capture-based rules; return-based access is always "current."
- Hard-delete must still exist as a deliberate, audited action (data retention).

**Cheap interim (no schema change).** Removal is already audit-logged and the
"Clear policy" UI already warns that getters revert to group-readable. Until the
above lands, treat clearing a live narrowing policy as a reviewed
change-management step, not a casual toggle.
