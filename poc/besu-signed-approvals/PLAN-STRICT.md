# Plan: strict V2 on Besu, so deployments stop being refused

Follow-up to [PLAN.md](PLAN.md) / [README.md](README.md). Two linked gaps close together:

- **Today:** `ops_prepareApproval` refuses any execution containing CREATE/CREATE2/SELFDESTRUCT, and
  OPS turns a `Prepare` error into `403` for the client. So with the Besu approval path enabled OPS
  refuses contract deployment — a *regression against OPS's own policy*, which allows deployment with
  the `deploy` claim. The Reth PoC does not have this gap: it falls back to the strict-V2 fingerprint
  for lifecycle transactions.
- **Cause:** strict V2 binds application state (storage read and written, code, contract nonces,
  balance deltas, logs, return data), which the Reth path gets from `debug_traceCall` +
  `prestateTracer{diffMode}`. Besu's `callTracer` has no `withLog`, and on this build
  `debug_traceCall` + `prestateTracer` answers `Internal error`.

**Approach: the plugin produces the state snapshots itself**, the same way it already produces the
call tree — from the execution it observes. Then *nothing* about the Go side changes: OPS keeps using
its existing `Fingerprint(calls, pre, diff)` encoder, and keeps recomputing and comparing before it
signs. The Java side must produce the same hash from the same three objects.

## What strict V2 hashes (`internal/nodeapproval/fingerprint.go`, authoritative)

`keccak256("OPS_EXECUTION_V2\0" ‖ canonical-json({"accounts": [...], "calls": {...}}))`, where the
canonical JSON is Go's `encoding/json` with `SetEscapeHTML(false)` and no trailing newline (Go sorts
object keys, so any encoder that sorts keys and emits compact JSON matches), capped at 1 MiB.

- `calls`: `normalizeCall` output — per frame `{calls, failed, from, input, logs, output,
  storageAddress, to, type, value}`; `value` is a 32-byte hex word; `input`/`output` lowercase hex;
  `logs` passed through verbatim from the trace; CREATE/CREATE2/SELFDESTRUCT allowed here.
- `accounts`: address-sorted, one entry per account that is a contract (code before or after, or any
  touched slot, or created in this transaction) **or** has a non-zero balance delta. Fields:
  `address`, `balanceDelta` (decimal, signed), `codeBefore`/`codeAfter` (keccak of the code),
  `nonceBefore`/`nonceAfter` (decimal, `"0"` for non-contracts), `storage` (slot-sorted
  `{after, before, slot}`, all 32-byte hex words).

Inputs are geth-shaped: `pre` = `prestateTracer` (balance/nonce/code/storage before), `diff` =
`prestateTracer{diffMode}` (`pre`/`post` with only the changed fields; an account present in
`diff.pre` but not in `diff.post` is deleted).

## What the plugin must observe, and how (Besu 26.8.1, verified)

| Fact | Source | Note |
|---|---|---|
| Account "before" values | first touch wins: `traceContextEnter` (caller + callee, before Besu transfers the call value), `tracePreExecution` for `SLOAD/SSTORE/BALANCE/EXTCODESIZE/EXTCODECOPY/EXTCODEHASH/SELFDESTRUCT` | anything that can change state is observed by one of these, so the touch set covers every change |
| Slot "before" | at the first `SLOAD`/`SSTORE` of that slot: `frame.getWorldUpdater().get(addr).getStorageValue(key)` | any earlier write in the same transaction would itself have been an observed `SSTORE`, so first touch is the pre-transaction value |
| "after" values | `traceEndTransaction(worldView, …)`: read balance/nonce/code/slots of the touched set from `worldView` | reverted frames are already rolled back at that point |
| Deleted accounts | `traceEndTransaction(selfDestructs)` plus EIP-6780 (`tracePreExecution` on `0xFF`) | an account in `selfDestructs` is emitted in `diff.pre` and omitted from `diff.post` |
| Created accounts, init code, deployed code | `traceContextEnter` on a `CONTRACT_CREATION` frame (`from`, `to`, init code as `input`, value) and its `traceContextExit` (`frame.getCode()`/world code after) | matches `normalizeCall`'s CREATE handling; `creationSets` on the OPS side needs the created address in `diff.post` |
| Logs per frame | `frame.getLogs()` at `traceContextExit`, minus each successful child's spliced-in subtree; a reverted frame reports none | Besu's own `callTracer` cannot do this; the plugin can |
| Return data per frame | `frame.getOutputData()` at `traceContextExit` | |

**Fees are excluded**, because the preflight block and the produced block have different base fees
and fee recipients, and the approval must survive that. *(Superseded by the revision below: rather
than computing the fee and subtracting it, the snapshot is taken over the application window only —
"before" at first touch, "after" at the root frame's exit — so the upfront charge cancels out of the
balance delta, and the refund and the fee recipient's credit both land after the window.)*

## Design

1. **`StateSnapshot`** — the touch set and its before/after values; builds the `pre` and `diff`
   objects in geth shape (lowercase hex keys, `0x`-prefixed values, storage keys 32-byte words).
2. **`ApprovalTracer`** gains: opcode hooks (`tracePreExecution`) for the storage/inspection opcodes,
   per-frame logs and output, `traceBeforeRewardTransaction`, and the fee parameters. Calls V3 keeps
   working unchanged (it ignores everything the snapshot collects).
3. **`StrictFingerprint`** — `CanonicalJson` (sorted keys, compact, no HTML escaping) + the account
   projection above + `keccak256("OPS_EXECUTION_V2\0" ‖ json)`. Shares the tree builder with
   `CallTreeJson`, extended with `logs`, `output`, and the lifecycle frame types.
4. **Mode choice** mirrors Go's `fingerprintForMode`: calls V3 unless the execution contains
   CREATE/CREATE2/SELFDESTRUCT, in which case strict V2 (`hashMode = 0`, approval domain
   `OPS_APPROVAL_V1`). `ops_prepareApproval` returns `calls`, `pre`, `diff`, `hashMode`; it no longer
   errors on lifecycle.
5. **`ApprovalSelector`** compares with the mode the approval carries: strict → `StrictFingerprint`,
   calls → `CallsFingerprint`. An approval whose mode does not match what the execution requires is a
   mismatch (e.g. a calls approval for an execution that turns out to deploy — scenario 15 today).
6. **OPS (`internal/nodeapproval/besu.go`)**: on `hashMode == 0`, recompute with the existing
   `Fingerprint(calls, pre, diff)`, refuse on any difference, and fill `FreshCreations`/
   `SurvivingCreations` from the existing `creationSets(trace, pre, diff)` so contract registration
   and the deploy-claim path work exactly as on the Reth branch. Root-frame envelope check extended:
   a deployment's root frame is a `CREATE` with `to` = the address `CreateAddress(sender, nonce)`.

## Tests, TDD order

**Java unit** (fail first, against the Go golden vector `internal/nodeapproval/testdata/fingerprint.json`):
1. `CanonicalJsonTest` — key sorting, compactness, no HTML escaping, nested arrays/objects, exact
   bytes for the golden `{"accounts":…,"calls":…}` object.
2. `StrictFingerprintTest` — the golden vector hashes to `expected`; each mutation (slot value, code,
   nonce, balance delta, log, output, an added/removed account) changes the hash; >1 MiB fails closed.
3. `StateSnapshotTest` — `pre`/`diff` construction from synthetic touches: read-only slot appears in
   `pre` and in neither side of `diff`; written slot appears in both; deleted account appears in
   `diff.pre` only; created account has `codeBefore` empty; fee-only touch of the fee recipient is
   dropped; the sender's fee is added back.
4. `ApprovalSelectorTest` — strict approval + matching strict execution → selected; storage-value
   change → mismatch; a calls-mode approval for a lifecycle execution → mismatch.

**Go unit** (`internal/nodeapproval/besu_test.go`): strict response recomputed and bound; plugin/OPS
disagreement refused; `SurvivingCreations` populated from `diff.post`; a deployment root frame that is
not `CREATE(sender, nonce)` refused.

**Integration** (real Besu, added to `run.py`):
| # | Scenario | Expected |
|---|---|---|
| A | plain deployment (`eth_sendRawTransaction` with init code) | approved in strict mode, included, code at the created address, OPS `SurvivingCreations` names it |
| B | runtime `CREATE` and `CREATE2` inside a call (`LifeFactory`) | approved and included; created addresses bound |
| C | `SELFDESTRUCT` (`Destructible.destroy`) | approved and included; balance swept; strict mode |
| D | deployment approved, then an earlier transaction in the same block changes the init-code path (`LifeFactory` target) | denied, nothing persisted |
| E | strict approval, application storage changed by an earlier transaction (shared counter) | denied — strict is deliberately state-exact |
| F | calls-mode approval for a transaction that gains a CREATE (existing scenario 15) | still denied |
| G | deployment on the Osaka chain beside Lineth's selector | included |

**Parity**: every preflight already re-encodes on the OPS side; scenarios A–C therefore double as
Go↔Java strict parity checks. Additionally a `run.py` check compares `ops_prepareApproval`'s `pre`/
`diff` against `debug_traceCall`'s `prestateTracer` output where Besu can produce it.

## Risks

- **Canonical JSON drift** — Go sorts map keys; my encoder must sort identically (byte-wise on UTF-8,
  which for our ASCII keys is the same). Covered by test 1 against the Go golden bytes.
- **Touch-set completeness** — if an account changes without a touch I observed, the snapshot is
  wrong and both sides would agree on a *wrong* hash. Mitigation: the producer compares against the
  approval, so a divergence between preflight and production execution is still caught; and the
  integration scenarios assert the actual on-chain state, not only the hashes.
- **Cost**: three more opcode cases in `tracePreExecution` (already on the traced path) plus a map
  lookup per touched slot. Measure with the benchmark, once it exists.
- **Not in scope**: strict mode as the *default* for ordinary calls (calls V3 stays the default, as
  on the Reth branch), and the `SELFDESTRUCT`-in-`selfDestructs` subtleties beyond EIP-6780.

## Revision after the critique

A critic pass against Besu's source found six blockers in the design above. The plan below is what
gets implemented; the differences are load-bearing, so they are spelled out.

| # | Finding | Decision |
|---|---|---|
| 1 | The sender's nonce is bumped and the upfront gas cost deducted *before* `traceStartTransaction` (`MainnetTransactionProcessor` ~:241/:256 vs :358), so "first touch" would record `nonce+1` and a fee-reduced balance | Snapshot the sender at `tracePrepareTransaction` (the only hook before both), and derive the fee from observed balances: `upfront = B@prepare − B@start`, `refund = B@beforeReward − B@lastApplicationTouch`. No gas arithmetic, no `gasUsed` ambiguity (EIP-7623 floor) |
| 2 | `traceEndTransaction` runs *before* `settleSelfDestructs` and `clearAccountsThatAreEmpty` (:623 → :632 → :636), so the world it hands us is not the committed state | The snapshot applies both itself: self-destructed accounts get the fork's settlement (balance-preserving fork → nonce 0, code empty, storage cleared; otherwise deleted), then any touched account that is empty (nonce 0, balance 0, no code) is deleted |
| 3 | The SELFDESTRUCT beneficiary is only on the stack; without reading it, its balance gain is invisible and both sides agree on a wrong hash | `tracePreExecution` on `0xFF` reads `frame.getStackItem(0)` and touches that address before the sweep |
| 4 | `MessageFrame.getLogs()` is cumulative — Besu copies child logs into the parent — while geth's `callTracer withLog` attributes a log only to the emitting frame | At each frame's exit, subtract the subtrees of the children that succeeded (Besu splices a child's logs into its parent only on success) and report nothing for a reverted frame |
| 5 | EIP-7702 delegations write code and nonces outside any frame and any tracer callback | `ops_prepareApproval` accepts only protected legacy and EIP-1559 transactions, so type 3 and type 4 can never obtain an approval and the producer drops them for the ordinary reason |
| 6 | If OPS believed the plugin's `hashMode`, a plugin bug could downgrade a lifecycle execution to calls-only | OPS derives the mode itself with the existing `fingerprintForMode` over the returned tree and refuses unless it equals the plugin's; the selector derives it from the *execution* and requires the approval to carry that mode |

Also applied: `logs` get a pinned schema (`{address, data, topics}` — geth's `position` is omitted,
and both sides use this same shape); code strings are lowercased before hashing and rejected unless
they parse as hex; the touch set is capped (4096 accounts, 16384 slots) and overflow fails the
transaction; `pre`/`diff` are decoded with
`UseNumber()` on the OPS side; the sender-is-also-fee-recipient case is handled additively (both
corrections apply to the same account); and the ASCII-key assumption behind sorted-key equivalence is
written down as a constraint in `CanonicalJson`.

**What proves the snapshot, not just the encoder** (the critique's sharpest point — the Go/Java
re-encode only shows the two encoders agree on the same input): after the block is mined, the harness
re-reads every account and slot the plugin reported in `diff.post` through `eth_getCode`,
`eth_getTransactionCount`, `eth_getStorageAt` and `eth_getBalance` and requires them to match
(the sender is exempt, since the chain balance also carries the gas fee the snapshot excludes). Every denial scenario gets a positive control: the same setup with the divergence
removed must be included.
