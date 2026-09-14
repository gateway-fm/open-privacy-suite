# Besu signed-approvals PoC — plan

Branch `poc/ops-besu-signed-approvals`. Base: the OPS-side signed-approval code copied from the
`poc/ops-reth-signed-approvals` working tree (first commit on this branch), on top of `7172795`.
Research and API verification: `docs/research/dsl-policy-and-node-enforcement/ops-besu-integration-2026-09-14/RESEARCH.md`.

## Decisions taken (recommended options from the research, unless Ivan objects)

| Question | Decision | Why |
|---|---|---|
| Who computes the preflight fingerprint | **The plugin** (`ops_prepareApproval`), OPS recomputes from the returned call tree and refuses on mismatch | Same Java tracer at preflight and block time; Go encoder stays the reference; every preflight is a parity check |
| Lifecycle txs (CREATE/CREATE2/SELFDESTRUCT) | **Rejected** in phase 1: `ops_prepareApproval` errors, so OPS denies before forwarding; a lifecycle op reached during block building is rejected (`OPS_APPROVAL_UNSUPPORTED`) | Strict V2 needs opcode-level tracing on Besu; no new approval domain invented for the PoC |
| Test node | Official Besu **26.8.1** release tarball as a post-merge execution client, the harness playing the consensus client over the Engine API; plugin built against Cloudsmith `26.8.1-d97cbd6` | Besu 26.x removed Clique block production. The Lineth-pinned commit `efa817c` differs from 26.8.1 only by nullability annotations in the selection code (GitHub compare, verified). Lineth's own sequencer plugin is not built here — coexistence is a follow-up |
| Delivery | Same TCP framing and Ed25519 batches as the Reth PoC | Zero change to `internal/nodeapproval` delivery |
| Block driver | Engine API (`forkchoiceUpdatedV2` with attributes → one `getPayloadV2` → `newPayloadV2`), as Maru drives Besu in Lineth | `engine_getPayload` finalises the proposal in Besu, so the harness waits for the selector's decision log before calling it once |

## Facts the design rests on (all verified in source, see RESEARCH.md §3)

- `BlockTransactionSelector` executes each candidate on a child `WorldUpdater` and commits only on
  `SELECTED`; not-selected → `rollback()`. `invalidTransient` keeps the tx in the pool, `invalid`
  removes it. `SkipSenderTransactionSelector` handles later nonces of a skipped sender.
- `PendingTransaction.getAddedAt()` is `System.currentTimeMillis()` at pool admission.
- `traceContextEnter/Exit(MessageFrame)` fire for every frame incl. root and precompiles;
  `frame.getContractAddress()` = code address, `getRecipientAddress()` = storage context,
  `getValue()` = 0 for STATICCALL/DELEGATECALL (`DelegateCallOperation.value` returns `Wei.ZERO`),
  parent op name from `parentFrame.getCurrentOperation().getName()` ∈ {CALL, CALLCODE, DELEGATECALL,
  STATICCALL, CREATE, CREATE2}. Insufficient-balance/too-deep CALLs create no frame.
- `TransactionSimulationService.simulate(tx, stateOverrides, pendingBlockHeader, tracer, params)` and
  `RpcEndpointService.registerRPCEndpoint("ops", …)` exist; `TransactionDecoder.decodeOpaqueBytes`
  decodes raw transactions; `Hash.keccak256` (besu-crypto-algorithms) is on the runtime classpath.
- Multiple plugin selector factories are aggregated; `--plugins=` + default
  `--plugin-continue-on-error=false` is fail-closed.

## Fingerprint mapping (calls V3, must equal `internal/nodeapproval/call_fingerprint.go`)

Per frame record, in enter order, with `parent` = index of the enclosing record (`0xffffffff` for root):

| Field | Go (from geth-shaped callTracer JSON) | Java (from `MessageFrame` at `traceContextEnter`) |
|---|---|---|
| kind | type CALL=1, STATICCALL=2, DELEGATECALL=3, CALLCODE=4; anything else → error | root → CALL; else parent's current op name; CREATE*/creation frame → lifecycle error |
| from | `from` | root: `frame.getSenderAddress()`; else `parent.getRecipientAddress()` |
| to | `to` | `frame.getContractAddress()` |
| storageAddress | `to`, or parent storage for kinds 3/4 | `frame.getRecipientAddress()` |
| code hash | keccak(prestate code of `to`), empty → keccak("") | `frame.getCode().getCodeHash()` |
| value | `value` (absent → 0) | `frame.getValue()` |
| failed | `error != null`, set at exit | `frame.getState() == COMPLETED_FAILED` at `traceContextExit` |
| input | `input` | `frame.getInputData()` copy |
| limits | 128 calls, 1 MiB | same |

Encoding: `"OPS_CALLS_V3\0"` ‖ u32 count ‖ per record: u32 parent ‖ u8 kind ‖ from ‖ to ‖ storage ‖ code
hash ‖ u256 value ‖ u8 failed ‖ u32 len ‖ input; keccak256 of the whole buffer.
SELFDESTRUCT and CREATE/CREATE2 are flagged at `tracePreExecution` by opcode (0xFF, 0xF0, 0xF5), because
under EIP-6780 a SELFDESTRUCT of a pre-existing contract never reaches `traceEndTransaction(selfDestructs)`
and a CREATE that fails before a frame exists never reaches `traceContextEnter`.

`ops_prepareApproval(rawTx)` simulates on the head state in the **pending block's** header context
(`simulatePendingBlockHeader`), the same context the producer will use, and returns `{hashMode:3, chainId,
txHash, parentBlockHash, pendingBlockNumber, fingerprint, calls: <geth-shaped tree from the same records>,
codeHashes: {to → hash}, status, gasUsed}`. OPS runs `normalizeCall` + `CallFingerprint` on
`calls`/`codeHashes`, checks that the root frame is the signed envelope (CALL, sender, to, input, value),
and refuses if the hashes differ.

## Plugin components (Java 25 — Besu 26.x requires it — Gradle, `poc/besu-signed-approvals/`)

Written before implementation; the code kept the roles and adjusted a few names (noted in brackets).

| Class | Role | Unit test |
|---|---|---|
| `Approval` (record) | item layout (`OPS_APPROVAL_V1\0`/`V3\0`, 120 bytes) | golden `batch.json`/`call-batch.json` from Go |
| `ApprovalBatch` [was `BatchDecoder`] | frame → `OPS_APPROVAL_BATCH_V1\0` ‖ u32 n ‖ items ‖ 64-byte sig; rejects bad size/domain/mode | golden + tamper cases |
| `ApprovalVerifier` | JDK Ed25519 verify against the configured public key (the chain-id filter lives in `ApprovalListener.accept`) | golden signature, wrong key |
| `ApprovalStore` | `ConcurrentHashMap<Hash, Entry>`, capacity with unpooled-first eviction, orphan TTL, `removeAll` | capacity/TTL/idempotence |
| `ApprovalListener` | `ServerSocket`, ≤32 connections, 16 KiB frame cap, one reader thread per connection | socket round trip with Go-signed frame |
| `CallRecord`, `CallsFingerprint` | encoder (above) | golden `call-v3.json` `expected_calls`; each tamper case from `call_hash.rs` tests |
| `CallTreeJson` | records → geth-shaped tree | round trip through the Go encoder (integration) |
| `ApprovalTracer` | `BlockAwareOperationTracer` → records; lifecycle flag | integration (real EVM) + OPS cross-check on every prepare |
| `ApprovalSelector`, `ApprovalSelectorFactory` | pre: approval? else pending/timeout; post: fingerprint compare | fake `TransactionEvaluationContext`/`PendingTransaction` |
| `PrepareApprovalRpc` | `ops_prepareApproval` via `TransactionSimulationService` | integration |
| `OpsApprovalPlugin` | `@AutoService`, PicoCLI options, service wiring, fail-closed start | integration (missing option → exit) |

Options: `--plugin-ops-approval-listen`, `--plugin-ops-approval-public-key`, `--plugin-ops-approval-chain-id`,
`--plugin-ops-approval-wait-ms` (5000), `--plugin-ops-approval-capacity` (100000),
`--plugin-ops-approval-max-connections` (32), `--plugin-ops-approval-orphan-ttl-ms` (300000).

## OPS-side change

`internal/nodeapproval`: `Prepare` dispatches on `OPS_APPROVAL_NODE=besu` to `prepareBesu`, which calls
`ops_prepareApproval`, recomputes the fingerprint with a code-hash variant of `CallFingerprint`, and builds
`Prepared` (Trace, CodeHashes, NoCodeRecipients, PlainValueTransfer; creations empty). Unit test with a
fake RPC server; a mismatch between plugin and Go fingerprints must fail closed.

## Integration scenarios (`run.py`, real Besu 26.8.1 + plugin + Go client using OPS `Prepare`)

| # | Scenario | Expected |
|---|---|---|
| 1 | approval before tx, A→A→A | receipt status 1, vault A = 7 |
| 2 | tx before approval (approval 1 s later) | included; not in the block before the approval |
| 3 | no approval | no receipt; tx gone from pool after wait; sender nonce unchanged |
| 4 | same-block target change after preflight (setTarget(B) then run) | setTarget included; run excluded; nonce/balance of Alice unchanged; approval retained until timeout cleanup |
| 5 | caught inner failure (`runCatch`) after target change | excluded |
| 6 | delegatecall path (`runDelegate`) | included; fingerprint has kind 3 with A's storage |
| 7 | approval with correct signature but wrong fingerprint | excluded, pool removal, nonce unchanged |
| 8 | invalid signature / wrong chain id / duplicate batch | ignored; duplicates do not extend the wait |
| 9 | 8 txs approved against one shared counter state | all included (calls V3) |
| 10 | CREATE (deployment) | `ops_prepareApproval` error → OPS refuses; unapproved tx dropped |
| 11 | node restart with a pending approved tx | approval lost → dropped after wait; resubmission after new prepare succeeds |
| 12 | plugin missing from `--plugins` list; plugin without options | Besu refuses to start (log evidence) |
| 13 | cross-check: Go fingerprint from Besu `debug_traceCall callTracer` + `eth_getCode` equals the plugin's | equal (asserted; callTracer-vs-frames parity on a simple path) |
| 14 | runtime CREATE inside a call; SELFDESTRUCT | both refused at preflight; the unapproved SELFDESTRUCT tx is dropped |
| 15 | approved `maybeCreate()` whose branch flips to CREATE in the same block | denied by the producer (lifecycle), excluded |
| 16 | same signed tx resubmitted after a MISMATCH drop, with a fresh preflight | included |
| 17 | precompile STATICCALL; plain value transfer to an EOA | both included |

Evidence under `evidence/` (tests.json, node logs, RPC transcripts). Producer-time benchmark is out of phase 1.

## Order of work (TDD)

1. Gradle skeleton compiles against `26.8.1-d97cbd6`; failing unit tests for encoder/batch/verifier/store/selector.
2. Implement until green; `spotless`-style formatting via `google-java-format` is skipped (PoC), but `-Werror`.
3. OPS `prepareBesu` with failing unit test → green; `go vet` + package tests.
4. Harness: Besu download, post-merge genesis with the Reth fixtures, Engine-API block driving, plugin JAR, Go client; scenarios 1–17.
5. Critic pass on the code, review pass on the diff, README with results and limits, commit (`-s`).
