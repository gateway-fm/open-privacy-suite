# Reth runtime implementation evidence

16 September 2026. This file records implemented slices, not a claim that the
complete OPS stack is ready.

## Private interpreter frame and transaction context

The initial three behavioral tests failed against the copied PoC: a private
allow policy could not run without the public account at `0x0900`; public allow
code incorrectly replaced the intended private deny policy; the gas/state
comparison could not execute. After injecting private runtime bytecode directly
through the frame's `known_bytecode`, all three passed.

The suite now additionally checks that application `EXTCODESIZE` cannot see the
private code; cold-access warming, user gas, and returned state match an ordinary
EVM; a caught forbidden inner call still vetoes the whole transaction; missing,
reverting, malformed, looping, or state-writing policy code fails closed.

Context tests were introduced before the corresponding interfaces. They now
check shared signing-address isolation, missing bindings, signer mismatch,
minimum snapshot version, and retention of an immutable snapshot across an
execution. Binding conversion tests distinguish signed envelopes whose unsigned
EVM environment is identical and invalidate a binding when its signed fields
are changed.

Validation command (local cached target location is optional):

```sh
python3 node/reth/scripts/prepare.py --offline
CARGO_TARGET_DIR=/Users/blade/work/software/privacy-proxy/.tmp/reth-policy-poc/target \
  cargo test --release --offline --manifest-path node/reth/Cargo.toml
```

Twelve tests passed at the first completed context/binding slice. Further
verification is recorded below as additional slices complete.

The subsequent signed-wire and registry slice passed the complete 21-test suite.
Rust verifies the exact Go-generated identity and snapshot signatures and the
simulation hash in `internal/nodepolicy/testdata/envelopes-v1.json`. Cases include
signature tampering, network/domain mismatch, expiry, ambiguous JSON, missing
fields, noncanonical base64, bounded/idempotent ingestion, stale renewal, and
independent identities for otherwise identical simulation requests. Required
`org_id`, scoped sanctions, and contract `code_hash` fields match the coordinated
Go wire schema. An additional active-fork classification test distinguishes EOA,
contract code, and active precompile addresses from observed execution.

The `reth-sdk` feature's compile test also passed against the pinned upstream
SDK, proving the custom factory/transaction type satisfies `ConfigureEvm`.
`cargo clippy --release --offline --locked --manifest-path node/reth/Cargo.toml
--tests -- -D warnings` passed for this slice.

## Trust boundaries and remaining integration

`IdentityResolver` is the trusted authenticated-context lookup boundary;
`FramePolicy` resolves immutable snapshot facts and prepares the contract ABI.
The interpreter itself makes no external calls for facts. It requires explicit
transaction/request bindings and checks signer and minimum snapshot version.
`PolicyTx` retains the signed-envelope hash through Reth's transaction conversion.
`PinnedPolicySnapshot` is held for the complete EVM lifetime, not replaced per frame.

The low-level fixture tests still encode the old PoC ABI in test code only.
Production A3 ABI encoding, fact stream transport, deployment handling, block
manifest persistence/self-import, authenticated simulation RPCs, and node startup
remain separate integration work. The initial interpreter conservatively denies
CREATE and SELFDESTRUCT until lifecycle enforcement is implemented. No production
disable-policy switch exists in the new crate.

Reth source is pinned to v2.5.2, commit
`5a6940e351fed80458fe6c9da8581cbe4b8bd036`. Preparation checks the exact commit and
refuses tracked modifications; it never changes an existing upstream checkout.

## Review notes

The shared-signer change is explicitly flagged for user review in
`docs/architecture/execution-context.md`. These unit tests use controlled resolver
fixtures; they are not evidence of signature verification or complete user
workflows. Historic reexecution must use the immutable produced-block manifest,
not current mutable authorization facts. Ordinary user history queries must
continue to apply current visibility permissions.

## Product runtime, compiler integration, and live node (17 September 2026)

The earlier “remaining integration” list above describes the initial slice. The
crate now builds the `ops-reth` binary with the pinned, unmodified upstream SDK.
`OpsEvmConfig` carries explicit immutable execution handles through candidate
construction, block assembly, engine self-import, and replay. Reth's generic RPC
add-ons support `PolicyTx`; its Ethereum convenience add-ons hard-code stock
`TxEnv`, so the binary uses the generic builder directly. The standard debug
launcher is required to start Reth's configured local development producer.

The complete SDK test invocation passed 57 tests, including the actual localhost
private HTTP transport test. Subsequent targeted tests cover canonical status
reconciliation and durable identity retention. The final full-suite count will
be recorded after the remaining integration checks. No upstream source was edited.

Completed foundations include the final A3 ABI (selector `0xdd789b6a`), exact
Go/Rust envelope and compiler fixtures, atomic snapshot/delta ingestion, separate
heartbeat freshness leases, bounded replay chains, content-addressed signed
artifacts, and durable exact-block manifests. Replay re-verifies the original
signatures and exact ordered transaction bindings. A test executes with the old
snapshot, applies a current ban, restarts, and proves original block replay still
succeeds while current execution denies. Renewing a ticket between execution and
assembly cannot replace the envelope that actually executed.

CREATE began with a red actual-EVM deployment regression. After adding the gate,
constructor bytes and the actual EVM-derived address reach the generated policy.
An execution-local ownership overlay supports nested CREATE/CREATE2 and calls
into successful children later in the block. Existing foreign registrations
remain authoritative. Frame and transaction rollback discard unsuccessful
creations. A red estimation test exposed ownership leaking between uncommitted
probes; each simulation attempt now starts with a fresh overlay.

The A4 record-party fixtures execute generated policy and getter bytecode in the
live interpreter. All eight getter outcomes pass, including changed parties,
short/malformed returns, revert, out-of-gas, and oversized return data. Review
identified a cross-organization read oracle through getter child calls. The
private frame driver now checks every child code/storage account against the
policy organization and separately guards BALANCE/EXTCODE account observations.
A scope violation aborts the entire policy evaluation, so a getter cannot catch
and conceal it. Adversarial tests cover foreign calls and account observations;
a same-organization proxy getter remains valid. Original application gas/state
isolation checks still pass.

The real-node smoke script passed against an isolated Shanghai chain. Signed
facts enabled scoped `eth_call`, `eth_estimateGas`, and `debug_traceCall`; public
unsigned calls and the public `ops_*` namespace remained denied/unavailable.
A signed call was mined in block 1, then a deployment in block 2 at
`0x2946259e0334f33a064106302415ad3391bed384`. Both blocks self-imported using the
durable local evidence. A later ban denied current simulations and prevented
nonce 2 from receiving a receipt. Evidence from that run is at
`.tmp/ops-reth-smoke-w0yrsglo/result.json` and `node.log` in the integration worktree.

The smoke also confirmed that Reth retries an invalid pool entry in later
candidate blocks: the banned nonce was denied in candidates 3, 4, and 5. A policy
denial must therefore be treated as current status rather than final eviction.
Status persistence retains pending/denied outcomes and canonical receipt-bound
creation metadata. Slot cleanup preserves the signed transaction's durable
principal/org binding, preventing rebinding after expiry, inclusion, or restart.

Explicit unsupported boundaries currently include EIP-7702/delegated code,
SELFDESTRUCT, custom precompiles, transaction-index traces, and privileged
`dry_run=true`. Complete OPS orchestration, admin diagnostics, and the broader
stack acceptance suite remain coordinated parent-task work; node unit tests are
not presented as proof of that entire user workflow.

The extended real-node run `.tmp/ops-reth-smoke-1i0owpq4/result.json` additionally
passed canonical creation status, facts/status recovery after restart, and scoped
admin diagnostics over the private HTTP listener. A banned impersonated user's
same-organization call returned the execution result plus `would_allow:false`;
a foreign registered target returned an error with no output. Diagnostic mode
cannot run a real transaction and guards direct account observations as well as
frames. The former `dry_run=true` unsupported boundary is now removed.

Independent review found two follow-up issues and both received regressions:
getter traversal now checks the original account bytecode before Reth's EIP-7702
normalization can conceal delegation, and renewed admission clears a prior
canonical marker so a post-reorg ticket survives restart. Durable principal/org
binding remains enforced after pending-slot cleanup. Ticket expiry is reported as
current lease status, not final eviction, because a previously pinned candidate
can still settle. OPS must continue receipt reconciliation for denied/expired work.

Final importer facts extend the ABI with `storageDeployer` and `storagePending`
(selector `0x9f0a7e8f`). The signed named principal determines the relationship;
an actual CREATE overlay supersedes stale preregistration metadata while the
registered organization remains authoritative. Constructor rollback removes
those provisional relationships. Cross-language compiler vectors pass.

Candidate previews have a separate ephemeral program/report and preserve the
active policy gate. Runtime regressions prove that an allow-all candidate cannot
bypass active denial, a denying candidate reports its verdict without changing
an allowed application execution, and candidate mode cannot execute a real
transaction. Candidate payloads require an explicit nullable artifact and verify
the artifact runtime digest.

Canonical receipts are no longer treated as finality evidence. Status includes
required `finalized` and nullable finalized hash/number, populated only from
Reth's finalized forkchoice header with canonical block checks. Tests reject
receipt-only, below-height, mismatched-fork, and pending-status finality. OPS
projects ownership only after this evidence. The pinned dev miner's default
finality depth is 64; the local smoke explicitly uses 1. Its restart hash window
begins at the current tip, which is a dev-consensus limitation documented in the
runtime README rather than an external finality guarantee.

After these slices, the complete offline SDK regression suite passed 69 tests.
The candidate wire validation regression was added afterward and is validated
separately alongside the final launcher build and real-node smoke.

The A5 real-node run `.tmp/ops-reth-smoke-c5n359o_/result.json` passed signed
simulation and submission, real CREATE/self-import, canonical finality checked
against a chain header, candidate preview without activation, active-policy
revocation despite an allowing candidate, scoped diagnostics, and restart.

Further independent review found that an unpublished candidate getter could
reveal a same-organization data predicate beyond its active application rule.
The regression reproduced that behavior before the fix. Ordinary candidate
programs now cannot issue child calls or observe accounts/storage (including
BALANCE, EXTCODE*, SELFBALANCE, SLOAD, and TLOAD). That aborts the whole preview
without returning a predicate. Scoped human diagnostics may evaluate the getter.
A generated recordParty integration test proves approved active getters still
work, ordinary candidate getters reject, and scoped diagnostic getters work.

A separate regression reproduced a mismatched signed implementation pin being
ignored by a private proxy getter. The fixed private read driver passes live
account code hashes into authorization for all descendants and account reads,
including precompile records. Diagnostic account guards honor the same pins.
The focused five-suite run passed; generated getter tests now total seven.

Final runtime checkpoint: all **75** SDK integration tests passed in the complete
`cargo test --release --offline --locked --features reth-sdk --test '*'` run
(10.39 seconds including incremental compilation). All-target SDK Clippy with
`-D warnings` passed. The upstream `proc-macro-error2` future-compatibility notice
remains informational.

The final binary smoke `.tmp/ops-reth-smoke-2cgnbx5_/result.json` passed all prior
checks plus independent candidate live-read isolation: ordinary candidate account
reads returned no output, scoped human diagnostic reads worked, active calls
remained unchanged, and current bans could not be bypassed. Call/CREATE landed in
blocks 1/2 with verified chain finality and durable recovery after restart. The
launcher advertises `per_frame_a5`, `candidate_simulation_v1`,
`scoped_diagnostics_v1`, and `finalized_status_v1` alongside the base protocol
capabilities. The full OPS workflow harness is owned by the stack integration
agent and remains separate evidence from this node checkpoint.

Root review identified a simulation override oracle: an authenticated allowed
selector could be combined with caller-supplied replacement bytecode that reads
hidden storage. The actual old binary reproduced it in
`.tmp/ops-reth-smoke-t2saknyg/node.log`. Signed request parsing now rejects every
nonempty state/code/storage and block override in normal, candidate, and admin
modes. The launcher never installs user overrides; tracing options remain
available. The adversarial signed-wire test went red→green, all 11 signed-wire
and 5 private-transport tests passed, and all-target SDK Clippy passed. Actual
rebuilt-node validation passed in `.tmp/ops-reth-smoke-813uz2ye/result.json`,
including hidden-storage code replacement and block override rejection plus the
existing functional lifecycle checks.

## Load measurement (harness path, development miner)

`node/reth/scripts/load.py` against the final guarded binary
(`db99022795bb…`), report `.tmp/ops-reth-load-ng_73021/result.json`, run on
2026-09-17. This measures the whole signed-wire path of the harness — identity
issue, signed submission over the private API, the development miner at 1 s
blocks, and status/receipt reconciliation — not the isolated cost of a policy
frame. It is a correctness-under-load and memory check, not a throughput claim.

| Setting | Value |
|---|---|
| Host | Apple M2 Max, 12 logical CPUs, 32 GiB; shared with the running OPS/explorer stack and Go test runs, no CPU isolation |
| Workload | 4 phases × 3 rounds × 512 signed transactions, 8 senders, concurrency 8, 1000 principals in facts, 150 M block gas, cross-block cache 64 MiB |
| Phases | `plain` (1 checked frame/tx), `nested` (3 frames/tx), `record-party` (live getter read in the policy frame), `churn` (fact deltas published every 0.25 s during the run) |

| Phase | Admitted / mined / correct | Wall s | Mined tx/s | Admission ms p50 / p95 / p99 | Submit→inclusion ms p50 / p95 | Peak RSS MiB |
|---|---|---|---|---|---|---|
| plain | 1536 / 1536 / yes | 139 | 11.0 | 352 / 529 / 1400 | 25 829 / 43 222 | 333 |
| nested | 1536 / 1536 / yes | 144 | 10.7 | 355 / 472 / 539 | 28 787 / 41 088 | 330 |
| record-party | 1536 / 1536 / yes | 139 | 11.1 | 366 / 456 / 510 | 24 996 / 35 026 | 328 |
| churn | 1536 / 1536 / yes | 160 | 9.6 | 452 / 643 / 710 | 27 540 / 43 600 | 336 |

Every phase also verified a denied probe (`admitted: true`, status `denied`) and
reconciled all 1536 canonical statuses. `churn` applied 398 fact publications
during the run (p50 303 ms, p95 611 ms, max 2.7 s, no errors) with no wrong
verdicts. Three checked frames per transaction cost no measurable throughput
against one frame; the live record-party read did not either. Node RSS rose
from ~120 MiB to ~335 MiB in every phase and is dominated by the explicit 64 MiB
execution cache plus receipts/status retention, not by policy state (policy
archive on disk: 32–45 MiB).

What this does **not** show: the roadmap's 5,000 TPS target. The harness is
bounded by its own admission path (~350 ms p50 per signed submission at
concurrency 8) and by 1 s development blocks; inclusion latency is queueing in
that path, not policy evaluation. A throughput claim needs an isolated host, a
block-production configuration matching the deployment, and a per-frame
measurement inside the node — none of which this run had.

## Per-frame cost of a policy check (2026-09-17)

The number the load harness could not give. `node/reth/tests/frame_cost.rs`
(`cargo test --release --features reth-sdk --test frame_cost -- --ignored --nocapture`)
runs the real inspector on the real EVM in-process: the fixture policy from
`internal/policydsl/testdata/lifecycle-v1.json` (compiled with the pinned solc;
three rules — org wildcard, EOA transfer, create), facts for 1 000 and 10 000
principals through the production `FactsPolicy` encoder, and an application
contract that forwards its call to itself so a transaction has exactly 1, 2 or 3
checked frames. 2 000 transactions per configuration after 200 warm-up; the
same transaction on a stock EVM without any policy is the baseline. Apple M2
Max, single thread, `InMemoryDB`, shared workstation. Timing comes from
`PolicyFactory::timed()` (new), which records per active check the fact
preparation time, the policy frame time and the gas the frame used.

| Frames/tx | check() µs mean / p50 / p95 / p99 | of which facts→calldata | gas per check | tx wall µs: no policy → with policy | overhead per frame |
|---|---|---|---|---|---|
| 1 | 17.7 / 17.4 / 20.0 / 22.9 | 1.9 µs | 6 436 | 0.8 → 18.7 | 17.9 µs |
| 2 | 18.0 / 17.5 / 21.5 / 25.1 | 1.8 µs | 6 436 | 1.1 → 37.7 | 18.3 µs |
| 3 | 17.9 / 17.5 / 18.6 / 22.1 | 1.9 µs | 6 436 | 1.4 → 55.8 | 18.2 µs |

(10 000 principals; the 1 000-principal rows are within noise of these — the
fact index is a hash lookup, so principal count does not enter the frame cost.)

Reading: **one checked frame costs ≈ 18 µs of node CPU and 6.4 k node-internal
gas** with this policy, and the overhead per frame equals the check itself — the
inspector adds nothing measurable around it. Against the roadmap workload:
5 000 tx/s × 3 frames = 15 000 checks/s × 18 µs ≈ 0.27 core-seconds per second,
i.e. about a quarter of one core at 1 s blocks (9 % at one frame per
transaction). Policy evaluation is therefore not what bounds the harness's 11
tx/s; the signed admission path and the development miner are.

What the measurement also found: the node printed one `OPS_POLICY_DECISION`
JSON line to stderr for **every allowed transaction** (a PoC diagnostic that had
survived into the runtime). With it on, the overhead per frame was 48–63 µs —
the synchronous serialization and write cost more than the policy check. The
print is now off by default and enabled with `OPS_POLICY_DECISION_LOG=1`; OPS
receives every outcome through the identity record regardless. Before/after:

| Frames/tx | overhead per frame, print on | overhead per frame, print off |
|---|---|---|
| 1 | 62–64 µs | 18–21 µs |
| 2 | 51 µs | 18 µs |
| 3 | 48 µs | 18 µs |

Limits of this measurement: one fixture policy with three wildcard rules — a
policy with many selector and argument rules runs more Solidity per check and
costs more gas, roughly in proportion to the rules the generated code evaluates
for the frame's target, so the acceptance stack's real policy should be
re-measured the same way before quoting a number for a customer configuration;
in-memory state (real state access is paid by the application frame with or
without a policy); one core, no block-building concurrency; a shared laptop.
Reports: `.tmp/frame-cost-report.json` (print on), `.tmp/frame-cost-report-nolog.json`
(print off).

## Where the stack's throughput actually goes (2026-09-17)

With the policy check at ≈18 µs per frame, the end-to-end ceiling the load
harness saw (≈11 tx/s; admission p50 352 ms at concurrency 8, submitting
directly to the node's private API) has another cause. `Runtime::accept_identity`
(`node/reth/src/runtime.rs`) takes the single `ingestion` mutex and, for every
transaction-scoped identity, does `archive.put` (temp file, `sync_all`, hard
link, directory `sync_all`), `set_pointer("tx-…")` (temp file, `sync_all`,
rename, directory `sync_all`) and `remove_pointer("terminal-…")`; canonical
reconciliation later adds another `put` + `set_pointer`. On macOS Rust's
`File::sync_all` is `F_FULLFSYNC`, measured here at **4.6 ms p50 / 8.5 ms p95
per call** (plain `fsync` is 0.03 ms), so one admission costs roughly 20–25 ms
of serialized disk time and reconciliation about as much again — a ceiling of a
few tens of transactions per second on this machine, and a few hundred on a
Linux host with ordinary `fsync`, independent of OPS, the load generator and the
policy.

Consequence for any load test (GasStorm included): until identity durability is
batched — one `sync_all` per block or per bounded interval for all identities
accepted in it, which keeps DECISION §3.4's "identities durable before the payload
is published" — the measured number will be the disk's full-sync rate, not the
system's. This is a design change to the node's admission path, not a tuning
knob; it is the next item before quoting throughput.

