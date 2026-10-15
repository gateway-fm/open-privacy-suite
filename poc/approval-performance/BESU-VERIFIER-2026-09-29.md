# Besu approval verifier follow-up, 29 September 2026

The change is in **our Besu approval plugin**. `ApprovalVerifier` now uses the raw-key
Ed25519 implementation in Bouncy Castle 1.84, already supplied by the supported Besu
26.8.1 distribution. Besu source and its libraries are unchanged. The plugin does not
bundle another crypto library or register a global JCA provider.

Immediate sending, maximum batch size 32, two verification workers, eight outstanding
delivery calls, bounded queues and in-memory retention are unchanged. Trusted keys are
copied defensively; signatures must be exactly 64 bytes. Verification still precedes
store insertion and acknowledgement. No batching delay or approval storage I/O was added.

## Why this change

The preceding focused investigation measured the original JDK verifier at 417.8 us per
singleton envelope versus 53.9 us for the selected Bouncy Castle path, median of three
warmed rounds on this machine. Allocation fell from approximately 55 KB to 7.6 KB per
verification. Signature verification accounted for 98% of the original receiver worker's
processing time. Raising outstanding calls from eight to 32 did not increase throughput;
it increased receiver queue wait.

With the actual OPS sender and receiver classes in isolation, the original two-worker
receiver confirmed about 4,168 approvals/sec under a 5,000/sec offered load, accumulating
24,975 approvals over 30 seconds. The alternative verified all 150,000 during the same
window, with mean signing-to-acknowledgement latency of 0.140 ms. It also kept up with
10,000 approvals/sec (the final approval completed between sampling and the drain check).
Average batches remained approximately one approval. These measurements identify the
crypto bottleneck; they are **not transaction TPS or solution capacity limits**.

## Full transaction comparison

Apple M2 Max, 12 CPU cores, 32 GiB RAM, macOS 26.6.1; Go 1.26.6, Temurin
25.0.4.1+1 and Besu 26.8.1. Each case uses a fresh disposable OPS/PostgreSQL/Redis/Besu
stack, the same uninstrumented OPS binary, real RBAC/preflight/signatures and locally
mocked identity. Ten funded wallets request 5,000 ETH transfers/sec for 60 seconds.
The generator is subject to backpressure; requested rate is not achieved input rate.
Block production uses a nominal one-second interval, 0.8-second build window and
200-million gas limit. Approval diagnostics are disabled. Runs are sequential, with no
compilation or separate CPU benchmark during load.

All cases use the existing **HTTP node connection cap of 256 in the fixture**, with
5,000 allowed concurrent OPS requests. An initial original-verifier run with the default
unbounded HTTP connections failed with macOS `EADDRNOTAVAIL`; it is excluded from TPS
results. Both verifier versions and the disabled baseline use the same capped setting.
No production default changed. This HTTP pool is separate from the approval transport,
which keeps its single persistent gRPC connection and eight outstanding calls.

| Case | Committed TPS during sending | Queue-to-commit p50 / p95 / p99 | Mean signed-to-ack | Approval-delivery p99 upper bound | Producer wait events |
|---|---:|---|---:|---:|---:|
| Original JDK verifier | 2,255.7 | 2.021 / 3.851 / 5.099 s | 197.3 ms | 2,500 ms | 339 |
| Bouncy Castle verifier | 2,323.7 | 1.794 / 3.146 / 3.436 s | 2.07 ms | 50 ms | 8 |
| Approvals disabled | 2,869.1 | 1.493 / 2.229 / 2.821 s | — | — | — |

**The 2,255.7 TPS "original JDK verifier" row is a new baseline run, not the previously
reported 1,296.3 TPS measurement from 25 September.** The older run used pre-rebase source,
Go 1.25.13 and the earlier diagnostic logging behavior; the new comparison uses current
rebased/hardened source, Go 1.26.6, diagnostics disabled and an explicit HTTP connection
cap of 256. Its approvals-disabled baseline also changed: 2,298.1 TPS previously versus
2,869.1 here. The historical [manifest](evidence/manifest.json) and
[results](evidence/results.json) identify those earlier runs. A subsequent
[controlled baseline investigation](BESU-BASELINE-2026-09-29.md) measured **867 versus
2,164 TPS by changing only approval success/timing/wait logging**, with the old verifier
and the same HTTP cap in both cases. Disabling those logs during release hardening was
a substantial approval-plugin performance change already present in this new baseline.
The historical 1,296-to-2,324 increase still cannot be attributed to the verifier
replacement; the matched verifier comparison is 2,256-to-2,324. The follow-up separates
the logging and HTTP-cap effects without claiming an exact replay of the older build.

The verifier change substantially reduces approval delivery delay. These individual
full-stack runs show only about **3% higher committed TPS**; that small difference is
not a reliable estimate of throughput improvement without repeated trials. The isolated
crypto speedup must not be presented as an equivalent full-stack TPS gain. Other work
still limits this transaction stack. These are development-machine measurements,
**not limits of the solution or production throughput guarantees**.
The optimized full stack remains approximately 19% below the approvals-disabled run;
the approval path also includes preflight and producer checks beyond signature verification.
Mean approval batch size was 1.41 before and 1.32 after: the latency improvement did not
depend on collecting larger batches. Both enabled runs recorded zero delivery retries,
zero unconfirmed approval drops and no producer deny/drop increments in their metric
snapshots. The normal retention cap evicted already-confirmed approvals as intended.

TPS counts successful receipts whose canonical block was observed within the 60-second
sending window. Every logged transaction hash is checked against its receipt and block
membership. Queue-to-commit percentiles include all successful receipts, including those
after sending. Approval latency is weighted by batch and covers signing to acknowledgement;
its p99 is a Prometheus bucket upper bound. Producer wait events can count repeat builds
of the same transaction and must not be converted into a percentage of late transactions.

| Case | Logged hashes | Successful receipts after drain | Missing receipts | Reverted |
|---|---:|---:|---:|---:|
| Original JDK verifier | 139,360 | 138,840 | 520 | 0 |
| Bouncy Castle verifier | 141,980 | 141,234 | 746 | 0 |
| Approvals disabled | 176,420 | 175,954 | 466 | 0 |

The generator classified the missing-receipt transactions as `discarded`; they are excluded
from throughput and successful-transaction latency.
These overloaded runs do not establish lossless processing of every requested transaction.

## Compatibility and security

- Gradle `check assemble dependencyInventory`: 105 tests passed, including all 151 pinned
  Wycheproof Ed25519 cases (88 valid accepted, 63 invalid rejected), shared Go-signed golden
  envelopes, malformed input and concurrent use of one verifier. The test corpus is
  attributed and licensed under test resources; it is absent from the plugin JAR.
- All 26 real-Besu scenario checks passed, including forgery/refusal, late and expired
  approvals, execution divergence, lifecycle calls, reorgs, restarts, live OPS replay,
  fail-closed startup and coexistence with Lineth plugins.
- All four OPS HTTP integration checks passed: same-organization execution, cross-organization
  refusal, producer exclusion on divergence and deployment registration.
- Thin-JAR validation passed: no Bouncy Castle classes are bundled. The dependency audit
  covers 66 coordinates and passes with two explicitly reviewed Bouncy Castle advisories,
  concerning certificate validation and ASN.1 parsing. Neither path is used by this verifier.
  See the [source-based review](../../docs/implementation/approvals-release-review.md#dependency-review)
  for the limited scope, upstream fixes and recheck deadline. This does not clear the host's
  other uses of the library.

These measurements used a locally built candidate from uncommitted changes on top of
`61d91e15816603b3c775443abe9174bdab685d64`. The source hashes in the evidence identify
the measured implementation. Linux compatibility CI for the committed change and
deployment qualification remain separate release gates; this report is not a release
publication record.

## Evidence and reproduction

[Compact evidence](evidence/besu-verifier-2026-09-29.json) records source and artifact hashes,
settings, receipt counts, counter deltas, histogram bounds, validation and dependency review.
The original plugin SHA-256 is
`c41a9ca903606aa5e6a1c0f75c3794085d4060eb40b9451181a9da036379b986`;
the candidate is
`8694a7fa7a571358460061a1f9fa775f207b113f32a2967e131fe1cfcd91f276`.
Both use OPS binary
`2dd3bbfcb5e818bd77c91b18254f8b0620592062fc8ed46816fc95091fba04fe`.

Detailed evidence remains under `.tmp/besu-verifier-change/` in the feature worktree:
`performance/{jdk,bouncy-castle,approvals-off}/`, `scenarios/`, `http/` and the Gradle/audit
logs. Large evidence files are compressed; stopped fixture chain state is removed.
The preceding focused probes remain under `.tmp/besu-bottleneck/verification-probe/`.

The local comparison wrapper `run_transactions.py` runs the existing
`poc/approval-performance/transactions.py` with a selected saved plugin JAR, isolated scratch
directory, the matched HTTP connection cap, diagnostics disabled and additional receiver
metric snapshots. It batches only **post-load receipt reads** (100 hashes per RPC batch,
eight threads), not approval delivery or the timed transaction workload. The sequential
`run_performance.py` wrapper selects original, candidate and gate-off cases and performs
cleanup. Their checksums are included in compact evidence. Both wrappers and saved artifacts
are retained locally; reruns need a fresh output directory. Build and compatibility commands
remain documented under [`node-approvals/`](../../node-approvals/README.md).
