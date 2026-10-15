# Besu approval bottleneck investigation — 29 September 2026

> Historical investigation from 29 September 2026, against source baseline `61d91e15`.
> References to "current", "unchanged" or "not implemented" describe that investigation.
> The Bouncy Castle verifier subsequently shipped in merged PR #514; see the
> [later verifier report](../../BESU-VERIFIER-2026-09-29.md). Raw probe files named
> below belong to the private local evidence archive, not this source checkout.


Diagnostic work only, at feature-branch commit `61d91e15816603b3c775443abe9174bdab685d64`. No production source fixes, commits or pushes were made. Instrumentation and deliberately unsafe ablations are confined to ignored diagnostic copies. The unsafe controls are measurement tools, not proposed implementations.

**Focused verification follow-up:** [focused verification report](besu-verification.md) measures the actual crypto and worker stages. Raising outstanding calls from 8 to 32 did not improve the approximately 4,170 approvals/sec receiver ceiling. The current JDK verifier took about 418 microseconds per singleton signature versus 31 microseconds for Reth's verifier on identical messages. A fully verifying diagnostic alternative using the Bouncy Castle library already shipped with Besu took about 54 microseconds and kept isolated approval delivery current at 5,000 and 10,000/sec, without a batching window. This is approval throughput, not transaction TPS. Production code remains unchanged.

## Findings

There are two interacting throughput limits. The ordinary OPS path queues heavily on database-backed admission checks. Once that constraint is reduced in the static fixture, Besu's approval delivery/verification capacity becomes a binding limit on committed transactions. Looking only at submitted requests initially obscured the second limit.

**Besu-specific finding: signature-verification work and the resulting approval queue matter to committed TPS.** The normal sender emits very small batches: approximately 1.3 approvals per batch in the ordinary workload and 1.66 in the higher-input control, despite a maximum of 32. It immediately signs whatever is already queued; it does not wait to assemble a batch. Consequently Besu performs almost one Ed25519 verification per transaction. The two verification-worker threads account for approximately 59–66% of Java execution samples, dominated by JDK Ed25519 arithmetic. That is a sampling observation, not a calibrated percentage of total process CPU.

With repeated RBAC checks removed for the fixed fixture identities and the upstream connection limit held at 256, normal verification produced **2,339.3 canonical committed TPS**. Signing-to-acknowledgement latency averaged **769.7 ms** during the profile window, whereas a delivery call averaged **3.84 ms**. Much of the delay therefore accumulated before dispatch. Disabling only Ed25519 verification in the disposable plugin reduced signing-to-acknowledgement latency to **4.13 ms**; canonical committed throughput rose to **2,914.6 TPS**, approximately **25% higher**, while mean Besu process CPU fell from about 400% to 321% (100% is one core). Preflight, signing, transport, approval storage, and the producer's fingerprint gate remained enabled in that control.

As a separate downstream check, removing only the producer selector under the same higher-input conditions raised committed throughput to **2,687.8 TPS**, even though the approval-delivery queue grew to **2,183 ms**. The transactions no longer depended on those queued approvals. This supports approval availability as a cause of lost production throughput; it does not prove that fingerprint computation alone costs the difference.

**Shared OPS finding: repeated synchronous database lookups limit admission.** The normal bounded-connection case spent about **210 ms** in RBAC checks, **54 ms** in compliance and **53 ms** linking an address, out of **365 ms** inside the raw-transaction processor. Authentication middleware runs additional database checks outside that timer. A goroutine snapshot found 673 requests waiting to acquire database connections. Token revocation, user ban, user lookup, membership, ownership, compliance and address linking all contributed. Doubling the database pool from 30 to 60 did not improve throughput.

Caching the successful access result only for the static fixture reduced RBAC timing to **0.089 ms** and increased completed raw requests in comparable profile windows from **104,033 to 140,213** (about 35%). Canonical committed TPS stayed near 2,340 because the downstream approval queue became limiting. This cache is not suitable as a production fix: it intentionally omits policy changes and revocation semantics.

**An additional saturation issue is upstream connection churn.** Removing repeated access checks while keeping the default unlimited upstream connection count reproducibly exhausted macOS ephemeral ports. A short capture recorded 13,068 `TIME_WAIT` sockets to the Besu RPC port within seconds, followed by `EADDRNOTAVAIL`. Those three aborted runs are excluded from TPS comparisons. Capping connections at 256 in the fixture kept socket counts stable and made the higher-input controls measurable. This was exposed by the diagnostic workload; it is not established as the cause of the historical 44% result.

## Main comparisons

Every completed case requested 5,000 TPS for 60 seconds from ten fixture wallets. TPS below counts unique successful canonical receipts included during the sending window. Submitted attempts and failed submissions are separate fields in `summary.json`.

| Case | Canonical committed TPS | Signed-to-ack mean during profile | Interpretation |
| --- | ---: | ---: | --- |
| Current approvals off, first run | 2,914.3 | — | Full OPS baseline |
| Current approvals off, repeat | 2,772.5 | — | Baseline repeat |
| Current approvals on, default settings | 1,843.0 | 8.09 ms | 23,293 failed submissions; nonce-distance errors reduce committed TPS |
| Approvals on, upstream connections capped at 256 | 2,341.4 | 56.95 ms | Normal policy and approval checks; no failed submissions |
| Same cap, static-fixture RBAC result cache | 2,339.3 | 769.72 ms | More admitted traffic exposes downstream queueing |
| Same cache/cap, producer selector omitted | 2,687.8 | 2,183.11 ms | Preflight/signature/delivery remain; block production no longer waits for approvals |
| Same cache/cap, only signature verification omitted | 2,914.6 | 4.13 ms | Producer fingerprint gate remains active |

Other single-component controls are preserved in `summary.json`: local rather than Redis preflight limiting; a 60-connection database pool; skipping the already-seeded address-link write; a synthetic EOA preflight; omission of the producer selector; and omission of signature verification at the ordinary admission rate. None alone established a general 5,000 TPS capacity. In the ordinary signature control, submitted request volume barely changed, but committed TPS increased from 1,843.0 to 2,297.8 and signed-to-ack latency fell from 8.09 to 0.66 ms. Thus an unchanged submitted rate does not rule out a downstream bottleneck.

Approval enqueue remained asynchronous and in memory, averaging approximately **2 microseconds**. No synchronous durable approval storage was introduced. Redis preflight limiting averaged roughly 1–3 ms; bypassing it did not materially increase request-processing capacity. Removing preflight RPC/simulation alone also failed to lift the ordinary admission ceiling. These measurements do not justify identifying either as the sole cause.

## Why the older comparison looked different

The older approximately 727/671 TPS comparison used adaptive offered load; the approval-on run never requested more than approximately 800 TPS. The later 2,298/1,296 TPS comparison requested a constant 5,000 TPS. They exercise different queueing regimes and do not establish a controlled 8%-to-44% code regression. The Besu preflight/tracer/state-snapshot implementation was already present in the earlier code; it was not newly added between those benchmark commits.

The September 25 numbers also predate the current rebase/hardening, including the default-off diagnostic logging change. This investigation disables high-volume approval diagnostics. It does not isolate how much of the historical difference came from logging, other intervening changes, or host activity. The old approximately 50-second p99 was not reproduced in these current-source runs. Nonce-distance rejections and the difference between offered, submitted, and committed transactions must remain visible when reporting overload results.

The block driver requests nominal one-second blocks with a 0.8-second build window; actual periods vary. The bounded normal case averaged 1.139 seconds between included blocks, while the higher-input fully verified case averaged 1.320 seconds. This is a local Engine-API fixture, not a measurement of a deployed consensus network.

## Follow-up: immediate batching and the Reth comparison

Immediate batching is intentional: send whatever is already available, up to 32, without waiting to fill a batch. Describing the absence of a batching window as a missing feature was incorrect. A collection timer can delay approval availability and miss a producer's candidate build. No measured result here establishes that adding such a timer improves the normal workload.

The September 25 full-stack evidence does **not** show larger Reth batches. Rechecking the before/after Prometheus snapshots gives:

| Full-stack case | Confirmed approval members | Successful delivery calls | Mean approvals per batch |
| --- | ---: | ---: | ---: |
| `reth-transactions-5000` | 121,694 | 97,001 | 1.255 |
| `besu-on-5000` | 104,168 | 80,411 | 1.295 |

Both cases recorded zero retries and zero redeliveries. The snapshot SHA-256 values match the committed compact evidence. These are whole-run approval-delivery counters, not canonical transaction counts or batches restricted to a block-production window.

The separate delivery-only test used the same OPS approval service and accepted 300,000 approvals in 60 seconds on both nodes, with no preflight, policy database work or transaction execution. Reth with two workers confirmed all 300,000 during sending; Besu with two workers confirmed 241,160 and needed another 14.55 seconds to drain 58,840 approvals. Mean batch sizes over sending plus drain were respectively 1.001 and 1.013. Besu with four workers reached 299,998 during sending with a mean batch size of 1.002; the final two completed before the drain check. The original delivery report hashes also match the compact evidence. This is a receiver-throughput difference under nearly identical singleton batching, not evidence that OPS cannot produce approvals quickly enough for Besu.

There are two queueing stages. `Service.takeBatch` snapshots the unsigned queue, then `signOne` signs and publishes immediately. Each producer's delivery lane reads those already-signed envelopes from retention, with at most eight delivery calls outstanding by default. Besu's slower responses hold those slots; a backlog can therefore accumulate after signing while the unsigned queue stays small. Already-signed envelopes are not merged into a new signature. Current Besu profiles measured mean signing at approximately 36–45 microseconds per batch, consistent with the signer draining small arrivals quickly. The backlog is not proof of a slow signer.

Besu verifies through the JDK Ed25519 implementation; Reth uses `ed25519-dalek::VerifyingKey::verify_strict`. Current Besu CPU profiles and the diagnostic signature-bypass control implicate the receiver's verification cost. The saved measurements do not isolate a precise per-signature Java/Rust speed ratio. Four workers improving isolated delivery also does not justify a default change: the earlier bounded full-stack four-worker case performed worse than its two-worker case, and verification competes with transaction execution for CPU.

OPS preflight precedes approval enqueue and transaction forwarding. A slow preflight can limit transaction admission, but it does not itself let that same transaction, forwarded through OPS, overtake its approval. After enqueue, forwarding and approval delivery proceed independently, so the availability race remains real. Earlier live Reth tests also recorded late approval availability; those figures describe arrival relative to pool insertion, not the percentage missing a block-building opportunity. This recheck does not establish the user's recalled 20% figure or a current equivalent.

Sources: [`poc/approval-performance/evidence/results.json`](../../evidence/results.json), the original `.tmp/approval-performance/<case>/metrics-{before,after}.txt` and `delivery.json` files, and [`poc/reth-signed-approvals/BATCHING-RESULTS.md`](../../../reth-signed-approvals/BATCHING-RESULTS.md). The September 25 results predate current-source diagnostics; they are not new benchmark runs.

## Proposed work, not implemented

1. Investigate reducing Besu's signature-verification cost while preserving immediate sending, cryptographic checks, bounded queues and asynchronous request enqueue. Compare approval-availability latency and committed TPS across ordinary and overloaded workloads. Do not introduce a fixed collection window or raise worker defaults based solely on isolated verification throughput. If batching is revisited, examine whether work already waiting for delivery can be grouped without an intentional collection delay; this is an untested design direction requiring care around multiple producers and retained signatures. Increasing the maximum batch size alone cannot resolve singleton-heavy traffic.
2. Reduce repeated admission database round trips, preferably by consolidating fresh reads and reusing data within one request. Preserve immediate ban, revocation and authorization behavior; do not promote the fixture's cross-request allow cache into production.
3. Bound upstream connection concurrency and validate queueing/backpressure under bursts. The fixture cap is evidence for a configuration/design review, not a universal production tuning recommendation.

## Evidence and limitations

Hardware: Apple M2 Max, 12 cores, 32 GiB RAM, macOS 26.6.1. Besu 26.8.1, Temurin 25.0.4.1+1, Go 1.26.6. PostgreSQL and Redis run in disposable local OrbStack containers. These are developer-machine observations, **not limits of the solution**.

The machine was shared with other applications; their CPU usage varied and was recorded. OrbStack CPU includes the benchmark's own databases. Low free disk space was also observed, reaching approximately 315 MiB before cleanup; subsequent runs had approximately 1–2 GiB. Completed disposable chain/audit state was removed and evidence compressed. Single-run differences are not precise isolated-host regression percentages.

Raw evidence includes JFR recordings, Go CPU/mutex/goroutine profiles, stage histograms, Prometheus snapshots, process samples, TCP counts, generator records, canonical receipts and block membership. Some large JSON/log files are gzip-compressed. Histogram percentiles are bucket upper bounds. Aggregate database wait-seconds sum many concurrent waiters and are not elapsed wall time. Profile windows include snapshot/JFR setup overhead and should not be treated as exactly 40 seconds.

See `summary.json` (private raw evidence), `manifest.json` (private raw evidence), each named case directory, and the reproducible diagnostic runner/overlay sources here. The manifest distinguishes the passive instrumentation versions used across runs. Production source stayed unchanged throughout this investigation.

Cleanup completed: diagnostic processes and disposable containers stopped, the release plugin restored in the private Besu distribution, and the feature worktree remained clean at the original commit. Large evidence files were retained with lossless compression.
