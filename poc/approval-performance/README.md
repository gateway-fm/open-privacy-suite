# Approval performance and retention at 5,000 TPS

Measured on 25 September 2026. **The approval delivery component can keep up with
5,000 approvals/sec on this machine; the complete transaction stack has not
demonstrated 5,000 committed TPS.** Besu needed four verification workers to avoid
a growing delivery backlog. Its default remains two, with a new bounded operator
setting, `--plugin-ops-approval-verify-workers=1..32`, matching Reth's existing
`OPS_APPROVAL_VERIFY_WORKERS` setting.

Approval persistence remains deferred. These measurements exercise the existing
asynchronous signer, bounded memory retention and gRPC delivery. No database
write, disk flush or batching delay was added to the approval path.

## Environment and measurement boundaries

One shared Apple M2 Max workstation, 12 cores, 32 GiB RAM, macOS 26.6.1; Go
1.25.13, JDK 25, Besu 26.8.1, and the Reth extension pinned to
`5a6940e351fed80458fe6c9da8581cbe4b8bd036`. Existing unrelated local services were
left running. Each measured case ran sequentially in a fresh disposable node or
stack. Builds and the heap benchmark did not overlap these timed cases. These
are individual local measurements, with no confidence intervals or production SLA.

The [compact evidence](evidence/results.json) contains counters, percentiles,
receipt counts and checksums of the detailed local reports. The
[manifest](evidence/manifest.json) identifies the binaries, and the
[retention matrix](evidence/retention.csv) records the nine heap samples.

Two separate paths are measured:

- `delivery.py` uses a persistent Go process running the **actual OPS approval
  service**, signer, retention and gRPC lanes against a real node. Unique
  synthetic hashes measure approval throughput without preflight, HTTP policy
  checks, transaction forwarding or execution. A ten-second warmup at 1,000/sec
  precedes the timed window. Acceptance ends at a fixed deadline; any undelivered
  backlog and subsequent drain time are reported separately.
- `transactions.py` runs the patched Gasstorm generator through OPS, PostgreSQL,
  Redis and the real node. Identity is a local mock; wallet linking, RBAC and
  preflight are real. Ten funded fixture wallets send ETH transfers. The same
  Engine API driver uses a nominal one-second block interval, a 0.8-second build
  window and a 200-million gas limit on both nodes. Actual block times and gas
  limits are recorded. Every logged hash is checked directly against its receipt
  and membership of a canonical block.

Delivery p50/p95/p99 values below are **Prometheus histogram bucket upper bounds**
from signing to acknowledgement, weighted by batch, including retries of first
delivery but excluding replayed batches. They exclude time waiting to be signed.
Enqueue timings measure the request's handoff only. Full-stack queue-to-commit
percentiles are individual successful transactions, from the generator's recorded
send time to observation of their canonical block. They include client/server
queuing and the block cadence; they are not node execution timings.

## Approval delivery

All steady cases offered and accepted 300,000 approvals in 60 seconds, with no
enqueue refusals or unconfirmed drops. OPS and receiver capacity were 100,000;
the signed TTL was ten minutes.

| Node | Verification workers | Confirmations during the 60-second window | Drain after sending | Delivery p50 / p95 / p99 |
|---|---:|---:|---:|---|
| Reth | 2 | 300,000 | <1 ms | ≤0.25 / ≤0.25 / ≤0.25 ms |
| Besu | 2 | 241,160 | 14.55 s | ≤10 s / >10 s / >10 s |
| Besu | 4 | 299,998 | <1 ms | ≤1 / ≤1 / ≤2.5 ms |

The two final Besu approvals finished between sampling and the drain check. This
is materially different from the default-worker run's 58,840-approval backlog.
Enqueue p99 was 0.916 µs on Reth, 2.125 µs on Besu with two workers and 1.459 µs
with four. These handoff measurements do not establish an overhead-free full
transaction path.

Four workers are a **tested tuning option**, not a universal default: verification
competes with block execution for CPU. The full transaction measurements below
must also be considered before choosing a pool size.

## Full transaction stack

All 5,000/sec cases run for 60 seconds; the two 1,000/sec cases run for 30 seconds.

| Node | Gate | Workers | Request cap | Requested TPS | Committed TPS | Queue-to-commit p50 / p95 / p99 (s) | Successful / missing receipts |
|---|---|---:|---:|---:|---:|---|---:|
| Reth | Off | — | 5,000 | 5,000 | 2,638.6 | 1.906 / 2.445 / 2.642 | 163,063 / 1,777 |
| Reth | On | 2 | 5,000 | 5,000 | 1,962.2 | 2.273 / 2.838 / 3.093 | 121,081 / 1,899 |
| Besu | Off | — | 5,000 | 5,000 | 2,298.1 | 1.669 / 2.298 / 2.575 | 139,956 / 2,142 |
| Besu | On | 2 | 5,000 | 5,000 | 1,296.3 | 6.427 / 14.652 / 50.630 | 86,940 / 456 |
| Reth | On | 2 | 256 | 5,000 | 1,751.6 | 2.552 / 3.784 / 4.994 | 107,038 / 3,279 |
| Besu | On | 2 | 256 | 5,000 | 959.4 | 11.724 / 21.920 / 24.125 | 73,091 / 3,228 |
| Besu | On | 4 | 256 | 5,000 | 752.0 | 16.204 / 27.036 / 29.912 | 61,547 / 2,216 |
| Reth | On | 2 | 256 | 1,000 | 968.3 | 1.486 / 1.966 / 2.085 | 29,956 / 55 |
| Besu | On | 4 | 256 | 1,000 | 961.6 | 1.113 / 2.091 / 2.808 | 29,841 / 170 |

Reducing the concurrency cap to 256 did not improve either overloaded stack in
these runs. Four Besu verification workers also did not improve the bounded
full-stack case: 752 committed TPS versus 959 with two workers. The isolated
delivery gain is therefore insufficient grounds for changing production defaults.
At a 1,000/sec target, both nodes completed approximately 96–97% of the target
inside the sending window; additional final-block receipts arrived afterwards.
These fresh-stack runs include startup and end-of-window effects.

Gate-off runs retain OPS policy enforcement through its existing execution-trace
path; they disable signed-approval preflight, delivery and the producer gate.
Thus this comparison covers the combined approval path, not memory retention's
isolated cost. With a 5,000/sec request target, neither gate-off baseline reached
5,000 committed TPS on this shared host.

Committed TPS counts successful transactions whose blocks were observed **inside
the configured sending window**, divided by that window. Later successful
receipts are counted separately; they do not inflate sustained TPS. No reverted
receipts were observed in the completed baseline cases. Missing receipts must
not be interpreted as lost approvals: the compact evidence also records whether
the generator marked each missing hash as discarded at its send cutoff.

The generator's `txFailed` counter omits transient failures it retries. OPS
recorded non-success RPC outcomes during overload, so that counter alone is not
evidence of error-free delivery. The evidence includes per-attempt
`eth_sendRawTransaction` outcomes and HTTP statuses for all RPC methods. Server
RPC processing histograms combine successful and failed handler attempts,
including concurrency refusals; they omit queues before the handler and refusals
in earlier middleware. Receipt-based results take precedence over the
generator's built-in verification, which uses an OPS-filtered view of the chain.

The OPS concurrency ceiling is a count of in-flight requests, independent of the
requested TPS. Lowering it can move queuing or retries to the client; it is not
automatically a throughput or latency improvement.

## Memory and history sizing

`BenchmarkRetentionHeap` fills actual OPS retention with signed envelopes and
approval structs, forces GC before and after, and keeps the retained objects
alive. It measures live heap attributable to filling retention, not total RSS.
There is no transport, EVM or transaction workload in this benchmark.

| Retained approvals | History at 5,000/sec | Batch size 1 | Batch size 8 | Batch size 32 |
|---|---:|---:|---:|---:|
| 100,000 | 20 s | 65.0 MiB | 31.0 MiB | 27.6 MiB |
| 300,000 | 60 s | 195.1 MiB | 93.0 MiB | 82.8 MiB |
| 1,000,000 | 200 s | 649.5 MiB | 310.1 MiB | 275.9 MiB |

Paced 5,000/sec traffic produced batches close to **one approval each**, because
OPS signs available work immediately. Use approximately **682 live bytes per
approval** for conservative sizing of this implementation, rather than assuming
every batch reaches the maximum of 32. Measured allocations were approximately
1,590 bytes per approval at batch size one; live heap is only part of the GC and
process memory budget. The steady delivery probe had roughly 71 MB of total live
Go heap at 100,000 retained approvals and peaked around 189–193 MB sender RSS
over the measured cases. Node RSS includes the whole execution client and cannot
be attributed to approval storage alone.

A ten-minute TTL at 5,000 approvals/sec would require three million entries to
retain *every* issued approval until expiry: approximately 1.9 GiB of live
retention heap at batch size one, **an extrapolation**, before process/GC overhead.
Neither that capacity nor that TTL-sized heap was measured as a live workload.
OPS can issue more approvals than unique committed transactions because of
retries, so deployment sizing must use observed approval issuance rates.

History length is not a guaranteed downtime allowance. OPS expires entries and
evicts the oldest when its cap fills, while the node can also release approvals
after finalized inclusion. A successful acknowledgement alone does not release
OPS's recovery copy. Multi-OPS deployments require receiver capacity for the
combined retained set plus fresh arrivals during recovery. Raising a cap that
is then allowed to fill cannot by itself guarantee complete replay under
continuous traffic: fresh approvals can evict older ones before recovery reaches
them. See the [wire contract's sizing guidance](../../docs/implementation/approvals-wire-contract.md#7-settings).

## Restart with fresh traffic

The sender stays alive while its producer is stopped and a new producer with the
same genesis and approval address starts. A real ETH transaction is preflighted
and its approval confirmed before restart, then resubmitted directly to the new
producer while fresh synthetic approvals arrive. A successful receipt proves
that this transaction's approval was recovered **without a new preflight**.
This isolates approval recovery; it does not claim that the transaction pool
survived the node restart or that OPS automatically resubmits transactions.

| Case | Sender / receiver capacity | Fresh accepted / requested after restart | Real probe: submission to receipt | Aggregate replay target |
|---|---:|---:|---:|---|
| Reth, full cache | 100k / 100k | 100,000 / 100,000 | 0.406 s | Not reached |
| Besu, four workers, full cache | 100k / 100k | 97,371 / 100,000 | 1.494 s | Not reached |
| Reth, spare capacity | 300k / 300k | 100,000 / 100,000 | 0.477 s | Reached within fresh-traffic window |
| Besu, four workers, spare capacity | 300k / 300k | 97,141 / 100,000 | 2.110 s | Reached after 7.49 s additional drain |

Fresh traffic runs for 20 seconds after restart. Besu had 2,629 or 2,859 enqueue
refusals during its sender-readiness transition, about half a second's traffic;
these must be retried by a caller. Node stop/start time is separate from the
probe receipt time and is retained in the evidence. The full-cache cases evicted
old approvals while replay was in progress. That is the bounded retention policy,
and demonstrates why a full replay promise would be incorrect.

Spare-capacity cases begin with 110,001 retained approvals and finish below
300,000 entries after the new arrivals. They demonstrate recovery with headroom,
not recovery of an already full 300,000-entry cache. Aggregate confirmations
include duplicates and replay: reaching the expected count does **not** prove
every hash recovered. The actual receipt proves recovery only for the recent
pending probe. Old pending transactions, successive OPS/producer failures,
graceful shutdown and client receipt-check/reapproval remain separate validation
requirements. Synthetic hashes never finalize, deliberately stressing retention.

## Reproduce

Run from the repository root. Use the prerequisites and pinned node builds in
the [Besu harness](../besu-signed-approvals/README.md) and
[Reth harness](../reth-signed-approvals/README.md): JDK 25, Besu 26.8.1, the
extension binary, `solc` 0.8.35, Foundry `cast`, Go, and Docker for full-stack runs.
Set `OPS_BESU_HOME` to a **disposable copy** of the Besu distribution, because the
harness installs its plugin there; set `OPS_JAVA_HOME` and `OPS_RETH_BINARY` to
the corresponding local builds. All fixture accounts and keys are public test
data. These tools are for isolated local nodes.

```sh
go build -tags mockauth -o .tmp/ops-server ./cmd/server
go build -o .tmp/approval-performance-driver ./poc/approval-performance/driver
go test ./internal/nodeapproval -run '^$' -bench '^BenchmarkRetentionHeap$' -benchtime=1x -count=1

python3 poc/approval-performance/delivery.py --node reth --rate 5000 --seconds 60 --restart --output .tmp/performance/reth
python3 poc/approval-performance/delivery.py --node besu --verify-workers 2 --rate 5000 --seconds 60 --output .tmp/performance/besu-two
python3 poc/approval-performance/delivery.py --node besu --verify-workers 4 --rate 5000 --seconds 60 --restart --output .tmp/performance/besu-four
python3 poc/approval-performance/delivery.py --node besu --verify-workers 4 --rate 5000 --seconds 20 --capacity 300000 --retain 300000 --restart --drain-seconds 120 --output .tmp/performance/besu-headroom
```

For the full stack, create the isolated patched generator checkout using
`prepare_gasstorm.py loadgenerator <upstream-checkout>`, as described in the
[Gasstorm workflow](../reth-signed-approvals/GASSTORM.md). Set
`GASSTORM_LOADGEN_SOURCE` to the path printed by that command and rebuild its
`./cmd/loadgen` into this repository's `.tmp/gasstorm-loadgen`. An already present
binary is reused by the harness, so rebuild after changing the generator source.

```sh
python3 poc/approval-performance/transactions.py --node reth --rate 5000 --seconds 60 --output .tmp/performance/reth-on
python3 poc/approval-performance/transactions.py --node reth --no-gate --rate 5000 --seconds 60 --output .tmp/performance/reth-off
python3 poc/approval-performance/transactions.py --node besu --verify-workers 4 --max-requests 256 --rate 5000 --seconds 60 --output .tmp/performance/besu-bounded
python3 poc/approval-performance/report.py .tmp/performance/reth .tmp/performance/besu-four .tmp/performance/reth-on
```

Use a new output directory for every run; existing directories are refused.
Run cases sequentially, without other builds or benchmarks. The tools stop their
owned nodes, senders and disposable database/cache containers on exit. Evidence
and scratch node databases remain under `.tmp` for inspection; remove only the
run directories you created when finished. RSS is sampled once per second for
owned process trees and can miss shorter peaks. Any sampling failure is recorded.

## Validation and security review

The configurable Besu pool preserves the two-worker default and validates the
range 1–32 at CLI parsing and construction. It changes scheduling capacity only;
signature, trusted key, source, expiry, chain and execution checks are unchanged,
as are connection and call caps. No new endpoint, authorization bypass or
persistent store is introduced. The existing Java suite, including boundary
validation and JAR packaging checks, passes (100 tests). Go approval tests pass
with the race detector. The real-node cases exercise the four-worker setting
and signed restart recovery. Production sizing still requires the actual
hardware, transaction mix, topology, finality behavior and operational recovery
requirements.
