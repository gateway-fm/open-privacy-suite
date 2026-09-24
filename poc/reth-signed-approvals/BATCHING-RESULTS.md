**Historical report before transport optimization.** Current instructions and findings: [DEMO.md](DEMO.md).

**The API/terminal demo works with the real OPS service, PostgreSQL, Redis and custom Reth.** It uses existing DB policies. It does not introduce a DSL compiler or Solidity policies.

Run this from the worktree:

```sh
cd "$(git rev-parse --show-toplevel)"
bash poc/reth-signed-approvals/demo.sh story --pause
```

Press Enter before each of the three steps. The script creates its own databases and node, prints the result of each check, and stops its services afterwards. Docker must be running. Public fixture keys are used; no existing developer stack or database is reused. Add `--keep` to keep the services available afterwards; Ctrl-C stops them. Connection details and logs are under `.tmp/approval-runs/`.

The demonstration shows:

1. **Allowed:** Alice calls Bank A's Router → Relay → Vault. OPS applies the actual DB rules and submits the signed transaction. Reth includes it. The successful receipt is retrieved through OPS.
2. **Rejected by OPS:** Alice tries a nested call into Bank B. The DB-backed trace validator rejects it before forwarding.
3. **Rejected by Reth after OPS approved it:** OPS approves Alice's Bank A call. Another valid, higher-fee transaction changes the relay to Bank B before Alice executes. Reth detects the different execution and excludes Alice's transaction. Her nonce, balance and application writes are unchanged.

In the third case, the transaction hash returned by OPS means submission. There is no success receipt. A separate user-facing rejection notification is not implemented; the excluded transaction can remain in the pool.

**What is real, and what is a fixture?**

The OPS HTTP handlers, JWT validation, wallet ownership signatures, PostgreSQL policies, Redis session/rate state, separate audit database, preflight tracing, Ethereum transactions, Ed25519 signatures, Reth execution and receipts are real. Organization membership and contract ownership are configured through the actual admin API. The application contracts contain no policy checks.

Users, organizations, keys and application contracts are test fixtures. The existing `mockauth` development login replaces the external identity provider; wallet linking and approval signatures still verify normally. A small Engine API driver schedules real Reth blocks instead of a consensus client. This is an API demo; the explorer UI/indexer, external identity provider and ASRN privacy network are not started.

**The signing workflow now follows our discussion.**

OPS completes its checks and queues the approved data. A signer takes a snapshot of whatever is already queued, up to 32 approvals, signs it, hands it to a separate delivery worker, and immediately takes the next snapshot. New arrivals stay queued for that next pass. There is no timer and no waiting to fill a batch. A single approval goes through immediately.

The sender owns the persistent TCP connection. OPS forwards the transaction independently, without waiting for signing or a delivery acknowledgement. Reth verifies signatures on dedicated CPU threads, then publishes verified approvals in RAM. The EVM execution thread performs the lookup and execution fingerprint comparison. Batching groups signatures only: one divergent transaction does not cancel its valid batch neighbours. Altering any signed batch member invalidates the entire signature.

Queues are bounded: 4,096 unsigned approvals, 128 signed batches, and a configurable Reth verification queue (default 64 batches, two workers). Full queues fail closed. The ingress frame limit is 16 KiB and each batch contains 1–32 approvals. `OPS_APPROVAL_MAX_BATCH` selects the OPS maximum. `OPS_APPROVAL_VERIFY_WORKERS` and `OPS_APPROVAL_VERIFY_QUEUE_BATCHES` configure Reth. Verification is ordered within a connection; separate connections can use separate workers. Crypto never runs on the EVM thread.

**Performance: distinguish execution cost from the whole request.**

The controlled Reth comparison uses identical blocks and equal preflight warming. It measures real payload construction, including execution and state/receipt roots. It excludes OPS, transaction admission, permission verification and Engine import. Nine measured blocks per workload/mode follow warmup, with three fresh nodes per mode and alternating order. The same binary runs with the module on/off. Stage profiling is disabled.

<!-- RETH_RESULTS_START -->
| Workload | Reth without module | Reth with module | Extra time |
|---|---:|---:|---:|
| One storage write | 11.13 µs/tx | 12.79 µs/tx | +1.66 µs (14.9%) |
| Three calls | 12.93 µs/tx | 16.71 µs/tx | +3.78 µs (29.2%) |
| Eighteen calls | 66.00 µs/tx | 88.74 µs/tx | +22.74 µs (34.4%) |

Full batches averaged 1.84 µs of verification per approval on separate workers. Those measurements are outside the execution table. Corresponding block hashes match for all 27 measured pairs. [Raw results and ranges](evidence/batching-benchmark/benchmark.json).
<!-- RETH_RESULTS_END -->

Go signing takes about 19 µs for one approval, or 29 µs for a full batch of 32 (about 0.9 µs per approval). These are signing CPU measurements, not request latency. The exact measurements are saved in [go-batching-bench.log](evidence/batching/go-batching-bench.log).

**Immediate batching does not guarantee batches of 32.** In the final live OPS test, 256 approvals formed 229 batches: 204 singletons, 23 pairs and two triples. The maximum of 32 is a limit, not a target. Verification on the worker averaged about 39 µs per approval in that live run, including singleton-heavy traffic and any scheduling delays; the prepared full-batch result above does not describe this workload.

92 approvals were ready when Reth first observed the transaction; 164 arrived later. For those late approvals, the measured time from pool insertion to approval availability averaged **0.116 ms**, with a maximum of **0.422 ms**. All 164 were below 0.5 ms. All 256 transactions succeeded; there were no invalid envelopes or full verification queues. This measures permission availability, not block inclusion. A late permission can miss a candidate build and wait for a later build; the PoC does not promise zero additional receipt latency.

The full HTTP test used 16 concurrent clients and 64 transactions per block, with one warmup and three measured blocks per mode. Baseline bursts measured **607–771 submissions/s**; the signed-approval path measured **557–695/s**. Median request latencies were approximately **17 ms** and **21 ms**, respectively. These short local bursts, on a laptop with Docker databases, establish a working comparison—not peak capacity or sustained TPS. The baseline uses existing OPS tracing; the new path uses the additional fingerprint preflight. Async durable auditing is enabled in both. See [the full live measurements](evidence/demo-final/live-load.json); block-commit durations also include the driver's 100 ms polling interval.

Replay the live load test:

```sh
bash poc/reth-signed-approvals/demo.sh load
# Longer bursts, if desired:
bash poc/reth-signed-approvals/demo.sh load --count 256 --concurrency 32 --samples 5
```

**Validation and reproduction.**

20 integration scenarios pass against real Reth, including actual OPS/PostgreSQL authorization, batch tampering, independent batch members, delayed/missing approvals, 128 waiting transactions, timeout/retry, restart, caught reverts and historical import. Eight Rust tests pass, including a shared Go-signed batch fixture, field/order/count tampering and bounded verification workers. Five Go tests pass under the race detector, repeated 20 times. Clippy and formatting checks pass. Raw evidence: [integration checks](evidence/batching-regression/tests.json), [HTTP demo](evidence/demo-final/demo.json), [build and source manifest](evidence/batching/manifest.json).

The upstream Reth checkout remains unmodified. The custom binary uses Reth extension traits; this is compiled integration, not a dynamically loaded plugin. Standard Ethereum RPC and transaction formats are unchanged. Our module adds a private approval ingress.

From another checkout, build with Rust, Go 1.25, Python 3, `cast`, solc 0.8.35 and Docker available:

```sh
python3 poc/reth-signed-approvals/setup.py
export OPS_RETH_BINARY="$PWD/.tmp/approval-target/release/ops-reth-approvals-poc"
export OPS_EVIDENCE_DIR="$PWD/poc/reth-signed-approvals/evidence/reproduced"
python3 poc/reth-signed-approvals/verify.py
python3 poc/reth-signed-approvals/run.py bench
bash poc/reth-signed-approvals/demo.sh all
```

`setup.py` respects `CARGO_TARGET_DIR`; set `OPS_RETH_BINARY` to its printed path when using a shared cache. The demo server uses the existing `mockauth` development build. The scripts remove their own containers but retain evidence and node directories for inspection.

The enforcement is **producer-side**, not a consensus rule for blocks from other producers. The historical V1 tested here supported protected legacy/EIP-1559, zero-ETH-value calls to existing contracts. The current PoC also supports native ETH transfers, creation and selfdestruct; calls V3 allows shared storage changes, with strict V2 retained for lifecycle operations. Permissions contain execution fingerprints, not a copy of OPS policies. The local TCP transport does not implement cross-perimeter encryption or ASRN privacy. See [current results and limitations](CALL-HASH.md).
