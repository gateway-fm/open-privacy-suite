This report records the fingerprint optimization **before asynchronous signed batching**. The later working HTTP demo, dedicated signature workers and measurements are in [DEMO.md](DEMO.md).

The main bottleneck was **my fingerprint implementation**. It constructed full Geth prestate and diff reports, converted those and the call tree into JSON objects, built another canonical JSON tree, then encoded and hashed it. It also loaded, hex-encoded, decoded and rehashed contract bytecode whose hash Reth already knows.

That work is now removed from the default path. The module encodes the **same V1 fingerprint** directly from execution results and original account code hashes, reuses its output buffer and resets the existing tracer without recreating its arena. The signed permission, fields checked, and decision before commit are unchanged. OPS needs no update for this optimization.

On Apple M2 Max, release build, the final comparison was:

| Workload | Stock Reth, µs/tx | Original module, µs/tx | Optimized module, µs/tx | Remaining overhead vs stock |
|---|---:|---:|---:|---:|
| One storage write | 11.54 | 24.79 | 13.72 | +2.18 µs / +18.9% |
| Three calls | 14.00 | 45.55 | 19.61 | +5.61 µs / +40.1% |
| Eighteen calls | 69.97 | 199.63 | 92.77 | +22.81 µs / +32.6% |

This removes about **82–84% of the added block-building time**. Total time with the module fell by **45–57%**. These are microseconds, not milliseconds; the figures include normal execution and block roots. They are not end-to-end OPS latency or a prediction of production TPS.

The stage profile explains the improvement. For eighteen calls, median time per transaction was:

| Stage | Original, µs | Optimized, µs |
|---|---:|---:|
| Prepare/encode fingerprint and dispose reports | 109.51 | 3.75 |
| Keccak of the final fingerprint | 12.88 | 12.67 |
| EVM execution with call tracing | 31.75 | 31.68 |
| Build Geth call frames | 2.25 | 2.29 |

This is instrumentation around synchronous stages, using elapsed clocks; it is not a hardware-sampling flame graph. These stage figures come from a separate run, include clock overhead, and should not be added to the uninstrumented table. Scheduling outliers are retained in the raw results; medians limit their influence.

There is no evidence here of an upstream Reth bug. I used expensive helpers intended to construct debug-trace responses in the enforcement path. Both comparison modes use the ordinary Ethereum EVM configuration; the optimized module still needs to observe execution and hash what happened. The stock EVM execution portion was not separately instrumented, so the whole “EVM with tracing” row must not be described as added overhead. Upstream Reth remains unmodified.

Follow-up: [authentication alternatives and measured costs](AUTHENTICATION.md) compares HMAC, persistent mTLS, and signing batches. The PoC still uses Ed25519.

The next opportunities are:

- **A smaller, versioned binary fingerprint.** V1 still hashes JSON with hex strings. Binary fields would reduce encoding and hashing work. This requires matching changes in OPS and Reth and another equivalence review; it is not part of this change.
- **A specialized inspector that records only calls and logs.** The general tracer still participates in the interpreter's inspection path. Measure a specialized version before claiming a benefit; removing fields or ignoring reverted calls would weaken the guarantee.
- **Ingress signature throughput.** Ed25519 verification averaged about **50 µs per permission** in the final run, separately from block building. Asynchronous delivery overlaps this work but does not eliminate its CPU cost. Sustained concurrent delivery and bounded verification workers are the next end-to-end measurement, particularly for simple transactions.

Validation: **17 integration scenarios passed** against real Reth, including the real OPS/PostgreSQL path, cross-org divergence, caught revert, missing-permission concurrency, forged signatures, timeout/retry, restart and historical import. New cases cover zeroing storage, unchanged reads/writes, log positions and dynamic returndata. Verification mode produced **46 identical old/new fingerprints, including all 8 recorded denial decisions**. Five Rust tests passed, including the shared Go/Rust golden and 128 generated combinations of storage and calls/logs; size/value/unsupported-call rejection is also tested. Clippy and formatting checks passed.

The final timing run used the **same binary in three modes**: stock, original algorithm, optimized algorithm. Each workload has 9 measured blocks per mode, with 32 transactions per block, across 3 fresh nodes per mode and rotated mode order; each node first runs one discarded warmup. **All 27 sets of corresponding block hashes matched across the three modes** (81 measured blocks). Both protected modes received 1,152 permissions, all ready on first observation. This prepared workload intentionally excludes approval waiting. Full ranges, including a slow three-call optimized sample, are retained.

The timed region is the real `default_ethereum_payload`: execution and state/receipt roots. Preflight warms both protected modes and stock identically. Network RPC, OPS preflight, permission delivery/signature verification, ordinary pool admission and Engine API import are outside this region. Producer-only enforcement still applies. The V1 coverage described here is historical; [current calls V3 results](CALL-HASH.md) include shared counters, ETH transfers and strict fallback for deployment/destruction.

Evidence: [final timings](evidence/optimized-benchmark/comparison.json), [stage profile](evidence/optimized-profile/comparison.json), [integration results](evidence/verify/tests.json), [fingerprint comparisons](evidence/verify/differential-checks.json), [source/binary manifest](evidence/optimized-benchmark/manifest.json). Historical measurements are preserved in [before-optimization](evidence/before-optimization).

Reproduce from this directory after [setup](README.md), with `OPS_RETH_BINARY` pointing to the release binary and a dedicated test `TEST_DATABASE_URL` configured:

```sh
# Correctness: compute both fingerprints on the same execution.
OPS_FINGERPRINT_MODE=verify OPS_EVIDENCE_DIR=evidence/verify python3 run.py test

# Attribution only: stage clocks enabled.
OPS_EVIDENCE_DIR=evidence/optimized-profile python3 profile_bench.py --profile --samples 3

# Final performance: stage clocks disabled; all three modes compared.
OPS_EVIDENCE_DIR=evidence/optimized-benchmark python3 profile_bench.py --samples 9
```

The optimized path is the default when `OPS_APPROVALS=1`. `OPS_FINGERPRINT_MODE=legacy` selects the original algorithm; `verify` compares both, and `direct` explicitly selects the default. `OPS_PROFILE=1` enables stage records in node stderr. Neither diagnostic mode skips signature verification or the execution check. Standard Ethereum RPC and transaction formats are unchanged.
