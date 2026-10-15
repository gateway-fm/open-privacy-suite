# Besu verification capacity: focused follow-up, 29 September 2026

> Historical investigation from 29 September 2026, against source baseline `61d91e15`.
> References to "current", "unchanged" or "not implemented" describe that investigation.
> The Bouncy Castle verifier subsequently shipped in merged PR #514; see the
> [later verifier report](../../BESU-VERIFIER-2026-09-29.md). Raw probe files named
> below belong to the private local evidence archive, not this source checkout.


**Finding:** the current JDK Ed25519 verifier is expensive enough to saturate Besu's two approval workers. Sending more concurrent requests does not resolve that limit. A diagnostic replacement using the Bouncy Castle verifier already shipped with this Besu distribution substantially reduced cost, preserved immediate batching, and kept delivery current at both 5,000 and 10,000 approvals/sec.

No production source, configuration, installed plugin, branch commit or remote was changed. All instrumentation and the alternate verifier are confined to this ignored directory. Unlike the earlier signature-bypass control, the alternate verifier actually checks every signature. All probe processes have stopped.

## What was measured

Two complementary probes used the same Apple M2 Max developer machine, with 12 CPU cores and 32 GiB RAM, running macOS 26.6.1. Runtime versions: Temurin 25.0.4.1+1, Besu libraries 26.8.1, Go 1.26.6, Bouncy Castle `bcprov-jdk18on-1.84.jar`, and Reth's pinned `ed25519-dalek` 2.2.0 release artifact.

1. A crypto microbenchmark verifies the same 64 distinct signed messages repeatedly in each implementation, with 8,000 warmup verifications and three measured rounds of 4,000. One-approval and 32-approval envelopes are measured separately. The Go-compatible fixture key is public test material. Corrupted messages and signatures must fail. Java thread CPU and allocation counters distinguish arithmetic cost from scheduling delay. Reth's comparison calls `verify_strict` using the existing release library, not a substitute algorithm.
2. A delivery probe runs the actual current OPS sender and the Besu plugin's receiver classes, including gRPC, worker pool, decoder, verifier, TTL/trust/chain checks and in-memory store. It excludes Besu block production, transaction execution, OPS admission checks and preflight. Receiver source copies add stage timers and an opt-in alternate verifier. Connections bind only to loopback. The sender retains its immediate batching, maximum batch size 32 and one persistent connection. Receiver/OPS capacities are 100,000, TTL ten minutes, and the receiver's per-connection stream cap remains 32. Each timed case sends for 30 seconds after a ten-second, 1,000/sec warmup. Unique hashes exercise store pressure and eviction after capacity is reached.

These are approval-verification and approval-delivery measurements, **not full-stack transaction TPS or solution capacity limits**. The machine is shared; process/background CPU samples are retained per case. Benchmarks ran sequentially. No compilation or separate CPU benchmark ran alongside a timed delivery case.

## Crypto cost

Median wall time across the three measured rounds:

| Verifier | One-approval envelope | 32-approval envelope | Allocation per one-approval verification |
| --- | ---: | ---: | ---: |
| Current Besu JDK path, new `Signature` per batch | 417.8 us | 428.6 us | 55,034 bytes |
| JDK path reusing an initialized `Signature` | 390.4 us | 400.1 us | 35,418 bytes |
| Bouncy Castle, raw trusted public key | 53.9 us | 66.0 us | 7,592 bytes |
| Bouncy Castle, cached validated public point | 48.6 us | 60.5 us | 7,032 bytes |
| Reth `ed25519-dalek::VerifyingKey::verify_strict` | 30.7 us | 36.6 us | Not measured |

The candidate raw-key path is approximately **7.8 times faster** than the current Besu path for singleton envelopes. Reth's verification is approximately **13.6 times faster** in this focused comparison. These ratios describe signature verification only. Java thread CPU closely matched wall time, so the 0.4 ms cost is principally CPU work rather than a thread waiting to run. Reusing the JDK object saves only about 7%; allocation/object construction alone does not explain the difference.

The installed JDK source makes two separate scalar multiplications for verification. Its Ed25519 base-point multiplication delegates to the generic bit-by-bit multiplication loop. This matches the earlier full-Besu JFR hotspot in field multiplication, point addition and doubling. Bouncy Castle's [1.84 source](https://raw.githubusercontent.com/bcgit/bc-java/r1rv84/core/src/main/java/org/bouncycastle/math/ec/rfc8032/Ed25519.java) uses a different verification algorithm with precomputation and a combined scalar-multiplication path. The measured advantage does not come from omitting the signature check. Installed JDK sources and the exact Bouncy Castle source are saved alongside the evidence.

Evidence: `crypto.jsonl`, `reth-crypto.jsonl`, `CryptoProbe.java`, `reth_crypto.rs`, `jdk-source/` and `bc-Ed25519.java`. The Java microbenchmark ran before the receiver-timing copies were compiled. The Reth fixture files are exactly those verified by the Java microbenchmark.

## Delivery results

All cases accepted every offered approval. All had zero retries and zero unconfirmed drops. Average batch size was 1.0005–1.0021, so larger batches do not explain the result.

| Verifier | Workers | Outstanding calls | Offered approvals/sec | Confirmed during sending/sec | Backlog at deadline | Mean signed-to-ack |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Current JDK | 2 | 8 | 5,000 | 4,167.5 | 24,975 | 2,994.71 ms |
| Current JDK | 2 | 32 | 5,000 | 4,174.8 | 24,755 | 2,938.89 ms |
| Current JDK, repeat | 2 | 8 | 5,000 | 4,165.0 | 25,050 | 2,980.11 ms |
| Current JDK | 4 | 8 | 5,000 | 4,999.93 | 2 | 0.598 ms |
| Bouncy Castle, raw key | 2 | 8 | 5,000 | 5,000.0 | 0 | 0.140 ms |
| Bouncy Castle, raw key | 2 | 8 | 10,000 | 9,999.97 | 1 | 0.160 ms |

The final two/final one approvals in the four-worker and 10,000/sec cases completed between the end-of-sending sample and the drain check. Those drain checks took under 0.05 ms. The default JDK cases took approximately six additional seconds to drain. Signing-to-ack statistics include the drain; the confirmation-rate column counts only the fixed sending window. Delivery percentiles are histogram bucket upper bounds: the Bouncy Castle candidate's p99 was at most 0.25 ms at 5,000/sec and 0.5 ms at 10,000/sec. These are not exact percentile samples or maximum latencies.

The timed receiver stages explain the capacity ceiling:

| Case | Worker-queue wait, mean | Signature verification, mean | Store insertion, mean | Decode, mean | Complete worker task, mean |
| --- | ---: | ---: | ---: | ---: | ---: |
| JDK, 2 workers, 8 calls | 1,335.8 us | 470.8 us | 3.53 us | 0.20 us | 479.7 us |
| JDK, 2 workers, 32 calls | 7,077.3 us | 469.5 us | 3.51 us | 0.20 us | 478.2 us |
| Bouncy Castle, 2 workers, 8 calls, 5,000/sec | 5.48 us | 63.5 us | 3.31 us | 0.29 us | 69.8 us |
| Bouncy Castle, 2 workers, 8 calls, 10,000/sec | 6.96 us | 65.2 us | 3.71 us | 0.28 us | 72.6 us |

Verification consumes approximately **98% of the current JDK worker's measured processing time**. Two workers taking roughly 0.48 ms per batch can process around 4,170 singleton batches/sec; that agrees with the observed throughput. Offering 5,000/sec accumulates roughly 25,000 queued approvals in 30 seconds. Seconds of sender backlog do not mean an individual signature takes seconds to verify.

Increasing outstanding requests from eight to 32 changes throughput by only about 0.2%, while increasing the receiver's internal queue wait from 1.3 to 7.1 ms. Eight outstanding requests already keep both workers occupied. More concurrency mostly moves waiting work from OPS into Besu.

Mean receiver process CPU, including I/O and GC, was approximately 220–222% with two JDK workers, 273% with four JDK workers, 58% with the Bouncy Castle candidate at 5,000/sec and 117% at 10,000/sec; 100% is one CPU core. Those means cover sending and drain. The four-worker result demonstrates an isolated tuning option, but the earlier full-stack four-worker run was worse than its two-worker counterpart. Spending more CPU on verification competes with block execution; improving the verifier's efficiency is the stronger candidate.

Evidence: `matrix1-*/report.json`, `headroom-10000-bc-2w-8f/report.json`, process samples and stderr logs. `summary.json` gathers the measured cases and crypto comparisons. The baseline repeat after the candidate and four-worker tests reproduces the initial ceiling.

## Compatibility checks

Both the JDK path and Bouncy Castle raw-key path passed all **151 pinned Wycheproof Ed25519 cases: 88 valid accepted, 63 invalid rejected**, with zero mismatches. They accepted both existing Go-signed golden batches and rejected their `S + group order` signature-malleability variants. The microbenchmark additionally checks corrupted messages and signatures; the delivery test verifies fresh signatures produced by the real Go sender.

See `compatibility.json` and `external-sources.json` for exact cases, immutable vector URL and SHA-256. The test corpus comes from [C2SP Wycheproof](https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/ed25519_test.json). These checks support evaluating the candidate; they do not prove equivalence for every encoding or complete the production integration/security review.

## Historical interpretation and recommended next change

The JDK verifier call sequence was already present in the initial September 14 plugin and in the September 24 gRPC version: create Ed25519 `Signature`, initialize the trusted key, update the batch bytes, verify. Thus this expensive primitive was not introduced by the latest rebase. The earlier mild-overhead Besu comparison stayed at approximately 800 offered TPS, well below the receiver ceiling measured here. The later 5,000/sec runs enter a different queueing regime. This explains a plausible threshold effect and the Reth/Besu verification difference; it does not allocate every part of the historical full-stack regression to this component. Transport, logging, scheduling and concurrent block execution also changed or varied.

**Recommended next change, not yet implemented:** evaluate integrating the measured Bouncy Castle Ed25519 verification path, using the version Besu supplies, while preserving the trust checks, wire format, immediate sender batching, bounded queues and verification-before-acknowledgement. Keep the existing two-worker/eight-in-flight defaults for the first full-stack comparison. The raw-key candidate already provides substantial improvement; cached-point optimization is optional and needs explicit key-validation semantics.

Before treating that change as release-ready, run the existing integration/refusal tests with the candidate and compare full-stack committed TPS and approval availability at the producer. The focused probe contains no block production and therefore cannot promise 10,000 transaction TPS or a 7.8x full-stack improvement. No batching window, cryptographic bypass or larger default queue is justified by these results.

## Reproduction and provenance

- `build_probe.py` creates and compiles diagnostic copies with stage timers; `source-manifest.json` hashes original and diagnostic receiver sources.
- `run_matrix.py --prefix <fresh-name>` runs the five 5,000/sec cases. It requires the driver built from `poc/approval-performance/driver` into this directory. `--prefix <fresh-name> --cases bc-2w-8f --rate 10000` runs the headroom case. Cases use a fresh directory and close their owned processes in cleanup handlers.
- `src/ops/approvals/CryptoProbe.java`, `CompatibilityProbe.java`, `ProbeMain.java`, `ProbeMetrics.java` and `reth_crypto.rs` are the diagnostic entry points. `classpath.txt` records the exact local libraries. The Reth probe links the existing release `libed25519_dalek` artifact with `rustc -C opt-level=3`.
- `manifest.json` records source HEAD, artifact hashes, versions and cleanup. All tracked files stayed unchanged at `61d91e15816603b3c775443abe9174bdab685d64`.
