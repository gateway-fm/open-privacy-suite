# Demo: the whole stack, and what it costs

One command brings up PostgreSQL, Redis, a Besu node with the approval plugin, and the **real OPS
server** — its own RBAC over its own database, its own signing, its own delivery — then walks four
steps. Nothing about authorization is stubbed: the fixtures are the test identities and wallets, the
development login, and the script standing in for a consensus client and an identity provider.

```sh
cd <repo>
export JAVA_HOME=$PWD/.tmp/jdk25/jdk-25.0.4.1+1/Contents/Home
go build -tags mockauth -o .tmp/ops-server ./cmd/server
(cd poc/besu-signed-approvals && gradle --no-daemon build)

python3 poc/besu-signed-approvals/demo.py            # the four steps, ~2 min
python3 poc/besu-signed-approvals/demo.py --pause    # stop before each step, for a live audience
python3 poc/besu-signed-approvals/demo.py --linea    # with Lineth's transaction-pool plugin loaded too
python3 poc/besu-signed-approvals/demo.py bench      # the numbers below, ~6 min
```

Requirements: Docker (PostgreSQL 15 and Redis 7 containers, removed on exit), JDK 25, Go, Python 3,
Foundry `cast`, solc 0.8.35, and the Besu 26.8.1 distribution under `.tmp/besu-dist/`. Everything is
created fresh per run and torn down afterwards; the OPS log, the node log and `evidence/demo.json`
are kept.

## What the four steps show

| Step | What happens | What it proves |
|---|---|---|
| 1 | Alice calls Bank A's router → relay → vault through OPS | The ordinary path: OPS applies its database policy, signs an approval, delivers it, and Besu commits the transaction. Vault A = 7 |
| 2 | Alice tries to reach Bank B's vault | OPS refuses from the real organization boundary in its database (`transaction denied: cross-org access not permitted`) — nothing reaches the node |
| 3 | Alice's approved call is overtaken by a higher-fee transaction that redirects the relay to Bank B | The producer excludes her transaction: no receipt, and her nonce, her balance and every application slot are unchanged. The hash her client received meant admission, not execution |
| 4 | Alice deploys a contract | Creation is bound by the strict fingerprint, the deployment is included, and OPS registers the new contract to her organization |

Step 3 is the point of the whole design: the approval describes an execution, and an execution that
no longer matches it does not get committed — not "fails with a receipt", but never enters the block.

## Cost

`demo.py bench`: 128 transactions per block from 16 concurrent clients, four samples per
configuration (the first discarded as warm-up), the same load with and without the gate, medians.
Apple M2 Max, everything — OPS, PostgreSQL, Redis, Besu and the load — on one laptop.
Raw data in [evidence/benchmark.json](evidence/benchmark.json).

| | OPS submissions/s | OPS request median | Gate work per transaction |
|---|---:|---:|---:|
| Without the gate | 775 | 17.5 ms | — |
| With the gate | 657 | 21.1 ms | 22 µs |

- **Submission** is end-to-end through the OPS HTTP API — RBAC, database, forwarding, and with the
  gate on also the `ops_prepareApproval` round trip, the Ed25519 signature and the delivery queue.
  The ~3.5 ms it adds to a request is what that preflight costs; the ~15 % difference in rate is
  what 16 clients get out of this laptop, not a capacity limit of the design.
- **Gate work** is the plugin's own pre- plus post-processing per transaction, timed inside the
  selector: the approval lookup, the fingerprint of the observed execution, and the comparison. It
  settles at 12–22 µs once the JIT is warm, and excludes the execution itself and the EVM tracing
  Besu does while building the candidate.
- The harness's block wall-clock is recorded too, but it contains a fixed wait and Besu's repeated
  candidate rebuilds, so it is **not** a producer benchmark. A proper one needs a load generator at
  the node's block cadence — the Reth PoC's Gasstorm runs are the model, and that work has not been
  done here.

Single-client numbers, for comparison: one connection submitting serially gets ~90/s simply because
each round trip is ~11 ms. That is a latency measurement wearing a throughput costume; it is the
concurrent figures above that say anything about the stack.

## Sustained load (Gasstorm)

`gasstorm.py` runs the same thing the Reth PoC does: Gasstorm's own load generator signs and submits
through OPS's JSON-RPC route while a clock-driven producer builds a block every second, and the
result is counted from receipts on chain, not from what the generator believes it sent. Ten funded
wallets under one identity, constant-rate ETH transfers, 20 s per rate, one isolated stack per
configuration.

```sh
python3 poc/besu-signed-approvals/gasstorm.py --rates 100,300,500 --duration 20
```

| Requested | Gate | Submitted | Successful receipts | No receipt | Reverted | Generator's send rate | Gate work/tx |
|---:|---|---:|---:|---:|---:|---:|---:|
| 100 | off | 2 002 | 2 000 | 2 | 0 | 76/s | — |
| 100 | **on** | 2 002 | 2 001 | 1 | 0 | 76/s | 14.2 µs |
| 300 | off | 6 004 | 5 964 | 40 | 0 | 228/s | — |
| 300 | **on** | 6 003 | 6 001 | 2 | 0 | 228/s | 8.1 µs |
| 500 | off | 10 012 | 10 012 | 0 | 0 | 362/s | — |
| 500 | **on** | 10 011 | 9 968 | 43 | 0 | 374/s | 7.0 µs |

**The gate does not change the outcome at these rates.** Around 10 000 transactions land in ~32 s
with it and without it; nothing reverts; the handful without a receipt are submissions still in the
pool when the window closed, and they appear on both sides. The generator's own send rate (76, 228,
374/s) is what it achieved while sharing this laptop with OPS, PostgreSQL, Redis and Besu — at a
requested 500 it could not keep up, which is why the two configurations look identical: the bottleneck
is the machine, not the gate.

**The ceiling was not found.** A 1 000/s run stalled the block producer on this hardware, so the
highest rate reported here is 500. Finding the real limit needs the generator on separate hardware
from the node, which the Reth PoC had and this one does not.

Raw data: [evidence/gasstorm/summary.json](evidence/gasstorm/summary.json), per-run generator records
and the block log of each producer beside it.
