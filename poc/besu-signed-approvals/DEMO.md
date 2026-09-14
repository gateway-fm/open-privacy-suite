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

## Sustained load: Gasstorm Adaptive, the real ceiling

This is the same test the Reth PoC runs, in Gasstorm's own dashboard: **Through Privacy Proxy →
Adaptive → ETH Transfer**, ten wallets, 200 M block gas limit, one-second blocks. Adaptive raises the
rate until the pool backs up, so the peak is measured rather than requested. A browser drives the real
UI; the screenshots below are that browser's, and every confirmation is re-checked against receipts on
chain afterwards.

```sh
# one interactive session to watch yourself
python3 poc/besu-signed-approvals/gasstorm_ui.py            # then open http://127.0.0.1:18000/load-test/
python3 poc/besu-signed-approvals/gasstorm_ui.py --without-gate

# or the scripted A/B that produced the screenshots (needs Playwright; see the script header)
OPS_PLAYWRIGHT_ROOT=... OPS_UI_DURATION=60 ./poc/besu-signed-approvals/run_ui_case.sh gate-on
OPS_PLAYWRIGHT_ROOT=... OPS_UI_DURATION=60 ./poc/besu-signed-approvals/run_ui_case.sh gate-off --without-gate
```

| 60 s Adaptive, ETH transfer | Peak TPS | Average TPS | Sent | Confirmed | Failed | Successful receipts | Blocks |
|---|---:|---:|---:|---:|---:|---:|---:|
| Gate **on** | **773** | 671 | 40 277 | 40 198 (99.8 %) | 0 | 40 198 | 59 |
| Gate off | 806 | 779 | 43 669 | 43 622 (99.9 %) | 0 | 43 622 | 59 |

![Adaptive run with the approval gate on](evidence/gasstorm/browser-gate-on/eth-transfer.png)

*Gate on: 773 tx/s peak, 40,198 confirmed, 0 failed. The same run without the gate is in
[evidence/gasstorm/browser-gate-off/eth-transfer.png](evidence/gasstorm/browser-gate-off/eth-transfer.png).*

**The ceiling on this machine is ~770–800 tx/s, and the gate costs about 8 % of it.** Nothing failed
in either run; the few dozen still pending are submissions that had not reached a block when the
window closed. Every displayed confirmation was verified against a receipt afterwards — 40,198
receipts with the gate on, all successful, no duplicates in the generator's log.

Caveats worth stating in the meeting: the generator, OPS, PostgreSQL, Redis and Besu all share one
laptop, so this is the ceiling of *this machine*, not of the design; the Reth PoC reached comparable
figures on the same hardware, which is the honest comparison to draw. Confirmation latency here is
1.1 s median (a one-second block cadence sets the floor), p99 6.5 s.

Raw evidence per run: the dashboard screenshot, the peak screenshot, the generator's own history
record, every status sample, the WebSocket frames, and the gzipped receipt list, under
`evidence/gasstorm/browser-gate-on/` and `browser-gate-off/`.


### Constant-rate runs, headless

`gasstorm.py` drives the same generator without the dashboard, at fixed rates, and counts receipts
itself — useful in CI or over SSH:

```sh
python3 poc/besu-signed-approvals/gasstorm.py --rates 100,300,500 --duration 20
```

| Requested | Gate | Submitted | Successful receipts | No receipt | Reverted | Gate work/tx |
|---:|---|---:|---:|---:|---:|---:|
| 100 | off | 2 002 | 2 000 | 2 | 0 | — |
| 100 | **on** | 2 002 | 2 001 | 1 | 0 | 14.2 µs |
| 300 | off | 6 004 | 5 964 | 40 | 0 | — |
| 300 | **on** | 6 003 | 6 001 | 2 | 0 | 8.1 µs |
| 500 | off | 10 012 | 10 012 | 0 | 0 | — |
| 500 | **on** | 10 011 | 9 968 | 43 | 0 | 7.0 µs |

At these fixed rates the two configurations are indistinguishable; the difference only appears when
Adaptive pushes past them. Raw data: [evidence/gasstorm/summary.json](evidence/gasstorm/summary.json).
