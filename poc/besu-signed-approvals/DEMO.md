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

Measured by `demo.py bench`: 32 transactions per block, four samples per configuration (the first
discarded as warm-up), the same load with and without the gate, medians. Apple M2 Max, Darwin arm64.
Raw data in [evidence/benchmark.json](evidence/benchmark.json).

| | OPS submissions/s | OPS request median | Gate work per transaction |
|---|---:|---:|---:|
| Without the gate | 91.9 | 10.1 ms | — |
| With the gate | 78.0 | 12.1 ms | 49 µs |

- **Submission** is end-to-end through the OPS HTTP API, including its RBAC and, with the gate on,
  the `ops_prepareApproval` round trip plus signing and queueing. The ~2 ms per request is what that
  preflight costs; the 15 % throughput difference is on a single-threaded submitter against a local
  stack, not a capacity measurement.
- **Gate work** is the plugin's own pre- plus post-processing per transaction, timed inside the
  selector. It excludes the execution itself and the tracing the EVM does while Besu builds the
  candidate.
- The harness's block wall-clock is recorded too, but it contains a fixed wait and Besu's repeated
  candidate rebuilds, so it is **not** a producer benchmark. A proper one needs a load generator and
  a node driven at its block cadence — the Reth PoC's Gasstorm runs are the model, and that work has
  not been done here.
