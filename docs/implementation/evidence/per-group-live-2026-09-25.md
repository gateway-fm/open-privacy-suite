# Per-group execution: live acceptance and cost evidence

Verified on 2026-09-25 against implementation commit `214ab2cd` on
`feat/ops-dsl-reth`, using freshly built native OPS and guarded Reth. The stack
used its own PostgreSQL, Redis, chain, signing trust, ports, indexer and explorer.
Human login used the development mock provider; Ethereum ownership proofs and
transactions used actual signatures. All application changes went through HTTP
APIs and reviewed configuration, with independent author/reviewer identities.

## Functional results

| Scenario | Result |
|---|---|
| Baseline full-stack acceptance | All 12 checks passed: deployment, finalized writes, reconciliation, principal isolation, explorer OAuth/events, live record-party storage changes and revoked submission. |
| 60-group execution document | All 60 artifacts compiled, reviewed, activated and published. A signed transaction was included and reconciled under that policy. |
| Multiple memberships | A later group permitted a call; removing that membership denied it while preserving the earlier group's own grant. |
| Candidate and active replacement | Candidate preview left active permissions intact. Activating a one-group replacement revoked the removed group's grant. |
| Empty artifact set | Denied ordinary execution. Scoped human diagnostics previewed a recovery candidate without changing active denial; activating recovery allowed execution. |
| Real restart | Preserved the active reviewed revision, reconciled transaction and authenticated explorer history. |
| Rebuilt TypeScript SDK | All five live checks passed, including refresh, readiness, candidate diagnostics, revocation and principal isolation. |

First 60-artifact compilation through HTTP took **29.254 seconds**; a later
complete rebuild took **28.718 seconds**. Artifact runtime sizes were
**3,077–3,305 bytes**, totaling **184,848 bytes**. These bindings contain one
ordinary method rule each, with a second method on the last group. Compilation
cost and size will depend on rule complexity.

## Policy cost inside the node EVM

Apple M2 Max, 32 GiB RAM, macOS 26.6.1, ARM64. Release build; 100 warmups and
1,000 measured frames per configuration, 24,000 measured frames total. The
benchmark uses the exact bytecode returned by the live compilation API, signed
synthetic facts, and a STOP application contract to isolate policy preparation
and evaluation. Signing, fact-index construction and database setup are outside
the timed section. This is per-frame policy cost, not transaction throughput.

| Caller memberships with artifacts | First match: median µs | Last match: median / p95 µs | Last match: gas | Last match verdict |
|---:|---:|---:|---:|---|
| 1 | 17.3 | 16.8 / 20.2 | 6,291 | Allowed |
| 2 | 16.5 | 32.1 / 34.5 | 13,141 | Allowed |
| 5 | 17.5 | 81.7 / 87.8 | 36,820 | Allowed |
| 10 | 19.3 | 173.0 / 188.6 | 86,745 | Allowed |
| 11 | 19.8 | 191.1 / 206.0 | 98,305 | Allowed |
| 12 | 19.8 | 190.2 / 205.5 | 100,000 | Denied: gas limit |
| 20 | 22.3 | 174.2 / 190.9 | 100,000 | Denied: gas limit |
| 40 | 28.2 | 161.4 / 171.9 | 100,000 | Denied: gas limit |
| 60 | 35.0 | 149.4 / 159.5 | 100,000 | Denied: gas limit |

Unrelated directory groups did not increase gas: the same one-, two- and
five-membership cases consumed identical gas with seven and sixty artifacts in
the organization. For five memberships with the match last, median check cost
was **80.5 µs** with seven directory groups and **81.7 µs** with sixty.

## Theoretical throughput from policy cost

For planning, invert the **mean** check time from the JSON report (not the
median above). Assuming one execution thread spends all its time on these
permission checks, one evaluation pass per transaction, and the same check
cost for every application frame:

`policy-only tx/s = 1,000,000 / (mean check microseconds × checked frames per transaction)`

| Caller groups checked, match last | Mean check µs | One checked frame/tx: theoretical tx/s | Three checked frames/tx: theoretical tx/s |
|---:|---:|---:|---:|
| 1 | 17.15 | 58,300 | 19,400 |
| 2 | 32.38 | 30,900 | 10,300 |
| 5 | 82.41 | 12,100 | 4,040 |
| 10 | 174.87 | 5,720 | 1,910 |
| 11 | 193.95 | 5,160 | 1,720 |

These are approximate **policy-only CPU ceilings**, not measured transaction
throughput. The three-frame column is an arithmetic projection, not a new
three-frame measurement with these group artifacts. Nested application calls
each require another policy check, and their policies may cost different amounts.
Rejected cases are excluded from successful-throughput estimates.

Application execution, signature checks, transaction admission, database/state
access, durable writes, block production/import and RPC/OPS overhead all consume
additional time. Re-executing transactions in additional passes also consumes
policy CPU. Multiplying by the host's core count is not justified by this
single-thread benchmark. Serial `eth_call` latency below is not a sustained
mined-transaction throughput measurement either.

For context, the earlier 2026-09-17 private-node load run achieved only
**9.6–11.1 mined transactions/s** on this shared development host. Its analysis
identified serialized per-transaction durable archive writes as a bottleneck.
The current code still performs those writes under the ingestion lock; the
per-group test run did not change or benchmark that admission path under load.
See [the historical load and durability evidence](reth-runtime.md#where-the-stacks-throughput-actually-goes-2026-09-17)
and [remaining capacity work](../../OPEN_ITEMS.md#13-reth-sustained-transaction-throughput).

## Serial live RPC latency

Each row contains 20 loopback HTTP `eth_call` requests after three warmups.
Requests were spaced by 120 ms outside the timing window to avoid rate-limit
interference. Latency includes OPS authentication/facts/database work and the
private Reth request, while the development miner runs. The caller also retains
one original membership with no artifact in this replacement document.

| Caller memberships with artifacts | First match: median / p95 ms | Last match: median / p95 ms | Last match verdict |
|---:|---:|---:|---|
| 1 | 11.19 / 49.90 | 11.17 / 67.09 | Allowed |
| 2 | 10.87 / 82.52 | 10.61 / 57.21 | Allowed |
| 5 | 11.67 / 59.95 | 10.21 / 64.29 | Allowed |
| 10 | 9.42 / 110.20 | 11.10 / 71.17 | Allowed |
| 20 | 12.27 / 58.50 | 13.44 / 98.37 | HTTP 403: node rejected |
| 40 | 13.02 / 174.21 | 11.48 / 155.84 | HTTP 403: node rejected |
| 60 | 12.19 / 166.31 | 13.36 / 129.29 | HTTP 403: node rejected |

## Capacity limit and remaining work

**Decision, 2026-09-25:** Retain this as an accepted temporary limitation;
optimization is deferred. It is tracked in
[OPEN_ITEMS §12](../../OPEN_ITEMS.md#12-reth-per-group-permission-budget).

The organization can contain sixty groups without overflowing one policy
contract. However, each frame still shares **100,000 policy gas** across all
evaluated groups. In the isolated benchmark, the last-match case passed with
11 memberships and exhausted the budget at 12. The live API passed at ten and
denied at twenty, forty and sixty; a first-matching rule succeeded at all tested
counts. Every denied benchmark sample consumed exactly 100,000 gas.

These counts are workload-specific, not a universal supported membership limit.
More expensive predicates and additional facts can reach the budget sooner.
Before promising callers many simultaneous memberships, reduce repeated policy
work or establish measured supported limits while retaining bounded execution.
No production code was changed during this test run. The test harness now
allows a longer HTTP timeout for large compilation requests.

Browser page interactions and a production identity provider were not exercised.
The explorer OAuth/BFF flow was tested over HTTP. These local latency samples
do not establish sustained production throughput or multi-node capacity.

## Reproduction and retained evidence

See the [stack runbook](../ops-reth-stack.md#per-group-acceptance-and-cost-measurement)
for commands. The [machine-readable report](per-group-live-2026-09-25.json)
contains all samples' summaries, check names, transaction hashes, revision IDs
and binary SHA-256 digests. It contains no credentials.

Local evidence and the generated benchmark fixture remain in
`.tmp/ops-reth-group-live-20260925`. Its private `state.json` contains credentials
and must remain local. The disposable test processes and Docker volumes were
removed after verification; unrelated services were left running.

Additional validation: Python harness ownership tests and syntax checks, SDK
TypeScript build, release benchmark, and Clippy on the benchmark with
`--features reth-sdk -- -D warnings` all passed.

| Tested binary | SHA-256 |
|---|---|
| ops | `dac5f1442568bd1ab63f9a77e985d3c49c9d72727ec3a6b642d81fa6c2bb28c5` |
| reth | `2707c2dce6acced20ee49b0ddefe80d9cc918134af98c0931192c7d45f5d129e` |

## Review fixes and verification

The follow-up review found that the production Nginx proxy still used its
60-second read timeout, despite the API allowing five minutes for artifact-set
compilation. Both production and E2E `/api/` proxy configurations now allow
330 seconds, covering compilation and the API's 15-second response margin.

An isolated Nginx container loaded the production configuration with a local
dummy upstream that waited 65 seconds before responding. The fixed configuration
returned HTTP 201 after 65.00 seconds; an otherwise identical control without the
timeout setting returned HTTP 504 after 60.01 seconds. Nginx syntax validation
also passed for both production and E2E configurations. This verifies proxy
timeout behavior; it does not repeat the full compilation or live-stack tests
above. The temporary container and dummy upstream were removed afterward.

The generated TypeScript SDK was regenerated from the checked-in OpenAPI spec
to include `ExecutionDiff.artifacts`. `npm --prefix sdk test` passed the generated
code drift check, SDK build, type checks and all 11 runtime tests.
