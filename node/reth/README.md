# OPS Reth policy runtime

`ops-reth` runs the generated DSL policy inside Reth's live EVM before each
application CALL, STATICCALL, DELEGATECALL, CALLCODE, CREATE, and CREATE2 frame.
Policy bytecode is private to the node. It is never deployed to a chain account,
and its gas, storage journal, access warming, and trace frames are isolated from
application execution. A denied inner frame vetoes the entire transaction even
when application code catches the revert.

Execution rules are published as one artifact per bound group. The guard runs
only the signer's current groups in the target policy organization, in sorted
order, until one permits the frame. The complete set shares the frame's 100,000
gas budget, and failures deny execution. A pinned snapshot cannot mix revisions
or legacy org-wide artifacts with grouped artifacts for the same organization.
Upgrade OPS and this node together before activating grouped revisions.

**Known membership limitation:** A frame can be denied when its shared policy
budget is exhausted before reaching a group that would allow it. Adding groups
to a caller can therefore cause an otherwise permitted action to fail. The
measured last-match workload passed at 11 memberships and exhausted the budget
at 12; this is not a universal membership limit. An organization with sixty
groups is supported by the tested workflow, but arbitrary memberships per caller
are not established. Optimization is deferred for now; see
[the accepted limitation](../../docs/OPEN_ITEMS.md#12-reth-per-group-permission-budget)
and [live measurements](../../docs/implementation/evidence/per-group-live-2026-09-25.md).

Reth is pinned to **v2.5.2**, commit
`5a6940e351fed80458fe6c9da8581cbe4b8bd036`. Preparation refuses tracked source
modifications and reuses the research checkout when available:

```sh
python3 node/reth/scripts/prepare.py --offline
cargo build --release --locked --manifest-path node/reth/Cargo.toml --features reth-sdk
cargo test --release --locked --manifest-path node/reth/Cargo.toml --features reth-sdk
```

Set `OPS_RETH_SOURCE` to another checkout of that exact commit. Omit `--offline`
from preparation to clone the pinned release if needed. Set `CARGO_TARGET_DIR`
to reuse a release artifact cache; otherwise Cargo writes `node/reth/target`.
The HTTP tests bind isolated localhost ports.

## Running

Configure these variables before starting the node. The signing private key
belongs to OPS; the node only receives trusted public keys.

| Variable | Value |
| --- | --- |
| `OPS_NODE_POLICY_CHAIN_ID` | Must match the genesis chain ID |
| `OPS_NODE_POLICY_DEPLOYMENT_ID` | Unique OPS deployment identifier |
| `OPS_NODE_POLICY_PUBLIC_KEYS` | JSON object mapping key ID to base64 Ed25519 public key |
| `OPS_NODE_POLICY_LISTEN` | Private listener, for example `127.0.0.1:8555` |
| `OPS_NODE_POLICY_TOKEN` | Bearer token shared with OPS |
| `OPS_NODE_POLICY_STATE_DIR` | Dedicated durable policy/archive directory |
| `OPS_NODE_POLICY_CAPACITY` | Optional pending identity limit; default `100000` |
| `OPS_POLICY_DECISION_LOG` | Set to `1` to print one `OPS_POLICY_DECISION {…}` JSON line per checked transaction on stderr (development diagnostic; off by default — it costs a synchronous write per transaction and records principal/selector pairs in the node log) |

```sh
node/reth/target/release/ops-reth node \
  --chain /absolute/path/to/genesis.json --dev --dev.block-time 1s \
  --dev.finality-depth 1 \
  --engine.cross-block-cache-size 64 \
  --datadir /absolute/path/to/reth-data \
  --http --http.addr 127.0.0.1 --http.api eth,net,web3
```

The `--dev` producer is intended for the local OPS stack. Production consensus
integration needs the same durable execution manifests at every importing node;
an arbitrary Ethereum peer cannot import OPS blocks without that evidence.
The node can start before OPS publishes facts; private status remains unready
and application execution fails closed until a fresh signed snapshot arrives.

Signed full-admin diagnostic requests may run while reporting `would_allow` and
per-frame policy decisions. An independent mandatory guard confines frames and
account reads to the selected organization or explicitly permitted public/shared
classes. Scope escape returns no execution output or trace. Ordinary requests
always enforce the active policy.

Candidate previews replace only the selected organization's policy in an
ephemeral execution handle. They report the candidate's decisions while the
active policy continues to authorize every application frame. Candidate bytecode
never enters the signed facts feed or changes later execution. The signed
simulation request requires an explicit `candidate_policy` key, with `null` for
ordinary calls.
An ordinary candidate cannot read live contract/account state, including through
record-party getters: an unpublished rule must not become a new data-access
oracle. Those previews require the scoped human-admin diagnostic route. Active
approved policy getters continue to operate normally.

The private listener supports `ops_policyApply`, `ops_policyStatus`,
`ops_submitTransaction`, `ops_simulate`, and `ops_transactionStatus`. Its exact
wire protocol is in [execution-context.md](../../docs/architecture/execution-context.md).
It is separate from public Reth JSON-RPC. IPC and public debug/trace modules are
disabled. `eth_call`, `eth_estimateGas`, and `debug_traceCall` are available through
signed private simulations; public calls cannot inherit an OPS principal.
Nonempty state/code/storage and block overrides are rejected for every simulation
mode. An authenticated call never authorizes replacing customer bytecode with a
program that reads otherwise inaccessible storage. Trace output options remain
available.

A pending transaction is bound to one principal and selected organization, even
when several principals share its signer. New execution requires a valid ticket; renewal must preserve that durable
binding. An `expired` status describes the current lease and is not final: a
previously pinned candidate can still settle, so OPS continues receipt polling. Rule denials describe the current
candidate and are not final pool eviction: Reth can retry an already admitted
transaction when later facts change. Included creation metadata is returned only
when a canonical receipt matches the exact archived block, and includes nested
successful CREATE/CREATE2 results. Reverted creations never become registration
evidence. Canonical reconciliation releases the bounded pending identity slot.
Permanent OPS registration and visibility projection wait for `finalized:true`,
backed by the node's finalized forkchoice header and canonical block checks.
Wait for that reconciliation before calling a newly deployed contract across
blocks. Inclusion alone remains provisional and can return to pending after a
reorganization.

The local example uses `--dev.finality-depth 1`; Reth's default is 64. These are
the dev miner's forkchoice decisions, not an external consensus guarantee. The
pinned dev miner starts its retained-hash window at the current tip on restart,
so that tip can immediately become its finalized head. Production finality must
come from the deployed consensus system.

Policy facts are immutable for a candidate block. Signed delta updates are atomic,
heartbeats extend only the installed digest's freshness lease, and produced blocks
retain the exact verified snapshot chain and executed identity envelopes before
publication. Self-import reuses that archive; ordinary simulations use current
permissions even when querying historical chain state.

Record-party getters run against live candidate storage. Every descendant code
and storage account must belong to the policy organization; active standard
precompiles are supported. Foreign account observations through BALANCE and
EXTCODE opcodes also fail the whole policy check, including caught child failures.
Same-organization proxy getters can delegate to registered implementations.
Optional signed code hashes apply to every getter descendant and diagnostic
account observation as well as ordinary application frames.

## Validation and supported boundaries

The repeatable smoke test needs the repository Go toolchain and Python
`cryptography`. It creates an isolated genesis, public development signing keys,
local ports, and a fresh data directory, then checks signed facts, scoped
simulations, pool submission, mining/self-import, deployment, and revocation:

```sh
python3 node/reth/scripts/smoke.py --binary node/reth/target/release/ops-reth
```

Evidence and logs remain under `.tmp/ops-reth-smoke-*`. The smoke chain enables
Shanghai; tests also verify active-fork precompile classification. EIP-7702
transactions and delegated accounts, SELFDESTRUCT, custom creation schemes,
custom precompile providers, and transaction-index traces currently fail explicitly. The local stack's supported
normal workflows do not require those features. MCP tooling is separate.

Implementation evidence: [reth-runtime.md](../../docs/implementation/evidence/reth-runtime.md).

## Reproducible load acceptance

The load harness measures signed private HTTP admission through canonical mining
with durable facts, identities, and block manifests enabled:

```sh
python3 node/reth/scripts/load.py --binary node/reth/target/release/ops-reth \
  --transactions 512 --rounds 3 --senders 8 --concurrency 8 \
  --facts-principals 1000 --execution-cache-mib 64 \
  --contention-note 'Describe other workloads running on this machine.'
```

It starts a fresh node for plain calls, three application frames, a compiled
record-party getter, and plain calls with signed delta/full-snapshot churn. Each
phase records attempted/admitted/mined/successful/reverted counts, latency,
publication timing, sampled RSS, hardware, and the exact binary hash. Receipt and
private-status reconciliation are reported separately from the timed mining
window. A banned transaction probe must remain without a receipt. Records and
logs stay in `.tmp/ops-reth-load-*`.

The default load chain uses 150 million gas per one-second dev block and only
public deterministic development keys. The successful record-party application
is [LoadRecord.sol](scripts/LoadRecord.sol), compiled outside the timed interval
using the pinned Solidity compiler. This measures the complete node path, not
isolated policy-interpreter cost or full OPS/explorer throughput. It does not
establish the roadmap's 5,000 TPS target.

Transaction identities currently require serialized synchronous archive writes.
That admission bottleneck remains open; see
[sustained throughput work](../../docs/OPEN_ITEMS.md#13-reth-sustained-transaction-throughput).
The current group's in-process timings imply only a
[policy-only theoretical ceiling](../../docs/implementation/evidence/per-group-live-2026-09-25.md#theoretical-throughput-from-policy-cost),
not achieved node TPS.

Reth's upstream 64-bit execution-cache default is 4 GiB and eagerly reserves
fixed-cache buckets when self-import starts. The local examples explicitly use
64 MiB; choose a cache budget suited to the production working set. Optional
`--memory-map` saves a bounded own-process macOS `vmmap` summary when available.
