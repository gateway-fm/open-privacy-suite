# OPS with guarded Reth: local stack and acceptance

Run these commands from the worktree whose V2 code you are validating. The harness starts the
actual OPS application, guarded Reth, chain-indexer, OPS frontend, and the
privacy-mode explorer (BFF plus frontend). PostgreSQL and Redis run in a unique
Docker Compose project. Every invocation gets separate ports, database volume,
chain data, signing trust, logs, and process manifest. Other stacks are untouched.

## Prerequisites

- Go from this repository's `go.mod`, Node compatible with the two frontends,
  Python 3, Docker Compose, and native **solc 0.8.35** on `PATH`.
- Installed dependencies in this worktree's `frontend/node_modules` and the
  sibling `block-explorer/frontend/node_modules`.
- Sibling `chain-indexer` and `block-explorer` checkouts. Their source stays
  unchanged; native binaries and the explorer frontend copy live in stack state.
- The guarded Reth binary built from `node/reth`'s pinned Reth v2.5.2 source.
  The default is the main checkout's
  `.tmp/reth-policy-poc/target/release/ops-reth`.

The native application build uses `-tags mockauth`, avoiding the missing native
compiler in the current ARM backend image. Explorer BFF uses `-tags privacy`, so
its indexer client and contract-verification writes are compiled out. The BFF
obtains viewer-filtered chain data only through OPS.

## Start, test, restart, stop

Use a fresh stack when moving from the original V2 development branch to the
main-reconciled branch. Main's published migration 071 remains unchanged; V2's
previous migrations 071–081 are now 072–082. Databases initialized by main
through 071 upgrade normally. Databases initialized by the old V2 branch have
different migration identities and must not be opened by the reconciled binary.
Keep their backup and original worktree if their local data is still needed;
start a separate database for reconciliation checks. Do not edit `schema_version`
to make an old V2 database appear compatible.

```sh
python3 scripts/ops-reth-stack/stack.py start
```

Optional paths: `--reth /path/to/ops-reth`, `--indexer /path/to/chain-indexer`,
`--explorer /path/to/block-explorer`, and `--directory /new/state/directory`.
The state directory must not already exist. Start prints the state directory and
three browser URLs. Set `STACK` to that exact directory:

```sh
STACK=/absolute/path/printed/by/start
python3 scripts/ops-reth-stack/stack.py status "$STACK"
python3 scripts/ops-reth-stack/stack.py acceptance "$STACK"
python3 scripts/ops-reth-stack/stack.py restart "$STACK"
python3 scripts/ops-reth-stack/stack.py acceptance "$STACK"
python3 scripts/ops-reth-stack/stack.py stop "$STACK"
```

`restart` restarts the native components, checks the Docker dependencies, and
preserves chain data, databases, node policy state, and signing keys.
When a completed acceptance run exists, restart also verifies the existing active
revision, reconciled transaction, and authenticated explorer history. A stopped
stack can be started again with the same `restart` command. It uses the existing
binaries; a fresh `start` rebuilds the current source.
Use `restart "$STACK" --rebuild` to rebuild OPS and the signing helper from this
worktree before restarting against the existing data. Reth is loaded from the
same configured path, so rebuilding that binary separately is picked up on
restart. The state manifest records SHA-256 digests of the four native binaries.

For disposable cleanup, `stop "$STACK" --remove-volumes` removes only that
Compose project's database volume. Local logs and chain data remain available
for inspection. Stopping native processes requires both their recorded PID and
start time to match; a reused PID is never killed. No global `pkill`, Docker
prune, shared container names, or shared database is used.

## What acceptance proves

The command uses real HTTP endpoints and signed transactions. It does not insert
application rows directly or bypass policy projection:

1. Authenticate named human author/reviewer identities; bootstrap an organization
   and its administrators through the existing platform operation endpoints.
2. Create ordinary groups by submitting, reviewing, and independently activating
   a complete groups source; reject the author's own activation.
3. Onboard users, mark KYC through the admin API, and prove ownership with real
   Ethereum personal-sign challenges. Two named users share the same signer.
4. Import the legacy execution baseline, compile it, independently approve it,
   and wait for OPS readiness to confirm node publication.
5. Submit a scoped signed CREATE, wait for canonical finalized execution and
   committed OPS registration, then adopt its ABI through the registry stream.
6. Execute a state-changing call and read live state. Verify the other principal
   with the same signer remains denied and cannot read another user's submission.
7. Retrieve the actual indexed transaction and emitted event with the user's JWT;
   anonymous transaction lookup returns 404. Complete explorer OAuth code
   exchange and retrieve the same transaction through the BFF's HttpOnly session.
8. Activate an ABI-pinned `recordParty` rule; execute while the linked signer is
   the live record party, change that party on-chain, and observe denial without
   changing the OPS membership or rule source.
9. Independently activate rule revocation, wait for publication, submit again,
   and verify `POLICY_DENIED` with no receipt across multiple candidate blocks.

Submission returning a transaction hash acknowledges a queued intent. It is not
an execution success response. `denied` is also not a permanent terminal state:
an already-running candidate may settle, and facts may change before the signed
ticket expires. The acceptance check observes the current denial and absence of
canonical inclusion. Included/reverted status and `reconciled` describe actual
execution and OPS bookkeeping separately.

The command writes `acceptance.json` with check names, test organization/principal
IDs, revision digest, and transaction hashes. `state.json` additionally contains
development credentials and the process restart manifest; it and the random
Ed25519 signing seed are mode 0600 in a mode 0700 directory. Do not publish that
state file. These are disposable mock-auth identities and the genesis funds the
well-known Ethereum development private key `1`.

The named identities are `did:test:ops-reth-author`,
`did:test:ops-reth-reviewer`, `did:test:ops-reth-user`, and
`did:test:ops-reth-other`. The first two are deployment-allowlisted platform
reviewers and also receive explicit organization administrator memberships.
Use their mock login identities to inspect configuration sources and revisions
in the OPS UI. The completed acceptance intentionally leaves the operator's
execution binding denied so revocation is visible and reviewable.

## Per-group acceptance and cost measurement

After baseline acceptance, run the group scenario against the same isolated
stack and its freshly built OPS/Reth binaries:

```sh
python3 scripts/ops-reth-stack/group_acceptance.py "$STACK"
OPS_GROUP_COST_FIXTURE="$STACK/group-cost-fixture.json" \
OPS_GROUP_COST_REPORT="$STACK/group-cost.json" \
  cargo test --release --locked --manifest-path node/reth/Cargo.toml \
  --features reth-sdk --test frame_cost group_policy_check_cost -- --ignored --nocapture
python3 scripts/ops-reth-stack/stack.py restart "$STACK"
```

This creates 60 groups through reviewed configuration, compiles and activates
their complete execution document, and waits for a signed transaction to be
included and reconciled. It checks grant union, membership removal, artifact
replacement, candidate isolation, and empty-set recovery. The original revoked
policy is restored before the ordinary restart assertions run.

`group-acceptance.json` records 20 serial RPC samples per configuration, after
three warmups. Requests are paced outside the timing window. `group-cost.json`
isolates preparation and EVM policy evaluation using the exact artifacts
returned by that live API run, with 1,000 samples after 100 warmups. Directory
sizes of seven and sixty distinguish unrelated groups from caller memberships.
The in-process benchmark uses a STOP application contract; it measures policy
cost, not network throughput or application execution. Both measurements record
denial when the shared 100,000 policy-gas budget is exhausted; an organization
with 60 groups does not imply that a caller can scan all 60 within that budget.

## Runtime boundaries and current limits

This is a development harness, not the production network layout. PostgreSQL,
Redis, Reth public/private RPC, Vite servers and indexer gRPC use loopback ports.
The existing native OPS and explorer BFF servers listen on their configured
ports on all interfaces; run on a trusted development host. Production should
retain the separate network zones from `docker-compose.privacy.yml` and private
authenticated node transport. The harness does not expose Reth's private policy
methods through public RPC.

Reth runs `--dev.finality-depth 1 --dev.block-time 1s`, allowing OPS to reconcile
finalized contract creations. Its development cross-block cache is explicitly
64 MiB (`--engine.cross-block-cache-size 64`), rather than the pinned Reth
production default of 4096 MiB. Each stack generates its own random Ed25519 trust
and private listener token. `/ready` must report synchronized fresh facts before
the acceptance run proceeds.

The indexer uses `ENABLE_TRACING=false`: blocks, transactions, receipts and event
logs are indexed and tested. Internal-call traces and trace-derived enrichment
are absent. Token metadata getters that require unauthenticated `eth_call` on
Reth cannot bypass named execution policy; they need a separately designed
authorized integration. This does not prevent the tested receipt/event/BFF
workflow. Explorer history remains filtered by the existing OPS visibility
model; `recordParty` here governs live execution, not historical visibility.

CI approval, compliance, approver trust-root, platform source, co-activation and
writer-closure regressions run in the backend suites documented in
[configuration stream evidence](evidence/configuration-streams.md). MCP tooling
is outside this implementation phase.

Harness ownership checks:

```sh
python3 -m unittest discover -s scripts/ops-reth-stack -p test_stack.py
```

On failure, inspect `ops.log`, `reth.log`, `indexer.log`, `explorer-api.log`,
`frontend.log` and `explorer-frontend.log` inside the printed state directory.
The harness leaves failed-start resources available for investigation; use its
printed scoped stop command for cleanup.
