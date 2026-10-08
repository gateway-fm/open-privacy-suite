# Reth development demo

From a clone of the signed-approvals branch, run:

```sh
make demo-reth
```

Requirements: Docker with Compose, Make and Bash. No host Rust, Go, Python,
Foundry, Solidity compiler, sibling clones or prebuilt local artifacts are needed.
The first build downloads the pinned toolchains and compiles custom Reth, so it
takes longer than subsequent cached starts. ARM64 and AMD64 use native Docker
builds; the host's Docker resources must be sufficient for Rust compilation.
Allow at least 10 GiB of free disk space for the initial build; additional
builder caches and existing images may require more.

The stack contains separate Reth, OPS backend, OPS frontend, PostgreSQL, Redis
and block-driver containers. An initialization container creates synthetic
contracts, wallets and keys. The fixture runner seeds Bank A and Bank B through
the real OPS API; a development Engine API driver then produces blocks every
second. External identity and consensus services are represented by fixtures.
There is no indexer/explorer in this stack.

The command prints the Compose project and random localhost URLs. Open the OPS
frontend to inspect the application; use its development identity picker for
`did:test:reth-demo-alice`. The local development admin token is
`ops-reth-local-demo-only`. Wallet keys, approval signing keys and all credentials
are public synthetic fixtures. Never fund them or use this configuration outside
local development. Engine API, approval delivery, databases and Redis have no
published host ports. Reth RPC includes debug methods and is published on localhost
for developer inspection; it is deliberately outside OPS authorization.

```sh
make demo-reth-status       # containers belonging to this checkout's project
make demo-reth-logs         # follow service logs
make demo-reth-down         # stop this demo, retain chain/database state
make demo-reth              # restart with the retained state
make demo-reth-reset        # stop this demo and remove its volumes
make demo-reth-check        # fresh stack; run all four acceptance scenarios
make demo-reth-walkthrough  # fresh stack; pause before each scenario
```

**Check and walkthrough reset this demo's volumes**, including its policy database
and chain. They pause automatic block production while showing an allowed call,
an OPS cross-org refusal, a producer veto after execution diverges, and exclusion
of a direct transaction without an approval. They verify actual receipts and
state, fail on any mismatch, save evidence under `.tmp/reth-demo-evidence/`, and
start normal block production afterward. The services remain running for inspection.

Projects are derived from the checkout path, so separate worktrees do not share
containers or volumes. The wrapper ignores the repository's `.env`. Override
`RETH_DEMO_PROJECT` to choose an explicit project (reuse that value for cleanup),
or `RETH_DEMO_BACKEND_PORT`, `RETH_DEMO_FRONTEND_PORT`, `RETH_DEMO_RPC_PORT` to
choose localhost ports. `RETH_DEMO_BUILD_JOBS` controls Rust build parallelism
(default four). Existing stacks are not selected by these commands.

Builds reuse `Dockerfile.backend` and `frontend/Dockerfile` development targets.
The Reth Dockerfile verifies the upstream commit in `compatibility.json`, uses
the matching Rust toolchain and locked dependencies, and runs as uid 1000.
The container fixture compiler uses Solidity 0.8.35 and the existing genesis,
seeding and demonstration code. Build inputs exclude host binaries and checkouts.
These targets do not publish a release or qualify a production deployment.
