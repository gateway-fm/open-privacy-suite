# OPS signed approvals

Supported integration source for OPS V1. Besu loads a plugin; Reth runs a custom binary built
against an unmodified upstream checkout. Both use the same [wire contract](../docs/implementation/approvals-wire-contract.md)
and Go-signed golden vectors. The OPS V2 policy runtime is separate work.

An approval authorizes one transaction hash and its observed execution fingerprint. OPS checks
policy and hands the approval to asynchronous signing/delivery workers before forwarding the
transaction. The producer executes a candidate provisionally and commits it only if its
fingerprint matches an unexpired approval. No approval database, synchronous flush, or batch-fill
timer is introduced.

This is **producer enforcement**, not a consensus rule. Imported blocks are not checked for
approvals. Every authorized producer must use enforcement; access to Engine API, node RPC,
delivery ports and signing secrets must be restricted. See [operations](OPERATIONS.md) before enabling it.

## Compatibility and builds

| Integration | Supported upstream | Toolchain | Artifact |
|---|---|---|---|
| Besu | 26.8.1, Maven 26.8.1-d97cbd6 | Temurin 25.0.4.1+1, Gradle 9.0.0 | `ops-besu-approvals-0.1.0-besu-26.8.1.jar` |
| Reth | 2.5.2, commit `5a6940e351fed80458fe6c9da8581cbe4b8bd036` | Rust 1.98.1, protoc | `ops-reth-approvals` |

The machine-readable pins are in [compatibility.json](compatibility.json). Besu's plugin API is
unstable: another Besu version needs a new build and the full compatibility suite. Do not copy
the JAR into a different version. Reth dependencies resolve from `.tmp/reth`; `build.py` clones
and verifies the exact upstream commit and refuses a modified checkout. Cargo is locked.

From the repository root, with the toolchain on PATH (and JAVA_HOME for Besu):

```sh
python3 node-approvals/build.py besu
python3 node-approvals/build.py reth
```

Each command runs native tests and packages a separate directory under `.tmp/approval-release/`
with the artifact, checksums, version, source commit, toolchain, compatibility and operator guide.
A dirty build is identified in `build.json`; release builds must have `source_dirty: false`.
Use `--output` for a fresh destination when rebuilding. Verify `SHA256SUMS` before installation.
The Besu archive is reproducibly ordered; this does not promise identical native binaries across
toolchains or operating systems. Reth bundles name the host OS and architecture.

CI builds both targets, runs their unit tests, shared vectors, real-node scenarios and OPS HTTP
scenarios, then retains candidate artifacts. Publishing a release is a separate maintainer action
after those jobs pass. Use an independent `approvals-vX.Y.Z` tag and include the supported node
versions and checksums. OPS backend/frontend image publication ignores that tag prefix. A
successful local build alone is not deployment qualification.

## Validation and upgrades

Scenario fixtures and historical measurements remain under `poc/`; shipped Java/Rust source
lives here. Follow the [Besu harness](../poc/besu-signed-approvals/README.md) and
[Reth harness](../poc/reth-signed-approvals/README.md). Set `OPS_EVIDENCE_DIR` to a fresh directory.
Never run fixtures against a production database or node distribution: the harness installs
plugins and prepares disposable databases.

For each node/library bump, update the compatibility record, lockfiles and artifact name; run
Go race tests, Java/Rust tests, golden-vector verification, real-node mismatch/lifecycle/reorg/
expiry/restart cases and HTTP policy scenarios. Recheck classpath isolation for Besu. Record
results in the [release review](../docs/implementation/approvals-release-review.md), including
any unsupported fork/plugin combinations. Roll out to a canary producer before the rest.

Supported transaction envelopes are replay-protected legacy and EIP-1559. Calls V3 binds the
call graph, inputs, value, code, storage context and success/failure; it deliberately permits
ordinary storage/output/log changes. Contract lifecycle operations use strict V2. EIP-2930,
4844 and 7702, policy revocation of existing approvals, durable recovery, automatic transaction
reconciliation and a separate preflight replica URL are outside this release.

## Development performance

On one Apple M2 Max (12 cores, 32 GiB, macOS 26.6.1), the 25 September local full-stack comparison
measured **Reth: 2,639 TPS without approvals / 1,962 with; Besu: 2,298 / 1,296**.
These are development measurements for that machine, workload and configuration, **not limits of
the solution or production throughput guarantees**. They precede the main rebase and subsequent
hardening; they have not been relabelled as measurements of this release build. See the
[full report](../poc/approval-performance/README.md) for receipt checks, overload latency and sizing.
