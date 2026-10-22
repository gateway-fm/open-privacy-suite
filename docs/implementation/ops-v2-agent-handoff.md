# OPS V2 DSL and Reth: agent handoff

Updated 25 September 2026. This is the starting point for continuing the PoC on
`feat/ops-dsl-reth`, originally at
`/Users/blade/work/software/privacy-proxy/.tmp/worktrees/ops-dsl-reth`.
The latest functional fix is `8d835dd4`; later documentation commits describe it.
The original branch is preserved on origin. For the main-reconciled migration
sequence and database compatibility, use the [stack runbook](ops-reth-stack.md).

## Scope and reading order

This work implements the agreed **V2 DSL and governed configuration scope**,
including node-side execution enforcement. It does not establish completion of
the whole V2 roadmap. V3 ASRN/operator-blind RPCs and V4 full operator blindness
remain future work. Solidity permission checks do not hide execution data from
the operator.

| Read | What it establishes |
|---|---|
| [Implementation plan](../dsl-node-policy-implementation-plan.md) | Accepted scope, original integration risks, delivery status and exclusions. Read the later delivery status alongside the original plan. |
| [Execution identity contract](../architecture/execution-context.md) | Authenticated principal binding, signed facts, simulation binding and replay. |
| [Configuration API](configuration-api.md) | Authoring, review, exact approval, activation, CI approval and configuration ownership. |
| [API migration map](api-migration-map.md) | Which configuration writes moved to documents and which operational APIs remain. |
| [Per-group artifact specification](execution-artifact-granularity.md) | Motivation, rejected alternatives, formats, compatibility and runtime semantics. |
| [Reth runtime](../../node/reth/README.md) | Build, private node interface and supported execution boundaries. |
| [Stack runbook](ops-reth-stack.md), [SDK](headless-sdk.md) | Reproduce an end-to-end workflow with real processes and named identities. |
| [September 25 evidence](evidence/per-group-live-2026-09-25.md), [JSON results](evidence/per-group-live-2026-09-25.json) | Actual checks and measured costs, distinguished from throughput projections. |
| [Open items](../OPEN_ITEMS.md) | Accepted limitations and work that has not been delivered. |

The original roadmap PDF and broader design research, including `DECISION.md`,
live in the main checkout outside this worktree. They are included in the local
backup under `supplemental-main-checkout/`. The documents linked above describe
the implementation without requiring those historical files to understand its
principal boundaries. Some older evidence records intermediate states; use this
handoff and the September 25 report for the continuation's final status.

## Why execution authorization moved into Reth

An OPS-side pre-flight trace can describe a different state or call tree from
the transaction that is eventually executed. This branch authenticates and
admits the request at OPS, then enforces the DSL during actual node execution.
The node checks actual application frames, including nested calls and creation,
against live execution state and a coherent pinned policy/facts snapshot. A
denied nested frame vetoes the transaction even if application code catches a
revert.

OPS supplies signed **identity context**, not a signed permission verdict or
predicted frame list. Several principals may share a signing address, so group
selection belongs to the authenticated principal, not an address-to-user guess.
Authentication, linked-signer checks, RPC admission and compliance still apply.
Simulation/preview remains available; a successful preview does not authorize
later execution or guarantee inclusion after state or permission changes.

Policies are compiled Solidity bytecode run privately inside the node's EVM.
They are not deployed to public chain accounts. Their gas, journal effects and
trace frames are isolated from the application. Postgres remains the writer of
operational facts such as memberships, bans and links; signed coherent updates
deliver facts and approved artifacts to Reth. Historical execution manifests
support replay without applying today's revocations to yesterday's block.

## What this continuation changed

The original compiler produced one organization-wide policy contract. With the
measured rules, 30 groups exceeded its 24,576-byte runtime bound. The chosen fix
is one artifact per bound group while retaining one organization document, one
review and one atomic activation. This avoids scanning unrelated groups and
keeps each individual artifact small. Repeated entry code means total published
bytes can increase; the design does not eliminate aggregate size or gas bounds.

| Change | Reason and behavior |
|---|---|
| Per-group compiler output | Each artifact retains the canonical whole-document digest while generating only its group's rules. All builds succeed or submission fails. |
| Complete artifact-set review/storage | Review checks the exact bindings, generated source, runtime hashes and compiler settings. Migration 082 persists the set; approval/audit cover every artifact. |
| Publication and removal | Feed keys include organization and group. Activation/export replace the complete set, including removal of omitted bindings; an empty set denies execution. |
| Reth group selection | Filter and sort the authenticated principal's applicable groups in the frame's policy organization; allow if one evaluated artifact allows. Full group/claim facts remain available for cross-group exceptions. |
| Candidate isolation | A complete candidate set replaces only the selected organization's candidate rules for that simulation. Active state is unchanged; diagnostics retain separate authority and scope checks. |
| Compatibility | Previously approved single artifacts keep their bytes and approval. Mixing legacy and grouped artifacts, or revisions/digests within one organization's set, is rejected. Upgrade OPS and Reth together. |
| Compilation deadlines | Five minutes for a set, API response deadline plus 15 seconds, and 330-second Nginx read timeout in production and E2E configurations. |
| SDK synchronization | Regenerated OpenAPI-derived types include `ExecutionDiff.artifacts`; generated-code validation now passes. |

Important invariants for future changes:

- A frame sees one coherent snapshot, never half of an activated set.
- A group's denial may be followed by another group's allowance, but malformed
  output, execution failure and budget exhaustion fail closed. Specific rule
  denials remain distinguishable from tagged no-match fallbacks.
- All group evaluations for one application frame share **100,000 internal
  policy gas**. Do not silently raise or remove this bound to make a test pass.
- Cross-group deployer exceptions use the principal's full relevant facts.
- Candidate preview cannot mutate active permissions or bypass ordinary active
  application authorization. Privileged diagnostics are explicit and audited.
- Current authorization and exact approved contents are rechecked at activation;
  a configuration commit is distinct from the node acknowledging application.

## Where to change or inspect behavior

Paths below are relative to the worktree root.

| Concern | Main implementation | Regression entry points |
|---|---|---|
| Compiler, set encoding and digest binding | `internal/policydsl/{validate,generate,compile,artifact_set}.go` | `per_group_test.go`, `per_group_vectors_test.go`, `testdata/per-group-v1.json` |
| Review and atomic activation | `internal/configuration/execution.go`, `internal/db/configuration_revision_execution.go` | `internal/db/execution_artifact_set_test.go` |
| Storage and feed export | `internal/db/migrations/083_execution_artifact_sets.sql`, `execution_policy_store.go`, `node_policy_export.go` | Database execution/export tests |
| Signed wire, deltas and simulation | `internal/nodepolicy/{envelope,feed,state,simulation,client}.go` | `internal/nodepolicy/group_artifacts_test.go` |
| Node selection and enforcement | `node/reth/src/{facts,policy,context,runtime,wire,stream}.rs` | `node/reth/tests/{group_artifacts,facts_adapter,diagnostics}.rs` |
| HTTP compile window and candidates | `internal/server/{admin_configuration,node_simulation}.go` | `configuration_execution_deadline_test.go`, `node_simulation_test.go` |
| Proxy timeouts | `frontend/nginx.prod.conf`, `frontend/nginx.e2e.conf` | Delayed-upstream check recorded in the September 25 report |
| API/client shape | `internal/server/apispec/swagger.json`, `sdk/src/generated.ts` | `npm --prefix sdk test`; regenerate rather than editing generated output |
| Live acceptance and benchmark | `scripts/ops-reth-stack/{stack,group_acceptance}.py`, `node/reth/tests/frame_cost.rs` | Stack runbook and retained JSON evidence |

## How to verify and continue

Run commands from this worktree. Compiler tests require pinned native
**solc 0.8.35**. Integration tests require Docker/Postgres; Rust dependencies
must already be cached for `--offline`. See the linked runbooks for toolchain
and sibling-repository prerequisites.

Focused compiler/protocol and node checks used during review:

```sh
go test ./internal/policydsl ./internal/nodepolicy \
  -run 'Test(PerGroupVectors|GroupArtifact|GroupCandidate|DeploymentOwnershipClassesAndMembershipExceptions)' \
  -count=1 -timeout=5m
cargo test --offline --locked --manifest-path node/reth/Cargo.toml \
  --no-default-features --test group_artifacts --test facts_adapter --test diagnostics
npm --prefix sdk test
```

For storage or submission changes, also run:

```sh
go test ./internal/db ./internal/server \
  -run 'Test(ExecutionArtifactSetActivationAuditAndRemoval|VerifyExecutionArtifactSetRejectsMissingExtraAndChangedGroups|ConfigurationExecutionSubmissionOutlivesOrdinaryWriteDeadline)$' \
  -count=1 -timeout=10m
```

For API schema changes, run `make api-spec`, then
`npm --prefix sdk run generate` and the SDK tests. For node changes, rebuild
the release binary using the Reth README; start a **fresh** stack with
`--reth /absolute/path/to/this/worktree/node/reth/target/release/ops-reth`.
The harness's default can point to an older binary in the main checkout.
Use the stack runbook's baseline acceptance, per-group acceptance, release cost
measurement, SDK smoke and restart checks. Stop only the stack you created.

The September 25 live run verified a 60-group document, finalized signed
execution, membership removal, set removal, candidate isolation, empty-set
recovery and restart persistence. SDK live smoke passed five checks. The later
review passed focused Go checks and 21 Rust tests. After the review fixes, the
SDK's drift/build/type checks and all 11 runtime tests passed. A real Nginx
proxy returned HTTP 201 after a dummy upstream waited 65 seconds; the original
60-second configuration returned 504. That last check tests proxy behavior,
not another full compilation run.

Local run evidence is under `.tmp/ops-reth-group-live-20260925`. Its stopped
processes and Docker database volume were removed, so start a new stack for a
fresh run rather than assuming its manifest describes a running environment.
Private `state.json` and keys contain development credentials; use the sanitized
checked-in report when sharing results.

## Remaining work and accepted limits

- **Membership gas budget:** optimization is explicitly deferred. In the
  measured last-match workload, 11 memberships passed and 12 exhausted the
  budget. Live HTTP checks passed at 10 and denied at 20/40/60. Early matches
  passed at 60. These are workload-specific observations, not universal limits.
  See [open item 12](../OPEN_ITEMS.md#12-reth-per-group-permission-budget).
- **Sustained throughput:** no 5,000 TPS claim is established. The historical
  stack measured roughly 9.6–11.1 mined transactions/s on the shared host, with
  serialized durable identity admission identified as a bottleneck. The latest
  per-group benchmark measured policy cost, not sustained transaction load.
  Its one-frame, one-thread CPU-only estimates are roughly 58,300 / 12,100 /
  5,720 checks per second for 1 / 5 / 10 groups; real throughput includes other
  work and repeated execution passes. See [open item 13](../OPEN_ITEMS.md#13-reth-sustained-transaction-throughput).
- **Other bounds:** per-artifact bytecode, total signed feed size, the 1 MiB
  candidate simulation request and deployer-exception limits still apply.
- **Scope exclusions:** Besu/Lineth delivery, new MCP tooling, ASRN/operator
  blindness, multi-validator consensus, scoped administrative roles/quotas and
  record-history visibility remain outside this delivery. Record-party
  execution checks are included. Existing read/disclosure behavior is retained.
- **Validation limits:** local development producer and mock identities;
  browser interactions, a production identity provider, customer CI and a
  production consensus deployment were not established by the latest run.

The two concrete review findings (proxy timeout and stale SDK) are fixed in
`8d835dd4`. No further functional defect from that review remains open. The
accepted performance work above should remain explicit when planning another
iteration; do not infer release readiness from the local acceptance checks.

## Change and backup trail

| Commit | Purpose |
|---|---|
| `fa2e9d51` | Artifact granularity design and measured alternatives. |
| `1d901ec7` | Initial per-group compiler support from the resumed Claude work. |
| `214ab2cd` | Complete storage, approval, export, node enforcement and candidate integration. |
| `6e92ee6e` | Live stack acceptance and policy-cost measurements. |
| `4aa8c2a3` | Accepted membership limit and qualified throughput projections. |
| `8d835dd4` | Proxy deadline and generated SDK review fixes, with evidence. |

The dated local ZIP is placed in `/Users/blade/work/software`, outside the
repository. Its `RESTORE.md` describes an independent clone from the included
Git bundle; `manifest.json` records the exact backed-up commit, file hashes and
exclusions. The archive also contains source, local evidence and supplemental
research. Dependency/build caches, external symlink targets and running-service
databases are not included. The archive is private, not encrypted. This local
copy protects against losing the worktree; another device is needed for disk
failure protection.
