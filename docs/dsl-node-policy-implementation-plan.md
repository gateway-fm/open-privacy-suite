# DSL configuration and node enforcement: implementation plan

Date: 16 September 2026. Status: accepted scope; implemented on `feat/ops-dsl-reth` in `.tmp/worktrees/ops-dsl-reth` — see [Delivery status](#delivery-status-17-september-2026) at the end for what is verified, what is measured, and what remains excluded.

## Outcome and scope

An operator can run an isolated OPS stack, create an organisation and groups, onboard and link a user, deploy/register an ordinary contract, author/review/activate configuration, and observe the correct permissions in RPCs and the explorer. A headless service can discover its capabilities, prepare configuration, perform authorised operations, and explain transaction and policy failures using the same API. MCP tooling is deferred.

The architectural authority is [DECISION.md](research/dsl-policy-and-node-enforcement/DECISION.md), especially §§3.3–3.5 and its explicit exclusions. The [roadmap](../OPS-Roadmap-Sep-26.pdf) supplies acceptance criteria where they do not conflict with that decision. Older research describing a generic change-set planner, a Go request-path evaluator, or signed preflight approvals is superseded. This plan does not reintroduce those designs.

User decisions recorded on 16 September 2026:

1. **Reth only for this delivery.** Besu/Lineth implementation and acceptance are deferred.
2. **DECISION.md scope**, retaining its explicit exclusions. MCP tooling is deferred.
3. **Preserve shared signing addresses with authenticated principal context.** The user accepted the recommended identity-only context bound to each transaction/simulation and requested a review reminder. See [the identity design and review checklist](architecture/execution-context.md).

These decisions supersede the provisional two-client work packages below. Implement and validate the Reth lane; do not spend this delivery on Besu/Java consumers. The signed-manifest approval adapter and the SDK/readiness/status support remain within the accepted workflow plan; this does not claim the entire V2 PDF roadmap is delivered.

Under the accepted scope, remaining exclusions are those already in DECISION §6: MCP, ASRN/operator blindness, multi-validator consensus, scoped administrative roles/quotas, and the record-history visibility extension. Existing visibility/disclosure functionality remains supported and must pass regressions. The record-party **execution** predicate remains included; the decision excludes the history half, not that predicate.

## Evidence and reusable implementation

The root worktree is on `fix/operator-token-doc-clarity` at `7172795`, with user-owned untracked roadmap/research files. Do not clean, reset, or overwrite it. Local `origin/main` is `6ebc3b7`; remote freshness has not yet been checked.

| Component | Located work | Reuse and limits |
|---|---|---|
| DSL and authoring | `.tmp/worktrees/ops-policy-builder`, clean at `1984457`, branch `poc/ops-policy-builder` | Nine commits in `f81937e..1984457`: schema, validator, Solidity generation, seven admin routes, revision table, UI and tests. Reuse these commits selectively on the integration base; the whole branch includes other ancestor work. |
| Reth evaluator | `docs/research/dsl-policy-and-node-enforcement/reth-policy-poc/` | Real nested static-frame mechanism and ten recorded cases. Fixture directory, public genesis policy address, deployment rejection and test bypass must be replaced. Evidence is historical, not a run of the planned integration. |
| Reth approval experiment | `.tmp/worktrees/ops-reth-signed-approvals`, branch `poc/ops-reth-signed-approvals` | Inspect and preserve uncommitted work. Reuse relevant transport/test machinery, not preflight approval or fingerprint matching. |
| Besu experiment | `.tmp/worktrees/ops-besu-signed-approvals`, branch `poc/ops-besu-signed-approvals` | Plugin integration, signed transport, RAM store and load harness. Nested policy execution is not implemented there. |
| Existing product | `internal/server`, `internal/db`, `frontend`, `e2e`, `deployments/privacy` | Retain auth, operational APIs, compliance, disclosure and non-executing read enforcement. Replace configuration writers and execution authorisation deliberately. |

Existing DSL coverage comprises 33 Go/Solidity conformance scenarios, seven lifecycle integration tests and 17 frontend tests. The HTTP tests mount routes directly and do not establish production middleware authorisation. There is no existing full-stack node-enforcement acceptance suite.

The root and archived roadmap PDFs have matching SHA-256 hashes. The archived text was read with the decision and supporting workflow/API/node research. All audit findings below are from source inspection unless explicitly described as historical experiment results. Tests have not yet been rerun.

## Critique: why simply joining the experiments would fail

| Finding | Consequence | Required correction/test |
|---|---|---|
| Signer is not the OPS principal: migration `027_eth_address_link_type.sql` permits several DIDs per address | A signer-to-user map can choose the wrong identity or combine permissions | Trusted, request-bound principal context; two principals sharing a key must retain different permissions. Never union their grants. |
| Policy activation currently has no live enforcement consumer | A green editor test does not prove the user is protected | End-to-end tests against the actual producer; UI reports node application separately from DB activation. |
| ABI offsets use the top-level argument index rather than encoded head width | A scalar after a static array/tuple can be checked at the wrong offset; both existing evaluators can agree on the same error | Independent ABI fixtures, including `f(uint256[2],uint256,bytes)`; derive correct offsets or reject unsupported layouts explicitly. |
| Activation lacks a persisted base and organisation-wide compare-and-swap | Old drafts or concurrent changes can overwrite newer policy | Recheck base, dependency digests and current authority inside one locked transaction. |
| Lifecycle audit is recorded after the DB commit | Crash can leave an activation without its audit event | Append `rbac_audit_log` in the same main-DB transaction using the existing chain-serialization rules. Access/decision evidence belongs to the separate audit DB and needs durable delivery. |
| Read-only middleware rejects every POST | The decision's read-only agent cannot draft or simulate | Explicit authoring permissions on the relevant endpoints; unchanged denial for operational mutations and activation. |
| Four-eyes and same-principal CI activation are both required | A blanket service-principal exemption defeats human control | Distinct trusted CI approval mode bound to the exact bundle/environment; default two-principal activation. |
| Approver configuration is named, but migration 041 removed governance | Reusing old approval tables would recreate a retired subsystem | Configure revision activation eligibility and external approval trust; do not restore the generic N-of-M request workflow. |
| Closing grant CRUD also removes read/event-rule authoring | Execution migration can silently break explorer privacy | Execution rules own function permissions; contract configuration owns retained visibility claims/event grants and their projections. |
| Reth fixture denies CREATE; current OPS discovers factory deployments through preflight | Removing preflight breaks deployment and auto-grants | Enforce CREATE/CREATE2 and constructor calls; obtain actual successful creation evidence and reconcile/adopt it. |
| Latest off-chain facts would be used during historical reexecution | Revocations could invalidate an old block or break restart | Persist the execution context for each locally produced block; use historical context for replay, never current facts. |
| Current Compose stacks use Anvil | Existing green E2E tests cannot prove node policy enforcement | Dedicated enforced-node stacks, private RPC/ingestion paths, capability probes and real signed transactions. |
| ARM64 backend image omits solc | Local stack runs but policy submission returns 503 | Ship/test a pinned compiler on the supported architecture; readiness must expose compilation capability. |
| Historical throughput measurements used different gates/workloads | They do not demonstrate this design meets the 5,000 TPS target | Measure this implementation, including per-frame work, depth, ingestion, compilation and end-to-end latency. |

Additional corrections to expectations:

- A simulation and later inclusion share an evaluator, but can still differ because chain state, facts or policies changed. Return their context versions; do not promise that a successful preview guarantees inclusion.
- A database transaction cannot make OPS caches, a node and Postgres switch simultaneously. Activation commits a desired version; each execution uses a coherent pinned version, and the product exposes when the producer acknowledged/applied it. The next-block revocation guarantee starts at node application, with a configured propagation bound and fail-closed staleness limit.
- An empty change stream does not establish freshness. Signed heartbeats/watermarks distinguish no changes from a failed pusher.
- Existing transport writes have no durable ACK and can lose a batch on failure. Reusing the framing does not make the fact stream reliable.
- Source-path-dependent solc metadata may make repeated builds differ. Prove artifact reproducibility across directories and machines; generated-source equality alone is insufficient.
- Deployment, externally approved CI and historical replay are core integration work, not cleanup after a demo.

## Contracts to settle before parallel implementation

### 1. Identity and admission

Accepted decision amendment: retain DID authentication, linked-signer checks, RPC method restrictions, bans and current compliance controls at OPS admission. Issue authenticated **identity context**, not an execution approval. The node resolves current permissions itself.

Transaction context is domain/version separated from old approvals and binds the principal's stable opaque ID, signed transaction hash, recovered signer, chain/deployment identity, validity window and unique context ID. It conveys no permission verdict or predicted frames. Node facts still determine bans, memberships, expiry, claims and linked addresses at execution. A ticket must not preserve authority after revocation.

Repeated delivery is idempotent. One pending signed transaction cannot be rebound to a different principal by last-writer-wins; conflicting bindings return a defined error. Replacement transactions have new hashes and contexts. An unauthenticated public RPC caller cannot manufacture context. Confirm context ingestion before forwarding, or expose a durable awaiting-context state; a socket write is not an acknowledgement.

For `eth_call`, `eth_estimateGas` and supported tracing, bind identity to that request, including canonical call, `from`, block reference, allowed overrides and the privileged dry-run mode. Use explicit request context or authenticated internal RPC on both clients as necessary. A global signer-to-current-principal map is unsafe under concurrency. Raw user overrides cannot replace policy bytecode, facts or enforcement flags.

### 2. Policy and fact interfaces

Version a language-neutral `check(Facts, Call) -> reasonCode` ABI with shared fixtures for Go, Rust, Java and Solidity. Include principal and all linked addresses, applicable active memberships/expiry, org and claim facts, signer, immediate caller, code/storage owners, shared infrastructure, sanctions, call kind, selector/calldata, native value and depth. Resolve groups across the principal's existing multi-org memberships without inventing a single home organisation.

Define which policy governs each frame, cross-org/disclosure-derived execution authority where currently supported, delegate-code versus storage ownership, inherited constructor ownership, EOA/native transfers, precompiles and protocol system calls. Preserve existing supported behaviour or report an explicit unsupported configuration during import/readiness. Unknown facts/semantics deny.

Pure argument rules remain pure. The record-party predicate is a separately typed, bounded live-state read through the same static policy frame. Define the getter selector, record-ID argument mapping and permitted return shapes in the schema; compare returned parties against all of the principal's linked addresses. Test same-block record mutation, malformed/reverting results, recursive reads and gas exhaustion. “Current record” means the live candidate state at that frame, not a cached or admission-time lookup. No arbitrary uploaded policy bytecode or unbounded external policy calls.

Set limits for document size, rules, bytecode size, compilation time/concurrency, policy gas, checked frames, calldata, simulation batches and audit payloads. Exhaustion denies with a stable diagnostic. The customer never pays policy-internal gas, and policy execution leaves no warm-access/journal effects.

### 3. Revision and projection ownership

One revision stream per `(scope, kind)`, with stable scope identity and the following ownership:

| Kind | Owned desired configuration | Operational data it must not overwrite |
|---|---|---|
| Execution rules | Function permissions, argument predicates, nested/delegate rules, templates and ABI references | Memberships, bans, identity links, chain observations |
| Groups | Definitions, access method allowlists, claims and permitted administrative flags | Membership records/expiry; protected bootstrap authority |
| Contract registry | Ownership/ABI/visibility configuration, read-side claims and event rules | Receipts and verified deployment provenance |
| Compliance | Org settings and address thresholds | Sanctions feeds, price observations, consumed evidence, incident bans |
| Approvers | Eligible existing admin groups and revision activation/CI trust configuration | Human identity, externally issued approval evidence |
| Platform | Shared infrastructure, tenant configuration and reserved trust-root configuration | One-time bootstrap operations and observed refresh state |

Execution rules become grants, not only a narrowing overlay over `contract_grants.functions`. Keep dormant columns under expand-only migrations. Retain necessary read-side projections. Import must preserve `null`/empty/wildcard distinctions and current claim semantics.

Store immutable canonical source, schema/compiler versions, source/artifact digests, base revision, dependency digests, explicit deletions, actor, environment and review evidence. Activation accepts an exact set of sibling drafts, takes locks in a stable order, checks pre-change authority and dependencies, and commits all projections, active pointers, audit events and fact outbox changes together. Every sibling draft is covered by the activation authority and approval; a permitted sibling cannot smuggle an unauthorised one.

An omitted resource is deleted only against a named base with deletion listed for review. Dropping a group with live members requires explicit acknowledgement tied to the reviewed member count/state. Automation-created resources are visible drift, adopted by the next revision, never swept away. Drift changes invalidate incompatible pending reviews. Closing writers means covering aliases, batches, explorer ABI updates, internal helpers and background writers, not just hiding UI buttons.

Bootstrap and successful deployment are narrow operational entry points: they create attributed resources/drift through shared services and outbox transactions. They do not become alternative arbitrary configuration APIs. Emergency rule removal and rollback use new revisions; rollback never restores expired membership or consumed approval/evidence.

### 4. Approval boundary

Default: a scoped read-only admin/service may read, draft and simulate; activation requires existing full-admin authority, a different submitter/activator principal, current scope/dependency checks and the exact approved bundle. Agent status is derived from trusted identity data, not an `isHuman` request parameter. A different service principal alone does not prove a human approved.

Support customer CI as an explicit trusted channel with verifiable approval evidence bound to bundle, base/dependencies, environment, issuer, expiry and nonce. Deliver one concrete signed-approval-manifest adapter, its signing CLI and a reference CI workflow whose signing job requires the customer's protected review/environment controls. The trusted public key and permitted CI subject/environment are configured through the protected approver/platform boundary; the private key belongs only to that approval-controlled job, never the proposing agent. Test successful same-principal CI activation as well as replay, changed content/base, wrong environment/subject, expired evidence and revoked trust. This trusts the configured external approval authority; a signature alone does not prove an arbitrary repository was reviewed. No caller-selected `ci=true`, blanket exemption for Azure service principals, or unrestricted admin token in a model-facing client. Without configured external trust, the default two-principal human flow works and CI exemption fails closed. Live customer CI validation is reported separately from local adapter tests.

Approver settings cannot let a submitter grant itself authority it lacked. Preserve existing platform-only creation of administrative trust roots. Current code permits removing the last org admin: add explicit lockout protection for the revision/approval flow and retain a platform recovery path instead of assuming that protection already exists. Development fixtures seed distinct author and approver accounts so four-eyes does not make the local workflow unusable.

### 5. Fact consistency, replay and deployment

Postgres remains the only facts writer. Changes and durable outbox entries commit in the same transaction. Assign a commit-ordered stream version under a serialisation mechanism; a bare sequence allocated before commit is insufficient for a consumer that skips to a watermark. Export a transactionally consistent initial snapshot and replay deltas after its watermark without gaps.

Use signed, canonical, versioned envelopes with stream/chain/deployment IDs, previous version/digest, content digest, key ID and validity metadata. Authenticate transport; ACK application durably; resend idempotently; detect duplicates, gaps, out-of-order delivery and signature failure; rebuild from an authenticated checkpoint when necessary. Publish heartbeats and expose soft/hard lag states. Verify artifact hashes and protocol/compiler compatibility before accepting policy activation.

Pin one immutable fact snapshot and policy set per candidate block. Define membership/credential expiry against the chosen execution context's timestamp and do not silently extend it through cached state. Deltas apply at the next block boundary. Missing/expired context stops permissioned execution; no fallback to old preflight enforcement.

Recommended replay strategy for Reth: persist block/parent/payload identity to snapshot, policy revisions and principal contexts before publishing a locally produced payload. Use the same retained context for self-import, restart and historic reexecution. Unknown historical context is explicit, not replaced with today's permissions. Besu producer enforcement must preserve equivalent evidence even if ordinary import remains outside that plugin's hook. This is not a claim of arbitrary external-validator consensus; unsupported producer/import paths must be rejected by deployment/readiness configuration.

Historical **user RPC access** is a different operation: an `eth_call` or trace against an old block still uses the caller's current authentication, bans, memberships and applicable access policy against historical chain state. Choosing an old block must not revive revoked access. Reproduction with original authorisation facts is a separately privileged forensic path whose output is subject to current viewer access. Test both behaviours independently.

CREATE/CREATE2 need transaction-local and candidate-block-local ownership facts so constructors and subsequent calls can be checked before the asynchronous Postgres projection catches up. Apply these overlays only to successful execution; rewind them on ancestor revert, whole-tx denial and abandoned blocks. Never let a reverted creation grant lasting access. Publish canonical successful creation events for receipt reconciliation; register provenance and adoption drift atomically. Reorg handling removes/reconciles orphaned observations without deleting independent approved configuration.

## Delivery sequence and concurrent TDD work

Every package follows red → green → refactor → review. Record the initial failing assertion and successful verification. A reviewer other than the implementer checks each completed package; the integrating agent also reviews seams, auth and retained privacy behaviour. Do not mark a package complete from mocked UI tests alone.

Use a new isolated integration worktree based on the verified current upstream main. Inspect all dirty experimental worktrees first; copy/cherry-pick only reviewed source and preserve the originals. Allocate non-overlapping files or worktrees to concurrent agents. Commit shared protocol/schema decisions before agents generate consumers. No production deployment or external publication is part of local development.

### Stage 0 — scope, baseline and executable interfaces

- Record the three scope answers and amend the implementation design for identity, approval, read-projection ownership and historical replay.
- Inventory existing migration numbers, writer entry points, service dependencies and supported transaction types/hardforks. Pin node revisions and toolchains.
- Build a representative populated-DB migration corpus before freezing the grammar: nil/empty/wildcard function grants, claims, disclosure-derived execution, deployment auto-grants, argument constraints and retained event visibility. Required existing workflows must translate faithfully; reporting them unsupported is not an acceptable substitute for parity.
- Port the nine policy-builder commits with review of conflicts against current main, especially DB transaction helpers, mandatory cache generation guards and extracted API models.
- Capture baseline unit/frontend results and establish isolated Postgres/node fixtures. Freeze protocol vectors, API schema and the acceptance scenarios below before parallel consumers are implemented.
- Prepare real user transactions and two-principal approval fixtures; replace Anvil-unlocked-account shortcuts in the new enforcement lane.

### Stage 1 — parallel foundations

| Work package | First failing tests | Completion gate |
|---|---|---|
| A. DSL/compiler | Static-array/tuple offset bypass; overflow/truncated ABI; deterministic artifact bytes; native value; ownership classes; CREATE; record-party reads; strict return decoding | Independent ABI/contract fixtures pass, supported grammar documented, pinned compiler works in the target image; Go evaluator only an offline oracle. |
| B. Revisions/governance | Stale/concurrent activation; read-only draft vs activate; same-person denial; pre-state escalation; all-or-nothing sibling activation; explicit deletion; audit/outbox crash | Production middleware exercised, transactional compare-and-swap and actor attribution demonstrated. |
| C. Facts/protocol | Commit-order inversion; bootstrap race; duplicate/gap/corrupt delta; ACK loss; key rotation; stale heartbeat; principal conflict; ban after ticket issuance | Shared Go/Rust/Java wire vectors and restart/catch-up tests pass; no silent data loss. |

With four agent slots, three agents can own A/B/C while the integrating agent owns shared fixtures, reviews, conflict resolution and acceptance harness design. A package is integrated only after its review findings are fixed.

Break these packages into individually reviewed slices: A1 ABI/artifact hardening, A2 facts/creation/value generation, A3 record predicates; B1 immutable bases/auth, B2 activation/audit, B3 approval adapter; C1 codec/signatures, C2 transactional export/outbox, C3 ACK/checkpoint recovery. Review and integrate each slice without waiting for its entire package.

Before finishing every stream or both clients, run an early vertical slice on the first selected node: authenticate a real principal, import one existing rule, publish a snapshot, activate through the real API, and include/deny real signed transactions. Add a small representative frame/gas/load measurement then. This is an integration gate, not final delivery; its findings can change interfaces before the second client and all UI consumers are built.

### Stage 2 — parallel feature integration

| Work package | First failing tests | Completion gate |
|---|---|---|
| D. Reth runtime | Node observes latest actual nested target; caught denial rejects whole transaction; immutable block snapshot; concurrent principals; preview identity; creation overlays; private policy bytecode; replay after revocation | Real producer passes ordinary signed sends, call/estimate/trace, deployment and restart; no fixture disable switch or on-chain policy installation. |
| E. Besu/Lineth runtime | Same shared vectors/scenarios plus plugin coexistence, rollback of world updater, plugin simulation RPC and transaction exclusion | Same visible semantics as Reth for supported operations; explicit diagnostics for any unsupported configuration. Required before completion if both clients are selected. |
| F. Configuration streams | Group creation/deletion safety; registry ABI+rules atomicity; read/event grants retained; compliance/approver/platform authority; legacy/batch/explorer writer refusal; drift adoption | All six streams can be reviewed and activated; old paths cannot create a second configuration writer. |

The integrating agent connects admission, node readiness, durable denial/status ingestion and receipt reconciliation. Do not retire a live execution gate until the replacement path is enforced and the transition's negative tests pass. Under the new supported mode, preflight authorisation, OPS trace validation and fingerprint signing leave every live execution path; tracing retained for diagnostics or post-receipt evidence is not an authorisation gate.

### Stage 3 — usable UI, headless API and full-stack workflows

- Update existing organisation/group/contract/compliance screens to produce revision candidates, show semantic permission changes, review deletions/drift, simulate through the node and activate exact bundles. Keep operational membership, ban, link and disclosure screens using their proper operations.
- Support all configured streams through forms plus JSON import/export. Show draft, DB-committed, awaiting-node, node-applied, failed/stale and withdrawn states accurately, including digests and versions.
- Add/complete transaction lifecycle records: submitted/accepted, pending, included, reverted, policy-rejected, expired/timed-out, replaced and reorged where applicable. Reconcile receipts and node decisions durably. A returned hash is not inclusion; no receipt is not proof of rejection. Surface deploy-success/config-failure distinctly and resume safely without submitting a second deployment.
- Publish machine-readable capability/readiness and stable error codes, scoped context reads, OpenAPI-derived typed clients and a minimal headless SDK example for service-principal login/refresh, revisions, operations, RPC submission and status tracking. An agent needs no MCP server to exercise this API.
- Correlate actor, request, transaction, rule ID/DSL location, bundle digest, snapshot and before/after configuration. Raw internal errors and other tenants' identities/calldata do not appear in user responses; restricted audit retains the needed evidence.
- Generate OpenAPI, endpoint inventory and operator docs in the same changes as their endpoints. Keep schema/route coverage gates passing.

### Stage 4 — transition, stack acceptance and release evidence

- Import existing function grants into initial execution documents and remaining configuration into its owned streams. Produce a reviewable report of unsupported/ambiguous cases instead of silently broadening or dropping rules. Preserve current read visibility, deployment entitlements and memberships.
- Test upgrading a populated DB and booting an empty one. Atomically initialise/import the configuration generation and fact watermark. A rollback is a new reviewed revision, not destructive schema rollback.
- Provide isolated Reth and selected Besu/Lineth Compose configurations with OPS backend/UI, Postgres, Redis, indexer and explorer. Include block production, node health/readiness, keys/checkpoint volumes, compiler, init/import and author/approver fixtures. Do not reuse or tear down unrelated stacks/volumes.
- Add one documented start command per supported node and an acceptance command that creates the scenario below from a clean volume. Verify both clean startup and restart of persistent data.
- Run required backend/frontend/API checks, real-node adversarial cases, full browser/headless scenarios, retained privacy bypass tests and load measurement. Resolve review findings before calling the stack ready.

## Acceptance matrix: what “working with OPS” means

Run the mandatory scenarios on every selected node, through actual OPS authentication and RPC routing. Assertions include final DB/node/chain state, not only HTTP status.

| Scenario | Positive and negative evidence |
|---|---|
| Bootstrap and isolation | Platform creates org/admin trust root; org admin creates declarative groups; unrelated org and restricted operator cannot read/mutate tenant data. |
| Onboard and membership | Onboard by DID, authenticate/link address, add/remove/expire membership; subsequent execution uses the correct current facts. Bans and sanctions survive config reapplication. |
| Shared signer | Same signer under two principals yields each principal's own permissions; retries cannot rebind a pending tx; simulation requests remain isolated under concurrency. |
| Contract deployment | Ordinary CREATE, factory CREATE/CREATE2 and constructor nested calls; allowed deploy claim succeeds; denied constructor/factory has no residual ownership/grant; receipt reconciles registration without duplicate deploys. |
| Rules and ABI | Allow/deny selector, argument AND/OR semantics supported by the schema, linked-address constraints, value, nested frames, delegate code/storage, ownership classes and shared infrastructure. ABI changes and dependent rules activate together. |
| Record-party execution | Actual contract state determines authorised parties; stale/missing/reverting record lookup denies; existing historical read rules remain intact. |
| Preflight race | Preview succeeds; earlier tx changes target/state; inclusion evaluates actual calls and denies if necessary, even when application catches the inner failure. No state/nonce/fee effects from excluded tx. |
| Preview parity | Call, gas estimation including binary-search behaviour, supported trace and actual execution use identical policy logic. Tests hold state/context constant when asserting equal verdicts. Dry-run privilege cannot leak into normal execution. |
| Governance | Read-only author drafts/simulates but cannot activate/operate; different authorised human activates; configured CI activates the exact externally approved bundle. Self-approval outside that mode, stale base, altered digest/environment, replayed/expired evidence and revoked issuer trust deny. |
| Declarative safety | Omitted base cannot delete; listed deletion is visible; live-member group removal needs exact acknowledgement; deployment drift is retained; all writer aliases and batches obey ownership. |
| Revocation and rollout | Activation is one coherent generation; block pinning never mixes revisions; node application/lag visible; ban/revoke reaches next eligible block; excessive staleness stops execution. |
| Privacy and compliance | Existing RPC/explorer log/receipt/storage/proof visibility, disclosure consent/expiry, compliance prices/evidence and access/visibility symmetry remain enforced. |
| Failure lifecycle | Distinguish rejection, EVM revert, no receipt yet, timeout, replacement and reorg; status and audit survive restart; user sees only authorised decision information. |
| Recovery and replay | Pusher crash, duplicate/missed events, node restart/checkpoint restore, historical replay after policy change, stale snapshot and corrupt signatures all produce defined safe outcomes. Lost/expired principal context and replacement transactions have explicit recoverable status. A revoked/banned caller cannot regain access through a historical block selector or forensic replay endpoint. |
| API/SDK workflow | Headless service discovers capability, logs in/renews, drafts/simulates, reaches human approval boundary, performs authorised operations and submits/tracks permitted transactions; explains denied/unsupported states. |
| Migration and performance | Populated deployment preserves tested existing permissions; unsupported cases block cutover. Publish gated/ungated measurements and limitations against the roadmap workload; do not infer 5,000 TPS from PoC numbers. |

## Review and verification discipline

- Review each package for authority escalation, tenant leakage, denial behaviour, malformed ABI/wire inputs, replay/races, resource exhaustion and bypasses. Review execution changes against retained explorer visibility semantics as required by `CLAUDE.md`.
- Keep genuinely independent test oracles: real ABI encoders and deployed contracts, not only two evaluators generated from the same assumptions. Test production router/middleware, not only handlers mounted in isolation.
- Run targeted Go package tests during TDD; serialise shared-DB suites as the repository requires. Add race/concurrency checks where snapshots, activation and caches change. Use isolated containers and real-node tests for those seams.
- Require frontend tests/build, API regeneration and route/spec coverage, native Rust/Java checks, and a real full-stack browser/headless run. Compilation and deployment scripts are tested inside the published image architecture.
- Retain source revisions, image/toolchain identities, commands, failing/passing results and performance environment in a delivery report. Historical research evidence is labelled separately.

## Environment observations and completion definition

This workspace is macOS ARM64. Go, Node/npm, Docker, Rust/Cargo, solc, Foundry and PDF extraction tools are present; sibling `chain-indexer` and `block-explorer` clones exist. Docker is accessible through the approved tool path and currently reports no running containers. Installed versions and build caches still need baseline verification. Required acceptance includes this ARM64 host: provide native compiler support or an explicit tested amd64 compiler/container execution path; do not accept a running UI with unavailable compilation. The existing E2E shell harness has GNU/Bash requirements; make the new lane work on this host through a controlled runner or portable wrapper rather than assuming stock macOS satisfies them.

Completion means code integrated on a clearly identified branch/worktree, reviewed package by package, required selected-node acceptance passing, and a tested start/test runbook that lets the user carry out the complete workflow. The report must name any unavailable external integration credentials or performance target not met. “Compiler works”, “revision activates in the DB”, mocked screens, or a historical node PoC are insufficient completion criteria.

## Delivery status (17 September 2026)

What is on the branch and how it was verified. Evidence files are under
`docs/implementation/evidence/`; the runbook is `docs/implementation/ops-reth-stack.md`.

| Area | State | Evidence |
|---|---|---|
| DSL / compiler hardening (A) | ABI offset/tuple fixes, native value, ownership classes, CREATE, record-party predicate, strict decoding; Go evaluator is an offline oracle | `compiler-hardening.md`, `facts-abi.md`, `record-party.md` |
| Revisions / governance (B) | Six streams (`groups`, `contract-registry`, `compliance`, `approvers`, `execution-rules`, `platform`), transactional compare-and-swap, four-eyes default, trusted-CI adapter, legacy writer closure, capabilities in every context | `configuration-streams.md`, `revision-activation.md`, `lifecycle-import.md`, `platform-scope-review.md`; API contract in `../implementation/configuration-api.md` |
| Facts / protocol (C) | Signed versioned envelopes, commit-ordered outbox, ACK/checkpoint recovery, identity binding per transaction and simulation | `node-facts.md`, `admission-rpc.md` |
| Reth runtime (D) | Guarded Reth v2.5.2 with per-frame policy evaluation, candidate simulation, scoped diagnostics, finalized status, restart recovery; 75 SDK integration tests | `reth-runtime.md` |
| Full stack acceptance | 12 scenarios pass on the isolated OPS + guarded Reth + indexer + explorer stack, including restart and a rerun after the final rebuild | `ops-reth-stack.md` |
| Headless SDK | TypeScript client generated from the OpenAPI document; offline tests and a live stack smoke | `../implementation/headless-sdk.md` |
| Migration | Expand-only migrations 072–077; populated-DB import of legacy grants into the first execution document | `deployment-migration.md`, `lifecycle-import.md` |

Measured, not claimed: the load harness sustains ~10–11 mined transactions per
second end to end on a shared laptop with 1 s development blocks, with no wrong
verdicts under nested frames, live record reads or continuous fact churn
(`reth-runtime.md`, "Load measurement"). That is a bound of the harness's signed
admission path and the development miner, not of policy evaluation. The policy
check itself was measured in-process on 2026-09-17 (`reth-runtime.md`, "Per-frame
cost"): ≈ 18 µs and 6.4 k node-internal gas per checked frame with the fixture
policy, i.e. about a quarter of one core at 5 000 tx/s × 3 frames. Neither
number is evidence for or against the roadmap's 5 000 TPS target as a whole;
that needs the deployment's block production, real policies and an isolated host.
The identified ceiling today is the node's per-transaction durable identity
admission (4–5 full disk syncs per transaction under one lock — `reth-runtime.md`,
"Where the stack's throughput actually goes"); batching it is the next design
item before any load figure is quoted.

Still excluded, as decided: Besu/Lineth runtime (E), MCP tooling, ASRN /
operator blindness, multi-validator consensus, scoped administrative roles and
quotas, record-history visibility. Known development-harness limits: indexer
tracing disabled, dev-miner finality depth 1, loopback-only network layout.

