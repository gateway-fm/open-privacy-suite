# Execution revision activation: B1 evidence

Date: 16 September 2026. Worktree: `feat/ops-dsl-reth`.

## Contract

- `base_revision` means the active revision at authoring time; zero means no
  active policy. Draft numbering remains monotonically increasing. Multiple
  drafts can share an active base.
- Submission requires an explicitly supplied nonnegative base and an identified
  user actor. An org-scoped read-only admin can submit and simulate drafts.
- Activation locks the organisation before the revision, requires an identified
  actor different from the submitter, and compares the recorded base with active
  state inside the transaction. Concurrent sibling activations yield one success
  and one stale-base conflict.
- Revision responses include `base_revision`, `created_by`, and `activated_by`.
  Shared bootstrap tokens do not identify authors or activators and cannot
  perform those actions. There is no implicit service-principal exemption from
  four-eyes; trusted CI authorization belongs to the later explicit policy.
- Migration 072 adds nullable base provenance without reconstructing unknown
  history. Existing active revisions stay active. Legacy drafts with missing
  base or author must be exported and resubmitted.

## Red evidence

The tests were added before their corresponding implementation changes.

`go test ./internal/db ./internal/server -run
'TestExecutionPolicyActivation|TestExecutionPolicyReadonlyPreparationScope'
-count=1 -timeout=5m`

- Scoped read-only draft submission returned 403 instead of success on both
  `/api/v1/admin` and `/api/admin`.
- A draft with no submitter was accepted.
- A second draft authored from active base zero was rejected because the former
  implementation treated latest draft numbering as active state.

`go test ./internal/server -run
TestExecutionPolicy_AuthenticatedReviewBoundary -count=1 -timeout=5m`

- Through real JWT authentication, submission without `base_revision` returned
  201 instead of 400. The handler previously defaulted the missing field to zero.

Initial harness attempts needed access to the normal Go build cache and Docker
socket. Runs used sandbox escalation for isolated testcontainers. A test fixture
compile error and duplicate group-name fixture were corrected before the
behavioral red results above; neither is counted as a regression demonstration.

## Green evidence

`go test ./internal/db ./internal/server -run
'TestExecutionPolicy|TestOrgScoping|TestAdminAuth|TestReadonly|TestEscalation'
-count=1 -timeout=5m`

Passed: database package 9.279s, server package 11.990s. Tests used ephemeral
PostgreSQL 15 containers and local pinned Solidity 0.8.35.

`go test -race ./internal/db -run TestExecutionPolicyActivation
-count=1 -timeout=5m`

Passed: database package 13.041s. Includes concurrent sibling activations,
missing/blank actors, case-insensitive UUID self-approval, and legacy rows
without base or author provenance.

The real JWT test covers read-only draft and simulation, same-author rejection,
different-admin activation, bootstrap-token rejection, and denial of read-only
membership mutation. Route-scope tests cover both API mounts, cross-org denial,
denied activation/withdrawal, unrelated operations, and lookalike URL paths.

## Security review and remaining integration

The exception is an exact registered POST route match inside the existing org
scope check. It does not grant generic POST authority or access to another org.
Actor comparisons and active-base validation also occur in the store, preventing
a handler-only check from being bypassed by another application caller. All
refused activations leave active state unchanged. New wire actor IDs remain on
existing org-scoped admin responses. Errors contain no internal database detail.

This is the bounded existing-stream lifecycle slice. It does not yet implement
generic streams, explicit trusted CI policy, role-authority revalidation under
activation locks, configuration projection/outbox activation, or UI changes.
Catalog revalidation and the handler's audit before-image still precede the
store transaction; the coordinated stream activation service must move those
checks and projection auditing into its atomic path. Node rollout completion
must remain distinct from the database's active status.

Handler annotations were updated. Full OpenAPI regeneration and operator-doc
updates are reserved for the integration pass to avoid competing generated-file
writes. No commit was created for this slice.
