# Execution artifacts: one per group, not one per organisation

Status: implemented. One organization document still receives one review and
one atomic activation. The compiler emits a set keyed by group; OPS stores and
publishes that set, and the Reth guard selects the authenticated principal's
applicable groups. Shared signing addresses do not merge principals' permissions.

## The problem

An `execution-rules` document compiles to a single contract per organisation.
That contract contains a dispatch block per group:

```solidity
if (g == 0xGRP_A) { ...A's rules... }
if (g == 0xGRP_B) { ...B's rules... }
if (g == 0xGRP_C) { ...C's rules... }
```

A frame only ever needs the groups its signer belongs to, but it carries the
whole organisation: in bytes, because every group's block is in the artifact,
and in time, because the dispatch walks them.

Both grow linearly with the number of groups, and the artifact is capped at
24576 bytes (EIP-170, mirrored in `nodepolicy` validation). Measured on the
pinned compiler, with two rules per group:

| groups | runtime bytecode | per check |
|-------:|-----------------:|----------:|
| 1      | 3 665 B          | ~45 µs    |
| 7      | 8 629 B          | ~46 µs    |
| 30     | 26 431 B         | refused   |
| 60     | 49 651 B         | refused   |

So an organisation stops being able to express execution rules at roughly
**thirty groups**, however few rules each group has. That is not a large
organisation; the demo's is seven.

Rule *bodies* are not the cause. Identical bodies across groups are already
merged by the optimiser — factoring them in the generator changes the source
but produces byte-identical bytecode. What cannot be merged is the per-group
dispatch, because each block compares against a different group constant.

## What was tried and rejected

**Sharing rule bodies in the generator.** Source shrank (18 408 → 13 258 B for
five identical groups) and bytecode did not move at all. Reverted: it would
have changed every artifact digest for no benefit.

**Table-driven dispatch** — groups and rules as a packed constant walked by a
loop, so adding a group adds data rather than code. Prototyped and measured
against the same shapes:

| groups | code per group | table-driven |
|-------:|---------------:|-------------:|
| 7      | 1 242 B / 10.7 µs | 1 129 B / 14.4 µs |
| 30     | 4 554 B / 21.9 µs | 3 015 B / 46.7 µs |
| 100    | 14 633 B / 45.6 µs | 8 755 B / 97.5 µs |
| 300    | 43 431 B          | 25 155 B          |

About 40% smaller and about twice as slow, with the gap widening. It buys
roughly 2.4× more groups for double the cost on the path that gates every
admitted call, and it still grows linearly. Rejected.

(The prototype numbers are lower than the table above because the prototype
contract omits the fact checks a real policy performs. The comparison between
the two shapes is what matters, not the absolute values.)

## The implementation

Keep straight-line generated code. Change the **scope of an artifact** from the
organisation to the group.

```
execution-rules document  (one per org — authored, reviewed, activated as today)
         │  compile
         ▼
 artifact GRP_A     artifact GRP_B     artifact GRP_C
   digest Da          digest Db          digest Dc      ← published, keyed org+group
```

A signer in one group runs only that group's artifact, whether the organisation
has three groups or three hundred. The compiler regression test builds seven
and sixty groups and checks that a group's bytecode is identical in both sets.
The earlier ~1 KB / ~10 µs figures describe the dispatch-only prototype above,
not the full compiled policy. Full artifacts repeat roughly 3 KB of fixed entry
code: total bytes grow even though each individual artifact remains small.
For example, seven groups can require roughly 23 KB in total rather than one
~10 KB artifact. Work per checked frame depends on the signer's groups and their
rules, not the number of other groups in the organization.

**What does not change.** The document, its review, four-eyes activation, the
generated code's shape, the node's EVM, and the `check(Facts, Call)` entry
point. Authors see exactly what they see today.

**What changes.**

| Where | Previous | Implemented |
|---|---|---|
| `nodepolicy.PolicyArtifact` | `OrgID` | `OrgID`, `GroupID` |
| `policyKey` (`feed.go:176`) | `p.OrgID` | `p.OrgID + "\0" + p.GroupID`; the separator cannot appear in either identifier |
| compiler | one artifact | one per group in the document |
| activation | publishes one digest | publishes the set, atomically |
| approval | one digest | the set of digests this document produced |
| node (`facts.rs`) | `policies: HashMap<org, (digest, code)>` | keyed by `(org, group)` |
| node evaluation (`facts.rs:299`) | look up by org, run once | run the signer's groups, combine |

The node filters and sorts the signer's current groups within the selected
policy organization. It tries their artifacts in that order and permits the
frame if any permits it. No applicable artifact means denial. Cross-group
exception checks still receive the signer's entire group list and aligned
claims. All artifacts for a frame share the existing 100,000 gas budget.

The compiler tags a no-matching-rule fallback with 256, keeping it distinct
from a matched rule's specific denial. The node prefers the first specific
denial, as the previous dispatcher did, and removes the fallback tag before
reporting. Malformed results, execution failures and exhausted gas fail closed.

**Why the protocol is comfortable with it.** `Snapshot.Policies` is already a
list with per-item upserts and deletes, so adding a dimension to the key is a
key change rather than a new wire shape. `MaxEnvelopeBytes` remains 64 MB. Full artifacts are several KB per group,
so total feed size remains a separate bound. A revision changes the document
digest and revision number on every member of its set; the current delta
therefore republishes those rows even if some runtime bytecode is unchanged.
Candidate previews also retain the existing 1 MB request bound.

## What needs care

- **Atomicity.** A frame must never see half a published set. Activation publishes
  every artifact the document produced, or none.
- **Approval semantics.** The reviewed thing becomes a set of digests. The
  activation record should carry them all so an auditor can tie every artifact
  back to the revision that produced it.
- **Removal.** A group deleted from the document must have its artifact deleted
  from the feed, not merely left unreferenced.
- **Cross-group rules.** Anything that reasons about *other* groups — today's
  deployer exceptions name the groups that may still reach a contract — must
  stay correct when each group compiles separately. The exception table is
  organisation-wide input to each group's artifact, so it is duplicated across
  artifacts; that is bounded by the 64-entry validation cap and adds to the
  repeated entry-point overhead described above.
- **The node is a second implementation.** The Rust guard changes with OPS, and
  the cross-language conformance vectors change with both.

## Not addressed here

The 64-entry cap on deployer exceptions is a separate limit: an organisation
with more than 64 granted contracts cannot express execution rules regardless
of artifact granularity.

## Storage, review and upgrades

`compiled_artifact` now holds `{policy_digest, groups: {groupID: artifact}}`.
Review verifies the exact binding set, each generated source and runtime hash,
and the pinned compiler settings. The activation audit retains every artifact.
The review's `sourceDigest` and `runtimeDigest` are digests of the sorted
`groupID -> digest` manifests; each artifact also retains its own digests.

Submission has a five-minute compilation budget and an HTTP write deadline
with a further 15-second response margin. The production and E2E Nginx `/api/`
proxies use `proxy_read_timeout 330s`; extending only the API deadline would
still leave the default proxy timeout at 60 seconds. Failure or cancellation
stores no partial set. The [review-fix evidence](evidence/per-group-live-2026-09-25.md#review-fixes-and-verification)
records the delayed-upstream regression check.

Migration 082 adds `execution_policy_revisions.artifact_set`. The complete set
is written alongside the active projection, audit and publication watermark in
the existing transaction. The repeatable-read exporter expands that set into
feed rows; a later revision omitting a binding deletes its old feed row. An
empty set is valid and grants no execution rights.

Previously approved single artifacts retain their original representation and
bytes. Their absent `group_id` selects the legacy org path. A snapshot cannot
mix that path with group artifacts for the same organization, or mix document
digests/revision numbers within a set. The composite delta key uses NUL because
colons are legal identifiers. Candidate simulation carries the complete group
set in `candidate_policies`, replacing that org's candidate rules atomically;
active state remains unchanged.

Deploy matching OPS and Reth versions before activating a group set. Older
strict node decoders reject the added fields. No migration recompiles or
silently changes an approval.

## Validation and security review

The compiler scale regression covers sixty groups and bytecode independence.
Shared Go/Rust fixtures compare whole-document decisions with actual per-group
execution inside the guarded EVM, including later-group allowances, specific
denials and fallback reasons. Tests cover current membership selection,
candidate removal, cross-group deployer exceptions, shared gas limits, invalid
results, atomic deltas, immutable pinned snapshots and mixed-revision rejection.
Database integration tests cover complete approval evidence, separate approvers,
rollback on authorization failure, removal and an empty replacement.

Authorization and organization scoping remain at the existing boundaries;
no new HTTP route is added. Candidate artifacts must belong to the signed
organization. Record reads retain the existing active-policy and diagnostic
scope checks. Every group evaluation restores its journal and memory before
the next group or application frame. Existing leak, isolation, malformed-input
and private-listener tests remain part of the Rust and Go suites.

Verified locally on 2026-09-25:

- Full `internal/policydsl`, `internal/nodepolicy`, and `internal/configuration`
  Go suites; targeted database/API execution, activation, node policy and OpenAPI
  integration tests against isolated PostgreSQL test containers.
- Complete Rust suite with `--no-default-features` (the opt-in benchmark remains
  ignored), plus targeted empty-policy/diagnostic regressions after final review.
- `cargo check --features reth-sdk` and `cargo clippy --all-targets --features
  reth-sdk -- -D warnings`; `go vet` for the five affected Go packages.
- Cross-group deployer exceptions and the real HTTP compilation deadline test.
- `make api-spec` regenerated the API reference successfully.
- Fresh native OPS/Reth full-stack acceptance, 60-group activation and finalized
  execution, grant removal, candidate isolation, empty-set recovery and restart
  persistence. Release measurements using the live compiled artifacts confirm
  that unrelated groups do not increase evaluation cost, while callers scanning
  many artifacts can exhaust the shared gas budget. See the
  [live evidence and measured limits](evidence/per-group-live-2026-09-25.md).
