# Execution artifacts: one per group, not one per organisation

Status: proposed. The reviewed document does not change; only what the
compiler emits and how the node keys it.

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

## The proposal

Keep straight-line generated code. Change the **scope of an artifact** from the
organisation to the group.

```
execution-rules document  (one per org — authored, reviewed, activated as today)
         │  compile
         ▼
 artifact GRP_A     artifact GRP_B     artifact GRP_C
   digest Da          digest Db          digest Dc      ← published, keyed org+group
```

A signer in one group runs one artifact of about a kilobyte in about ten
microseconds, whether the organisation has three groups or three hundred. Size
and time stop depending on the rest of the organisation.

**What does not change.** The document, its review, four-eyes activation, the
generated code's shape, the node's EVM, and the `check(Facts, Call)` entry
point. Authors see exactly what they see today.

**What changes.**

| Where | Today | Proposed |
|---|---|---|
| `nodepolicy.PolicyArtifact` | `OrgID` | `OrgID`, `GroupID` |
| `policyKey` (`feed.go:176`) | `p.OrgID` | `p.OrgID + ":" + p.GroupID` — the shape `sanctionKey` already uses |
| compiler | one artifact | one per group in the document |
| activation | publishes one digest | publishes the set, atomically |
| approval | one digest | the set of digests this document produced |
| node (`facts.rs`) | `policies: HashMap<org, (digest, code)>` | keyed by `(org, group)` |
| node evaluation (`facts.rs:299`) | look up by org, run once | run the signer's groups, combine |

The node already filters and sorts the signer's groups for the org before
evaluating, and already combines the worst reason across frames; combining
across a signer's one or two groups is the same shape of work.

**Why the protocol is comfortable with it.** `Snapshot.Policies` is already a
list with per-item upserts and deletes, so adding a dimension to the key is a
key change rather than a new wire shape. `MaxEnvelopeBytes` is 64 MB; three
hundred groups at about a kilobyte each is 300 KB. Deltas improve: changing one
group republishes that group's kilobyte instead of the organisation's whole
artifact.

## What needs care

- **Atomicity.** A frame must never see half a published set. Activation has to
  publish every artifact the document produced, or none.
- **Approval semantics.** The reviewed thing becomes a set of digests. The
  activation record should carry them all so an auditor can tie every artifact
  back to the revision that produced it.
- **Removal.** A group deleted from the document must have its artifact deleted
  from the feed, not merely left unreferenced.
- **Cross-group rules.** Anything that reasons about *other* groups — today's
  deployer exceptions name the groups that may still reach a contract — must
  stay correct when each group compiles separately. The exception table is
  organisation-wide input to each group's artifact, so it is duplicated across
  artifacts; that is bounded by the 64-entry validation cap and is the one place
  where per-group artifacts cost more bytes in total than one artifact did.
- **The node is a second implementation.** The Rust guard changes with OPS, and
  the cross-language conformance vectors change with both.

## Not addressed here

The 64-entry cap on deployer exceptions is a separate limit: an organisation
with more than 64 granted contracts cannot express execution rules regardless
of artifact granularity.
