# Execution rules in the configuration lifecycle

The `execution-rules` stream accepts a complete closed DSL policy under
`spec.policy`. It retains the server-compiled artifact with the immutable draft.
Compilation can use current catalog state or explicitly declared same-scope
groups/contract-registry draft dependencies. The source document cannot supply
bytecode or compiler metadata.

Activation validates the policy against the final projected sibling catalog,
checks the stored source, policy/runtime digests and pinned compiler contract,
and writes the exact approved artifact to the existing node-export projection.
The projection uses the configuration revision ID. Its legacy revision counter
remains independent of the generic stream counter; the diff records both.
Configuration source, projection, node-policy dirty version and RBAC audit
content share the main database transaction. Access-log delivery is separate.

Migration 077 adds the legacy execution-policy writer barrier after adoption.
Only the scoped configuration projector can write that table for an adopted
organization. Existing unmanaged organizations retain their earlier path.

## Tests and review

The first tests failed with undefined `ExecutionSpec` and execution-store hooks
before implementation. The initial vertical database test then passed:

```text
go test ./internal/db -run '^TestConfigurationExecution' -count=1
ok privacy-proxy/internal/db 4.636s
```

A separate review regression exposed missing initial-migration permissions:

```text
go test ./internal/db -run '^TestConfigurationExecution' -count=1
FAIL TestConfigurationExecutionFirstAdoptionReviewsLegacyGrantRemoval
Expected value not to be nil: initial migration must expose the permissions it replaces
FAIL privacy-proxy/internal/db 8.999s
```

The fix imports current legacy grants as the review baseline, before applying
any sibling candidate changes. Review shows complete old/new binding rules.
Unsupported legacy records fail with a typed import report instead of silently
disappearing from the baseline.

```text
go test ./internal/db -run '^TestConfigurationExecution' -count=1
ok privacy-proxy/internal/db 8.771s

go test -race ./internal/configuration ./internal/db -run '^(TestExecution|TestConfigurationExecution)' -count=1
ok privacy-proxy/internal/configuration 1.471s
ok privacy-proxy/internal/db 22.076s
```

The database tests exercise actual solc 0.8.35 compilation and isolated PostgreSQL
migrations. They cover undeclared versus declared draft dependencies, atomic
three-stream activation, artifact immutability, legacy writer closure, context
roundtrip, ABI-only activation rejection and matching coactivation, nil-functions
wildcard versus explicit-empty deny, initial grant-removal review, differing
legacy/generic revision counters, node-version invalidation and artifact audit
retention. Existing execution-policy activation concurrency and actor tests run
in the final selection as well.

Independent review identified the legacy POC intersection ambiguity. A new test
first failed because context export returned that restriction as a complete
policy (`FAIL ...LegacyRestrictionRequiresExplicitMigration`, 3.834s). Context
export returns an editable RBAC baseline and separate read-only migration
evidence when the active legacy row has no matching generic source revision.
Submission and activation require the exact old policy digest in
`spec.legacyRestrictionDigest`. The independent reviewer receives both sources,
the old artifact and the proposed complete policy; no effective intersection is
claimed. The reviewed acknowledgement survives context/source roundtrip.

```text
go test -race ./internal/db -run '^TestConfigurationExecution' -count=1
ok privacy-proxy/internal/db 31.787s
```

## Deployment migration follow-up

A5 now preserves individual-deployer fallback and preregistration with explicit
ownership classes and signed live facts. Reviewed ordinary proxy pairs can be
supplied in `spec.proxyPairs`; compilation expands them to ordinary explicit
DELEGATECALL rules while preserving the implementation's selectors and argument
limits. Context retains the compact source, review shows the expanded policy,
and first-adoption context explicitly warns that proxy relationships require
operator review. See [deployment-migration.md](deployment-migration.md).

The full database selection, including migration acknowledgement and proxy-pair
roundtrip, passes with the race detector (25.756s). The configuration schema race
selection passes (1.575s). The acknowledgement regression first failed because
context export dropped the acknowledgement; retaining the complete source spec
fixed it (6.078s). Current source and artifacts are trusted server-produced revision data;
activation verifies their integrity and immutable linkage, and does not rerun
solc on every approval. Draft compilation currently holds the organization scope
lock for the compiler operation (bounded at 60 seconds). This limits control-plane
throughput; a future compile-before-lock optimization must revalidate the catalog
under the lock before storing the artifact.
