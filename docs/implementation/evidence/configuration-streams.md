# Configuration revision lifecycle evidence

## B2: typed source and group projection

The initial tests failed against parser/diff and store stubs. The implementation then passed the typed-document tests and isolated PostgreSQL lifecycle tests. Later sections record the HTTP and remaining stream slices.

Implemented:

- Exact, versioned JSON documents with immutable scope and stream kind, active base revision, sibling dependency digests, explicit arrays and explicit deletions. Unknown/case-aliased keys, duplicate keys, missing fields and null collections fail closed. Canonical digests sort ID resources and set-valued fields.
- Group context export and safe projection preserve unmanaged rows and RPC secrets. Deleting a managed group requires its explicit ID and acknowledgement of its current live membership count. System groups are protected. Full-admin group changes are marked for platform authorization.
- Additive migration 074 stores immutable review source, digest, dependencies and activation evidence. Draft numbering is independent of the active base. The compiled artifact column is reserved for the execution stream.
- Activation locks the organization, reviewed revisions, group parents, access rows and memberships, then repeats the diff and invokes a mandatory authorization callback. Four-eyes and named non-banned actor identity are store checks. API-level current author/activator role enforcement remains the next slice.
- Group projection, revision state changes, cache invalidation and the existing RBAC hash-chain audit row commit together. Injected audit insertion failure rolls back both projection and chain advancement. The persisted row passes the actual audit verifier.
- Editing context uses a repeatable-read snapshot so source, active base and membership counts are consistent.

Validation:

```text
go test ./internal/configuration ./internal/db -run 'TestDocument|TestGroupDiff|TestLegacyExport|TestConfiguration' -count=1 -timeout=5m
ok privacy-proxy/internal/configuration 0.497s
ok privacy-proxy/internal/db 7.643s

go test -race ./internal/configuration ./internal/db -run 'TestDocument|TestGroupDiff|TestLegacyExport|TestConfiguration' -count=1 -timeout=5m
ok privacy-proxy/internal/configuration 1.280s
ok privacy-proxy/internal/db 14.909s
```

The race run includes the later repeatable-read context change and a concurrent membership insertion versus group deletion regression. One intermediate race attempt could not compile while the independently owned compiler package was being edited; the completed run above passed after that package became buildable.

The following B3 slices add registry/co-activation, remaining streams, authority locking, last-admin protection and writer closure. Physical `contract_grants.claims` is historical metadata; current runtime authority comes from the granting group's `group_access.claims`. The registry model does not present dormant column changes as effective permissions.

## B3a: registry projection and authority hardening

The registry source owns contract names, ABIs, visibility flags and read-grant links/event rules. Every grant has its existing UUID; removing a managed nested grant requires its explicit ID, including when its parent contract is removed. Unmanaged operational registrations and grants remain drift until adopted. The source field `legacyClaims` preserves the dormant database column, cannot be changed, and grants no authority. New links have `functions=[]`; editing an existing link never changes its legacy `functions` value (including SQL NULL, meaning all).

Group/registry co-activation creates groups before referenced contracts/grants and removes reviewed links before deleting their groups. The complete set commits with one audit entry and one transactional outbox batch. Contract deployment metadata and group RPC secrets/historical hierarchy metadata are retained. ABI validation rejects unknown event topics, name mismatches, duplicate topics/parameter constraints, invalid predicate types and malformed scalar values. Custom literal event addresses must resolve to the same organization at activation.

New regressions first failed for banned/deleted original authors, removing the last active full administrator, registry projection, and accepting an unregistered custom event address. Their fixes passed:

```text
go test -race ./internal/configuration ./internal/db -run 'TestDocument|TestGroupDiff|TestLegacyExport|TestRegistry|TestConfiguration' -count=1 -timeout=5m
ok privacy-proxy/internal/configuration 1.418s
ok privacy-proxy/internal/db 29.954s
```

Scope user rows are held with shared locks alongside membership and group locks, preventing ban/status changes from invalidating an authorization callback during commit. Original authors must still exist and be unbanned. Current-role enforcement is delegated to the mandatory callback and is being wired into the common HTTP lifecycle; this evidence does not claim the remaining streams or old-writer closure are complete.

## B3b: authenticated principal kind

New signed access/refresh token claims distinguish verified human login from Azure service-principal login. Refresh preserves that distinction; a legacy token without the claim remains unclassified until a fresh login. Subject strings and request body fields cannot assert human status. The Azure service-principal end-to-end test and refresh regression initially failed, then passed with explicit issuance from the verified login routes:

```text
go test ./internal/auth ./internal/server -run 'TestJWT|TestHashToken|TestHandleRefresh|TestHandleAuthCallback|TestHandleAuthVerify|TestHandleAzureServicePrincipal' -count=1 -timeout=5m
ok privacy-proxy/internal/auth 0.508s
ok privacy-proxy/internal/server 4.592s
```

## B3c: managed writers and named lifecycle API

Actual JWT middleware tests initially returned 404 for the generic lifecycle.
They now exercise readonly service drafting and simulation, independent human
approval, original-author authority revocation, exact URL/source scope,
projection visibility and 409 closure of legacy desired-state writers.
Missing-kind and service tokens cannot use interactive activation. An internal
error response regression first exposed raw error text as 409; unexpected
errors are now opaque 500, while typed review conflicts remain actionable.

Migration 075 checks managed ownership under the same scope lock as activation.
The first-activation race initially let an already-started legacy INSERT commit
after activation; the trigger now rejects it. The deployment exception is an
internal scoped INSERT-only transaction marker, not an HTTP option. User
membership/ban/KYC, sanctions, fetched prices and operational credentials stay
outside desired-state ownership. The credential endpoint edits only encrypted
RPC secret material and logs no secret value.

Lock-inversion verification explicitly holds a legacy group lock, starts
activation holding the organization lock, then creates the old group→org versus
new org→group cycle. PostgreSQL aborts a complete contender. After rollback and
retry, only the reviewed name exists and exactly one activation audit row was
committed (`TestConfigurationLegacyLockInversionRollsBackAndRetries`, 4.610s).

## B3d: compliance, approvers, platform and external CI

Typed parser tests first rejected each unsupported stream. Integration tests
then failed at missing projection before the new projectors were implemented.
Compliance owns settings, thresholds and authored static prices/source mappings;
urgent sanctions remain writable and survive reapplication. Approvers references
must point at current full-admin groups and retain an eligible live member.
Activation eligibility uses the old trust policy. Trusted CI removals are
explicit resource deletions. Platform uses a distinct lock/scope/audit org=NULL,
codehash-pinned shared infrastructure and validated tenant placement.

Platform lifecycle tests first failed 404; verified allowlisted humans can now
draft and independently activate without gaining ordinary organization roles.
Withdrawal had a separate RED409 (organization-only loader) and now passes.
`/me/admin-status` exposes a separate `is_platform_admin` presentation flag;
service and legacy-kind JWTs cannot claim it.

External CI has a separate activation route and an Ed25519 signed manifest
binding exact candidate digests, org, service subject, repository/ref, reviewed
commit, independent named reviewers and bounded expiry. The independently
configured signer attests Git approval; the app does not claim to query Git.
Current service/reviewer authority and bans are rechecked under activation
locks. Invalid signatures and revoked reviewers fail. The complete assertion
is retained in the same activation hash-chain entry. CI cannot alter platform
or its own approver trust root. Approver/platform drafts retain immutable
`created_principal_kind`; both source author and activator must be humans.
Normal organization streams still allow service/readonly drafts.

Combined checkpoint, including generic execution hooks supplied by the compiler
slice (see `execution-stream.md`):

```text
go test -race ./internal/configuration ./internal/db -run 'TestDocument|TestGroupDiff|TestLegacyExport|TestRegistry|TestConfiguration|TestComplianceDocument|TestApproversDocument|TestPlatformDocument|TestCIApproval' -count=1 -timeout=7m
ok privacy-proxy/internal/configuration 1.485s
ok privacy-proxy/internal/db 65.840s

go test ./internal/server -run 'TestConfigurationPlatformRequires|TestConfigurationCIAPI|TestConfigurationPlatformStatus|TestConfigurationAPI' -count=1 -timeout=5m
ok privacy-proxy/internal/server 5.826s
```

The later human-author provenance tightening and OAuth propagation have their
own follow-up verification. OAuth review found that code exchange dropped the
signed principal kind. A real mock OAuth exchange first failed human-vs-empty;
memory/Redis sessions now preserve verified human versus service identity, and
silent SSO preserves the caller's signed kind instead of inferring it from DID
text. Legacy sessions remain unclassified and require interactive login before
approval. Initial OAuth exchange/silent-SSO regression suite passed 5.315s;
Redis OAuth store regressions passed 4.645s.

Follow-up after immutable human-author provenance and OAuth service/legacy
preservation:

```text
go test ./internal/server ./internal/db -run 'TestConfigurationCIAPI|TestConfigurationPlatformRequires|TestConfigurationApproversReference|TestConfigurationCIRequires|TestConfigurationPlatformScope|TestOAuthSilentCompletionPreserves|TestOAuth_TokenExchange_ReturnsRefreshToken' -count=1 -timeout=5m
ok privacy-proxy/internal/server 4.832s
ok privacy-proxy/internal/db 9.359s
```

The source/app contract and setup instructions are documented in
`../configuration-api.md`. OpenAPI generation, SDK/UI and the real OPS/Reth
stack acceptance run are coordinated separately; these unit/integration
results are not presented as a completed deployed-stack acceptance run.

Final source-fidelity review found PostgreSQL threshold rounding: authored
`1.234` was accepted and projected to `1.23` by `NUMERIC(20,2)`. New regressions
failed on that input and overflowing manual token-price values. Thresholds now
require at most two decimal places and values below `1e18`; token-price integer
range must fit the backing `NUMERIC(20,8)` column while authoritative JSON price
maps retain sub-eight-decimal precision. Compliance numeric tokens must survive
the existing float model's decimal JSON round trip; bounded token length and
underflow rejection prevent huge rational exponent allocations.

```text
go test ./internal/configuration ./internal/db -run 'TestComplianceDocument|TestConfigurationCompliance' -count=1 -timeout=3m
ok privacy-proxy/internal/configuration 0.546s
ok privacy-proxy/internal/db 5.516s

go test ./internal/configuration -run 'TestComplianceDocument' -count=1
ok privacy-proxy/internal/configuration 0.449s
```

Actual OPS/Reth/PG/Redis/indexer/explorer deployment acceptance subsequently
passed; see [full-stack evidence](ops-reth-stack.md).

## Handoff checkpoint (2026-09-17, continued after the Codex session ended)

Two red tests were left by the previous session and are now green:

- `TestConfigurationWriterRejectsOperatorBeforeDatabaseLookup` (new): the
  legacy-writer 409 guard performed the managed-stream lookup before any
  authorization, so an operator token on a tenant registry/compliance route hit a
  nil dependency (HTTP 500 in `TestOperatorTokenDeniedOnTenantAndFleetEndpoints_RD1173`)
  and, in production, would have learned whether a tenant stream is managed
  before the handler rejected it. The guard now runs `denyOperatorOrgScoped`
  (organization streams) or `requireSuperAdmin` (platform) first.
- `TestConfigurationContextReportsCapabilitiesAndMissingCompiler` (new): every
  `GET …/context` carries `capabilities` (API version, organization kinds,
  human-only kinds, approval modes, document size limit, pinned compiler version
  and a live availability probe of that exact compiler). The human-only rule is
  now a single helper, `configuration.RequiresHumanAuthor`, used by submission,
  activation and the capabilities block.

The seven platform routes lacked OpenAPI entries (`TestOpenAPICoverage_RouteSpecGate`)
and 65 new schemas were unrecorded (`TestSchemaNameBaselineIsCurrent`). Platform
routes now have their own documented handlers without organization path
parameters; the spec, endpoint inventory, site copy, schema baseline and the
SDK's generated types were regenerated together.

```text
go test ./internal/server -run 'TestConfigurationWriterRejectsOperatorBeforeDatabaseLookup|TestOperatorTokenDeniedOnTenantAndFleetEndpoints_RD1173|TestConfigurationContextReportsCapabilitiesAndMissingCompiler|TestConfigurationAPI.*|TestConfigurationPlatform.*' -count=1
ok privacy-proxy/internal/server 7.335s
go test ./internal/configuration ./internal/db -run 'TestConfiguration(Platform|Approvers|CI)|TestDocument|TestPlatformDocument|TestApproversDocument|TestCIApproval|TestConfigurationRevision' -count=1
ok privacy-proxy/internal/configuration 0.403s
ok privacy-proxy/internal/db 19.297s
go test ./internal/server/apispec -count=1            ok 0.509s
go test ./internal/server -run '^TestOpenAPICoverage' ok 3.255s
sdk: npm run generate && npm test                      11 passed, generated types in sync
frontend: tsc -b; vitest src/components/rbac           Configuration.test.tsx 8 passed
```

The CI lint `tools/check-err-leak.sh` (RD-934: no `err.Error()` in a response
body) failed on this branch: twelve handler sites in the configuration,
CI-activation and execution-policy handlers echoed validation and conflict
errors. Those messages are the document author's own diagnostics, so hiding
them would make the API unusable; the fix makes the carve-out a matter of
**type** rather than call site. `policydsl.Parse/Validate/ApplyProxyPairs`
return `*policydsl.ValidationError`, every exported parser/validator/diff in
`internal/configuration` returns `*configuration.SourceError`, and
`db.ConfigurationConflict` returns `*db.ConfigurationConflictError`, which
renders an error argument only by its client text and replaces anything
untyped (driver, I/O) with `internal error` while keeping it in the chain and
logging it. Handlers go through `respondClientError`, which writes the client
text when the error carries one and an opaque fallback plus a log line
otherwise; DB sentinels (`ErrPolicyStaleBase`, …) are written as their
constant text. Red tests first: `TestRespondClientErrorKeepsUntypedErrorsOpaque`,
`TestDocumentFaultsAreValidationErrors`, `TestAuthoredDocumentFaultsAreSourceErrors`,
`TestConfigurationConflictRendersOnlyClientText`. The tracked-file lint and a
manual scan of the not-yet-committed handler files both report zero hits.

An independent adversarial review of these handoff changes (2026-09-17) found
six should-fix items and five nits, all addressed the same day:

| Finding | Fix |
|---|---|
| Every context read forked `solc --version`; the admin group has no request limiter | one probe shared by all readers for 30 s, single-flight, re-probed on a path change (`TestCompilerProbeSharesOneProbePerTTL`) |
| `compileRule` echoed go-ethereum's ABI parser wording through the typed path | constant message; parser error logged |
| Legacy `/execution-policy/revisions` submit/activate/withdraw were not closed when the `execution-rules` stream is managed | `configurationWriterGuard(ExecutionRules)` on the three routes; guard test covers the kind |
| A conflict wrapped a plain sentinel and would have rendered `internal error` on a business path | plain `%w` wrap of `ErrConfigurationForbidden` |
| A driver error from the execution import path became a conflict, and its `SQLState` could flip the status | wrap only errors that carry client text; driver errors keep their type → opaque 500 |
| Platform swaggo blocks omitted 400/404/409 the shared handlers return | annotations completed, spec/SDK regenerated |
| Nits | legacy import report names the records (bounded); serialization failures are constants; `SourceError` contract names the `ExportRegistry` exception; dead `/activate-ci` platform route entry removed; test helper uses the real parse error |

The generator still labels the platform routes "Admin token + private network"
in `API_ENDPOINTS.md`; `requireConfigurationPlatform` rejects token callers, so
the label is a limitation of the inventory generator's auth mapping, not of the
route.

Follow-up (2026-09-17, DECISION §4 item 10): the legacy `…/grants` routes closed
only when the registry stream was active; the `contract_grants` trigger already
refused a `functions` write under an active execution-rules stream, so the
route answered an opaque 500 instead of the 409 the other legacy writers give.
`TestLegacyGrantWritersCloseWhenExecutionRulesAreManaged` (red: 404 reached the
handler → green: 409 on POST/PUT/DELETE) and the three routes now carry both
stream guards.

