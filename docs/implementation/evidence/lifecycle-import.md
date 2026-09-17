# Lifecycle grammar and legacy import — TDD evidence

Historical A3 evidence; [A5 deployment migration](deployment-migration.md) replaces
this ABI and resolves the individual-deployer/preregistration adapter gaps.
Ordinary proxy relationships now have an explicit reviewed `spec.proxyPairs`
input; they are never inferred automatically.

Date: 17 September 2026. Scope: `internal/policydsl`; node and directory
integration are separate slices. This is the final A3 interface, superseding
the undeployed A2 facts ABI. Older artifacts require review and recompilation.

## Final ABI

```text
check((address,address[],bytes32[],bytes32,bytes32,bytes32,bytes32,uint8,bool,bool,uint8,bytes32,uint8[]),(uint8,address,address,address,bytes,uint256,uint256)) returns (uint256)
selector: 0xdd789b6a
```

Facts order: signer, linkedAddresses, groups, policyOrg, callerOrg, codeOrg,
storageOrg, claims, codeShared, storageShared, **codeKind, upgradeTargetOrg,
groupClaims**. Call order remains kind, caller, codeAddress, storageAddress,
data, value, depth. Organisation/group IDs are Keccak-256 of stable UTF-8 DB
identifiers; absent ownership is the zero word. No claim is taken from a
transaction identity envelope.

`codeKind`: 0 unknown, 1 no-code/EOA, 2 contract, 3 active precompile. The node
classifies the actual execution state, including its active precompile set.
An EOA rule cannot match an unregistered contract's fallback or receive code.
Shared flags are resolved only after the node's live codehash checks.

Claim bits: admin 1, deploy 2, upgrade 4. `groupClaims` must align exactly with
`groups`. Privileged rules consult the matching binding's mask, never the
aggregate `claims` field. CREATE uses that group's current operational claims.
Registered frames use those claims only where the group has the current target
grant. Org-admin role supplies 7. This follows `rbac/resolver.go`'s
`groupPerms`: **group_access.claims gated by contract_grants**. The legacy
physical `contract_grants.claims` column is not current resolver authority.

Known upgrade selectors require explicit `allowUpgrade: true`, this binding's
current upgrade/admin bit, and a canonical nonzero target address whose owner
equals policyOrg. Target is argument 0 for `3659cfe6`, `4f1ef286`, `d784d426`;
argument 1 for `99a88ec4`, `9623609d`. The node resolves upgradeTargetOrg from
that actual argument. This applies even when an upgrade only writes a pointer
and never calls the new implementation. Revoking one group's upgrade claim
cannot borrow a different membership's claim.

Reasons 0–8 retain A2 meanings (7 now means no permitted CREATE rule). New
reasons: 9 operational claim denied; 10 invalid facts, including misaligned
group/claim arrays. Any nonzero reason denies; malformed returns/reverts deny.

## Grammar and migration semantics

- Omitted `targetClass` means existing literal registered storage/code pairs.
  Both owners must equal policyOrg; shared flags do not widen these rules.
- `org` matches code and storage owned by policyOrg. `shared` requires matching
  code/storage address, contract kind, and both verified shared flags. `eoa`
  requires an unowned, matching no-code address. `precompile` requires matching
  addresses and an active precompile classification. All default to CALL and
  STATICCALL; org may explicitly allow DELEGATECALL/CALLCODE. Other classes
  cannot borrow storage. Classes and literal addresses are mutually exclusive.
- `create` requires explicit CREATE/CREATE2 call types, nonempty initcode,
  inherited code/storage owner equal to policyOrg, and the matching group's
  deploy/admin bit. Nested factories must belong to policyOrg. Constructor
  external calls still require their own rules; ownership inheritance is not
  permission inheritance.
- `selector: "*"` permits any input, including fallback/receive. `selector:
  "0x"` means exactly empty input, required for eoa. Neither form accepts ABI
  digests or argument constraints. Exact selectors retain the existing pinned
  ABI and argument grammar. Existing value/depth/caller bounds also apply.
- `ImportLegacy` takes explicit neutral group/grant source records. Real
  `rbac.ContractGrant` JSON fixtures prove `functions: null` means wildcard,
  `functions: []` contributes no execution rules, and `must_be: self` means
  principal.linked (including non-signer linked addresses). Operational admin
  does not imply org-admin's all-contract role. Admin/deploy/upgrade semantics
  are preserved without inventing old read/write claims.
- Import groups, grants, functions and issue reports are sorted. Unsupported
  source records produce `LegacyImportError` and **no policy**, preventing
  accidental activation of a partial conversion. Literal legacy parameter
  conditions (not actually supported by the old runtime), missing ABI for an
  exact selector, individual deployer access, and preregistration records need
  explicit follow-up adapters. Event visibility and RPC method allowlists stay
  separate gates.
- Ordinary imported grants do not infer DELEGATECALL storage/code pairs.
  Reviewed proxy relationships are needed. Org-admin's org class explicitly
  covers the four non-CREATE frame kinds across same-org owners. These migration
  limits are outstanding integration work, not completed end-to-end flows.

## Red evidence

```sh
go test ./internal/policydsl -run 'TestLifecycle' -count=1
```

```text
TestLifecycle_WildcardIncludesFallbackWithoutABI: selector "*" must be a 0x-prefixed four-byte hex value
TestLifecycle_TargetClasses: unknown frame rule field "targetClass"
TestLifecycle_CreateRequiresOwnGroupDeployAndInheritedOwner: unknown frame rule field "targetClass"
TestLifecycle_UpgradePointerWriteChecksClaimsAndTarget: unknown frame rule field "allowUpgrade"
FAIL privacy-proxy/internal/policydsl 0.513s
```

The importer test was introduced before its API/implementation:

```sh
go test ./internal/policydsl -run 'TestImportLegacy' -count=1
```

It failed to build with undefined `ImportLegacy`, `LegacyGrant`,
`LegacyFunction`, and `LegacySnapshot`. The corpus decodes the actual RBAC grant
type first, preserving JSON null versus empty-array meaning.

## Green evidence and cross-language fixture

```text
go test ./internal/policydsl -run 'TestLifecycle' -count=1
ok privacy-proxy/internal/policydsl 4.676s

go test ./internal/policydsl -run 'TestImportLegacy|TestLifecycle|TestFactsABI' -count=1
ok privacy-proxy/internal/policydsl 8.904s

go test -race ./internal/policydsl -count=1
ok privacy-proxy/internal/policydsl 12.133s
```

Lifecycle tests independently pack the final ABI, execute compiled bytecode
within 100,000 gas, and compare with the Go oracle. They cover fallback,
ownership classes, native-contract confusion, default delegate denial,
CREATE/CREATE2, inherited ownership, admin implication, upgrade intent, all
five upgrade selectors, canonical/truncated addresses, foreign pointer targets,
cross-group claim borrowing, revocation, and malformed fact arrays. Schema
tests reject ambiguous classes, class/address mixtures and omitted create kinds.

`internal/policydsl/testdata/lifecycle-v1.json` contains a complete unsigned
snapshot with base64 policy runtime bytecode, explicit hex facts, call inputs,
the independently packed calldata, and expected reasons. It covers ordinary
org calls, native transfers, CREATE/CREATE2, unknown contracts, revoked deploy
claims and foreign deployment owners. Rust consumes this same artifact.
The fixture's fixed network is 31337 / compiler-fixture, timestamp 1800000000.

`TestLifecycleVectors` first failed because the fixture was absent (1.242s).
Regeneration then passed (1.391s):

```sh
OPS_DSL_UPDATE_FIXTURES=1 go test ./internal/policydsl -run '^TestLifecycleVectors$' -count=1
```

Ordinary test runs rebuild deterministically and compare the fixture byte for
byte; fixture changes must be reviewed before regeneration. Go 1.26.6 and solc
0.8.35 were used. `gofmt` and `git diff --check` passed. Independent parent
review is requested before integration.

Final verification including the shared Rust fixture:

```text
go test -race ./internal/policydsl -count=1
ok privacy-proxy/internal/policydsl 13.350s
```
