# Facts/frame ABI — TDD evidence

Historical A2 interface: the subsequent [A3 lifecycle slice](lifecycle-import.md)
appends facts and supersedes this ABI before deployment.

Date: 16 September 2026. Scope: compiler and offline oracle in
`internal/policydsl`. Reth execution/admission integration is a separate slice.

## Interface and semantics

The generated node entry point is:

```text
check((address,address[],bytes32[],bytes32,bytes32,bytes32,bytes32,uint8,bool,bool),(uint8,address,address,address,bytes,uint256,uint256)) returns (uint256)
```

Facts tuple order: signer, linkedAddresses, groups, policyOrg, callerOrg,
codeOrg, storageOrg, claims, codeShared, storageShared.

Call tuple order: kind, caller, codeAddress, storageAddress, data, value, depth.
Depth is zero for the top-level frame. Group/organisation words are Keccak-256
of the stable database ID in UTF-8; missing organisation facts use a zero word.

Reason codes:

| Code | Meaning |
|---|---|
| 0 | Allow |
| 1 | No matching rule |
| 2 | Argument constraint |
| 3 | Malformed calldata |
| 4 | Ownership mismatch/missing owner |
| 5 | Native value exceeds bound |
| 6 | Depth exceeds bound |
| 7 | CREATE/CREATE2 unsupported by this slice |
| 8 | Immediate caller mismatch |

Existing call/staticcall/delegatecall/callcode ordinals remain 0–3. CREATE and
CREATE2 reserve 4/5 but cannot yet be authored as permitted call types.

The policy organisation must equal the compiled organisation. Existing exact
address rules require both code and storage owners to match it. Shared flags do
not grant access or bypass this requirement. Caller organisation and claim
facts are carried for subsequent grammar work, not used to invent new grants.

Frame rules accept optional `maxValue` (decimal uint256 string), `maxDepth`
(nonnegative integer, represented by an optional int64), and `callerAddress`
(immediate-caller address). Omission leaves that constraint unbounded; explicit
zero is a real bound. Null, duplicate and case-variant frame-rule fields are
rejected. Address/uint argument constraints and existing selector semantics
remain unchanged.

The offline Go context gains claims; frames gain explicit owner/shared facts,
caller, native value and depth. No owner is inferred from the requested policy
organisation. `EVMEvaluator.Evaluate` calls the new entry point. The old
`checkFrame` wrapper is offline compatibility only and cannot allow a rule that
requires facts absent from that interface. Both functions use the same internal
predicate, without an external self-call.

## Red

Before implementation, independent ABI-encoded calls to compiled policy code
failed and the parser rejected the proposed fields:

```sh
go test ./internal/policydsl -run 'TestFactsABI|TestFactsSchema' -count=1
```

```text
--- FAIL: TestFactsABI_ExplicitOwnershipAndKinds
    facts-based policy call failed: execution reverted
--- FAIL: TestFactsABI_ValueDepthAndCaller
    policy: malformed document: json: unknown field "callerAddress"
--- FAIL: TestFactsSchema_OptionalFrameConstraints
    policy: malformed document: json: unknown field "maxValue"
    policy: malformed document: json: unknown field "maxDepth"
FAIL privacy-proxy/internal/policydsl 1.149s
```

A second red regression caught duplicate/case-variant bounds silently erasing a
constraint during JSON decoding:

```sh
go test ./internal/policydsl -run 'TestFactsSchema_RejectsAmbiguousBounds' -count=1
```

```text
--- FAIL: TestFactsSchema_RejectsAmbiguousBounds
    ambiguous bound accepted: "maxValue":"0","MaxValue":null
    ambiguous bound accepted: "maxValue":null,"maxValue":"100"
FAIL privacy-proxy/internal/policydsl 0.482s
```

These are excerpts with repeated subtest assertions omitted.

## Green

Tests use a separately written ABI fixture to pack tuples and invoke the
compiled EVM bytecode. They compare its encoding with the production packer and
test value/depth/caller decisions, absent/foreign ownership, shared-flag bypass
attempts, unsupported deployment kinds, legacy-wrapper denial and strict
32-byte return decoding. Zero-bound tests also mutate original and exported
policy copies to verify validated constraints remain immutable. Representative
compiled checks run within the agreed 100,000 internal-gas budget.

Existing selector/argument fixtures now state their known organisation facts
explicitly. They continue exercising the existing Go/Solidity conformance
corpus and A1 ABI-offset/compiler hardening, rather than passing because both
evaluators reject missing ownership.

```sh
go test ./internal/policydsl -count=1
```

```text
ok privacy-proxy/internal/policydsl 5.777s
```

Final verification, after zero-bound/immutability and node-budget assertions:

```sh
go test -race ./internal/policydsl -count=1
```

```text
ok privacy-proxy/internal/policydsl 6.892s
```

Environment: Go 1.26.6, solc 0.8.35, macOS ARM64; same installed compiler as A1.
`gofmt` and `git diff --check` passed. Independent review is requested before
integration.

## Integration boundaries

- The node must authenticate the principal and resolve bans, links, membership
  expiry and current snapshot authority before calling the policy. This ABI
  does not accept permission verdicts from admission tickets.
- Callers of the offline evaluator, including the current admin simulator,
  must supply resolved owner facts. The server integration must use its catalog
  or the node simulation path; missing owner facts now deny.
- Existing stored bytecode without the new function is not silently accepted
  by the facts evaluator. It must be rebuilt/reviewed during migration.
- Claims, ownership classes, wildcard selectors, deployment rules and record
  predicates require subsequent reviewed grammar slices. Their presence in
  the tuple does not claim they are already enforced here.
