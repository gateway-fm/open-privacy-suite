# Live record-party execution constraint

The call half of RD-1206 is implemented as an argument constraint:

```json
{
  "index": 0,
  "recordParty": {
    "getter": "0x018fce0e",
    "abiDigest": "<SHA-256 of the registered storage contract ABI>",
    "partyOutputs": [2, 3]
  }
}
```

`index` selects the guarded call's record ID. It is mapped to the getter's sole
input, whose ABI type must be identical. Supported IDs are `uintN`, `bytes32`,
`string`, and `bytes`; dynamic IDs are limited to 1,024 bytes. The compiler
accounts for full static tuple/array head widths before the selected ID and
validates dynamic offsets, lengths, padding, and integer width.

The getter target is always the guarded frame's storage address. A document
cannot choose another target. Its separately pinned ABI must be registered in
the policy organization and explicitly declare the getter `view` or `pure`.
The getter returns between 1 and 16 scalar values: `address`, `uintN`, `bool`, or
`bytes32`. `partyOutputs` names distinct address outputs. Dynamic and composite
return shapes are rejected explicitly. This covers the reviewed RD-1206
`getPaymentInfo(string)` return shape: amount, timestamp, payer, payee, completed.

All return words are checked for canonical encoding and the total returned
length must be exact. Any nonzero selected party matching any current linked
address of the authenticated principal satisfies the constraint. The signer
alone does not substitute for principal links; zero/absent record parties deny.

Generated policies issue a nested `STATICCALL`, capped at 50,000 gas. Return
copying is bounded to the validated output length, avoiding arbitrary return
allocation. Reverts, gas exhaustion, malformed results, and non-party callers
return existing reason `2` (`argument_constraint`); malformed record-ID calldata
returns reason `3`. The A3 facts/frame ABI and its selector `0xdd789b6a` are
unchanged. Only policies containing live reads change their entrypoints to
`view`; artifacts for policies with no record reads are unchanged.

The getter's answer must be independent of caller identity. Operators must
review that requirement: **a view/pure ABI annotation cannot prove independence
from `msg.sender` or `tx.origin`**. The getter sees the private policy account as
its immediate caller. The node must also scope any further calls made by a
getter to permitted policy-read targets; skipping recursive policy evaluation
must not permit a getter to probe another organization's private state. That
separate node integration guard was raised during review and is tracked by the
node agent; compiler tests alone do not establish it.

The Go evaluator remains an offline oracle. `Context.ReadRecord` supplies an
explicit live-state reader; its absence denies. `EVMEvaluator.ReadContract`
provides a bounded static reader over the oracle's candidate state and reverts
its journal snapshot after each read. Production authority is the node's nested
policy execution, never an admission-time lookup or cached record audience.
The reference callback is a trusted test/preview dependency: supplying a callback
does not independently prove live-state provenance or nested-call isolation.
Record-history visibility remains deferred as specified in DECISION.

## TDD and verification

Initial red:

```text
go test ./internal/policydsl -run '^TestRecordParty' -count=1
FAIL TestRecordPartyReadsLiveSameBlockStateAndAllLinkedAddresses:
  argument constraint: json: unknown field "recordParty"
FAIL TestRecordPartyGetterFailuresDeny:
  argument constraint: json: unknown field "recordParty"
FAIL privacy-proxy/internal/policydsl 0.426s
```

Green after grammar and generation, then expanded independent ABI/state tests:

```text
go test ./internal/policydsl -run '^TestRecordParty' -count=1
ok privacy-proxy/internal/policydsl 2.815s

go test ./internal/policydsl -count=1
ok privacy-proxy/internal/policydsl 23.575s

go test ./internal/policydsl -run '^TestRecordParty' -count=1
ok privacy-proxy/internal/policydsl 9.051s

OPS_DSL_UPDATE_FIXTURES=1 go test ./internal/policydsl -run '^TestRecordPartyVectors$' -count=1
ok privacy-proxy/internal/policydsl 1.400s

go test -race ./internal/policydsl -count=1
ok privacy-proxy/internal/policydsl 27.165s
```

`record_party_test.go` compiles an independent Solidity record contract and
executes generated policy bytecode in the same EVM state. A real setter call
changes parties within the candidate state; the next policy evaluation sees the
change immediately. Tests cover every supported ID type, a composite ABI head,
all linked addresses, exact getter calldata hashing, unknown/non-view getters,
wrong ABI digests, unsupported party outputs, malformed dynamic IDs, over-bound
IDs, duplicate/null/case-confusable JSON, missing offline reader, immutable
validated constraints, short/noncanonical returns, reverts, out-of-gas loops,
return bombs, and attempted storage writes.

`testdata/record-party-v1.json` is a deterministic cross-language fixture. It
contains the policy document and runtime, independent record runtime/ABI, exact
facts-call ABI bytes, real setter calldata, and eight expected state/decision
cases. The node integration consumes the same artifact and vectors. The
existing A3 lifecycle golden fixture also remains unchanged and passes.
