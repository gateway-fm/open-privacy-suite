# Compiler hardening — TDD evidence

Date: 16 September 2026. Worktree: `.tmp/worktrees/ops-dsl-reth`, branch
`feat/ops-dsl-reth`. Initial implementation base: `37adf65` (the nine policy
builder commits cherry-picked onto the integration branch).

Scope: `internal/policydsl` only. The existing `checkFrame` ABI and document
schema are unchanged. This slice does not claim live transaction enforcement.

Environment: macOS ARM64; Go `go1.26.6 darwin/arm64`; solc
`0.8.35+commit.47b9dedd.Darwin.appleclang` at `/opt/homebrew/bin/solc`.

## Red

Added `internal/policydsl/hardening_test.go` before changing implementation.

```sh
go test ./internal/policydsl -run 'TestABIHeadOffsets_CompositeInputs|TestBuild_ReproducibleAcrossDirectories|TestEVMEvaluator_StrictResultDecoding' -count=1
```

The first sandboxed attempt could not write the existing Go build cache. The
same command then ran with approved cache access and exited 1 in 2.341 seconds.
Observed failures included:

```text
--- FAIL: TestABIHeadOffsets_CompositeInputs
    array_cannot_hide_excessive_amount:
        Go: allowed=true, want false
        Solidity: allowed=true, want false
    tuple_cannot_hide_excessive_amount:
        Go: allowed=true, want false
        Solidity: allowed=true, want false
    fully_static_array_amount_at_bound:
        Go: calldata ... is 100 bytes, but its arguments occupy exactly 68
        Solidity: allowed=false, want true
    truncated_static_head:
        Go: truncated calldata decision={Allowed:true Code: Reason:}
        Solidity: truncated calldata decision={Allowed:true Code: Reason:}
--- FAIL: TestBuild_ReproducibleAcrossDirectories
    same source produced different runtime artifacts:
      e0e88c65b875367e6e959eee0223c275d2790f51837302a47446ad24bd5fba84
      642c707858b59eeee31ebc0a88e64032fa1257e2e1143152da8f2e48fb8c04d4
    same source produced different creation bytecode
--- FAIL: TestEVMEvaluator_StrictResultDecoding
    boolean_two: allowed=true reason=0 err=<nil>, want valid=false
    boolean_high_bits: allowed=true reason=0 err=<nil>, want valid=false
    reason_overflows_uint16: allowed=false reason=1 err=<nil>, want valid=false
    reason_high_bits: allowed=false reason=0 err=<nil>, want valid=false
    allow_with_denial_reason: allowed=true reason=2 err=<nil>, want valid=false
    deny_with_success_reason: allowed=false reason=0 err=<nil>, want valid=false
    unknown_reason: allowed=false reason=4 err=<nil>, want valid=false
FAIL privacy-proxy/internal/policydsl 2.341s
```

This is an excerpt of the failing assertions, with repetition and source-line
prefixes omitted. Additional failures showed valid calls incorrectly denied
after arrays and a signer constraint applied to an array element.

The ABI fixtures use go-ethereum's real ABI encoder, independent of the policy
offset calculation, and assert intended allow/deny outcomes for both the Go
oracle and compiled Solidity. They include static arrays, nested arrays,
tuples containing arrays, dynamic tuples, fixed arrays of dynamic values,
fully static signatures, unconstrained composite inputs and truncated heads.

The result-decoding fixtures execute handwritten EVM bytecode returning chosen
ABI words. They cover canonical decisions, malformed booleans, integer
overflow/high bits, inconsistent allow/reason pairs, unknown reasons and
short/trailing return data. They do not rely on the generator to create bad
results.

## Fix and green

- `validate.go` calculates complete ABI head widths and scalar byte offsets,
  including recursive static arrays/tuples. Arithmetic rejects overflow before
  offsets can wrap. Dynamic values retain their single head-offset word.
- `evaluate.go` and `generate.go` use those prepared offsets; complete head
  lengths also protect unconstrained rules and truncated calldata.
- `compile.go` passes the temporary directory as solc's `--base-path`, leaving
  stable source-unit names in metadata. Identical builds in different temporary
  roots now produce the same runtime and creation bytes/digests.
- `evm.go` accepts only canonical Boolean/uint16 words and consistent known
  decision codes. Malformed results become denials.

The original regression command passed after the fixes:

```text
ok  privacy-proxy/internal/policydsl 2.643s
```

The full package, including its existing Go/Solidity conformance corpus, passed
with the race detector:

```sh
go test -race ./internal/policydsl -count=1
```

```text
ok  privacy-proxy/internal/policydsl 3.832s
```

`gofmt` and `git diff --check` passed. This local run proves reproducibility
across build directories on the installed compiler/platform; cross-image
reproduction remains part of stack/compiler-image verification.

## Review boundary

Self-review checked scalar bounds, signedness/width handling, unknown decisions,
unchanged external ABI and compiler path compatibility. The full package
passed after the changes. Independent review is requested before integrating
this slice; its outcome should be appended here by the integrating reviewer.

No request-path access/visibility logic changed. The reusable package remains
an authoring/compiler/offline-oracle component until the node integration is
implemented and separately tested.

## Runtime size follow-up

An oversized compiled artifact could pass draft creation and then invalidate
the node's complete organization snapshot. `Build` now rejects runtime bytecode
above 24,576 bytes, matching node artifact validation; activation independently
checks the stored size. `TestBuildRejectsRuntimeLargerThanNodeLimit` uses a
controlled executable compiler fixture returning 24,577 bytes. It failed with
an accepted artifact (0.967s), then passed after the build boundary check
(0.735s). The complete compiler race selection, including A5, passes (25.334s).
