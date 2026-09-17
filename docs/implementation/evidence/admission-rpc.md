# Node execution admission and OPS JSON-RPC routing

Implementation: `internal/rbac/admission.go`,
`internal/server/jsonrpc_node_policy.go`, and the narrow configuration/dispatch
addition in `internal/server/jsonrpc_processor.go`.

## Boundary

With `JSONRPCProcessorConfig.NodeExecution` configured, raw signed transactions
use the private node submission API. Calls, gas estimates, and call traces use
the private simulation API. Registered method aliases use the same execution
path, with their original method allowlist and a canonical signed simulation
method. No error falls back to the legacy upstream or trace authorization.
An omitted service preserves the existing legacy processor; startup must supply
the service whenever Reth mode is selected.

Admission retains named-user authentication, ban/KYC gates, current organization
selection, method allowlists, linked signer validation, and the historical-state
privacy guard. The same historical guard applies to all simulation methods and
aliases. Contract/function grants, deployment and upgrade claims, fingerprint
checks, and preflight traces do not authorize execution on this path. The node
resolves current execution facts and invokes the compiled policy.

The signed identity carries the stable principal ID separately from its linked
Ethereum signer. Two principals sharing an address remain distinct identities.
A simulation without `from` defaults only when exactly one distinct valid linked
address exists; otherwise it requires an explicit linked address. An explicit
unlinked or malformed sender is rejected. `eth_sendTransaction` returns an
explicit unsupported-method error directing the caller to sign locally and use
`eth_sendRawTransaction`.

The transaction binding is the decoded Ethereum consensus transaction hash,
which excludes pooled blob sidecars. Simulation binding covers the exact
normalized request bytes, including the resolved sender. The service's identity
preparation contract requires the current database fact version and node
readiness before signing; the separately implemented startup bridge fulfills
that contract.

Concurrency admission, existing open circuits, compliance on submitted
transactions, access logging, and `visibleTo` resolution/outbox behavior remain
in place. Private service errors are opaque. The bridge saves an immutable
principal/org/signer-bound submission and visibility intent before transport.
Successful CREATE/CREATE2 ownership and visibility are reconciled atomically
from the node's actual finalized execution evidence. No predicted address or
in-memory receipt watcher is used on this path. Lost ACKs and process restarts
resume observation without automatically resubmitting a deployment. Included
but unfinalized outcomes remain observable and can return to pending on reorg.

## TDD evidence

Initial tests were added before production code:

```text
go test ./internal/rbac -run '^TestExecutionAdmission' -count=1
FAIL: CheckExecutionAdmission undefined

go test ./internal/server -run '^TestNodeExecution' -count=1
FAIL: NodeExecutionIdentityRequest / JSONRPCProcessorConfig.NodeExecution undefined
```

After the first implementation:

```text
go test ./internal/rbac -run '^TestExecutionAdmission' -count=1
ok privacy-proxy/internal/rbac 0.531s

go test ./internal/server -run '^TestNodeExecution' -count=1
ok privacy-proxy/internal/server 3.648s
```

Review found that the existing historical-state helper recognizes `eth_call`
but not gas estimation or call tracing. A regression was added before extending
the new admission path:

```text
go test ./internal/rbac -run '^TestExecutionAdmissionHistoricalGuard' -count=1
FAIL: historical simulation eth_estimateGas admitted
FAIL: historical simulation debug_traceCall admitted
FAIL: historical simulation chain_traceCall admitted
FAIL privacy-proxy/internal/rbac 0.697s

go test ./internal/rbac -run '^TestExecutionAdmission' -count=1
ok privacy-proxy/internal/rbac 0.559s
```

Final targeted race run, including the root-owned identity bridge and existing
processor regression tests:

```text
go test -race ./internal/rbac ./internal/server -run '^(TestExecutionAdmission|TestNodeExecution|TestNodeIdentityBridge|TestNewJSONRPCProcessor|TestJSONRPCProcessor)' -count=1
ok privacy-proxy/internal/rbac 1.769s
ok privacy-proxy/internal/server 4.408s
```

The server test harness created and cleaned its isolated PostgreSQL 15 container.
No shared development database was changed.

## Review coverage

Tests cover transport admission with no legacy execution grants, anonymous and
unknown principals, bans, missing KYC, method rejection, foreign ownership,
unlinked signers, lookup failures, historical simulations, absent/ambiguous
simulation senders, shared-signer principal separation, canonical methods and
aliases, exact simulation binding, stale readiness, node denial, malformed node
results, mismatched submitted hashes, opaque errors, concurrency-slot release,
open circuits, compliance failure, visibility metadata stripping/outbox writes,
and CREATE tracking only after acceptance.

Unexpected legacy authorization/store calls panic in the routing fixture, and
the fixture has no legacy proxy or tracer. Successful tests therefore cannot be
explained by an accidental fallback. Existing non-execution/history paths are
outside the dispatch branch and remain unchanged. Independent security review of
this slice is performed by the integrating parent agent.
