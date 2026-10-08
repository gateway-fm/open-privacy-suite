# Signed approvals: release review, 29 September 2026

Scope: OPS V1 signed approvals, its Besu plugin and custom Reth producer, rebased onto
`origin/main` at `6ebc3b77b0f83770f894f3c93715bd088719e835`. This does not incorporate the OPS V2
policy runtime. The supported source and release instructions are under
[`node-approvals/`](../../node-approvals/README.md); fixtures and historical measurements stay in
`poc/`. No approval persistence or synchronous storage step was added.

This is an implementation/security review with local validation, not an independent penetration
test or certification of a production deployment. Publication follows passing compatibility CI;
deployment qualification follows the [operator guide](../../node-approvals/OPERATIONS.md).

## Alignment with main

| Principle on main | Approval integration |
|---|---|
| Fully configured constructors (RD-1259) | Approval service and preflight limiter are built before `NewJSONRPCProcessor` and passed through `JSONRPCProcessorConfig`. Production setter-style setup was removed. Failed initialization closes the newly created service. |
| Shared middleware and API models | Uses `internal/server/middleware` concurrency/circuit-breaker facilities and shared rate-limit message. OpenAPI remains generated from `internal/apimodels`; regeneration produces no additional schema drift. |
| Role-separated audit access and config boundaries | Uses the existing access-log writer and refusal auditing. No new SQL store, migration, config→audit→DB dependency or application-role audit write was introduced. |
| Cache generation guards and shared policy/visibility rules | The approval branch consumes main's access controller and prepared-trace validation. Global blocks precede policy/cache lookup. Approval issuance follows RBAC, trace policy, compliance and visibility validation; public reads retain main's filtering. |
| Small node-specific adapters | Go owns policy and asynchronous delivery; Java/Rust own provisional execution and veto. The `.proto`, signed domains and common vectors define the boundary. Node observations are trusted execution facts; Go recomputes fingerprints and validates the signed transaction's root frame. |
| Bounded work and isolation of expensive tasks | Signing/delivery are asynchronous. Verification runs on dedicated workers; queues, stores, messages, streams and connections are bounded. Preflight is subject to principal and request-concurrency budgets. |
| Controlled outbound destinations | Producer/node URLs are operator configuration. Main's dial-time protections for user-configured webhooks remain intact. Public-address-only webhook rules are not applied to private node endpoints, which legitimately use internal addresses. |
| Supply-chain and version discipline | Separate version, supported-node manifest, locked Rust dependencies, pinned CI actions, JAR classpath check, dependency inventories/checksums and per-node compatibility jobs. Upstream Reth source remains unmodified. |

## Findings fixed in this pass

| Finding | Impact and fix | Regression evidence |
|---|---|---|
| Private `ops_prepareApproval` namespace could pass broad method grants | Exposes execution/state facts and bypasses the dedicated preflight budget. Reserve all `ops_` methods in the global blocklist before policy lookup. Private internal node preflight remains available. | RBAC tests cover anonymous/named principals and case variants; common HTTP/WebSocket processor test uses wildcard and explicit grants, asserts opaque 404, audited refusal and zero upstream requests. |
| Chain-id truncation | `Uint64()` accepted a larger signed chain id by truncation. Reject non-uint64 ids before preflight or signing. | A signed transaction with chain id `2^64 + 31337` is rejected without any node call. |
| Besu verification executor had an unbounded queue | Stream limits do not bound work left behind by canceled/reset streams. Use a bounded 128-batch verification queue, keep lightweight RPC dispatch/status responsive, and return retryable `UNAVAILABLE` on saturation. | A real-gRPC test blocks the worker, fills the queue, observes retryable refusal and a responsive Status call, releases it, and verifies recovery. |
| Reth silently disabled its gate for malformed `OPS_APPROVALS` | Values such as `true` looked plausible but disabled enforcement. Accept only `1` or explicit `0`; invalid values fail startup (absence also fails startup, see the next row). | Parser regression covers valid/invalid values; real-node negative scenarios verify enforcement. |
| Reth ran without enforcement when `OPS_APPROVALS` was absent (amendment after this review; the 29 September evidence predates it and the binary needs re-qualification) | A deployment template that omitted the variable would silently build blocks without enforcement: OPS still refused its own submissions with `503` once no compatible producer was ready, but transactions sent straight to the node were included. The variable is now required when starting the node: absence refuses startup, `0` remains available for benchmark baselines and logs a startup warning, and maintenance commands do not need it. Besu's equivalent condition is documented: keep `--plugin-continue-on-error` at its default `false`. The operator limits of producer enforcement are listed in one place in the operations guide. | Unit tests cover explicit, missing and malformed values; the real-node scenario `node_refuses_to_start_without_enable_flag` starts the binary without the variable and expects a refusal; all repository launchers already set the variable explicitly. |
| High-volume success/timing diagnostics were enabled normally | Routine traffic could create unnecessary log work and storage volume. Gate success/wait/timing diagnostics behind `OPS_APPROVAL_DIAGNOSTICS=1`; fixtures explicitly enable them. Deny/drop records remain available. | Existing scenario logs still validate decisions; normal receiver monitoring uses counters. |
| Reth receiver statistics depended on block diagnostic output | Operators lacked a standard scrape path during idle periods. Export bounded store/counter metrics through Reth's existing metrics recorder once per second. | Real-node test scrapes `ops_approval_verified_total` from the standard metrics endpoint. |
| Advisory-fixed Rust patch versions were missing from the lockfile | Updated h2 to 0.4.16 (empty-DATA memory growth), quinn-proto to 0.11.15 (reassembly exhaustion), rustls to 0.23.45 (encryption-level checking), lru 0.18 to 0.18.2, and imbl to 7.0.2/chunks 0.2.0 (panic safety; removes bitmaps). | Locked build/tests and repeat advisory scan; see dependency review below. |

The unbounded-queue finding is based on the executor's storage behavior and a saturation test;
this review does not claim a demonstrated remote exploit through an independently firewalled port.

## Attack surfaces and trust assumptions

| Surface | Review result / boundary |
|---|---|
| Authorization bypass and tenant data | The private RPC namespace is now denied unconditionally. Existing raw-transaction checks validate nested calls, delegatecall storage context, deployment/lifecycle operations and caught failures. Cross-org HTTP and producer-divergence scenarios verify denial without nonce, fee or state commitment. |
| Signature forgery, malformed frames and replay | Ed25519 binds key id, issued/expiry times, chain, transaction hash and fingerprint domains. Receivers reject malformed/trailing data, wrong keys/signatures/chains and bad lifetime before atomic insertion. Replays of valid batches are intentionally idempotent, not a revocation mechanism. Transaction nonce and hash binding prevent reuse for another signed transaction. |
| Time of check vs execution | Producer execution is provisional and its result commits only after fingerprint/expiry checks. Calls V3 intentionally permits storage/output/log changes with the same approved call behavior; lifecycle operations use strict V2. Imported blocks are outside producer enforcement. |
| Resource exhaustion | Principal preflight limiting, request concurrency, delivery backoff, bounded retention/verification, message caps, source lists, connection/stream caps and preface/idle timeouts limit work. A reachable malicious permitted peer can still consume its budget; network isolation and deployment RPC limits remain required. |
| API/error/metrics leakage | Public private-RPC denials are opaque and audited; upstream preflight errors use a generic client message. Dynamic transaction/principal values are not added as metric labels. Decision logs and node/metrics endpoints remain private operational data. |
| SQL/command injection, SSRF, secret access | The feature adds no public command-execution or arbitrary-destination API and no approval SQL persistence. Endpoint/seed paths are operator-only configuration. Network peers cannot supply seed paths or delivery destinations through the wire contract. Existing auth, SQL and webhook protections on main remain in place. |
| Transport and malicious node | Plaintext delivery does not authenticate Status or provide confidentiality. Signatures do not stop suppression/replay/DoS. The configured execution node's simulation facts are trusted. Do not cross an untrusted network without authenticated transport. |
| Policy changes and compromised keys | Already issued approvals remain usable until expiry/eviction/finality; removing a key alone does not revoke stored approvals. The operator guide describes isolated rotation and emergency producer restart. Shorter TTL trades recovery against exposure; no new revocation promise is made. |
| Availability/recovery | Memory-only retention can lose queued/undelivered approvals on OPS loss, or confirmed approvals after successive OPS/producer restarts. Surviving OPS replay is capacity/lifetime bounded. Client receipt checking and fresh-policy resubmission are required when all copies are gone. |

## Dependency review

Go `govulncheck` v1.5.0 scanned with the actual Go 1.26.6 toolchain: no reachable or imported-package
vulnerabilities. It reports the unused `golang.org/x/crypto/openpgp` maintenance/design advisory
[GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) at module level.

The verifier follow-up makes Besu's existing Bouncy Castle 1.84 an explicit compile dependency.
OSV now scans **66** resolved Besu compile/runtime coordinates and reports two advisories in
that library: [X.509 name-constraint bypass](https://github.com/advisories/GHSA-9pwp-9qqc-pr26)
and [lazy ASN.1 parsing recursion](https://github.com/advisories/GHSA-qp49-qgx5-5m26), both fixed
upstream in 1.85. Source review of the [name-constraint fix](https://github.com/bcgit/bc-java/commit/2c28b25)
and [ASN.1 fix](https://github.com/bcgit/bc-java/commit/77454da) found neither path reachable
from `ApprovalVerifier`: its direct `math.ec.rfc8032.Ed25519.verify` call consumes a raw
32-byte key, 64-byte signature and bounded message. That implementation uses byte decoding,
curve arithmetic and SHA-512; it does not invoke certificate validation or ASN.1 parsing.
The plugin registers no global security provider and bundles no copy of Bouncy Castle.
These two exact-version exceptions are recorded with a deadline in the review file below.
This is a narrow source-based assessment of the approval API, **not clearance of other Besu
certificate, TLS or ASN.1 uses**. Updating the host library requires a supported Besu version
and renewed compatibility checks; adding another copy to the plugin would not update Besu's
parent classloader. The initial scan previously covered 65 coordinates and had no findings.

The corrected Rust lockfile has 854 registry packages; its remaining notices are explicitly recorded in
[`advisory-review.json`](../../node-approvals/advisory-review.json), with a recheck deadline.
Four are upstream maintenance notices. The remaining
[LRU advisory](https://rustsec.org/advisories/RUSTSEC-2026-0253.html) requires a panicking key
destructor: the pinned alloy-provider 2.3.0 caches use `u64` or `B256` keys, which have none.
That is a source-based reachability assessment, not a claim that every use of lru 0.16.4 is safe.
The other LRU dependency is fixed. New advisories, changed versions or an expired review fail CI.

### Advisory follow-up, 8 October 2026

Reth's locked Hickory resolver, network and protocol crates are updated from 0.26.1 to
**0.26.2** together; the resolver's fixed APIs require the matching companion crates. This fixes
the reported [DNSSEC validation failure](https://github.com/advisories/GHSA-5j98-2g5x-46v6),
[irrelevant CNAME following](https://github.com/advisories/GHSA-6f2x-v7q7-m7m5) and
[truncated-response retry loop](https://github.com/advisories/GHSA-6w6g-hm98-mhgm).
The pinned Reth source and its APIs remain unchanged. No exception is added for Hickory.

The Besu scan also reports two advisories in the host-provided Jackson Core **2.21.5**:

| Finding | Scope of this review |
| --- | --- |
| [Unbounded malformed-token error message](https://github.com/advisories/GHSA-7hhh-6rmp-j9qf) | Requires `JsonFactory.createParser(DataInput)`. Pinned Besu's IPC parser uses an `InputStream`; its HTTP parser uses Vert.x buffer decoding. The approval plugin receives parsed parameters and does not create a Jackson parser. |
| [Quadratic numeric-string conversion](https://github.com/advisories/GHSA-p6pp-m3f8-5c89) | Requires `NumberInput.looksLikeValidNumber()`, including floating-point coercion of string values. `ops_prepareApproval` accepts exactly one raw-transaction string, reads `getParams()` without typed numeric conversion, and decodes hex/RLP. It performs no floating-point conversion. |

Source evidence: pinned Besu's
[`JsonRpcParserHandler`](https://github.com/besu-eth/besu/blob/26.8.1/ethereum/api/src/main/java/org/hyperledger/besu/ethereum/api/handlers/JsonRpcParserHandler.java),
[`JsonRpcObjectExecutor`](https://github.com/besu-eth/besu/blob/26.8.1/ethereum/api/src/main/java/org/hyperledger/besu/ethereum/api/handlers/JsonRpcObjectExecutor.java)
and [`JsonRpcRequest`](https://github.com/besu-eth/besu/blob/26.8.1/ethereum/api/src/main/java/org/hyperledger/besu/ethereum/api/jsonrpc/internal/JsonRpcRequest.java),
plus the plugin's [`PrepareApprovalRpc`](../../node-approvals/besu/src/main/java/ops/approvals/PrepareApprovalRpc.java)
and [`CanonicalJson`](../../node-approvals/besu/src/main/java/ops/approvals/CanonicalJson.java).
Approval delivery uses bounded protobuf; fingerprint JSON uses the handwritten output encoder.
The plugin has no Jackson parser or numeric coercion calls and its verified thin JAR contains
no Jackson classes. Two exact-version exceptions are recorded with the existing review deadline.
The gate also checks Besu's version, Maven coordinates and archive checksum against the review:
changing the host invalidates its exceptions even when the Jackson version stays the same.

These exceptions cover the approval extension's ingress and RPC only. **They do not clear other
Besu methods, plugins or host uses of Jackson.** Upstream fixes are available in Jackson 2.21.7;
updating the plugin's compile classpath or bundling another copy would leave Besu's parent-first
runtime unchanged. A host upgrade requires its own supported distribution and compatibility
qualification. Reassess these exceptions whenever the host version, RPC parsing, parameter
conversion or serialization changes. Changed versions, new findings and expired reviews still
fail the advisory gate.

A broader `npm audit` of the frontend on this same date reports **48 affected package entries**
(2 critical, 19 high, 25 moderate, 2 low); `--omit=dev` reports **29** (7 high, 21 moderate,
1 low). These counts include transitive propagation and are not counts of demonstrated exploits.
Both frontend package files are identical to the reviewed main baseline. The critical entries
are Vitest/coverage development tooling; production-tree findings include router redirects,
wallet dependencies and CSS tooling. They require a separate frontend dependency/reachability
review and are **not cleared by this approval review**. The native approval bundles contain no
frontend dependencies. An approval candidate passing its own gates does not establish that a
complete OPS application release has a clean dependency audit.

The separate Java transport benchmark had resolved Netty 4.1.130 instead of the documented
Besu runtime version. It now enforces the same 4.2.17 BOM as the plugin. Its rebuilt 36-coordinate
tree has no OSV findings; the Rust authentication benchmark's 52 registry packages also have none.
These fixture fixes do not change the provenance of historical performance measurements.

The scans cover resolved coordinates/registry packages and Go call reachability as described.
They are not scans of the entire Besu distribution, optional third-party plugins, OS images,
native libraries or deployment infrastructure. Upstream clients and deployment images also need
their normal security maintenance.

## Validation record

The [Besu verifier follow-up](../../poc/approval-performance/BESU-VERIFIER-2026-09-29.md)
records the subsequent switch to the host's Bouncy Castle Ed25519 implementation. Its
local checks passed 105 Java tests (including 151 Wycheproof cases), all 26 real-Besu
scenario checks and all four OPS HTTP checks. Thin-JAR checks confirm that the dependency
is provided by Besu. The change keeps immediate sending, two verification workers and
eight outstanding delivery calls. Its dependency review is included above.

Local validation uses disposable databases and loopback-only nodes on an Apple M2 Max, macOS
26.6.1. The unrelated workspace and its services are not test targets. Compact final results are
recorded in [compact evidence](evidence/approvals-release-2026-09-29.json); raw logs remain local. The compatibility workflow supplies the Linux
build/runtime gate. Standard Linux-only repository E2E lanes remain required in main CI; the
macOS pre-push hook explicitly skips those unsupported harness lanes.

Production qualification still needs the actual network/secret controls, clock configuration,
exact consensus/node/fork/plugin combination, alert routing and shutdown/retry behavior on the
deployment hardware. These are environment checks, not a requirement for 5,000 TPS on a laptop.

The accepted full-stack comparison measured Reth **2,639 TPS without / 1,962 with approvals** and
Besu **2,298 / 1,296**, on the same 12-core, 32-GiB M2 Max. These 25 September measurements predate
this rebase/hardening and are **not limits of the solution**. See the
[measurement report](../../poc/approval-performance/README.md) for overload latency and receipt data.
