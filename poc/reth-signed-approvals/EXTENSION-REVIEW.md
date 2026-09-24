| Reviewed area | Outcome |
|---|---|
| Enforcement | Same provisional execution is compared before commit. Fee normalization changes the comparison only; committed fees remain real. |
| Native value | Every call's value and application balance deltas are compared, including accounts without code and reverted nested transfers. |
| Fee arithmetic | Sender/beneficiary overlap uses the net fee, avoiding an intermediate uint256 overflow. A new regression failed before this fix. |
| Fee-only accounts | A frame observer distinguishes accounts accessed by execution from the account loaded only for the block reward. This prevents false rejection when the fee recipient is a contract without dropping application accesses. |
| Wallet payouts | The existing root ETH-transfer carve-out also applies to nested CALL/SELFDESTRUCT recipients proven to have no code in the signed snapshot. Foreign registrations still deny access; delegation gets no exemption. |
| Deployment snapshot | Both traces use one block hash and the signed nonce. OPS validates that prepared trace and its code hashes. |
| Creation ownership | A deploy claim, a matching CREATE frame, empty original code/nonce and no foreign owner are required before treating a new address as part of this deployment. Failed collisions cannot grant existing code. |
| Registration | Only surviving creations are registered. Temporary/reverted creations are excluded; approval-queue failure cleans up pre-registration. |
| CALLCODE | Review found the shared-code restriction covered only DELEGATECALL. A failing test now covers CALLCODE too, and the restriction applies to both. |
| SELFDESTRUCT | Compare actual code/storage/balance results, including self-beneficiaries, prefunded deployments, caught reverts and redeployment behavior. [Fork rules](https://eips.ethereum.org/EIPS/eip-6780). |
| No-op destruction trace | Pinned Reth omits addresses on Cancun self-to-self SELFDESTRUCT. Only its exact zero-caller / absent-target / zero-value successful marker is normalized to the parent contract. Other incomplete transfers are rejected. |
| Compatibility | Execution fingerprint V2 has a new hash domain; there is no V1 fallback. Signed envelope batching and standard transaction RPC remain unchanged. |

| Validation | Evidence |
|---|---|
| Tests written before implementation | [Fingerprint failures](evidence/value-lifecycle/red-go.log), [real-node restriction](evidence/value-lifecycle/red-real.log), [ownership failure](evidence/value-lifecycle/red-rbac.log), [wallet payouts](evidence/value-lifecycle/red-wallet-recipient.log) |
| Review regressions before fixes | [Fee arithmetic](evidence/value-lifecycle/red-fees.log), [contract fee recipient](evidence/value-lifecycle/red-beneficiary.log), [CALLCODE](evidence/value-lifecycle/red-callcode.log), [no-op destruction](evidence/value-lifecycle/red-noop-selfdestruct.log) |
| Real-node regressions | [55 passed](evidence/value-lifecycle/regression-final/tests.json), including direct/reference fingerprint equivalence, late approvals, restart and historical import. |
| OPS HTTP stack | [12 passed](evidence/value-lifecycle/ops-final/tests.json) with real PostgreSQL, Redis and Reth; development identities and Engine API scheduling. |
| Go race suites | [Approvals, RBAC and tracer passed](evidence/value-lifecycle/go-tests-final.log). |
| Rust tests / lint | [13 tests passed](evidence/value-lifecycle/rust-tests-final.log); [clippy passed](evidence/value-lifecycle/clippy.log). |
| Build / static review | [Release build passed](evidence/value-lifecycle/build-final.log); formatting, Python compilation, shell syntax and diff checks passed. Upstream Reth remains clean at the pinned commit. |
| Performance | [9 measured blocks per mode/workload, 32 tx/block](evidence/value-lifecycle/benchmark-final/benchmark.json): +26.1% / +38.4% / +26.3% producer time for one write / three calls / eighteen calls. All 27 measured stock/module pairs produced identical block hashes. |
| Reproducibility | [Manifest](evidence/value-lifecycle/manifest.json): commands, pinned versions and source/binary hashes. The [initial smaller run](evidence/value-lifecycle/benchmark/benchmark.json) is retained separately. |

The benchmark includes EVM execution and state/receipt roots, with the same preflight warming in both modes. It excludes preflight, approval delivery/wait and block import. Signature verification still consumes CPU on the receiver thread (about 1.8 µs per approval amortized over 32 in this run). No claim about sustained OPS TPS or zero overhead follows from these measurements.

Existing scope: enforcement is in our producer; imported blocks still use stock execution. Hardfork behavior is validated on Shanghai and Cancun. The comparison covers application effects rather than every environmental read or exact gas expenditure. OPS approvals retain the existing policy-revocation and retry semantics.
