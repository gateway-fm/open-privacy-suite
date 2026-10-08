Completed in the existing `poc/ops-reth-signed-approvals` worktree. [Review, test evidence and benchmark](EXTENSION-REVIEW.md).

| Stage | Work / acceptance |
|---|---|
| Plan | Extend the existing producer check to ETH value, CREATE/CREATE2 and SELFDESTRUCT; keep async approvals and standard Ethereum RPC. |
| Critique | Resolve fee normalization, deployment nonce handling, identical policy/signature traces, reverted operations and fork-dependent destruction before implementing. Findings below. |
| TDD | Record failing tests first. Then implement Go/Rust fingerprint V2 and OPS integration. Test allowed operations and state changes that must exclude the whole transaction. |
| Review | Inspect security boundaries and compatibility; run Go race tests, Rust tests/lints, real OPS/PostgreSQL/Reth regressions and a small performance comparison. Update the brief demo and retain evidence. |

| Guarantee | Implementation and tests |
|---|---|
| ETH effects match approval | Include value on every call and application balance deltas, including recipient accounts without code. Remove only actual protocol fees from the execution comparison. Cover sender = beneficiary, internal transfers and caught reverts. |
| Creation effects match approval | Include CREATE/CREATE2 inputs, destination, output code, initial storage and contract nonces; support payable and nested creation. Use the signed transaction nonce in preflight, including queued deployments. |
| OPS authorizes the signed execution | Feed the same prepared trace and pinned code hashes to deployment/RBAC validation. Preserve deploy claims, constructor cross-org checks and org registration. |
| Destruction effects match approval | Include SELFDESTRUCT beneficiary/value and resulting account code/storage/balance effects. Test existing accounts and create-and-destroy, same beneficiary, and reverted parents. |
| No unsafe version fallback | Domain-separate V2 fingerprints. V1 approvals cannot authorize V2 execution. |
| Existing behavior remains usable | Retain batching, late-approval waiting, nonblocking independent senders and direct encoding; rerun existing regressions. |

Critique findings:

1. Pinning every sender balance/nonce would invalidate later queued approvals just because earlier transactions paid gas. Compare application balance deltas; continue binding the exact signed transaction. Contract nonces and touched storage remain checked.
2. This pinned Reth's `debug_traceCall` disables protocol fee charging and discards the request nonce. Normalize actual execution fees and supply a sender nonce state override to both preflight traces. No extra node-to-OPS calls.
3. The existing deployment path performs another trace at `latest`. Reuse the prepared trace; otherwise OPS could authorize a different constructor execution from the one it signs.
4. Trace CREATE flags must be populated for the deploy-claim gate. Value recipients and SELFDESTRUCT beneficiaries must remain visible to OPS policy checks. Newly created contracts called in the same transaction need ownership handling without trusting an unrelated address.
5. SELFDESTRUCT does not always delete an account. Follow actual EVM results, testing both Shanghai and Cancun, including reverted and temporary contracts. [EIP-6780](https://eips.ethereum.org/EIPS/eip-6780), [EIP-161](https://eips.ethereum.org/EIPS/eip-161).

The existing producer-only enforcement boundary remains: this work does not turn approvals into a network consensus rule or change policy revocation semantics. Protocol gas amounts and every environmental opcode read are not independently pinned; their effects on the compared execution remain checked.
