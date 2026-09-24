**Calls V3 is implemented and is the default for the PoC.** It permits shared-counter and token-balance changes while requiring the approved call tree and inputs to match. CREATE/CREATE2/SELFDESTRUCT retain strict V2 automatically.

| What is checked | Calls V3 |
|---|---|
| Call order and parent; caller, destination, executed code and storage context | Exact |
| Full calldata, ETH value, success/revert status, including caught calls | Exact |
| Ordinary storage values, balances, account nonces, return values and logs | May differ |
| Approval mode | Signed; changing it invalidates the signature. Unknown modes fail closed. |

| Real test | Result |
|---|---|
| 64 transactions approved against one shared-counter state | Strict: 1 executed. Calls: all 64 executed. |
| Same counter test through real OPS HTTP + PostgreSQL + Redis | All 64 executed after concurrent preflights. |
| Shared token balances / nested counters | 64 token transfers and 32 three-call transactions executed successfully. |
| Changed nested arguments, ETH value, call count or bytecode | Rejected without committing the rejected transaction's nonce, fees or writes. |
| Cross-org redirection, including caught failures and read-only calls | Rejected. |
| Deployment/destruction regressions | 35 node scenarios plus 12 OPS HTTP scenarios passed with strict fallback. |

[Node evidence](evidence/call-hash/node-final/tests.json) · [Real OPS evidence](evidence/call-hash/ops/tests.json) · [Lifecycle evidence](evidence/call-hash/lifecycle/tests.json)

Gasstorm’s real browser **Storage Write** run confirmed **25,368 transactions**, with zero submission errors; 85 submitted transactions had no receipt at the final check. The reported confirmations exactly matched unique successful Reth receipts. This 30-second functional run is not a maximum-TPS claim. [Screenshot](evidence/gasstorm-ui/stability/call-hash-ui/browser/storage-write.png) · [Receipt verification](evidence/gasstorm-ui/stability/call-hash-ui/browser/browser-results.json). Reset returned the UI to idle after completion.

| Remaining limit | Practical effect |
|---|---|
| Different financial result inside the same calls | May pass. A test changes an internal increment from 0 to 120 and confirms that calls mode allows it. Storage values, return values and logs are not compared. State-dependent business rules need stricter checks. |
| A changing counter becomes an argument to another call, or changes the call branch | Still blocked: the full call tree and inputs must match. Selectively ignoring parameters is not implemented. |
| CREATE / CREATE2 / SELFDESTRUCT | Supported through automatic strict V2 fallback; their state contention is not relaxed. An unexpected lifecycle operation under a calls approval is rejected. |
| Custom business predicates / policies generated from past transactions | Not implemented. Existing OPS DB access rules still apply. |
| Other producers / imported blocks | Not enforced. This PoC checks transactions while its own producer builds a block. |
| Transaction formats and size | Protected legacy and EIP-1559 only; at most 128 call frames and 1 MiB of canonical data. |

**Separate load-test issue:** consecutive runs on the same wallets can collide with transactions left queued by a previous run. A later ERC20 run recorded 1,652 submission failures out of 26,302 generated transactions. The saved error samples are nonce-replacement failures; the exact error breakdown was not retained. This does not invalidate the isolated counter test, but repeated-run reliability is not yet established. [Investigation](REPEATED-RUN-FAILURES.md).

| Reth workload | Module off | Strict V2 | Calls V3 | Calls overhead vs off |
|---|---:|---:|---:|---:|
| One storage write | 11.71 µs | 14.50 µs | 12.91 µs | +10.2% |
| Three calls | 13.81 µs | 19.67 µs | 16.59 µs | +20.1% |
| Eighteen calls | 69.69 µs | 101.65 µs | 83.59 µs | +19.9% |

Calls mode took **11–18% less processing time than strict mode** in this run. M2 Max; medians of 9 blocks per mode/workload, 32 transactions/block, rotated modes, one warmup per node. Measures Reth execution plus state/receipt roots; excludes OPS preflight, signature verification/delivery and import. All 27 compared block triples matched. This is not whole-stack TPS. [Raw benchmark](evidence/call-hash/benchmark/comparison.json).

Start the UI as usual:

```sh
bash poc/reth-signed-approvals/gasstorm.sh ui
```

For the previous behavior: `OPS_APPROVAL_HASH_MODE=strict bash poc/reth-signed-approvals/gasstorm.sh ui`. `--without-fix` disables enforcement for comparison. Restart both OPS and Reth after updating; an older node rejects V3 approvals.

One provisional EVM execution, existing async signing/delivery, no execution-time network calls. Both preflight traces remain pinned to the same block. Enforcement still applies to this producer, not imported blocks or network consensus.

Validation: 18 Rust tests, Go approval/RBAC/tracer race checks, Python control tests, and the real scenarios above passed. [Plan/critique](CALL-HASH-PLAN.md) · [Review](CALL-HASH-REVIEW.md) · [Source manifest](evidence/call-hash/manifest.json).
