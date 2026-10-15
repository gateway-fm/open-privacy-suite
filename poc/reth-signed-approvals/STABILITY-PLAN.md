Repair the interactive Gasstorm test path before collecting replacement performance evidence.

| Step | Verification |
|---|---|
| Preserve and reproduce | Keep previous failures; inspect a constant 2,000 TPS ETH run while it is running. Collect process stacks, real node queue, receipt counts and RPC errors. |
| Sender ownership | Apply the independently reproduced batch-buffer fix in an isolated loadgenerator checkout. Keep red/green tests, including callback identity and cancellation. |
| Diagnose overload | Separate node execution, request admission, socket churn and approval-store capacity. Fix measured causes; do not merely raise timeouts or bypass enforcement. |
| Control lifecycle | Stop must cancel sending promptly. Reset must not race outstanding callbacks. A driver failure must leave the UI reachable with an explicit error. |
| Review and proof | Test through the actual browser: constant 2K, Stop, Reset, another run, and Adaptive. Compare off/on with identical final settings. Save Gasstorm screenshots with the relevant chart visible and raw results. |

Critique: nonce gaps and approval timeouts invalidate the previous capacity claims. Merely showing a different plot, lowering offered load, increasing approval capacity, or restarting a crashed stack does not repair the underlying behavior. Preserve the user's UI configuration, record actual successful throughput and distinguish overload from a broken test runner.
