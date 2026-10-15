The review found three additional faults after the initial sender/cache fixes: a timed-out HTTP connection could crash the launcher on its next use; retrying a mined transaction could count it twice; and a 2,000-slot sender could launch 40,000 individual RPC requests because it counted batches.

| Check | Result |
|---|---|
| Transaction and callback identity | Sender regression reproduced the wrong nonce before copying the outer batch buffers. Fixed tests and race checks pass. |
| Nonce recovery | Consumed nonces cannot be recycled by late callbacks. Resynchronization preserves unmined gaps. An ambiguous send is considered successful only when the exact transaction has a receipt. |
| Real request limit | Privacy batches reserve one slot per individual RPC. Producers wait for capacity without polling; Stop cancels that wait. Native JSON-RPC batches retain their one-request cost. |
| Stop and Reset | Cancellation precedes draining workers and callbacks. A slow worker cannot expose Reset or a new test while it still writes shared state. Initialization and verification are cancellable. |
| Launcher recovery | Timed-out connections are discarded. A failed Engine mutation is not automatically replayed. Reset reads the canonical head before restarting the block driver. The dashboard survives driver errors. |
| Approval storage | Mined transactions release cached approvals promptly; queued transactions retain theirs. Obsolete timers are removed. Capacity stays at 100,000. |
| Authorization | OPS still checks its real DB-backed permissions. Reth still enforces signed execution fingerprints. PostgreSQL durability and audit persistence remain enabled. |
| Measurements | Browser comparisons verify unique hashes against actual Reth receipts. Receipt requests run in read-only batches after measurement; saved receipts use gzip to reduce disk use. Screenshots come from the native Gasstorm UI. |

Exact confirmation deduplication retains hashes for the current load test and clears them on reset. Its memory cost grows with test length in the load generator, outside Reth.

The earlier screenshots with nonce gaps, inflated counters or interrupted runs are retained as diagnostics. They do not establish maximum sustainable TPS. The final results and browser timings belong in [the brief report](STABILITY-REPORT.md).
