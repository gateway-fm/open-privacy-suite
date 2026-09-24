Historical strict V2 investigation. Shared-counter behavior has since changed; see [current results and caveats](CALL-HASH.md).

Completed: [results](GASSTORM.md), [review](GASSTORM-REVIEW.md), [reproducibility manifest](evidence/gasstorm/final/manifest.json).

| Step | Acceptance |
|---|---|
| Research | Gasstorm local main includes privacy routing fixes. Its bundled stack uses op-reth/blockbuilder and builds the main OPS checkout, not this PoC. Use its actual sibling Go loadgenerator against the isolated PoC stack. |
| Critique | Keep the same binaries, genesis, DB/RBAC setup, block schedule and load settings. Toggle both OPS signed approvals and Reth enforcement. Do not count accepted transaction hashes as successful execution. |
| Correctness | Run the same preflight/route-change scenario in both modes: the old path executes the now-forbidden call; enforcement excludes it with no user nonce, fee or application writes committed. |
| Configuration | Real OPS HTTP, PostgreSQL and Redis. One test DID, one group, ten funded/signature-linked test wallets, deploy claim and registered/granted contracts. Route all loadgenerator RPC through OPS. Local nonce reservation remains enabled. |
| Measurement | Headless loadgenerator HTTP API. Warm up, then measure repeated fixed-rate runs; save history, receipts and Reth producer timings. Report failures and backlog alongside throughput. |
| Contention | Fingerprints can become stale during legitimate writes too. Separate that behavior from execution overhead; do not silently count stale approvals as successful transactions. |
| Review | Verify actual mined receipts independently, record source/binary revisions and configuration, retain failure evidence, clean up only the isolated test services. |

The block scheduler is a local Engine API driver; it does not replace EVM execution or OPS policy checks. No UI, indexer, external identity provider or production capacity claim is required for this comparison.

The shared-counter test confirmed the anticipated contention problem: 97 of 98 protected transactions remained pending after the first changed the approved storage. This investigation measures and reports that limitation; it does not add automatic retries or weaken the fingerprint.
