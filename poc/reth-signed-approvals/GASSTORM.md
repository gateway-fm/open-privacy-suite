**Shared-counter writes now pass with calls V3, the default.** The call tree and full inputs must still match; ordinary storage changes are allowed.

| Current check | Result |
|---|---|
| 64 approvals against one shared-counter state | Calls V3: 64 execute; strict V2: 1. Real OPS HTTP also confirms all 64. |
| Gasstorm browser Storage Write, 30 seconds | 25,368 confirmed; zero submission errors; 85 without receipts at the final check. [Native screenshot](evidence/gasstorm-ui/stability/call-hash-ui/browser/storage-write.png). |
| Consecutive runs using the same wallets | Open nonce-handling issue: later ERC20 run has 1,652 submission failures / 26,302 generated. [Investigation](REPEATED-RUN-FAILURES.md). |

The storage run proves shared writes work; it does not establish maximum TPS or reliable repeated runs. Calls V3 does not guarantee identical internal financial results. Changing nested parameters or call branches still causes rejection; deployment/destruction retain strict checking. [Current Reth benchmark and remaining limits](CALL-HASH.md).

**Historical measurements below use strict V2.** Their counter rejection describes the previous behavior, not the calls V3 default.

Ran Gasstorm automatically through real OPS → Reth, with PostgreSQL and Redis. Checked **173,695 successful receipts** across 20 measured runs.

For interactive Adaptive tests: [one-command UI startup](GASSTORM-UI.md).

| Workload / target | Successful TPS, fix off | Fix on | Reth µs/tx, off → on |
|---|---:|---:|---:|
| ETH / 500 TPS | 499.4 | 497.7 | 2.59 → 4.88 |
| ETH / 1,000 TPS | 923.6–992.5 | 987.3–994.3 | 2.53 → 5.61 |
| ERC20 approve / 500 TPS | 498.3 | 498.2 | 7.06 → 10.50 |

Two 20-second runs per mode/rate on M2 Max, with reversed mode order. Values are means except the 1,000-TPS ranges: one baseline wallet stalled with a large nonce backlog, so this is **not evidence of a throughput improvement**. TPS counts successful receipts, including those arriving after sending stops. These are fixed-load measurements, not maximum capacity. Reth time covers selected payload execution and roots, excluding preflight, delivery and import.

**The historical strict V2 contention test showed why the hash needed to change:**

| Correctness test | Fix off | Fix on |
|---|---|---|
| Call redirected into a foreign org after preflight | Incorrectly executes | Excluded; user nonce, fees and application writes unchanged |
| 98 transactions updating one shared counter | 98 complete | **1 completes; 97 remain pending** |

In strict V2, the first counter write made other approvals stale. Calls V3 removes this conflict when only ordinary storage values change; the new 64-transaction test above verifies that separately. The original 98-transaction measurement is preserved. The old ERC20 workload used pre-initialized, idempotent approvals.

| Setup / caveat | Details |
|---|---|
| Permissions | One test DID, ten funded wallets linked with real signatures; org/group, deploy claim, registered/granted contracts |
| Fixtures | Identity-provider login and one-second Engine API block scheduling. No indexer or UI. Enforcement is producer-only. |
| Incomplete submissions | 2,408 logged hashes lacked receipts: 1,600 still in the pool, 808 unknown to the node. Kept separate from successes; zero reported send failures or reverted receipts. |
| Fix found under load | Preflight connection pool now reuses connections: 160 requests opened 152 connections before, 32 after. All 67 integration scenarios and Go race suites pass. |

```sh
cd "$(git rev-parse --show-toplevel)"
bash poc/reth-signed-approvals/gasstorm.sh all
```

This command now uses calls V3 by default; set `OPS_APPROVAL_HASH_MODE=strict` to select the old hash mode.

Requires the built PoC Reth, Docker, Go, Python 3, `cast`, `solc`, and sibling `loadgenerator`. Creates/configures isolated stacks and cleans up. No UI. Local Gasstorm `main` already contains the privacy-routing branch fixes; no switch needed.

[All measurements](evidence/gasstorm/final/comparison.json) · [Versions and hashes](evidence/gasstorm/final/manifest.json) · [Script/branch findings and review](GASSTORM-REVIEW.md) · [Plan](GASSTORM-PLAN.md)
