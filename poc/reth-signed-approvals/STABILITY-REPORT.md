These stability comparisons used **strict V2**. Calls V3 now permits shared-counter updates when calls and inputs match; see [current results and caveats](CALL-HASH.md). A later sequence of calls V3 UI runs exposed a separate [nonce-collision issue](REPEATED-RUN-FAILURES.md); the clean runs below do not establish repeated-run reliability.

Fees did **not** cause these failures. The checked wallets still held almost one million ETH each, and the base fee checked after the affected run was 7 wei. Its busiest block used 52.1M gas, below the 100M target. This chain **still charges fees**; Gasstorm's Gasless switch does not change the node's fee rules. [Fee evidence](evidence/gasstorm-ui/stability/header-stop-profile/fee-check.json)

| What broke | What changed |
|---|---|
| The 2,000-request limit counted batches, allowing up to 40,000 individual requests. | Count actual RPC requests; wait for capacity before starting their HTTP timeout. Stop cancels that wait. |
| Reused buffers and nonce recovery could mix up transactions or endlessly retry consumed nonces. | Give the sender its own buffers; preserve genuine nonce gaps and retire consumed nonces. |
| A timed-out HTTP connection was reused and could crash the launcher. | Discard broken connections; monitoring failures preserve the UI. Driver failures are shown explicitly. |
| Stop/Reset could race unfinished workers and callbacks. | Cancel sending and verification, drain outstanding work, then allow Reset and another test. |
| Preflight fetched and compressed an entire block just to read its hash. | Fetch the header; keep both traces pinned to that same hash. |
| Mined approvals occupied the 100,000-entry cache for five minutes. | Remove mined entries promptly; retain approvals still needed by queued transactions. |
| Retried confirmations were counted twice; completed charts lost their first minute. | Deduplicate confirmations and display the full retained chart. |

The final four **120-second Adaptive runs** completed without submission errors. These are real Gasstorm screenshots; every reported confirmation was checked against a unique successful Reth receipt.

| Workload | State check | UI peak TPS / screenshot | Best 30s TPS¹ | Successful receipts | Still unconfirmed² |
|---|---|---:|---:|---:|---:|
| ETH transfer | Off | [2,254](evidence/gasstorm-ui/stability/verified-comparison/eth-transfer-off/browser/eth-transfer.png) | 2,019 | 213,872 | 109 |
| ETH transfer | On | [2,274](evidence/gasstorm-ui/stability/verified-comparison/eth-transfer-on/browser/eth-transfer.png) | 1,970 | 197,001 | 130 |
| ERC20 approve | Off | [2,234](evidence/gasstorm-ui/stability/verified-comparison/erc20-approve-off/browser/erc20-approve.png) | 1,865 | 211,562 | 290 |
| ERC20 approve | On | [1,750](evidence/gasstorm-ui/stability/verified-comparison/erc20-approve-on/browser/erc20-approve.png) | 1,565 | 167,857 | 146 |

¹ Best 30-second window with no net growth in the measured node pool. It can include draining a backlog; it does **not** prove a sustained maximum. These measure the whole local OPS stack, not Reth alone. One run per case, ten wallets, one-second blocks, 200M gas limit. [Raw comparison and configuration](evidence/gasstorm-ui/stability/verified-comparison/comparison.json)

² No receipt at the final check. These transactions are excluded from successful counts. The ERC20-on screenshot has a duration-field display bug showing `0`; the actual run configuration, elapsed time and chart cover 120 seconds. The UI peak uses unsmoothed samples; the plotted line is smoothed over three seconds.

| Browser control test, enforcement on | Result |
|---|---|
| Constant 2,000 TPS offered for 75 seconds | 149,205 confirmed before Stop; zero submission errors. |
| Stop → Reset | 245 ms → 233 ms. |
| Start again on the same stack | 9,967 confirmations in the subsequent 1,000 TPS / 10-second test; zero submission errors. |
| Requested 6,000 TPS for 20 seconds | Sender waited at its request limit: 49,120 sent, 44,756 confirmed before Stop; zero submission errors. This did not achieve 6,000 TPS. |
| Stop → Reset after overload | 247 ms → 241 ms; the next test confirmed 9,898 transactions with zero submission errors. |

[Control timings](evidence/gasstorm-ui/stability/ready-ui/normal/result.json) · [Running screenshot](evidence/gasstorm-ui/stability/ready-ui/normal/constant-2000.png) · [Stopped](evidence/gasstorm-ui/stability/ready-ui/normal/stopped.png) · [Second test](evidence/gasstorm-ui/stability/ready-ui/normal/retest.png)

[Overload timings](evidence/gasstorm-ui/stability/ready-ui/overload/result.json) · [Overload screenshot](evidence/gasstorm-ui/stability/ready-ui/overload/constant-6000.png) · [Second test after overload](evidence/gasstorm-ui/stability/ready-ui/overload/retest.png). Both checks ended with the UI idle and available for another test.

Regression tests, targeted Go race checks, Rust tests and the [real-node cross-organization rejection test](evidence/gasstorm-ui/stability/safety/safety.json) pass. [Review](STABILITY-REVIEW.md). Earlier broken runs remain saved as diagnostics and are superseded by this comparison.

The [normal launch command](GASSTORM-UI.md) automatically applies the saved patches in isolated clones. The sibling repositories and upstream Reth checkout remain unchanged. OPS DB authorization, PostgreSQL durability and signed state enforcement remain enabled. This fixture uses development authentication and a test block driver; it does not run the indexer.
