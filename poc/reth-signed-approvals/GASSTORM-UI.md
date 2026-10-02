```sh
cd "$(git rev-parse --show-toplevel)"
bash poc/reth-signed-approvals/gasstorm.sh ui
```

Open **http://127.0.0.1:18000/load-test/** when the command prints `READY`.

Select **Through Privacy Proxy → Adaptive → Start Test**. Leave **JWT empty**, **Gasless off** and **Fix nonce gaps off**. Choose **ETH Transfer** or **ERC20 Approve** to compare processing performance. Login, ten funded wallets, org/group permissions and contract deployment are automatic.

| Adaptive setting used for screenshots | Value |
|---|---:|
| Initial rate | 500 tx/s |
| Step | 50 tx/s |
| Target pending | 2,000 |
| Duration | 120 seconds |

Stop with **Ctrl+C**. For the comparison without enforcement, start a fresh session:

```sh
bash poc/reth-signed-approvals/gasstorm.sh ui --without-fix
```

| Detail | Behaviour |
|---|---|
| Requirements | Docker running, built PoC Reth, Go, Python, `cast`, `solc`, sibling Gasstorm/loadgenerator. Dashboard build is cached after first launch. |
| Isolation | Each launch starts a fresh chain and DBs. Ctrl+C removes its containers and stops its processes. Logs/history remain in the printed evidence directory. |
| Capacity configuration | One-second blocks, 200M gas/block; override with `--gas-limit`. `--port` changes the UI port. |
| Real node queue | [Live Reth pending/queued counts](http://127.0.0.1:18000/poc/status); saved every second in `ui-pool.jsonl`. Gasstorm's pending counter is its own outstanding-work count. |
| UI scope | Load Test and History work. L1/L2 connection lights refer to absent WebSocket feeds; block confirmations arrive through OPS polling. OPS hides block gas usage, so gas/fill charts show zero. |
| Approval mode | Default `calls`: shared storage may change; calls and their full inputs must match. Set `OPS_APPROVAL_HASH_MODE=strict` before launching for the old comparison. Lifecycle operations always retain strict checking. [Details](CALL-HASH.md). |
| Workload limits | Changing internal arguments or call structure can still block transactions. Mixed workloads are disabled in this ten-wallet fixture. |

For **Storage Write**, the new calls V3 run confirmed 25,368 transactions with zero submission errors and 85 without a receipt at the final check. [Native screenshot](evidence/gasstorm-ui/stability/call-hash-ui/browser/storage-write.png). This is a functional check, not a maximum-TPS measurement.

**Open issue with consecutive runs:** old queued transactions can collide with new nonce allocations on the same wallets. A later ERC20 run recorded 1,652 submission failures. Resetting the UI does not clear Reth’s pool. [Investigation and current workaround](REPEATED-RUN-FAILURES.md).

The [historical strict V2 stability report](STABILITY-REPORT.md) contains the replacement Adaptive screenshots, verified transaction counts and Stop/Reset checks at requested rates of 2,000 and 6,000 TPS. Earlier broken-run screenshots are superseded.

The launcher automatically builds isolated, patched copies of Gasstorm and the load generator. No edits to the sibling repositories or manual configuration are needed.
