**Calls V3 is the default. Shared-counter writes now work when the call tree and inputs stay the same.** [Full results and caveats](CALL-HASH.md).

```sh
cd "$(git rev-parse --show-toplevel)"
bash poc/reth-signed-approvals/gasstorm.sh ui
```

Open **http://127.0.0.1:18000/load-test/** after `READY`. Docker required; org/group, ten wallets, permissions and contracts are configured automatically. [UI settings](GASSTORM-UI.md). Terminal lifecycle demo: `bash poc/reth-signed-approvals/demo.sh lifecycle`.

| What runs | Details |
|---|---|
| Real stack | OPS HTTP server, PostgreSQL, Redis, custom Reth; real DB rules, signatures, EVM and receipts |
| Fixtures | Test identities, wallets/contracts, development login and Engine API block scheduling; no indexer |
| Enforcement | One provisional execution, fingerprint check before commit; async signing/delivery over persistent TCP |

| Current test | Result |
|---|---|
| 64 writes approved against the same shared-counter state | All 64 execute with calls V3; only 1 with strict V2. All 64 also pass through real OPS. |
| Shared token balances / nested counters | 64 transfers and 32 three-call transactions pass. |
| Changed call inputs/code or cross-org redirection | Rejected without committing nonce, fees or application writes. |
| ETH transfers, CREATE/CREATE2, SELFDESTRUCT | Supported; lifecycle operations retain strict V2. 35 node and 12 OPS lifecycle scenarios pass. |
| Validation | 19 call-hash node scenarios; 18 Rust tests; Go approval/RBAC/tracer race checks pass. |
| Gasstorm Storage Write | 25,368 confirmed, zero submission errors, 85 without a receipt at the final check. [Native screenshot](evidence/gasstorm-ui/stability/call-hash-ui/browser/storage-write.png). |
| Consecutive Gasstorm runs | A later ERC20 run exposed nonce collisions with old queued transactions: 1,652 submission failures / 26,302 generated. [Open issue](REPEATED-RUN-FAILURES.md). |

| Reth processing time per transaction | Module off | Strict V2 | Calls V3 |
|---|---:|---:|---:|
| One storage write | 11.71 µs | 14.50 µs | 12.91 µs |
| Three calls | 13.81 µs | 19.67 µs | 16.59 µs |
| Eighteen calls | 69.69 µs | 101.65 µs | 83.59 µs |

M2 Max; medians of 9 blocks per mode/workload, 32 transactions/block. Includes execution and state/receipt roots; excludes OPS preflight, approval verification/delivery and import. All 27 compared block triples match. This is not whole-stack TPS. [Raw measurements](evidence/call-hash/benchmark/comparison.json).

**Limits:** identical calls can still produce different internal accounting, outputs and logs. Changing nested arguments/branches still causes rejection; no parameter masks or business predicates. Deployment/destruction can still hit strict state conflicts. Enforcement is producer-only; protected legacy/EIP-1559 transactions only. [Review](CALL-HASH-REVIEW.md).
