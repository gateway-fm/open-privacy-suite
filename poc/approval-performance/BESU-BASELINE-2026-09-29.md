# What changed between the Besu throughput baselines

The earlier 1,296 TPS result and the later 2,256 TPS baseline did not use the same code
and runtime settings. Calling the latter "old verifier" was accurate about its crypto
implementation but concealed other changes already made to the approval plugin.

**A controlled follow-up identifies normal-path approval logging as a major cause of
the slowdown.** During release hardening, commit `3e365453` put successful-decision,
wait and timing logs behind `OPS_APPROVAL_DIAGNOSTICS=1`, off by default. Previously
`ApprovalSelector` emitted two INFO records for every successful transaction selection,
plus records for waiting transactions. Those calls execute in Besu's block-selection path.
The bundled logger uses a normal Root logger and Console appender; the fixture redirects
stdout to a file. Both formatting and output are part of the logging work.

This change predates the Bouncy Castle verifier replacement. It changes the cost of
approval handling while preserving the approval checks, store, wire format and immediate
sender batching. Deny/drop logs and metrics remain enabled.

## Controlled logging comparison

Both runs below use the **same original JDK verifier JAR**, same actual OPS binary,
same 256-connection HTTP cap, two verification workers, eight outstanding approval
calls and no policy/crypto bypass. Only `OPS_APPROVAL_DIAGNOSTICS` changes. Each uses a
fresh disposable OPS/PostgreSQL/Redis/Besu stack, ten wallets, requested 5,000 ETH
transfers/sec for 60 seconds, 5,000 allowed OPS requests, nominal one-second blocks,
0.8-second build windows and a 200-million gas limit. Runs are sequential, without
compilation or CPU profiling during load.

| Original JDK verifier | Committed TPS | Transaction p99 | Generator submission failures |
|---|---:|---:|---:|
| Approval success/timing/wait logs enabled | 867.0 | 56.655 s | 58,121 |
| Those logs disabled | 2,163.9 | 3.828 s | 1 |

Removing those logs alone raised committed throughput approximately **2.5 times** in
this pair. The logged run recorded 72,912 success records and 72,912 timing records;
the producer recorded no wait/deny/drop decisions. It still performed signature
verification and delivered approvals. The long delay in this case therefore cannot
be described simply as missing approvals at the producer. The workload also suffered
many submission failures under overload; the table measures canonical successful
transactions, not submitted attempts.

The logs-off result is close to the earlier current-source JDK baseline of 2,255.7 TPS,
and substantially different from the historical logging-on result of 1,296.3 TPS.
This reproduces a large throughput and tail-latency effect by changing logging alone;
it does not reproduce the exact older build and machine state or assign every historical
TPS difference to logging. These are single measurements on a shared Apple M2 Max
(12 cores, 32 GiB, macOS 26.6.1), **not solution limits or production guarantees**.

## Other changes and scope

The newer comparison also used `NODE_HTTP_MAX_CONNS_PER_HOST=256`. That is a fixture
setting for HTTP RPC/preflight traffic to Besu, separate from the single persistent
approval gRPC connection. It limits simultaneous connections; the production default
was not changed. Keeping logging disabled and removing only this cap produced:

| Original verifier, logs disabled | Committed TPS | Generator submission failures |
|---|---:|---:|
| Default unbounded HTTP connections | 1,864.9 | 10,769 |
| HTTP connections capped at 256 | 2,163.9 | 1 |

This independently reproduces a smaller throughput benefit from the cap, with far fewer
submission failures. The earlier diagnostic comparison was 1,843.0 versus 2,341.4 TPS.
The new uncapped case completed; a prior uncapped attempt failed with local port
exhaustion. Unbounded connections do not fail identically on every run. These results
support a deployment-specific connection-setting review, not a claim that 256 is a
universal optimum or that the production default was already fixed.

The intervening rebase also brought changes from main, including permission-query batching,
cache-generation guards and a Go toolchain update. Release hardening bounded the approval
verification executor and moved cheap RPC dispatch/status outside its verification queue.
Those changes are **held constant** in the logging comparison above. Their individual
contributions to the historical September 25 result have not been measured here.

The separate [verifier comparison](BESU-VERIFIER-2026-09-29.md) already had normal-path
logging disabled on both sides. It measured 2,255.7 to 2,323.7 TPS and 197.3 to 2.07 ms
mean signing-to-acknowledgement latency. That small TPS difference cannot be used to
claim that replacing the verifier caused the entire 1,296-to-2,324 historical increase.
Old-verifier delivery latency also varies with load: the current logs-off/capped repeat
averaged 16.0 ms, versus 197.3 ms in the preceding verifier comparison. The earlier
approximately 95-fold latency ratio describes that pair, not a repeatable fixed factor.

All three cases completed receipt verification. Successful/missing receipts after drain
were 68,237/2,439 with logging, 132,154/1,945 with logging off and the cap, and
113,885/4,055 with logging off and no cap. All had zero reverted receipts. Missing
receipts are excluded from committed TPS and successful-transaction latency. The
generator's confirmation snapshot can differ from the later direct receipt check;
canonical receipts, not its snapshot counter, determine TPS here.

## Evidence

[Compact evidence](evidence/besu-baseline-2026-09-29.json) records settings, hashes,
receipts, counters, log counts and historical results. Raw evidence and the isolated
runners remain under `.tmp/besu-baseline-explanation/` in the feature worktree.

All new cases use source baseline `61d91e15816603b3c775443abe9174bdab685d64`, Besu
26.8.1, Temurin 25.0.4.1+1 and Go 1.26.6. Original verifier JAR SHA-256:
`c41a9ca903606aa5e6a1c0f75c3794085d4060eb40b9451181a9da036379b986`.
OPS SHA-256: `2dd3bbfcb5e818bd77c91b18254f8b0620592062fc8ed46816fc95091fba04fe`.

TPS counts successful canonical receipts observed during the 60-second sending window;
p99 includes successful transactions confirmed after sending. Receipt/hash/block-membership
checks are identical across runs. Source comparison also confirms that the original
verifier, approval store, batch decoder, tracer and preflight RPC implementations were
unchanged between the historical source and the pre-optimization current plugin.
