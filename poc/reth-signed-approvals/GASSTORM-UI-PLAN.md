Completed: the launcher and four fresh Adaptive browser captures work. The runs expose nonce/approval queue problems, so they establish observed peaks rather than sustainable capacity. [Results](GASSTORM-UI.md) · [Review](GASSTORM-UI-REVIEW.md).

| Step | Check |
|---|---|
| Launch | Add `gasstorm.sh ui` using the real Gasstorm dashboard, existing isolated OPS stack and custom Reth. Keep all transaction RPC through OPS. |
| Configuration critique | UI requests automatic wallet generation, but this fixture has ten funded/granted wallets. Resolve automatic count to those ten at the test-control endpoint; record the resulting count. Refresh the development login before each test. No token paste or manual org setup. |
| Capacity | Use a configurable 200M block gas limit for the interactive session, consistently in genesis and the builder. Earlier 30M/one-second fixture cannot fit 5,000 ordinary ETH transfers per second. This changes test configuration, not the node implementation. |
| TDD | Exercise start-request normalization before implementation: preserve adaptive parameters, select fixture wallets and require privacy routing. Reject unsupported fixture configurations explicitly. |
| Browser check | Open the actual dashboard, select privacy/adaptive, start and complete ETH and ERC20-approval tests, verify live WebSocket metrics and real receipts. Also smoke-test the module-off launcher. |
| Review | No changes to sibling repositories. Clean up owned processes/containers; document one command, URL, mode toggle and existing state-mismatch limitation. |
