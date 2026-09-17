# Full OPS / guarded Reth acceptance evidence

Verified 2026-09-17 in `feat/ops-dsl-reth`. The runnable commands and current
development limitations are in [the stack runbook](../ops-reth-stack.md).

## Test-first and review checkpoints

- Harness ownership tests first failed because the implementation was absent.
  They now pass both process-start ownership/reused-PID refusal and isolated
  Compose/loopback-port assertions.
- Actual startup found and corrected PostgreSQL's temporary initialization
  socket appearing healthy before its real TCP server, plus copied explorer
  Vite configuration relying on bundled `__dirname` under the runner loader.
- Actual restart found and corrected the indexer's fail-fast initial RPC
  connection: the harness now waits for Reth's correct chain ID first.
- Acceptance initially expected revoked submission to reject synchronously.
  Actual evidence showed queued hash → `denied` / `POLICY_DENIED`, no receipt.
  The final assertion checks that protocol and no receipt across three candidate
  block intervals; denial is explicitly not described as terminal.
- Repeated acceptance uses a higher test gas price to replace a prior denied
  pool nonce, without clearing the pool or resetting the chain.
- Secrets and process manifests stay under mode 0700 stack state with mode 0600
  files. Source checkouts and unrelated running stacks are not modified.

## Final native binaries and result

The final run rebuilt native OPS after the platform authorization, simulation
override and compliance decimal fixes, then restarted the same persisted chain
and database using the override-fixed guarded Reth binary. Reth uses the explicit
64 MiB development cross-block cache.

| Binary | SHA-256 |
|---|---|
| OPS | `d023186be49c8a85482a9cba3f6a2d31ea7af28b80bf8ba2aa2367f41cb17afe` |
| Guarded Reth | `db99022795bbbbd8b3b2f13ab7f349b6ec9695bdd60acdc71092669e8e67d852` |
| Chain indexer | `5852f828805f9286e1935051e71a15f7a0634e50d7f67994510e0567edc1d788` |
| Privacy explorer BFF | `27e1e80d0e868f9110ab130ec6b708aafbb01bf7c04810183743b6f2d68e9639` |

All 12 actual-stack checks passed:

1. Organization and independent named human administrators bootstrapped by API.
2. Group source submitted/reviewed/activated; author's self-approval rejected.
3. User onboarding, KYC administration and real Ethereum signer proof.
4. Baseline source import, native compilation, independent activation and fresh
   node publication.
5. Signed scoped CREATE finalized, then registered by OPS reconciliation.
6. Deployed drift and ABI adopted through reviewed registry source.
7. Actual transaction and live `eth_call` executed on Reth.
8. Second named principal with the same proven signer denied execution and denied
   access to the other principal's durable transaction status.
9. Indexer receipt/event data visible through authenticated OPS; anonymous lookup
   returned opaque 404.
10. Actual explorer OAuth code exchange, HttpOnly session, and BFF transaction
    lookup through OPS.
11. ABI-pinned record-party predicate permitted an actual transaction, then
    denied after a separate actual transaction changed the live on-chain party.
12. Reviewed rule revocation produced `POLICY_DENIED` and no canonical receipt
    across multiple candidate blocks.

The persistent restart check also passed: existing active source, reconciled
canonical transaction and authenticated explorer history survived. Indexer logs
show receipt retrieval through `eth_getBlockReceipts` with tracing disabled.
Historical trace-derived enrichment and unauthenticated token getter enrichment
are not claimed.

Local stack state: `.tmp/ops-reth-6fe399425e`. At handoff the URLs are OPS
`http://localhost:54418`, frontend `http://localhost:54419`, explorer
`http://localhost:54422`. `acceptance.json` holds test principal IDs and hashes;
`state.json` also holds credentials and must not be published.

Example final evidence: organization `d3f7271a-b62a-44ff-bf84-08e40443e621`,
CREATE `0x0e526e6fafadbfe3f3d7693d44ec7b736b32438029e9d9512cb7abcc89618332`,
call `0xed9d0fa9f469b01c8be0ddcc96c9667953e51562359366d88fe39b4a920068d6`,
record-party transaction
`0xddbec6c4f556283749fd28d34f4714faa14114ed9a943f5c80821dcb350d3158`,
and denied intent
`0x9c026adff834fd08158812ace25890200535cb79d318a49336402f767f2d3c7b`.

The independent SDK smoke exercised real mock-human login and refresh, readiness,
configuration context, privileged candidate diagnostic simulation, revoked RPC,
own finalized status and shared-signer status privacy. See
`sdk/test/stack-smoke.mjs` and the stack's `sdk-acceptance.json`.

## Re-run after the handoff fixes (2026-09-17, later)

OPS was rebuilt from the worktree with `restart --rebuild` on the same stack
state (`.tmp/ops-reth-6fe399425e`: same chain, databases, signing trust and
node policy state; guarded Reth binary unchanged). Restart self-check passed
(reviewed policy, finalized execution and authenticated explorer history
preserved), then the full acceptance command passed all 12 checks again.

| Binary | SHA-256 |
|---|---|
| OPS (rebuilt after the review fixes; final) | `ae7d23dc22f249fd6a36e73c660cbee1809b0452ce4a1646dda65d5427801921` |

The same restart-and-acceptance sequence was repeated after the independent
review fixes (compiler probe memoization, typed client errors, guarded legacy
execution-policy writers); the final binary above is the one that passed.

Live checks of the new behaviour against that stack, as the mock-auth author:
`GET …/configuration/groups/context`, `…/execution-rules/context` and
`/api/v1/admin/configuration/platform/context` all return the `capabilities`
block with `compiler.available: true` (native solc 0.8.35 on this host); an
unknown stream name returns 400 `unsupported configuration kind`.

After the per-frame cost measurement (`reth-runtime.md`) the guarded Reth binary
was rebuilt with the per-transaction decision print off by default and the
optional check timing; the stack was restarted on it and the acceptance passed
all 12 checks again.

| Binary | SHA-256 (prefix) |
|---|---|
| Guarded Reth (final) | `6f2b3ddbd8e1136c…` |
| OPS (unchanged) | `ae7d23dc22f249fd…` |

