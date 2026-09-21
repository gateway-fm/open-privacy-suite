# RD-855 behavioral shifts — SQL → gRPC indexer migration

Tracks every place where the gRPC-backed `ExplorerBackend` (privacy-mode path)
behaves differently from the legacy direct-SQL `*Store` (standalone path).

Kept as a living checklist. Each item is: **what breaks, why, suggested fix**.
Items in the **"Mitigated"** section have code in place that preserves behavior
or degrades it acceptably; **"Open"** items still need attention.

---

## How to read this

- **What** — user-visible difference when the gRPC backend is used (i.e., when `INDEXER_URL` is set in privacy mode).
- **Why** — root cause. Usually "the indexer has no concept of X by design" (trust model), "the indexer API doesn't expose Y yet", or "pagination semantics differ".
- **Suggestion** — concrete next step. Could be: add an indexer RPC, fall back to SQL for this method, accept the shift with a docs note, etc.

> Architecture-of-record (trust boundary, BFF deployment, network
> isolation, auth decisions) lives in `deployments/privacy/README.md`,
> not here. This file is strictly a ledger of SQL → gRPC behavior
> deltas.

---

## Mitigated

### 1. Offset totals on log / transfer / internal-tx list endpoints

- **What**: `GET /address/{addr}/logs`, `GET /token/{token}/transfers`, `GET /address/{addr}/internal-txs` return `total_items` in the offset pagination response. With the gRPC backend this value equals the current page's row count (`len(rows)`), not a DB-wide COUNT.
- **Why**: The indexer gRPC API exposes the rows, not a total. `SELECT COUNT(*)` was a per-request side-effect of the legacy SQL query; porting that would require a new RPC or a second call.
- **User impact**: UI pagers that render "Showing 50 of 12,345" will say "Showing 50 of 50". Navigation to deep pages still works (offset is respected), but the "last page" hint is gone.
- **Suggestion**: either (a) add counts to the indexer — probably `BatchGetLogCounts` / `BatchGetTransferCounts` per key, or (b) accept the shift and change the UI to a "load more" pattern. Option (b) is lighter and matches cursor pagination; option (a) is needed if exact totals matter for compliance.

### 1a. Transactions paginated total — RESTORED to a DB-wide COUNT (RD-1061)

- **What**: `GET /api/v1/explorer/transactions/paginated` previously returned a **page-local** `total` under the gRPC backend (`len(filtered rows after skip)`), so the value grew as the client paginated — e.g. 47 on page 1, 70 on page 2 — inflating the computed page count and producing a phantom extra page.
- **Fix**: `GetTransactionsPaginatedFiltered` now sources `total` from the embedded SQL `*Store.CountTransactionsFiltered` — the same visibility-aware `SELECT COUNT(*) FROM transactions WHERE <visClause>` that `GetChainStatsFiltered` already uses through this backend. The page **rows** still come from the indexer over gRPC; only the **total** is sourced from SQL. The total respects the viewer's visibility allowlist + `VisibleTxHashes`, so it never leaks counts the viewer cannot see.
- **Why this one and not §1**: the transactions table is queryable via the embedded `*Store` (`EXPLORER_DATABASE_URL`); logs/transfers/internal-tx in §1 would each need their own visibility-aware COUNT and are left page-local for now.
- **Residual**: the SQL COUNT does not subtract post-query "G10" redaction drops, so the total can still very slightly overcount vs the rendered rows (pre-existing; documented at `explorer_api.go` `getExplorerTransactionsPaginated`). Stable across pages, which was the user-visible bug.

### 2. `GetTransactionHistory` interval quantizes to enum

- **What**: Legacy takes `intervalSeconds int`; new path maps to `TimeBucket` enum (HOUR / DAY / WEEK). An intermediate interval (e.g., 15 minutes, 6 hours) rounds up to the next larger bucket.
- **Why**: The proto picked a coarse enum for simplicity. Intermediate buckets are rarely useful for chart UIs.
- **User impact**: If the admin UI ever requests non-standard intervals, it now gets coarser bins than asked for.
- **Suggestion**: add a `bucket_seconds` field on `GetTransactionHistoryRequest` as an alternative to `bucket`, honoring whichever is set. Low-effort proto + server change.

### 3. `GetTransactionHistory` has no `range` parameter yet

- **What**: Legacy supported `(intervalSeconds, limit)` — i.e., "last N buckets". The current proto accepts a `range` but Open Privacy Suite's gRPC client doesn't populate it; the indexer applies its own default lookback.
- **Why**: Oversight during stage 2a — easier to ship without.
- **User impact**: Returned window may be longer or shorter than expected. Limit is applied client-side after fetch, so data correctness is fine; only the response size and server work differ.
- **Suggestion**: populate `range` from `(now - intervalSeconds * limit, now)`. One-line fix when we're back in this handler.

### 4. `GetAllTransfers` stays on SQL

- **What**: `GET /transfers` (no filter) falls back to the embedded `*Store`. In privacy-mode deployments without SQL access, this endpoint is unavailable.
- **Why**: The indexer's `ListTokenTransfers` requires at least one filter (`by_tx_hash`, `by_address`, or `by_token`). Deliberate — an unbounded global transfer feed is not a supported gRPC operation.
- **User impact**: Admin-style "show me all transfers" view doesn't work once the SQL path is removed.
- **Suggestion**: either (a) add a dedicated `ListAllTokenTransfers` RPC on the indexer, or (b) drop this endpoint (nobody uses it operationally, just admin spelunking). Recommend (b).

### 5. `Contract` response omits ABI / source / verified / compiler metadata

- **What**: `GET /contract/{addr}` from gRPC returns only `Address`, `Bytecode`, `Creator`, `CreationTx`, `BlockNumber`. Legacy SQL path returned `IsVerified`, `ABI`, `SourceCode`, `CompilerVersion`, `OptimizationUsed`, `EVMVersion`, `ContractName`, `LicenseType`.
- **Why**: RD-855 design: contract verification is standalone-block-explorer-only. Indexer is chain-facts-only.
- **User impact**: In privacy mode, the contract detail page shows no decoded ABI or source. (This is product-intent: customers running corporate chains don't use verification features.)
- **Suggestion**: none — this is the documented product decision. Frontend should feature-gate verification UI on `INDEXER_URL != ""` or on an explicit privacy-mode flag.

### 6. `SetContractABI` stays on SQL

- **What**: The contract-ABI upload endpoint writes only to the legacy explorer postgres. In privacy mode the endpoint has nowhere to write to if the SQL path is eventually removed.
- **Why**: Indexer is read-only. ABI is derived metadata, not chain data.
- **User impact**: Privacy-mode frontend cannot upload / overwrite ABIs (which is fine given #5 — verification isn't a privacy-mode feature).
- **Suggestion**: remove the `POST /contract/{addr}/abi` route from the privacy-mode API surface entirely. In standalone mode it keeps working.
- **Resolved**: the route (`POST /api/v1/explorer/addresses/{address}/abi`), its handler and `Store.SetContractABI` are deleted. The standalone explorer keeps verification in its own database.

### 7. `GetIndexerProgress` stays on SQL

- **What**: Admin API `GET /indexer/progress` reads `indexer_progress` rows directly from the legacy DB. The new indexer has its own internal progress table that isn't exposed over gRPC.
- **Why**: Intentional — the indexer considers its backfill state internal. `GetSyncStatus` covers the user-facing "how caught up are we" question; deep internals (min/max fetched block ranges, gap lists) are out of scope.
- **User impact**: If the admin UI renders backfill gap details from `GetIndexerProgress`, that shows stale / nothing in privacy mode.
- **Suggestion**: replace the admin UI's detail view with `GetSyncStatus`, which already carries `latest_indexed_block`, `latest_chain_block`, `gap_count`. Drop `GetIndexerProgress` from the privacy-mode admin surface.

---

## Open (stage 2b territory)

### 8. Filtered-variant page sizes may shrink

- **What**: `GetTransactionsFiltered`, `GetBlocksFiltered`, `*WithCategoriesFiltered` etc. apply visibility filtering after fetching. A page request for `limit=25` may return fewer rows if some of the first 25 are filtered out. Legacy SQL used `WHERE <visibility>` so SQL did the trimming and always returned up to `limit` visible rows.
- **Why**: The indexer has no concept of visibility by design (RD-855 trust model). Filtering must happen after fetch.
- **User impact**: Pagination in the UI can look jumpy — "page 1 has 18 rows, page 2 has 22, page 3 has 25 and a 'next' button". Cursor progression remains correct; pages are just variably-sized.
- **Suggestion**: in the gRPC client, over-fetch (e.g., `limit * 2`, up to a cap) and return up to `limit` filtered rows; emit a next cursor pointing at the last *fetched* (not filtered) row. For high-filter-rate cases, a fetch-and-filter loop that keeps pulling until it has `limit` visible rows is the "exactly match SQL" option — accept the cost.

### 9. `GetChainStatsFiltered` cannot subtract filtered counts over gRPC

- **What**: `GetChainStatsFiltered` reduces `TotalTransactions` / `TotalAddresses` by the count of filtered-out transactions. The gRPC indexer can't answer "how many transactions would your filter exclude?" without a full scan.
- **Why**: Indexer has no visibility concept; a Go-layer loop over all transactions is infeasible on big chains.
- **User impact**: Dashboard "Total txs" in privacy mode shows the real totals, not per-viewer adjusted totals. This is arguably **correct** product behavior — totals should not leak per-viewer deltas.
- **Suggestion**: return unfiltered `ChainStats` and document that dashboard counts are network-wide, not viewer-specific. If we ever want viewer-specific counts, that's a new indexer RPC (`GetFilteredChainStats(hidden_addresses[], visible_addresses[])`) — expensive to implement and may itself leak via timing. Recommend keeping the network-wide semantic.

### 10. `GetTransactionHistoryFiltered` cannot subtract filtered buckets over gRPC

- **What**: Same shape as #9 but for the time-bucket histogram.
- **Why**: Same reason.
- **Suggestion**: same — return unfiltered buckets and document. Most deployments don't need viewer-specific history charts.

---

## Decided: no shift (yet)

### A. Pagination cursors are now opaque server-encoded strings

- **What**: Cursors are no longer SQL block-numbers; they're opaque base64(JSON) blobs.
- **Impact**: None for clients that treat them as opaque strings (per docs). Anything that was parsing cursors would break — there isn't any such consumer in the codebase.

### B. Addresses are always lowercase in responses

- **What**: The indexer normalizes addresses to lowercase. Legacy SQL returned whatever was stored (already lowercase in practice).
- **Impact**: None if consumers don't rely on EIP-55 checksum case from the API; frontend does its own EIP-55 conversion for display.

---

## Unknown

Items flagged during development that need someone who knows the product to weigh in:

- **None open right now.** Update this list during stage 2b if anything else turns up.
