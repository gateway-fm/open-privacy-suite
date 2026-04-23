# RD-855 Phase 0 — Consolidated SQL Inventory

Merged inventory of chain-data SQL access across privacy-proxy and block-explorer, grouped by access pattern. Phase 0 deliverable. Drives the gRPC API design in Phase 1.

**Scope.** Only chain-indexed data: blocks, transactions, logs, addresses, tokens, token transfers, token balances, contracts, internal transactions, OP deposits, gas stats, sync/progress. RBAC, compliance, disclosure, auth, audit all excluded — they stay where they are.

**Source audits.** `rd-855-audit-privacy-proxy.md`, `rd-855-audit-block-explorer.md`.

---

## Summary

| Metric | Value |
|---|---|
| Privacy-proxy read methods on chain data | 47 |
| Block-explorer read methods on chain data | ~60 |
| Block-explorer write methods (indexer-internal) | ~25 |
| Overlapping read patterns (same thing in both consumers) | 21 |
| Proposed gRPC read methods (deduplicated) | **22** |
| Hot-path methods | 8 |
| N+1 risks identified | 5 |

**Key finding.** Both consumers read the same shapes: point-reads, range-reads with cursor or offset pagination, subresource lookups by address or tx, aggregates, and a small search surface. Privacy-proxy adds a visibility-filter layer on top of the same queries. After deduplication the gRPC surface is moderate — 22 unary RPCs plus subscription streams.

---

## Tables the indexer will own

`blocks`, `transactions`, `logs`, `token_transfers`, `tokens`, `token_balances`, `contracts`, `address_stats`, `internal_transactions`, `op_deposits`, `daily_stats`, `sync_status` / `indexer_progress`, `missing_block_ranges`.

`missing_block_ranges`, `indexer_progress`, `counters` are **indexer-internal** — no consumer reads them via the API.

---

## Reads by access pattern

### 1. Point reads (by hash / number / address)

Both consumers have equivalent surfaces. Single row, O(1) on primary key.

| Candidate RPC | Privacy-proxy method | Block-explorer method | Hot | Notes |
|---|---|---|---|---|
| `GetBlock` | `GetBlock(number)`, `GetBlockByHash(hash)` | `GetBlock`, `GetBlockByHash` | ● | Merge number/hash into a oneof. |
| `GetTransaction` | `GetTransaction`, `GetTransactionWithCategories` | `GetTransaction`, `GetTransactionWithCategories` | ● | Category enrichment is a server-side join; expose as an option flag, not a separate RPC. |
| `GetAddress` | `GetAddressStats` | `GetAddressStats` | ● | Includes `is_contract`, tx counts, first/last seen, token count. |
| `GetContract` | `GetContract`, `IsContract` | `GetContract`, `IsContract` | — | `IsContract` is a thin wrapper → fold into `GetAddress`. |
| `GetToken` | `GetToken` | `GetToken` | ● | Case-insensitive address match. |
| `GetLatestBlockNumber` | `GetLatestBlockNumber` | `GetLatestBlockNumber` | ● | Used on every dashboard load; cacheable. |
| `GetSyncStatus` | `GetSyncStatus` | (via `missing_ranges` queries) | — | Reports last indexed block + syncing flag. |
| `GetOPDeposit` | — | `GetOPDeposit(l2_tx_hash)` | — | OP-Stack specific; gate by chain capability. |

### 2. Range reads (paginated feeds)

Cursor pagination (`block_number DESC, tx_index DESC`) for feeds; offset only for bounded browsing lists.

| Candidate RPC | Privacy-proxy | Block-explorer | Hot | Pagination |
|---|---|---|---|---|
| `ListBlocks` | `GetBlocks`, `GetBlocksFiltered` | `GetBlocks` | ● | Cursor: `number < $1`. |
| `ListTransactions` | `GetTransactions`, `GetTransactionsFiltered`, `GetTransactionsWithCategories{Filtered}`, `GetTransactionsPaginated{WithCategories}{Filtered}` (6 variants) | `GetTransactions`, `GetTransactionsPaginated`, `GetTransactionsWithCategories`, `GetTransactionsPaginatedWithCategories` (4 variants) | ● | One RPC with option flags collapses 10 methods. Cursor + optional offset fallback. |
| `ListTransactionsByAddress` | `GetTransactionsByAddress` | `GetTransactionsByAddress` | ● | Address filter; cursor. |
| `ListTransactionsByBlock` | `GetTransactionsByBlock` | `GetTransactionsByBlock` | ● | All txs for a block, ordered by `tx_index`. |

The variant sprawl (`Filtered`, `WithCategories`, `Paginated`) in the current code is a sign of copy-paste growth. The API should **not** mirror it. One `ListTransactions` RPC with option fields:

- `category_mode` — off / inline (returns coin/contract/token flags).
- `pagination` — cursor (default) or offset.
- Filters (from/to address, block range, types) as a typed message.

Visibility filtering is **not** a per-RPC variant — that's entirely privacy-proxy's job at the RedactionEngine layer after the API responds.

### 3. Index lookups (subresources by owner)

Grouped by what the subresource is attached to.

| Candidate RPC | Covers |
|---|---|
| `ListLogs` | `GetLogsByTransaction`, `GetLogsByAddress`, `GetLogsByTopic`, `GetLogs` (multi-filter). Single RPC with typed filters: `by_tx_hash`, `by_address`, `by_topic0`, `block_range`. |
| `ListTokenTransfers` | `GetTransfersByAddress`, `GetTransfersByTransaction`, `GetTransfersByToken`, `GetAllTransfers`. One RPC with optional `by_address`, `by_tx_hash`, `by_token` filters. |
| `ListInternalTransactions` | `GetInternalTransactionsByTx`, `GetInternalTransactionsByAddress`, `GetInternalTransactionsByBlock`. One RPC. |
| `ListTokenHolders` | `GetTokenHolders`. |
| `ListTokenBalances` | `GetTokenBalances`, `GetLatestBalance`. One RPC with optional `token_address` filter to collapse both. |

### 4. Aggregates

| Candidate RPC | Privacy-proxy | Block-explorer | Hot | Notes |
|---|---|---|---|---|
| `GetChainStats` | `GetChainStats`, `GetChainStatsFiltered` | `GetChainStats` | ● | Block count, tx count, avg block time. Filter variant moves to privacy-proxy post-processing. |
| `GetTransactionHistory` | `GetTransactionHistoryFiltered` | `GetTransactionHistory` | ● | Time-bucket histogram. |
| `GetGasPrices` | — | `GetGasPercentiles` | ● | `PERCENTILE_CONT` over N recent blocks. Already cached 30s in explorer; indexer keeps the cache. |
| `GetDailyStats` | — | `GetDailyStats`, `GetDailyStatsForDate` | — | Pre-aggregated table; range + single-date modes. |
| `GetBlockTransactionCount` | `GetBlockTransactionCountFiltered` | (implicit in block record) | — | Bulk variant: `BatchGetBlockTransactionCounts(numbers[])` to avoid N+1 from `ListBlocks`. |
| `GetAddressTransactionCount` | `GetAddressTransactionCountFiltered` | — | — | Same story — expose the batch version. |

### 5. Search

| Candidate RPC | Privacy-proxy | Block-explorer | Hot |
|---|---|---|---|
| `Search` | `SearchSuggestions` | `SearchSuggestions` | ● |

Prefix-match autocomplete across blocks, txs, addresses, tokens. Current impl is a UNION of four `LIKE 'prefix%'` queries. API stays identical; the implementation is the indexer's problem.

### 6. List / browse (bounded offset pagination)

| Candidate RPC | Privacy-proxy | Block-explorer |
|---|---|---|
| `ListAccounts` | `GetAccountsPaginated` | `GetAccountsPaginated` |
| `ListTokens` | `GetTokens` | `GetTokens` |
| `ListVerifiedContracts` | — | `GetVerifiedContracts` |

Browse-style pages. Offset pagination is acceptable here because the set is bounded by how far a human scrolls.

### 7. Subscriptions (server-streaming)

Server-streaming RPCs replace the current WebSocket hub. Per-event redaction happens at privacy-proxy after it receives the stream; standalone explorer consumes raw.

| Candidate RPC | What it streams |
|---|---|
| `SubscribeBlocks` | New block headers. |
| `SubscribeTransactions` | New transactions, optional filter by address. |
| `SubscribeAddressActivity` | Events touching a given address (txs + transfers + logs). |

Price updates from the current hub are **not** chain data — they come from CoinGecko / manual configuration in privacy-proxy. Keep the price stream inside privacy-proxy; don't push it into the indexer API.

---

## Writes (indexer-internal, not exposed)

All of these stay inside the indexer — never exposed over gRPC. They remain part of the indexer repo's internal code.

- `InsertBlock`, `InsertTransaction`, `InsertLog`, `InsertTokenTransfer`, `InsertToken`, `InsertContract`, `InsertInternalTransaction`, `InsertBalance`, `InsertOPDepositsBatch`, `UpsertAddressStats`, `UpdateTokenStats`, `UpdateTokenPrice`, `UpsertDailyStats`.
- Batch drivers: `InsertBlockDataBatch`, `InsertBalancesBatch`, `RebuildAddressStats`.
- Backfill state: `GetIndexerProgress`, `UpdateIndexerProgress`, `SaveMissingRanges`, `GetMissingRangesBatch`, `DeleteMissingRange`, `ShrinkMissingRange`, `RequeueMissingBlock`, `FindMissingBlocksInRange`, `HasBlock`.
- Contract verification writes: `UpdateContractABI`, `VerifyContract` — these currently live in block-explorer's api. **Decision needed for Phase 1**: does the indexer own contract verification state, or does privacy-proxy own it and tell the indexer? Either is defensible; verification metadata is derived from chain data + external Solc, so indexer is the cleaner home.

---

## Hot paths (must be fast)

Appear on every common page load. API design must optimize for these:

1. `GetLatestBlockNumber` — navbar / dashboard.
2. `ListBlocks` — dashboard feed.
3. `ListTransactions` — dashboard feed.
4. `GetAddress` (stats) — address detail page.
5. `GetBlock` — block detail page.
6. `GetTransaction` — tx detail page.
7. `Search` — autocomplete on every keystroke.
8. `GetChainStats` — dashboard.

All are point or bounded-range reads; sub-millisecond with proper indexes. None of these should go through the indexer DB more than once per request — aggressive caching (per-block TTLs for `GetChainStats` / `GetLatestBlockNumber`) is fair game.

---

## N+1 risks — design the API to kill them

| Current issue | Where | Fix in the API |
|---|---|---|
| `GetTokenBalances` called per address in account listings. | block-explorer `api/handlers.go:450`. | `BatchGetTokenBalances(addresses[])`. |
| `GetBlockTransactionCount` called in a loop over `ListBlocks`. | Privacy-proxy already batches via `ANY($1)`. | Expose `BatchGetBlockTransactionCounts(numbers[])` as a first-class RPC, not a hidden optimization. |
| `GetTransactionsByAddress` called per address. | Account enumeration. | `BatchListTransactionsByAddress(addresses[])` if enumeration is kept; otherwise design away via `ListTransactions` with an `addresses[]` filter. |
| Category-column EXISTS subqueries (4 per row) in `GetTransactionWithCategories`. | Privacy-proxy `store.go:795`. | Materialize a `tx_category` column at index time so reads are a single scan, not per-row EXISTS. |
| `SearchSuggestions` UNION of 4 queries. | Both consumers. | Keep as-is or build a dedicated search index later. Not blocking. |

---

## Pagination policy for the API

- **Default: opaque cursor strings.** Server-encoded, client passes back verbatim.
- **Offset fallback** only for bounded browse pages (`ListAccounts`, `ListTokens`). Even there, cap at 10k total.
- **Page size** bounded by the server (document the cap).
- **Sort order is fixed per RPC** (tx feed = block DESC, tx_index DESC). No client-configurable `ORDER BY`.

---

## Filtering policy for the API

- **No SQL-like `where` field.** Every filter is a typed message field on the request.
- **Composable with AND semantics** (e.g., `address + block_range + topic0`).
- **Server-chosen indexes** — client can't ask for plans the indexer can't execute efficiently.

---

## Categories / visibility / redaction — explicit boundaries

- **Category computation** (coin / contract / token-transfer flags per tx) is data enrichment. It's the indexer's job — materialize at index time, return as columns. Consumers don't recompute.
- **Visibility filtering** (blocklist / allowlist / visibleTo) is **not** in the indexer. Indexer returns raw data. Privacy-proxy's `RedactionEngine` applies filters post-fetch.
- **Redaction** (address masking, pseudonyms, value stripping) is also privacy-proxy only. Indexer has no concept of viewer identity.

This boundary matters for the RD-855 thesis — the indexer does not know about users.

---

## Proposed gRPC surface — full list

```proto
syntax = "proto3";
package chain_indexer.v1;

service IndexerService {
  // Point reads
  rpc GetBlock(GetBlockRequest) returns (Block);
  rpc GetTransaction(GetTransactionRequest) returns (Transaction);
  rpc GetAddress(GetAddressRequest) returns (Address);
  rpc GetContract(GetContractRequest) returns (Contract);
  rpc GetToken(GetTokenRequest) returns (Token);
  rpc GetLatestBlockNumber(Empty) returns (LatestBlockNumber);
  rpc GetSyncStatus(Empty) returns (SyncStatus);
  rpc GetOPDeposit(GetOPDepositRequest) returns (OPDeposit);

  // Range reads (cursor by default)
  rpc ListBlocks(ListBlocksRequest) returns (ListBlocksResponse);
  rpc ListTransactions(ListTransactionsRequest) returns (ListTransactionsResponse);
  rpc ListTransactionsByAddress(ListTransactionsByAddressRequest) returns (ListTransactionsResponse);
  rpc ListTransactionsByBlock(ListTransactionsByBlockRequest) returns (ListTransactionsResponse);

  // Subresources
  rpc ListLogs(ListLogsRequest) returns (ListLogsResponse);
  rpc ListTokenTransfers(ListTokenTransfersRequest) returns (ListTokenTransfersResponse);
  rpc ListInternalTransactions(ListInternalTransactionsRequest) returns (ListInternalTransactionsResponse);
  rpc ListTokenHolders(ListTokenHoldersRequest) returns (ListTokenHoldersResponse);
  rpc ListTokenBalances(ListTokenBalancesRequest) returns (ListTokenBalancesResponse);

  // Aggregates
  rpc GetChainStats(Empty) returns (ChainStats);
  rpc GetTransactionHistory(GetTransactionHistoryRequest) returns (TransactionHistory);
  rpc GetGasPrices(GetGasPricesRequest) returns (GasPrices);
  rpc GetDailyStats(GetDailyStatsRequest) returns (DailyStatsRange);

  // Batch variants to kill N+1
  rpc BatchGetBlockTransactionCounts(BatchGetBlockTransactionCountsRequest) returns (BatchGetBlockTransactionCountsResponse);
  rpc BatchGetTokenBalances(BatchGetTokenBalancesRequest) returns (BatchGetTokenBalancesResponse);

  // Browse (offset OK)
  rpc ListAccounts(ListAccountsRequest) returns (ListAccountsResponse);
  rpc ListTokens(ListTokensRequest) returns (ListTokensResponse);
  rpc ListVerifiedContracts(ListVerifiedContractsRequest) returns (ListVerifiedContractsResponse);

  // Search
  rpc Search(SearchRequest) returns (SearchResponse);

  // Subscriptions
  rpc SubscribeBlocks(SubscribeBlocksRequest) returns (stream BlockEvent);
  rpc SubscribeTransactions(SubscribeTransactionsRequest) returns (stream TransactionEvent);
  rpc SubscribeAddressActivity(SubscribeAddressActivityRequest) returns (stream AddressActivityEvent);
}
```

**Count: 22 unary + 3 streaming = 25 RPCs.** Compared to ~100 SQL methods today, this is the intended collapse.

---

## Decisions (confirmed 2026-04-23)

1. **Contract verification is standalone-only.** Private chains running privacy-proxy are corporate chains — contract verification has no product value there. Verification stays out of both the indexer and privacy-proxy entirely. Block-explorer api (only deployed in standalone mode) owns verification state in its own small postgres — chain facts come from the indexer, verification metadata from block-explorer's local DB, merged server-side when serving the contract detail page. Privacy-mode frontend feature-gates verification UI off.
2. **Category flags: materialized.** New `category` bitfield column on `transactions`, populated at index time. Reads become a single scan; the 4-way EXISTS subquery pattern goes away. Requires an indexer-internal migration.
3. **Subscriptions / WebSockets: deferred.** No `Subscribe*` RPCs in the indexer for now. No WS endpoint in privacy-proxy. Block-explorer's WS hub is deleted as part of Phase 4 regardless. Will revisit if/when WS becomes a confirmed product requirement.
4. **OP-Stack endpoints: environment-dependent.** Single indexer service with an `OP_STACK_ENABLED` config flag. When enabled, the indexer populates `op_deposits` and serves `GetOPDeposit`. When disabled, the RPC returns gRPC `Unavailable` and consumers feature-gate the UI. One image, one service, behavior varies by config.
5. **Daily stats: indexer.** Pure chain aggregation, no privacy logic. Indexer runs a periodic rollup task (end-of-day) and writes to `daily_stats`. Exposed via `GetDailyStats`; privacy-proxy passes through.

### Consequence for the gRPC surface

Drop the three `Subscribe*` RPCs from the proposed surface. Revised count: **22 unary RPCs, 0 streaming.**

```proto
// REMOVED from the Phase 1 surface (deferred until WS is confirmed as a product requirement):
// rpc SubscribeBlocks(SubscribeBlocksRequest) returns (stream BlockEvent);
// rpc SubscribeTransactions(SubscribeTransactionsRequest) returns (stream TransactionEvent);
// rpc SubscribeAddressActivity(SubscribeAddressActivityRequest) returns (stream AddressActivityEvent);
```

### Consequence for contract verification

The `Contract` message returned by `indexer.GetContract()` contains only chain facts (bytecode, deployer, deployment block/tx, proxy info). It does **not** carry `abi`, `source_code`, `is_verified`, `compiler_version`. Those live in block-explorer api's standalone-only DB and are merged server-side before the frontend response.

---

## Deliverable status

- Individual audits: `rd-855-audit-privacy-proxy.md`, `rd-855-audit-block-explorer.md`
- Consolidated inventory (this doc): `rd-855-phase-0-inventory.md`

Phase 0 complete. Ready for Phase 1 (API design).
