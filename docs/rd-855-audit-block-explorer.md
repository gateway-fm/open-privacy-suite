# RD-855 Phase 0: Block Explorer SQL Audit

**Objective:** Inventory all chain-data SQL queries in block-explorer backend for future gRPC indexer API design.

**Date:** 2026-04-22  
**Scope:** `/Users/blade/work/software/block-explorer/backend/internal/`

---

## Executive Summary

- **Total chain-data queries:** ~100 distinct SQL operations
- **Read queries:** ~75 (candidates for gRPC methods)
- **Write queries:** ~25 (indexer-internal, stays in postgres)
- **Hot paths:** 6–8 endpoints called on every UI page load
- **N+1 risks:** 3 identified (address stats, token balances, internal tx iteration)
- **Key tables:** blocks, transactions, logs, tokens, token_transfers, contracts, address_stats, internal_transactions, op_deposits

---

## Write Operations (Indexer-Internal, NOT for gRPC)

All writes are in `db/` and called from `indexer/` package. These remain in postgres (not exported to gRPC):

| Function | File:Line | Called By | Pattern | Tables | Notes |
|----------|-----------|-----------|---------|--------|-------|
| InsertBlock | queries.go:25 | indexer.go:563 | point-write | blocks | INSERT ON CONFLICT |
| InsertTransaction | queries.go:103 | batch.go:57 | batch-write | transactions | pgx.Batch, ON CONFLICT |
| InsertTokenTransfer | queries.go:481 | batch.go:124 | batch-write | token_transfers | pgx.Batch, ON CONFLICT |
| InsertLog | queries.go:926 | batch.go:109 | batch-write | logs | pgx.Batch, ON CONFLICT |
| InsertToken | queries.go:396 | indexer.go:1023 | batch-write | tokens | pgx.Batch, ON CONFLICT |
| InsertContract | queries.go:820 | batch.go:74 | batch-write | contracts | pgx.Batch, ON CONFLICT |
| InsertInternalTransaction | queries.go:1032 | batch.go:141 | batch-write | internal_transactions | pgx.Batch, ON CONFLICT |
| InsertBalance | queries.go:625 | batch.go:265 | batch-write | balances | pgx.Batch, ON CONFLICT |
| InsertOPDepositsBatch | op_deposits.go:11 | opdeposits/fetcher.go:112 | batch-write | op_deposits | pgx.Batch, ON CONFLICT |
| UpsertAddressStats | queries.go:752 | batch.go:159 | upsert | address_stats | ON CONFLICT + counter deltas |
| UpdateTokenStats | queries.go:464 | api/handlers.go (manual) | point-update | tokens | holder_count, transfer_count |
| UpdateTokenPrice | queries.go:471 | price service (external) | point-update | tokens | price, icon_url |
| UpdateContractABI | queries.go:871 | api/handlers.go:341 | point-update | contracts | abi (upsert via SetContractABI) |
| VerifyContract | queries.go:853 | api/handlers.go:1373 | point-update | contracts | verification metadata |
| UpdateSyncStatus | queries.go:1119 | indexer.go:258 | point-update | indexer_progress | last_indexed_block, is_syncing |
| UpdateSyncStatusBlocks | queries.go:1127 | (not found in code) | point-update | indexer_progress | verified/finalized blocks |
| UpsertDailyStats | queries.go:1369 | indexer (implied) | upsert | daily_stats | aggregation table |
| DeleteBlock | queries.go:96 | (test only) | point-delete | blocks | Cleanup/reorg |
| IncrementCounter | queries.go:708 | (not found) | point-update | counters | Address tx counts |

**Batch Operations (key transaction points):**
- `InsertBlockDataBatch` (batch.go:32): Atomically inserts blocks, txs, logs, transfers, contracts, tokens, internal_txs, address_stats in single txn
- `InsertBalancesBatch` (batch.go:253): Batches balance updates per token address
- `RebuildAddressStats` (batch.go:181): Rebuilds entire address_stats table post-catchup (complex self-join aggregate)

---

## Read Operations (Candidates for gRPC Methods)

Organized by access pattern. All are called from `api/handlers.go` or `publicapi/handlers.go` (public-api is also exposed).

### Point-Read (by ID/Hash/Address)

| Function | File:Line | Endpoints | Hot? | Fields | Filter | N+1 Risk |
|----------|-----------|-----------|------|--------|--------|----------|
| GetBlock | queries.go:36 | /block/{n} (api, public) | **HOT** | 18 cols | number = $1 | None |
| GetBlockByHash | queries.go:50 | /block/{hash} (api) | Normal | 18 cols | hash = $1 | None |
| GetLatestBlockNumber | queries.go:16 | /latest-block, /health (api, public) | **HOT** | 1 col (MAX) | — | None |
| GetTransaction | queries.go:114 | /tx/{hash} (api) | **HOT** | 17 cols | hash = $1 | None |
| GetTransactionWithCategories | queries.go:315 | /tx/{hash} (api, public) | **HOT** | 17 cols + category join | hash = $1 | None |
| GetToken | queries.go:409 | /token/{addr} (api, public) | **HOT** | 10 cols | address = $1 (case-insensitive) | None |
| GetTokenBalances | queries.go:677 | /address/{addr}/balances (api, public) | **HOT** | balances by token | address = $1 | **YES** – loops over tokens, may fetch 100+ balances |
| GetLatestBalance | queries.go:634 | balance endpoint (api) | Normal | 5 cols | address, token_address | None |
| GetContract | queries.go:831 | /address/{addr}/contract (api, public) | **HOT** | 12 cols | address = $1 | None |
| IsContract | queries.go:847 | (internal) | Normal | 1 col (EXISTS) | address = $1 | None |
| GetAddressStats | queries.go:776 | /address/{addr} (api, public) | **HOT** | 11 cols | address = $1 | None |
| GetOPDeposit | op_deposits.go:39 | /tx/{hash}/deposit (api) | Normal | 6 cols | l2_tx_hash = $1 | None |
| GetLastIndexedL1Block | op_deposits.go:56 | opdeposits/fetcher.go | Normal | 1 col (MAX) | — | None |

### Range-Read (paginated, ordered)

| Function | File:Line | Endpoints | Hot? | Pagination | Filter | N+1 Risk |
|----------|-----------|-----------|------|------------|--------|----------|
| GetBlocks | queries.go:64 | /blocks (api, public) | **HOT** | LIMIT+1, cursor | number < $1 or none | None |
| GetTransactions | queries.go:137 | /txs (api, public) | **HOT** | LIMIT+1, cursor | number < $1 or none | None |
| GetTransactionsPaginated | queries.go:166 | /txs?page=N (api, public) | **HOT** | OFFSET/LIMIT | tx_type NOT IN (hidden) | None |
| GetTransactionsPaginatedWithCategories | queries.go:284 | /txs?page=N (api, public) | **HOT** | OFFSET/LIMIT | tx_type filter + JOIN | None |
| GetTransactionsWithCategories | queries.go:253 | /txs (api, public) | **HOT** | LIMIT+1, cursor | number < $1 | None |

### Index-Lookup (by Address)

| Function | File:Line | Endpoints | Hot? | Pagination | Filter | N+1 Risk |
|----------|-----------|-----------|------|------------|--------|----------|
| GetTransactionsByAddress | queries.go:207 | /address/{addr}/txs (api, public) | **HOT** | LIMIT+1, cursor | from_address OR to_address | **YES** – called in loop for account enumeration |
| GetTransactionsByBlock | queries.go:192 | /block/{n}/txs (api, public) | **HOT** | — | block_number = $1 | None |
| GetTransfersByAddress | queries.go:492 | /address/{addr}/transfers (api, public) | **HOT** | LIMIT+1, cursor | from OR to address | **YES** – similar to txs-by-address |
| GetTransfersByTransaction | queries.go:516 | /tx/{hash}/transfers (api, public) | **HOT** | — | tx_hash = $1 | None |
| GetTransfersByToken | queries.go:529 | /token/{addr}/transfers (api, public) | Normal | OFFSET/LIMIT | token_address = $1 | None |
| GetInternalTransactionsByTx | queries.go:1043 | /tx/{hash}/internal-txs (api, public) | **HOT** | — | tx_hash = $1 | None |
| GetInternalTransactionsByBlock | queries.go:1056 | /block/{n}/internal-txs (api, public) | Normal | — | block_number = $1 | None |
| GetInternalTransactionsByAddress | queries.go:1069 | /address/{addr}/internal-txs (api, public) | Normal | OFFSET/LIMIT | from OR to address | **YES** – paginated but called per-address |

### Aggregate / Search

| Function | File:Line | Endpoints | Hot? | Query Type | Columns | Notes |
|----------|-----------|-----------|------|-----------|---------|-------|
| GetLogsByTransaction | queries.go:935 | /tx/{hash}/logs (api, public) | **HOT** | SELECT by tx_hash | 9 cols | Simple filter, no pagination |
| GetLogsByAddress | queries.go:947 | /address/{addr}/logs (api, public) | Normal | SELECT by address | 9 cols | OFFSET/LIMIT, case-insensitive |
| GetLogsByTopic | queries.go:964 | /logs?topic0={t} (api, public) | Normal | SELECT by topic0 | 9 cols | OFFSET/LIMIT |
| GetLogs | queries.go:981 | /logs (api, public) | Normal | SELECT multi-filter | 9 cols | address, topic0, fromBlock, toBlock, LIMIT |
| SearchSuggestions | queries.go:1196 | /search/suggestions (api, public) | **HOT** | Multi-UNION, 4 SELECTs | — | Searches blocks, txs, addresses, tokens by prefix; each UNION returns LIMIT rows |
| GetChainStats | queries.go:1140 | /stats (api, public) | **HOT** | SELECT aggregate | 1 col (COUNT blocks) | Single row, no filter |
| GetTransactionHistory | queries.go:1161 | /tx-history (api, public) | **HOT** | SELECT GROUP BY interval | 2 cols | GROUP BY time bucket, ORDER BY timestamp DESC, LIMIT |
| GetTokenHolders | queries.go:582 | /token/{addr}/holders (api, public) | Normal | SELECT from balances | 3 cols | OFFSET/LIMIT, complex subquery (top holders) |
| GetTokens | queries.go:423 | /tokens (api, public) | Normal | SELECT | 10 cols | OFFSET/LIMIT, tokenType filter |
| GetAllTransfers | queries.go:547 | /transfers (api, public) | Normal | SELECT | 12 cols | OFFSET/LIMIT, no filter |
| GetAccountsPaginated | queries.go:788 | /accounts (api, public) | Normal | SELECT | 11 cols | OFFSET/LIMIT, order by tx_count DESC |
| GetVerifiedContracts | queries.go:898 | (not found in handlers) | — | SELECT | 12 cols | OFFSET/LIMIT, is_verified = true |
| GetGasPercentiles | queries.go:1335 | /gas-prices (api, public) | **HOT** | SELECT with PERCENTILE_CONT | 4 cols | Complex window function, numBlocks parameter |
| GetDailyStats | queries.go:1398 | /daily-stats (api) | Normal | SELECT range | 10 cols | from_date, to_date, ORDER BY date DESC |
| GetDailyStatsForDate | queries.go:1427 | (not found) | — | SELECT | 10 cols | Single date point-query |

### Specialty / Infrastructure

| Function | File:Line | Called From | Purpose | Pattern |
|----------|-----------|-------------|---------|---------|
| GetIndexerProgress | missing_ranges.go:25 | indexer.go | Track backfill state | point-read, internal |
| UpdateIndexerProgress | missing_ranges.go:37 | indexer.go | Update min/max blocks | point-update, internal |
| GetMissingRangesBatch | missing_ranges.go:76 | indexer catchup | Fetch ranges to reprocess | range-read, ORDER BY DESC |
| GetBlockCount | missing_ranges.go:215 | (implied) | Count indexed blocks | aggregate |
| GetTotalMissingBlocks | missing_ranges.go:153 | (implied) | Sum missing ranges | aggregate |
| FindMissingBlocksInRange | missing_ranges.go:163 | (catchup) | Generate_series, find gaps | specialty (complex CTE) |
| SaveMissingRanges | missing_ranges.go:49 | indexer | Insert missing block ranges | batch-write |
| DeleteMissingRange | missing_ranges.go:98 | indexer | Remove processed range | point-delete |
| ShrinkMissingRange | missing_ranges.go:112 | indexer | Shrink range after block | range-manipulation |
| RequeueMissingBlock | missing_ranges.go:225 | indexer | Re-insert failed block | point-write |
| HasBlock | missing_ranges.go:239 | (test/debug) | Check block exists | exists-query |

---

## Access Pattern Summary

| Pattern | Count | Examples | Hot Path |
|---------|-------|----------|----------|
| **Point-read** | ~15 | GetBlock, GetTransaction, GetToken | 6 ops |
| **Range-read** | ~8 | GetBlocks, GetTransactions, GetTransactionsByAddress | 4 ops |
| **Index-lookup** | ~8 | GetTransfersByToken, GetLogsByAddress | 2 ops |
| **Aggregate** | ~15 | SearchSuggestions, GetChainStats, GetGasPercentiles | 4 ops |
| **Specialty** | ~10 | FindMissingBlocksInRange, RebuildAddressStats | 0 ops |
| **Write/Batch** | ~25 | InsertBlockDataBatch, UpsertAddressStats | (indexer) |

---

## N+1 Risks & Performance Concerns

| Issue | Location | Risk Level | Notes |
|-------|----------|------------|-------|
| **GetTokenBalances in loop** | queries.go:677 | **HIGH** | Called per-address; iterates all tokens for a single user. Consider cached balance aggregates or pre-computed snapshots. |
| **GetTransactionsByAddress in account enumeration** | api/handlers.go:450 | **MEDIUM** | handleGetAccounts loads paginated accounts, then calls GetBalance for each. Could batch if account counts are large. |
| **GetInternalTransactionsByAddress paginated** | queries.go:1069 | **MEDIUM** | Paginated per-address; useful but not batched. If loading many addresses' internal txs, becomes N queries. |
| **SearchSuggestions 4-way UNION** | queries.go:1196 | **MEDIUM** | Each UNION arm does a separate query (blocks, txs, addresses, tokens). No issue if cache is short-lived, but could be optimized with single table scan or prefix index. |
| **RebuildAddressStats complex CTE** | batch.go:181 | **LOW** | Only runs post-backfill; single bulk operation. Complex but not in hot path. |

---

## Candidate gRPC API Methods

Based on read query inventory. One RPC per access pattern + special cases. **Not** 1:1 per SQL function.

### Core Chain-Data RPCs

```proto
service BlockExplorer {
  // Blocks
  rpc GetBlock(GetBlockRequest) returns (Block);
  rpc GetBlocks(GetBlocksRequest) returns (GetBlocksResponse);
  rpc GetLatestBlockNumber(Empty) returns (GetLatestBlockNumberResponse);

  // Transactions
  rpc GetTransaction(GetTransactionRequest) returns (Transaction);
  rpc GetTransactions(GetTransactionsRequest) returns (GetTransactionsResponse);
  rpc GetTransactionsByBlock(GetTransactionsByBlockRequest) returns (GetTransactionsResponse);
  rpc GetTransactionsByAddress(GetTransactionsByAddressRequest) returns (GetTransactionsResponse);

  // Logs
  rpc GetLogsByTransaction(GetLogsByTransactionRequest) returns (GetLogsResponse);
  rpc GetLogsByAddress(GetLogsByAddressRequest) returns (GetLogsResponse);
  rpc GetLogs(GetLogsRequest) returns (GetLogsResponse); // Multi-filter: address + topic0 + blockRange

  // Tokens & Transfers
  rpc GetToken(GetTokenRequest) returns (Token);
  rpc GetTokens(GetTokensRequest) returns (GetTokensResponse);
  rpc GetTokenTransfers(GetTokenTransfersRequest) returns (GetTokenTransfersResponse);
  rpc GetTokenHolders(GetTokenHoldersRequest) returns (GetTokenHoldersResponse);

  // Addresses
  rpc GetAddress(GetAddressRequest) returns (AddressStats); // Includes is_contract, tx_counts
  rpc GetAddresses(GetAddressesRequest) returns (GetAddressesResponse); // Paginated top accounts
  rpc GetTokenBalances(GetTokenBalancesRequest) returns (GetTokenBalancesResponse);

  // Contracts
  rpc GetContract(GetContractRequest) returns (Contract);

  // Internal Transactions
  rpc GetInternalTransactionsByTx(GetInternalTransactionsByTxRequest) returns (GetInternalTransactionsResponse);
  rpc GetInternalTransactionsByAddress(GetInternalTransactionsByAddressRequest) returns (GetInternalTransactionsResponse);

  // OP Stack Deposits
  rpc GetOPDeposit(GetOPDepositRequest) returns (OPDeposit);

  // Search & Analytics
  rpc SearchSuggestions(SearchSuggestionsRequest) returns (SearchSuggestionsResponse);
  rpc GetChainStats(Empty) returns (ChainStats);
  rpc GetTransactionHistory(GetTransactionHistoryRequest) returns (GetTransactionHistoryResponse);
  rpc GetGasPrices(GetGasPricesRequest) returns (GetGasPricesResponse);
  rpc GetDailyStats(GetDailyStatsRequest) returns (GetDailyStatsResponse);

  // Sync & Status
  rpc GetSyncStatus(Empty) returns (SyncStatus);
}
```

### Overlaps (Same Query, Both API & Public-API)

These should be **single gRPC method** exposed to both authenticated (`api`) and public (`public-api`) callers:

- **GetBlock**: api/handlers.go:93 + publicapi/handlers.go:145
- **GetBlocks**: api/handlers.go:66 + publicapi/handlers.go:118
- **GetTransaction**: api/handlers.go:215 + publicapi/handlers.go:215
- **GetTransactions**: api/handlers.go:154 + publicapi/handlers.go:179
- **GetTransactionsByBlock**: api/handlers.go:121 + publicapi/handlers.go (implied in block endpoint)
- **GetTransactionsByAddress**: api/handlers.go:311 + publicapi/handlers.go:338
- **GetLogsByTransaction**: api/handlers.go:417 + publicapi/handlers.go:245
- **GetLogsByAddress**: api/handlers.go:1047 + publicapi/handlers.go:431
- **GetToken**: api/handlers.go:744 + publicapi/handlers.go:498
- **GetTokens**: api/handlers.go:700 + publicapi/handlers.go:479
- **GetTokenTransfers**: api/handlers.go:816 + publicapi/handlers.go:544
- **GetTokenHolders**: api/handlers.go:765 + publicapi/handlers.go:519
- **GetAddress**: api/handlers.go:262 + publicapi/handlers.go:300
- **GetAddresses**: api/handlers.go:450 + publicapi/handlers.go:591
- **GetTokenBalances**: api/handlers.go:1097 + publicapi/handlers.go:385
- **GetContract**: api/handlers.go:328 + publicapi/handlers.go:456
- **GetChainStats**: api/handlers.go:24 + publicapi/handlers.go:690
- **GetSyncStatus**: api/handlers.go:1026 + publicapi/handlers.go:752
- **GetTransactionHistory**: api/handlers.go:486 + publicapi/handlers.go:698
- **SearchSuggestions**: api/handlers.go:517 + publicapi/handlers.go:665
- **GetGasPrices**: api/handlers.go:51 + publicapi/handlers.go:729

**API-only methods** (no public-api equivalent):
- GetInternalTransactionsByBlock, GetInternalTransactionsByTx, GetInternalTransactionsByAddress (all at api/handlers.go)
- GetAddressTransfers (api/handlers.go:376) — no public-api version
- UpdateContractABI (POST, api/handlers.go:341)
- VerifyContract (POST, api/handlers.go:1373)
- GetLogs (advanced filter, api/handlers.go:978) — public-api has GetAddressLogs + GetLogsByTransaction only

---

## Implementation Notes for gRPC Transition

1. **Cursor Pagination:** Migrate from `OFFSET/LIMIT` to block-number or timestamp cursors (queries already support `beforeBlock` parameter).
2. **Address Visibility:** Privacy service integration (in `privacy/client.go`) does **not** touch postgres — it's an external redaction layer. Keep as HTTP middleware.
3. **Categories Join:** `GetTransactionWithCategories` (queries.go:315) joins on a tx_type column; ensure categorization logic is replicated in gRPC service if needed.
4. **Address Stats Hot Path:** `RebuildAddressStats` is a one-time post-backfill operation; cache the full stats table after, don't rebuild per-query.
5. **Gas Tracker Caching:** `GetGasPercentiles` is already cached in `gas/tracker.go` (30s TTL); move this caching to the gRPC service layer.
6. **Missing Ranges Infrastructure:** Indexer-internal tables (`indexer_progress`, `missing_block_ranges`) should **not** be exposed via gRPC; they're internal state.

---

## Exclusions (Out of Scope)

- Auth tables: `users`, `sessions`, `api_keys` (in `auth/` package, no direct SQL queries found)
- Config/metadata tables: `settings`, `feature_flags` (not in scope)
- Privacy service: External HTTP calls to privacy-proxy (not postgres writes to block-explorer)
- Verifier package: No direct SQL queries found; compilation/verification is stateless

---

## Files Scanned

- `/Users/blade/work/software/block-explorer/backend/internal/db/queries.go` (1648 lines, 60+ functions)
- `/Users/blade/work/software/block-explorer/backend/internal/db/batch.go` (298 lines, batch writes + RebuildAddressStats)
- `/Users/blade/work/software/block-explorer/backend/internal/db/op_deposits.go` (68 lines, OP deposit reads/writes)
- `/Users/blade/work/software/block-explorer/backend/internal/db/missing_ranges.go` (245 lines, internal indexer state)
- `/Users/blade/work/software/block-explorer/backend/internal/api/handlers.go` (1600+ lines, consumer endpoints)
- `/Users/blade/work/software/block-explorer/backend/internal/publicapi/handlers.go` (900+ lines, public endpoints)
- `/Users/blade/work/software/block-explorer/backend/internal/gas/tracker.go` (187 lines, caching wrapper)
- `/Users/blade/work/software/block-explorer/backend/internal/opdeposits/fetcher.go` (226 lines, indexer caller)
- `/Users/blade/work/software/block-explorer/backend/internal/indexer/*.go` (various, batch insert callers)

---

**End of Audit. Ready for RD-855 Phase 1: gRPC schema design.**
