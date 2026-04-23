# RD-855 Phase 0: SQL Audit Report — privacy-proxy Chain-Data Queries

## Executive Summary

Comprehensive inventory of all SQL queries accessing chain-indexed data across `internal/explorer/store.go` and `internal/server/explorer_api.go`. This audit supports future gRPC indexer API design by cataloging all current read patterns, filter modes, pagination strategies, and visibility/redaction layers.

**Scope:** Chain data only (blocks, transactions, logs, addresses, tokens, internal txs). Excluded: RBAC, compliance, disclosure, audit tables.

**Key Findings:**
- 47 distinct query methods in Store
- 5 primary access patterns: point-read, range-read, index-lookup, aggregate, search
- Visibility filtering applied at SQL layer (blocklist/allowlist modes) and in Go (redaction)
- Cursor-based and offset-based pagination coexist
- Multiple category-enrichment variants (coins/contracts/token-transfers computed in-query)

---

## Access Pattern Catalog

### 1. POINT-READ (by hash/address/number)

| Name | File:Line | Consumer | Fields | Filters | Hot? | Redact |
|------|-----------|----------|--------|---------|------|--------|
| GetBlock | store.go:155 | /blocks/:number | block header (18 cols) | WHERE number=$1 | Yes | SQL+Go |
| GetBlockByHash | store.go:169 | /blocks/hash/:hash | block header (18 cols) | WHERE hash=$1 | Rare | SQL+Go |
| GetTransaction | store.go:269 | /transactions/:hash | tx fields (18 cols) | WHERE hash=$1 | Yes | SQL+Go |
| GetTransactionWithCategories | store.go:795 | /transactions/:hash (cat variant) | tx+4 category cols | WHERE hash=$1 JOIN blocks | Yes | SQL+Go |
| GetSyncStatus | store.go:369 | /internal/stats | last_block, syncing, timestamp | ORDER BY id DESC LIMIT 1 | Rare | None |
| GetAddressStats | store.go:381 | /addresses/:addr/stats | tx_count, token_count, first_seen, is_contract | WHERE address=$1 | Very High | SQL+Go |
| IsContract | store.go:992 | contract detection | boolean + address_stats fallback | contracts + address_stats | High | None |
| GetContract | store.go:970 | contract details | bytecode, ABI, creator, verified flag | WHERE address=$1 | Medium | None |
| GetToken | store.go:1051 | /tokens/:address | symbol, supply, holder_count, price | WHERE address=$1 | Medium | None |

**Redaction Strategy:** Point-reads apply visibility filters (block hidden addresses) in Go layer post-fetch, except transaction categories which are computed inline in SQL.

---

### 2. RANGE-READ (cursor/limit pagination)

| Name | File:Line | Consumer | Query | Pagination | Hot? | Redact |
|------|-----------|----------|-------|------------|------|--------|
| GetBlocks | store.go:183 | /blocks?before=N | SELECT * FROM blocks | cursor: number < $1 LIMIT | Yes | SQL+Go |
| GetBlocksFiltered | store.go:216 | /blocks (filtered) | blocks + filtered tx count | cursor + visibility clause | Yes | SQL+Go |
| GetTransactions | store.go:291 | /transactions | SELECT * FROM transactions JOIN blocks | cursor: block DESC, tx_index DESC | Yes | SQL+Go |
| GetTransactionsFiltered | store.go:656 | /transactions (filtered) | same + visibility WHERE clause | cursor + vis filter | Yes | SQL+Go |
| GetTransactionsWithCategories | store.go:525 | /transactions (cat variant) | tx + coin/contract/token categories | cursor + category subqueries | Yes | SQL+Go |
| GetTransactionsWithCategoriesFiltered | store.go:726 | /transactions (cat+filter) | all above combined | cursor + vis + categories | Yes | SQL+Go |
| GetTransactionsByAddress | store.go:320 | /addresses/:addr/transactions | tx WHERE (from OR to)=addr | cursor + address filter | High | SQL+Go |
| GetTransactionsByBlock | store.go:432 | /blocks/:number/transactions | tx WHERE block=N | ORDER tx_index | Medium | SQL+Go |
| GetTransfersByAddress | store.go:849 | /addresses/:addr/transfers | token_transfers WHERE (from OR to) | cursor + address | Medium | SQL+Go |
| GetTransfersByToken | store.go:1133 | token transfers paginated | token_transfers WHERE token_addr | offset: LIMIT/OFFSET | Medium | None |
| GetAllTransfers | store.go:1157 | all token transfers | token_transfers no filter | offset: LIMIT/OFFSET | Low | None |

**Pagination Strategy:** Cursor-based (block_number DESC, field ASC) preferred for real-time views; offset-based (LIMIT/OFFSET) for bounded token/account lists.

---

### 3. INDEX-LOOKUP (aggregates, counts, stats)

| Name | File:Line | Consumer | Query | Pattern | Hot? | Redact |
|------|-----------|----------|-------|---------|------|--------|
| GetChainStats | store.go:37 | /stats | COUNT(*) x4 tables + AVG window | multiple QueryRow calls | Yes | SQL (visibility-aware variant) |
| GetChainStatsFiltered | store.go:71 | /stats (filtered) | COUNT(*) FROM txs WHERE vis_clause | visibility filter | Yes | SQL |
| GetBlockTransactionCountFiltered | store.go:139 | block tx counts | COUNT(*) WHERE block=$1 AND vis_clause | per-block visibility | High | SQL |
| GetAddressTransactionCountFiltered | store.go:398 | addr tx counts | COUNT(*) WHERE (from OR to)=$1 AND vis_clause | per-address visibility | High | SQL |
| GetTransactionHistoryFiltered | store.go:103 | /stats/tx-history | time-bucket histogram with visibility | GROUP BY (timestamp/interval) | High | SQL |
| GetLatestBlockNumber | store.go:448 | block sync status | MAX(number) FROM blocks | single scalar | Very High | None |

**Optimization:** Window functions (LAG) for time-series; array aggregation for batch counts; pre-computed address_stats table avoids per-tx scans.

---

### 4. SPECIALIZED (internal txs, logs, categories)

| Name | File:Line | Consumer | Query | Pattern | Hot? | Redact |
|------|-----------|----------|-------|---------|------|--------|
| GetInternalTransactionsByTx | store.go:419 | /tx/:hash/internal | internal_txs WHERE tx_hash=$1 | point-to-collection | Medium | None |
| GetInternalTransactionsByAddress | store.go:877 | /addr/internal-txs | internal_txs WHERE (from OR to)=$1 | offset paginated | Low | None |
| GetInternalTransactionsByBlock | store.go:1320 | /blocks/:number/internal | internal_txs WHERE block=$1 | range (all in block) | Medium | None |
| GetLogsByTransaction | store.go:837 | /tx/:hash/logs | logs WHERE tx_hash=$1 | point-to-collection | Medium | None |
| GetLogsByAddress | store.go:904 | /addr/logs | logs WHERE address=$1 | offset paginated | Low | None |
| GetLogs | store.go:928 | /logs (advanced filter) | logs WHERE addr/topic/block-range | dynamic WHERE builder | Low | None |
| GetTransfersByTransaction | store.go:824 | /tx/:hash/transfers | token_transfers WHERE tx_hash=$1 | point-to-collection | Medium | None |
| GetTokenHolders | store.go:1068 | /tokens/:addr/holders | token_balances + metadata JOINs | offset paginated | Medium | None |
| GetTokenBalances | store.go:1108 | /addr/balances | token_balances WHERE addr=$1 | all (no pagination) | Low | None |

**Pattern:** Subresources (txs of a tx, logs of an address) use point-or-address lookup + join on logs/transfers table.

---

### 5. SEARCH

| Name | File:Line | Consumer | Query | Pattern | Hot? |
|------|-----------|----------|-------|---------|------|
| SearchSuggestions | store.go:1208 | autocomplete | 3-part UNION LIKE prefix queries | tx hash, address, block number | Medium |

**Implementation:** Sequential LIKE queries; early exit when limit reached. Topics not indexed.

---

### 6. LIST/PAGINATED (accounts, tokens)

| Name | File:Line | Consumer | Query | Pagination | Hot? |
|------|-----------|----------|-------|------------|------|
| GetAccountsPaginated | store.go:1179 | /accounts | address_stats ORDER BY tx_count | offset: page/pageSize | Medium |
| GetTokens | store.go:1019 | /tokens | tokens (filtered by type) | offset: LIMIT/OFFSET | Medium |
| GetTransactionsPaginated | store.go:455 | /transactions (offset variant) | transactions with offset | offset: (page-1)*size | Low |
| GetTransactionsPaginatedWithCategories | store.go:554 | /transactions (cat+offset) | txs + categories inline | offset: (page-1)*size | Low |
| GetTransactionsPaginatedFiltered | store.go:693 | /transactions (filter+offset) | txs + visibility filter | offset + vis clause | Low |
| GetTransactionsPaginatedWithCategoriesFiltered | store.go:763 | /transactions (cat+filter+offset) | all combined | offset + vis + categories | Low |

**Pagination Pattern:** Offset-based for list views (account/token browsing); cursor-based for real-time transaction feeds.

---

## Visibility & Redaction Strategy

### Filter Types

**1. VisibilityFilter (SQL-layer filtering)**
- **Blocklist mode:** Exclude transactions where both from AND to are hidden, or contract creation (to IS NULL) with from hidden.
- **Allowlist mode:** Only show transactions where at least one participant in VisibleAddresses, or hash in VisibleTxHashes.
- **VisibleTxHashes override:** Force-include specific tx hashes (for "visible_to" disclosure grants).

Applied in: GetChainStatsFiltered, GetBlockTransactionCountFiltered, GetAddressTransactionCountFiltered, GetTransactionHistoryFiltered, GetTransactionsFiltered, GetTransactionsPaginatedFiltered, GetTransactionsWithCategoriesFiltered, GetTransactionsPaginatedWithCategoriesFiltered.

**2. Redaction Engine (Go-layer post-processing)**
- Masks addresses (pseudonym, redacted, hidden) based on viewer DID and grant scope.
- Hides value/gas fields for non-full disclosures.
- Applied in API handlers before JSON response.

---

## N+1 Risk Assessment

| Query | Risk | Mitigation |
|-------|------|-----------|
| GetBlocksFiltered + GetBlockTransactionCountFiltered loop | **High** | Batch count query (ANY array + GROUP BY) avoids 1 query per block |
| GetTransactionsByAddress (called per-address) | **Medium** | Filtered scan; caller must limit addresses |
| GetInternalTransactionsByAddress | **Medium** | Offset paginated; no hot path in single request |
| GetLogsByAddress | **Medium** | Offset paginated; scoped to single address |
| GetTokenHolders (implicit in detail page) | **Low** | Offset paginated |
| GetTransactionWithCategories (subquery per field) | **High** | 4 inline EXISTS subqueries; not batched. Consider materialized view. |

**Hot Paths (every page load):**
- GetAddressStats (address detail page)
- GetChainStats (dashboard)
- GetTransactions (feed view)
- GetBlock (block detail)
- GetTransaction (tx detail)

---

## Candidate gRPC API Methods

Proposed RPC surface for future indexer API (one per access pattern):

```protobuf
// Point-read endpoints
rpc GetBlock(BlockRequest) returns (BlockResponse);
rpc GetTransaction(TransactionRequest) returns (TransactionResponse);
rpc GetAddressStats(AddressRequest) returns (AddressStatsResponse);
rpc GetContract(AddressRequest) returns (ContractResponse);
rpc GetToken(AddressRequest) returns (TokenResponse);

// Range-read endpoints (cursor pagination)
rpc GetBlocks(BlocksRequest) returns (BlocksResponse);
rpc GetTransactions(TransactionsRequest) returns (TransactionsResponse);
rpc GetTransactionsByAddress(AddressTxRequest) returns (TransactionsResponse);
rpc GetTransactionsByBlock(BlockTxRequest) returns (TransactionsResponse);

// Subresource collections
rpc GetInternalTransactions(TransactionRequest) returns (InternalTxResponse);
rpc GetLogs(LogsRequest) returns (LogsResponse);
rpc GetTokenTransfers(TransactionRequest) returns (TokenTransfersResponse);

// Aggregates
rpc GetChainStats(StatsRequest) returns (StatsResponse);
rpc GetTransactionHistory(HistoryRequest) returns (HistoryResponse);

// List/search
rpc SearchSuggestions(SearchRequest) returns (SearchResponse);
rpc GetAccounts(PageRequest) returns (AccountsResponse);
rpc GetTokens(PageRequest) returns (TokensResponse);

// Category-enriched variants
rpc GetTransactionsWithCategories(TransactionsRequest) returns (TransactionsResponse);

// Visibility-filtered variants
rpc GetTransactionsFiltered(FilteredTxRequest) returns (TransactionsResponse);
rpc GetStatsFiltered(FilteredStatsRequest) returns (StatsResponse);
```

**Design Notes:**
- Unify pagination: cursor-based for feed (offset stored in client); offset-based for bounded lists.
- Category computation: push to indexer or compute server-side at API gateway.
- Visibility filtering: move allowlist/blocklist logic to gateway; indexer returns all data with visibility markers.
- Batch operations: GetBlocksFiltered shows batch visibility count pattern—expose as BatchGetBlockTransactionCounts RPC.

---

## Table Dependencies

| Table | Read-Only Methods | Indices Used |
|-------|------------------|--------------|
| blocks | GetBlock, GetBlocks, GetChainStats, GetLatestBlockNumber, GetBlocksFiltered | number (PK), hash |
| transactions | GetTransaction, GetTransactions, GetTransactionsByAddress, GetTransactionsByBlock, GetChainStatsFiltered, all filtered variants | hash (PK), block_number, (from_address, to_address) |
| address_stats | GetAddressStats, GetAccounts, GetChainStats | address (PK), tx_count (sort), is_contract |
| internal_transactions | GetInternalTransactionsByTx, GetInternalTransactionsByAddress, GetInternalTransactionsByBlock | tx_hash, block_number, (from_address, to_address) |
| logs | GetLogsByTransaction, GetLogsByAddress, GetLogs | tx_hash, address, (topic0, block_number) |
| token_transfers | GetTransfersByTransaction, GetTransfersByAddress, GetTransfersByToken, GetAllTransfers | tx_hash, block_number, (from_address, to_address, token_address) |
| tokens | GetToken, GetTokens, GetTokenHolders (JOIN) | address (PK), token_type |
| token_balances | GetTokenBalances, GetTokenHolders | (address, token_address) |
| contracts | GetContract, IsContract (fallback), txCategorySelectCols EXISTS | address (PK) |
| sync_status | GetSyncStatus | id (PK) |

---

## Summary Statistics

- **Total store methods:** 47
- **Lines of SQL:** ~1400 (including category subqueries)
- **JOINs:** blocks ↔ transactions (most common for tx details)
- **Subqueries:** 5+ (category columns, EXISTS checks, time bucketing)
- **Dynamic query building:** visibilityWhereClause, GetLogs WHERE builder
- **Batch operations:** 1 (GetBlocksFiltered batch count)
- **Missing indices?** Consider (token_address, block_number DESC) for transfer pagination.

