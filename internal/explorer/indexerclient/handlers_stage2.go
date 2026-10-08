// Stage 2 method overrides. These ride on top of the stage-1 handlers.go
// point reads and add cursor feeds + subresource lists + browse endpoints.
//
// Not yet ported (still delegated to embedded *Store via method fallthrough):
//   - *Filtered variants — they require post-fetch visibility filtering,
//     coming in stage 2b.
//   - SetContractABI — write path; explicitly not exposed by the indexer.
//   - GetIndexerProgress — indexer-internal state; no gRPC surface for it.

package indexerclient

import (
	"context"

	indexerv1 "privacy-proxy/gen/go/chain_indexer/v1"
	"privacy-proxy/internal/explorer"
)

// cursor encoding -- we reuse the opaque cursor produced by the indexer and
// propagate it through as `beforeBlock` on subsequent requests.
//
// The legacy *Store signature takes a *uint64 beforeBlock. We translate:
//   - first page   : page cursor empty, no beforeBlock
//   - later pages  : encode the requested beforeBlock into a request cursor
// and always ignore the server's returned cursor — the legacy API contract
// returns at most `limit` rows and the caller reissues with a new
// beforeBlock. That's semantics-preserving.

// pageRequest returns a PageRequest carrying only the page size. Subsequent
// pages on cursor feeds are addressed through method-specific fields
// (before_number on ListBlocks, block_range.to_block on ListTransactions etc.)
// rather than cursors, matching the legacy *Store signature which takes
// *uint64 beforeBlock.
func pageRequest(limit int) *indexerv1.PageRequest {
	return &indexerv1.PageRequest{PageSize: int32(limit)}
}

// ----- Blocks feed -----

func (b *Backend) GetBlocks(ctx context.Context, limit int, beforeBlock *uint64) ([]explorer.Block, error) {
	req := &indexerv1.ListBlocksRequest{Page: pageRequest(limit)}
	if beforeBlock != nil {
		req.BeforeNumber = *beforeBlock
	}
	resp, err := b.client.ListBlocks(ctx, req)
	if err != nil {
		return nil, err
	}
	return mapBlocks(resp.GetBlocks()), nil
}

// ----- Transactions feed -----

func (b *Backend) GetTransactions(ctx context.Context, limit int, beforeBlock *uint64) ([]explorer.Transaction, error) {
	return b.listTxFeed(ctx, limit, beforeBlock)
}

// GetTransactionsWithCategories shares the same gRPC call; the indexer
// returns categories materialized on every transaction row.
func (b *Backend) GetTransactionsWithCategories(ctx context.Context, limit int, beforeBlock *uint64) ([]explorer.Transaction, error) {
	return b.listTxFeed(ctx, limit, beforeBlock)
}

func (b *Backend) listTxFeed(ctx context.Context, limit int, beforeBlock *uint64) ([]explorer.Transaction, error) {
	req := &indexerv1.ListTransactionsRequest{
		Page: &indexerv1.PageRequest{PageSize: int32(limit)},
	}
	if beforeBlock != nil {
		req.BlockRange = &indexerv1.BlockRange{ToBlock: *beforeBlock}
	}
	resp, err := b.client.ListTransactions(ctx, req)
	if err != nil {
		return nil, err
	}
	return mapTransactions(resp.GetTransactions()), nil
}

// GetTransactionsByAddress — indexer ListTransactions with address filter.
// RD-1149: the indexer's opaque cursor is round-tripped verbatim, so paging
// resumes on the exact (block, tx_index) keyset position — bare block-range
// paging skipped a boundary block's remaining rows, and the indexer clamps
// PageSize (~100), so next_cursor is the only reliable continuation signal.
// The legacy BeforeBlock and the proto's block_range.to_block are both
// exclusive (BlockRange is half-open; 0 = unbounded), so before=N passes
// through unchanged — except before=0, which means "nothing" and must
// short-circuit (to_block=0 would mean unbounded and restart the feed).
func (b *Backend) GetTransactionsByAddress(ctx context.Context, address string, limit int, page explorer.AddressPage) ([]explorer.Transaction, string, error) {
	if page.Cursor == "" && page.BeforeBlock != nil && *page.BeforeBlock == 0 {
		return nil, "", nil
	}
	req := &indexerv1.ListTransactionsRequest{
		Page: &indexerv1.PageRequest{PageSize: int32(limit), Cursor: page.Cursor},
		Filter: &indexerv1.ListTransactionsRequest_ByAddress{
			ByAddress: &indexerv1.ListTransactionsRequest_AddressFilter{
				Address: address,
			},
		},
	}
	if page.Cursor == "" && page.BeforeBlock != nil {
		req.BlockRange = &indexerv1.BlockRange{ToBlock: *page.BeforeBlock}
	}
	resp, err := b.client.ListTransactions(ctx, req)
	if err != nil {
		return nil, "", err
	}
	return mapTransactions(resp.GetTransactions()), resp.GetPage().GetNextCursor(), nil
}

// GetTransactionsByBlock — indexer ListTransactions with block filter.
func (b *Backend) GetTransactionsByBlock(ctx context.Context, blockNumber uint64) ([]explorer.Transaction, error) {
	req := &indexerv1.ListTransactionsRequest{
		Filter: &indexerv1.ListTransactionsRequest_ByBlock{
			ByBlock: &indexerv1.ListTransactionsRequest_BlockFilter{
				Selector: &indexerv1.ListTransactionsRequest_BlockFilter_Number{Number: blockNumber},
			},
		},
	}
	resp, err := b.client.ListTransactions(ctx, req)
	if err != nil {
		return nil, err
	}
	return mapTransactions(resp.GetTransactions()), nil
}

// ----- Logs -----

func (b *Backend) GetLogsByTransaction(ctx context.Context, txHash string) ([]explorer.Log, error) {
	req := &indexerv1.ListLogsRequest{ByTxHash: txHash}
	resp, err := b.client.ListLogs(ctx, req)
	if err != nil {
		return nil, err
	}
	return mapLogs(resp.GetLogs()), nil
}

var _ explorer.TxDataBatchResolver = (*Backend)(nil)

// GetLogsByTransactions keeps the strict profile's batched log lookup on the
// indexer (explorer.TxDataBatchResolver): without this override the embedded
// SQL fallback store's method would be promoted and answer from a different
// data source than GetLogsByTransaction. The indexer API takes one hash per
// ListLogs call.
func (b *Backend) GetLogsByTransactions(ctx context.Context, txHashes []string) ([]explorer.Log, error) {
	var out []explorer.Log
	for _, h := range txHashes {
		logs, err := b.GetLogsByTransaction(ctx, h)
		if err != nil {
			return nil, err
		}
		out = append(out, logs...)
	}
	return out, nil
}

// GetTransactionsByHashes keeps the strict profile's batched parent lookup on
// the indexer, for the same reason as GetLogsByTransactions. Unknown hashes
// are absent from the result.
func (b *Backend) GetTransactionsByHashes(ctx context.Context, hashes []string) ([]explorer.Transaction, error) {
	var out []explorer.Transaction
	for _, h := range hashes {
		tx, err := b.GetTransaction(ctx, h)
		if err != nil {
			return nil, err
		}
		if tx != nil {
			out = append(out, *tx)
		}
	}
	return out, nil
}

func (b *Backend) GetLogsByAddress(ctx context.Context, address string, limit int, offset int) ([]explorer.Log, int64, error) {
	req := &indexerv1.ListLogsRequest{
		ByAddress: address,
		Page:      &indexerv1.PageRequest{PageSize: int32(limit)},
	}
	resp, err := b.client.ListLogs(ctx, req)
	if err != nil {
		return nil, 0, err
	}
	logs := mapLogs(resp.GetLogs())
	// Indexer API has no total; return 0 for callers that only use the rows.
	// Legacy *Store returns a real total, which matters for the offset UI —
	// this is a known behavioral gap recorded in the handoff notes; consumers
	// needing a real total should fall back to the SQL path until the indexer
	// exposes counts.
	return logs, int64(len(logs)), nil
}

func (b *Backend) GetLogs(ctx context.Context, address *string, topic0 *string, fromBlock *uint64, toBlock *uint64, limit int) ([]explorer.Log, error) {
	req := &indexerv1.ListLogsRequest{
		Page: &indexerv1.PageRequest{PageSize: int32(limit)},
	}
	if address != nil {
		req.ByAddress = *address
	}
	if topic0 != nil {
		req.Topic0 = *topic0
	}
	if fromBlock != nil || toBlock != nil {
		br := &indexerv1.BlockRange{}
		if fromBlock != nil {
			br.FromBlock = *fromBlock
		}
		if toBlock != nil {
			br.ToBlock = *toBlock
		}
		req.BlockRange = br
	}
	resp, err := b.client.ListLogs(ctx, req)
	if err != nil {
		return nil, err
	}
	return mapLogs(resp.GetLogs()), nil
}

// ----- Token transfers -----

func (b *Backend) GetTransfersByTransaction(ctx context.Context, txHash string) ([]explorer.TokenTransfer, error) {
	resp, err := b.client.ListTokenTransfers(ctx, &indexerv1.ListTokenTransfersRequest{ByTxHash: txHash})
	if err != nil {
		return nil, err
	}
	return mapTokenTransfers(resp.GetTransfers()), nil
}

// GetTransfersByAddress — RD-1149 cursor round-trip; see
// GetTransactionsByAddress for the rationale (incl. the exclusive
// to_block passthrough and the before=0 short-circuit).
func (b *Backend) GetTransfersByAddress(ctx context.Context, address string, limit int, page explorer.AddressPage) ([]explorer.TokenTransfer, string, error) {
	if page.Cursor == "" && page.BeforeBlock != nil && *page.BeforeBlock == 0 {
		return nil, "", nil
	}
	req := &indexerv1.ListTokenTransfersRequest{
		ByAddress: address,
		Page:      &indexerv1.PageRequest{PageSize: int32(limit), Cursor: page.Cursor},
	}
	if page.Cursor == "" && page.BeforeBlock != nil {
		req.BlockRange = &indexerv1.BlockRange{ToBlock: *page.BeforeBlock}
	}
	resp, err := b.client.ListTokenTransfers(ctx, req)
	if err != nil {
		return nil, "", err
	}
	return mapTokenTransfers(resp.GetTransfers()), resp.GetPage().GetNextCursor(), nil
}

func (b *Backend) GetTransfersByToken(ctx context.Context, tokenAddress string, limit int, offset int) ([]explorer.TokenTransfer, int64, error) {
	resp, err := b.client.ListTokenTransfers(ctx, &indexerv1.ListTokenTransfersRequest{
		ByToken: tokenAddress,
		Page:    &indexerv1.PageRequest{PageSize: int32(limit)},
	})
	if err != nil {
		return nil, 0, err
	}
	transfers := mapTokenTransfers(resp.GetTransfers())
	return transfers, int64(len(transfers)), nil
}

func (b *Backend) GetAllTransfers(ctx context.Context, limit int, offset int) ([]explorer.TokenTransfer, int64, error) {
	// Indexer requires at least one filter on ListTokenTransfers. "All
	// transfers" isn't a supported indexer use case — legacy SQL behavior
	// only; delegate to *Store.
	return b.Store.GetAllTransfers(ctx, limit, offset)
}

// ----- Internal transactions -----

func (b *Backend) GetInternalTransactionsByTx(ctx context.Context, txHash string) ([]explorer.InternalTransaction, error) {
	resp, err := b.client.ListInternalTransactions(ctx, &indexerv1.ListInternalTransactionsRequest{
		ByTxHash: txHash,
	})
	if err != nil {
		return nil, err
	}
	return mapInternalTxs(resp.GetInternalTransactions()), nil
}

func (b *Backend) GetInternalTransactionsByAddress(ctx context.Context, address string, limit int, offset int) ([]explorer.InternalTransaction, int64, error) {
	resp, err := b.client.ListInternalTransactions(ctx, &indexerv1.ListInternalTransactionsRequest{
		ByAddress: address,
		Page:      &indexerv1.PageRequest{PageSize: int32(limit)},
	})
	if err != nil {
		return nil, 0, err
	}
	rows := mapInternalTxs(resp.GetInternalTransactions())
	return rows, int64(len(rows)), nil
}

func (b *Backend) GetInternalTransactionsByBlock(ctx context.Context, blockNumber uint64) ([]explorer.InternalTransaction, error) {
	resp, err := b.client.ListInternalTransactions(ctx, &indexerv1.ListInternalTransactionsRequest{
		ByBlock: &indexerv1.ListInternalTransactionsRequest_BlockFilter{
			Selector: &indexerv1.ListInternalTransactionsRequest_BlockFilter_Number{Number: blockNumber},
		},
	})
	if err != nil {
		return nil, err
	}
	return mapInternalTxs(resp.GetInternalTransactions()), nil
}

// ----- Tokens -----

func (b *Backend) GetToken(ctx context.Context, address string) (*explorer.Token, error) {
	resp, err := b.client.GetToken(ctx, &indexerv1.GetTokenRequest{Address: address})
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return mapToken(resp), nil
}

func (b *Backend) GetTokens(ctx context.Context, limit int, offset int, tokenType string) ([]explorer.Token, int64, error) {
	page := offset/limit + 1
	var tt indexerv1.TokenType
	switch tokenType {
	case "ERC20":
		tt = indexerv1.TokenType_TOKEN_TYPE_ERC20
	case "ERC721":
		tt = indexerv1.TokenType_TOKEN_TYPE_ERC721
	case "ERC1155":
		tt = indexerv1.TokenType_TOKEN_TYPE_ERC1155
	}
	resp, err := b.client.ListTokens(ctx, &indexerv1.ListTokensRequest{
		Page:      &indexerv1.OffsetPageRequest{Page: int32(page), PageSize: int32(limit)},
		TokenType: tt,
	})
	if err != nil {
		return nil, 0, err
	}
	return mapTokens(resp.GetTokens()), resp.GetPage().GetTotalItems(), nil
}

func (b *Backend) GetTokenHolders(ctx context.Context, tokenAddress string, limit int, offset int) ([]explorer.TokenHolder, int64, error) {
	page := offset/limit + 1
	resp, err := b.client.ListTokenHolders(ctx, &indexerv1.ListTokenHoldersRequest{
		TokenAddress: tokenAddress,
		Page:         &indexerv1.OffsetPageRequest{Page: int32(page), PageSize: int32(limit)},
	})
	if err != nil {
		return nil, 0, err
	}
	return mapTokenHolders(resp.GetHolders()), resp.GetPage().GetTotalItems(), nil
}

func (b *Backend) GetTokenBalances(ctx context.Context, address string) ([]explorer.Balance, error) {
	resp, err := b.client.ListTokenBalances(ctx, &indexerv1.ListTokenBalancesRequest{Address: address})
	if err != nil {
		return nil, err
	}
	return mapBalances(resp.GetBalances()), nil
}

// ----- Contracts -----

func (b *Backend) GetContract(ctx context.Context, address string) (*explorer.Contract, error) {
	// The indexer returns chain-facts-only contract data. If the caller needs
	// verification metadata (ABI, source, compiler version), the SQL store
	// provides it — and SetContractABI (the write path) still hits SQL. This
	// handler returns the indexer's lean view; consumers can merge the SQL
	// fields on top if they need the full shape.
	resp, err := b.client.GetContract(ctx, &indexerv1.GetContractRequest{Address: address})
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return mapContract(resp), nil
}

func (b *Backend) IsContract(ctx context.Context, address string) (bool, error) {
	addr, err := b.client.GetAddress(ctx, &indexerv1.GetAddressRequest{Address: address})
	if err != nil {
		if isNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return addr.GetIsContract(), nil
}

// ----- Accounts / search / history -----

func (b *Backend) GetAccountsPaginated(ctx context.Context, page, pageSize int) ([]explorer.AddressStats, int64, error) {
	resp, err := b.client.ListAddresses(ctx, &indexerv1.ListAddressesRequest{
		Page: &indexerv1.OffsetPageRequest{Page: int32(page), PageSize: int32(pageSize)},
	})
	if err != nil {
		return nil, 0, err
	}
	return mapAccounts(resp.GetAddresses()), resp.GetPage().GetTotalItems(), nil
}

func (b *Backend) SearchSuggestions(ctx context.Context, query string, limit int) ([]explorer.SearchSuggestion, error) {
	resp, err := b.client.Search(ctx, &indexerv1.SearchRequest{
		Query:        query,
		LimitPerKind: uint32(limit),
	})
	if err != nil {
		return nil, err
	}
	return mapSearchResults(resp), nil
}

func (b *Backend) GetTransactionHistory(ctx context.Context, intervalSeconds int, limit int) ([]explorer.TxHistoryPoint, error) {
	bucket := indexerv1.TimeBucket_TIME_BUCKET_HOUR
	switch {
	case intervalSeconds >= 86400*7:
		bucket = indexerv1.TimeBucket_TIME_BUCKET_WEEK
	case intervalSeconds >= 86400:
		bucket = indexerv1.TimeBucket_TIME_BUCKET_DAY
	}
	resp, err := b.client.GetTransactionHistory(ctx, &indexerv1.GetTransactionHistoryRequest{
		Bucket: bucket,
		// Range is intentionally unset here — legacy *Store took (interval,
		// limit) not a range. The indexer applies a default lookback; that's
		// a known behavioral shift and will be tightened in stage 2b.
	})
	if err != nil {
		return nil, err
	}
	pts := mapTxHistory(resp)
	if limit > 0 && len(pts) > limit {
		pts = pts[:limit]
	}
	return pts, nil
}
