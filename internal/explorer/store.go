package explorer

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type Store struct {
	db *sql.DB
}

func NewStore(databaseURL string) (*Store, error) {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open explorer database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping explorer database: %w", err)
	}

	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

// Chain Stats oeprations

func (s *Store) GetChainStats(ctx context.Context) (*ChainStats, error) {
	var stats ChainStats
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM blocks").Scan(&stats.TotalBlocks)
	if err != nil {
		return nil, err
	}
	err = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM transactions").Scan(&stats.TotalTransactions)
	if err != nil {
		return nil, err
	}
	err = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM address_stats").Scan(&stats.TotalAddresses)
	if err != nil {
		return nil, err
	}
	// Count distinct token addresses from token_transfers (may be 0 if table doesn't exist)
	_ = s.db.QueryRowContext(ctx, "SELECT COUNT(DISTINCT token_address) FROM token_transfers").Scan(&stats.TotalTokens)

	// Compute average block time from the last 100 consecutive blocks
	var avgBlockTime sql.NullFloat64
	_ = s.db.QueryRowContext(ctx, `
		SELECT AVG(diff) FROM (
			SELECT timestamp - LAG(timestamp) OVER (ORDER BY number) AS diff
			FROM blocks ORDER BY number DESC LIMIT 100
		) sub WHERE diff IS NOT NULL AND diff > 0`).Scan(&avgBlockTime)
	if avgBlockTime.Valid {
		stats.AvgBlockTime = avgBlockTime.Float64
	}

	stats.PrivacyEnabled = true
	return &stats, nil
}

// GetChainStatsFiltered returns chain stats with visibility filtering.
// TotalTransactions and TotalAddresses exclude hidden/private data.
func (s *Store) GetChainStatsFiltered(ctx context.Context, filter *VisibilityFilter) (*ChainStats, error) {
	stats, err := s.GetChainStats(ctx)
	if err != nil {
		return nil, err
	}
	if !isFilterActive(filter) {
		return stats, nil
	}

	// Adjust TotalTransactions: subtract txs that would be filtered
	visClause, visArgs, _ := visibilityWhereClause(filter, 1)
	var filteredTxCount int64
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM transactions t WHERE 1=1%s", visClause)
	if err := s.db.QueryRowContext(ctx, countQuery, visArgs...).Scan(&filteredTxCount); err != nil {
		return nil, err
	}
	stats.TotalTransactions = filteredTxCount

	// Adjust TotalAddresses based on filter mode
	if filter.AllPrivate {
		stats.TotalAddresses = int64(len(filter.VisibleAddresses))
	} else {
		stats.TotalAddresses -= int64(len(filter.HiddenAddresses))
	}
	if stats.TotalAddresses < 0 {
		stats.TotalAddresses = 0
	}

	return stats, nil
}

// GetTransactionHistoryFiltered returns tx history with visibility filtering.
func (s *Store) GetTransactionHistoryFiltered(ctx context.Context, intervalSeconds int, limit int, filter *VisibilityFilter) ([]TxHistoryPoint, error) {
	if !isFilterActive(filter) {
		return s.GetTransactionHistory(ctx, intervalSeconds, limit)
	}

	visClause, visArgs, nextArg := visibilityWhereClause(filter, 1)
	intervalArg := nextArg
	limitArg := nextArg + 1
	query := fmt.Sprintf(`
		SELECT bucket, cnt FROM (
			SELECT (b.timestamp / $%d) * $%d AS bucket, COUNT(*) AS cnt
			FROM transactions t
			JOIN blocks b ON t.block_number = b.number
			WHERE 1=1%s
			GROUP BY bucket ORDER BY bucket DESC LIMIT $%d
		) sub ORDER BY bucket ASC`, intervalArg, intervalArg, visClause, limitArg)

	args := append(visArgs, intervalSeconds, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []TxHistoryPoint
	for rows.Next() {
		var p TxHistoryPoint
		if err := rows.Scan(&p.Timestamp, &p.Count); err != nil {
			return nil, err
		}
		points = append(points, p)
	}
	return points, rows.Err()
}

// GetBlockTransactionCountFiltered returns the visible tx count for a block.
func (s *Store) GetBlockTransactionCountFiltered(ctx context.Context, blockNumber uint64, filter *VisibilityFilter) (int, error) {
	if !isFilterActive(filter) {
		var count int
		err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM transactions WHERE block_number = $1", blockNumber).Scan(&count)
		return count, err
	}
	visClause, visArgs, nextArg := visibilityWhereClause(filter, 1)
	query := fmt.Sprintf("SELECT COUNT(*) FROM transactions t WHERE t.block_number = $%d%s", nextArg, visClause)
	args := append(visArgs, blockNumber)
	var count int
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&count)
	return count, err
}

// Block operations

func (s *Store) GetBlock(ctx context.Context, number uint64) (*Block, error) {
	var b Block
	err := s.db.QueryRowContext(ctx, `
		SELECT number, hash, parent_hash, timestamp, gas_used, gas_limit, base_fee_per_gas, transaction_count,
			size, difficulty, total_difficulty, nonce, miner, extra_data, state_root, transactions_root, receipts_root, created_at
		FROM blocks WHERE number = $1`, number).Scan(
		&b.Number, &b.Hash, &b.ParentHash, &b.Timestamp, &b.GasUsed, &b.GasLimit, &b.BaseFeePerGas, &b.TransactionCount,
		&b.Size, &b.Difficulty, &b.TotalDifficulty, &b.Nonce, &b.Miner, &b.ExtraData, &b.StateRoot, &b.TransactionsRoot, &b.ReceiptsRoot, &b.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &b, err
}

func (s *Store) GetBlockByHash(ctx context.Context, hash string) (*Block, error) {
	var b Block
	err := s.db.QueryRowContext(ctx, `
		SELECT number, hash, parent_hash, timestamp, gas_used, gas_limit, base_fee_per_gas, transaction_count,
			size, difficulty, total_difficulty, nonce, miner, extra_data, state_root, transactions_root, receipts_root, created_at
		FROM blocks WHERE hash = $1`, hash).Scan(
		&b.Number, &b.Hash, &b.ParentHash, &b.Timestamp, &b.GasUsed, &b.GasLimit, &b.BaseFeePerGas, &b.TransactionCount,
		&b.Size, &b.Difficulty, &b.TotalDifficulty, &b.Nonce, &b.Miner, &b.ExtraData, &b.StateRoot, &b.TransactionsRoot, &b.ReceiptsRoot, &b.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &b, err
}

func (s *Store) GetBlocks(ctx context.Context, limit int, beforeBlock *uint64) ([]Block, error) {
	var rows *sql.Rows
	var err error

	if beforeBlock != nil {
		rows, err = s.db.QueryContext(ctx, `
			SELECT number, hash, parent_hash, timestamp, gas_used, gas_limit, base_fee_per_gas, transaction_count,
				size, difficulty, total_difficulty, nonce, miner, extra_data, state_root, transactions_root, receipts_root, created_at
			FROM blocks WHERE number < $1 ORDER BY number DESC LIMIT $2`, *beforeBlock, limit)
	} else {
		rows, err = s.db.QueryContext(ctx, `
			SELECT number, hash, parent_hash, timestamp, gas_used, gas_limit, base_fee_per_gas, transaction_count,
				size, difficulty, total_difficulty, nonce, miner, extra_data, state_root, transactions_root, receipts_root, created_at
			FROM blocks ORDER BY number DESC LIMIT $1`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var blocks []Block
	for rows.Next() {
		var b Block
		if err := rows.Scan(&b.Number, &b.Hash, &b.ParentHash, &b.Timestamp, &b.GasUsed, &b.GasLimit, &b.BaseFeePerGas, &b.TransactionCount,
			&b.Size, &b.Difficulty, &b.TotalDifficulty, &b.Nonce, &b.Miner, &b.ExtraData, &b.StateRoot, &b.TransactionsRoot, &b.ReceiptsRoot, &b.CreatedAt); err != nil {
			return nil, err
		}
		blocks = append(blocks, b)
	}
	return blocks, rows.Err()
}

// GetBlocksFiltered returns blocks with their transaction counts filtered by visibility.
func (s *Store) GetBlocksFiltered(ctx context.Context, limit int, beforeBlock *uint64, filter *VisibilityFilter) ([]Block, error) {
	blocks, err := s.GetBlocks(ctx, limit, beforeBlock)
	if err != nil || len(blocks) == 0 || !isFilterActive(filter) {
		return blocks, err
	}

	var blockNums []int64
	for _, b := range blocks {
		// Only evaluate if the block has > 0 transactions initially
		if b.TransactionCount > 0 {
			blockNums = append(blockNums, int64(b.Number))
		}
	}

	if len(blockNums) == 0 {
		return blocks, nil
	}

	visClause, visArgs, nextArg := visibilityWhereClause(filter, 1)
	query := fmt.Sprintf(`
		SELECT t.block_number, COUNT(*) 
		FROM transactions t 
		WHERE t.block_number = ANY($%d)%s 
		GROUP BY t.block_number`, nextArg, visClause)

	args := append(visArgs, blockNums)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	visibleCounts := make(map[uint64]int)
	for rows.Next() {
		var num uint64
		var count int
		if err := rows.Scan(&num, &count); err != nil {
			return nil, err
		}
		visibleCounts[num] = count
	}

	for i := range blocks {
		if blocks[i].TransactionCount > 0 {
			blocks[i].TransactionCount = visibleCounts[blocks[i].Number]
		}
	}

	return blocks, rows.Err()
}

// Transaction operations

func (s *Store) GetTransaction(ctx context.Context, hash string) (*Transaction, error) {
	var tx Transaction
	var valueStr string
	err := s.db.QueryRowContext(ctx, `
		SELECT t.hash, t.block_number, t.tx_index, t.from_address, t.to_address, t.value::text,
			t.gas_used, t.gas_price, t.gas_limit, t.max_fee_per_gas, t.max_priority_fee_per_gas, t.nonce,
			t.tx_type, t.input_data, t.status, t.error, t.revert_reason, t.created_at
		FROM transactions t
		WHERE t.hash = $1`, hash).Scan(
		&tx.Hash, &tx.BlockNumber, &tx.TxIndex, &tx.From, &tx.To, &valueStr,
		&tx.GasUsed, &tx.GasPrice, &tx.GasLimit, &tx.MaxFeePerGas, &tx.MaxPriorityFeePerGas, &tx.Nonce,
		&tx.TxType, &tx.InputData, &tx.Status, &tx.Error, &tx.RevertReason, &tx.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	tx.Value = JSONString(valueStr)
	return &tx, nil
}

func (s *Store) GetTransactions(ctx context.Context, limit int, beforeBlock *uint64) ([]Transaction, error) {
	var rows *sql.Rows
	var err error

	if beforeBlock != nil {
		rows, err = s.db.QueryContext(ctx, `
			SELECT t.hash, t.block_number, b.timestamp, t.tx_index, t.from_address, t.to_address, t.value::text,
				t.gas_used, t.gas_price, t.gas_limit, t.max_fee_per_gas, t.max_priority_fee_per_gas, t.nonce,
				t.tx_type, t.input_data, t.status, t.error, t.revert_reason, t.created_at
			FROM transactions t
			JOIN blocks b ON t.block_number = b.number
			WHERE t.block_number < $1 ORDER BY t.block_number DESC, t.tx_index DESC LIMIT $2`, *beforeBlock, limit)
	} else {
		rows, err = s.db.QueryContext(ctx, `
			SELECT t.hash, t.block_number, b.timestamp, t.tx_index, t.from_address, t.to_address, t.value::text,
				t.gas_used, t.gas_price, t.gas_limit, t.max_fee_per_gas, t.max_priority_fee_per_gas, t.nonce,
				t.tx_type, t.input_data, t.status, t.error, t.revert_reason, t.created_at
			FROM transactions t
			JOIN blocks b ON t.block_number = b.number
			ORDER BY t.block_number DESC, t.tx_index DESC LIMIT $1`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return s.scanTransactions(rows)
}

func (s *Store) GetTransactionsByAddress(ctx context.Context, address string, limit int, page AddressPage) ([]Transaction, string, error) {
	address = strings.ToLower(address)
	var rows *sql.Rows

	bound, err := sqlFeedBound(page)
	if err != nil {
		return nil, "", err
	}
	if bound != nil {
		// Keyset seek (RD-1149): the exclusive row-value comparison resumes
		// exactly after the cursor row — a page boundary inside a block cannot
		// skip the block's remaining rows the way bare `block_number < $2` did.
		// Fetch limit+1 to learn whether a further page exists.
		rows, err = s.db.QueryContext(ctx, `
			SELECT t.hash, t.block_number, b.timestamp, t.tx_index, t.from_address, t.to_address, t.value::text,
				t.gas_used, t.gas_price, t.gas_limit, t.max_fee_per_gas, t.max_priority_fee_per_gas, t.nonce,
				t.tx_type, t.input_data, t.status, t.error, t.revert_reason, t.created_at
			FROM transactions t
			JOIN blocks b ON t.block_number = b.number
			WHERE (LOWER(t.from_address) = $1 OR LOWER(t.to_address) = $1) AND (t.block_number, t.tx_index) < ($2, $3)
			ORDER BY t.block_number DESC, t.tx_index DESC LIMIT $4`, address, bound.Block, bound.Index, limit+1)
	} else {
		rows, err = s.db.QueryContext(ctx, `
			SELECT t.hash, t.block_number, b.timestamp, t.tx_index, t.from_address, t.to_address, t.value::text,
				t.gas_used, t.gas_price, t.gas_limit, t.max_fee_per_gas, t.max_priority_fee_per_gas, t.nonce,
				t.tx_type, t.input_data, t.status, t.error, t.revert_reason, t.created_at
			FROM transactions t
			JOIN blocks b ON t.block_number = b.number
			WHERE LOWER(t.from_address) = $1 OR LOWER(t.to_address) = $1
			ORDER BY t.block_number DESC, t.tx_index DESC LIMIT $2`, address, limit+1)
	}
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	txs, err := s.scanTransactions(rows)
	if err != nil {
		return nil, "", err
	}
	nextCursor := ""
	if len(txs) > limit {
		txs = txs[:limit]
		last := txs[len(txs)-1]
		nextCursor = encodeFeedCursor(feedCursor{Block: last.BlockNumber, Index: uint32(last.TxIndex)})
	}
	return txs, nextCursor, nil
}

func (s *Store) scanTransactions(rows *sql.Rows) ([]Transaction, error) {
	var txs []Transaction
	for rows.Next() {
		var tx Transaction
		var valueStr string
		if err := rows.Scan(&tx.Hash, &tx.BlockNumber, &tx.BlockTimestamp, &tx.TxIndex, &tx.From, &tx.To, &valueStr,
			&tx.GasUsed, &tx.GasPrice, &tx.GasLimit, &tx.MaxFeePerGas, &tx.MaxPriorityFeePerGas, &tx.Nonce,
			&tx.TxType, &tx.InputData, &tx.Status, &tx.Error, &tx.RevertReason, &tx.CreatedAt); err != nil {
			return nil, err
		}
		tx.Value = JSONString(valueStr)
		txs = append(txs, tx)
	}
	return txs, rows.Err()
}

// Sync Status

func (s *Store) GetSyncStatus(ctx context.Context) (*SyncStatus, error) {
	var ss SyncStatus
	err := s.db.QueryRowContext(ctx, `
		SELECT last_indexed_block, is_syncing, updated_at
		FROM sync_status ORDER BY id DESC LIMIT 1`).Scan(
		&ss.LastIndexedBlock, &ss.IsSyncing, &ss.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &ss, err
}

func (s *Store) GetAddressStats(ctx context.Context, address string) (*AddressStats, error) {
	address = strings.ToLower(address)
	var stats AddressStats
	err := s.db.QueryRowContext(ctx, `
		SELECT address, tx_count, internal_tx_count, token_transfer_count, first_seen, last_seen, is_contract, updated_at
		FROM address_stats WHERE LOWER(address) = $1`, address).Scan(
		&stats.Address, &stats.TxCount, &stats.InternalTxCount, &stats.TokenTransferCount, &stats.FirstSeen, &stats.LastSeen, &stats.IsContract, &stats.UpdatedAt)
	if err == sql.ErrNoRows {
		// Return empty stats if not found
		return &AddressStats{Address: address}, nil
	}
	return &stats, err
}

// GetAddressTransactionCountFiltered returns the visible tx count for an address.
// It counts transactions where the address appears as from or to, excluding
// hidden transactions based on the visibility filter.
func (s *Store) GetAddressTransactionCountFiltered(ctx context.Context, address string, filter *VisibilityFilter) (int, error) {
	address = strings.ToLower(address)
	if !isFilterActive(filter) {
		var count int
		err := s.db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM transactions t WHERE LOWER(t.from_address) = $1 OR LOWER(t.to_address) = $1",
			address).Scan(&count)
		return count, err
	}
	visClause, visArgs, nextArg := visibilityWhereClause(filter, 1)
	query := fmt.Sprintf(
		"SELECT COUNT(*) FROM transactions t WHERE (LOWER(t.from_address) = $%d OR LOWER(t.to_address) = $%d)%s",
		nextArg, nextArg, visClause)
	args := append(visArgs, address)
	var count int
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&count)
	return count, err
}

// Internal Transactions

func (s *Store) GetInternalTransactionsByTx(ctx context.Context, txHash string) ([]InternalTransaction, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, tx_hash, block_number, trace_address, from_address, to_address, value::text,
			gas, gas_used, input, output, call_type, error, timestamp
		FROM internal_transactions WHERE tx_hash = $1 ORDER BY id`, txHash)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return s.scanInternalTransactions(rows)
}

// GetTransactionsByBlock returns all transactions in a given block.
func (s *Store) GetTransactionsByBlock(ctx context.Context, blockNumber uint64) ([]Transaction, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT t.hash, t.block_number, b.timestamp, t.tx_index, t.from_address, t.to_address, t.value::text,
			t.gas_used, t.gas_price, t.gas_limit, t.max_fee_per_gas, t.max_priority_fee_per_gas, t.nonce,
			t.tx_type, t.input_data, t.status, t.error, t.revert_reason, t.created_at
		FROM transactions t
		JOIN blocks b ON t.block_number = b.number
		WHERE t.block_number = $1 ORDER BY t.tx_index`, blockNumber)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return s.scanTransactions(rows)
}

// GetLatestBlockNumber returns the highest indexed block number.
func (s *Store) GetLatestBlockNumber(ctx context.Context) (uint64, error) {
	var num uint64
	err := s.db.QueryRowContext(ctx, "SELECT COALESCE(MAX(number), 0) FROM blocks").Scan(&num)
	return num, err
}

// GetTransactionsPaginated returns transactions with offset-based pagination.
func (s *Store) GetTransactionsPaginated(ctx context.Context, page, pageSize int) ([]Transaction, int64, error) {
	var total int64
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM transactions").Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	rows, err := s.db.QueryContext(ctx, `
		SELECT t.hash, t.block_number, b.timestamp, t.tx_index, t.from_address, t.to_address, t.value::text,
			t.gas_used, t.gas_price, t.gas_limit, t.max_fee_per_gas, t.max_priority_fee_per_gas, t.nonce,
			t.tx_type, t.input_data, t.status, t.error, t.revert_reason, t.created_at
		FROM transactions t
		JOIN blocks b ON t.block_number = b.number
		ORDER BY t.block_number DESC, t.tx_index DESC
		LIMIT $1 OFFSET $2`, pageSize, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	txs, err := s.scanTransactions(rows)
	return txs, total, err
}

const txCategorySelectCols = `,
		t.value > 0 AS is_coin_transfer,
		(t.to_address IS NOT NULL AND LENGTH(t.input_data) > 2 AND EXISTS(SELECT 1 FROM contracts c WHERE LOWER(c.address) = LOWER(t.to_address))) AS is_contract_call,
		(t.to_address IS NULL) AS is_contract_creation,
		(SELECT COUNT(*) FROM token_transfers tt WHERE tt.tx_hash = t.hash) AS token_transfer_count`

// scanTransactionsWithCategories scans rows that include the 4 extra category columns appended by txCategorySelectCols.
func (s *Store) scanTransactionsWithCategories(rows *sql.Rows) ([]Transaction, error) {
	var txs []Transaction
	for rows.Next() {
		var tx Transaction
		var valueStr string
		var isCoinTransfer, isContractCall, isContractCreation bool
		var tokenTransferCount int
		if err := rows.Scan(&tx.Hash, &tx.BlockNumber, &tx.BlockTimestamp, &tx.TxIndex, &tx.From, &tx.To, &valueStr,
			&tx.GasUsed, &tx.GasPrice, &tx.GasLimit, &tx.MaxFeePerGas, &tx.MaxPriorityFeePerGas, &tx.Nonce,
			&tx.TxType, &tx.InputData, &tx.Status, &tx.Error, &tx.RevertReason, &tx.CreatedAt,
			&isCoinTransfer, &isContractCall, &isContractCreation, &tokenTransferCount); err != nil {
			return nil, err
		}
		tx.Value = JSONString(valueStr)
		tx.TxCategories = buildTxCategories(isCoinTransfer, isContractCall, isContractCreation, tokenTransferCount)
		tx.TokenTransferCount = tokenTransferCount
		txs = append(txs, tx)
	}
	return txs, rows.Err()
}

func buildTxCategories(isCoinTransfer, isContractCall, isContractCreation bool, tokenTransferCount int) []string {
	var cats []string
	if isContractCreation {
		cats = append(cats, "contract_creation")
	}
	if isContractCall {
		cats = append(cats, "contract_call")
	}
	if tokenTransferCount > 0 {
		cats = append(cats, "token_transfer")
	} else if isCoinTransfer {
		cats = append(cats, "coin_transfer")
	}
	return cats
}

// GetTransactionsWithCategories returns transactions with categories computed inline.
func (s *Store) GetTransactionsWithCategories(ctx context.Context, limit int, beforeBlock *uint64) ([]Transaction, error) {
	var rows *sql.Rows
	var err error

	if beforeBlock != nil {
		rows, err = s.db.QueryContext(ctx, `
			SELECT t.hash, t.block_number, b.timestamp, t.tx_index, t.from_address, t.to_address, t.value::text,
				t.gas_used, t.gas_price, t.gas_limit, t.max_fee_per_gas, t.max_priority_fee_per_gas, t.nonce,
				t.tx_type, t.input_data, t.status, t.error, t.revert_reason, t.created_at`+txCategorySelectCols+`
			FROM transactions t
			JOIN blocks b ON t.block_number = b.number
			WHERE t.block_number < $1 ORDER BY t.block_number DESC, t.tx_index DESC LIMIT $2`, *beforeBlock, limit)
	} else {
		rows, err = s.db.QueryContext(ctx, `
			SELECT t.hash, t.block_number, b.timestamp, t.tx_index, t.from_address, t.to_address, t.value::text,
				t.gas_used, t.gas_price, t.gas_limit, t.max_fee_per_gas, t.max_priority_fee_per_gas, t.nonce,
				t.tx_type, t.input_data, t.status, t.error, t.revert_reason, t.created_at`+txCategorySelectCols+`
			FROM transactions t
			JOIN blocks b ON t.block_number = b.number
			ORDER BY t.block_number DESC, t.tx_index DESC LIMIT $1`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return s.scanTransactionsWithCategories(rows)
}

// GetTransactionsPaginatedWithCategories returns paginated transactions with categories computed inline.
func (s *Store) GetTransactionsPaginatedWithCategories(ctx context.Context, page, pageSize int) ([]Transaction, int64, error) {
	var total int64
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM transactions").Scan(&total); err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	rows, err := s.db.QueryContext(ctx, `
		SELECT t.hash, t.block_number, b.timestamp, t.tx_index, t.from_address, t.to_address, t.value::text,
			t.gas_used, t.gas_price, t.gas_limit, t.max_fee_per_gas, t.max_priority_fee_per_gas, t.nonce,
			t.tx_type, t.input_data, t.status, t.error, t.revert_reason, t.created_at`+txCategorySelectCols+`
		FROM transactions t
		JOIN blocks b ON t.block_number = b.number
		ORDER BY t.block_number DESC, t.tx_index DESC
		LIMIT $1 OFFSET $2`, pageSize, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	txs, err := s.scanTransactionsWithCategories(rows)
	return txs, total, err
}

// VisibilityFilter contains addresses that should be excluded from transaction queries.
// Two modes:
//
//  1. Blocklist mode (AllPrivate=false): HiddenAddresses are excluded.
//     Transactions are excluded when both from AND to are hidden,
//     or contract creation (to IS NULL) with from in hidden.
//
//  2. Allowlist mode (AllPrivate=true): VisibleAddresses are the only ones allowed.
//     Transactions are excluded unless at least one participant is in the allowlist.
//
// VisibleTxHashes provides an additional override: transactions whose hash appears
// in this list are always visible regardless of address-based filtering. This is
// used by the visibleTo feature to surface shared transactions in regular views.
type VisibilityFilter struct {
	HiddenAddresses  []string // blocklist mode: addresses with VisibilityHidden or VisibilityRedacted
	AllPrivate       bool     // when true, use allowlist mode (VisibleAddresses)
	VisibleAddresses []string // allowlist mode: addresses with VisibilityFull
	VisibleTxHashes  []string // tx hashes that are always visible (visibleTo override)
	// ParticipantTxHashes is a LABEL-ONLY subset of VisibleTxHashes: hashes
	// added by the RD-1009 transfer-participant union (visible because the
	// viewer participates in the tx), NOT genuine visibleTo shares. It does
	// not affect SQL filtering or row survival — it only lets the redactor
	// label a revealed counterparty "Counterparty" vs "Shared" (RD-1155).
	ParticipantTxHashes []string
}

// isFilterActive returns true if the filter has any effect.
func isFilterActive(filter *VisibilityFilter) bool {
	if filter == nil {
		return false
	}
	if filter.AllPrivate {
		return true // allowlist mode is always active (even with empty visible list = hide everything)
	}
	return len(filter.HiddenAddresses) > 0
}

// visibilityWhereClause builds the SQL WHERE clause for visibility filtering.
// Returns the clause fragment and args starting from argIdx.
// If filter is nil or inactive, returns empty string and no args.
func visibilityWhereClause(filter *VisibilityFilter, argIdx int) (string, []any, int) {
	if !isFilterActive(filter) {
		return "", nil, argIdx
	}

	if filter.AllPrivate {
		// Allowlist mode: only show transactions where at least one participant is visible.
		// If VisibleAddresses is empty and no VisibleTxHashes, no transactions are shown
		// (fully private network with no viewer access). This is correct — fail closed.
		if len(filter.VisibleAddresses) == 0 && len(filter.VisibleTxHashes) == 0 {
			return " AND FALSE", nil, argIdx
		}

		// Build clause: show tx if from OR to is in visible set, OR hash is in VisibleTxHashes.
		var parts []string
		var args []any

		if len(filter.VisibleAddresses) > 0 {
			parts = append(parts, fmt.Sprintf(
				"LOWER(t.from_address) = ANY($%d) OR LOWER(COALESCE(t.to_address, '')) = ANY($%d)",
				argIdx, argIdx))
			args = append(args, filter.VisibleAddresses)
			argIdx++
		}

		if len(filter.VisibleTxHashes) > 0 {
			parts = append(parts, fmt.Sprintf("t.hash = ANY($%d)", argIdx))
			args = append(args, filter.VisibleTxHashes)
			argIdx++
		}

		clause := " AND (" + strings.Join(parts, " OR ") + ")"
		return clause, args, argIdx
	}

	// Blocklist mode (legacy): exclude txs where both sides are hidden.
	clause := fmt.Sprintf(` AND NOT (
		(t.to_address IS NULL AND LOWER(t.from_address) = ANY($%d))
		OR (LOWER(t.from_address) = ANY($%d) AND LOWER(t.to_address) = ANY($%d))
	)`, argIdx, argIdx, argIdx)
	return clause, []any{filter.HiddenAddresses}, argIdx + 1
}

// GetTransactionsFiltered returns transactions with visibility filtering applied at SQL level.
func (s *Store) GetTransactionsFiltered(ctx context.Context, limit int, beforeBlock *uint64, filter *VisibilityFilter) ([]Transaction, error) {
	visClause, visArgs, nextArg := visibilityWhereClause(filter, 1)

	var rows *sql.Rows
	var err error

	if beforeBlock != nil {
		query := fmt.Sprintf(`
			SELECT t.hash, t.block_number, b.timestamp, t.tx_index, t.from_address, t.to_address, t.value::text,
				t.gas_used, t.gas_price, t.gas_limit, t.max_fee_per_gas, t.max_priority_fee_per_gas, t.nonce,
				t.tx_type, t.input_data, t.status, t.error, t.revert_reason, t.created_at
			FROM transactions t
			JOIN blocks b ON t.block_number = b.number
			WHERE t.block_number < $%d%s
			ORDER BY t.block_number DESC, t.tx_index DESC LIMIT $%d`, nextArg, visClause, nextArg+1)
		args := append(visArgs, *beforeBlock, limit)
		rows, err = s.db.QueryContext(ctx, query, args...)
	} else {
		query := fmt.Sprintf(`
			SELECT t.hash, t.block_number, b.timestamp, t.tx_index, t.from_address, t.to_address, t.value::text,
				t.gas_used, t.gas_price, t.gas_limit, t.max_fee_per_gas, t.max_priority_fee_per_gas, t.nonce,
				t.tx_type, t.input_data, t.status, t.error, t.revert_reason, t.created_at
			FROM transactions t
			JOIN blocks b ON t.block_number = b.number
			WHERE 1=1%s
			ORDER BY t.block_number DESC, t.tx_index DESC LIMIT $%d`, visClause, nextArg)
		args := append(visArgs, limit)
		rows, err = s.db.QueryContext(ctx, query, args...)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return s.scanTransactions(rows)
}

// CountTransactionsFiltered returns the visibility-aware total transaction
// count — the same COUNT(*) the paginated SQL queries use. It is exposed so
// callers that fetch the page rows from a different source (e.g. the
// chain-indexer gRPC backend) can still surface a stable, DB-wide total
// instead of a page-local len(). With no active filter it returns the
// chain-wide transaction count.
func (s *Store) CountTransactionsFiltered(ctx context.Context, filter *VisibilityFilter) (int64, error) {
	visClause, visArgs, _ := visibilityWhereClause(filter, 1)
	var total int64
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM transactions t WHERE 1=1%s", visClause)
	if err := s.db.QueryRowContext(ctx, countQuery, visArgs...).Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

// GetTransactionsPaginatedFiltered returns paginated transactions with visibility filtering.
func (s *Store) GetTransactionsPaginatedFiltered(ctx context.Context, page, pageSize int, filter *VisibilityFilter) ([]Transaction, int64, error) {
	total, err := s.CountTransactionsFiltered(ctx, filter)
	if err != nil {
		return nil, 0, err
	}

	visClause, visArgs, nextArg := visibilityWhereClause(filter, 1)
	offset := (page - 1) * pageSize
	query := fmt.Sprintf(`
		SELECT t.hash, t.block_number, b.timestamp, t.tx_index, t.from_address, t.to_address, t.value::text,
			t.gas_used, t.gas_price, t.gas_limit, t.max_fee_per_gas, t.max_priority_fee_per_gas, t.nonce,
			t.tx_type, t.input_data, t.status, t.error, t.revert_reason, t.created_at
		FROM transactions t
		JOIN blocks b ON t.block_number = b.number
		WHERE 1=1%s
		ORDER BY t.block_number DESC, t.tx_index DESC
		LIMIT $%d OFFSET $%d`, visClause, nextArg, nextArg+1)
	args := append(visArgs, pageSize, offset)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	txs, err := s.scanTransactions(rows)
	return txs, total, err
}

// GetTransactionsWithCategoriesFiltered returns transactions with categories and visibility filtering.
func (s *Store) GetTransactionsWithCategoriesFiltered(ctx context.Context, limit int, beforeBlock *uint64, filter *VisibilityFilter) ([]Transaction, error) {
	visClause, visArgs, nextArg := visibilityWhereClause(filter, 1)

	var rows *sql.Rows
	var err error

	if beforeBlock != nil {
		query := fmt.Sprintf(`
			SELECT t.hash, t.block_number, b.timestamp, t.tx_index, t.from_address, t.to_address, t.value::text,
				t.gas_used, t.gas_price, t.gas_limit, t.max_fee_per_gas, t.max_priority_fee_per_gas, t.nonce,
				t.tx_type, t.input_data, t.status, t.error, t.revert_reason, t.created_at`+txCategorySelectCols+`
			FROM transactions t
			JOIN blocks b ON t.block_number = b.number
			WHERE t.block_number < $%d%s
			ORDER BY t.block_number DESC, t.tx_index DESC LIMIT $%d`, nextArg, visClause, nextArg+1)
		args := append(visArgs, *beforeBlock, limit)
		rows, err = s.db.QueryContext(ctx, query, args...)
	} else {
		query := fmt.Sprintf(`
			SELECT t.hash, t.block_number, b.timestamp, t.tx_index, t.from_address, t.to_address, t.value::text,
				t.gas_used, t.gas_price, t.gas_limit, t.max_fee_per_gas, t.max_priority_fee_per_gas, t.nonce,
				t.tx_type, t.input_data, t.status, t.error, t.revert_reason, t.created_at`+txCategorySelectCols+`
			FROM transactions t
			JOIN blocks b ON t.block_number = b.number
			WHERE 1=1%s
			ORDER BY t.block_number DESC, t.tx_index DESC LIMIT $%d`, visClause, nextArg)
		args := append(visArgs, limit)
		rows, err = s.db.QueryContext(ctx, query, args...)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return s.scanTransactionsWithCategories(rows)
}

// GetTransactionsPaginatedWithCategoriesFiltered returns paginated transactions with categories and visibility filtering.
func (s *Store) GetTransactionsPaginatedWithCategoriesFiltered(ctx context.Context, page, pageSize int, filter *VisibilityFilter) ([]Transaction, int64, error) {
	total, err := s.CountTransactionsFiltered(ctx, filter)
	if err != nil {
		return nil, 0, err
	}

	visClause, visArgs, nextArg := visibilityWhereClause(filter, 1)
	offset := (page - 1) * pageSize
	query := fmt.Sprintf(`
		SELECT t.hash, t.block_number, b.timestamp, t.tx_index, t.from_address, t.to_address, t.value::text,
			t.gas_used, t.gas_price, t.gas_limit, t.max_fee_per_gas, t.max_priority_fee_per_gas, t.nonce,
			t.tx_type, t.input_data, t.status, t.error, t.revert_reason, t.created_at`+txCategorySelectCols+`
		FROM transactions t
		JOIN blocks b ON t.block_number = b.number
		WHERE 1=1%s
		ORDER BY t.block_number DESC, t.tx_index DESC
		LIMIT $%d OFFSET $%d`, visClause, nextArg, nextArg+1)
	args := append(visArgs, pageSize, offset)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	txs, err := s.scanTransactionsWithCategories(rows)
	return txs, total, err
}

// GetTransactionWithCategories returns a single transaction with categories computed inline.
func (s *Store) GetTransactionWithCategories(ctx context.Context, hash string) (*Transaction, error) {
	var tx Transaction
	var valueStr string
	var isCoinTransfer, isContractCall, isContractCreation bool
	var tokenTransferCount int
	err := s.db.QueryRowContext(ctx, `
		SELECT t.hash, t.block_number, b.timestamp, t.tx_index, t.from_address, t.to_address, t.value::text,
			t.gas_used, t.gas_price, t.gas_limit, t.max_fee_per_gas, t.max_priority_fee_per_gas, t.nonce,
			t.tx_type, t.input_data, t.status, t.error, t.revert_reason, t.created_at`+txCategorySelectCols+`
		FROM transactions t
		JOIN blocks b ON t.block_number = b.number
		WHERE t.hash = $1`, hash).Scan(
		&tx.Hash, &tx.BlockNumber, &tx.BlockTimestamp, &tx.TxIndex, &tx.From, &tx.To, &valueStr,
		&tx.GasUsed, &tx.GasPrice, &tx.GasLimit, &tx.MaxFeePerGas, &tx.MaxPriorityFeePerGas, &tx.Nonce,
		&tx.TxType, &tx.InputData, &tx.Status, &tx.Error, &tx.RevertReason, &tx.CreatedAt,
		&isCoinTransfer, &isContractCall, &isContractCreation, &tokenTransferCount)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	tx.Value = JSONString(valueStr)
	tx.TxCategories = buildTxCategories(isCoinTransfer, isContractCall, isContractCreation, tokenTransferCount)
	tx.TokenTransferCount = tokenTransferCount
	return &tx, nil
}

// GetTransfersByTransaction returns token transfers for a specific transaction.
func (s *Store) GetTransfersByTransaction(ctx context.Context, txHash string) ([]TokenTransfer, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, tx_hash, log_index, token_address, from_address, to_address, value::text,
			block_number, timestamp, transfer_type, token_type, token_id, is_internal
		FROM token_transfers WHERE tx_hash = $1 ORDER BY log_index`, txHash)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return s.scanTokenTransfers(rows)
}

// GetLogsByTransaction returns event logs for a specific transaction.
func (s *Store) GetLogsByTransaction(ctx context.Context, txHash string) ([]Log, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, tx_hash, log_index, address, topic0, topic1, topic2, topic3, data, block_number, timestamp, removed
		FROM logs WHERE tx_hash = $1 ORDER BY log_index`, txHash)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return s.scanLogs(rows)
}

// FindLogParticipantTxs implements explorer.LogParticipantStore for the
// SQL-backed indexer store. Returns the subset of txHashes where any of
// viewerAddrs appears in an indexed address topic of a log whose topic0
// is in ParticipantEventSlots (Transfer / Approval / ApprovalForAll /
// TransferSingle / TransferBatch / Deposit / Withdrawal).
//
// Inputs:
//   - viewerAddrs: lowercase 0x-prefixed 20-byte hex (e.g.
//     "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65"). Empty slice → return
//     empty map (no work to do).
//   - txHashes: lowercase 0x-prefixed tx hashes. Empty slice → empty map.
//
// Implementation notes:
//   - The viewer addresses are left-padded to 32-byte topic form before
//     matching against topic1/topic2/topic3 columns (those are stored as
//     0x-prefixed 32-byte hex by the indexer).
//   - Only ParticipantEventSlots topic0 values trigger a match — broader
//     filters would over-reveal (e.g. operator addresses in events the
//     viewer wasn't actually a counterparty for). See the
//     ParticipantEventSlots docstring for why this list is intentional.
//   - For each accepted event, only the slots declared in
//     ParticipantEventSlots are checked. ApprovalForAll's bool is in
//     topic3 (some implementations) but we don't accept it as a
//     participant slot — only the address slots count.
//   - Uses one query with ANY(...) on tx_hash and topic0 to keep the
//     batch round-tripped efficiently; the per-slot OR ladder runs over
//     the smaller match window after the topic0 / tx_hash filter.
func (s *Store) FindLogParticipantTxs(ctx context.Context, viewerAddrs []string, txHashes []string) (map[string]bool, error) {
	out := make(map[string]bool)
	if len(viewerAddrs) == 0 || len(txHashes) == 0 {
		return out, nil
	}

	// Normalise inputs. The store contract is "lowercase 0x-prefixed"; we
	// defensively normalise once so callers can't poison the map with
	// mixed-case duplicates (and so addrToTopic below doesn't have to
	// repeat the same trim/lower per row).
	normHashes := make([]string, 0, len(txHashes))
	for _, h := range txHashes {
		normHashes = append(normHashes, strings.ToLower(strings.TrimSpace(h)))
	}
	paddedTopics := make([]string, 0, len(viewerAddrs))
	for _, a := range viewerAddrs {
		// Left-pad 20-byte address to 32-byte topic: 12 zero bytes (24
		// hex chars) + the 40-char address body.
		addr := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(a)), "0x")
		if len(addr) != 40 {
			continue // Skip malformed inputs rather than poison the query.
		}
		paddedTopics = append(paddedTopics, "0x000000000000000000000000"+addr)
	}
	if len(paddedTopics) == 0 {
		return out, nil
	}

	// Collect accepted topic0s from the canonical map.
	accepted := make([]string, 0, len(ParticipantEventSlots))
	for sig := range ParticipantEventSlots {
		accepted = append(accepted, sig)
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT tx_hash
		FROM logs
		WHERE tx_hash = ANY($1)
		  AND topic0   = ANY($2)
		  AND (topic1 = ANY($3) OR topic2 = ANY($3) OR topic3 = ANY($3))`,
		normHashes, accepted, paddedTopics)
	if err != nil {
		return nil, fmt.Errorf("FindLogParticipantTxs: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, fmt.Errorf("FindLogParticipantTxs scan: %w", err)
		}
		out[strings.ToLower(h)] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("FindLogParticipantTxs rows.Err: %w", err)
	}
	return out, nil
}

// FindTransferParticipantTxs returns the subset of tx hashes whose token_transfers
// row references any of the supplied addresses on either side (from_address or
// to_address). Used by buildVisibilityFilter to close the RD-1009 cross-redactor
// row-survival asymmetry: a tx whose tx.from / tx.to are both hidden to the
// viewer would normally be dropped by the SQL allowlist filter and by
// RedactTransactions' bothHidden branch — but if one of that tx's derived
// token-transfer rows has an admin-visible counterparty, RedactTransfers keeps
// the transfer (which already exposes the parent tx hash via TokenTransfer.TxHash).
// Surfacing those tx hashes here lets the tx row survive too, so /transactions
// is a superset of /transfers and the admin UX stays coherent.
//
// Inputs:
//   - visibleAddrs: lowercase 0x-prefixed 20-byte hex. Empty slice → empty map.
//   - beforeBlock: optional upper bound (exclusive) on block_number. When the
//     caller is paginating through a windowed tx feed (e.g. getExplorerTransactions
//     with ?before=N), passing the same bound here keeps the cardinality scan-safe.
//     nil means "no upper bound."
//   - limit: optional cap on rows scanned for the union. Bounded scan is
//     intentional — visible-address sets can be large in an org admin's view
//     and we don't want to walk the entire token_transfers table on every
//     /transactions hit. 0 or negative → no LIMIT clause (caller takes
//     responsibility, used by tests).
//
// Returns lowercase tx hashes. Empty input addresses → empty map (no work).
func (s *Store) FindTransferParticipantTxs(ctx context.Context, visibleAddrs []string, beforeBlock *uint64, limit int) (map[string]bool, error) {
	out := make(map[string]bool)
	if len(visibleAddrs) == 0 {
		return out, nil
	}

	// Normalise once so callers can't poison the query with mixed-case input,
	// matching the convention used by FindLogParticipantTxs above.
	norm := make([]string, 0, len(visibleAddrs))
	for _, a := range visibleAddrs {
		addr := strings.TrimSpace(strings.ToLower(a))
		if addr == "" {
			continue
		}
		norm = append(norm, addr)
	}
	if len(norm) == 0 {
		return out, nil
	}

	// Window the scan to the same pagination cursor the surrounding tx feed
	// uses; without this, an admin view on a chain with millions of transfers
	// would do a full table scan on every /transactions hit.
	query := `SELECT DISTINCT tx_hash FROM token_transfers
		WHERE (LOWER(from_address) = ANY($1) OR LOWER(to_address) = ANY($1))`
	args := []any{norm}
	if beforeBlock != nil {
		query += ` AND block_number < $2`
		args = append(args, *beforeBlock)
	}
	// ORDER BY ensures the LIMIT picks the most recent matches — same shape
	// the surrounding tx feed renders, so the visibility-union mirrors what
	// the user will scroll through.
	query += ` ORDER BY tx_hash`
	if limit > 0 {
		query += fmt.Sprintf(` LIMIT %d`, limit)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("FindTransferParticipantTxs: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, fmt.Errorf("FindTransferParticipantTxs scan: %w", err)
		}
		out[strings.ToLower(h)] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("FindTransferParticipantTxs rows.Err: %w", err)
	}
	return out, nil
}

// GetTransfersByAddress returns token transfers involving a specific address.
func (s *Store) GetTransfersByAddress(ctx context.Context, address string, limit int, page AddressPage) ([]TokenTransfer, string, error) {
	address = strings.ToLower(address)
	var rows *sql.Rows

	bound, err := sqlFeedBound(page)
	if err != nil {
		return nil, "", err
	}
	if bound != nil {
		// Keyset seek (RD-1149): see GetTransactionsByAddress.
		rows, err = s.db.QueryContext(ctx, `
			SELECT id, tx_hash, log_index, token_address, from_address, to_address, value::text,
				block_number, timestamp, transfer_type, token_type, token_id, is_internal
			FROM token_transfers
			WHERE (LOWER(from_address) = $1 OR LOWER(to_address) = $1) AND (block_number, log_index) < ($2, $3)
			ORDER BY block_number DESC, log_index DESC LIMIT $4`, address, bound.Block, bound.Index, limit+1)
	} else {
		rows, err = s.db.QueryContext(ctx, `
			SELECT id, tx_hash, log_index, token_address, from_address, to_address, value::text,
				block_number, timestamp, transfer_type, token_type, token_id, is_internal
			FROM token_transfers
			WHERE LOWER(from_address) = $1 OR LOWER(to_address) = $1
			ORDER BY block_number DESC, log_index DESC LIMIT $2`, address, limit+1)
	}
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	transfers, err := s.scanTokenTransfers(rows)
	if err != nil {
		return nil, "", err
	}
	nextCursor := ""
	if len(transfers) > limit {
		transfers = transfers[:limit]
		last := transfers[len(transfers)-1]
		nextCursor = encodeFeedCursor(feedCursor{Block: last.BlockNumber, Index: uint32(last.LogIndex)})
	}
	return transfers, nextCursor, nil
}

// GetInternalTransactionsByAddress returns internal transactions for an address with pagination.
func (s *Store) GetInternalTransactionsByAddress(ctx context.Context, address string, limit int, offset int) ([]InternalTransaction, int64, error) {
	address = strings.ToLower(address)
	var total int64
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM internal_transactions
		WHERE LOWER(from_address) = $1 OR LOWER(to_address) = $1`, address).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, tx_hash, block_number, trace_address, from_address, to_address, value::text,
			gas, gas_used, input, output, call_type, error, timestamp
		FROM internal_transactions
		WHERE LOWER(from_address) = $1 OR LOWER(to_address) = $1
		ORDER BY block_number DESC, id DESC
		LIMIT $2 OFFSET $3`, address, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	txs, err := s.scanInternalTransactions(rows)
	return txs, total, err
}

// GetLogsByAddress returns logs emitted by a specific address with pagination.
func (s *Store) GetLogsByAddress(ctx context.Context, address string, limit int, offset int) ([]Log, int64, error) {
	address = strings.ToLower(address)
	var total int64
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM logs WHERE LOWER(address) = $1`, address).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, tx_hash, log_index, address, topic0, topic1, topic2, topic3, data, block_number, timestamp, removed
		FROM logs WHERE LOWER(address) = $1
		ORDER BY block_number DESC, log_index DESC
		LIMIT $2 OFFSET $3`, address, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	logs, err := s.scanLogs(rows)
	return logs, total, err
}

// GetLogs returns event logs filtered by address, topic0, and block range.
func (s *Store) GetLogs(ctx context.Context, address *string, topic0 *string, fromBlock *uint64, toBlock *uint64, limit int) ([]Log, error) {
	where := []string{}
	args := []interface{}{}
	argIdx := 1

	if address != nil {
		where = append(where, fmt.Sprintf("LOWER(address) = $%d", argIdx))
		args = append(args, strings.ToLower(*address))
		argIdx++
	}
	if topic0 != nil {
		where = append(where, fmt.Sprintf("topic0 = $%d", argIdx))
		args = append(args, *topic0)
		argIdx++
	}
	if fromBlock != nil {
		where = append(where, fmt.Sprintf("block_number >= $%d", argIdx))
		args = append(args, *fromBlock)
		argIdx++
	}
	if toBlock != nil {
		where = append(where, fmt.Sprintf("block_number <= $%d", argIdx))
		args = append(args, *toBlock)
		argIdx++
	}

	query := "SELECT id, tx_hash, log_index, address, topic0, topic1, topic2, topic3, data, block_number, timestamp, removed FROM logs"
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += fmt.Sprintf(" ORDER BY block_number DESC, log_index DESC LIMIT $%d", argIdx)
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return s.scanLogs(rows)
}

// GetContract returns the contract record for an address.
func (s *Store) GetContract(ctx context.Context, address string) (*Contract, error) {
	address = strings.ToLower(address)
	var c Contract
	var abiData []byte
	err := s.db.QueryRowContext(ctx, `
		SELECT address, bytecode, bytecode_hash, creator, creation_tx, block_number, is_verified,
			contract_name, compiler_version, optimization_used, evm_version, source_code, abi, created_at,
			license_type, constructor_args, optimization_runs
		FROM contracts WHERE LOWER(address) = $1`, address).Scan(
		&c.Address, &c.Bytecode, &c.BytecodeHash, &c.Creator, &c.CreationTx, &c.BlockNumber, &c.IsVerified,
		&c.ContractName, &c.CompilerVersion, &c.OptimizationUsed, &c.EVMVersion, &c.SourceCode, &abiData, &c.CreatedAt,
		&c.LicenseType, &c.ConstructorArgs, &c.OptimizationRuns)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if abiData != nil {
		c.ABI = abiData
	}
	return &c, err
}

// IsContract checks whether the address is a contract.
func (s *Store) IsContract(ctx context.Context, address string) (bool, error) {
	address = strings.ToLower(address)
	var exists bool
	err := s.db.QueryRowContext(ctx, `
		SELECT EXISTS(SELECT 1 FROM contracts WHERE LOWER(address) = $1)`, address).Scan(&exists)
	if err != nil {
		return false, err
	}
	if exists {
		return true, nil
	}
	err = s.db.QueryRowContext(ctx, `
		SELECT is_contract FROM address_stats WHERE LOWER(address) = $1`, address).Scan(&exists)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return exists, err
}

// SetContractABI updates the ABI for an existing contract.
func (s *Store) SetContractABI(ctx context.Context, address string, abi json.RawMessage) error {
	address = strings.ToLower(address)
	_, err := s.db.ExecContext(ctx, `UPDATE contracts SET abi = $1 WHERE LOWER(address) = $2`, abi, address)
	return err
}

// GetTokens returns tokens with pagination and optional type filter.
func (s *Store) GetTokens(ctx context.Context, limit int, offset int, tokenType string) ([]Token, int64, error) {
	var total int64

	if tokenType != "" {
		_ = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM tokens WHERE token_type = $1", tokenType).Scan(&total)
		rows, err := s.db.QueryContext(ctx, `
			SELECT address, symbol, name, decimals, token_type, total_supply, holder_count, transfer_count,
				usd_price, icon_url, l1_address, block_number, creation_tx, off_chain_updated_at, created_at
			FROM tokens WHERE token_type = $1 ORDER BY transfer_count DESC LIMIT $2 OFFSET $3`,
			tokenType, limit, offset)
		if err != nil {
			return nil, 0, err
		}
		defer rows.Close()
		tokens, err := s.scanTokens(rows)
		return tokens, total, err
	}

	_ = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM tokens").Scan(&total)
	rows, err := s.db.QueryContext(ctx, `
		SELECT address, symbol, name, decimals, token_type, total_supply, holder_count, transfer_count,
			usd_price, icon_url, l1_address, block_number, creation_tx, off_chain_updated_at, created_at
		FROM tokens ORDER BY transfer_count DESC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	tokens, err := s.scanTokens(rows)
	return tokens, total, err
}

// GetToken returns a single token by address.
func (s *Store) GetToken(ctx context.Context, address string) (*Token, error) {
	address = strings.ToLower(address)
	var t Token
	err := s.db.QueryRowContext(ctx, `
		SELECT address, symbol, name, decimals, token_type, total_supply, holder_count, transfer_count,
			usd_price, icon_url, l1_address, block_number, creation_tx, off_chain_updated_at, created_at
		FROM tokens WHERE LOWER(address) = $1`, address).Scan(
		&t.Address, &t.Symbol, &t.Name, &t.Decimals, &t.TokenType, &t.TotalSupply,
		&t.HolderCount, &t.TransferCount, &t.USDPrice, &t.IconURL, &t.L1Address, &t.BlockNumber,
		&t.CreationTx, &t.OffChainUpdatedAt, &t.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &t, err
}

// GetTokenHolders returns holders of a specific token with pagination.
func (s *Store) GetTokenHolders(ctx context.Context, address string, limit int, offset int) ([]TokenHolder, int64, error) {
	address = strings.ToLower(address)
	var total int64
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM token_balances WHERE LOWER(token_address) = $1`, address).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT tb.address, tb.balance::text,
			CASE WHEN ts.total_supply IS NOT NULL AND ts.total_supply != '0' THEN
				(tb.balance::numeric / ts.total_supply::numeric * 100)
			ELSE 0 END as percentage,
			COALESCE(ast.is_contract, false) as is_contract
		FROM token_balances tb
		LEFT JOIN tokens ts ON LOWER(ts.address) = LOWER(tb.token_address)
		LEFT JOIN address_stats ast ON LOWER(ast.address) = LOWER(tb.address)
		WHERE LOWER(tb.token_address) = $1
		ORDER BY tb.balance::numeric DESC
		LIMIT $2 OFFSET $3`, address, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var holders []TokenHolder
	for rows.Next() {
		var h TokenHolder
		var balStr string
		if err := rows.Scan(&h.Address, &balStr, &h.Percentage, &h.IsContract); err != nil {
			return nil, 0, err
		}
		h.Balance = JSONString(balStr)
		holders = append(holders, h)
	}
	return holders, total, rows.Err()
}

// GetTokenBalances returns token balances for an address.
func (s *Store) GetTokenBalances(ctx context.Context, address string) ([]Balance, error) {
	address = strings.ToLower(address)
	rows, err := s.db.QueryContext(ctx, `
		SELECT address, token_address, block_number, balance::text
		FROM token_balances WHERE LOWER(address) = $1
		ORDER BY balance::numeric DESC`, address)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var balances []Balance
	for rows.Next() {
		var b Balance
		var balStr string
		if err := rows.Scan(&b.Address, &b.TokenAddress, &b.BlockNumber, &balStr); err != nil {
			return nil, err
		}
		b.Balance = JSONString(balStr)
		balances = append(balances, b)
	}
	return balances, rows.Err()
}

// GetTransfersByToken returns token transfers for a specific token with pagination.
func (s *Store) GetTransfersByToken(ctx context.Context, tokenAddress string, limit int, offset int) ([]TokenTransfer, int64, error) {
	tokenAddress = strings.ToLower(tokenAddress)
	var total int64
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM token_transfers WHERE LOWER(token_address) = $1`, tokenAddress).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, tx_hash, log_index, token_address, from_address, to_address, value::text,
			block_number, timestamp, transfer_type, token_type, token_id, is_internal
		FROM token_transfers WHERE LOWER(token_address) = $1
		ORDER BY block_number DESC, log_index DESC
		LIMIT $2 OFFSET $3`, tokenAddress, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	transfers, err := s.scanTokenTransfers(rows)
	return transfers, total, err
}

// GetAllTransfers returns all token transfers with pagination.
func (s *Store) GetAllTransfers(ctx context.Context, limit int, offset int) ([]TokenTransfer, int64, error) {
	var total int64
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM token_transfers").Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, tx_hash, log_index, token_address, from_address, to_address, value::text,
			block_number, timestamp, transfer_type, token_type, token_id, is_internal
		FROM token_transfers
		ORDER BY block_number DESC, log_index DESC
		LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	transfers, err := s.scanTokenTransfers(rows)
	return transfers, total, err
}

// GetAccountsPaginated returns addresses ordered by tx_count with pagination.
func (s *Store) GetAccountsPaginated(ctx context.Context, page, pageSize int) ([]AddressStats, int64, error) {
	var total int64
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM address_stats").Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	rows, err := s.db.QueryContext(ctx, `
		SELECT address, tx_count, internal_tx_count, token_transfer_count, first_seen, last_seen, is_contract, updated_at
		FROM address_stats ORDER BY tx_count DESC LIMIT $1 OFFSET $2`, pageSize, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var accounts []AddressStats
	for rows.Next() {
		var a AddressStats
		if err := rows.Scan(&a.Address, &a.TxCount, &a.InternalTxCount, &a.TokenTransferCount,
			&a.FirstSeen, &a.LastSeen, &a.IsContract, &a.UpdatedAt); err != nil {
			return nil, 0, err
		}
		accounts = append(accounts, a)
	}
	return accounts, total, rows.Err()
}

// SearchSuggestions returns search suggestions matching the query.
func (s *Store) SearchSuggestions(ctx context.Context, query string, limit int) ([]SearchSuggestion, error) {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return nil, nil
	}

	var suggestions []SearchSuggestion

	// Search transaction hashes
	if strings.HasPrefix(query, "0x") && len(query) > 4 {
		txRows, err := s.db.QueryContext(ctx, `
			SELECT hash FROM transactions WHERE LOWER(hash) LIKE $1 LIMIT $2`,
			query+"%", limit)
		if err == nil {
			for txRows.Next() {
				var hash string
				if txRows.Scan(&hash) == nil {
					suggestions = append(suggestions, SearchSuggestion{
						Type:  "transaction",
						Value: hash,
						Label: "Transaction " + hash[:10] + "...",
					})
				}
			}
			txRows.Close()
		}
	}

	// Search addresses
	if strings.HasPrefix(query, "0x") && len(query) >= 4 && len(suggestions) < limit {
		addrRows, err := s.db.QueryContext(ctx, `
			SELECT address FROM address_stats WHERE LOWER(address) LIKE $1 LIMIT $2`,
			query+"%", limit-len(suggestions))
		if err == nil {
			for addrRows.Next() {
				var addr string
				if addrRows.Scan(&addr) == nil {
					suggestions = append(suggestions, SearchSuggestion{
						Type:  "address",
						Value: addr,
						Label: "Address " + addr[:10] + "...",
					})
				}
			}
			addrRows.Close()
		}
	}

	// Search block numbers
	if len(query) > 0 && query[0] >= '0' && query[0] <= '9' && len(suggestions) < limit {
		blockRows, err := s.db.QueryContext(ctx, `
			SELECT number FROM blocks WHERE CAST(number AS TEXT) LIKE $1 ORDER BY number DESC LIMIT $2`,
			query+"%", limit-len(suggestions))
		if err == nil {
			for blockRows.Next() {
				var num uint64
				if blockRows.Scan(&num) == nil {
					suggestions = append(suggestions, SearchSuggestion{
						Type:  "block",
						Value: fmt.Sprintf("%d", num),
						Label: fmt.Sprintf("Block #%d", num),
					})
				}
			}
			blockRows.Close()
		}
	}

	return suggestions, nil
}

// GetTransactionHistory returns transaction counts bucketed by time interval.
func (s *Store) GetTransactionHistory(ctx context.Context, intervalSeconds int, limit int) ([]TxHistoryPoint, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT bucket, cnt FROM (
			SELECT (b.timestamp / $1) * $1 AS bucket, COUNT(*) AS cnt
			FROM transactions t
			JOIN blocks b ON t.block_number = b.number
			GROUP BY bucket
			ORDER BY bucket DESC
			LIMIT $2
		) sub ORDER BY bucket ASC`, intervalSeconds, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []TxHistoryPoint
	for rows.Next() {
		var p TxHistoryPoint
		if err := rows.Scan(&p.Timestamp, &p.Count); err != nil {
			return nil, err
		}
		points = append(points, p)
	}
	return points, rows.Err()
}

// GetIndexerProgress returns the current indexer progress.
func (s *Store) GetIndexerProgress(ctx context.Context) (*IndexerProgress, error) {
	var p IndexerProgress
	err := s.db.QueryRowContext(ctx, `
		SELECT id, min_fetched_block, max_fetched_block, backfill_complete, updated_at
		FROM indexer_progress ORDER BY id DESC LIMIT 1`).Scan(
		&p.ID, &p.MinFetchedBlock, &p.MaxFetchedBlock, &p.BackfillComplete, &p.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &p, err
}

// GetInternalTransactionsByBlock returns internal transactions for a block.
func (s *Store) GetInternalTransactionsByBlock(ctx context.Context, blockNumber uint64) ([]InternalTransaction, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, tx_hash, block_number, trace_address, from_address, to_address, value::text,
			gas, gas_used, input, output, call_type, error, timestamp
		FROM internal_transactions WHERE block_number = $1 ORDER BY id`, blockNumber)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return s.scanInternalTransactions(rows)
}

// scanTokenTransfers scans rows into TokenTransfer slices.
func (s *Store) scanTokenTransfers(rows *sql.Rows) ([]TokenTransfer, error) {
	var transfers []TokenTransfer
	for rows.Next() {
		var t TokenTransfer
		var valueStr string
		if err := rows.Scan(&t.ID, &t.TxHash, &t.LogIndex, &t.TokenAddress, &t.From, &t.To, &valueStr,
			&t.BlockNumber, &t.Timestamp, &t.TransferType, &t.TokenType, &t.TokenID, &t.IsInternal); err != nil {
			return nil, err
		}
		t.Value = JSONString(valueStr)
		transfers = append(transfers, t)
	}
	return transfers, rows.Err()
}

// scanLogs scans rows into Log slices.
func (s *Store) scanLogs(rows *sql.Rows) ([]Log, error) {
	var logs []Log
	for rows.Next() {
		var l Log
		if err := rows.Scan(&l.ID, &l.TxHash, &l.LogIndex, &l.Address, &l.Topic0, &l.Topic1, &l.Topic2, &l.Topic3,
			&l.Data, &l.BlockNumber, &l.Timestamp, &l.Removed); err != nil {
			return nil, err
		}
		logs = append(logs, l)
	}
	return logs, rows.Err()
}

// scanInternalTransactions scans rows into InternalTransaction slices.
func (s *Store) scanInternalTransactions(rows *sql.Rows) ([]InternalTransaction, error) {
	var txs []InternalTransaction
	for rows.Next() {
		var tx InternalTransaction
		var valueStr string
		if err := rows.Scan(&tx.ID, &tx.TxHash, &tx.BlockNumber, &tx.TraceAddress, &tx.From, &tx.To, &valueStr,
			&tx.Gas, &tx.GasUsed, &tx.Input, &tx.Output, &tx.CallType, &tx.Error, &tx.Timestamp); err != nil {
			return nil, err
		}
		tx.Value = JSONString(valueStr)
		txs = append(txs, tx)
	}
	return txs, rows.Err()
}

// scanTokens scans rows into Token slices.
func (s *Store) scanTokens(rows *sql.Rows) ([]Token, error) {
	var tokens []Token
	for rows.Next() {
		var t Token
		if err := rows.Scan(&t.Address, &t.Symbol, &t.Name, &t.Decimals, &t.TokenType, &t.TotalSupply,
			&t.HolderCount, &t.TransferCount, &t.USDPrice, &t.IconURL, &t.L1Address, &t.BlockNumber,
			&t.CreationTx, &t.OffChainUpdatedAt, &t.CreatedAt); err != nil {
			return nil, err
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}
