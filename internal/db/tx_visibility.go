package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// SaveTxVisibility stores visibleTo DIDs for a transaction.
//
// Post-M7 / migration 053: tx_visible_to.tx_hash is UNIQUE. This
// method becomes idempotent — repeat calls with the same tx_hash
// no-op. The reconciler uses the same ON CONFLICT path; direct
// callers (tests, migrations, recovery scripts) get the same
// behavior. If a caller needs to OVERWRITE an existing row (different
// recipients, different sender), they should DELETE then INSERT in
// their own transaction — silently updating from inside SaveTxVisibility
// would erase a previously-saved recipient list that the original
// caller relied on.
func (d *DB) SaveTxVisibility(ctx context.Context, txHash string, visibleToDIDs []string, senderDID, orgID string) error {
	if txHash == "" || len(visibleToDIDs) == 0 {
		return nil
	}
	query := `INSERT INTO tx_visible_to (tx_hash, visible_to_dids, sender_did, org_id)
	          VALUES ($1, $2, $3, $4)
	          ON CONFLICT (tx_hash) DO NOTHING`
	_, err := d.conn.ExecContext(ctx, query, strings.ToLower(txHash), visibleToDIDs, senderDID, orgID)
	if err != nil {
		return fmt.Errorf("failed to save tx visibility: %w", err)
	}
	return nil
}

// GetTxVisibility returns the visible_to_dids for a single tx hash.
// Returns nil (not an error) if no visibleTo rule exists for the tx.
func (d *DB) GetTxVisibility(ctx context.Context, txHash string) ([]string, error) {
	query := `SELECT visible_to_dids FROM tx_visible_to WHERE tx_hash = $1 LIMIT 1`
	var dids []string
	err := d.conn.QueryRowContext(ctx, query, strings.ToLower(txHash)).Scan(ScanTextArray(&dids))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get tx visibility: %w", err)
	}
	return dids, nil
}

// GetBatchTxVisibility returns visible_to_dids for multiple tx hashes in a
// single query. Returns map[txHash][]string. Hashes not found are absent from
// the map (not an error).
func (d *DB) GetBatchTxVisibility(ctx context.Context, txHashes []string) (map[string][]string, error) {
	if len(txHashes) == 0 {
		return nil, nil
	}

	// Normalize to lowercase.
	lower := make([]string, len(txHashes))
	for i, h := range txHashes {
		lower[i] = strings.ToLower(h)
	}

	query := `SELECT tx_hash, visible_to_dids FROM tx_visible_to WHERE tx_hash = ANY($1)`
	rows, err := d.conn.QueryContext(ctx, query, lower)
	if err != nil {
		return nil, fmt.Errorf("failed to batch get tx visibility: %w", err)
	}
	defer rows.Close()

	result := make(map[string][]string)
	for rows.Next() {
		var txHash string
		var dids []string
		if err := rows.Scan(&txHash, ScanTextArray(&dids)); err != nil {
			return nil, fmt.Errorf("failed to scan tx visibility row: %w", err)
		}
		result[txHash] = dids
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate tx visibility rows: %w", err)
	}
	return result, nil
}

// GetVisibleTxHashesForDID returns all tx hashes where the given DID appears
// in visible_to_dids. Used by buildVisibilityFilter to include visibleTo txs
// in regular explorer views.
func (d *DB) GetVisibleTxHashesForDID(ctx context.Context, viewerDID string) ([]string, error) {
	if viewerDID == "" {
		return nil, nil
	}

	query := `SELECT tx_hash FROM tx_visible_to WHERE $1 = ANY(visible_to_dids)`
	rows, err := d.conn.QueryContext(ctx, query, viewerDID)
	if err != nil {
		return nil, fmt.Errorf("failed to query visible tx hashes: %w", err)
	}
	defer rows.Close()

	var hashes []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, fmt.Errorf("failed to scan visible tx hash: %w", err)
		}
		hashes = append(hashes, h)
	}
	return hashes, rows.Err()
}
