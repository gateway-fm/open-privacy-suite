package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"
)

// MaxVisibilityAttempts is the soft cap on reconciliation retries before a
// row stops being picked up by the reconciler. Rows that hit this count are
// surfaced via the dead-letter metric for operator review; the row is NEVER
// auto-deleted (manual recovery decision belongs with the operator).
const MaxVisibilityAttempts = 10

// PendingTxVisibility is one outbox row for tx_visible_to.
type PendingTxVisibility struct {
	ID             int64
	TxHash         string
	VisibleToDIDs  []string
	SenderDID      string
	OrgID          string
	AttemptCount   int
	LastAttemptAt  sql.NullTime
	LastError      sql.NullString
}

// EnqueuePendingTxVisibility writes one outbox row. Called from the JSON-RPC
// hot path right after the node accepts the tx (M7). The reconciler later
// promotes the row into tx_visible_to.
func (d *DB) EnqueuePendingTxVisibility(ctx context.Context, txHash string, visibleToDIDs []string, senderDID, orgID string) error {
	if txHash == "" || len(visibleToDIDs) == 0 {
		return nil
	}
	const query = `
		INSERT INTO pending_tx_visibility (tx_hash, visible_to_dids, sender_did, org_id)
		VALUES ($1, $2, $3, $4)
	`
	_, err := d.conn.ExecContext(ctx, query,
		strings.ToLower(txHash),
		pq.Array(visibleToDIDs),
		senderDID,
		orgID,
	)
	if err != nil {
		return fmt.Errorf("enqueue pending tx visibility: %w", err)
	}
	return nil
}

// ListDuePendingTxVisibility returns outbox rows that still need to be
// promoted, ordered oldest-first to keep latency predictable. attempt_count
// >= MaxVisibilityAttempts are excluded (dead-letter — see
// CountDeadLetterPendingTxVisibility).
func (d *DB) ListDuePendingTxVisibility(ctx context.Context, limit int) ([]*PendingTxVisibility, error) {
	if limit <= 0 {
		limit = 100
	}
	const query = `
		SELECT id, tx_hash, visible_to_dids, sender_did, org_id, attempt_count, last_attempt_at, last_error
		FROM pending_tx_visibility
		WHERE attempt_count < $1
		ORDER BY created_at ASC
		LIMIT $2
	`
	rows, err := d.conn.QueryContext(ctx, query, MaxVisibilityAttempts, limit)
	if err != nil {
		return nil, fmt.Errorf("list pending tx visibility: %w", err)
	}
	defer rows.Close()

	var out []*PendingTxVisibility
	for rows.Next() {
		row := &PendingTxVisibility{}
		if err := rows.Scan(
			&row.ID, &row.TxHash, pq.Array(&row.VisibleToDIDs),
			&row.SenderDID, &row.OrgID,
			&row.AttemptCount, &row.LastAttemptAt, &row.LastError,
		); err != nil {
			return nil, fmt.Errorf("scan pending tx visibility: %w", err)
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// PromotePendingTxVisibility atomically moves one outbox row into
// tx_visible_to. Uses a transaction: INSERT into tx_visible_to (ON CONFLICT
// DO NOTHING — tx_visible_to is keyed by tx_hash so retries are idempotent)
// then DELETE the pending row. Both succeed or both rollback.
func (d *DB) PromotePendingTxVisibility(ctx context.Context, row *PendingTxVisibility) error {
	// Concurrent reconciler instances can pick the same row; both statements
	// are idempotent (ON CONFLICT DO NOTHING + delete-by-id), so the whole
	// transaction is safe to retry on deadlock.
	return withRetry(ctx, func() error {
		return d.WithTx(ctx, func(tx *Tx) error {
			const insertQ = `
				INSERT INTO tx_visible_to (tx_hash, visible_to_dids, sender_did, org_id)
				VALUES ($1, $2, $3, $4)
				ON CONFLICT (tx_hash) DO NOTHING
			`
			if _, err := tx.tx.ExecContext(ctx, insertQ,
				row.TxHash, pq.Array(row.VisibleToDIDs), row.SenderDID, row.OrgID,
			); err != nil {
				return fmt.Errorf("insert tx_visible_to: %w", err)
			}

			// A zero-row delete means another reconciler instance already
			// promoted this row. Not an error; the work is done.
			const deleteQ = `DELETE FROM pending_tx_visibility WHERE id = $1`
			if _, err := tx.tx.ExecContext(ctx, deleteQ, row.ID); err != nil {
				return fmt.Errorf("delete pending row: %w", err)
			}
			return nil
		})
	})
}

// MarkPendingTxVisibilityFailed records a transient failure on an outbox row.
// The row stays in pending; the next reconciler tick will retry until
// attempt_count reaches MaxVisibilityAttempts.
func (d *DB) MarkPendingTxVisibilityFailed(ctx context.Context, id int64, lastErr error) error {
	msg := ""
	if lastErr != nil {
		msg = lastErr.Error()
		if len(msg) > 500 {
			msg = msg[:500]
		}
	}
	const query = `
		UPDATE pending_tx_visibility
		SET attempt_count = attempt_count + 1,
		    last_attempt_at = NOW(),
		    last_error = $2
		WHERE id = $1
	`
	_, err := d.conn.ExecContext(ctx, query, id, msg)
	if err != nil {
		return fmt.Errorf("mark pending failed: %w", err)
	}
	return nil
}

// CountDeadLetterPendingTxVisibility returns the count of rows that have
// exhausted retries. Operators alert on this >0 — each row needs manual
// review (rare; usually means tx_visible_to schema drift or a poisoned
// payload). Auto-deletion would silently lose recipients' visibility.
func (d *DB) CountDeadLetterPendingTxVisibility(ctx context.Context) (int64, error) {
	const query = `SELECT COUNT(*) FROM pending_tx_visibility WHERE attempt_count >= $1`
	var n int64
	err := d.conn.QueryRowContext(ctx, query, MaxVisibilityAttempts).Scan(&n)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil
		}
		return 0, fmt.Errorf("count dead-letter: %w", err)
	}
	return n, nil
}

// OldestPendingTxVisibilityAgeSeconds returns the age (in seconds) of the
// oldest unprocessed outbox row, or 0 when the table is empty. Exported for
// Prometheus gauge so operators can alert when the reconciler falls
// behind.
func (d *DB) OldestPendingTxVisibilityAgeSeconds(ctx context.Context) (int64, error) {
	const query = `
		SELECT COALESCE(EXTRACT(EPOCH FROM (NOW() - MIN(created_at)))::BIGINT, 0)
		FROM pending_tx_visibility
		WHERE attempt_count < $1
	`
	var age int64
	err := d.conn.QueryRowContext(ctx, query, MaxVisibilityAttempts).Scan(&age)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil
		}
		return 0, fmt.Errorf("oldest pending age: %w", err)
	}
	return age, nil
}
