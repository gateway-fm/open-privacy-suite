package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"privacy-proxy/internal/rbac"
)

// Method access policy capture store (RD-1206). Two tables:
//   - contract_record_captures : the durable per-record capture rows used to
//     gate reader calls.
//   - pending_record_captures  : the write-ahead outbox; a reconciler promotes
//     rows only after the source tx's receipt confirms status==1.
//
// Merge semantics: every captured (field,value) is stored idempotently
// (ON CONFLICT DO NOTHING on the full uniqueness tuple, which includes value).
// A `union` field may therefore hold several values (e.g. a settlement
// audience). A `set_once` field is expected to hold exactly one; if two
// distinct set_once values ever coexist for one (record,field) — a race or a
// front-running attempt — the reader-side evaluator treats the key as poisoned
// and denies all reads (rbac.setOncePoisoned). This is the audit-preferred
// "deny-all on conflict" over "silently trust the first writer".

// PendingRecordCapture is one outbox row awaiting receipt confirmation.
type PendingRecordCapture struct {
	ID              int64
	TxHash          string
	OrgID           string
	ContractAddress string
	SenderDID       string
	Captures        []rbac.CapturedWrite
	AttemptCount    int
}

// EnqueuePendingRecordCaptures writes the pre-decoded capture payload to the
// outbox. No-op when there is nothing to capture.
func (d *DB) EnqueuePendingRecordCaptures(ctx context.Context, txHash, orgID, contractAddr, senderDID string, writes []rbac.CapturedWrite) error {
	if len(writes) == 0 {
		return nil
	}
	payload, err := json.Marshal(writes)
	if err != nil {
		return fmt.Errorf("marshal pending captures: %w", err)
	}
	_, err = d.conn.ExecContext(ctx,
		`INSERT INTO pending_record_captures (tx_hash, org_id, contract_address, captures, sender_did)
		 VALUES ($1, $2, $3, $4, $5)`,
		strings.ToLower(txHash), orgID, strings.ToLower(contractAddr), payload, senderDID)
	if err != nil {
		return fmt.Errorf("enqueue pending captures: %w", err)
	}
	return nil
}

// Capture outbox retention/retry bounds (RD-1206). attempt_count counts only
// hard failures (transient upstream/lookup errors, promote errors) — NOT the
// "not mined yet" wait, so a slow-to-mine tx is never dead-lettered before it
// lands. maxCaptureAge bounds a row that never mines / stays stuck, so the
// outbox cannot grow without bound. Kept in sync with the partial index in
// migration 070 (attempt_count < 20).
const (
	MaxCaptureAttempts = 20
	maxCaptureAgeSQL   = "24 hours"
)

// ListDuePendingRecordCaptures returns outbox rows still eligible for a promotion
// attempt (under the hard-failure cap and younger than the retention bound),
// oldest first.
func (d *DB) ListDuePendingRecordCaptures(ctx context.Context, limit int) ([]PendingRecordCapture, error) {
	rows, err := d.conn.QueryContext(ctx,
		`SELECT id, tx_hash, org_id, contract_address, captures, sender_did, attempt_count
		 FROM pending_record_captures
		 WHERE attempt_count < 20
		   AND created_at > NOW() - INTERVAL '`+maxCaptureAgeSQL+`'
		 ORDER BY created_at ASC
		 LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list pending captures: %w", err)
	}
	defer rows.Close()

	var out []PendingRecordCapture
	for rows.Next() {
		var pc PendingRecordCapture
		var payload []byte
		if err := rows.Scan(&pc.ID, &pc.TxHash, &pc.OrgID, &pc.ContractAddress, &payload, &pc.SenderDID, &pc.AttemptCount); err != nil {
			return nil, fmt.Errorf("scan pending capture: %w", err)
		}
		if err := json.Unmarshal(payload, &pc.Captures); err != nil {
			return nil, fmt.Errorf("unmarshal pending capture payload: %w", err)
		}
		out = append(out, pc)
	}
	return out, rows.Err()
}

// PromoteRecordCapture upserts a confirmed outbox row's captures into the
// durable store and deletes the outbox row, atomically.
func (d *DB) PromoteRecordCapture(ctx context.Context, pc PendingRecordCapture) error {
	tx, err := d.conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin promote tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, w := range pc.Captures {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO contract_record_captures
			   (org_id, contract_address, record_type, record_key, field, value, merge_mode, source_tx_hash, sender_did)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			 ON CONFLICT (org_id, contract_address, record_type, record_key, field, value) DO NOTHING`,
			pc.OrgID, strings.ToLower(pc.ContractAddress), w.RecordType, w.RecordKey, w.Field, w.Value, w.Merge, strings.ToLower(pc.TxHash), pc.SenderDID); err != nil {
			return fmt.Errorf("insert capture: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM pending_record_captures WHERE id = $1`, pc.ID); err != nil {
		return fmt.Errorf("delete promoted pending: %w", err)
	}
	return tx.Commit()
}

// DeletePendingRecordCapture drops an outbox row (used when the source tx
// reverted — a failed create must not plant capture rows).
func (d *DB) DeletePendingRecordCapture(ctx context.Context, id int64) error {
	_, err := d.conn.ExecContext(ctx, `DELETE FROM pending_record_captures WHERE id = $1`, id)
	return err
}

// PurgePendingRecordCaptures deletes outbox rows that will never promote: those
// that exhausted the hard-failure cap (dead-lettered) or aged past the retention
// bound without mining. Returns the number reaped so the caller can surface a
// dead-letter signal to operators. Bounds outbox growth.
func (d *DB) PurgePendingRecordCaptures(ctx context.Context) (int64, error) {
	res, err := d.conn.ExecContext(ctx,
		`DELETE FROM pending_record_captures
		 WHERE attempt_count >= $1
		    OR created_at <= NOW() - INTERVAL '`+maxCaptureAgeSQL+`'`, MaxCaptureAttempts)
	if err != nil {
		return 0, fmt.Errorf("purge pending captures: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// MarkPendingRecordCaptureFailure records a HARD failure (transient upstream /
// lookup error, or a promote error) so the reconciler retries and eventually
// dead-letters at the cap. NOT used for "not mined yet" — that is a normal wait
// and must not count toward the cap (else a slow-to-mine tx is dead-lettered
// before it lands, permanently denying the record's stakeholders).
func (d *DB) MarkPendingRecordCaptureFailure(ctx context.Context, id int64, errMsg string) error {
	_, err := d.conn.ExecContext(ctx,
		`UPDATE pending_record_captures
		 SET attempt_count = attempt_count + 1, last_attempt_at = NOW(), last_error = $2
		 WHERE id = $1`, id, truncateErr(errMsg))
	return err
}

// GetRecordCaptures loads the capture rows for one record, scoped to the
// contract's owning org (C1: org_id is in the lookup key).
func (d *DB) GetRecordCaptures(ctx context.Context, orgID, contractAddr, recordType, recordKey string) ([]rbac.CapturedField, error) {
	rows, err := d.conn.QueryContext(ctx,
		`SELECT field, value, merge_mode
		 FROM contract_record_captures
		 WHERE org_id = $1 AND contract_address = $2 AND record_type = $3 AND record_key = $4`,
		orgID, strings.ToLower(contractAddr), recordType, recordKey)
	if err != nil {
		return nil, fmt.Errorf("get record captures: %w", err)
	}
	defer rows.Close()

	var out []rbac.CapturedField
	for rows.Next() {
		var cf rbac.CapturedField
		if err := rows.Scan(&cf.Field, &cf.Value, &cf.Merge); err != nil {
			return nil, fmt.Errorf("scan record capture: %w", err)
		}
		out = append(out, cf)
	}
	return out, rows.Err()
}

func truncateErr(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	if len(s) > 500 {
		s = s[:500]
	}
	return sql.NullString{String: s, Valid: true}
}
