package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"privacy-proxy/internal/disclosure"

	"github.com/jackc/pgx/v5/pgconn"
)

// CreateDisclosureEvents normally inserts all access events in one statement.
// If a foreign-key failure rolls back the batch, it attempts each event once
// within the caller's existing context budget. Valid events can therefore be
// saved even when another grant was deleted after enumeration. A non-nil error
// may accompany partial success. Generated event IDs are not populated.
func (d *DB) CreateDisclosureEvents(ctx context.Context, events []disclosure.Event) error {
	return insertDisclosureEventsWithRecovery(ctx, events, d.insertDisclosureEventBatch)
}

func (d *DB) insertDisclosureEventBatch(ctx context.Context, events []disclosure.Event) error {
	payload, err := json.Marshal(events)
	if err != nil {
		return fmt.Errorf("failed to marshal disclosure events: %w", err)
	}
	_, err = d.conn.ExecContext(ctx, `INSERT INTO disclosure_events
		(grant_id, viewer_user_id, action, resource_type, data_summary, viewer_ip, accessed_at)
		SELECT grant_id, viewer_user_id, action, resource_type, data_summary, COALESCE(viewer_ip, ''), accessed_at
		FROM jsonb_to_recordset($1::jsonb) AS e(
			grant_id uuid, viewer_user_id uuid, action text, resource_type text,
			data_summary jsonb, viewer_ip text, accessed_at timestamptz)`, payload)
	return err
}

func insertDisclosureEventsWithRecovery(ctx context.Context, events []disclosure.Event, insert func(context.Context, []disclosure.Event) error) error {
	if len(events) == 0 {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	err := insert(ctx, events)
	if err == nil || len(events) == 1 {
		return err
	}
	// PostgreSQL's foreign_key_violation guarantees this statement rolled
	// back. A connection/timeout error can instead hide a committed write;
	// retrying it would duplicate events, so it must never trigger recovery.
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
		return err
	}
	var failures []error
	for i := range events {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return errors.Join(append(failures, err, ctxErr)...)
		}
		// No recursive retries: every event gets at most one recovery attempt,
		// including when its individual write has an uncertain outcome.
		if rowErr := insert(ctx, events[i:i+1]); rowErr != nil {
			failures = append(failures, fmt.Errorf("grant %s audit write failed: %w", events[i].GrantID, rowErr))
		}
	}
	return errors.Join(failures...)
}
