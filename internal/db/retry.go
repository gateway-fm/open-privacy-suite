package db

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// Retriable transaction SQLSTATEs. Every transaction in this package runs at
// Read Committed (BeginTx passes nil options), so the class seen in practice
// is deadlock_detected (40P01) between concurrent composite writes;
// serialization_failure (40001) is included so the classifier stays correct
// if an isolation level is ever raised.
const (
	sqlstateSerializationFailure = "40001"
	sqlstateDeadlockDetected     = "40P01"
)

const (
	txRetryAttempts  = 3
	txRetryBaseDelay = 10 * time.Millisecond
)

// isRetriableTxError reports whether err is a PostgreSQL error that is safe
// to retry as a whole new transaction (deadlock or serialization failure).
// The pgx stdlib driver surfaces *pgconn.PgError through database/sql, and
// this package wraps query errors with %w, so errors.As unwraps reliably.
func isRetriableTxError(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == sqlstateSerializationFailure || pgErr.Code == sqlstateDeadlockDetected
	}
	return false
}

// withRetry runs fn up to txRetryAttempts times, retrying only errors for
// which isRetriableTxError is true, with exponential backoff between
// attempts. fn must be safe to re-run from scratch: callers wrap a whole
// WithTx block (the aborted transaction is fully rolled back by PostgreSQL),
// never a statement inside an open transaction. Non-retriable errors and
// successes return immediately; when attempts are exhausted the last error is
// returned unchanged so callers' wrapping (and error opacity toward clients)
// is preserved.
func withRetry(ctx context.Context, fn func() error) error {
	var err error
	for attempt := 0; attempt < txRetryAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return errors.Join(err, ctx.Err())
			case <-time.After(txRetryBaseDelay << (attempt - 1)):
			}
		}
		err = fn()
		if err == nil || !isRetriableTxError(err) {
			return err
		}
	}
	return err
}
