package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// DBTX is an interface satisfied by both *sql.DB and *sql.Tx.
//
// It is the shared-querier seam for every query that exists on both *DB and
// *Tx (RD-1257): the SQL + scan logic lives in one unexported function taking
// a DBTX, and the *DB / *Tx methods are thin delegations passing d.conn or
// t.tx. Never hand-copy a query between the two receivers — the copies drift
// (dropped columns, skipped normalization; see tx_twin_divergence_test.go).
type DBTX interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Tx wraps a database transaction and provides the same methods as DB.
type Tx struct {
	tx          *sql.Tx
	databaseURL string
}

// BeginTx starts a new database transaction.
func (d *DB) BeginTx(ctx context.Context) (*Tx, error) {
	tx, err := d.conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	return &Tx{tx: tx, databaseURL: d.databaseURL}, nil
}

// Commit commits the transaction.
func (t *Tx) Commit() error {
	return t.tx.Commit()
}

// Rollback rolls back the transaction.
func (t *Tx) Rollback() error {
	return t.tx.Rollback()
}

// WithTx executes a function within a transaction.
// If the function returns an error, the transaction is rolled back.
// If the function succeeds, the transaction is committed.
func (d *DB) WithTx(ctx context.Context, fn func(*Tx) error) error {
	tx, err := d.BeginTx(ctx)
	if err != nil {
		return err
	}

	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return wrapTxAndRollbackErrors(err, rbErr)
		}
		return err
	}

	return tx.Commit()
}

// wrapTxAndRollbackErrors combines a failed transaction body with a failed
// rollback so that BOTH stay inspectable.
//
// errors.Join rather than a %v/%w pair: retry.go classifies retriable
// failures with errors.As on *pgconn.PgError, and formatting the original
// cause with %v dropped it from the unwrap chain — so a deadlock whose
// rollback also failed was unclassifiable and silently lost its retry
// (RD-1278). The rollback failure matters too, because it means the
// connection was left in a bad state, so neither error may be discarded.
func wrapTxAndRollbackErrors(err, rbErr error) error {
	return errors.Join(
		fmt.Errorf("tx failed: %w", err),
		fmt.Errorf("rollback failed: %w", rbErr),
	)
}
