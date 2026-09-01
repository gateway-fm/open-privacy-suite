package db

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func wrappedPgError(code string) error {
	return fmt.Errorf("failed to create contract grant: %w", &pgconn.PgError{Code: code, Message: "test"})
}

func TestIsRetriableTxError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"plain error", errors.New("boom"), false},
		{"wrapped deadlock 40P01", wrappedPgError("40P01"), true},
		{"wrapped serialization failure 40001", wrappedPgError("40001"), true},
		{"unique violation 23505", wrappedPgError("23505"), false},
		{"deeply wrapped deadlock", fmt.Errorf("outer: %w", wrappedPgError("40P01")), true},
		{"context canceled", context.Canceled, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRetriableTxError(tt.err); got != tt.want {
				t.Fatalf("isRetriableTxError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestWithRetry_RetriableThenSuccess(t *testing.T) {
	calls := 0
	err := withRetry(context.Background(), func() error {
		calls++
		if calls < 3 {
			return wrappedPgError("40P01")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("expected success after retries, got: %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 attempts, got %d", calls)
	}
}

func TestWithRetry_NonRetriableSingleAttempt(t *testing.T) {
	calls := 0
	wantErr := wrappedPgError("23505")
	err := withRetry(context.Background(), func() error {
		calls++
		return wantErr
	})
	if calls != 1 {
		t.Fatalf("expected exactly 1 attempt for a non-retriable error, got %d", calls)
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected the original error to be returned unchanged, got: %v", err)
	}
}

func TestWithRetry_Exhausted(t *testing.T) {
	calls := 0
	err := withRetry(context.Background(), func() error {
		calls++
		return wrappedPgError("40001")
	})
	if calls != txRetryAttempts {
		t.Fatalf("expected %d attempts, got %d", txRetryAttempts, calls)
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "40001" {
		t.Fatalf("expected the last retriable error to be surfaced with its cause intact, got: %v", err)
	}
}

func TestWithRetry_ContextCancelledBetweenAttempts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	err := withRetry(ctx, func() error {
		calls++
		return wrappedPgError("40P01")
	})
	if calls != 1 {
		t.Fatalf("expected exactly 1 attempt with a cancelled context, got %d", calls)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled in the error chain, got: %v", err)
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("expected the last DB error to stay inspectable alongside ctx error, got: %v", err)
	}
}

// TestIsRetriableTxError_RealDeadlock proves that a real PostgreSQL deadlock
// surfaces through the pgx stdlib driver + database/sql as an inspectable
// *pgconn.PgError with SQLSTATE 40P01, i.e. that the classifier works against
// the wire, not just constructed errors.
func TestIsRetriableTxError_RealDeadlock(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	d := setupTestDB(t)
	defer cleanupTestDB(t, d)
	ctx := context.Background()

	if _, err := d.conn.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS retry_deadlock_probe (id INT PRIMARY KEY, n INT NOT NULL)`); err != nil {
		t.Fatalf("create probe table: %v", err)
	}
	if _, err := d.conn.ExecContext(ctx,
		`INSERT INTO retry_deadlock_probe (id, n) VALUES (1, 0), (2, 0) ON CONFLICT (id) DO NOTHING`); err != nil {
		t.Fatalf("seed probe table: %v", err)
	}

	tx1, err := d.conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin tx1: %v", err)
	}
	defer func() { _ = tx1.Rollback() }()
	tx2, err := d.conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin tx2: %v", err)
	}
	defer func() { _ = tx2.Rollback() }()

	// Each transaction locks one row, then tries to lock the other's row —
	// PostgreSQL resolves the cycle by aborting one side with SQLSTATE 40P01
	// after deadlock_timeout (default 1s).
	if _, err := tx1.ExecContext(ctx, `UPDATE retry_deadlock_probe SET n = n + 1 WHERE id = 1`); err != nil {
		t.Fatalf("tx1 first update: %v", err)
	}
	if _, err := tx2.ExecContext(ctx, `UPDATE retry_deadlock_probe SET n = n + 1 WHERE id = 2`); err != nil {
		t.Fatalf("tx2 first update: %v", err)
	}

	errCh := make(chan error, 2)
	go func() {
		_, err := tx1.ExecContext(ctx, `UPDATE retry_deadlock_probe SET n = n + 1 WHERE id = 2`)
		errCh <- err
	}()
	go func() {
		_, err := tx2.ExecContext(ctx, `UPDATE retry_deadlock_probe SET n = n + 1 WHERE id = 1`)
		errCh <- err
	}()

	var deadlockErr error
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			deadlockErr = err
		}
	}
	if deadlockErr == nil {
		t.Fatal("expected one of the two transactions to be aborted with a deadlock")
	}
	if !isRetriableTxError(deadlockErr) {
		t.Fatalf("real deadlock not classified as retriable: %v", deadlockErr)
	}
}
