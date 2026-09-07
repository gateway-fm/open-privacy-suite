package db

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// WithTx wraps two errors when a rolled-back transaction ALSO fails to roll
// back. Both must stay inspectable: internal/db/retry.go classifies retriable
// failures with errors.As on *pgconn.PgError, so if the original cause is
// formatted with %v instead of being wrapped, a deadlock whose rollback also
// fails becomes unclassifiable and silently loses its retry (RD-1278).
//
// This exercises the wrapping shape directly rather than through a real
// transaction, because provoking a genuine deadlock AND a genuine rollback
// failure in the same transaction is not reliably reproducible.
func TestWithTxErrorWrapping_PreservesRetriableCause(t *testing.T) {
	deadlock := &pgconn.PgError{Code: sqlstateDeadlockDetected, Message: "deadlock detected"}
	rollbackErr := errors.New("rollback failed: connection reset")

	combined := wrapTxAndRollbackErrors(deadlock, rollbackErr)

	var pgErr *pgconn.PgError
	if !errors.As(combined, &pgErr) {
		t.Fatalf("the original PgError is not reachable through the combined error: %v", combined)
	}
	if pgErr.Code != sqlstateDeadlockDetected {
		t.Fatalf("recovered SQLSTATE = %q, want %q", pgErr.Code, sqlstateDeadlockDetected)
	}

	// The whole point: the retry classifier must still see it as retriable.
	if !isRetriableTxError(combined) {
		t.Error("isRetriableTxError = false for a deadlock whose rollback also failed; the retry is silently lost")
	}

	// The rollback failure must not be swallowed either — an operator needs
	// to know the connection was left in a bad state.
	if !errors.Is(combined, rollbackErr) {
		t.Errorf("rollback cause not reachable through the combined error: %v", combined)
	}
}

// A non-retriable cause must stay non-retriable even when the rollback fails,
// so the fix cannot make everything look retriable.
func TestWithTxErrorWrapping_DoesNotInventRetriability(t *testing.T) {
	plain := fmt.Errorf("constraint violated")
	combined := wrapTxAndRollbackErrors(plain, errors.New("rollback failed"))

	if isRetriableTxError(combined) {
		t.Error("isRetriableTxError = true for a non-PgError cause; retry classification is now over-inclusive")
	}
	if !errors.Is(combined, plain) {
		t.Error("original cause not reachable")
	}
}
