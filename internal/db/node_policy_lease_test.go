package db

import (
	"context"
	"testing"
)

// Two OPS instances share one database. Exactly one of them may publish node
// policy at a time, and the loser must be able to take over once the holder
// lets go. Each lease pins its own connection, as two instances would.
func TestNodePolicyLeaseIsExclusiveAndTransferable(t *testing.T) {
	d := setupTestDB(t)
	ctx := context.Background()
	first, second := d.NodePolicyLease(), d.NodePolicyLease()
	t.Cleanup(func() { _ = first.Release(ctx); _ = second.Release(ctx) })

	// Nothing is held before acquisition.
	held, err := first.Held(ctx)
	if err != nil || held {
		t.Fatalf("fresh lease reports held=%v err=%v", held, err)
	}

	got, err := first.Acquire(ctx)
	if err != nil || !got {
		t.Fatalf("first acquisition: got=%v err=%v", got, err)
	}
	got, err = second.Acquire(ctx)
	if err != nil || got {
		t.Fatalf("second acquisition must fail while the first holds: got=%v err=%v", got, err)
	}

	held, err = first.Held(ctx)
	if err != nil || !held {
		t.Fatalf("holder reports held=%v err=%v", held, err)
	}
	held, err = second.Held(ctx)
	if err != nil || held {
		t.Fatalf("non-holder reports held=%v err=%v", held, err)
	}

	// Re-acquiring while already holding is idempotent, not a second lock.
	got, err = first.Acquire(ctx)
	if err != nil || !got {
		t.Fatalf("re-acquisition by the holder: got=%v err=%v", got, err)
	}

	// Release hands the lease over.
	if err := first.Release(ctx); err != nil {
		t.Fatal(err)
	}
	held, err = first.Held(ctx)
	if err != nil || held {
		t.Fatalf("released lease still held=%v err=%v", held, err)
	}
	got, err = second.Acquire(ctx)
	if err != nil || !got {
		t.Fatalf("second acquisition after release: got=%v err=%v", got, err)
	}
	held, err = second.Held(ctx)
	if err != nil || !held {
		t.Fatalf("new holder reports held=%v err=%v", held, err)
	}

	// Releasing a lease that is not held is harmless.
	if err := first.Release(ctx); err != nil {
		t.Fatalf("double release: %v", err)
	}
}

// A lease whose connection has gone away no longer holds anything, and says so
// instead of pretending. The next acquisition opens a fresh connection.
func TestNodePolicyLeaseSurvivesLosingItsConnection(t *testing.T) {
	d := setupTestDB(t)
	ctx := context.Background()
	lease := d.NodePolicyLease()
	t.Cleanup(func() { _ = lease.Release(ctx) })
	if got, err := lease.Acquire(ctx); err != nil || !got {
		t.Fatalf("acquire: got=%v err=%v", got, err)
	}
	pid := lease.backendPID(t)
	if _, err := d.conn.ExecContext(ctx, `SELECT pg_terminate_backend($1)`, pid); err != nil {
		t.Fatal(err)
	}
	held, _ := lease.Held(ctx)
	if held {
		t.Fatal("lease reports held after its backend was terminated")
	}
	if got, err := lease.Acquire(ctx); err != nil || !got {
		t.Fatalf("re-acquire on a fresh connection: got=%v err=%v", got, err)
	}
	if held, err := lease.Held(ctx); err != nil || !held {
		t.Fatalf("holder after reconnect reports held=%v err=%v", held, err)
	}
}

// backendPID exposes the pinned session so a test can kill it from outside.
func (l *NodePolicyLease) backendPID(t *testing.T) int {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn == nil {
		t.Fatal("lease has no pinned connection")
	}
	var pid int
	if err := l.conn.QueryRowContext(context.Background(), `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	return pid
}
