package db

import (
	"context"
	"database/sql"
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

// The lease is only as good as the database's ability to notice a dead holder.
// Postgres inherits the OS keepalive defaults — about two hours idle on Linux —
// while facts expire after thirty seconds, so the lease sets its own session
// keepalives instead of asking every operator to tune the server.
func TestNodePolicyLeaseSetsSessionKeepalives(t *testing.T) {
	d := setupTestDB(t)
	ctx := context.Background()
	lease := d.NodePolicyLease()
	t.Cleanup(func() { _ = lease.Release(ctx) })
	if got, err := lease.Acquire(ctx); err != nil || !got {
		t.Fatalf("acquire: got=%v err=%v", got, err)
	}
	if lease.sessionSetting(t, "inet_server_addr") == "" {
		t.Skip("keepalives apply to TCP sessions only; this database is reached over a Unix socket")
	}
	for name, want := range map[string]string{"tcp_keepalives_idle": "5", "tcp_keepalives_interval": "2", "tcp_keepalives_count": "3", "tcp_user_timeout": "11000"} {
		if got := lease.sessionSetting(t, name); got != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
	// The settings belong to the holder, not to the pool: after release the
	// same backend, handed out again by the pool, must not carry them. The
	// pool prefers free connections over dialling, so draining it finds the
	// released backend deterministically.
	pid := lease.backendPID(t)
	if err := lease.Release(ctx); err != nil {
		t.Fatal(err)
	}
	var found *sql.Conn
	var taken []*sql.Conn
	defer func() {
		for _, c := range taken {
			_ = c.Close()
		}
	}()
	for i := 0; i < 8 && found == nil; i++ {
		c, err := d.conn.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		taken = append(taken, c)
		var p int
		if err := c.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&p); err != nil {
			t.Fatal(err)
		}
		if p == pid {
			found = c
		}
	}
	if found == nil {
		t.Fatalf("released backend %d did not return to the pool", pid)
	}
	var idle string
	if err := found.QueryRowContext(ctx, `SELECT current_setting('tcp_keepalives_idle')`).Scan(&idle); err != nil {
		t.Fatal(err)
	}
	// RESET restores the server's default, whatever it is; only the holder's
	// value is wrong here.
	if idle == "5" {
		t.Fatal("released session still carries the holder's keepalive setting")
	}
}

// sessionSetting reads a GUC (or, for inet_server_addr, the session's server
// address) on the pinned session; an SQL NULL reads as "".
func (l *NodePolicyLease) sessionSetting(t *testing.T, name string) string {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn == nil {
		t.Fatal("lease has no pinned connection")
	}
	query := `SELECT COALESCE(current_setting($1), '')`
	args := []any{name}
	if name == "inet_server_addr" {
		query, args = `SELECT COALESCE(inet_server_addr()::text, '')`, nil
	}
	var value string
	if err := l.conn.QueryRowContext(context.Background(), query, args...).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}
