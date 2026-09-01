package db_test

import (
	"context"
	"testing"

	"privacy-proxy/internal/db"
	migrationsaudit "privacy-proxy/internal/db/migrations_audit"
)

// TestNewWithoutMigrateUTCPinned proves the RD-1256 fix: NewWithoutMigrate must
// pin the session timezone to UTC exactly like New does (RD-1005). The audit
// pools are opened through NewWithoutMigrate, so before the fix they inherited
// the server's default timezone GUC and skewed NOW()/CURRENT_TIMESTAMP
// comparisons against Go-written plain TIMESTAMP values.
func TestNewWithoutMigrateUTCPinned(t *testing.T) {
	url, cleanup := db.SetupTestContainer(t)
	t.Cleanup(cleanup)

	ctx := context.Background()

	// Skew the database-level default timezone so an un-pinned session would
	// inherit a non-UTC value.
	bootstrap, err := db.NewWithoutMigrate(url)
	if err != nil {
		t.Fatalf("open bootstrap handle: %v", err)
	}
	var dbName string
	if err := bootstrap.Conn().QueryRowContext(ctx, "SELECT current_database()").Scan(&dbName); err != nil {
		bootstrap.Close()
		t.Fatalf("current_database: %v", err)
	}
	if _, err := bootstrap.Conn().ExecContext(ctx, `ALTER DATABASE "`+dbName+`" SET timezone TO 'America/New_York'`); err != nil {
		bootstrap.Close()
		t.Fatalf("skew database timezone: %v", err)
	}
	bootstrap.Close()

	handle, err := db.NewWithoutMigrate(url)
	if err != nil {
		t.Fatalf("open handle after skew: %v", err)
	}
	t.Cleanup(func() { handle.Close() })

	var tz string
	if err := handle.Conn().QueryRowContext(ctx, "SHOW timezone").Scan(&tz); err != nil {
		t.Fatalf("SHOW timezone: %v", err)
	}
	if tz != "UTC" {
		t.Fatalf("NewWithoutMigrate session timezone = %q, want UTC (RD-1005 pinning missing)", tz)
	}
}

// TestAuditHandlesDelegate exercises the RD-1256 role-scoped audit handles
// end-to-end against a real lean-migrated audit database: the runtime handle
// writes and reads access logs, the admin handle runs the retention counters.
func TestAuditHandlesDelegate(t *testing.T) {
	url, cleanup := db.SetupTestContainer(t)
	t.Cleanup(cleanup)

	ctx := context.Background()

	pool, err := db.NewWithoutMigrate(url)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	if err := pool.MigrateAuditOnly(ctx, migrationsaudit.FS); err != nil {
		t.Fatalf("apply lean audit migrations: %v", err)
	}

	runtime := db.NewAuditHandle(pool)
	admin := db.NewAuditAdminHandle(pool)

	if err := runtime.LogAccess(ctx, "did:test:rd1256", "eth_blockNumber", 200, "127.0.0.1"); err != nil {
		t.Fatalf("runtime LogAccess: %v", err)
	}
	total, err := admin.CountAccessLogsTotal(ctx)
	if err != nil {
		t.Fatalf("admin CountAccessLogsTotal: %v", err)
	}
	if total != 1 {
		t.Fatalf("CountAccessLogsTotal = %d, want 1", total)
	}

	// The pool-identity accessor is what Server.Stop uses for its double-close
	// aliasing guards; both handles wrap the same pool here.
	if runtime.Conn() != pool.Conn() || admin.Conn() != pool.Conn() {
		t.Fatal("role handles must expose the wrapped pool's connection")
	}
}
