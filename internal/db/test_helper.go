package db

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	migrationsaudit "privacy-proxy/internal/db/migrations_audit"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// EnsureAuditSchemaForTest re-applies the lean audit migration set
// (internal/db/migrations_audit) to the SAME database handle so access_logs +
// the audit_chain_* tables exist there for tests (RD-1147).
//
// In production access_logs lives ONLY in a separate audit database; migration
// 068 drops it from main. Tests, however, co-locate access_logs with the main
// schema in a single testcontainer for simplicity (and because most Server test
// literals leave auditDB nil, so accessLogDB() falls back to the main handle).
// The lean FS is idempotent (CREATE ... IF NOT EXISTS, separate schema_version_
// audit tern table, CREATE ROLE guarded), so applying it on top of a
// main-migrated DB simply re-creates access_logs and re-grants — the chain
// tables already exist and no-op. Safe to call repeatedly.
func EnsureAuditSchemaForTest(database *DB) error {
	return database.MigrateAuditOnly(context.Background(), migrationsaudit.FS)
}

// EnsureTestDatabase creates the test database if it doesn't exist
// This is exported so it can be used by other test packages
func EnsureTestDatabase(dbURL string) error {
	// Parse the database URL to extract components
	// Format: postgres://user:password@host:port/database?sslmode=disable

	// Extract database name from URL
	parts := strings.Split(dbURL, "/")
	if len(parts) < 4 {
		return fmt.Errorf("invalid database URL format")
	}

	dbNamePart := strings.Split(parts[3], "?")[0]
	if dbNamePart == "" {
		return fmt.Errorf("no database name in URL")
	}

	// Create connection URL to 'postgres' database (default)
	baseURL := strings.Replace(dbURL, "/"+dbNamePart, "/postgres", 1)
	if idx := strings.Index(baseURL, "?"); idx == -1 {
		baseURL += "?sslmode=disable"
	}

	// Connect to postgres database to create test database
	conn, err := sql.Open("pgx", baseURL)
	if err != nil {
		return fmt.Errorf("failed to connect to postgres: %w", err)
	}
	defer conn.Close()

	ctx := context.Background()
	if err := conn.PingContext(ctx); err != nil {
		return fmt.Errorf("failed to ping postgres: %w", err)
	}

	// Check if database exists (using parameterized query for safety)
	var exists bool
	checkQuery := "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)"
	err = conn.QueryRow(checkQuery, dbNamePart).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check database existence: %w", err)
	}

	// Create database if it doesn't exist
	if !exists {
		// Terminate any existing connections to the database
		terminateQuery := `
			SELECT pg_terminate_backend(pg_stat_activity.pid)
			FROM pg_stat_activity
			WHERE pg_stat_activity.datname = $1
			AND pid <> pg_backend_pid()`
		conn.Exec(terminateQuery, dbNamePart)

		// Note: CREATE DATABASE doesn't support parameters, but dbNamePart is controlled
		// and only used in test code, so it's safe
		createQuery := fmt.Sprintf("CREATE DATABASE %s", dbNamePart)
		_, err = conn.Exec(createQuery)
		if err != nil {
			return fmt.Errorf("failed to create database: %w", err)
		}
	}

	return nil
}

// ResetTestDatabase clears all data tables to get a clean slate.
// This preserves the schema and migration state while clearing test data.
// This is useful when using an external PostgreSQL database that may have leftover data.
func ResetTestDatabase(database *DB) error {
	ctx := context.Background()
	conn := database.Conn()

	// RD-1147: production drops access_logs from main (migration 068) — it lives
	// in a separate audit DB. Tests co-locate it, so re-create access_logs + the
	// chain tables in this container via the lean audit FS before the DELETEs
	// below (which include access_logs). Idempotent; no-op after the first call.
	if err := EnsureAuditSchemaForTest(database); err != nil {
		return fmt.Errorf("failed to ensure audit schema for test: %w", err)
	}

	// Delete data from tables in correct order to respect foreign keys
	// This is safer than TRUNCATE which can cause deadlocks in concurrent tests
	tables := []string{
		// Remove desired-state ownership before clearing its projected rows.
		// Production projection guards intentionally reject direct writes while
		// an active revision owns the stream.
		"configuration_revisions",
		"node_submissions",
		"tx_visible_to",
		"rbac_audit_log",
		"effective_permissions_cache",
		"contract_grants",
		"contracts",
		"user_memberships",
		"group_access",
		"allowed_azure_tenants",
		"groups",
		"users",
		"organizations",
		"disclosure_access_events",
		"disclosure_reports",
		"disclosure_grants",
		"disclosure_requests",
		"refresh_tokens",
		"revoked_tokens",
		"access_logs",
		"audit_chain_anchor",
		// RD-1112 signed-checkpoint + break-glass tables. Stand-alone (no FK
		// cascade from access_logs), so they must be reset explicitly. Without
		// this, a checkpoint left by an earlier test/package on a SHARED Postgres
		// (CI) survives, and the verifier — which validates every chain_name's
		// checkpoint with the caller's single signer — rejects the foreign-key
		// signature (checkpoint_signature_invalid), an order-dependent flake.
		"audit_chain_checkpoint",
		"audit_chain_reanchor",
		"eth_address_links",
		// RD-993: stand-alone audit table (no FK cascade), so explicit reset
		// is required to keep tests isolated when they run against a shared
		// external Postgres (CI). Local testcontainer runs would otherwise
		// hide the leak.
		"oauth_silent_sso_log",
	}

	for _, table := range tables {
		_, err := conn.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s", table))
		if err != nil {
			// Ignore errors for tables that might not exist
			if !strings.Contains(err.Error(), "does not exist") {
				return fmt.Errorf("failed to clear table %s: %w", table, err)
			}
		}
	}

	return nil
}

var harnessDatabaseSequence uint64

func uniqueHarnessDatabaseURL(baseURL string) (string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parse E2E_DATABASE_URL: %w", err)
	}
	baseName := strings.TrimPrefix(parsed.Path, "/")
	if baseName == "" || strings.Contains(baseName, "/") {
		return "", fmt.Errorf("E2E_DATABASE_URL must contain one database name")
	}

	var sanitized strings.Builder
	for _, char := range strings.ToLower(baseName) {
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '_' {
			sanitized.WriteRune(char)
		} else {
			sanitized.WriteByte('_')
		}
	}
	name := strings.Trim(sanitized.String(), "_")
	if name == "" {
		name = "e2e"
	}
	if name[0] >= '0' && name[0] <= '9' {
		name = "e2e_" + name
	}
	if len(name) > 24 {
		name = name[:24]
	}
	name = fmt.Sprintf("%s_h%d_%d", name, os.Getpid(), atomic.AddUint64(&harnessDatabaseSequence, 1))

	parsed.Path = "/" + name
	parsed.RawPath = ""
	return parsed.String(), nil
}

// SetupTestContainer creates a fresh child database on the harness-owned
// PostgreSQL server, or starts an isolated PostgreSQL testcontainer.
// Callers that intentionally support TEST_DATABASE_URL must opt in before
// calling this helper.
// There is deliberately no implicit localhost fallback: ResetTestDatabase deletes
// data, so a failed testcontainer must never redirect a run to an unowned database.
func SetupTestContainer(t *testing.T) (string, func()) {
	ctx := context.Background()

	if baseURL := strings.TrimSpace(os.Getenv("E2E_DATABASE_URL")); baseURL != "" {
		dbURL, err := uniqueHarnessDatabaseURL(baseURL)
		if err != nil {
			t.Fatalf("invalid E2E_DATABASE_URL: %v", err)
		}
		if err := EnsureTestDatabase(dbURL); err != nil {
			t.Fatalf("could not create a fresh database on harness-owned PostgreSQL: %v", err)
		}
		t.Log("using a fresh child database on harness-owned PostgreSQL")
		return dbURL, func() {}
	}

	// Start an isolated PostgreSQL container.
	postgresContainer, err := postgres.RunContainer(ctx,
		testcontainers.WithImage("postgres:15-alpine"),
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("failed to start isolated PostgreSQL testcontainer: %v (Docker is required; no implicit external fallback is used)", err)
	}

	// Get connection string
	connStr, err := postgresContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		if terminateErr := postgresContainer.Terminate(ctx); terminateErr != nil {
			t.Logf("failed to terminate PostgreSQL testcontainer after connection-string error: %v", terminateErr)
		}
		t.Fatalf("failed to get isolated PostgreSQL testcontainer connection string: %v", err)
	}

	// Cleanup function
	cleanup := func() {
		if err := postgresContainer.Terminate(ctx); err != nil {
			t.Logf("failed to terminate container: %v", err)
		}
	}

	return connStr, cleanup
}
