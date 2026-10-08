package db

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"privacy-proxy/internal/db/migrations"
	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/tern/v2/migrate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMigration071_ExpandsWildcardAllowedMethods exercises migration 071's
// one-time rewrite of group_access rows that hold "*" or "prefix*" entries
// (RD-1311). Like the 060 test it drives an isolated database to the migration
// before 071, seeds offending rows, applies 071 alone, and asserts the result.
func TestMigration071_ExpandsWildcardAllowedMethods(t *testing.T) {
	connStr, cleanup := SetupTestContainer(t)
	defer cleanup()
	if strings.Contains(connStr, "privacy_proxy_test") {
		t.Skip("needs an isolated, non-migrated database (testcontainers unavailable)")
	}
	ctx := context.Background()

	pgxConn, err := pgx.Connect(ctx, connStr)
	require.NoError(t, err)
	defer pgxConn.Close(ctx)

	migrator, err := migrate.NewMigrator(ctx, pgxConn, "schema_version")
	require.NoError(t, err)
	require.NoError(t, migrator.LoadMigrations(migrations.FS))

	var seq int32
	for i, m := range migrator.Migrations {
		if strings.HasPrefix(m.Name, "071_") {
			seq = int32(i + 1)
			break
		}
	}
	require.NotZero(t, seq, "migration 071 should be loaded")
	require.NoError(t, migrator.MigrateTo(ctx, seq-1))

	sqlDB, err := sql.Open("pgx", connStr)
	require.NoError(t, err)
	defer sqlDB.Close()

	orgID := uuid.New().String()
	_, err = sqlDB.ExecContext(ctx, `INSERT INTO organizations (id, slug, name) VALUES ($1, $2, 'Mig071')`,
		orgID, "mig071-"+uuid.New().String()[:8])
	require.NoError(t, err)
	userID := uuid.New().String()
	_, err = sqlDB.ExecContext(ctx, `INSERT INTO users (id, external_id) VALUES ($1, $2)`, userID, "did:mig071:"+userID)
	require.NoError(t, err)

	seed := func(methods []string) string {
		groupID := uuid.New().String()
		slug := "g-" + groupID[:8]
		_, e := sqlDB.ExecContext(ctx,
			`INSERT INTO groups (id, org_id, slug, name, path) VALUES ($1, $2, $3, $4, $5)`, groupID, orgID, slug, slug, slug)
		require.NoError(t, e)
		_, e = sqlDB.ExecContext(ctx,
			`INSERT INTO group_access (id, group_id, allowed_methods, claims) VALUES ($1, $2, $3, '{deploy}')`,
			uuid.New().String(), groupID, methods)
		require.NoError(t, e)
		return groupID
	}
	star := seed([]string{"*"})
	starPlusExplicit := seed([]string{"eth_getProof", "*"})
	chainGlob := seed([]string{"eth_call", "linea_*", "linea_estimateGas"})
	traceGlob := seed([]string{"debug_*"})
	oddStars := seed([]string{"a*b", "**", "eth_call"})
	noStar := seed([]string{"eth_call", "trace_block"})
	// The anonymous group (seeded by 044) never honored "*": expanding it
	// would widen unauthenticated access, so its star entries are only dropped.
	_, err = sqlDB.ExecContext(ctx, `UPDATE group_access SET allowed_methods = $1 WHERE group_id = $2`,
		[]string{"*", "eth_chainId"}, rbac.AnonymousGroupID)
	require.NoError(t, err)

	// A cached permission row derived from a "*" group, and one that is not.
	_, err = sqlDB.ExecContext(ctx,
		`INSERT INTO effective_permissions_cache (user_id, org_id, allowed_methods, expires_at)
		 VALUES ($1, $2, '{*}', NOW() + INTERVAL '1 hour')`, userID, orgID)
	require.NoError(t, err)
	otherUser := uuid.New().String()
	_, err = sqlDB.ExecContext(ctx, `INSERT INTO users (id, external_id) VALUES ($1, $2)`, otherUser, "did:mig071:"+otherUser)
	require.NoError(t, err)
	_, err = sqlDB.ExecContext(ctx,
		`INSERT INTO effective_permissions_cache (user_id, org_id, allowed_methods, expires_at)
		 VALUES ($1, $2, '{eth_call}', NOW() + INTERVAL '1 hour')`, otherUser, orgID)
	require.NoError(t, err)
	var genBefore int64
	require.NoError(t, sqlDB.QueryRowContext(ctx, `SELECT generation FROM rbac_cache_generation WHERE id = 1`).Scan(&genBefore))

	require.NoError(t, migrator.MigrateTo(ctx, seq))

	methodsOf := func(groupID string) []string {
		var out []string
		require.NoError(t, sqlDB.QueryRowContext(ctx,
			`SELECT allowed_methods FROM group_access WHERE group_id = $1`, groupID).Scan(ScanTextArray(&out)))
		return out
	}

	// "*" becomes the explicit built-in "*" expansion, a point-in-time
	// snapshot pinned here in full (byte-order sorted, deduplicated). It must
	// never grant a method runtime "*" would not.
	starMethods := methodsOf(star)
	assert.Equal(t, []string{
		"debug_traceCall", "debug_traceTransaction",
		"eth_accounts", "eth_blockNumber", "eth_call", "eth_chainId", "eth_estimateGas", "eth_feeHistory",
		"eth_gasPrice", "eth_getBalance", "eth_getBlockByHash", "eth_getBlockByNumber",
		"eth_getBlockTransactionCountByHash", "eth_getBlockTransactionCountByNumber", "eth_getCode",
		"eth_getLogs", "eth_getStorageAt", "eth_getTransactionByBlockHashAndIndex",
		"eth_getTransactionByBlockNumberAndIndex", "eth_getTransactionByHash", "eth_getTransactionCount",
		"eth_getTransactionReceipt", "eth_maxPriorityFeePerGas", "eth_sendRawTransaction",
		"eth_sendTransaction", "eth_syncing",
		"net_listening", "net_peerCount", "net_version",
		"web3_clientVersion", "web3_sha3",
	}, starMethods)
	for _, m := range starMethods {
		assert.Truef(t, rbac.InWildcardExpansion(m), "migration grants %s, which runtime '*' does not", m)
	}

	// Explicit entries next to "*" are kept.
	withProof := methodsOf(starPlusExplicit)
	assert.Contains(t, withProof, "eth_getProof")
	assert.ElementsMatch(t, append(append([]string{}, starMethods...), "eth_getProof"), withProof)

	// Globs are dropped, never expanded by prefix: a glob granted methods only
	// through an operator wildcard, which never covered catalog methods, so
	// expanding "debug_*" would grant what it never granted. The explicit
	// entries around a glob stay; a glob-only row ends up empty (fail-closed).
	assert.Equal(t, []string{"eth_call", "linea_estimateGas"}, methodsOf(chainGlob))
	assert.Empty(t, methodsOf(traceGlob))
	// Star patterns that were never honored are dropped.
	assert.Equal(t, []string{"eth_call"}, methodsOf(oddStars))
	// Rows without any "*" entry are untouched (unknown names stay; the
	// runtime gate refuses them).
	assert.Equal(t, []string{"eth_call", "trace_block"}, methodsOf(noStar))
	assert.Equal(t, []string{"eth_chainId"}, methodsOf(rbac.AnonymousGroupID), "anonymous '*' is dropped, never expanded")

	var starRows int
	require.NoError(t, sqlDB.QueryRowContext(ctx,
		`SELECT count(*) FROM group_access WHERE EXISTS (SELECT 1 FROM unnest(allowed_methods) m WHERE strpos(m, '*') > 0)`).Scan(&starRows))
	assert.Zero(t, starRows, "no group_access row may hold a '*' entry after 071")

	// Cache rows derived from rewritten groups are invalidated (RD-1267
	// protocol: delete + generation bump); others are kept.
	var cached int
	require.NoError(t, sqlDB.QueryRowContext(ctx,
		`SELECT count(*) FROM effective_permissions_cache WHERE user_id = $1`, userID).Scan(&cached))
	assert.Zero(t, cached)
	require.NoError(t, sqlDB.QueryRowContext(ctx,
		`SELECT count(*) FROM effective_permissions_cache WHERE user_id = $1`, otherUser).Scan(&cached))
	assert.Equal(t, 1, cached)
	var genAfter int64
	require.NoError(t, sqlDB.QueryRowContext(ctx, `SELECT generation FROM rbac_cache_generation WHERE id = 1`).Scan(&genAfter))
	assert.Greater(t, genAfter, genBefore)
}
