package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"privacy-proxy/internal/disclosure"
	"privacy-proxy/internal/viewscope"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// FullDisclosureGrantAddresses is the lookup behind the shared disclosure-grant
// fact of the read decisions: the addresses an active, approved Full grant of
// the viewer covers. It must agree with the grant merge in GetBatchVisibility
// (same membership scoping and level mapping), and admit nothing that is not a
// live Full grant.
func TestFullDisclosureGrantAddresses(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)
	ctx := context.Background()
	conn := database.Conn()
	day := time.Now().Add(24 * time.Hour)

	type grant struct {
		viewer, target, addr, level string
		expires                     time.Time
	}
	grants := map[string]grant{
		"full":         {"did:test:fga_full", "did:test:fga_t_full", "0xfa00000000000000000000000000000000000001", "full", day},
		"full_case":    {"did:test:fga_case", "did:test:fga_t_case", "0xfa00000000000000000000000000000000000002", " Full ", day},
		"pseudonymous": {"did:test:fga_pseudo", "did:test:fga_t_pseudo", "0xfa00000000000000000000000000000000000003", "pseudonymous", day},
		"redacted":     {"did:test:fga_red", "did:test:fga_t_red", "0xfa00000000000000000000000000000000000004", "redacted", day},
		"missing":      {"did:test:fga_missing", "did:test:fga_t_missing", "0xfa00000000000000000000000000000000000005", "", day},
		"expired":      {"did:test:fga_expired", "did:test:fga_t_expired", "0xfa00000000000000000000000000000000000006", "full", time.Now().Add(-time.Hour)},
		"revoked":      {"did:test:fga_revoked", "did:test:fga_t_revoked", "0xfa00000000000000000000000000000000000007", "full", day},
	}
	orgs := map[string]string{}
	for name, g := range grants {
		orgID, _, grantID := setupDisclosureGrantWithLevel(t, database, g.viewer, g.target, g.addr, g.level, g.expires)
		orgs[name] = orgID
		if name == "revoked" {
			_, err := conn.ExecContext(ctx, `UPDATE disclosure_grants SET revoked_at = NOW() WHERE id = $1`, grantID)
			require.NoError(t, err)
		}
	}

	got := func(ctx context.Context, viewer string) map[string]bool {
		t.Helper()
		addrs, err := database.FullDisclosureGrantAddresses(ctx, viewer)
		require.NoError(t, err)
		out := map[string]bool{}
		for a, ids := range addrs {
			require.NotEmpty(t, ids, "a covered address names its grants")
			out[a] = true
		}
		return out
	}

	assert.Equal(t, map[string]bool{grants["full"].addr: true}, got(ctx, grants["full"].viewer), "an active Full grant covers its subject's address")
	ids, err := database.FullDisclosureGrantAddresses(ctx, grants["full"].viewer)
	require.NoError(t, err)
	assert.Len(t, ids[grants["full"].addr], 1, "the covering grant's id is returned for the audit trail")
	assert.True(t, got(ctx, grants["full_case"].viewer)[grants["full_case"].addr], "the level is matched like the visibility merge (case and spaces ignored)")
	for _, name := range []string{"pseudonymous", "redacted", "missing", "expired", "revoked"} {
		assert.Empty(t, got(ctx, grants[name].viewer), "%s grant must not count as Full", name)
	}
	assert.Empty(t, got(ctx, ""), "an anonymous viewer holds no grant")
	assert.Empty(t, got(ctx, grants["pseudonymous"].target), "a grant belongs to its requester, not its subject")

	// Under the impersonation mark (View-as / dry-run) the viewer's grants do
	// not apply.
	assert.Empty(t, got(disclosure.WithoutViewerGrants(ctx), grants["full"].viewer), "the impersonation mark suppresses the grant")

	// An impersonated read pinned to another org counts only grants requested
	// in that org.
	assert.Empty(t, got(viewscope.WithOrg(ctx, orgs["pseudonymous"]), grants["full"].viewer), "a read pinned to another org ignores the grant")
	assert.True(t, got(viewscope.WithOrg(ctx, orgs["full"]), grants["full"].viewer)[grants["full"].addr], "a read pinned to the grant's org keeps it")

	// Agreement with the visibility merge.
	vis, err := database.GetBatchVisibilityDetailed(ctx, grants["full"].viewer, []string{grants["full"].addr})
	require.NoError(t, err)
	assert.Equal(t, "full", string(vis[grants["full"].addr].Level))

	// A Full grant scoped to a date range or to contract addresses is honoured
	// on its grant pages only, never as a regular read (fail closed, also for a
	// malformed restriction). An empty address list restricts nothing.
	for _, sc := range []struct {
		name, scope string
		covers      bool
	}{
		{"date_range", `{"disclosure_level":"full","date_range":{"start":"2026-01-01T00:00:00Z","end":"2026-02-01T00:00:00Z"}}`, false},
		{"addresses", `{"disclosure_level":"full","addresses":["0x70c3000000000000000000000000000000000003"]}`, false},
		{"malformed_addresses", `{"disclosure_level":"full","addresses":"0x70c3"}`, false},
		{"empty_addresses", `{"disclosure_level":"full","addresses":[],"date_range":null}`, true},
		{"methods_only", `{"disclosure_level":"full","methods":["activity_logs"]}`, true},
	} {
		viewer := "did:test:fga_scope_" + sc.name
		addr := "0xfb" + fmt.Sprintf("%038x", len(sc.name)*7919)
		_, _, grantID := setupDisclosureGrantWithLevel(t, database, viewer, "did:test:fga_scope_t_"+sc.name, addr, "full", day)
		_, err := conn.ExecContext(ctx, `UPDATE disclosure_grants SET scope = $1::jsonb WHERE id = $2`, sc.scope, grantID)
		require.NoError(t, err)
		assert.Equal(t, sc.covers, got(ctx, viewer)[addr], "%s grant", sc.name)
		vis, err := database.GetBatchVisibility(ctx, viewer, []string{addr})
		require.NoError(t, err)
		assert.Equal(t, "full", string(vis[addr]), "%s: the visibility merge is unchanged", sc.name)
	}
}
