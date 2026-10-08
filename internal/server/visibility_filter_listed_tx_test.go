package server

import (
	"context"
	"sort"
	"strings"
	"testing"

	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// RD-1307: the explorer decides "is the viewer listed in this tx's visibleTo?"
// (the RD-874 unlock and the ordinary param-rule fallback) from the viewer's
// genuine tx_visible_to rows only — never from the RD-1009 transfer-participant
// union, which also lives in VisibleTxHashes for row survival.

func TestRedactOptsFromFilter_ListedTxHashesAreOnlyGenuineListings(t *testing.T) {
	listed := "0x" + strings.Repeat("aa", 32)
	union := "0x" + strings.Repeat("bb", 32)
	filter := &explorer.VisibilityFilter{
		AllPrivate:          true,
		VisibleTxHashes:     []string{listed, union},
		ParticipantTxHashes: []string{union},
		ListedTxHashes:      []string{strings.ToUpper(listed[:2]) + listed[2:]},
	}
	opts := redactOptsFromFilter(filter)
	require.Equal(t, map[string]bool{listed: true}, opts.ListedTxHashes, "only tx_visible_to hashes, lowercased")
	require.True(t, opts.VisibleTxHashes[union], "the union still drives row survival")

	// The disclosure-address copy keeps the listing.
	cp := (&Server{}).addDisclosureAddressToFilter(filter, "0x"+strings.Repeat("cc", 20))
	require.Equal(t, filter.ListedTxHashes, cp.ListedTxHashes)
}

func TestBuildVisibilityFilter_ListedTxHashesExcludeTransferUnion(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	srv.config.ReadProfile = rbac.ReadProfileStandard
	_, err := conn.ExecContext(context.Background(), extendedExplorerSchemaRD1009)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = conn.ExecContext(context.Background(), "DROP TABLE IF EXISTS token_transfers") })
	ctx := context.Background()

	orgID := uuid.New().String()
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{ID: orgID, Slug: "listed-org", Name: "Listed", Settings: map[string]any{}}))
	gid := wiringCreateGroup(t, database, orgID, "listed-grantees", nil, false)
	contract := "0x" + strings.Repeat("c1", 20)
	cid := wiringCreateContractWithABI(t, database, orgID, contract, "Payments", erc20ABI)
	wiringCreateGrant(t, database, cid, gid, &rbac.EventRulesField{Wildcard: true})
	const viewer = "did:test:listed-viewer"
	wiringCreateUserInGroup(t, database, viewer, gid)
	viewerAddr := "0x" + strings.Repeat("d4", 20)
	require.NoError(t, database.SystemLinkEthAddress(ctx, viewer, viewerAddr))

	listed := "0x" + strings.Repeat("a1", 32)
	unionViewer := "0x" + strings.Repeat("a2", 32)   // viewer's own address is a transfer party
	unionContract := "0x" + strings.Repeat("a3", 32) // the granted contract is a transfer party
	block := seedExplorerBlock(t, conn)
	for _, h := range []string{listed, unionViewer, unionContract} {
		seedExplorerTransaction(t, conn, block, h, "0x"+strings.Repeat("e5", 20), contract)
	}
	for _, tt := range []struct{ tx, from, to string }{
		{unionViewer, "0x" + strings.Repeat("e5", 20), viewerAddr},
		{unionContract, contract, "0x" + strings.Repeat("e5", 20)},
	} {
		_, err := conn.ExecContext(ctx,
			`INSERT INTO token_transfers (tx_hash, log_index, token_address, from_address, to_address, value, block_number) VALUES ($1, 0, $2, $3, $4, 1, $5)`,
			tt.tx, contract, tt.from, tt.to, block)
		require.NoError(t, err)
	}
	require.NoError(t, database.SaveTxVisibility(ctx, listed, []string{viewer}, "did:test:sender", orgID))

	filter := srv.buildVisibilityFilter(ctx, viewer)
	visible := append([]string(nil), filter.VisibleTxHashes...)
	sort.Strings(visible)
	require.Equal(t, []string{listed, unionViewer, unionContract}, visible, "precondition: the union feeds VisibleTxHashes")
	require.Equal(t, []string{listed}, filter.ListedTxHashes, "only the genuine listing may be treated as 'listed'")

	opts := srv.buildRedactOptsForViewer(ctx, viewer)
	require.Equal(t, map[string]bool{listed: true}, opts.ListedTxHashes)
}
