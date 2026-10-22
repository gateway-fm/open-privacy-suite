package server

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// TestBuildVisibilityFilter_DisclosureGrant_NeverDrivesUnion_RD1079
// verifies that disclosure grants never contribute parent-row hashes.
func TestBuildVisibilityFilter_DisclosureGrant_NeverDrivesUnion_RD1079(t *testing.T) {
	cases := []struct {
		level         string
		wantTxInUnion bool
		reason        string
	}{
		{"full", false, "a full disclosure grant cannot drive ordinary transfer unions"},
		{"pseudonymous", false, "RD-1079: a pseudonymous grant must NOT force-reveal the subject's counterparty"},
		{"redacted", false, "RD-1079: a redacted grant must NOT force-reveal the subject's counterparty"},
	}

	for _, tc := range cases {
		t.Run(tc.level, func(t *testing.T) {
			srv, _, conn := setupTestServerForExplorerTransactions(t)

			_, err := conn.ExecContext(context.Background(), extendedExplorerSchemaRD1009)
			require.NoError(t, err, "create token_transfers table")
			t.Cleanup(func() {
				_, _ = conn.ExecContext(context.Background(), "DROP TABLE IF EXISTS token_transfers")
			})

			ctx := context.Background()

			// Org that owns the disclosure request + the viewer's group (M13
			// org-scoping requires the viewer to be a member of a group in the
			// request's org).
			orgID := uuid.New().String()
			_, err = conn.ExecContext(ctx,
				"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
				orgID, "rd1079-"+tc.level, "RD-1079 "+tc.level)
			require.NoError(t, err)

			// Viewer (Dave) — a plain member, NOT an org admin. His only visibility
			// onto the counterparty is the disclosure grant below.
			viewerUserID := uuid.New().String()
			viewerDID := "did:test:rd1079_dave_" + tc.level
			_, err = conn.ExecContext(ctx,
				"INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, false, false, '{}')",
				viewerUserID, viewerDID)
			require.NoError(t, err)

			groupID := uuid.New().String()
			_, err = conn.ExecContext(ctx,
				"INSERT INTO groups (id, org_id, slug, name, depth, path) VALUES ($1, $2, 'members', 'Members', 0, 'members')",
				groupID, orgID)
			require.NoError(t, err)
			_, err = conn.ExecContext(ctx,
				"INSERT INTO user_memberships (id, user_id, group_id, source) VALUES ($1, $2, $3, 'manual')",
				uuid.New().String(), viewerUserID, groupID)
			require.NoError(t, err)

			// Eve — the disclosed subject. Her EOA is the transfer recipient.
			eveUserID := uuid.New().String()
			eveDID := "did:test:rd1079_eve_" + tc.level
			const eveEOA = "0x9965507d1a55bcc2695c58ba16fb37d819b0a4dc"
			_, err = conn.ExecContext(ctx,
				"INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, false, false, '{}')",
				eveUserID, eveDID)
			require.NoError(t, err)
			_, err = conn.ExecContext(ctx,
				`INSERT INTO eth_address_links (did, eth_address, link_type) VALUES ($1, $2, 'user')`,
				eveDID, eveEOA)
			require.NoError(t, err)

			// Disclosure request + grant: viewer → Eve at the case's level.
			scopeJSON := `{"disclosure_level":"` + tc.level + `"}`
			requestID := uuid.New().String()
			_, err = conn.ExecContext(ctx, `
				INSERT INTO disclosure_requests
					(id, requester_did, target_user_id, org_id, scope, reason, status, requested_at)
				VALUES ($1, $2, $3, $4, $5::jsonb, 'rd1079 test', 'approved', NOW())`,
				requestID, viewerDID, eveUserID, orgID, scopeJSON)
			require.NoError(t, err)
			_, err = conn.ExecContext(ctx, `
				INSERT INTO disclosure_grants
					(id, request_id, grant_token_hash, scope, granted_at, expires_at)
				VALUES ($1, $2, $3, $4::jsonb, NOW(), $5)`,
				uuid.New().String(), requestID, "rd1079hash_"+tc.level, scopeJSON,
				time.Now().Add(24*time.Hour))
			require.NoError(t, err)

			// Charlie (counterparty EOA) + private token contract — both Hidden to
			// the viewer (Charlie linked to a foreign user; token in another org).
			const charlieEOA = "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc"
			charlieUserID := uuid.New().String()
			_, err = conn.ExecContext(ctx,
				"INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, false, false, '{}')",
				charlieUserID, "did:test:rd1079_charlie_"+tc.level)
			require.NoError(t, err)
			_, err = conn.ExecContext(ctx,
				`INSERT INTO eth_address_links (did, eth_address, link_type) VALUES ($1, $2, 'user')`,
				"did:test:rd1079_charlie_"+tc.level, charlieEOA)
			require.NoError(t, err)

			const token = "0xdaddaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			otherOrgID := uuid.New().String()
			_, err = conn.ExecContext(ctx,
				"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
				otherOrgID, "rd1079-other-"+tc.level, "Other "+tc.level)
			require.NoError(t, err)
			_, err = conn.ExecContext(ctx,
				"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, $4)",
				uuid.New().String(), otherOrgID, token, "Private Token")
			require.NoError(t, err)

			// Chain data: tx Charlie → token, with an ERC-20 transfer Charlie → Eve.
			blockNum := seedExplorerBlock(t, conn)
			const txHash = "0xrd1079_reproducer"
			seedExplorerTransaction(t, conn, blockNum, txHash, charlieEOA, token)
			_, err = conn.ExecContext(ctx, `
				INSERT INTO token_transfers (tx_hash, log_index, token_address, from_address, to_address, value, block_number)
				VALUES ($1, 0, $2, $3, $4, 100, $5)`,
				txHash, token, charlieEOA, eveEOA, blockNum)
			require.NoError(t, err)

			filter := srv.buildVisibilityFilter(ctx, viewerDID, srv.isViewerAdmin(ctx, viewerDID))
			require.NotNil(t, filter)
			require.True(t, filter.AllPrivate)

			// A disclosure subject cannot enter the ordinary SQL allowlist.
			require.NotContainsf(t, filter.VisibleAddresses, eveEOA,
				"disclosed subject EOA must not enter the ordinary SQL allowlist (level=%s)", tc.level)

			// No disclosure level may drive the transfer union.
			if tc.wantTxInUnion {
				require.Containsf(t, filter.VisibleTxHashes, txHash,
					"level=%s: %s", tc.level, tc.reason)
			} else {
				require.NotContainsf(t, filter.VisibleTxHashes, txHash,
					"level=%s: %s", tc.level, tc.reason)
			}
		})
	}
}
