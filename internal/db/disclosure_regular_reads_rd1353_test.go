package db

import (
	"context"
	"testing"
	"time"

	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/viewscope"

	"github.com/stretchr/testify/require"
)

// A disclosure grants access only through the grant API. The shared address
// resolver must return exactly the same ordinary-read decision at every level.
func TestRegularVisibilityIgnoresDisclosureGrantsRD1353(t *testing.T) {
	for _, level := range []string{"full", "pseudonymous", "redacted", "", "unknown"} {
		t.Run(level, func(t *testing.T) {
			database := setupRBACTestDB(t)
			t.Cleanup(func() { _ = database.Close() })
			ctx := context.Background()
			const viewer = "did:rd1353:viewer"
			const subject = "did:rd1353:subject"
			const address = "0x1353000000000000000000000000000000000001"
			orgID, _, grantID := setupDisclosureGrantWithLevel(t, database, viewer, subject, address, level, time.Now().Add(time.Hour))
			for _, readCtx := range []context.Context{ctx, viewscope.WithOrg(ctx, orgID)} {
				plain, err := database.GetBatchVisibility(readCtx, viewer, []string{address})
				require.NoError(t, err)
				require.Equal(t, explorer.VisibilityHidden, plain[address])
				detailed, err := database.GetBatchVisibilityDetailed(readCtx, viewer, []string{address})
				require.NoError(t, err)
				require.Equal(t, explorer.AddressVisibility{Address: address, Level: explorer.VisibilityHidden, Reason: explorer.ReasonNoAccess}, detailed[address])
				require.Empty(t, explorer.StrictAllowlist(detailed))
			}
			_, err := database.Conn().ExecContext(ctx, `UPDATE disclosure_grants SET revoked_at = NOW() WHERE id = $1`, grantID)
			require.NoError(t, err)
			plain, err := database.GetBatchVisibility(ctx, viewer, []string{address})
			require.NoError(t, err)
			require.Equal(t, explorer.VisibilityHidden, plain[address], "revocation must not change regular visibility")
			own, err := database.GetBatchVisibilityDetailed(ctx, subject, []string{address})
			require.NoError(t, err)
			require.Equal(t, explorer.VisibilityFull, own[address].Level)
			require.Equal(t, explorer.ReasonOwnAddress, own[address].Reason)
		})
	}
}
