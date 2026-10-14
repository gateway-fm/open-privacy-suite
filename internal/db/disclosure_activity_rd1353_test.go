package db

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/disclosure"
)

func TestDisclosureActivityCategoriesAndBoundsRD1353(t *testing.T) {
	database := setupDisclosureTestDB(t)
	defer cleanupTestDB(t, database)
	ctx := context.Background()
	org := createTestOrg(t, database, "activity-scope")
	userID := createTestUserForDisclosure(t, database, "did:test:activity-scope")
	did, err := database.GetUserExternalID(ctx, userID)
	require.NoError(t, err)
	now := time.Now().UTC().Truncate(time.Second)
	for i, method := range []string{"eth_call", "eth_getBalance", "eth_call"} {
		_, err := database.Conn().ExecContext(ctx, `INSERT INTO access_logs (external_id,method,status_code,created_at) VALUES ($1,$2,200,$3)`, did, method, now.Add(time.Duration(i-2)*time.Hour))
		require.NoError(t, err)
	}
	scope := disclosure.Scope{Methods: []string{disclosure.MethodActivityLogs}, DateRange: &disclosure.DateRange{Start: now.Add(-90 * time.Minute), End: now.Add(-30 * time.Minute)}}
	logs, err := database.GetDisclosureActivityLogs(ctx, did, &scope, 100, 0)
	require.NoError(t, err)
	require.Len(t, logs, 1, "activity_logs is a data category, not an RPC method")
	assert.Equal(t, "eth_getBalance", logs[0].Method)
	summary, err := database.GetDisclosureActivitySummary(ctx, did, &scope)
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalRequests)
	preciseScope := disclosure.Scope{Methods: scope.Methods, DateRange: &disclosure.DateRange{Start: now.Add(-time.Hour).Add(time.Nanosecond), End: now.Add(-30 * time.Minute)}}
	preciseLogs, err := database.GetDisclosureActivityLogs(ctx, did, &preciseScope, 100, 0)
	require.NoError(t, err)
	assert.Empty(t, preciseLogs, "do not round a fractional lower consent bound backwards")

	req := &disclosure.Request{ID: uuid.NewString(), TargetUserID: userID, OrgID: org, Scope: scope, Status: disclosure.StatusApproved, RequestedAt: now.Add(-3 * time.Hour)}
	require.NoError(t, database.CreateDisclosureRequest(ctx, req))
	grant := &disclosure.Grant{ID: uuid.NewString(), RequestID: req.ID, GrantTokenHash: uuid.NewString(), Scope: scope, GrantedAt: now.Add(-3 * time.Hour), ExpiresAt: now.Add(time.Hour)}
	require.NoError(t, database.CreateDisclosureGrant(ctx, grant))
	bounds, err := database.GetGrantActivityBounds(ctx, grant.ID)
	require.NoError(t, err)
	require.NotNil(t, bounds)
	filtered, count, err := database.GetAccessLogsForExternalIDInRange(ctx, did, bounds.GrantedAt, bounds.ExpiresAt, 10, 0)
	require.NoError(t, err)
	assert.Len(t, filtered, 1)
	assert.Equal(t, 1, count, "count must use the same data-time bounds")

	scope.Addresses = []string{"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	_, err = database.GetDisclosureActivityLogs(ctx, did, &scope, 100, 0)
	assert.Error(t, err, "cannot ignore address restrictions on activity")
	_, err = database.GetDisclosureActivitySummary(ctx, did, &scope)
	assert.Error(t, err)
	_, err = database.Conn().ExecContext(ctx, `UPDATE disclosure_grants SET scope = '{"methods":["activity_logs"],"date_range":{"start":"2026-01-01T00:00:00Z"}}' WHERE id = $1`, grant.ID)
	require.NoError(t, err)
	_, err = database.GetGrantActivityBounds(ctx, grant.ID)
	assert.Error(t, err, "malformed stored scope must fail closed")
}
