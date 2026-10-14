package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"privacy-proxy/internal/disclosure"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestGrantAuditBatch_ListKeepsEveryGrantAndViewer(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	createTestUserForExplorer(t, database, testViewerDID)
	expected := map[string]int{}
	for i := 1; i <= 3; i++ {
		did := fmt.Sprintf("did:auditbatch:subject%d", i)
		user := createTestUserForExplorer(t, database, did)
		for j := 0; j < i; j++ {
			linkEthAddressToUser(t, database, did, fmt.Sprintf("0x%040x", 1000+i*10+j))
		}
		id := createDisclosureGrantWithLevel(t, database, testViewerDID, user, disclosure.DisclosureFull, time.Now().Add(time.Hour))
		expected[id] = i
	}
	before := time.Now()
	w := rd1353Get(t, setupExplorerRouter(srv), srv, testViewerDID, "/api/v1/explorer/viewable-addresses")
	require.Equal(t, http.StatusOK, w.Code)
	rows, err := conn.QueryContext(context.Background(), `SELECT e.grant_id, u.external_id, e.action,
		e.resource_type, e.data_summary, e.viewer_ip, e.accessed_at FROM disclosure_events e
		JOIN users u ON u.id=e.viewer_user_id ORDER BY e.grant_id`)
	require.NoError(t, err)
	defer rows.Close()
	seen := map[string]int{}
	for rows.Next() {
		var grant, viewer, action, resource, ip string
		var summary []byte
		var at time.Time
		require.NoError(t, rows.Scan(&grant, &viewer, &action, &resource, &summary, &ip, &at))
		var data disclosure.DataSummary
		require.NoError(t, json.Unmarshal(summary, &data))
		require.Equal(t, testViewerDID, viewer)
		require.Equal(t, "list_addresses", action)
		require.Equal(t, "addresses", resource)
		require.NotEmpty(t, ip)
		require.False(t, at.Before(before.Add(-time.Millisecond)))
		require.False(t, at.After(time.Now()))
		require.NotContains(t, seen, grant, "exactly one event per grant")
		seen[grant] = data.RecordCount
	}
	require.NoError(t, rows.Err())
	require.Equal(t, expected, seen)
}

func TestGrantAuditBatch_EmptyAndMissingGrant(t *testing.T) {
	f := newRD1353Fixture(t)
	ctx := context.Background()
	require.NoError(t, f.srv.db.CreateDisclosureEvents(ctx, nil))
	grant, _ := f.grant(t, `{"disclosure_level":"full"}`)
	rows := []disclosure.Event{
		{GrantID: grant, Action: disclosure.ActionListAddresses, ResourceType: disclosure.ResourceAddresses, AccessedAt: time.Now()},
		{GrantID: uuid.NewString(), Action: disclosure.ActionListAddresses, ResourceType: disclosure.ResourceAddresses, AccessedAt: time.Now()},
	}
	require.Error(t, f.srv.db.CreateDisclosureEvents(ctx, rows), "foreign-key failure must be reported")
	var count int
	require.NoError(t, f.conn.QueryRowContext(ctx, "SELECT count(*) FROM disclosure_events").Scan(&count))
	require.Equal(t, 1, count, "valid event survives while the missing-grant error is reported")
	var savedGrant string
	require.NoError(t, f.conn.QueryRowContext(ctx, "SELECT grant_id FROM disclosure_events").Scan(&savedGrant))
	require.Equal(t, grant, savedGrant)
	events, err := f.srv.db.ListDisclosureEventsByGrant(ctx, grant, 10, 0)
	require.NoError(t, err, "an omitted IP must retain the single-write empty-string representation")
	require.Len(t, events, 1)
	require.Empty(t, events[0].ViewerIP)
	require.Nil(t, events[0].ViewerUserID)
	require.Nil(t, events[0].DataSummary)
	require.Positive(t, events[0].ID)
}
