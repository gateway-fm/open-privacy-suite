package db

import (
	"context"
	"testing"
	"time"

	"privacy-proxy/internal/disclosure"
	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupDisclosureTestDB(t *testing.T) *DB {
	database := setupTestDB(t)

	// Clear disclosure tables for fresh test
	ctx := context.Background()
	conn := database.Conn()

	// Clear in correct order due to foreign keys
	conn.ExecContext(ctx, "DELETE FROM disclosure_reports")
	conn.ExecContext(ctx, "DELETE FROM disclosure_events")
	conn.ExecContext(ctx, "DELETE FROM disclosure_grants")
	conn.ExecContext(ctx, "DELETE FROM disclosure_requests")

	return database
}

// createTestOrg creates a test organization and returns its ID
func createTestOrg(t *testing.T, database *DB, slugPrefix string) string {
	ctx := context.Background()
	uniqueSlug := slugPrefix + "-" + uuid.New().String()[:8]
	org := &rbac.Organization{
		ID:       uuid.New().String(),
		Slug:     uniqueSlug,
		Name:     "Test Org " + uniqueSlug,
		Settings: map[string]interface{}{},
	}
	err := database.CreateOrganization(ctx, org)
	require.NoError(t, err)
	return org.ID
}

// createTestUserForDisclosure creates a test user and returns its ID
func createTestUserForDisclosure(t *testing.T, database *DB, externalIDPrefix string) string {
	ctx := context.Background()
	uniqueExternalID := externalIDPrefix + "-" + uuid.New().String()[:8]
	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: uniqueExternalID,
		KYC:        false,
		Banned:     false,
		Metadata:   map[string]interface{}{},
	}
	err := database.CreateUser(ctx, user)
	require.NoError(t, err)
	return user.ID
}

// ============================================================================
// Request Tests
// ============================================================================

func TestDisclosureRequest_CRUD(t *testing.T) {
	database := setupDisclosureTestDB(t)
	defer cleanupTestDB(t, database)

	ctx := context.Background()

	// Create shared org and users for tests
	sharedOrgID := createTestOrg(t, database, "disclosure-crud-org")
	sharedTargetUserID := createTestUserForDisclosure(t, database, "did:test:shared-target")
	sharedRequesterID := createTestUserForDisclosure(t, database, "did:test:shared-requester")

	t.Run("Create", func(t *testing.T) {
		req := &disclosure.Request{
			ID:              uuid.New().String(),
			RequesterUserID: &sharedRequesterID,
			TargetUserID:    sharedTargetUserID,
			OrgID:           sharedOrgID,
			Scope: disclosure.Scope{
				Methods:   []string{"eth_call", "eth_getBalance"},
				Addresses: []string{"0x1234567890abcdef"},
				DateRange: &disclosure.DateRange{
					Start: time.Now().Add(-24 * time.Hour),
					End:   time.Now(),
				},
			},
			Reason:      "Compliance audit",
			LegalBasis:  "GDPR Article 6(1)(c)",
			Status:      disclosure.StatusPending,
			RequestedAt: time.Now(),
		}

		err := database.CreateRequest(ctx, req)
		require.NoError(t, err)

		// Verify it was created
		retrieved, err := database.GetRequest(ctx, req.ID)
		require.NoError(t, err)
		require.NotNil(t, retrieved)
		assert.Equal(t, req.ID, retrieved.ID)
		assert.Equal(t, req.TargetUserID, retrieved.TargetUserID)
		assert.Equal(t, req.Reason, retrieved.Reason)
		assert.Equal(t, req.LegalBasis, retrieved.LegalBasis)
		assert.Equal(t, disclosure.StatusPending, retrieved.Status)
		assert.Len(t, retrieved.Scope.Methods, 2)
		assert.Len(t, retrieved.Scope.Addresses, 1)
	})

	t.Run("CreateWithExpiration", func(t *testing.T) {
		expiresAt := time.Now().Add(48 * time.Hour)
		req := &disclosure.Request{
			ID:           uuid.New().String(),
			TargetUserID: sharedTargetUserID,
			OrgID:        sharedOrgID,
			Scope:        disclosure.Scope{},
			Reason:       "Test expiration",
			Status:       disclosure.StatusPending,
			RequestedAt:  time.Now(),
			ExpiresAt:    &expiresAt,
		}

		err := database.CreateRequest(ctx, req)
		require.NoError(t, err)

		retrieved, err := database.GetRequest(ctx, req.ID)
		require.NoError(t, err)
		require.NotNil(t, retrieved.ExpiresAt)
		assert.WithinDuration(t, expiresAt, *retrieved.ExpiresAt, time.Second)
	})

	t.Run("GetNonExistent", func(t *testing.T) {
		retrieved, err := database.GetRequest(ctx, uuid.New().String())
		require.NoError(t, err)
		assert.Nil(t, retrieved)
	})

	t.Run("GetWithDetails", func(t *testing.T) {
		// Create a new user for the target with distinct external ID prefix
		targetExtID := "did:test:target-details-" + uuid.New().String()[:8]
		targetUserID := uuid.New().String()
		_, err := database.Conn().ExecContext(ctx,
			"INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, false, false, '{}')",
			targetUserID, targetExtID)
		require.NoError(t, err)

		req := &disclosure.Request{
			ID:           uuid.New().String(),
			TargetUserID: targetUserID,
			OrgID:        sharedOrgID,
			Scope:        disclosure.Scope{Methods: []string{"eth_call"}},
			Reason:       "Test with details",
			Status:       disclosure.StatusPending,
			RequestedAt:  time.Now(),
		}
		err = database.CreateRequest(ctx, req)
		require.NoError(t, err)

		details, err := database.GetRequestWithDetails(ctx, req.ID)
		require.NoError(t, err)
		require.NotNil(t, details)
		assert.Equal(t, targetExtID, details.TargetDID)
	})

	t.Run("UpdateStatus", func(t *testing.T) {
		decidedByUserID := createTestUserForDisclosure(t, database, "did:test:decider")

		req := &disclosure.Request{
			ID:           uuid.New().String(),
			TargetUserID: sharedTargetUserID,
			OrgID:        sharedOrgID,
			Scope:        disclosure.Scope{},
			Reason:       "Test update",
			Status:       disclosure.StatusPending,
			RequestedAt:  time.Now(),
		}
		err := database.CreateRequest(ctx, req)
		require.NoError(t, err)

		// Approve the request
		err = database.UpdateRequestStatus(ctx, req.ID, disclosure.StatusApproved, &decidedByUserID, "Approved for audit")
		require.NoError(t, err)

		// Verify status was updated
		retrieved, err := database.GetRequest(ctx, req.ID)
		require.NoError(t, err)
		assert.Equal(t, disclosure.StatusApproved, retrieved.Status)
		require.NotNil(t, retrieved.DecidedByUserID)
		assert.Equal(t, decidedByUserID, *retrieved.DecidedByUserID)
		assert.Equal(t, "Approved for audit", retrieved.DecisionReason)
		require.NotNil(t, retrieved.DecidedAt)
	})
}

func TestDisclosureRequest_ListMethods(t *testing.T) {
	database := setupDisclosureTestDB(t)
	defer cleanupTestDB(t, database)

	ctx := context.Background()

	// Setup test data - create proper users and orgs
	targetUser1 := createTestUserForDisclosure(t, database, "did:test:listmethods:target1")
	targetUser2 := createTestUserForDisclosure(t, database, "did:test:listmethods:target2")
	requester1 := createTestUserForDisclosure(t, database, "did:test:listmethods:requester1")
	org1 := createTestOrg(t, database, "listmethods-org1")
	org2 := createTestOrg(t, database, "listmethods-org2")

	requests := []*disclosure.Request{
		{
			ID:              uuid.New().String(),
			RequesterUserID: &requester1,
			TargetUserID:    targetUser1,
			OrgID:           org1,
			Scope:           disclosure.Scope{},
			Reason:          "Request 1",
			Status:          disclosure.StatusPending,
			RequestedAt:     time.Now(),
		},
		{
			ID:              uuid.New().String(),
			RequesterUserID: &requester1,
			TargetUserID:    targetUser1,
			OrgID:           org1,
			Scope:           disclosure.Scope{},
			Reason:          "Request 2",
			Status:          disclosure.StatusApproved,
			RequestedAt:     time.Now(),
		},
		{
			ID:           uuid.New().String(),
			TargetUserID: targetUser2,
			OrgID:        org1,
			Scope:        disclosure.Scope{},
			Reason:       "Request 3",
			Status:       disclosure.StatusPending,
			RequestedAt:  time.Now(),
		},
		{
			ID:           uuid.New().String(),
			TargetUserID: targetUser1,
			OrgID:        org2,
			Scope:        disclosure.Scope{},
			Reason:       "Request 4",
			Status:       disclosure.StatusPending,
			RequestedAt:  time.Now(),
		},
	}

	for _, req := range requests {
		err := database.CreateRequest(ctx, req)
		require.NoError(t, err)
	}

	t.Run("ListByTarget", func(t *testing.T) {
		// All requests for target user 1
		results, err := database.ListRequestsByTarget(ctx, targetUser1, nil)
		require.NoError(t, err)
		assert.Len(t, results, 3)

		// Only pending requests for target user 1
		pendingStatus := disclosure.StatusPending
		results, err = database.ListRequestsByTarget(ctx, targetUser1, &pendingStatus)
		require.NoError(t, err)
		assert.Len(t, results, 2)
	})

	t.Run("ListByRequester", func(t *testing.T) {
		results, err := database.ListRequestsByRequester(ctx, requester1)
		require.NoError(t, err)
		assert.Len(t, results, 2)
	})

	t.Run("ListByOrg", func(t *testing.T) {
		// All requests for org 1
		results, err := database.ListRequestsByOrg(ctx, org1, nil)
		require.NoError(t, err)
		assert.Len(t, results, 3)

		// Only pending requests for org 1
		pendingStatus := disclosure.StatusPending
		results, err = database.ListRequestsByOrg(ctx, org1, &pendingStatus)
		require.NoError(t, err)
		assert.Len(t, results, 2)
	})

	t.Run("ListPendingForUser", func(t *testing.T) {
		results, err := database.ListPendingRequestsForUser(ctx, targetUser1)
		require.NoError(t, err)
		// Should only return pending requests (excluding approved)
		assert.Len(t, results, 2)
		for _, r := range results {
			assert.Equal(t, disclosure.StatusPending, r.Request.Status)
		}
	})
}

func TestDisclosureRequest_ExpirePending(t *testing.T) {
	database := setupDisclosureTestDB(t)
	defer cleanupTestDB(t, database)

	ctx := context.Background()

	// Create shared resources
	orgID := createTestOrg(t, database, "expire-pending-org")
	targetUserID := createTestUserForDisclosure(t, database, "did:test:expire-target")

	// Create expired pending request
	pastExpiry := time.Now().Add(-1 * time.Hour)
	expiredReq := &disclosure.Request{
		ID:           uuid.New().String(),
		TargetUserID: targetUserID,
		OrgID:        orgID,
		Scope:        disclosure.Scope{},
		Reason:       "Expired request",
		Status:       disclosure.StatusPending,
		RequestedAt:  time.Now().Add(-48 * time.Hour),
		ExpiresAt:    &pastExpiry,
	}
	err := database.CreateRequest(ctx, expiredReq)
	require.NoError(t, err)

	// Create non-expired pending request
	futureExpiry := time.Now().Add(24 * time.Hour)
	activeReq := &disclosure.Request{
		ID:           uuid.New().String(),
		TargetUserID: targetUserID,
		OrgID:        orgID,
		Scope:        disclosure.Scope{},
		Reason:       "Active request",
		Status:       disclosure.StatusPending,
		RequestedAt:  time.Now(),
		ExpiresAt:    &futureExpiry,
	}
	err = database.CreateRequest(ctx, activeReq)
	require.NoError(t, err)

	// Expire pending requests
	count, err := database.ExpirePendingRequests(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	// Verify expired request status
	retrieved, err := database.GetRequest(ctx, expiredReq.ID)
	require.NoError(t, err)
	assert.Equal(t, disclosure.StatusExpired, retrieved.Status)

	// Verify active request unchanged
	retrieved, err = database.GetRequest(ctx, activeReq.ID)
	require.NoError(t, err)
	assert.Equal(t, disclosure.StatusPending, retrieved.Status)
}

// ============================================================================
// Grant Tests
// ============================================================================

func TestDisclosureGrant_CRUD(t *testing.T) {
	database := setupDisclosureTestDB(t)
	defer cleanupTestDB(t, database)

	ctx := context.Background()

	// Create shared resources
	orgID := createTestOrg(t, database, "grant-crud-org")
	targetUserID := createTestUserForDisclosure(t, database, "did:test:grant-target")

	// Create a request first
	req := &disclosure.Request{
		ID:           uuid.New().String(),
		TargetUserID: targetUserID,
		OrgID:        orgID,
		Scope:        disclosure.Scope{Methods: []string{"eth_call"}},
		Reason:       "Test grant",
		Status:       disclosure.StatusApproved,
		RequestedAt:  time.Now(),
	}
	err := database.CreateRequest(ctx, req)
	require.NoError(t, err)

	t.Run("Create", func(t *testing.T) {
		grant := &disclosure.Grant{
			ID:             uuid.New().String(),
			RequestID:      req.ID,
			GrantTokenHash: "test_token_hash_123",
			Scope: disclosure.Scope{
				Methods:   []string{"eth_call"},
				Addresses: []string{"0xabcd"},
			},
			GrantedAt: time.Now(),
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}

		err := database.CreateGrant(ctx, grant)
		require.NoError(t, err)

		// Verify
		retrieved, err := database.GetGrant(ctx, grant.ID)
		require.NoError(t, err)
		require.NotNil(t, retrieved)
		assert.Equal(t, grant.ID, retrieved.ID)
		assert.Equal(t, grant.RequestID, retrieved.RequestID)
		assert.Equal(t, grant.GrantTokenHash, retrieved.GrantTokenHash)
		assert.Len(t, retrieved.Scope.Methods, 1)
	})

	t.Run("GetByToken", func(t *testing.T) {
		tokenHash := "unique_token_hash_456"
		grant := &disclosure.Grant{
			ID:             uuid.New().String(),
			RequestID:      req.ID,
			GrantTokenHash: tokenHash,
			Scope:          disclosure.Scope{},
			GrantedAt:      time.Now(),
			ExpiresAt:      time.Now().Add(24 * time.Hour),
		}
		err := database.CreateGrant(ctx, grant)
		require.NoError(t, err)

		retrieved, err := database.GetGrantByToken(ctx, tokenHash)
		require.NoError(t, err)
		require.NotNil(t, retrieved)
		assert.Equal(t, grant.ID, retrieved.ID)
	})

	t.Run("GetWithRequest", func(t *testing.T) {
		grant := &disclosure.Grant{
			ID:             uuid.New().String(),
			RequestID:      req.ID,
			GrantTokenHash: "test_token_789",
			Scope:          disclosure.Scope{},
			GrantedAt:      time.Now(),
			ExpiresAt:      time.Now().Add(24 * time.Hour),
		}
		err := database.CreateGrant(ctx, grant)
		require.NoError(t, err)

		result, err := database.GetGrantWithRequest(ctx, grant.ID)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.NotNil(t, result.Grant)
		require.NotNil(t, result.Request)
		assert.Equal(t, grant.ID, result.Grant.ID)
		assert.Equal(t, req.ID, result.Request.ID)
	})

	t.Run("GetActiveForRequest", func(t *testing.T) {
		// Create a new request
		newReq := &disclosure.Request{
			ID:           uuid.New().String(),
			TargetUserID: targetUserID,
			OrgID:        orgID,
			Scope:        disclosure.Scope{},
			Reason:       "Test active grant",
			Status:       disclosure.StatusApproved,
			RequestedAt:  time.Now(),
		}
		database.CreateRequest(ctx, newReq)

		// Create active grant
		activeGrant := &disclosure.Grant{
			ID:             uuid.New().String(),
			RequestID:      newReq.ID,
			GrantTokenHash: "active_token",
			Scope:          disclosure.Scope{},
			GrantedAt:      time.Now(),
			ExpiresAt:      time.Now().Add(24 * time.Hour),
		}
		database.CreateGrant(ctx, activeGrant)

		// Create expired grant for same request
		expiredGrant := &disclosure.Grant{
			ID:             uuid.New().String(),
			RequestID:      newReq.ID,
			GrantTokenHash: "expired_token",
			Scope:          disclosure.Scope{},
			GrantedAt:      time.Now().Add(-48 * time.Hour),
			ExpiresAt:      time.Now().Add(-24 * time.Hour), // Expired
		}
		database.CreateGrant(ctx, expiredGrant)

		// Should only find active grant
		result, err := database.GetActiveGrantForRequest(ctx, newReq.ID)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, activeGrant.ID, result.ID)
	})

	t.Run("Revoke", func(t *testing.T) {
		grant := &disclosure.Grant{
			ID:             uuid.New().String(),
			RequestID:      req.ID,
			GrantTokenHash: "revoke_test_token_" + uuid.New().String(), // Unique token
			Scope:          disclosure.Scope{},
			GrantedAt:      time.Now(),
			ExpiresAt:      time.Now().Add(24 * time.Hour),
		}
		err := database.CreateGrant(ctx, grant)
		require.NoError(t, err)

		err = database.RevokeGrant(ctx, grant.ID, "User requested revocation")
		require.NoError(t, err)

		retrieved, err := database.GetGrant(ctx, grant.ID)
		require.NoError(t, err)
		require.NotNil(t, retrieved, "Grant should exist after revocation")
		require.NotNil(t, retrieved.RevokedAt, "RevokedAt should be set")
		assert.Equal(t, "User requested revocation", retrieved.RevokedReason)
	})

	t.Run("ListActiveForTarget", func(t *testing.T) {
		targetUser := createTestUserForDisclosure(t, database, "did:test:list-active-target")

		// Create request and active grant
		activeReq := &disclosure.Request{
			ID:           uuid.New().String(),
			TargetUserID: targetUser,
			OrgID:        orgID,
			Scope:        disclosure.Scope{},
			Reason:       "Active grant test",
			Status:       disclosure.StatusApproved,
			RequestedAt:  time.Now(),
		}
		database.CreateRequest(ctx, activeReq)

		activeGrant := &disclosure.Grant{
			ID:             uuid.New().String(),
			RequestID:      activeReq.ID,
			GrantTokenHash: "list_active_token",
			Scope:          disclosure.Scope{},
			GrantedAt:      time.Now(),
			ExpiresAt:      time.Now().Add(24 * time.Hour),
		}
		database.CreateGrant(ctx, activeGrant)

		results, err := database.ListActiveGrantsForTarget(ctx, targetUser)
		require.NoError(t, err)
		assert.Len(t, results, 1)
		assert.Equal(t, activeGrant.ID, results[0].Grant.ID)
	})
}

// ============================================================================
// Event Tests
// ============================================================================

func TestDisclosureEvent_CRUD(t *testing.T) {
	database := setupDisclosureTestDB(t)
	defer cleanupTestDB(t, database)

	ctx := context.Background()

	// Create shared resources
	orgID := createTestOrg(t, database, "event-crud-org")
	targetUserID := createTestUserForDisclosure(t, database, "did:test:event-target")

	// Setup: Create request and grant
	req := &disclosure.Request{
		ID:           uuid.New().String(),
		TargetUserID: targetUserID,
		OrgID:        orgID,
		Scope:        disclosure.Scope{},
		Reason:       "Event test",
		Status:       disclosure.StatusApproved,
		RequestedAt:  time.Now(),
	}
	database.CreateRequest(ctx, req)

	grant := &disclosure.Grant{
		ID:             uuid.New().String(),
		RequestID:      req.ID,
		GrantTokenHash: "event_test_token",
		Scope:          disclosure.Scope{},
		GrantedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(24 * time.Hour),
	}
	database.CreateGrant(ctx, grant)

	t.Run("Create", func(t *testing.T) {
		viewerID := createTestUserForDisclosure(t, database, "did:test:event-viewer")
		event := &disclosure.Event{
			GrantID:      grant.ID,
			ViewerUserID: &viewerID,
			Action:       disclosure.ActionViewLogs,
			ResourceType: disclosure.ResourceAccessLogs,
			DataSummary: &disclosure.DataSummary{
				RecordCount: 50,
				DateRange: disclosure.DateRange{
					Start: time.Now().Add(-24 * time.Hour),
					End:   time.Now(),
				},
				Methods: []string{"eth_call"},
			},
			ViewerIP:   "192.168.1.100",
			AccessedAt: time.Now(),
		}

		err := database.CreateEvent(ctx, event)
		require.NoError(t, err)
		assert.NotZero(t, event.ID)
	})

	t.Run("CreateWithoutViewer", func(t *testing.T) {
		event := &disclosure.Event{
			GrantID:      grant.ID,
			Action:       disclosure.ActionViewSummary,
			ResourceType: disclosure.ResourceSummary,
			ViewerIP:     "10.0.0.1",
			AccessedAt:   time.Now(),
		}

		err := database.CreateEvent(ctx, event)
		require.NoError(t, err)
	})

	t.Run("ListByGrant", func(t *testing.T) {
		// Create multiple events
		for i := 0; i < 5; i++ {
			event := &disclosure.Event{
				GrantID:      grant.ID,
				Action:       disclosure.ActionViewLogs,
				ResourceType: disclosure.ResourceAccessLogs,
				ViewerIP:     "127.0.0.1",
				AccessedAt:   time.Now(),
			}
			database.CreateEvent(ctx, event)
		}

		// List with limit
		events, err := database.ListEventsByGrant(ctx, grant.ID, 3, 0)
		require.NoError(t, err)
		assert.Len(t, events, 3)

		// List with offset
		events, err = database.ListEventsByGrant(ctx, grant.ID, 10, 2)
		require.NoError(t, err)
		assert.True(t, len(events) >= 5) // At least 5 from this test
	})

	t.Run("GetStats", func(t *testing.T) {
		// Create events with different actions
		actions := []disclosure.EventAction{
			disclosure.ActionViewLogs,
			disclosure.ActionViewLogs,
			disclosure.ActionViewSummary,
			disclosure.ActionExportReport,
		}

		for _, action := range actions {
			event := &disclosure.Event{
				GrantID:      grant.ID,
				Action:       action,
				ResourceType: disclosure.ResourceAccessLogs,
				ViewerIP:     "127.0.0.1",
				AccessedAt:   time.Now(),
			}
			database.CreateEvent(ctx, event)
		}

		stats, err := database.GetEventStats(ctx, grant.ID)
		require.NoError(t, err)
		assert.True(t, stats[disclosure.ActionViewLogs] >= 2)
		assert.True(t, stats[disclosure.ActionViewSummary] >= 1)
		assert.True(t, stats[disclosure.ActionExportReport] >= 1)
	})
}

// ============================================================================
// Report Tests
// ============================================================================

func TestDisclosureReport_CRUD(t *testing.T) {
	database := setupDisclosureTestDB(t)
	defer cleanupTestDB(t, database)

	ctx := context.Background()

	// Create shared resources
	orgID := createTestOrg(t, database, "report-crud-org")
	targetUserID := createTestUserForDisclosure(t, database, "did:test:report-target")

	// Setup: Create request and grant
	req := &disclosure.Request{
		ID:           uuid.New().String(),
		TargetUserID: targetUserID,
		OrgID:        orgID,
		Scope:        disclosure.Scope{},
		Reason:       "Report test",
		Status:       disclosure.StatusApproved,
		RequestedAt:  time.Now(),
	}
	database.CreateRequest(ctx, req)

	grant := &disclosure.Grant{
		ID:             uuid.New().String(),
		RequestID:      req.ID,
		GrantTokenHash: "report_test_token",
		Scope:          disclosure.Scope{},
		GrantedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(24 * time.Hour),
	}
	database.CreateGrant(ctx, grant)

	t.Run("Create", func(t *testing.T) {
		report := &disclosure.Report{
			ID:         uuid.New().String(),
			GrantID:    grant.ID,
			ReportType: disclosure.ReportActivitySummary,
			ReportData: map[string]any{
				"total_requests":   100,
				"successful_count": 90,
				"failed_count":     10,
			},
			GeneratedAt: time.Now(),
			ExpiresAt:   time.Now().Add(24 * time.Hour),
		}

		err := database.CreateReport(ctx, report)
		require.NoError(t, err)

		// Verify
		retrieved, err := database.GetReport(ctx, report.ID)
		require.NoError(t, err)
		require.NotNil(t, retrieved)
		assert.Equal(t, report.ID, retrieved.ID)
		assert.Equal(t, disclosure.ReportActivitySummary, retrieved.ReportType)
		assert.Equal(t, float64(100), retrieved.ReportData["total_requests"])
	})

	t.Run("GetByGrantAndType", func(t *testing.T) {
		// Create reports for different types
		activityReport := &disclosure.Report{
			ID:          uuid.New().String(),
			GrantID:     grant.ID,
			ReportType:  disclosure.ReportActivitySummary,
			ReportData:  map[string]any{"type": "activity"},
			GeneratedAt: time.Now(),
			ExpiresAt:   time.Now().Add(24 * time.Hour),
		}
		database.CreateReport(ctx, activityReport)

		sanctionsReport := &disclosure.Report{
			ID:          uuid.New().String(),
			GrantID:     grant.ID,
			ReportType:  disclosure.ReportSanctionsCheck,
			ReportData:  map[string]any{"type": "sanctions"},
			GeneratedAt: time.Now(),
			ExpiresAt:   time.Now().Add(24 * time.Hour),
		}
		database.CreateReport(ctx, sanctionsReport)

		// Get activity report
		result, err := database.GetReportByGrantAndType(ctx, grant.ID, disclosure.ReportActivitySummary)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "activity", result.ReportData["type"])

		// Get sanctions report
		result, err = database.GetReportByGrantAndType(ctx, grant.ID, disclosure.ReportSanctionsCheck)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "sanctions", result.ReportData["type"])
	})

	t.Run("GetByGrantAndType_Expired", func(t *testing.T) {
		expiredReport := &disclosure.Report{
			ID:          uuid.New().String(),
			GrantID:     grant.ID,
			ReportType:  disclosure.ReportCompliance,
			ReportData:  map[string]any{"expired": true},
			GeneratedAt: time.Now().Add(-48 * time.Hour),
			ExpiresAt:   time.Now().Add(-24 * time.Hour), // Expired
		}
		database.CreateReport(ctx, expiredReport)

		// Should not find expired report
		result, err := database.GetReportByGrantAndType(ctx, grant.ID, disclosure.ReportCompliance)
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("DeleteExpired", func(t *testing.T) {
		// Create expired report
		expiredReport := &disclosure.Report{
			ID:          uuid.New().String(),
			GrantID:     grant.ID,
			ReportType:  disclosure.ReportActivitySummary,
			ReportData:  map[string]any{},
			GeneratedAt: time.Now().Add(-48 * time.Hour),
			ExpiresAt:   time.Now().Add(-1 * time.Hour), // Expired
		}
		database.CreateReport(ctx, expiredReport)

		// Delete expired reports
		count, err := database.DeleteExpiredReports(ctx)
		require.NoError(t, err)
		assert.True(t, count >= 1)

		// Verify it was deleted
		result, err := database.GetReport(ctx, expiredReport.ID)
		require.NoError(t, err)
		assert.Nil(t, result)
	})
}

// ============================================================================
// Activity Data Tests
// ============================================================================

func TestDisclosureActivityData(t *testing.T) {
	database := setupDisclosureTestDB(t)
	defer cleanupTestDB(t, database)

	ctx := context.Background()

	// Create test access logs
	testUserDID := "did:test:activityuser"

	// Insert some access logs directly
	for i := 0; i < 10; i++ {
		statusCode := 200
		if i%3 == 0 {
			statusCode = 400 // Some failures
		}
		method := "eth_call"
		if i%2 == 0 {
			method = "eth_getBalance"
		}
		err := database.LogAccess(ctx, testUserDID, method, statusCode, "127.0.0.1")
		require.NoError(t, err)
	}

	t.Run("GetActivityLogs", func(t *testing.T) {
		logs, err := database.GetActivityLogs(ctx, testUserDID, nil, 100, 0)
		require.NoError(t, err)
		assert.Len(t, logs, 10)
	})

	t.Run("GetActivityLogs_WithMethodScope", func(t *testing.T) {
		scope := &disclosure.Scope{
			Methods: []string{disclosure.MethodActivityLogs},
		}
		logs, err := database.GetActivityLogs(ctx, testUserDID, scope, 100, 0)
		require.NoError(t, err)
		assert.Len(t, logs, 10, "activity_logs authorizes the data category, not one RPC name")
	})

	t.Run("GetActivityLogs_WithDateRange", func(t *testing.T) {
		scope := &disclosure.Scope{
			DateRange: &disclosure.DateRange{
				Start: time.Now().Add(-24 * time.Hour),
				End:   time.Now().Add(24 * time.Hour),
			},
		}
		logs, err := database.GetActivityLogs(ctx, testUserDID, scope, 100, 0)
		require.NoError(t, err)
		assert.True(t, len(logs) >= 1, "Should find logs within date range")
	})

	t.Run("GetActivityLogs_Pagination", func(t *testing.T) {
		// Get first page
		logs1, err := database.GetActivityLogs(ctx, testUserDID, nil, 5, 0)
		require.NoError(t, err)
		assert.Len(t, logs1, 5)

		// Get second page
		logs2, err := database.GetActivityLogs(ctx, testUserDID, nil, 5, 5)
		require.NoError(t, err)
		assert.Len(t, logs2, 5)

		// Verify they're different
		assert.NotEqual(t, logs1[0].ID, logs2[0].ID)
	})

	t.Run("GetActivitySummary", func(t *testing.T) {
		summary, err := database.GetActivitySummary(ctx, testUserDID, nil)
		require.NoError(t, err)
		require.NotNil(t, summary)

		assert.Equal(t, 10, summary.TotalRequests)
		assert.True(t, summary.SuccessfulCount >= 6) // Most are 200
		assert.True(t, summary.FailedCount >= 2)     // Some are 400
		assert.Equal(t, 2, summary.UniqueMethodCount)
		assert.Contains(t, summary.MethodBreakdown, "eth_call")
		assert.Contains(t, summary.MethodBreakdown, "eth_getBalance")
	})

	t.Run("GetActivitySummary_WithScope", func(t *testing.T) {
		scope := &disclosure.Scope{
			Methods: []string{disclosure.MethodActivityLogs},
		}
		summary, err := database.GetActivitySummary(ctx, testUserDID, scope)
		require.NoError(t, err)
		require.NotNil(t, summary)

		assert.Equal(t, 2, summary.UniqueMethodCount)
		assert.Contains(t, summary.MethodBreakdown, "eth_call")
		assert.Contains(t, summary.MethodBreakdown, "eth_getBalance")
	})
}

// ============================================================================
// Integration Test: Full Disclosure Workflow
// ============================================================================

func TestDisclosure_FullWorkflow(t *testing.T) {
	database := setupDisclosureTestDB(t)
	defer cleanupTestDB(t, database)

	ctx := context.Background()

	// 1. Create a disclosure request with proper users and org
	orgID := createTestOrg(t, database, "full-workflow-org")
	targetUser := createTestUserForDisclosure(t, database, "did:test:workflow-target")
	requester := createTestUserForDisclosure(t, database, "did:test:workflow-requester")
	approver := createTestUserForDisclosure(t, database, "did:test:workflow-approver")

	req := &disclosure.Request{
		ID:              uuid.New().String(),
		RequesterUserID: &requester,
		TargetUserID:    targetUser,
		OrgID:           orgID,
		Scope: disclosure.Scope{
			Methods:   []string{"eth_call", "eth_getBalance"},
			DateRange: &disclosure.DateRange{Start: time.Now().Add(-7 * 24 * time.Hour), End: time.Now()},
		},
		Reason:      "Regulatory compliance audit",
		LegalBasis:  "GDPR Article 6(1)(c)",
		Status:      disclosure.StatusPending,
		RequestedAt: time.Now(),
	}
	err := database.CreateRequest(ctx, req)
	require.NoError(t, err)

	// 2. Approve the request
	err = database.UpdateRequestStatus(ctx, req.ID, disclosure.StatusApproved, &approver, "Approved for audit")
	require.NoError(t, err)

	// 3. Create a grant
	grant := &disclosure.Grant{
		ID:             uuid.New().String(),
		RequestID:      req.ID,
		GrantTokenHash: "workflow_test_token_hash",
		Scope:          req.Scope,
		GrantedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(24 * time.Hour),
	}
	err = database.CreateGrant(ctx, grant)
	require.NoError(t, err)

	// 4. Log some access events
	event1 := &disclosure.Event{
		GrantID:      grant.ID,
		ViewerUserID: &requester,
		Action:       disclosure.ActionViewLogs,
		ResourceType: disclosure.ResourceAccessLogs,
		DataSummary: &disclosure.DataSummary{
			RecordCount: 100,
		},
		ViewerIP:   "192.168.1.1",
		AccessedAt: time.Now(),
	}
	err = database.CreateEvent(ctx, event1)
	require.NoError(t, err)

	event2 := &disclosure.Event{
		GrantID:      grant.ID,
		ViewerUserID: &requester,
		Action:       disclosure.ActionViewSummary,
		ResourceType: disclosure.ResourceSummary,
		ViewerIP:     "192.168.1.1",
		AccessedAt:   time.Now(),
	}
	err = database.CreateEvent(ctx, event2)
	require.NoError(t, err)

	// 5. Create a compliance report
	report := &disclosure.Report{
		ID:         uuid.New().String(),
		GrantID:    grant.ID,
		ReportType: disclosure.ReportCompliance,
		ReportData: map[string]any{
			"target_user":    targetUser,
			"total_activity": 100,
			"compliant":      true,
		},
		GeneratedAt: time.Now(),
		ExpiresAt:   time.Now().Add(24 * time.Hour),
	}
	err = database.CreateReport(ctx, report)
	require.NoError(t, err)

	// 6. Verify the full state
	// Check request
	retrievedReq, err := database.GetRequest(ctx, req.ID)
	require.NoError(t, err)
	assert.Equal(t, disclosure.StatusApproved, retrievedReq.Status)

	// Check grant
	retrievedGrant, err := database.GetGrant(ctx, grant.ID)
	require.NoError(t, err)
	assert.True(t, retrievedGrant.IsActive())

	// Check events
	events, err := database.ListEventsByGrant(ctx, grant.ID, 10, 0)
	require.NoError(t, err)
	assert.Len(t, events, 2)

	// Check event stats
	stats, err := database.GetEventStats(ctx, grant.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, stats[disclosure.ActionViewLogs])
	assert.Equal(t, 1, stats[disclosure.ActionViewSummary])

	// Check report
	retrievedReport, err := database.GetReportByGrantAndType(ctx, grant.ID, disclosure.ReportCompliance)
	require.NoError(t, err)
	require.NotNil(t, retrievedReport)
	assert.True(t, retrievedReport.ReportData["compliant"].(bool))

	// 7. Revoke the grant
	err = database.RevokeGrant(ctx, grant.ID, "Audit completed")
	require.NoError(t, err)

	// Verify revocation
	retrievedGrant, err = database.GetGrant(ctx, grant.ID)
	require.NoError(t, err)
	assert.False(t, retrievedGrant.IsActive())
	require.NotNil(t, retrievedGrant.RevokedAt)
}
