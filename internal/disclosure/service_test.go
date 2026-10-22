package disclosure

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockStore implements the Store interface for testing.
type mockStore struct {
	// Request storage
	requests map[string]*Request

	// Grant storage
	grants        map[string]*Grant
	grantsByToken map[string]*Grant

	// Event storage
	events []*Event

	// Report storage
	reports            map[string]*Report
	reportsByGrantType map[string]*Report // key: grantID + reportType

	// Activity data
	activityLogs    []*ActivityLogEntry
	activitySummary *ActivitySummary

	// User mapping (userID -> externalID)
	users map[string]string

	// Error simulation
	createRequestErr          error
	getRequestErr             error
	updateRequestStatusErr    error
	createGrantErr            error
	getGrantErr               error
	getGrantByTokenErr        error
	getGrantWithRequestErr    error
	revokeGrantErr            error
	createEventErr            error
	createReportErr           error
	getActivityLogsErr        error
	getActivitySummaryErr     error
	expirePendingReqCount     int64
	deleteExpiredReportsCount int64
}

func newMockStore() *mockStore {
	return &mockStore{
		requests:           make(map[string]*Request),
		grants:             make(map[string]*Grant),
		grantsByToken:      make(map[string]*Grant),
		reports:            make(map[string]*Report),
		reportsByGrantType: make(map[string]*Report),
		activityLogs:       []*ActivityLogEntry{},
		activitySummary: &ActivitySummary{
			TotalRequests:     100,
			SuccessfulCount:   90,
			FailedCount:       10,
			UniqueMethodCount: 5,
			MethodBreakdown:   map[string]int{"eth_call": 50, "eth_getBalance": 30, "eth_sendTransaction": 20},
			DateRange:         DateRange{Start: time.Now().Add(-24 * time.Hour), End: time.Now()},
			GeneratedAt:       time.Now(),
		},
	}
}

// Request operations

func (m *mockStore) CreateRequest(ctx context.Context, req *Request) error {
	if m.createRequestErr != nil {
		return m.createRequestErr
	}
	m.requests[req.ID] = req
	return nil
}

func (m *mockStore) GetRequest(ctx context.Context, id string) (*Request, error) {
	if m.getRequestErr != nil {
		return nil, m.getRequestErr
	}
	req, exists := m.requests[id]
	if !exists {
		return nil, nil
	}
	return req, nil
}

func (m *mockStore) GetRequestWithDetails(ctx context.Context, id string) (*RequestWithDetails, error) {
	req, err := m.GetRequest(ctx, id)
	if err != nil || req == nil {
		return nil, err
	}
	return &RequestWithDetails{Request: req, TargetDID: "did:test:target"}, nil
}

func (m *mockStore) UpdateRequestStatus(ctx context.Context, id string, status RequestStatus, decidedByUserID *string, reason string) error {
	if m.updateRequestStatusErr != nil {
		return m.updateRequestStatusErr
	}
	req, exists := m.requests[id]
	if !exists {
		return ErrRequestNotFound
	}
	req.Status = status
	now := time.Now()
	req.DecidedAt = &now
	req.DecidedByUserID = decidedByUserID
	req.DecisionReason = reason
	return nil
}

func (m *mockStore) ListRequestsByTarget(ctx context.Context, targetUserID string, status *RequestStatus) ([]*Request, error) {
	var results []*Request
	for _, req := range m.requests {
		if req.TargetUserID == targetUserID {
			if status == nil || req.Status == *status {
				results = append(results, req)
			}
		}
	}
	return results, nil
}

func (m *mockStore) ListRequestsByRequester(ctx context.Context, requesterUserID string) ([]*Request, error) {
	var results []*Request
	for _, req := range m.requests {
		if req.RequesterUserID != nil && *req.RequesterUserID == requesterUserID {
			results = append(results, req)
		}
	}
	return results, nil
}

func (m *mockStore) ListRequestsByOrg(ctx context.Context, orgID string, status *RequestStatus) ([]*Request, error) {
	var results []*Request
	for _, req := range m.requests {
		if req.OrgID == orgID {
			if status == nil || req.Status == *status {
				results = append(results, req)
			}
		}
	}
	return results, nil
}

func (m *mockStore) ListPendingRequestsForUser(ctx context.Context, targetUserID string) ([]*RequestWithDetails, error) {
	var results []*RequestWithDetails
	for _, req := range m.requests {
		if req.TargetUserID == targetUserID && req.Status == StatusPending {
			results = append(results, &RequestWithDetails{Request: req, TargetDID: "did:test:target"})
		}
	}
	return results, nil
}

func (m *mockStore) ExpirePendingRequests(ctx context.Context) (int64, error) {
	return m.expirePendingReqCount, nil
}

func (m *mockStore) DeleteRequest(ctx context.Context, id string) error {
	req, exists := m.requests[id]
	if !exists {
		return ErrRequestNotFound
	}
	if req.Status != StatusPending {
		return ErrRequestNotPending
	}
	delete(m.requests, id)
	return nil
}

func (m *mockStore) ListRequestsWithFilter(ctx context.Context, filter *DisclosureFilter) (*DisclosureListResult, error) {
	var results []*RequestWithDetails
	for _, req := range m.requests {
		if filter.Status != nil && req.Status != *filter.Status {
			continue
		}
		if filter.TargetUserID != "" && req.TargetUserID != filter.TargetUserID {
			continue
		}
		if filter.OrgID != "" && req.OrgID != filter.OrgID {
			continue
		}
		results = append(results, &RequestWithDetails{Request: req, TargetDID: "did:test:target"})
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	return &DisclosureListResult{
		Requests: results,
		Total:    int64(len(results)),
		Limit:    limit,
		Offset:   filter.Offset,
	}, nil
}

func (m *mockStore) ListGrantsWithFilter(ctx context.Context, filter *DisclosureFilter) (*GrantListResult, error) {
	var results []*GrantWithRequest
	for _, grant := range m.grants {
		req := m.requests[grant.RequestID]
		if req != nil {
			results = append(results, &GrantWithRequest{Grant: grant, Request: req})
		}
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	return &GrantListResult{
		Grants: results,
		Total:  int64(len(results)),
		Limit:  limit,
		Offset: filter.Offset,
	}, nil
}

func (m *mockStore) ListAllRequestsForUser(ctx context.Context, targetUserID string) ([]*RequestWithDetails, error) {
	var results []*RequestWithDetails
	for _, req := range m.requests {
		if req.TargetUserID == targetUserID {
			results = append(results, &RequestWithDetails{Request: req, TargetDID: "did:test:target"})
		}
	}
	return results, nil
}

func (m *mockStore) ListAllGrantsForTarget(ctx context.Context, targetUserID string) ([]*GrantWithRequest, error) {
	var results []*GrantWithRequest
	for _, grant := range m.grants {
		req := m.requests[grant.RequestID]
		if req != nil && req.TargetUserID == targetUserID {
			results = append(results, &GrantWithRequest{Grant: grant, Request: req})
		}
	}
	return results, nil
}

// Grant operations

func (m *mockStore) CreateGrant(ctx context.Context, grant *Grant) error {
	if m.createGrantErr != nil {
		return m.createGrantErr
	}
	m.grants[grant.ID] = grant
	m.grantsByToken[grant.GrantTokenHash] = grant
	return nil
}

func (m *mockStore) GetGrant(ctx context.Context, id string) (*Grant, error) {
	if m.getGrantErr != nil {
		return nil, m.getGrantErr
	}
	grant, exists := m.grants[id]
	if !exists {
		return nil, nil
	}
	return grant, nil
}

func (m *mockStore) GetGrantByToken(ctx context.Context, tokenHash string) (*Grant, error) {
	if m.getGrantByTokenErr != nil {
		return nil, m.getGrantByTokenErr
	}
	grant, exists := m.grantsByToken[tokenHash]
	if !exists {
		return nil, nil
	}
	return grant, nil
}

func (m *mockStore) GetGrantWithRequest(ctx context.Context, id string) (*GrantWithRequest, error) {
	if m.getGrantWithRequestErr != nil {
		return nil, m.getGrantWithRequestErr
	}
	grant, exists := m.grants[id]
	if !exists {
		return nil, nil
	}
	req := m.requests[grant.RequestID]
	return &GrantWithRequest{Grant: grant, Request: req}, nil
}

func (m *mockStore) GetActiveGrantForRequest(ctx context.Context, requestID string) (*Grant, error) {
	for _, grant := range m.grants {
		if grant.RequestID == requestID && grant.IsActive() {
			return grant, nil
		}
	}
	return nil, nil
}

func (m *mockStore) RevokeGrant(ctx context.Context, id string, reason string) error {
	if m.revokeGrantErr != nil {
		return m.revokeGrantErr
	}
	grant, exists := m.grants[id]
	if !exists {
		return ErrGrantNotFound
	}
	now := time.Now()
	grant.RevokedAt = &now
	grant.RevokedReason = reason
	return nil
}

func (m *mockStore) ListActiveGrantsForTarget(ctx context.Context, targetUserID string) ([]*GrantWithRequest, error) {
	var results []*GrantWithRequest
	for _, grant := range m.grants {
		if grant.IsActive() {
			req := m.requests[grant.RequestID]
			if req != nil && req.TargetUserID == targetUserID {
				results = append(results, &GrantWithRequest{Grant: grant, Request: req})
			}
		}
	}
	return results, nil
}

// Event operations

func (m *mockStore) CreateEvent(ctx context.Context, event *Event) error {
	if m.createEventErr != nil {
		return m.createEventErr
	}
	event.ID = int64(len(m.events) + 1)
	m.events = append(m.events, event)
	return nil
}

func (m *mockStore) ListEventsByGrant(ctx context.Context, grantID string, limit, offset int) ([]*Event, error) {
	var results []*Event
	for _, event := range m.events {
		if event.GrantID == grantID {
			results = append(results, event)
		}
	}
	// Apply limit and offset
	if offset >= len(results) {
		return []*Event{}, nil
	}
	end := offset + limit
	if end > len(results) {
		end = len(results)
	}
	return results[offset:end], nil
}

func (m *mockStore) GetEventStats(ctx context.Context, grantID string) (map[EventAction]int, error) {
	stats := make(map[EventAction]int)
	for _, event := range m.events {
		if event.GrantID == grantID {
			stats[event.Action]++
		}
	}
	return stats, nil
}

// Report operations

func (m *mockStore) CreateReport(ctx context.Context, report *Report) error {
	if m.createReportErr != nil {
		return m.createReportErr
	}
	m.reports[report.ID] = report
	key := report.GrantID + string(report.ReportType)
	m.reportsByGrantType[key] = report
	return nil
}

func (m *mockStore) GetReport(ctx context.Context, id string) (*Report, error) {
	report, exists := m.reports[id]
	if !exists {
		return nil, nil
	}
	return report, nil
}

func (m *mockStore) GetReportByGrantAndType(ctx context.Context, grantID string, reportType ReportType) (*Report, error) {
	key := grantID + string(reportType)
	report, exists := m.reportsByGrantType[key]
	if !exists {
		return nil, nil
	}
	// Check if expired
	if time.Now().After(report.ExpiresAt) {
		return nil, nil
	}
	return report, nil
}

func (m *mockStore) DeleteExpiredReports(ctx context.Context) (int64, error) {
	return m.deleteExpiredReportsCount, nil
}

// Activity data access

func (m *mockStore) GetActivityLogs(ctx context.Context, userExternalID string, scope *Scope, limit, offset int) ([]*ActivityLogEntry, error) {
	if m.getActivityLogsErr != nil {
		return nil, m.getActivityLogsErr
	}
	// Return mock activity logs
	if len(m.activityLogs) == 0 {
		m.activityLogs = []*ActivityLogEntry{
			{ID: 1, Method: "eth_call", StatusCode: 200, IPAddress: "127.0.0.1", CreatedAt: time.Now()},
			{ID: 2, Method: "eth_getBalance", StatusCode: 200, IPAddress: "127.0.0.1", CreatedAt: time.Now()},
		}
	}
	// Apply limit and offset
	if offset >= len(m.activityLogs) {
		return []*ActivityLogEntry{}, nil
	}
	end := offset + limit
	if end > len(m.activityLogs) {
		end = len(m.activityLogs)
	}
	return m.activityLogs[offset:end], nil
}

func (m *mockStore) GetActivitySummary(ctx context.Context, userExternalID string, scope *Scope) (*ActivitySummary, error) {
	if m.getActivitySummaryErr != nil {
		return nil, m.getActivitySummaryErr
	}
	return m.activitySummary, nil
}

func (m *mockStore) GetUserExternalID(ctx context.Context, userID string) (string, error) {
	// Return a mock external ID based on the user ID
	// For tests, we use a simple mapping
	if m.users != nil {
		if externalID, ok := m.users[userID]; ok {
			return externalID, nil
		}
	}
	// Default: return a test external ID
	return "did:test:" + userID, nil
}

// Verify mockStore implements Store interface
var _ Store = (*mockStore)(nil)

// ============================================================================
// Test: Request Workflow
// ============================================================================

func TestCreateRequest(t *testing.T) {
	tests := []struct {
		name            string
		requesterUserID string
		requesterDID    string
		targetUserID    string
		orgID           string
		scope           Scope
		reason          string
		legalBasis      string
		expiresIn       *time.Duration
		storeErr        error
		wantErr         bool
	}{
		{
			name:            "success with all fields",
			requesterUserID: "requester-123",
			requesterDID:    "did:privado:auditor123",
			targetUserID:    "target-456",
			orgID:           "org-789",
			scope: Scope{
				Methods:         []string{"transaction_history", "activity_logs"},
				Addresses:       []string{"0x00000000000000000000000000000000000012aB"},
				DateRange:       &DateRange{Start: time.Now().Add(-24 * time.Hour), End: time.Now()},
				DisclosureLevel: DisclosurePseudonymous,
			},
			reason:     "Compliance audit",
			legalBasis: "GDPR Article 6(1)(c)",
			expiresIn:  durationPtr(24 * time.Hour),
			wantErr:    false,
		},
		{
			name:            "success without requester",
			requesterUserID: "",
			requesterDID:    "",
			targetUserID:    "target-456",
			orgID:           "org-789",
			scope:           Scope{},
			reason:          "Regulatory request",
			legalBasis:      "",
			expiresIn:       nil,
			wantErr:         false,
		},
		{
			name:            "store error",
			requesterUserID: "requester-123",
			requesterDID:    "did:privado:auditor123",
			targetUserID:    "target-456",
			orgID:           "org-789",
			scope:           Scope{},
			reason:          "Test",
			storeErr:        errors.New("database error"),
			wantErr:         true,
		},
		{
			name:         "unknown method rejected (RD-1353)",
			requesterDID: "did:privado:auditor123",
			targetUserID: "target-456",
			orgID:        "org-789",
			scope:        Scope{Methods: []string{"eth_call"}},
			reason:       "Test",
			wantErr:      true,
		},
		{
			name:         "inverted date range rejected (RD-1353)",
			requesterDID: "did:privado:auditor123",
			targetUserID: "target-456",
			orgID:        "org-789",
			scope:        Scope{DateRange: &DateRange{Start: time.Now(), End: time.Now().Add(-time.Hour)}},
			reason:       "Test",
			wantErr:      true,
		},
		{
			name:         "malformed address rejected (RD-1353)",
			requesterDID: "did:privado:auditor123",
			targetUserID: "target-456",
			orgID:        "org-789",
			scope:        Scope{Addresses: []string{"0x1234"}},
			reason:       "Test",
			wantErr:      true,
		},
		{
			name:         "unknown level rejected (RD-1353)",
			requesterDID: "did:privado:auditor123",
			targetUserID: "target-456",
			orgID:        "org-789",
			scope:        Scope{DisclosureLevel: "everything"},
			reason:       "Test",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newMockStore()
			store.createRequestErr = tt.storeErr
			svc := NewService(store)

			req, err := svc.CreateRequest(
				context.Background(),
				tt.requesterUserID,
				tt.requesterDID,
				tt.targetUserID,
				tt.orgID,
				tt.scope,
				tt.reason,
				tt.legalBasis,
				tt.expiresIn,
			)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.storeErr == nil {
					assert.ErrorIs(t, err, ErrInvalidScope)
					assert.Empty(t, store.requests, "an invalid scope is never stored")
				}
				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, req.ID)
			want, nerr := tt.scope.Normalize()
			require.NoError(t, nerr)
			assert.Equal(t, want, req.Scope, "the stored scope is the normalised one")
			if tt.scope.DisclosureLevel == "" {
				assert.Equal(t, DisclosureRedacted, req.Scope.DisclosureLevel, "an empty level is stored as redacted")
			}
			assert.Equal(t, tt.targetUserID, req.TargetUserID)
			assert.Equal(t, tt.orgID, req.OrgID)
			assert.Equal(t, tt.reason, req.Reason)
			assert.Equal(t, tt.legalBasis, req.LegalBasis)
			assert.Equal(t, StatusPending, req.Status)
			assert.False(t, req.RequestedAt.IsZero())
			assert.Equal(t, tt.requesterDID, req.RequesterDID)

			if tt.requesterUserID != "" {
				require.NotNil(t, req.RequesterUserID)
				assert.Equal(t, tt.requesterUserID, *req.RequesterUserID)
			} else {
				assert.Nil(t, req.RequesterUserID)
			}

			if tt.expiresIn != nil {
				require.NotNil(t, req.ExpiresAt)
				assert.True(t, req.ExpiresAt.After(time.Now()))
			} else {
				assert.Nil(t, req.ExpiresAt)
			}
		})
	}
}

func TestApproveRequest(t *testing.T) {
	tests := []struct {
		name           string
		setupRequest   *Request
		requestID      string
		decidedByUser  string
		narrowedScope  *Scope
		grantDuration  time.Duration
		reason         string
		storeGetErr    error
		storeGrantErr  error
		storeUpdateErr error
		wantErr        error
	}{
		{
			name: "success",
			setupRequest: &Request{
				ID:           "req-123",
				TargetUserID: "target-user",
				OrgID:        "org-1",
				Scope:        Scope{Methods: []string{"transaction_history"}, DisclosureLevel: DisclosureFull},
				Reason:       "Audit",
				Status:       StatusPending,
				RequestedAt:  time.Now(),
			},
			requestID:     "req-123",
			decidedByUser: "approver-user",
			narrowedScope: nil,
			grantDuration: 24 * time.Hour,
			reason:        "Approved for compliance",
			wantErr:       nil,
		},
		{
			name: "success with narrowed scope",
			setupRequest: &Request{
				ID:           "req-124",
				TargetUserID: "target-user",
				OrgID:        "org-1",
				Scope:        Scope{Methods: []string{"transaction_history", "activity_logs"}, DisclosureLevel: DisclosureFull},
				Reason:       "Audit",
				Status:       StatusPending,
				RequestedAt:  time.Now(),
			},
			requestID:     "req-124",
			decidedByUser: "approver-user",
			narrowedScope: &Scope{Methods: []string{"transaction_history"}, DisclosureLevel: DisclosureFull}, // Narrow to transactions only
			grantDuration: 12 * time.Hour,
			reason:        "Approved with limited scope",
			wantErr:       nil,
		},
		{
			name:          "request not found",
			setupRequest:  nil,
			requestID:     "nonexistent",
			decidedByUser: "approver-user",
			grantDuration: 24 * time.Hour,
			reason:        "Test",
			wantErr:       ErrRequestNotFound,
		},
		{
			name: "request not pending",
			setupRequest: &Request{
				ID:           "req-125",
				TargetUserID: "target-user",
				OrgID:        "org-1",
				Status:       StatusApproved, // Already approved
				RequestedAt:  time.Now(),
			},
			requestID:     "req-125",
			decidedByUser: "approver-user",
			grantDuration: 24 * time.Hour,
			reason:        "Test",
			wantErr:       ErrRequestNotPending,
		},
		{
			name: "request expired",
			setupRequest: &Request{
				ID:           "req-126",
				TargetUserID: "target-user",
				OrgID:        "org-1",
				Status:       StatusPending,
				RequestedAt:  time.Now().Add(-48 * time.Hour),
				ExpiresAt:    timePtr(time.Now().Add(-24 * time.Hour)), // Expired yesterday
			},
			requestID:     "req-126",
			decidedByUser: "approver-user",
			grantDuration: 24 * time.Hour,
			reason:        "Test",
			wantErr:       ErrRequestExpired,
		},
		{
			name: "reject scope widening (methods superset)",
			setupRequest: &Request{
				ID:           "req-127",
				TargetUserID: "target-user",
				OrgID:        "org-1",
				Scope:        Scope{Methods: []string{"activity_logs"}},
				Status:       StatusPending,
				RequestedAt:  time.Now(),
			},
			requestID:     "req-127",
			decidedByUser: "approver-user",
			narrowedScope: &Scope{Methods: []string{"activity_logs", "transaction_history"}}, // widens beyond request
			grantDuration: 24 * time.Hour,
			reason:        "should be rejected",
			wantErr:       ErrScopeOutOfBounds,
		},
		{
			name: "reject disclosure-level escalation",
			setupRequest: &Request{
				ID:           "req-128",
				TargetUserID: "target-user",
				OrgID:        "org-1",
				Scope:        Scope{DisclosureLevel: DisclosurePseudonymous},
				Status:       StatusPending,
				RequestedAt:  time.Now(),
			},
			requestID:     "req-128",
			decidedByUser: "approver-user",
			narrowedScope: &Scope{DisclosureLevel: DisclosureFull}, // escalates beyond request
			grantDuration: 24 * time.Hour,
			reason:        "should be rejected",
			wantErr:       ErrScopeOutOfBounds,
		},
		{
			// RD-1353: an empty level is redacted, so it cannot be "narrowed"
			// to pseudonymous or full.
			name: "reject escalation from an empty (redacted) level",
			setupRequest: &Request{
				ID:           "req-129",
				TargetUserID: "target-user",
				OrgID:        "org-1",
				Status:       StatusPending,
				RequestedAt:  time.Now(),
			},
			requestID:     "req-129",
			decidedByUser: "approver-user",
			narrowedScope: &Scope{DisclosureLevel: DisclosurePseudonymous},
			grantDuration: 24 * time.Hour,
			reason:        "should be rejected",
			wantErr:       ErrScopeOutOfBounds,
		},
		{
			// RD-1353: a request stored before scopes were validated cannot be
			// approved with a scope the grant API would not understand.
			name: "reject approving an invalid legacy scope",
			setupRequest: &Request{
				ID:           "req-130",
				TargetUserID: "target-user",
				OrgID:        "org-1",
				Scope:        Scope{Methods: []string{"eth_call"}},
				Status:       StatusPending,
				RequestedAt:  time.Now(),
			},
			requestID:     "req-130",
			decidedByUser: "approver-user",
			grantDuration: 24 * time.Hour,
			reason:        "should be rejected",
			wantErr:       ErrInvalidScope,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newMockStore()
			store.getRequestErr = tt.storeGetErr
			store.createGrantErr = tt.storeGrantErr
			store.updateRequestStatusErr = tt.storeUpdateErr

			if tt.setupRequest != nil {
				store.requests[tt.setupRequest.ID] = tt.setupRequest
			}

			svc := NewService(store)

			grant, err := svc.ApproveRequest(
				context.Background(),
				tt.requestID,
				tt.decidedByUser,
				tt.narrowedScope,
				tt.grantDuration,
				tt.reason,
			)

			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, grant)
			assert.NotEmpty(t, grant.ID)
			assert.Equal(t, tt.requestID, grant.RequestID)
			assert.NotEmpty(t, grant.GrantTokenHash) // Placeholder hash for DID-based auth
			assert.True(t, grant.ExpiresAt.After(time.Now()))

			// Verify scope: the granted scope is stored normalised (RD-1353).
			want := tt.setupRequest.Scope
			if tt.narrowedScope != nil {
				want = *tt.narrowedScope
			}
			want, nerr := want.Normalize()
			require.NoError(t, nerr)
			assert.Equal(t, want, grant.Scope)

			// Verify request status was updated
			req := store.requests[tt.requestID]
			assert.Equal(t, StatusApproved, req.Status)
		})
	}
}

// TestScopeIsSubsetOf covers the RD-1164 #9 approval bound: an approved
// (narrowed) scope may never grant more than the request. An empty dimension on
// the child means "unrestricted" and is therefore NOT a subset of a restricted
// parent; an empty disclosure level is redacted (RD-1353), the least revealing.
func TestScopeIsSubsetOf(t *testing.T) {
	jan := &DateRange{Start: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), End: time.Date(2026, 1, 31, 23, 59, 59, 0, time.UTC)}
	q1 := &DateRange{Start: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), End: time.Date(2026, 3, 31, 23, 59, 59, 0, time.UTC)}

	tests := []struct {
		name   string
		child  Scope
		parent Scope
		want   bool
	}{
		{"method subset", Scope{Methods: []string{MethodActivityLogs}}, Scope{Methods: []string{MethodFullDisclosure}}, true},
		{"method superset rejected", Scope{Methods: []string{MethodFullDisclosure}}, Scope{Methods: []string{MethodActivityLogs}}, false},
		{"empty child under method-restricted parent rejected", Scope{}, Scope{Methods: []string{MethodActivityLogs}}, false},
		{"transaction history under empty parent", Scope{Methods: []string{MethodTransactionHistory}}, Scope{}, true},
		{"address subset case-insensitive", Scope{Addresses: []string{"0xABC"}}, Scope{Addresses: []string{"0xabc", "0xdef"}}, true},
		{"address superset rejected", Scope{Addresses: []string{"0xabc", "0x999"}}, Scope{Addresses: []string{"0xabc"}}, false},
		{"date range within", Scope{DateRange: jan}, Scope{DateRange: q1}, true},
		{"date range wider rejected", Scope{DateRange: q1}, Scope{DateRange: jan}, false},
		{"unbounded child under bounded parent rejected", Scope{}, Scope{DateRange: jan}, false},
		{"level narrowing full to pseudonymous", Scope{DisclosureLevel: DisclosurePseudonymous}, Scope{DisclosureLevel: DisclosureFull}, true},
		{"level escalation pseudonymous to full rejected", Scope{DisclosureLevel: DisclosureFull}, Scope{DisclosureLevel: DisclosurePseudonymous}, false},
		{"empty level (=redacted) under a pseudonymous parent", Scope{}, Scope{DisclosureLevel: DisclosurePseudonymous}, true},
		{"pseudonymous child escalates an empty-level (=redacted) parent", Scope{DisclosureLevel: DisclosurePseudonymous}, Scope{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.child.isSubsetOf(tt.parent); got != tt.want {
				t.Errorf("isSubsetOf() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRejectRequest(t *testing.T) {
	tests := []struct {
		name          string
		setupRequest  *Request
		requestID     string
		decidedByUser string
		reason        string
		wantErr       error
	}{
		{
			name: "success",
			setupRequest: &Request{
				ID:           "req-200",
				TargetUserID: "target-user",
				Status:       StatusPending,
				RequestedAt:  time.Now(),
			},
			requestID:     "req-200",
			decidedByUser: "rejector-user",
			reason:        "Insufficient justification",
			wantErr:       nil,
		},
		{
			name:          "request not found",
			setupRequest:  nil,
			requestID:     "nonexistent",
			decidedByUser: "rejector-user",
			reason:        "Test",
			wantErr:       ErrRequestNotFound,
		},
		{
			name: "request not pending",
			setupRequest: &Request{
				ID:           "req-201",
				TargetUserID: "target-user",
				Status:       StatusRejected, // Already rejected
				RequestedAt:  time.Now(),
			},
			requestID:     "req-201",
			decidedByUser: "rejector-user",
			reason:        "Test",
			wantErr:       ErrRequestNotPending,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newMockStore()
			if tt.setupRequest != nil {
				store.requests[tt.setupRequest.ID] = tt.setupRequest
			}

			svc := NewService(store)

			err := svc.RejectRequest(
				context.Background(),
				tt.requestID,
				tt.decidedByUser,
				tt.reason,
			)

			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)

			// Verify request status was updated
			req := store.requests[tt.requestID]
			assert.Equal(t, StatusRejected, req.Status)
			assert.Equal(t, tt.reason, req.DecisionReason)
		})
	}
}

func TestRevokeRequest(t *testing.T) {
	tests := []struct {
		name          string
		setupRequest  *Request
		setupGrant    *Grant
		requestID     string
		revokedByUser string
		reason        string
		wantErr       error
	}{
		{
			name: "success with active grant",
			setupRequest: &Request{
				ID:           "req-300",
				TargetUserID: "target-user",
				Status:       StatusApproved,
				RequestedAt:  time.Now(),
			},
			setupGrant: &Grant{
				ID:             "grant-300",
				RequestID:      "req-300",
				GrantTokenHash: "hash123",
				GrantedAt:      time.Now(),
				ExpiresAt:      time.Now().Add(24 * time.Hour),
			},
			requestID:     "req-300",
			revokedByUser: "revoker-user",
			reason:        "User requested revocation",
			wantErr:       nil,
		},
		{
			name: "success without active grant",
			setupRequest: &Request{
				ID:           "req-301",
				TargetUserID: "target-user",
				Status:       StatusApproved,
				RequestedAt:  time.Now(),
			},
			setupGrant:    nil,
			requestID:     "req-301",
			revokedByUser: "revoker-user",
			reason:        "Changed mind",
			wantErr:       nil,
		},
		{
			name:          "request not found",
			setupRequest:  nil,
			requestID:     "nonexistent",
			revokedByUser: "revoker-user",
			reason:        "Test",
			wantErr:       ErrRequestNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newMockStore()
			if tt.setupRequest != nil {
				store.requests[tt.setupRequest.ID] = tt.setupRequest
			}
			if tt.setupGrant != nil {
				store.grants[tt.setupGrant.ID] = tt.setupGrant
			}

			svc := NewService(store)

			err := svc.RevokeRequest(
				context.Background(),
				tt.requestID,
				tt.revokedByUser,
				tt.reason,
			)

			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)

			// Verify request status was updated
			req := store.requests[tt.requestID]
			assert.Equal(t, StatusRevoked, req.Status)

			// Verify grant was revoked if it existed
			if tt.setupGrant != nil {
				grant := store.grants[tt.setupGrant.ID]
				assert.NotNil(t, grant.RevokedAt)
				assert.Equal(t, tt.reason, grant.RevokedReason)
			}
		})
	}
}

// ============================================================================
// Test: Grant Access
// ============================================================================

func TestValidateGrantToken(t *testing.T) {
	tests := []struct {
		name       string
		setupGrant *Grant
		setupReq   *Request
		token      string
		wantErr    error
	}{
		{
			name: "valid token",
			setupGrant: &Grant{
				ID:             "grant-400",
				RequestID:      "req-400",
				GrantTokenHash: hashToken("valid-token"),
				GrantedAt:      time.Now(),
				ExpiresAt:      time.Now().Add(24 * time.Hour),
			},
			setupReq: &Request{
				ID:           "req-400",
				TargetUserID: "target-user",
				Status:       StatusApproved,
			},
			token:   "valid-token",
			wantErr: nil,
		},
		{
			name:       "invalid token",
			setupGrant: nil,
			token:      "invalid-token",
			wantErr:    ErrInvalidToken,
		},
		{
			name: "expired grant",
			setupGrant: &Grant{
				ID:             "grant-401",
				RequestID:      "req-401",
				GrantTokenHash: hashToken("expired-token"),
				GrantedAt:      time.Now().Add(-48 * time.Hour),
				ExpiresAt:      time.Now().Add(-24 * time.Hour), // Expired
			},
			setupReq: &Request{
				ID:           "req-401",
				TargetUserID: "target-user",
				Status:       StatusApproved,
			},
			token:   "expired-token",
			wantErr: ErrGrantNotActive,
		},
		{
			name: "revoked grant",
			setupGrant: &Grant{
				ID:             "grant-402",
				RequestID:      "req-402",
				GrantTokenHash: hashToken("revoked-token"),
				GrantedAt:      time.Now(),
				ExpiresAt:      time.Now().Add(24 * time.Hour),
				RevokedAt:      timePtr(time.Now()), // Revoked
				RevokedReason:  "User requested",
			},
			setupReq: &Request{
				ID:           "req-402",
				TargetUserID: "target-user",
				Status:       StatusRevoked,
			},
			token:   "revoked-token",
			wantErr: ErrGrantNotActive,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newMockStore()
			if tt.setupGrant != nil {
				store.grants[tt.setupGrant.ID] = tt.setupGrant
				store.grantsByToken[tt.setupGrant.GrantTokenHash] = tt.setupGrant
			}
			if tt.setupReq != nil {
				store.requests[tt.setupReq.ID] = tt.setupReq
			}

			svc := NewService(store)

			result, err := svc.ValidateGrantToken(context.Background(), tt.token)

			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.NotNil(t, result.Grant)
			assert.NotNil(t, result.Request)
		})
	}
}

func TestRevokeGrant(t *testing.T) {
	tests := []struct {
		name       string
		setupGrant *Grant
		grantID    string
		reason     string
		wantErr    error
	}{
		{
			name: "success",
			setupGrant: &Grant{
				ID:        "grant-500",
				RequestID: "req-500",
				GrantedAt: time.Now(),
				ExpiresAt: time.Now().Add(24 * time.Hour),
			},
			grantID: "grant-500",
			reason:  "No longer needed",
			wantErr: nil,
		},
		{
			name:       "grant not found",
			setupGrant: nil,
			grantID:    "nonexistent",
			reason:     "Test",
			wantErr:    ErrGrantNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newMockStore()
			if tt.setupGrant != nil {
				store.grants[tt.setupGrant.ID] = tt.setupGrant
			}

			svc := NewService(store)

			err := svc.RevokeGrant(context.Background(), tt.grantID, tt.reason)

			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)

			// Verify grant was revoked
			grant := store.grants[tt.grantID]
			assert.NotNil(t, grant.RevokedAt)
			assert.Equal(t, tt.reason, grant.RevokedReason)
		})
	}
}

// ============================================================================
// Test: Data Access
// ============================================================================

func TestGetActivityLogs(t *testing.T) {
	tests := []struct {
		name       string
		setupGrant *Grant
		setupReq   *Request
		grantID    string
		viewerID   string
		viewerIP   string
		limit      int
		offset     int
		storeErr   error
		wantErr    error
	}{
		{
			name: "success",
			setupGrant: &Grant{
				ID:        "grant-600",
				RequestID: "req-600",
				Scope:     Scope{Methods: []string{MethodActivityLogs}},
				GrantedAt: time.Now(),
				ExpiresAt: time.Now().Add(24 * time.Hour),
			},
			setupReq: &Request{
				ID:           "req-600",
				TargetUserID: "target-user",
				Status:       StatusApproved,
			},
			grantID:  "grant-600",
			viewerID: "viewer-user",
			viewerIP: "192.168.1.1",
			limit:    100,
			offset:   0,
			wantErr:  nil,
		},
		{
			name:       "grant not found",
			setupGrant: nil,
			grantID:    "nonexistent",
			viewerID:   "viewer-user",
			viewerIP:   "192.168.1.1",
			limit:      100,
			offset:     0,
			wantErr:    ErrGrantNotFound,
		},
		{
			name: "grant not active (expired)",
			setupGrant: &Grant{
				ID:        "grant-601",
				RequestID: "req-601",
				GrantedAt: time.Now().Add(-48 * time.Hour),
				ExpiresAt: time.Now().Add(-24 * time.Hour), // Expired
			},
			setupReq: &Request{
				ID:           "req-601",
				TargetUserID: "target-user",
				Status:       StatusApproved,
			},
			grantID:  "grant-601",
			viewerID: "viewer-user",
			viewerIP: "192.168.1.1",
			limit:    100,
			offset:   0,
			wantErr:  ErrGrantNotActive,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newMockStore()
			store.getActivityLogsErr = tt.storeErr
			if tt.setupGrant != nil {
				store.grants[tt.setupGrant.ID] = tt.setupGrant
			}
			if tt.setupReq != nil {
				store.requests[tt.setupReq.ID] = tt.setupReq
			}

			svc := NewService(store)

			logs, err := svc.GetActivityLogs(
				context.Background(),
				tt.grantID,
				tt.viewerID,
				tt.viewerIP,
				tt.limit,
				tt.offset,
			)

			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, logs)

			// Verify access event was logged
			assert.Len(t, store.events, 1)
			assert.Equal(t, ActionViewLogs, store.events[0].Action)
			assert.Equal(t, ResourceAccessLogs, store.events[0].ResourceType)
		})
	}
}

func TestGetActivitySummary(t *testing.T) {
	tests := []struct {
		name       string
		setupGrant *Grant
		setupReq   *Request
		grantID    string
		viewerID   string
		viewerIP   string
		wantErr    error
	}{
		{
			name: "success",
			setupGrant: &Grant{
				ID:        "grant-700",
				RequestID: "req-700",
				Scope:     Scope{Methods: []string{MethodActivityLogs}},
				GrantedAt: time.Now(),
				ExpiresAt: time.Now().Add(24 * time.Hour),
			},
			setupReq: &Request{
				ID:           "req-700",
				TargetUserID: "target-user",
				Status:       StatusApproved,
			},
			grantID:  "grant-700",
			viewerID: "viewer-user",
			viewerIP: "192.168.1.1",
			wantErr:  nil,
		},
		{
			name:       "grant not found",
			setupGrant: nil,
			grantID:    "nonexistent",
			viewerID:   "viewer-user",
			viewerIP:   "192.168.1.1",
			wantErr:    ErrGrantNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newMockStore()
			if tt.setupGrant != nil {
				store.grants[tt.setupGrant.ID] = tt.setupGrant
			}
			if tt.setupReq != nil {
				store.requests[tt.setupReq.ID] = tt.setupReq
			}

			svc := NewService(store)

			summary, err := svc.GetActivitySummary(
				context.Background(),
				tt.grantID,
				tt.viewerID,
				tt.viewerIP,
			)

			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, summary)
			assert.Equal(t, 100, summary.TotalRequests)

			// Verify access event was logged
			assert.Len(t, store.events, 1)
			assert.Equal(t, ActionViewSummary, store.events[0].Action)
		})
	}
}

func TestGenerateComplianceReport(t *testing.T) {
	tests := []struct {
		name        string
		setupGrant  *Grant
		setupReq    *Request
		setupReport *Report
		grantID     string
		viewerID    string
		viewerIP    string
		reportType  ReportType
		wantErr     error
		wantCached  bool
	}{
		{
			name: "generate activity summary report",
			setupGrant: &Grant{
				ID:        "grant-800",
				RequestID: "req-800",
				Scope:     Scope{Methods: []string{MethodActivityLogs}},
				GrantedAt: time.Now(),
				ExpiresAt: time.Now().Add(24 * time.Hour),
			},
			setupReq: &Request{
				ID:           "req-800",
				TargetUserID: "target-user",
				Status:       StatusApproved,
			},
			grantID:    "grant-800",
			viewerID:   "viewer-user",
			viewerIP:   "192.168.1.1",
			reportType: ReportActivitySummary,
			wantErr:    nil,
		},
		{
			name: "generate sanctions check report",
			setupGrant: &Grant{
				ID:        "grant-801",
				RequestID: "req-801",
				Scope:     Scope{Methods: []string{MethodActivityLogs}},
				GrantedAt: time.Now(),
				ExpiresAt: time.Now().Add(24 * time.Hour),
			},
			setupReq: &Request{
				ID:           "req-801",
				TargetUserID: "target-user",
				Status:       StatusApproved,
			},
			grantID:    "grant-801",
			viewerID:   "viewer-user",
			viewerIP:   "192.168.1.1",
			reportType: ReportSanctionsCheck,
			wantErr:    nil,
		},
		{
			name: "generate compliance report",
			setupGrant: &Grant{
				ID:        "grant-802",
				RequestID: "req-802",
				Scope:     Scope{Methods: []string{MethodActivityLogs}},
				GrantedAt: time.Now(),
				ExpiresAt: time.Now().Add(24 * time.Hour),
			},
			setupReq: &Request{
				ID:           "req-802",
				TargetUserID: "target-user",
				Status:       StatusApproved,
			},
			grantID:    "grant-802",
			viewerID:   "viewer-user",
			viewerIP:   "192.168.1.1",
			reportType: ReportCompliance,
			wantErr:    nil,
		},
		{
			name: "return cached report",
			setupGrant: &Grant{
				ID:        "grant-803",
				RequestID: "req-803",
				Scope:     Scope{Methods: []string{MethodActivityLogs}},
				GrantedAt: time.Now(),
				ExpiresAt: time.Now().Add(24 * time.Hour),
			},
			setupReq: &Request{
				ID:           "req-803",
				TargetUserID: "target-user",
				Status:       StatusApproved,
			},
			setupReport: &Report{
				ID:          "report-803",
				GrantID:     "grant-803",
				ReportType:  ReportActivitySummary,
				ReportData:  map[string]any{"cached": true},
				GeneratedAt: time.Now(),
				ExpiresAt:   time.Now().Add(24 * time.Hour),
			},
			grantID:    "grant-803",
			viewerID:   "viewer-user",
			viewerIP:   "192.168.1.1",
			reportType: ReportActivitySummary,
			wantErr:    nil,
			wantCached: true,
		},
		{
			name:       "grant not found",
			setupGrant: nil,
			grantID:    "nonexistent",
			viewerID:   "viewer-user",
			viewerIP:   "192.168.1.1",
			reportType: ReportActivitySummary,
			wantErr:    ErrGrantNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newMockStore()
			if tt.setupGrant != nil {
				store.grants[tt.setupGrant.ID] = tt.setupGrant
			}
			if tt.setupReq != nil {
				store.requests[tt.setupReq.ID] = tt.setupReq
			}
			if tt.setupReport != nil {
				store.reports[tt.setupReport.ID] = tt.setupReport
				key := tt.setupReport.GrantID + string(tt.setupReport.ReportType)
				store.reportsByGrantType[key] = tt.setupReport
			}

			svc := NewService(store)

			report, err := svc.GenerateComplianceReport(
				context.Background(),
				tt.grantID,
				tt.viewerID,
				tt.viewerIP,
				tt.reportType,
			)

			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, report)
			assert.Equal(t, tt.reportType, report.ReportType)

			if tt.wantCached {
				// Should return cached report
				assert.Equal(t, tt.setupReport.ID, report.ID)
			} else {
				// Should generate new report
				assert.NotEmpty(t, report.ID)
				assert.NotNil(t, report.ReportData)
			}
		})
	}
}

// ============================================================================
// Test: User-facing Methods
// ============================================================================

func TestGetMyPendingRequests(t *testing.T) {
	store := newMockStore()
	store.requests["req-1"] = &Request{
		ID:           "req-1",
		TargetUserID: "user-123",
		Status:       StatusPending,
		RequestedAt:  time.Now(),
	}
	store.requests["req-2"] = &Request{
		ID:           "req-2",
		TargetUserID: "user-123",
		Status:       StatusApproved, // Not pending
		RequestedAt:  time.Now(),
	}
	store.requests["req-3"] = &Request{
		ID:           "req-3",
		TargetUserID: "other-user", // Different user
		Status:       StatusPending,
		RequestedAt:  time.Now(),
	}

	svc := NewService(store)

	requests, err := svc.GetMyPendingRequests(context.Background(), "user-123")
	require.NoError(t, err)
	assert.Len(t, requests, 1)
	assert.Equal(t, "req-1", requests[0].Request.ID)
}

func TestGetMyActiveGrants(t *testing.T) {
	store := newMockStore()
	store.requests["req-1"] = &Request{
		ID:           "req-1",
		TargetUserID: "user-123",
		Status:       StatusApproved,
	}
	store.grants["grant-1"] = &Grant{
		ID:        "grant-1",
		RequestID: "req-1",
		GrantedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour), // Active
	}
	store.grants["grant-2"] = &Grant{
		ID:        "grant-2",
		RequestID: "req-1",
		GrantedAt: time.Now().Add(-48 * time.Hour),
		ExpiresAt: time.Now().Add(-24 * time.Hour), // Expired
	}

	svc := NewService(store)

	grants, err := svc.GetMyActiveGrants(context.Background(), "user-123")
	require.NoError(t, err)
	assert.Len(t, grants, 1)
	assert.Equal(t, "grant-1", grants[0].Grant.ID)
}

func TestListAllRequests(t *testing.T) {
	store := newMockStore()
	store.requests["req-1"] = &Request{
		ID:          "req-1",
		OrgID:       "org-123",
		Status:      StatusPending,
		RequestedAt: time.Now(),
	}
	store.requests["req-2"] = &Request{
		ID:          "req-2",
		OrgID:       "org-123",
		Status:      StatusApproved,
		RequestedAt: time.Now(),
	}
	store.requests["req-3"] = &Request{
		ID:          "req-3",
		OrgID:       "other-org", // Different org
		Status:      StatusPending,
		RequestedAt: time.Now(),
	}

	svc := NewService(store)

	// List all for org
	requests, err := svc.ListAllRequests(context.Background(), "org-123", nil)
	require.NoError(t, err)
	assert.Len(t, requests, 2)

	// Filter by status
	pendingStatus := StatusPending
	requests, err = svc.ListAllRequests(context.Background(), "org-123", &pendingStatus)
	require.NoError(t, err)
	assert.Len(t, requests, 1)
	assert.Equal(t, StatusPending, requests[0].Request.Status)
}

// ============================================================================
// Test: Maintenance Methods
// ============================================================================

func TestExpireOldRequests(t *testing.T) {
	store := newMockStore()
	store.expirePendingReqCount = 5

	svc := NewService(store)

	count, err := svc.ExpireOldRequests(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(5), count)
}

func TestCleanupExpiredReports(t *testing.T) {
	store := newMockStore()
	store.deleteExpiredReportsCount = 10

	svc := NewService(store)

	count, err := svc.CleanupExpiredReports(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(10), count)
}

// ============================================================================
// Test: Model Methods
// ============================================================================

func TestGrant_IsActive(t *testing.T) {
	tests := []struct {
		name     string
		grant    Grant
		expected bool
	}{
		{
			name: "active grant",
			grant: Grant{
				GrantedAt: time.Now(),
				ExpiresAt: time.Now().Add(24 * time.Hour),
			},
			expected: true,
		},
		{
			name: "expired grant",
			grant: Grant{
				GrantedAt: time.Now().Add(-48 * time.Hour),
				ExpiresAt: time.Now().Add(-24 * time.Hour),
			},
			expected: false,
		},
		{
			name: "revoked grant",
			grant: Grant{
				GrantedAt: time.Now(),
				ExpiresAt: time.Now().Add(24 * time.Hour),
				RevokedAt: timePtr(time.Now()),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.grant.IsActive())
		})
	}
}

func TestRequest_IsExpired(t *testing.T) {
	tests := []struct {
		name     string
		request  Request
		expected bool
	}{
		{
			name: "not expired (no expiry)",
			request: Request{
				Status:    StatusPending,
				ExpiresAt: nil,
			},
			expected: false,
		},
		{
			name: "not expired (future expiry)",
			request: Request{
				Status:    StatusPending,
				ExpiresAt: timePtr(time.Now().Add(24 * time.Hour)),
			},
			expected: false,
		},
		{
			name: "expired",
			request: Request{
				Status:    StatusPending,
				ExpiresAt: timePtr(time.Now().Add(-24 * time.Hour)),
			},
			expected: true,
		},
		{
			name: "not pending (already decided)",
			request: Request{
				Status:    StatusApproved,
				ExpiresAt: timePtr(time.Now().Add(-24 * time.Hour)),
			},
			expected: false, // Not expired because not pending
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.request.IsExpired())
		})
	}
}

func TestRequest_CanBeDecided(t *testing.T) {
	tests := []struct {
		name     string
		request  Request
		expected bool
	}{
		{
			name: "can be decided (pending, no expiry)",
			request: Request{
				Status:    StatusPending,
				ExpiresAt: nil,
			},
			expected: true,
		},
		{
			name: "can be decided (pending, future expiry)",
			request: Request{
				Status:    StatusPending,
				ExpiresAt: timePtr(time.Now().Add(24 * time.Hour)),
			},
			expected: true,
		},
		{
			name: "cannot be decided (already approved)",
			request: Request{
				Status: StatusApproved,
			},
			expected: false,
		},
		{
			name: "cannot be decided (expired)",
			request: Request{
				Status:    StatusPending,
				ExpiresAt: timePtr(time.Now().Add(-24 * time.Hour)),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.request.CanBeDecided())
		})
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

func durationPtr(d time.Duration) *time.Duration {
	return &d
}

func timePtr(t time.Time) *time.Time {
	return &t
}
