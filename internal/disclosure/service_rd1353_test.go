package disclosure

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApprovalMethodCapabilitiesRD1353(t *testing.T) {
	for _, tc := range []struct {
		name          string
		parent, child Scope
		wantErr       error
	}{
		{"empty cannot gain activity", Scope{}, Scope{Methods: []string{MethodActivityLogs}}, ErrScopeOutOfBounds},
		{"full can narrow to transactions", Scope{Methods: []string{MethodFullDisclosure}}, Scope{Methods: []string{MethodTransactionHistory}}, nil},
		{"full can narrow to activity", Scope{Methods: []string{MethodFullDisclosure}}, Scope{Methods: []string{MethodActivityLogs}}, nil},
		{"transactions cannot gain activity", Scope{Methods: []string{MethodTransactionHistory}}, Scope{Methods: []string{MethodFullDisclosure}}, ErrScopeOutOfBounds},
		{"normalize before narrowing", Scope{DisclosureLevel: DisclosureFull, Addresses: []string{"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}, Scope{Addresses: []string{" 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA "}}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newMockStore()
			store.requests["r"] = &Request{ID: "r", Status: StatusPending, Scope: tc.parent}
			_, err := NewService(store).ApproveRequest(context.Background(), "r", "owner", &tc.child, time.Hour, "")
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				assert.Empty(t, store.grants)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestScopeDatePrecisionRD1353(t *testing.T) {
	start := time.Unix(1_800_000_000, 500_000_000)
	scope := Scope{DateRange: &DateRange{Start: start, End: start.Add(time.Second)}}
	assert.False(t, scope.InDateRange(start.Unix()), "fractional lower bound must not disclose the preceding half-second")
	assert.True(t, scope.InDateRange(start.Unix()+1))
	assert.False(t, scope.InDateRange(start.Unix()+2))
}

func rd1353ActivityService(scope Scope) (*DefaultService, *mockStore) {
	store := newMockStore()
	store.requests["r"] = &Request{ID: "r", Status: StatusApproved, TargetUserID: "target"}
	store.grants["g"] = &Grant{ID: "g", RequestID: "r", Scope: scope, ExpiresAt: time.Now().Add(time.Hour)}
	return NewService(store), store
}

func TestActivityReadScopeRD1353(t *testing.T) {
	for _, scope := range []Scope{
		{},
		{Methods: []string{MethodTransactionHistory}},
		{Methods: []string{MethodActivityLogs}, Addresses: []string{"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
		{Methods: []string{"eth_call"}},
		{Methods: []string{MethodActivityLogs}, DateRange: &DateRange{Start: time.Now()}},
	} {
		svc, _ := rd1353ActivityService(scope)
		_, err := svc.GetActivityLogs(context.Background(), "g", "viewer", "", 10, 0)
		assert.Error(t, err, "scope %+v", scope)
		_, err = svc.GetActivitySummary(context.Background(), "g", "viewer", "")
		assert.Error(t, err, "scope %+v", scope)
		_, err = svc.GenerateComplianceReport(context.Background(), "g", "viewer", "", ReportCompliance)
		assert.Error(t, err, "scope %+v", scope)
	}
}

func TestActivityReadRenderingAndCachedAuditRD1353(t *testing.T) {
	svc, store := rd1353ActivityService(Scope{Methods: []string{MethodActivityLogs}, DisclosureLevel: DisclosurePseudonymous})
	logs, err := svc.GetActivityLogs(context.Background(), "g", "viewer", "127.0.0.1", 10, 0)
	require.NoError(t, err)
	for _, entry := range logs {
		assert.Empty(t, entry.IPAddress)
	}
	assert.NotEmpty(t, store.activityLogs[0].IPAddress, "rendering must not mutate stored records")
	_, err = svc.GenerateComplianceReport(context.Background(), "g", "viewer", "", ReportCompliance)
	require.NoError(t, err)
	before := len(store.events)
	_, err = svc.GenerateComplianceReport(context.Background(), "g", "viewer", "", ReportCompliance)
	require.NoError(t, err)
	assert.Len(t, store.events, before+1, "cached reports are audited too")
}
