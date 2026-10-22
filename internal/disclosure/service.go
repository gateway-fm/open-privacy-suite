package disclosure

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrRequestNotFound   = errors.New("disclosure request not found")
	ErrRequestNotPending = errors.New("disclosure request is not pending")
	ErrRequestExpired    = errors.New("disclosure request has expired")
	ErrGrantNotFound     = errors.New("disclosure grant not found")
	ErrGrantNotActive    = errors.New("disclosure grant is not active")
	ErrInvalidToken      = errors.New("invalid disclosure token")
	ErrUnauthorized      = errors.New("unauthorized to perform this action")
	ErrScopeOutOfBounds  = errors.New("requested scope exceeds granted scope")
)

// DefaultService implements the Service interface.
type DefaultService struct {
	store Store
}

// NewService creates a new disclosure service.
func NewService(store Store) *DefaultService {
	return &DefaultService{store: store}
}

// CreateRequest creates a new disclosure request.
func (s *DefaultService) CreateRequest(ctx context.Context, requesterUserID, requesterDID, targetUserID, orgID string, scope Scope, reason, legalBasis string, expiresIn *time.Duration) (*Request, error) {
	// RD-1353: the scope is what the subject will be asked to consent to and
	// what the grant API enforces, so it is validated and stored normalised.
	scope, err := scope.Normalize()
	if err != nil {
		return nil, err
	}
	req := &Request{
		ID:           uuid.New().String(),
		RequesterDID: requesterDID,
		TargetUserID: targetUserID,
		OrgID:        orgID,
		Scope:        scope,
		Reason:       reason,
		LegalBasis:   legalBasis,
		Status:       StatusPending,
		RequestedAt:  time.Now(),
	}

	if requesterUserID != "" {
		req.RequesterUserID = &requesterUserID
	}

	if expiresIn != nil {
		expiresAt := time.Now().Add(*expiresIn)
		req.ExpiresAt = &expiresAt
	}

	if err := s.store.CreateRequest(ctx, req); err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	return req, nil
}

// ApproveRequest approves a disclosure request and creates a grant.
// Access is controlled via requester_did - no token needed for DID-based auth.
func (s *DefaultService) ApproveRequest(ctx context.Context, requestID, decidedByUserID string, narrowedScope *Scope, grantDuration time.Duration, reason string) (*Grant, error) {
	req, err := s.store.GetRequest(ctx, requestID)
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrRequestNotFound
	}

	if req.Status != StatusPending {
		return nil, ErrRequestNotPending
	}
	if req.IsExpired() {
		return nil, ErrRequestExpired
	}

	// Determine granted scope (may be narrower than requested). RD-1164 #9:
	// reject an "approval" that would WIDEN the requested scope — the narrowed
	// scope must stay within the request's bounds. Previously the narrowed scope
	// simply replaced the requested one, leaving ErrScopeOutOfBounds dead code
	// and letting an approver grant more than was asked.
	requestedScope, err := req.Scope.Normalize()
	if err != nil {
		return nil, err
	}
	grantedScope := requestedScope
	if narrowedScope != nil {
		// Merge: unset fields in the narrowed scope inherit from the request, so
		// a partial narrowing (e.g. only lowering the disclosure level) does not
		// accidentally widen the untouched dimensions. The merged scope must then
		// stay within the request's bounds — an approval may only narrow.
		merged, err := mergeNarrowedScope(requestedScope, *narrowedScope).Normalize()
		if err != nil {
			return nil, err
		}
		if !merged.isSubsetOf(requestedScope) {
			return nil, ErrScopeOutOfBounds
		}
		grantedScope = merged
	}
	// RD-1353: a granted scope is validated and stored normalised, so a request
	// stored before scopes were validated cannot mint a grant the grant API
	// would read ambiguously (an empty level becomes redacted).
	grantedScope, err = grantedScope.Normalize()
	if err != nil {
		return nil, err
	}

	// Create grant - use a placeholder hash since we're using DID-based auth now
	grant := &Grant{
		ID:             uuid.New().String(),
		RequestID:      requestID,
		GrantTokenHash: fmt.Sprintf("did-auth-%s", uuid.New().String()), // Placeholder for DID-based auth
		Scope:          grantedScope,
		GrantedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(grantDuration),
	}

	if err := s.store.CreateGrant(ctx, grant); err != nil {
		return nil, fmt.Errorf("failed to create grant: %w", err)
	}

	// Update request status
	if err := s.store.UpdateRequestStatus(ctx, requestID, StatusApproved, &decidedByUserID, reason); err != nil {
		return nil, fmt.Errorf("failed to update request status: %w", err)
	}

	return grant, nil
}

// mergeNarrowedScope returns base with any explicitly-set field of override
// applied. An unset field in override (empty slice, nil DateRange, empty
// DisclosureLevel) inherits base's value, so a partial narrowing never widens
// an untouched dimension.
func mergeNarrowedScope(base, override Scope) Scope {
	out := base
	if len(override.Methods) > 0 {
		out.Methods = override.Methods
	}
	if len(override.Addresses) > 0 {
		out.Addresses = override.Addresses
	}
	if override.DateRange != nil {
		out.DateRange = override.DateRange
	}
	if override.DisclosureLevel != "" {
		out.DisclosureLevel = override.DisclosureLevel
	}
	return out
}

// isSubsetOf reports whether s stays within the bounds of parent — i.e. it does
// not grant anything parent does not (RD-1164 #9). An unset dimension on parent
// (empty Addresses or nil DateRange) imposes no restriction there. Empty
// Methods permits transaction history only.
func (s Scope) isSubsetOf(parent Scope) bool {
	// Categories are capabilities, not RPC names: full_disclosure includes both
	// data classes, while an empty list covers transactions only.
	if s.AllowsTransactionHistory() && !parent.AllowsTransactionHistory() ||
		s.AllowsActivityLogs() && !parent.AllowsActivityLogs() {
		return false
	}
	// Addresses: same rule, case-insensitive on the hex address.
	if len(parent.Addresses) > 0 {
		if len(s.Addresses) == 0 {
			return false
		}
		allowed := make(map[string]bool, len(parent.Addresses))
		for _, a := range parent.Addresses {
			allowed[strings.ToLower(a)] = true
		}
		for _, a := range s.Addresses {
			if !allowed[strings.ToLower(a)] {
				return false
			}
		}
	}
	// DateRange: if parent is time-bounded, s must be bounded and within it.
	if parent.DateRange != nil {
		if s.DateRange == nil {
			return false
		}
		if s.DateRange.Start.Before(parent.DateRange.Start) || s.DateRange.End.After(parent.DateRange.End) {
			return false
		}
	}
	// DisclosureLevel: s must not reveal more than parent.
	return disclosureRank(s.DisclosureLevel) <= disclosureRank(parent.DisclosureLevel)
}

// disclosureRank orders disclosure levels by how much they reveal (higher =
// more revealing), by the level a read renders at (Scope.EffectiveLevel): an
// empty or unknown level is redacted (RD-1353), the least revealing.
func disclosureRank(l DisclosureLevel) int {
	switch (Scope{DisclosureLevel: l}).EffectiveLevel() {
	case DisclosureFull:
		return 3
	case DisclosurePseudonymous:
		return 2
	default:
		return 1
	}
}

// RejectRequest rejects a disclosure request.
func (s *DefaultService) RejectRequest(ctx context.Context, requestID, decidedByUserID, reason string) error {
	req, err := s.store.GetRequest(ctx, requestID)
	if err != nil {
		return err
	}
	if req == nil {
		return ErrRequestNotFound
	}

	if req.Status != StatusPending {
		return ErrRequestNotPending
	}

	return s.store.UpdateRequestStatus(ctx, requestID, StatusRejected, &decidedByUserID, reason)
}

// RevokeRequest revokes an approved request (and its grant).
func (s *DefaultService) RevokeRequest(ctx context.Context, requestID, revokedByUserID, reason string) error {
	req, err := s.store.GetRequest(ctx, requestID)
	if err != nil {
		return err
	}
	if req == nil {
		return ErrRequestNotFound
	}

	// Revoke any active grants
	grant, err := s.store.GetActiveGrantForRequest(ctx, requestID)
	if err != nil {
		return err
	}
	if grant != nil {
		if err := s.store.RevokeGrant(ctx, grant.ID, reason); err != nil {
			return fmt.Errorf("failed to revoke grant: %w", err)
		}
	}

	return s.store.UpdateRequestStatus(ctx, requestID, StatusRevoked, &revokedByUserID, reason)
}

// ValidateGrantToken validates a disclosure token and returns the grant with request.
func (s *DefaultService) ValidateGrantToken(ctx context.Context, token string) (*GrantWithRequest, error) {
	tokenHash := hashToken(token)

	grant, err := s.store.GetGrantByToken(ctx, tokenHash)
	if err != nil {
		return nil, err
	}
	if grant == nil {
		return nil, ErrInvalidToken
	}

	if !grant.IsActive() {
		return nil, ErrGrantNotActive
	}

	req, err := s.store.GetRequest(ctx, grant.RequestID)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Status != StatusApproved {
		return nil, ErrGrantNotActive
	}
	scope, err := grant.Scope.ForRead()
	if err != nil {
		return nil, err
	}
	grantCopy := *grant
	grantCopy.Scope = scope

	return &GrantWithRequest{Grant: &grantCopy, Request: req}, nil
}

// RevokeGrant revokes a disclosure grant.
func (s *DefaultService) RevokeGrant(ctx context.Context, grantID, reason string) error {
	grant, err := s.store.GetGrant(ctx, grantID)
	if err != nil {
		return err
	}
	if grant == nil {
		return ErrGrantNotFound
	}

	return s.store.RevokeGrant(ctx, grantID, reason)
}

// GetActivityLogs retrieves activity logs within the granted scope.
func (s *DefaultService) GetActivityLogs(ctx context.Context, grantID, viewerUserID, viewerIP string, limit, offset int) ([]*ActivityLogEntry, error) {
	grantWithReq, err := s.store.GetGrantWithRequest(ctx, grantID)
	if err != nil {
		return nil, err
	}
	if grantWithReq == nil || grantWithReq.Grant == nil {
		return nil, ErrGrantNotFound
	}

	if grantWithReq.Request == nil || grantWithReq.Request.Status != StatusApproved || !grantWithReq.Grant.IsActive() {
		return nil, ErrGrantNotActive
	}
	scope, err := grantWithReq.Grant.Scope.ForRead()
	if err != nil {
		return nil, err
	}
	if err := scope.ValidateActivity(); err != nil {
		return nil, err
	}

	// Get target user's external ID from internal ID
	req := grantWithReq.Request
	targetUserExternalID, err := s.store.GetUserExternalID(ctx, req.TargetUserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get target user external ID: %w", err)
	}

	// Query activity logs using the external ID
	logs, err := s.store.GetActivityLogs(ctx, targetUserExternalID, &scope, limit, offset)
	if err != nil {
		return nil, err
	}

	// Log this access event
	event := &Event{
		GrantID:      grantID,
		Action:       ActionViewLogs,
		ResourceType: ResourceAccessLogs,
		ViewerIP:     viewerIP,
		AccessedAt:   time.Now(),
		DataSummary: &DataSummary{
			RecordCount: len(logs),
		},
	}
	if viewerUserID != "" {
		event.ViewerUserID = &viewerUserID
	}

	s.recordReadEvent(ctx, event)

	if scope.EffectiveLevel() != DisclosureFull {
		rendered := make([]*ActivityLogEntry, 0, len(logs))
		for _, entry := range logs {
			if entry == nil {
				continue
			}
			copy := *entry
			copy.IPAddress = ""
			rendered = append(rendered, &copy)
		}
		logs = rendered
	}
	return logs, nil
}

// GetActivitySummary retrieves an activity summary within the granted scope.
func (s *DefaultService) GetActivitySummary(ctx context.Context, grantID, viewerUserID, viewerIP string) (*ActivitySummary, error) {
	grantWithReq, err := s.store.GetGrantWithRequest(ctx, grantID)
	if err != nil {
		return nil, err
	}
	if grantWithReq == nil || grantWithReq.Grant == nil {
		return nil, ErrGrantNotFound
	}

	if grantWithReq.Request == nil || grantWithReq.Request.Status != StatusApproved || !grantWithReq.Grant.IsActive() {
		return nil, ErrGrantNotActive
	}
	scope, err := grantWithReq.Grant.Scope.ForRead()
	if err != nil {
		return nil, err
	}
	if err := scope.ValidateActivity(); err != nil {
		return nil, err
	}

	req := grantWithReq.Request
	targetUserExternalID, err := s.store.GetUserExternalID(ctx, req.TargetUserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get target user external ID: %w", err)
	}

	summary, err := s.store.GetActivitySummary(ctx, targetUserExternalID, &scope)
	if err != nil {
		return nil, err
	}

	// Log this access event
	event := &Event{
		GrantID:      grantID,
		Action:       ActionViewSummary,
		ResourceType: ResourceSummary,
		ViewerIP:     viewerIP,
		AccessedAt:   time.Now(),
		DataSummary: &DataSummary{
			RecordCount: summary.TotalRequests,
			DateRange:   summary.DateRange,
		},
	}
	if viewerUserID != "" {
		event.ViewerUserID = &viewerUserID
	}

	s.recordReadEvent(ctx, event)

	return summary, nil
}

// GenerateComplianceReport generates a compliance report.
func (s *DefaultService) GenerateComplianceReport(ctx context.Context, grantID, viewerUserID, viewerIP string, reportType ReportType) (*Report, error) {
	grantWithReq, err := s.store.GetGrantWithRequest(ctx, grantID)
	if err != nil {
		return nil, err
	}
	if grantWithReq == nil || grantWithReq.Grant == nil {
		return nil, ErrGrantNotFound
	}

	if grantWithReq.Request == nil || grantWithReq.Request.Status != StatusApproved || !grantWithReq.Grant.IsActive() {
		return nil, ErrGrantNotActive
	}
	scope, err := grantWithReq.Grant.Scope.ForRead()
	if err != nil {
		return nil, err
	}
	if err := scope.ValidateActivity(); err != nil {
		return nil, err
	}

	// Check for cached report
	existing, err := s.store.GetReportByGrantAndType(ctx, grantID, reportType)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		event := &Event{GrantID: grantID, Action: ActionExportReport, ResourceType: ResourceReport, ViewerIP: viewerIP, AccessedAt: time.Now(), DataSummary: &DataSummary{RecordCount: 1}}
		if viewerUserID != "" {
			event.ViewerUserID = &viewerUserID
		}
		s.recordReadEvent(ctx, event)
		return renderReport(existing, scope), nil
	}

	// Generate new report based on type
	req := grantWithReq.Request
	targetUserExternalID, err := s.store.GetUserExternalID(ctx, req.TargetUserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get target user external ID: %w", err)
	}

	var reportData map[string]any

	switch reportType {
	case ReportActivitySummary:
		summary, err := s.store.GetActivitySummary(ctx, targetUserExternalID, &scope)
		if err != nil {
			return nil, err
		}
		reportData = map[string]any{
			"type":             "activity_summary",
			"target_user_id":   req.TargetUserID,
			"total_requests":   summary.TotalRequests,
			"successful_count": summary.SuccessfulCount,
			"failed_count":     summary.FailedCount,
			"unique_methods":   summary.UniqueMethodCount,
			"method_breakdown": summary.MethodBreakdown,
			"date_range":       summary.DateRange,
			"generated_at":     time.Now(),
		}

	case ReportSanctionsCheck:
		// For now, return a clean sanctions check
		// In production, this would integrate with actual sanctions lists
		reportData = map[string]any{
			"type":                 "sanctions_check",
			"target_user_id":       req.TargetUserID,
			"checked_at":           time.Now(),
			"is_clear":             true,
			"sanctioned_addresses": []string{},
			"scope":                grantWithReq.Grant.Scope,
		}

	case ReportCompliance:
		summary, err := s.store.GetActivitySummary(ctx, targetUserExternalID, &scope)
		if err != nil {
			return nil, err
		}
		reportData = map[string]any{
			"type":             "compliance_report",
			"target_user_id":   req.TargetUserID,
			"generated_at":     time.Now(),
			"scope":            grantWithReq.Grant.Scope,
			"activity_summary": summary,
			"sanctions_clear":  true,
			"kyc_verified":     false, // Would need to fetch from user
		}

	default:
		return nil, fmt.Errorf("unknown report type: %s", reportType)
	}

	report := &Report{
		ID:          uuid.New().String(),
		GrantID:     grantID,
		ReportType:  reportType,
		ReportData:  reportData,
		GeneratedAt: time.Now(),
		ExpiresAt:   time.Now().Add(24 * time.Hour), // Reports valid for 24 hours
	}

	if err := s.store.CreateReport(ctx, report); err != nil {
		return nil, fmt.Errorf("failed to save report: %w", err)
	}

	// Log this access event
	event := &Event{
		GrantID:      grantID,
		Action:       ActionExportReport,
		ResourceType: ResourceReport,
		ViewerIP:     viewerIP,
		AccessedAt:   time.Now(),
		DataSummary: &DataSummary{
			RecordCount: 1,
			Methods:     []string{string(reportType)},
		},
	}
	if viewerUserID != "" {
		event.ViewerUserID = &viewerUserID
	}

	s.recordReadEvent(ctx, event)

	return renderReport(report, scope), nil
}

func (s *DefaultService) recordReadEvent(ctx context.Context, event *Event) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := s.store.CreateEvent(ctx, event); err != nil {
		slog.ErrorContext(ctx, "failed to record disclosure read", "action", event.Action, "err", err)
	}
}

// Reports may have been cached under an earlier rendering policy. Project
// non-full responses onto the report schema instead of trusting cached fields.
func renderReport(report *Report, scope Scope) *Report {
	if scope.EffectiveLevel() == DisclosureFull {
		return report
	}
	copy := *report
	copy.ReportData = make(map[string]any)
	for _, key := range []string{"type", "total_requests", "successful_count", "failed_count", "unique_methods", "method_breakdown", "date_range", "generated_at", "checked_at", "is_clear", "sanctions_clear", "kyc_verified", "activity_summary"} {
		if value, ok := report.ReportData[key]; ok {
			copy.ReportData[key] = value
		}
	}
	return &copy
}

// GetMyPendingRequests returns pending disclosure requests for a user.
func (s *DefaultService) GetMyPendingRequests(ctx context.Context, userID string) ([]*RequestWithDetails, error) {
	return s.store.ListPendingRequestsForUser(ctx, userID)
}

// GetMyActiveGrants returns active disclosure grants for a user's data.
func (s *DefaultService) GetMyActiveGrants(ctx context.Context, userID string) ([]*GrantWithRequest, error) {
	return s.store.ListActiveGrantsForTarget(ctx, userID)
}

// ListAllRequests lists all disclosure requests for an organization.
func (s *DefaultService) ListAllRequests(ctx context.Context, orgID string, status *RequestStatus) ([]*RequestWithDetails, error) {
	requests, err := s.store.ListRequestsByOrg(ctx, orgID, status)
	if err != nil {
		return nil, err
	}

	// Convert to RequestWithDetails (without full details for efficiency)
	var results []*RequestWithDetails
	for _, req := range requests {
		results = append(results, &RequestWithDetails{Request: req})
	}
	return results, nil
}

// ExpireOldRequests expires pending requests that have passed their expiration.
func (s *DefaultService) ExpireOldRequests(ctx context.Context) (int64, error) {
	return s.store.ExpirePendingRequests(ctx)
}

// CleanupExpiredReports removes expired report records.
func (s *DefaultService) CleanupExpiredReports(ctx context.Context) (int64, error) {
	return s.store.DeleteExpiredReports(ctx)
}

// ListRequestsWithFilter returns filtered disclosure requests.
func (s *DefaultService) ListRequestsWithFilter(ctx context.Context, filter *DisclosureFilter) (*DisclosureListResult, error) {
	if filter == nil {
		filter = NewDefaultFilter()
	}
	if filter.Limit <= 0 {
		filter.Limit = 100
	}
	if filter.Limit > 1000 {
		filter.Limit = 1000
	}
	return s.store.ListRequestsWithFilter(ctx, filter)
}

// ListGrantsWithFilter returns filtered disclosure grants.
func (s *DefaultService) ListGrantsWithFilter(ctx context.Context, filter *DisclosureFilter) (*GrantListResult, error) {
	if filter == nil {
		filter = NewDefaultFilter()
	}
	if filter.Limit <= 0 {
		filter.Limit = 100
	}
	if filter.Limit > 1000 {
		filter.Limit = 1000
	}
	return s.store.ListGrantsWithFilter(ctx, filter)
}

// DeletePendingRequest deletes a pending disclosure request (admin action).
func (s *DefaultService) DeletePendingRequest(ctx context.Context, requestID string) error {
	req, err := s.store.GetRequest(ctx, requestID)
	if err != nil {
		return err
	}
	if req == nil {
		return ErrRequestNotFound
	}

	if req.Status != StatusPending {
		return ErrRequestNotPending
	}

	return s.store.DeleteRequest(ctx, requestID)
}

// GetAllMyRequests returns all disclosure requests for a user (not just pending).
func (s *DefaultService) GetAllMyRequests(ctx context.Context, userID string) ([]*RequestWithDetails, error) {
	return s.store.ListAllRequestsForUser(ctx, userID)
}

// GetAllMyGrants returns all disclosure grants for a user's data (not just active).
func (s *DefaultService) GetAllMyGrants(ctx context.Context, userID string) ([]*GrantWithRequest, error) {
	return s.store.ListAllGrantsForTarget(ctx, userID)
}

// hashToken creates a SHA256 hash of a token.
func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
