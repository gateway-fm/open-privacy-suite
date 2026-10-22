// Package disclosure provides selective disclosure features for compliance and audit.
// Inspired by ZkSync Prividium's disclosure architecture.
package disclosure

import (
	"time"
)

// RequestStatus represents the status of a disclosure request.
type RequestStatus string

const (
	StatusPending  RequestStatus = "pending"
	StatusApproved RequestStatus = "approved"
	StatusRejected RequestStatus = "rejected"
	StatusExpired  RequestStatus = "expired"
	StatusRevoked  RequestStatus = "revoked"
)

// EventAction represents the type of disclosure event.
type EventAction string

const (
	ActionViewLogs         EventAction = "view_logs"
	ActionViewTransactions EventAction = "view_transactions"
	ActionViewSummary      EventAction = "view_summary"
	ActionExportReport     EventAction = "export_report"
	// ActionViewTransaction: one disclosed transaction read by hash.
	ActionViewTransaction EventAction = "view_transaction"
	// ActionListAddresses: the grant listed among the viewer's disclosed
	// addresses (the subject's addresses at the grant's level).
	ActionListAddresses EventAction = "list_addresses"
	// ActionResolveAddress: a disclosed address resolved by its address_id.
	ActionResolveAddress EventAction = "resolve_address"
	ActionViewEvents     EventAction = "view_events"
)

// ResourceType represents the type of resource accessed in a disclosure event.
type ResourceType string

const (
	ResourceAccessLogs   ResourceType = "access_logs"
	ResourceTransactions ResourceType = "transactions"
	ResourceSummary      ResourceType = "summary"
	ResourceReport       ResourceType = "report"
	ResourceAddresses    ResourceType = "addresses"
	ResourceEvents       ResourceType = "events"
)

// ReportType represents the type of compliance report.
type ReportType string

const (
	ReportActivitySummary ReportType = "activity_summary"
	ReportSanctionsCheck  ReportType = "sanctions_check"
	ReportCompliance      ReportType = "compliance_report"
)

// DisclosureLevel controls how much address detail is revealed.
type DisclosureLevel string

const (
	// DisclosureFull shows real addresses - for regulatory subpoenas, law enforcement
	DisclosureFull DisclosureLevel = "full"
	// DisclosurePseudonymous shows consistent pseudonyms (Address-A, Address-B) - for audits
	DisclosurePseudonymous DisclosureLevel = "pseudonymous"
	// DisclosureRedacted hides all addresses - for minimal disclosure
	DisclosureRedacted DisclosureLevel = "redacted"
)

// Scope defines what data can be accessed in a disclosure.
type Scope struct {
	Methods         []string        `json:"methods,omitempty"`          // Data categories: activity_logs, transaction_history, full_disclosure
	Addresses       []string        `json:"addresses,omitempty"`        // Specific contract addresses
	DateRange       *DateRange      `json:"date_range,omitempty"`       // Time period
	DisclosureLevel DisclosureLevel `json:"disclosure_level,omitempty"` // How much address detail to reveal
}

// DateRange represents a time period for filtering disclosed data.
type DateRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// Request represents a disclosure request from an authorized party.
type Request struct {
	ID              string        `json:"id"`
	RequesterUserID *string       `json:"requester_user_id,omitempty"` // Who is requesting (may be external)
	RequesterDID    string        `json:"requester_did,omitempty"`     // DID of authorized viewer (for block explorer auth)
	TargetUserID    string        `json:"target_user_id"`              // Whose data is being requested
	OrgID           string        `json:"org_id"`
	Scope           Scope         `json:"scope"`
	Reason          string        `json:"reason"`
	LegalBasis      string        `json:"legal_basis,omitempty"` // GDPR article, court order, etc.
	Status          RequestStatus `json:"status"`
	RequestedAt     time.Time     `json:"requested_at"`
	ExpiresAt       *time.Time    `json:"expires_at,omitempty"` // When request expires if not acted upon
	DecidedAt       *time.Time    `json:"decided_at,omitempty"`
	DecidedByUserID *string       `json:"decided_by_user_id,omitempty"`
	DecisionReason  string        `json:"decision_reason,omitempty"`
}

// Grant represents an active disclosure grant (approved request with access token).
type Grant struct {
	ID             string     `json:"id"`
	RequestID      string     `json:"request_id"`
	GrantTokenHash string     `json:"-"` // Never expose hash in API
	Scope          Scope      `json:"scope"`
	GrantedAt      time.Time  `json:"granted_at"`
	ExpiresAt      time.Time  `json:"expires_at"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
	RevokedReason  string     `json:"revoked_reason,omitempty"`
}

// Event represents a disclosure access event (audit trail).
type Event struct {
	ID           int64        `json:"id"`
	GrantID      string       `json:"grant_id"`
	ViewerUserID *string      `json:"viewer_user_id,omitempty"`
	Action       EventAction  `json:"action"`
	ResourceType ResourceType `json:"resource_type"`
	DataSummary  *DataSummary `json:"data_summary,omitempty"`
	ViewerIP     string       `json:"viewer_ip,omitempty"`
	AccessedAt   time.Time    `json:"accessed_at"`
}

// DataSummary provides metadata about accessed data without exposing the actual data.
type DataSummary struct {
	RecordCount int       `json:"record_count,omitempty"`
	DateRange   DateRange `json:"date_range,omitempty"`
	Methods     []string  `json:"methods,omitempty"`   // Methods that were accessed
	Addresses   []string  `json:"addresses,omitempty"` // Addresses that were accessed
}

// Report represents a generated compliance report.
type Report struct {
	ID          string         `json:"id"`
	GrantID     string         `json:"grant_id"`
	ReportType  ReportType     `json:"report_type"`
	ReportData  map[string]any `json:"report_data"`
	GeneratedAt time.Time      `json:"generated_at"`
	ExpiresAt   time.Time      `json:"expires_at"`
}

// RequestWithDetails includes request with related user information.
type RequestWithDetails struct {
	Request       *Request `json:"request"`
	RequesterDID  string   `json:"requester_did,omitempty"`
	TargetDID     string   `json:"target_did"`
	DecidedByDID  string   `json:"decided_by_did,omitempty"`
	ActiveGrantID *string  `json:"active_grant_id,omitempty"`
}

// GrantWithRequest includes grant with its associated request.
type GrantWithRequest struct {
	Grant   *Grant   `json:"grant"`
	Request *Request `json:"request"`
}

// ActivityLogEntry represents a single activity log entry for disclosure.
type ActivityLogEntry struct {
	ID         int64     `json:"id"`
	Method     string    `json:"method"`
	StatusCode int       `json:"status_code"`
	IPAddress  string    `json:"ip_address,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// ActivitySummary provides aggregated activity statistics.
type ActivitySummary struct {
	TotalRequests     int            `json:"total_requests"`
	SuccessfulCount   int            `json:"successful_count"`
	FailedCount       int            `json:"failed_count"`
	UniqueMethodCount int            `json:"unique_method_count"`
	MethodBreakdown   map[string]int `json:"method_breakdown"` // method -> count
	DateRange         DateRange      `json:"date_range"`
	GeneratedAt       time.Time      `json:"generated_at"`
}

// SanctionsCheckResult represents the result of a sanctions check.
type SanctionsCheckResult struct {
	UserDID             string    `json:"user_did"`
	CheckedAt           time.Time `json:"checked_at"`
	SanctionedAddresses []string  `json:"sanctioned_addresses,omitempty"` // Empty if clean
	IsClear             bool      `json:"is_clear"`
	DateRange           DateRange `json:"date_range"`
}

// IsActive returns true if the grant is currently active (not expired or revoked).
func (g *Grant) IsActive() bool {
	if g.RevokedAt != nil {
		return false
	}
	return time.Now().Before(g.ExpiresAt)
}

// IsExpired returns true if the request has expired without action.
func (r *Request) IsExpired() bool {
	if r.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*r.ExpiresAt) && r.Status == StatusPending
}

// CanBeDecided returns true if the request can still be approved/rejected.
func (r *Request) CanBeDecided() bool {
	return r.Status == StatusPending && !r.IsExpired()
}
