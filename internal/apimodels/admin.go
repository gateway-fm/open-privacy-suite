package apimodels

import (
	"privacy-proxy/internal/rbac"
)

// Transport models relocated from admin_dry_run.go, admin_rbac_contract.go, admin_rbac_session.go, admin_rbac_user.go, admin_shared_infra.go, admin_system.go (RD-1265).
// These describe the wire contract; the schema names in the published
// OpenAPI document derive from this package, not from handler layout.

// DryRunRequest is the JSON body of POST /api/orgs/:org_id/dry-run.
type DryRunRequest struct {
	UserDID string         `json:"user_did" binding:"required"`
	RPC     DryRunRPCBlock `json:"rpc" binding:"required"`
}

// DryRunRPCBlock carries the JSON-RPC method + params that the admin
// is asking the proxy to evaluate as the impersonated user.
type DryRunRPCBlock struct {
	Method string `json:"method" binding:"required"`
	Params []any  `json:"params"`
}

// DryRunResponseDoc is the OpenAPI mirror of dryRunResponse (RD-1166):
// swag cannot schema json.RawMessage, so the spec documents those
// pass-through fields as free-form JSON values. Wire shape is identical.
// Spec-only; never constructed at runtime.
type DryRunResponseDoc struct {
	Decision          string `json:"decision" example:"allow"`
	Reason            string `json:"reason,omitempty"`
	Response          any    `json:"response,omitempty"`
	Trace             any    `json:"trace,omitempty"`
	LogsEmitted       []any  `json:"logs_emitted,omitempty"`
	LogsVisibleToUser []any  `json:"logs_visible_to_user,omitempty"`
}

// ContractSyncStatus represents the on-chain status of a contract
type ContractSyncStatus struct {
	ID      string `json:"id"`
	Address string `json:"address"`
	Name    string `json:"name"`
	Status  string `json:"status"` // "exists", "missing", "error"
	Error   string `json:"error,omitempty"`
}

// SessionListResponse represents the response for listing sessions.
type SessionListResponse struct {
	Sessions []*SessionInfoResponse `json:"sessions"`
	Total    int64                  `json:"total"`
}

type SessionInfoResponse struct {
	ID          string `json:"id"`
	CreatedAt   string `json:"created_at"`
	ExpiresAt   string `json:"expires_at"`
	Completed   bool   `json:"completed"`
	CompletedAt string `json:"completed_at,omitempty"`
	// Failure state (RD-1242). This is the operator channel for the PRECISE
	// reason: the polled session-status endpoint collapses oracle-sensitive
	// codes, this super-admin view does not.
	Failed        bool   `json:"failed,omitempty"`
	FailureReason string `json:"failure_reason,omitempty"`
	FailedAt      string `json:"failed_at,omitempty"`
}

// UserListItem extends rbac.User with the user's group memberships for the
// list response. Memberships are scoped to the caller's accessible orgs
// for non-super-admin callers (cross-org isolation).
type UserListItem struct {
	*rbac.User
	Groups []rbac.UserGroupMembership `json:"groups"`
}

// MembershipListItem is a membership-with-details plus a server-computed
// `expired` flag, so the admin UI can tell a live time-boxed grant from one
// whose window has already lapsed. `expired` mirrors the RBAC resolver's
// `expires_at > NOW()` access filter (RD-1157): a grant is expired once
// `expires_at <= now`, so the boundary the badge shows matches enforcement.
// (The resolver's clock is the database's NOW(); this uses the app's UTC now —
// not the identical instant, but the boundary semantics are the same and the
// skew is immaterial for a display badge.) The raw expires_at is still carried
// on the embedded membership.
type MembershipListItem struct {
	Membership *rbac.UserMembership `json:"membership"`
	Group      *rbac.Group          `json:"group"`
	Expired    bool                 `json:"expired"`
}

// SharedInfraInput is the request body for create and update. Address
// on create comes from the body; on update it comes from the path and
// the body field is ignored.
type SharedInfraInput struct {
	Address     string `json:"address"`
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
	// Codehash is optional. Empty / omitted = no codehash pin
	// (legacy behaviour: trust by address alone). When supplied it
	// must be a 0x-prefixed lowercase 32-byte hex string. The
	// recommended workflow is to omit on create and use the
	// /refresh-codehash endpoint immediately after, which computes
	// it server-side from the current bytecode.
	Codehash string `json:"codehash"`
}

// SystemVersionResponse is the GET /api/v1/admin/system/version shape.
type SystemVersionResponse struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
}

// SystemToggleRequest is the request body for the system on/off toggle POSTs
// (eth_call tracing, intra-org grant scoping). Shared shape.
type SystemToggleRequest struct {
	Enabled *bool  `json:"enabled" binding:"required"` // pointer so we distinguish "false" from "omitted"
	Reason  string `json:"reason"`
}

// SystemToggleResponse is the GET / POST response shape for a system toggle.
type SystemToggleResponse struct {
	Enabled    bool   `json:"enabled"`
	EnvDefault bool   `json:"env_default"`
	Source     string `json:"source"` // "env" | "runtime_override"
	ChangedAt  string `json:"changed_at,omitempty"`
	ChangedBy  string `json:"changed_by,omitempty"`
	Reason     string `json:"reason,omitempty"`
}
