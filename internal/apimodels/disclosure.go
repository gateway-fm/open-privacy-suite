package apimodels

// Spec-only request/response models for the disclosure handlers (RD-1166).
//
// Several disclosure handlers in disclosure.go bind an anonymous request struct
// (inline `var input struct{...}` passed to ShouldBindJSON) and/or respond with
// gin.H (anonymous JSON objects). swaggo cannot reference an anonymous struct
// from @Param/@Success, so the structs below mirror those wire shapes exactly —
// same JSON keys, types, and omitempty behaviour — purely so the generated
// OpenAPI document has an accurate schema. They are never constructed at
// runtime. Handlers that bind or marshal a concrete named type (e.g.
// disclosure.Request, disclosure.DisclosureListResult) reference that type
// directly and do not appear here.

import "privacy-proxy/internal/disclosure"

// ---- Request bodies (mirror the anonymous ShouldBindJSON structs) ----

// CreateDisclosureRequestBody mirrors the JSON body bound by
// createDisclosureRequest. target_user_id and reason are required.
type CreateDisclosureRequestBody struct {
	RequesterUserID string           `json:"requester_user_id,omitempty" example:"user-123"`
	RequesterDID    string           `json:"requester_did,omitempty" example:"did:example:auditor"`
	TargetUserID    string           `json:"target_user_id" example:"user-456"`
	OrgID           string           `json:"org_id,omitempty" example:"00000000-0000-0000-0000-000000000001"`
	Scope           disclosure.Scope `json:"scope"`
	Reason          string           `json:"reason" example:"regulatory audit"`
	LegalBasis      string           `json:"legal_basis,omitempty" example:"GDPR Art. 6(1)(c)"`
	ExpiresInHours  int              `json:"expires_in_hours,omitempty" example:"72"`
}

// DisclosureReasonBody mirrors the optional {"reason": "..."} body accepted by
// adminRevokeDisclosureGrant, rejectDisclosureRequest, and
// revokeDisclosureRequest. The whole body is optional; reason is free text.
type DisclosureReasonBody struct {
	Reason string `json:"reason,omitempty" example:"no longer required"`
}

// ApproveDisclosureRequestBody mirrors the optional body bound by
// approveDisclosureRequest. All fields are optional: scope narrows (never
// widens) the requested scope, grant_duration_hours defaults to 24 when omitted
// or non-positive.
type ApproveDisclosureRequestBody struct {
	Scope              *disclosure.Scope `json:"scope,omitempty"`
	GrantDurationHours int               `json:"grant_duration_hours,omitempty" example:"24"`
	Reason             string            `json:"reason,omitempty" example:"approved for audit window"`
}

// ---- Response bodies (mirror the gin.H shapes) ----

// DisclosureStatusResponse is the body of the status-only admin/user actions
// that reply with a single {"status": "..."} object. The concrete value is
// operation-specific: deleteDisclosureRequest returns "deleted",
// adminRevokeDisclosureGrant / revokeDisclosureRequest return "revoked", and
// rejectDisclosureRequest returns "rejected". No field-level example is set so
// the single value does not bleed a wrong status onto the other operations that
// share this shape; the per-operation @Success description states the actual
// value, and the enum below documents the full domain.
type DisclosureStatusResponse struct {
	Status string `json:"status" enums:"deleted,revoked,rejected"`
}

// DisclosureCheckAccessResponse is the body of GET
// /api/v1/admin/disclosure/check-access. It is a superset of the two shapes the
// handler returns: when no active grant exists only has_access (false) and
// message are set; when an active grant exists has_access is true and the
// grant_id, scope, expires_at, and disclosure_level fields describe it (message
// is then absent).
type DisclosureCheckAccessResponse struct {
	HasAccess       bool                       `json:"has_access" example:"true"`
	Message         string                     `json:"message,omitempty" example:"No active disclosure grant found"`
	GrantID         string                     `json:"grant_id,omitempty" example:"11111111-1111-1111-1111-111111111111"`
	Scope           *disclosure.Scope          `json:"scope,omitempty"`
	ExpiresAt       string                     `json:"expires_at,omitempty" example:"2026-01-01T00:00:00Z"`
	DisclosureLevel disclosure.DisclosureLevel `json:"disclosure_level,omitempty" example:"pseudonymous"`
}

// DisclosureApproveResponse is the body of POST
// /api/v1/me/disclosure/requests/{request_id}/approve: the newly created grant
// plus a human-readable message. The grant's token hash is never included (the
// disclosure.Grant type omits it from JSON).
type DisclosureApproveResponse struct {
	Grant   *disclosure.Grant `json:"grant"`
	Message string            `json:"message" example:"Access granted. Authorized viewer can access data via their authenticated session."`
}
