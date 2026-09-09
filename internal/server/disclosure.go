package server

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/disclosure"
	"privacy-proxy/internal/rbac"
)

// resolveAdminOrgID is the core "no org_id supplied → which org does
// the caller mean?" decision shared by all disclosure handlers whose
// route does not carry :org_id (list endpoints read org_id from the
// query string; createDisclosureRequest reads it from the JSON body).
// Callers pass the already-extracted explicit value in and a
// caller-facing description of how that value should have been
// supplied — used in the 400 error message so multi-org admins know
// which field to set.
//
// It enforces the explicit-over-implicit API contract: a JWT admin
// gets the fall-back ONLY when there is exactly one valid choice
// across their full-admin and read-only-admin scope; otherwise the
// caller must supply org_id explicitly and we surface a 400 rather
// than silently scoping to one of several.
//
// Returns (orgID, ok). When ok is false the helper has already
// written the response and the caller must return.
//
// Behaviour matrix:
//
//   - Explicit value supplied (any caller) → use it. Cross-org
//     authority is verified separately by the caller via
//     requireTargetInScope / requireFullAdminInScope; this helper
//     only resolves the *value*.
//
//   - JWT admin with exactly 1 distinct org in admin_org_ids ∪
//     admin_readonly_admin_org_ids → use it (single-valid-case
//     fall-back; matches the RD-877 single-real-org pattern on /rpc).
//
//   - JWT admin with 0 or ≥2 distinct admin orgs and no explicit
//     org_id → 400 with a "<field> is required" message. Frontends
//     should pass org_id explicitly from the active org in their
//     session; API clients must always pass it.
//
//   - Super admin / dev mode (auth_method != "jwt_admin") with no
//     explicit org_id → system default org. Preserved for backward
//     compatibility with admin scripts that target the system
//     defaults.
func resolveAdminOrgID(c *gin.Context, explicit, missingFieldDesc string) (string, bool) {
	if explicit != "" {
		return explicit, true
	}

	if c.GetString("auth_method") != "jwt_admin" {
		// Super-admin / dev mode keeps the pre-RD-944 default.
		return "00000000-0000-0000-0000-000000000001", true
	}

	// Build the set of orgs the JWT admin can plausibly target.
	scope := map[string]struct{}{}
	if ids, ok := c.Get("admin_org_ids"); ok {
		if list, ok := ids.([]string); ok {
			for _, id := range list {
				scope[id] = struct{}{}
			}
		}
	}
	if ids, ok := c.Get("admin_readonly_org_ids"); ok {
		if list, ok := ids.([]string); ok {
			for _, id := range list {
				scope[id] = struct{}{}
			}
		}
	}

	if len(scope) != 1 {
		// 0 (no admin scope at all — shouldn't happen given middleware
		// already established jwt_admin authority, but defensive) or
		// 2+ (genuine ambiguity — caller must choose explicitly).
		respondBadRequest(c, missingFieldDesc+" is required")
		return "", false
	}
	for id := range scope {
		return id, true
	}
	// Unreachable — keeps the compiler happy.
	respondBadRequest(c, missingFieldDesc+" is required")
	return "", false
}

// resolveAdminListOrgID wraps resolveAdminOrgID for GET handlers that
// read org_id from the `?org_id=` query string.
func resolveAdminListOrgID(c *gin.Context) (string, bool) {
	return resolveAdminOrgID(c, c.Query("org_id"), "org_id query parameter")
}

// registerDisclosureRoutes registers admin disclosure API endpoints.
//
// SECURITY: These endpoints are protected by localhostOnlyMiddleware (applied in server.go).
// This means only requests from localhost, Docker networks, or Tailscale are allowed.
// The admin UI runs on localhost and is the intended consumer of these APIs.
//
// Authorization model: These are super-admin endpoints that can access all organizations.
// This is intentional for a central admin interface managing multiple orgs.
func (s *Server) registerDisclosureRoutes(api *gin.RouterGroup) {
	disclosureGroup := api.Group("/disclosure")
	{
		// Admin endpoints (for creating requests on behalf of regulators)
		// SECURITY: Protected by localhostOnlyMiddleware - admin-only access
		disclosureGroup.POST("/requests", s.createDisclosureRequest)
		disclosureGroup.GET("/requests", s.listDisclosureRequests)
		disclosureGroup.GET("/requests/:request_id", s.getDisclosureRequest)
		disclosureGroup.DELETE("/requests/:request_id", s.deleteDisclosureRequest)

		// Admin grant management
		// SECURITY: Protected by localhostOnlyMiddleware - admin-only access
		disclosureGroup.GET("/grants", s.listDisclosureGrants)
		disclosureGroup.POST("/grants/:grant_id/revoke", s.adminRevokeDisclosureGrant)

		// Block explorer integration - check if a DID has access to a user's data
		disclosureGroup.GET("/check-access", s.checkDisclosureAccess)

		// Grant access endpoints (require disclosure token)
		disclosureGroup.GET("/grants/:grant_id/logs", s.getDisclosureLogs)
		disclosureGroup.GET("/grants/:grant_id/summary", s.getDisclosureSummary)
		disclosureGroup.GET("/grants/:grant_id/report/:report_type", s.getDisclosureReport)
		disclosureGroup.GET("/grants/:grant_id/events", s.getDisclosureEvents)
	}
}

// registerUserDisclosureRoutes registers user-facing disclosure endpoints (public with JWT auth).
func (s *Server) registerUserDisclosureRoutes(router *gin.Engine) {
	// User-facing endpoints (require JWT auth, accessible from external IPs)
	meDisclosure := router.Group("/api/v1/me/disclosure")
	meDisclosure.Use(auth.JWTAuthMiddleware(s.jwtService, s.db))
	meDisclosure.Use(s.disclosureUserMiddleware())
	{
		meDisclosure.GET("/requests", s.getMyDisclosureRequests)
		meDisclosure.GET("/requests/all", s.getAllMyDisclosureRequests)
		meDisclosure.POST("/requests/:request_id/approve", s.approveDisclosureRequest)
		meDisclosure.POST("/requests/:request_id/reject", s.rejectDisclosureRequest)
		meDisclosure.POST("/requests/:request_id/revoke", s.revokeDisclosureRequest)
		meDisclosure.GET("/grants", s.getMyActiveGrants)
		meDisclosure.GET("/grants/all", s.getAllMyGrants)
	}
}

// disclosureUserMiddleware adds user_id to context from subject (DID)
func (s *Server) disclosureUserMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		subject, exists := c.Get("subject")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing subject in context"})
			c.Abort()
			return
		}

		// Get user from database
		user, err := s.db.GetUserByExternalID(c.Request.Context(), subject.(string))
		if err != nil || user == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
			c.Abort()
			return
		}

		c.Set("user_id", user.ID)
		c.Next()
	}
}

// createDisclosureRequest creates a new disclosure request (admin endpoint).
//
// Audit C3: pre-fix this endpoint trusted org_id and target_user_id
// from the request body without any caller-scope check. A tier-2
// admin of Org A could manufacture a disclosure request for any Org B
// user; once the target approved, the requester saw that user's ETH
// activity globally via getDisclosedAddressesForViewer. Now the
// handler enforces both org_id ∈ caller_scope and target_user_id ∈
// caller_scope.
//
// RD-1011: pre-fix an empty `org_id` in the JSON body silently
// defaulted to the system default org ("00000000-…001"), so a tier-2
// admin of a non-default org whose FE forgot to send org_id either
// got a 403 from requireFullAdminInScope (single-org case) or could
// be silently scoped to the wrong org if they happened to have admin
// rights in the system default org. PR #278 already fixed the FE to
// always send org_id; this is the defensive backend mirror of the
// RD-944 LIST-endpoint rule so a future FE regression fails cleanly:
// single-org JWT admins get their only org picked, multi-org JWT
// admins must specify org_id (400 otherwise), super-admin / dev keeps
// the system-default fall-back for admin scripts.
//
// @Summary      Create a disclosure request
// @Description  Creates a disclosure request on behalf of an authorized viewer (e.g. a regulator) targeting one user's activity. Scoped to the caller's admin authority: org_id must be an org the caller fully administers and target_user_id must share an org with the caller — a request cannot be manufactured for another org's user. org_id may be omitted only when it is unambiguous (single-org JWT admin, or super-admin/dev which defaults to the system org); a multi-org JWT admin must supply it. The created request is pending until the target user approves or rejects it.
// @Tags         Admin: disclosure
// @Accept       json
// @Produce      json
// @Param        request body apimodels.CreateDisclosureRequestBody true "disclosure request (target_user_id and reason required)"
// @Success      201 {object} disclosure.Request
// @Failure      400 {object} apimodels.APIError "invalid body, or org_id required (ambiguous multi-org caller)"
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network, or org_id / target_user_id outside the caller's scope"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/disclosure/requests [post]
func (s *Server) createDisclosureRequest(c *gin.Context) {
	if denyOperatorOrgScoped(c) { // RD-1173: operator token must not mutate tenant disclosure state
		return
	}
	var input struct {
		RequesterUserID string           `json:"requester_user_id"` // Optional - who's requesting (internal user ID)
		RequesterDID    string           `json:"requester_did"`     // DID of authorized viewer (for block explorer auth)
		TargetUserID    string           `json:"target_user_id" binding:"required"`
		OrgID           string           `json:"org_id"` // Optional for super-admin / single-org JWT admin; required for multi-org JWT admin (RD-1011)
		Scope           disclosure.Scope `json:"scope"`
		Reason          string           `json:"reason" binding:"required"`
		LegalBasis      string           `json:"legal_basis"`
		ExpiresInHours  int              `json:"expires_in_hours"` // 0 = no expiration
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		slog.Warn("disclosure: invalid create-request body", "err", err)
		respondBadRequest(c, "invalid request body")
		return
	}

	orgID, ok := resolveAdminOrgID(c, input.OrgID, "org_id")
	if !ok {
		return
	}

	// Cross-org gate. Super-admin / dev: any org. JWT admin: org must
	// be in admin_org_ids (mutating action — read-only not enough).
	if !requireFullAdminInScope(c, orgID) {
		return
	}

	// Target user must share at least one org with the caller. Pre-fix,
	// a tier-2 admin of Org A could manufacture a disclosure request
	// for any Org B user.
	if !s.requireUserInCallerScope(c, input.TargetUserID) {
		return
	}

	var expiresIn *time.Duration
	if input.ExpiresInHours > 0 {
		d := time.Duration(input.ExpiresInHours) * time.Hour
		expiresIn = &d
	}

	req, err := s.disclosureService.CreateRequest(
		c.Request.Context(),
		input.RequesterUserID,
		input.RequesterDID,
		input.TargetUserID,
		orgID,
		input.Scope,
		input.Reason,
		input.LegalBasis,
		expiresIn,
	)
	if err != nil {
		slog.Error("disclosure: create request failed", "err", err, "target_user_id", input.TargetUserID, "org_id", orgID)
		respondInternalError(c, "failed to create disclosure request")
		return
	}

	s.recordAuditActionScoped(c, rbac.AuditActionCreate, rbac.ResourceTypeDisclosureRequest, req.ID, input.Reason, orgID,
		nil,
		map[string]any{
			"target_user_id": input.TargetUserID,
			"requester_did":  input.RequesterDID,
			"scope":          input.Scope,
		})

	c.JSON(http.StatusCreated, req)
}

// listDisclosureRequests lists disclosure requests with filtering support.
//
// Audit C3: pre-fix the ?org_id= query was honoured without scope
// check, leaking any org's request list to any tier-2 admin. Now
// clamped to caller's org_id set.
//
// RD-944: when no `org_id` is supplied, JWT admins fall back to their
// own admin scope ONLY when there's exactly one valid choice — single
// admin org → use it; zero or 2+ admin orgs → 400 require explicit
// `org_id`. The previous behaviour ("default to admin_org_ids[0]")
// silently scoped multi-org admins to the first of their orgs without
// surfacing the ambiguity, which violates the explicit-over-implicit
// principle on the API surface. The dashboard frontend now passes
// `org_id` explicitly so it never hits the multi-org reject branch.
// Super-admin / dev mode keeps the system-default fallback for
// backward compatibility with admin scripts.
//
// @Summary      List disclosure requests
// @Description  Lists disclosure requests, filtered and clamped to the caller's org scope: the org_id filter must be within the caller's admin scope, so a caller only ever sees requests for orgs they administer. When org_id is omitted it falls back to the caller's single admin org (super-admin/dev defaults to the system org); a multi-org JWT admin must supply org_id. Additional filters narrow the result set.
// @Tags         Admin: disclosure
// @Produce      json
// @Param        org_id query string false "Organization to list requests for; required for multi-org JWT admins"
// @Param        status query string false "Filter by request status" Enums(pending, approved, rejected, expired, revoked)
// @Param        target_user_id query string false "Filter by the user whose data is targeted"
// @Param        requester_did query string false "Filter by the requester DID"
// @Param        disclosure_level query string false "Filter by disclosure level" Enums(full, pseudonymous, redacted)
// @Param        date_from query string false "Only requests created on or after this RFC3339 timestamp"
// @Param        date_to query string false "Only requests created on or before this RFC3339 timestamp"
// @Param        limit query int false "Maximum number of results"
// @Param        offset query int false "Number of results to skip"
// @Success      200 {object} disclosure.DisclosureListResult
// @Failure      400 {object} apimodels.APIError "org_id required (ambiguous multi-org caller)"
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network, or org_id outside the caller's scope"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/disclosure/requests [get]
func (s *Server) listDisclosureRequests(c *gin.Context) {
	if denyOperatorTenantRead(c) { // RD-1173: operator token must not read tenant disclosure data
		return
	}
	filter := &disclosure.DisclosureFilter{}

	orgID, ok := resolveAdminListOrgID(c)
	if !ok {
		return
	}
	filter.OrgID = orgID

	// Cross-org gate: the requested org must be in caller's scope.
	if !requireTargetInScope(c, filter.OrgID) {
		return
	}

	// Parse status
	if statusStr := c.Query("status"); statusStr != "" {
		st := disclosure.RequestStatus(statusStr)
		filter.Status = &st
	}

	// Parse target_user_id
	if targetUserID := c.Query("target_user_id"); targetUserID != "" {
		filter.TargetUserID = targetUserID
	}

	// Parse requester_did
	if requesterDID := c.Query("requester_did"); requesterDID != "" {
		filter.RequesterDID = requesterDID
	}

	// Parse disclosure_level
	if levelStr := c.Query("disclosure_level"); levelStr != "" {
		level := disclosure.DisclosureLevel(levelStr)
		filter.DisclosureLevel = &level
	}

	// Parse date_from
	if dateFromStr := c.Query("date_from"); dateFromStr != "" {
		dateFrom, err := time.Parse(time.RFC3339, dateFromStr)
		if err == nil {
			filter.DateFrom = &dateFrom
		}
	}

	// Parse date_to
	if dateToStr := c.Query("date_to"); dateToStr != "" {
		dateTo, err := time.Parse(time.RFC3339, dateToStr)
		if err == nil {
			filter.DateTo = &dateTo
		}
	}

	// Parse limit
	if limitStr := c.Query("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 {
			filter.Limit = limit
		}
	}

	// Parse offset
	if offsetStr := c.Query("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil && offset >= 0 {
			filter.Offset = offset
		}
	}

	result, err := s.disclosureService.ListRequestsWithFilter(c.Request.Context(), filter)
	if err != nil {
		slog.Error("disclosure: list requests failed", "err", err, "org_id", filter.OrgID)
		respondInternalError(c, "failed to list disclosure requests")
		return
	}

	c.JSON(http.StatusOK, result)
}

// listDisclosureGrants lists disclosure grants with filtering support (admin endpoint).
// Audit C3 — same fix as listDisclosureRequests.
//
// RD-944: shares resolveAdminListOrgID with listDisclosureRequests so
// both endpoints answer the same way to "no org_id supplied" — fall
// back ONLY when the caller has exactly one admin scope, otherwise 400.
// Multi-org admins must pass `org_id` explicitly; silently picking
// `admin_org_ids[0]` was the pre-fix behaviour and violated the
// explicit-over-implicit principle on the API surface.
//
// @Summary      List disclosure grants
// @Description  Lists disclosure grants (approved requests with an access token), filtered and clamped to the caller's org scope so a caller only sees grants for orgs they administer. When org_id is omitted it falls back to the caller's single admin org (super-admin/dev defaults to the system org); a multi-org JWT admin must supply org_id. Grant token hashes are never included in the response.
// @Tags         Admin: disclosure
// @Produce      json
// @Param        org_id query string false "Organization to list grants for; required for multi-org JWT admins"
// @Param        status query string false "Filter by grant status" Enums(approved, revoked, expired)
// @Param        target_user_id query string false "Filter by the user whose data is targeted"
// @Param        requester_did query string false "Filter by the requester DID"
// @Param        disclosure_level query string false "Filter by disclosure level" Enums(full, pseudonymous, redacted)
// @Param        date_from query string false "Only grants created on or after this RFC3339 timestamp"
// @Param        date_to query string false "Only grants created on or before this RFC3339 timestamp"
// @Param        limit query int false "Maximum number of results"
// @Param        offset query int false "Number of results to skip"
// @Success      200 {object} disclosure.GrantListResult
// @Failure      400 {object} apimodels.APIError "org_id required (ambiguous multi-org caller)"
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network, or org_id outside the caller's scope"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/disclosure/grants [get]
func (s *Server) listDisclosureGrants(c *gin.Context) {
	if denyOperatorTenantRead(c) { // RD-1173: operator token must not read tenant disclosure data
		return
	}
	filter := &disclosure.DisclosureFilter{}

	orgID, ok := resolveAdminListOrgID(c)
	if !ok {
		return
	}
	filter.OrgID = orgID

	// Cross-org gate.
	if filter.OrgID != "" && !requireTargetInScope(c, filter.OrgID) {
		return
	}

	// Parse status (for grants: approved = active, revoked, expired)
	if statusStr := c.Query("status"); statusStr != "" {
		st := disclosure.RequestStatus(statusStr)
		filter.Status = &st
	}

	// Parse target_user_id
	if targetUserID := c.Query("target_user_id"); targetUserID != "" {
		filter.TargetUserID = targetUserID
	}

	// Parse requester_did
	if requesterDID := c.Query("requester_did"); requesterDID != "" {
		filter.RequesterDID = requesterDID
	}

	// Parse disclosure_level
	if levelStr := c.Query("disclosure_level"); levelStr != "" {
		level := disclosure.DisclosureLevel(levelStr)
		filter.DisclosureLevel = &level
	}

	// Parse date_from
	if dateFromStr := c.Query("date_from"); dateFromStr != "" {
		dateFrom, err := time.Parse(time.RFC3339, dateFromStr)
		if err == nil {
			filter.DateFrom = &dateFrom
		}
	}

	// Parse date_to
	if dateToStr := c.Query("date_to"); dateToStr != "" {
		dateTo, err := time.Parse(time.RFC3339, dateToStr)
		if err == nil {
			filter.DateTo = &dateTo
		}
	}

	// Parse limit
	if limitStr := c.Query("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 {
			filter.Limit = limit
		}
	}

	// Parse offset
	if offsetStr := c.Query("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil && offset >= 0 {
			filter.Offset = offset
		}
	}

	result, err := s.disclosureService.ListGrantsWithFilter(c.Request.Context(), filter)
	if err != nil {
		slog.Error("disclosure: list grants failed", "err", err, "org_id", filter.OrgID)
		respondInternalError(c, "failed to list disclosure grants")
		return
	}

	c.JSON(http.StatusOK, result)
}

// deleteDisclosureRequest deletes a pending disclosure request (admin endpoint).
// Audit C3: re-verify the loaded request's org is in caller's scope.
//
// @Summary      Delete a pending disclosure request
// @Description  Deletes a disclosure request that is still pending. Only requests in an org the caller fully administers can be deleted; a request outside the caller's scope, or one that does not exist, returns a generic 403 (no existence oracle). Only pending requests are deletable — an already-decided request returns 400.
// @Tags         Admin: disclosure
// @Produce      json
// @Param        request_id path string true "Disclosure request ID"
// @Success      200 {object} apimodels.DisclosureStatusResponse "status: deleted"
// @Failure      400 {object} apimodels.APIError "request is not pending"
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network, or request not found / outside the caller's scope"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/disclosure/requests/{request_id} [delete]
func (s *Server) deleteDisclosureRequest(c *gin.Context) {
	if denyOperatorOrgScoped(c) { // RD-1173: operator token must not mutate tenant disclosure state
		return
	}
	requestID := c.Param("request_id")

	// Load the request to find its org before any mutation.
	reqDetails, err := s.db.GetDisclosureRequestWithDetails(c.Request.Context(), requestID)
	if err != nil {
		slog.Error("disclosure: delete pre-load failed", "err", err, "request_id", requestID)
		respondInternalError(c, "failed to retrieve disclosure request")
		return
	}
	if reqDetails == nil || reqDetails.Request == nil {
		// Generic 403 to avoid existence oracle.
		respondForbidden(c, errTargetForeignOrg)
		return
	}
	if !requireFullAdminInScope(c, reqDetails.Request.OrgID) {
		return
	}

	err = s.disclosureService.DeletePendingRequest(c.Request.Context(), requestID)
	if err != nil {
		if err == disclosure.ErrRequestNotFound {
			respondForbidden(c, errTargetForeignOrg)
			return
		}
		if err == disclosure.ErrRequestNotPending {
			respondBadRequest(c, "can only delete pending requests")
			return
		}
		slog.Error("disclosure: delete request failed", "err", err, "request_id", requestID)
		respondInternalError(c, "failed to delete disclosure request")
		return
	}

	s.recordAuditActionScoped(c, rbac.AuditActionDelete, rbac.ResourceTypeDisclosureRequest, reqDetails.Request.ID, reqDetails.Request.Reason, reqDetails.Request.OrgID,
		map[string]any{"target_user_id": reqDetails.Request.TargetUserID, "requester_did": reqDetails.Request.RequesterDID, "status": reqDetails.Request.Status},
		nil)

	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// adminRevokeDisclosureGrant revokes a disclosure grant (admin endpoint).
// Audit C3: verify the loaded grant belongs to an org in caller's scope.
//
// @Summary      Revoke a disclosure grant (admin)
// @Description  Revokes an active disclosure grant, immediately ending the authorized viewer's access. Only grants whose owning org the caller fully administers can be revoked; a grant outside the caller's scope, or one that does not exist, returns a generic 403 (no existence oracle). The request body is optional and carries only a free-text revocation reason.
// @Tags         Admin: disclosure
// @Accept       json
// @Produce      json
// @Param        grant_id path string true "Disclosure grant ID"
// @Param        request body apimodels.DisclosureReasonBody false "optional revocation reason"
// @Success      200 {object} apimodels.DisclosureStatusResponse "status: revoked"
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network, or grant not found / outside the caller's scope"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/disclosure/grants/{grant_id}/revoke [post]
func (s *Server) adminRevokeDisclosureGrant(c *gin.Context) {
	if denyOperatorOrgScoped(c) { // RD-1173: operator token must not mutate tenant disclosure state
		return
	}
	grantID := c.Param("grant_id")

	// Load grant to find owning org via its parent request.
	grantWithReq, err := s.db.GetDisclosureGrantWithRequest(c.Request.Context(), grantID)
	if err != nil {
		slog.Error("disclosure: revoke pre-load failed", "err", err, "grant_id", grantID)
		respondInternalError(c, "failed to retrieve disclosure grant")
		return
	}
	if grantWithReq == nil || grantWithReq.Request == nil {
		respondForbidden(c, errTargetForeignOrg)
		return
	}
	if !requireFullAdminInScope(c, grantWithReq.Request.OrgID) {
		return
	}

	var input struct {
		Reason string `json:"reason"`
	}

	// Allow empty body - reason is optional
	_ = c.ShouldBindJSON(&input)

	if err := s.disclosureService.RevokeGrant(c.Request.Context(), grantID, input.Reason); err != nil {
		if err == disclosure.ErrGrantNotFound {
			respondForbidden(c, errTargetForeignOrg)
			return
		}
		slog.Error("disclosure: revoke grant failed", "err", err, "grant_id", grantID)
		respondInternalError(c, "failed to revoke disclosure grant")
		return
	}

	s.recordAuditActionScoped(c, rbac.AuditActionRevoke, rbac.ResourceTypeDisclosureGrant, grantID, input.Reason, grantWithReq.Request.OrgID,
		map[string]any{"request_id": grantWithReq.Request.ID, "requester_did": grantWithReq.Request.RequesterDID},
		nil)

	c.JSON(http.StatusOK, gin.H{"status": "revoked"})
}

// getDisclosureRequest gets a disclosure request by ID.
// Audit C3: verify request's org is in caller's scope.
//
// @Summary      Get a disclosure request
// @Description  Returns a single disclosure request with related details (requester/target DIDs, any active grant ID). Readable only when the request's org is within the caller's admin scope; a request outside the caller's scope, or one that does not exist, returns a generic 403 (no existence oracle).
// @Tags         Admin: disclosure
// @Produce      json
// @Param        request_id path string true "Disclosure request ID"
// @Success      200 {object} disclosure.RequestWithDetails
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network, or request not found / outside the caller's scope"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/disclosure/requests/{request_id} [get]
func (s *Server) getDisclosureRequest(c *gin.Context) {
	if denyOperatorTenantRead(c) { // RD-1173: operator token must not read tenant disclosure data
		return
	}
	requestID := c.Param("request_id")

	reqDetails, err := s.db.GetDisclosureRequestWithDetails(c.Request.Context(), requestID)
	if err != nil {
		slog.Error("disclosure: get request failed", "err", err, "request_id", requestID)
		respondInternalError(c, "failed to retrieve disclosure request")
		return
	}
	if reqDetails == nil || reqDetails.Request == nil {
		respondForbidden(c, errTargetForeignOrg)
		return
	}
	if !requireTargetInScope(c, reqDetails.Request.OrgID) {
		return
	}

	c.JSON(http.StatusOK, reqDetails)
}

// checkDisclosureAccess checks if a requester DID has access to a target user's data.
// This is used by the block explorer to verify auditor permissions.
// GET /api/disclosure/check-access?requester_did=did:...&target_user_did=did:...
//
// @Summary      Check disclosure access for a DID pair
// @Description  Reports whether the requester DID currently holds an active, non-expired disclosure grant over the target user's data. Used by the block explorer to authorize a viewer. Fail-closed: when no active grant exists the response is 200 with has_access=false (not an error), and when a grant exists the response includes the grant ID, scope, disclosure level, and expiry so the caller can enforce it.
// @Tags         Admin: disclosure
// @Produce      json
// @Param        requester_did query string true "DID of the viewer whose access is being checked"
// @Param        target_user_did query string true "DID of the user whose data would be viewed"
// @Success      200 {object} apimodels.DisclosureCheckAccessResponse
// @Failure      400 {object} apimodels.APIError "requester_did and target_user_did are required"
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/disclosure/check-access [get]
func (s *Server) checkDisclosureAccess(c *gin.Context) {
	if denyOperatorTenantRead(c) { // RD-1173: operator token must not probe tenant disclosure relationships
		return
	}
	requesterDID := c.Query("requester_did")
	targetUserDID := c.Query("target_user_did")

	if requesterDID == "" || targetUserDID == "" {
		respondBadRequest(c, "requester_did and target_user_did are required")
		return
	}

	// Check if there's an active grant for this requester DID and target user
	grantWithReq, err := s.db.GetActiveGrantByRequesterDID(c.Request.Context(), requesterDID, targetUserDID)
	if err != nil {
		slog.Error("disclosure: check-access lookup failed", "err", err)
		respondInternalError(c, "failed to check disclosure access")
		return
	}

	// RD-1180: a jwt_admin (tier-2) must not learn whether a disclosure grant
	// exists over ANOTHER org's user. The lookup is global by DID pair, and the
	// success body leaks grant ID / scope / level / expiry, so without a scope
	// clamp this endpoint is a cross-org relationship oracle. When a grant exists
	// but its org is outside the caller's scope, collapse to the SAME opaque
	// "no active grant" body as the not-found case so the two are indistinguishable.
	// inScope bypasses for super-admin (admin_token) and dev; the operator token
	// is blocked upstream by denyOperatorTenantRead.
	if grantWithReq != nil && !inScope(c, grantWithReq.Request.OrgID) {
		grantWithReq = nil
	}

	if grantWithReq == nil {
		c.JSON(http.StatusOK, gin.H{
			"has_access": false,
			"message":    "No active disclosure grant found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"has_access":       true,
		"grant_id":         grantWithReq.Grant.ID,
		"scope":            grantWithReq.Grant.Scope,
		"expires_at":       grantWithReq.Grant.ExpiresAt,
		"disclosure_level": grantWithReq.Grant.Scope.DisclosureLevel,
	})
}

// getMyDisclosureRequests gets pending disclosure requests for the authenticated user
//
// @Summary      List my pending disclosure requests
// @Description  Lists disclosure requests that are pending the authenticated user's decision — i.e. requests targeting the caller's own data. Scoped to the caller: a user only ever sees requests for their own data.
// @Tags         Disclosure (user)
// @Produce      json
// @Success      200 {array} disclosure.RequestWithDetails
// @Failure      401 {object} apimodels.APIError "missing or invalid token, or no matching user"
// @Failure      500 {object} apimodels.APIError
// @Security     BearerAuth
// @Router       /api/v1/me/disclosure/requests [get]
func (s *Server) getMyDisclosureRequests(c *gin.Context) {
	userID, _ := c.Get("user_id")

	requests, err := s.disclosureService.GetMyPendingRequests(c.Request.Context(), userID.(string))
	if err != nil {
		slog.Error("disclosure: list pending requests failed", "err", err, "user_id", userID)
		respondInternalError(c, "failed to retrieve disclosure requests")
		return
	}

	c.JSON(http.StatusOK, requests)
}

// getAllMyDisclosureRequests gets all disclosure requests for the authenticated user (not just pending)
//
// @Summary      List all my disclosure requests
// @Description  Lists every disclosure request targeting the authenticated user's data, in any status (pending, approved, rejected, expired, revoked). Scoped to the caller: a user only ever sees requests for their own data.
// @Tags         Disclosure (user)
// @Produce      json
// @Success      200 {array} disclosure.RequestWithDetails
// @Failure      401 {object} apimodels.APIError "missing or invalid token, or no matching user"
// @Failure      500 {object} apimodels.APIError
// @Security     BearerAuth
// @Router       /api/v1/me/disclosure/requests/all [get]
func (s *Server) getAllMyDisclosureRequests(c *gin.Context) {
	userID, _ := c.Get("user_id")

	requests, err := s.disclosureService.GetAllMyRequests(c.Request.Context(), userID.(string))
	if err != nil {
		slog.Error("disclosure: list all my requests failed", "err", err, "user_id", userID)
		respondInternalError(c, "failed to retrieve disclosure requests")
		return
	}

	c.JSON(http.StatusOK, requests)
}

// approveDisclosureRequest approves a disclosure request
//
// @Summary      Approve a disclosure request
// @Description  Approves a pending disclosure request that targets the caller's own data, minting an access grant for the requester. A user can only approve requests targeting their own data (otherwise 403). The optional body may narrow (never widen) the granted scope and set the grant duration (defaults to 24 hours). The response returns the new grant without its token hash.
// @Tags         Disclosure (user)
// @Accept       json
// @Produce      json
// @Param        request_id path string true "Disclosure request ID"
// @Param        request body apimodels.ApproveDisclosureRequestBody false "optional scope narrowing, grant duration, and reason"
// @Success      200 {object} apimodels.DisclosureApproveResponse
// @Failure      400 {object} apimodels.APIError "request cannot be approved (e.g. not pending or expired)"
// @Failure      401 {object} apimodels.APIError "missing or invalid token, or no matching user"
// @Failure      403 {object} apimodels.APIError "request does not target the caller's data"
// @Failure      404 {object} apimodels.APIError "request not found"
// @Failure      500 {object} apimodels.APIError
// @Security     BearerAuth
// @Router       /api/v1/me/disclosure/requests/{request_id}/approve [post]
func (s *Server) approveDisclosureRequest(c *gin.Context) {
	requestID := c.Param("request_id")
	userID, _ := c.Get("user_id")

	var input struct {
		Scope              *disclosure.Scope `json:"scope"` // Optional - narrow the scope
		GrantDurationHours int               `json:"grant_duration_hours"`
		Reason             string            `json:"reason"`
	}

	// Allow empty body - all fields are optional
	_ = c.ShouldBindJSON(&input)

	// Default grant duration: 24 hours
	grantDuration := 24 * time.Hour
	if input.GrantDurationHours > 0 {
		grantDuration = time.Duration(input.GrantDurationHours) * time.Hour
	}

	// Verify user is the target of the request
	req, err := s.db.GetDisclosureRequest(c.Request.Context(), requestID)
	if err != nil {
		slog.Error("disclosure: approve lookup failed", "err", err, "request_id", requestID)
		respondInternalError(c, "failed to retrieve disclosure request")
		return
	}
	if req == nil {
		respondNotFound(c, "request not found")
		return
	}
	if req.TargetUserID != userID.(string) {
		respondForbidden(c, "you can only approve requests targeting your own data")
		return
	}

	grant, err := s.disclosureService.ApproveRequest(
		c.Request.Context(),
		requestID,
		userID.(string),
		input.Scope,
		grantDuration,
		input.Reason,
	)
	if err != nil {
		slog.Warn("disclosure: approve request failed", "err", err, "request_id", requestID)
		respondBadRequest(c, "failed to approve disclosure request")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"grant":   grant,
		"message": "Access granted. Authorized viewer can access data via their authenticated session.",
	})
}

// rejectDisclosureRequest rejects a disclosure request
//
// @Summary      Reject a disclosure request
// @Description  Rejects a pending disclosure request that targets the caller's own data; no grant is created. A user can only reject requests targeting their own data (otherwise 403). The request body is optional and carries only a free-text reason.
// @Tags         Disclosure (user)
// @Accept       json
// @Produce      json
// @Param        request_id path string true "Disclosure request ID"
// @Param        request body apimodels.DisclosureReasonBody false "optional rejection reason"
// @Success      200 {object} apimodels.DisclosureStatusResponse "status: rejected"
// @Failure      400 {object} apimodels.APIError "request cannot be rejected (e.g. not pending)"
// @Failure      401 {object} apimodels.APIError "missing or invalid token, or no matching user"
// @Failure      403 {object} apimodels.APIError "request does not target the caller's data"
// @Failure      404 {object} apimodels.APIError "request not found"
// @Failure      500 {object} apimodels.APIError
// @Security     BearerAuth
// @Router       /api/v1/me/disclosure/requests/{request_id}/reject [post]
func (s *Server) rejectDisclosureRequest(c *gin.Context) {
	requestID := c.Param("request_id")
	userID, _ := c.Get("user_id")

	var input struct {
		Reason string `json:"reason"`
	}

	// Allow empty body - reason is optional
	_ = c.ShouldBindJSON(&input)

	// Verify user is the target of the request
	req, err := s.db.GetDisclosureRequest(c.Request.Context(), requestID)
	if err != nil {
		slog.Error("disclosure: reject lookup failed", "err", err, "request_id", requestID)
		respondInternalError(c, "failed to retrieve disclosure request")
		return
	}
	if req == nil {
		respondNotFound(c, "request not found")
		return
	}
	if req.TargetUserID != userID.(string) {
		respondForbidden(c, "you can only reject requests targeting your own data")
		return
	}

	if err := s.disclosureService.RejectRequest(c.Request.Context(), requestID, userID.(string), input.Reason); err != nil {
		slog.Warn("disclosure: reject request failed", "err", err, "request_id", requestID)
		respondBadRequest(c, "failed to reject disclosure request")
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "rejected"})
}

// revokeDisclosureRequest revokes a previously approved disclosure request
//
// @Summary      Revoke a disclosure request (user)
// @Description  Revokes a disclosure request the caller previously approved, ending the requester's access to the caller's data. A user can only revoke requests targeting their own data (otherwise 403). The request body is optional and carries only a free-text reason.
// @Tags         Disclosure (user)
// @Accept       json
// @Produce      json
// @Param        request_id path string true "Disclosure request ID"
// @Param        request body apimodels.DisclosureReasonBody false "optional revocation reason"
// @Success      200 {object} apimodels.DisclosureStatusResponse "status: revoked"
// @Failure      400 {object} apimodels.APIError "request cannot be revoked (e.g. not currently approved)"
// @Failure      401 {object} apimodels.APIError "missing or invalid token, or no matching user"
// @Failure      403 {object} apimodels.APIError "request does not target the caller's data"
// @Failure      404 {object} apimodels.APIError "request not found"
// @Failure      500 {object} apimodels.APIError
// @Security     BearerAuth
// @Router       /api/v1/me/disclosure/requests/{request_id}/revoke [post]
func (s *Server) revokeDisclosureRequest(c *gin.Context) {
	requestID := c.Param("request_id")
	userID, _ := c.Get("user_id")

	var input struct {
		Reason string `json:"reason"`
	}

	// Allow empty body - reason is optional
	_ = c.ShouldBindJSON(&input)

	// Verify user is the target of the request
	req, err := s.db.GetDisclosureRequest(c.Request.Context(), requestID)
	if err != nil {
		slog.Error("disclosure: revoke lookup failed", "err", err, "request_id", requestID)
		respondInternalError(c, "failed to retrieve disclosure request")
		return
	}
	if req == nil {
		respondNotFound(c, "request not found")
		return
	}
	if req.TargetUserID != userID.(string) {
		respondForbidden(c, "you can only revoke requests targeting your own data")
		return
	}

	if err := s.disclosureService.RevokeRequest(c.Request.Context(), requestID, userID.(string), input.Reason); err != nil {
		slog.Warn("disclosure: revoke request failed", "err", err, "request_id", requestID)
		respondBadRequest(c, "failed to revoke disclosure request")
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "revoked"})
}

// getMyActiveGrants gets active disclosure grants for the authenticated user's data
//
// @Summary      List my active disclosure grants
// @Description  Lists disclosure grants over the authenticated user's data that are currently active (approved, not expired, not revoked) — i.e. who can see the caller's data right now. Scoped to the caller: a user only ever sees grants over their own data. Grant token hashes are never included.
// @Tags         Disclosure (user)
// @Produce      json
// @Success      200 {array} disclosure.GrantWithRequest
// @Failure      401 {object} apimodels.APIError "missing or invalid token, or no matching user"
// @Failure      500 {object} apimodels.APIError
// @Security     BearerAuth
// @Router       /api/v1/me/disclosure/grants [get]
func (s *Server) getMyActiveGrants(c *gin.Context) {
	userID, _ := c.Get("user_id")

	grants, err := s.disclosureService.GetMyActiveGrants(c.Request.Context(), userID.(string))
	if err != nil {
		slog.Error("disclosure: list active grants failed", "err", err, "user_id", userID)
		respondInternalError(c, "failed to retrieve disclosure grants")
		return
	}

	c.JSON(http.StatusOK, grants)
}

// getAllMyGrants gets all disclosure grants for the authenticated user's data (not just active)
//
// @Summary      List all my disclosure grants
// @Description  Lists every disclosure grant over the authenticated user's data, in any state (active, expired, or revoked) — the full access history. Scoped to the caller: a user only ever sees grants over their own data. Grant token hashes are never included.
// @Tags         Disclosure (user)
// @Produce      json
// @Success      200 {array} disclosure.GrantWithRequest
// @Failure      401 {object} apimodels.APIError "missing or invalid token, or no matching user"
// @Failure      500 {object} apimodels.APIError
// @Security     BearerAuth
// @Router       /api/v1/me/disclosure/grants/all [get]
func (s *Server) getAllMyGrants(c *gin.Context) {
	userID, _ := c.Get("user_id")

	grants, err := s.disclosureService.GetAllMyGrants(c.Request.Context(), userID.(string))
	if err != nil {
		slog.Error("disclosure: list all my grants failed", "err", err, "user_id", userID)
		respondInternalError(c, "failed to retrieve disclosure grants")
		return
	}

	c.JSON(http.StatusOK, grants)
}

// disclosureTokenMiddleware validates disclosure token from header or query param
func (s *Server) validateDisclosureToken(c *gin.Context) (*disclosure.GrantWithRequest, error) {
	// Check header first
	token := c.GetHeader("X-Disclosure-Token")
	if token == "" {
		// Fall back to query param
		token = c.Query("token")
	}

	if token == "" {
		return nil, disclosure.ErrInvalidToken
	}

	return s.disclosureService.ValidateGrantToken(c.Request.Context(), token)
}

// getDisclosureLogs gets activity logs via disclosure grant
//
// @Summary      Get activity logs for a grant
// @Description  Returns the target user's RPC activity log entries authorized by a disclosure grant. Requires a valid grant token (X-Disclosure-Token header or token query parameter) that must belong to the grant named in the path — a token for a different grant is rejected (403). Results are bounded to the grant's scope and time window; each access is itself recorded as a disclosure event.
// @Tags         Admin: disclosure
// @Produce      json
// @Param        grant_id path string true "Disclosure grant ID"
// @Param        X-Disclosure-Token header string false "Grant access token (or pass as the token query parameter)"
// @Param        token query string false "Grant access token (alternative to the X-Disclosure-Token header)"
// @Param        limit query int false "Max rows to return (1-1000)" default(100)
// @Param        offset query int false "Rows to skip (pagination)" default(0)
// @Success      200 {array} disclosure.ActivityLogEntry
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token, or invalid/absent disclosure token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network, or token does not match the grant"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/disclosure/grants/{grant_id}/logs [get]
func (s *Server) getDisclosureLogs(c *gin.Context) {
	grantID := c.Param("grant_id")

	grantWithReq, err := s.validateDisclosureToken(c)
	if err != nil {
		slog.Warn("disclosure: token validation failed (logs)", "err", err, "grant_id", grantID)
		respondUnauthorized(c, "invalid disclosure token")
		return
	}

	if grantWithReq.Grant.ID != grantID {
		respondForbidden(c, "token does not match grant")
		return
	}

	limit := 100
	offset := 0
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}
	if o := c.Query("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	viewerIP := c.ClientIP()
	viewerUserID := ""
	if uid, exists := c.Get("user_id"); exists {
		viewerUserID = uid.(string)
	}

	logs, err := s.disclosureService.GetActivityLogs(c.Request.Context(), grantID, viewerUserID, viewerIP, limit, offset)
	if err != nil {
		slog.Error("disclosure: get activity logs failed", "err", err, "grant_id", grantID)
		respondInternalError(c, "failed to retrieve disclosure logs")
		return
	}

	c.JSON(http.StatusOK, logs)
}

// getDisclosureSummary gets activity summary via disclosure grant
//
// @Summary      Get activity summary for a grant
// @Description  Returns aggregated activity statistics (request counts, per-method breakdown, date range) for the target user's activity authorized by a disclosure grant. Requires a valid grant token (X-Disclosure-Token header or token query parameter) that must belong to the grant named in the path — a token for a different grant is rejected (403). The access is recorded as a disclosure event.
// @Tags         Admin: disclosure
// @Produce      json
// @Param        grant_id path string true "Disclosure grant ID"
// @Param        X-Disclosure-Token header string false "Grant access token (or pass as the token query parameter)"
// @Param        token query string false "Grant access token (alternative to the X-Disclosure-Token header)"
// @Success      200 {object} disclosure.ActivitySummary
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token, or invalid/absent disclosure token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network, or token does not match the grant"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/disclosure/grants/{grant_id}/summary [get]
func (s *Server) getDisclosureSummary(c *gin.Context) {
	grantID := c.Param("grant_id")

	grantWithReq, err := s.validateDisclosureToken(c)
	if err != nil {
		slog.Warn("disclosure: token validation failed (summary)", "err", err, "grant_id", grantID)
		respondUnauthorized(c, "invalid disclosure token")
		return
	}

	if grantWithReq.Grant.ID != grantID {
		respondForbidden(c, "token does not match grant")
		return
	}

	viewerIP := c.ClientIP()
	viewerUserID := ""
	if uid, exists := c.Get("user_id"); exists {
		viewerUserID = uid.(string)
	}

	summary, err := s.disclosureService.GetActivitySummary(c.Request.Context(), grantID, viewerUserID, viewerIP)
	if err != nil {
		slog.Error("disclosure: get activity summary failed", "err", err, "grant_id", grantID)
		respondInternalError(c, "failed to retrieve disclosure summary")
		return
	}

	c.JSON(http.StatusOK, summary)
}

// getDisclosureReport gets or generates a compliance report via disclosure grant
//
// @Summary      Generate a compliance report for a grant
// @Description  Generates (or returns) a compliance report of the given type over the target user's activity authorized by a disclosure grant. Requires a valid grant token (X-Disclosure-Token header or token query parameter) that must belong to the grant named in the path — a token for a different grant is rejected (403). The report_type must be one of the supported values; the access is recorded as a disclosure event.
// @Tags         Admin: disclosure
// @Produce      json
// @Param        grant_id path string true "Disclosure grant ID"
// @Param        report_type path string true "Report type to generate" Enums(activity_summary, sanctions_check, compliance_report)
// @Param        X-Disclosure-Token header string false "Grant access token (or pass as the token query parameter)"
// @Param        token query string false "Grant access token (alternative to the X-Disclosure-Token header)"
// @Success      200 {object} disclosure.Report
// @Failure      400 {object} apimodels.APIError "invalid report type"
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token, or invalid/absent disclosure token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network, or token does not match the grant"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/disclosure/grants/{grant_id}/report/{report_type} [get]
func (s *Server) getDisclosureReport(c *gin.Context) {
	grantID := c.Param("grant_id")
	reportTypeStr := c.Param("report_type")

	grantWithReq, err := s.validateDisclosureToken(c)
	if err != nil {
		slog.Warn("disclosure: token validation failed (report)", "err", err, "grant_id", grantID)
		respondUnauthorized(c, "invalid disclosure token")
		return
	}

	if grantWithReq.Grant.ID != grantID {
		respondForbidden(c, "token does not match grant")
		return
	}

	reportType := disclosure.ReportType(reportTypeStr)
	switch reportType {
	case disclosure.ReportActivitySummary, disclosure.ReportSanctionsCheck, disclosure.ReportCompliance:
		// Valid report type
	default:
		respondBadRequest(c, "invalid report type")
		return
	}

	viewerIP := c.ClientIP()
	viewerUserID := ""
	if uid, exists := c.Get("user_id"); exists {
		viewerUserID = uid.(string)
	}

	report, err := s.disclosureService.GenerateComplianceReport(c.Request.Context(), grantID, viewerUserID, viewerIP, reportType)
	if err != nil {
		slog.Error("disclosure: generate compliance report failed", "err", err, "grant_id", grantID, "report_type", reportTypeStr)
		respondInternalError(c, "failed to generate disclosure report")
		return
	}

	c.JSON(http.StatusOK, report)
}

// getDisclosureEvents gets disclosure access events for a grant
//
// @Summary      Get access events for a grant
// @Description  Returns the disclosure access audit trail for a grant — each event records when the grant's data was viewed, by whom, and what resource was accessed. Requires a valid grant token (X-Disclosure-Token header or token query parameter) that must belong to the grant named in the path — a token for a different grant is rejected (403).
// @Tags         Admin: disclosure
// @Produce      json
// @Param        grant_id path string true "Disclosure grant ID"
// @Param        X-Disclosure-Token header string false "Grant access token (or pass as the token query parameter)"
// @Param        token query string false "Grant access token (alternative to the X-Disclosure-Token header)"
// @Param        limit query int false "Max rows to return (1-1000)" default(100)
// @Param        offset query int false "Rows to skip (pagination)" default(0)
// @Success      200 {array} disclosure.Event
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token, or invalid/absent disclosure token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network, or token does not match the grant"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/disclosure/grants/{grant_id}/events [get]
func (s *Server) getDisclosureEvents(c *gin.Context) {
	grantID := c.Param("grant_id")

	grantWithReq, err := s.validateDisclosureToken(c)
	if err != nil {
		slog.Warn("disclosure: token validation failed (events)", "err", err, "grant_id", grantID)
		respondUnauthorized(c, "invalid disclosure token")
		return
	}

	if grantWithReq.Grant.ID != grantID {
		respondForbidden(c, "token does not match grant")
		return
	}

	limit := 100
	offset := 0
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}
	if o := c.Query("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	events, err := s.db.ListDisclosureEventsByGrant(c.Request.Context(), grantID, limit, offset)
	if err != nil {
		slog.Error("disclosure: list events failed", "err", err, "grant_id", grantID)
		respondInternalError(c, "failed to retrieve disclosure events")
		return
	}

	c.JSON(http.StatusOK, events)
}

// swaggo resolves an annotation's apimodels.Type through this file's import
// list, but a reference from a comment is not Go usage — so without this the
// import would be stripped and `make api-spec` would fail. See RD-1265.
var _ = apimodels.APIError{}
