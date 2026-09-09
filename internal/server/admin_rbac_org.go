package server

import (
	"log/slog"
	"regexp"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/rbac"
)

// slugRegex validates that slugs contain only letters (case-insensitive), numbers, hyphens, and underscores.
// Slugs must start with a letter or number, not a hyphen or underscore.
var slugRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

// validateSlug checks if a slug is valid for use in URLs and database storage.
// Returns an error message if invalid, empty string if valid.
func validateSlug(slug string) string {
	if slug == "" {
		return "slug is required"
	}
	if len(slug) > 100 {
		return "slug must be 100 characters or less"
	}
	if !slugRegex.MatchString(slug) {
		return "slug must contain only letters, numbers, hyphens, and underscores, and start with a letter or number"
	}
	return ""
}

// parsePaginationParams extracts limit and offset from query parameters with
// defaults. The limit is clamped to maxPaginationLimit (RD-1179) so an
// unbounded ?limit= can't turn one admin list request into a full-table scan
// / memory blow-up. Non-numeric, zero, or negative values fall back to the
// defaults. This clamp previously lived only in compliancePaginationParams;
// it now applies to every admin list endpoint (users, orgs, contracts, groups).
func parsePaginationParams(c *gin.Context, defaultLimit int) (limit, offset int) {
	limit = defaultLimit
	offset = 0
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	if limit > maxPaginationLimit {
		limit = maxPaginationLimit
	}
	if o := c.Query("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}
	return
}

// Organization handlers

// listOrganizations enumerates orgs visible to the caller.
//
// Cross-org isolation (RD-916): super-admin (X-Admin-Token) sees every org.
// JWT admins see only orgs where they're is_org_admin or is_org_readonly_admin
// — i.e. their tenant boundary matches what `orgScopingMiddleware` already
// enforces on per-:org_id routes. Without this scope a JWT admin of org A
// could enumerate every other tenant's slug/name/UUID via this endpoint.
//
// @Summary      List organizations
// @Description  Returns a paginated list of organizations. Visibility is scoped to the caller: a super-admin (full X-Admin-Token) sees every org, while a tier-2 org-admin JWT sees only the orgs it administers. System orgs are hidden unless include_system=true. The operator token may list orgs (org metadata is not tenant-confidential).
// @Tags         Admin: RBAC
// @Produce      json
// @Param        limit query int false "Max rows to return (default 50)"
// @Param        offset query int false "Rows to skip for pagination (default 0)"
// @Param        include_system query bool false "Include seeded is_system orgs (default false)"
// @Success      200 {object} apimodels.OrgListResponse
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs [get]
func (s *Server) listOrganizations(c *gin.Context) {
	limit, offset := parsePaginationParams(c, 50)

	var (
		orgs  []*rbac.Organization
		total int
		err   error
	)
	if c.GetString("auth_method") == "jwt_admin" {
		// Build the visible-orgs set from middleware-populated context.
		// Both is_org_admin and is_org_readonly_admin grant visibility — a
		// readonly admin still has legitimate dashboard access to their org.
		seen := make(map[string]struct{})
		var allowed []string
		appendUnique := func(ids []string) {
			for _, id := range ids {
				if _, ok := seen[id]; ok {
					continue
				}
				seen[id] = struct{}{}
				allowed = append(allowed, id)
			}
		}
		if v, ok := c.Get("admin_org_ids"); ok {
			if slice, ok := v.([]string); ok {
				appendUnique(slice)
			}
		}
		if v, ok := c.Get("admin_readonly_org_ids"); ok {
			if slice, ok := v.([]string); ok {
				appendUnique(slice)
			}
		}
		orgs, total, err = s.db.ListOrganizationsByIDsPaginated(c.Request.Context(), allowed, limit, offset)
	} else {
		// admin_token (super-admin) — full visibility.
		orgs, total, err = s.db.ListOrganizationsPaginated(c.Request.Context(), limit, offset)
	}
	if err != nil {
		slog.Error("list organizations: db read failed", "err", err)
		respondInternalError(c, "failed to list organizations")
		return
	}

	includeSystem := c.Query("include_system") == "true"
	filtered := make([]*rbac.Organization, 0, len(orgs))
	for _, org := range orgs {
		if s.config.HideDevAdminOrg && org.Slug == "dev-admin-org" {
			continue
		}
		// is_system rows (e.g. the anonymous org from RD-870) are hidden by
		// default and only surface when ?include_system=true is passed.
		if org.IsSystem && !includeSystem {
			continue
		}
		filtered = append(filtered, org)
	}
	total -= len(orgs) - len(filtered)
	orgs = filtered
	respondOK(c, gin.H{"data": orgs, "total": total, "limit": limit, "offset": offset})
}

// createOrganization handles POST /api/v1/admin/orgs — tenant creation.
//
// @Summary      Create an organization
// @Description  Creates a new organization (tenant). This is a platform-level lifecycle operation reserved for the super-admin (full X-Admin-Token) and the operator token; a tier-2 org-admin JWT is rejected with 403. The slug must be URL-safe and unique: ^[A-Za-z0-9][A-Za-z0-9_-]*$, <=100 chars.
// @Tags         Admin: RBAC
// @Accept       json
// @Produce      json
// @Param        request body apimodels.OrgCreateRequest true "organization to create"
// @Success      201 {object} rbac.Organization
// @Failure      400 {object} apimodels.APIError "invalid body or slug format"
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network, or caller is a tier-2 org-admin JWT (only super-admin/operator may create orgs)"
// @Failure      409 {object} apimodels.APIError "an organization with this slug already exists"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs [post]
func (s *Server) createOrganization(c *gin.Context) {
	// Tenant lifecycle (creating a new org / tenant) is platform-level and
	// reserved for super-admin (X-Admin-Token). JWT-admin tier-2 cannot
	// create orgs — they're scoped to managing existing tenants. Mirrors the
	// is_org_admin escalation gate in createGroup (admin_rbac_group.go:73).
	// RD-917 §1.
	//
	// Dev mode (auth_method == "" — no admin token configured) and the
	// adminAuthMiddleware bypass test fixtures both reach this handler with
	// no auth context; they pass through because in those modes there is
	// no authentication boundary to enforce. Production deployments
	// configure ADMIN_API_TOKEN, which makes auth_method always either
	// "admin_token" or "jwt_admin" — and only "jwt_admin" is rejected.
	if c.GetString("auth_method") == "jwt_admin" {
		respondForbidden(c, "only super admin can create organizations")
		return
	}

	var input struct {
		Slug     string         `json:"slug" binding:"required"`
		Name     string         `json:"name" binding:"required"`
		Settings map[string]any `json:"settings"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respondBadRequest(c, "invalid request body")
		return
	}

	// Validate slug format before database insertion
	if errMsg := validateSlug(input.Slug); errMsg != "" {
		respondBadRequest(c, errMsg)
		return
	}

	org := &rbac.Organization{
		ID:       uuid.New().String(),
		Slug:     input.Slug,
		Name:     input.Name,
		Settings: input.Settings,
	}
	if org.Settings == nil {
		org.Settings = make(map[string]any)
	}

	if err := s.db.CreateOrganization(c.Request.Context(), org); err != nil {
		// Check for unique constraint violation (duplicate slug). Translating
		// pq's error text to a 409 — not echoing the raw error to the client.
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			respondConflict(c, "organization with this slug already exists")
			return
		}
		slog.Error("create organization: db insert failed", "slug", input.Slug, "err", err)
		respondInternalError(c, "failed to create organization")
		return
	}

	s.recordAuditActionScoped(c, rbac.AuditActionCreate, rbac.ResourceTypeOrganization, org.ID, org.Name, org.ID,
		nil,
		map[string]any{"slug": org.Slug, "name": org.Name})

	respondCreated(c, org)
}

// getOrganization returns a single organization by ID.
//
// @Summary      Get an organization
// @Description  Returns a single organization by its ID. Org-scoping middleware restricts a tier-2 org-admin JWT to orgs it administers; a super-admin (X-Admin-Token) or operator token may read any org.
// @Tags         Admin: RBAC
// @Produce      json
// @Param        org_id path string true "Organization ID (UUID)"
// @Success      200 {object} rbac.Organization
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network, or org outside the caller's scope"
// @Failure      404 {object} apimodels.APIError "organization not found"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id} [get]
func (s *Server) getOrganization(c *gin.Context) {
	orgID := c.Param("org_id")
	org, err := s.db.GetOrganization(c.Request.Context(), orgID)
	if err != nil {
		slog.Error("get organization: db read failed", "org_id", orgID, "err", err)
		respondInternalError(c, "failed to get organization")
		return
	}
	if org == nil {
		respondNotFound(c, "organization not found")
		return
	}
	respondOK(c, org)
}

// updateOrganization edits an organization's slug, name, and/or settings.
//
// @Summary      Update an organization
// @Description  Updates the slug, name, and/or settings of an organization. All body fields are optional; only supplied fields change. is_system organizations are identity-immutable and rejected with 403. Org-scoping middleware limits a tier-2 org-admin JWT to orgs it administers.
// @Tags         Admin: RBAC
// @Accept       json
// @Produce      json
// @Param        org_id path string true "Organization ID (UUID)"
// @Param        request body apimodels.OrgUpdateRequest true "fields to update (all optional)"
// @Success      200 {object} rbac.Organization
// @Failure      400 {object} apimodels.APIError "invalid body or slug format"
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network, org outside the caller's scope, or the org is a system org"
// @Failure      404 {object} apimodels.APIError "organization not found"
// @Failure      409 {object} apimodels.APIError "an organization with this slug already exists"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id} [put]
func (s *Server) updateOrganization(c *gin.Context) {
	orgID := c.Param("org_id")

	org, err := s.db.GetOrganization(c.Request.Context(), orgID)
	if err != nil {
		slog.Error("update organization: get failed", "org_id", orgID, "err", err)
		respondInternalError(c, "failed to update organization")
		return
	}
	if org == nil {
		respondNotFound(c, "organization not found")
		return
	}
	if org.IsSystem {
		// is_system rows are identity-immutable. Their group_access can be
		// edited via the dedicated PUT endpoint (super-admin only); the org
		// row itself (slug/name) is locked.
		respondForbidden(c, "system organization cannot be modified")
		return
	}

	var input struct {
		Slug     *string        `json:"slug"`
		Name     *string        `json:"name"`
		Settings map[string]any `json:"settings"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respondBadRequest(c, "invalid request body")
		return
	}

	oldValue := map[string]any{"slug": org.Slug, "name": org.Name}

	if input.Slug != nil {
		// Validate slug format before update
		if errMsg := validateSlug(*input.Slug); errMsg != "" {
			respondBadRequest(c, errMsg)
			return
		}
		org.Slug = *input.Slug
	}
	if input.Name != nil {
		org.Name = *input.Name
	}
	if input.Settings != nil {
		org.Settings = input.Settings
	}

	if err := s.db.UpdateOrganization(c.Request.Context(), org); err != nil {
		// Translate unique-constraint violations to 409 — see createOrganization.
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			respondConflict(c, "organization with this slug already exists")
			return
		}
		slog.Error("update organization: db update failed", "org_id", orgID, "err", err)
		respondInternalError(c, "failed to update organization")
		return
	}

	s.recordAuditActionScoped(c, rbac.AuditActionUpdate, rbac.ResourceTypeOrganization, org.ID, org.Name, org.ID,
		oldValue,
		map[string]any{"slug": org.Slug, "name": org.Name})

	respondOK(c, org)
}

// deleteOrganization deletes a tenant org.
//
// @Summary      Delete an organization
// @Description  Deletes an organization and cascades to its groups, contracts, and grants. Platform-level lifecycle reserved for the super-admin (full X-Admin-Token) and the operator token; a tier-2 org-admin JWT is rejected with 403. The default organization and system orgs cannot be deleted.
// @Tags         Admin: RBAC
// @Produce      json
// @Param        org_id path string true "Organization ID (UUID)"
// @Success      200 {object} apimodels.APIMessage "organization deleted"
// @Failure      400 {object} apimodels.APIError "cannot delete the default organization"
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network, caller is a tier-2 org-admin JWT, or the org is a system org"
// @Failure      404 {object} apimodels.APIError "organization not found"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id} [delete]
func (s *Server) deleteOrganization(c *gin.Context) {
	// Tenant deletion is platform-level and reserved for super-admin
	// (X-Admin-Token). Tier-2 admins retain read + edit-metadata on their
	// own orgs, but DELETE is locked: deleting a tenant is operator
	// territory, not in-tenant authority. RD-917 §1.
	//
	// See createOrganization for the dev-mode rationale.
	if c.GetString("auth_method") == "jwt_admin" {
		respondForbidden(c, "only super admin can delete organizations")
		return
	}

	orgID := c.Param("org_id")

	// Prevent deleting the default organization
	if orgID == rbac.DefaultOrgID {
		respondBadRequest(c, "cannot delete the default organization")
		return
	}

	// Check if organization exists
	org, err := s.db.GetOrganization(c.Request.Context(), orgID)
	if err != nil {
		slog.Error("delete organization: get failed", "org_id", orgID, "err", err)
		respondInternalError(c, "failed to delete organization")
		return
	}
	if org == nil {
		respondNotFound(c, "organization not found")
		return
	}
	if org.IsSystem {
		respondForbidden(c, "system organization cannot be deleted")
		return
	}

	// Delete the organization (cascades to groups, contracts, etc. via DB constraints)
	if err := s.db.DeleteOrganization(c.Request.Context(), orgID); err != nil {
		slog.Error("delete organization: db delete failed", "org_id", orgID, "err", err)
		respondInternalError(c, "failed to delete organization")
		return
	}

	// Invalidate cache for this organization
	s.rbacAccessCtrl.InvalidateOrg(c.Request.Context(), orgID)

	s.recordAuditActionScoped(c, rbac.AuditActionDelete, rbac.ResourceTypeOrganization, org.ID, org.Name, org.ID,
		map[string]any{"slug": org.Slug, "name": org.Name},
		nil)

	respondDeleted(c, "organization")
}

// swaggo resolves an annotation's apimodels.Type through this file's import
// list, but a reference from a comment is not Go usage — so without this the
// import would be stripped and `make api-spec` would fail. See RD-1265.
var _ = apimodels.APIError{}
