package server

import (
	"privacy-proxy/internal/apimodels"
	"strconv"

	"github.com/gin-gonic/gin"
)

// Audit Log handlers

// listAuditLogs returns RBAC audit log rows.
//
// Audit H1: pre-fix this endpoint returned every audit entry across
// every org for a given resource_type / actor_id query. A tier-2
// admin of Org A could enumerate is_org_admin mutations, group
// renames, contract changes, and actor identities across the entire
// cluster.
//
// Fix: super-admin sees everything; JWT admins receive only entries
// whose resource lives in one of their admin_org_ids /
// admin_readonly_org_ids. The DB layer filters at the SQL level so
// the response cardinality cannot be used as an enumeration oracle.
//
// @Summary      List RBAC audit logs
// @Description  Returns RBAC audit-log entries. At least one of resource_type or actor_id must be supplied to avoid unbounded scans; resource_id further narrows a resource_type query. A super-admin sees all entries; a tier-2 org-admin JWT receives only entries whose resource lives in an org it administers (filtered in SQL, so cardinality is not an enumeration oracle). Tenant-confidential: rejected for the operator token (403).
// @Tags         Admin: RBAC
// @Produce      json
// @Param        resource_type query string false "Filter by resource type (required unless actor_id is given)"
// @Param        resource_id query string false "Further narrow a resource_type query to one resource"
// @Param        actor_id query string false "Filter by actor (required unless resource_type is given)"
// @Param        limit query int false "Max rows to return (default 100, max 1000)"
// @Param        offset query int false "Rows to skip for pagination (default 0)"
// @Success      200 {array} apimodels.AuditLogEntryDoc
// @Failure      400 {object} apimodels.APIError "at least one filter (resource_type or actor_id) is required"
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network, or operator token (tenant data not readable)"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/audit-logs [get]
func (s *Server) listAuditLogs(c *gin.Context) {
	// RD-1132: tenant-confidential read — not readable with the operator token.
	if denyOperatorTenantRead(c) {
		return
	}
	// Parse pagination params
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

	// Parse filter params
	resourceType := c.Query("resource_type")
	resourceID := c.Query("resource_id")
	actorID := c.Query("actor_id")

	// At least one filter must be provided to avoid massive queries
	if resourceType == "" && actorID == "" {
		respondBadRequest(c, "at least one filter (resource_type or actor_id) is required")
		return
	}

	var resourceIDPtr *string
	if resourceID != "" {
		resourceIDPtr = &resourceID
	}

	ctx := c.Request.Context()

	// Compute caller's scope. nil means super-admin / dev (no filter).
	scopedOrgIDs := callerOrgScope(c)

	// Use actor filter if provided
	if actorID != "" {
		logs, err := s.db.ListAuditLogsByActorScoped(ctx, actorID, scopedOrgIDs, limit, offset)
		if err != nil {
			respondInternalErrorAndLog(c, "failed to read audit log",
				"admin_rbac_audit: ListAuditLogsByActorScoped failed",
				"actor_id", actorID, "err", err)
			return
		}
		respondOK(c, logs)
		return
	}

	// Use resource type filter
	logs, err := s.db.ListAuditLogsScoped(ctx, resourceType, resourceIDPtr, scopedOrgIDs, limit, offset)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to read audit log",
			"admin_rbac_audit: ListAuditLogsScoped failed",
			"resource_type", resourceType, "err", err)
		return
	}
	respondOK(c, logs)
}

// callerOrgScope returns the org IDs the JWT-admin caller may see
// (union of full-admin and read-only-admin org IDs), or nil for
// super-admin / dev-mode callers (= no filter).
func callerOrgScope(c *gin.Context) []string {
	if c.GetString("auth_method") != "jwt_admin" {
		return nil
	}
	seen := map[string]struct{}{}
	out := []string{}
	if ids, ok := c.Get("admin_org_ids"); ok {
		if list, ok := ids.([]string); ok {
			for _, id := range list {
				if _, dup := seen[id]; !dup {
					seen[id] = struct{}{}
					out = append(out, id)
				}
			}
		}
	}
	if ids, ok := c.Get("admin_readonly_org_ids"); ok {
		if list, ok := ids.([]string); ok {
			for _, id := range list {
				if _, dup := seen[id]; !dup {
					seen[id] = struct{}{}
					out = append(out, id)
				}
			}
		}
	}
	// Empty slice (not nil) signals "caller is jwt_admin with no
	// orgs" — the SQL layer should return zero rows in that case.
	return out
}

// swaggo resolves an annotation's apimodels.Type through this file's import
// list, but a reference from a comment is not Go usage — so without this the
// import would be stripped and `make api-spec` would fail. See RD-1265.
var _ = apimodels.APIError{}
