package server

import (
	"database/sql"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/configuration"
)

// @Summary Activate exact externally reviewed configuration from trusted CI
// @Tags Admin: Configuration
// @Accept json
// @Produce json
// @Param org_id path string true "Organization UUID"
// @Param kind path string true "Configuration stream"
// @Param revision_id path string true "Revision UUID"
// @Param request body configuration.CIActivationRequest true "Independent signed external approval"
// @Success 200 {object} apimodels.ConfigurationRevisionList
// @Failure 400 {object} apimodels.APIError
// @Failure 403 {object} apimodels.APIError
// @Failure 409 {object} apimodels.APIError
// @Security BearerAuth
// @Router /api/v1/admin/orgs/{org_id}/configuration/{kind}/revisions/{revision_id}/activate-ci [post]
func (s *Server) activateConfigurationCI(c *gin.Context) {
	kind, _ := c.Get("admin_principal_kind")
	if kind != auth.PrincipalService {
		c.JSON(http.StatusForbidden, gin.H{"error": "CI activation requires a verified service-principal login"})
		return
	}
	actor, ok := configurationRequestActor(c)
	if !ok {
		return
	}
	scope, stream, ok := configurationRoute(c)
	if !ok {
		return
	}
	raw, err := io.ReadAll(io.LimitReader(c.Request.Body, 65537))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot read approval"})
		return
	}
	request, err := configuration.ParseCIActivationRequest(raw)
	if err != nil {
		respondClientError(c, http.StatusBadRequest, err, "invalid CI activation request", "admin_configuration_ci: request rejected without client text")
		return
	}
	revision, err := s.db.GetConfigurationRevision(c.Request.Context(), scope, stream, c.Param("revision_id"))
	if err != nil {
		configurationError(c, err)
		return
	}
	if revision == nil {
		configurationError(c, sql.ErrNoRows)
		return
	}
	actor.CIApproval = request.Approval
	rows, err := s.db.ActivateConfigurationRevisions(c.Request.Context(), scope, append([]string{revision.ID}, request.Coactivate...), actor, s.authorizeConfigurationActivation)
	if err != nil {
		configurationError(c, err)
		return
	}
	if s.rbacAccessCtrl != nil {
		s.rbacAccessCtrl.InvalidateOrgLocalCache(scope.ID)
	}
	c.JSON(http.StatusOK, configurationRevisionList(rows))
}

// Referenced by OpenAPI annotations; ensure this file's API vocabulary stays
// aligned with the normal activation route's response.
var _ apimodels.ConfigurationRevisionList
