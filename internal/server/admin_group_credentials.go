package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"privacy-proxy/internal/crypto"
	"privacy-proxy/internal/rbac"
)

// @Summary Rotate operational upstream RPC credentials for a group
// @Tags Admin: Configuration
// @Accept json
// @Param org_id path string true "Organization UUID"
// @Param group_id path string true "Group UUID"
// @Param request body object true "rpc_api_key only; empty string clears it"
// @Success 204
// @Security BearerAuth
// @Router /api/v1/admin/orgs/{org_id}/groups/{group_id}/rpc-credential [put]
func (s *Server) rotateGroupRPCCredential(c *gin.Context) {
	group, err := s.db.GetGroup(c.Request.Context(), c.Param("group_id"))
	if err != nil {
		internalError(c, "failed to read group", err)
		return
	}
	if !verifyGroupBelongsToPathOrg(c, group) {
		return
	}
	if group.IsSystem && c.GetString("auth_method") != "admin_token" {
		c.JSON(http.StatusForbidden, gin.H{"error": "system group credentials require bootstrap authority"})
		return
	}
	if denyJWTAdminTouchOrgAdminGroup(c, group) || denyOperatorRegularGroup(c, group) {
		return
	}
	var input struct {
		Key *string `json:"rpc_api_key"`
	}
	decoder := json.NewDecoder(io.LimitReader(c.Request.Body, 16385))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil || input.Key == nil || len(*input.Key) > 8192 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "rpc_api_key is required; no desired-state fields are accepted"})
		return
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unexpected credential request content"})
		return
	}
	var encrypted *string
	if *input.Key != "" {
		key, err := crypto.Encrypt(*input.Key, s.config.RPCAPIKeyEncryptionKey)
		if err != nil {
			internalError(c, "failed to protect RPC credential", err)
			return
		}
		encrypted = &key
	}
	if err := s.db.RotateGroupRPCCredential(c.Request.Context(), group.OrgID, group.ID, encrypted); err != nil {
		configurationError(c, err)
		return
	}
	s.recordAuditActionScoped(c, rbac.AuditActionUpdate, rbac.ResourceTypeAccess, group.ID, group.Name, group.OrgID, nil, map[string]any{"rpc_credential_rotated": true, "rpc_credential_present": encrypted != nil})
	if s.rbacAccessCtrl != nil {
		s.rbacAccessCtrl.InvalidateOrgLocalCache(group.OrgID)
	}
	c.Status(http.StatusNoContent)
}
