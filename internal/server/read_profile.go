package server

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/rbac"
)

// readProfile is the deployment-wide read privacy profile (PRIVACY_READ_PROFILE,
// RD-1299). A server without a config reports ReadProfileUnset, which every
// decision enforces as strict (fail closed).
func (s *Server) readProfile() rbac.ReadProfile {
	if s == nil || s.config == nil {
		return rbac.ReadProfileUnset
	}
	return s.config.ReadProfile
}

// orgAdminViewUserTxsEffective reports whether the explorer's elevated org-admin
// audit view (ORG_ADMIN_VIEW_USER_TXS) actually applies. Strict wins: under the
// strict read profile the flag has no effect, so it can never re-admit rows the
// profile hides.
func (s *Server) orgAdminViewUserTxsEffective() bool {
	if s == nil || s.config == nil {
		return false
	}
	return s.config.OrgAdminViewUserTxs && !s.readProfile().Strict()
}

// newExplorerRedactor is the single construction path of the explorer
// redaction engine, used at startup and by the explorer reconnect loop: the
// server's read profile (RD-1299) and every resolver wired by
// wireExplorerRedactor (ABI, admin, event rules, visibleTo unlock, dynamic
// payload, log participants, parent-transaction data).
func (s *Server) newExplorerRedactor(backend explorer.ExplorerBackend, rbacDB *db.DB) *explorer.RedactionEngine {
	engine := explorer.NewRedactionEngine(backend, rbacDB, s.readProfile())
	var key []byte
	if s.config != nil {
		key = s.config.ExplorerPseudonymKey
	}
	var store rbac.Store
	if rbacDB != nil {
		store = rbacDB
	}
	var chainData explorerChainData
	if backend != nil {
		chainData = backend
	}
	wireExplorerRedactor(engine, store, s.rbacAccessCtrl, chainData, key)
	return engine
}

// logReadProfile records the effective read profile at startup, and warns when
// ORG_ADMIN_VIEW_USER_TXS is configured but overridden by strict.
func (s *Server) logReadProfile() {
	profile := s.readProfile()
	slog.Info("read privacy profile", "profile", profile.String(),
		"org_admin_view_user_txs", s.orgAdminViewUserTxsEffective())
	if profile.Strict() && s.config != nil && s.config.OrgAdminViewUserTxs {
		slog.Warn("ORG_ADMIN_VIEW_USER_TXS=true has no effect under PRIVACY_READ_PROFILE=strict: the strict read profile wins")
	}
}

// handleGetReadProfile reports the effective read privacy profile.
//
// @Summary      Get the read privacy profile
// @Description  Effective deployment-wide read privacy profile (PRIVACY_READ_PROFILE, fixed at startup) and the effective state of the org-admin audit view (ORG_ADMIN_VIEW_USER_TXS). Under "strict", transactions and receipts are returned only to a transaction participant and an event only when an indexed address parameter of its registered ABI is one of the viewer's linked addresses; the org-admin audit view is then always off, whatever ORG_ADMIN_VIEW_USER_TXS says. Read-only; any admin the middleware admits.
// @Tags         Admin: system
// @Produce      json
// @Success      200 {object} apimodels.SystemReadProfileResponse
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network"
// @Security     AdminToken
// @Router       /api/v1/admin/system/read-profile [get]
func (s *Server) handleGetReadProfile(c *gin.Context) {
	configured := s.config != nil && s.config.OrgAdminViewUserTxs
	c.JSON(http.StatusOK, apimodels.SystemReadProfileResponse{
		Profile:                       s.readProfile().String(),
		OrgAdminViewUserTxs:           s.orgAdminViewUserTxsEffective(),
		OrgAdminViewUserTxsConfigured: configured,
	})
}
