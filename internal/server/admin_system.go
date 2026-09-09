package server

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/version"
)

// handleGetVersion returns the build identity (version / commit / build time)
// of the running binary. Admin-gated via the /api/v1/admin/system group
// (localhost + admin auth). It is deliberately NOT surfaced on the
// unauthenticated /health endpoint, nor injected into the standard
// web3_clientVersion RPC (RD-1023): web3_clientVersion is in the anonymous
// allowlist (migration 044) and is defined as the *execution client's*
// version, so broadcasting the proxy build there would both leak our exact
// build to unauthenticated callers and break the method's semantics. The
// build identity is operational data for ops/support, so it lives behind the
// admin surface (plus the startup log line and the Prometheus build_info
// label).
//
// @Summary      Build version of the running proxy
// @Description  Build identity (version, commit, build time) of the running binary. Read-only; any admin token. Deliberately not exposed on /health or web3_clientVersion.
// @Tags         Admin: system
// @Produce      json
// @Success      200 {object} apimodels.SystemVersionResponse
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network"
// @Security     AdminToken
// @Router       /api/v1/admin/system/version [get]
func (s *Server) handleGetVersion(c *gin.Context) {
	c.JSON(http.StatusOK, apimodels.SystemVersionResponse{
		Version:   version.Version,
		Commit:    version.Commit,
		BuildTime: version.BuildTime,
	})
}

// Admin "system" endpoints — fleet-wide settings the super-admin can flip
// at runtime without a redeploy. Pre-RD-915 the eth_call cross-org tracing
// knob was env-only; that's still the durable control (a restart re-arms
// the env value), but ops sometimes needs a faster lever for sev-1 rollback
// (ISO 27001 A.8.32, see docs/rd-915-design.md §KD-5).
//
// Risk model and mitigations (the "is it safe to have this endpoint?"
// question):
//
//   - The endpoint flips a security-critical control, so the auth bar is
//     the strongest one in the system: super-admin token only
//     (auth_method == "admin_token", i.e. ADMIN_API_TOKEN). Tier-2 org
//     admin JWTs cannot reach it.
//   - The toggle is **in-memory only**. A restart re-installs the env
//     value, so a compromised token cannot durably disable the protection
//     without ALSO redeploying with a tampered env, which is the
//     change-management touchpoint that gets audited separately.
//   - Every toggle writes a row to rbac_audit_log (and fires a SIEM event
//     when configured) so the action is reviewable.
//   - The GET endpoint exposes the current effective state plus
//     change-metadata so an auditor can prove "control was on" without
//     needing pod access.
//
// The reverse threat — "what if an attacker turns tracing ON?" — has
// no exploit value: tracing is the protective layer, enabling it does
// not weaken anything else.

func snapshotToResponse(s runtimeToggleState) apimodels.SystemToggleResponse {
	resp := apimodels.SystemToggleResponse{
		Enabled:    s.Enabled,
		EnvDefault: s.EnvDefault,
		Source:     s.Source,
		ChangedBy:  s.ChangedBy,
		Reason:     s.Reason,
	}
	if !s.ChangedAt.IsZero() {
		resp.ChangedAt = s.ChangedAt.UTC().Format("2006-01-02T15:04:05.000Z")
	}
	return resp
}

// handleGetEthCallTracing returns the current state of the eth_call
// cross-org tracing knob. Available to any caller the admin middleware
// chain admits (super-admin token OR tier-2 admin JWT) — the read is
// harmless and ops dashboards may want it.
//
// @Summary      Get eth_call cross-org tracing state
// @Description  Current effective state of the eth_call cross-org tracing control, plus its env default and change metadata. Read-only; any admin the middleware admits.
// @Tags         Admin: system
// @Produce      json
// @Success      200 {object} apimodels.SystemToggleResponse
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network"
// @Failure      503 {object} apimodels.APIError "request processor not initialised"
// @Security     AdminToken
// @Router       /api/v1/admin/system/eth-call-tracing [get]
func (s *Server) handleGetEthCallTracing(c *gin.Context) {
	if s.jsonrpcProcessor == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "processor not initialised"})
		return
	}
	snap := s.jsonrpcProcessor.EthCallTracingSnapshot()
	c.JSON(http.StatusOK, snapshotToResponse(snap))
}

// handlePostEthCallTracing toggles the in-memory eth_call cross-org
// tracing knob. Super-admin (admin_token) only. Audit-logged. The
// effect is **not persisted** — the next restart re-installs the env
// value, which is the durable control.
//
// @Summary      Toggle eth_call cross-org tracing
// @Description  Sets the in-memory eth_call cross-org tracing control. Super-admin token only (tier-2 admin JWTs get 403). A non-empty reason is required and audit-logged. The change is not persisted — a restart re-installs the env default.
// @Tags         Admin: system
// @Accept       json
// @Produce      json
// @Param        request body apimodels.SystemToggleRequest true "enabled flag and audit reason"
// @Success      200 {object} apimodels.SystemToggleResponse
// @Failure      400 {object} apimodels.APIError "missing enabled flag, missing reason, or reason too long"
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "not a super-admin token, or source address not on the private network"
// @Failure      503 {object} apimodels.APIError "request processor not initialised"
// @Security     AdminToken
// @Router       /api/v1/admin/system/eth-call-tracing [post]
func (s *Server) handlePostEthCallTracing(c *gin.Context) {
	if s.jsonrpcProcessor == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "processor not initialised"})
		return
	}
	// Super-admin only. Mirrors the system-group guard in
	// admin_rbac_group.go:261 — system-wide mutations are gated to the
	// super-admin token (ADMIN_API_TOKEN), not tier-2 org admin JWTs.
	if c.GetString("auth_method") != "admin_token" {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "system settings require super-admin authentication",
		})
		return
	}

	var req apimodels.SystemToggleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondBadRequestAndLog(c, "invalid request body",
			"admin_system: invalid eth-call-tracing toggle body", "err", err)
		return
	}
	if req.Enabled == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "enabled field is required"})
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "reason is required — this toggle is audited and reviewers need to know why",
		})
		return
	}
	if len(reason) > 500 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "reason too long (max 500 chars)"})
		return
	}

	actor := "system:admin_token" // super-admin token has no DID
	prev := s.jsonrpcProcessor.EthCallTracingSnapshot()
	next := s.jsonrpcProcessor.SetEthCallTracingRuntimeOverride(*req.Enabled, actor, reason)

	// Audit log + SIEM. We do these in best-effort fashion — the toggle
	// has already taken effect. A log-write failure should not roll back
	// the operator's emergency action, but it should be noisy.
	if store := s.rbacAccessCtrl.Store(); store != nil {
		if auditErr := store.CreateAuditLog(c.Request.Context(), &rbac.AuditLogEntry{
			ActorExternalID: actor,
			Action:          rbac.AuditActionUpdate,
			ResourceType:    "system_setting",
			ResourceName:    "eth_call_tracing",
			OldValue: map[string]any{
				"enabled": prev.Enabled,
				"source":  prev.Source,
			},
			NewValue: map[string]any{
				"enabled": next.Enabled,
				"source":  next.Source,
				"reason":  reason,
			},
			IPAddress: c.ClientIP(),
		}); auditErr != nil {
			// Loud failure — if audit logging is broken, the toggle is
			// not reviewable. Operators should treat this as a sev-2.
			slog.Error("system setting toggle: audit log write failed",
				slog.String("setting", "eth_call_tracing"),
				slog.Any("err", auditErr))
		}
	}
	if s.siemForwarder != nil {
		s.siemForwarder.Send(audit.SIEMEvent{
			EventType:     "system_setting_change",
			Action:        "toggle_eth_call_tracing",
			ActorID:       actor,
			Outcome:       boolStr(next.Enabled, "enabled", "disabled"),
			SourceIP:      c.ClientIP(),
			CorrelationID: c.GetHeader("X-Correlation-ID"),
			Details:       "eth_call cross-org tracing toggled via super-admin endpoint; reason=" + reason,
		})
	}
	slog.Warn("system setting: eth_call tracing toggled",
		slog.Bool("enabled", next.Enabled),
		slog.Bool("was_enabled", prev.Enabled),
		slog.String("actor", actor),
		slog.String("client_ip", c.ClientIP()),
		slog.String("reason", reason))

	c.JSON(http.StatusOK, snapshotToResponse(*next))
}

// handleGetIntraOrgGrantTracing returns the current state of the RD-1053
// intra-org contract-grant scoping knob. Same read-access posture as the
// eth_call tracing GET (any admin the middleware admits).
//
// @Summary      Get intra-org grant tracing state
// @Description  Current effective state of the RD-1053 intra-org contract-grant scoping control, plus its env default and change metadata. Read-only; any admin the middleware admits.
// @Tags         Admin: system
// @Produce      json
// @Success      200 {object} apimodels.SystemToggleResponse
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network"
// @Failure      503 {object} apimodels.APIError "request processor not initialised"
// @Security     AdminToken
// @Router       /api/v1/admin/system/intra-org-grant-tracing [get]
func (s *Server) handleGetIntraOrgGrantTracing(c *gin.Context) {
	if s.jsonrpcProcessor == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "processor not initialised"})
		return
	}
	snap := s.jsonrpcProcessor.IntraOrgGrantTracingSnapshot()
	c.JSON(http.StatusOK, snapshotToResponse(snap))
}

// handlePostIntraOrgGrantTracing toggles the in-memory RD-1053 intra-org
// grant scoping knob. Super-admin (admin_token) only, audit-logged, not
// persisted — the next restart re-installs the env value. Same risk model as
// handlePostEthCallTracing: this flips a security control, so the bar is the
// strongest in the system and every change leaves an audit trail. Note the
// directions are NOT symmetric in blast radius — turning this knob OFF
// *widens* read/send access within an org (back to org-ownership-only
// frames), so the audit row matters most on a disable.
//
// @Summary      Toggle intra-org grant tracing
// @Description  Sets the in-memory RD-1053 intra-org contract-grant scoping control. Super-admin token only (tier-2 admin JWTs get 403). A non-empty reason is required and audit-logged. The change is not persisted — a restart re-installs the env default. Disabling this control widens intra-org read/send access, so the audit trail matters most on a disable.
// @Tags         Admin: system
// @Accept       json
// @Produce      json
// @Param        request body apimodels.SystemToggleRequest true "enabled flag and audit reason"
// @Success      200 {object} apimodels.SystemToggleResponse
// @Failure      400 {object} apimodels.APIError "missing enabled flag, missing reason, or reason too long"
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "not a super-admin token, or source address not on the private network"
// @Failure      503 {object} apimodels.APIError "request processor not initialised"
// @Security     AdminToken
// @Router       /api/v1/admin/system/intra-org-grant-tracing [post]
func (s *Server) handlePostIntraOrgGrantTracing(c *gin.Context) {
	if s.jsonrpcProcessor == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "processor not initialised"})
		return
	}
	if c.GetString("auth_method") != "admin_token" {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "system settings require super-admin authentication",
		})
		return
	}

	var req apimodels.SystemToggleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondBadRequestAndLog(c, "invalid request body",
			"admin_system: invalid intra-org-grant-tracing toggle body", "err", err)
		return
	}
	if req.Enabled == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "enabled field is required"})
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "reason is required — this toggle is audited and reviewers need to know why",
		})
		return
	}
	if len(reason) > 500 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "reason too long (max 500 chars)"})
		return
	}

	actor := "system:admin_token"
	prev := s.jsonrpcProcessor.IntraOrgGrantTracingSnapshot()
	next := s.jsonrpcProcessor.SetIntraOrgGrantTracingRuntimeOverride(*req.Enabled, actor, reason)

	if store := s.rbacAccessCtrl.Store(); store != nil {
		if auditErr := store.CreateAuditLog(c.Request.Context(), &rbac.AuditLogEntry{
			ActorExternalID: actor,
			Action:          rbac.AuditActionUpdate,
			ResourceType:    "system_setting",
			ResourceName:    "intra_org_grant_tracing",
			OldValue: map[string]any{
				"enabled": prev.Enabled,
				"source":  prev.Source,
			},
			NewValue: map[string]any{
				"enabled": next.Enabled,
				"source":  next.Source,
				"reason":  reason,
			},
			IPAddress: c.ClientIP(),
		}); auditErr != nil {
			slog.Error("system setting toggle: audit log write failed",
				slog.String("setting", "intra_org_grant_tracing"),
				slog.Any("err", auditErr))
		}
	}
	if s.siemForwarder != nil {
		s.siemForwarder.Send(audit.SIEMEvent{
			EventType:     "system_setting_change",
			Action:        "toggle_intra_org_grant_tracing",
			ActorID:       actor,
			Outcome:       boolStr(next.Enabled, "enabled", "disabled"),
			SourceIP:      c.ClientIP(),
			CorrelationID: c.GetHeader("X-Correlation-ID"),
			Details:       "intra-org grant scoping toggled via super-admin endpoint; reason=" + reason,
		})
	}
	slog.Warn("system setting: intra-org grant tracing toggled",
		slog.Bool("enabled", next.Enabled),
		slog.Bool("was_enabled", prev.Enabled),
		slog.String("actor", actor),
		slog.String("client_ip", c.ClientIP()),
		slog.String("reason", reason))

	c.JSON(http.StatusOK, snapshotToResponse(*next))
}

// boolStr returns one of two strings based on a bool.
func boolStr(b bool, ifTrue, ifFalse string) string {
	if b {
		return ifTrue
	}
	return ifFalse
}
