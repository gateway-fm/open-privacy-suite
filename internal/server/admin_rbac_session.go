package server

import (
	"github.com/gin-gonic/gin"
)

// Session management handlers

// SessionListResponse represents the response for listing sessions.
type SessionListResponse struct {
	Sessions []*sessionInfoResponse `json:"sessions"`
	Total    int64                  `json:"total"`
}

type sessionInfoResponse struct {
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

// listSessions exposes the in-flight auth session store. The entries
// are not org-tagged — they're cluster-wide auth-flow sessions, so a
// JWT admin in Org A has no legitimate need to enumerate them
// (audit H7). Restrict to super-admin.
//
// @Summary      List auth sessions
// @Description  Returns the in-flight authentication sessions (id, created/expiry/completed timestamps, and for a rejected wallet proof the precise failure reason) held in the session store. These are cluster-wide auth-flow sessions, not org-tagged, so the endpoint is restricted to the super-admin (full X-Admin-Token); tier-2 org-admin JWTs and the operator token are rejected with 403.
// @Tags         Admin: RBAC
// @Produce      json
// @Success      200 {object} SessionListResponse
// @Failure      401 {object} APIError "missing or invalid admin token"
// @Failure      403 {object} APIError "source address not on the private network, caller is not a super-admin, or operator token (tenant data not readable)"
// @Security     AdminToken
// @Router       /api/v1/admin/sessions [get]
func (s *Server) listSessions(c *gin.Context) {
	// RD-1132: tenant-confidential read — not readable with the operator token.
	if denyOperatorTenantRead(c) {
		return
	}
	if !requireSuperAdmin(c) {
		return
	}
	sessions := s.sessionStore.ListSessions()
	count := s.sessionStore.Count()

	// Convert to response format
	var responseItems []*sessionInfoResponse
	for _, session := range sessions {
		item := &sessionInfoResponse{
			ID:        session.ID,
			CreatedAt: session.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			ExpiresAt: session.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
			Completed: session.Completed,
		}
		if session.Completed && !session.CompletedAt.IsZero() {
			item.CompletedAt = session.CompletedAt.Format("2006-01-02T15:04:05Z07:00")
		}
		if session.Failed {
			item.Failed = true
			item.FailureReason = session.FailureReason
			if !session.FailedAt.IsZero() {
				item.FailedAt = session.FailedAt.Format("2006-01-02T15:04:05Z07:00")
			}
		}
		responseItems = append(responseItems, item)
	}

	respondOK(c, SessionListResponse{
		Sessions: responseItems,
		Total:    count,
	})
}

// deleteSession terminates an in-flight auth session. Same reason as
// listSessions — sessions are cluster-wide and not org-tagged, so a
// JWT admin in Org A could mass-DoS in-progress logins across the
// cluster (audit H7). Restrict to super-admin.
//
// @Summary      Delete an auth session
// @Description  Terminates a single in-flight authentication session by ID. Restricted to the super-admin (full X-Admin-Token) — sessions are cluster-wide, so allowing tier-2 org-admin JWTs would enable mass-DoS of in-progress logins; the operator token is likewise rejected.
// @Tags         Admin: RBAC
// @Produce      json
// @Param        session_id path string true "Auth session ID"
// @Success      200 {object} APIMessage "session deleted"
// @Failure      401 {object} APIError "missing or invalid admin token"
// @Failure      403 {object} APIError "source address not on the private network, or caller is not a super-admin"
// @Failure      404 {object} APIError "session not found or expired"
// @Security     AdminToken
// @Router       /api/v1/admin/sessions/{session_id} [delete]
func (s *Server) deleteSession(c *gin.Context) {
	if !requireSuperAdmin(c) {
		return
	}
	sessionID := c.Param("session_id")

	// Check if session exists
	session := s.sessionStore.GetSession(sessionID)
	if session == nil {
		respondNotFound(c, "session not found or expired")
		return
	}

	// Delete the session
	s.sessionStore.DeleteSession(sessionID)

	respondDeleted(c, "session")
}
