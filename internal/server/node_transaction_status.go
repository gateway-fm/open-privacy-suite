package server

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/nodepolicy"
)

// getMyNodeTransactionStatus returns the caller's own durable execution state.
// @Summary My transaction execution status
// @Description Status for a transaction submitted by this named principal, with current organization membership and KYC required. Shared signing addresses do not share status access. Queued, pending, denied and expired are nonterminal: an execution already started may still be included. Included or reverted reflects canonical node evidence; reconciled means OPS bookkeeping is committed. This endpoint never returns raw transactions, signing envelopes or visibility recipients.
// @Tags Profile
// @Produce json
// @Param hash path string true "Lowercase transaction hash"
// @Success 200 {object} apimodels.NodeTransactionProgress
// @Failure 401 {object} apimodels.APIError
// @Failure 404 {object} apimodels.APIError
// @Failure 429 {object} apimodels.APIError
// @Failure 500 {object} apimodels.APIError
// @Failure 503 {object} apimodels.APIError
// @Security BearerAuth
// @Router /api/v1/me/transactions/{hash}/execution [get]
func (s *Server) getMyNodeTransactionStatus(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	missing := func() { c.JSON(http.StatusNotFound, gin.H{"error": "transaction status not found"}) }
	if s.config == nil || !s.config.NodePolicy.Enabled() {
		missing()
		return
	}
	subject := c.GetString("subject")
	if subject == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}
	if s.rateLimiter == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "transaction status unavailable"})
		return
	}
	rps := 20
	if allowed, _ := s.rateLimiter.CheckAndIncrement("execution-status:"+subject, &rps, nil); !allowed {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "status request limit reached"})
		return
	}
	hash := c.Param("hash")
	if len(hash) != 66 || !strings.HasPrefix(hash, "0x") || strings.ToLower(hash) != hash {
		missing()
		return
	}
	if _, err := hex.DecodeString(hash[2:]); err != nil {
		missing()
		return
	}
	ctx := c.Request.Context()
	user, err := s.db.GetUserByExternalID(ctx, subject)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "transaction status unavailable"})
		return
	}
	if user == nil || user.Banned || !user.KYC {
		missing()
		return
	}
	network := nodepolicy.Network{ChainID: s.config.NodePolicy.ChainID, DeploymentID: s.config.NodePolicy.DeploymentID}
	stored, err := s.db.GetNodeSubmission(ctx, network, hash)
	if errors.Is(err, sql.ErrNoRows) {
		missing()
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "transaction status unavailable"})
		return
	}
	if stored.PrincipalID != user.ID {
		missing()
		return
	}
	memberships, err := s.db.ListUserMembershipsInOrg(ctx, user.ID, stored.OrgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "transaction status unavailable"})
		return
	}
	if len(memberships) == 0 {
		missing()
		return
	}
	response := apimodels.NodeTransactionProgress{TransactionHash: stored.TransactionHash, ContextID: stored.ContextID, Status: stored.State, Reconciled: stored.ReconciledAt != nil, ReconciliationNote: stored.ReconciliationNote}
	if len(stored.Outcome) > 0 {
		var status nodepolicy.TransactionStatus
		if err := json.Unmarshal(stored.Outcome, &status); err != nil || status.Validate() != nil || status.PrincipalID != stored.PrincipalID || status.OrgID != stored.OrgID || status.TransactionHash != hash {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "transaction status unavailable"})
			return
		}
		response.Execution = &status.Execution
	}
	c.JSON(http.StatusOK, response)
}
