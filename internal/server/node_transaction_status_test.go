package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/nodepolicy"
	"privacy-proxy/internal/server/middleware"
)

func TestMyNodeTransactionStatusRequiresOriginalLivePrincipal(t *testing.T) {
	f := configurationAPI(t)
	s := f.server
	s.config.NodePolicy = config.NodePolicyConfig{Mode: "reth", ChainID: 31337, DeploymentID: "status-test"}
	s.rateLimiter = middleware.NewRateLimiter(middleware.RateLimiterCleanupInterval)
	t.Cleanup(s.rateLimiter.Stop)
	_, err := s.db.Conn().ExecContext(t.Context(), `UPDATE users SET kyc=true WHERE id=$1`, f.readonlyUserID)
	require.NoError(t, err)
	user, err := s.db.GetUser(t.Context(), f.readonlyUserID)
	require.NoError(t, err)
	network := nodepolicy.Network{ChainID: 31337, DeploymentID: "status-test"}
	hash := "0x" + strings.Repeat("11", 32)
	require.NoError(t, s.db.SaveNodeSubmission(t.Context(), db.NodeSubmission{Network: network, TransactionHash: hash, PrincipalID: user.ID, OrgID: f.orgID, Signer: "0x" + strings.Repeat("22", 20), ContextID: uuid.NewString(), RawTransaction: "0xdeadbeef", IdentityEnvelope: []byte("private-signed-envelope"), SenderDID: user.ExternalID, VisibleTo: []string{"private-recipient"}}))
	router := gin.New()
	s.registerUserProfileRoutes(router)
	request := func(token, target string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/me/transactions/"+target+"/execution", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		router.ServeHTTP(w, req)
		return w
	}
	response := request(f.readonly, hash)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var got map[string]any
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &got))
	require.Equal(t, "queued", got["status"])
	for _, secret := range []string{"deadbeef", "private-signed-envelope", "private-recipient"} {
		require.NotContains(t, response.Body.String(), secret)
	}
	require.Equal(t, http.StatusNotFound, request(f.admin, hash).Code, "other admin does not inherit submitter's status")
	require.Equal(t, http.StatusNotFound, request(f.readonly, "0x"+strings.Repeat("00", 32)).Code)
	_, err = s.db.Conn().ExecContext(t.Context(), `DELETE FROM user_memberships WHERE user_id=$1`, user.ID)
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, request(f.readonly, hash).Code, "revoked organization membership retains no status visibility")
	// Authentication is still provided by the ordinary JWT middleware.
	require.Equal(t, http.StatusUnauthorized, request("", hash).Code)
}
