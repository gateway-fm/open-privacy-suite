package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/configuration"
)

// The groups stream is deliberately absent: the operator token may manage
// org-admin and system groups (RD-1107), which only the handler can decide
// after loading the group — see TestRD1107_OperatorKeepsPlatformAndAdminTierOps.
func TestConfigurationWriterRejectsOperatorBeforeDatabaseLookup(t *testing.T) {
	for _, kind := range []configuration.Kind{configuration.ContractRegistry, configuration.Compliance, configuration.ExecutionRules, configuration.Platform} {
		t.Run(string(kind), func(t *testing.T) {
			router := gin.New()
			router.Use(gin.Recovery(), func(c *gin.Context) { c.Set("auth_method", "operator_token"); c.Next() })
			server := &Server{} // Forbidden credentials must never reach a dependency.
			router.POST("/orgs/:org_id/write", server.configurationWriterGuard(kind), func(c *gin.Context) { t.Fatal("unauthorized handler reached") })
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/orgs/11111111-1111-1111-1111-111111111111/write", nil))
			require.Equal(t, http.StatusForbidden, response.Code)
		})
	}
}
