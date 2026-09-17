package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/rbac"
)

func TestConfigurationPlatformStatusDoesNotInventOrgAuthority(t *testing.T) {
	s, router := setupAdminAuthTestServer(t, "")
	user := &rbac.User{ID: uuid.NewString(), ExternalID: "did:test:platform:" + uuid.NewString()}
	require.NoError(t, s.db.CreateUser(t.Context(), user))
	s.config.PlatformAdminSubjects = []string{user.ExternalID}
	for _, kind := range []auth.PrincipalKind{auth.PrincipalHuman, auth.PrincipalService, ""} {
		token, err := s.jwtService.IssueAccessTokenForPrincipal(user.ExternalID, true, kind, nil)
		require.NoError(t, err)
		response := orgAdminGateReq(t, router, http.MethodGet, "/api/v1/me/admin-status", token, "", nil)
		require.Equal(t, 200, response.Code, response.Body.String())
		var body map[string]any
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
		require.Equal(t, kind == auth.PrincipalHuman, body["is_platform_admin"])
		require.Equal(t, false, body["is_admin"])
		require.Empty(t, body["admin_org_ids"])
	}
}
