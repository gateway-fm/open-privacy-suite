package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/configuration"
)

func TestConfigurationPlatformRequiresNamedAllowlistedHumans(t *testing.T) {
	f := configurationAPI(t)
	base := "/api/v1/admin/configuration/platform"
	response := f.request(t, f.admin, http.MethodGet, base+"/context", nil)
	require.Equal(t, http.StatusForbidden, response.Code, response.Body.String())
	for _, token := range []string{f.admin, f.reviewer} {
		claims, err := f.server.jwtService.ValidateAccessToken(token)
		require.NoError(t, err)
		f.server.config.PlatformAdminSubjects = append(f.server.config.PlatformAdminSubjects, claims.Subject)
	}
	response = f.request(t, f.admin, http.MethodGet, base+"/context", nil)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var context apimodels.ConfigurationContext
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &context))
	require.True(t, context.Viewer.CanActivate)
	doc, err := configuration.Parse(context.Source)
	require.NoError(t, err)
	require.Equal(t, "platform", doc.Scope.Kind)
	response = f.request(t, f.admin, http.MethodPost, base+"/revisions", doc)
	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
	var draft apimodels.ConfigurationRevision
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &draft))
	response = f.request(t, f.admin, http.MethodPost, base+"/revisions/"+draft.ID+"/activate", nil)
	require.Equal(t, http.StatusForbidden, response.Code, response.Body.String())
	response = f.request(t, f.reviewer, http.MethodPost, base+"/revisions/"+draft.ID+"/activate", nil)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	// Allowlist privilege is deliberately local to configuration routes.
	response = f.request(t, f.admin, http.MethodPost, "/api/v1/admin/azure-tenants", map[string]any{"tenant_id": "invalid"})
	require.Equal(t, http.StatusForbidden, response.Code, response.Body.String())
	doc.BaseRevision = draft.Revision
	response = f.request(t, f.admin, http.MethodPost, base+"/revisions", doc)
	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &draft))
	response = f.request(t, f.admin, http.MethodPost, base+"/revisions/"+draft.ID+"/withdraw", nil)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
}
