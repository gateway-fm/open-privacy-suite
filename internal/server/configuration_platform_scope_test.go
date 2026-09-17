package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/configuration"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"
)

func TestConfigurationPlatformAllowlistDoesNotGrantTenantAuthority(t *testing.T) {
	f := configurationAPI(t)
	claims, err := f.server.jwtService.ValidateAccessToken(f.admin)
	require.NoError(t, err)
	f.server.config.PlatformAdminSubjects = []string{claims.Subject}
	foreign := &rbac.Organization{ID: uuid.NewString(), Slug: "foreign-" + uuid.NewString(), Name: "Other tenant"}
	require.NoError(t, f.server.db.CreateOrganization(t.Context(), foreign))
	foreignPath := "/api/v1/admin/orgs/" + foreign.ID + "/configuration/groups"
	for _, suffix := range []string{"/context", "/revisions"} {
		response := f.request(t, f.admin, http.MethodGet, foreignPath+suffix, nil)
		require.Equal(t, http.StatusForbidden, response.Code, response.Body.String())
	}
	response := f.request(t, f.admin, http.MethodGet, "/api/v1/admin/configuration/platform/context", nil)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	// A platform allowlist also cannot elevate a tenant's read-only role.
	readonly, err := f.server.jwtService.ValidateAccessToken(f.readonly)
	require.NoError(t, err)
	human, err := f.server.jwtService.IssueAccessTokenForPrincipal(readonly.Subject, true, auth.PrincipalHuman, nil)
	require.NoError(t, err)
	f.server.config.PlatformAdminSubjects = append(f.server.config.PlatformAdminSubjects, readonly.Subject)
	response = f.request(t, human, http.MethodGet, f.base()+"/context", nil)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var out apimodels.ConfigurationContext
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &out))
	require.False(t, out.Viewer.CanActivate)
	err = f.server.db.WithTx(t.Context(), func(tx *db.Tx) error {
		return f.server.authorizeConfigurationActivation(t.Context(), tx, db.ConfigurationActivation{Scope: configuration.Scope{Kind: "organization", ID: f.orgID}, Actor: db.ConfigurationActor{UserID: f.readonlyUserID, ExternalID: readonly.Subject, PrincipalKind: "human"}})
	})
	require.ErrorIs(t, err, db.ErrConfigurationForbidden)
}
