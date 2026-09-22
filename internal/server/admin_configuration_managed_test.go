package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/configuration"
)

// The admin screens need one cheap, honest answer before they offer an edit
// control: is this stream owned by a reviewed document right now? The answer
// must be readable with the same credentials the screens already use — a named
// login or the operator token — and must flip the moment a revision activates.
func TestConfigurationManagedReadFollowsActivation(t *testing.T) {
	f := configurationAPI(t)
	managedPath := f.base() + "/managed"

	read := func(t *testing.T, jwt, adminToken string) apimodels.ConfigurationManaged {
		t.Helper()
		response := orgAdminGateReq(t, f.router, http.MethodGet, managedPath, jwt, adminToken, nil)
		require.Equal(t, http.StatusOK, response.Code, response.Body.String())
		var out apimodels.ConfigurationManaged
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &out))
		return out
	}

	// Nothing active yet: the legacy setters are open, so the screens may edit.
	before := read(t, f.readonly, "")
	require.Equal(t, "groups", before.Kind)
	require.False(t, before.Managed)

	// The full admin token gets the same answer; it is not a named principal,
	// but this is a read of one boolean, not an authoring action.
	require.False(t, read(t, "", f.server.config.AdminAPIToken).Managed)

	// The restricted operator token is refused a tenant's stream state, exactly
	// as every other per-tenant read refuses it.
	f.server.config.OperatorAPIToken = "operator-managed-read-test"
	response := orgAdminGateReq(t, f.router, http.MethodGet, managedPath, "", f.server.config.OperatorAPIToken, nil)
	require.Equal(t, http.StatusForbidden, response.Code, response.Body.String())

	// Draft and activate a groups revision through the normal path.
	doc := f.document(t)
	spec := doc.Spec.(configuration.GroupsSpec)
	spec.Groups = append(spec.Groups, configuration.Group{ID: uuid.NewString(), Slug: "payments", Name: "Payments", AllowedMethods: []string{"eth_call"}, Claims: []string{}})
	doc.Spec = spec
	response = f.request(t, f.readonly, http.MethodPost, f.base()+"/revisions", doc)
	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
	var draft apimodels.ConfigurationRevision
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &draft))
	response = f.request(t, f.reviewer, http.MethodPost, f.base()+"/revisions/"+draft.ID+"/activate", nil)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())

	// Now the stream is managed, for both kinds of caller.
	require.True(t, read(t, f.readonly, "").Managed)
	require.True(t, read(t, "", f.server.config.AdminAPIToken).Managed)

	// Sibling streams are unaffected: only groups was activated.
	response = orgAdminGateReq(t, f.router, http.MethodGet, "/api/v1/admin/orgs/"+f.orgID+"/configuration/contract-registry/managed", f.readonly, "", nil)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var registry apimodels.ConfigurationManaged
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &registry))
	require.Equal(t, "contract-registry", registry.Kind)
	require.False(t, registry.Managed)

	// An unknown stream is a client error, not a silent false.
	response = orgAdminGateReq(t, f.router, http.MethodGet, "/api/v1/admin/orgs/"+f.orgID+"/configuration/nonsense/managed", f.readonly, "", nil)
	require.Equal(t, http.StatusBadRequest, response.Code, response.Body.String())

	// Unauthenticated callers learn nothing.
	response = orgAdminGateReq(t, f.router, http.MethodGet, managedPath, "", "", nil)
	require.Equal(t, http.StatusUnauthorized, response.Code, response.Body.String())
}

// The platform stream's read is for the two principals that manage tenants and
// shared infrastructure: a named human on the platform allowlist and the full
// admin token. An organisation admin must not learn whether the platform
// document is active, and the answer must follow platform activation.
func TestPlatformConfigurationManagedReadFollowsPlatformActivation(t *testing.T) {
	f := configurationAPI(t)
	base := "/api/v1/admin/configuration/platform"
	read := func(t *testing.T, jwt, adminToken string) *httptest.ResponseRecorder {
		t.Helper()
		return orgAdminGateReq(t, f.router, http.MethodGet, base+"/managed", jwt, adminToken, nil)
	}
	decode := func(t *testing.T, response *httptest.ResponseRecorder) apimodels.ConfigurationManaged {
		t.Helper()
		require.Equal(t, http.StatusOK, response.Code, response.Body.String())
		var out apimodels.ConfigurationManaged
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &out))
		require.Equal(t, "platform", out.Kind)
		return out
	}

	// An organisation admin is not a platform principal.
	response := read(t, f.admin, "")
	require.Equal(t, http.StatusForbidden, response.Code, response.Body.String())

	// The full admin token reads it: that is the credential the tenant and
	// shared-infrastructure screens run on.
	require.False(t, decode(t, read(t, "", f.server.config.AdminAPIToken)).Managed)

	// So does a named human on the platform allowlist, once allowlisted.
	for _, token := range []string{f.admin, f.reviewer} {
		claims, err := f.server.jwtService.ValidateAccessToken(token)
		require.NoError(t, err)
		f.server.config.PlatformAdminSubjects = append(f.server.config.PlatformAdminSubjects, claims.Subject)
	}
	require.False(t, decode(t, read(t, f.admin, "")).Managed)

	// Activate a platform revision through the normal path; both readers see it.
	response = f.request(t, f.admin, http.MethodGet, base+"/context", nil)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var context apimodels.ConfigurationContext
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &context))
	doc, err := configuration.Parse(context.Source)
	require.NoError(t, err)
	response = f.request(t, f.admin, http.MethodPost, base+"/revisions", doc)
	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
	var draft apimodels.ConfigurationRevision
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &draft))
	response = f.request(t, f.reviewer, http.MethodPost, base+"/revisions/"+draft.ID+"/activate", nil)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.True(t, decode(t, read(t, f.admin, "")).Managed)
	require.True(t, decode(t, read(t, "", f.server.config.AdminAPIToken)).Managed)
}
