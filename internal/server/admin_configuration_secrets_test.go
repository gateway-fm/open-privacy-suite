package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/configuration"
)

// End to end over the HTTP API: a groups document declares which environment
// variable holds a group's upstream credential. The value never crosses the
// wire in either direction, the rotation endpoint yields to the document, and
// a variable that cannot be resolved refuses the activation by name.
func TestConfigurationGroupCredentialPlaceholderEndToEnd(t *testing.T) {
	f := configurationAPI(t)
	f.server.config.RPCAPIKeyEncryptionKey = []byte(strings.Repeat("k", 32))
	f.server.db.SetConfigurationSecretResolver(configuration.NewEnvSecretResolver(f.server.config.RPCAPIKeyEncryptionKey))
	variable := "OPS_RPC_CREDENTIAL_" + strings.ToUpper(strings.ReplaceAll(f.orgID, "-", "")) + "_PAYMENTS"
	t.Setenv(variable, "wire-secret-value")

	doc := f.document(t)
	group := configuration.Group{ID: uuid.NewString(), Slug: "payments", Name: "Payments", AllowedMethods: []string{"eth_call"}, Claims: []string{}, RpcCredential: &configuration.SecretRef{FromEnv: variable}}
	spec := doc.Spec.(configuration.GroupsSpec)
	spec.Groups = append(spec.Groups, group)
	doc.Spec = spec

	response := f.request(t, f.readonly, http.MethodPost, f.base()+"/revisions", doc)
	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
	require.Contains(t, response.Body.String(), variable)
	require.NotContains(t, response.Body.String(), "wire-secret-value")
	var draft apimodels.ConfigurationRevision
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &draft))

	// Review never resolves anything.
	response = f.request(t, f.readonly, http.MethodPost, f.base()+"/revisions/"+draft.ID+"/simulate", map[string]any{"coactivate": []string{}})
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.NotContains(t, response.Body.String(), "wire-secret-value")

	response = f.request(t, f.reviewer, http.MethodPost, f.base()+"/revisions/"+draft.ID+"/activate", nil)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.NotContains(t, response.Body.String(), "wire-secret-value")

	// The current state renders the placeholder and says the credential is declared.
	response = f.request(t, f.readonly, http.MethodGet, f.base()+"/context", nil)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.Contains(t, response.Body.String(), variable)
	require.Contains(t, response.Body.String(), `"credential":"declared"`)
	require.NotContains(t, response.Body.String(), "wire-secret-value")

	// The stored credential is ciphertext of the variable's value.
	access, err := f.server.db.GetGroupAccess(t.Context(), group.ID)
	require.NoError(t, err)
	require.NotNil(t, access.RPCAPIKey)
	require.NotEqual(t, "wire-secret-value", *access.RPCAPIKey)
	require.NotNil(t, access.RPCAPIKeySource)
	require.Equal(t, variable, *access.RPCAPIKeySource)

	// The rotation endpoint refuses: the document owns this credential now.
	response = f.request(t, f.admin, http.MethodPut, "/api/v1/admin/orgs/"+f.orgID+"/groups/"+group.ID+"/rpc-credential", map[string]any{"rpc_api_key": "operator-typed"})
	require.Equal(t, http.StatusConflict, response.Code, response.Body.String())

	// A later revision whose variable is not set fails closed, naming the variable only.
	missing := "OPS_RPC_CREDENTIAL_" + strings.ToUpper(strings.ReplaceAll(f.orgID, "-", "")) + "_MISSING"
	group.RpcCredential = &configuration.SecretRef{FromEnv: missing}
	doc = f.document(t)
	spec = doc.Spec.(configuration.GroupsSpec)
	for i := range spec.Groups {
		if spec.Groups[i].ID == group.ID {
			spec.Groups[i] = group
		}
	}
	doc.Spec = spec
	response = f.request(t, f.readonly, http.MethodPost, f.base()+"/revisions", doc)
	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &draft))
	response = f.request(t, f.reviewer, http.MethodPost, f.base()+"/revisions/"+draft.ID+"/activate", nil)
	require.Equal(t, http.StatusConflict, response.Code, response.Body.String())
	require.Contains(t, response.Body.String(), missing)
	require.NotContains(t, response.Body.String(), "wire-secret-value")

	// Nothing changed: the previous declaration still stands.
	access, err = f.server.db.GetGroupAccess(t.Context(), group.ID)
	require.NoError(t, err)
	require.Equal(t, variable, *access.RPCAPIKeySource)
}

// A placeholder outside the organisation's own namespace is a client error at
// submit time: it never reaches activation, so it can never read the process
// environment at large or another tenant's variable.
func TestConfigurationGroupCredentialPlaceholderOutsideNamespaceIsRefusedAtSubmit(t *testing.T) {
	f := configurationAPI(t)
	for _, variable := range []string{"JWT_SECRET", "RPC_API_KEY", "OPS_RPC_CREDENTIAL_" + strings.Repeat("A", 32) + "_OTHER_TENANT"} {
		doc := f.document(t)
		spec := doc.Spec.(configuration.GroupsSpec)
		spec.Groups = append(spec.Groups, configuration.Group{ID: uuid.NewString(), Slug: "leak", Name: "Leak", AllowedMethods: []string{"eth_call"}, Claims: []string{}, RpcCredential: &configuration.SecretRef{FromEnv: variable}})
		doc.Spec = spec
		response := f.request(t, f.readonly, http.MethodPost, f.base()+"/revisions", doc)
		require.Equal(t, http.StatusBadRequest, response.Code, "%s: %s", variable, response.Body.String())
	}
}
