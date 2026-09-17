package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/configuration"
	"privacy-proxy/internal/rbac"
)

type configurationAPIFixture struct {
	server                             *Server
	router                             *gin.Engine
	orgID                              string
	readonly, admin, reviewer, service string
	readonlyUserID                     string
}

func configurationAPI(t *testing.T) configurationAPIFixture {
	t.Helper()
	s, _ := setupTestServerForAuth(t)
	t.Cleanup(func() { _ = s.db.Close() })
	s.config.AdminAPIToken = "configuration-bootstrap-test"
	s.db.SetRBACAuditChain(audit.NewHashChain(""))
	org := &rbac.Organization{ID: uuid.NewString(), Slug: "configuration-" + uuid.NewString(), Name: "Configuration API"}
	require.NoError(t, s.db.CreateOrganization(t.Context(), org))
	principal := func(readonly bool, kind auth.PrincipalKind) (string, string) {
		id := uuid.NewString()
		group := &rbac.Group{ID: uuid.NewString(), OrgID: org.ID, Slug: "admins-" + id, Name: "Admins " + id, Path: "admins-" + id, IsOrgAdmin: !readonly, IsOrgReadonlyAdmin: readonly}
		require.NoError(t, s.db.CreateGroup(t.Context(), group))
		_, err := s.db.Conn().ExecContext(t.Context(), `INSERT INTO group_access(id,group_id,allowed_methods,claims) VALUES($1,$2,$3,$4)`, uuid.NewString(), group.ID, []string{"eth_call"}, []string{})
		require.NoError(t, err)
		user := &rbac.User{ID: id, ExternalID: "did:test:" + id}
		require.NoError(t, s.db.CreateUser(t.Context(), user))
		require.NoError(t, s.db.CreateMembership(t.Context(), &rbac.UserMembership{ID: uuid.NewString(), UserID: id, GroupID: group.ID, Source: rbac.MembershipSourceAdmin}))
		token, err := s.jwtService.IssueAccessTokenForPrincipal(user.ExternalID, true, kind, nil)
		require.NoError(t, err)
		return token, id
	}
	f := configurationAPIFixture{server: s, orgID: org.ID}
	f.readonly, f.readonlyUserID = principal(true, auth.PrincipalService)
	f.admin, _ = principal(false, auth.PrincipalHuman)
	f.reviewer, _ = principal(false, auth.PrincipalHuman)
	f.service, _ = principal(false, auth.PrincipalService)
	gin.SetMode(gin.TestMode)
	f.router = gin.New()
	s.registerRBACRoutes(f.router.Group("/api/v1/admin", s.adminAuthMiddleware(), s.orgScopingMiddleware()))
	return f
}
func (f configurationAPIFixture) base() string {
	return "/api/v1/admin/orgs/" + f.orgID + "/configuration/groups"
}
func (f configurationAPIFixture) request(t *testing.T, token, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var raw []byte
	if body != nil {
		raw = mustJSON(t, body)
	}
	return orgAdminGateReq(t, f.router, method, path, token, "", raw)
}
func (f configurationAPIFixture) document(t *testing.T) *configuration.Document {
	t.Helper()
	response := f.request(t, f.readonly, http.MethodGet, f.base()+"/context", nil)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var out struct {
		Source json.RawMessage `json:"source"`
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &out))
	doc, err := configuration.Parse(out.Source)
	require.NoError(t, err)
	return doc
}

func TestConfigurationAPIAuthenticatedDraftReviewAndClosure(t *testing.T) {
	f := configurationAPI(t)
	doc := f.document(t)
	group := configuration.Group{ID: uuid.NewString(), Slug: "payments", Name: "Payments", AllowedMethods: []string{"eth_call"}, Claims: []string{}}
	spec := doc.Spec.(configuration.GroupsSpec)
	spec.Groups = append(spec.Groups, group)
	doc.Spec = spec
	response := f.request(t, f.readonly, http.MethodPost, f.base()+"/revisions", doc)
	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
	var draft apimodels.ConfigurationRevision
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &draft))
	require.NotEmpty(t, draft.ID)
	stored, err := f.server.db.GetGroup(t.Context(), group.ID)
	require.NoError(t, err)
	require.Nil(t, stored)
	response = f.request(t, f.readonly, http.MethodPost, f.base()+"/revisions/"+draft.ID+"/simulate", map[string]any{"coactivate": []string{}})
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var review apimodels.ConfigurationReview
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &review))
	require.NotNil(t, review.GroupDiff)
	for _, token := range []string{f.readonly, f.service} {
		response = f.request(t, token, http.MethodPost, f.base()+"/revisions/"+draft.ID+"/activate", nil)
		require.Equal(t, http.StatusForbidden, response.Code, response.Body.String())
	}
	response = f.request(t, f.reviewer, http.MethodPost, f.base()+"/revisions/"+draft.ID+"/activate", nil)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	stored, err = f.server.db.GetGroup(t.Context(), group.ID)
	require.NoError(t, err)
	require.NotNil(t, stored)
	response = f.request(t, f.admin, http.MethodPost, "/api/v1/admin/orgs/"+f.orgID+"/groups", map[string]any{"slug": "bypass", "name": "Bypass"})
	require.Equal(t, http.StatusConflict, response.Code, response.Body.String())
	f.server.config.RPCAPIKeyEncryptionKey = make([]byte, 32)
	credentialPath := "/api/v1/admin/orgs/" + f.orgID + "/groups/" + group.ID + "/rpc-credential"
	response = f.request(t, f.admin, http.MethodPut, credentialPath, map[string]any{"rpc_api_key": "test-upstream-secret"})
	require.Equal(t, http.StatusNoContent, response.Code, response.Body.String())
	access, err := f.server.db.GetGroupAccess(t.Context(), group.ID)
	require.NoError(t, err)
	require.NotNil(t, access.RPCAPIKey)
	require.NotEqual(t, "test-upstream-secret", *access.RPCAPIKey)
	response = f.request(t, f.admin, http.MethodPut, credentialPath, map[string]any{"rpc_api_key": "other", "claims": []string{"admin"}})
	require.Equal(t, http.StatusBadRequest, response.Code, response.Body.String())
	response = f.request(t, f.readonly, http.MethodPost, "/api/v1/admin/orgs/"+f.orgID+"/memberships/by-did", map[string]any{})
	require.Equal(t, http.StatusForbidden, response.Code)
	response = f.request(t, f.reviewer, http.MethodGet, f.base()+"/revisions/"+draft.ID, nil)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
}

func TestConfigurationAPIRechecksAuthorAuthorityAndScope(t *testing.T) {
	f := configurationAPI(t)
	doc := f.document(t)
	response := f.request(t, f.readonly, http.MethodPost, f.base()+"/revisions", doc)
	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
	var draft apimodels.ConfigurationRevision
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &draft))
	_, err := f.server.db.Conn().ExecContext(t.Context(), `DELETE FROM user_memberships WHERE user_id=$1`, f.readonlyUserID)
	require.NoError(t, err)
	response = f.request(t, f.reviewer, http.MethodPost, f.base()+"/revisions/"+draft.ID+"/activate", nil)
	require.Equal(t, http.StatusForbidden, response.Code, response.Body.String())
	doc.Scope.ID = uuid.NewString()
	response = f.request(t, f.admin, http.MethodPost, f.base()+"/revisions", doc)
	require.Equal(t, http.StatusForbidden, response.Code)
}
