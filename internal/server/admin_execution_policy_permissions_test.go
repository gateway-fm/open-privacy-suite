package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// Exercise the production scoping middleware with already authenticated role
// facts. The exception is a registered route capability, never a URL substring
// or a permission to perform arbitrary POST requests.
func TestExecutionPolicyReadonlyPreparationScope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Server{}
	for _, mount := range []string{"/api/v1/admin", "/api/admin"} {
		t.Run(mount, func(t *testing.T) {
			r := gin.New()
			r.Use(func(c *gin.Context) {
				c.Set("auth_method", "jwt_admin")
				c.Set("admin_org_ids", []string{"other-full-org"})
				c.Set("admin_readonly_org_ids", []string{"our-org"})
			}, s.orgScopingMiddleware())
			for _, route := range []string{
				"/orgs/:org_id/execution-policy/revisions",
				"/orgs/:org_id/execution-policy/revisions/:revision_id/simulate",
				"/orgs/:org_id/execution-policy/revisions/:revision_id/activate",
				"/orgs/:org_id/execution-policy/revisions/:revision_id/withdraw",
				"/orgs/:org_id/groups", "/orgs/:org_id/memberships/by-did",
				"/orgs/:org_id/unrelated/execution-policy/revisions",
			} {
				r.POST(mount+route, func(c *gin.Context) { c.Status(http.StatusNoContent) })
			}
			for _, tc := range []struct {
				path string
				want int
			}{
				{"/orgs/our-org/execution-policy/revisions", 204},
				{"/orgs/our-org/execution-policy/revisions/r1/simulate", 204},
				{"/orgs/foreign-org/execution-policy/revisions", 403},
				{"/orgs/our-org/execution-policy/revisions/r1/activate", 403},
				{"/orgs/our-org/execution-policy/revisions/r1/withdraw", 403},
				{"/orgs/our-org/groups", 403},
				{"/orgs/our-org/memberships/by-did", 403},
				{"/orgs/our-org/unrelated/execution-policy/revisions", 403},
			} {
				rec := httptest.NewRecorder()
				r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, mount+tc.path, strings.NewReader("{}")))
				require.Equal(t, tc.want, rec.Code, tc.path+": "+rec.Body.String())
			}
		})
	}
}
