package server

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// The function rules of a grant belong to the execution-rules stream (DECISION
// §4 item 10). The database trigger already refuses the write once that stream
// is active; the route must say so with the same 409 the other legacy writers
// use, not an opaque 500 from the trigger.
func TestLegacyGrantWritersCloseWhenExecutionRulesAreManaged(t *testing.T) {
	f := configurationAPI(t)
	base := "/api/v1/admin/orgs/" + f.orgID + "/contracts/0x0000000000000000000000000000000000001300/grants"

	response := f.request(t, f.admin, http.MethodPost, base, map[string]any{"group_id": uuid.NewString()})
	require.NotEqual(t, http.StatusConflict, response.Code, "without an active stream the route reaches its handler: "+response.Body.String())

	_, err := f.server.db.Conn().ExecContext(t.Context(), `INSERT INTO configuration_revisions
		(scope_kind, org_id, kind, revision, base_revision, source, digest, dependencies, status, created_by, activated_by, activated_at)
		VALUES ('organization', $1, 'execution-rules', 1, 0, '{}', 'sha256:'||repeat('0', 64), '{}', 'active', $2, $3, NOW())`,
		f.orgID, f.readonlyUserID, f.readonlyUserID)
	require.NoError(t, err)

	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, base},
		{http.MethodPut, base + "/" + uuid.NewString()},
		{http.MethodDelete, base + "/" + uuid.NewString()},
	} {
		response := f.request(t, f.admin, tc.method, tc.path, map[string]any{"functions": nil})
		require.Equal(t, http.StatusConflict, response.Code, tc.method+" "+tc.path+": "+response.Body.String())
		require.Contains(t, response.Body.String(), "use a configuration revision")
	}
}
