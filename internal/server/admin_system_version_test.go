package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/version"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-1023: GET /api/v1/admin/system/version returns the build identity of the
// running binary. The endpoint shares the /api/v1/admin/system group's gates
// (localhost + admin auth) with the eth-call-tracing handlers, which are
// covered by admin_system_test.go — here we assert the handler faithfully
// reflects the build-time version package into the JSON response.
func TestHandleGetVersion_ReflectsBuildInfo(t *testing.T) {
	ts := setupTestServerForRBAC(t)

	// Override the linker-injected vars to prove the response is sourced
	// from the version package (and restore so sibling tests are unaffected).
	origV, origC, origB := version.Version, version.Commit, version.BuildTime
	t.Cleanup(func() { version.Version, version.Commit, version.BuildTime = origV, origC, origB })
	version.Version = "v1.2.3-test"
	version.Commit = "deadbee"
	version.BuildTime = "2026-06-01T12:34:56Z"

	// Mount the route on the bare test router exactly as server.go wires it
	// under the system group (the auth middleware itself is exercised by the
	// eth-call-tracing tests, so we focus on handler correctness here).
	ts.router.GET("/api/v1/admin/system/version", ts.Server.handleGetVersion)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/system/version", nil)
	w := httptest.NewRecorder()
	ts.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp apimodels.SystemVersionResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	assert.Equal(t, "v1.2.3-test", resp.Version)
	assert.Equal(t, "deadbee", resp.Commit)
	assert.Equal(t, "2026-06-01T12:34:56Z", resp.BuildTime)

	// JSON keys are the operator-facing contract — pin them.
	var raw map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))
	assert.Contains(t, raw, "version")
	assert.Contains(t, raw, "commit")
	assert.Contains(t, raw, "build_time")
}
