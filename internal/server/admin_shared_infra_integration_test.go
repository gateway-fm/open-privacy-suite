package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// HTTP/DB integration tests for the shared_infrastructure admin API
// (KD-1, follow-up to M5 / RD-915). Boots a Postgres testcontainer,
// runs migrations, mounts the routes, and exercises the full request
// flow.
//
// The dev-mode auth (empty auth_method, no X-Admin-Token configured)
// is treated as super-admin by requireSuperAdmin — same as every
// other admin endpoint test in this package. The jwt-admin rejection
// path is exercised by an explicit middleware injection (see
// TestSharedInfra_JWTAdminRejected).

type testServerSharedInfra struct {
	*Server
	router *gin.Engine
}

func setupTestServerForSharedInfra(t *testing.T) *testServerSharedInfra {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = sharedTestDBURL(t)
	} else if err := db.EnsureTestDatabase(dbURL); err != nil {
		t.Fatalf("PostgreSQL not available: %v", err)
	}

	database, err := db.New(dbURL)
	require.NoError(t, err)
	require.NoError(t, database.Migrate(context.Background()))
	t.Cleanup(func() { database.Close() })

	// Clean state for the table under test.
	conn := database.Conn()
	_, _ = conn.ExecContext(context.Background(), "DELETE FROM shared_infrastructure")

	cfg := &config.Config{
		ReadProfile: rbac.ReadProfileStandard,
		NodeURL:     "http://localhost:8545",
		BaseURL:     "http://localhost:8080",
	}
	jwtSvc, err := auth.NewJWTService("test-secret", "test-refresh", 30*time.Minute, 24*time.Hour)
	require.NoError(t, err)
	rbacCtrl := rbac.NewAccessController(database, 5*time.Minute)
	t.Cleanup(rbacCtrl.Stop)

	gin.SetMode(gin.TestMode)
	router := gin.New()

	srv := &Server{
		db:             database,
		config:         cfg,
		jwtService:     jwtSvc,
		rbacAccessCtrl: rbacCtrl,
		// runtimeTracer left nil — refresh-codehash returns 503
		// without a configured tracer (tested below).
	}
	api := router.Group("/api")
	srv.registerSharedInfraRoutes(api)

	return &testServerSharedInfra{Server: srv, router: router}
}

// withJWTAdmin returns a router that injects auth_method="jwt_admin"
// before delegating to the shared_infra routes. Used to verify the
// super-admin gate denies tier-2 callers.
func withJWTAdmin(srv *Server) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("auth_method", "jwt_admin")
		c.Set("admin_org_ids", []string{"00000000-0000-0000-0000-000000000001"})
		c.Next()
	})
	api := r.Group("/api")
	srv.registerSharedInfraRoutes(api)
	return r
}

const (
	siTestAddr     = "0xe592427a0aece92de3edee1f18e0157c05861564" // Uniswap V3 Router (canonical test value)
	siTestAddrAlt  = "0xc0ffee254729296a45a3885639ac7e10f9d54979"
	siTestCodehash = "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
)

func TestSharedInfra_CRUD(t *testing.T) {
	s := setupTestServerForSharedInfra(t)

	t.Run("ListEmpty", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/shared-infrastructure", nil)
		w := httptest.NewRecorder()
		s.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("Create_NoCodehash", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{
			"address":     siTestAddr,
			"name":        "Uniswap V3 Router",
			"description": "Public DEX router",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/shared-infrastructure", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("Create_Duplicate_Conflict", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{
			"address": siTestAddr,
			"name":    "Duplicate",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/shared-infrastructure", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusConflict, w.Code)
	})

	t.Run("Get_Found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/shared-infrastructure/"+siTestAddr, nil)
		w := httptest.NewRecorder()
		s.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
		var resp rbac.SharedInfrastructure
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, siTestAddr, resp.Address)
		assert.Equal(t, "Uniswap V3 Router", resp.Name)
		assert.Nil(t, resp.Codehash, "no codehash was set on create")
	})

	t.Run("Get_NotFound", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/shared-infrastructure/"+siTestAddrAlt, nil)
		w := httptest.NewRecorder()
		s.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("Update_AddCodehash", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{
			"name":     "Uniswap V3 Router (pinned)",
			"codehash": siTestCodehash,
		})
		req := httptest.NewRequest(http.MethodPut, "/api/shared-infrastructure/"+siTestAddr, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		// Verify via GET.
		req2 := httptest.NewRequest(http.MethodGet, "/api/shared-infrastructure/"+siTestAddr, nil)
		w2 := httptest.NewRecorder()
		s.router.ServeHTTP(w2, req2)
		var resp rbac.SharedInfrastructure
		require.NoError(t, json.Unmarshal(w2.Body.Bytes(), &resp))
		require.NotNil(t, resp.Codehash)
		assert.Equal(t, siTestCodehash, *resp.Codehash)
		assert.Equal(t, "Uniswap V3 Router (pinned)", resp.Name)
	})

	t.Run("Update_NotFound", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{"name": "Nope"})
		req := httptest.NewRequest(http.MethodPut, "/api/shared-infrastructure/"+siTestAddrAlt, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("Delete_Found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/shared-infrastructure/"+siTestAddr, nil)
		w := httptest.NewRecorder()
		s.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("Delete_NotFound", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/shared-infrastructure/"+siTestAddrAlt, nil)
		w := httptest.NewRecorder()
		s.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("RefreshCodehash_TracerNotConfigured", func(t *testing.T) {
		// Re-create the entry so refresh has something to act on.
		body, _ := json.Marshal(map[string]any{"address": siTestAddr, "name": "Tmp"})
		req := httptest.NewRequest(http.MethodPost, "/api/shared-infrastructure", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		s.router.ServeHTTP(httptest.NewRecorder(), req)

		req2 := httptest.NewRequest(http.MethodPost, "/api/shared-infrastructure/"+siTestAddr+"/refresh-codehash", nil)
		w := httptest.NewRecorder()
		s.router.ServeHTTP(w, req2)
		// runtimeTracer is nil in the test fixture → 503 with an
		// operator-actionable message.
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestSharedInfra_BadInput(t *testing.T) {
	s := setupTestServerForSharedInfra(t)

	t.Run("Create_BadAddress", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{"address": "not-an-address", "name": "X"})
		req := httptest.NewRequest(http.MethodPost, "/api/shared-infrastructure", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Create_BadCodehash", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{"address": siTestAddr, "name": "X", "codehash": "0xabc"})
		req := httptest.NewRequest(http.MethodPost, "/api/shared-infrastructure", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Create_MissingName", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{"address": siTestAddr})
		req := httptest.NewRequest(http.MethodPost, "/api/shared-infrastructure", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Get_BadAddress", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/shared-infrastructure/not-an-address", nil)
		w := httptest.NewRecorder()
		s.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Delete_BadAddress", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/shared-infrastructure/not-an-address", nil)
		w := httptest.NewRecorder()
		s.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestSharedInfra_JWTAdminRejected pins the super-admin gate: a
// tier-2 JWT admin (auth_method="jwt_admin" with valid admin_org_ids)
// must be rejected on every endpoint, including the read paths.
// Pre-fix would have been the threat shape from audit C4 (Azure
// tenant CRUD reachable by tier-2 admin via a global-policy table);
// this test guards against the same pattern for shared_infrastructure.
func TestSharedInfra_JWTAdminRejected(t *testing.T) {
	s := setupTestServerForSharedInfra(t)
	router := withJWTAdmin(s.Server)

	tests := []struct {
		method, path string
		body         []byte
	}{
		{http.MethodGet, "/api/shared-infrastructure", nil},
		{http.MethodGet, "/api/shared-infrastructure/" + siTestAddr, nil},
		{http.MethodPost, "/api/shared-infrastructure", []byte(`{"address":"` + siTestAddr + `","name":"X"}`)},
		{http.MethodPut, "/api/shared-infrastructure/" + siTestAddr, []byte(`{"name":"X"}`)},
		{http.MethodDelete, "/api/shared-infrastructure/" + siTestAddr, nil},
		{http.MethodPost, "/api/shared-infrastructure/" + siTestAddr + "/refresh-codehash", nil},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			var body *bytes.Reader
			if tt.body != nil {
				body = bytes.NewReader(tt.body)
			} else {
				body = bytes.NewReader(nil)
			}
			req := httptest.NewRequest(tt.method, tt.path, body)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusForbidden, w.Code,
				"jwt_admin must be rejected on %s %s", tt.method, tt.path)
		})
	}
}

// TestSharedInfra_AddressNormalization confirms that a checksummed
// (mixed-case) address on input matches a lowercase row on lookup.
// Avoids the operator footgun of "I added 0xE592... and now GET
// 0xe592... returns 404".
func TestSharedInfra_AddressNormalization(t *testing.T) {
	s := setupTestServerForSharedInfra(t)

	// Create with a checksummed address.
	checksummed := "0xE592427A0Aece92De3Edee1f18E0157C05861564"
	body, _ := json.Marshal(map[string]any{"address": checksummed, "name": "Uniswap V3 Router"})
	req := httptest.NewRequest(http.MethodPost, "/api/shared-infrastructure", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	// Look up via lowercase — must match.
	req2 := httptest.NewRequest(http.MethodGet, "/api/shared-infrastructure/"+siTestAddr, nil)
	w2 := httptest.NewRecorder()
	s.router.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code)

	// And via uppercase — also matches (read uses LOWER() too).
	req3 := httptest.NewRequest(http.MethodGet, "/api/shared-infrastructure/"+checksummed, nil)
	w3 := httptest.NewRecorder()
	s.router.ServeHTTP(w3, req3)
	assert.Equal(t, http.StatusOK, w3.Code)
}
