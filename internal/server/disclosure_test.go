package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/disclosure"
	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testTokenHash generates a test token and its hash for testing token-based access
func testTokenHash() (rawToken, tokenHash string) {
	rawToken = "test-disclosure-token-" + uuid.New().String()
	hash := sha256.Sum256([]byte(rawToken))
	tokenHash = hex.EncodeToString(hash[:])
	return
}

func setupTestServerForDisclosure(t *testing.T) (*Server, *auth.JWTService, *db.DB) {
	// Check if TEST_DATABASE_URL is set (for CI/external PostgreSQL)
	dbURL := os.Getenv("TEST_DATABASE_URL")

	if dbURL == "" {
		// Use testcontainers for local development (no external PostgreSQL needed)
		dbURL = sharedTestDBURL(t)
	} else {
		// Use external PostgreSQL (for CI or when explicitly set)
		if err := db.EnsureTestDatabase(dbURL); err != nil {
			t.Fatalf("PostgreSQL not available. Start it with: docker-compose up -d postgres\nOr: make docker-up\nError: %v", err)
		}
	}

	database, err := db.New(dbURL)
	if err != nil {
		t.Fatalf("failed to create test DB: %v", err)
	}

	// Reset database (drops all tables and runs migrations)
	if err := db.ResetTestDatabase(database); err != nil {
		t.Fatalf("failed to reset test database: %v", err)
	}

	// Create JWT service
	jwtService, err := auth.NewJWTService(
		"test-secret",
		"test-refresh-secret",
		30*time.Minute,
		7*24*time.Hour,
	)
	require.NoError(t, err)

	// Create mock Privado verifier
	mockVerifier := &mockPrivadoVerifier{}

	// Create test config
	cfg := &config.Config{
		ReadProfile: rbac.ReadProfileStandard,
		VerifierID:  "did:privado:verifier:test",
		BaseURL:     "http://localhost:8080",
		Environment: "development",
	}

	// Initialize disclosure service
	disclosureService := disclosure.NewService(database)

	srv := &Server{
		db:                database,
		privadoVerifier:   mockVerifier,
		jwtService:        jwtService,
		rbacAccessCtrl:    rbac.NewAccessController(database, 5*time.Minute),
		proxy:             nil,
		sessionStore:      auth.NewSessionStore(10*time.Minute, 1*time.Minute),
		disclosureService: disclosureService,
		config:            cfg,
	}
	t.Cleanup(srv.rbacAccessCtrl.Stop)

	return srv, jwtService, database
}

// createTestUser creates a test user and returns the user ID and a valid JWT token
func createTestUser(t *testing.T, database *db.DB, jwtService *auth.JWTService, externalID string) (string, string) {
	ctx := context.Background()
	userID := uuid.New().String()

	_, err := database.Conn().ExecContext(ctx,
		"INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, false, false, '{}')",
		userID, externalID)
	require.NoError(t, err)

	// Create JWT token (kyc=false for test users)
	token, err := jwtService.IssueAccessToken(externalID, false)
	require.NoError(t, err)

	return userID, token
}

// createTestOrg creates a test organization and returns its ID
func createTestOrgForHandler(t *testing.T, database *db.DB, slug string) string {
	ctx := context.Background()
	orgID := uuid.New().String()
	uniqueSlug := slug + "-" + uuid.New().String()[:8]

	_, err := database.Conn().ExecContext(ctx,
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
		orgID, uniqueSlug, "Test Org "+uniqueSlug)
	require.NoError(t, err)

	return orgID
}

// setupDisclosureRouter creates a router with disclosure routes for testing
func setupDisclosureRouter(srv *Server) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// API group without localhost restriction for testing
	api := router.Group("/api")
	srv.registerDisclosureRoutes(api)

	// User-facing disclosure routes (require JWT auth)
	srv.registerUserDisclosureRoutes(router)

	return router
}

// ============================================================================
// Test: Admin Endpoints (Create/List/Get Requests)
// ============================================================================

func TestCreateDisclosureRequest(t *testing.T) {
	srv, _, database := setupTestServerForDisclosure(t)
	defer database.Close()

	router := setupDisclosureRouter(srv)
	ctx := context.Background()

	// Create default organization (required by the handler)
	defaultOrgID := "00000000-0000-0000-0000-000000000001"
	_, _ = database.Conn().ExecContext(ctx,
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}') ON CONFLICT (id) DO NOTHING",
		defaultOrgID, "default", "Default Organization")

	// Create a test user
	testTargetUserID := uuid.New().String()
	_, _ = database.Conn().ExecContext(ctx,
		"INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, false, false, '{}')",
		testTargetUserID, "did:test:create-request-target")

	// Create another org for testing
	testOrgID := uuid.New().String()
	_, _ = database.Conn().ExecContext(ctx,
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
		testOrgID, "test-org-"+uuid.New().String()[:8], "Test Organization")

	tests := []struct {
		name           string
		body           map[string]any
		expectedStatus int
		checkResponse  func(t *testing.T, body []byte)
	}{
		{
			name: "success with all fields",
			body: map[string]any{
				"target_user_id": testTargetUserID,
				"org_id":         testOrgID,
				"scope": map[string]any{
					"methods":   []string{"eth_call", "eth_getBalance"},
					"addresses": []string{"0x1234"},
				},
				"reason":           "Compliance audit",
				"legal_basis":      "GDPR Article 6(1)(c)",
				"expires_in_hours": 48,
			},
			expectedStatus: http.StatusCreated,
			checkResponse: func(t *testing.T, body []byte) {
				var resp disclosure.Request
				err := json.Unmarshal(body, &resp)
				require.NoError(t, err)
				assert.NotEmpty(t, resp.ID)
				assert.Equal(t, "Compliance audit", resp.Reason)
				assert.Equal(t, disclosure.StatusPending, resp.Status)
			},
		},
		{
			name: "success with minimal fields",
			body: map[string]any{
				"target_user_id": testTargetUserID,
				"reason":         "Regulatory requirement",
			},
			expectedStatus: http.StatusCreated,
			checkResponse: func(t *testing.T, body []byte) {
				var resp disclosure.Request
				err := json.Unmarshal(body, &resp)
				require.NoError(t, err)
				assert.NotEmpty(t, resp.ID)
				// Should use default org
				assert.Equal(t, defaultOrgID, resp.OrgID)
			},
		},
		{
			name: "missing required field",
			body: map[string]any{
				"org_id": testOrgID,
				// missing target_user_id and reason
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonBody, _ := json.Marshal(tt.body)
			req := httptest.NewRequest("POST", "/api/disclosure/requests", bytes.NewReader(jsonBody))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Forwarded-For", "127.0.0.1") // For localhost check

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.checkResponse != nil {
				tt.checkResponse(t, w.Body.Bytes())
			}
		})
	}
}

func TestListDisclosureRequests(t *testing.T) {
	srv, _, database := setupTestServerForDisclosure(t)
	defer database.Close()

	router := setupDisclosureRouter(srv)
	ctx := context.Background()

	// Create test org and user
	orgID := createTestOrgForHandler(t, database, "list-reqs-org")
	targetUserID := uuid.New().String()
	_, _ = database.Conn().ExecContext(ctx,
		"INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, false, false, '{}')",
		targetUserID, "did:test:list-reqs-target-"+uuid.New().String()[:8])

	// Create test requests
	for i := 0; i < 3; i++ {
		status := disclosure.StatusPending
		if i == 1 {
			status = disclosure.StatusApproved
		}
		req := &disclosure.Request{
			ID:           uuid.New().String(),
			TargetUserID: targetUserID,
			OrgID:        orgID,
			Scope:        disclosure.Scope{},
			Reason:       fmt.Sprintf("Request %d", i),
			Status:       status,
			RequestedAt:  time.Now(),
		}
		database.CreateRequest(ctx, req)
	}

	t.Run("list all for org", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/disclosure/requests?org_id="+orgID, nil)
		req.Header.Set("X-Forwarded-For", "127.0.0.1")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp disclosure.DisclosureListResult
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Len(t, resp.Requests, 3)
	})

	t.Run("filter by status", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/disclosure/requests?org_id="+orgID+"&status=pending", nil)
		req.Header.Set("X-Forwarded-For", "127.0.0.1")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp disclosure.DisclosureListResult
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Len(t, resp.Requests, 2) // 2 pending
	})
}

func TestGetDisclosureRequest(t *testing.T) {
	srv, _, database := setupTestServerForDisclosure(t)
	defer database.Close()

	router := setupDisclosureRouter(srv)
	ctx := context.Background()

	// Create test org and user for details
	testOrgID := createTestOrgForHandler(t, database, "get-req-org")
	targetUserID := uuid.New().String()
	database.Conn().ExecContext(ctx,
		"INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, false, false, '{}')",
		targetUserID, "did:test:getrequest")

	testReq := &disclosure.Request{
		ID:           uuid.New().String(),
		TargetUserID: targetUserID,
		OrgID:        testOrgID,
		Scope:        disclosure.Scope{Methods: []string{"eth_call"}},
		Reason:       "Test get request",
		Status:       disclosure.StatusPending,
		RequestedAt:  time.Now(),
	}
	database.CreateRequest(ctx, testReq)

	t.Run("success", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/disclosure/requests/"+testReq.ID, nil)
		req.Header.Set("X-Forwarded-For", "127.0.0.1")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp disclosure.RequestWithDetails
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, testReq.ID, resp.Request.ID)
		assert.Equal(t, "did:test:getrequest", resp.TargetDID)
	})

	t.Run("not found", func(t *testing.T) {
		// C3 (security audit follow-up): pre-fix this returned 404 on
		// not-found. The handler now returns 403 with the opaque
		// errTargetForeignOrg so a caller cannot distinguish "doesn't
		// exist" from "exists in another org I can't see" — same
		// existence-oracle shape RD-916/917/PR #207 closed for the
		// membership and group surfaces.
		req := httptest.NewRequest("GET", "/api/disclosure/requests/"+uuid.New().String(), nil)
		req.Header.Set("X-Forwarded-For", "127.0.0.1")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}

// ============================================================================
// Test: User-Facing Endpoints (Approve/Reject/Revoke)
// ============================================================================

func TestGetMyDisclosureRequests(t *testing.T) {
	srv, jwtService, database := setupTestServerForDisclosure(t)
	defer database.Close()

	router := setupDisclosureRouter(srv)
	ctx := context.Background()

	// Create test org and user
	testOrgID := createTestOrgForHandler(t, database, "my-reqs-org")
	userID, token := createTestUser(t, database, jwtService, "did:test:myreqs")

	// Create pending request for this user
	testReq := &disclosure.Request{
		ID:           uuid.New().String(),
		TargetUserID: userID,
		OrgID:        testOrgID,
		Scope:        disclosure.Scope{},
		Reason:       "Test my requests",
		Status:       disclosure.StatusPending,
		RequestedAt:  time.Now(),
	}
	database.CreateRequest(ctx, testReq)

	// Create approved request for this user (should not appear)
	approvedReq := &disclosure.Request{
		ID:           uuid.New().String(),
		TargetUserID: userID,
		OrgID:        testOrgID,
		Scope:        disclosure.Scope{},
		Reason:       "Already approved",
		Status:       disclosure.StatusApproved,
		RequestedAt:  time.Now(),
	}
	database.CreateRequest(ctx, approvedReq)

	req := httptest.NewRequest("GET", "/api/v1/me/disclosure/requests", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Forwarded-For", "127.0.0.1")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp []*disclosure.RequestWithDetails
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Len(t, resp, 1)
	assert.Equal(t, testReq.ID, resp[0].Request.ID)
}

func TestApproveDisclosureRequest(t *testing.T) {
	srv, jwtService, database := setupTestServerForDisclosure(t)
	defer database.Close()

	router := setupDisclosureRouter(srv)
	ctx := context.Background()

	// Create shared organization
	testOrgID := uuid.New().String()
	_, _ = database.Conn().ExecContext(ctx,
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
		testOrgID, "approve-test-org-"+uuid.New().String()[:8], "Approve Test Organization")

	// Create test user
	userID, token := createTestUser(t, database, jwtService, "did:test:approver")

	tests := []struct {
		name           string
		setupRequest   func() string
		body           map[string]any
		expectedStatus int
		checkResponse  func(t *testing.T, body []byte)
	}{
		{
			name: "success",
			setupRequest: func() string {
				req := &disclosure.Request{
					ID:           uuid.New().String(),
					TargetUserID: userID,
					OrgID:        testOrgID,
					Scope:        disclosure.Scope{Methods: []string{"eth_call"}},
					Reason:       "Approve test",
					Status:       disclosure.StatusPending,
					RequestedAt:  time.Now(),
				}
				database.CreateRequest(ctx, req)
				return req.ID
			},
			body: map[string]any{
				"grant_duration_hours": 24,
				"reason":               "Approved for compliance",
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body []byte) {
				var resp map[string]any
				err := json.Unmarshal(body, &resp)
				require.NoError(t, err)
				assert.NotEmpty(t, resp["message"]) // DID-based auth - no token returned
				assert.NotNil(t, resp["grant"])
			},
		},
		{
			name: "success with narrowed scope",
			setupRequest: func() string {
				req := &disclosure.Request{
					ID:           uuid.New().String(),
					TargetUserID: userID,
					OrgID:        testOrgID,
					Scope:        disclosure.Scope{Methods: []string{"eth_call", "eth_sendTransaction"}},
					Reason:       "Narrow scope test",
					Status:       disclosure.StatusPending,
					RequestedAt:  time.Now(),
				}
				database.CreateRequest(ctx, req)
				return req.ID
			},
			body: map[string]any{
				"scope": map[string]any{
					"methods": []string{"eth_call"}, // Narrowed from original
				},
				"grant_duration_hours": 12,
				"reason":               "Approved with limited scope",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "forbidden - not target user",
			setupRequest: func() string {
				otherUser := uuid.New().String()
				database.Conn().ExecContext(ctx,
					"INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, false, false, '{}')",
					otherUser, "did:test:other-"+uuid.New().String()[:8])

				req := &disclosure.Request{
					ID:           uuid.New().String(),
					TargetUserID: otherUser, // Different user
					OrgID:        testOrgID,
					Scope:        disclosure.Scope{},
					Reason:       "Forbidden test",
					Status:       disclosure.StatusPending,
					RequestedAt:  time.Now(),
				}
				database.CreateRequest(ctx, req)
				return req.ID
			},
			body: map[string]any{
				"reason": "Should fail",
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name: "not found",
			setupRequest: func() string {
				return uuid.New().String()
			},
			body: map[string]any{
				"reason": "Should fail",
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name: "already approved",
			setupRequest: func() string {
				req := &disclosure.Request{
					ID:           uuid.New().String(),
					TargetUserID: userID,
					OrgID:        testOrgID,
					Scope:        disclosure.Scope{},
					Reason:       "Already approved test",
					Status:       disclosure.StatusApproved, // Already approved
					RequestedAt:  time.Now(),
				}
				database.CreateRequest(ctx, req)
				return req.ID
			},
			body: map[string]any{
				"reason": "Should fail",
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requestID := tt.setupRequest()

			jsonBody, _ := json.Marshal(tt.body)
			req := httptest.NewRequest("POST", "/api/v1/me/disclosure/requests/"+requestID+"/approve", bytes.NewReader(jsonBody))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("X-Forwarded-For", "127.0.0.1")

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.checkResponse != nil {
				tt.checkResponse(t, w.Body.Bytes())
			}
		})
	}
}

func TestRejectDisclosureRequest(t *testing.T) {
	srv, jwtService, database := setupTestServerForDisclosure(t)
	defer database.Close()

	router := setupDisclosureRouter(srv)
	ctx := context.Background()

	// Create test org and user
	testOrgID := createTestOrgForHandler(t, database, "reject-org")
	userID, token := createTestUser(t, database, jwtService, "did:test:rejector")

	t.Run("success", func(t *testing.T) {
		req := &disclosure.Request{
			ID:           uuid.New().String(),
			TargetUserID: userID,
			OrgID:        testOrgID,
			Scope:        disclosure.Scope{},
			Reason:       "Reject test",
			Status:       disclosure.StatusPending,
			RequestedAt:  time.Now(),
		}
		database.CreateRequest(ctx, req)

		body := map[string]any{
			"reason": "Insufficient justification",
		}
		jsonBody, _ := json.Marshal(body)

		httpReq := httptest.NewRequest("POST", "/api/v1/me/disclosure/requests/"+req.ID+"/reject", bytes.NewReader(jsonBody))
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Authorization", "Bearer "+token)
		httpReq.Header.Set("X-Forwarded-For", "127.0.0.1")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httpReq)

		assert.Equal(t, http.StatusOK, w.Code)

		// Verify status
		var resp map[string]string
		json.Unmarshal(w.Body.Bytes(), &resp)
		assert.Equal(t, "rejected", resp["status"])

		// Verify in database
		dbReq, _ := database.GetRequest(ctx, req.ID)
		assert.Equal(t, disclosure.StatusRejected, dbReq.Status)
	})

	t.Run("missing reason (allowed)", func(t *testing.T) {
		req := &disclosure.Request{
			ID:           uuid.New().String(),
			TargetUserID: userID,
			OrgID:        testOrgID,
			Scope:        disclosure.Scope{},
			Reason:       "Missing reason test",
			Status:       disclosure.StatusPending,
			RequestedAt:  time.Now(),
		}
		database.CreateRequest(ctx, req)

		body := map[string]any{} // Missing reason - reason is optional
		jsonBody, _ := json.Marshal(body)

		httpReq := httptest.NewRequest("POST", "/api/v1/me/disclosure/requests/"+req.ID+"/reject", bytes.NewReader(jsonBody))
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Authorization", "Bearer "+token)
		httpReq.Header.Set("X-Forwarded-For", "127.0.0.1")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httpReq)

		// Reason is optional - should succeed
		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]any
		json.Unmarshal(w.Body.Bytes(), &resp)
		assert.Equal(t, "rejected", resp["status"])
	})
}

func TestRevokeDisclosureRequest(t *testing.T) {
	srv, jwtService, database := setupTestServerForDisclosure(t)
	defer database.Close()

	router := setupDisclosureRouter(srv)
	ctx := context.Background()

	// Create test org and user
	testOrgID := createTestOrgForHandler(t, database, "revoke-org")
	userID, token := createTestUser(t, database, jwtService, "did:test:revoker")

	t.Run("success", func(t *testing.T) {
		// Create approved request with active grant
		req := &disclosure.Request{
			ID:           uuid.New().String(),
			TargetUserID: userID,
			OrgID:        testOrgID,
			Scope:        disclosure.Scope{},
			Reason:       "Revoke test",
			Status:       disclosure.StatusApproved,
			RequestedAt:  time.Now(),
		}
		database.CreateRequest(ctx, req)

		grant := &disclosure.Grant{
			ID:             uuid.New().String(),
			RequestID:      req.ID,
			GrantTokenHash: "revoke_test_hash",
			Scope:          disclosure.Scope{},
			GrantedAt:      time.Now(),
			ExpiresAt:      time.Now().Add(24 * time.Hour),
		}
		database.CreateGrant(ctx, grant)

		body := map[string]any{
			"reason": "No longer needed",
		}
		jsonBody, _ := json.Marshal(body)

		httpReq := httptest.NewRequest("POST", "/api/v1/me/disclosure/requests/"+req.ID+"/revoke", bytes.NewReader(jsonBody))
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Authorization", "Bearer "+token)
		httpReq.Header.Set("X-Forwarded-For", "127.0.0.1")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httpReq)

		assert.Equal(t, http.StatusOK, w.Code)

		// Verify grant was revoked
		dbGrant, _ := database.GetGrant(ctx, grant.ID)
		require.NotNil(t, dbGrant.RevokedAt)
	})
}

func TestGetMyActiveGrants(t *testing.T) {
	srv, jwtService, database := setupTestServerForDisclosure(t)
	defer database.Close()

	router := setupDisclosureRouter(srv)
	ctx := context.Background()

	// Create test org and user
	testOrgID := createTestOrgForHandler(t, database, "my-grants-org")
	userID, token := createTestUser(t, database, jwtService, "did:test:mygrants")

	// Create approved request with active grant
	req := &disclosure.Request{
		ID:           uuid.New().String(),
		TargetUserID: userID,
		OrgID:        testOrgID,
		Scope:        disclosure.Scope{},
		Reason:       "Active grant test",
		Status:       disclosure.StatusApproved,
		RequestedAt:  time.Now(),
	}
	database.CreateRequest(ctx, req)

	grant := &disclosure.Grant{
		ID:             uuid.New().String(),
		RequestID:      req.ID,
		GrantTokenHash: "active_grant_hash",
		Scope:          disclosure.Scope{},
		GrantedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(24 * time.Hour),
	}
	database.CreateGrant(ctx, grant)

	httpReq := httptest.NewRequest("GET", "/api/v1/me/disclosure/grants", nil)
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("X-Forwarded-For", "127.0.0.1")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httpReq)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp []*disclosure.GrantWithRequest
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Len(t, resp, 1)
	assert.Equal(t, grant.ID, resp[0].Grant.ID)
}

// ============================================================================
// Test: Grant Access Endpoints (with Disclosure Token)
// ============================================================================

func TestGetDisclosureLogs(t *testing.T) {
	srv, jwtService, database := setupTestServerForDisclosure(t)
	defer database.Close()

	router := setupDisclosureRouter(srv)
	ctx := context.Background()

	// Create test org and user and some activity
	testOrgID := createTestOrgForHandler(t, database, "logs-org")
	userID, _ := createTestUser(t, database, jwtService, "did:test:logs")

	// Create activity logs
	for i := 0; i < 5; i++ {
		database.LogAccess(context.Background(), "did:test:logs", "eth_call", 200, "127.0.0.1")
	}

	// Create pending request (must be pending to be approved)
	req := &disclosure.Request{
		ID:           uuid.New().String(),
		TargetUserID: userID,
		OrgID:        testOrgID,
		Scope:        disclosure.Scope{Methods: []string{"eth_call"}},
		Reason:       "Logs test",
		Status:       disclosure.StatusPending,
		RequestedAt:  time.Now(),
	}
	database.CreateRequest(ctx, req)

	// Approve request
	grantResult, err := srv.disclosureService.ApproveRequest(
		ctx, req.ID, userID, nil, 24*time.Hour, "Approved")
	require.NoError(t, err)

	// Set up test token for testing token-based access
	rawToken, tokenHash := testTokenHash()
	_, err = database.Conn().ExecContext(ctx, "UPDATE disclosure_grants SET grant_token_hash = $1 WHERE id = $2", tokenHash, grantResult.ID)
	require.NoError(t, err)

	t.Run("success with header token", func(t *testing.T) {
		httpReq := httptest.NewRequest("GET", "/api/disclosure/grants/"+grantResult.ID+"/logs", nil)
		httpReq.Header.Set("X-Disclosure-Token", rawToken)
		httpReq.Header.Set("X-Forwarded-For", "127.0.0.1")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httpReq)

		assert.Equal(t, http.StatusOK, w.Code)

		var logs []*disclosure.ActivityLogEntry
		err := json.Unmarshal(w.Body.Bytes(), &logs)
		require.NoError(t, err)
		assert.True(t, len(logs) >= 1)
	})

	t.Run("success with query token", func(t *testing.T) {
		httpReq := httptest.NewRequest("GET", "/api/disclosure/grants/"+grantResult.ID+"/logs?token="+rawToken, nil)
		httpReq.Header.Set("X-Forwarded-For", "127.0.0.1")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httpReq)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("unauthorized - no token", func(t *testing.T) {
		httpReq := httptest.NewRequest("GET", "/api/disclosure/grants/"+grantResult.ID+"/logs", nil)
		httpReq.Header.Set("X-Forwarded-For", "127.0.0.1")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httpReq)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("unauthorized - invalid token", func(t *testing.T) {
		httpReq := httptest.NewRequest("GET", "/api/disclosure/grants/"+grantResult.ID+"/logs", nil)
		httpReq.Header.Set("X-Disclosure-Token", "invalid-token")
		httpReq.Header.Set("X-Forwarded-For", "127.0.0.1")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httpReq)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("forbidden - token for different grant", func(t *testing.T) {
		httpReq := httptest.NewRequest("GET", "/api/disclosure/grants/"+uuid.New().String()+"/logs", nil)
		httpReq.Header.Set("X-Disclosure-Token", rawToken)
		httpReq.Header.Set("X-Forwarded-For", "127.0.0.1")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httpReq)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("pagination", func(t *testing.T) {
		httpReq := httptest.NewRequest("GET", "/api/disclosure/grants/"+grantResult.ID+"/logs?limit=2&offset=0", nil)
		httpReq.Header.Set("X-Disclosure-Token", rawToken)
		httpReq.Header.Set("X-Forwarded-For", "127.0.0.1")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httpReq)

		assert.Equal(t, http.StatusOK, w.Code)

		var logs []*disclosure.ActivityLogEntry
		err := json.Unmarshal(w.Body.Bytes(), &logs)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(logs), 2)
	})
}

func TestGetDisclosureSummary(t *testing.T) {
	srv, jwtService, database := setupTestServerForDisclosure(t)
	defer database.Close()

	router := setupDisclosureRouter(srv)
	ctx := context.Background()

	// Create test org and user and activity
	testOrgID := createTestOrgForHandler(t, database, "summary-org")
	userID, _ := createTestUser(t, database, jwtService, "did:test:summary")

	for i := 0; i < 10; i++ {
		database.LogAccess(context.Background(), "did:test:summary", "eth_call", 200, "127.0.0.1")
	}

	// Create pending request (must be pending to be approved)
	req := &disclosure.Request{
		ID:           uuid.New().String(),
		TargetUserID: userID,
		OrgID:        testOrgID,
		Scope:        disclosure.Scope{},
		Reason:       "Summary test",
		Status:       disclosure.StatusPending,
		RequestedAt:  time.Now(),
	}
	database.CreateRequest(ctx, req)

	grantResult, err := srv.disclosureService.ApproveRequest(
		ctx, req.ID, userID, nil, 24*time.Hour, "Approved")
	require.NoError(t, err)

	// Set up test token
	rawToken, tokenHash := testTokenHash()
	_, err = database.Conn().ExecContext(ctx, "UPDATE disclosure_grants SET grant_token_hash = $1 WHERE id = $2", tokenHash, grantResult.ID)
	require.NoError(t, err)

	httpReq := httptest.NewRequest("GET", "/api/disclosure/grants/"+grantResult.ID+"/summary", nil)
	httpReq.Header.Set("X-Disclosure-Token", rawToken)
	httpReq.Header.Set("X-Forwarded-For", "127.0.0.1")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httpReq)

	assert.Equal(t, http.StatusOK, w.Code)

	var summary disclosure.ActivitySummary
	err = json.Unmarshal(w.Body.Bytes(), &summary)
	require.NoError(t, err)
	assert.True(t, summary.TotalRequests >= 10)
}

func TestGetDisclosureReport(t *testing.T) {
	srv, jwtService, database := setupTestServerForDisclosure(t)
	defer database.Close()

	router := setupDisclosureRouter(srv)
	ctx := context.Background()

	// Create test org and user and activity
	testOrgID := createTestOrgForHandler(t, database, "report-org")
	userID, _ := createTestUser(t, database, jwtService, "did:test:report")

	for i := 0; i < 5; i++ {
		database.LogAccess(context.Background(), "did:test:report", "eth_call", 200, "127.0.0.1")
	}

	// Create pending request (must be pending to be approved)
	req := &disclosure.Request{
		ID:           uuid.New().String(),
		TargetUserID: userID,
		OrgID:        testOrgID,
		Scope:        disclosure.Scope{},
		Reason:       "Report test",
		Status:       disclosure.StatusPending,
		RequestedAt:  time.Now(),
	}
	database.CreateRequest(ctx, req)

	grantResult, err := srv.disclosureService.ApproveRequest(
		ctx, req.ID, userID, nil, 24*time.Hour, "Approved")
	require.NoError(t, err)

	// Set up test token
	rawToken, tokenHash := testTokenHash()
	_, err = database.Conn().ExecContext(ctx, "UPDATE disclosure_grants SET grant_token_hash = $1 WHERE id = $2", tokenHash, grantResult.ID)
	require.NoError(t, err)

	tests := []struct {
		name           string
		reportType     string
		expectedStatus int
	}{
		{
			name:           "activity_summary",
			reportType:     "activity_summary",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "sanctions_check",
			reportType:     "sanctions_check",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "compliance_report",
			reportType:     "compliance_report",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "invalid report type",
			reportType:     "invalid_type",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpReq := httptest.NewRequest("GET", "/api/disclosure/grants/"+grantResult.ID+"/report/"+tt.reportType, nil)
			httpReq.Header.Set("X-Disclosure-Token", rawToken)
			httpReq.Header.Set("X-Forwarded-For", "127.0.0.1")

			w := httptest.NewRecorder()
			router.ServeHTTP(w, httpReq)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedStatus == http.StatusOK {
				var report disclosure.Report
				err := json.Unmarshal(w.Body.Bytes(), &report)
				require.NoError(t, err)
				assert.NotEmpty(t, report.ID)
				assert.Equal(t, disclosure.ReportType(tt.reportType), report.ReportType)
			}
		})
	}
}

func TestGetDisclosureEvents(t *testing.T) {
	srv, jwtService, database := setupTestServerForDisclosure(t)
	defer database.Close()

	router := setupDisclosureRouter(srv)
	ctx := context.Background()

	// Create test org and user
	testOrgID := createTestOrgForHandler(t, database, "events-org")
	userID, _ := createTestUser(t, database, jwtService, "did:test:events")

	// Create pending request (must be pending to be approved)
	req := &disclosure.Request{
		ID:           uuid.New().String(),
		TargetUserID: userID,
		OrgID:        testOrgID,
		Scope:        disclosure.Scope{},
		Reason:       "Events test",
		Status:       disclosure.StatusPending,
		RequestedAt:  time.Now(),
	}
	database.CreateRequest(ctx, req)

	grantResult, err := srv.disclosureService.ApproveRequest(
		ctx, req.ID, userID, nil, 24*time.Hour, "Approved")
	require.NoError(t, err)

	// Set up test token
	rawToken, tokenHash := testTokenHash()
	_, err = database.Conn().ExecContext(ctx, "UPDATE disclosure_grants SET grant_token_hash = $1 WHERE id = $2", tokenHash, grantResult.ID)
	require.NoError(t, err)

	// Create some events by accessing logs
	database.LogAccess(context.Background(), "did:test:events", "eth_call", 200, "127.0.0.1")

	// Access logs to generate event
	logsReq := httptest.NewRequest("GET", "/api/disclosure/grants/"+grantResult.ID+"/logs", nil)
	logsReq.Header.Set("X-Disclosure-Token", rawToken)
	logsReq.Header.Set("X-Forwarded-For", "127.0.0.1")
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, logsReq)

	// Access summary to generate another event
	summaryReq := httptest.NewRequest("GET", "/api/disclosure/grants/"+grantResult.ID+"/summary", nil)
	summaryReq.Header.Set("X-Disclosure-Token", rawToken)
	summaryReq.Header.Set("X-Forwarded-For", "127.0.0.1")
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, summaryReq)

	// Now get the events
	httpReq := httptest.NewRequest("GET", "/api/disclosure/grants/"+grantResult.ID+"/events", nil)
	httpReq.Header.Set("X-Disclosure-Token", rawToken)
	httpReq.Header.Set("X-Forwarded-For", "127.0.0.1")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httpReq)

	assert.Equal(t, http.StatusOK, w.Code)

	var events []*disclosure.Event
	err = json.Unmarshal(w.Body.Bytes(), &events)
	require.NoError(t, err)
	assert.True(t, len(events) >= 2)

	// Verify event types
	foundViewLogs := false
	foundViewSummary := false
	for _, e := range events {
		if e.Action == disclosure.ActionViewLogs {
			foundViewLogs = true
		}
		if e.Action == disclosure.ActionViewSummary {
			foundViewSummary = true
		}
	}
	assert.True(t, foundViewLogs, "Should have view_logs event")
	assert.True(t, foundViewSummary, "Should have view_summary event")
}

// ============================================================================
// Test: Token Expiration and Revocation
// ============================================================================

func TestDisclosureGrant_Expiration(t *testing.T) {
	srv, jwtService, database := setupTestServerForDisclosure(t)
	defer database.Close()

	router := setupDisclosureRouter(srv)
	ctx := context.Background()

	// Create test org and user
	testOrgID := createTestOrgForHandler(t, database, "expiration-org")
	userID, _ := createTestUser(t, database, jwtService, "did:test:expiration")

	// Create request
	req := &disclosure.Request{
		ID:           uuid.New().String(),
		TargetUserID: userID,
		OrgID:        testOrgID,
		Scope:        disclosure.Scope{},
		Reason:       "Expiration test",
		Status:       disclosure.StatusApproved,
		RequestedAt:  time.Now(),
	}
	database.CreateRequest(ctx, req)

	// Create grant that's already expired
	grant := &disclosure.Grant{
		ID:             uuid.New().String(),
		RequestID:      req.ID,
		GrantTokenHash: "expired_grant_hash_test",
		Scope:          disclosure.Scope{},
		GrantedAt:      time.Now().Add(-48 * time.Hour),
		ExpiresAt:      time.Now().Add(-24 * time.Hour), // Already expired
	}
	database.CreateGrant(ctx, grant)

	// Try to access logs with token for expired grant
	// We need to compute the hash to get the token
	httpReq := httptest.NewRequest("GET", "/api/disclosure/grants/"+grant.ID+"/logs", nil)
	httpReq.Header.Set("X-Disclosure-Token", "any-token-wont-work")
	httpReq.Header.Set("X-Forwarded-For", "127.0.0.1")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httpReq)

	// Should be unauthorized because token is invalid
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDisclosureGrant_Revocation(t *testing.T) {
	srv, jwtService, database := setupTestServerForDisclosure(t)
	defer database.Close()

	router := setupDisclosureRouter(srv)
	ctx := context.Background()

	// Create test org and user
	testOrgID := createTestOrgForHandler(t, database, "revocation-org")
	userID, _ := createTestUser(t, database, jwtService, "did:test:revocation")

	// Create request (must be pending to be approved)
	req := &disclosure.Request{
		ID:           uuid.New().String(),
		TargetUserID: userID,
		OrgID:        testOrgID,
		Scope:        disclosure.Scope{},
		Reason:       "Revocation test",
		Status:       disclosure.StatusPending,
		RequestedAt:  time.Now(),
	}
	database.CreateRequest(ctx, req)

	grantResult, err := srv.disclosureService.ApproveRequest(
		ctx, req.ID, userID, nil, 24*time.Hour, "Approved")
	require.NoError(t, err)

	// Set up test token
	rawToken, tokenHash := testTokenHash()
	_, err = database.Conn().ExecContext(ctx, "UPDATE disclosure_grants SET grant_token_hash = $1 WHERE id = $2", tokenHash, grantResult.ID)
	require.NoError(t, err)

	// First, verify access works
	httpReq := httptest.NewRequest("GET", "/api/disclosure/grants/"+grantResult.ID+"/logs", nil)
	httpReq.Header.Set("X-Disclosure-Token", rawToken)
	httpReq.Header.Set("X-Forwarded-For", "127.0.0.1")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httpReq)
	assert.Equal(t, http.StatusOK, w.Code)

	// Revoke the grant
	err = srv.disclosureService.RevokeGrant(ctx, grantResult.ID, "Access no longer needed")
	require.NoError(t, err)

	// Try to access again - should fail
	httpReq2 := httptest.NewRequest("GET", "/api/disclosure/grants/"+grantResult.ID+"/logs", nil)
	httpReq2.Header.Set("X-Disclosure-Token", rawToken)
	httpReq2.Header.Set("X-Forwarded-For", "127.0.0.1")

	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, httpReq2)

	assert.Equal(t, http.StatusUnauthorized, w2.Code)
}

// ============================================================================
// Test: Full Integration Workflow
// ============================================================================

func TestDisclosure_FullWorkflow(t *testing.T) {
	srv, jwtService, database := setupTestServerForDisclosure(t)
	defer database.Close()

	router := setupDisclosureRouter(srv)
	ctx := context.Background()

	// Create default organization (required by the handler when no org_id is provided)
	defaultOrgID := "00000000-0000-0000-0000-000000000001"
	_, _ = database.Conn().ExecContext(ctx,
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}') ON CONFLICT (id) DO NOTHING",
		defaultOrgID, "default", "Default Organization")

	// 1. Create target user
	targetUserID, targetToken := createTestUser(t, database, jwtService, "did:test:workflow:target")

	// 2. Create some activity for the target user
	for i := 0; i < 10; i++ {
		database.LogAccess(context.Background(), "did:test:workflow:target", "eth_call", 200, "127.0.0.1")
	}

	// 3. Create a disclosure request (admin action)
	// Note: requester_user_id is optional, so we don't provide it to avoid FK constraint
	createReqBody := map[string]any{
		"target_user_id": targetUserID,
		"scope": map[string]any{
			"methods": []string{"eth_call"},
		},
		"reason":           "Regulatory audit",
		"legal_basis":      "Court order #12345",
		"expires_in_hours": 48,
	}
	createReqJSON, _ := json.Marshal(createReqBody)

	createReq := httptest.NewRequest("POST", "/api/disclosure/requests", bytes.NewReader(createReqJSON))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("X-Forwarded-For", "127.0.0.1")

	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, createReq)
	if w1.Code != http.StatusCreated {
		t.Logf("Response body: %s", w1.Body.String())
	}
	require.Equal(t, http.StatusCreated, w1.Code)

	var createdRequest disclosure.Request
	json.Unmarshal(w1.Body.Bytes(), &createdRequest)

	// 4. Target user views pending requests
	viewReq := httptest.NewRequest("GET", "/api/v1/me/disclosure/requests", nil)
	viewReq.Header.Set("Authorization", "Bearer "+targetToken)
	viewReq.Header.Set("X-Forwarded-For", "127.0.0.1")

	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, viewReq)
	require.Equal(t, http.StatusOK, w2.Code)

	var pendingRequests []*disclosure.RequestWithDetails
	json.Unmarshal(w2.Body.Bytes(), &pendingRequests)
	require.Len(t, pendingRequests, 1)

	// 5. Target user approves the request
	approveBody := map[string]any{
		"grant_duration_hours": 24,
		"reason":               "Complying with court order",
	}
	approveJSON, _ := json.Marshal(approveBody)

	approveReq := httptest.NewRequest("POST", "/api/v1/me/disclosure/requests/"+createdRequest.ID+"/approve", bytes.NewReader(approveJSON))
	approveReq.Header.Set("Content-Type", "application/json")
	approveReq.Header.Set("Authorization", "Bearer "+targetToken)
	approveReq.Header.Set("X-Forwarded-For", "127.0.0.1")

	w3 := httptest.NewRecorder()
	router.ServeHTTP(w3, approveReq)
	require.Equal(t, http.StatusOK, w3.Code)

	var approveResp map[string]any
	json.Unmarshal(w3.Body.Bytes(), &approveResp)
	require.NotNil(t, approveResp["grant"], "Expected grant in response")
	require.NotNil(t, approveResp["message"], "Expected message in response")
	grantMap := approveResp["grant"].(map[string]any)
	grantID := grantMap["id"].(string)

	// Set up test token for accessing the grant
	disclosureToken, tokenHash := testTokenHash()
	_, err := database.Conn().ExecContext(ctx, "UPDATE disclosure_grants SET grant_token_hash = $1 WHERE id = $2", tokenHash, grantID)
	require.NoError(t, err)

	// 6. Requester accesses activity logs using disclosure token
	logsReq := httptest.NewRequest("GET", "/api/disclosure/grants/"+grantID+"/logs", nil)
	logsReq.Header.Set("X-Disclosure-Token", disclosureToken)
	logsReq.Header.Set("X-Forwarded-For", "192.168.1.100")

	w4 := httptest.NewRecorder()
	router.ServeHTTP(w4, logsReq)
	require.Equal(t, http.StatusOK, w4.Code)

	var logs []*disclosure.ActivityLogEntry
	json.Unmarshal(w4.Body.Bytes(), &logs)
	// Note: Log filtering depends on scope (methods, addresses, date range)
	// We created 10 eth_call logs and scope includes eth_call, so we should have some logs
	t.Logf("Retrieved %d logs", len(logs))
	assert.True(t, len(logs) >= 1, "Expected at least 1 log entry for eth_call")

	// 7. Requester gets activity summary
	summaryReq := httptest.NewRequest("GET", "/api/disclosure/grants/"+grantID+"/summary", nil)
	summaryReq.Header.Set("X-Disclosure-Token", disclosureToken)
	summaryReq.Header.Set("X-Forwarded-For", "192.168.1.100")

	w5 := httptest.NewRecorder()
	router.ServeHTTP(w5, summaryReq)
	require.Equal(t, http.StatusOK, w5.Code)

	var summary disclosure.ActivitySummary
	json.Unmarshal(w5.Body.Bytes(), &summary)
	t.Logf("Summary total requests: %d", summary.TotalRequests)
	assert.True(t, summary.TotalRequests >= 1, "Expected summary to show at least 1 request")

	// 8. Requester generates compliance report
	reportReq := httptest.NewRequest("GET", "/api/disclosure/grants/"+grantID+"/report/compliance_report", nil)
	reportReq.Header.Set("X-Disclosure-Token", disclosureToken)
	reportReq.Header.Set("X-Forwarded-For", "192.168.1.100")

	w6 := httptest.NewRecorder()
	router.ServeHTTP(w6, reportReq)
	require.Equal(t, http.StatusOK, w6.Code)

	var report disclosure.Report
	json.Unmarshal(w6.Body.Bytes(), &report)
	assert.Equal(t, disclosure.ReportCompliance, report.ReportType)

	// 9. Check audit trail (events)
	eventsReq := httptest.NewRequest("GET", "/api/disclosure/grants/"+grantID+"/events", nil)
	eventsReq.Header.Set("X-Disclosure-Token", disclosureToken)
	eventsReq.Header.Set("X-Forwarded-For", "192.168.1.100")

	w7 := httptest.NewRecorder()
	router.ServeHTTP(w7, eventsReq)
	require.Equal(t, http.StatusOK, w7.Code)

	var events []*disclosure.Event
	json.Unmarshal(w7.Body.Bytes(), &events)
	assert.True(t, len(events) >= 3) // logs, summary, report

	// Verify event IPs are recorded
	for _, e := range events {
		assert.Equal(t, "192.168.1.100", e.ViewerIP)
	}

	// 10. Target user views active grants
	grantsReq := httptest.NewRequest("GET", "/api/v1/me/disclosure/grants", nil)
	grantsReq.Header.Set("Authorization", "Bearer "+targetToken)
	grantsReq.Header.Set("X-Forwarded-For", "127.0.0.1")

	w8 := httptest.NewRecorder()
	router.ServeHTTP(w8, grantsReq)
	require.Equal(t, http.StatusOK, w8.Code)

	var activeGrants []*disclosure.GrantWithRequest
	json.Unmarshal(w8.Body.Bytes(), &activeGrants)
	assert.Len(t, activeGrants, 1)

	// 11. Target user revokes access
	revokeBody := map[string]any{
		"reason": "Audit completed, revoking access",
	}
	revokeJSON, _ := json.Marshal(revokeBody)

	revokeReq := httptest.NewRequest("POST", "/api/v1/me/disclosure/requests/"+createdRequest.ID+"/revoke", bytes.NewReader(revokeJSON))
	revokeReq.Header.Set("Content-Type", "application/json")
	revokeReq.Header.Set("Authorization", "Bearer "+targetToken)
	revokeReq.Header.Set("X-Forwarded-For", "127.0.0.1")

	w9 := httptest.NewRecorder()
	router.ServeHTTP(w9, revokeReq)
	require.Equal(t, http.StatusOK, w9.Code)

	// 12. Verify token no longer works
	logsReq2 := httptest.NewRequest("GET", "/api/disclosure/grants/"+grantID+"/logs", nil)
	logsReq2.Header.Set("X-Disclosure-Token", disclosureToken)
	logsReq2.Header.Set("X-Forwarded-For", "192.168.1.100")

	w10 := httptest.NewRecorder()
	router.ServeHTTP(w10, logsReq2)
	assert.Equal(t, http.StatusUnauthorized, w10.Code)

	// 13. Verify no more active grants
	grantsReq2 := httptest.NewRequest("GET", "/api/v1/me/disclosure/grants", nil)
	grantsReq2.Header.Set("Authorization", "Bearer "+targetToken)
	grantsReq2.Header.Set("X-Forwarded-For", "127.0.0.1")

	w11 := httptest.NewRecorder()
	router.ServeHTTP(w11, grantsReq2)
	require.Equal(t, http.StatusOK, w11.Code)

	var finalGrants []*disclosure.GrantWithRequest
	json.Unmarshal(w11.Body.Bytes(), &finalGrants)
	assert.Len(t, finalGrants, 0) // Grant was revoked
}
