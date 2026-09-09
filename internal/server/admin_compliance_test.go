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

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/compliance"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testServerCompliance wraps Server with a router for compliance integration testing.
type testServerCompliance struct {
	*Server
	router   *gin.Engine
	mockNode *httptest.Server
}

// complianceSeedData holds the IDs created by seedComplianceTestData.
type complianceSeedData struct {
	orgID   string
	userID  string
	groupID string
}

func setupTestServerForCompliance(t *testing.T) *testServerCompliance {
	dbURL := os.Getenv("TEST_DATABASE_URL")

	if dbURL == "" {
		dbURL = sharedTestDBURL(t)
	} else {
		if err := db.EnsureTestDatabase(dbURL); err != nil {
			t.Fatalf("PostgreSQL not available: %v", err)
		}
	}

	database, err := db.New(dbURL)
	if err != nil {
		t.Fatalf("failed to create test DB: %v", err)
	}

	if err := database.Migrate(context.Background()); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	ctx := context.Background()
	conn := database.Conn()

	// Clean compliance tables
	conn.ExecContext(ctx, "DELETE FROM compliance_logs")
	conn.ExecContext(ctx, "DELETE FROM travel_rule_records")
	conn.ExecContext(ctx, "DELETE FROM token_prices")
	conn.ExecContext(ctx, "DELETE FROM compliance_config")
	conn.ExecContext(ctx, "DELETE FROM sanctioned_addresses")

	// Clean RBAC tables
	conn.ExecContext(ctx, "DELETE FROM rbac_audit_log")
	conn.ExecContext(ctx, "DELETE FROM effective_permissions_cache")
	conn.ExecContext(ctx, "DELETE FROM contract_grants")
	conn.ExecContext(ctx, "DELETE FROM contracts")
	conn.ExecContext(ctx, "DELETE FROM preregistered_addresses")
	conn.ExecContext(ctx, "DELETE FROM user_memberships")
	conn.ExecContext(ctx, "DELETE FROM group_access")
	conn.ExecContext(ctx, "DELETE FROM groups")
	conn.ExecContext(ctx, "DELETE FROM users")
	conn.ExecContext(ctx, "DELETE FROM organizations")

	t.Cleanup(func() {
		database.Close()
	})

	cfg := &config.Config{
		NodeURL:     "http://localhost:8545",
		JWTSecret:   "test-secret-key-for-jwt-signing-123",
		BaseURL:     "http://localhost:8080",
		Environment: "development",
	}

	jwtService, err := auth.NewJWTService(
		cfg.JWTSecret,
		"test-refresh-secret",
		30*time.Minute,
		7*24*time.Hour,
	)
	require.NoError(t, err)

	rbacAccessCtrl := rbac.NewAccessController(database, 5*time.Minute)
	t.Cleanup(rbacAccessCtrl.Stop)
	checker := compliance.NewChecker(database, 24*time.Hour, 15*time.Minute)

	// Mock node that returns a canned JSON-RPC response
	mockNode := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x1"}`))
	}))
	t.Cleanup(mockNode.Close)

	proxySvc := proxy.New(mockNode.URL)

	server := &Server{
		db:                database,
		config:            cfg,
		jwtService:        jwtService,
		rbacAccessCtrl:    rbacAccessCtrl,
		complianceChecker: checker,
		proxy:             proxySvc,
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.SetTrustedProxies([]string{"127.0.0.1", "::1", "172.16.0.0/12", "192.168.0.0/16", "10.0.0.0/8"})

	api := router.Group("/api/v1/admin")
	api.Use(server.localhostOnlyMiddleware())
	api.POST("/test-request", server.handleTestRequest)

	return &testServerCompliance{
		Server:   server,
		router:   router,
		mockNode: mockNode,
	}
}

func seedComplianceTestData(t *testing.T, database *db.DB) complianceSeedData {
	t.Helper()

	ctx := context.Background()
	conn := database.Conn()

	orgID := uuid.New().String()
	userID := uuid.New().String()
	groupID := uuid.New().String()
	groupAccessID := uuid.New().String()
	membershipID := uuid.New().String()

	// Create organization
	_, err := conn.ExecContext(ctx,
		`INSERT INTO organizations (id, slug, name, settings, created_at, updated_at)
		 VALUES ($1, 'comp-test', 'Compliance Test Org', '{}', NOW(), NOW())`,
		orgID)
	require.NoError(t, err)

	// Create user with external_id matching the default test identity
	_, err = conn.ExecContext(ctx,
		`INSERT INTO users (id, external_id, kyc, banned, note, metadata, created_at, updated_at)
		 VALUES ($1, 'test:dashboard', true, false, '', '{}', NOW(), NOW())`,
		userID)
	require.NoError(t, err)

	// Create group
	_, err = conn.ExecContext(ctx,
		`INSERT INTO groups (id, org_id, slug, name, path, created_at, updated_at)
		 VALUES ($1, $2, 'default', 'Default Group', 'default', NOW(), NOW())`,
		groupID, orgID)
	require.NoError(t, err)

	// Create group access with claims and allowed methods
	_, err = conn.ExecContext(ctx,
		`INSERT INTO group_access (id, group_id, claims, allowed_methods, created_at, updated_at)
		 VALUES ($1, $2, '{read,write}', '{eth_sendTransaction,eth_blockNumber,eth_call}', NOW(), NOW())`,
		groupAccessID, groupID)
	require.NoError(t, err)

	// Create membership
	_, err = conn.ExecContext(ctx,
		`INSERT INTO user_memberships (id, user_id, group_id, created_at)
		 VALUES ($1, $2, $3, NOW())`,
		membershipID, userID, groupID)
	require.NoError(t, err)

	// Enable compliance for the org
	_, err = conn.ExecContext(ctx,
		`INSERT INTO compliance_config (id, org_id, enabled, threshold_fiat, created_at, updated_at)
		 VALUES ($1, $2, true, 1000, NOW(), NOW())`,
		uuid.New().String(), orgID)
	require.NoError(t, err)

	// Create native ETH token price: symbol "ETH", decimals 18, price $2000
	_, err = conn.ExecContext(ctx,
		`INSERT INTO token_prices (id, org_id, token_address, symbol, decimals, price_fiat, created_at, updated_at)
		 VALUES ($1, $2, 'native', 'ETH', 18, 2000, NOW(), NOW())`,
		uuid.New().String(), orgID)
	require.NoError(t, err)

	return complianceSeedData{
		orgID:   orgID,
		userID:  userID,
		groupID: groupID,
	}
}

func TestHandleTestRequest_ComplianceCheck(t *testing.T) {
	ts := setupTestServerForCompliance(t)
	seed := seedComplianceTestData(t, ts.db)

	fromAddr := "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
	toAddr := "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"

	tests := []struct {
		name           string
		setup          func(t *testing.T)
		teardown       func(t *testing.T)
		body           apimodels.TestRequestInput
		expectedStatus int
		bodyContains   string
	}{
		{
			name: "eth_sendTransaction below threshold is allowed",
			body: apimodels.TestRequestInput{
				Method: "eth_sendTransaction",
				OrgID:  seed.orgID,
				Params: []interface{}{
					map[string]interface{}{
						"from":  fromAddr,
						"to":    toAddr,
						"value": "0x16345785d8a0000", // 0.1 ETH = $200, below $1000
					},
				},
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "eth_sendTransaction above threshold denied without travel rule record",
			body: apimodels.TestRequestInput{
				Method: "eth_sendTransaction",
				OrgID:  seed.orgID,
				Params: []interface{}{
					map[string]interface{}{
						"from":  fromAddr,
						"to":    toAddr,
						"value": "0xde0b6b3a7640000", // 1 ETH = $2000, above $1000
					},
				},
			},
			expectedStatus: http.StatusForbidden,
			bodyContains:   "compliance denied",
		},
		{
			name: "eth_sendTransaction above threshold allowed with travel rule record",
			setup: func(t *testing.T) {
				t.Helper()
				ctx := context.Background()
				_, err := ts.db.Conn().ExecContext(ctx,
					`INSERT INTO travel_rule_records
					 (id, org_id, originator_user_id, originator_data, beneficiary_data,
					  transfer_type, token_address, beneficiary_address, amount_wei, amount_fiat,
					  expires_at, created_at)
					 VALUES ($1, $2, $3, '{}', '{}', 'eth', NULL, $4, '1000000000000000000', 2000, $5, NOW())`,
					uuid.New().String(), seed.orgID, seed.userID, toAddr, time.Now().Add(24*time.Hour))
				require.NoError(t, err)
			},
			body: apimodels.TestRequestInput{
				Method: "eth_sendTransaction",
				OrgID:  seed.orgID,
				Params: []interface{}{
					map[string]interface{}{
						"from":  fromAddr,
						"to":    toAddr,
						"value": "0xde0b6b3a7640000", // 1 ETH = $2000
					},
				},
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "eth_blockNumber bypasses compliance",
			body: apimodels.TestRequestInput{
				Method: "eth_blockNumber",
				OrgID:  seed.orgID,
				Params: []interface{}{},
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "eth_sendTransaction to sanctioned address denied",
			setup: func(t *testing.T) {
				t.Helper()
				ctx := context.Background()
				_, err := ts.db.Conn().ExecContext(ctx,
					`INSERT INTO sanctioned_addresses (id, org_id, address, reason, source, created_at, updated_at)
					 VALUES ($1, $2, $3, 'test sanction', 'test', NOW(), NOW())`,
					uuid.New().String(), seed.orgID, toAddr)
				require.NoError(t, err)
			},
			teardown: func(t *testing.T) {
				t.Helper()
				ctx := context.Background()
				ts.db.Conn().ExecContext(ctx, "DELETE FROM sanctioned_addresses")
			},
			body: apimodels.TestRequestInput{
				Method: "eth_sendTransaction",
				OrgID:  seed.orgID,
				Params: []interface{}{
					map[string]interface{}{
						"from":  fromAddr,
						"to":    toAddr,
						"value": "0x16345785d8a0000", // 0.1 ETH, below threshold but sanctioned
					},
				},
			},
			expectedStatus: http.StatusForbidden,
			bodyContains:   "sanctioned",
		},
		{
			name: "compliance check skipped when checker is nil",
			setup: func(t *testing.T) {
				t.Helper()
				ts.complianceChecker = nil
			},
			teardown: func(t *testing.T) {
				t.Helper()
				ts.complianceChecker = compliance.NewChecker(ts.db, 24*time.Hour, 15*time.Minute)
			},
			body: apimodels.TestRequestInput{
				Method: "eth_sendTransaction",
				OrgID:  seed.orgID,
				Params: []interface{}{
					map[string]interface{}{
						"from":  fromAddr,
						"to":    toAddr,
						"value": "0xde0b6b3a7640000", // 1 ETH = $2000, above threshold
					},
				},
			},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setup != nil {
				tc.setup(t)
			}
			if tc.teardown != nil {
				defer tc.teardown(t)
			}

			jsonBody, err := json.Marshal(tc.body)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/test-request", bytes.NewReader(jsonBody))
			req.RemoteAddr = "127.0.0.1:12345"
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			ts.router.ServeHTTP(w, req)

			assert.Equal(t, tc.expectedStatus, w.Code, "response body: %s", w.Body.String())

			if tc.bodyContains != "" {
				assert.Contains(t, w.Body.String(), tc.bodyContains)
			}
		})
	}
}

func TestUpdateComplianceConfig_UnknownPricePolicy(t *testing.T) {
	ts := setupTestServerForCompliance(t)
	seed := seedComplianceTestData(t, ts.db)

	ctx := context.Background()
	orgID := seed.orgID

	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantPolicy compliance.UnknownPricePolicy
	}{
		{
			name:       "valid allowed policy",
			body:       `{"unknown_price_policy": "allowed"}`,
			wantStatus: http.StatusOK,
			wantPolicy: compliance.UnknownPriceAllowed,
		},
		{
			name:       "valid forbidden policy",
			body:       `{"unknown_price_policy": "forbidden"}`,
			wantStatus: http.StatusOK,
			wantPolicy: compliance.UnknownPriceForbidden,
		},
		{
			name:       "invalid policy rejected",
			body:       `{"unknown_price_policy": "ignore"}`,
			wantStatus: http.StatusBadRequest,
			wantPolicy: compliance.UnknownPriceForbidden, // should not have changed
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodPut, "/", bytes.NewBuffer([]byte(tc.body)))
			c.Params = gin.Params{gin.Param{Key: "org_id", Value: orgID}}

			ts.updateComplianceConfig(c)

			assert.Equal(t, tc.wantStatus, w.Code)

			// Verify DB
			cfg, err := ts.db.GetComplianceConfig(ctx, orgID)
			require.NoError(t, err)
			assert.Equal(t, tc.wantPolicy, cfg.UnknownPricePolicy)
		})
	}
}

// TestUpdateComplianceConfig_Currency locks in the RD-1158 fix: a tier-2 org
// admin can set their org's currency through the per-org config endpoint
// (previously this required the super-admin base-currency switch and 403'd from
// the dashboard), an invalid currency is rejected with 400 (not silently
// ignored), and the value is normalised + persisted.
func TestUpdateComplianceConfig_Currency(t *testing.T) {
	ts := setupTestServerForCompliance(t)
	seed := seedComplianceTestData(t, ts.db)

	ctx := context.Background()
	orgID := seed.orgID

	tests := []struct {
		name         string
		body         string
		wantStatus   int
		wantCurrency string
	}{
		{
			name:         "valid currency persists",
			body:         `{"currency": "eur"}`,
			wantStatus:   http.StatusOK,
			wantCurrency: "eur",
		},
		{
			name:         "uppercase is normalised to lowercase",
			body:         `{"currency": "GBP"}`,
			wantStatus:   http.StatusOK,
			wantCurrency: "gbp",
		},
		{
			name:         "unsupported currency rejected, prior value unchanged",
			body:         `{"currency": "btc"}`,
			wantStatus:   http.StatusBadRequest,
			wantCurrency: "gbp", // unchanged from the previous case
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodPut, "/", bytes.NewBuffer([]byte(tc.body)))
			c.Params = gin.Params{gin.Param{Key: "org_id", Value: orgID}}

			ts.updateComplianceConfig(c)

			assert.Equal(t, tc.wantStatus, w.Code, "body: %s", w.Body.String())

			cfg, err := ts.db.GetComplianceConfig(ctx, orgID)
			require.NoError(t, err)
			assert.Equal(t, tc.wantCurrency, cfg.Currency)
		})
	}
}

// createBareOrg inserts an organization with NO compliance_config row and
// returns its id. The compliance config is created lazily by the first PUT
// /compliance/config — this is the exact precondition RD-1111 needs (the bug
// only fires when no config row exists yet).
func createBareOrg(t *testing.T, database *db.DB, slug string) string {
	t.Helper()
	orgID := uuid.New().String()
	_, err := database.Conn().ExecContext(context.Background(),
		`INSERT INTO organizations (id, slug, name, settings, created_at, updated_at)
		 VALUES ($1, $2, $3, '{}', NOW(), NOW())`,
		orgID, slug, slug)
	require.NoError(t, err)
	return orgID
}

// TestUpdateComplianceConfig_CreateWithoutUnknownPricePolicy is the RD-1111
// regression test. Creating a brand-new compliance config (no existing row)
// WITHOUT unknown_price_policy must NOT 500. The server must default the field
// to the fail-closed value ("forbidden") so an unknown token price BLOCKS
// transfers — and a raw DB CHECK-constraint error must never reach the client.
//
// Note: TestUpdateComplianceConfig_UnknownPricePolicy above does NOT cover this
// because seedComplianceTestData pre-creates a compliance_config row, so the
// isNew (config == nil) branch is never exercised there.
func TestUpdateComplianceConfig_CreateWithoutUnknownPricePolicy(t *testing.T) {
	ts := setupTestServerForCompliance(t)
	ctx := context.Background()

	t.Run("create without policy defaults to fail-closed forbidden", func(t *testing.T) {
		orgID := createBareOrg(t, ts.db, "rd1111-default")

		// Sanity: no config row exists yet — this is the bug precondition.
		pre, err := ts.db.GetComplianceConfig(ctx, orgID)
		require.NoError(t, err)
		require.Nil(t, pre, "org must have no compliance_config row before the first PUT")

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		// Body intentionally omits unknown_price_policy (matches the QA repro).
		c.Request = httptest.NewRequest(http.MethodPut, "/",
			bytes.NewBufferString(`{"enabled": true, "threshold_fiat": 5000}`))
		c.Params = gin.Params{gin.Param{Key: "org_id", Value: orgID}}

		ts.updateComplianceConfig(c)

		// The core of RD-1111: must be 200, not 500.
		require.Equal(t, http.StatusOK, w.Code,
			"first PUT without unknown_price_policy must succeed, got body: %s", w.Body.String())
		assert.NotContains(t, w.Body.String(), "constraint",
			"raw DB constraint error must never reach the client")

		// Stored policy must be the fail-closed default. UnknownPriceForbidden is
		// the value the checker treats as "block on unknown price" (see
		// checker.go: priceFiat<0 + UnknownPriceForbidden => denied in enforce
		// mode), so the safe default does NOT silently allow unpriced transfers.
		cfg, err := ts.db.GetComplianceConfig(ctx, orgID)
		require.NoError(t, err)
		require.NotNil(t, cfg)
		assert.Equal(t, compliance.UnknownPriceForbidden, cfg.UnknownPricePolicy)
		assert.True(t, cfg.Enabled)
		assert.Equal(t, float64(5000), cfg.ThresholdFiat)
		// EnforcementMode is also coalesced to the safe default (enforce).
		assert.Equal(t, compliance.EnforcementEnforce, cfg.EnforcementMode)
	})

	t.Run("create with explicit allowed policy is honored", func(t *testing.T) {
		// Defaulting must not override an explicit opt-in to the fail-open policy.
		orgID := createBareOrg(t, ts.db, "rd1111-explicit-allowed")

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPut, "/",
			bytes.NewBufferString(`{"enabled": true, "unknown_price_policy": "allowed"}`))
		c.Params = gin.Params{gin.Param{Key: "org_id", Value: orgID}}

		ts.updateComplianceConfig(c)

		require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
		cfg, err := ts.db.GetComplianceConfig(ctx, orgID)
		require.NoError(t, err)
		require.NotNil(t, cfg)
		assert.Equal(t, compliance.UnknownPriceAllowed, cfg.UnknownPricePolicy)
	})

	t.Run("create with invalid policy returns clean 400 not 500", func(t *testing.T) {
		// Genuinely-invalid input on CREATE must be a clean 400 (opaque), never a
		// 500 leaking a DB CHECK error, and must not persist a row.
		orgID := createBareOrg(t, ts.db, "rd1111-invalid")

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPut, "/",
			bytes.NewBufferString(`{"enabled": true, "unknown_price_policy": "ignore"}`))
		c.Params = gin.Params{gin.Param{Key: "org_id", Value: orgID}}

		ts.updateComplianceConfig(c)

		require.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
		assert.Contains(t, w.Body.String(), "unknown_price_policy must be")
		assert.NotContains(t, w.Body.String(), "constraint")

		// No partial write: the config row must not have been created.
		cfg, err := ts.db.GetComplianceConfig(ctx, orgID)
		require.NoError(t, err)
		assert.Nil(t, cfg, "invalid CREATE must not persist a compliance_config row")
	})
}
