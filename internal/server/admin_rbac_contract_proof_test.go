package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testServerContractProof wraps Server with a router and a controllable mock node.
type testServerContractProof struct {
	*Server
	router   *gin.Engine
	mockNode *httptest.Server

	// mockReceiptHandler controls the RPC response for getTransactionReceipt and getCode.
	// Set this before each test to control node responses.
	mockHandler func(w http.ResponseWriter, r *http.Request)
}

func setupTestServerForContractProof(t *testing.T) *testServerContractProof {
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

	// Clean relevant tables
	ctx := context.Background()
	conn := database.Conn()
	conn.ExecContext(ctx, "DELETE FROM rbac_audit_log")
	conn.ExecContext(ctx, "DELETE FROM effective_permissions_cache")
	conn.ExecContext(ctx, "DELETE FROM contract_grants")
	conn.ExecContext(ctx, "DELETE FROM contracts")
	conn.ExecContext(ctx, "DELETE FROM preregistered_addresses")
	conn.ExecContext(ctx, "DELETE FROM user_memberships")
	conn.ExecContext(ctx, "DELETE FROM group_access")
	conn.ExecContext(ctx, "DELETE FROM allowed_azure_tenants")
	conn.ExecContext(ctx, "DELETE FROM groups")
	conn.ExecContext(ctx, "DELETE FROM users")
	conn.ExecContext(ctx, "DELETE FROM organizations")

	t.Cleanup(func() {
		database.Close()
	})

	ts := &testServerContractProof{}

	// Mock node: dispatch based on ts.mockHandler
	mockNode := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ts.mockHandler != nil {
			ts.mockHandler(w, r)
			return
		}
		// Default: return generic success
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x1"}`))
	}))
	t.Cleanup(mockNode.Close)

	cfg := &config.Config{
		ReadProfile: rbac.ReadProfileStandard,
		NodeURL:     mockNode.URL,
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
	proxySvc := proxy.New(mockNode.URL)

	gin.SetMode(gin.TestMode)
	router := gin.New()

	server := &Server{
		db:             database,
		config:         cfg,
		jwtService:     jwtService,
		rbacAccessCtrl: rbacAccessCtrl,
		proxy:          proxySvc,
	}

	// Register RBAC routes
	api := router.Group("/api")
	server.registerRBACRoutes(api)

	ts.Server = server
	ts.router = router
	ts.mockNode = mockNode

	return ts
}

func createTestOrgForProof(t *testing.T, ts *testServerContractProof, slug string) string {
	body := map[string]any{
		"slug":     slug,
		"name":     slug + " Org",
		"settings": map[string]any{},
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/orgs", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	ts.router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	var response map[string]any
	json.Unmarshal(w.Body.Bytes(), &response)
	return response["id"].(string)
}

// rpcRequestBody parses the JSON-RPC method from the HTTP request body.
func rpcRequestBody(r *http.Request) (method string, params []interface{}) {
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()
	var req map[string]interface{}
	json.Unmarshal(body, &req)
	method, _ = req["method"].(string)
	if p, ok := req["params"].([]interface{}); ok {
		params = p
	}
	return
}

// validReceiptAndCodeHandler returns a mock handler that provides a valid receipt
// for the given txHash/contractAddress/deployerAddress and valid bytecode at the address.
func validReceiptAndCodeHandler(txHash, contractAddress string, deployerAddr ...string) func(w http.ResponseWriter, r *http.Request) {
	deployer := "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	if len(deployerAddr) > 0 {
		deployer = deployerAddr[0]
	}
	return func(w http.ResponseWriter, r *http.Request) {
		method, _ := rpcRequestBody(r)
		w.Header().Set("Content-Type", "application/json")

		switch method {
		case "eth_getTransactionReceipt":
			receipt := map[string]interface{}{
				"contractAddress": strings.ToLower(contractAddress),
				"from":            strings.ToLower(deployer),
				"status":          "0x1",
				"blockNumber":     "0xa",
			}
			resp := map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      1,
				"result":  receipt,
			}
			json.NewEncoder(w).Encode(resp)
		case "eth_getCode":
			resp := map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      1,
				"result":  "0x6080604052",
			}
			json.NewEncoder(w).Encode(resp)
		default:
			w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x1"}`))
		}
	}
}

// setupDeployerInOrg creates a user, links an ETH address, and adds them to a group in the org.
// Returns the deployer's ETH address.
func setupDeployerInOrg(t *testing.T, ts *testServerContractProof, orgID string) string {
	t.Helper()
	ctx := context.Background()
	conn := ts.db.Conn()

	deployerAddr := "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	deployerDID := "did:test:deployer"

	// Create user
	userID := uuid.New().String()
	_, err := conn.ExecContext(ctx,
		"INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, false, false, '{}')",
		userID, deployerDID)
	require.NoError(t, err)

	// Link ETH address
	err = ts.db.SystemLinkEthAddress(ctx, deployerDID, deployerAddr)
	require.NoError(t, err)

	// Create group in org and add user
	groupID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path) VALUES ($1, $2, 'deployers', 'Deployers', 0, 'deployers')",
		groupID, orgID)
	require.NoError(t, err)

	membershipID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO user_memberships (id, user_id, group_id, source) VALUES ($1, $2, $3, 'admin')",
		membershipID, userID, groupID)
	require.NoError(t, err)

	return deployerAddr
}

func TestContractRegistrationProofOfDeployment(t *testing.T) {
	ts := setupTestServerForContractProof(t)
	orgID := createTestOrgForProof(t, ts, "proof-test-org")
	deployerAddr := setupDeployerInOrg(t, ts, orgID)

	contractAddr := "0x1234567890abcdef1234567890abcdef12345678"
	validTxHash := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	t.Run("ValidTxHashSucceeds", func(t *testing.T) {
		addr := "0x1111111111111111111111111111111111111111"
		txHash := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

		ts.mockHandler = validReceiptAndCodeHandler(txHash, addr, deployerAddr)

		body := map[string]any{
			"address":            addr,
			"name":               "Test Contract",
			"deployment_tx_hash": txHash,
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/contracts/claim", orgID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		ts.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, strings.ToLower(addr), response["address"])
	})

	t.Run("MissingTxHashFails", func(t *testing.T) {
		body := map[string]any{
			"address": "0x2222222222222222222222222222222222222222",
			"name":    "Missing TX Hash Contract",
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/contracts/claim", orgID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		ts.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "address and deployment_tx_hash are required", response["error"])
	})

	t.Run("TxHashAddressMismatchFails", func(t *testing.T) {
		// Receipt says contract was deployed at a DIFFERENT address
		differentAddr := "0x9999999999999999999999999999999999999999"
		ts.mockHandler = validReceiptAndCodeHandler(validTxHash, differentAddr)

		body := map[string]any{
			"address":            contractAddr,
			"name":               "Mismatched Contract",
			"deployment_tx_hash": validTxHash,
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/contracts/claim", orgID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		ts.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		// Verify opaque error message
		assert.Equal(t, "contract registration failed", response["error"])
	})

	t.Run("AddressOwnedByAnotherOrgFails", func(t *testing.T) {
		// First, register the contract to orgID (deployer is in this org)
		addr := "0x3333333333333333333333333333333333333333"
		txHash := "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
		ts.mockHandler = validReceiptAndCodeHandler(txHash, addr, deployerAddr)

		body := map[string]any{
			"address":            addr,
			"name":               "Org1 Contract",
			"deployment_tx_hash": txHash,
		}
		jsonBody, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/contracts/claim", orgID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		ts.router.ServeHTTP(w, req)
		require.Equal(t, http.StatusCreated, w.Code)

		// Create another org and try to register the same address
		org2ID := createTestOrgForProof(t, ts, "proof-test-org-2")
		txHash2 := "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
		ts.mockHandler = validReceiptAndCodeHandler(txHash2, addr)

		body2 := map[string]any{
			"address":            addr,
			"name":               "Org2 Squatted Contract",
			"deployment_tx_hash": txHash2,
		}
		jsonBody2, _ := json.Marshal(body2)
		req2 := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/contracts/claim", org2ID), bytes.NewReader(jsonBody2))
		req2.Header.Set("Content-Type", "application/json")
		w2 := httptest.NewRecorder()
		ts.router.ServeHTTP(w2, req2)

		assert.Equal(t, http.StatusBadRequest, w2.Code)

		var response map[string]any
		err := json.Unmarshal(w2.Body.Bytes(), &response)
		require.NoError(t, err)
		// Opaque error — does NOT reveal that another org owns it
		assert.Equal(t, "contract registration failed", response["error"])
	})

	t.Run("AlreadyRegisteredSameOrgFails", func(t *testing.T) {
		// Register a contract first (deployer in org)
		addr := "0x4444444444444444444444444444444444444444"
		txHash := "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
		ts.mockHandler = validReceiptAndCodeHandler(txHash, addr, deployerAddr)

		body := map[string]any{
			"address":            addr,
			"name":               "First Registration",
			"deployment_tx_hash": txHash,
		}
		jsonBody, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/contracts/claim", orgID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		ts.router.ServeHTTP(w, req)
		require.Equal(t, http.StatusCreated, w.Code)

		// Now try to re-register the same address to the same org without tx hash.
		// The handler should see the existing contract and skip verification.
		// However, the DB will reject due to unique constraint — this is an update case.
		// The current handler does INSERT so this will hit the unique constraint.
		// For same-org, the existing record means verification is skipped,
		// but the INSERT will still fail with unique violation (same org).
		// The handler should detect same-org unique violations differently.
		// Actually the code detects existing != nil and skips verification, but then
		// the INSERT will fail because the address already exists. The unique constraint
		// error is still returned as opaque. Let's verify the re-registration by using
		// the UPDATE endpoint instead.
		//
		// Actually: re-reading the requirement, "re-registration by the same org"
		// skips verification. The contract already exists, so `existing != nil` is true.
		// The code then proceeds to INSERT which fails on unique constraint.
		// The unique constraint violation message is "contract registration failed".
		// This is correct behavior because the contract IS already registered.
		// The user should use PUT to update it.
		//
		// The test verifies that the second POST doesn't make RPC calls (since
		// existing != nil means we skip verification). Set mock to panic if called.
		ts.mockHandler = func(w http.ResponseWriter, r *http.Request) {
			// If this gets called during re-registration, the skip logic failed
			t.Error("RPC should not be called for re-registration of same-org contract")
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"should not be called"}}`))
		}

		body2 := map[string]any{
			"address": addr,
			"name":    "Re-Registration",
			// No deployment_tx_hash — should be OK because existing contract is same org
		}
		jsonBody2, _ := json.Marshal(body2)
		req2 := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/contracts/claim", orgID), bytes.NewReader(jsonBody2))
		req2.Header.Set("Content-Type", "application/json")
		w2 := httptest.NewRecorder()
		ts.router.ServeHTTP(w2, req2)

		// Should fail because the address is already registered.
		// Opaque error — doesn't reveal which org owns it.
		assert.Equal(t, http.StatusBadRequest, w2.Code)
	})

	t.Run("ReceiptNotFoundFails", func(t *testing.T) {
		ts.mockHandler = func(w http.ResponseWriter, r *http.Request) {
			method, _ := rpcRequestBody(r)
			w.Header().Set("Content-Type", "application/json")
			if method == "eth_getTransactionReceipt" {
				// Receipt not found (pending or non-existent tx)
				w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":null}`))
			} else {
				w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x1"}`))
			}
		}

		body := map[string]any{
			"address":            "0x5555555555555555555555555555555555555555",
			"name":               "Pending TX Contract",
			"deployment_tx_hash": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		}
		jsonBody, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/contracts/claim", orgID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		ts.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "contract registration failed", response["error"])
	})

	t.Run("NoBytecodeAtAddressFails", func(t *testing.T) {
		addr := "0x6666666666666666666666666666666666666666"
		txHash := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"

		ts.mockHandler = func(w http.ResponseWriter, r *http.Request) {
			method, _ := rpcRequestBody(r)
			w.Header().Set("Content-Type", "application/json")

			switch method {
			case "eth_getTransactionReceipt":
				receipt := map[string]interface{}{
					"contractAddress": strings.ToLower(addr),
					"status":          "0x1",
					"blockNumber":     "0xa",
				}
				resp := map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      1,
					"result":  receipt,
				}
				json.NewEncoder(w).Encode(resp)
			case "eth_getCode":
				// No code at address (self-destructed or EOA)
				resp := map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      1,
					"result":  "0x",
				}
				json.NewEncoder(w).Encode(resp)
			default:
				w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x1"}`))
			}
		}

		body := map[string]any{
			"address":            addr,
			"name":               "No Bytecode Contract",
			"deployment_tx_hash": txHash,
		}
		jsonBody, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/contracts/claim", orgID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		ts.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "contract registration failed", response["error"])
	})

	t.Run("InvalidTxHashFormatFails", func(t *testing.T) {
		body := map[string]any{
			"address":            "0x7777777777777777777777777777777777777777",
			"name":               "Bad TX Hash",
			"deployment_tx_hash": "not-a-valid-hash",
		}
		jsonBody, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/contracts/claim", orgID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		ts.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "contract registration failed", response["error"])
	})

	t.Run("CaseInsensitiveAddressMatching", func(t *testing.T) {
		addr := "0xABCDEF0123456789ABCDEF0123456789ABCDEF01"
		txHash := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac"

		ts.mockHandler = validReceiptAndCodeHandler(txHash, addr, deployerAddr)

		body := map[string]any{
			"address":            addr,
			"name":               "Mixed Case Contract",
			"deployment_tx_hash": txHash,
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/contracts/claim", orgID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		ts.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		// Address should be stored lowercase
		assert.Equal(t, strings.ToLower(addr), response["address"])
	})

	t.Run("DeployerNotInClaimingOrgFails", func(t *testing.T) {
		// Create a second org WITHOUT the deployer
		otherOrgID := createTestOrgForProof(t, ts, "other-org-no-deployer")
		addr := "0x7777777777777777777777777777777777777777"
		txHash := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad"

		// Receipt has the correct deployer, but they're not in otherOrg
		ts.mockHandler = validReceiptAndCodeHandler(txHash, addr, deployerAddr)

		body := map[string]any{
			"address":            addr,
			"name":               "Stolen Contract",
			"deployment_tx_hash": txHash,
		}
		jsonBody, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/contracts/claim", otherOrgID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		ts.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var response map[string]any
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "contract registration failed", response["error"])
	})
}

func TestGlobalUniqueAddressConstraint(t *testing.T) {
	ts := setupTestServerForContractProof(t)
	org1ID := createTestOrgForProof(t, ts, "unique-org-1")
	org2ID := createTestOrgForProof(t, ts, "unique-org-2")
	deployerAddr := setupDeployerInOrg(t, ts, org1ID)

	addr := "0xaaaa000000000000000000000000000000000001"
	txHash := "0x1111111111111111111111111111111111111111111111111111111111111111"

	// Register to org1
	ts.mockHandler = validReceiptAndCodeHandler(txHash, addr, deployerAddr)

	body := map[string]any{
		"address":            addr,
		"name":               "Org1 Contract",
		"deployment_tx_hash": txHash,
	}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/contracts/claim", org1ID), bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ts.router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code, "first registration should succeed")

	// Try to register same address (different case) to org2
	txHash2 := "0x2222222222222222222222222222222222222222222222222222222222222222"
	ts.mockHandler = validReceiptAndCodeHandler(txHash2, strings.ToUpper(addr), deployerAddr)

	body2 := map[string]any{
		"address":            strings.ToUpper(strings.TrimPrefix(addr, "0x")),
		"name":               "Org2 Squatting",
		"deployment_tx_hash": txHash2,
	}
	// Fix: address needs 0x prefix for validation
	body2["address"] = "0x" + strings.ToUpper(strings.TrimPrefix(addr, "0x"))
	jsonBody2, _ := json.Marshal(body2)
	req2 := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/contracts/claim", org2ID), bytes.NewReader(jsonBody2))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	ts.router.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusBadRequest, w2.Code)

	var response map[string]any
	json.Unmarshal(w2.Body.Bytes(), &response)
	// Opaque error — does NOT reveal who owns it
	assert.Equal(t, "contract registration failed", response["error"])
}
