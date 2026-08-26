package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/server"

	"github.com/google/uuid"
	"github.com/iden3/iden3comm/v2/protocol"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// mockPrivadoVerifier is a mock for E2E testing
type mockPrivadoVerifier struct {
	userDID string
}

func (m *mockPrivadoVerifier) CreateAuthorizationRequest(verifierID, callbackURL, reason string) (*protocol.AuthorizationRequestMessage, error) {
	return &protocol.AuthorizationRequestMessage{
		ID:       "mock-request-id",
		ThreadID: "mock-thread-id",
		Typ:      "application/iden3comm-plain-json",
		Type:     "https://iden3-communication.io/authorization/1.0/request",
		From:     verifierID,
		Body: protocol.AuthorizationRequestMessageBody{
			CallbackURL: callbackURL,
			Reason:      reason,
		},
	}, nil
}

func (m *mockPrivadoVerifier) CreateHumanityAuthRequest(verifierID, callbackURL, reason, issuerDID string, hc auth.HumanityRequestConfig) (*protocol.AuthorizationRequestMessage, error) {
	circuitID := hc.CircuitID
	if circuitID == "" {
		circuitID = "credentialAtomicQueryMTPV2"
	}
	credentialSubject, _ := hc.Query["credentialSubject"]
	if credentialSubject == nil {
		credentialSubject = map[string]any{"isHuman": map[string]any{"$eq": 1}}
	}
	credType := hc.CredentialType
	if credType == "" {
		credType = "ProofOfHumanity"
	}
	return &protocol.AuthorizationRequestMessage{
		ID:       "mock-request-id",
		ThreadID: "mock-thread-id",
		Typ:      "application/iden3comm-plain-json",
		Type:     "https://iden3-communication.io/authorization/1.0/request",
		From:     verifierID,
		Body: protocol.AuthorizationRequestMessageBody{
			CallbackURL: callbackURL,
			Reason:      reason,
			Scope: []protocol.ZeroKnowledgeProofRequest{
				{
					ID:        1,
					CircuitID: circuitID,
					Query: map[string]any{
						"allowedIssuers":    []string{issuerDID},
						"credentialSubject": credentialSubject,
						"context":           hc.SchemaURL,
						"type":              credType,
					},
				},
			},
		},
	}, nil
}

func (m *mockPrivadoVerifier) VerifyJWZ(ctx context.Context, jwzToken string, authRequest *protocol.AuthorizationRequestMessage, verifierID string) (string, error) {
	// Return the user DID based on the JWZ token
	// For E2E tests, we'll use the token as a simple identifier
	if m.userDID != "" {
		return m.userDID, nil
	}
	// Default: extract DID from token or use a default
	return "did:privado:test_user", nil
}

func (m *mockPrivadoVerifier) VerifyJWZWithProofData(ctx context.Context, jwzToken string, authRequest *protocol.AuthorizationRequestMessage, verifierID string) (*auth.VerificationResult, error) {
	did, err := m.VerifyJWZ(ctx, jwzToken, authRequest, verifierID)
	if err != nil {
		return nil, err
	}
	return &auth.VerificationResult{UserDID: did}, nil
}

// RegisteredNetworks reports the pair a deployment wires once the Billions RPC
// is configured, so E2E behaves like a fully-configured install (RD-1241).
func (m *mockPrivadoVerifier) RegisteredNetworks() []string {
	return []string{"billions:main", "privado:main"}
}

func setupE2E(t *testing.T) (*server.Server, string, func()) {
	return setupE2EWithVerifier(t, nil)
}

func setupE2EWithVerifier(t *testing.T, verifier server.PrivadoVerifier) (*server.Server, string, func()) {
	// The server harness provides a run-owned database. TEST_DATABASE_URL remains
	// an explicit developer/CI override; otherwise testcontainers owns the DB.
	dbURL := os.Getenv("E2E_DATABASE_URL")
	if dbURL == "" {
		dbURL = os.Getenv("TEST_DATABASE_URL")
	}

	var rawCleanupDB func()
	if dbURL == "" {
		dbURL, rawCleanupDB = db.SetupTestContainer(t)
	} else {
		if err := db.EnsureTestDatabase(dbURL); err != nil {
			t.Fatalf("configured E2E PostgreSQL is unavailable: %v", err)
		}
		rawCleanupDB = func() {}
	}

	var cleanupDBOnce sync.Once
	cleanupDB := func() {
		cleanupDBOnce.Do(rawCleanupDB)
	}
	// Register immediately so setup failures cannot leak a testcontainer.
	t.Cleanup(cleanupDB)

	// Connect to database and reset it for clean test state.
	database, err := db.New(dbURL)
	if err != nil {
		t.Fatalf("failed to connect to E2E database: %v", err)
	}
	if err := db.ResetTestDatabase(database); err != nil {
		database.Close()
		t.Fatalf("failed to reset E2E database: %v", err)
	}
	database.Close()

	listenerAddresses := make(chan string, 1)

	nodeURL := os.Getenv("E2E_NODE_URL")
	if nodeURL == "" {
		nodeURL = "http://localhost:8545"
	}

	cfg := &config.Config{
		NodeURL:     nodeURL,
		DatabaseURL: dbURL,
		// RD-1147: audit logs live in a separate DB via the real server.New path.
		// For e2e, co-locate the audit schema in this same testcontainer DB (the
		// lean audit migration is idempotent — CREATE ... IF NOT EXISTS — so it just
		// recreates access_logs here after main dropped it). Production keeps the
		// audit DB strictly separate; owner creds here are fine (the INSERT-only
		// seal is exercised by the internal/db integration test, not e2e).
		AuditDatabaseURL:      dbURL,
		AuditAdminDatabaseURL: dbURL,
		PrivadoRPCURL:         "https://rpc-mainnet.privado.id",
		IPFSGateway:           "https://ipfs-proxy-cache.privado.id",
		JWTSecret:             "test-secret",
		JWTRefreshSecret:      "test-refresh-secret",
		VerifierID:            "did:privado:verifier:test",
		BaseURL:               "http://127.0.0.1",
		Environment:           "development",
		// AllowMockLogin is inert without the mockauth build tag
		// (auth_prod.go stubs tryMockLogin out); enabling it here is
		// safe for production builds and lets mockauth-tagged tests
		// mint per-DID JWTs via the mock.<did> token format.
		AllowMockLogin: true,
	}

	// Use mock verifier if provided, otherwise create the real one.
	srv, err := server.NewWithVerifier(cfg, verifier)
	if err != nil {
		t.Fatalf("failed to create E2E server: %v", err)
	}

	httpServer := &http.Server{
		Addr:              "127.0.0.1:0",
		ReadHeaderTimeout: 5 * time.Second,
		BaseContext: func(listener net.Listener) context.Context {
			listenerAddresses <- listener.Addr().String()
			return context.Background()
		},
	}
	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := httpServer.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
				t.Logf("failed to stop E2E HTTP server cleanly: %v", err)
			}
			srv.Stop()
			cleanupDB()
		})
	}
	t.Cleanup(cleanup)

	// Reset database for a fresh test after server migrations complete.
	if err := db.ResetTestDatabase(srv.DB()); err != nil {
		t.Fatalf("failed to reset E2E database after server setup: %v", err)
	}

	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- srv.RunWithServer(httpServer)
	}()

	var serverAddr string
	select {
	case serverAddr = <-listenerAddresses:
	case runErr := <-serverErrors:
		t.Fatalf("E2E server exited before binding a listener: %v", runErr)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for E2E server listener")
	}
	serverURL := "http://" + serverAddr
	// Server retains cfg; publish the assigned URL before sending any requests.
	cfg.BaseURL = serverURL

	// Wait for server readiness, but fail immediately if the listener exits.
	client := &http.Client{Timeout: time.Second}
	ready := false
	for i := 0; i < 10; i++ {
		select {
		case runErr := <-serverErrors:
			if runErr != nil {
				t.Fatalf("E2E server exited during startup: %v", runErr)
			}
		default:
		}

		resp, requestErr := client.Get(serverURL + "/health")
		if requestErr == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				ready = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("E2E server failed to start on %s", serverAddr)
	}

	// Server/database lifetime is owned by t.Cleanup so fixture cleanups
	// registered later run before shutdown. Keep the returned function as a
	// compatibility no-op for the many legacy `defer cleanup()` call sites.
	return srv, serverURL, func() {}
}

// getJWTToken performs the auth flow and returns a JWT access token
func getJWTToken(t *testing.T, serverURL, userDID string) string {
	client := &http.Client{Timeout: 5 * time.Second}

	// Step 1: Request authorization
	req, _ := http.NewRequest("POST", serverURL+"/auth/request", nil)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("auth request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("auth request returned %d: %s", resp.StatusCode, string(body))
	}

	var authResp struct {
		SessionID string `json:"session_id"`
	}
	json.NewDecoder(resp.Body).Decode(&authResp)

	// Step 2: Verify with mock token (dev mode)
	verifyBody := map[string]any{
		"session_id": authResp.SessionID,
		"jwz_token":  "mock." + userDID, // Mock token format
	}
	jsonBody, _ := json.Marshal(verifyBody)

	req2, _ := http.NewRequest("POST", serverURL+"/auth/verify", bytes.NewReader(jsonBody))
	req2.Header.Set("Content-Type", "application/json")

	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("auth verify failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("auth verify returned %d: %s", resp2.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	json.NewDecoder(resp2.Body).Decode(&tokenResp)

	return tokenResp.AccessToken
}

// createRBACUser creates a user in the RBAC system with the specified properties
func createRBACUser(t *testing.T, database *db.DB, externalID string, kyc, banned bool) {
	ctx := context.Background()
	// database implements rbac.Store interface

	// Ensure default organization exists
	org := &rbac.Organization{
		ID:       rbac.DefaultOrgID,
		Slug:     "default",
		Name:     "Default Organization",
		Settings: map[string]any{},
	}
	_ = database.CreateOrganization(ctx, org) // Ignore error if already exists

	// Ensure default group exists
	group := &rbac.Group{
		ID:    rbac.DefaultGroupID,
		OrgID: rbac.DefaultOrgID,
		Slug:  "default",
		Name:  "Default Group",
		Depth: 0,
		Path:  "default",
	}
	_ = database.CreateGroup(ctx, group) // Ignore error if already exists

	// Ensure default group has access permissions
	groupAccess := &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        rbac.DefaultGroupID,
		AllowedMethods: []string{"eth_call", "eth_getBalance", "eth_blockNumber", "eth_chainId", "eth_estimateGas", "eth_gasPrice", "eth_getCode", "eth_getLogs", "eth_getStorageAt", "eth_getTransactionByHash", "eth_getTransactionCount", "eth_getTransactionReceipt", "eth_sendRawTransaction", "net_version"},
		Claims:         []rbac.Claim{},
	}
	_ = database.CreateGroupAccess(ctx, groupAccess) // Ignore error if already exists

	// Create user
	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: externalID,
		KYC:        kyc,
		Banned:     banned,
		Metadata:   make(map[string]any),
	}

	if err := database.CreateUser(ctx, user); err != nil {
		t.Fatalf("failed to create RBAC user: %v", err)
	}

	// Add to default group (permissions come from GroupAccess, not roles)
	membership := &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  user.ID,
		GroupID: rbac.DefaultGroupID,
		Source:  rbac.MembershipSourceAdmin,
	}

	if err := database.CreateMembership(ctx, membership); err != nil {
		t.Fatalf("failed to create RBAC membership: %v", err)
	}
}

func TestE2E_Proxy_JSONRPCWithAuth(t *testing.T) {
	userDID := "did:privado:test_user"

	// Setup server with mock verifier
	mockVerifier := &mockPrivadoVerifier{userDID: userDID}
	srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
	defer cleanup()

	// Create RBAC user with KYC=true (required for access)
	createRBACUser(t, srv.DB(), userDID, true, false)

	// Get JWT token using the auth flow
	accessToken := getJWTToken(t, serverURL, userDID)

	// Make JSON-RPC request with JWT token
	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "eth_call",
		"params":  []any{},
		"id":      1,
	}

	jsonBody, _ := json.Marshal(reqBody)

	// Use /rpc/:org_id — explicit org required since getUserDefaultOrganization was removed (RD-877)
	req, _ := http.NewRequest("POST", serverURL+"/rpc/"+rbac.DefaultOrgID, bytes.NewReader(jsonBody))
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusBadGateway {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("expected 200 or 502 (node might not be running), got %d: %s", resp.StatusCode, string(body))
	}
}

func TestE2E_UnauthorizedRequest_NoToken(t *testing.T) {
	_, serverURL, cleanup := setupE2E(t)
	defer cleanup()

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "eth_call",
		"params":  []any{},
		"id":      1,
	}

	jsonBody, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", serverURL+"/", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 (opaque denial), got %d: %s", resp.StatusCode, string(body))
	}
	assertOpaqueErrorBody(t, body, "unauthorized", "token")
}

func TestE2E_ForbiddenRequest_DisallowedMethod(t *testing.T) {
	userDID := "did:privado:restricted_user"

	// Setup server with mock verifier
	mockVerifier := &mockPrivadoVerifier{userDID: userDID}
	srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
	defer cleanup()

	// Create RBAC user with KYC=true
	createRBACUser(t, srv.DB(), userDID, true, false)

	// Get JWT token
	accessToken := getJWTToken(t, serverURL, userDID)

	// Try to call a blocked debug method (debug_storageRangeAt is blocked by prefix,
	// unlike debug_traceTransaction which is exempted via prefixBlockExemptions)
	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "debug_storageRangeAt",
		"params":  []any{"0x123"},
		"id":      1,
	}

	jsonBody, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", serverURL+"/", bytes.NewReader(jsonBody))
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 (opaque denial), got %d: %s", resp.StatusCode, string(body))
	}
	assertOpaqueErrorBody(t, body, "debug", "disallowed")
}

func TestE2E_BannedUser(t *testing.T) {
	userDID := "did:privado:banned_user"

	// Setup server with mock verifier
	mockVerifier := &mockPrivadoVerifier{userDID: userDID}
	srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
	defer cleanup()

	// Create RBAC user with KYC=true, NOT banned yet (so /auth/verify succeeds)
	createRBACUser(t, srv.DB(), userDID, true, false)

	// Get JWT token while user is still active
	accessToken := getJWTToken(t, serverURL, userDID)

	// Now ban the user via direct DB update
	_, err := srv.DB().Conn().ExecContext(context.Background(),
		"UPDATE users SET banned = true, updated_at = CURRENT_TIMESTAMP WHERE external_id = $1",
		userDID)
	if err != nil {
		t.Fatalf("failed to ban user: %v", err)
	}

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "eth_call",
		"params":  []any{},
		"id":      1,
	}

	jsonBody, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", serverURL+"/", bytes.NewReader(jsonBody))
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 (opaque denial), got %d: %s", resp.StatusCode, string(body))
	}
	assertOpaqueErrorBody(t, body, "banned")
}

func TestE2E_NoKYC(t *testing.T) {
	userDID := "did:privado:no_kyc_user"

	// Setup server with mock verifier
	mockVerifier := &mockPrivadoVerifier{userDID: userDID}
	srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
	defer cleanup()

	// Create RBAC user with KYC=false
	createRBACUser(t, srv.DB(), userDID, false, false)

	// Get JWT token (even non-KYC users can get tokens, but requests will be blocked)
	accessToken := getJWTToken(t, serverURL, userDID)

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "eth_call",
		"params":  []any{},
		"id":      1,
	}

	jsonBody, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", serverURL+"/", bytes.NewReader(jsonBody))
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 (opaque denial), got %d: %s", resp.StatusCode, string(body))
	}
	assertOpaqueErrorBody(t, body, "kyc")
}
