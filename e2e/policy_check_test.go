//go:build mockauth

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/server"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
)

// TestPolicyCheckMatchesLiveEnforcement is the end-to-end counterpart to the
// unit tests in internal/server/admin_policy_check_test.go. Those call the
// handler directly; this one goes through the real listening server (real
// adminAuthMiddleware, real /rpc dispatch) and checks that policy-check's
// verdict matches what actually happens when the same operation is submitted
// live. That agreement is the endpoint's core contract.
func TestPolicyCheckMatchesLiveEnforcement(t *testing.T) {
	const adminToken = "pc-e2e-admin-token"
	const operatorToken = "pc-e2e-operator-token"
	srv, serverURL, cleanup := setupPolicyCheckE2E(t, adminToken, operatorToken)
	defer cleanup()
	database := srv.DB()
	ctx := context.Background()

	// One participant org has a contract grant. A third-party org has none.
	orgID := uuid.New().String()
	otherOrgID := uuid.New().String()
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{ID: orgID, Slug: "pc-e2e-a", Name: "PC E2E A", Settings: map[string]any{}}))
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{ID: otherOrgID, Slug: "pc-e2e-b", Name: "PC E2E B", Settings: map[string]any{}}))

	participantGID := createGroup(t, database, orgID, "pc-e2e-participant", nil, false)
	attachAllowedMethods(t, database, participantGID, []string{"eth_call", "eth_sendTransaction"})
	participantDID := "did:pc-e2e:participant"
	createUserInGroup(t, database, participantDID, participantGID)

	thirdPartyGID := createGroup(t, database, otherOrgID, "pc-e2e-thirdparty", nil, false)
	attachAllowedMethods(t, database, thirdPartyGID, []string{"eth_call", "eth_sendTransaction"})
	thirdPartyDID := "did:pc-e2e:thirdparty"
	createUserInGroup(t, database, thirdPartyDID, thirdPartyGID)

	grantedContract := "0x1000000000000000000000000000000000000e2e"
	ungrantedContract := "0x2000000000000000000000000000000000000e2e"
	grantedContractID := createContract(t, database, orgID, grantedContract, "PCE2EGranted")
	createContract(t, database, orgID, ungrantedContract, "PCE2EUngranted")
	createGrant(t, database, grantedContractID, participantGID)

	subjectAddr := "0x0000000000000000000000000000000000000ea1"
	require.NoError(t, database.SystemLinkEthAddress(ctx, participantDID, subjectAddr))

	tests := []struct {
		name string
		// subject is what policy-check is asked about; liveDID is who submits
		// the ground-truth /rpc call. They differ only for the address case,
		// which policy-check must itself resolve back to liveDID.
		subject  map[string]any
		liveDID  string
		contract string
		want     bool
	}{
		{"participant on granted contract, by DID", map[string]any{"did": participantDID}, participantDID, grantedContract, true},
		{"participant on granted contract, by address", map[string]any{"address": subjectAddr}, participantDID, grantedContract, true},
		{"participant on ungranted contract", map[string]any{"did": participantDID}, participantDID, ungrantedContract, false},
		{"third party on the granted contract", map[string]any{"did": thirdPartyDID}, thirdPartyDID, grantedContract, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			op := map[string]any{
				"method": "eth_call",
				"params": []any{map[string]any{"to": tc.contract, "data": "0x"}, "latest"},
			}

			// Ground truth: submit the same operation for real. An RBAC denial
			// is masked as 404; anything else means RBAC let it through (502
			// here, since no upstream node is reachable in this environment).
			jwt := getJWTToken(t, serverURL, tc.liveDID)
			rpcBody, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": op["method"], "params": op["params"]})
			rpcReq, _ := http.NewRequest(http.MethodPost, serverURL+"/rpc/"+orgID, bytes.NewReader(rpcBody))
			rpcReq.Header.Set("Authorization", "Bearer "+jwt)
			rpcReq.Header.Set("Content-Type", "application/json")
			rpcResp, err := (&http.Client{Timeout: 5 * time.Second}).Do(rpcReq)
			require.NoError(t, err)
			defer rpcResp.Body.Close()
			liveAllowed := rpcResp.StatusCode != http.StatusNotFound

			// Pinning want as well as the comparison keeps this honest: if the
			// fixture ever stops producing the intended allow/deny mix, both
			// sides could agree on the wrong answer and the test would still
			// pass on the comparison alone.
			require.Equal(t, tc.want, liveAllowed,
				"fixture no longer produces the intended live outcome (status %d)", rpcResp.StatusCode)

			allowed, _ := policyCheckVerdict(t, serverURL, adminToken, map[string]any{
				"subject": tc.subject, "operation": op, "org_id": orgID,
			})
			require.Equal(t, liveAllowed, allowed, "policy-check disagrees with live enforcement")
		})
	}

	// The operator token cannot inspect tenant policy.
	t.Run("operator token is rejected", func(t *testing.T) {
		body := map[string]any{
			"subject":   map[string]any{"did": participantDID},
			"operation": map[string]any{"method": "eth_call", "params": []any{map[string]any{"to": grantedContract, "data": "0x"}, "latest"}},
			"org_id":    orgID,
		}
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, serverURL+"/api/v1/admin/policy-check", bytes.NewReader(raw))
		require.NoError(t, err)
		req.Header.Set("X-Admin-Token", operatorToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
	})
}

// policyCheckVerdict POSTs to policy-check with an X-Admin-Token and returns
// the verdict, failing the test on any non-200.
func policyCheckVerdict(t *testing.T, serverURL, token string, body map[string]any) (bool, string) {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, serverURL+"/api/v1/admin/policy-check", bytes.NewReader(raw))
	require.NoError(t, err)
	req.Header.Set("X-Admin-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var out struct {
		Allowed bool   `json:"allowed"`
		Reason  string `json:"reason"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return out.Allowed, out.Reason
}

// The unit tests fake auth_method through a test middleware, so this is the
// only place a real JWT admin, minted through the real auth flow, reaches
// handlePolicyCheck's credential gate.
func TestPolicyCheckRejectsRealJWTAdmin(t *testing.T) {
	const adminToken = "pc-e2e-jwt-admin-token"
	srv, serverURL, cleanup := setupPolicyCheckE2E(t, adminToken, "")
	defer cleanup()
	database := srv.DB()
	ctx := context.Background()

	orgID := uuid.New().String()
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{ID: orgID, Slug: "pc-e2e-jwt", Name: "PC E2E JWT", Settings: map[string]any{}}))
	orgAdminGID := createGroup(t, database, orgID, "pc-e2e-org-admin", nil, true)
	attachAllowedMethods(t, database, orgAdminGID, []string{"eth_call"})
	orgAdminDID := "did:pc-e2e:org-admin"
	createUserInGroup(t, database, orgAdminDID, orgAdminGID)

	jwt := getJWTToken(t, serverURL, orgAdminDID)
	body, _ := json.Marshal(map[string]any{
		"subject":   map[string]any{"did": orgAdminDID},
		"operation": map[string]any{"method": "eth_call", "params": []any{}},
	})
	req, _ := http.NewRequest(http.MethodPost, serverURL+"/api/v1/admin/policy-check", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestPolicyCheckRejectsRealNoCredential(t *testing.T) {
	const adminToken = "pc-e2e-nocred-token"
	_, serverURL, cleanup := setupPolicyCheckE2E(t, adminToken, "")
	defer cleanup()

	body, _ := json.Marshal(map[string]any{
		"subject":   map[string]any{"did": "did:pc-e2e:whoever"},
		"operation": map[string]any{"method": "eth_call", "params": []any{}},
	})
	req, _ := http.NewRequest(http.MethodPost, serverURL+"/api/v1/admin/policy-check", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestPolicyCheckRejectsRealWrongToken(t *testing.T) {
	const adminToken = "pc-e2e-wrongtoken-real"
	_, serverURL, cleanup := setupPolicyCheckE2E(t, adminToken, "")
	defer cleanup()

	body, _ := json.Marshal(map[string]any{
		"subject":   map[string]any{"did": "did:pc-e2e:whoever"},
		"operation": map[string]any{"method": "eth_call", "params": []any{}},
	})
	req, _ := http.NewRequest(http.MethodPost, serverURL+"/api/v1/admin/policy-check", bytes.NewReader(body))
	req.Header.Set("X-Admin-Token", "not-the-configured-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// setupPolicyCheckE2E mirrors setupE2EWithVerifier (proxy_test.go) but sets
// AdminAPIToken/OperatorAPIToken. The shared helper leaves them empty, i.e.
// no-token dev mode, which is the wrong fixture for tests whose whole point is
// the token gate. operatorToken may be "".
func setupPolicyCheckE2E(t *testing.T, adminToken, operatorToken string) (*server.Server, string, func()) {
	t.Helper()

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
	cleanupDB := func() { cleanupDBOnce.Do(rawCleanupDB) }
	t.Cleanup(cleanupDB)

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
	nodeCleanup := func() {}
	if nodeURL == "" {
		node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Method string            `json:"method"`
				Params []json.RawMessage `json:"params"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}
			result := any("0x")
			if req.Method == "debug_traceCall" && len(req.Params) > 0 {
				var tx map[string]any
				if err := json.Unmarshal(req.Params[0], &tx); err != nil {
					http.Error(w, "invalid trace request", http.StatusBadRequest)
					return
				}
				from, _ := tx["from"].(string)
				to, _ := tx["to"].(string)
				if from == "" {
					from = "0x0000000000000000000000000000000000000000"
				}
				result = map[string]any{"type": "CALL", "from": from, "to": to}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
		}))
		nodeURL = node.URL
		nodeCleanup = node.Close
	}

	cfg := &config.Config{
		NodeURL:                      nodeURL,
		DatabaseURL:                  dbURL,
		AuditDatabaseURL:             dbURL,
		AuditAdminDatabaseURL:        dbURL,
		PrivadoRPCURL:                "https://rpc-mainnet.privado.id",
		IPFSGateway:                  "https://ipfs-proxy-cache.privado.id",
		JWTSecret:                    "test-secret",
		JWTRefreshSecret:             "test-refresh-secret",
		VerifierID:                   "did:privado:verifier:test",
		BaseURL:                      "http://127.0.0.1",
		Environment:                  "development",
		AllowMockLogin:               true,
		AdminAPIToken:                adminToken,
		OperatorAPIToken:             operatorToken,
		RuntimeTracingEthCallEnabled: true,
	}

	srv, err := server.NewWithVerifier(cfg, nil)
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
			nodeCleanup()
			cleanupDB()
		})
	}
	t.Cleanup(cleanup)

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
	cfg.BaseURL = serverURL

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

	return srv, serverURL, func() {}
}
