//go:build mockauth

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"privacy-proxy/e2e/testfixtures"
	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
)

// methodRecorder is a reverse proxy in front of the real E2E node that records
// the JSON-RPC method of every request the proxy forwards. It is the canary
// that proves an unsupported method never reaches the node.
type methodRecorder struct {
	mu      sync.Mutex
	methods map[string]int
}

func (r *methodRecorder) count(method string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.methods[method]
}

func startMethodRecorder(t *testing.T, nodeURL string) (*methodRecorder, string) {
	t.Helper()
	target, err := url.Parse(nodeURL)
	if err != nil {
		t.Fatalf("parse node URL: %v", err)
	}
	rec := &methodRecorder{methods: map[string]int{}}
	rp := httputil.NewSingleHostReverseProxy(target)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		var env struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &env)
		rec.mu.Lock()
		rec.methods[env.Method]++
		rec.mu.Unlock()
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
		req.Host = target.Host
		rp.ServeHTTP(w, req)
	}))
	t.Cleanup(srv.Close)
	return rec, srv.URL
}

// TestMethodCatalog_UnsupportedMethodsNeverReachNode drives the full stack
// (real HTTP server, mock-login JWT, real node behind a recording proxy): a
// method the proxy does not model is refused for a "*" group and for a legacy
// literal-"*" row, and never reaches the node; the admin API refuses to store
// such a method.
func TestMethodCatalog_UnsupportedMethodsNeverReachNode(t *testing.T) {
	nodeURL := os.Getenv("E2E_NODE_URL")
	if nodeURL == "" {
		nodeURL = "http://localhost:8545"
	}
	rec, recorderURL := startMethodRecorder(t, nodeURL)
	t.Setenv("E2E_NODE_URL", recorderURL)

	srv, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	testfixtures.SeedRBACDefaults(t, srv.DB())

	f := testfixtures.New(t, serverURL)
	org := f.CreateOrg("catalog")
	group := f.CreateGroup(org.ID, "g", testfixtures.CreateGroupOptions{})

	// The admin API refuses unsupported names, with a fixed opaque message.
	for _, methods := range [][]string{{"eth_getRawTransactionByHash"}, {"trace_block"}, {"linea_*"}, {"eth_sendRawTransactionSync"}} {
		status, body := f.Client.DoRaw(t, http.MethodPut, "/api/v1/admin/orgs/"+org.ID+"/groups/"+group.ID+"/access",
			map[string]any{"allowed_methods": methods, "claims": []string{}})
		if status != http.StatusBadRequest {
			t.Errorf("PUT allowed_methods=%v: status %d, want 400; body=%s", methods, status, body)
		}
		if strings.Contains(string(body), methods[0]) {
			t.Errorf("PUT allowed_methods=%v: rejection echoes the method name: %s", methods, body)
		}
	}

	// "*" is accepted and stored as the explicit list.
	access := f.SetGroupAccess(org.ID, group.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{"*"},
		Claims:         []testfixtures.Claim{},
	})
	for _, m := range access.AllowedMethods {
		if strings.Contains(m, "*") {
			t.Fatalf("stored allowed_methods still holds %q", m)
		}
	}
	_, token := f.CreateUserWithMembership(group.ID, testfixtures.CreateUserOptions{})
	auth := map[string]string{"Authorization": "Bearer " + token}

	// A legacy literal "*" row follows the same catalog admission policy.
	legacyGroup := f.CreateGroup(org.ID, "legacy", testfixtures.CreateGroupOptions{})
	if _, err := srv.DB().Conn().ExecContext(context.Background(),
		`INSERT INTO group_access (id, group_id, allowed_methods, claims) VALUES ($1, $2, '{*}', '{deploy}')`,
		uuid.New().String(), legacyGroup.ID); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}
	_, legacyToken := f.CreateUserWithMembership(legacyGroup.ID, testfixtures.CreateUserOptions{})
	legacyAuth := map[string]string{"Authorization": "Bearer " + legacyToken}

	txHash := "0x" + strings.Repeat("11", 32)
	addr := "0x" + strings.Repeat("22", 20)
	unsupported := []struct {
		method string
		params []any
	}{
		{"eth_getRawTransactionByHash", []any{txHash}},
		{"eth_getRawTransactionByBlockNumberAndIndex", []any{"latest", "0x0"}},
		{"eth_getTransactionBySenderAndNonce", []any{addr, "0x0"}},
		{"eth_getAccount", []any{addr, "latest"}},
		{"eth_simulateV1", []any{map[string]any{"blockStateCalls": []any{}}, "latest"}},
		{"eth_sendRawTransactionSync", []any{"0x02f8"}},
		{"trace_transaction", []any{txHash}},
		{"trace_block", []any{"latest"}},
		{"ots_getTransactionBySenderAndNonce", []any{addr, "0x0"}},
		{"erigon_getLogs", []any{map[string]any{}}},
	}
	for _, caller := range []struct {
		name    string
		headers map[string]string
	}{{"api-star group", auth}, {"legacy literal-star row", legacyAuth}, {"anonymous", nil}} {
		for _, tc := range unsupported {
			res := testfixtures.JSONRPCPostAt(t, serverURL, "/rpc/"+org.ID, tc.method, tc.params, caller.headers)
			if res.Status == http.StatusOK {
				t.Errorf("%s: %s returned 200: %s", caller.name, tc.method, res.Body)
			}
			if rec.count(tc.method) != 0 {
				t.Fatalf("%s: %s reached the node", caller.name, tc.method)
			}
		}
	}

	// Control: a catalog method is still forwarded for the same caller.
	before := rec.count("eth_feeHistory")
	res := testfixtures.JSONRPCPostAt(t, serverURL, "/rpc/"+org.ID, "eth_feeHistory", []any{"0x1", "latest", []any{}}, auth)
	if res.Status != http.StatusOK {
		t.Fatalf("eth_feeHistory: status %d, want 200; body=%s", res.Status, res.Body)
	}
	if rec.count("eth_feeHistory") != before+1 {
		t.Fatal("eth_feeHistory did not reach the node — the refusals above prove nothing")
	}
	if !rbac.IsForwardableMethod("eth_feeHistory") {
		t.Fatal("control method must be a catalog method")
	}
}
