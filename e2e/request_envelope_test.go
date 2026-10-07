package e2e

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"privacy-proxy/internal/rbac"
)

// The proxy decides access on its own parse of a JSON-RPC body and forwards a
// body to the node. These tests put a recording relay between the proxy and
// the real node, so they observe what the node receives: an ambiguous envelope
// (duplicate or case-variant member names, which exact-case node parsers read
// differently from Go's case-folding, last-wins decoder) must never arrive,
// and an accepted request must arrive as exactly the members the proxy read.

type recordingRelay struct {
	srv    *httptest.Server
	mu     sync.Mutex
	bodies []string
}

// newRecordingRelay forwards every request to the E2E node and records the
// body. Registered before the server so it outlives it.
func newRecordingRelay(t *testing.T) *recordingRelay {
	t.Helper()
	upstream := e2eNodeURL()
	client := &http.Client{Timeout: 10 * time.Second}
	r := &recordingRelay{}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.bodies = append(r.bodies, string(body))
		r.mu.Unlock()
		resp, err := client.Post(upstream, "application/json", bytes.NewReader(body))
		if err != nil {
			http.Error(w, "relay: upstream unavailable", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(out)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *recordingRelay) reset() {
	r.mu.Lock()
	r.bodies = nil
	r.mu.Unlock()
}

func (r *recordingRelay) received() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.bodies...)
}

func postRPC(t *testing.T, url, token, body string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

const (
	envelopeAddrA = "0x000000000000000000000000000000000000000a"
	envelopeAddrB = "0x000000000000000000000000000000000000000b"
	// identity precompile: eth_call echoes the calldata back.
	envelopeIdentity = "0x0000000000000000000000000000000000000004"
)

func TestE2E_RequestEnvelope_AmbiguousNeverReachesNode(t *testing.T) {
	userDID := "did:privado:envelope_user"
	relay := newRecordingRelay(t)
	srv, serverURL, cleanup := setupE2EWithVerifierAndNode(t, &mockPrivadoVerifier{userDID: userDID}, relay.srv.URL)
	defer cleanup()
	seedAnonymousGroup(t, srv.DB())
	createRBACUser(t, srv.DB(), userDID, true, false)
	token := getJWTToken(t, serverURL, userDID)

	cases := []struct {
		name, path, token, body string
	}{
		// Old reading: the last case-insensitive match. Exact-case nodes run
		// the lower-case member instead.
		{"anonymous method then Method", "/", "",
			`{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","Method":"eth_blockNumber","params":["` + envelopeAddrA + `","latest"]}`},
		{"anonymous duplicate method", "/rpc", "",
			`{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","method":"eth_blockNumber","params":["` + envelopeAddrA + `","latest"]}`},
		{"authenticated method then Method", "/rpc/" + rbac.DefaultOrgID, token,
			`{"jsonrpc":"2.0","id":1,"method":"eth_getProof","Method":"eth_blockNumber","params":["` + envelopeAddrA + `",[],"latest"]}`},
		{"authenticated params then Params", "/rpc/" + rbac.DefaultOrgID, token,
			`{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":["` + envelopeAddrA + `","latest"],"Params":["` + envelopeAddrB + `","latest"]}`},
		{"authenticated nested data and Data", "/rpc/" + rbac.DefaultOrgID, token,
			`{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"` + envelopeIdentity + `","data":"0x1111","Data":"0x2222"},"latest"]}`},
		// A Go-based node reads To as the call target; the proxy's exact
		// lookup would see a call without one.
		{"authenticated call with To", "/rpc/" + rbac.DefaultOrgID, token,
			`{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"To":"` + envelopeIdentity + `","data":"0x1111"},"latest"]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			relay.reset()
			status, body := postRPC(t, serverURL+tc.path, tc.token, tc.body)
			if status != http.StatusBadRequest {
				t.Errorf("status = %d, want 400; body=%s", status, body)
			}
			if strings.TrimSpace(string(body)) != `{"error":"invalid JSON-RPC request"}` {
				t.Errorf("rejection must be opaque, got %s", body)
			}
			assertNoStackLeakage(t, body)
			if got := relay.received(); len(got) != 0 {
				t.Errorf("an ambiguous envelope reached the node: %q", got)
			}
		})
	}
}

func TestE2E_RequestEnvelope_NodeReceivesCanonicalBody(t *testing.T) {
	userDID := "did:privado:envelope_canonical_user"
	relay := newRecordingRelay(t)
	srv, serverURL, cleanup := setupE2EWithVerifierAndNode(t, &mockPrivadoVerifier{userDID: userDID}, relay.srv.URL)
	defer cleanup()
	seedAnonymousGroup(t, srv.DB())
	createRBACUser(t, srv.DB(), userDID, true, false)
	token := getJWTToken(t, serverURL, userDID)

	cases := []struct {
		name, path, token, body, want string
		wantID                        any
	}{
		{"anonymous, string id, extra member dropped", "/", "",
			`{"id":"abc","method":"eth_chainId","jsonrpc":"2.0","params":[],"foo":"bar"}`,
			`{"jsonrpc":"2.0","id":"abc","method":"eth_chainId","params":[]}`, "abc"},
		{"authenticated eth_getBalance", "/rpc/" + rbac.DefaultOrgID, token,
			`{"jsonrpc":"2.0","method":"eth_getBalance","params":["` + envelopeAddrA + `","latest"],"id":5}`,
			`{"jsonrpc":"2.0","id":5,"method":"eth_getBalance","params":["` + envelopeAddrA + `","latest"]}`, float64(5)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			relay.reset()
			status, body := postRPC(t, serverURL+tc.path, tc.token, tc.body)
			if status != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", status, body)
			}
			got := relay.received()
			if len(got) != 1 {
				t.Fatalf("node received %d requests, want 1: %q", len(got), got)
			}
			if got[0] != tc.want {
				t.Errorf("node received\n  %s\nwant\n  %s", got[0], tc.want)
			}
			var resp struct {
				ID     any             `json:"id"`
				Result json.RawMessage `json:"result"`
				Error  json.RawMessage `json:"error"`
			}
			if err := json.Unmarshal(body, &resp); err != nil {
				t.Fatalf("response is not JSON-RPC: %v: %s", err, body)
			}
			if resp.ID != tc.wantID {
				t.Errorf("response id = %#v, want %#v", resp.ID, tc.wantID)
			}
			if len(resp.Result) == 0 || len(resp.Error) != 0 {
				t.Errorf("node must answer the forwarded request: %s", body)
			}
		})
	}
}
