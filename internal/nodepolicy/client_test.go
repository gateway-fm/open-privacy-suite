package nodepolicy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func signedSubmissionFixture(t *testing.T, blob bool) (Identity, []byte, string) {
	t.Helper()
	b, err := os.ReadFile("testdata/envelopes-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture map[string]json.RawMessage
	if err := json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	identityKey, rawKey := "transaction_identity", "raw_transaction"
	if blob {
		identityKey, rawKey = "blob_identity", "blob_transaction"
	}
	wire := fixture[identityKey]
	i, err := testVerifier().OpenIdentity(wire)
	if err != nil {
		t.Fatal(err)
	}
	var raw string
	if err := json.Unmarshal(fixture[rawKey], &raw); err != nil {
		t.Fatal(err)
	}
	return i, wire, raw
}

func TestPrivateNodeClientBindsAuthenticatedRPCAndExactPayloads(t *testing.T) {
	expectedIdentity, identity, rawTx := signedSubmissionFixture(t, false)
	simulation, _ := EncodeSimulation(SimulationRequest{Method: "eth_call", Params: json.RawMessage(`[{"from":"0x1111111111111111111111111111111111111111"}]`)})
	simulationIdentity := identityFixture()
	simulationIdentity.Scope, simulationIdentity.ContextID, simulationIdentity.BindingHash = "simulation", "sim-1", SimulationHash(simulation)
	simulationWire, _ := testSigner().Seal("identity", simulationIdentity)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer private-test-token" {
			t.Error("private authentication missing")
		}
		var req struct {
			JSONRPC string            `json:"jsonrpc"`
			ID      string            `json:"id"`
			Method  string            `json:"method"`
			Params  []json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			return
		}
		if req.JSONRPC != "2.0" || req.ID == "" {
			t.Error("missing request binding")
		}
		var result any
		switch req.Method {
		case "ops_policyStatus":
			if len(req.Params) != 0 {
				t.Error("status params")
			}
			result = NodeStatus{ProtocolVersion: 1, Network: identityFixture().Network, Capabilities: RequiredCapabilities(), Version: 7, Digest: strings.Repeat("a", 64), ExpiresAt: 1100, Ready: true, Reason: ""}
		case "ops_submitTransaction":
			var submitted string
			if len(req.Params) != 2 || json.Unmarshal(req.Params[1], &submitted) != nil || submitted != rawTx {
				t.Error("submit payload changed")
			}
			result = Submission{TransactionHash: expectedIdentity.BindingHash, ContextID: expectedIdentity.ContextID, Status: "accepted"}
		case "ops_simulate":
			var encoded string
			if len(req.Params) != 2 {
				t.Error("simulate params")
				return
			}
			if err := json.Unmarshal(req.Params[1], &encoded); err != nil {
				t.Error(err)
			}
			if encoded != base64.StdEncoding.EncodeToString(simulation) {
				t.Error("simulation bytes changed")
			}
			result = "0x1234"
		default:
			t.Errorf("unexpected method %s", req.Method)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}))
	defer s.Close()
	c, err := NewClient(s.URL, "private-test-token", identityFixture().Network, s.Client())
	if err != nil {
		t.Fatal(err)
	}
	status, err := c.PolicyStatus(context.Background())
	if err != nil || !status.Ready {
		t.Fatalf("status %+v %v", status, err)
	}
	if _, err := c.SubmitTransaction(context.Background(), identity, rawTx); err != nil {
		t.Fatal(err)
	}
	result, err := c.Simulate(context.Background(), simulationWire, simulation)
	if err != nil || string(result) != `"0x1234"` {
		t.Fatalf("simulation result %s %v", result, err)
	}
}

func TestPrivateNodeClientRejectsMismatchedSimulationBeforeSending(t *testing.T) {
	request, _ := EncodeSimulation(SimulationRequest{Method: "eth_call", Params: json.RawMessage(`[{"from":"0x1111111111111111111111111111111111111111"}]`)})
	for _, what := range []string{"scope", "network", "hash", "signer"} {
		t.Run(what, func(t *testing.T) {
			i := identityFixture()
			i.Scope = "simulation"
			i.BindingHash = SimulationHash(request)
			switch what {
			case "scope":
				i.Scope = "transaction"
			case "network":
				i.Network.DeploymentID = "other"
			case "hash":
				i.BindingHash = identityFixture().BindingHash
			case "signer":
				i.Signer = "0x" + strings.Repeat("22", 20)
			}
			wire, _ := testSigner().Seal("identity", i)
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Error("mismatched simulation sent to private node")
				w.WriteHeader(500)
			}))
			defer s.Close()
			c, err := NewClient(s.URL, "private-test-token", identityFixture().Network, s.Client())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Simulate(context.Background(), wire, request); !errors.Is(err, ErrIdentity) {
				t.Fatalf("simulation binding not rejected: %v", err)
			}
		})
	}
}

func TestPrivateNodeClientRejectsMismatchedSubmission(t *testing.T) {
	for _, what := range []string{"response_hash", "response_context", "input_binding"} {
		t.Run(what, func(t *testing.T) {
			i, _, rawTx := signedSubmissionFixture(t, false)
			ack := Submission{TransactionHash: i.BindingHash, ContextID: i.ContextID, Status: "accepted"}
			switch what {
			case "response_hash":
				ack.TransactionHash = identityFixture().BindingHash
			case "response_context":
				ack.ContextID = "another-context"
			case "input_binding":
				i.BindingHash = identityFixture().BindingHash
			}
			wire, _ := testSigner().Seal("identity", i)
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req map[string]json.RawMessage
				_ = json.NewDecoder(r.Body).Decode(&req)
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req["id"], "result": ack})
			}))
			defer s.Close()
			c, err := NewClient(s.URL, "private-test-token", i.Network, s.Client())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.SubmitTransaction(context.Background(), wire, rawTx); err == nil {
				t.Fatal("mismatched submitted transaction/context accepted")
			}
		})
	}
}

func TestPrivateNodeClientBindsBlobConsensusHashExcludingSidecar(t *testing.T) {
	i, wire, raw := signedSubmissionFixture(t, true)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]json.RawMessage
		_ = json.NewDecoder(r.Body).Decode(&req)
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req["id"], "result": Submission{TransactionHash: i.BindingHash, ContextID: i.ContextID, Status: "accepted"}})
	}))
	defer s.Close()
	c, err := NewClient(s.URL, "private-test-token", i.Network, s.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.SubmitTransaction(context.Background(), wire, raw); err != nil {
		t.Fatalf("network wrapper changed consensus binding: %v", err)
	}
}

func TestPrivateNodeClientFailsClosedOnWrongResponses(t *testing.T) {
	for _, what := range []string{"http_failure", "wrong_id", "duplicate", "result_and_error", "unknown_result", "network", "protocol", "redirect", "rpc_error", "oversize"} {
		t.Run(what, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				var req map[string]json.RawMessage
				_ = json.Unmarshal(body, &req)
				id := string(req["id"])
				status := NodeStatus{ProtocolVersion: 1, Network: identityFixture().Network, Capabilities: RequiredCapabilities(), Version: 7, Digest: strings.Repeat("a", 64), ExpiresAt: 1100, Ready: true, Reason: ""}
				switch what {
				case "http_failure":
					w.WriteHeader(503)
					return
				case "redirect":
					http.Redirect(w, r, "http://example.invalid", 307)
					return
				case "wrong_id":
					id = `"different"`
				case "duplicate":
					_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+id+`,"id":`+id+`,"result":{}}`)
					return
				case "result_and_error":
					_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+id+`,"result":{},"error":{"code":-1,"message":"private details"}}`)
					return
				case "unknown_result":
					_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+id+`,"result":{"unexpected":true}}`)
					return
				case "rpc_error":
					_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+id+`,"error":{"code":-32000,"message":"private details"}}`)
					return
				case "network":
					status.Network.DeploymentID = "other"
				case "protocol":
					status.ProtocolVersion++
				case "oversize":
					_, _ = io.WriteString(w, strings.Repeat(" ", MaxNodeResponseBytes+1))
					return
				}
				raw, _ := json.Marshal(status)
				_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+id+`,"result":`+string(raw)+`}`)
			}))
			defer s.Close()
			c, err := NewClient(s.URL, "private-test-token", identityFixture().Network, s.Client())
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.PolicyStatus(context.Background())
			if err == nil {
				t.Fatal("invalid private response accepted")
			}
			if strings.Contains(err.Error(), "private details") {
				t.Fatal("node error leaked")
			}
			if what == "rpc_error" && !errors.Is(err, ErrNodeRejected) {
				t.Fatalf("node rejection not classified: %v", err)
			}
		})
	}
}
