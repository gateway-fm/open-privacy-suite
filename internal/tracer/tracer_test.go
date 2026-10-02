package tracer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewTracer(t *testing.T) {
	tracer := NewTracer("http://localhost:8545", 0)
	if tracer == nil {
		t.Fatal("NewTracer returned nil")
	}
	if tracer.timeout != DefaultTimeout {
		t.Errorf("expected default timeout %v, got %v", DefaultTimeout, tracer.timeout)
	}

	tracer = NewTracer("http://localhost:8545", 10*time.Second)
	if tracer.timeout != 10*time.Second {
		t.Errorf("expected timeout 10s, got %v", tracer.timeout)
	}
}

func TestParseHexUint64(t *testing.T) {
	tests := []struct {
		input    string
		expected uint64
	}{
		{"0x0", 0},
		{"0x1", 1},
		{"0xa", 10},
		{"0xf", 15},
		{"0x10", 16},
		{"0xff", 255},
		{"0x100", 256},
		{"0xdeadbeef", 3735928559},
		{"deadbeef", 3735928559}, // Without 0x prefix
		{"", 0},
	}

	for _, tt := range tests {
		result := parseHexUint64(tt.input)
		if result != tt.expected {
			t.Errorf("parseHexUint64(%q) = %d, want %d", tt.input, result, tt.expected)
		}
	}
}

func TestExtractCallTargets(t *testing.T) {
	tracer := NewTracer("http://localhost:8545", DefaultTimeout)

	// Test nested call structure
	frame := &callFrame{
		Type: "CALL",
		From: "0xsender",
		To:   "0xcontract1",
		Calls: []callFrame{
			{
				Type: "STATICCALL",
				From: "0xcontract1",
				To:   "0xcontract2",
				Calls: []callFrame{
					{
						Type: "CALL",
						From: "0xcontract2",
						To:   "0xcontract3",
					},
				},
			},
			{
				Type: "DELEGATECALL",
				From: "0xcontract1",
				To:   "0xlibrary",
			},
		},
	}

	result := &TraceResult{CallTargets: make([]CallTarget, 0)}
	tracer.extractCallTargets(frame, result, 0)

	if len(result.CallTargets) != 4 {
		t.Errorf("expected 4 call targets, got %d", len(result.CallTargets))
	}

	// Verify depths
	expectedDepths := []int{0, 1, 2, 1}
	for i, depth := range expectedDepths {
		if i < len(result.CallTargets) && result.CallTargets[i].Depth != depth {
			t.Errorf("target %d: expected depth %d, got %d", i, depth, result.CallTargets[i].Depth)
		}
	}
}

func TestExtractCallTargets_CreateOperations(t *testing.T) {
	tracer := NewTracer("http://localhost:8545", DefaultTimeout)

	frame := &callFrame{
		Type: "CALL",
		From: "0xsender",
		To:   "0xfactory",
		Calls: []callFrame{
			{
				Type: "CREATE",
				From: "0xfactory",
				To:   "0xnewcontract1",
			},
			{
				Type: "CREATE2",
				From: "0xfactory",
				To:   "0xnewcontract2",
			},
		},
	}

	result := &TraceResult{CallTargets: make([]CallTarget, 0)}
	tracer.extractCallTargets(frame, result, 0)

	if !result.HasCreate {
		t.Error("expected HasCreate to be true")
	}
	if !result.HasCreate2 {
		t.Error("expected HasCreate2 to be true")
	}
	if len(result.CallTargets) != 3 {
		t.Errorf("expected 3 call targets, got %d", len(result.CallTargets))
	}
}

func TestParseCallTraceResult_AcceptsNestedSelfdestruct(t *testing.T) {
	raw := `{"type":"CALL","from":"0x1","to":"0x2","calls":[{"type":"SELFDESTRUCT","from":"0x2","to":"0x2"}]}`
	result, err := ParseCallTraceResult(json.RawMessage(raw))
	if err != nil {
		t.Fatalf("expected nested SELFDESTRUCT to parse: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestParseCallTraceResult_RejectsRootSelfdestruct(t *testing.T) {
	if _, err := ParseCallTraceResult(json.RawMessage(`{"type":"SELFDESTRUCT","from":"0x1","to":"0x1"}`)); err == nil {
		t.Fatal("expected root SELFDESTRUCT to fail closed")
	}
}

func TestParseCallTraceResult_RejectsMissingCallTarget(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "root", raw: `{"type":"CALL"}`},
		{
			name: "nested",
			raw:  `{"type":"CALL","to":"0xroot","calls":[{"type":"STATICCALL"}]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseCallTraceResult(json.RawMessage(tt.raw)); err == nil {
				t.Fatal("expected missing call target to fail closed")
			}
		})
	}
}

func TestTraceCall_MockServer(t *testing.T) {
	// Create a mock server that returns a valid trace result
	mockResponse := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"result": map[string]any{
			"type":    "CALL",
			"from":    "0xsender",
			"to":      "0xcontract",
			"gasUsed": "0x5208",
			"calls": []map[string]any{
				{
					"type": "STATICCALL",
					"from": "0xcontract",
					"to":   "0x0000000000000000000000000000000000000001",
				},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockResponse)
	}))
	defer server.Close()

	tracer := NewTracer(server.URL, 5*time.Second)
	result, err := tracer.TraceCall(context.Background(), "0xsender", "0xcontract", "0x", "", "latest")
	if err != nil {
		t.Fatalf("TraceCall failed: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if len(result.CallTargets) != 2 {
		t.Errorf("expected 2 call targets, got %d", len(result.CallTargets))
	}

	if result.GasUsed != 21000 { // 0x5208 = 21000
		t.Errorf("expected gasUsed 21000, got %d", result.GasUsed)
	}
}

func TestHasCode_Contract(t *testing.T) {
	// Mock server returns bytecode for a contract address
	mockResponse := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"result":  "0x6080604052348015600e575f80fd5b50",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockResponse)
	}))
	defer server.Close()

	tr := NewTracer(server.URL, 5*time.Second)
	hasCode, err := tr.HasCode(context.Background(), "0x1234567890abcdef1234567890abcdef12345678")
	if err != nil {
		t.Fatalf("HasCode failed: %v", err)
	}
	if !hasCode {
		t.Error("expected hasCode=true for contract address")
	}
}

func TestHasCode_EOA(t *testing.T) {
	// Mock server returns "0x" for an EOA (no code)
	mockResponse := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"result":  "0x",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockResponse)
	}))
	defer server.Close()

	tr := NewTracer(server.URL, 5*time.Second)
	hasCode, err := tr.HasCode(context.Background(), "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	if err != nil {
		t.Fatalf("HasCode failed: %v", err)
	}
	if hasCode {
		t.Error("expected hasCode=false for EOA address")
	}
}

func TestHasCode_RPCError(t *testing.T) {
	// Mock server returns an RPC error
	mockResponse := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"error": map[string]any{
			"code":    -32000,
			"message": "internal error",
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockResponse)
	}))
	defer server.Close()

	tr := NewTracer(server.URL, 5*time.Second)
	_, err := tr.HasCode(context.Background(), "0x1234567890abcdef1234567890abcdef12345678")
	if err == nil {
		t.Fatal("expected error for RPC error response")
	}
}

func TestTraceTransaction_MockServer(t *testing.T) {
	// Create a mock server that validates the request and returns a trace with CREATE2
	txHash := "0xabc123def456789012345678901234567890123456789012345678901234abcd"

	mockResponse := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"result": map[string]any{
			"type":    "CALL",
			"from":    "0xdeployer",
			"to":      "0xfactory",
			"gasUsed": "0x1e848",
			"calls": []map[string]any{
				{
					"type":    "CREATE2",
					"from":    "0xfactory",
					"to":      "0xnewcontract1",
					"gasUsed": "0xc350",
				},
				{
					"type": "CALL",
					"from": "0xfactory",
					"to":   "0xhelper",
					"calls": []map[string]any{
						{
							"type":    "CREATE",
							"from":    "0xhelper",
							"to":      "0xnewcontract2",
							"gasUsed": "0x4e20",
						},
					},
				},
			},
		},
	}

	var receivedMethod string
	var receivedParams []json.RawMessage

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		receivedMethod = req.Method
		receivedParams = req.Params

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockResponse)
	}))
	defer server.Close()

	tracer := NewTracer(server.URL, 5*time.Second)
	result, err := tracer.TraceTransaction(context.Background(), txHash)
	if err != nil {
		t.Fatalf("TraceTransaction failed: %v", err)
	}

	// Verify the correct RPC method was used
	if receivedMethod != "debug_traceTransaction" {
		t.Errorf("expected method debug_traceTransaction, got %s", receivedMethod)
	}

	// Verify tx hash was passed as first parameter
	if len(receivedParams) != 2 {
		t.Fatalf("expected 2 params, got %d", len(receivedParams))
	}
	var paramTxHash string
	json.Unmarshal(receivedParams[0], &paramTxHash)
	if paramTxHash != txHash {
		t.Errorf("expected tx hash %s, got %s", txHash, paramTxHash)
	}

	// Verify tracer config in second parameter
	var tracerCfg map[string]any
	json.Unmarshal(receivedParams[1], &tracerCfg)
	if tracerCfg["tracer"] != "callTracer" {
		t.Errorf("expected tracer callTracer, got %v", tracerCfg["tracer"])
	}

	// Verify parsed result
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if !result.HasCreate2 {
		t.Error("expected HasCreate2 to be true")
	}
	if !result.HasCreate {
		t.Error("expected HasCreate to be true")
	}

	// 4 targets: top-level CALL, CREATE2, nested CALL, nested CREATE
	if len(result.CallTargets) != 4 {
		t.Errorf("expected 4 call targets, got %d", len(result.CallTargets))
	}

	// Verify CREATE2 target
	if result.CallTargets[1].Type != "CREATE2" {
		t.Errorf("expected target[1] type CREATE2, got %s", result.CallTargets[1].Type)
	}
	if result.CallTargets[1].To != "0xnewcontract1" {
		t.Errorf("expected target[1] to 0xnewcontract1, got %s", result.CallTargets[1].To)
	}
	if result.CallTargets[1].From != "0xfactory" {
		t.Errorf("expected target[1] from 0xfactory, got %s", result.CallTargets[1].From)
	}

	// Verify nested CREATE target
	if result.CallTargets[3].Type != "CREATE" {
		t.Errorf("expected target[3] type CREATE, got %s", result.CallTargets[3].Type)
	}
	if result.CallTargets[3].To != "0xnewcontract2" {
		t.Errorf("expected target[3] to 0xnewcontract2, got %s", result.CallTargets[3].To)
	}
	if result.CallTargets[3].Depth != 2 {
		t.Errorf("expected target[3] depth 2, got %d", result.CallTargets[3].Depth)
	}

	if result.GasUsed != 125000 { // 0x1e848 = 125000
		t.Errorf("expected gasUsed 125000, got %d", result.GasUsed)
	}
}

func TestTraceCall_RPCError(t *testing.T) {
	// Create a mock server that returns an RPC error
	mockResponse := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"error": map[string]any{
			"code":    -32000,
			"message": "execution reverted",
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockResponse)
	}))
	defer server.Close()

	tracer := NewTracer(server.URL, 5*time.Second)
	_, err := tracer.TraceCall(context.Background(), "0xsender", "0xcontract", "0x", "", "latest")
	if err == nil {
		t.Fatal("expected error for RPC error response")
	}
}

func TestParseCallTraceResultRejectsStructurallyEmptyRoot(t *testing.T) {
	for _, raw := range []string{
		`null`,
		`{}`,
		`{ }`,
		`{"foo":"bar"}`,
		`{"type":"BOGUS","from":"0x1","to":"0x2"}`,
	} {
		t.Run(raw, func(t *testing.T) {
			_, err := ParseCallTraceResult(json.RawMessage(raw))
			if err == nil {
				t.Fatalf("ParseCallTraceResult(%s) unexpectedly succeeded", raw)
			}
		})
	}
}

func TestParseCallTraceResultRejectsUnknownNestedFrame(t *testing.T) {
	raw := json.RawMessage(`{
		"type":"CALL","from":"0x1","to":"0x2",
		"calls":[{"type":"BOGUS","from":"0x2","to":"0x3"}]
	}`)
	if _, err := ParseCallTraceResult(raw); err == nil {
		t.Fatal("expected unknown nested frame to fail closed")
	}
}

// buildNestedFrameChain constructs a single-child chain of depth `chainDepth`
// frames (root at depth 0, one nested CALL per level). The resulting root can
// be handed to extractCallTargets(frame, result, 0) and the deepest frame will
// be visited with depth == chainDepth-1.
func buildNestedFrameChain(chainDepth int) *callFrame {
	if chainDepth <= 0 {
		return nil
	}
	leaf := &callFrame{Type: "CALL", From: "0xsender", To: "0xleaf"}
	cur := leaf
	for i := 1; i < chainDepth; i++ {
		parent := &callFrame{
			Type:  "CALL",
			From:  "0xsender",
			To:    "0xintermediate",
			Calls: []callFrame{*cur},
		}
		cur = parent
	}
	return cur
}

// TestExtractCallTargets_MaxDepthExceeded verifies that a malicious / pathological
// trace deeper than maxTraceDepth fails closed with ErrTraceDepthExceeded rather
// than blowing the stack. The check is depth > maxTraceDepth, so a chain that
// reaches depth == maxTraceDepth+1 must trip it.
func TestExtractCallTargets_MaxDepthExceeded(t *testing.T) {
	tracer := NewTracer("http://localhost:8545", DefaultTimeout)

	// Build a chain such that the deepest extractCallTargets invocation sees
	// depth = maxTraceDepth+1 (= 257), which must return ErrTraceDepthExceeded.
	// That requires maxTraceDepth+2 frames (root at depth 0 ... leaf at 257).
	root := buildNestedFrameChain(maxTraceDepth + 2)

	result := &TraceResult{}
	err := tracer.extractCallTargets(root, result, 0)
	if err == nil {
		t.Fatal("expected ErrTraceDepthExceeded, got nil")
	}
	if err != ErrTraceDepthExceeded {
		t.Fatalf("expected ErrTraceDepthExceeded, got %v", err)
	}
}

// TestExtractCallTargets_MaxDepthAllowed verifies the boundary: a chain whose
// deepest frame is visited at depth == maxTraceDepth must succeed (the check
// is strictly '>'). That requires maxTraceDepth+1 frames.
func TestExtractCallTargets_MaxDepthAllowed(t *testing.T) {
	tracer := NewTracer("http://localhost:8545", DefaultTimeout)

	root := buildNestedFrameChain(maxTraceDepth + 1)

	result := &TraceResult{}
	if err := tracer.extractCallTargets(root, result, 0); err != nil {
		t.Fatalf("expected nil error at max allowed depth, got %v", err)
	}
	// Every frame in the chain is type CALL, so every depth contributes one
	// CallTarget. Expect maxTraceDepth+1 entries.
	if got := len(result.CallTargets); got != maxTraceDepth+1 {
		t.Fatalf("expected %d call targets, got %d", maxTraceDepth+1, got)
	}
}
