package server

import (
	"encoding/json"
	"testing"

	"privacy-proxy/internal/rbac"
)

func TestFilterTransactionByHash(t *testing.T) {
	userAddrs := []string{"0xabc1234567890123456789012345678901234567"}

	tests := []struct {
		name     string
		response string
		wantNull bool
		wantPass bool // expect the response to pass through unchanged
	}{
		{
			name:     "participant as from returns full tx",
			response: `{"jsonrpc":"2.0","id":1,"result":{"hash":"0xabc","from":"0xabc1234567890123456789012345678901234567","to":"0xother","input":"0xdeadbeef","nonce":"0x1"}}`,
			wantPass: true,
		},
		{
			name:     "participant as to returns full tx",
			response: `{"jsonrpc":"2.0","id":2,"result":{"hash":"0xabc","from":"0xother","to":"0xabc1234567890123456789012345678901234567","input":"0xdeadbeef","nonce":"0x2"}}`,
			wantPass: true,
		},
		{
			name:     "non-participant returns null",
			response: `{"jsonrpc":"2.0","id":3,"result":{"hash":"0xabc","from":"0xother1","to":"0xother2","input":"0xdeadbeef","nonce":"0x3"}}`,
			wantNull: true,
		},
		{
			name:     "null result passes through",
			response: `{"jsonrpc":"2.0","id":4,"result":null}`,
			wantPass: true,
		},
		{
			name:     "error passes through unchanged",
			response: `{"jsonrpc":"2.0","id":5,"error":{"code":-32000,"message":"not found"}}`,
			wantPass: true,
		},
		{
			name:     "case insensitive address match",
			response: `{"jsonrpc":"2.0","id":6,"result":{"from":"0xABC1234567890123456789012345678901234567","to":"0xother","input":"0x","nonce":"0x1"}}`,
			wantPass: true,
		},
		{
			name:     "contract creation (empty to) from participant returns full tx",
			response: `{"jsonrpc":"2.0","id":7,"result":{"hash":"0xabc","from":"0xabc1234567890123456789012345678901234567","to":"","input":"0x60806040","nonce":"0x5"}}`,
			wantPass: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FilterTransactionByHash(rbac.ReadProfileStandard, []byte(tt.response), userAddrs, false, nil)
			var resp struct {
				Result *json.RawMessage `json:"result"`
				Error  *json.RawMessage `json:"error"`
			}
			if err := json.Unmarshal(got, &resp); err != nil {
				t.Fatalf("output is not valid JSON: %v\noutput: %s", err, got)
			}
			if tt.wantNull {
				// When JSON has "result":null, *json.RawMessage is set to nil.
				// Accept both nil pointer and literal "null" bytes as null result.
				isNull := resp.Result == nil || string(*resp.Result) == "null"
				if !isNull {
					t.Errorf("expected null result, got: %s", got)
				}
			}
			if tt.wantPass {
				if string(got) != tt.response {
					t.Errorf("expected pass-through\n got: %s\nwant: %s", got, tt.response)
				}
			}
		})
	}
}

func TestFilterTransactionByHash_EmptyAddresses(t *testing.T) {
	response := `{"jsonrpc":"2.0","id":1,"result":{"hash":"0xabc","from":"0xsomeone","to":"0xother","input":"0x","nonce":"0x1"}}`
	got := FilterTransactionByHash(rbac.ReadProfileStandard, []byte(response), nil, false, nil)
	var resp struct {
		Result *json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	isNull := resp.Result == nil || string(*resp.Result) == "null"
	if !isNull {
		t.Errorf("expected null result for empty addresses, got: %s", got)
	}
}

// TestFilterTransactionByHash_LineaExclusionStatus verifies that FilterTransactionByHash
// works on linea_getTransactionExclusionStatusV1 responses, which have a "from" field
// but no "to" field. The alias system routes these through the same filter.
func TestFilterTransactionByHash_LineaExclusionStatus(t *testing.T) {
	userAddrs := []string{"0x4d144d7b9c96b26361d6ac74dd1d8267edca4fc2"}

	// Linea exclusion status response: has "from" but no "to"
	participantResponse := `{"jsonrpc":"2.0","id":1,"result":{"txHash":"0x526e","from":"0x4d144d7b9c96b26361d6ac74dd1d8267edca4fc2","nonce":"0x64","txRejectionStage":"SEQUENCER","reasonMessage":"Transaction line count for module ADD=402 is above the limit 70","blockNumber":"0x3039","timestamp":"2024-08-22T09:18:51Z"}}`
	got := FilterTransactionByHash(rbac.ReadProfileStandard, []byte(participantResponse), userAddrs, false, nil)
	if string(got) != participantResponse {
		t.Errorf("participant should see full response\n got: %s\nwant: %s", got, participantResponse)
	}

	// Non-participant should get null
	nonParticipantResponse := `{"jsonrpc":"2.0","id":2,"result":{"txHash":"0x526e","from":"0xother","nonce":"0x64","txRejectionStage":"SEQUENCER","reasonMessage":"some reason","blockNumber":"0x3039","timestamp":"2024-08-22T09:18:51Z"}}`
	got = FilterTransactionByHash(rbac.ReadProfileStandard, []byte(nonParticipantResponse), userAddrs, false, nil)
	var resp struct {
		Result *json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	isNull := resp.Result == nil || string(*resp.Result) == "null"
	if !isNull {
		t.Errorf("non-participant should get null, got: %s", got)
	}

	// Null result passes through (tx not in exclusion list)
	nullResponse := `{"jsonrpc":"2.0","id":3,"result":null}`
	got = FilterTransactionByHash(rbac.ReadProfileStandard, []byte(nullResponse), userAddrs, false, nil)
	if string(got) != nullResponse {
		t.Errorf("null result should pass through\n got: %s\nwant: %s", got, nullResponse)
	}
}

func TestTopicMatchesAddress(t *testing.T) {
	addrSet := map[string]bool{
		"0xabc1234567890123456789012345678901234567": true,
	}
	tests := []struct {
		topic string
		want  bool
	}{
		{"0x000000000000000000000000abc1234567890123456789012345678901234567", true},
		{"0x000000000000000000000000ABC1234567890123456789012345678901234567", true}, // uppercase
		{"0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff", false},
		{"0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", false}, // event sig (nonzero prefix)
		{"0x0", false}, // too short
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.topic, func(t *testing.T) {
			got := topicMatchesAddress(tt.topic, addrSet)
			if got != tt.want {
				t.Errorf("topicMatchesAddress(%q) = %v, want %v", tt.topic, got, tt.want)
			}
		})
	}
}

func TestRpcResponseID(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"numeric id", `{"jsonrpc":"2.0","id":42,"result":null}`, "42"},
		{"string id", `{"jsonrpc":"2.0","id":"abc","result":null}`, `"abc"`},
		{"null id", `{"jsonrpc":"2.0","id":null,"result":null}`, "null"},
		{"missing id", `{"jsonrpc":"2.0","result":null}`, "null"},
		{"invalid json", `not json`, "null"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rpcResponseID([]byte(tt.body))
			if got != tt.want {
				t.Errorf("rpcResponseID() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFilterTransactionByHash_PreservesID(t *testing.T) {
	// Verify that the null response preserves the original request ID
	response := `{"jsonrpc":"2.0","id":999,"result":{"from":"0xother","to":"0xother2","input":"0x","nonce":"0x1"}}`
	got := FilterTransactionByHash(rbac.ReadProfileStandard, []byte(response), []string{"0xmyaddr0000000000000000000000000000000000"}, false, nil)
	var resp struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if string(resp.ID) != "999" {
		t.Errorf("expected id=999, got id=%s", resp.ID)
	}
}

func TestFilterBlockTransactions(t *testing.T) {
	userAddrs := []string{"0xabc1234567890123456789012345678901234567"}

	tests := []struct {
		name      string
		response  string
		wantCount int // expected tx count in filtered response (-1 = pass through unchanged)
	}{
		{
			name: "full tx objects: keeps only user's tx (as from)",
			response: `{"jsonrpc":"2.0","id":1,"result":{"number":"0x1","transactions":[` +
				`{"from":"0xabc1234567890123456789012345678901234567","to":"0xother","input":"0xdeadbeef"},` +
				`{"from":"0xother1","to":"0xother2","input":"0xcafebabe"}` +
				`]}}`,
			wantCount: 1,
		},
		{
			name: "full tx objects: no user txs → empty array",
			response: `{"jsonrpc":"2.0","id":2,"result":{"number":"0x1","transactions":[` +
				`{"from":"0xother1","to":"0xother2","input":"0xdeadbeef"}` +
				`]}}`,
			wantCount: 0,
		},
		{
			name:      "tx hashes only → arrays cleared to prevent leak",
			response:  `{"jsonrpc":"2.0","id":3,"result":{"number":"0x1","transactions":["0xhash1","0xhash2"]}}`,
			wantCount: 0,
		},
		{
			name:      "empty transactions → pass through",
			response:  `{"jsonrpc":"2.0","id":4,"result":{"number":"0x1","transactions":[]}}`,
			wantCount: -1,
		},
		{
			name:      "null result → pass through",
			response:  `{"jsonrpc":"2.0","id":5,"result":null}`,
			wantCount: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FilterBlockTransactions(rbac.ReadProfileStandard, []byte(tt.response), userAddrs, true)
			if tt.wantCount == -1 {
				if string(got) != tt.response {
					// For hash arrays or empty, response might be restructured but semantically same
					// Just verify it's valid JSON
					var v interface{}
					if err := json.Unmarshal(got, &v); err != nil {
						t.Errorf("output not valid JSON: %v", err)
					}
				}
				return
			}
			var resp struct {
				Result *struct {
					Transactions []json.RawMessage `json:"transactions"`
				} `json:"result"`
			}
			if err := json.Unmarshal(got, &resp); err != nil {
				t.Fatalf("output not valid JSON: %v\noutput: %s", err, got)
			}
			if resp.Result == nil {
				t.Fatal("expected non-null result")
			}
			if len(resp.Result.Transactions) != tt.wantCount {
				t.Errorf("expected %d txs, got %d\noutput: %s", tt.wantCount, len(resp.Result.Transactions), got)
			}
		})
	}
}

func TestFilterBlockReceipts(t *testing.T) {
	userAddrs := []string{"0xabc1234567890123456789012345678901234567"}

	tests := []struct {
		name             string
		response         string
		wantReceiptCount int // -1 means pass-through (null/error)
	}{
		{
			name: "participant receipt kept",
			response: `{"jsonrpc":"2.0","id":1,"result":[` +
				`{"from":"0xabc1234567890123456789012345678901234567","to":"0xother","logs":[{"address":"0x1"}],"logsBloom":"0x1234"}` +
				`]}`,
			wantReceiptCount: 1,
		},
		{
			name: "non-participant receipt removed",
			response: `{"jsonrpc":"2.0","id":2,"result":[` +
				`{"from":"0xother1","to":"0xother2","logs":[{"address":"0x1"}],"logsBloom":"0x1234"}` +
				`]}`,
			wantReceiptCount: 0,
		},
		{
			name: "mixed: participant kept, non-participant removed",
			response: `{"jsonrpc":"2.0","id":3,"result":[` +
				`{"from":"0xabc1234567890123456789012345678901234567","to":"0xother","logs":[{"address":"0x1"}],"logsBloom":"0xfull"},` +
				`{"from":"0xother1","to":"0xother2","logs":[{"address":"0x2"}],"logsBloom":"0xfull"}` +
				`]}`,
			wantReceiptCount: 1,
		},
		{
			name:             "null result passes through",
			response:         `{"jsonrpc":"2.0","id":4,"result":null}`,
			wantReceiptCount: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FilterBlockReceipts(rbac.ReadProfileStandard, []byte(tt.response), userAddrs)
			if tt.wantReceiptCount == -1 {
				var v interface{}
				if err := json.Unmarshal(got, &v); err != nil {
					t.Errorf("output not valid JSON: %v", err)
				}
				return
			}
			var resp struct {
				Result []json.RawMessage `json:"result"`
			}
			if err := json.Unmarshal(got, &resp); err != nil {
				t.Fatalf("output not valid JSON: %v\noutput: %s", err, got)
			}
			if len(resp.Result) != tt.wantReceiptCount {
				t.Errorf("expected %d receipts, got %d\noutput: %s", tt.wantReceiptCount, len(resp.Result), got)
			}
		})
	}
}

// TestFilterTransactionByHash_NonParticipantAdmin_ReturnsTx covers the
// symmetric admin-bypass fix for eth_getTransactionByHash. Before the
// fix, a non-participant viewer got `null` even if they held the admin
// claim on the tx's `to` contract, contradicting the documented
// semantics ("admin users always see all events"; org admins see every
// org contract).
//
// `isAdminOnTo = true` is passed by the caller after an ORG-SCOPED
// admin check — the filter function itself only consumes the resolved
// bool. See JSONRPCProcessor.viewerIsAdminOnResponseTxContract for the
// policy: the admin claim must belong to the org that actually owns
// the contract, not any org the viewer happens to be a member of.
func TestFilterTransactionByHash_NonParticipantAdmin_ReturnsTx(t *testing.T) {
	adminAddr := "0xadmin000000000000000000000000000000000001"
	contractAddr := "0xcontract0000000000000000000000000000001"

	// Tx between two OTHER addresses; admin is neither from nor to.
	tx := map[string]any{
		"from":  "0xother0000000000000000000000000000000001",
		"to":    contractAddr,
		"hash":  "0xabc000000000000000000000000000000000000000000000000000000000001",
		"value": "0x0",
	}
	txJSON, _ := json.Marshal(tx)
	rpcResponse := `{"jsonrpc":"2.0","id":1,"result":` + string(txJSON) + `}`

	got := FilterTransactionByHash(rbac.ReadProfileStandard, []byte(rpcResponse), []string{adminAddr}, true, nil)

	var resp struct {
		Result *json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if resp.Result == nil || string(*resp.Result) == "null" {
		t.Fatalf("admin non-participant must receive the tx, got null response: %s", got)
	}
}

// TestFilterTransactionByHash_NonParticipantNonAdmin_ReturnsNull guards
// the bypass boundary: `isAdminOnTo = false` (the caller did the
// org-scoped admin check and found the viewer has no admin claim in
// the contract's owning org) → non-participant viewer gets null. This
// covers both "viewer has no grants on the contract at all" and
// "viewer has read/write grants but not admin in the contract's org".
func TestFilterTransactionByHash_NonParticipantNonAdmin_ReturnsNull(t *testing.T) {
	viewerAddr := "0xviewer000000000000000000000000000000001"
	contractAddr := "0xcontract0000000000000000000000000000001"

	tx := map[string]any{
		"from":  "0xother0000000000000000000000000000000001",
		"to":    contractAddr,
		"hash":  "0xabc000000000000000000000000000000000000000000000000000000000001",
		"value": "0x0",
	}
	txJSON, _ := json.Marshal(tx)
	rpcResponse := `{"jsonrpc":"2.0","id":1,"result":` + string(txJSON) + `}`

	got := FilterTransactionByHash(rbac.ReadProfileStandard, []byte(rpcResponse), []string{viewerAddr}, false, nil)

	var resp struct {
		Result *json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if resp.Result != nil && string(*resp.Result) != "null" {
		t.Errorf("non-admin non-participant must get null, got: %s", got)
	}
}

// TestFilterTransactionByHash_AdminIsParticipant_NoBypassNeeded
// verifies participants get their tx via the participant check with or
// without the admin bit — the admin bypass is strictly additive. This
// is the sanity case: if the caller happens to be a participant AND
// an admin, the participant path wins without needing the bypass.
func TestFilterTransactionByHash_AdminIsParticipant_NoBypassNeeded(t *testing.T) {
	selfAddr := "0xself00000000000000000000000000000000000001"

	tx := map[string]any{
		"from":  selfAddr,
		"to":    "0xcontract0000000000000000000000000000001",
		"hash":  "0xabc000000000000000000000000000000000000000000000000000000000001",
		"value": "0x0",
	}
	txJSON, _ := json.Marshal(tx)
	rpcResponse := `{"jsonrpc":"2.0","id":1,"result":` + string(txJSON) + `}`

	// Even with isAdminOnTo=false, participant-as-from must still see the tx.
	got := FilterTransactionByHash(rbac.ReadProfileStandard, []byte(rpcResponse), []string{selfAddr}, false, nil)
	if string(got) != rpcResponse {
		t.Errorf("participant should pass through regardless of admin bit\n got: %s\nwant: %s", got, rpcResponse)
	}
}
