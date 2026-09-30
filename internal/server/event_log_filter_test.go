package server

import (
	"encoding/json"
	"strings"
	"testing"

	"privacy-proxy/internal/rbac"
)

// testABIProviderServer implements rbac.ABIProvider for tests.
type testABIProviderServer struct {
	abis map[string]string
}

func (p *testABIProviderServer) GetContractABI(address string) string {
	if p == nil {
		return ""
	}
	// Zero-value provider (no explicit abis map) acts as "every contract
	// has an ABI registered" — the historical default these tests assume,
	// and the path the new RD-875 deny-without-ABI gate is OFF for. Tests
	// that need to assert no-ABI behavior populate `abis` explicitly with
	// the contract addresses they care about (missing key → empty string
	// → gate fires).
	if p.abis == nil {
		return "[]"
	}
	return p.abis[address]
}

// TestFilterReceiptLogsWithEventRules_AllowedEventPreserved reproduces the bug
// where eth_getTransactionReceipt strips ALL logs -- even those matching the
// event rules allowlist. With event rules configured allowing "NumberSet"
// (topic0 = 0xaaa...), a receipt containing one allowed log and one disallowed
// log must preserve the allowed log and only strip the disallowed one.
func TestFilterReceiptLogsWithEventRules_AllowedEventPreserved(t *testing.T) {
	userAddr := "0xabc1234567890123456789012345678901234567"
	contractAddr := "0xcontract0000000000000000000000000000001"

	allowedTopic0 := "0xaaa0000000000000000000000000000000000000000000000000000000000000"
	disallowedTopic0 := "0xbbb0000000000000000000000000000000000000000000000000000000000000"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractAddr: {
				Claims: []rbac.Claim{},
				EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{
					{Topic0: allowedTopic0, Name: "NumberSet"},
				}},
			},
		},
	}

	// Build a realistic receipt with two logs: one allowed, one disallowed.
	receipt := map[string]any{
		"from":            userAddr,
		"to":              contractAddr,
		"status":          "0x1",
		"gasUsed":         "0x5208",
		"blockHash":       "0x0000000000000000000000000000000000000000000000000000000000000001",
		"blockNumber":     "0x1",
		"transactionHash": "0xabcdef",
		"logsBloom":       "0x1234",
		"logs": []map[string]any{
			{
				"address":          contractAddr,
				"topics":           []string{allowedTopic0, "0x0000000000000000000000000000000000000000000000000000000000000042"},
				"data":             "0x",
				"logIndex":         "0x0",
				"transactionIndex": "0x0",
			},
			{
				"address":          contractAddr,
				"topics":           []string{disallowedTopic0},
				"data":             "0x",
				"logIndex":         "0x1",
				"transactionIndex": "0x0",
			},
		},
	}
	receiptJSON, _ := json.Marshal(receipt)
	rpcResponse := `{"jsonrpc":"2.0","id":1,"result":` + string(receiptJSON) + `}`

	got := FilterReceiptLogsWithEventRules(rbac.ReadProfileStandard,
		[]byte(rpcResponse),
		[]string{userAddr},
		perms,
		&testABIProviderServer{},
		nil,
		nil,
	)

	var resp struct {
		Result *struct {
			Logs []json.RawMessage `json:"logs"`
		} `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\nraw: %s", err, got)
	}
	if resp.Result == nil {
		t.Fatalf("expected non-null result for participant, got null\nraw: %s", got)
	}
	if len(resp.Result.Logs) != 1 {
		t.Errorf("expected 1 log (allowed event preserved, disallowed stripped), got %d\nraw: %s",
			len(resp.Result.Logs), got)
	}

	// Verify the preserved log is the allowed one.
	if len(resp.Result.Logs) > 0 {
		var log struct {
			Topics []string `json:"topics"`
		}
		if err := json.Unmarshal(resp.Result.Logs[0], &log); err != nil {
			t.Fatalf("failed to unmarshal preserved log: %v", err)
		}
		if len(log.Topics) == 0 || log.Topics[0] != allowedTopic0 {
			t.Errorf("preserved log should have topic0=%s, got %v", allowedTopic0, log.Topics)
		}
	}
}

// TestFilterReceiptLogsWithEventRules_ParticipantSeesAddresslessOwnTxLog_RD1162
// covers the receipt-path glue added in RD-1162 (addressing a Copilot review
// note): FilterReceiptLogsWithEventRules must inject the receipt's
// transactionHash into visCtx.ParticipantTxHashes so FilterEventLogs admits an
// address-less log of the viewer's own tx (e.g. PaymentCompleted, keyed by a
// business id) instead of stripping it — while the admission stays BOUNDED by
// contract-grant access: a log from a contract the viewer has no grant on stays
// hidden even for the tx participant. The existing RD-1162 tests exercise
// FilterEventLogs directly; this one exercises the server-level receipt glue
// (passing visCtx=nil so the function must build the context itself).
func TestFilterReceiptLogsWithEventRules_ParticipantSeesAddresslessOwnTxLog_RD1162(t *testing.T) {
	userAddr := "0xabc1234567890123456789012345678901234567"
	grantedContract := "0xcontract0000000000000000000000000000001"
	ungrantedContract := "0xcontract0000000000000000000000000000002"

	// PaymentCompleted-style event: topic0 = event signature, topic1 = an
	// indexed bytes32 record key (NOT an address). No topic matches the viewer
	// and no event_rules are configured, so WITHOUT participant admission this
	// log is denied — isolating the RD-1162 path under test.
	eventTopic0 := "0xddd0000000000000000000000000000000000000000000000000000000000000"
	recordKey := "0x1111111111111111111111111111111111111111111111111111111111111111"

	// grantedContract is present (access != nil) with nil EventRules (deny-all
	// baseline); ungrantedContract is absent (access == nil).
	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			grantedContract: {Claims: []rbac.Claim{}},
		},
	}

	buildReceipt := func(emitter string) []byte {
		receipt := map[string]any{
			"from":            userAddr, // viewer is the tx sender → participant
			"to":              emitter,
			"status":          "0x1",
			"transactionHash": "0xdeadbeef",
			"logsBloom":       "0x1234",
			"logs": []map[string]any{
				{
					"address": emitter,
					"topics":  []string{eventTopic0, recordKey},
					"data":    "0x",
					// Real receipt logs carry the tx hash; logTxIsParticipant
					// matches on it against the injected ParticipantTxHashes.
					"transactionHash":  "0xdeadbeef",
					"logIndex":         "0x0",
					"transactionIndex": "0x0",
				},
			},
		}
		receiptJSON, _ := json.Marshal(receipt)
		return []byte(`{"jsonrpc":"2.0","id":1,"result":` + string(receiptJSON) + `}`)
	}

	logCount := func(t *testing.T, out []byte) int {
		t.Helper()
		var resp struct {
			Result *struct {
				Logs []json.RawMessage `json:"logs"`
			} `json:"result"`
		}
		if err := json.Unmarshal(out, &resp); err != nil {
			t.Fatalf("output not valid JSON: %v\nraw: %s", err, out)
		}
		if resp.Result == nil {
			t.Fatalf("expected non-null receipt for participant, got null\nraw: %s", out)
		}
		return len(resp.Result.Logs)
	}

	t.Run("granted emitter: participant sees address-less own-tx log", func(t *testing.T) {
		got := FilterReceiptLogsWithEventRules(rbac.ReadProfileStandard, buildReceipt(grantedContract), []string{userAddr}, perms, &testABIProviderServer{}, nil, nil)
		if n := logCount(t, got); n != 1 {
			t.Errorf("participant should see their own tx's address-less log on a granted contract; got %d logs, want 1\nraw: %s", n, got)
		}
	})

	t.Run("ungranted emitter: log stays hidden even for participant", func(t *testing.T) {
		got := FilterReceiptLogsWithEventRules(rbac.ReadProfileStandard, buildReceipt(ungrantedContract), []string{userAddr}, perms, &testABIProviderServer{}, nil, nil)
		if n := logCount(t, got); n != 0 {
			t.Errorf("participant must NOT see a log from a contract they have no grant on (bound); got %d logs, want 0\nraw: %s", n, got)
		}
	})
}

// TestFilterReceiptLogsWithEventRules_NoEventRules_DenyAll verifies that
// nil event rules deny all logs (same as empty []). No address-based fallback.
func TestFilterReceiptLogsWithEventRules_NoEventRules_DenyAll(t *testing.T) {
	userAddr := "0xabc1234567890123456789012345678901234567"
	paddedUser := "0x000000000000000000000000" + userAddr[2:]
	contractAddr := "0xcontract0000000000000000000000000000001"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractAddr: {
				Claims:     []rbac.Claim{},
				EventRules: nil, // nil = deny all (same as empty [])
			},
		},
	}

	receipt := map[string]any{
		"from":      userAddr,
		"to":        contractAddr,
		"status":    "0x1",
		"gasUsed":   "0x5208",
		"logsBloom": "0x1234",
		"logs": []map[string]any{
			{
				"address": contractAddr,
				"topics":  []string{"0xevent1", paddedUser},
				"data":    "0x",
			},
			{
				"address": contractAddr,
				"topics":  []string{"0xevent2", "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
				"data":    "0x",
			},
		},
	}
	receiptJSON, _ := json.Marshal(receipt)
	rpcResponse := `{"jsonrpc":"2.0","id":1,"result":` + string(receiptJSON) + `}`

	got := FilterReceiptLogsWithEventRules(rbac.ReadProfileStandard,
		[]byte(rpcResponse),
		[]string{userAddr},
		perms,
		&testABIProviderServer{},
		nil,
		nil,
	)

	var resp struct {
		Result *struct {
			Logs []json.RawMessage `json:"logs"`
		} `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if resp.Result == nil {
		t.Fatalf("expected non-null result for participant")
	}
	if len(resp.Result.Logs) != 0 {
		t.Errorf("nil EventRules: expected 0 logs (deny all), got %d", len(resp.Result.Logs))
	}
}

// TestFilterReceiptLogsWithEventRules_NonParticipantEntitledViaEventRule_ReturnsReceipt_RD1183
// verifies the RD-1183 fix: a viewer who is NOT the tx's from/to/visibleTo/admin
// but IS entitled to a log under their group's event rules now gets the receipt
// envelope (with that log). Before RD-1183 they got null even though eth_getLogs
// already returned them the same log — an over-restriction, not a protection.
// (A truly non-entitled non-participant still gets null — see the RD-1183 file.)
func TestFilterReceiptLogsWithEventRules_NonParticipantEntitledViaEventRule_ReturnsReceipt_RD1183(t *testing.T) {
	userAddr := "0xabc1234567890123456789012345678901234567"
	contractAddr := "0xcontract0000000000000000000000000000001"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractAddr: {
				Claims: []rbac.Claim{},
				EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{
					{Topic0: "0xaaa0000000000000000000000000000000000000000000000000000000000000", Name: "NumberSet"},
				}},
			},
		},
	}

	receipt := map[string]any{
		"from":      "0xother0000000000000000000000000000000001",
		"to":        contractAddr,
		"status":    "0x1",
		"logsBloom": "0x1234",
		"logs": []map[string]any{
			{
				"address": contractAddr,
				"topics":  []string{"0xaaa0000000000000000000000000000000000000000000000000000000000000"},
				"data":    "0x",
			},
		},
	}
	receiptJSON, _ := json.Marshal(receipt)
	rpcResponse := `{"jsonrpc":"2.0","id":1,"result":` + string(receiptJSON) + `}`

	got := FilterReceiptLogsWithEventRules(rbac.ReadProfileStandard,
		[]byte(rpcResponse),
		[]string{userAddr},
		perms,
		&testABIProviderServer{},
		nil,
		nil,
	)

	var resp struct {
		Result *struct {
			Logs      []json.RawMessage `json:"logs"`
			LogsBloom string            `json:"logsBloom"`
		} `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if resp.Result == nil {
		t.Fatalf("RD-1183: log-entitled non-participant should get the receipt, got null: %s", got)
	}
	if len(resp.Result.Logs) != 1 {
		t.Errorf("expected 1 entitled log in the receipt, got %d", len(resp.Result.Logs))
	}
	if resp.Result.LogsBloom != "0x"+strings.Repeat("0", 512) {
		t.Errorf("logsBloom must be zeroed on an admitted receipt, got %s", resp.Result.LogsBloom)
	}
}

// TestFilterReceiptLogsWithEventRules_NilPerms_FailClosed verifies that when
// permissions cannot be resolved (nil), all receipt logs are stripped (fail-closed).
func TestFilterReceiptLogsWithEventRules_NilPerms_FailClosed(t *testing.T) {
	userAddr := "0xabc1234567890123456789012345678901234567"
	contractAddr := "0xcontract0000000000000000000000000000001"

	receipt := map[string]any{
		"from":      userAddr,
		"to":        contractAddr,
		"status":    "0x1",
		"logsBloom": "0x1234",
		"logs": []map[string]any{
			{
				"address": contractAddr,
				"topics":  []string{"0xaaa0000000000000000000000000000000000000000000000000000000000000"},
				"data":    "0x",
			},
		},
	}
	receiptJSON, _ := json.Marshal(receipt)
	rpcResponse := `{"jsonrpc":"2.0","id":1,"result":` + string(receiptJSON) + `}`

	got := FilterReceiptLogsWithEventRules(rbac.ReadProfileStandard,
		[]byte(rpcResponse),
		[]string{userAddr},
		nil, // nil perms = resolution failed
		&testABIProviderServer{},
		nil,
		nil,
	)

	var resp struct {
		Result *struct {
			Logs []json.RawMessage `json:"logs"`
		} `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if resp.Result == nil {
		t.Fatalf("participant should still get a receipt (with empty logs), not null")
	}
	if len(resp.Result.Logs) != 0 {
		t.Errorf("nil perms: expected 0 logs (fail-closed), got %d", len(resp.Result.Logs))
	}
}

// TestFilterReceiptLogsWithEventRules_MultipleContracts tests filtering when
// the receipt has logs from multiple contracts with different event rules.
func TestFilterReceiptLogsWithEventRules_MultipleContracts(t *testing.T) {
	userAddr := "0xabc1234567890123456789012345678901234567"
	contract1 := "0xcontract0000000000000000000000000000001"
	contract2 := "0xcontract0000000000000000000000000000002"

	allowedTopic := "0xaaa0000000000000000000000000000000000000000000000000000000000000"
	otherTopic := "0xbbb0000000000000000000000000000000000000000000000000000000000000"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contract1: {
				Claims: []rbac.Claim{},
				EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{
					{Topic0: allowedTopic, Name: "NumberSet"},
				}},
			},
			contract2: {
				Claims: []rbac.Claim{},
				EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{
					{Topic0: otherTopic, Name: "OtherEvent"},
				}},
			},
		},
	}

	receipt := map[string]any{
		"from":      userAddr,
		"to":        contract1,
		"status":    "0x1",
		"logsBloom": "0x1234",
		"logs": []map[string]any{
			// contract1, allowed topic -> keep
			{"address": contract1, "topics": []string{allowedTopic}, "data": "0x"},
			// contract1, other topic -> strip (not in contract1's allowlist)
			{"address": contract1, "topics": []string{otherTopic}, "data": "0x"},
			// contract2, other topic -> keep (in contract2's allowlist)
			{"address": contract2, "topics": []string{otherTopic}, "data": "0x"},
			// contract2, allowed topic -> strip (not in contract2's allowlist)
			{"address": contract2, "topics": []string{allowedTopic}, "data": "0x"},
		},
	}
	receiptJSON, _ := json.Marshal(receipt)
	rpcResponse := `{"jsonrpc":"2.0","id":1,"result":` + string(receiptJSON) + `}`

	got := FilterReceiptLogsWithEventRules(rbac.ReadProfileStandard,
		[]byte(rpcResponse),
		[]string{userAddr},
		perms,
		&testABIProviderServer{},
		nil,
		nil,
	)

	var resp struct {
		Result *struct {
			Logs []json.RawMessage `json:"logs"`
		} `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if resp.Result == nil {
		t.Fatalf("expected non-null result for participant")
	}
	if len(resp.Result.Logs) != 2 {
		t.Errorf("expected 2 logs (one from each contract's allowlist), got %d\nraw: %s",
			len(resp.Result.Logs), got)
	}
}

// TestFilterReceiptLogsWithEventRules_EmptyEventRules_AllLogsStripped verifies
// that when event_rules is an empty slice (not nil), ALL logs from that
// contract are stripped. This is the "No events visible" mode.
func TestFilterReceiptLogsWithEventRules_EmptyEventRules_AllLogsStripped(t *testing.T) {
	userAddr := "0xabc1234567890123456789012345678901234567"
	contractAddr := "0xcontract0000000000000000000000000000001"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractAddr: {
				Claims:     []rbac.Claim{},
				EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{}}}, // empty = block all events

		},
	}

	receipt := map[string]any{
		"from":      userAddr,
		"to":        contractAddr,
		"status":    "0x1",
		"gasUsed":   "0x5208",
		"logsBloom": "0x1234",
		"logs": []map[string]any{
			{
				"address": contractAddr,
				"topics":  []string{"0xaaa0000000000000000000000000000000000000000000000000000000000000"},
				"data":    "0x",
			},
			{
				"address": contractAddr,
				"topics":  []string{"0xbbb0000000000000000000000000000000000000000000000000000000000000"},
				"data":    "0x",
			},
		},
	}
	receiptJSON, _ := json.Marshal(receipt)
	rpcResponse := `{"jsonrpc":"2.0","id":1,"result":` + string(receiptJSON) + `}`

	got := FilterReceiptLogsWithEventRules(rbac.ReadProfileStandard,
		[]byte(rpcResponse),
		[]string{userAddr},
		perms,
		&testABIProviderServer{},
		nil,
		nil,
	)

	var resp struct {
		Result *struct {
			Logs []json.RawMessage `json:"logs"`
		} `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\nraw: %s", err, got)
	}
	if resp.Result == nil {
		t.Fatalf("participant should still get a receipt (with empty logs), not null")
	}
	if len(resp.Result.Logs) != 0 {
		t.Errorf("empty EventRules: expected 0 logs (all events blocked), got %d\nraw: %s",
			len(resp.Result.Logs), got)
	}
}

// TestFilterLogsWithEventRules_EmptyEventRules_AllLogsStripped verifies the
// eth_getLogs response filtering: when event_rules is an empty slice, ALL logs
// from the contract are stripped.
func TestFilterLogsWithEventRules_EmptyEventRules_AllLogsStripped(t *testing.T) {
	userAddr := "0xabc1234567890123456789012345678901234567"
	paddedUser := "0x000000000000000000000000" + userAddr[2:]
	contractAddr := "0xcontract0000000000000000000000000000001"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractAddr: {
				Claims:     []rbac.Claim{},
				EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{}}}, // empty = block all events

		},
	}

	// Two logs: one with user address in topic, one without.
	// Both should be blocked because empty event rules means "no events visible".
	logs := []map[string]any{
		{
			"address": contractAddr,
			"topics":  []string{"0xaaa0000000000000000000000000000000000000000000000000000000000000", paddedUser},
			"data":    "0x",
		},
		{
			"address": contractAddr,
			"topics":  []string{"0xbbb0000000000000000000000000000000000000000000000000000000000000"},
			"data":    "0x",
		},
	}
	logsJSON, _ := json.Marshal(logs)
	rpcResponse := `{"jsonrpc":"2.0","id":1,"result":` + string(logsJSON) + `}`

	got := FilterLogsWithEventRules(rbac.ReadProfileStandard,
		[]byte(rpcResponse),
		[]string{userAddr},
		perms,
		&testABIProviderServer{},
		nil,
		nil,
	)

	var resp struct {
		Result []json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\nraw: %s", err, got)
	}
	if len(resp.Result) != 0 {
		t.Errorf("empty EventRules: expected 0 logs (all events blocked), got %d\nraw: %s",
			len(resp.Result), got)
	}
}

// TestFilterReceiptLogsWithEventRules_LogsBloomZeroed verifies that logsBloom
// is zeroed when logs are filtered.
func TestFilterReceiptLogsWithEventRules_LogsBloomZeroed(t *testing.T) {
	userAddr := "0xabc1234567890123456789012345678901234567"
	contractAddr := "0xcontract0000000000000000000000000000001"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractAddr: {
				Claims: []rbac.Claim{},
				EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{
					{Topic0: "0xaaa0000000000000000000000000000000000000000000000000000000000000", Name: "NumberSet"},
				}},
			},
		},
	}

	receipt := map[string]any{
		"from":      userAddr,
		"to":        contractAddr,
		"status":    "0x1",
		"logsBloom": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"logs": []map[string]any{
			{"address": contractAddr, "topics": []string{"0xaaa0000000000000000000000000000000000000000000000000000000000000"}, "data": "0x"},
		},
	}
	receiptJSON, _ := json.Marshal(receipt)
	rpcResponse := `{"jsonrpc":"2.0","id":1,"result":` + string(receiptJSON) + `}`

	got := FilterReceiptLogsWithEventRules(rbac.ReadProfileStandard,
		[]byte(rpcResponse),
		[]string{userAddr},
		perms,
		&testABIProviderServer{},
		nil,
		nil,
	)

	var resp struct {
		Result *struct {
			LogsBloom string `json:"logsBloom"`
		} `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if resp.Result == nil {
		t.Fatalf("expected non-null result for participant")
	}

	// logsBloom should be zeroed (0x + 512 zeros)
	expectedBloom := "0x" + string(make([]byte, 512))
	for i := range expectedBloom[2:] {
		_ = i // just ensure the length is 514
	}
	if len(resp.Result.LogsBloom) != 514 { // "0x" + 512 hex chars
		t.Errorf("logsBloom should be 514 chars (0x + 512 zeros), got %d chars: %s",
			len(resp.Result.LogsBloom), resp.Result.LogsBloom)
	}
}

// ---------------------------------------------------------------------------
// Well-known topic0 hashes for test assertions (integration-level constants).
// ---------------------------------------------------------------------------
const (
	integTransferTopic0 = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	integApprovalTopic0 = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c20b9b"
)

// Standard ERC20 ABI for integration tests.
const integERC20ABI = `[
	{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "from", "type": "address"},
			{"indexed": true, "name": "to", "type": "address"},
			{"indexed": false, "name": "value", "type": "uint256"}
		],
		"name": "Transfer",
		"type": "event"
	},
	{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "owner", "type": "address"},
			{"indexed": true, "name": "spender", "type": "address"},
			{"indexed": false, "name": "value", "type": "uint256"}
		],
		"name": "Approval",
		"type": "event"
	}
]`

// CustomEvent(uint256 indexed id, address recipient) — recipient is non-indexed.
const integCustomEventABI = `[{
	"anonymous": false,
	"inputs": [
		{"indexed": true, "name": "id", "type": "uint256"},
		{"indexed": false, "name": "recipient", "type": "address"}
	],
	"name": "CustomEvent",
	"type": "event"
}]`

// buildLogsRPCResponse wraps a logs array into a JSON-RPC eth_getLogs response.
func buildLogsRPCResponse(t *testing.T, logs []map[string]any) []byte {
	t.Helper()
	logsJSON, err := json.Marshal(logs)
	if err != nil {
		t.Fatalf("failed to marshal logs: %v", err)
	}
	return []byte(`{"jsonrpc":"2.0","id":1,"result":` + string(logsJSON) + `}`)
}

// buildReceiptRPCResponse wraps a receipt into a JSON-RPC eth_getTransactionReceipt response.
func buildReceiptRPCResponse(t *testing.T, receipt map[string]any) []byte {
	t.Helper()
	receiptJSON, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("failed to marshal receipt: %v", err)
	}
	return []byte(`{"jsonrpc":"2.0","id":1,"result":` + string(receiptJSON) + `}`)
}

// parseLogsResult unmarshals an eth_getLogs response and returns the log array.
func parseLogsResult(t *testing.T, body []byte) []json.RawMessage {
	t.Helper()
	var resp struct {
		Result []json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\nraw: %s", err, body)
	}
	return resp.Result
}

// parseReceiptLogs unmarshals a receipt response and returns the logs from result.
// Returns nil if the result is null (non-participant).
func parseReceiptLogs(t *testing.T, body []byte) *[]json.RawMessage {
	t.Helper()
	var resp struct {
		Result *struct {
			Logs []json.RawMessage `json:"logs"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\nraw: %s", err, body)
	}
	if resp.Result == nil {
		return nil
	}
	return &resp.Result.Logs
}

// ---------------------------------------------------------------------------
// I14-I20: eth_getLogs Filtering
// These test FilterLogsWithEventRules with realistic RPC response payloads.
// ---------------------------------------------------------------------------

func TestFilterLogs_I14_NoRules_DenyAll(t *testing.T) {
	// I14: No event rules configured (nil) — deny all logs (same as empty []).
	userAddr := "0xabc1234567890123456789012345678901234567"
	paddedUser := "0x000000000000000000000000" + userAddr[2:]
	contractAddr := "0xcontract0000000000000000000000000000001"
	otherPadded := "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractAddr: {
				Claims:     []rbac.Claim{},
				EventRules: nil, // nil = deny all
			},
		},
	}

	logs := []map[string]any{
		{"address": contractAddr, "topics": []string{integTransferTopic0, paddedUser}, "data": "0x"},
		{"address": contractAddr, "topics": []string{integApprovalTopic0, otherPadded}, "data": "0x"},
		{"address": contractAddr, "topics": []string{integTransferTopic0, otherPadded}, "data": "0x"},
	}

	got := FilterLogsWithEventRules(rbac.ReadProfileStandard, buildLogsRPCResponse(t, logs), []string{userAddr}, perms, &testABIProviderServer{}, nil, nil)
	result := parseLogsResult(t, got)

	if len(result) != 0 {
		t.Errorf("I14: expected 0 logs (nil event rules = deny all), got %d", len(result))
	}
}

func TestFilterLogs_I15_AllowTransferOnly(t *testing.T) {
	// I15: rules allow Transfer only — Approval logs are filtered out.
	userAddr := "0xabc1234567890123456789012345678901234567"
	contractAddr := "0xcontract0000000000000000000000000000001"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractAddr: {
				Claims: []rbac.Claim{},
				EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{
					{Topic0: integTransferTopic0, Name: "Transfer"},
				}},
			},
		},
	}

	logs := []map[string]any{
		{"address": contractAddr, "topics": []string{integTransferTopic0}, "data": "0x"},
		{"address": contractAddr, "topics": []string{integApprovalTopic0}, "data": "0x"},
	}

	got := FilterLogsWithEventRules(rbac.ReadProfileStandard, buildLogsRPCResponse(t, logs), []string{userAddr}, perms, &testABIProviderServer{}, nil, nil)
	result := parseLogsResult(t, got)

	if len(result) != 1 {
		t.Errorf("I15: expected 1 log (Transfer only), got %d", len(result))
	}
	// Verify the preserved log is Transfer
	if len(result) > 0 {
		var log struct{ Topics []string }
		json.Unmarshal(result[0], &log)
		if len(log.Topics) == 0 || !strings.EqualFold(log.Topics[0], integTransferTopic0) {
			t.Errorf("I15: preserved log should be Transfer, got topic0=%v", log.Topics)
		}
	}
}

func TestFilterLogs_I16_ParamRuleSelfMatch(t *testing.T) {
	// I16: Transfer with param 0 self, topics[1] = userA — Transfer visible.
	userAddr := "0x1234567890abcdef1234567890abcdef12345678"
	paddedUser := "0x000000000000000000000000" + userAddr[2:]
	otherPadded := "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	contractAddr := "0xcontract0000000000000000000000000000001"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractAddr: {
				Claims: []rbac.Claim{},
				EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{
					{
						Topic0: integTransferTopic0,
						Name:   "Transfer",
						ParamRules: []rbac.ParamRule{
							{Index: 0, MustBe: "self"},
						},
					},
				}},
			},
		},
	}

	abiProv := &testABIProviderServer{abis: map[string]string{contractAddr: integERC20ABI}}
	logs := []map[string]any{
		{"address": contractAddr, "topics": []string{integTransferTopic0, paddedUser, otherPadded}, "data": "0x0000000000000000000000000000000000000000000000000000000000000064"},
	}

	got := FilterLogsWithEventRules(rbac.ReadProfileStandard, buildLogsRPCResponse(t, logs), []string{userAddr}, perms, abiProv, nil, nil)
	result := parseLogsResult(t, got)

	if len(result) != 1 {
		t.Errorf("I16: expected 1 log (self match on param 0), got %d", len(result))
	}
}

func TestFilterLogs_I17_ParamRuleSelfNoMatch(t *testing.T) {
	// I17: Transfer with param 0 self, but topics[1] = userB — Transfer hidden.
	userAddr := "0x1234567890abcdef1234567890abcdef12345678"
	otherPadded := "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	contractAddr := "0xcontract0000000000000000000000000000001"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractAddr: {
				Claims: []rbac.Claim{},
				EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{
					{
						Topic0: integTransferTopic0,
						Name:   "Transfer",
						ParamRules: []rbac.ParamRule{
							{Index: 0, MustBe: "self"},
						},
					},
				}},
			},
		},
	}

	abiProv := &testABIProviderServer{abis: map[string]string{contractAddr: integERC20ABI}}
	logs := []map[string]any{
		{"address": contractAddr, "topics": []string{integTransferTopic0, otherPadded, otherPadded}, "data": "0x0000000000000000000000000000000000000000000000000000000000000064"},
	}

	got := FilterLogsWithEventRules(rbac.ReadProfileStandard, buildLogsRPCResponse(t, logs), []string{userAddr}, perms, abiProv, nil, nil)
	result := parseLogsResult(t, got)

	if len(result) != 0 {
		t.Errorf("I17: expected 0 logs (self no match), got %d", len(result))
	}
}

func TestFilterLogs_I18_EmptyRulesDenyAll(t *testing.T) {
	// I18: event_rules: [] — all logs filtered regardless of content.
	userAddr := "0xabc1234567890123456789012345678901234567"
	paddedUser := "0x000000000000000000000000" + userAddr[2:]
	contractAddr := "0xcontract0000000000000000000000000000001"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractAddr: {
				Claims:     []rbac.Claim{},
				EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{}}}, // deny all

		},
	}

	logs := []map[string]any{
		{"address": contractAddr, "topics": []string{integTransferTopic0, paddedUser}, "data": "0x"},
		{"address": contractAddr, "topics": []string{integApprovalTopic0, paddedUser}, "data": "0x"},
	}

	got := FilterLogsWithEventRules(rbac.ReadProfileStandard, buildLogsRPCResponse(t, logs), []string{userAddr}, perms, &testABIProviderServer{}, nil, nil)
	result := parseLogsResult(t, got)

	if len(result) != 0 {
		t.Errorf("I18: expected 0 logs (empty rules = deny all), got %d", len(result))
	}
}

func TestFilterLogs_I19_NoGrant_NoLogs(t *testing.T) {
	// I19: User has no grant on the contract — contract not in perms → no logs.
	userAddr := "0xabc1234567890123456789012345678901234567"
	contractAddr := "0xcontract0000000000000000000000000000001"

	// Perms with access to a different contract, not contractAddr.
	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			"0xother00000000000000000000000000000000001": {
				Claims: []rbac.Claim{},
			},
		},
	}

	logs := []map[string]any{
		{"address": contractAddr, "topics": []string{integTransferTopic0}, "data": "0x"},
	}

	got := FilterLogsWithEventRules(rbac.ReadProfileStandard, buildLogsRPCResponse(t, logs), []string{userAddr}, perms, &testABIProviderServer{}, nil, nil)
	result := parseLogsResult(t, got)

	if len(result) != 0 {
		t.Errorf("I19: expected 0 logs (no grant on contract), got %d", len(result))
	}
}

func TestFilterLogs_I20_MixedContracts_DifferentRules(t *testing.T) {
	// I20: Contract X has [Transfer] rules, Contract Z has nil (deny all).
	// Logs from X: only Transfer passes. Logs from Z: all denied.
	userAddr := "0xabc1234567890123456789012345678901234567"
	paddedUser := "0x000000000000000000000000" + userAddr[2:]
	contractX := "0xcontractx000000000000000000000000000001"
	contractZ := "0xcontractz000000000000000000000000000001"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractX: {
				Claims: []rbac.Claim{},
				EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{
					{Topic0: integTransferTopic0, Name: "Transfer"},
				}},
			},
			contractZ: {
				Claims:     []rbac.Claim{},
				EventRules: nil, // nil = deny all
			},
		},
	}

	logs := []map[string]any{
		// X: Transfer — allowed by rule
		{"address": contractX, "topics": []string{integTransferTopic0}, "data": "0x"},
		// X: Approval — blocked by rules (not in allowlist)
		{"address": contractX, "topics": []string{integApprovalTopic0}, "data": "0x"},
		// Z: log with user address in topic — blocked (nil = deny all)
		{"address": contractZ, "topics": []string{integTransferTopic0, paddedUser}, "data": "0x"},
		// Z: log without user address — blocked (nil = deny all)
		{"address": contractZ, "topics": []string{integApprovalTopic0, "0x000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}, "data": "0x"},
	}

	got := FilterLogsWithEventRules(rbac.ReadProfileStandard, buildLogsRPCResponse(t, logs), []string{userAddr}, perms, &testABIProviderServer{}, nil, nil)
	result := parseLogsResult(t, got)

	if len(result) != 1 {
		t.Errorf("I20: expected 1 log (Transfer from X only, Z denied), got %d", len(result))
	}
}

// ---------------------------------------------------------------------------
// I25-I27: Cross-Org Isolation
// ---------------------------------------------------------------------------

func TestFilterLogs_I25_CrossOrg_NoAccess(t *testing.T) {
	// I25: User in Org A, contract belongs to Org B — no access in perms → no logs.
	userAddr := "0xaaaa000000000000000000000000000000000001"
	orgBContract := "0x6666666666666666666666666666666666666666"

	// User's perms only include Org A contracts — Org B's contract is absent.
	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			"0x5555555555555555555555555555555555555555": {
				Claims: []rbac.Claim{},
				EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{
					{Topic0: integTransferTopic0, Name: "Transfer"},
				}},
			},
		},
	}

	logs := []map[string]any{
		{"address": orgBContract, "topics": []string{integTransferTopic0}, "data": "0x"},
	}

	got := FilterLogsWithEventRules(rbac.ReadProfileStandard, buildLogsRPCResponse(t, logs), []string{userAddr}, perms, &testABIProviderServer{}, nil, nil)
	result := parseLogsResult(t, got)

	if len(result) != 0 {
		t.Errorf("I25: expected 0 logs (cross-org contract not in perms), got %d", len(result))
	}
}

func TestFilterLogs_I26_PartialContractAccess(t *testing.T) {
	// I26: User has grants on X and Z but not Y — only X and Z logs appear.
	userAddr := "0xaaaa000000000000000000000000000000000001"
	contractX := "0xcontractx000000000000000000000000000001"
	contractY := "0xcontracty000000000000000000000000000001"
	contractZ := "0xcontractz000000000000000000000000000001"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractX: {
				Claims: []rbac.Claim{},
				EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{
					{Topic0: integTransferTopic0, Name: "Transfer"},
				}},
			},
			contractZ: {
				Claims: []rbac.Claim{},
				EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{
					{Topic0: integTransferTopic0, Name: "Transfer"},
				}},
			},
			// No entry for contractY
		},
	}

	logs := []map[string]any{
		{"address": contractX, "topics": []string{integTransferTopic0}, "data": "0x"},
		{"address": contractY, "topics": []string{integTransferTopic0}, "data": "0x"},
		{"address": contractZ, "topics": []string{integTransferTopic0}, "data": "0x"},
	}

	got := FilterLogsWithEventRules(rbac.ReadProfileStandard, buildLogsRPCResponse(t, logs), []string{userAddr}, perms, &testABIProviderServer{}, nil, nil)
	result := parseLogsResult(t, got)

	if len(result) != 2 {
		t.Errorf("I26: expected 2 logs (X and Z only), got %d", len(result))
	}
}

func TestFilterReceipt_I27_MixedOrgs(t *testing.T) {
	// I27: Receipt with logs from contracts in different orgs.
	// User has access to Org A's contract but not Org B's.
	userAddr := "0xabc1234567890123456789012345678901234567"
	orgAContract := "0x5555555555555555555555555555555555555555"
	orgBContract := "0x6666666666666666666666666666666666666666"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			orgAContract: {
				Claims: []rbac.Claim{},
				EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{
					{Topic0: integTransferTopic0, Name: "Transfer"},
				}},
			},
			// No access for orgBContract
		},
	}

	receipt := map[string]any{
		"from":      userAddr,
		"to":        orgAContract,
		"status":    "0x1",
		"logsBloom": "0x1234",
		"logs": []map[string]any{
			{"address": orgAContract, "topics": []string{integTransferTopic0}, "data": "0x"},
			{"address": orgBContract, "topics": []string{integTransferTopic0}, "data": "0x"},
		},
	}

	got := FilterReceiptLogsWithEventRules(rbac.ReadProfileStandard,
		buildReceiptRPCResponse(t, receipt), []string{userAddr}, perms, &testABIProviderServer{}, nil,
		nil,
	)
	logs := parseReceiptLogs(t, got)
	if logs == nil {
		t.Fatal("I27: expected non-null result for participant")
	}
	if len(*logs) != 1 {
		t.Errorf("I27: expected 1 log (own-org only), got %d", len(*logs))
	}
}

// ---------------------------------------------------------------------------
// I28-I30: Admin Bypass
// ---------------------------------------------------------------------------

func TestFilterLogs_I28_AdminClaim_Bypass(t *testing.T) {
	// I28: Admin bypass on contract: admin sees ALL logs regardless of
	// event_rules. Admin status is now ORG-SCOPED — passed via
	// isAdminByContract by the caller (resolved from contract's owning
	// org only). Semantics unchanged; mechanism no-longer-merged.
	contractAddr := "0xcontract0000000000000000000000000000001"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractAddr: {
				EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{
					{Topic0: integTransferTopic0, Name: "Transfer"},
				}},
			},
		},
	}

	logs := []map[string]any{
		{"address": contractAddr, "topics": []string{integTransferTopic0}, "data": "0x"},
		{"address": contractAddr, "topics": []string{integApprovalTopic0}, "data": "0x"},
	}

	adminMap := map[string]bool{contractAddr: true}
	got := FilterLogsWithEventRules(rbac.ReadProfileStandard, buildLogsRPCResponse(t, logs), []string{"0xadmin"}, perms, &testABIProviderServer{}, nil, adminMap)
	result := parseLogsResult(t, got)

	if len(result) != 2 {
		t.Errorf("I28: admin should bypass event rules, expected 2 logs, got %d", len(result))
	}
}

func TestFilterLogs_I29_OrgAdmin_Bypass(t *testing.T) {
	// I29: Org admin sees ALL logs on every org contract via the admin
	// bypass. Org admin status is determined at the caller (resolver
	// via computeOrgAdminPermissions → viewerAdminContracts produces
	// the map for the contract's owning org) and passed here as
	// isAdminByContract.
	otherAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	paddedOther := "0x000000000000000000000000" + otherAddr[2:]
	contractAddr := "0xcontract0000000000000000000000000000001"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractAddr: {
				EventRules: nil, // normally deny-all — admin bypasses
			},
		},
	}

	logs := []map[string]any{
		{"address": contractAddr, "topics": []string{integTransferTopic0, paddedOther}, "data": "0x"},
		{"address": contractAddr, "topics": []string{integApprovalTopic0, paddedOther}, "data": "0x"},
	}

	userAddr := "0xabc1234567890123456789012345678901234567"
	adminMap := map[string]bool{contractAddr: true}
	got := FilterLogsWithEventRules(rbac.ReadProfileStandard, buildLogsRPCResponse(t, logs), []string{userAddr}, perms, &testABIProviderServer{}, nil, adminMap)
	result := parseLogsResult(t, got)

	if len(result) != 2 {
		t.Errorf("I29: org admin should see all logs via admin bypass, expected 2, got %d", len(result))
	}
}

func TestFilterLogs_I30_ReadClaim_NoBypass(t *testing.T) {
	// I30: Read claim only, rules: [Transfer] → only Transfer visible.
	contractAddr := "0xcontract0000000000000000000000000000001"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractAddr: {
				Claims: []rbac.Claim{},
				EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{
					{Topic0: integTransferTopic0, Name: "Transfer"},
				}},
			},
		},
	}

	logs := []map[string]any{
		{"address": contractAddr, "topics": []string{integTransferTopic0}, "data": "0x"},
		{"address": contractAddr, "topics": []string{integApprovalTopic0}, "data": "0x"},
	}

	got := FilterLogsWithEventRules(rbac.ReadProfileStandard, buildLogsRPCResponse(t, logs), []string{"0xuser"}, perms, &testABIProviderServer{}, nil, nil)
	result := parseLogsResult(t, got)

	if len(result) != 1 {
		t.Errorf("I30: read claim should not bypass event_rules, expected 1 log, got %d", len(result))
	}
}

// ---------------------------------------------------------------------------
// I31-I33: Multiple Grants Union
// These test the union of event rules from multiple grants as reflected
// in the resolved ContractAccess (the resolver merges before filtering).
// ---------------------------------------------------------------------------

func TestFilterLogs_I31_UnionRules(t *testing.T) {
	// I31: Group1 allows [Transfer], Group2 allows [Approval] → union: both visible.
	// Resolved ContractAccess already has the union.
	contractAddr := "0xcontract0000000000000000000000000000001"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractAddr: {
				Claims: []rbac.Claim{},
				EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{
					{Topic0: integTransferTopic0, Name: "Transfer"},
					{Topic0: integApprovalTopic0, Name: "Approval"},
				}},
			},
		},
	}

	logs := []map[string]any{
		{"address": contractAddr, "topics": []string{integTransferTopic0}, "data": "0x"},
		{"address": contractAddr, "topics": []string{integApprovalTopic0}, "data": "0x"},
	}

	got := FilterLogsWithEventRules(rbac.ReadProfileStandard, buildLogsRPCResponse(t, logs), []string{"0xuser"}, perms, &testABIProviderServer{}, nil, nil)
	result := parseLogsResult(t, got)

	if len(result) != 2 {
		t.Errorf("I31: union of Transfer+Approval should show both, got %d", len(result))
	}
}

func TestFilterLogs_I32_NilRulesDenyAll(t *testing.T) {
	// I32: Group1 allows [Transfer], Group2 has nil → resolved to nil.
	// nil = deny all — no logs pass.
	userAddr := "0xabc1234567890123456789012345678901234567"
	paddedUser := "0x000000000000000000000000" + userAddr[2:]
	contractAddr := "0xcontract0000000000000000000000000000001"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractAddr: {
				Claims:     []rbac.Claim{},
				EventRules: nil, // nil = deny all
			},
		},
	}

	logs := []map[string]any{
		{"address": contractAddr, "topics": []string{integTransferTopic0, paddedUser}, "data": "0x"},
		{"address": contractAddr, "topics": []string{integApprovalTopic0, paddedUser}, "data": "0x"},
		{"address": contractAddr, "topics": []string{"0x1111111111111111111111111111111111111111111111111111111111111111", paddedUser}, "data": "0x"},
	}

	got := FilterLogsWithEventRules(rbac.ReadProfileStandard, buildLogsRPCResponse(t, logs), []string{userAddr}, perms, &testABIProviderServer{}, nil, nil)
	result := parseLogsResult(t, got)

	if len(result) != 0 {
		t.Errorf("I32: nil event rules should deny all logs, got %d", len(result))
	}
}

func TestFilterLogs_I33_UnionParamRules(t *testing.T) {
	// I33: Group1 allows Transfer with param 0 self, Group2 allows Transfer with param 1 self.
	// Resolved union: Transfer with param rules on both positions (OR semantics).
	userAddr := "0x1234567890abcdef1234567890abcdef12345678"
	paddedUser := "0x000000000000000000000000" + userAddr[2:]
	otherPadded := "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	contractAddr := "0xcontract0000000000000000000000000000001"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractAddr: {
				Claims: []rbac.Claim{},
				EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{
					{
						Topic0: integTransferTopic0,
						Name:   "Transfer",
						ParamRules: []rbac.ParamRule{
							{Index: 0, MustBe: "self"},
							{Index: 1, MustBe: "self"},
						},
					},
				}},
			},
		},
	}

	abiProv := &testABIProviderServer{abis: map[string]string{contractAddr: integERC20ABI}}

	// User is "to" (param 1) but not "from" (param 0) — should match via OR.
	logs := []map[string]any{
		{"address": contractAddr, "topics": []string{integTransferTopic0, otherPadded, paddedUser}, "data": "0x0000000000000000000000000000000000000000000000000000000000000064"},
	}

	got := FilterLogsWithEventRules(rbac.ReadProfileStandard, buildLogsRPCResponse(t, logs), []string{userAddr}, perms, abiProv, nil, nil)
	result := parseLogsResult(t, got)

	if len(result) != 1 {
		t.Errorf("I33: union param rules (OR semantics), user matches param 1, expected 1, got %d", len(result))
	}
}

// ---------------------------------------------------------------------------
// I34-I36: ParamRule Integration
// ---------------------------------------------------------------------------

func TestFilterLogs_I34_NonIndexed_SelfMatch(t *testing.T) {
	// I34: CustomEvent(uint256 indexed id, address recipient), data has userA at param 1 → visible.
	userAddr := "0x1234567890abcdef1234567890abcdef12345678"
	userAddrPadded := "000000000000000000000000" + userAddr[2:]
	contractAddr := "0xcontract0000000000000000000000000000001"

	sigs, err := rbac.ExtractEventSignatures(integCustomEventABI)
	if err != nil {
		t.Fatalf("failed to extract sigs: %v", err)
	}
	if len(sigs) != 1 {
		t.Fatalf("expected 1 sig, got %d", len(sigs))
	}
	customTopic0 := sigs[0].Topic0

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractAddr: {
				Claims: []rbac.Claim{},
				EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{
					{
						Topic0: customTopic0,
						Name:   "CustomEvent",
						ParamRules: []rbac.ParamRule{
							{Index: 1, MustBe: "self"}, // recipient (non-indexed)
						},
					},
				}},
			},
		},
	}

	abiProv := &testABIProviderServer{abis: map[string]string{contractAddr: integCustomEventABI}}
	idTopic := "0x000000000000000000000000000000000000000000000000000000000000002a"

	logs := []map[string]any{
		{"address": contractAddr, "topics": []string{customTopic0, idTopic}, "data": "0x" + userAddrPadded},
	}

	got := FilterLogsWithEventRules(rbac.ReadProfileStandard, buildLogsRPCResponse(t, logs), []string{userAddr}, perms, abiProv, nil, nil)
	result := parseLogsResult(t, got)

	if len(result) != 1 {
		t.Errorf("I34: non-indexed self match should pass, expected 1, got %d", len(result))
	}
}

func TestFilterLogs_I35_NonIndexed_SelfNoMatch(t *testing.T) {
	// I35: CustomEvent data has userB at param 1 (not userA) → hidden.
	userAddr := "0x1234567890abcdef1234567890abcdef12345678"
	otherAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	otherAddrPadded := "000000000000000000000000" + otherAddr[2:]
	contractAddr := "0xcontract0000000000000000000000000000001"

	sigs, err := rbac.ExtractEventSignatures(integCustomEventABI)
	if err != nil {
		t.Fatalf("failed to extract sigs: %v", err)
	}
	customTopic0 := sigs[0].Topic0

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractAddr: {
				Claims: []rbac.Claim{},
				EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{
					{
						Topic0: customTopic0,
						Name:   "CustomEvent",
						ParamRules: []rbac.ParamRule{
							{Index: 1, MustBe: "self"},
						},
					},
				}},
			},
		},
	}

	abiProv := &testABIProviderServer{abis: map[string]string{contractAddr: integCustomEventABI}}
	idTopic := "0x000000000000000000000000000000000000000000000000000000000000002a"

	logs := []map[string]any{
		{"address": contractAddr, "topics": []string{customTopic0, idTopic}, "data": "0x" + otherAddrPadded},
	}

	got := FilterLogsWithEventRules(rbac.ReadProfileStandard, buildLogsRPCResponse(t, logs), []string{userAddr}, perms, abiProv, nil, nil)
	result := parseLogsResult(t, got)

	if len(result) != 0 {
		t.Errorf("I35: non-indexed self no match should be hidden, expected 0, got %d", len(result))
	}
}

func TestFilterLogs_I36_NoABI_FailClosed(t *testing.T) {
	// I36: No ABI, param_rules on non-indexed param → hidden (fail-closed).
	// Without ABI the filter cannot decode non-indexed params from data.
	userAddr := "0x1234567890abcdef1234567890abcdef12345678"
	userAddrPadded := "000000000000000000000000" + userAddr[2:]
	contractAddr := "0xcontract0000000000000000000000000000001"

	// Use a topic0 for CustomEvent(uint256,address).
	customTopic0 := "0x1111111111111111111111111111111111111111111111111111111111111111"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractAddr: {
				Claims: []rbac.Claim{},
				EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{
					{
						Topic0: customTopic0,
						Name:   "CustomEvent",
						ParamRules: []rbac.ParamRule{
							{Index: 1, MustBe: "self"}, // non-indexed param
						},
					},
				}},
			},
		},
	}

	// No ABI provider — the filter has no way to decode param 1 from data.
	idTopic := "0x000000000000000000000000000000000000000000000000000000000000002a"

	logs := []map[string]any{
		{"address": contractAddr, "topics": []string{customTopic0, idTopic}, "data": "0x" + userAddrPadded},
	}

	got := FilterLogsWithEventRules(rbac.ReadProfileStandard, buildLogsRPCResponse(t, logs), []string{userAddr}, perms, nil, nil, nil)
	result := parseLogsResult(t, got)

	if len(result) != 0 {
		t.Errorf("I36: no ABI with non-indexed param rule should fail-closed, expected 0, got %d", len(result))
	}
}

// ---------------------------------------------------------------------------
// I37: Cache Invalidation
// Note: FilterLogsWithEventRules and FilterReceiptLogsWithEventRules are
// stateless functions — they take perms as input and don't cache internally.
// Cache invalidation happens at the permission resolver layer (re-resolve
// EffectivePermissions when rules change). Testing the full server cache
// invalidation requires the proxy server wired up with the DB.
// This test verifies that calling the filter with different perms produces
// different results — i.e., the function has no internal state.
// ---------------------------------------------------------------------------

func TestFilterLogs_I37_CacheInvalidation_Stateless(t *testing.T) {
	// First call: Transfer only allowed.
	contractAddr := "0xcontract0000000000000000000000000000001"

	perms1 := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractAddr: {
				Claims: []rbac.Claim{},
				EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{
					{Topic0: integTransferTopic0, Name: "Transfer"},
				}},
			},
		},
	}

	logs := []map[string]any{
		{"address": contractAddr, "topics": []string{integTransferTopic0}, "data": "0x"},
		{"address": contractAddr, "topics": []string{integApprovalTopic0}, "data": "0x"},
	}
	rpcResp := buildLogsRPCResponse(t, logs)

	got1 := FilterLogsWithEventRules(rbac.ReadProfileStandard, rpcResp, []string{"0xuser"}, perms1, &testABIProviderServer{}, nil, nil)
	result1 := parseLogsResult(t, got1)
	if len(result1) != 1 {
		t.Errorf("I37 first call: expected 1 (Transfer only), got %d", len(result1))
	}

	// Second call: rules updated to allow both Transfer and Approval.
	perms2 := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractAddr: {
				Claims: []rbac.Claim{},
				EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{
					{Topic0: integTransferTopic0, Name: "Transfer"},
					{Topic0: integApprovalTopic0, Name: "Approval"},
				}},
			},
		},
	}

	got2 := FilterLogsWithEventRules(rbac.ReadProfileStandard, rpcResp, []string{"0xuser"}, perms2, &testABIProviderServer{}, nil, nil)
	result2 := parseLogsResult(t, got2)
	if len(result2) != 2 {
		t.Errorf("I37 second call: expected 2 (Transfer+Approval), got %d", len(result2))
	}
}

// ---------------------------------------------------------------------------
// I21-I24: Receipt Filtering
// ---------------------------------------------------------------------------

func TestFilterReceipt_I21_FiltersReceiptLogs(t *testing.T) {
	// I21: Participant with rules [Transfer] — only Transfer logs in receipt.
	userAddr := "0xabc1234567890123456789012345678901234567"
	contractAddr := "0xcontract0000000000000000000000000000001"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractAddr: {
				Claims: []rbac.Claim{},
				EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{
					{Topic0: integTransferTopic0, Name: "Transfer"},
				}},
			},
		},
	}

	receipt := map[string]any{
		"from":      userAddr,
		"to":        contractAddr,
		"status":    "0x1",
		"logsBloom": "0x1234",
		"logs": []map[string]any{
			{"address": contractAddr, "topics": []string{integTransferTopic0}, "data": "0x"},
			{"address": contractAddr, "topics": []string{integApprovalTopic0}, "data": "0x"},
		},
	}

	got := FilterReceiptLogsWithEventRules(rbac.ReadProfileStandard,
		buildReceiptRPCResponse(t, receipt), []string{userAddr}, perms, &testABIProviderServer{}, nil,
		nil,
	)
	logs := parseReceiptLogs(t, got)
	if logs == nil {
		t.Fatal("I21: expected non-null result for participant")
	}
	if len(*logs) != 1 {
		t.Errorf("I21: expected 1 log (Transfer only), got %d", len(*logs))
	}
}

func TestFilterReceipt_I22_NonParticipantEntitled_ReturnsReceipt_RD1183(t *testing.T) {
	// I22 (updated for RD-1183): a non-participant whose group's event rules
	// allowlist this event (Transfer) is entitled to the log — eth_getLogs
	// already returns it — so eth_getTransactionReceipt now returns the receipt
	// with that log instead of null. (Was: asserted null, the pre-RD-1183
	// over-restriction.)
	userAddr := "0xabc1234567890123456789012345678901234567"
	contractAddr := "0xcontract0000000000000000000000000000001"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractAddr: {
				Claims: []rbac.Claim{},
				EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{
					{Topic0: integTransferTopic0, Name: "Transfer"},
				}},
			},
		},
	}

	receipt := map[string]any{
		"from":      "0xother0000000000000000000000000000000001",
		"to":        contractAddr,
		"status":    "0x1",
		"logsBloom": "0x1234",
		"logs": []map[string]any{
			{"address": contractAddr, "topics": []string{integTransferTopic0}, "data": "0x"},
		},
	}

	got := FilterReceiptLogsWithEventRules(rbac.ReadProfileStandard,
		buildReceiptRPCResponse(t, receipt), []string{userAddr}, perms, &testABIProviderServer{}, nil,
		nil,
	)

	logs := parseReceiptLogs(t, got)
	if logs == nil {
		t.Fatalf("RD-1183: log-entitled non-participant should get the receipt, got null: %s", got)
	}
	if len(*logs) != 1 {
		t.Errorf("expected 1 entitled log, got %d", len(*logs))
	}
}

func TestFilterReceipt_I23_NilRules_DenyAll(t *testing.T) {
	// I23: No event rules (nil) — deny all logs (same as empty []).
	userAddr := "0xabc1234567890123456789012345678901234567"
	paddedUser := "0x000000000000000000000000" + userAddr[2:]
	contractAddr := "0xcontract0000000000000000000000000000001"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractAddr: {
				Claims:     []rbac.Claim{},
				EventRules: nil, // nil = deny all
			},
		},
	}

	receipt := map[string]any{
		"from":      userAddr,
		"to":        contractAddr,
		"status":    "0x1",
		"logsBloom": "0x1234",
		"logs": []map[string]any{
			{"address": contractAddr, "topics": []string{integTransferTopic0, paddedUser}, "data": "0x"},
			{"address": contractAddr, "topics": []string{integApprovalTopic0, "0x000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}, "data": "0x"},
		},
	}

	got := FilterReceiptLogsWithEventRules(rbac.ReadProfileStandard,
		buildReceiptRPCResponse(t, receipt), []string{userAddr}, perms, &testABIProviderServer{}, nil,
		nil,
	)
	logs := parseReceiptLogs(t, got)
	if logs == nil {
		t.Fatal("I23: expected non-null result for participant")
	}
	if len(*logs) != 0 {
		t.Errorf("I23: nil EventRules should deny all logs, got %d", len(*logs))
	}
}

func TestFilterReceipt_I24_MixedContracts(t *testing.T) {
	// I24: Tx touches X (rules) and Z (nil = deny all).
	// Only Transfer from X passes; all Z logs are denied.
	userAddr := "0xabc1234567890123456789012345678901234567"
	paddedUser := "0x000000000000000000000000" + userAddr[2:]
	contractX := "0xcontractx000000000000000000000000000001"
	contractZ := "0xcontractz000000000000000000000000000001"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractX: {
				Claims: []rbac.Claim{},
				EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{
					{Topic0: integTransferTopic0, Name: "Transfer"},
				}},
			},
			contractZ: {
				Claims:     []rbac.Claim{},
				EventRules: nil, // nil = deny all
			},
		},
	}

	receipt := map[string]any{
		"from":      userAddr,
		"to":        contractX,
		"status":    "0x1",
		"logsBloom": "0x1234",
		"logs": []map[string]any{
			// X: Transfer -> keep (rule match)
			{"address": contractX, "topics": []string{integTransferTopic0}, "data": "0x"},
			// X: Approval -> strip (not in X's allowlist)
			{"address": contractX, "topics": []string{integApprovalTopic0}, "data": "0x"},
			// Z: log with user address -> blocked (nil = deny all)
			{"address": contractZ, "topics": []string{integTransferTopic0, paddedUser}, "data": "0x"},
			// Z: log without user address -> blocked (nil = deny all)
			{"address": contractZ, "topics": []string{integApprovalTopic0, "0x000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}, "data": "0x"},
		},
	}

	got := FilterReceiptLogsWithEventRules(rbac.ReadProfileStandard,
		buildReceiptRPCResponse(t, receipt), []string{userAddr}, perms, &testABIProviderServer{}, nil,
		nil,
	)
	logs := parseReceiptLogs(t, got)
	if logs == nil {
		t.Fatal("I24: expected non-null result for participant")
	}
	if len(*logs) != 1 {
		t.Errorf("I24: expected 1 log (Transfer from X only, Z denied), got %d", len(*logs))
	}
}

// ---------------------------------------------------------------------------
// visibleTo receipt and getLogs tests — RPC response filter gaps
// ---------------------------------------------------------------------------

// TestFilterReceiptLogsWithEventRules_VisibleTo_NonParticipantSeesReceipt
// verifies that a non-participant whose DID is in the tx's visibleTo list
// receives the receipt (not null). This was a real bug: the participant gate
// returned null even after the visibleTo check passed.
func TestFilterReceiptLogsWithEventRules_VisibleTo_NonParticipantSeesReceipt(t *testing.T) {
	contractAddr := "0xcontract0000000000000000000000000000001"
	txHash := "0xaaaa000000000000000000000000000000000000000000000000000000000001"
	viewerDID := "did:test:bank"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractAddr: {
				Claims: []rbac.Claim{},
				EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{
					{Topic0: "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", Name: "Transfer"},
				}},
			},
		},
	}

	receipt := map[string]any{
		"transactionHash": txHash,
		"from":            "0xsender0000000000000000000000000000001",
		"to":              contractAddr,
		"status":          "0x1",
		"logsBloom":       "0x00",
		"logs": []map[string]any{
			{
				"address":         contractAddr,
				"transactionHash": txHash,
				"topics":          []string{"0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", "0x000000000000000000000000sender0000000000000000000000000000001", "0x000000000000000000000000receiver000000000000000000000000000001"},
				"data":            "0x0000000000000000000000000000000000000000000000000000000000000064",
			},
		},
	}
	receiptJSON, _ := json.Marshal(receipt)
	rpcResponse := `{"jsonrpc":"2.0","id":1,"result":` + string(receiptJSON) + `}`

	// Viewer has no linked addresses — they're a DID-only entity (settlement bank)
	visCtx := &rbac.TxVisibilityContext{
		ViewerDID: viewerDID,
		TxVisibility: map[string][]string{
			strings.ToLower(txHash): {viewerDID},
		},
	}

	got := FilterReceiptLogsWithEventRules(rbac.ReadProfileStandard,
		[]byte(rpcResponse),
		nil, // no linked addresses
		perms,
		&testABIProviderServer{},
		visCtx,
		nil,
	)

	var resp struct {
		Result *json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	isNull := resp.Result == nil || string(*resp.Result) == "null"
	if isNull {
		t.Error("visibleTo non-participant should get receipt, not null")
	}
}

// TestFilterReceiptLogsWithEventRules_VisibleTo_NonParticipantWithoutVisibleTo_StillNull
// verifies that a non-participant WITHOUT visibleTo still gets null.
func TestFilterReceiptLogsWithEventRules_VisibleTo_NonParticipantWithoutVisibleTo_StillNull(t *testing.T) {
	contractAddr := "0xcontract0000000000000000000000000000001"
	txHash := "0xaaaa000000000000000000000000000000000000000000000000000000000001"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractAddr: {Claims: []rbac.Claim{}},
		},
	}

	receipt := map[string]any{
		"transactionHash": txHash,
		"from":            "0xsender0000000000000000000000000000001",
		"to":              contractAddr,
		"status":          "0x1",
		"logsBloom":       "0x00",
		"logs":            []map[string]any{},
	}
	receiptJSON, _ := json.Marshal(receipt)
	rpcResponse := `{"jsonrpc":"2.0","id":1,"result":` + string(receiptJSON) + `}`

	// No visibleTo context — viewer is a random non-participant
	got := FilterReceiptLogsWithEventRules(rbac.ReadProfileStandard,
		[]byte(rpcResponse),
		[]string{"0xrandomuser00000000000000000000000000001"},
		perms,
		&testABIProviderServer{},
		nil,
		nil,
	)

	var resp struct {
		Result *json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	isNull := resp.Result == nil || string(*resp.Result) == "null"
	if !isNull {
		t.Error("non-participant without visibleTo should get null")
	}
}

// TestFilterReceiptLogsWithEventRules_VisibleTo_WrongTxHash_StillNull
// verifies visibleTo only matches the specific tx hash, not any tx.
func TestFilterReceiptLogsWithEventRules_VisibleTo_WrongTxHash_StillNull(t *testing.T) {
	contractAddr := "0xcontract0000000000000000000000000000001"
	txHash := "0xaaaa000000000000000000000000000000000000000000000000000000000001"
	otherHash := "0xbbbb000000000000000000000000000000000000000000000000000000000002"
	viewerDID := "did:test:bank"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractAddr: {Claims: []rbac.Claim{}},
		},
	}

	receipt := map[string]any{
		"transactionHash": txHash,
		"from":            "0xsender0000000000000000000000000000001",
		"to":              contractAddr,
		"status":          "0x1",
		"logsBloom":       "0x00",
		"logs":            []map[string]any{},
	}
	receiptJSON, _ := json.Marshal(receipt)
	rpcResponse := `{"jsonrpc":"2.0","id":1,"result":` + string(receiptJSON) + `}`

	// visibleTo is for a DIFFERENT tx hash
	visCtx := &rbac.TxVisibilityContext{
		ViewerDID: viewerDID,
		TxVisibility: map[string][]string{
			strings.ToLower(otherHash): {viewerDID},
		},
	}

	got := FilterReceiptLogsWithEventRules(rbac.ReadProfileStandard,
		[]byte(rpcResponse),
		nil,
		perms,
		&testABIProviderServer{},
		visCtx,
		nil,
	)

	var resp struct {
		Result *json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	isNull := resp.Result == nil || string(*resp.Result) == "null"
	if !isNull {
		t.Error("visibleTo for wrong tx hash should still return null")
	}
}

// TestFilterLogsWithEventRules_NoLinkedAddresses_VisibleToStillWorks
// verifies that users with no linked ETH addresses can still see visibleTo
// logs via eth_getLogs. This was a real bug: empty addrs returned empty
// immediately without checking visibleTo.
func TestFilterLogsWithEventRules_NoLinkedAddresses_VisibleToStillWorks(t *testing.T) {
	contractAddr := "0xcontract0000000000000000000000000000001"
	txHash := "0xaaaa000000000000000000000000000000000000000000000000000000000001"
	viewerDID := "did:test:bank"
	transferTopic := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractAddr: {
				Claims: []rbac.Claim{},
				EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{
					{
						Topic0: transferTopic,
						Name:   "Transfer",
						ParamRules: []rbac.ParamRule{
							{Index: 0, MustBe: "self"}, // param rule requires self — will fail for DID-only user
						},
					},
				}},
			},
		},
	}

	logJSON := `{"address":"` + contractAddr + `","transactionHash":"` + txHash + `","topics":["` + transferTopic + `","0x000000000000000000000000sender0000000000000000000000000000001","0x000000000000000000000000receiver000000000000000000000000000001"],"data":"0x0000000000000000000000000000000000000000000000000000000000000064"}`
	rpcResponse := `{"jsonrpc":"2.0","id":1,"result":[` + logJSON + `]}`

	visCtx := &rbac.TxVisibilityContext{
		ViewerDID: viewerDID,
		TxVisibility: map[string][]string{
			strings.ToLower(txHash): {viewerDID},
		},
	}

	// No linked addresses — bank user has only a DID
	got := FilterLogsWithEventRules(rbac.ReadProfileStandard,
		[]byte(rpcResponse),
		nil, // empty user addresses
		perms,
		&testABIProviderServer{},
		visCtx,
		nil,
	)

	var resp struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}

	var logs []json.RawMessage
	if err := json.Unmarshal(resp.Result, &logs); err != nil {
		t.Fatalf("result not a JSON array: %v", err)
	}
	if len(logs) != 1 {
		t.Errorf("expected 1 log (visibleTo), got %d", len(logs))
	}
}

// TestFilterReceiptLogsWithEventRules_NonParticipantAdmin_ReturnsReceipt
// covers the RD-855 admin-bypass gap: a viewer who is neither a tx
// participant (from/to) nor a visibleTo recipient MUST still receive
// the receipt when the ORG-SCOPED admin check (pre-computed by the
// caller as isAdminByContract) says they hold the admin claim in the
// tx's `to` contract's OWNING org. Regression guard: before the fix,
// the receipt path returned null for any non-participant regardless of
// admin status, contradicting the documented semantics ("admin users
// always see all events").
func TestFilterReceiptLogsWithEventRules_NonParticipantAdmin_ReturnsReceipt(t *testing.T) {
	adminAddr := "0xadmin000000000000000000000000000000000001"
	contractAddr := "0xcontract0000000000000000000000000000001"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractAddr: {
				Claims: []rbac.Claim{rbac.ClaimAdmin},
			},
		},
	}

	// Tx between two OTHER addresses; admin is neither from nor to.
	receipt := map[string]any{
		"from":            "0xother0000000000000000000000000000000001",
		"to":              contractAddr,
		"status":          "0x1",
		"logsBloom":       "0x1234",
		"transactionHash": "0xabc000000000000000000000000000000000000000000000000000000000001",
		"logs": []map[string]any{
			{
				"address": contractAddr,
				"topics":  []string{"0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"},
				"data":    "0x",
			},
		},
	}
	receiptJSON, _ := json.Marshal(receipt)
	rpcResponse := `{"jsonrpc":"2.0","id":1,"result":` + string(receiptJSON) + `}`

	// isAdminByContract simulates the result of JSONRPCProcessor.viewerAdminContracts:
	// the admin claim is resolved in the contract's owning org only. Presence here
	// means "admin in that contract's org", not "admin merged across orgs".
	isAdminByContract := map[string]bool{contractAddr: true}

	got := FilterReceiptLogsWithEventRules(rbac.ReadProfileStandard,
		[]byte(rpcResponse),
		[]string{adminAddr}, // admin's own EOA, NOT in the tx's from/to
		perms,
		&testABIProviderServer{},
		nil, // no visibleTo disclosure
		isAdminByContract,
	)

	var resp struct {
		Result *json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if resp.Result == nil || string(*resp.Result) == "null" {
		t.Fatalf("admin non-participant must receive the receipt, got null response: %s", got)
	}

	// Per-log admin bypass also applies: the Transfer log is returned.
	var receiptOut struct {
		Logs []json.RawMessage `json:"logs"`
	}
	if err := json.Unmarshal(*resp.Result, &receiptOut); err != nil {
		t.Fatalf("result not a receipt: %v", err)
	}
	if len(receiptOut.Logs) != 1 {
		t.Errorf("admin must see all logs on the contract, got %d logs (expected 1): %s",
			len(receiptOut.Logs), string(*resp.Result))
	}
}

// TestFilterReceiptLogsWithEventRules_NonParticipantNonAdmin_ReturnsNull
// guards the boundary of the admin bypass: a viewer whose isAdminByContract
// is empty/false for the tx's `to` (because the caller's ORG-SCOPED check
// determined they are NOT admin in the contract's owning org) — must get
// null even if their merged perms happen to show read/write access.
func TestFilterReceiptLogsWithEventRules_NonParticipantNonAdmin_ReturnsNull(t *testing.T) {
	viewerAddr := "0xviewer000000000000000000000000000000001"
	contractAddr := "0xcontract0000000000000000000000000000001"

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractAddr: {
				Claims: []rbac.Claim{},
			},
		},
	}

	receipt := map[string]any{
		"from":            "0xother0000000000000000000000000000000001",
		"to":              contractAddr,
		"status":          "0x1",
		"logsBloom":       "0x1234",
		"transactionHash": "0xabc000000000000000000000000000000000000000000000000000000000001",
		"logs":            []map[string]any{},
	}
	receiptJSON, _ := json.Marshal(receipt)
	rpcResponse := `{"jsonrpc":"2.0","id":1,"result":` + string(receiptJSON) + `}`

	// Empty isAdminByContract — viewer is NOT admin in the contract's owning org.
	got := FilterReceiptLogsWithEventRules(rbac.ReadProfileStandard,
		[]byte(rpcResponse),
		[]string{viewerAddr},
		perms,
		&testABIProviderServer{},
		nil,
		map[string]bool{},
	)

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
