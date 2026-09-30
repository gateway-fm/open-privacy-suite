package server

import (
	"encoding/json"
	"strings"
	"testing"

	"privacy-proxy/internal/rbac"
)

// RD-1183: eth_getTransactionReceipt returned null for a viewer entitled to the
// tx's logs ONLY via an event param rule (e.g. a payee admitted to a payment
// event by must_be:self on an indexed param) but who is not the tx's
// from/to/visibleTo/admin. The receipt is now admitted when the viewer is
// entitled to >=1 of its logs — mirroring what eth_getLogs already returns them.

const rd1183PayerEOA = "0xpayer000000000000000000000000000000f00d"

// buildRD1183Receipt returns a JSON-RPC receipt whose tx envelope belongs to
// `payer`→`to`, carrying `logs`. The viewer is intentionally NOT the tx from/to.
func buildRD1183Receipt(t *testing.T, from, to string, logs []map[string]any) []byte {
	t.Helper()
	receipt := map[string]any{
		"from":            from,
		"to":              to,
		"status":          "0x1",
		"gasUsed":         "0x5208",
		"transactionHash": "0xrd1183feed",
		"logsBloom":       "0x1234",
		"logs":            logs,
	}
	b, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("marshal receipt: %v", err)
	}
	return []byte(`{"jsonrpc":"2.0","id":1,"result":` + string(b) + `}`)
}

func rd1183Perms(contract string, rules ...rbac.EventRule) *rbac.EffectivePermissions {
	return &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contract: {Claims: []rbac.Claim{}, EventRules: &rbac.EventRulesField{Rules: rules}},
		},
	}
}

func rd1183ReceiptResult(t *testing.T, out []byte) *[]json.RawMessage {
	t.Helper()
	var resp struct {
		Result *struct {
			Logs      []json.RawMessage `json:"logs"`
			LogsBloom string            `json:"logsBloom"`
		} `json:"result"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\nraw: %s", err, out)
	}
	if resp.Result == nil {
		return nil
	}
	if resp.Result.LogsBloom != "" && resp.Result.LogsBloom != "0x"+strings.Repeat("0", 512) {
		t.Errorf("logsBloom must be zeroed on an admitted receipt, got %s", resp.Result.LogsBloom)
	}
	return &resp.Result.Logs
}

// The ticket's exact repro: viewer is a party in the LOG (indexed param,
// must_be:self) but not the tx from/to. Receipt is admitted with that log.
func TestFilterReceipt_RD1183_NonParticipantEntitledViaParamRule_ReturnsReceipt(t *testing.T) {
	viewer := "0x1234567890abcdef1234567890abcdef12345678"
	paddedViewer := "0x000000000000000000000000" + viewer[2:]
	otherPadded := "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	contract := "0xcontract0000000000000000000000000000001"

	perms := rd1183Perms(contract, rbac.EventRule{
		Topic0:     integTransferTopic0,
		Name:       "Transfer",
		ParamRules: []rbac.ParamRule{{Index: 0, MustBe: "self"}},
	})
	abi := &testABIProviderServer{abis: map[string]string{contract: integERC20ABI}}

	// Log names the viewer at indexed param 0; the tx envelope is payer→contract
	// (viewer is neither), so the viewer is a non-participant.
	logs := []map[string]any{
		{"address": contract, "topics": []string{integTransferTopic0, paddedViewer, otherPadded},
			"data": "0x0000000000000000000000000000000000000000000000000000000000000064"},
	}
	out := FilterReceiptLogsWithEventRules(rbac.ReadProfileStandard,
		buildRD1183Receipt(t, rd1183PayerEOA, contract, logs), []string{viewer}, perms, abi, nil, nil)

	got := rd1183ReceiptResult(t, out)
	if got == nil {
		t.Fatalf("RD-1183: entitled non-participant should get the receipt, got null: %s", out)
	}
	if len(*got) != 1 {
		t.Errorf("expected the 1 entitled log, got %d", len(*got))
	}
}

// A non-participant NOT entitled to any log (param rule doesn't match) still
// gets null — the fail-closed direction is preserved.
func TestFilterReceipt_RD1183_NonParticipantNotEntitled_ReturnsNull(t *testing.T) {
	viewer := "0x1234567890abcdef1234567890abcdef12345678"
	otherPadded := "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	contract := "0xcontract0000000000000000000000000000001"

	perms := rd1183Perms(contract, rbac.EventRule{
		Topic0:     integTransferTopic0,
		Name:       "Transfer",
		ParamRules: []rbac.ParamRule{{Index: 0, MustBe: "self"}},
	})
	abi := &testABIProviderServer{abis: map[string]string{contract: integERC20ABI}}

	// Log's indexed param 0 is someone else — viewer matches nothing.
	logs := []map[string]any{
		{"address": contract, "topics": []string{integTransferTopic0, otherPadded, otherPadded},
			"data": "0x0000000000000000000000000000000000000000000000000000000000000064"},
	}
	out := FilterReceiptLogsWithEventRules(rbac.ReadProfileStandard,
		buildRD1183Receipt(t, rd1183PayerEOA, contract, logs), []string{viewer}, perms, abi, nil, nil)

	if got := rd1183ReceiptResult(t, out); got != nil {
		t.Errorf("non-entitled non-participant must get null, got receipt with %d logs: %s", len(*got), out)
	}
}

// A receipt with no logs field must be null for a non-participant (N1: the
// counted helper's "no logs" branch maps to 0 → not admitted).
func TestFilterReceipt_RD1183_NonParticipantNoLogsField_ReturnsNull(t *testing.T) {
	viewer := "0x1234567890abcdef1234567890abcdef12345678"
	contract := "0xcontract0000000000000000000000000000001"
	perms := rd1183Perms(contract, rbac.EventRule{Topic0: integTransferTopic0, Name: "Transfer",
		ParamRules: []rbac.ParamRule{{Index: 0, MustBe: "self"}}})

	receipt := map[string]any{"from": rd1183PayerEOA, "to": contract, "status": "0x1"} // no "logs"
	b, _ := json.Marshal(receipt)
	out := FilterReceiptLogsWithEventRules(rbac.ReadProfileStandard,
		[]byte(`{"jsonrpc":"2.0","id":1,"result":`+string(b)+`}`),
		[]string{viewer}, perms, &testABIProviderServer{}, nil, nil)

	var resp struct {
		Result *json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if !(resp.Result == nil || string(*resp.Result) == "null") {
		t.Errorf("no-logs receipt must be null for a non-participant, got: %s", out)
	}
}

// A contract-DEPLOYMENT receipt (to == "") must NOT be admitted via the RD-1183
// path even if a log is entitled — the RPC layer never redacts the top-level
// contractAddress (RD-1143 is explorer-only), so admitting it would leak the
// deployed contract address to a log-entitled non-participant.
func TestFilterReceipt_RD1183_DeploymentReceiptNotAdmitted(t *testing.T) {
	viewer := "0x1234567890abcdef1234567890abcdef12345678"
	paddedViewer := "0x000000000000000000000000" + viewer[2:]
	otherPadded := "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	contract := "0xcontract0000000000000000000000000000001"
	perms := rd1183Perms(contract, rbac.EventRule{Topic0: integTransferTopic0, Name: "Transfer",
		ParamRules: []rbac.ParamRule{{Index: 0, MustBe: "self"}}})
	abi := &testABIProviderServer{abis: map[string]string{contract: integERC20ABI}}

	// Deployment: to is null; an (entitled) log is emitted by the new contract.
	receipt := map[string]any{
		"from":            rd1183PayerEOA,
		"to":              nil,
		"contractAddress": contract,
		"status":          "0x1",
		"logs": []map[string]any{
			{"address": contract, "topics": []string{integTransferTopic0, paddedViewer, otherPadded}, "data": "0x"},
		},
	}
	b, _ := json.Marshal(receipt)
	out := FilterReceiptLogsWithEventRules(rbac.ReadProfileStandard,
		[]byte(`{"jsonrpc":"2.0","id":1,"result":`+string(b)+`}`),
		[]string{viewer}, perms, abi, nil, nil)

	var resp struct {
		Result *json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if !(resp.Result == nil || string(*resp.Result) == "null") {
		t.Errorf("deployment receipt must stay null for a log-entitled non-participant, got: %s", out)
	}
}

// A non-participant must NOT get the RD-1162 participant-hash admission: an
// address-less log on the granted contract that is not allowlisted stays hidden
// (only a participant would see it). The receipt returns only the entitled log.
func TestFilterReceipt_RD1183_NonParticipantNoSiblingOverAdmission(t *testing.T) {
	viewer := "0x1234567890abcdef1234567890abcdef12345678"
	paddedViewer := "0x000000000000000000000000" + viewer[2:]
	otherPadded := "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	contract := "0xcontract0000000000000000000000000000001"

	// Only Transfer (with must_be:self) is allowlisted. Approval is NOT.
	perms := rd1183Perms(contract, rbac.EventRule{
		Topic0:     integTransferTopic0,
		Name:       "Transfer",
		ParamRules: []rbac.ParamRule{{Index: 0, MustBe: "self"}},
	})
	abi := &testABIProviderServer{abis: map[string]string{contract: integERC20ABI}}

	logs := []map[string]any{
		// Entitled: Transfer naming the viewer at param 0.
		{"address": contract, "topics": []string{integTransferTopic0, paddedViewer, otherPadded}, "data": "0x"},
		// Address-less, non-allowlisted event: only RD-1162 participant admission
		// would surface it. A non-participant must NOT see it.
		{"address": contract, "topics": []string{integApprovalTopic0}, "data": "0x"},
	}
	out := FilterReceiptLogsWithEventRules(rbac.ReadProfileStandard,
		buildRD1183Receipt(t, rd1183PayerEOA, contract, logs), []string{viewer}, perms, abi, nil, nil)

	got := rd1183ReceiptResult(t, out)
	if got == nil {
		t.Fatalf("RD-1183: entitled non-participant should get the receipt, got null: %s", out)
	}
	if len(*got) != 1 {
		t.Errorf("non-participant must see ONLY the entitled log (no participant-hash sibling admission), got %d logs: %s", len(*got), out)
	}
}
