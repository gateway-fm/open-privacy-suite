package server

import (
	"encoding/json"
	"strings"
	"testing"

	"privacy-proxy/internal/rbac"
)

// RD-1176 regression guard. The eth_getBlockByHash/ByNumber and
// getBlockReceipts handlers now pass nil addresses to these filters when the
// linked-address lookup errors (fail CLOSED) instead of returning the raw
// response. This pins the invariant those handlers rely on: with nil (or
// empty) addresses the filters must strip EVERY transaction / receipt, never
// pass them through — so a transient DB error can never leak a block's
// participants.
func TestBlockFilters_NilAddresses_FailClosed_RD1176(t *testing.T) {
	// A block with two full transactions between real-looking addresses, a
	// non-zero logsBloom and gasUsed.
	blockResp := `{"jsonrpc":"2.0","id":1,"result":{` +
		`"number":"0x1","logsBloom":"0x` + strings.Repeat("f", 512) + `","gasUsed":"0x5208",` +
		`"transactions":[` +
		`{"hash":"0xaaa","from":"0x1111111111111111111111111111111111111111","to":"0x2222222222222222222222222222222222222222"},` +
		`{"hash":"0xbbb","from":"0x3333333333333333333333333333333333333333","to":"0x4444444444444444444444444444444444444444"}` +
		`]}}`

	for _, addrs := range [][]string{nil, {}} {
		out := FilterBlockTransactions(rbac.ReadProfileStandard, []byte(blockResp), addrs, true)
		var parsed struct {
			Result struct {
				Transactions []json.RawMessage `json:"transactions"`
				LogsBloom    string            `json:"logsBloom"`
				GasUsed      string            `json:"gasUsed"`
			} `json:"result"`
		}
		if err := json.Unmarshal(out, &parsed); err != nil {
			t.Fatalf("FilterBlockTransactions(%v) produced invalid JSON: %v\n%s", addrs, err, out)
		}
		if len(parsed.Result.Transactions) != 0 {
			t.Errorf("FilterBlockTransactions(addrs=%v): got %d transactions, want 0 (fail-closed) — block would leak participants on a DB error",
				addrs, len(parsed.Result.Transactions))
		}
		if strings.Trim(parsed.Result.LogsBloom, "0x") != "" {
			t.Errorf("FilterBlockTransactions(addrs=%v): logsBloom not zeroed: %s", addrs, parsed.Result.LogsBloom)
		}
	}

	receiptsResp := `{"jsonrpc":"2.0","id":1,"result":[` +
		`{"transactionHash":"0xaaa","from":"0x1111111111111111111111111111111111111111","to":"0x2222222222222222222222222222222222222222"},` +
		`{"transactionHash":"0xbbb","from":"0x3333333333333333333333333333333333333333","to":"0x4444444444444444444444444444444444444444"}` +
		`]}`

	for _, addrs := range [][]string{nil, {}} {
		out := FilterBlockReceipts(rbac.ReadProfileStandard, []byte(receiptsResp), addrs)
		var parsed struct {
			Result []json.RawMessage `json:"result"`
		}
		if err := json.Unmarshal(out, &parsed); err != nil {
			t.Fatalf("FilterBlockReceipts(%v) produced invalid JSON: %v\n%s", addrs, err, out)
		}
		if len(parsed.Result) != 0 {
			t.Errorf("FilterBlockReceipts(addrs=%v): got %d receipts, want 0 (fail-closed)", addrs, len(parsed.Result))
		}
	}
}
