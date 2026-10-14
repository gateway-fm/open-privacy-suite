package server

import (
	"encoding/json"
	"strings"
	"testing"

	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/rbac"
)

// RD-1052: block `size` (serialized byte-length — a per-block aggregate over
// every tx, including hidden ones) must not be served. At the RPC layer it is
// zeroed alongside logsBloom/gasUsed; at the explorer layer it is never
// serialized (json:"-").

func extractBlockSize(t *testing.T, body []byte) (string, bool) {
	t.Helper()
	var resp struct {
		Result *map[string]json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\nbody: %s", err, body)
	}
	if resp.Result == nil {
		t.Fatal("expected non-null result")
	}
	raw, ok := (*resp.Result)["size"]
	return string(raw), ok
}

func TestFilterBlockTransactions_BlockSize_Zeroed_RD1052(t *testing.T) {
	userAddr := "0xabc1234567890123456789012345678901234567"
	// 0x1c9c380 = ~30MB — a plausible real block size that must not leak.
	response := `{"jsonrpc":"2.0","id":1,"result":{"number":"0x1","size":"0x1c9c380","logsBloom":"0xdead","transactions":[` +
		`{"from":"0xother1","to":"0xother2","input":"0x"}` +
		`]}}`

	// Participant and non-participant alike: size is zeroed unconditionally.
	for _, full := range []bool{true, false} {
		got := FilterBlockTransactions(rbac.ReadProfileStandard, []byte(response), []string{userAddr}, full)
		size, ok := extractBlockSize(t, got)
		if !ok {
			t.Fatalf("size key unexpectedly removed (full=%v): %s", full, got)
		}
		if size != `"0x0"` {
			t.Errorf("block size must be zeroed (full=%v)\ngot:  %s\nwant: \"0x0\"", full, size)
		}
	}
}

func TestFilterBlockTransactions_BlockSize_Zeroed_EmptyAndHashOnly_RD1052(t *testing.T) {
	userAddr := "0xabc1234567890123456789012345678901234567"
	cases := map[string]string{
		"empty tx array":  `{"jsonrpc":"2.0","id":1,"result":{"number":"0x1","size":"0x2b0","transactions":[]}}`,
		"hash-only array": `{"jsonrpc":"2.0","id":1,"result":{"number":"0x1","size":"0x2b0","transactions":["0xhash1"]}}`,
		"no tx field":     `{"jsonrpc":"2.0","id":1,"result":{"number":"0x1","size":"0x2b0"}}`,
	}
	for name, response := range cases {
		got := FilterBlockTransactions(rbac.ReadProfileStandard, []byte(response), []string{userAddr}, true)
		size, _ := extractBlockSize(t, got)
		if size != `"0x0"` {
			t.Errorf("%s: size must be zeroed, got %s", name, size)
		}
	}
}

// A block response that never had a size field stays without one (the guard is
// `if _, ok := block["size"]` — no key is injected).
func TestFilterBlockTransactions_MissingSize_StaysAbsent_RD1052(t *testing.T) {
	userAddr := "0xabc1234567890123456789012345678901234567"
	response := `{"jsonrpc":"2.0","id":1,"result":{"number":"0x1","logsBloom":"0xdead","transactions":[]}}`
	got := FilterBlockTransactions(rbac.ReadProfileStandard, []byte(response), []string{userAddr}, true)
	if _, ok := extractBlockSize(t, got); ok {
		t.Errorf("size must stay absent when the source had none: %s", got)
	}
}

// Explorer layer: explorer.Block never serializes `size` (json:"-"), even when
// the struct field is non-zero. Non-vacuous: Size is explicitly set to 12345.
func TestExplorerBlock_SizeNeverSerialized_RD1052(t *testing.T) {
	b := explorer.Block{Number: 1, Hash: "0xabc", Size: 12345, GasUsed: 21000}
	out, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(out), `"size"`) {
		t.Errorf("explorer.Block must not serialize a size field, got: %s", out)
	}
	if strings.Contains(string(out), "12345") {
		t.Errorf("explorer.Block leaked the size value: %s", out)
	}
	// The struct field itself is still populated for internal use.
	if b.Size != 12345 {
		t.Errorf("Size struct field should remain set for internal use, got %d", b.Size)
	}
}
