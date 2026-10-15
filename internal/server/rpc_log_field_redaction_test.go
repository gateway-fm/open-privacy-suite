package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/rbac"
)

// mockAddrVisResolver implements addressVisibilityResolver for unit tests. Any
// address not listed defaults to VisibilityRedacted (no access) — the fail-safe
// default the real resolver also produces for an unknown address.
type mockAddrVisResolver struct {
	vis map[string]explorer.VisibilityLevel
	err error
}

func (m *mockAddrVisResolver) GetBatchVisibilityDetailed(_ context.Context, _ string, addrs []string) (map[string]explorer.AddressVisibility, error) {
	if m.err != nil {
		return nil, m.err
	}
	out := make(map[string]explorer.AddressVisibility, len(addrs))
	for _, a := range addrs {
		lvl, ok := m.vis[strings.ToLower(a)]
		if !ok {
			lvl = explorer.VisibilityRedacted
		}
		out[strings.ToLower(a)] = explorer.AddressVisibility{Level: lvl, Reason: explorer.ReasonNoAccess}
	}
	return out, nil
}

// noABIProvider satisfies rbac.ABIProvider and reports no ABI for any contract,
// so the non-indexed data scan is skipped (these tests exercise topic
// redaction; the data scan shares extractDataAddresses/redactLogData, covered by
// the explorer suite).
type noABIProvider struct{}

func (noABIProvider) GetContractABI(string) string { return "" }

// mapABIProvider returns a per-contract ABI (keyed by lowercased address), so
// tests can exercise the deny-when-no-ABI gate and the non-indexed data scan.
type mapABIProvider map[string]string

func (m mapABIProvider) GetContractABI(addr string) string { return m[strings.ToLower(addr)] }

// paymentABI has a NON-indexed address parameter (recipient), so the redacted
// address lands in the log's data field rather than a topic.
const paymentABI = `[{"anonymous":false,"inputs":[{"indexed":true,"name":"payer","type":"address"},{"indexed":false,"name":"recipient","type":"address"},{"indexed":false,"name":"amount","type":"uint256"}],"name":"PaymentMade","type":"event"}]`

// TestRPCFieldRedaction_DataFieldNonIndexedAddress closes the edge case where a
// private address rides in the ABI-decoded, non-indexed `data` field rather than
// an indexed topic. The RPC must zero that slot (via the shared redactLogData)
// while leaving the numeric amount slot intact.
func TestRPCFieldRedaction_DataFieldNonIndexedAddress(t *testing.T) {
	emitter := "0x1111111111111111111111111111111111111111"
	payer := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"     // indexed, visible (own)
	recipient := "0x9999999999999999999999999999999999999999" // non-indexed, NOT visible
	topic0 := "0x" + topicHex("PaymentMade(address,address,uint256)")

	recipientSlot := strings.Repeat("0", 24) + strings.TrimPrefix(strings.ToLower(recipient), "0x")
	amountSlot := fmt.Sprintf("%064x", 1000)
	data := "0x" + recipientSlot + amountSlot

	p := &JSONRPCProcessor{readProfile: rbac.ReadProfileStandard, addrVisResolver: &mockAddrVisResolver{vis: map[string]explorer.VisibilityLevel{
		strings.ToLower(payer): explorer.VisibilityFull,
	}}}
	abiProv := mapABIProvider{strings.ToLower(emitter): paymentABI}
	logs := []json.RawMessage{rawLogJSON(t, emitter, []string{topic0, topicOf(payer)}, data)}

	out := p.redactEmbeddedLogAddresses(context.Background(), "did:viewer", logs, abiProv)

	var m struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal(out[0], &m); err != nil {
		t.Fatal(err)
	}
	gotRecipientSlot := strings.TrimPrefix(m.Data, "0x")[:64]
	gotAmountSlot := strings.TrimPrefix(m.Data, "0x")[64:128]
	if gotRecipientSlot != strings.Repeat("0", 64) {
		t.Errorf("non-indexed recipient address must be zeroed in data, got %s", gotRecipientSlot)
	}
	if gotAmountSlot != amountSlot {
		t.Errorf("numeric amount slot must be preserved, got %s want %s", gotAmountSlot, amountSlot)
	}
}

const zeroTopic = "0x0000000000000000000000000000000000000000000000000000000000000000"

func topicOf(addr string) string {
	return "0x" + strings.Repeat("0", 24) + strings.TrimPrefix(strings.ToLower(addr), "0x")
}

func rawLogJSON(t *testing.T, address string, topics []string, data string) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"address":     address,
		"topics":      topics,
		"data":        data,
		"blockNumber": "0x10",
		"logIndex":    "0x1",
		"txHash":      "0xabc",
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func topicsOf(t *testing.T, raw json.RawMessage) []string {
	t.Helper()
	var m struct {
		Topics []string `json:"topics"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m.Topics
}

// TestRPCFieldRedaction_ZeroesNonVisibleEmbeddedAddress is the RPC half of the
// RD-1214 unification: an admitted log whose topic carries a third party's
// address the viewer cannot see must have that slot zeroed — matching what the
// explorer does for the same (viewer, log). Pre-RD-1214 the RPC returned the
// admitted log whole, leaking the embedded address verbatim.
func TestRPCFieldRedaction_ZeroesNonVisibleEmbeddedAddress(t *testing.T) {
	eventSig := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	thirdParty := "0x9999999999999999999999999999999999999999"

	p := &JSONRPCProcessor{readProfile: rbac.ReadProfileStandard, addrVisResolver: &mockAddrVisResolver{vis: map[string]explorer.VisibilityLevel{}}}
	logs := []json.RawMessage{rawLogJSON(t, "0x1111111111111111111111111111111111111111",
		[]string{eventSig, topicOf(thirdParty)}, "0x")}

	out := p.redactEmbeddedLogAddresses(context.Background(), "did:viewer", logs, noABIProvider{})
	if len(out) != 1 {
		t.Fatalf("expected 1 log, got %d", len(out))
	}
	topics := topicsOf(t, out[0])
	if topics[0] != eventSig {
		t.Errorf("event signature topic0 must be untouched, got %s", topics[0])
	}
	if topics[1] != zeroTopic {
		t.Errorf("non-visible embedded address must be zeroed, got %s", topics[1])
	}
	// Other fields preserved.
	var m map[string]json.RawMessage
	_ = json.Unmarshal(out[0], &m)
	if string(m["blockNumber"]) != `"0x10"` || string(m["txHash"]) != `"0xabc"` {
		t.Errorf("non-topic fields must be preserved, got blockNumber=%s txHash=%s", m["blockNumber"], m["txHash"])
	}
}

// TestRPCFieldRedaction_KeepsVisibleEmbeddedAddress is the anti-over-redaction
// guard (RD-1144 lesson): an embedded address the viewer IS entitled to see
// (e.g. their own) must be left intact.
func TestRPCFieldRedaction_KeepsVisibleEmbeddedAddress(t *testing.T) {
	eventSig := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	ownAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	thirdParty := "0x9999999999999999999999999999999999999999"

	p := &JSONRPCProcessor{readProfile: rbac.ReadProfileStandard, addrVisResolver: &mockAddrVisResolver{vis: map[string]explorer.VisibilityLevel{
		strings.ToLower(ownAddr): explorer.VisibilityFull,
	}}}
	logs := []json.RawMessage{rawLogJSON(t, "0x1111111111111111111111111111111111111111",
		[]string{eventSig, topicOf(ownAddr), topicOf(thirdParty)}, "0x")}

	out := p.redactEmbeddedLogAddresses(context.Background(), "did:viewer", logs, noABIProvider{})
	topics := topicsOf(t, out[0])
	if !strings.EqualFold(topics[1], topicOf(ownAddr)) {
		t.Errorf("viewer's own address must be preserved, got %s", topics[1])
	}
	if topics[2] != zeroTopic {
		t.Errorf("third-party address must be zeroed, got %s", topics[2])
	}
}

// TestRPCFieldRedaction_FailClosedOnResolverError: a resolver error must NOT
// let raw addresses through — every embedded address is zeroed.
func TestRPCFieldRedaction_FailClosedOnResolverError(t *testing.T) {
	eventSig := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	ownAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	p := &JSONRPCProcessor{readProfile: rbac.ReadProfileStandard, addrVisResolver: &mockAddrVisResolver{
		vis: map[string]explorer.VisibilityLevel{strings.ToLower(ownAddr): explorer.VisibilityFull},
		err: context.DeadlineExceeded, // resolver fails
	}}
	logs := []json.RawMessage{rawLogJSON(t, "0x1111111111111111111111111111111111111111",
		[]string{eventSig, topicOf(ownAddr)}, "0x")}

	out := p.redactEmbeddedLogAddresses(context.Background(), "did:viewer", logs, noABIProvider{})
	topics := topicsOf(t, out[0])
	if topics[1] != zeroTopic {
		t.Errorf("fail-closed: embedded address must be zeroed on resolver error, got %s", topics[1])
	}
}

// TestRPCFieldRedaction_NilResolverNoOp: without a wired resolver (unit-test
// ergonomics) the step is a no-op and returns the logs unchanged.
func TestRPCFieldRedaction_NilResolverNoOp(t *testing.T) {
	eventSig := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	thirdParty := "0x9999999999999999999999999999999999999999"

	p := &JSONRPCProcessor{readProfile: rbac.ReadProfileStandard} // addrVisResolver nil
	logs := []json.RawMessage{rawLogJSON(t, "0x1111111111111111111111111111111111111111",
		[]string{eventSig, topicOf(thirdParty)}, "0x")}

	out := p.redactEmbeddedLogAddresses(context.Background(), "did:viewer", logs, noABIProvider{})
	topics := topicsOf(t, out[0])
	if !strings.EqualFold(topics[1], topicOf(thirdParty)) {
		t.Errorf("nil resolver must be a no-op, got %s", topics[1])
	}
}
