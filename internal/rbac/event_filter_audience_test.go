package rbac

import (
	"encoding/json"
	"testing"
)

// fakeABIProv returns a fixed ABI for any contract.
type fakeABIProv struct{ abi string }

func (f fakeABIProv) GetContractABI(string) string { return f.abi }

// fakeGate is a RecordAudienceGate whose verdict is fixed; records call count.
type fakeGate struct {
	admit bool
	calls int
}

func (f *fakeGate) EventLogAdmits(_, _ string, _ []string, _ string) bool {
	f.calls++
	return f.admit
}

// TestFilterEventLogs_RecordAudienceAdditive proves the RD-1206 rule-71 branch:
// it ADDS the record audience (admitting a dynamic-payload event that M15 would
// otherwise drop), is bounded by contract eligibility, and never removes a
// baseline viewer.
func TestFilterEventLogs_RecordAudienceAdditive(t *testing.T) {
	parsed := mustParseEventsABI(t)
	topics, data := processedLog(t, parsed, "PAY-1", 2) // PaymentProcessed(string,uint8): dynamic string → M15 would drop
	const addr = "0xcccccccccccccccccccccccccccccccccccccc10"
	logJSON, err := json.Marshal(map[string]any{"address": addr, "topics": topics, "data": "0x" + toHex(data)})
	if err != nil {
		t.Fatalf("marshal log: %v", err)
	}
	logs := []json.RawMessage{logJSON}
	abiProv := fakeABIProv{eventsABI}

	// deny-by-default baseline with a grant (access != nil): without the gate the
	// dynamic-payload event is dropped by M15.
	granted := &EffectivePermissions{ContractAccess: map[string]ContractAccess{addr: {EventRules: nil}}}
	// no grant → not eligible.
	noGrant := &EffectivePermissions{ContractAccess: map[string]ContractAccess{}}

	t.Run("baseline (no gate) drops the dynamic-payload event", func(t *testing.T) {
		out := FilterEventLogs(logs, granted, nil, abiProv, &TxVisibilityContext{ViewerDID: "did:test:alice"}, nil)
		if len(out) != 0 {
			t.Fatalf("want 0 (M15 drop), got %d", len(out))
		}
	})

	t.Run("gate admits → event passes (M15 bypassed, additive)", func(t *testing.T) {
		g := &fakeGate{admit: true}
		out := FilterEventLogs(logs, granted, nil, abiProv, &TxVisibilityContext{ViewerDID: "did:test:alice", RecordAudience: g}, nil)
		if len(out) != 1 {
			t.Fatalf("want 1 admitted via record audience, got %d", len(out))
		}
		if g.calls == 0 {
			t.Fatal("gate must be consulted")
		}
	})

	t.Run("gate abstains → event stays dropped", func(t *testing.T) {
		g := &fakeGate{admit: false}
		out := FilterEventLogs(logs, granted, nil, abiProv, &TxVisibilityContext{ViewerDID: "did:test:eve", RecordAudience: g}, nil)
		if len(out) != 0 {
			t.Fatalf("want 0, got %d", len(out))
		}
	})

	t.Run("no contract grant → gate not consulted (eligibility bound)", func(t *testing.T) {
		g := &fakeGate{admit: true}
		out := FilterEventLogs(logs, noGrant, nil, abiProv, &TxVisibilityContext{ViewerDID: "did:test:alice", RecordAudience: g}, nil)
		if len(out) != 0 {
			t.Fatalf("want 0 (not eligible), got %d", len(out))
		}
		if g.calls != 0 {
			t.Fatal("the record gate must not be consulted without contract eligibility")
		}
	})
}
