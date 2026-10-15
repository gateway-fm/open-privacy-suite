package rbac

import (
	"encoding/json"
	"reflect"
	"testing"
)

// TestFilterEventLogsDetailed_UnlockIsPerLogTuple (RD-1300) pins that the
// full-payload policy is decided per log, for the exact (viewer, emitting
// contract, transaction) tuple carried by that log — never inferred from a
// sibling log, another transaction, another contract, or the fact that a log
// was admitted.
func TestFilterEventLogsDetailed_UnlockIsPerLogTuple(t *testing.T) {
	const (
		flagged = "0xa00000000000000000000000000000000000000a" // allow_visibleto_unlock + eligible
		other   = "0xb00000000000000000000000000000000000000b" // not unlockable, wildcard grant
		viewer  = "did:test:viewer"
		listed  = "0xabababababababababababababababababababababababababababababababab"
		later   = "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
	)
	staticABI := `[{"anonymous":false,"inputs":[{"indexed":false,"name":"v","type":"uint256"}],"name":"E","type":"event"}]`
	topic0 := "0xabc0000000000000000000000000000000000000000000000000000000000000"
	perms := &EffectivePermissions{ContractAccess: map[string]ContractAccess{
		flagged: {EventRules: &EventRulesField{}}, // deny-all: only the unlock can admit
		other:   {EventRules: &EventRulesField{Wildcard: true}},
	}}
	abiProv := &testABIProvider{abis: map[string]string{flagged: staticABI, other: staticABI}}
	visCtx := &TxVisibilityContext{
		ViewerDID:           viewer,
		TxVisibility:        map[string][]string{listed: {viewer}},
		UnlockableContracts: map[string]bool{flagged: true},
	}
	log := func(addr, tx string) json.RawMessage {
		if tx == "" {
			return json.RawMessage(`{"address":"` + addr + `","topics":["` + topic0 + `"],"data":"0x"}`)
		}
		return json.RawMessage(`{"address":"` + addr + `","topics":["` + topic0 + `"],"data":"0x","transactionHash":"` + tx + `"}`)
	}

	in := []json.RawMessage{
		log(flagged, listed), // 0: unlocked → full
		log(other, listed),   // 1: same tx, other emitter → ordinary wildcard, masked
		log(flagged, later),  // 2: same emitter, unlisted tx → deny-all drop
		log(flagged, ""),     // 3: no transactionHash → cannot be tied to a listing → drop
		log("0xA00000000000000000000000000000000000000A", "0xABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB"), // 4: upper-case address and hash → same tuple, full
		log(flagged, listed), // 5: duplicate of 0 → full
		log(other, later),    // 6: other emitter, unlisted → wildcard, masked
	}
	got := FilterEventLogsDetailed(ReadProfileStandard, in, perms, nil, abiProv, visCtx, nil)
	want := []AdmittedLog{
		{Raw: in[0], Payload: LogPayloadFull},
		{Raw: in[1], Payload: LogPayloadMasked},
		{Raw: in[4], Payload: LogPayloadFull},
		{Raw: in[5], Payload: LogPayloadFull},
		{Raw: in[6], Payload: LogPayloadMasked},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("FilterEventLogsDetailed:\n got %s\nwant %s", fmtAdmitted(got), fmtAdmitted(want))
	}

	// FilterEventLogs is exactly the raw half of the detailed result.
	raws := FilterEventLogs(ReadProfileStandard, in, perms, nil, abiProv, visCtx, nil)
	if len(raws) != len(got) {
		t.Fatalf("FilterEventLogs returned %d logs, detailed %d", len(raws), len(got))
	}
	for i := range raws {
		if string(raws[i]) != string(got[i].Raw) {
			t.Fatalf("FilterEventLogs[%d] != FilterEventLogsDetailed[%d].Raw", i, i)
		}
	}
}

// TestFilterEventLogsDetailed_UnlockRequiresExactListedDID pins that the
// listing is matched on the exact DID recorded in tx_visible_to: a DID that
// differs only in case is a different identity and never unlocks.
func TestFilterEventLogsDetailed_UnlockRequiresExactListedDID(t *testing.T) {
	const (
		flagged = "0xa00000000000000000000000000000000000000a"
		tx      = "0x1111111111111111111111111111111111111111111111111111111111111111"
	)
	staticABI := `[{"anonymous":false,"inputs":[{"indexed":false,"name":"v","type":"uint256"}],"name":"E","type":"event"}]`
	perms := &EffectivePermissions{ContractAccess: map[string]ContractAccess{flagged: {EventRules: &EventRulesField{}}}}
	visCtx := &TxVisibilityContext{
		ViewerDID:           "did:test:Viewer",
		TxVisibility:        map[string][]string{tx: {"did:test:viewer"}},
		UnlockableContracts: map[string]bool{flagged: true},
	}
	in := []json.RawMessage{json.RawMessage(`{"address":"` + flagged + `","topics":["0xabc0000000000000000000000000000000000000000000000000000000000000"],"data":"0x","transactionHash":"` + tx + `"}`)}
	if got := FilterEventLogsDetailed(ReadProfileStandard, in, perms, nil, &testABIProvider{abis: map[string]string{flagged: staticABI}}, visCtx, nil); len(got) != 0 {
		t.Fatalf("a case-variant DID must not unlock, got %s", fmtAdmitted(got))
	}
}

// TestFilterEventLogsDetailed_NilPermsFailsClosed: unresolved permissions
// admit nothing, whatever the unlock context says.
func TestFilterEventLogsDetailed_NilPermsFailsClosed(t *testing.T) {
	const flagged = "0xa00000000000000000000000000000000000000a"
	const tx = "0x1111111111111111111111111111111111111111111111111111111111111111"
	visCtx := &TxVisibilityContext{
		ViewerDID:           "did:test:viewer",
		TxVisibility:        map[string][]string{tx: {"did:test:viewer"}},
		UnlockableContracts: map[string]bool{flagged: true},
	}
	in := []json.RawMessage{json.RawMessage(`{"address":"` + flagged + `","topics":[],"data":"0x","transactionHash":"` + tx + `"}`)}
	if got := FilterEventLogsDetailed(ReadProfileStandard, in, nil, nil, nil, visCtx, nil); len(got) != 0 {
		t.Fatalf("nil perms must admit nothing, got %s", fmtAdmitted(got))
	}
}

func fmtAdmitted(a []AdmittedLog) string {
	out := "["
	for i, l := range a {
		if i > 0 {
			out += ", "
		}
		out += l.Payload.String() + ":" + string(l.Raw)
	}
	return out + "]"
}
