package tracer

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// RD-1304: the client debug_trace* path returns a callTracer payload to the
// caller, so the payload it validates must be exactly the payload it returns.
// ParseStrictCallTrace accepts only a well-formed callTracer tree, records
// every frame that can reveal another contract, and re-emits only the known
// callTracer fields — never the node's raw bytes.

const (
	addrA = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	addrB = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	addrE = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
)

func TestParseStrictCallTrace_ValidTreeSanitized(t *testing.T) {
	raw := `{"type":"CALL","from":"` + addrE + `","to":"` + addrA + `","input":"0x01","output":"0x02",
		"gas":"0x10","gasUsed":"0x8","value":"0x0","logs":[{"address":"` + addrA + `","topics":[],"data":"0xdead"}],
		"unknownField":"x","calls":[{"type":"STATICCALL","from":"` + addrA + `","to":"` + addrB + `","output":"0x03"}]}`
	sanitized, res, err := ParseStrictCallTrace(json.RawMessage(raw))
	if err != nil {
		t.Fatalf("valid tree rejected: %v", err)
	}
	if len(res.CallTargets) != 2 {
		t.Fatalf("want 2 targets (root + nested), got %+v", res.CallTargets)
	}
	if res.CallTargets[0].To != addrA || res.CallTargets[1].To != addrB || res.CallTargets[1].Type != "STATICCALL" {
		t.Fatalf("unexpected targets %+v", res.CallTargets)
	}
	s := string(sanitized)
	for _, banned := range []string{"logs", "unknownField", "0xdead"} {
		if strings.Contains(s, banned) {
			t.Fatalf("sanitized payload must not carry %q: %s", banned, s)
		}
	}
	for _, kept := range []string{addrA, addrB, `"output":"0x03"`, `"type":"STATICCALL"`} {
		if !strings.Contains(s, kept) {
			t.Fatalf("sanitized payload lost %q: %s", kept, s)
		}
	}
}

func TestParseStrictCallTrace_StorageContextFollowsFrameType(t *testing.T) {
	raw := `{"type":"CALL","from":"` + addrE + `","to":"` + addrA + `","calls":[
		{"type":"DELEGATECALL","from":"` + addrA + `","to":"` + addrB + `","calls":[
			{"type":"CALLCODE","from":"` + addrB + `","to":"` + addrE + `"},
			{"type":"CALL","from":"` + addrA + `","to":"` + addrB + `","calls":[
				{"type":"DELEGATECALL","from":"` + addrB + `","to":"` + addrE + `"}]}]}]}`
	_, trace, err := ParseStrictCallTrace(json.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{addrA, addrA, addrA, addrB, addrB}
	if len(trace.CallTargets) != len(want) {
		t.Fatalf("unexpected frames: %+v", trace.CallTargets)
	}
	for i, target := range trace.CallTargets {
		if target.StorageAddress != want[i] {
			t.Fatalf("frame %d storage context = %s, want %s", i, target.StorageAddress, want[i])
		}
	}
}

func TestParseStrictCallTrace_RejectsNonCallTracerShapes(t *testing.T) {
	cases := map[string]string{
		"json null":           `null`,
		"empty object":        `{}`,
		"array":               `[]`,
		"string":              `"x"`,
		"prestate shape":      `{"` + addrA + `":{"balance":"0x0","storage":{"0x01":"0x05"}}}`,
		"struct logger shape": `{"failed":false,"gas":28189,"returnValue":"0x","structLogs":[]}`,
		"lowercase type":      `{"type":"call","from":"` + addrE + `","to":"` + addrA + `"}`,
		"unknown root type":   `{"type":"JUMP","from":"` + addrE + `","to":"` + addrA + `"}`,
		"unknown nested type": `{"type":"CALL","from":"` + addrE + `","to":"` + addrA + `","calls":[{"type":"SLOAD","to":"` + addrB + `"}]}`,
		"call with empty to":  `{"type":"CALL","from":"` + addrE + `","to":""}`,
		"call with bad to":    `{"type":"CALL","from":"` + addrE + `","to":"0x1234"}`,
		"non-string gas":      `{"type":"CALL","from":"` + addrE + `","to":"` + addrA + `","gas":16}`,
		"calls not an array":  `{"type":"CALL","from":"` + addrE + `","to":"` + addrA + `","calls":{}}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ParseStrictCallTrace(json.RawMessage(raw)); err == nil {
				t.Fatalf("%s must be rejected", name)
			}
		})
	}
}

// CALLCODE runs the callee's code against the CALLER's storage, like
// DELEGATECALL, so it must be validated with DELEGATECALL semantics (the M6
// shared-infrastructure deny applies). SELFDESTRUCT's beneficiary is revealed
// in the frame and is validated like a CALL target.
func TestParseStrictCallTrace_CallcodeAndSelfdestructRecorded(t *testing.T) {
	raw := `{"type":"CALL","from":"` + addrE + `","to":"` + addrA + `","calls":[
		{"type":"CALLCODE","from":"` + addrA + `","to":"` + addrB + `"},
		{"type":"SELFDESTRUCT","from":"` + addrA + `","to":"` + addrE + `","value":"0x1"}]}`
	_, res, err := ParseStrictCallTrace(json.RawMessage(raw))
	if err != nil {
		t.Fatalf("rejected: %v", err)
	}
	if len(res.CallTargets) != 3 {
		t.Fatalf("want 3 targets, got %+v", res.CallTargets)
	}
	if res.CallTargets[1].Type != "DELEGATECALL" || res.CallTargets[1].To != addrB {
		t.Fatalf("CALLCODE must be recorded as DELEGATECALL to %s, got %+v", addrB, res.CallTargets[1])
	}
	if res.CallTargets[2].Type != "CALL" || res.CallTargets[2].To != addrE {
		t.Fatalf("SELFDESTRUCT beneficiary must be recorded as a CALL target, got %+v", res.CallTargets[2])
	}
}

func TestParseStrictCallTrace_CreateFramesFlagged(t *testing.T) {
	raw := `{"type":"CALL","from":"` + addrE + `","to":"` + addrA + `","calls":[
		{"type":"CREATE2","from":"` + addrA + `","to":"` + addrB + `"},
		{"type":"CREATE","from":"` + addrA + `","to":"","error":"execution reverted"}]}`
	_, res, err := ParseStrictCallTrace(json.RawMessage(raw))
	if err != nil {
		t.Fatalf("rejected: %v", err)
	}
	if !res.HasCreate || !res.HasCreate2 {
		t.Fatalf("CREATE/CREATE2 must be flagged: %+v", res)
	}
}

// `from` is returned to the caller, so it is checked like `to`: a nested frame
// must name a valid address; only the root may omit it.
func TestParseStrictCallTrace_FromChecked(t *testing.T) {
	ok := `{"type":"CALL","to":"` + addrA + `","calls":[{"type":"STATICCALL","from":"` + addrA + `","to":"` + addrB + `"}]}`
	if _, _, err := ParseStrictCallTrace(json.RawMessage(ok)); err != nil {
		t.Fatalf("root without from must be accepted: %v", err)
	}
	for name, raw := range map[string]string{
		"bad root from":     `{"type":"CALL","from":"0x12","to":"` + addrA + `"}`,
		"nested empty from": `{"type":"CALL","from":"` + addrE + `","to":"` + addrA + `","calls":[{"type":"STATICCALL","to":"` + addrB + `"}]}`,
		"nested bad from":   `{"type":"CALL","from":"` + addrE + `","to":"` + addrA + `","calls":[{"type":"STATICCALL","from":"0xzz","to":"` + addrB + `"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ParseStrictCallTrace(json.RawMessage(raw)); err == nil {
				t.Fatalf("%s must be rejected", name)
			}
		})
	}
}

func TestParseStrictCallTrace_DepthBounded(t *testing.T) {
	frame := `{"type":"CALL","from":"` + addrE + `","to":"` + addrA + `"}`
	for i := 0; i < maxTraceDepth+2; i++ {
		frame = `{"type":"CALL","from":"` + addrE + `","to":"` + addrA + `","calls":[` + frame + `]}`
	}
	_, _, err := ParseStrictCallTrace(json.RawMessage(frame))
	if !errors.Is(err, ErrTraceDepthExceeded) {
		t.Fatalf("want ErrTraceDepthExceeded, got %v", err)
	}
}
