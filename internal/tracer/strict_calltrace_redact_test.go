package tracer

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// A client trace shows each value only to a viewer who may read the storage of
// the contract that produced it. A nested frame's input and value come from
// the parent frame's storage context; its output and revert data come from its
// own storage context. The top frame and the call-tree shape are always shown.

const (
	addrPayroll = "0x1111111111111111111111111111111111111111"
	addrToken   = "0x2222222222222222222222222222222222222222"
	addrImpl    = "0x3333333333333333333333333333333333333333"
	addrUser    = "0x4444444444444444444444444444444444444444"

	topInput     = "0xbd0af85d0001"
	topOutput    = "0x0000000000000000000000000000000000000000000000000000000000000001"
	nestedInput  = "0xa9059cbb00000000000000000000000000000000000000000000000000000000005a1a12"
	nestedOutput = "0x00000000000000000000000000000000000000000000000000000000007e3c1d"
	nestedRevert = "transfer refused"
)

// payrollTrace is Payroll.pay → Token.transfer(employee, salary).
func payrollTrace(t *testing.T) json.RawMessage {
	t.Helper()
	raw := `{"type":"CALL","from":"` + addrUser + `","to":"` + addrPayroll + `","value":"0x0","gas":"0x100","gasUsed":"0x80",
		"input":"` + topInput + `","output":"` + topOutput + `","calls":[
		{"type":"CALL","from":"` + addrPayroll + `","to":"` + addrToken + `","value":"0x7","gas":"0x50","gasUsed":"0x20",
		 "input":"` + nestedInput + `","output":"` + nestedOutput + `","error":"execution reverted","revertReason":"` + nestedRevert + `"}]}`
	sanitized, _, err := ParseStrictCallTrace(json.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	return sanitized
}

func decodeFrame(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("redacted payload is not JSON: %v", err)
	}
	return m
}

func nestedFrame(t *testing.T, root map[string]any, path ...int) map[string]any {
	t.Helper()
	f := root
	for _, i := range path {
		calls, _ := f["calls"].([]any)
		if len(calls) <= i {
			t.Fatalf("missing nested frame %v in %v", path, root)
		}
		f, _ = calls[i].(map[string]any)
	}
	return f
}

func redactedFields(f map[string]any) []string {
	raw, _ := f["redacted"].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		s, _ := v.(string)
		out = append(out, s)
	}
	return out
}

func TestRedactStrictCallTrace_PayrollToken(t *testing.T) {
	cases := []struct {
		name         string
		readable     map[string]bool
		inputShown   bool
		outputShown  bool
		wantRedacted []string
	}{
		{"grant only", map[string]bool{}, false, false, []string{"input", "value", "output", "revertReason"}},
		{"admin of payroll", map[string]bool{addrPayroll: true}, true, false, []string{"output", "revertReason"}},
		{"admin of token", map[string]bool{addrToken: true}, false, true, []string{"input", "value"}},
		{"admin of both", map[string]bool{addrPayroll: true, addrToken: true}, true, true, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := RedactStrictCallTrace(payrollTrace(t), tc.readable)
			if err != nil {
				t.Fatal(err)
			}
			body := string(out)
			root := decodeFrame(t, out)

			// The top frame is always shown in full, and never marked.
			if root["input"] != topInput || root["output"] != topOutput || root["value"] != "0x0" {
				t.Fatalf("top frame values must always be shown: %v", root)
			}
			if _, marked := root["redacted"]; marked {
				t.Fatalf("top frame must never be marked redacted: %v", root)
			}

			child := nestedFrame(t, root, 0)
			// Shape, addressing, gas and the error string are always shown.
			for key, want := range map[string]string{"type": "CALL", "from": addrPayroll, "to": addrToken, "gas": "0x50", "gasUsed": "0x20", "error": "execution reverted"} {
				if child[key] != want {
					t.Fatalf("%s must always be shown: got %v in %v", key, child[key], child)
				}
			}
			if got := strings.Contains(body, strings.TrimPrefix(nestedInput, "0x")); got != tc.inputShown {
				t.Fatalf("nested input shown=%v, want %v: %s", got, tc.inputShown, body)
			}
			if _, has := child["value"]; has != tc.inputShown {
				t.Fatalf("nested value shown=%v, want %v: %s", has, tc.inputShown, body)
			}
			if got := strings.Contains(body, strings.TrimPrefix(nestedOutput, "0x")); got != tc.outputShown {
				t.Fatalf("nested output shown=%v, want %v: %s", got, tc.outputShown, body)
			}
			if got := strings.Contains(body, nestedRevert); got != tc.outputShown {
				t.Fatalf("nested revert reason shown=%v, want %v: %s", got, tc.outputShown, body)
			}
			if got := redactedFields(child); !reflect.DeepEqual(got, tc.wantRedacted) && !(len(got) == 0 && len(tc.wantRedacted) == 0) {
				t.Fatalf("redacted marker = %v, want %v", got, tc.wantRedacted)
			}
		})
	}
}

// The marker depends only on the viewer's access and the tree shape, never on
// whether a hidden field had data or how long it was.
func TestRedactStrictCallTrace_MarkerIndependentOfHiddenData(t *testing.T) {
	short := `{"type":"CALL","from":"` + addrUser + `","to":"` + addrPayroll + `","calls":[
		{"type":"STATICCALL","from":"` + addrPayroll + `","to":"` + addrToken + `"}]}`
	long := `{"type":"CALL","from":"` + addrUser + `","to":"` + addrPayroll + `","calls":[
		{"type":"STATICCALL","from":"` + addrPayroll + `","to":"` + addrToken + `","input":"0x` + strings.Repeat("ab", 200) + `","output":"0x` + strings.Repeat("cd", 300) + `"}]}`
	var bodies []string
	for _, raw := range []string{short, long} {
		sanitized, _, err := ParseStrictCallTrace(json.RawMessage(raw))
		if err != nil {
			t.Fatal(err)
		}
		out, err := RedactStrictCallTrace(sanitized, map[string]bool{})
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, string(out))
	}
	if bodies[0] != bodies[1] {
		t.Fatalf("a fully hidden frame must look the same whatever it carried:\n%s\n%s", bodies[0], bodies[1])
	}
}

// A DELEGATECALL runs the implementation's code against the caller's
// storage, so the storage context, not the code address, decides.
func TestRedactStrictCallTrace_DelegatecallParentUsesStorageContext(t *testing.T) {
	raw := `{"type":"CALL","from":"` + addrUser + `","to":"` + addrPayroll + `","input":"` + topInput + `","calls":[
		{"type":"DELEGATECALL","from":"` + addrPayroll + `","to":"` + addrImpl + `","input":"0x01","output":"0x02","calls":[
			{"type":"CALL","from":"` + addrPayroll + `","to":"` + addrToken + `","input":"` + nestedInput + `","output":"` + nestedOutput + `"}]}]}`
	sanitized, _, err := ParseStrictCallTrace(json.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}

	// Admin of the proxy (the storage context): the delegated frame's output
	// and the inner call's input are shown; the token's output is not.
	out, err := RedactStrictCallTrace(sanitized, map[string]bool{addrPayroll: true})
	if err != nil {
		t.Fatal(err)
	}
	root := decodeFrame(t, out)
	delegated := nestedFrame(t, root, 0)
	inner := nestedFrame(t, root, 0, 0)
	if delegated["input"] != "0x01" || delegated["output"] != "0x02" {
		t.Fatalf("the delegated frame's values belong to the proxy's storage context: %v", delegated)
	}
	if inner["input"] != nestedInput {
		t.Fatalf("the inner call's input was produced in the proxy's storage context: %v", inner)
	}
	if _, has := inner["output"]; has {
		t.Fatalf("the token's output needs the token's admin: %v", inner)
	}

	// Admin of the implementation only: nothing nested is shown.
	out, err = RedactStrictCallTrace(sanitized, map[string]bool{addrImpl: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), strings.TrimPrefix(nestedInput, "0x")) || strings.Contains(string(out), `"output":"0x02"`) {
		t.Fatalf("the implementation's code address is not the storage context: %s", out)
	}
}

func TestTraceValueOwners(t *testing.T) {
	owners, err := TraceValueOwners(payrollTrace(t))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{addrPayroll, addrToken}; !reflect.DeepEqual(owners, want) {
		t.Fatalf("owners = %v, want %v", owners, want)
	}

	// A top frame alone carries no nested values: nothing to resolve.
	sanitized, _, err := ParseStrictCallTrace(json.RawMessage(`{"type":"CALL","to":"` + addrPayroll + `","output":"0x01"}`))
	if err != nil {
		t.Fatal(err)
	}
	owners, err = TraceValueOwners(sanitized)
	if err != nil {
		t.Fatal(err)
	}
	if len(owners) != 0 {
		t.Fatalf("a top frame alone needs no lookups, got %v", owners)
	}
}

// A field named like the marker that a node returns is not passed through.
func TestRedactStrictCallTrace_NodeMarkerNotTrusted(t *testing.T) {
	raw := `{"type":"CALL","to":"` + addrPayroll + `","redacted":["x"],"calls":[
		{"type":"CALL","from":"` + addrPayroll + `","to":"` + addrToken + `","redacted":["y"]}]}`
	sanitized, _, err := ParseStrictCallTrace(json.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	out, err := RedactStrictCallTrace(sanitized, map[string]bool{addrPayroll: true, addrToken: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "redacted") {
		t.Fatalf("a node-supplied marker must be dropped: %s", out)
	}
}

func TestRedactStrictCallTrace_RejectsMalformedInput(t *testing.T) {
	for _, raw := range []string{"", "null", "[]", `{"type":"CALL","calls":"x"}`} {
		if _, err := RedactStrictCallTrace(json.RawMessage(raw), nil); err == nil {
			t.Fatalf("%q must be rejected", raw)
		}
		if _, err := TraceValueOwners(json.RawMessage(raw)); err == nil {
			t.Fatalf("%q must be rejected by TraceValueOwners", raw)
		}
	}
}

// CALLCODE, failed CREATE, SELFDESTRUCT and precompile frames apply the same
// rule: input from the parent's storage context, output from the frame's own
// (CALLCODE runs against the parent's storage; a failed CREATE has no `to`, so
// its output has no owner). DELEGATECALL is covered above.
func TestRedactStrictCallTrace_FrameTypes(t *testing.T) {
	precompile := "0x0000000000000000000000000000000000000004"
	raw := `{"type":"CALL","from":"` + addrUser + `","to":"` + addrPayroll + `","calls":[
		{"type":"CALLCODE","from":"` + addrPayroll + `","to":"` + addrImpl + `","input":"0xc0de01","output":"0xc0de02"},
		{"type":"CREATE","from":"` + addrPayroll + `","input":"0xc0de03","output":"0xc0de04","error":"out of gas"},
		{"type":"SELFDESTRUCT","from":"` + addrPayroll + `","to":"` + addrToken + `","value":"0xc0de05"},
		{"type":"STATICCALL","from":"` + addrPayroll + `","to":"` + precompile + `","input":"0xc0de06","output":"0xc0de06"}]}`
	sanitized, _, err := ParseStrictCallTrace(json.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}

	// Readable parent only: every input-side value is shown. Only the
	// CALLCODE output (the parent's storage context) is shown; the failed
	// CREATE and the precompile have no readable owner.
	out, err := RedactStrictCallTrace(sanitized, map[string]bool{addrPayroll: true})
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, shown := range []string{"c0de01", "c0de02", "c0de03", "c0de05", `"input":"0xc0de06"`, `"error":"out of gas"`} {
		if !strings.Contains(body, shown) {
			t.Fatalf("%s must be shown: %s", shown, body)
		}
	}
	for _, hidden := range []string{"c0de04", `"output":"0xc0de06"`} {
		if strings.Contains(body, hidden) {
			t.Fatalf("%s must be hidden: %s", hidden, body)
		}
	}

	// Nothing readable: no nested value is shown at all.
	out, err = RedactStrictCallTrace(sanitized, map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "c0de") {
		t.Fatalf("no nested value may be shown: %s", out)
	}
}
