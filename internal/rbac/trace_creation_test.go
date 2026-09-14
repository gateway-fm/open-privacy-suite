package rbac

import (
	"context"
	"privacy-proxy/internal/tracer"
	"testing"
)

func TestPreflightCreationOwnership(t *testing.T) {
	const factory = "0x1111111111111111111111111111111111111111"
	const child = "0x2222222222222222222222222222222222222222"
	for _, tc := range []struct {
		name                                    string
		deploy, fresh, create, foreign, allowed bool
	}{
		{"new child is callable", true, true, true, false, true},
		{"deploy claim required", false, true, true, false, false},
		{"failed collision cannot grant existing code", true, false, true, false, false},
		{"unrelated address cannot be granted", true, true, false, false, false},
		{"foreign ownership still denied", true, true, true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewMockTraceStore()
			s.AddOwnedAddress("a", factory)
			if tc.foreign {
				s.AddOwnedAddress("b", child)
			}
			trace := &tracer.TraceResult{HasCreate: tc.create, CallTargets: []tracer.CallTarget{{Type: "CALL", To: factory}}}
			if tc.create {
				trace.CallTargets = append(trace.CallTargets, tracer.CallTarget{Type: "CREATE", From: factory, To: child})
			}
			trace.CallTargets = append(trace.CallTargets, tracer.CallTarget{Type: "CALL", From: factory, To: child})
			fresh := map[string]bool{}
			if tc.fresh {
				fresh[child] = true
			}
			r, err := NewTraceValidator(s).ValidateTrace(context.Background(), map[string]bool{"a": true}, trace, tc.deploy, WithPreflightCreations(fresh), WithIntraOrgGrantScoping(map[string]bool{factory: true}))
			if err != nil {
				t.Fatal(err)
			}
			if r.Allowed != tc.allowed {
				t.Fatalf("allowed=%v want=%v: %+v", r.Allowed, tc.allowed, r)
			}
		})
	}
}

func TestPreflightValueRecipients(t *testing.T) {
	const recipient = "0x2222222222222222222222222222222222222222"
	for _, tc := range []struct {
		name, kind             string
		noCode, foreign, allow bool
	}{
		{"native call", "CALL", true, false, true},
		{"destruction payout", "SELFDESTRUCT", true, false, true},
		{"unknown contract remains private", "CALL", false, false, false},
		{"foreign registration wins", "CALL", true, true, false},
		{"foreign destruction target", "SELFDESTRUCT", true, true, false},
		{"no delegation exemption", "DELEGATECALL", true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewMockTraceStore()
			if tc.foreign {
				s.AddOwnedAddress("b", recipient)
			}
			trace := &tracer.TraceResult{CallTargets: []tracer.CallTarget{{Type: tc.kind, To: recipient}}}
			r, err := NewTraceValidator(s).ValidateTrace(context.Background(), map[string]bool{"a": true}, trace, false, WithPreflightValueRecipients(map[string]bool{recipient: tc.noCode}))
			if err != nil {
				t.Fatal(err)
			}
			if r.Allowed != tc.allow {
				t.Fatalf("allowed=%v want=%v: %+v", r.Allowed, tc.allow, r)
			}
		})
	}
}
