package server

import (
	"context"
	"encoding/json"

	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/tracer"
)

// strictTraceAllowed reports whether debug_traceTransaction may return the
// trace of a mined transaction to this caller (RD-1299). Under the standard
// profile it always may (the method allowlist and the cross-org trace check
// decide). Under strict the top frame — sender, calldata and value — is
// returned only to a participant of the traced transaction: the
// caller's linked address is the root frame's `from` or `to`
// (rbac.DecideTxEnvelope). A linked-address lookup failure or a trace without a
// root frame denies (fail closed).
func (p *JSONRPCProcessor) strictTraceAllowed(ctx context.Context, userDID string, tr *tracer.TraceResult) bool {
	if !p.readProfile.Strict() {
		return true
	}
	linked, err := p.rbacAccessCtrl.Store().GetLinkedEthAddresses(ctx, userDID)
	if err != nil {
		return false
	}
	return rbac.DecideTxEnvelope(p.readProfile, rbac.TxEnvelopeFacts{
		Surface:       rbac.TxSurfaceTransaction,
		IsParticipant: traceRootParticipant(tr, linked),
	})
}

// traceRootParticipant reports whether one of the linked addresses is the
// traced transaction's sender or recipient, read from the root (depth 0) call
// frame. For a contract creation the root `to` is the created contract, which
// is never a participant.
func traceRootParticipant(tr *tracer.TraceResult, linked []string) bool {
	if tr == nil {
		return false
	}
	for _, ct := range tr.CallTargets {
		if ct.Depth != 0 {
			continue
		}
		to := ct.To
		if ct.Type == "CREATE" || ct.Type == "CREATE2" {
			to = ""
		}
		return isTxParticipant(linked, ct.From, to)
	}
	return false
}

// strictTraceUnsupportedConfig refuses, under the strict read profile, a
// debug_traceTransaction tracer configuration other than the call tracer.
const strictTraceUnsupportedConfig = "only the call tracer is available for debug_traceTransaction on this network"

// strictTraceForwardBody vets a debug_traceTransaction request under the strict
// read profile and builds a top-frame callTracer body without logs. The trace
// processor uses this helper to vet options, then builds its canonical plan. That
// matches the participant transaction and receipt view under strict
// (RD-1299). Accepted caller options: none,
// or the call tracer with no setting other than onlyTopCall:true and
// withLog:false. Anything else (the default opcode logger, the prestate
// tracer, JS tracers, timeouts) returns ok=false. Under the standard profile it
// returns (nil, true), leaving option validation to the common trace gate.
func (p *JSONRPCProcessor) strictTraceForwardBody(req *ProcessRequest) (body []byte, ok bool) {
	if !p.readProfile.Strict() {
		return nil, true
	}
	if len(req.Params) == 0 || len(req.Params) > 2 {
		return nil, false
	}
	if len(req.Params) == 2 && req.Params[1] != nil {
		opts, isMap := req.Params[1].(map[string]any)
		if !isMap || !strictCallTracerOptions(opts) {
			return nil, false
		}
	}
	env := map[string]json.RawMessage{}
	if len(req.Body) > 0 {
		if err := json.Unmarshal(req.Body, &env); err != nil {
			env = map[string]json.RawMessage{}
		}
	}
	if _, has := env["jsonrpc"]; !has {
		env["jsonrpc"] = json.RawMessage(`"2.0"`)
	}
	if _, has := env["id"]; !has {
		env["id"] = json.RawMessage(`1`)
	}
	method, err := json.Marshal(req.Method)
	if err != nil {
		return nil, false
	}
	env["method"] = method
	params, err := json.Marshal([]any{req.Params[0], map[string]any{
		"tracer":       "callTracer",
		"tracerConfig": map[string]any{"onlyTopCall": true, "withLog": false},
	}})
	if err != nil {
		return nil, false
	}
	env["params"] = params
	out, err := json.Marshal(env)
	if err != nil {
		return nil, false
	}
	return out, true
}

// strictCallTracerOptions reports whether caller-supplied trace options name
// the call tracer and set nothing beyond onlyTopCall:true / withLog:false.
func strictCallTracerOptions(opts map[string]any) bool {
	if opts["tracer"] != "callTracer" {
		return false
	}
	for k, v := range opts {
		switch k {
		case "tracer":
		case "tracerConfig":
			if v == nil {
				continue
			}
			cfg, isMap := v.(map[string]any)
			if !isMap {
				return false
			}
			for ck, cv := range cfg {
				switch ck {
				case "onlyTopCall":
					if cv != true {
						return false
					}
				case "withLog":
					if cv != false {
						return false
					}
				default:
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}
