package tracer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ErrUntrustedTrace is returned by ParseStrictCallTrace when a node response
// is not a well-formed callTracer tree. Callers must fail closed.
var ErrUntrustedTrace = errors.New("trace is not a well-formed callTracer tree")

// strictFrame is the callTracer frame shape the client debug_trace* path
// re-emits. Only these fields leave the proxy; anything else the node returns
// (logs, prestate/struct-log fields, vendor extensions) is dropped. All values
// are strings, exactly as geth's callTracer emits them, so a struct-logger or
// other fallback body (numeric "gas", etc.) fails to decode and is rejected.
type strictFrame struct {
	Type         string        `json:"type"`
	From         string        `json:"from,omitempty"`
	To           string        `json:"to,omitempty"`
	Value        string        `json:"value,omitempty"`
	Gas          string        `json:"gas,omitempty"`
	GasUsed      string        `json:"gasUsed,omitempty"`
	Input        string        `json:"input,omitempty"`
	Output       string        `json:"output,omitempty"`
	Error        string        `json:"error,omitempty"`
	RevertReason string        `json:"revertReason,omitempty"`
	Calls        []strictFrame `json:"calls,omitempty"`
}

// ParseStrictCallTrace parses a callTracer result for the client debug_trace*
// path (RD-1304) and returns (sanitized payload, call targets, error).
//
// Unlike ParseCallTraceResult — a lenient projection used by the internal
// validators — this is the gate for a payload that is RETURNED to the caller,
// so the validated payload and the returned payload must be the same bytes:
//
//   - the root must be a JSON object with a known frame type (rejects null,
//     {}, arrays, prestate/struct-logger shapes, lowercase/unknown types);
//   - every nested frame type must be known; anything else fails closed;
//   - every frame that can reveal another account records a target:
//     CALL/STATICCALL/DELEGATECALL as-is, CALLCODE with DELEGATECALL
//     semantics (it runs the callee's code against the caller's storage, so
//     the M6 shared-infrastructure deny must apply), SELFDESTRUCT's
//     beneficiary as a CALL target, and CREATE/CREATE2 as creates;
//   - a non-create frame must name a valid 20-byte `to`;
//   - the returned payload is the re-marshaled strictFrame, never the node's
//     raw bytes.
func ParseStrictCallTrace(raw json.RawMessage) (json.RawMessage, *TraceResult, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, nil, ErrUntrustedTrace
	}
	var root strictFrame
	if err := json.Unmarshal(trimmed, &root); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrUntrustedTrace, err)
	}
	result := &TraceResult{CallTargets: make([]CallTarget, 0), Error: root.Error}
	if root.GasUsed != "" {
		result.GasUsed = parseHexUint64(root.GasUsed)
	}
	if err := collectStrictTargets(&root, result, 0, ""); err != nil {
		return nil, nil, err
	}
	sanitized, err := json.Marshal(root)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrUntrustedTrace, err)
	}
	return sanitized, result, nil
}

func collectStrictTargets(f *strictFrame, result *TraceResult, depth int, parentStorage string) error {
	if depth > maxTraceDepth {
		return ErrTraceDepthExceeded
	}
	// `from` is returned too: it must be a valid address, and may be omitted
	// only on the root frame (a call simulated without a sender).
	if f.From != "" || depth > 0 {
		if !isStrictAddress(f.From) {
			return ErrUntrustedTrace
		}
	}
	storageAddress := frameStorageContext(f.Type, f.To, parentStorage)
	switch f.Type {
	case "CALL", "STATICCALL", "DELEGATECALL":
		if !isStrictAddress(f.To) {
			return ErrUntrustedTrace
		}
		result.CallTargets = append(result.CallTargets, CallTarget{Type: f.Type, From: f.From, To: f.To, Depth: depth})
	case "CALLCODE":
		if !isStrictAddress(f.To) {
			return ErrUntrustedTrace
		}
		result.CallTargets = append(result.CallTargets, CallTarget{Type: "DELEGATECALL", From: f.From, To: f.To, Depth: depth})
	case "SELFDESTRUCT":
		if !isStrictAddress(f.To) {
			return ErrUntrustedTrace
		}
		result.CallTargets = append(result.CallTargets, CallTarget{Type: "CALL", From: f.From, To: f.To, Depth: depth})
	case "CREATE", "CREATE2":
		// `to` is the created address; empty when the creation failed.
		if f.To != "" && !isStrictAddress(f.To) {
			return ErrUntrustedTrace
		}
		if f.Type == "CREATE" {
			result.HasCreate = true
		} else {
			result.HasCreate2 = true
		}
		result.CallTargets = append(result.CallTargets, CallTarget{Type: f.Type, From: f.From, To: f.To, Depth: depth})
	default:
		return ErrUntrustedTrace
	}
	result.CallTargets[len(result.CallTargets)-1].StorageAddress = storageAddress
	result.CallTargets[len(result.CallTargets)-1].Input = f.Input
	for i := range f.Calls {
		if err := collectStrictTargets(&f.Calls[i], result, depth+1, storageAddress); err != nil {
			return err
		}
	}
	return nil
}

// isStrictAddress reports whether s is a 0x-prefixed 20-byte hex address.
func isStrictAddress(s string) bool {
	if len(s) != 42 || (!strings.HasPrefix(s, "0x") && !strings.HasPrefix(s, "0X")) {
		return false
	}
	for _, c := range s[2:] {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
