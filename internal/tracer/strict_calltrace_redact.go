package tracer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// Client trace value visibility.
//
// A client trace returns the call tree to every viewer who passes the access
// checks, but each value in it only to a viewer who may read the storage of
// the contract that produced it:
//
//   - the top frame's input, value, output and revert data are always shown
//     (the caller supplied the input; eth_call returns the output anyway);
//   - a nested frame's input and value were produced by the PARENT frame's
//     storage context (for a DELEGATECALL parent, the contract whose storage
//     ran);
//   - a nested frame's output and revert reason were produced by the frame's
//     OWN storage context;
//   - type, from, to, gas, gasUsed, the error string and the tree shape are
//     always shown.
//
// A hidden field is omitted and named in the frame's "redacted" list. The list
// is one of three fixed values (redactedInput, redactedOutput, or both, in
// that order) chosen only by the viewer's access, so it reveals neither
// whether the hidden field had data nor its length.
var (
	redactedInput  = []string{"input", "value"}
	redactedOutput = []string{"output", "revertReason"}
)

// clientFrame is strictFrame plus the redaction marker. It is built only by
// RedactStrictCallTrace; a node-supplied "redacted" field never reaches it,
// because ParseStrictCallTrace drops unknown fields.
type clientFrame struct {
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
	Redacted     []string      `json:"redacted,omitempty"`
	Calls        []clientFrame `json:"calls,omitempty"`
}

// frameStorageContext is the contract whose storage a frame runs against:
// its `to`, except for DELEGATECALL and CALLCODE, which run the callee's code
// against the parent's storage.
func frameStorageContext(frameType, to, parentStorage string) string {
	if frameType == "DELEGATECALL" || frameType == "CALLCODE" {
		return parentStorage
	}
	return to
}

func decodeSanitizedTrace(sanitized json.RawMessage) (*strictFrame, error) {
	trimmed := bytes.TrimSpace(sanitized)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, ErrUntrustedTrace
	}
	var root strictFrame
	if err := json.Unmarshal(trimmed, &root); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUntrustedTrace, err)
	}
	return &root, nil
}

// TraceValueOwners returns the storage contexts that produced a nested value
// in a payload returned by ParseStrictCallTrace: for every nested frame, its
// parent's storage context and its own. Lowercased, de-duplicated, in
// first-seen order. A trace with only a top frame returns none.
func TraceValueOwners(sanitized json.RawMessage) ([]string, error) {
	root, err := decodeSanitizedTrace(sanitized)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var owners []string
	add := func(addr string) {
		addr = strings.ToLower(addr)
		if addr != "" && !seen[addr] {
			seen[addr] = true
			owners = append(owners, addr)
		}
	}
	var walk func(f *strictFrame, storage string, depth int) error
	walk = func(f *strictFrame, storage string, depth int) error {
		if depth > maxTraceDepth {
			return ErrTraceDepthExceeded
		}
		for i := range f.Calls {
			child := &f.Calls[i]
			childStorage := frameStorageContext(child.Type, child.To, storage)
			add(storage)
			add(childStorage)
			if err := walk(child, childStorage, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(root, frameStorageContext(root.Type, root.To, ""), 0); err != nil {
		return nil, err
	}
	return owners, nil
}

// RedactStrictCallTrace applies the client trace value visibility rule to a
// payload returned by ParseStrictCallTrace. readable holds the lowercased
// storage contexts whose values the viewer may see; any other context,
// including an empty one, is hidden.
func RedactStrictCallTrace(sanitized json.RawMessage, readable map[string]bool) (json.RawMessage, error) {
	root, err := decodeSanitizedTrace(sanitized)
	if err != nil {
		return nil, err
	}
	canRead := func(addr string) bool {
		addr = strings.ToLower(addr)
		return addr != "" && readable[addr]
	}
	var convert func(f *strictFrame, storage, parentStorage string, depth int) (clientFrame, error)
	convert = func(f *strictFrame, storage, parentStorage string, depth int) (clientFrame, error) {
		if depth > maxTraceDepth {
			return clientFrame{}, ErrTraceDepthExceeded
		}
		out := clientFrame{
			Type: f.Type, From: f.From, To: f.To, Value: f.Value, Gas: f.Gas, GasUsed: f.GasUsed,
			Input: f.Input, Output: f.Output, Error: f.Error, RevertReason: f.RevertReason,
		}
		if depth > 0 {
			if !canRead(parentStorage) {
				out.Input, out.Value = "", ""
				out.Redacted = append(out.Redacted, redactedInput...)
			}
			if !canRead(storage) {
				out.Output, out.RevertReason = "", ""
				out.Redacted = append(out.Redacted, redactedOutput...)
			}
		}
		for i := range f.Calls {
			child := &f.Calls[i]
			c, err := convert(child, frameStorageContext(child.Type, child.To, storage), storage, depth+1)
			if err != nil {
				return clientFrame{}, err
			}
			out.Calls = append(out.Calls, c)
		}
		return out, nil
	}
	client, err := convert(root, frameStorageContext(root.Type, root.To, ""), "", 0)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(client)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUntrustedTrace, err)
	}
	return b, nil
}
