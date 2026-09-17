package nodepolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// SimulationRequest is transmitted as exact base64-encoded JSON bytes alongside
// its signed identity envelope. Verifiers hash those bytes before decoding them;
// they never reconstruct an equivalent JSON document in another language.
type SimulationRequest struct {
	Method          string          `json:"method"`
	Params          json.RawMessage `json:"params"`
	DryRun          bool            `json:"dry_run"`
	CandidatePolicy *PolicyArtifact `json:"candidate_policy"`
}

func EncodeSimulation(request SimulationRequest) ([]byte, error) {
	b, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	if _, err := ParseSimulation(b, SimulationHash(b)); err != nil {
		return nil, err
	}
	return b, nil
}

func SimulationHash(request []byte) string {
	if len(request) == 0 || len(request) > 1<<20 {
		return ""
	}
	b := []byte("OPS_SIMULATION_V1\x00")
	b = binary.BigEndian.AppendUint32(b, uint32(len(request)))
	b = append(b, request...)
	h := sha256.Sum256(b)
	return "0x" + hex.EncodeToString(h[:])
}

func ParseSimulation(request []byte, expectedHash string) (SimulationRequest, error) {
	var out SimulationRequest
	if !hexField(expectedHash, 32) || SimulationHash(request) != expectedHash {
		return out, ErrIdentity
	}
	if err := decodeStrict(request, &out); err != nil {
		return out, ErrIdentity
	}
	if out.CandidatePolicy != nil && !validPolicyArtifact(*out.CandidatePolicy) {
		return SimulationRequest{}, ErrIdentity
	}
	switch out.Method {
	case "eth_call", "eth_estimateGas", "debug_traceCall":
	default:
		return SimulationRequest{}, ErrIdentity
	}
	var params []json.RawMessage
	if err := json.Unmarshal(out.Params, &params); err != nil || len(params) < 1 || len(params) > 3 {
		return SimulationRequest{}, ErrIdentity
	}
	// Replacing an allowed contract's code with a storage reader would bypass
	// the reviewed selector/argument rules. Simulations always use real state.
	if len(params) == 3 {
		if out.Method != "debug_traceCall" {
			if !emptySimulationOverride(params[2]) {
				return SimulationRequest{}, ErrIdentity
			}
		} else {
			var options map[string]json.RawMessage
			if err := json.Unmarshal(params[2], &options); err != nil {
				return SimulationRequest{}, ErrIdentity
			}
			for key, value := range options {
				if (strings.EqualFold(key, "stateOverrides") || strings.EqualFold(key, "blockOverrides") || key == "state_overrides" || key == "block_overrides") && !emptySimulationOverride(value) {
					return SimulationRequest{}, ErrIdentity
				}
			}
		}
	}
	var call map[string]json.RawMessage
	if err := json.Unmarshal(params[0], &call); err != nil {
		return SimulationRequest{}, ErrIdentity
	}
	var from string
	if err := json.Unmarshal(call["from"], &from); err != nil || !hexField(from, 20) {
		return SimulationRequest{}, ErrIdentity
	}
	return out, nil
}

func emptySimulationOverride(raw json.RawMessage) bool {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return true
	}
	var object map[string]json.RawMessage
	return json.Unmarshal(raw, &object) == nil && len(object) == 0
}
