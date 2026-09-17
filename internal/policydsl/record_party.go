package policydsl

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"slices"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

const (
	RecordReadGas    uint64 = 50_000
	MaxRecordIDBytes        = 1024
	MaxRecordOutputs        = 16
)

// RecordPartyMatch reads the selected call argument through a getter on the
// guarded storage account. The getter must take exactly one identically typed
// ID and return bounded static scalar outputs; PartyOutputs selects addresses.
// Its ABI must declare view/pure. Operators must additionally review that its
// answer is independent of msg.sender: an ABI cannot prove that property, and
// the nested getter's caller is the private policy account, not the principal.
type RecordPartyMatch struct {
	Getter       string `json:"getter"`
	ABIDigest    string `json:"abiDigest"`
	PartyOutputs []int  `json:"partyOutputs"`
}

func (r *RecordPartyMatch) UnmarshalJSON(data []byte) error {
	if _, err := strictFields(data, "getter", "abiDigest", "partyOutputs"); err != nil {
		return fmt.Errorf("recordParty: %w", err)
	}
	type plain RecordPartyMatch
	var out plain
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*r = RecordPartyMatch(out)
	return nil
}

// strictFields keeps custom JSON decoders closed, duplicate-free and explicit.
// Null is never an alternative spelling of an omitted constraint or index zero.
func strictFields(data []byte, allowed ...string) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	if opening, err := d.Token(); err != nil || opening != json.Delim('{') {
		return nil, fmt.Errorf("expected object")
	}
	out := map[string]json.RawMessage{}
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return nil, err
		}
		name, ok := token.(string)
		if !ok || !slices.Contains(allowed, name) {
			return nil, fmt.Errorf("unknown field %q", name)
		}
		if _, exists := out[name]; exists {
			return nil, fmt.Errorf("duplicate field %q", name)
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return nil, err
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, fmt.Errorf("field %q must not be null", name)
		}
		out[name] = value
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("unexpected trailing data")
	}
	return out, nil
}

type compiledRecordParty struct {
	selector [4]byte
	input    abi.Type
	outputs  []abi.Type
	parties  []int
}

func compileRecordParty(spec RecordPartyMatch, input abi.Type, storage ContractInfo) (*compiledRecordParty, error) {
	if spec.ABIDigest == "" || !strings.EqualFold(spec.ABIDigest, ABIDigest(storage.ABI)) {
		return nil, fmt.Errorf("recordParty abiDigest must pin the guarded storage account's ABI")
	}
	selector, err := parseSelector(spec.Getter)
	if err != nil {
		return nil, err
	}
	parsed, err := abi.JSON(strings.NewReader(storage.ABI))
	if err != nil {
		return nil, fmt.Errorf("recordParty storage ABI does not parse: %w", err)
	}
	var method *abi.Method
	for _, candidate := range parsed.Methods {
		if bytes.Equal(candidate.ID, selector[:]) {
			if method != nil {
				return nil, fmt.Errorf("recordParty getter selector is ambiguous")
			}
			copy := candidate
			method = &copy
		}
	}
	if method == nil || (method.StateMutability != "view" && method.StateMutability != "pure") {
		return nil, fmt.Errorf("recordParty getter must resolve to a view or pure method")
	}
	if len(method.Inputs) != 1 || method.Inputs[0].Type.String() != input.String() {
		return nil, fmt.Errorf("recordParty getter must take only the selected ID with exactly the same ABI type")
	}
	if input.T != abi.UintTy && input.T != abi.StringTy && input.T != abi.BytesTy && !(input.T == abi.FixedBytesTy && input.Size == 32) {
		return nil, fmt.Errorf("recordParty ID must be uint, bytes32, string or bytes")
	}
	if len(method.Outputs) == 0 || len(method.Outputs) > MaxRecordOutputs {
		return nil, fmt.Errorf("recordParty getter requires 1..%d static scalar outputs", MaxRecordOutputs)
	}
	out := &compiledRecordParty{selector: selector, input: input, parties: append([]int(nil), spec.PartyOutputs...)}
	for _, output := range method.Outputs {
		t := output.Type
		if t.T != abi.AddressTy && t.T != abi.UintTy && t.T != abi.BoolTy && !(t.T == abi.FixedBytesTy && t.Size == 32) {
			return nil, fmt.Errorf("recordParty getter outputs support address, uint, bool and bytes32 only")
		}
		out.outputs = append(out.outputs, t)
	}
	if len(spec.PartyOutputs) == 0 {
		return nil, fmt.Errorf("recordParty requires at least one party output")
	}
	seen := map[int]bool{}
	for _, index := range spec.PartyOutputs {
		if index < 0 || index >= len(out.outputs) || out.outputs[index].T != abi.AddressTy || seen[index] {
			return nil, fmt.Errorf("recordParty partyOutputs must name distinct address outputs")
		}
		seen[index] = true
	}
	return out, nil
}

func (a compiledArg) recordInput(data []byte, headLen int) ([]byte, error) {
	r := a.record
	word := data[a.offset : a.offset+32]
	input := append([]byte(nil), r.selector[:]...)
	if r.input.T != abi.StringTy && r.input.T != abi.BytesTy {
		if r.input.T == abi.UintTy && new(big.Int).SetBytes(word).BitLen() > r.input.Size {
			return nil, errMalformedArgument
		}
		return append(input, word...), nil
	}
	offset := new(big.Int).SetBytes(word)
	if !offset.IsUint64() || offset.Uint64()%32 != 0 || offset.Uint64() < uint64(headLen-4) || offset.Uint64() > uint64(len(data)-4-32) {
		return nil, errMalformedArgument
	}
	start := 4 + int(offset.Uint64())
	length := new(big.Int).SetBytes(data[start : start+32])
	if !length.IsUint64() || length.Uint64() > MaxRecordIDBytes {
		return nil, errMalformedArgument
	}
	n := int(length.Uint64())
	padded := (n + 31) / 32 * 32
	if padded > len(data)-start-32 {
		return nil, errMalformedArgument
	}
	for _, padding := range data[start+32+n : start+32+padded] {
		if padding != 0 {
			return nil, errMalformedArgument
		}
	}
	encoded := make([]byte, 64+padded)
	encoded[31] = 32
	copy(encoded[32:64], data[start:start+32])
	copy(encoded[64:], data[start+32:start+32+n])
	return append(input, encoded...), nil
}

func (a compiledArg) checkRecordParty(ctx Context, frame Frame, headLen int) (DenialCode, error) {
	input, err := a.recordInput(frame.Calldata, headLen)
	if err != nil {
		return DenialMalformedCalldata, fmt.Errorf("%w: record ID", err)
	}
	if ctx.ReadRecord == nil {
		return DenialArgumentConstraint, fmt.Errorf("record-party evaluation requires a live-state reader")
	}
	result, err := ctx.ReadRecord(frame.StorageAddress, input, RecordReadGas)
	if err != nil || len(result) != 32*len(a.record.outputs) {
		return DenialArgumentConstraint, fmt.Errorf("record-party getter failed or returned malformed data")
	}
	for i, output := range a.record.outputs {
		bits := recordOutputBits(output)
		if new(big.Int).SetBytes(result[i*32:i*32+32]).BitLen() > bits {
			return DenialArgumentConstraint, fmt.Errorf("record-party getter returned a noncanonical output")
		}
	}
	for _, index := range a.record.parties {
		party := common.BytesToAddress(result[index*32 : index*32+32])
		if party != (common.Address{}) && slices.Contains(ctx.LinkedAddresses, party) {
			return "", nil
		}
	}
	return DenialArgumentConstraint, fmt.Errorf("principal is not a current record party")
}

func recordOutputBits(t abi.Type) int {
	switch t.T {
	case abi.AddressTy:
		return 160
	case abi.BoolTy:
		return 1
	case abi.UintTy:
		return t.Size
	default:
		return 256
	}
}

func (v *Validated) hasRecordReads() bool {
	for _, index := range v.byGroup {
		for _, rules := range index {
			for _, rule := range rules {
				if rule.hasRecordRead() {
					return true
				}
			}
		}
	}
	return false
}
func (r *compiledRule) hasRecordRead() bool {
	for _, a := range r.args {
		if a.kind == argRecordParty {
			return true
		}
	}
	return false
}
