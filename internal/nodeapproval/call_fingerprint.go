package nodeapproval

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"privacy-proxy/internal/tracer"
)

const HashStrict uint8 = 0 // Existing strict V2 fingerprint and V1 approval domain.
const HashCalls uint8 = 3
const callDomain = "OPS_CALLS_V3\x00"

var errCallLifecycle = errors.New("lifecycle requires strict fingerprint")

func configuredHashMode() (uint8, error) {
	switch os.Getenv("OPS_APPROVAL_HASH_MODE") {
	case "", "calls":
		return HashCalls, nil
	case "strict":
		return HashStrict, nil
	default:
		return 0, errors.New("OPS_APPROVAL_HASH_MODE must be calls or strict")
	}
}
func validHashMode(mode uint8) bool { return mode == HashStrict || mode == HashCalls }

// CallFingerprint binds call structure, inputs, value and executed code. It
// deliberately does not bind storage, balances, account nonces, outputs or logs.
func CallFingerprint(calls, pre object) (common.Hash, *tracer.TraceResult, error) {
	trace := &tracer.TraceResult{}
	count := 0
	normalized, err := normalizeCall(calls, "", &count, trace, 0)
	if err != nil {
		return common.Hash{}, nil, err
	}
	for _, target := range trace.CallTargets {
		if target.Type == "CREATE" || target.Type == "CREATE2" || target.Type == "SELFDESTRUCT" {
			return common.Hash{}, nil, errCallLifecycle
		}
	}
	codes := map[string]common.Hash{}
	for address, account := range pre {
		code, e := hexutil.Decode(field(obj(account), "code", "0x"))
		if e != nil {
			return common.Hash{}, nil, e
		}
		codes[strings.ToLower(address)] = crypto.Keccak256Hash(code)
	}
	buf := append([]byte{}, callDomain...)
	buf = binary.BigEndian.AppendUint32(buf, uint32(count))
	index := uint32(0)
	var encode func(object, uint32) error
	encode = func(call object, parent uint32) error {
		kind := map[string]byte{"CALL": 1, "STATICCALL": 2, "DELEGATECALL": 3, "CALLCODE": 4}[str(call["type"])]
		if kind == 0 {
			return errors.New("unsupported call operation")
		}
		code, ok := codes[str(call["to"])]
		if !ok {
			return fmt.Errorf("missing executed code at %s", call["to"])
		}
		input, e := hexutil.Decode(str(call["input"]))
		if e != nil {
			return e
		}
		if len(buf)+134+len(input) > 1<<20 {
			return errors.New("call fingerprint exceeds 1 MiB")
		}
		this := index
		index++
		buf = binary.BigEndian.AppendUint32(buf, parent)
		buf = append(buf, kind)
		for _, field := range []string{"from", "to", "storageAddress"} {
			buf = append(buf, common.HexToAddress(str(call[field])).Bytes()...)
		}
		buf = append(buf, code[:]...)
		value, e := hexutil.Decode(str(call["value"]))
		if e != nil {
			return e
		}
		buf = append(buf, value...)
		if call["failed"] == true {
			buf = append(buf, 1)
		} else {
			buf = append(buf, 0)
		}
		buf = binary.BigEndian.AppendUint32(buf, uint32(len(input)))
		buf = append(buf, input...)
		for _, child := range call["calls"].([]any) {
			if e := encode(obj(child), this); e != nil {
				return e
			}
		}
		return nil
	}
	if err = encode(normalized, ^uint32(0)); err != nil {
		return common.Hash{}, nil, err
	}
	return crypto.Keccak256Hash(buf), trace, nil
}

func fingerprintForMode(mode uint8, calls, pre, diff object) (common.Hash, *tracer.TraceResult, uint8, error) {
	if !validHashMode(mode) {
		return common.Hash{}, nil, mode, errors.New("unknown approval hash mode")
	}
	if mode == HashCalls {
		hash, trace, err := CallFingerprint(calls, pre)
		if !errors.Is(err, errCallLifecycle) {
			return hash, trace, HashCalls, err
		}
	}
	hash, trace, err := Fingerprint(calls, pre, diff)
	return hash, trace, HashStrict, err
}
