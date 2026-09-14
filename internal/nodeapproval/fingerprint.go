// Package nodeapproval implements the opt-in signed-preflight PoC.
package nodeapproval

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"
	"privacy-proxy/internal/tracer"
	"sort"
	"strconv"
	"strings"
)

type object = map[string]any

func obj(v any) object {
	m, _ := v.(map[string]any)
	if m == nil {
		return object{}
	}
	return m
}
func str(v any) string { s, _ := v.(string); return s }
func word(v any) (string, error) {
	s := strings.TrimPrefix(str(v), "0x")
	if len(s) > 64 {
		return "", fmt.Errorf("oversize word")
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return "", fmt.Errorf("invalid word")
		}
	}
	return "0x" + strings.Repeat("0", 64-len(s)) + strings.ToLower(s), nil
}
func field(v object, k, def string) string {
	if s, ok := v[k].(string); ok {
		return strings.ToLower(s)
	}
	return def
}

func normalizeCall(v object, parent string, count *int, trace *tracer.TraceResult, depth int) (object, error) {
	*count++
	if *count > 128 {
		return nil, fmt.Errorf("more than 128 calls")
	}
	kind := str(v["type"])
	if kind != "CALL" && kind != "STATICCALL" && kind != "DELEGATECALL" && kind != "CALLCODE" && kind != "CREATE" && kind != "CREATE2" && kind != "SELFDESTRUCT" {
		return nil, fmt.Errorf("unsupported call %q", kind)
	}
	value, err := word(v["value"])
	if err != nil {
		return nil, err
	}
	trace.HasCreate = trace.HasCreate || kind == "CREATE"
	trace.HasCreate2 = trace.HasCreate2 || kind == "CREATE2"
	to, from := field(v, "to", ""), field(v, "from", "")
	// Pinned revm-inspectors derives SELFDESTRUCT metadata from journal entries.
	// Cancun self-to-self on an existing account has no entry: its marker has
	// zero caller, no destination/value and succeeds. It denotes a no-op on parent.
	zero, _ := word(nil)
	if kind == "SELFDESTRUCT" && to == "" && from == (common.Address{}).Hex() && value == zero && v["error"] == nil && parent != "" {
		from, to = parent, parent
	}

	failedCreate := (kind == "CREATE" || kind == "CREATE2") && v["error"] != nil && to == ""
	if (!common.IsHexAddress(to) && !failedCreate) || !common.IsHexAddress(from) {
		return nil, fmt.Errorf("invalid call address")
	}
	storage := to
	if kind == "SELFDESTRUCT" {
		storage = from
	}
	if kind == "DELEGATECALL" || kind == "CALLCODE" {
		storage = parent
		if storage == "" {
			return nil, fmt.Errorf("root delegate")
		}
	}
	trace.CallTargets = append(trace.CallTargets, tracer.CallTarget{Type: kind, From: from, To: to, Depth: depth})
	children := []any{}
	if list, ok := v["calls"].([]any); ok {
		for _, c := range list {
			n, e := normalizeCall(obj(c), storage, count, trace, depth+1)
			if e != nil {
				return nil, e
			}
			children = append(children, n)
		}
	}
	logs := v["logs"]
	if logs == nil {
		logs = []any{}
	}
	return object{"type": kind, "from": from, "to": to, "storageAddress": storage, "input": field(v, "input", "0x"), "output": field(v, "output", "0x"), "failed": v["error"] != nil, "value": value, "calls": children, "logs": logs}, nil
}

// Fingerprint uses the same canonical JSON/domain as the producer module.
func Fingerprint(calls, pre, diff object) (common.Hash, *tracer.TraceResult, error) {
	trace := &tracer.TraceResult{}
	count := 0
	c, err := normalizeCall(calls, "", &count, trace, 0)
	if err != nil {
		return common.Hash{}, nil, err
	}
	accounts := []any{}
	created := map[string]bool{}
	for _, t := range trace.CallTargets {
		if t.Type == "CREATE" || t.Type == "CREATE2" {
			created[t.To] = true
		}
	}
	addresses := map[string]bool{}
	for a := range pre {
		addresses[a] = true
	}
	for a := range obj(diff["pre"]) {
		addresses[a] = true
	}
	for a := range obj(diff["post"]) {
		addresses[a] = true
	}
	ordered := make([]string, 0, len(addresses))
	for a := range addresses {
		ordered = append(ordered, a)
	}
	sort.Strings(ordered)
	for _, a := range ordered {
		if !common.IsHexAddress(a) {
			return common.Hash{}, nil, fmt.Errorf("invalid account address")
		}
		before := obj(pre[a])
		changedPre, hasPre := obj(diff["pre"])[a]
		changedPost, hasPost := obj(diff["post"])[a]
		deleted := hasPre && !hasPost
		post := obj(changedPost)
		codeBefore := field(before, "code", "0x")
		codeAfter := field(post, "code", codeBefore)
		if deleted {
			codeAfter = "0x"
		}
		balanceBefore, e := number(before["balance"])
		if e != nil {
			return common.Hash{}, nil, e
		}
		balanceAfter := new(big.Int).Set(balanceBefore)
		if v, ok := post["balance"]; ok {
			balanceAfter, e = number(v)
		}
		if deleted {
			balanceAfter = new(big.Int)
		}
		if e != nil {
			return common.Hash{}, nil, e
		}
		delta := new(big.Int).Sub(balanceAfter, balanceBefore).String()
		slotsBefore := obj(before["storage"])
		slotsPre, slotsPost := obj(obj(changedPre)["storage"]), obj(post["storage"])
		slots := map[string]bool{}
		for k := range slotsBefore {
			slots[k] = true
		}
		for k := range slotsPre {
			slots[k] = true
		}
		for k := range slotsPost {
			slots[k] = true
		}
		contract := codeBefore != "0x" || codeAfter != "0x" || len(slots) != 0 || created[strings.ToLower(a)]
		if !contract && delta == "0" {
			continue
		}
		nb, na := "0", "0"
		if contract {
			n, e := number(before["nonce"])
			if e != nil {
				return common.Hash{}, nil, e
			}
			nb = n.String()
			na = nb
			if v, ok := post["nonce"]; ok {
				n, e = number(v)
				if e != nil {
					return common.Hash{}, nil, e
				}
				na = n.String()
			}
			if deleted {
				na = "0"
			}
		}
		storage := []any{}
		for k := range slots {
			slot, e := word(k)
			if e != nil {
				return common.Hash{}, nil, e
			}
			bv, e := word(slotsBefore[k])
			if e != nil {
				return common.Hash{}, nil, e
			}
			av := bv
			_, p := slotsPre[k]
			_, q := slotsPost[k]
			if deleted || p || q {
				av, e = word(slotsPost[k])
				if e != nil {
					return common.Hash{}, nil, e
				}
			}
			storage = append(storage, object{"slot": slot, "before": bv, "after": av})
		}
		sort.Slice(storage, func(i, j int) bool { return str(obj(storage[i])["slot"]) < str(obj(storage[j])["slot"]) })
		accounts = append(accounts, object{"address": strings.ToLower(a), "codeBefore": crypto.Keccak256Hash(common.FromHex(codeBefore)).Hex(), "codeAfter": crypto.Keccak256Hash(common.FromHex(codeAfter)).Hex(), "nonceBefore": nb, "nonceAfter": na, "balanceDelta": delta, "storage": storage})
	}
	var buffer bytes.Buffer
	enc := json.NewEncoder(&buffer)
	enc.SetEscapeHTML(false)
	if err = enc.Encode(object{"calls": c, "accounts": accounts}); err != nil {
		return common.Hash{}, nil, err
	}
	data := bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'})
	if len(data) > 1048576 {
		return common.Hash{}, nil, fmt.Errorf("fingerprint exceeds 1 MiB")
	}
	return crypto.Keccak256Hash([]byte("OPS_EXECUTION_V2\x00"), data), trace, nil
}

// RPC nonce fields can be JSON numbers; decoding with UseNumber preserves uint64.
func number(v any) (*big.Int, error) {
	if v == nil {
		return new(big.Int), nil
	}
	var s string
	switch n := v.(type) {
	case string:
		s = n
	case json.Number:
		s = string(n)
	case float64:
		if n < 0 || n > 1<<53 || n != float64(uint64(n)) {
			return nil, fmt.Errorf("inexact integer")
		}
		s = strconv.FormatUint(uint64(n), 10)
	default:
		return nil, fmt.Errorf("invalid integer %T", v)
	}
	base := 10
	if strings.HasPrefix(s, "0x") {
		s = s[2:]
		base = 16
	}
	n, ok := new(big.Int).SetString(s, base)
	if !ok || n.Sign() < 0 || n.BitLen() > 256 {
		return nil, fmt.Errorf("invalid uint256")
	}
	return n, nil
}
