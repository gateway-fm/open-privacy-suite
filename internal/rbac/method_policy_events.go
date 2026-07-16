package rbac

import (
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// Additive write-side audience gates (RD-1206 rules 71/72). Unlike the eth_call
// reader gate (which NARROWS a permissive baseline), event/transaction gating
// runs over a deny-by-default baseline and only ADDS the record's captured
// audience as an extra admit path. Both entry points below are therefore
// admit-or-abstain: true means "the record audience admits this caller"; false
// means "this branch does not admit" (not a deny) — the caller then applies its
// normal baseline. Every decode/lookup failure returns false (fail-safe: a
// governed subject is never *admitted* on error, and never *un*-admitted either).
//
// These are the single shared decision used by BOTH the RPC filter
// (FilterEventLogs) and the explorer redactor, so the two surfaces cannot drift.

// eventSpecForTopic0 finds the EventSpec (and its record type + ABI event) whose
// event signature hashes to topic0, or ok=false when no events rule governs it.
func (d *MethodPolicyDocument) eventSpecForTopic0(parsed abi.ABI, topic0 string) (recordType string, spec EventSpec, evABI abi.Event, ok bool) {
	if d == nil {
		return "", EventSpec{}, abi.Event{}, false
	}
	for rt, rec := range d.Records {
		for _, ev := range rec.Events {
			e, found := eventBySig(parsed, ev.Event)
			if !found {
				continue
			}
			if strings.EqualFold(e.ID.Hex(), topic0) {
				return rt, ev, e, true
			}
		}
	}
	return "", EventSpec{}, abi.Event{}, false
}

// txSpecForMethod finds the TransactionSpec (and record type) governing a method
// signature, or ok=false when none does.
func (d *MethodPolicyDocument) txSpecForMethod(sig string) (recordType string, spec TransactionSpec, ok bool) {
	if d == nil {
		return "", TransactionSpec{}, false
	}
	for rt, rec := range d.Records {
		for _, tx := range rec.Transactions {
			if tx.Method == sig {
				return rt, tx, true
			}
		}
	}
	return "", TransactionSpec{}, false
}

// decodeIndexedTopic decodes a single STATIC indexed event parameter from its
// 32-byte topic word using the ABI machinery (the topic word is the ABI encoding
// of a static value). Dynamic types are unrecoverable from a topic (validation
// rejects them); this returns an error for them too, as defense in depth.
func decodeIndexedTopic(t abi.Type, topicHex string) (any, error) {
	b := common.FromHex(topicHex)
	if len(b) != 32 {
		return nil, errDecode
	}
	vals, err := abi.Arguments{{Type: t}}.Unpack(b)
	if err != nil || len(vals) != 1 {
		return nil, errDecode
	}
	return vals[0], nil
}

// decodeEventKeyValue extracts the decoded Go value of the key parameter (by ABI
// input index) from a log's topics/data, handling the indexed-vs-non-indexed
// split. Returns an error on any shape mismatch (→ caller abstains).
func decodeEventKeyValue(ev abi.Event, index int, topics []string, data []byte) (any, error) {
	if index < 0 || index >= len(ev.Inputs) {
		return nil, errDecode
	}
	in := ev.Inputs[index]
	if in.Indexed {
		// topics[0] is the event signature; indexed params follow in order.
		pos := 0
		for i := 0; i < index; i++ {
			if ev.Inputs[i].Indexed {
				pos++
			}
		}
		topicIdx := 1 + pos
		if topicIdx >= len(topics) {
			return nil, errDecode
		}
		return decodeIndexedTopic(in.Type, topics[topicIdx])
	}
	vals, err := ev.Inputs.NonIndexed().Unpack(data)
	if err != nil {
		return nil, errDecode
	}
	pos := 0
	for i := 0; i < index; i++ {
		if !ev.Inputs[i].Indexed {
			pos++
		}
	}
	if pos >= len(vals) {
		return nil, errDecode
	}
	return vals[pos], nil
}

// audienceAdmits is the shared tail: canonicalize the record key, load that
// record's captures, and test the additive allow rules. Fail-safe: any error,
// an empty/oversized key, a poisoned set-once field, or no match → false.
func audienceAdmits(
	recordType string, keyVal any, allow []AllowRule, caller CallerIdentity,
	load func(recordType, recordKey string) ([]CapturedField, error),
) bool {
	if load == nil {
		return false
	}
	key, err := canonicalizeValue(keyVal)
	if err != nil || key == "" || len(key) > MethodPolicyMaxRecordKeyBytes {
		return false
	}
	caps, err := load(recordType, key)
	if err != nil {
		return false
	}
	if setOncePoisoned(caps) {
		return false // poisoned key → abstain (additive, so this never leaks)
	}
	byField := map[string][]string{}
	for _, c := range caps {
		byField[c.Field] = append(byField[c.Field], c.Value)
	}
	matched, _, _ := matchCaptureSide(allow, caller, byField)
	return matched
}

// EventAudienceAdmits reports whether the caller is in the captured record
// audience for a log's governed event (rule 71). Additive/fail-safe (see file
// doc). `data` is the log's decoded data bytes. `load` loads captures for
// (recordType, recordKey) scoped to the contract's owning org.
func (d *MethodPolicyDocument) EventAudienceAdmits(
	topics []string, data []byte, caller CallerIdentity, parsed abi.ABI,
	load func(recordType, recordKey string) ([]CapturedField, error),
) bool {
	if d == nil || len(topics) == 0 {
		return false
	}
	rt, spec, evABI, ok := d.eventSpecForTopic0(parsed, strings.ToLower(topics[0]))
	if !ok {
		return false // event not governed by any events rule → abstain
	}
	keyVal, err := decodeEventKeyValue(evABI, spec.Key.Index, topics, data)
	if err != nil {
		return false
	}
	return audienceAdmits(rt, keyVal, spec.Allow, caller, load)
}

// TxAudienceAdmits reports whether the caller is in the captured record audience
// for a transaction, keyed by a parameter of its own calldata (rule 72).
// Additive/fail-safe.
func (d *MethodPolicyDocument) TxAudienceAdmits(
	calldata []byte, caller CallerIdentity, parsed abi.ABI,
	load func(recordType, recordKey string) ([]CapturedField, error),
) bool {
	if d == nil || len(calldata) < 4 {
		return false
	}
	m, err := parsed.MethodById(calldata[:4])
	if err != nil {
		return false
	}
	rt, spec, ok := d.txSpecForMethod(m.Sig)
	if !ok {
		return false // method not governed by any transactions rule → abstain
	}
	args, err := m.Inputs.Unpack(calldata[4:])
	if err != nil {
		return false
	}
	keyVal, err := argAt(args, spec.Key.Index)
	if err != nil {
		return false
	}
	return audienceAdmits(rt, keyVal, spec.Allow, caller, load)
}

// argAt returns the decoded arg at index (bounds-checked) — the value form of
// the record key, canonicalized by audienceAdmits so it matches the capture.
func argAt(args []any, index int) (any, error) {
	if index < 0 || index >= len(args) {
		return nil, errDecode
	}
	return args[index], nil
}
