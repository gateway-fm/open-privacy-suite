package rbac

import (
	"encoding/hex"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

// IndexedSelfMatcher decides the strict read profile's event predicate
// (RD-1299): a log "names the viewer" only when the emitting contract's
// registered ABI identifies, for the log's topic0, a standard (non-anonymous)
// event whose indexed `address` parameter holds one of the viewer's linked
// addresses. It memoises parsed ABIs for one filter pass; the zero value and a
// nil matcher are safe (a nil matcher never matches).
//
// Fail closed: an unknown or unparseable ABI, a topic0 the ABI does not
// declare, an anonymous event, a topic count that does not match the event's
// indexed parameters, a malformed or non-canonically padded topic, and a data
// payload that does not decode against the event's non-indexed parameters all
// return false. Only `address`-typed indexed parameters count: dynamic indexed
// types (address[], bytes, string) are stored as hashes and never match.
//
// An ABI may declare several events with one topic0 (the ERC-20 and ERC-721
// Transfer share a signature but differ in which parameters are indexed). Every
// such candidate is evaluated, and the log names the viewer when any candidate
// whose layout the log fits does — a deterministic answer, independent of the
// order the ABI parser happens to keep them in.
type IndexedSelfMatcher struct {
	parsed map[string]map[string][]abi.Event // ABI JSON -> lower-case topic0 -> events (nil = unparseable)
}

// NewIndexedSelfMatcher returns a matcher with an empty ABI memo.
func NewIndexedSelfMatcher() *IndexedSelfMatcher {
	return &IndexedSelfMatcher{parsed: make(map[string]map[string][]abi.Event)}
}

// Match reports whether the log (topics, data) emitted by a contract with ABI
// contractABI names one of the linked addresses (lowercase, 0x-prefixed) in an
// indexed `address` parameter.
func (m *IndexedSelfMatcher) Match(contractABI string, topics []string, data string, linked map[string]bool) bool {
	if m == nil || contractABI == "" || len(topics) == 0 || len(linked) == 0 {
		return false
	}
	byTopic0 := m.parse(contractABI)
	if byTopic0 == nil {
		return false
	}
	for _, event := range byTopic0[strings.ToLower(topics[0])] {
		if eventNamesLinked(event, topics, data, linked) {
			return true
		}
	}
	return false
}

// eventNamesLinked evaluates one candidate event declaration for the log.
func eventNamesLinked(event abi.Event, topics []string, data string, linked map[string]bool) bool {
	if event.Anonymous {
		return false
	}
	var indexed, nonIndexed abi.Arguments
	for _, in := range event.Inputs {
		if in.Indexed {
			indexed = append(indexed, in)
		} else {
			nonIndexed = append(nonIndexed, in)
		}
	}
	if len(topics) != 1+len(indexed) {
		return false // malformed: topics do not match the declared event
	}
	if !dataDecodes(nonIndexed, data) {
		return false // malformed payload
	}

	named := false
	for i, in := range indexed {
		topic := strings.ToLower(topics[1+i])
		if len(topic) != 66 || !strings.HasPrefix(topic, "0x") {
			return false
		}
		if _, err := hex.DecodeString(topic[2:]); err != nil {
			return false
		}
		if in.Type.T != abi.AddressTy {
			continue
		}
		if strings.Trim(topic[2:26], "0") != "" {
			return false // not a canonically padded address: malformed
		}
		if linked["0x"+topic[26:]] {
			named = true
		}
	}
	return named
}

// parse returns the ABI's events grouped by lower-case topic0, memoised per
// ABI JSON; nil when the ABI does not parse.
func (m *IndexedSelfMatcher) parse(contractABI string) map[string][]abi.Event {
	if m.parsed == nil {
		m.parsed = make(map[string]map[string][]abi.Event)
	}
	if p, ok := m.parsed[contractABI]; ok {
		return p
	}
	var out map[string][]abi.Event
	if p, err := abi.JSON(strings.NewReader(contractABI)); err == nil {
		out = make(map[string][]abi.Event, len(p.Events))
		for _, ev := range p.Events {
			id := "0x" + hex.EncodeToString(ev.ID.Bytes())
			out[id] = append(out[id], ev)
		}
	}
	m.parsed[contractABI] = out
	return out
}

// dataDecodes reports whether data is valid hex that unpacks against the
// event's non-indexed parameters. An event without non-indexed parameters must
// carry an empty payload.
func dataDecodes(nonIndexed abi.Arguments, data string) bool {
	raw := strings.TrimPrefix(strings.TrimPrefix(data, "0x"), "0X")
	b, err := hex.DecodeString(raw)
	if err != nil {
		return false
	}
	if len(nonIndexed) == 0 {
		return len(b) == 0
	}
	_, err = nonIndexed.Unpack(b)
	return err == nil
}
