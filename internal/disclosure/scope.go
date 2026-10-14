package disclosure

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Scope methods: what kind of the subject's data a grant covers.
const (
	// MethodActivityLogs covers the subject's activity: their RPC request log.
	MethodActivityLogs = "activity_logs"
	// MethodTransactionHistory covers the subject's transactions.
	MethodTransactionHistory = "transaction_history"
	// MethodFullDisclosure covers both.
	MethodFullDisclosure = "full_disclosure"
)

// ErrInvalidScope reports a scope that cannot be stored: an unknown level or
// method, a malformed address, or a date range that is incomplete or inverted.
var ErrInvalidScope = errors.New("invalid disclosure scope")

// Normalize validates a requested or granted scope and returns it in canonical
// form: the level lower-cased (empty → redacted), methods and addresses
// de-duplicated, addresses lower-cased. Methods must be scope methods
// (activity_logs, transaction_history, full_disclosure); addresses 0x-prefixed
// 20-byte hex; a date range needs both bounds and must not end before it starts.
func (s Scope) Normalize() (Scope, error) {
	out := Scope{}

	switch lvl := DisclosureLevel(strings.ToLower(strings.TrimSpace(string(s.DisclosureLevel)))); lvl {
	case "":
		out.DisclosureLevel = DisclosureRedacted
	case DisclosureFull, DisclosurePseudonymous, DisclosureRedacted:
		out.DisclosureLevel = lvl
	default:
		return Scope{}, fmt.Errorf("%w: unknown disclosure_level", ErrInvalidScope)
	}

	seen := make(map[string]bool, len(s.Methods))
	for _, m := range s.Methods {
		switch m {
		case MethodActivityLogs, MethodTransactionHistory, MethodFullDisclosure:
		default:
			return Scope{}, fmt.Errorf("%w: unknown method", ErrInvalidScope)
		}
		if !seen[m] {
			seen[m] = true
			out.Methods = append(out.Methods, m)
		}
	}

	seen = make(map[string]bool, len(s.Addresses))
	for _, a := range s.Addresses {
		a = strings.ToLower(strings.TrimSpace(a))
		if !isHexAddress(a) {
			return Scope{}, fmt.Errorf("%w: malformed address", ErrInvalidScope)
		}
		if !seen[a] {
			seen[a] = true
			out.Addresses = append(out.Addresses, a)
		}
	}

	if dr := s.DateRange; dr != nil {
		if dr.Start.IsZero() || dr.End.IsZero() {
			return Scope{}, fmt.Errorf("%w: date_range needs both start and end", ErrInvalidScope)
		}
		if dr.End.Before(dr.Start) {
			return Scope{}, fmt.Errorf("%w: date_range ends before it starts", ErrInvalidScope)
		}
		out.DateRange = &DateRange{Start: dr.Start, End: dr.End}
	}
	return out, nil
}

func isHexAddress(a string) bool {
	if len(a) != 42 || !strings.HasPrefix(a, "0x") {
		return false
	}
	for _, c := range a[2:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// EffectiveLevel is the level a read renders at: full or pseudonymous when the
// scope says so, redacted for anything else — an empty or unknown level never
// reveals more than redacted.
func (s Scope) EffectiveLevel() DisclosureLevel {
	switch lvl := DisclosureLevel(strings.ToLower(strings.TrimSpace(string(s.DisclosureLevel)))); lvl {
	case DisclosureFull, DisclosurePseudonymous:
		return lvl
	default:
		return DisclosureRedacted
	}
}

// ForRead validates stored scopes without allowing legacy empty or unknown
// disclosure levels to reveal data. Malformed filters fail closed.
func (s Scope) ForRead() (Scope, error) {
	s.DisclosureLevel = s.EffectiveLevel()
	return s.Normalize()
}

// ValidateActivity rejects filters the activity store cannot safely enforce.
// Access logs have no authoritative transaction/counterparty address column;
// matching arbitrary request_params text would not establish address scope.
func (s Scope) ValidateActivity() error {
	if !s.AllowsActivityLogs() || len(s.Addresses) != 0 {
		return ErrScopeOutOfBounds
	}
	return nil
}

// InDateRange reports whether a block time (Unix seconds) lies inside the
// scope's date range, bounds included. Without a date range every time is in
// scope. With one, an unknown time (≤ 0) is out of scope: fail closed.
func (s Scope) InDateRange(blockTime int64) bool {
	if s.DateRange == nil {
		return true
	}
	if blockTime <= 0 {
		return false
	}
	ts := time.Unix(blockTime, 0)
	return !ts.Before(s.DateRange.Start) && !ts.After(s.DateRange.End)
}

// InAddressScope reports whether one of addrs is in the scope's address list
// (case-insensitively). Without an address list every address is in scope.
func (s Scope) InAddressScope(addrs ...string) bool {
	if len(s.Addresses) == 0 {
		return true
	}
	for _, a := range addrs {
		if a == "" {
			continue
		}
		for _, sa := range s.Addresses {
			if strings.EqualFold(a, sa) {
				return true
			}
		}
	}
	return false
}

// AllowsTransactionHistory reports whether the scope's methods cover the
// subject's transactions: no method restriction, transaction_history or
// full_disclosure.
func (s Scope) AllowsTransactionHistory() bool {
	if len(s.Methods) == 0 {
		return true
	}
	return s.hasMethod(MethodTransactionHistory) || s.hasMethod(MethodFullDisclosure)
}

// AllowsActivityLogs reports whether the scope's methods cover the subject's
// activity log: activity_logs or full_disclosure (an empty method list does
// not).
func (s Scope) AllowsActivityLogs() bool {
	return s.hasMethod(MethodActivityLogs) || s.hasMethod(MethodFullDisclosure)
}

// CoversTransaction reports whether the scope covers a transaction of the
// subject with these parties at this block time: the methods allow
// transactions, the time is in range, and a party is in the address list.
func (s Scope) CoversTransaction(from, to string, blockTime int64) bool {
	return s.AllowsTransactionHistory() && s.InDateRange(blockTime) && s.InAddressScope(from, to)
}

func (s Scope) hasMethod(m string) bool {
	for _, x := range s.Methods {
		if x == m {
			return true
		}
	}
	return false
}
