package disclosure

import (
	"errors"
	"testing"
	"time"
)

// The scope semantics the grant API applies: a grant discloses only what its
// scope covers.
func TestScopeSemantics(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 1, 31, 23, 59, 59, 0, time.UTC)
	dated := Scope{DateRange: &DateRange{Start: start, End: end}}

	t.Run("date range is inclusive, unknown time is out", func(t *testing.T) {
		for _, c := range []struct {
			ts   int64
			want bool
		}{
			{start.Unix() - 1, false},
			{start.Unix(), true},
			{start.Unix() + 3600, true},
			{end.Unix(), true},
			{end.Unix() + 1, false},
			{0, false},
			{-5, false},
		} {
			if got := dated.InDateRange(c.ts); got != c.want {
				t.Errorf("InDateRange(%d) = %v, want %v", c.ts, got, c.want)
			}
		}
		if !(Scope{}).InDateRange(0) || !(Scope{}).InDateRange(123) {
			t.Error("no date range restricts nothing, not even an unknown time")
		}
	})

	t.Run("address scope matches either party, case-insensitively", func(t *testing.T) {
		s := Scope{Addresses: []string{"0xAbC0000000000000000000000000000000000001"}}
		if !s.InAddressScope("0x1111111111111111111111111111111111111111", "0xabc0000000000000000000000000000000000001") {
			t.Error("a party in the address list is in scope")
		}
		if s.InAddressScope("0x1111111111111111111111111111111111111111", "") {
			t.Error("no party in the list → out of scope")
		}
		if !(Scope{}).InAddressScope("0x1111111111111111111111111111111111111111") {
			t.Error("no address list restricts nothing")
		}
	})

	t.Run("methods per surface", func(t *testing.T) {
		for _, c := range []struct {
			methods       []string
			txs, activity bool
		}{
			{nil, true, false},
			{[]string{}, true, false},
			{[]string{"transaction_history"}, true, false},
			{[]string{"activity_logs"}, false, true},
			{[]string{"full_disclosure"}, true, true},
			{[]string{"activity_logs", "transaction_history"}, true, true},
			{[]string{"eth_call"}, false, false},
		} {
			s := Scope{Methods: c.methods}
			if got := s.AllowsTransactionHistory(); got != c.txs {
				t.Errorf("%v AllowsTransactionHistory = %v, want %v", c.methods, got, c.txs)
			}
			if got := s.AllowsActivityLogs(); got != c.activity {
				t.Errorf("%v AllowsActivityLogs = %v, want %v", c.methods, got, c.activity)
			}
		}
	})

	t.Run("covers a transaction", func(t *testing.T) {
		const subject, token, other = "0x5b1ec70000000000000000000000000000000001", "0x70c3000000000000000000000000000000000002", "0x07e4000000000000000000000000000000000003"
		s := Scope{Methods: []string{"full_disclosure"}, Addresses: []string{token}, DateRange: &DateRange{Start: start, End: end}}
		in := start.Unix() + 60
		if !s.CoversTransaction(subject, token, in) {
			t.Error("in range, counterparty in the address list")
		}
		if s.CoversTransaction(subject, other, in) || s.CoversTransaction(subject, token, end.Unix()+1) || s.CoversTransaction(subject, token, 0) {
			t.Error("outside the address list or the range, or an unknown time")
		}
		if (Scope{Methods: []string{"activity_logs"}}).CoversTransaction(subject, other, in) {
			t.Error("activity logs do not cover transactions")
		}
	})
}

// A requested or granted scope is validated and normalised before it is stored:
// the grant API treats it as the subject's consent, so nothing ambiguous may
// reach a read.
func TestScopeNormalize(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 1, 31, 0, 0, 0, 0, time.UTC)

	t.Run("an empty level is redacted; addresses lower-cased; duplicates dropped", func(t *testing.T) {
		got, err := Scope{
			Methods:   []string{"transaction_history", "transaction_history", "activity_logs"},
			Addresses: []string{"0xABCDEF0000000000000000000000000000000001", "0xabcdef0000000000000000000000000000000001"},
		}.Normalize()
		if err != nil {
			t.Fatal(err)
		}
		if got.DisclosureLevel != DisclosureRedacted {
			t.Errorf("level = %q, want redacted", got.DisclosureLevel)
		}
		if len(got.Methods) != 2 || len(got.Addresses) != 1 || got.Addresses[0] != "0xabcdef0000000000000000000000000000000001" {
			t.Errorf("normalised = %+v", got)
		}
		if got, _ := (Scope{DisclosureLevel: " Full "}).Normalize(); got.DisclosureLevel != DisclosureFull {
			t.Errorf("level = %q, want full", got.DisclosureLevel)
		}
	})

	invalid := []struct {
		name  string
		scope Scope
	}{
		{"unknown level", Scope{DisclosureLevel: "everything"}},
		{"unknown method", Scope{Methods: []string{"eth_call"}}},
		{"empty method", Scope{Methods: []string{""}}},
		{"malformed address", Scope{Addresses: []string{"0x1234"}}},
		{"non-hex address", Scope{Addresses: []string{"0xzz00000000000000000000000000000000000001"}}},
		{"date range without a start", Scope{DateRange: &DateRange{End: end}}},
		{"date range without an end", Scope{DateRange: &DateRange{Start: start}}},
		{"date range ending before it starts", Scope{DateRange: &DateRange{Start: end, End: start}}},
	}
	for _, c := range invalid {
		t.Run(c.name, func(t *testing.T) {
			if _, err := c.scope.Normalize(); !errors.Is(err, ErrInvalidScope) {
				t.Fatalf("err = %v, want ErrInvalidScope", err)
			}
		})
	}

	t.Run("a one-instant range is valid", func(t *testing.T) {
		if _, err := (Scope{DateRange: &DateRange{Start: start, End: start}}).Normalize(); err != nil {
			t.Fatal(err)
		}
	})
}

// An empty or unknown disclosure level renders as redacted, never full.
func TestEffectiveLevel(t *testing.T) {
	for in, want := range map[DisclosureLevel]DisclosureLevel{
		"":             DisclosureRedacted,
		"bogus":        DisclosureRedacted,
		"redacted":     DisclosureRedacted,
		"pseudonymous": DisclosurePseudonymous,
		" FULL ":       DisclosureFull,
	} {
		if got := (Scope{DisclosureLevel: in}).EffectiveLevel(); got != want {
			t.Errorf("EffectiveLevel(%q) = %q, want %q", in, got, want)
		}
	}
}
