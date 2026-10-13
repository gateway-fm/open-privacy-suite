package rbac

import "testing"

// TestDecideLogEmitter_FullDisclosureGrant pins the disclosure-grant branch of
// the shared event decision, identical in both read profiles: a log whose
// ABI-indexed address parameter names an address the viewer's Full disclosure
// grant covers is admitted — masked, with the grant lens attributed — when the
// embedded-address gates pass and the viewer's own grant and event rules on
// the emitter reach the event with the grant subjects counting as the viewer.
// The payload is never full: only the RD-874 unlock returns a log verbatim.
func TestDecideLogEmitter_FullDisclosureGrant(t *testing.T) {
	base := LogEmitterFacts{
		FullDisclosureGrant: true,
		HasGrant:            true,
		ABIResolvable:       true,
		Rules:               LogEventRulesAllowlist,
		HasTopic0:           true,
		Topic0Allowlisted:   true,
		GrantEventAllowed:   true,
	}
	with := func(mut func(*LogEmitterFacts)) LogEmitterFacts {
		f := base
		mut(&f)
		return f
	}
	grantLens := LogDecision{Admit: true, Payload: LogPayloadMasked, DisclosureGrant: true}
	masked := LogDecision{Admit: true, Payload: LogPayloadMasked}

	cases := []struct {
		name     string
		facts    LogEmitterFacts
		standard LogDecision
		strict   LogDecision
	}{
		{"grant + rules admitting the subject's event", base, grantLens, grantLens},
		{"grant + wildcard rules", with(func(f *LogEmitterFacts) {
			f.Rules = LogEventRulesWildcard
			f.Topic0Allowlisted, f.GrantEventAllowed = false, false
		}), grantLens, grantLens},
		// Admin authority stands in for the event rules, as it does elsewhere.
		{"grant + admin with deny-all rules", with(func(f *LogEmitterFacts) {
			f.Rules = LogEventRulesDeny
			f.Topic0Allowlisted, f.GrantEventAllowed = false, false
			f.IsAdmin = true
		}), grantLens, grantLens},
		// must_be:self naming the viewer fails, but holds for the subject.
		{"self param rule satisfied by the subject only", with(func(f *LogEmitterFacts) { f.EventAllowed = false }), grantLens, grantLens},

		// Bounds: none of these lets the grant through.
		{"param rules fail even for the subject (e.g. a literal value)", with(func(f *LogEmitterFacts) { f.GrantEventAllowed = false }), LogDecision{}, LogDecision{}},
		{"no contract grant on the emitter", with(func(f *LogEmitterFacts) { f.HasGrant = false }), LogDecision{}, LogDecision{}},
		{"deny-all event rules", with(func(f *LogEmitterFacts) {
			f.Rules = LogEventRulesDeny
			f.Topic0Allowlisted, f.GrantEventAllowed = false, false
		}), LogDecision{}, LogDecision{}},
		{"topic0 not allowlisted", with(func(f *LogEmitterFacts) { f.Topic0Allowlisted, f.GrantEventAllowed = false, false }), LogDecision{}, LogDecision{}},
		{"anonymous event", with(func(f *LogEmitterFacts) { f.HasTopic0 = false }), LogDecision{}, LogDecision{}},
		{"no resolvable ABI", with(func(f *LogEmitterFacts) { f.ABIResolvable = false }), LogDecision{}, LogDecision{}},
		{"dynamic payload", with(func(f *LogEmitterFacts) { f.DynamicPayloadDropped = true }), LogDecision{}, LogDecision{}},
		{"no grant fact", with(func(f *LogEmitterFacts) { f.FullDisclosureGrant = false }), LogDecision{}, LogDecision{}},
		// The visibleTo fallback does not stand in for the grant's own rule.
		{"failed grant rule with visibleTo", with(func(f *LogEmitterFacts) { f.GrantEventAllowed = false; f.InVisibleTo = true }), masked, LogDecision{}},

		// Without the grant branch the ordinary verdict applies, unattributed.
		{"no ABI but admin: ordinary admin verdict", with(func(f *LogEmitterFacts) { f.ABIResolvable = false; f.IsAdmin = true }),
			masked, LogDecision{}},
		{"no grant fact, viewer's own entitlement", with(func(f *LogEmitterFacts) { f.FullDisclosureGrant = false; f.EventAllowed = true; f.IndexedSelf = true }),
			masked, masked},

		// A log the viewer could already read gets the grant lens.
		{"grant over a log the viewer's rules admit", with(func(f *LogEmitterFacts) { f.EventAllowed = true; f.IndexedSelf = true }), grantLens, grantLens},

		// Standard: the visibleTo unlock (full payload) is the viewer's own
		// path and wins; strict has no unlock, so the grant decides.
		{"unlock wins over the grant (standard)", with(func(f *LogEmitterFacts) { f.Unlocked = true; f.InVisibleTo = true }),
			LogDecision{Admit: true, Payload: LogPayloadFull}, grantLens},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DecideLogEmitter(ReadProfileStandard, tc.facts); got != tc.standard {
				t.Errorf("standard = %+v, want %+v (facts %+v)", got, tc.standard, tc.facts)
			}
			for _, p := range []ReadProfile{ReadProfileStrict, ReadProfileUnset} {
				if got := DecideLogEmitter(p, tc.facts); got != tc.strict {
					t.Errorf("%v = %+v, want %+v (facts %+v)", p, got, tc.strict, tc.facts)
				}
			}
		})
	}
}

// IndexedAddresses returns the parties an event names in its ABI-indexed
// address parameters — what the grant lens reveals — and nothing when the log
// does not fit exactly one declared layout.
func TestIndexedAddresses(t *testing.T) {
	m := NewIndexedSelfMatcher()
	topics := []string{isTransferT0, isTopic(isViewer), isTopic(isOther)}
	got := m.IndexedAddresses(indexedSelfABI, topics, "0x"+isWord(1))
	if len(got) != 2 || got[0] != isViewer || got[1] != isOther {
		t.Fatalf("Transfer names from and to: %v", got)
	}
	if got := m.IndexedAddresses(indexedSelfABI, topics, "0x"); got != nil {
		t.Fatalf("a payload that does not decode fits no layout: %v", got)
	}
	if got := m.IndexedAddresses("", topics, "0x"+isWord(1)); got != nil {
		t.Fatalf("no ABI, no parties: %v", got)
	}
}
