package rbac

import "testing"

// TestDecideLogEmitter_StrictProfile pins the strict event predicate (RD-1299):
// a log is admitted only when it names one of the viewer's linked addresses in
// an ABI-indexed `address` parameter (IndexedSelf) AND the viewer holds a grant
// on the emitter AND the ABI / dynamic-payload gates pass AND the event rules
// admit it (or the viewer is an admin, who may relax the rules but never
// IndexedSelf). The admin claim, the visibleTo unlock, participation and the
// ordinary visibleTo fallback never admit a log that fails IndexedSelf, and an
// admitted log is always masked. Each row varies one fact against a
// baseline with every standard entitlement present.
func TestDecideLogEmitter_StrictProfile(t *testing.T) {
	base := LogEmitterFacts{
		IndexedSelf:   true,
		HasGrant:      true,
		ABIResolvable: true,
		Rules:         LogEventRulesWildcard,
		HasTopic0:     true,
	}
	with := func(mut func(*LogEmitterFacts)) LogEmitterFacts {
		f := base
		mut(&f)
		return f
	}
	// All standard-profile entitlements are present together.
	standardEntitlements := func(f *LogEmitterFacts) {
		f.IsAdmin = true
		f.Unlocked = true
		f.IsParticipant = true
		f.InVisibleTo = true
		f.Topic0Allowlisted = true
	}

	cases := []struct {
		name  string
		facts LogEmitterFacts
		admit bool
	}{
		{"indexed-self + grant + wildcard admits", base, true},
		{"allowlist: event allowed admits", with(func(f *LogEmitterFacts) {
			f.Rules = LogEventRulesAllowlist
			f.EventAllowed = true
			f.Topic0Allowlisted = true
		}), true},

		// IndexedSelf is mandatory: nothing substitutes for it.
		{"not indexed-self drops", with(func(f *LogEmitterFacts) { f.IndexedSelf = false }), false},
		{"not indexed-self drops despite admin", with(func(f *LogEmitterFacts) { f.IndexedSelf = false; f.IsAdmin = true }), false},
		{"not indexed-self drops despite unlock", with(func(f *LogEmitterFacts) { f.IndexedSelf = false; f.Unlocked = true }), false},
		{"not indexed-self drops despite participation", with(func(f *LogEmitterFacts) { f.IndexedSelf = false; f.IsParticipant = true }), false},
		{"not indexed-self drops despite visibleTo", with(func(f *LogEmitterFacts) { f.IndexedSelf = false; f.InVisibleTo = true }), false},
		{"not indexed-self drops despite all standard entitlements", with(func(f *LogEmitterFacts) { f.IndexedSelf = false; standardEntitlements(f) }), false},

		// Grant and embedded-address gates still apply, whatever else holds.
		{"no grant drops despite all standard entitlements", with(func(f *LogEmitterFacts) { f.HasGrant = false; standardEntitlements(f) }), false},
		{"no ABI drops despite all standard entitlements", with(func(f *LogEmitterFacts) { f.ABIResolvable = false; standardEntitlements(f) }), false},
		{"dynamic payload drops despite all standard entitlements", with(func(f *LogEmitterFacts) { f.DynamicPayloadDropped = true; standardEntitlements(f) }), false},

		// Event rules: deny-all and a failed allowlist drop a non-admin,
		// including participants and visibleTo recipients (no RD-1162 / RD-842
		// fallback under strict).
		{"deny-all rules drop", with(func(f *LogEmitterFacts) { f.Rules = LogEventRulesDeny }), false},
		{"deny-all rules drop a participant", with(func(f *LogEmitterFacts) { f.Rules = LogEventRulesDeny; f.IsParticipant = true }), false},
		{"deny-all rules drop despite unlock", with(func(f *LogEmitterFacts) { f.Rules = LogEventRulesDeny; f.Unlocked = true; f.InVisibleTo = true }), false},
		{"allowlist param failed drops despite visibleTo", with(func(f *LogEmitterFacts) {
			f.Rules = LogEventRulesAllowlist
			f.Topic0Allowlisted = true
			f.InVisibleTo = true
		}), false},
		{"allowlist without topic0 drops", with(func(f *LogEmitterFacts) { f.Rules = LogEventRulesAllowlist; f.EventAllowed = true; f.HasTopic0 = false }), false},

		// Admin relaxes the event rules only (org admins resolve nil rules).
		{"admin with deny-all rules admits an indexed-self log", with(func(f *LogEmitterFacts) { f.Rules = LogEventRulesDeny; f.IsAdmin = true }), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, profile := range []ReadProfile{ReadProfileStrict, ReadProfileUnset} {
				d := DecideLogEmitter(profile, tc.facts)
				if d.Admit != tc.admit {
					t.Errorf("%v: Admit = %v, want %v (facts %+v)", profile, d.Admit, tc.admit, tc.facts)
				}
				if d.Payload != LogPayloadMasked {
					t.Errorf("%v: Payload = %v, want masked — strict never returns a full payload", profile, d.Payload)
				}
				if got := DecideLogEmitterAccess(profile, tc.facts); got != d.Admit {
					t.Errorf("%v: DecideLogEmitterAccess = %v, DecideLogEmitter.Admit = %v", profile, got, d.Admit)
				}
			}
		})
	}
}

// The standard profile ignores IndexedSelf entirely: its verdict is the
// documented default policy, with or without the fact.
func TestDecideLogEmitter_StandardIgnoresIndexedSelf(t *testing.T) {
	facts := []LogEmitterFacts{
		{IsAdmin: true},
		{Unlocked: true},
		{HasGrant: true, ABIResolvable: true, Rules: LogEventRulesWildcard, HasTopic0: true},
		{HasGrant: true, ABIResolvable: true, IsParticipant: true, Rules: LogEventRulesDeny, HasTopic0: true},
		{HasGrant: true, ABIResolvable: true, Rules: LogEventRulesDeny, HasTopic0: true},
	}
	for _, f := range facts {
		without := DecideLogEmitter(ReadProfileStandard, f)
		f.IndexedSelf = true
		with := DecideLogEmitter(ReadProfileStandard, f)
		if with != without {
			t.Errorf("standard verdict changed with IndexedSelf: %+v vs %+v (facts %+v)", with, without, f)
		}
	}
}
