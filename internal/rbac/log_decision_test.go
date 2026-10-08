package rbac

import "testing"

// TestDecideLogEmitterAccess is the exhaustive, layer-agnostic truth table for
// the shared log-visibility decision (RD-1214). Every gate is tested in
// ISOLATION: to prove gate X is the sole cause of a verdict, every other gate
// is held in a "would-admit" state. In particular the grant gate is tested with
// Rules=Wildcard (which would otherwise admit) — a Drop there proves grant cuts
// independently of event-rules, the decoupling that makes the RD-1208 /
// participant leaks impossible to hide behind the event-rule deny-all backstop.
func TestDecideLogEmitterAccess(t *testing.T) {
	// grantWildcard is the maximally-permissive baseline for a granted viewer:
	// any single field flipped that still yields Drop isolates that gate.
	grantWildcard := LogEmitterFacts{
		HasGrant:      true,
		ABIResolvable: true,
		Rules:         LogEventRulesWildcard,
		HasTopic0:     true,
	}
	with := func(base LogEmitterFacts, mut func(*LogEmitterFacts)) LogEmitterFacts {
		f := base
		mut(&f)
		return f
	}

	cases := []struct {
		name  string
		facts LogEmitterFacts
		admit bool
	}{
		// ---- bypasses ----
		{"admin bypasses everything (no grant, deny, no ABI)", LogEmitterFacts{IsAdmin: true}, true},
		{"unlock bypasses everything (no grant, deny, no ABI)", LogEmitterFacts{Unlocked: true}, true},

		// ---- embedded-address gates: independent of grant/rules (anti-mask) ----
		{"no ABI drops even with grant+wildcard", with(grantWildcard, func(f *LogEmitterFacts) { f.ABIResolvable = false }), false},
		{"M15 dynamic payload drops even with grant+wildcard", with(grantWildcard, func(f *LogEmitterFacts) { f.DynamicPayloadDropped = true }), false},
		{"no ABI drops even for a participant", LogEmitterFacts{HasGrant: true, IsParticipant: true, ABIResolvable: false, Rules: LogEventRulesWildcard, HasTopic0: true}, false},
		{"M15 drops even for a participant", LogEmitterFacts{HasGrant: true, IsParticipant: true, ABIResolvable: true, DynamicPayloadDropped: true, Rules: LogEventRulesWildcard, HasTopic0: true}, false},
		{"admin bypasses the no-ABI gate", LogEmitterFacts{IsAdmin: true, ABIResolvable: false}, true},

		// ---- grant gate: load-bearing, independent of event-rules (ANTI-MASK core) ----
		{"NO grant drops even with wildcard rules", with(grantWildcard, func(f *LogEmitterFacts) { f.HasGrant = false }), false},
		{"NO grant + participant drops (participant is grant-bounded, RD-1162)", with(grantWildcard, func(f *LogEmitterFacts) { f.HasGrant = false; f.IsParticipant = true }), false},
		{"NO grant + visibleTo drops (ordinary visibleTo not a grant, RD-1208)", with(grantWildcard, func(f *LogEmitterFacts) { f.HasGrant = false; f.InVisibleTo = true }), false},
		{"NO grant + allowlisted+param-matched still drops", LogEmitterFacts{HasGrant: false, ABIResolvable: true, Rules: LogEventRulesAllowlist, HasTopic0: true, EventAllowed: true, Topic0Allowlisted: true}, false},

		// ---- participant (grant-bounded) ----
		{"participant + grant admits even under deny-all rules", LogEmitterFacts{HasGrant: true, IsParticipant: true, ABIResolvable: true, Rules: LogEventRulesDeny, HasTopic0: true}, true},

		// ---- event rules (grant held) ----
		{"grant + wildcard admits", grantWildcard, true},
		{"grant + wildcard admits anonymous event", with(grantWildcard, func(f *LogEmitterFacts) { f.HasTopic0 = false }), true},
		{"grant + deny-all drops", with(grantWildcard, func(f *LogEmitterFacts) { f.Rules = LogEventRulesDeny }), false},

		// ---- allowlist mode (grant held) ----
		{"allowlist: topic0 allowed + param matched → admit", LogEmitterFacts{HasGrant: true, ABIResolvable: true, Rules: LogEventRulesAllowlist, HasTopic0: true, EventAllowed: true, Topic0Allowlisted: true}, true},
		{"allowlist: topic0 allowlisted, param failed, in visibleTo → admit (fallback)", LogEmitterFacts{HasGrant: true, ABIResolvable: true, Rules: LogEventRulesAllowlist, HasTopic0: true, EventAllowed: false, Topic0Allowlisted: true, InVisibleTo: true}, true},
		{"allowlist: topic0 allowlisted, param failed, NOT in visibleTo → drop", LogEmitterFacts{HasGrant: true, ABIResolvable: true, Rules: LogEventRulesAllowlist, HasTopic0: true, EventAllowed: false, Topic0Allowlisted: true, InVisibleTo: false}, false},
		{"allowlist: topic0 NOT allowlisted → drop even with visibleTo", LogEmitterFacts{HasGrant: true, ABIResolvable: true, Rules: LogEventRulesAllowlist, HasTopic0: true, EventAllowed: false, Topic0Allowlisted: false, InVisibleTo: true}, false},
		{"allowlist: anonymous event (no topic0) → drop", LogEmitterFacts{HasGrant: true, ABIResolvable: true, Rules: LogEventRulesAllowlist, HasTopic0: false, EventAllowed: false, Topic0Allowlisted: false}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DecideLogEmitterAccess(ReadProfileStandard, tc.facts); got != tc.admit {
				t.Errorf("DecideLogEmitterAccess(%+v) = %v, want %v", tc.facts, got, tc.admit)
			}
		})
	}
}

// TestDecideLogEmitter_PayloadPolicy pins the field-policy half of the shared
// decision (RD-1300): the payload policy of an admitted log. Full payload is
// produced by the RD-874 visibleTo unlock and by nothing else; every other
// admit path — including admin — renders with embedded-address masking, and a
// dropped log carries the zero value. Both layers consume Payload, so a verdict
// here is the verdict on eth_getLogs, receipt logs and the explorer alike.
func TestDecideLogEmitter_PayloadPolicy(t *testing.T) {
	var zeroPolicy LogPayloadPolicy
	if zeroPolicy != LogPayloadMasked {
		t.Fatalf("zero LogPayloadPolicy must be LogPayloadMasked (fail-closed), got %v", zeroPolicy)
	}
	if (LogDecision{}) != (LogDecision{Admit: false, Payload: LogPayloadMasked}) {
		t.Fatalf("zero LogDecision must be drop + masked")
	}

	grantWildcard := LogEmitterFacts{HasGrant: true, ABIResolvable: true, Rules: LogEventRulesWildcard, HasTopic0: true}
	allowlistFallback := LogEmitterFacts{HasGrant: true, ABIResolvable: true, Rules: LogEventRulesAllowlist, HasTopic0: true, Topic0Allowlisted: true, InVisibleTo: true}
	allowlistMatch := LogEmitterFacts{HasGrant: true, ABIResolvable: true, Rules: LogEventRulesAllowlist, HasTopic0: true, Topic0Allowlisted: true, EventAllowed: true}

	cases := []struct {
		name  string
		facts LogEmitterFacts
		want  LogDecision
	}{
		// ---- the only full-payload path ----
		{"unlock alone → full payload", LogEmitterFacts{Unlocked: true}, LogDecision{Admit: true, Payload: LogPayloadFull}},
		{"unlock full payload without ABI", LogEmitterFacts{Unlocked: true, HasGrant: true, ABIResolvable: false}, LogDecision{Admit: true, Payload: LogPayloadFull}},
		{"unlock full payload with dynamic event", LogEmitterFacts{Unlocked: true, HasGrant: true, ABIResolvable: true, DynamicPayloadDropped: true, HasTopic0: true}, LogDecision{Admit: true, Payload: LogPayloadFull}},
		{"unlock + admin → full payload (the unlock wins)", LogEmitterFacts{Unlocked: true, IsAdmin: true}, LogDecision{Admit: true, Payload: LogPayloadFull}},

		// ---- every other admit path is masked ----
		{"admin alone → masked", LogEmitterFacts{IsAdmin: true}, LogDecision{Admit: true, Payload: LogPayloadMasked}},
		{"participant + grant → masked", LogEmitterFacts{HasGrant: true, IsParticipant: true, ABIResolvable: true, Rules: LogEventRulesDeny, HasTopic0: true}, LogDecision{Admit: true, Payload: LogPayloadMasked}},
		{"grant + wildcard → masked", grantWildcard, LogDecision{Admit: true, Payload: LogPayloadMasked}},
		{"allowlist match → masked", allowlistMatch, LogDecision{Admit: true, Payload: LogPayloadMasked}},
		{"ordinary visibleTo fallback → masked (listing alone is never full payload)", allowlistFallback, LogDecision{Admit: true, Payload: LogPayloadMasked}},

		// ---- a gated-off unlock falls back to the ordinary verdict, which
		// must see the real ABI / M15 facts (never defaults) ----
		{"no unlock, no ABI → drop", LogEmitterFacts{HasGrant: true, ABIResolvable: false, Rules: LogEventRulesWildcard, HasTopic0: true}, LogDecision{}},
		{"no unlock, M15 → drop", LogEmitterFacts{HasGrant: true, ABIResolvable: true, DynamicPayloadDropped: true, Rules: LogEventRulesWildcard, HasTopic0: true}, LogDecision{}},
		{"no unlock, no grant, listed → drop", LogEmitterFacts{ABIResolvable: true, Rules: LogEventRulesWildcard, HasTopic0: true, InVisibleTo: true}, LogDecision{}},
		{"no unlock, deny-all → drop", LogEmitterFacts{HasGrant: true, ABIResolvable: true, Rules: LogEventRulesDeny, HasTopic0: true, InVisibleTo: true}, LogDecision{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DecideLogEmitter(ReadProfileStandard, tc.facts)
			if got != tc.want {
				t.Errorf("DecideLogEmitter(%+v) = %+v, want %+v", tc.facts, got, tc.want)
			}
			if DecideLogEmitterAccess(ReadProfileStandard, tc.facts) != got.Admit {
				t.Errorf("DecideLogEmitterAccess must equal DecideLogEmitter(...).Admit for %+v", tc.facts)
			}
		})
	}
}
