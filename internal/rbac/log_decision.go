package rbac

// LogEventRuleMode is the tri-state resolution of a viewer's event_rules for a
// contract, normalised so both the RPC and explorer layers describe it the
// same way.
type LogEventRuleMode int

const (
	// LogEventRulesDeny — nil/empty event_rules ⇒ deny-all (the default).
	LogEventRulesDeny LogEventRuleMode = iota
	// LogEventRulesWildcard — event_rules: "*" ⇒ every event passes.
	LogEventRulesWildcard
	// LogEventRulesAllowlist — an explicit set of allowed topic0s (each
	// optionally carrying param rules).
	LogEventRulesAllowlist
)

// LogEmitterFacts are the normalised, per-(viewer, log) inputs to the shared
// log-visibility decision. Each layer resolves these from its own data model
// and calls DecideLogEmitter, so the admit/deny decision has a single
// source of truth and the RPC filter (rbac.FilterEventLogs) and the explorer
// redactor (explorer.RedactionEngine.RedactLogsWithOpts) cannot drift apart.
// (RD-1214 — completes RD-887; the symmetry invariant becomes an
// implementation, not a convention.)
type LogEmitterFacts struct {
	// IsAdmin: the viewer holds the admin claim in the emitting contract's
	// owning org (per-contract, org-scoped). Bypasses every gate below.
	IsAdmin bool

	// Unlocked: the emitter has `allow_visibleto_unlock` set, the viewer is
	// eligible, AND the viewer is listed in THIS log's transaction's own
	// visibleTo row (RD-874) — the exact (viewer, emitting contract, tx) tuple.
	// This is the ONLY path by which visibleTo becomes a standalone grant; it
	// bypasses every gate below and is the only source of LogPayloadFull.
	Unlocked bool

	// HasGrant: the viewer holds a contract_grant on the emitter — the
	// load-bearing grant-eligibility signal (RD-874 / RD-1208). RPC:
	// perms.GetContractAccess(addr) != nil. Explorer: the emitter resolves to
	// VisibilityFull for the viewer.
	HasGrant bool

	// ABIResolvable: the emitter has a resolvable ABI, OR the ABI gate is
	// disabled for this call. When false the log is dropped — without an ABI,
	// non-indexed address params embedded in `data` cannot be decoded and
	// redacted (RD-875 / RD-889).
	ABIResolvable bool

	// DynamicPayloadDropped: the matched event declares a dynamic non-indexed
	// param AND the contract is not opted out of the drop gate (M15). Only ever
	// set when HasTopic0 is true.
	DynamicPayloadDropped bool

	// IsParticipant: the viewer is a from/to participant of the log's tx
	// (RD-1162). Grant-bounded — only admits together with HasGrant.
	IsParticipant bool

	// InVisibleTo: the viewer's DID is listed in the tx's (ordinary,
	// non-unlock) visibleTo set. Additive only: it extends the param-rule
	// fallback for a grant holder, never a standalone grant (RD-1208).
	InVisibleTo bool

	// Rules: the viewer's event_rules resolution for the emitter.
	Rules LogEventRuleMode

	// HasTopic0: the log carries a topic0 (i.e. is not an anonymous event).
	HasTopic0 bool

	// EventAllowed (allowlist mode only): topic0 matches an allowlisted rule
	// AND that rule's param constraints are satisfied (or it has none).
	EventAllowed bool

	// Topic0Allowlisted (allowlist mode only): topic0 matches some allowlisted
	// rule, ignoring its param constraints. Drives the visibleTo param-rule
	// fallback.
	Topic0Allowlisted bool
}

// LogPayloadPolicy is how an admitted log's payload (topics + data) is
// rendered. It is part of the shared decision so the RPC and explorer layers
// render an admitted log identically (RD-1300).
type LogPayloadPolicy int

const (
	// LogPayloadMasked — every embedded address (indexed topics + ABI-decoded
	// non-indexed data) the viewer may not see is zeroed via the shared
	// explorer.RedactLogAddressFields primitive (RD-1214). The zero value, so
	// any log whose policy was never set explicitly is masked (fail-closed).
	LogPayloadMasked LogPayloadPolicy = iota
	// LogPayloadFull — the log is returned exactly as emitted. Produced ONLY by
	// the RD-874 visibleTo unlock: the contract owner opted the emitter in, and
	// the sender listed this viewer on this transaction (REDACTION_SPEC §3.7.1).
	LogPayloadFull
)

// String implements fmt.Stringer for test diagnostics.
func (p LogPayloadPolicy) String() string {
	switch p {
	case LogPayloadMasked:
		return "masked"
	case LogPayloadFull:
		return "full"
	default:
		return "unknown"
	}
}

// LogDecision is the shared per-(viewer, log) verdict: whether the log is
// admitted and, if so, how its payload is rendered. The zero value is
// "drop" (and Masked), so a partially-filled decision never admits.
type LogDecision struct {
	Admit   bool
	Payload LogPayloadPolicy
}

// DecideLogEmitter is the single source of truth for "may this viewer see this
// log, and with which payload?", shared by the RPC filter and the explorer
// redactor. The gate order is identical for both layers:
//
//  1. visibleTo unlock          → admit, full payload (bypass everything)
//  2. admin                     → admit, masked
//  3. no resolvable ABI         → drop   (RD-875/889 embedded-address protection)
//  4. M15 dynamic payload       → drop   (embedded-address protection)
//  5. participant AND grant     → admit, masked (RD-1162, grant-bounded)
//  6. no grant                  → drop   (RD-874/RD-1208 — grant eligibility is load-bearing)
//  7. event_rules:
//     wildcard                → admit, masked
//     allowlist               → admit, masked iff topic0 is allowlisted AND
//     (param rules satisfied OR viewer in visibleTo); else drop
//     deny-all                → drop
//
// Structural invariants (not left to each caller):
//   - LogPayloadFull comes from the unlock branch only. Admin, participant,
//     ordinary visibleTo and event rules never skip embedded-address masking.
//   - The embedded-address protections (3, 4) are never relaxed by
//     participation or visibleTo.
//   - The grant gate (6) sits before event_rules and before the
//     participant/visibleTo relaxations, so neither can admit a no-grant
//     emitter — the class of leak RD-1208 closed.
//
// A policy profile that must switch the unlock off for some viewer does so by
// clearing Unlocked before calling this function (or by a gate placed ahead of
// branch 1); the ordinary verdict below then applies, which is why callers
// must resolve every fact (ABI, M15, rules) even when Unlocked is set.
func DecideLogEmitter(f LogEmitterFacts) LogDecision {
	if f.Unlocked {
		return LogDecision{Admit: true, Payload: LogPayloadFull}
	}
	if f.IsAdmin {
		return LogDecision{Admit: true, Payload: LogPayloadMasked}
	}
	if !f.ABIResolvable {
		return LogDecision{}
	}
	if f.DynamicPayloadDropped {
		return LogDecision{}
	}
	admitMasked := LogDecision{Admit: true, Payload: LogPayloadMasked}
	if f.IsParticipant && f.HasGrant {
		return admitMasked
	}
	if !f.HasGrant {
		return LogDecision{}
	}
	switch f.Rules {
	case LogEventRulesWildcard:
		return admitMasked
	case LogEventRulesAllowlist:
		if !f.HasTopic0 {
			return LogDecision{}
		}
		if f.EventAllowed || (f.Topic0Allowlisted && f.InVisibleTo) {
			return admitMasked
		}
		return LogDecision{}
	default: // LogEventRulesDeny
		return LogDecision{}
	}
}

// DecideLogEmitterAccess reports only the admit half of DecideLogEmitter. Kept
// for callers that do not render payloads; a caller that renders an admitted
// log MUST use DecideLogEmitter so it honours the payload policy.
func DecideLogEmitterAccess(f LogEmitterFacts) bool {
	return DecideLogEmitter(f).Admit
}
