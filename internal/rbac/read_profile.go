package rbac

import (
	"fmt"
	"strings"
)

// ReadProfile selects the read-side privacy policy applied to transaction,
// receipt and event data on every read surface (JSON-RPC and the proxy-mode
// Explorer Data API). It is deployment-wide and fixed at startup
// (PRIVACY_READ_PROFILE).
//
//   - ReadProfileStandard: the documented default policy. Participants, contract
//     admins (RD-751), visibleTo recipients, log-entitled viewers (RD-1183) and the
//     per-contract visibleTo unlock (RD-874) are admitted as described in
//     REDACTION_SPEC.
//   - ReadProfileStrict: a transaction or receipt is returned only to a
//     transaction participant (the viewer's linked address is the tx `from` or
//     `to`); an event is admitted only when its registered ABI identifies an
//     indexed `address` parameter equal to one of the viewer's linked
//     addresses. No read authority is inferred from the admin claim, visibleTo,
//     the unlock, log entitlement or tx participation. The only surviving
//     exception is an approved disclosure grant on the explorer.
//
// The zero value is ReadProfileUnset, which every decision treats as strict:
// a component whose profile was never wired fails closed rather than open.
type ReadProfile uint8

const (
	// ReadProfileUnset is the zero value. Decisions treat it as strict.
	ReadProfileUnset ReadProfile = iota
	// ReadProfileStandard is the documented default read policy.
	ReadProfileStandard
	// ReadProfileStrict is the participant / indexed-self read policy.
	ReadProfileStrict
)

// ParseReadProfile parses the PRIVACY_READ_PROFILE value. Only "standard" and
// "strict" are accepted (case-insensitive, surrounding whitespace ignored);
// anything else is an error so a typo cannot silently select a policy.
func ParseReadProfile(s string) (ReadProfile, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "standard":
		return ReadProfileStandard, nil
	case "strict":
		return ReadProfileStrict, nil
	default:
		return ReadProfileUnset, fmt.Errorf("invalid read profile %q: must be \"standard\" or \"strict\"", s)
	}
}

// Strict reports whether the strict policy applies. Only an explicit
// ReadProfileStandard is non-strict; ReadProfileUnset and any unknown value are
// strict (fail closed).
func (p ReadProfile) Strict() bool {
	return p != ReadProfileStandard
}

// String returns the effective profile name ("standard" or "strict"). An unset
// profile reports "strict" because that is how it is enforced.
func (p ReadProfile) String() string {
	if p.Strict() {
		return "strict"
	}
	return "standard"
}
