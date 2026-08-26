package server

import (
	"regexp"
	"strings"
)

// UnsupportedNetworkError is returned when a wallet's proof cannot be verified
// because this deployment has no state resolver registered for the iden3
// network its DID is anchored on — i.e. the network is not configured here.
//
// It is deliberately distinguishable from a generic verification failure: an
// operator reading a user's screenshot can tell "your deployment is missing a
// config value" from "this proof is bad" without pod logs. Naming the network
// discloses nothing — it is the wallet's own network, already known to the
// caller. What must never appear is the raw library error or the RPC endpoint
// the resolver would have dialled (RD-934 / RD-1178).
type UnsupportedNetworkError struct {
	Error   string `json:"error"   example:"network_not_supported"`
	Message string `json:"message" example:"This deployment does not support the wallet's identity network."`
	Network string `json:"network" example:"billions:main"`
}

// errUnsupportedNetworkCode is the stable machine-readable code clients match on.
const errUnsupportedNetworkCode = "network_not_supported"

// iden3ResolverMissingPhrase is the fixed tail of the error the iden3 library
// raises when a proof's "blockchain:network" has no registered resolver
// (go-iden3-auth/v2 pubsignals: `errors.Errorf("%s resolver not found", ...)`).
const iden3ResolverMissingPhrase = " resolver not found"

// iden3NetworkKey matches a bare iden3 "blockchain:network" identifier and
// nothing else. Both halves are lowercase alphanumeric with optional _ or -.
// Crucially it admits neither "." nor "/", so a dialled URL that happens to sit
// next to the phrase can never be mistaken for a network name.
var iden3NetworkKey = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*:[a-z0-9][a-z0-9_-]*$`)

// unsupportedNetworkFromVerifyError reports whether a verification error is the
// "no resolver registered for this network" case, and if so which network.
//
// The parse is deliberately narrow. Rather than pattern-matching the whole
// error — which can carry dialled endpoints, issuer DIDs and circuit internals
// — it takes only the whitespace-delimited token immediately preceding the
// library's fixed phrase and returns it only if it is a well-formed
// "blockchain:network" identifier. Anything else yields ok=false and the caller
// falls back to the opaque generic failure.
func unsupportedNetworkFromVerifyError(err error) (string, bool) {
	if err == nil {
		return "", false
	}
	msg := err.Error()
	idx := strings.LastIndex(msg, iden3ResolverMissingPhrase)
	if idx < 0 {
		return "", false
	}
	fields := strings.Fields(msg[:idx])
	if len(fields) == 0 {
		return "", false
	}
	candidate := fields[len(fields)-1]
	if !iden3NetworkKey.MatchString(candidate) {
		return "", false
	}
	return candidate, true
}
