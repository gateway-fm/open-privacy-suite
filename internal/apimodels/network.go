package apimodels

// Transport models relocated from auth_network_support.go (RD-1265).
// These describe the wire contract; the schema names in the published
// OpenAPI document derive from this package, not from handler layout.

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
