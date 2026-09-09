package apimodels

// Transport models relocated from eth_link.go (RD-1265).
// These describe the wire contract; the schema names in the published
// OpenAPI document derive from this package, not from handler layout.

// ChallengeResponse is the response for a link challenge
type ChallengeResponse struct {
	Nonce   string `json:"nonce"`
	Message string `json:"message"`
}

// VerifyLinkRequest is the request body for verifying a link
type VerifyLinkRequest struct {
	Nonce     string `json:"nonce" binding:"required"`
	Address   string `json:"address" binding:"required"`
	Signature string `json:"signature" binding:"required"`
}

// EthAddressResponse represents a linked ETH address in API responses
type EthAddressResponse struct {
	Address       string  `json:"address"`
	VerifiedAt    string  `json:"verified_at"`
	ENSName       *string `json:"ens_name,omitempty"`
	ENSResolvedAt *string `json:"ens_resolved_at,omitempty"`
}
