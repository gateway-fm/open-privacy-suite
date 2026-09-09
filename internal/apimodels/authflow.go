package apimodels

import (
	"github.com/iden3/iden3comm/v2/protocol"
)

// Transport models relocated from auth.go (RD-1265).
// These describe the wire contract; the schema names in the published
// OpenAPI document derive from this package, not from handler layout.

// AuthResponse represents the response from /auth endpoint
type AuthResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"` // seconds
}

// RefreshRequest represents the request body for /refresh endpoint
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// RevokeRequest represents the request body for /revoke endpoint
type RevokeRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
	AccessToken  string `json:"access_token"` // Optional: if provided, also revokes the access token
}

// AuthRequestResponse represents the response from /auth/request endpoint
type AuthRequestResponse struct {
	SessionID   string                                `json:"session_id"`
	AuthRequest *protocol.AuthorizationRequestMessage `json:"auth_request"`
}

// AuthVerifyRequest represents the request body for /auth/verify endpoint
type AuthVerifyRequest struct {
	SessionID string `json:"session_id" binding:"required"`
	JWZToken  string `json:"jwz_token" binding:"required"`
}

// AuthRequestBody represents optional request body for /auth/request endpoint
type AuthRequestBody struct {
	// CallbackOrigin is the browser's window.location.origin (e.g., "http://max-mac:5173")
	// Used to construct callback URLs that work from any hostname (localhost, Tailscale, etc.)
	CallbackOrigin string `json:"callback_origin"`
}

// HumanityVerificationError represents a failure to verify ProofOfHumanity
type HumanityVerificationError struct {
	Error     string `json:"error"`
	Message   string `json:"message"`
	VerifyURL string `json:"verify_url"`
}

// SessionStatusResponse represents the response for session status polling
type SessionStatusResponse struct {
	Completed bool          `json:"completed"`
	Tokens    *AuthResponse `json:"tokens,omitempty"`
	// Failed reports that the wallet's proof was rejected. Additive: clients
	// that only read `completed` are unaffected.
	Failed bool `json:"failed,omitempty"`
	// Reason is one of: verification_failed, humanity_required,
	// invalid_request, network_not_supported, authentication_failed. Sensitive
	// and unrecognised failures collapse to authentication_failed.
	Reason string `json:"reason,omitempty"`
}

// IntrospectResponse represents the response from /introspect endpoint (RFC 7662)
type IntrospectResponse struct {
	Active    bool   `json:"active"`
	Sub       string `json:"sub,omitempty"`        // Subject (user DID)
	Exp       int64  `json:"exp,omitempty"`        // Expiration time
	Iat       int64  `json:"iat,omitempty"`        // Issued at time
	TokenType string `json:"token_type,omitempty"` // "access_token" or "refresh_token"
	KYC       bool   `json:"kyc,omitempty"`        // KYC status (only for access tokens)
}
