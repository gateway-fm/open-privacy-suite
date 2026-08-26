package server

import (
	"github.com/iden3/iden3comm/v2/protocol"
	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/types"
)

// SessionManager abstracts the session store operations for dependency injection and testing.
type SessionManager interface {
	// CreateSession creates a new session and returns the session ID.
	// Returns empty string if the store is at capacity.
	CreateSession(authRequest *protocol.AuthorizationRequestMessage) string

	// GetSession retrieves a session by ID.
	// Returns nil if session doesn't exist or has expired.
	GetSession(sessionID string) *auth.Session

	// DeleteSession removes a session.
	DeleteSession(sessionID string)

	// UpdateSession updates an existing session's auth request.
	UpdateSession(sessionID string, authRequest *protocol.AuthorizationRequestMessage) error

	// CompleteSession marks a session as completed with tokens.
	CompleteSession(sessionID, accessToken, refreshToken string) error

	// FailSession records that the wallet callback was rejected, so the polling
	// browser learns why instead of waiting out its poll budget (RD-1242).
	// reason must be a curated code from auth_failure_reasons.go.
	FailSession(sessionID, reason string) error

	// ListSessions returns information about all active sessions.
	ListSessions() []*auth.SessionInfo

	// Count returns the current number of sessions.
	Count() int64

	// Stop stops the cleanup goroutine.
	Stop()
}

// RateLimiterInterface abstracts the rate limiter operations for dependency injection and testing.
type RateLimiterInterface interface {
	// CheckAndIncrement checks if a request is allowed and increments counters atomically.
	// Returns (allowed, reason) where reason explains why the request was denied.
	CheckAndIncrement(userID string, rpsLimit, dailyLimit *int) (bool, string)

	// Stop stops the cleanup goroutine.
	Stop()
}

// OAuthSessionManager abstracts OAuth session storage.
// Uses *types.OAuthSession so that implementations in other packages (e.g. redis)
// can satisfy the interface without importing the server package.
type OAuthSessionManager interface {
	// CreateSession creates a new OAuth session. initiatorDID is the
	// JWT-subject DID of the caller that triggered /authorize (empty for
	// anonymous callers). RD-993 silent-SSO uses this field to ensure only
	// the initiator can auto-complete their own session.
	CreateSession(clientID, redirectURI, state, authSessionID, initiatorDID string) string
	GetSession(sessionID string) *types.OAuthSession
	GetSessionByCode(code string) *types.OAuthSession
	SetCode(sessionID, code, userDID string, kyc bool) error
	MarkCodeUsed(code string) bool
	DeleteSession(sessionID string)
	Stop()
}

// AzureStateManager abstracts Azure AD CSRF state storage.
type AzureStateManager interface {
	Create() (state, nonce string)
	Consume(state string) (nonce string, ok bool)
	Stop()
}

// ChallengeManager abstracts ETH address linking challenge storage.
type ChallengeManager interface {
	CreateChallenge(did string) (*LinkChallenge, error)
	GetChallenge(nonce string) *LinkChallenge
	Stop()
}

// Verify that concrete types implement the interfaces.
// Redis implementations are verified in internal/redis/interfaces_check.go
// to avoid a circular dependency.
var (
	_ SessionManager       = (*auth.SessionStore)(nil)
	_ RateLimiterInterface = (*RateLimiter)(nil)
	_ OAuthSessionManager  = (*OAuthSessionStore)(nil)
	_ AzureStateManager    = (*AzureStateStore)(nil)
	_ ChallengeManager     = (*ChallengeStore)(nil)
)
