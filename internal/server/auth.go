package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	"github.com/iden3/iden3comm/v2/protocol"
)

// humanityRequestConfig builds the per-issuer config for a ProofOfHumanity
// authorization request from the server's loaded config. Safe to call only
// when RequireProofOfHumanity=true — callers check that flag before invoking.
func (s *Server) humanityRequestConfig() auth.HumanityRequestConfig {
	return auth.HumanityRequestConfig{
		CircuitID:      s.config.PrivadoCircuitID,
		SchemaURL:      s.config.BillionsCredentialSchemaURL,
		CredentialType: s.config.BillionsCredentialType,
		Query:          s.config.BillionsCredentialQuery,
	}
}

// getCallbackBaseURL determines the base URL for auth callbacks.
// Priority: tunnel URL (for localhost callers) > callback_origin > dynamic detection > config
//
// When a cloudflared tunnel is running, the tunnel URL file contains the public HTTPS URL.
// If the caller is on localhost, we use the tunnel URL so the Privado wallet (on phone)
// can reach the callback endpoint through the tunnel.
func (s *Server) getCallbackBaseURL(c *gin.Context, callbackOrigin string) string {
	// If the caller is on localhost, prefer the tunnel URL (cloudflared) so the
	// Privado wallet (on a phone) can reach the callback endpoint.
	// If no tunnel is configured, fall through to getPublicURL so that BASE_URL
	// (e.g. an ngrok URL) is used instead of constructing an unreachable
	// "http://localhost:8080" URL.
	if s.isLocalOrigin(callbackOrigin) {
		if tunnelURL := s.readTunnelURL(); tunnelURL != "" {
			return tunnelURL
		}
		// Local origin, no tunnel — use BASE_URL / header detection.
		return s.getPublicURL(c)
	}

	// Non-local origin (e.g. the browser opened via ngrok/Tailscale): use the
	// origin hostname directly so the callback URL matches the tunnel the user
	// already has open.
	if callbackOrigin != "" {
		// Parse the origin to extract the hostname
		// Origin format: "http://hostname:port" or "https://hostname:port"
		// We need to replace the frontend port with the backend port
		if strings.HasPrefix(callbackOrigin, "http://") || strings.HasPrefix(callbackOrigin, "https://") {
			// Extract proto and host from origin
			parts := strings.SplitN(callbackOrigin, "://", 2)
			if len(parts) == 2 {
				proto := parts[0]
				hostWithPort := parts[1]
				// Check if origin has an explicit port
				hostname := hostWithPort
				hasExplicitPort := false
				if colonIdx := strings.LastIndex(hostWithPort, ":"); colonIdx != -1 {
					// Check for IPv6 literal
					isIPv6Literal := strings.Contains(hostWithPort, "[")
					hasPortAfterBracket := !strings.HasSuffix(hostWithPort, "]")
					if !isIPv6Literal || hasPortAfterBracket {
						hostname = hostWithPort[:colonIdx]
						hasExplicitPort = true
					}
				}
				if !hasExplicitPort {
					// No port in origin (e.g., tunnel URL) — return as-is
					return fmt.Sprintf("%s://%s", proto, hostname)
				}
				// Has explicit port — swap to backend port (existing behavior)
				port := s.config.Port
				if port == "" {
					port = "8080"
				}
				return fmt.Sprintf("%s://%s:%s", proto, hostname, port)
			}
		}
	}

	// Fall back to header-based detection
	return s.getPublicURL(c)
}

// isLocalOrigin returns true if the origin is localhost or loopback.
func (s *Server) isLocalOrigin(origin string) bool {
	if origin == "" {
		return false
	}
	lower := strings.ToLower(origin)
	return strings.Contains(lower, "localhost") || strings.Contains(lower, "127.0.0.1") || strings.Contains(lower, "[::1]")
}

// readTunnelURL reads the tunnel URL from the file specified by TUNNEL_URL_FILE.
// Returns empty string if not configured or file doesn't exist yet (tunnel still starting).
func (s *Server) readTunnelURL() string {
	path := s.config.TunnelURLFile
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	url := strings.TrimSpace(string(data))
	if url == "" || !strings.HasPrefix(url, "https://") {
		return ""
	}
	return url
}

// getPublicURL extracts the public-facing URL for callbacks.
// Priority: explicit BASE_URL config > dynamic detection from headers
func (s *Server) getPublicURL(c *gin.Context) string {
	// If BASE_URL is configured, use it directly.
	if s.config.BaseURL != "" {
		return s.config.BaseURL
	}

	// Dynamic detection for local development
	proto := c.GetHeader("X-Forwarded-Proto")
	if proto == "" {
		if s.config.IsProduction() {
			proto = "https"
		} else {
			proto = "http"
		}
	}

	host := c.GetHeader("X-Forwarded-Host")
	if host == "" {
		host = c.Request.Host
	}

	if host != "" {
		// Strip any port from the forwarded host
		// For IPv6 literals like [::1]:8080, we want to strip ":8080" but keep [::1]
		// For IPv6 without port like [::1], we don't want to strip at the internal colon
		// Logic: strip port if (not IPv6 literal) OR (IPv6 literal with port, i.e. doesn't end with ])
		hostname := host
		hasExplicitPort := false
		if colonIdx := strings.LastIndex(host, ":"); colonIdx != -1 {
			isIPv6Literal := strings.Contains(host, "[")
			hasPortAfterBracket := !strings.HasSuffix(host, "]")
			if !isIPv6Literal || hasPortAfterBracket {
				hostname = host[:colonIdx]
				hasExplicitPort = true
			}
		}
		if !hasExplicitPort {
			// No port in host (e.g., tunnel URL) — return as-is
			return fmt.Sprintf("%s://%s", proto, hostname)
		}
		port := s.config.Port
		if port == "" {
			port = "8080"
		}
		return fmt.Sprintf("%s://%s:%s", proto, hostname, port)
	}

	return s.config.BaseURL
}

// AuthRequest represents the request body for /auth endpoint
type AuthRequest struct {
	JWZToken string `json:"jwz_token" binding:"required"`
}

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

// handleAuthRequest handles POST /auth/request - creates authorization request
// Step 1: Client requests authentication, server creates proof request
//
// @Summary      Start a Privado ID authentication session
// @Description  Step 1 of the Privado ID wallet login. Creates a pending session and returns a session ID plus the authorization request the frontend renders as a QR code for the wallet to scan. The optional body may carry the browser's window.location.origin so the wallet callback URL is reachable from the caller's hostname. Rate-limited.
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        request body AuthRequestBody false "optional callback origin"
// @Success      200 {object} AuthRequestResponse
// @Failure      500 {object} APIError "VERIFIER_ID not configured (production) or failed to create the authorization request"
// @Failure      503 {object} APIError "authentication service at capacity"
// @Router       /api/v1/auth/request [post]
func (s *Server) handleAuthRequest(c *gin.Context) {
	// Parse optional request body for callback_origin
	var reqBody AuthRequestBody
	_ = c.ShouldBindJSON(&reqBody) // Ignore errors - body is optional

	// Generate session ID first (needed for callback URL)
	sessionID := s.sessionStore.CreateSession(nil) // Create empty session, will update below
	if sessionID == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "authentication service at capacity, please try again later"})
		return
	}

	// Determine the base URL for callback
	// Priority: callback_origin from request > dynamic detection from headers > config
	baseURL := s.getCallbackBaseURL(c, reqBody.CallbackOrigin)

	// In development mode with VERIFIER_ID not configured, return a mock session
	// This allows demo recording and testing without Privado infrastructure
	if s.config.VerifierID == "" {
		if s.config.IsProduction() {
			s.sessionStore.DeleteSession(sessionID)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "VERIFIER_ID not configured"})
			return
		}
		// Development mode: return mock session for demo/testing
		slog.Warn("VERIFIER_ID not configured, returning mock auth session for development")

		// Create a mock auth request via the library so ThreadID and fields are set correctly
		callbackURL := fmt.Sprintf("%s/auth/callback?session=%s", baseURL, sessionID)
		mockAuthReq, err := s.privadoVerifier.CreateAuthorizationRequest(
			devVerifierDID,
			callbackURL,
			"Authenticate to access Open Privacy Suite (demo mode)",
		)
		if err != nil {
			s.sessionStore.DeleteSession(sessionID)
			respondInternalErrorAndLog(c, "failed to create mock auth request",
				"auth: CreateAuthorizationRequest (mock) failed",
				"session_id", sessionID, "err", err)
			return
		}

		// Store the mock auth request in the session so callback verification works
		if err := s.sessionStore.UpdateSession(sessionID, mockAuthReq); err != nil {
			s.sessionStore.DeleteSession(sessionID)
			respondInternalErrorAndLog(c, "failed to update session",
				"auth: UpdateSession (mock) failed",
				"session_id", sessionID, "err", err)
			return
		}

		c.JSON(http.StatusOK, AuthRequestResponse{
			SessionID:   sessionID,
			AuthRequest: mockAuthReq,
		})

		// Schedule auto-auth for demo mode (if enabled)
		s.scheduleDemoAutoAuth(sessionID)
		return
	}

	// Build callback URL with session ID
	callbackURL := fmt.Sprintf("%s/auth/callback?session=%s", baseURL, sessionID)

	var authReq *protocol.AuthorizationRequestMessage
	var err error

	// Use ProofOfHumanity auth request when enabled and issuer DID is configured
	if s.config.RequireProofOfHumanity && s.config.BillionsIssuerDID != "" {
		authReq, err = s.privadoVerifier.CreateHumanityAuthRequest(
			s.config.VerifierID,
			callbackURL,
			"Authenticate and verify humanity to access Ethereum node",
			s.config.BillionsIssuerDID,
			s.humanityRequestConfig(),
		)
	} else {
		// Fall back to basic auth (just DID proof)
		authReq, err = s.privadoVerifier.CreateAuthorizationRequest(
			s.config.VerifierID,
			callbackURL,
			"Authenticate to access Ethereum node",
		)
	}
	if err != nil {
		s.sessionStore.DeleteSession(sessionID)
		respondInternalErrorAndLog(c, "failed to create authorization request",
			"auth: CreateAuthorizationRequest failed",
			"session_id", sessionID, "err", err)
		return
	}

	// Update session with the real auth request
	if err := s.sessionStore.UpdateSession(sessionID, authReq); err != nil {
		s.sessionStore.DeleteSession(sessionID)
		respondInternalErrorAndLog(c, "failed to update session",
			"auth: UpdateSession failed",
			"session_id", sessionID, "err", err)
		return
	}

	// Return authorization request and session ID
	c.JSON(http.StatusOK, AuthRequestResponse{
		SessionID:   sessionID,
		AuthRequest: authReq,
	})

	// Schedule auto-auth for demo mode (if enabled)
	s.scheduleDemoAutoAuth(sessionID)
}

// scheduleDemoAutoAuth schedules automatic session completion for demo mode.
// Spawns a goroutine that completes the session with a mock DID after the configured delay.
func (s *Server) scheduleDemoAutoAuth(sessionID string) {
	delay := s.config.DemoAutoAuthDelay
	if delay <= 0 || s.config.IsProduction() {
		return
	}

	go func() {
		time.Sleep(delay)

		// Check if session still pending (may have been completed or expired)
		session := s.sessionStore.GetSession(sessionID)
		if session == nil || session.Completed {
			return
		}

		// Generate mock DID and issue tokens
		mockDID := fmt.Sprintf("did:privado:demo_%d", time.Now().UnixNano())
		kyc := false
		if s.rbacAccessCtrl != nil {
			if user, err := s.rbacAccessCtrl.EnsureUserExists(context.Background(), mockDID, kyc, false); err == nil && user != nil {
				kyc = user.KYC
			}
		}

		accessToken, err := s.jwtService.IssueAccessToken(mockDID, kyc)
		if err != nil {
			slog.Error("demo auto-auth: failed to issue access token", "error", err)
			return
		}
		refreshToken, err := s.jwtService.IssueRefreshToken(mockDID)
		if err != nil {
			slog.Error("demo auto-auth: failed to issue refresh token", "error", err)
			return
		}

		tokenHash := auth.HashToken(refreshToken)
		expiresAt := time.Now().Add(RefreshTokenTTL)
		if err := s.db.SaveRefreshToken(context.Background(), tokenHash, mockDID, expiresAt); err != nil {
			slog.Error("demo auto-auth: failed to save refresh token", "error", err)
			return
		}

		if err := s.sessionStore.CompleteSession(sessionID, accessToken, refreshToken); err != nil {
			slog.Error("demo auto-auth: failed to complete session", "error", err)
			return
		}

		slog.Info("demo auto-auth: session completed", "session_id", sessionID, "did", mockDID)
	}()
}

// handleAuthCallback handles POST /auth/callback - wallet callback with proof
// Step 2: Wallet automatically sends proof here after user approves
//
// @Summary      Submit a Privado ID proof (wallet callback)
// @Description  Step 2 of the Privado ID wallet login. The wallet posts the JWZ proof to the session named by the `session` query parameter (the callback URL from step 1). On success the proof is verified and access + refresh tokens are issued. The body is the JWZ token, accepted either as JSON (`{"token":"<jwz>"}` or `{"jwz_token":"<jwz>"}`) or as the raw token string; it is size-capped. If the wallet's DID is anchored on an iden3 network this deployment has no state resolver for, the response is a 401 carrying `error: network_not_supported` and the network name, distinguishing a missing deployment setting from a bad proof; every other verification failure stays opaque. Rate-limited.
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        session query string true "auth session ID from /auth/request"
// @Param        request body object true "JWZ token, as {\"token\":\"<jwz>\"} or the raw token string"
// @Success      200 {object} AuthResponse
// @Failure      400 {object} APIError "missing session parameter, unreadable body, or missing JWZ token"
// @Failure      401 {object} UnsupportedNetworkError "session not found/expired; JWZ verification failed (opaque); or the wallet's iden3 network is not configured here (error: network_not_supported)"
// @Failure      403 {object} HumanityVerificationError "ProofOfHumanity verification required, or account banned"
// @Failure      500 {object} APIError "failed to persist user record or issue tokens"
// @Router       /api/v1/auth/callback [post]
func (s *Server) handleAuthCallback(c *gin.Context) {
	// Get session ID from query parameter (wallet includes it in callback URL)
	sessionID := c.Query("session")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "session parameter required"})
		return
	}

	// Get session
	session := s.sessionStore.GetSession(sessionID)
	if session == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "session not found or expired"})
		return
	}

	// Read JWZ token from request body
	// Wallet sends it as JSON: {"token": "..."} or just the token string
	// Limit body size to 1MB to prevent DoS attacks
	const maxBodySize = 1 << 20 // 1MB
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxBodySize))
	if err != nil {
		s.failAuthSession(sessionID, AuthFailInvalidRequest)
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read request body"})
		return
	}

	var jwzToken string
	// Try to parse as JSON first
	var tokenPayload map[string]interface{}
	if err := json.Unmarshal(body, &tokenPayload); err == nil {
		if token, ok := tokenPayload["token"].(string); ok {
			jwzToken = token
		} else if token, ok := tokenPayload["jwz_token"].(string); ok {
			jwzToken = token
		} else {
			s.failAuthSession(sessionID, AuthFailInvalidRequest)
			c.JSON(http.StatusBadRequest, gin.H{"error": "token not found in request body"})
			return
		}
	} else {
		// If not JSON, treat as plain string
		jwzToken = string(body)
	}

	if jwzToken == "" {
		s.failAuthSession(sessionID, AuthFailInvalidRequest)
		c.JSON(http.StatusBadRequest, gin.H{"error": "jwz_token required"})
		return
	}

	// Verify proof and issue tokens
	response, err := s.verifyAndIssueTokens(c, jwzToken, session.AuthRequest, sessionID)
	if err != nil {
		return // Error already sent in verifyAndIssueTokens
	}

	c.JSON(http.StatusOK, response)
}

// handleAuthVerify handles POST /auth/verify - manual proof submission (development only)
// Alternative flow for testing: client submits proof manually
//
// @Summary      Submit a Privado ID proof manually (dev only)
// @Description  Available only in non-production builds. Alternative to the wallet callback: the client submits the session ID and JWZ token in the body, the proof is verified, and access + refresh tokens are issued (also mirrored into an HttpOnly access cookie). Used by the dev mock-login flow. Rate-limited.
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        request body AuthVerifyRequest true "session ID and JWZ token"
// @Success      200 {object} AuthResponse
// @Failure      400 {object} APIError "invalid request body"
// @Failure      401 {object} UnsupportedNetworkError "session not found/expired; JWZ verification failed (opaque); or the wallet's iden3 network is not configured here (error: network_not_supported)"
// @Failure      403 {object} HumanityVerificationError "ProofOfHumanity verification required, or account banned"
// @Failure      500 {object} APIError "failed to persist user record or issue tokens"
// @Router       /api/v1/auth/verify [post]
func (s *Server) handleAuthVerify(c *gin.Context) {
	var req AuthVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondBadRequestAndLog(c, "invalid request body",
			"auth: handleAuthVerify invalid body", "err", err)
		return
	}

	// Get session
	session := s.sessionStore.GetSession(req.SessionID)
	if session == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "session not found or expired"})
		return
	}

	// Verify proof and issue tokens
	response, err := s.verifyAndIssueTokens(c, req.JWZToken, session.AuthRequest, req.SessionID)
	if err != nil {
		return // Error already sent in verifyAndIssueTokens
	}

	// RD-1008: mirror the access JWT into an HttpOnly cookie. /auth/verify
	// is the path taken by the dev mock-login flow (and any browser
	// posting the JWZ directly) — those callers receive the token here
	// and never poll /status, so without this they'd get no cookie.
	auth.SetAccessCookie(c, response.AccessToken, AccessTokenTTL)

	c.JSON(http.StatusOK, response)
}

// HumanityVerificationError represents a failure to verify ProofOfHumanity
type HumanityVerificationError struct {
	Error     string `json:"error"`
	Message   string `json:"message"`
	VerifyURL string `json:"verify_url"`
}

// failAuthSession records a rejected auth attempt on the session so the polling
// browser is told what happened (RD-1242). The wallet already has the error in
// its own response; this is the only channel the browser has.
//
// sessionID is empty on the paths that never resolved a session (dev manual
// verify with a bad body, a callback with no session parameter) - nothing to
// record there, and the caller in those cases is the browser itself.
func (s *Server) failAuthSession(sessionID, reason string) {
	if sessionID == "" || s.sessionStore == nil {
		return
	}
	if err := s.sessionStore.FailSession(sessionID, reason); err != nil {
		// Expected when the session already expired; the wallet still got its
		// error response, so this is not worth failing the request over.
		slog.Debug("auth: could not record session failure",
			"session_id", sessionID, "reason", reason, "err", err)
		return
	}
	// The precise reason, for operators. The polled status endpoint collapses
	// oracle-sensitive codes, so this log and the super-admin session list are
	// the only places the exact cause is available.
	slog.Info("auth: session marked failed", "session_id", sessionID, "reason", reason)
}

// verifyAndIssueTokens is a helper that verifies JWZ proof and issues JWT tokens
// Returns the response or sends error and returns nil
func (s *Server) verifyAndIssueTokens(c *gin.Context, jwzToken string, authRequest *protocol.AuthorizationRequestMessage, sessionID string) (*AuthResponse, error) {
	var userDID string
	var err error
	var zkClaims *auth.ZKRoleClaims

	// Support mock tokens for testing - only in non-production builds
	isMockLogin := false
	userDID, err = s.tryMockLogin(c, jwzToken)
	if err != nil {
		// Malformed mock token (dev builds only). tryMockLogin has already
		// written the response; record it so a browser polling this session is
		// not left waiting either.
		s.failAuthSession(sessionID, AuthFailInvalidRequest)
		return nil, err
	}
	if userDID != "" {
		isMockLogin = true
	}

	if userDID == "" {
		// Verify JWZ token against the original authorization request
		// Use VerifyJWZWithProofData to get both the DID and any ZK credential data
		verificationResult, verifyErr := s.privadoVerifier.VerifyJWZWithProofData(c.Request.Context(), jwzToken, authRequest, s.config.VerifierID)
		if verifyErr != nil {
			// RD-1241 owns the wire response so the auth and OAuth paths cannot
			// drift on what they disclose; RD-1242 records the same outcome on
			// the session, so a browser polling it stops instead of waiting out
			// the poll budget and then reporting a timeout that never happened.
			class := s.respondVerificationError(c, "auth", verifyErr)
			s.recordAuthAttempt("privado", string(class))
			s.failAuthSession(sessionID, authFailReasonForVerification(class))
			return nil, verifyErr
		}
		userDID = verificationResult.UserDID

		// Extract ZK role claims from the proof data if available
		if s.zkRoleExtractor != nil && len(verificationResult.ProofData) > 0 {
			// Process each proof's credential data
			for _, proofData := range verificationResult.ProofData {
				claims, extractErr := s.zkRoleExtractor.ExtractRoleClaims(proofData)
				if extractErr != nil {
					slog.Warn("failed to extract ZK role claims", "error", extractErr)
					continue
				}
				if claims != nil && (len(claims.Groups) > 0 || len(claims.Claims) > 0) {
					zkClaims = claims
					break // Use the first proof that has role claims
				}
			}
		}
	}

	// Ensure user exists in RBAC system and get their KYC status. New users
	// default to KYC=false; KYC status is updated through admin API.
	//
	// RD-945 — fail-closed on persistence failure. Pre-fix, an `EnsureUserExists`
	// error was logged and the auth flow continued, so the caller received a
	// signed JWT for a DID that has no row in `users`. Downstream code paths
	// that look up the user by DID then silently degrade (RBAC checks against
	// a non-existent user, RD-877 metadata methods bypassed because there is
	// no user to read KYC / ban state from, etc.). Treat persistence failure
	// the same as any other create-then-issue error in this file: return 500,
	// no token. The caller will retry.
	//
	// RD-1131: a NEW Privado user is created KYC-verified iff AUTO_KYC_PRIVADO is
	// set. EnsureUserExists applies this only to newly-created rows; existing
	// users keep their admin-managed KYC (re-read into `kyc` below).
	kyc := s.config.AutoKYCPrivado
	var user *rbac.User
	if s.rbacAccessCtrl != nil {
		var err error
		user, err = s.rbacAccessCtrl.EnsureUserExists(c.Request.Context(), userDID, kyc, false)
		if err != nil {
			slog.Error("auth: failed to ensure RBAC user exists", "user", userDID, "error", err)
			s.failAuthSession(sessionID, AuthFailInternalError)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist user record"})
			return nil, fmt.Errorf("ensure user exists: %w", err)
		}
		if user != nil {
			if user.Banned {
				// Recorded precisely for operators; collapsed on the wire so a
				// third party holding only the on-screen QR cannot learn an
				// account's ban state (see auth_failure_reasons.go).
				s.failAuthSession(sessionID, AuthFailAccountBanned)
				c.JSON(http.StatusForbidden, gin.H{"error": "account is banned"})
				return nil, fmt.Errorf("account is banned")
			}
			kyc = user.KYC
		}
	}

	// Auto-grant admin claim to mock-login users (dev builds only, no-op in prod)
	if isMockLogin && user != nil {
		s.ensureMockUserIsAdmin(c.Request.Context(), user.ID, userDID)
	}

	// Process ZK role claims if available and user exists
	// This synchronizes RBAC memberships based on ZK-attested credentials
	if s.zkRoleExtractor != nil && user != nil && zkClaims != nil {
		if err := s.zkRoleExtractor.ProcessZKMemberships(c.Request.Context(), user.ID, zkClaims); err != nil {
			slog.Warn("failed to process ZK memberships", "user", userDID, "error", err)
		}
	}

	// Issue access token (short-lived)
	accessToken, err := s.jwtService.IssueAccessToken(userDID, kyc)
	if err != nil {
		s.failAuthSession(sessionID, AuthFailInternalError)
		respondInternalErrorAndLog(c, "failed to issue access token",
			"auth: IssueAccessToken failed", "user_did", userDID, "err", err)
		return nil, err
	}

	// Issue refresh token (long-lived)
	refreshToken, err := s.jwtService.IssueRefreshToken(userDID)
	if err != nil {
		s.failAuthSession(sessionID, AuthFailInternalError)
		respondInternalErrorAndLog(c, "failed to issue refresh token",
			"auth: IssueRefreshToken failed", "user_did", userDID, "err", err)
		return nil, err
	}

	// Store refresh token in database
	tokenHash := auth.HashToken(refreshToken)
	expiresAt := time.Now().Add(RefreshTokenTTL)
	if err := s.db.SaveRefreshToken(c.Request.Context(), tokenHash, userDID, expiresAt); err != nil {
		s.failAuthSession(sessionID, AuthFailInternalError)
		respondInternalErrorAndLog(c, "failed to save refresh token",
			"auth: SaveRefreshToken failed", "user_did", userDID, "err", err)
		return nil, err
	}

	// Mark session as completed with tokens (keep alive for frontend polling)
	// Session will auto-expire after 2 minutes giving frontend time to poll
	if err := s.sessionStore.CompleteSession(sessionID, accessToken, refreshToken); err != nil {
		// Session may have been deleted or expired - log but continue
		// The wallet still gets the tokens directly from the callback response
		slog.Warn("failed to complete session", "session_id", sessionID, "error", err)
	}

	provider := "privado"
	if isMockLogin {
		provider = "mock"
	}
	s.recordAuthAttempt(provider, "success")

	return &AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(AccessTokenTTL.Seconds()),
	}, nil
}

// SessionStatusResponse represents the response for session status polling
type SessionStatusResponse struct {
	Completed bool          `json:"completed"`
	Tokens    *AuthResponse `json:"tokens,omitempty"`
	// Failed reports that the wallet's proof was rejected. Additive: clients
	// that only read `completed` are unaffected.
	Failed bool `json:"failed,omitempty"`
	// Reason is one of: verification_failed, humanity_required,
	// invalid_request, authentication_failed. Sensitive and unrecognised
	// failures collapse to authentication_failed.
	Reason string `json:"reason,omitempty"`
}

// handleAuthSessionStatus handles GET /api/auth/session/:id/status - poll for session completion
// Frontend polls this after displaying QR code to check if wallet has completed auth
//
// @Summary      Poll a Privado ID auth session for completion
// @Description  The frontend polls this after showing the QR code to learn whether the wallet has completed authentication. While pending it returns `completed:false`; once complete it returns the issued tokens (and mirrors the access JWT into an HttpOnly cookie). If the wallet's proof was rejected it returns `failed:true` with a `reason`, so the caller can surface the failure immediately instead of polling until it times out. `reason` is one of `verification_failed`, `humanity_required`, `invalid_request`, or `authentication_failed`; sensitive and unrecognised failures collapse to `authentication_failed`, and the value never carries internal error detail. A rejection is not final: a wallet that retries successfully still completes the session, so callers should keep polling while presenting the failure. Deliberately not rate-limited: it is read-only polling during the login flow.
// @Tags         Auth
// @Produce      json
// @Param        id path string true "auth session ID"
// @Success      200 {object} SessionStatusResponse
// @Failure      400 {object} APIError "session ID required"
// @Failure      404 {object} APIError "session not found or expired"
// @Router       /api/v1/auth/session/{id}/status [get]
func (s *Server) handleAuthSessionStatus(c *gin.Context) {
	sessionID := c.Param("id")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "session ID required"})
		return
	}

	session := s.sessionStore.GetSession(sessionID)
	if session == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found or expired"})
		return
	}

	if !session.Completed {
		// RD-1242: a rejected proof is reported so the browser can stop polling.
		// Checked inside the not-completed branch so a session that failed and
		// then succeeded on a wallet retry still returns its tokens. The 404
		// above stays the only signal about session existence - a failed
		// session looks like any other live one to an ID that does not exist.
		if session.Failed {
			c.JSON(http.StatusOK, SessionStatusResponse{
				Completed: false,
				Failed:    true,
				Reason:    wireAuthFailureReason(session.FailureReason),
			})
			return
		}
		c.JSON(http.StatusOK, SessionStatusResponse{Completed: false})
		return
	}

	// RD-1008: mirror the access JWT into an HttpOnly cookie so it travels
	// on cross-subdomain browser navigations to server-side endpoints (e.g.
	// /oauth/authorize), which is what silent SSO relies on. The Bearer
	// header path keeps working for existing API clients.
	auth.SetAccessCookie(c, session.AccessToken, AccessTokenTTL)

	// Session is completed - return tokens
	c.JSON(http.StatusOK, SessionStatusResponse{
		Completed: true,
		Tokens: &AuthResponse{
			AccessToken:  session.AccessToken,
			RefreshToken: session.RefreshToken,
			TokenType:    "Bearer",
			ExpiresIn:    int(AccessTokenTTL.Seconds()),
		},
	})
}

// handleRefresh handles POST /refresh - issues new access token from refresh token
//
// @Summary      Exchange a refresh token for new tokens
// @Description  Validates the refresh token, rejects it if revoked, expired, or the account is banned, then issues a new access token and rotates the refresh token (the old one is revoked). The access JWT is also refreshed in an HttpOnly cookie. Rate-limited.
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        request body RefreshRequest true "refresh token"
// @Success      200 {object} AuthResponse
// @Failure      400 {object} APIError "invalid request body"
// @Failure      401 {object} APIError "refresh token invalid, expired, revoked, or not found"
// @Failure      403 {object} APIError "account is banned"
// @Failure      500 {object} APIError "failed to check or issue tokens"
// @Router       /api/v1/refresh [post]
func (s *Server) handleRefresh(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondBadRequestAndLog(c, "invalid request body",
			"auth: handleRefresh invalid body", "err", err)
		return
	}

	// Validate refresh token
	claims, err := s.jwtService.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		if err == auth.ErrExpiredToken {
			respondUnauthorized(c, "refresh token expired")
		} else {
			// Validator err can include token-shape internals; never echo.
			slog.Warn("auth: refresh token validation failed", "err", err, "ip", c.ClientIP())
			respondUnauthorized(c, "invalid refresh token")
		}
		return
	}

	// Check if refresh token is revoked in database
	tokenHash := auth.HashToken(req.RefreshToken)
	storedToken, err := s.db.GetRefreshToken(c.Request.Context(), tokenHash)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to check refresh token",
			"auth: GetRefreshToken failed", "err", err)
		return
	}

	if storedToken == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token not found"})
		return
	}

	if storedToken.Revoked {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token revoked"})
		return
	}

	// Check if token expired in database
	expiresAt, err := time.Parse(time.RFC3339, storedToken.ExpiresAt)
	if err == nil && time.Now().After(expiresAt) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token expired"})
		return
	}

	// Get user status from RBAC — block refresh if banned
	kyc := false
	if s.rbacAccessCtrl != nil {
		user, err := s.rbacAccessCtrl.EnsureUserExists(c.Request.Context(), claims.Subject, false, false)
		if err == nil && user != nil {
			if user.Banned {
				// Revoke the token and reject
				_ = s.db.RevokeRefreshToken(c.Request.Context(), tokenHash)
				c.JSON(http.StatusForbidden, gin.H{"error": "account is banned"})
				return
			}
			kyc = user.KYC
		}
	}

	// Issue new access token
	accessToken, err := s.jwtService.IssueAccessToken(claims.Subject, kyc)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to issue access token",
			"auth: refresh→IssueAccessToken failed",
			"subject", claims.Subject, "err", err)
		return
	}

	// Optionally rotate refresh token (security best practice)
	// For now, we'll issue a new refresh token and revoke the old one
	newRefreshToken, err := s.jwtService.IssueRefreshToken(claims.Subject)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to issue new refresh token",
			"auth: refresh→IssueRefreshToken failed",
			"subject", claims.Subject, "err", err)
		return
	}

	// Revoke old refresh token
	if err := s.db.RevokeRefreshToken(c.Request.Context(), tokenHash); err != nil {
		// Log error but continue (non-critical)
		slog.Warn("failed to revoke old refresh token", "error", err)
	}

	// Store new refresh token
	newTokenHash := auth.HashToken(newRefreshToken)
	newExpiresAt := time.Now().Add(RefreshTokenTTL)
	if err := s.db.SaveRefreshToken(c.Request.Context(), newTokenHash, claims.Subject, newExpiresAt); err != nil {
		respondInternalErrorAndLog(c, "failed to save new refresh token",
			"auth: refresh→SaveRefreshToken failed",
			"subject", claims.Subject, "err", err)
		return
	}

	s.recordTokenRefresh("success")

	// RD-1008: refresh the access-token cookie alongside the JSON response
	// so browser navigations keep working after rotation.
	auth.SetAccessCookie(c, accessToken, AccessTokenTTL)

	c.JSON(http.StatusOK, AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(AccessTokenTTL.Seconds()),
	})
}

// IntrospectRequest represents the request body for /introspect endpoint (RFC 7662)
type IntrospectRequest struct {
	Token         string `form:"token" binding:"required"`
	TokenTypeHint string `form:"token_type_hint"` // Optional: "access_token" or "refresh_token"
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

// handleIntrospect handles POST /introspect - token introspection per RFC 7662
// Allows clients to validate tokens and retrieve basic token metadata
//
// @Summary      Introspect a token (RFC 7662)
// @Description  OAuth 2.0 token introspection. Accepts a form-encoded `token` (and optional `token_type_hint`) and reports whether it is currently active, with basic metadata for active tokens. Per RFC 7662 the response is always 200 with `active:false` for unknown, expired, or revoked tokens. Rate-limited.
// @Tags         Auth
// @Accept       x-www-form-urlencoded
// @Produce      json
// @Param        token formData string true "the token to introspect"
// @Param        token_type_hint formData string false "\"access_token\" or \"refresh_token\""
// @Success      200 {object} IntrospectResponse
// @Failure      400 {object} APIError "token is required"
// @Router       /api/v1/introspect [post]
func (s *Server) handleIntrospect(c *gin.Context) {
	var req IntrospectRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: token is required"})
		return
	}

	// Try to validate as access token first
	accessClaims, accessErr := s.jwtService.ValidateAccessToken(req.Token)
	if accessErr == nil && accessClaims != nil {
		// Check if token is revoked
		tokenID := auth.HashToken(req.Token)
		isRevoked, _ := s.db.IsAccessTokenRevoked(c.Request.Context(), tokenID)
		if isRevoked {
			c.JSON(http.StatusOK, IntrospectResponse{Active: false})
			return
		}

		c.JSON(http.StatusOK, IntrospectResponse{
			Active:    true,
			Sub:       accessClaims.Subject,
			Exp:       accessClaims.ExpiresAt.Unix(),
			Iat:       accessClaims.IssuedAt.Unix(),
			TokenType: "access_token",
			KYC:       accessClaims.KYC,
		})
		return
	}

	// Try to validate as refresh token
	refreshClaims, refreshErr := s.jwtService.ValidateRefreshToken(req.Token)
	if refreshErr == nil && refreshClaims != nil {
		// Check if refresh token is revoked
		tokenHash := auth.HashToken(req.Token)
		storedToken, err := s.db.GetRefreshToken(c.Request.Context(), tokenHash)
		if err != nil || storedToken == nil || storedToken.Revoked {
			c.JSON(http.StatusOK, IntrospectResponse{Active: false})
			return
		}

		c.JSON(http.StatusOK, IntrospectResponse{
			Active:    true,
			Sub:       refreshClaims.Subject,
			Exp:       refreshClaims.ExpiresAt.Unix(),
			Iat:       refreshClaims.IssuedAt.Unix(),
			TokenType: "refresh_token",
		})
		return
	}

	// Token is invalid or expired
	c.JSON(http.StatusOK, IntrospectResponse{Active: false})
}

// handleRevoke handles POST /revoke - revokes refresh and optionally access tokens
//
// @Summary      Revoke a refresh token (and optionally an access token)
// @Description  Revokes the supplied refresh token; if an access token is also supplied it is blacklisted for immediate invalidation. The access cookie is cleared. Revocation is best-effort against already-invalid tokens (defense in depth). Rate-limited.
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        request body RevokeRequest true "refresh token, and optional access token"
// @Success      200 {object} APIMessage "token revoked successfully"
// @Failure      400 {object} APIError "invalid request body"
// @Failure      500 {object} APIError "failed to revoke token"
// @Router       /api/v1/revoke [post]
func (s *Server) handleRevoke(c *gin.Context) {
	var req RevokeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondBadRequestAndLog(c, "invalid request body",
			"auth: handleRevoke invalid body", "err", err)
		return
	}

	ctx := c.Request.Context()

	// Revoke access token if provided (for immediate invalidation)
	if req.AccessToken != "" {
		accessClaims, err := s.jwtService.ValidateAccessToken(req.AccessToken)
		if err == nil && accessClaims != nil {
			// Token is valid, revoke it by adding to blacklist
			tokenID := auth.HashToken(req.AccessToken)
			if err := s.db.RevokeAccessToken(ctx, tokenID, accessClaims.Subject, accessClaims.ExpiresAt.Time); err != nil {
				respondInternalErrorAndLog(c, "failed to revoke access token",
					"auth: RevokeAccessToken failed",
					"subject", accessClaims.Subject, "err", err)
				return
			}
		}
		// If access token is invalid/expired, ignore - it's already unusable
	}

	// Validate refresh token to get subject (optional, but helps with logging)
	claims, err := s.jwtService.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		// Even if token is invalid/expired, we can still revoke it (defense in depth)
		_ = claims
	}

	// Revoke refresh token
	tokenHash := auth.HashToken(req.RefreshToken)
	if err := s.db.RevokeRefreshToken(ctx, tokenHash); err != nil {
		respondInternalErrorAndLog(c, "failed to revoke token",
			"auth: RevokeRefreshToken failed", "err", err)
		return
	}

	// RD-1008: clear the access-token cookie too so the browser session
	// is gone after logout. Idempotent — no-op for clients that never
	// received the cookie (API callers, server-to-server flows).
	auth.ClearAccessCookie(c)

	c.JSON(http.StatusOK, gin.H{"message": "token revoked successfully"})
}
