package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	authpkg "privacy-proxy/internal/auth"
	"privacy-proxy/internal/types"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/iden3/iden3comm/v2/protocol"
)

// OAuth TTL constants
const (
	// OAuthCodeTTL is how long authorization codes are valid (5 minutes)
	OAuthCodeTTL = 5 * time.Minute

	// OAuthSessionTTL is how long OAuth sessions are valid (10 minutes)
	OAuthSessionTTL = 10 * time.Minute

	// OAuthCleanupInterval is how often to clean up expired OAuth sessions
	OAuthCleanupInterval = 1 * time.Minute

	// DefaultMaxOAuthSessions is the default maximum number of concurrent OAuth sessions
	DefaultMaxOAuthSessions = 1000
)

// OAuthSession wraps types.OAuthSession with an in-memory mutex for the
// in-process store. The Redis store uses types.OAuthSession directly since
// Redis provides its own concurrency guarantees.
type OAuthSession struct {
	mu sync.Mutex
	types.OAuthSession
}

// OAuthSessionStore manages OAuth authorization sessions
type OAuthSessionStore struct {
	sessions    sync.Map // map[sessionID]*OAuthSession
	codeIndex   sync.Map // map[code]sessionID - for quick code lookup
	mu          sync.Mutex
	ttl         time.Duration
	stopCh      chan struct{}
	wg          sync.WaitGroup
	maxSessions int
	count       int64
}

// NewOAuthSessionStore creates a new OAuth session store
func NewOAuthSessionStore(sessionTTL, cleanupInterval time.Duration, maxSessions int) *OAuthSessionStore {
	store := &OAuthSessionStore{
		ttl:         sessionTTL,
		stopCh:      make(chan struct{}),
		maxSessions: maxSessions,
	}

	// Start cleanup goroutine
	store.wg.Add(1)
	go store.cleanup(cleanupInterval)

	return store
}

// CreateSession creates a new OAuth session.
// initiatorDID is the JWT-subject DID of the caller that triggered /authorize
// (empty for anonymous callers — the normal interactive flow). The silent-SSO
// endpoint refuses to complete unless the completing user matches this field.
// Returns the session ID or empty string if at capacity.
func (s *OAuthSessionStore) CreateSession(clientID, redirectURI, state, authSessionID, initiatorDID string) string {
	s.mu.Lock()
	if s.maxSessions > 0 && s.count >= int64(s.maxSessions) {
		s.mu.Unlock()
		return ""
	}
	s.count++
	s.mu.Unlock()

	sessionID := generateSecureCode()
	now := time.Now()

	session := &OAuthSession{
		OAuthSession: types.OAuthSession{
			ClientID:      clientID,
			RedirectURI:   redirectURI,
			State:         state,
			AuthSessionID: authSessionID,
			InitiatorDID:  initiatorDID,
			CreatedAt:     now,
			ExpiresAt:     now.Add(s.ttl),
		},
	}

	s.sessions.Store(sessionID, session)
	return sessionID
}

// GetSession retrieves an OAuth session by ID.
// Returns the embedded types.OAuthSession (without the mutex wrapper) to satisfy
// the OAuthSessionManager interface.
func (s *OAuthSessionStore) GetSession(sessionID string) *types.OAuthSession {
	value, ok := s.sessions.Load(sessionID)
	if !ok {
		return nil
	}

	session := value.(*OAuthSession)
	if time.Now().After(session.ExpiresAt) {
		s.deleteSession(sessionID)
		return nil
	}

	return &session.OAuthSession
}

// GetSessionByCode retrieves an OAuth session by authorization code
func (s *OAuthSessionStore) GetSessionByCode(code string) *types.OAuthSession {
	value, ok := s.codeIndex.Load(code)
	if !ok {
		return nil
	}

	sessionID := value.(string)
	return s.GetSession(sessionID)
}

// SetCode sets the authorization code for a session
func (s *OAuthSessionStore) SetCode(sessionID, code, userDID string, kyc bool) error {
	value, ok := s.sessions.Load(sessionID)
	if !ok {
		return fmt.Errorf("session not found")
	}

	session := value.(*OAuthSession)
	session.mu.Lock()
	defer session.mu.Unlock()

	session.Code = code
	session.CodeExpires = time.Now().Add(OAuthCodeTTL)
	session.UserDID = userDID
	session.KYC = kyc

	// Index by code for quick lookup
	s.codeIndex.Store(code, sessionID)

	return nil
}

// MarkCodeUsed marks the authorization code as used (single-use)
func (s *OAuthSessionStore) MarkCodeUsed(code string) bool {
	value, ok := s.codeIndex.Load(code)
	if !ok {
		return false
	}

	sessionID := value.(string)
	sessionValue, ok := s.sessions.Load(sessionID)
	if !ok {
		return false
	}

	session := sessionValue.(*OAuthSession)
	session.mu.Lock()
	defer session.mu.Unlock()

	if session.CodeUsed {
		return false
	}

	session.CodeUsed = true
	return true
}

// DeleteSession removes an OAuth session
func (s *OAuthSessionStore) DeleteSession(sessionID string) {
	s.deleteSession(sessionID)
}

func (s *OAuthSessionStore) deleteSession(sessionID string) {
	value, loaded := s.sessions.LoadAndDelete(sessionID)
	if loaded {
		s.mu.Lock()
		s.count--
		s.mu.Unlock()

		// Clean up code index
		session := value.(*OAuthSession)
		if session.Code != "" {
			s.codeIndex.Delete(session.Code)
		}
	}
}

// cleanup periodically removes expired sessions
func (s *OAuthSessionStore) cleanup(interval time.Duration) {
	defer s.wg.Done()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			s.sessions.Range(func(key, value any) bool {
				session := value.(*OAuthSession)
				if now.After(session.ExpiresAt) {
					s.deleteSession(key.(string))
				}
				return true
			})
		case <-s.stopCh:
			return
		}
	}
}

// Stop stops the cleanup goroutine
func (s *OAuthSessionStore) Stop() {
	close(s.stopCh)
	s.wg.Wait()
}

// generateSecureCode generates a cryptographically secure random code
func generateSecureCode() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// handleOAuthMockComplete handles POST /oauth/session/:id/mock-complete
// Dev-only: instantly completes an OAuth session with a mock DID, bypassing Privado verification.
//
// @Summary      Complete an OAuth session with a mock DID (dev only)
// @Description  Available only in non-production builds with mock login enabled. Instantly completes a pending OAuth session with a mock DID (optionally supplied in the body), bypassing Privado verification, and mints the authorization code. Rate-limited.
// @Tags         OAuth SSO
// @Accept       json
// @Produce      json
// @Param        id path string true "OAuth session ID"
// @Param        request body object false "optional {\"did\":\"did:...\"} to complete as a specific mock identity"
// @Success      200 {object} oauthMockCompleteResponse
// @Failure      403 {object} APIError "mock login not available"
// @Failure      404 {object} APIError "session not found or expired"
// @Failure      409 {object} APIError "session already completed"
// @Failure      500 {object} APIError "failed to complete session"
// @Router       /oauth/session/{id}/mock-complete [post]
func (s *Server) handleOAuthMockComplete(c *gin.Context) {
	if s.config.IsProduction() || !s.config.AllowMockLogin {
		c.JSON(http.StatusForbidden, gin.H{"error": "mock login not available"})
		return
	}

	oauthSessionID := c.Param("id")
	oauthSession := s.oauthSessionStore.GetSession(oauthSessionID)
	if oauthSession == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found or expired"})
		return
	}
	if oauthSession.Code != "" {
		c.JSON(http.StatusConflict, gin.H{"error": "session already completed"})
		return
	}

	// Accept optional DID from request body (for dev identity picker)
	var body struct {
		DID string `json:"did"`
	}
	_ = c.ShouldBindJSON(&body) // ignore errors — body is optional

	mockDID := body.DID
	if mockDID == "" {
		mockDID = fmt.Sprintf("did:privado:mock_%d", time.Now().UnixNano())
	}
	kyc := false
	if s.rbacAccessCtrl != nil {
		if user, err := s.rbacAccessCtrl.EnsureUserExists(c.Request.Context(), mockDID, kyc, false); err == nil && user != nil {
			kyc = user.KYC
		}
	}

	code := generateSecureCode()
	if err := s.oauthSessionStore.SetCode(oauthSessionID, code, mockDID, kyc); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to complete session"})
		return
	}

	if oauthSession.AuthSessionID != "" {
		_ = s.sessionStore.CompleteSession(oauthSession.AuthSessionID, "", "")
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "did": mockDID})
}

// handleOAuthSilentComplete handles POST /oauth/session/:id/silent-complete.
//
// RD-993 — production-safe silent SSO for explicitly-configured first-party
// OAuth clients. The endpoint short-circuits the interactive Privado /
// mock-login flow when:
//
//  1. The caller has a valid PP JWT (JWTAuthMiddleware on the route gates
//     this; otherwise 401).
//  2. The caller's JWT subject DID equals the OAuth session's InitiatorDID
//     (set at /authorize time from the same JWT middleware). Defeats T2 in
//     the RD-928 audit: an attacker pre-creating an oauth_session and luring
//     the victim cannot drive a silent grant because the victim is not the
//     initiator of the attacker-started session.
//  3. The session's ClientID is on the OAUTH_FIRST_PARTY_CLIENTS allowlist.
//     Foreign clients always fall back to interactive even if everything
//     else lines up.
//  4. The session is still pending (no Code already set).
//
// On success: mints an auth code, writes one row to oauth_silent_sso_log,
// and returns the same `{ completed, redirect_url }` payload the existing
// status endpoint returns so the FE can reuse its redirect logic.
//
// On any precondition failure: returns 403/404/409 with a generic body so
// the FE can fall through to the interactive Privado flow without leaking
// which condition tripped.
//
// @Summary      Silently complete an OAuth session (first-party SSO)
// @Description  Production-safe silent SSO. Requires a valid Bearer JWT. Completes a pending OAuth session without the interactive wallet step only when it is fail-closed safe to do so: the caller's DID must equal the session's initiator DID and the session's client must be on the first-party allowlist (an anonymous initiator or a non-first-party client is never eligible and falls through to the interactive flow). On success it mints an authorization code and returns the same shape as the status endpoint. Rate-limited.
// @Tags         OAuth SSO
// @Produce      json
// @Param        id path string true "OAuth session ID"
// @Success      200 {object} OAuthSessionStatusResponse "completed, with redirect_url"
// @Failure      401 {object} APIError "authentication required"
// @Failure      403 {object} APIError "silent SSO not available for this session or client"
// @Failure      404 {object} APIError "session not found or expired"
// @Failure      409 {object} APIError "session already completed"
// @Failure      500 {object} APIError "failed to complete session"
// @Security     BearerAuth
// @Router       /oauth/session/{id}/silent-complete [post]
func (s *Server) handleOAuthSilentComplete(c *gin.Context) {
	oauthSessionID := c.Param("id")
	oauthSession := s.oauthSessionStore.GetSession(oauthSessionID)
	if oauthSession == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found or expired"})
		return
	}
	if oauthSession.Code != "" {
		c.JSON(http.StatusConflict, gin.H{"error": "session already completed"})
		return
	}

	// Caller DID from validated JWT — JWTAuthMiddleware on the route
	// guarantees presence; we still check defensively.
	subject, _ := c.Get("subject")
	callerDID, _ := subject.(string)
	if callerDID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	// Gate 1: session-binding. The initiator of /authorize is the only
	// user allowed to silent-complete this session. An anonymous initiator
	// (empty InitiatorDID) is never eligible for silent-SSO — that path
	// falls through to interactive.
	if oauthSession.InitiatorDID == "" || !strings.EqualFold(oauthSession.InitiatorDID, callerDID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "silent SSO not available for this session"})
		return
	}

	// Gate 2: first-party allowlist. Empty config means no client gets
	// silent SSO; misconfiguration fails closed.
	if !s.config.IsFirstPartyOAuthClient(oauthSession.ClientID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "silent SSO not available for this client"})
		return
	}

	// Best-effort KYC lookup so the issued code carries the right KYC
	// flag in the eventual token exchange. Same shape as mock-complete.
	// RD-1131: new Privado users auto-KYC'd iff AUTO_KYC_PRIVADO (new rows only).
	kyc := s.config.AutoKYCPrivado
	if s.rbacAccessCtrl != nil {
		if user, err := s.rbacAccessCtrl.EnsureUserExists(c.Request.Context(), callerDID, kyc, false); err == nil && user != nil {
			kyc = user.KYC
		}
	}

	code := generateSecureCode()
	if err := s.oauthSessionStore.SetCode(oauthSessionID, code, callerDID, kyc); err != nil {
		slog.Error("oauth silent-complete: SetCode failed", "session_id", oauthSessionID, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to complete session"})
		return
	}

	if oauthSession.AuthSessionID != "" {
		_ = s.sessionStore.CompleteSession(oauthSession.AuthSessionID, "", "")
	}

	// Audit log: fire-and-forget at this layer. The row is best-effort
	// because the auth code is already issued; if the DB write fails the
	// operator finds out via the slog error + SIEM gap, not by surprising
	// the caller. (Compare RD-872's impersonation_log which is fail-closed
	// — that endpoint can refuse the response if audit fails; here the code
	// has already been minted and returning 500 would leave the user
	// stranded with a valid auth code they can't redeem cleanly.)
	if err := s.recordOAuthSilentSSO(c.Request.Context(), callerDID, oauthSession.ClientID, oauthSession.RedirectURI, getCorrelationID(c)); err != nil {
		slog.Error("oauth silent-complete: audit write failed", "actor_did", callerDID, "client_id", oauthSession.ClientID, "err", err)
	}

	// Mirror the status endpoint's response shape so the FE can reuse its
	// existing redirect path.
	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", oauthSession.RedirectURI, code, oauthSession.State)
	c.JSON(http.StatusOK, gin.H{
		"completed":    true,
		"redirect_url": redirectURL,
	})
}

// recordOAuthSilentSSO writes one row to oauth_silent_sso_log.
func (s *Server) recordOAuthSilentSSO(ctx context.Context, actorDID, clientID, redirectURI, correlationID string) error {
	if s.db == nil {
		return nil
	}
	conn := s.db.Conn()
	if conn == nil {
		return nil
	}
	sum := sha256.Sum256([]byte(redirectURI))
	redirectHash := hex.EncodeToString(sum[:])
	corr := uuid.NullUUID{}
	if id, err := uuid.Parse(correlationID); err == nil {
		corr.UUID = id
		corr.Valid = true
	}
	_, err := conn.ExecContext(ctx, `
		INSERT INTO oauth_silent_sso_log (actor_did, client_id, redirect_uri_hash, correlation_id)
		VALUES ($1, $2, $3, $4)`,
		actorDID, clientID, redirectHash, corr,
	)
	return err
}

// handleOAuthSessionInfo handles GET /oauth/session/:id/info
// Returns the auth request data for a pending OAuth session, allowing the frontend
// login page to render the QR code for an OAuth flow initiated by a third-party app.
//
// @Summary      Get pending OAuth session info
// @Description  Returns the underlying Privado authorization request for a pending OAuth session so the login page can render its QR code, plus whether the dev mock-complete path is offered. Rate-limited.
// @Tags         OAuth SSO
// @Produce      json
// @Param        id path string true "OAuth session ID"
// @Success      200 {object} oauthSessionInfoResponse
// @Failure      404 {object} APIError "OAuth session or its auth session not found"
// @Router       /oauth/session/{id}/info [get]
func (s *Server) handleOAuthSessionInfo(c *gin.Context) {
	oauthSessionID := c.Param("id")
	oauthSession := s.oauthSessionStore.GetSession(oauthSessionID)
	if oauthSession == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found or expired"})
		return
	}

	authSession := s.sessionStore.GetSession(oauthSession.AuthSessionID)
	if authSession == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "auth session not found"})
		return
	}

	allowMock := s.config.AllowMockLogin && !s.config.IsProduction()
	c.JSON(http.StatusOK, gin.H{
		"auth_request": authSession.AuthRequest,
		"allow_mock":   allowMock,
	})
}

// OAuthAuthorizeRequest represents query parameters for /oauth/authorize
type OAuthAuthorizeRequest struct {
	ClientID     string `form:"client_id" binding:"required"`
	RedirectURI  string `form:"redirect_uri" binding:"required"`
	State        string `form:"state" binding:"required"`
	ResponseType string `form:"response_type" binding:"required"`
}

// OAuthTokenRequest represents the request body for /oauth/token
type OAuthTokenRequest struct {
	GrantType    string `json:"grant_type" form:"grant_type" binding:"required"`
	Code         string `json:"code" form:"code" binding:"required"`
	RedirectURI  string `json:"redirect_uri" form:"redirect_uri" binding:"required"`
	ClientID     string `json:"client_id" form:"client_id" binding:"required"`
	ClientSecret string `json:"client_secret" form:"client_secret"` // RD-1006 client_secret_post; client_secret_basic also accepted via HTTP Basic
}

// OAuthTokenResponse represents the response from /oauth/token
type OAuthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// OAuthErrorResponse represents an OAuth error response
type OAuthErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// handleOAuthAuthorize handles GET /oauth/authorize - OAuth authorization endpoint
// This initiates the OAuth flow by creating a pending session and returning the auth page
//
// @Summary      OAuth 2.0 authorization endpoint
// @Description  Starts the OAuth authorization-code flow: validates the parameters and redirect_uri, creates a pending session, and generates the underlying Privado authorization request. Browser clients (Accept: text/html) receive a 302 redirect to the login page; other clients receive JSON with the session IDs and the authorization request to render as a QR code. An optional Bearer JWT may be supplied — when present, the caller's DID is bound to the session as its initiator, enabling later first-party silent SSO; anonymous callers simply complete via the interactive flow. Only response_type=code is supported. Rate-limited.
// @Tags         OAuth SSO
// @Produce      json
// @Param        client_id query string true "OAuth client ID"
// @Param        redirect_uri query string true "client redirect URI (must be allowlisted)"
// @Param        state query string true "opaque CSRF state echoed back to the client"
// @Param        response_type query string true "must be \"code\""
// @Success      200 {object} oauthAuthorizeJSONResponse "non-browser clients: session IDs and auth request"
// @Success      302 {string} string "browser clients: redirect to the login page"
// @Failure      400 {object} OAuthErrorResponse "invalid_request or unsupported_response_type"
// @Failure      500 {object} OAuthErrorResponse "server misconfiguration or failure creating the session"
// @Failure      503 {object} OAuthErrorResponse "authentication or OAuth service at capacity"
// @Router       /oauth/authorize [get]
func (s *Server) handleOAuthAuthorize(c *gin.Context) {
	var req OAuthAuthorizeRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, OAuthErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "missing required parameters: client_id, redirect_uri, state, response_type",
		})
		return
	}

	// Validate response_type
	if req.ResponseType != "code" {
		c.JSON(http.StatusBadRequest, OAuthErrorResponse{
			Error:            "unsupported_response_type",
			ErrorDescription: "only response_type=code is supported",
		})
		return
	}

	// Validate redirect_uri
	if !s.isValidRedirectURI(req.RedirectURI) {
		c.JSON(http.StatusBadRequest, OAuthErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "redirect_uri is not allowed",
		})
		return
	}

	// Create the underlying auth session (Privado ID flow)
	authSessionID := s.sessionStore.CreateSession(nil)
	if authSessionID == "" {
		c.JSON(http.StatusServiceUnavailable, OAuthErrorResponse{
			Error:            "server_error",
			ErrorDescription: "authentication service at capacity, please try again later",
		})
		return
	}

	// Capture the initiator DID from the optional JWT (RD-993). When the
	// caller is anonymous (no Authorization header / invalid token), this
	// is the empty string and silent-complete will refuse to auto-complete
	// for anyone — the flow must finish via the normal interactive path.
	initiatorDID, _ := c.Get("subject")
	initiatorDIDStr, _ := initiatorDID.(string)

	// Create OAuth session linked to auth session
	oauthSessionID := s.oauthSessionStore.CreateSession(req.ClientID, req.RedirectURI, req.State, authSessionID, initiatorDIDStr)
	if oauthSessionID == "" {
		s.sessionStore.DeleteSession(authSessionID)
		c.JSON(http.StatusServiceUnavailable, OAuthErrorResponse{
			Error:            "server_error",
			ErrorDescription: "OAuth service at capacity, please try again later",
		})
		return
	}

	// Generate the authorization request (same as normal auth flow)
	baseURL := s.getPublicURL(c)
	callbackURL := fmt.Sprintf("%s/oauth/callback?session=%s&oauth_session=%s", baseURL, authSessionID, oauthSessionID)

	var authReq *protocol.AuthorizationRequestMessage
	var err error

	// In development mode with VERIFIER_ID not configured, return a mock session
	if s.config.VerifierID == "" {
		if s.config.IsProduction() {
			s.sessionStore.DeleteSession(authSessionID)
			s.oauthSessionStore.DeleteSession(oauthSessionID)
			c.JSON(http.StatusInternalServerError, OAuthErrorResponse{
				Error:            "server_error",
				ErrorDescription: "VERIFIER_ID not configured",
			})
			return
		}
		// Development mode: create mock auth request via the library
		slog.Warn("VERIFIER_ID not configured, returning mock OAuth auth session for development")
		authReq, err = s.privadoVerifier.CreateAuthorizationRequest(
			devVerifierDID,
			callbackURL,
			"Authenticate for OAuth authorization (demo mode)",
		)
		if err != nil {
			s.sessionStore.DeleteSession(authSessionID)
			s.oauthSessionStore.DeleteSession(oauthSessionID)
			c.JSON(http.StatusInternalServerError, OAuthErrorResponse{
				Error:            "server_error",
				ErrorDescription: "failed to create mock auth request: " + err.Error(),
			})
			return
		}
	} else {
		// Use ProofOfHumanity auth request when enabled
		if s.config.RequireProofOfHumanity && s.config.BillionsIssuerDID != "" {
			authReq, err = s.privadoVerifier.CreateHumanityAuthRequest(
				s.config.VerifierID,
				callbackURL,
				"Authenticate and verify humanity for OAuth authorization",
				s.config.BillionsIssuerDID,
				s.humanityRequestConfig(),
			)
		} else {
			authReq, err = s.privadoVerifier.CreateAuthorizationRequest(
				s.config.VerifierID,
				callbackURL,
				"Authenticate for OAuth authorization",
			)
		}

		if err != nil {
			s.sessionStore.DeleteSession(authSessionID)
			s.oauthSessionStore.DeleteSession(oauthSessionID)
			c.JSON(http.StatusInternalServerError, OAuthErrorResponse{
				Error:            "server_error",
				ErrorDescription: "failed to create authorization request",
			})
			return
		}
	}

	// Store the auth request in the session (required for JWZ verification in callback)
	if err := s.sessionStore.UpdateSession(authSessionID, authReq); err != nil {
		s.sessionStore.DeleteSession(authSessionID)
		s.oauthSessionStore.DeleteSession(oauthSessionID)
		c.JSON(http.StatusInternalServerError, OAuthErrorResponse{
			Error:            "server_error",
			ErrorDescription: "failed to store authorization request",
		})
		return
	}

	// Detect browser requests via Accept header
	accept := c.GetHeader("Accept")
	isBrowser := strings.Contains(accept, "text/html")

	if isBrowser {
		// Browser clients are redirected to the React login page at
		// FRONTEND_URL. FRONTEND_URL must be configured — the inline-HTML
		// fallback was removed so we have a single login UI to audit.
		if s.config.FrontendURL == "" {
			c.JSON(http.StatusInternalServerError, OAuthErrorResponse{
				Error:            "server_error",
				ErrorDescription: "FRONTEND_URL is not configured on the OAuth server",
			})
			return
		}
		frontendURL := strings.TrimRight(s.config.FrontendURL, "/")
		c.Redirect(http.StatusFound, frontendURL+"/login?oauth_session="+oauthSessionID)
	} else {
		// Return JSON response with auth request for the client to display QR code
		// The client should poll /oauth/session/:id/status and display the QR code
		c.JSON(http.StatusOK, gin.H{
			"oauth_session_id": oauthSessionID,
			"auth_session_id":  authSessionID,
			"auth_request":     authReq,
		})
	}

	// Schedule auto-auth for demo mode (if enabled)
	s.scheduleOAuthDemoAutoAuth(oauthSessionID, authSessionID)
}

// handleOAuthCallback handles POST /oauth/callback - wallet callback with proof
// This is similar to handleAuthCallback but handles the OAuth redirect
//
// @Summary      Submit a Privado ID proof for an OAuth session (wallet callback)
// @Description  The wallet posts the JWZ proof for an OAuth flow, naming both the auth session and the OAuth session via query parameters (the OAuth session must be linked to the given auth session). On success an authorization code is minted and a redirect URL (client redirect_uri with code and state) is returned. The body is the JWZ token, accepted as JSON (`{"token":"<jwz>"}` or `{"jwz_token":"<jwz>"}`) or the raw token string; it is size-capped. Rate-limited.
// @Tags         OAuth SSO
// @Accept       json
// @Produce      json
// @Param        session query string true "auth session ID"
// @Param        oauth_session query string true "OAuth session ID (must be linked to the auth session)"
// @Param        request body object true "JWZ token, as {\"token\":\"<jwz>\"} or the raw token string"
// @Success      200 {object} oauthCallbackResponse
// @Failure      400 {object} APIError "missing session parameters, unreadable body, or missing/invalid JWZ token"
// @Failure      401 {object} APIError "session not found/expired, session mismatch, or verification failed"
// @Failure      403 {object} HumanityVerificationError "ProofOfHumanity verification required, or account banned"
// @Failure      500 {object} APIError "failed to generate authorization code or build redirect"
// @Router       /oauth/callback [post]
func (s *Server) handleOAuthCallback(c *gin.Context) {
	// Get session IDs from query parameters
	authSessionID := c.Query("session")
	oauthSessionID := c.Query("oauth_session")

	if authSessionID == "" || oauthSessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "session parameters required"})
		return
	}

	// Get OAuth session
	oauthSession := s.oauthSessionStore.GetSession(oauthSessionID)
	if oauthSession == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "OAuth session not found or expired"})
		return
	}

	// SECURITY: Verify the OAuth session is linked to the provided auth session
	// This prevents an attacker from using a valid OAuth session with a different auth session
	if oauthSession.AuthSessionID != authSessionID {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "session mismatch"})
		return
	}

	// Get auth session
	authSession := s.sessionStore.GetSession(authSessionID)
	if authSession == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "auth session not found or expired"})
		return
	}

	// Read JWZ token from request body (same as normal auth callback)
	body, err := readLimitedBody(c.Request.Body, MaxRequestBodySize)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read request body"})
		return
	}

	jwzToken := extractJWZToken(body)
	if jwzToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "jwz_token required"})
		return
	}

	// Verify the proof and get user DID
	var userDID string
	if s.config.AllowMockLogin && len(jwzToken) > 5 && jwzToken[:5] == "mock." {
		// Extract DID from mock token
		parts := strings.Split(jwzToken, ".")
		if len(parts) >= 2 {
			userDID = parts[len(parts)-1]
			if !strings.HasPrefix(userDID, "did:") {
				userDID = "did:privado:" + userDID
			}
		}
		if userDID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid mock token format"})
			return
		}
	} else {
		userDID, err = s.privadoVerifier.VerifyJWZ(c.Request.Context(), jwzToken, authSession.AuthRequest, s.config.VerifierID)
		if err != nil {
			// Shared with the wallet-callback path. This used to be a second
			// copy of the same mapping and fell behind it: an unconfigured
			// wallet network was reported there and silently opaque here, even
			// though the login page drives both (RD-1241).
			s.respondVerificationError(c, "oauth", err)
			return
		}
	}

	// Get user KYC status from RBAC
	// RD-1131: new Privado users auto-KYC'd iff AUTO_KYC_PRIVADO (new rows only).
	kyc := s.config.AutoKYCPrivado
	if s.rbacAccessCtrl != nil {
		user, err := s.rbacAccessCtrl.EnsureUserExists(c.Request.Context(), userDID, kyc, false)
		if err == nil && user != nil {
			if user.Banned {
				c.JSON(http.StatusForbidden, gin.H{"error": "account is banned"})
				return
			}
			kyc = user.KYC
		}
	}

	// Generate authorization code
	code := generateSecureCode()

	// Store the code in the OAuth session
	if err := s.oauthSessionStore.SetCode(oauthSessionID, code, userDID, kyc); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate authorization code"})
		return
	}

	// Mark auth session as completed (for status polling)
	// We don't store the actual tokens here - those are issued at the token endpoint
	if err := s.sessionStore.CompleteSession(authSessionID, "", ""); err != nil {
		slog.Warn("failed to complete auth session", "session_id", authSessionID, "error", err)
	}

	// Build redirect URL with code and state
	redirectURL, err := url.Parse(oauthSession.RedirectURI)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid redirect URI"})
		return
	}

	q := redirectURL.Query()
	q.Set("code", code)
	q.Set("state", oauthSession.State)
	redirectURL.RawQuery = q.Encode()

	// Return the redirect URL (wallet will follow it)
	// Also return success for the wallet callback
	c.JSON(http.StatusOK, gin.H{
		"status":       "success",
		"redirect_url": redirectURL.String(),
	})
}

// handleOAuthToken handles POST /oauth/token - Token endpoint
// Exchanges authorization code for JWT access token
//
// @Summary      OAuth 2.0 token endpoint
// @Description  Exchanges an authorization code for access and refresh tokens. Only grant_type=authorization_code is supported; the code, client_id, and redirect_uri must match the session, the code must be unexpired and unused (single-use). First-party clients must additionally authenticate with their client secret, via HTTP Basic (client_secret_basic) or the client_secret body parameter (client_secret_post). Accepts JSON or form-encoded bodies. Rate-limited.
// @Tags         OAuth SSO
// @Accept       json
// @Accept       x-www-form-urlencoded
// @Produce      json
// @Param        request body OAuthTokenRequest true "authorization-code grant parameters"
// @Success      200 {object} OAuthTokenResponse
// @Failure      400 {object} OAuthErrorResponse "invalid_request, unsupported_grant_type, or invalid_grant"
// @Failure      401 {object} OAuthErrorResponse "invalid_client — client authentication failed"
// @Failure      500 {object} OAuthErrorResponse "server_error — failed to issue or persist tokens"
// @Router       /oauth/token [post]
func (s *Server) handleOAuthToken(c *gin.Context) {
	var req OAuthTokenRequest

	// Support both JSON and form-encoded requests (OAuth spec allows both)
	contentType := c.GetHeader("Content-Type")
	if strings.Contains(contentType, "application/json") {
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, OAuthErrorResponse{
				Error:            "invalid_request",
				ErrorDescription: "invalid request body",
			})
			return
		}
	} else {
		if err := c.ShouldBind(&req); err != nil {
			c.JSON(http.StatusBadRequest, OAuthErrorResponse{
				Error:            "invalid_request",
				ErrorDescription: "invalid request body",
			})
			return
		}
	}

	// Validate grant_type
	if req.GrantType != "authorization_code" {
		c.JSON(http.StatusBadRequest, OAuthErrorResponse{
			Error:            "unsupported_grant_type",
			ErrorDescription: "only grant_type=authorization_code is supported",
		})
		return
	}

	// Look up session by code
	session := s.oauthSessionStore.GetSessionByCode(req.Code)
	if session == nil {
		c.JSON(http.StatusBadRequest, OAuthErrorResponse{
			Error:            "invalid_grant",
			ErrorDescription: "authorization code not found or expired",
		})
		return
	}

	// Validate client_id matches
	if session.ClientID != req.ClientID {
		c.JSON(http.StatusBadRequest, OAuthErrorResponse{
			Error:            "invalid_grant",
			ErrorDescription: "client_id does not match",
		})
		return
	}

	// RD-1006: first-party clients must authenticate at the token endpoint.
	// Secret accepted via client_secret_basic (HTTP Basic, RFC 6749 §2.3.1
	// preferred) or client_secret_post (body parameter, RFC 6749 §2.3.1
	// alternative). Non-first-party clients are not currently supported on
	// this endpoint — they fall through silently (caught earlier by the
	// session lookup), but the gate here makes the intent explicit.
	if s.config.IsFirstPartyOAuthClient(req.ClientID) {
		secret := req.ClientSecret
		if basicUser, basicPass, ok := c.Request.BasicAuth(); ok && basicUser == req.ClientID {
			secret = basicPass
		}
		if !s.config.VerifyFirstPartyClientSecret(req.ClientID, secret) {
			slog.Warn("oauth token: first-party client authentication failed",
				"client_id", req.ClientID,
				"remote_ip", c.ClientIP())
			c.Header("WWW-Authenticate", `Basic realm="oauth_token"`)
			c.JSON(http.StatusUnauthorized, OAuthErrorResponse{
				Error:            "invalid_client",
				ErrorDescription: "client authentication failed",
			})
			return
		}
	}

	// Validate redirect_uri matches
	if session.RedirectURI != req.RedirectURI {
		c.JSON(http.StatusBadRequest, OAuthErrorResponse{
			Error:            "invalid_grant",
			ErrorDescription: "redirect_uri does not match",
		})
		return
	}

	// Check if code has expired
	if time.Now().After(session.CodeExpires) {
		c.JSON(http.StatusBadRequest, OAuthErrorResponse{
			Error:            "invalid_grant",
			ErrorDescription: "authorization code has expired",
		})
		return
	}

	// Mark code as used (single-use)
	if !s.oauthSessionStore.MarkCodeUsed(req.Code) {
		c.JSON(http.StatusBadRequest, OAuthErrorResponse{
			Error:            "invalid_grant",
			ErrorDescription: "authorization code has already been used",
		})
		return
	}

	// Issue access token (same JWT format as regular auth)
	accessToken, err := s.jwtService.IssueAccessToken(session.UserDID, session.KYC)
	if err != nil {
		c.JSON(http.StatusInternalServerError, OAuthErrorResponse{
			Error:            "server_error",
			ErrorDescription: "failed to issue access token",
		})
		return
	}

	// Issue refresh token so the client can obtain new access tokens without
	// a full re-authentication. The access token is intentionally short-lived
	// (AccessTokenTTL = 5 min) so that banning a user takes effect within one
	// TTL window — banned users are rejected at refresh time.
	refreshToken, err := s.jwtService.IssueRefreshToken(session.UserDID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, OAuthErrorResponse{
			Error:            "server_error",
			ErrorDescription: "failed to issue refresh token",
		})
		return
	}

	tokenHash := authpkg.HashToken(refreshToken)
	if err := s.db.SaveRefreshToken(c.Request.Context(), tokenHash, session.UserDID, time.Now().Add(RefreshTokenTTL)); err != nil {
		c.JSON(http.StatusInternalServerError, OAuthErrorResponse{
			Error:            "server_error",
			ErrorDescription: "failed to save refresh token",
		})
		return
	}

	// Return token response
	c.JSON(http.StatusOK, OAuthTokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(AccessTokenTTL.Seconds()),
	})
}

// OAuthSessionStatusResponse represents the response for OAuth session status polling
type OAuthSessionStatusResponse struct {
	Completed   bool   `json:"completed"`
	RedirectURL string `json:"redirect_url,omitempty"`
}

// handleOAuthSessionStatus handles GET /oauth/session/:id/status - poll for OAuth session completion
// Frontend polls this to check if the user has completed Privado auth
//
// @Summary      Poll an OAuth session for completion
// @Description  The frontend polls this during the QR scan to learn whether the user has completed authentication. While pending it returns `completed:false`; once complete it returns the client redirect URL with the authorization code and state. Deliberately not rate-limited: it is read-only polling during the login flow.
// @Tags         OAuth SSO
// @Produce      json
// @Param        id path string true "OAuth session ID"
// @Success      200 {object} OAuthSessionStatusResponse
// @Failure      400 {object} APIError "session ID required"
// @Failure      404 {object} APIError "session not found or expired"
// @Failure      500 {object} APIError "invalid redirect URI"
// @Router       /oauth/session/{id}/status [get]
func (s *Server) handleOAuthSessionStatus(c *gin.Context) {
	oauthSessionID := c.Param("id")
	if oauthSessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "session ID required"})
		return
	}

	oauthSession := s.oauthSessionStore.GetSession(oauthSessionID)
	if oauthSession == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found or expired"})
		return
	}

	// Check if code has been generated (means auth completed)
	if oauthSession.Code == "" {
		c.JSON(http.StatusOK, OAuthSessionStatusResponse{Completed: false})
		return
	}

	// Build redirect URL with code and state
	redirectURL, err := url.Parse(oauthSession.RedirectURI)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid redirect URI"})
		return
	}

	q := redirectURL.Query()
	q.Set("code", oauthSession.Code)
	q.Set("state", oauthSession.State)
	redirectURL.RawQuery = q.Encode()

	c.JSON(http.StatusOK, OAuthSessionStatusResponse{
		Completed:   true,
		RedirectURL: redirectURL.String(),
	})
}

// isValidRedirectURI validates that the redirect URI is allowed.
// Compares the full origin (scheme + host + port) against an allowlist:
// - localhost (any port) — development only
// - The configured BASE_URL origin
// - Configured CORS allowed origins (explicit list, not "*")
func (s *Server) isValidRedirectURI(uri string) bool {
	parsed, err := url.Parse(uri)
	if err != nil {
		return false
	}

	// Must be http or https
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}

	// Extract origin (scheme + host + port) from the redirect URI
	uriOrigin := parsed.Scheme + "://" + parsed.Host // Host includes port if present

	host := parsed.Hostname()

	// Allow localhost in development only
	if !s.config.IsProduction() {
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return true
		}
	}

	// Allow the configured BASE_URL origin (full origin match)
	if s.config.BaseURL != "" {
		baseURL, err := url.Parse(s.config.BaseURL)
		if err == nil {
			baseOrigin := baseURL.Scheme + "://" + baseURL.Host
			if uriOrigin == baseOrigin {
				return true
			}
		}
	}

	// Allow configured CORS origins (explicit list only, "*" does NOT allow arbitrary redirect URIs)
	if s.config.CORSAllowedOrigins != "" && s.config.CORSAllowedOrigins != "*" {
		for _, origin := range strings.Split(s.config.CORSAllowedOrigins, ",") {
			origin = strings.TrimSpace(origin)
			if origin != "" && origin == uriOrigin {
				return true
			}
		}
	}

	return false
}

// scheduleOAuthDemoAutoAuth schedules automatic OAuth session completion for demo mode
func (s *Server) scheduleOAuthDemoAutoAuth(oauthSessionID, authSessionID string) {
	delay := s.config.DemoAutoAuthDelay
	if delay <= 0 || s.config.IsProduction() {
		return
	}

	go func() {
		time.Sleep(delay)

		// Check if OAuth session still pending
		oauthSession := s.oauthSessionStore.GetSession(oauthSessionID)
		if oauthSession == nil || oauthSession.Code != "" {
			return
		}

		// Generate mock DID and complete the OAuth flow
		mockDID := fmt.Sprintf("did:privado:demo_%d", time.Now().UnixNano())
		kyc := false
		if s.rbacAccessCtrl != nil {
			if user, err := s.rbacAccessCtrl.EnsureUserExists(context.Background(), mockDID, kyc, false); err == nil && user != nil {
				kyc = user.KYC
			}
		}

		// Generate authorization code
		code := generateSecureCode()
		if err := s.oauthSessionStore.SetCode(oauthSessionID, code, mockDID, kyc); err != nil {
			slog.Error("demo OAuth auto-auth: failed to set code", "error", err)
			return
		}

		// Mark auth session as completed
		if err := s.sessionStore.CompleteSession(authSessionID, "", ""); err != nil {
			slog.Error("demo OAuth auto-auth: failed to complete auth session", "error", err)
		}

		slog.Info("demo OAuth auto-auth: session completed", "session_id", oauthSessionID, "did", mockDID)
	}()
}

// Helper functions

// readLimitedBody reads a request body with a size limit
func readLimitedBody(body interface{ Read([]byte) (int, error) }, maxSize int64) ([]byte, error) {
	buf := make([]byte, 0, 1024)
	total := int64(0)
	for {
		if total >= maxSize {
			return nil, fmt.Errorf("body too large")
		}
		chunk := make([]byte, 1024)
		n, err := body.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
			total += int64(n)
		}
		if err != nil {
			break
		}
	}
	return buf, nil
}

// extractJWZToken extracts the JWZ token from the request body
// Supports both JSON format and plain string
func extractJWZToken(body []byte) string {
	// Try JSON parsing
	var tokenPayload map[string]interface{}
	if err := json.Unmarshal(body, &tokenPayload); err == nil {
		if token, ok := tokenPayload["token"].(string); ok {
			return token
		}
		if token, ok := tokenPayload["jwz_token"].(string); ok {
			return token
		}
	}
	// Fall back to plain string
	return strings.TrimSpace(string(body))
}
