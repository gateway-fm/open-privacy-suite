package server

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"sync"
	"time"

	"privacy-proxy/internal/auth"

	"github.com/gin-gonic/gin"
)

// TTL constants for Azure AD state tokens.
const (
	AzureStateTTL             = 10 * time.Minute
	AzureStateCleanupInterval = 1 * time.Minute
)

// azureStateEntry stores the nonce alongside a CSRF state token.
type azureStateEntry struct {
	nonce     string
	createdAt time.Time
}

// AzureStateStore is a thread-safe, TTL-expiring CSRF state store for Azure AD logins.
// Each state token is single-use: Consume removes it from the store.
type AzureStateStore struct {
	mu      sync.Mutex
	entries map[string]*azureStateEntry
	ttl     time.Duration
	stop    chan struct{}
}

// NewAzureStateStore creates a store with a background TTL cleanup goroutine.
func NewAzureStateStore(ttl, cleanupInterval time.Duration) *AzureStateStore {
	s := &AzureStateStore{
		entries: make(map[string]*azureStateEntry),
		ttl:     ttl,
		stop:    make(chan struct{}),
	}
	go s.cleanupLoop(cleanupInterval)
	return s
}

// Create generates a cryptographically random (state, nonce) pair and stores them.
func (s *AzureStateStore) Create() (state, nonce string) {
	state = randomToken(16)
	nonce = randomToken(16)
	s.mu.Lock()
	s.entries[state] = &azureStateEntry{nonce: nonce, createdAt: time.Now()}
	s.mu.Unlock()
	return state, nonce
}

// Consume validates a state token and returns its associated nonce.
// The entry is removed on success (single-use). Returns ok=false if missing or expired.
func (s *AzureStateStore) Consume(state string) (nonce string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, exists := s.entries[state]
	if !exists {
		return "", false
	}
	if time.Since(entry.createdAt) > s.ttl {
		delete(s.entries, state)
		return "", false
	}
	nonce = entry.nonce
	delete(s.entries, state)
	return nonce, true
}

// Stop terminates the background cleanup goroutine.
func (s *AzureStateStore) Stop() {
	close(s.stop)
}

func (s *AzureStateStore) cleanupLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.cleanup()
		case <-s.stop:
			return
		}
	}
}

func (s *AzureStateStore) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for state, entry := range s.entries {
		if now.Sub(entry.createdAt) > s.ttl {
			delete(s.entries, state)
		}
	}
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// --- Handlers ---

// AzureURLResponse is the response from GET /api/v1/auth/azure/url.
type AzureURLResponse struct {
	URL   string `json:"url"`
	State string `json:"state"`
}

// AzureCallbackRequest is the body for POST /api/v1/auth/azure/callback.
type AzureCallbackRequest struct {
	Code        string `json:"code" binding:"required"`
	State       string `json:"state" binding:"required"`
	RedirectURI string `json:"redirect_uri" binding:"required"`
}

// ProvidersResponse is the response from GET /api/v1/auth/providers.
type ProvidersResponse struct {
	Providers []string `json:"providers"`
}

// handleAzureAuthURL handles GET /api/v1/auth/azure/url.
// Returns the Microsoft authorization URL and a CSRF state token.
func (s *Server) handleAzureAuthURL(c *gin.Context) {
	if s.azureAuthenticator == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Azure AD authentication not configured"})
		return
	}

	redirectURI := c.Query("redirect_uri")
	if redirectURI == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "redirect_uri query parameter required"})
		return
	}

	state, nonce := s.azureStateStore.Create()
	url := s.azureAuthenticator.GetAuthorizationURL(redirectURI, state, nonce)
	c.JSON(http.StatusOK, AzureURLResponse{URL: url, State: state})
}

// handleAzureCallback handles POST /api/v1/auth/azure/callback.
// Validates CSRF state, exchanges the authorization code, and issues our JWT tokens.
func (s *Server) handleAzureCallback(c *gin.Context) {
	if s.azureAuthenticator == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Azure AD authentication not configured"})
		return
	}

	var req AzureCallbackRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}

	// Validate CSRF state — single-use, TTL-enforced
	nonce, ok := s.azureStateStore.Consume(req.State)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired state token"})
		return
	}

	// Exchange authorization code for verified Azure identity
	identity, err := s.azureAuthenticator.ExchangeCode(c.Request.Context(), req.Code, req.RedirectURI, nonce)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Azure AD authentication failed: " + err.Error()})
		return
	}

	subject := auth.AzureSubject(identity.OID)

	// Ensure user exists in RBAC system and retrieve their KYC status
	kyc := false
	if s.rbacAccessCtrl != nil {
		user, ensureErr := s.rbacAccessCtrl.EnsureUserExists(c.Request.Context(), subject, kyc)
		if ensureErr != nil {
			log.Printf("Warning: failed to ensure RBAC user for %s: %v", subject, ensureErr)
		} else if user != nil {
			kyc = user.KYC
		}
	}

	// Issue access token (short-lived)
	accessToken, err := s.jwtService.IssueAccessToken(subject, kyc)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue access token: " + err.Error()})
		return
	}

	// Issue refresh token (long-lived)
	refreshToken, err := s.jwtService.IssueRefreshToken(subject)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue refresh token: " + err.Error()})
		return
	}

	// Persist refresh token
	tokenHash := auth.HashToken(refreshToken)
	expiresAt := time.Now().Add(RefreshTokenTTL)
	if err := s.db.SaveRefreshToken(c.Request.Context(), tokenHash, subject, expiresAt); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save refresh token: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(AccessTokenTTL.Seconds()),
	})
}

// handleAuthProviders handles GET /api/v1/auth/providers.
// Returns the list of configured authentication provider identifiers.
func (s *Server) handleAuthProviders(c *gin.Context) {
	providers := []string{"privado"}
	if s.azureAuthenticator != nil {
		providers = append(providers, "azuread")
	}
	c.JSON(http.StatusOK, ProvidersResponse{Providers: providers})
}
