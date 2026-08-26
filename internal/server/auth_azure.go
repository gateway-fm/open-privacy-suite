package server

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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
	// Networks lists the iden3 "blockchain:network" identifiers this deployment
	// has a state resolver for (e.g. ["billions:main","privado:main"]). The
	// login UI uses it to avoid advertising a wallet network that cannot be
	// verified here (RD-1241). Always present, possibly empty.
	Networks []string `json:"networks"`
}

// handleAzureAuthURL handles GET /api/v1/auth/azure/url.
// Returns the Microsoft authorization URL and a CSRF state token.
//
// @Summary      Get the Azure AD authorization URL
// @Description  Returns the Microsoft Entra ID authorization URL to redirect the user to, plus a single-use CSRF state token to replay at the callback. The `redirect_uri` must be on the server's allowlist. Available only when Azure AD is configured. Rate-limited.
// @Tags         Auth
// @Produce      json
// @Param        redirect_uri query string true "post-login redirect URI (must be allowlisted)"
// @Success      200 {object} AzureURLResponse
// @Failure      400 {object} APIError "redirect_uri missing or not allowed"
// @Failure      404 {object} APIError "Azure AD authentication not configured"
// @Router       /api/v1/auth/azure/url [get]
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

	if !s.isValidRedirectURI(redirectURI) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "redirect_uri is not allowed"})
		return
	}

	state, nonce := s.azureStateStore.Create()
	url := s.azureAuthenticator.GetAuthorizationURL(redirectURI, state, nonce)
	c.JSON(http.StatusOK, AzureURLResponse{URL: url, State: state})
}

// handleAzureCallback handles POST /api/v1/auth/azure/callback.
// Validates CSRF state, exchanges the authorization code, and issues our JWT tokens.
//
// @Summary      Complete Azure AD interactive login
// @Description  Validates the single-use CSRF state, exchanges the Azure AD authorization code, enforces the tenant allowlist, provisions the RBAC user, and issues our access + refresh tokens. Available only when Azure AD is configured. Rate-limited.
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        request body AzureCallbackRequest true "authorization code, CSRF state, and redirect URI"
// @Success      200 {object} AuthResponse
// @Failure      400 {object} APIError "invalid request, redirect_uri not allowed, or invalid/expired state token"
// @Failure      401 {object} APIError "Azure AD authentication failed or invalid tenant ID in token"
// @Failure      403 {object} APIError "tenant not authorized, auto-provisioning disabled, tenant mismatch, or account banned"
// @Failure      404 {object} APIError "Azure AD authentication not configured"
// @Failure      500 {object} APIError "failed to check tenant authorization, provision user, or issue tokens"
// @Router       /api/v1/auth/azure/callback [post]
func (s *Server) handleAzureCallback(c *gin.Context) {
	if s.azureAuthenticator == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Azure AD authentication not configured"})
		return
	}

	var req AzureCallbackRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request format"})
		return
	}

	// Validate redirect_uri against allowlist
	if !s.isValidRedirectURI(req.RedirectURI) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "redirect_uri is not allowed"})
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
		s.recordAuthAttempt("azure_ad", "error")
		slog.Error("Azure AD code exchange failed", "error", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Azure AD authentication failed"})
		return
	}

	s.completeAzureLogin(c, identity, "azure_ad", s.config.AutoKYCAzureUser)
}

// completeAzureLogin runs the shared post-identity flow for both Azure AD login
// paths — the interactive authorization-code flow (handleAzureCallback) and the
// service-principal client-credentials flow (handleAzureServicePrincipal). It
// enforces the tenant allowlist, auto-provisions the RBAC user, issues our
// local access + refresh tokens, and writes the HTTP response. Both paths share
// this so the security gates (allowlist, ban, tenant-pinning, group assignment)
// can never drift apart. providerMetric is the recordAuthAttempt provider label.
func (s *Server) completeAzureLogin(c *gin.Context, identity *auth.AzureIdentity, providerMetric string, autoKYCNewUser bool) {
	// Validate tid is a valid UUID before using it for lookups
	if _, parseErr := uuid.Parse(identity.TenantID); parseErr != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid tenant ID in token"})
		return
	}

	// --- Tenant allowlist gate ---
	// Check if the user's Azure AD tenant is in the allowlist.
	tenantConfig, err := s.db.GetAllowedAzureTenantByTenantID(c.Request.Context(), identity.TenantID)
	if err != nil {
		slog.Error("failed to check Azure tenant allowlist", "tenant_id", identity.TenantID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check tenant authorization"})
		return
	}
	if tenantConfig == nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "your Azure AD tenant is not authorized"})
		return
	}

	subject := auth.AzureSubject(identity.OID)

	// Ensure user exists in RBAC system and retrieve their KYC status.
	// RD-1131: a NEW user is created KYC-verified iff its class opted in via
	// auto-KYC config (azure_user vs azure_service_principal — set by the caller);
	// existing users keep their admin-managed KYC (re-read below).
	kyc := autoKYCNewUser
	if s.rbacAccessCtrl != nil {
		if !tenantConfig.AutoProvision {
			// Auto-provision disabled: only allow login if user already exists
			existing, getErr := s.db.GetUserByExternalID(c.Request.Context(), subject)
			if getErr != nil {
				slog.Warn("failed to check user existence", "subject", subject, "error", getErr)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check user status"})
				return
			}
			if existing == nil {
				c.JSON(http.StatusForbidden, gin.H{"error": "auto-provisioning is disabled for your tenant and no existing account was found"})
				return
			}
			if existing.Banned {
				c.JSON(http.StatusForbidden, gin.H{"error": "account is banned"})
				return
			}
			kyc = existing.KYC
			// Pin auth_tenant_id if not yet set (immutable after first write).
			if existing.AuthTenantID == nil {
				if _, err := s.db.SetAuthTenantID(c.Request.Context(), existing.ID, identity.TenantID); err != nil {
					slog.Warn("failed to set auth_tenant_id", "subject", subject, "error", err)
				}
				existing.AuthTenantID = &identity.TenantID
			} else if *existing.AuthTenantID != identity.TenantID {
				slog.Warn("user tenant mismatch", "subject", subject, "existing_tenant", *existing.AuthTenantID, "login_tenant", identity.TenantID)
				c.JSON(http.StatusForbidden, gin.H{"error": "account is associated with a different Azure AD tenant"})
				return
			}
		} else {
			// Skip default group if tenant configures a specific group — user will be added there instead
			skipDefaultGroup := tenantConfig.DefaultOrgID != nil && tenantConfig.DefaultGroupID != nil
			user, ensureErr := s.rbacAccessCtrl.EnsureUserExists(c.Request.Context(), subject, kyc, skipDefaultGroup)
			if ensureErr != nil {
				slog.Error("failed to ensure RBAC user", "subject", subject, "error", ensureErr)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to provision user account"})
				return
			}
			if user != nil {
				if user.Banned {
					c.JSON(http.StatusForbidden, gin.H{"error": "account is banned"})
					return
				}
				kyc = user.KYC

				// Pin auth_tenant_id if not yet set (immutable after first write).
				if user.AuthTenantID == nil {
					if _, err := s.db.SetAuthTenantID(c.Request.Context(), user.ID, identity.TenantID); err != nil {
						slog.Warn("failed to set auth_tenant_id", "subject", subject, "error", err)
					}
					user.AuthTenantID = &identity.TenantID
				} else if *user.AuthTenantID != identity.TenantID {
					slog.Warn("user tenant mismatch", "subject", subject, "existing_tenant", *user.AuthTenantID, "login_tenant", identity.TenantID)
					c.JSON(http.StatusForbidden, gin.H{"error": "account is associated with a different Azure AD tenant"})
					return
				}

				// Auto-add user to tenant's configured group (idempotent — safe against concurrent logins)
				if tenantConfig.DefaultOrgID != nil && tenantConfig.DefaultGroupID != nil {
					membership := &rbac.UserMembership{
						ID:      uuid.New().String(),
						UserID:  user.ID,
						GroupID: *tenantConfig.DefaultGroupID,
						Source:  "auto_provision",
					}
					created, createErr := s.db.CreateMembershipIfNotExists(c.Request.Context(), membership)
					if createErr != nil {
						// Tenant group assignment failed — fall back to default group so user isn't orphaned
						slog.Warn("failed to auto-add user to tenant group, falling back to default", "subject", subject, "group_id", *tenantConfig.DefaultGroupID, "error", createErr)
						fallback := &rbac.UserMembership{
							ID:      uuid.New().String(),
							UserID:  user.ID,
							GroupID: rbac.DefaultGroupID,
							Source:  "auto_provision",
						}
						if _, fbErr := s.db.CreateMembershipIfNotExists(c.Request.Context(), fallback); fbErr != nil {
							slog.Warn("fallback to default group also failed", "subject", subject, "error", fbErr)
						}
					} else if created {
						slog.Info("auto-provisioned membership for user", "subject", subject, "group_id", *tenantConfig.DefaultGroupID)
					}
				}
			}
		}
	}

	// Issue access token (short-lived)
	accessToken, err := s.jwtService.IssueAccessToken(subject, kyc)
	if err != nil {
		// JWT signing errors expose key-material state; never to client. RD-934.
		respondInternalErrorAndLog(c, "failed to issue access token",
			"auth_azure: IssueAccessToken failed", "subject", subject, "err", err)
		return
	}

	// Issue refresh token (long-lived)
	refreshToken, err := s.jwtService.IssueRefreshToken(subject)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to issue refresh token",
			"auth_azure: IssueRefreshToken failed", "subject", subject, "err", err)
		return
	}

	// Persist refresh token
	tokenHash := auth.HashToken(refreshToken)
	expiresAt := time.Now().Add(RefreshTokenTTL)
	if err := s.db.SaveRefreshToken(c.Request.Context(), tokenHash, subject, expiresAt); err != nil {
		respondInternalErrorAndLog(c, "failed to save refresh token",
			"auth_azure: SaveRefreshToken failed", "subject", subject, "err", err)
		return
	}

	s.recordAuthAttempt(providerMetric, "success")

	c.JSON(http.StatusOK, AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(AccessTokenTTL.Seconds()),
	})
}

// AzureServicePrincipalRequest is the body for
// POST /api/v1/auth/azure/service-principal. The client obtains the Azure AD
// access token out-of-band via the OAuth2 client-credentials grant
// (`scope=<resource>/.default`) against its own tenant, then exchanges it here
// for our local tokens.
type AzureServicePrincipalRequest struct {
	AccessToken string `json:"access_token" binding:"required"`
}

// handleAzureServicePrincipal handles POST /api/v1/auth/azure/service-principal.
//
// Machine-to-machine (M2M) login for Azure AD service principals (RD-1120). The
// client authenticates non-interactively via the client-credentials grant and
// posts the resulting Azure AD access token. We verify it (signature/JWKS,
// expiry, audience), then run the same tenant-allowlist + provisioning +
// token-issuance flow as the interactive path so the SP can call /rpc with our
// standard Bearer access token.
//
// @Summary      Azure AD service-principal (M2M) login
// @Description  Machine-to-machine login for Azure AD service principals. The client obtains an Azure AD access token out-of-band via the client-credentials grant and posts it here; the proxy verifies it (signature/JWKS, expiry, audience), enforces the tenant allowlist, provisions the RBAC user, and issues our access + refresh tokens. Available only when Azure AD is configured. Rate-limited.
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        request body AzureServicePrincipalRequest true "Azure AD access token from the client-credentials grant"
// @Success      200 {object} AuthResponse
// @Failure      400 {object} APIError "invalid request format"
// @Failure      401 {object} APIError "Azure AD authentication failed or invalid tenant ID in token"
// @Failure      403 {object} APIError "tenant not authorized, auto-provisioning disabled, tenant mismatch, or account banned"
// @Failure      404 {object} APIError "Azure AD authentication not configured"
// @Failure      500 {object} APIError "failed to check tenant authorization, provision user, or issue tokens"
// @Router       /api/v1/auth/azure/service-principal [post]
func (s *Server) handleAzureServicePrincipal(c *gin.Context) {
	if s.azureAuthenticator == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Azure AD authentication not configured"})
		return
	}

	var req AzureServicePrincipalRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request format"})
		return
	}

	identity, err := s.azureAuthenticator.VerifyAccessToken(c.Request.Context(), req.AccessToken)
	if err != nil {
		s.recordAuthAttempt("azure_ad_sp", "error")
		// Keep the verbose reason in slog only; never echo token-validation
		// detail to the client.
		slog.Warn("Azure AD service-principal token verification failed", "error", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Azure AD authentication failed"})
		return
	}

	s.completeAzureLogin(c, identity, "azure_ad_sp", s.config.AutoKYCAzureServicePrincipal)
}

// handleAuthProviders handles GET /api/v1/auth/providers.
// Returns the list of configured authentication provider identifiers.
//
// @Summary      List configured auth providers
// @Description  Returns the identifiers of the authentication providers this deployment has configured (always includes "privado"; adds "azuread" when Azure AD is enabled), plus the iden3 identity networks it has a state resolver for (e.g. "privado:main", "billions:main"), so the login UI can render the right options and avoid advertising a wallet network this deployment cannot verify. Deployment capability only -- no tenant or user data. Public.
// @Tags         Auth
// @Produce      json
// @Success      200 {object} ProvidersResponse
// @Router       /api/v1/auth/providers [get]
func (s *Server) handleAuthProviders(c *gin.Context) {
	providers := []string{"privado"}
	if s.azureAuthenticator != nil {
		providers = append(providers, "azuread")
	}
	c.JSON(http.StatusOK, ProvidersResponse{
		Providers: providers,
		Networks:  s.registeredNetworks(),
	})
}

// registeredNetworks returns the iden3 networks the verifier can resolve, or an
// empty (never nil) slice when no verifier is wired. Failing closed matters:
// advertising a network we cannot confirm is exactly the false promise RD-1241
// removes, so an absent verifier advertises nothing.
func (s *Server) registeredNetworks() []string {
	if s.privadoVerifier == nil {
		return []string{}
	}
	networks := s.privadoVerifier.RegisteredNetworks()
	if networks == nil {
		return []string{}
	}
	return networks
}
