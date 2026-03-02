package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/compliance"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/disclosure"
	"privacy-proxy/internal/ens"
	"privacy-proxy/internal/evm/create3"
	"privacy-proxy/internal/pricing"
	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/tracer"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/iden3/iden3comm/v2/protocol"
)

// TTL constants for various components
const (
	// JWT token TTLs
	AccessTokenTTL  = 30 * time.Minute
	RefreshTokenTTL = 7 * 24 * time.Hour

	// Cache and store TTLs
	RBACCacheTTL             = 5 * time.Minute
	SessionTTL               = 10 * time.Minute
	SessionCleanupInterval   = 1 * time.Minute
	ChallengeTTL             = 5 * time.Minute
	ChallengeCleanupInterval = 1 * time.Minute

	// Rate limiter cleanup interval
	RateLimiterCleanupInterval = 10 * time.Second

	// ENS resolution timeout
	ENSResolutionTimeout = 30 * time.Second

	// devVerifierDID is a valid placeholder DID used in dev mode when VERIFIER_ID is not configured.
	// Uses did:pkh (public key hash) which the Privado wallet can parse without on-chain resolution.
	devVerifierDID = "did:pkh:eip155:1:0x0000000000000000000000000000000000000001"
)

type Server struct {
	db                *db.DB
	rbacAccessCtrl    *rbac.AccessController
	proxy             *proxy.Proxy
	privadoVerifier   PrivadoVerifier
	jwtService        *auth.JWTService
	sessionStore      SessionManager
	oauthSessionStore *OAuthSessionStore
	challengeStore    *ChallengeStore
	rateLimiter       RateLimiterInterface
	authRateLimiter   *AuthRateLimiter
	disclosureService *disclosure.DefaultService
	complianceChecker *compliance.Checker
	priceService      *pricing.Service
	config            *config.Config
	ensResolver       *ens.Resolver
	jsonrpcProcessor  *JSONRPCProcessor
	zkRoleExtractor   *auth.ZKRoleExtractor
	runtimeTracer     *tracer.RuntimeTracer
	retentionCleaner  *audit.RetentionCleaner
	siemForwarder     *audit.SIEMForwarder
	azureAuthenticator *auth.AzureADAuthenticator
	azureStateStore    *AzureStateStore
}

// DB returns the database instance (for testing)
func (s *Server) DB() *db.DB {
	return s.db
}

// Stop gracefully stops all background goroutines.
// Should be called before server shutdown.
func (s *Server) Stop() {
	if s.sessionStore != nil {
		s.sessionStore.Stop()
	}
	if s.oauthSessionStore != nil {
		s.oauthSessionStore.Stop()
	}
	if s.rateLimiter != nil {
		s.rateLimiter.Stop()
	}
	if s.authRateLimiter != nil {
		s.authRateLimiter.Stop()
	}
	if s.challengeStore != nil {
		s.challengeStore.Stop()
	}
	if s.rbacAccessCtrl != nil {
		s.rbacAccessCtrl.Stop()
	}
	if s.priceService != nil {
		s.priceService.Stop()
	}
	if s.runtimeTracer != nil {
		s.runtimeTracer.Stop()
	}
	if s.siemForwarder != nil {
		s.siemForwarder.Stop()
	}
	if s.retentionCleaner != nil {
		s.retentionCleaner.Stop()
	}
	if s.azureStateStore != nil {
		s.azureStateStore.Stop()
	}
	if s.db != nil {
		s.db.Close()
	}
}

// PrivadoVerifier interface for Privado ID operations
type PrivadoVerifier interface {
	CreateAuthorizationRequest(verifierID, callbackURL, reason string) (*protocol.AuthorizationRequestMessage, error)
	CreateHumanityAuthRequest(verifierID, callbackURL, reason, issuerDID string) (*protocol.AuthorizationRequestMessage, error)
	VerifyJWZ(ctx context.Context, jwzToken string, authRequest *protocol.AuthorizationRequestMessage, verifierID string) (string, error)
	VerifyJWZWithProofData(ctx context.Context, jwzToken string, authRequest *protocol.AuthorizationRequestMessage, verifierID string) (*auth.VerificationResult, error)
}

func New(cfg *config.Config) (*Server, error) {
	return NewWithVerifier(cfg, nil)
}

// NewWithVerifier creates a new server with an optional PrivadoVerifier
// If verifier is nil, creates a real PrivadoVerifier from config
// This allows injecting a mock verifier for testing
func NewWithVerifier(cfg *config.Config, verifier PrivadoVerifier) (*Server, error) {
	database, err := db.New(cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create database: %w", err)
	}

	// Initialize Privado ID verifier
	var privadoVerifier PrivadoVerifier
	if verifier != nil {
		privadoVerifier = verifier
	} else {
		privadoVerifier, err = auth.NewPrivadoVerifier(cfg.PrivadoRPCURL, cfg.IPFSGateway)
		if err != nil {
			database.Close()
			return nil, fmt.Errorf("failed to create Privado verifier: %w", err)
		}
	}

	// Initialize JWT service
	jwtService, err := auth.NewJWTService(
		cfg.JWTSecret,
		cfg.JWTRefreshSecret,
		AccessTokenTTL,
		RefreshTokenTTL,
	)
	if err != nil {
		database.Close()
		return nil, fmt.Errorf("failed to create JWT service: %w", err)
	}

	proxySvc := proxy.New(cfg.NodeURL)

	// Initialize RBAC access controller
	// Note: Unregistered address handling is now controlled by default_claims in GroupAccess
	rbacAccessCtrl := rbac.NewAccessController(database, RBACCacheTTL)
	rbacAccessCtrl.SetAllowUnregisteredAddresses(cfg.AllowUnregisteredAddresses)

	// Configure runtime tracing mode for deployment validation
	// When enabled, contracts with dynamic calls are allowed at deploy time
	// because those calls will be validated at runtime via debug_traceCall
	if cfg.EnableRuntimeTracing {
		rbacAccessCtrl.SetRuntimeTracingEnabled(true)
	}

	// Load additional trusted factory hashes from config
	if len(cfg.TrustedFactoryHashes) > 0 {
		for _, hash := range cfg.TrustedFactoryHashes {
			create3.AddTrustedFactory(create3.TrustedFactory{
				Name:         "Custom factory (from TRUSTED_FACTORY_HASHES env)",
				BytecodeHash: hash,
				Source:       "environment variable",
			})
		}
		fmt.Printf("Loaded %d additional trusted factory hashes from config\n", len(cfg.TrustedFactoryHashes))
	}

	// Initialize session store
	sessionStore := auth.NewSessionStore(SessionTTL, SessionCleanupInterval)

	// Initialize challenge store for ETH address linking
	challengeStore := NewChallengeStore(ChallengeTTL, ChallengeCleanupInterval)

	// Initialize rate limiter
	rateLimiter := NewRateLimiter(RateLimiterCleanupInterval)

	// Initialize auth rate limiter for protecting auth endpoints from brute force
	// Use relaxed limits in development/testing to avoid issues during E2E tests
	var authRateLimiterCfg AuthRateLimiterConfig
	if cfg.IsProduction() {
		authRateLimiterCfg = DefaultAuthRateLimiterConfig()
	} else {
		authRateLimiterCfg = DevAuthRateLimiterConfig()
	}
	authRateLimiter := NewAuthRateLimiter(authRateLimiterCfg)

	// Initialize ENS resolver (optional - may fail if no mainnet RPC available)
	var ensResolver *ens.Resolver
	if cfg.ENSResolverURL != "" {
		ensResolver, err = ens.NewResolver(cfg.ENSResolverURL)
		if err != nil {
			// Log warning but don't fail - ENS resolution is optional
			fmt.Printf("Warning: failed to create ENS resolver: %v\n", err)
		}
	}

	// Initialize Azure AD authenticator (optional — only when credentials are configured)
	var azureAuthenticator *auth.AzureADAuthenticator
	var azureStateStore *AzureStateStore
	if cfg.AzureADEnabled() {
		azureAuthenticator, err = auth.NewAzureADAuthenticator(cfg.AzureADClientID, cfg.AzureADClientSecret, cfg.AzureADTenantID)
		if err != nil {
			// Log warning but don't fail — Azure AD is optional
			fmt.Printf("Warning: failed to initialize Azure AD authenticator: %v\n", err)
		} else {
			azureStateStore = NewAzureStateStore(AzureStateTTL, AzureStateCleanupInterval)
			fmt.Printf("Azure AD authentication enabled (tenant: %s)\n", cfg.AzureADTenantID)
		}
	}

	// Initialize ZK role extractor for extracting role claims from Privado proofs
	zkRoleExtractor := auth.NewZKRoleExtractor(database)

	// Initialize disclosure service
	disclosureService := disclosure.NewService(database)

	// Initialize OAuth session store
	oauthSessionStore := NewOAuthSessionStore(OAuthSessionTTL, OAuthCleanupInterval, DefaultMaxOAuthSessions)

	// Initialize runtime tracer (optional - only when enabled)
	var runtimeTracer *tracer.RuntimeTracer
	var traceValidator *rbac.TraceValidator
	if cfg.EnableRuntimeTracing {
		runtimeTracer = tracer.NewRuntimeTracer(tracer.RuntimeTracerConfig{
			NodeURL:       cfg.NodeURL,
			Enabled:       true,
			CacheTTL:      cfg.TraceCacheTTL,
			Timeout:       cfg.TraceTimeout,
			TieredEnabled: cfg.TraceTieredValidation,
		})
		traceValidator = rbac.NewTraceValidator(database)
		fmt.Printf("Runtime tracing enabled (cache TTL: %v, timeout: %v, tiered: %v)\n",
			cfg.TraceCacheTTL, cfg.TraceTimeout, cfg.TraceTieredValidation)
	}

	s := &Server{
		db:                 database,
		rbacAccessCtrl:     rbacAccessCtrl,
		proxy:              proxySvc,
		privadoVerifier:    privadoVerifier,
		jwtService:         jwtService,
		sessionStore:       sessionStore,
		oauthSessionStore:  oauthSessionStore,
		challengeStore:     challengeStore,
		rateLimiter:        rateLimiter,
		authRateLimiter:    authRateLimiter,
		disclosureService:  disclosureService,
		config:             cfg,
		ensResolver:        ensResolver,
		zkRoleExtractor:    zkRoleExtractor,
		runtimeTracer:      runtimeTracer,
		azureAuthenticator: azureAuthenticator,
		azureStateStore:    azureStateStore,
	}

	// Initialize JSON-RPC processor with dependencies
	if runtimeTracer != nil {
		s.jsonrpcProcessor = NewJSONRPCProcessorWithTracing(rbacAccessCtrl, rateLimiter, proxySvc, database, runtimeTracer, traceValidator)
	} else {
		s.jsonrpcProcessor = NewJSONRPCProcessor(rbacAccessCtrl, rateLimiter, proxySvc, database)
	}

	// Initialize compliance checker for travel rule enforcement
	if cfg.EnableTravelRule {
		checker := compliance.NewChecker(database, cfg.TravelRecordExpiry, cfg.PriceStalenessThreshold)
		s.complianceChecker = checker
		s.jsonrpcProcessor.SetComplianceChecker(checker)
		log.Printf("Travel rule compliance enabled (record expiry: %s)", cfg.TravelRecordExpiry)

		// Start background CoinGecko price fetcher
		priceSvc := pricing.NewService(database, cfg.PriceFetchInterval)
		priceSvc.Start()
		s.priceService = priceSvc
	} else {
		log.Printf("WARNING: Travel rule compliance is DISABLED (ENABLE_TRAVEL_RULE=false). Value transfers will NOT be checked against thresholds or sanctions lists.")
	}

	// Initialize enhanced audit: hash chain, SIEM forwarder, retention cleaner
	hashChainSeed, err := database.GetLatestAccessLogHash(context.Background())
	if err != nil {
		log.Printf("Warning: failed to seed hash chain from DB: %v (starting fresh)", err)
	}
	hashChain := audit.NewHashChain(hashChainSeed)

	// Initialize SIEM forwarder if webhook URL is configured
	var siemForwarder *audit.SIEMForwarder
	if cfg.SIEMWebhookURL != "" {
		siemForwarder = audit.NewSIEMForwarder(audit.SIEMConfig{
			WebhookURL:    cfg.SIEMWebhookURL,
			AuthHeader:    cfg.SIEMAuthHeader,
			BatchSize:     cfg.SIEMBatchSize,
			FlushInterval: cfg.SIEMFlushInterval,
		})
		s.siemForwarder = siemForwarder
		log.Printf("SIEM forwarding enabled (webhook: %s, batch size: %d, flush interval: %s)",
			cfg.SIEMWebhookURL, cfg.SIEMBatchSize, cfg.SIEMFlushInterval)
	}

	// Wire enhanced audit into JSON-RPC processor
	s.jsonrpcProcessor.SetEnhancedAudit(database, hashChain, siemForwarder, cfg.AuditLogParams)

	// Initialize retention cleaner
	retentionCleaner := audit.NewRetentionCleaner(audit.RetentionConfig{
		AccessLogs:      cfg.RetentionAccessLogs,
		ComplianceLogs:  cfg.RetentionComplianceLogs,
		RBACAuditLogs:   cfg.RetentionRBACAuditLogs,
		TravelRecords:   cfg.RetentionTravelRecords,
		CleanupInterval: cfg.RetentionCleanupInterval,
	}, database, cfg.EnableTravelRule)
	s.retentionCleaner = retentionCleaner
	log.Printf("Retention cleaner started (access: %s, compliance: %s, rbac: %s, travel: %s, interval: %s)",
		cfg.RetentionAccessLogs, cfg.RetentionComplianceLogs, cfg.RetentionRBACAuditLogs,
		cfg.RetentionTravelRecords, cfg.RetentionCleanupInterval)

	return s, nil
}

func (s *Server) Run(addr string) error {
	router := s.setupRouter()
	return router.Run(addr)
}

// RunWithServer runs the server with a custom http.Server for graceful shutdown support.
func (s *Server) RunWithServer(httpServer *http.Server) error {
	router := s.setupRouter()
	httpServer.Handler = router
	return httpServer.ListenAndServe()
}

func (s *Server) setupRouter() *gin.Engine {
	router := gin.Default()

	// Trust Docker network proxies (allows X-Forwarded-For to work correctly)
	// This enables localhost detection when accessing from host to Docker container
	// SECURITY: Only requests FROM these IPs can set X-Forwarded-For headers.
	// External attackers cannot spoof X-Forwarded-For because their IP won't be trusted.
	// Trusted proxy IPs that can set X-Forwarded-For headers
	// Includes default private ranges + user-configured trusted proxies
	trustedProxies := []string{
		"127.0.0.1",
		"::1",
		"172.16.0.0/12",  // Docker bridge networks
		"192.168.0.0/16", // Docker custom networks / private networks
		"10.0.0.0/8",     // Private networks
		"100.64.0.0/10",  // Tailscale / CGNAT
	}
	if len(s.config.TrustedProxies) > 0 {
		trustedProxies = append(trustedProxies, s.config.TrustedProxies...)
	}
	router.SetTrustedProxies(trustedProxies)

	// Correlation ID middleware (generates/propagates request IDs for audit trail)
	router.Use(correlationIDMiddleware())

	// CORS middleware for frontend
	router.Use(s.corsMiddleware())

	// Health check endpoint (no auth required)
	// Support both GET and HEAD for healthchecks (wget --spider uses HEAD)
	healthHandler := func(c *gin.Context) {
		if c.Request.Method == http.MethodHead {
			c.Status(http.StatusOK)
		} else {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		}
	}
	router.GET("/health", healthHandler)
	router.HEAD("/health", healthHandler)

	// Authentication endpoints (no auth required)
	// Rate limited to prevent brute force attacks
	authRL := s.authRateLimiter.Middleware()

	// Register at both root level (for direct access) and under /api (for frontend proxy)
	router.POST("/auth/request", authRL, s.handleAuthRequest)
	router.POST("/auth/callback", authRL, s.handleAuthCallback)
	router.POST("/refresh", authRL, s.handleRefresh)
	router.POST("/revoke", authRL, s.handleRevoke)
	router.POST("/introspect", authRL, s.handleIntrospect)

	// Versioned API auth endpoints (v1) - primary path
	router.POST("/api/v1/auth/request", authRL, s.handleAuthRequest)
	router.POST("/api/v1/auth/callback", authRL, s.handleAuthCallback)
	router.GET("/api/v1/auth/session/:id/status", s.handleAuthSessionStatus)
	router.POST("/api/v1/refresh", authRL, s.handleRefresh)
	router.POST("/api/v1/revoke", authRL, s.handleRevoke)
	router.POST("/api/v1/introspect", authRL, s.handleIntrospect)

	// Legacy API auth endpoints (unversioned) - deprecated, for backwards compatibility
	deprecation := s.deprecationMiddleware("/api", "/api/v1")
	router.POST("/api/auth/request", authRL, deprecation, s.handleAuthRequest)
	router.POST("/api/auth/callback", authRL, deprecation, s.handleAuthCallback)
	router.GET("/api/auth/session/:id/status", deprecation, s.handleAuthSessionStatus)
	router.POST("/api/refresh", authRL, deprecation, s.handleRefresh)
	router.POST("/api/revoke", authRL, deprecation, s.handleRevoke)
	router.POST("/api/introspect", authRL, deprecation, s.handleIntrospect)

	// Azure AD / Microsoft Entra ID authentication endpoints
	// Always registered; handlers return 404 when Azure AD is not configured.
	router.GET("/api/v1/auth/azure/url", authRL, s.handleAzureAuthURL)
	router.POST("/api/v1/auth/azure/callback", authRL, s.handleAzureCallback)
	router.GET("/api/v1/auth/providers", s.handleAuthProviders)

	// Manual verification endpoint (development/testing only)
	if !s.config.IsProduction() {
		router.POST("/auth/verify", authRL, s.handleAuthVerify)
		router.POST("/api/v1/auth/verify", authRL, s.handleAuthVerify)
		router.POST("/api/auth/verify", authRL, deprecation, s.handleAuthVerify)
	}

	// OAuth 2.0 endpoints - enables privacy-proxy as an Identity Provider
	// Used by block explorer for Single Sign-On with Privado ID authentication
	// Rate limited to prevent brute force attacks
	router.GET("/oauth/authorize", authRL, s.handleOAuthAuthorize)
	router.POST("/oauth/callback", authRL, s.handleOAuthCallback)
	router.POST("/oauth/token", authRL, s.handleOAuthToken)
	router.GET("/oauth/session/:id/status", s.handleOAuthSessionStatus)

	// ETH address linking endpoints - available at multiple paths for flexibility:
	// - /api/v1/eth/* - versioned API (primary)
	// - /api/eth/* - legacy unversioned (deprecated)
	// - /eth/* - for direct API access (mobile apps, CLI tools)
	// All require JWT authentication.
	ethEndpoints := func(group *gin.RouterGroup) {
		group.POST("/link/challenge", s.handleEthLinkChallenge)
		group.POST("/link/verify", s.handleEthLinkVerify)
		group.GET("/addresses", s.handleGetEthAddresses)
		group.DELETE("/addresses/:address", s.handleDeleteEthAddress)
		group.POST("/addresses/:address/refresh-ens", s.handleRefreshENS)
	}

	// Versioned API eth endpoints (v1) - primary
	apiV1Eth := router.Group("/api/v1/eth")
	apiV1Eth.Use(auth.JWTAuthMiddleware(s.jwtService, s.db))
	ethEndpoints(apiV1Eth)

	// Legacy API eth endpoints (unversioned) - deprecated
	apiEth := router.Group("/api/eth")
	apiEth.Use(auth.JWTAuthMiddleware(s.jwtService, s.db))
	apiEth.Use(deprecation)
	ethEndpoints(apiEth)

	// Direct eth endpoints (no /api prefix)
	eth := router.Group("/eth")
	eth.Use(auth.JWTAuthMiddleware(s.jwtService, s.db))
	ethEndpoints(eth)

	// JSON-RPC proxy endpoint - protected by JWT
	// Support both "/" (direct access) and "/rpc" (frontend proxy)
	// For users with multiple org memberships, use "/rpc/:org_id" to specify org
	router.POST("/", auth.JWTAuthMiddleware(s.jwtService, s.db), s.handleJSONRPC)
	router.POST("/rpc", auth.JWTAuthMiddleware(s.jwtService, s.db), s.handleJSONRPC)
	router.POST("/rpc/:org_id", auth.JWTAuthMiddleware(s.jwtService, s.db), s.handleJSONRPC)

	// User disclosure endpoints - protected by JWT but accessible from external IPs
	s.registerUserDisclosureRoutes(router)

	// User profile endpoints - protected by JWT but accessible from external IPs
	s.registerUserProfileRoutes(router)

	// Explorer API endpoints - internal APIs for block explorer integration
	// Protected by localhost-only middleware (called by explorer backend)
	s.registerExplorerRoutes(router)

	// API endpoints for UI - protected by localhost-only middleware
	// Register versioned API (v1) - primary path
	adminAuth := s.adminAuthMiddleware()
	apiV1 := router.Group("/api/v1")
	{
		// Admin endpoints - localhost only
		admin := apiV1.Group("/admin")
		admin.Use(s.localhostOnlyMiddleware(), adminAuth)
		{
			admin.GET("/logs", s.getLogs)
			admin.GET("/status", s.getStatus)
			admin.POST("/test-request", s.handleTestRequest)

			// RBAC endpoints
			s.registerRBACRoutes(admin)

			// Disclosure admin endpoints
			s.registerDisclosureRoutes(admin)

			// Compliance endpoints (travel rule)
			s.registerComplianceRoutes(admin)

			// Dev-only endpoints (CREATE3 factory deployment)
			admin.GET("/dev/create3-factory", s.getCreate3Factory)
			admin.POST("/dev/create3-factory", s.deployCreate3Factory)
			admin.GET("/dev/create3-factory/bytecode", s.getCreate3FactoryBytecodeHash)
			admin.POST("/dev/orgs/:org_id/create3/auto-register", s.autoRegisterCreate3)
			admin.POST("/dev/deploy-demo-erc20", s.handleDeployDemoERC20)
		}
	}

	// Legacy API (unversioned) - deprecated, for backwards compatibility
	// Adds X-Deprecated header to responses
	api := router.Group("/api")
	{
		adminLegacy := api.Group("/admin")
		adminLegacy.Use(s.localhostOnlyMiddleware(), adminAuth)
		adminLegacy.Use(s.deprecationMiddleware("/api/admin", "/api/v1/admin"))
		{
			adminLegacy.GET("/logs", s.getLogs)
			adminLegacy.GET("/status", s.getStatus)
			adminLegacy.POST("/test-request", s.handleTestRequest)

			// RBAC endpoints
			s.registerRBACRoutes(adminLegacy)

			// Disclosure admin endpoints
			s.registerDisclosureRoutes(adminLegacy)

			// Compliance endpoints (travel rule)
			s.registerComplianceRoutes(adminLegacy)

			// Dev-only endpoints (CREATE3 factory deployment)
			adminLegacy.GET("/dev/create3-factory", s.getCreate3Factory)
			adminLegacy.POST("/dev/create3-factory", s.deployCreate3Factory)
			adminLegacy.GET("/dev/create3-factory/bytecode", s.getCreate3FactoryBytecodeHash)
			adminLegacy.POST("/dev/orgs/:org_id/create3/auto-register", s.autoRegisterCreate3)
		}
	}

	return router
}

// MaxRequestBodySize is the maximum allowed request body size (1MB).
const MaxRequestBodySize = 1 << 20 // 1MB

func (s *Server) handleJSONRPC(c *gin.Context) {
	// Extract identity from JWT (set by middleware)
	subject, exists := c.Get("subject")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing identity in context"})
		return
	}

	subjectStr, ok := subject.(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid identity in context"})
		return
	}

	// Read request body with size limit to prevent DoS
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, MaxRequestBodySize+1))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read request body"})
		return
	}

	// Parse and validate the request body
	method, params, parseErr := ParseAndValidateBody(body)
	if parseErr != nil {
		c.JSON(parseErr.StatusCode, gin.H{"error": parseErr.Message})
		return
	}

	// Extract optional org_id from path (for /rpc/:org_id route)
	orgID := c.Param("org_id")

	// Process the request through the business logic layer
	result := s.jsonrpcProcessor.Process(c.Request.Context(), &ProcessRequest{
		UserID:        subjectStr,
		OrgID:         orgID,
		Method:        method,
		Params:        params,
		Body:          body,
		ClientIP:      c.ClientIP(),
		CorrelationID: getCorrelationID(c),
	})

	// Handle errors from processing
	if result.Error != nil {
		c.JSON(result.Error.StatusCode, gin.H{"error": result.Error.Message})
		return
	}

	// Return response from node
	c.Data(result.StatusCode, "application/json", result.ResponseBody)
}

func (s *Server) getLogs(c *gin.Context) {
	limit := 100 // default
	if limitStr := c.Query("limit"); limitStr != "" {
		if _, err := fmt.Sscanf(limitStr, "%d", &limit); err != nil {
			limit = 100
		}
	}

	logs, err := s.db.GetAccessLogs(c.Request.Context(), limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, logs)
}

// corsMiddleware returns a CORS middleware configured from server settings.
// In development (or with CORSAllowedOrigins="*"), allows all origins.
// In production, only allows configured origins.
func (s *Server) corsMiddleware() gin.HandlerFunc {
	allowedOrigins := s.config.CORSAllowedOrigins

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")

		// Determine if this origin should be allowed
		var allowOrigin string
		if allowedOrigins == "*" {
			allowOrigin = "*"
		} else if allowedOrigins != "" {
			// Check if origin is in the allowed list
			for _, allowed := range strings.Split(allowedOrigins, ",") {
				if strings.TrimSpace(allowed) == origin {
					allowOrigin = origin
					break
				}
			}
		}

		if allowOrigin != "" {
			c.Writer.Header().Set("Access-Control-Allow-Origin", allowOrigin)
			if allowOrigin != "*" {
				c.Writer.Header().Set("Vary", "Origin")
				c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
			}
			c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
			c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")
		}

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// adminAuthMiddleware enforces shared-token authentication for admin APIs.
// If no admin token is configured, the middleware is a no-op and localhost/network
// controls remain the only gate.
func (s *Server) adminAuthMiddleware() gin.HandlerFunc {
	expectedToken := strings.TrimSpace(s.config.AdminAPIToken)
	if expectedToken == "" {
		return func(c *gin.Context) { c.Next() }
	}

	return func(c *gin.Context) {
		providedToken := strings.TrimSpace(c.GetHeader("X-Admin-Token"))
		if providedToken == "" {
			authHeader := strings.TrimSpace(c.GetHeader("Authorization"))
			if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
				providedToken = strings.TrimSpace(authHeader[7:])
			}
		}

		if providedToken == "" || subtle.ConstantTimeCompare([]byte(providedToken), []byte(expectedToken)) != 1 {
			c.JSON(http.StatusForbidden, gin.H{"error": "admin authentication required"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// deprecationMiddleware adds deprecation headers to responses.
// It signals to clients that they should migrate to the versioned API.
func (s *Server) deprecationMiddleware(oldPath, newPath string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Add deprecation headers per RFC 8594
		c.Header("Deprecation", "true")
		c.Header("Sunset", "2027-01-01T00:00:00Z") // Give clients a year to migrate
		c.Header("Link", fmt.Sprintf("<%s%s>; rel=\"successor-version\"", newPath, strings.TrimPrefix(c.Request.URL.Path, oldPath)))
		c.Next()
	}
}

// localhostOnlyMiddleware restricts access to localhost only
// Works both when running locally and in Docker (when accessed from host)
// When accessed from host via localhost:8080, Docker shows client as gateway IP (172.17.0.1)
// Gin's ClientIP() with trusted proxies will correctly extract the real client IP
//
// SECURITY MODEL:
// - Gin's SetTrustedProxies ensures only requests FROM trusted IPs can set X-Forwarded-For
// - External attackers (e.g., 203.0.113.1) cannot spoof X-Forwarded-For: 127.0.0.1 because:
//  1. Their remote IP (203.0.113.1) is not in the trusted proxy list
//  2. Gin will ignore X-Forwarded-For and use the actual remote IP
//  3. Middleware will reject the request
//
// - Only localhost (127.0.0.1, ::1), Docker network IPs (172.x.x.x), and Tailscale IPs are allowed
func (s *Server) localhostOnlyMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Gin's ClientIP() only trusts X-Forwarded-For if remote IP is in trusted proxy list
		// External attackers cannot spoof because their IP won't be trusted
		clientIP := c.ClientIP()
		ip := net.ParseIP(clientIP)
		if ip == nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "invalid client IP"})
			c.Abort()
			return
		}

		// Allowed private networks:
		// - 127.0.0.1/32: Localhost IPv4
		// - ::1/128: Localhost IPv6
		// - 172.16.0.0/12: Docker bridge networks (RFC1918)
		// - 192.168.0.0/16: Docker custom networks / WiFi (RFC1918)
		// - 100.64.0.0/10: Tailscale / CGNAT
		allowedCIDRs := []string{
			"127.0.0.1/32",
			"::1/128",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"10.0.0.0/8",
			"100.64.0.0/10",
		}

		isAllowed := false
		for _, cidr := range allowedCIDRs {
			_, subnet, _ := net.ParseCIDR(cidr)
			if subnet != nil && subnet.Contains(ip) {
				isAllowed = true
				break
			}
		}

		if !isAllowed {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "management API is only accessible from localhost, private networks, or Tailscale",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// StatusResponse represents the system status
type StatusResponse struct {
	Proxy    ProxyStatus    `json:"proxy"`
	Node     NodeStatus     `json:"node"`
	Security SecurityStatus `json:"security"`
}

// ProxyStatus represents the proxy status
type ProxyStatus struct {
	Status string `json:"status"`
	Port   string `json:"port"`
}

// SecurityStatus represents the security configuration status
type SecurityStatus struct {
	RuntimeTracingEnabled bool `json:"runtime_tracing_enabled"`
	TravelRuleEnabled     bool `json:"travel_rule_enabled"`
}

// NodeStatus represents the node status
type NodeStatus struct {
	Status    string `json:"status"`
	URL       string `json:"url"`
	LatencyMs int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
}

func (s *Server) getStatus(c *gin.Context) {
	// Check node health
	nodeHealth := s.proxy.CheckHealth()

	// Check if runtime tracing is enabled
	runtimeTracingEnabled := s.runtimeTracer != nil && s.runtimeTracer.IsEnabled()
	proxyPort := "8080"
	if s.config != nil && s.config.Port != "" {
		proxyPort = s.config.Port
	}

	status := StatusResponse{
		Proxy: ProxyStatus{
			Status: "running",
			Port:   proxyPort,
		},
		Node: NodeStatus{
			Status:    nodeHealth.Status,
			URL:       nodeHealth.URL,
			LatencyMs: nodeHealth.LatencyMs,
			Error:     nodeHealth.Error,
		},
		Security: SecurityStatus{
			RuntimeTracingEnabled: runtimeTracingEnabled,
			TravelRuleEnabled:     s.complianceChecker != nil,
		},
	}

	c.JSON(http.StatusOK, status)
}

// TestRequestInput represents the input for test request
type TestRequestInput struct {
	Method   string        `json:"method"`
	Params   []interface{} `json:"params"`
	JWTToken string        `json:"jwt_token,omitempty"`
}

// TestRequestResponse represents the response for test request
type TestRequestResponse struct {
	Result    interface{} `json:"result,omitempty"`
	Error     string      `json:"error,omitempty"`
	LatencyMs int64       `json:"latency_ms,omitempty"`
	Identity  string      `json:"identity,omitempty"` // The identity used for access control
}

func (s *Server) handleTestRequest(c *gin.Context) {
	var input TestRequestInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Use synthetic identity for test requests or extract from JWT token
	testIdentity := "test:dashboard"
	if input.JWTToken != "" {
		claims, err := s.jwtService.ValidateAccessToken(input.JWTToken)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JWT: " + err.Error()})
			return
		}
		testIdentity = claims.Subject
	}

	// Check access via RBAC
	var testRequiredClaims []rbac.Claim
	if claim := rbac.ClassifyOperation(input.Method, input.Params); claim != "" {
		testRequiredClaims = []rbac.Claim{claim}
	}
	accessReq := &rbac.AccessCheckRequest{
		UserExternalID:   testIdentity,
		Method:           input.Method,
		Params:           input.Params,
		TargetAddress:    rbac.GetTargetAddress(input.Method, input.Params),
		FunctionSelector: rbac.GetFunctionSelector(input.Method, input.Params),
		RequiredClaims:   testRequiredClaims,
	}
	result, err := s.rbacAccessCtrl.CheckAccess(c.Request.Context(), accessReq)
	if err != nil {
		s.db.LogAccess(c.Request.Context(), testIdentity, input.Method, http.StatusInternalServerError, c.ClientIP())
		c.JSON(http.StatusInternalServerError, TestRequestResponse{
			Error:    "access check failed: " + err.Error(),
			Identity: testIdentity,
		})
		return
	}
	if !result.Allowed {
		s.db.LogAccess(c.Request.Context(), testIdentity, input.Method, http.StatusForbidden, c.ClientIP())
		c.JSON(http.StatusForbidden, TestRequestResponse{
			Error:    result.Reason,
			Identity: testIdentity,
		})
		return
	}

	// Travel rule compliance check for eth_sendTransaction and eth_sendRawTransaction
	if s.complianceChecker != nil {
		var compFrom, compTo, compData, compValue string
		var needsCheck bool

		switch input.Method {
		case "eth_sendTransaction":
			compFrom, compTo, compData, compValue = extractTxParams(input.Params)
			needsCheck = true
		case "eth_sendRawTransaction":
			rawTxHex, extractErr := extractRawTxHex(input.Params)
			if extractErr != nil {
				c.JSON(http.StatusBadRequest, TestRequestResponse{
					Error:    "failed to extract raw transaction: " + extractErr.Error(),
					Identity: testIdentity,
				})
				return
			}
			var decodeErr error
			compFrom, compTo, compData, compValue, decodeErr = decodeRawTransaction(rawTxHex)
			if decodeErr != nil {
				c.JSON(http.StatusBadRequest, TestRequestResponse{
					Error:    "failed to decode raw transaction: " + decodeErr.Error(),
					Identity: testIdentity,
				})
				return
			}
			needsCheck = true
		}

		if needsCheck {
			compResult, compErr := s.complianceChecker.Check(c.Request.Context(), &compliance.CheckRequest{
				OrgID:         result.OrgID,
				UserID:        result.UserID,
				From:          compFrom,
				To:            compTo,
				Data:          compData,
				Value:         compValue,
				CorrelationID: getCorrelationID(c),
			})
			if compErr != nil {
				c.JSON(http.StatusInternalServerError, TestRequestResponse{
					Error:    "compliance check failed: " + compErr.Error(),
					Identity: testIdentity,
				})
				return
			}
			if !compResult.Allowed {
				s.db.LogAccess(c.Request.Context(), testIdentity, input.Method, http.StatusForbidden, c.ClientIP())
				c.JSON(http.StatusForbidden, TestRequestResponse{
					Error:    "compliance denied: " + compResult.Reason,
					Identity: testIdentity,
				})
				return
			}
		}
	}

	// Build JSON-RPC request
	rpcReq := proxy.JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  input.Method,
		Params:  input.Params,
		ID:      1,
	}
	reqBody, _ := json.Marshal(rpcReq)

	// Forward to node and measure latency
	start := time.Now()
	respBody, statusCode, err := s.proxy.Forward(reqBody)
	latency := time.Since(start).Milliseconds()

	if err != nil {
		s.db.LogAccess(c.Request.Context(), testIdentity, input.Method, http.StatusBadGateway, c.ClientIP())
		c.JSON(http.StatusBadGateway, TestRequestResponse{
			Error:     err.Error(),
			LatencyMs: latency,
			Identity:  testIdentity,
		})
		return
	}

	// Parse response
	var rpcResp proxy.JSONRPCResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		s.db.LogAccess(c.Request.Context(), testIdentity, input.Method, http.StatusBadGateway, c.ClientIP())
		c.JSON(http.StatusBadGateway, TestRequestResponse{
			Error:     "invalid JSON-RPC response",
			LatencyMs: latency,
			Identity:  testIdentity,
		})
		return
	}

	// Log successful access
	s.db.LogAccess(c.Request.Context(), testIdentity, input.Method, statusCode, c.ClientIP())

	// Return JSON-RPC response (may contain RPC-level error, that's fine - HTTP 200)
	if rpcResp.Error != nil {
		c.JSON(http.StatusOK, TestRequestResponse{
			Error:     rpcResp.Error.Message,
			LatencyMs: latency,
			Identity:  testIdentity,
		})
		return
	}

	c.JSON(http.StatusOK, TestRequestResponse{
		Result:    rpcResp.Result,
		LatencyMs: latency,
		Identity:  testIdentity,
	})
}

// registerUserProfileRoutes registers user profile endpoints (JWT-authenticated, accessible from external IPs).
func (s *Server) registerUserProfileRoutes(router *gin.Engine) {
	me := router.Group("/api/v1/me")
	me.Use(auth.JWTAuthMiddleware(s.jwtService, s.db))
	{
		me.GET("/orgs", s.getMyOrganizations)
	}
}

// UserOrgResponse represents an organization the user belongs to.
type UserOrgResponse struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
}

// getMyOrganizations returns the organizations the authenticated user belongs to.
func (s *Server) getMyOrganizations(c *gin.Context) {
	subject, exists := c.Get("subject")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing subject in context"})
		return
	}

	// Get user from database
	user, err := s.db.GetUserByExternalID(c.Request.Context(), subject.(string))
	if err != nil || user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
		return
	}

	// Get user's memberships
	memberships, err := s.db.ListUserMembershipsWithDetails(c.Request.Context(), user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get memberships"})
		return
	}

	// Collect unique orgs
	orgMap := make(map[string]*UserOrgResponse)
	for _, m := range memberships {
		if m.Group != nil && m.Group.OrgID != "" {
			if _, exists := orgMap[m.Group.OrgID]; !exists {
				org, err := s.db.GetOrganization(c.Request.Context(), m.Group.OrgID)
				if err == nil && org != nil {
					orgMap[org.ID] = &UserOrgResponse{
						ID:   org.ID,
						Slug: org.Slug,
						Name: org.Name,
					}
				}
			}
		}
	}

	// Convert to slice
	orgs := make([]*UserOrgResponse, 0, len(orgMap))
	for _, org := range orgMap {
		orgs = append(orgs, org)
	}

	c.JSON(http.StatusOK, gin.H{"organizations": orgs})
}
