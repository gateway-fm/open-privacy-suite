package config

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	NodeURL                    string
	DatabaseURL                string
	PrivadoRPCURL              string
	IPFSGateway                string
	JWTSecret                  string
	JWTRefreshSecret           string
	VerifierID                 string        // DID or identifier of the verifier
	BaseURL                    string        // Base URL for callback (e.g., https://api.example.com)
	Port                       string        // Server port (e.g., "8080")
	Environment                string        // "production" or "development"
	BillionsIssuerDID          string        // Billions issuer DID for ProofOfHumanity verification
	RequireProofOfHumanity     bool          // Whether to require ProofOfHumanity credential (default: true in prod)
	AllowUnregisteredAddresses bool          // If true, deploy/admin default claims can access unregistered addresses (default: true)
	AdminAPIToken              string        // Shared token required for admin API access (required in production)
	ENSResolverURL             string        // Ethereum mainnet RPC URL for ENS resolution
	CORSAllowedOrigins         string        // Comma-separated list of allowed origins, or "*" for all (default: "*" in dev)
	MockSignatures             bool          // If true, accept any signature without verification (dev/demo only, NEVER in production)
	AllowMockLogin             bool          // If true, accept mock JWZ tokens for testing (dev/demo only, NEVER in production)
	DemoAutoAuthDelay          time.Duration // Auto-complete auth sessions for demo recording (0 = disabled, forced off in production)
	TrustedFactoryHashes       []string      // Additional CREATE3 factory bytecode hashes to whitelist (comma-separated in env)

	// Runtime tracing configuration
	EnableRuntimeTracing  bool          // If true, enable debug_traceCall validation (default: false)
	TraceCacheTTL         time.Duration // TTL for trace result cache (default: 10s)
	TraceTimeout          time.Duration // Timeout for debug_traceCall requests (default: 30s)
	TraceTieredValidation bool          // If true, skip trace for known org addresses (default: true)

	// Travel rule compliance configuration
	EnableTravelRule   bool          // If true, enable travel rule enforcement (default: false)
	TravelRecordExpiry time.Duration // How long travel rule records stay valid (default: 24h)

	// Token price fetching configuration
	PriceFetchInterval      time.Duration // How often to fetch prices from CoinGecko (default: 5m)
	PriceStalenessThreshold time.Duration // After this duration, prices are considered stale (default: 15m)

	// Audit configuration
	AuditLogParams bool // If true, log redacted request parameters in access_logs (default: false)

	// Retention policy configuration (0 = keep forever)
	RetentionAccessLogs      time.Duration // Retention for access_logs (default: 90 days)
	RetentionComplianceLogs  time.Duration // Retention for compliance_logs (default: 7 years)
	RetentionRBACAuditLogs   time.Duration // Retention for rbac_audit_log (default: 1 year)
	RetentionTravelRecords   time.Duration // Retention for used travel_rule_records (default: 7 years)
	RetentionCleanupInterval time.Duration // How often retention cleanup runs (default: 1 hour)

	// SIEM webhook configuration
	SIEMWebhookURL    string        // SIEM webhook endpoint (empty = disabled)
	SIEMAuthHeader    string        // Authorization header for SIEM webhook
	SIEMBatchSize     int           // Events per SIEM batch (default: 100)
	SIEMFlushInterval time.Duration // Max time before flushing SIEM batch (default: 10s)

	// Tunnel URL file path — cloudflared writes the public URL here (auto-detected)
	TunnelURLFile string

	// Trusted Proxies for X-Forwarded-For trust
	TrustedProxies []string // List of IPs/CIDRs to trust for client IP extraction

	// Azure AD / Microsoft Entra ID authentication
	AzureADClientID     string // AZURE_AD_CLIENT_ID
	AzureADClientSecret string // AZURE_AD_CLIENT_SECRET
	AzureADTenantID     string // AZURE_AD_TENANT_ID (default: "common" for multi-tenant)
}

func Load() *Config {
	env := getEnv("ENVIRONMENT", "development")
	// Default RequireProofOfHumanity to true in production, false in development
	requirePoH := getEnv("REQUIRE_PROOF_OF_HUMANITY", "")
	requirePoHBool := env == "production" // Default based on environment
	if requirePoH == "true" {
		requirePoHBool = true
	} else if requirePoH == "false" {
		requirePoHBool = false
	}

	// Default AllowUnregisteredAddresses to true (addresses not in RBAC bypass permission checks)
	allowUnregistered := getEnv("ALLOW_UNREGISTERED_ADDRESSES", "")
	allowUnregisteredBool := true // Default to true (bypass enabled)
	if allowUnregistered == "false" {
		allowUnregisteredBool = false
	}

	// Default CORS origins: "*" in dev, must be configured in production
	corsOrigins := getEnv("CORS_ALLOWED_ORIGINS", "")
	if corsOrigins == "" {
		if env == "production" {
			corsOrigins = "" // Empty means no origins allowed - must be configured
		} else {
			corsOrigins = "*" // Allow all in development
		}
	}

	// MockSignatures: Only allow in non-production environments
	// This skips cryptographic signature verification for wallet linking (demo/dev only)
	mockSigs := getEnv("MOCK_SIGNATURES", "false") == "true"
	if mockSigs && env == "production" {
		// Force disable in production - this is a critical security setting
		mockSigs = false
	}

	// AllowMockLogin: Only allow in non-production environments
	// This allows mock JWZ tokens for testing without Privado wallet (demo/dev only)
	allowMockLogin := getEnv("ALLOW_MOCK_LOGIN", "false") == "true"
	if allowMockLogin && env == "production" {
		// Force disable in production - this is a critical security setting
		allowMockLogin = false
	}

	// DemoAutoAuthDelay: Auto-complete auth sessions for demo recording
	// Value in seconds, 0 or empty = disabled. Forced off in production.
	demoDelayStr := getEnv("DEMO_AUTO_AUTH_DELAY", "")
	var demoDelay time.Duration
	if demoDelayStr != "" {
		if secs, err := strconv.Atoi(demoDelayStr); err == nil && secs > 0 {
			demoDelay = time.Duration(secs) * time.Second
		}
	}
	if env == "production" {
		demoDelay = 0 // Force disable in production
	}

	// TrustedFactoryHashes: Additional CREATE3 factory bytecode hashes to whitelist
	// Comma-separated list of keccak256 hashes (with or without 0x prefix)
	var trustedFactoryHashes []string
	if hashesStr := getEnv("TRUSTED_FACTORY_HASHES", ""); hashesStr != "" {
		for _, hash := range strings.Split(hashesStr, ",") {
			hash = strings.TrimSpace(hash)
			if hash != "" {
				trustedFactoryHashes = append(trustedFactoryHashes, hash)
			}
		}
	}

	// Runtime tracing configuration
	enableTracing := getEnv("ENABLE_RUNTIME_TRACING", "false") == "true"
	traceCacheTTL := 10 * time.Second
	if ttlStr := getEnv("TRACE_CACHE_TTL", ""); ttlStr != "" {
		if d, err := time.ParseDuration(ttlStr); err == nil {
			traceCacheTTL = d
		}
	}
	traceTimeout := 30 * time.Second
	if timeoutStr := getEnv("TRACE_TIMEOUT", ""); timeoutStr != "" {
		if d, err := time.ParseDuration(timeoutStr); err == nil {
			traceTimeout = d
		}
	}
	traceTiered := getEnv("TRACE_TIERED_VALIDATION", "true") != "false"

	// Travel rule compliance configuration
	enableTravelRule := getEnv("ENABLE_TRAVEL_RULE", "false") == "true"
	travelRecordExpiry := 24 * time.Hour
	if expiryStr := getEnv("TRAVEL_RECORD_EXPIRY", ""); expiryStr != "" {
		if d, err := time.ParseDuration(expiryStr); err == nil {
			travelRecordExpiry = d
		}
	}

	// Token price fetching configuration
	priceFetchInterval := 5 * time.Minute
	if intervalStr := getEnv("PRICE_FETCH_INTERVAL", ""); intervalStr != "" {
		if d, err := time.ParseDuration(intervalStr); err == nil {
			priceFetchInterval = d
		}
	}
	if priceFetchInterval < 1*time.Minute {
		priceFetchInterval = 1 * time.Minute
	}
	priceStalenessThreshold := 15 * time.Minute
	if staleStr := getEnv("PRICE_STALENESS_THRESHOLD", ""); staleStr != "" {
		if d, err := time.ParseDuration(staleStr); err == nil {
			priceStalenessThreshold = d
		}
	}

	// Audit configuration
	auditLogParams := getEnv("AUDIT_LOG_PARAMS", "false") == "true"

	// Retention policy configuration
	retentionAccessLogs := parseDurationEnv("RETENTION_ACCESS_LOGS", 90*24*time.Hour)       // 90 days
	retentionComplianceLogs := parseDurationEnv("RETENTION_COMPLIANCE_LOGS", 7*365*24*time.Hour) // ~7 years
	retentionRBACAuditLogs := parseDurationEnv("RETENTION_RBAC_AUDIT_LOGS", 365*24*time.Hour)    // 1 year
	retentionTravelRecords := parseDurationEnv("RETENTION_TRAVEL_RECORDS", 7*365*24*time.Hour)   // ~7 years
	retentionCleanupInterval := parseDurationEnv("RETENTION_CLEANUP_INTERVAL", 1*time.Hour)

	// SIEM webhook configuration
	siemWebhookURL := getEnv("SIEM_WEBHOOK_URL", "")
	siemAuthHeader := getEnv("SIEM_AUTH_HEADER", "")
	siemBatchSize := 100
	if bsStr := getEnv("SIEM_BATCH_SIZE", ""); bsStr != "" {
		if n, err := strconv.Atoi(bsStr); err == nil && n > 0 {
			siemBatchSize = n
		}
	}
	siemFlushInterval := parseDurationEnv("SIEM_FLUSH_INTERVAL", 10*time.Second)

	return &Config{
		NodeURL:                    getEnv("NODE_URL", "http://localhost:8545"),
		DatabaseURL:                getEnv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/privacy_proxy?sslmode=disable"),
		PrivadoRPCURL:              getEnv("PRIVADO_RPC_URL", "https://rpc-mainnet.privado.id"),
		IPFSGateway:                getEnv("IPFS_GATEWAY", "https://ipfs-proxy-cache.privado.id"), // IPFS gateway for schema resolution
		JWTSecret:                  getEnv("JWT_SECRET", ""),                                      // If empty, will be auto-generated (dev only)
		JWTRefreshSecret:           getEnv("JWT_REFRESH_SECRET", ""),                              // If empty, will be auto-generated (dev only)
		VerifierID:                 getEnv("VERIFIER_ID", ""),                                     // Required in production
		BaseURL:                    getEnv("BASE_URL", "http://localhost:8080"),                   // Base URL for callback
		Port:                       getEnv("PORT", "8080"),                                        // Server port
		Environment:                env,
		BillionsIssuerDID:          getEnv("BILLIONS_ISSUER_DID", ""), // Billions issuer DID for PoH
		RequireProofOfHumanity:     requirePoHBool,
		AllowUnregisteredAddresses: allowUnregisteredBool,
		AdminAPIToken:              getEnv("ADMIN_API_TOKEN", ""),
		ENSResolverURL:             getEnv("ENS_RESOLVER_URL", "https://eth.llamarpc.com"), // Public mainnet RPC
		CORSAllowedOrigins:         corsOrigins,
		MockSignatures:             mockSigs,
		AllowMockLogin:             allowMockLogin,
		DemoAutoAuthDelay:          demoDelay,
		TrustedFactoryHashes:       trustedFactoryHashes,
		EnableRuntimeTracing:       enableTracing,
		TraceCacheTTL:              traceCacheTTL,
		TraceTimeout:               traceTimeout,
		TraceTieredValidation:      traceTiered,
		EnableTravelRule:           enableTravelRule,
		TravelRecordExpiry:         travelRecordExpiry,
		PriceFetchInterval:         priceFetchInterval,
		PriceStalenessThreshold:    priceStalenessThreshold,
		AuditLogParams:             auditLogParams,
		RetentionAccessLogs:        retentionAccessLogs,
		RetentionComplianceLogs:    retentionComplianceLogs,
		RetentionRBACAuditLogs:     retentionRBACAuditLogs,
		RetentionTravelRecords:     retentionTravelRecords,
		RetentionCleanupInterval:   retentionCleanupInterval,
		SIEMWebhookURL:             siemWebhookURL,
		SIEMAuthHeader:             siemAuthHeader,
		SIEMBatchSize:              siemBatchSize,
		SIEMFlushInterval:          siemFlushInterval,
		TunnelURLFile:              getEnv("TUNNEL_URL_FILE", ""),
		TrustedProxies:             getSliceEnv("TRUSTED_PROXIES", ","),
		AzureADClientID:            getEnv("AZURE_AD_CLIENT_ID", ""),
		AzureADClientSecret:        getEnv("AZURE_AD_CLIENT_SECRET", ""),
		AzureADTenantID:            getEnv("AZURE_AD_TENANT_ID", "common"),
	}
}

func getSliceEnv(key, sep string) []string {
	val := os.Getenv(key)
	if val == "" {
		return nil
	}
	parts := strings.Split(val, sep)
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// IsProduction returns true if running in production mode
func (c *Config) IsProduction() bool {
	return c.Environment == "production"
}

// AzureADEnabled returns true if Azure AD authentication is configured.
func (c *Config) AzureADEnabled() bool {
	return c.AzureADClientID != "" && c.AzureADClientSecret != ""
}

// Validate checks that required configuration is present.
// In production, certain values must be explicitly configured.
func (c *Config) Validate() error {
	if !c.IsProduction() {
		return nil // Development mode allows auto-generated values
	}

	// In production, JWT secrets must be explicitly configured
	if c.JWTSecret == "" {
		return errors.New("JWT_SECRET is required in production")
	}
	if c.JWTRefreshSecret == "" {
		return errors.New("JWT_REFRESH_SECRET is required in production")
	}

	// Warn about other important production settings
	if c.VerifierID == "" {
		return errors.New("VERIFIER_ID is required in production for authentication")
	}
	if c.AdminAPIToken == "" {
		return errors.New("ADMIN_API_TOKEN is required in production for admin API authentication")
	}

	return nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// parseDurationEnv reads an environment variable as a time.Duration.
// Returns the default value if the variable is empty or unparseable.
// A value of "0" returns 0 (keep forever for retention settings).
func parseDurationEnv(key string, defaultValue time.Duration) time.Duration {
	s := os.Getenv(key)
	if s == "" {
		return defaultValue
	}
	if s == "0" {
		return 0
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return defaultValue
	}
	return d
}
