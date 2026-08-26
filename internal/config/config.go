package config

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/proxy"

	"golang.org/x/crypto/bcrypt"
)

// ExtraRPCNamespaces defines additional JSON-RPC method namespaces
// that the proxy should accept and forward to the node.
// This allows operators to support chain-specific methods (e.g. Linea's linea_*)
// without code changes.
//
// Schema versions:
//
//   - v1: each namespace value is an array of {method, alias} entries (explicit only).
//   - v2: each namespace value is either an array (same as v1) or an object
//     {"explicit": [...], "wildcard": {"prefix": "...", "deny": [...]}}. The
//     wildcard block lets operators allow any method matching the prefix to pass
//     through without alias-based redaction; see WildcardConfig.
type ExtraRPCNamespaces struct {
	Version    int                        `json:"version"`
	Namespaces map[string]NamespaceConfig `json:"-"` // parsed from mixed JSON shape
}

// NamespaceConfig holds the explicit and (optional) wildcard configuration for
// one chain-specific namespace. v1 arrays parse into Explicit only; v2 objects
// may also set Wildcard.
type NamespaceConfig struct {
	Explicit []ExtraRPCMethod
	Wildcard *WildcardConfig
}

// ExtraRPCMethod represents a single explicit chain-specific RPC method entry.
// Every entry must have an alias to a standard Ethereum method so contract
// access checks and response redaction inherit a known shape.
type ExtraRPCMethod struct {
	Method string `json:"method"`          // The chain-specific method name (e.g. "linea_estimateGas")
	Alias  string `json:"alias,omitempty"` // Standard method to inherit access control from (e.g. "eth_estimateGas")
}

// WildcardConfig opts a namespace into prefix-wildcard mode (v2+). Methods that
// start with Prefix and don't match any Deny glob are forwarded to the upstream
// node as-is — no contract access check, no field-level redaction. The proxy
// trusts the operator's deny list + the global blocklist; the operator owns
// responsibility for what the upstream may expose under this prefix.
type WildcardConfig struct {
	// Prefix is matched verbatim against the start of the method name (e.g. "linea_").
	// Required; must be non-empty.
	Prefix string `json:"prefix"`

	// Deny is a list of glob patterns (suffix-* supported) that block specific
	// methods even when they match Prefix. Evaluated before the prefix allow.
	// Examples: "linea_sendTransaction", "linea_sign*".
	Deny []string `json:"deny,omitempty"`
}

// UnmarshalJSON dispatches on the JSON shape of each namespace value:
//   - array → v1-style explicit list
//   - object → v2-style {explicit, wildcard}
//
// The object form is rejected when the file declares Version < 2.
func (e *ExtraRPCNamespaces) UnmarshalJSON(data []byte) error {
	var raw struct {
		Version    int                        `json:"version"`
		Namespaces map[string]json.RawMessage `json:"namespaces"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	e.Version = raw.Version
	e.Namespaces = make(map[string]NamespaceConfig, len(raw.Namespaces))
	for ns, entry := range raw.Namespaces {
		nc, err := parseNamespaceConfig(ns, entry, raw.Version)
		if err != nil {
			return err
		}
		e.Namespaces[ns] = nc
	}
	return nil
}

func parseNamespaceConfig(ns string, raw json.RawMessage, version int) (NamespaceConfig, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return NamespaceConfig{}, fmt.Errorf("namespace %q: empty value", ns)
	}
	switch trimmed[0] {
	case '[':
		entries, err := parseExplicitMethods(ns, trimmed)
		if err != nil {
			return NamespaceConfig{}, err
		}
		return NamespaceConfig{Explicit: entries}, nil
	case '{':
		if version < 2 {
			return NamespaceConfig{}, fmt.Errorf("namespace %q: object form (with wildcard) requires version >= 2 in the EXTRA_RPC_NAMESPACES file", ns)
		}
		var obj struct {
			Explicit []json.RawMessage `json:"explicit"`
			Wildcard *WildcardConfig   `json:"wildcard,omitempty"`
		}
		if err := json.Unmarshal(trimmed, &obj); err != nil {
			return NamespaceConfig{}, fmt.Errorf("namespace %q: invalid object: %w", ns, err)
		}
		// Re-marshal explicit entries through parseExplicitMethods so validation
		// stays in one place. Build a synthetic JSON array for it.
		var explicit []ExtraRPCMethod
		if len(obj.Explicit) > 0 {
			arrBytes, err := json.Marshal(obj.Explicit)
			if err != nil {
				return NamespaceConfig{}, fmt.Errorf("namespace %q: failed to re-marshal explicit list: %w", ns, err)
			}
			explicit, err = parseExplicitMethods(ns, arrBytes)
			if err != nil {
				return NamespaceConfig{}, err
			}
		}
		if obj.Wildcard != nil {
			if err := obj.Wildcard.validate(ns); err != nil {
				return NamespaceConfig{}, err
			}
		}
		return NamespaceConfig{Explicit: explicit, Wildcard: obj.Wildcard}, nil
	default:
		return NamespaceConfig{}, fmt.Errorf("namespace %q: value must be a v1-style array or v2-style object, got: %s", ns, string(trimmed))
	}
}

func parseExplicitMethods(ns string, data []byte) ([]ExtraRPCMethod, error) {
	var entries []json.RawMessage
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("namespace %q: invalid array: %w", ns, err)
	}
	methods := make([]ExtraRPCMethod, 0, len(entries))
	for _, entry := range entries {
		var m ExtraRPCMethod
		if err := json.Unmarshal(entry, &m); err != nil {
			return nil, fmt.Errorf("namespace %q: invalid entry (must be {\"method\":..., \"alias\":...}): %s", ns, string(entry))
		}
		if m.Method == "" {
			return nil, fmt.Errorf("namespace %q: entry missing 'method' field: %s", ns, string(entry))
		}
		if m.Alias == "" {
			return nil, fmt.Errorf("namespace %q: method %q missing 'alias' field — all extra methods must have an alias to a standard Ethereum method for access control and response filtering", ns, m.Method)
		}
		methods = append(methods, m)
	}
	return methods, nil
}

func (w *WildcardConfig) validate(ns string) error {
	if strings.TrimSpace(w.Prefix) == "" {
		return fmt.Errorf("namespace %q wildcard: 'prefix' is required and must be non-empty (e.g. \"linea_\")", ns)
	}
	for _, deny := range w.Deny {
		if strings.TrimSpace(deny) == "" {
			return fmt.Errorf("namespace %q wildcard: 'deny' entries must be non-empty", ns)
		}
	}
	return nil
}

// MethodNames returns a flat list of explicit method names per namespace
// (for the status API; wildcard methods are not enumerated since they are open-ended).
func (e *ExtraRPCNamespaces) MethodNames() map[string][]string {
	result := make(map[string][]string, len(e.Namespaces))
	for ns, nc := range e.Namespaces {
		names := make([]string, len(nc.Explicit))
		for i, m := range nc.Explicit {
			names[i] = m.Method
		}
		result[ns] = names
	}
	return result
}

// Aliases returns a map of method→alias for every explicit chain-specific method.
func (e *ExtraRPCNamespaces) Aliases() map[string]string {
	aliases := make(map[string]string)
	for _, nc := range e.Namespaces {
		for _, m := range nc.Explicit {
			if m.Alias != "" {
				aliases[m.Method] = m.Alias
			}
		}
	}
	return aliases
}

// Wildcards returns the namespace→wildcard config map for namespaces that opt in.
// Used by the rbac registration step at startup.
func (e *ExtraRPCNamespaces) Wildcards() map[string]*WildcardConfig {
	out := make(map[string]*WildcardConfig)
	for ns, nc := range e.Namespaces {
		if nc.Wildcard != nil {
			out[ns] = nc.Wildcard
		}
	}
	return out
}

type Config struct {
	Version     string // Set by cmd/server/main.go from build-time constant
	NodeURL     string
	DatabaseURL string
	// DB connection pool sizing (RD-1112). DBMaxIdleConns defaults to
	// DBMaxOpenConns to avoid connection churn; size DBMaxOpenConns so N
	// replicas stay under Postgres max_connections.
	DBMaxOpenConns    int
	DBMaxIdleConns    int
	DBConnMaxLifetime time.Duration
	// Upstream node HTTP transport pool (RD-1112). proxy + tracer talk to one
	// node host at high concurrency; Go's default caps idle keep-alive at 2
	// per host, churning TCP connections. These tune the pool.
	NodeMaxIdleConns        int
	NodeMaxIdleConnsPerHost int
	NodeMaxConnsPerHost     int
	NodeIdleConnTimeout     time.Duration
	// AuditBufferDir, when set, enables async access-log auditing (RD-1112):
	// the hot path appends to a durable Pebble buffer at this path and a
	// background sealer drains it into the chain. Empty = synchronous (legacy).
	AuditBufferDir string
	// AuditCheckpointKey, when set, enables signed truncation-detection
	// checkpoints (RD-1112 #8): the checkpoint worker signs the chain head +
	// row count so the verifier can detect tail truncation. HMAC key for MVP —
	// source it from a secret DISTINCT from the DB credential (a signature the
	// DB-writing identity can also forge is decorative). Empty = disabled.
	AuditCheckpointKey      string
	AuditCheckpointInterval time.Duration
	// AuditChainName is this instance's audit chain partition (RD-1112 #8).
	// Default 'access_logs' (one global chain). For multi-instance, set a
	// per-instance value (e.g. hostname / pod name) so each instance is the
	// SOLE writer of its own chain — preventing the multi-writer chain fork.
	AuditChainName string
	// AuditDatabaseURL is the RUNTIME identity for the SEPARATE, always-on
	// append-only audit database that holds access_logs (RD-1147). access_logs is
	// ALWAYS in a separate database — there is NO fallback to the main DB. This
	// DSN SHOULD connect as the restricted privacy_proxy_app role so the
	// append-only seal (INSERT+SELECT, no UPDATE/DELETE — audit migration 002)
	// actually bites. When AUDIT_DATABASE_URL is unset it is DERIVED from
	// DATABASE_URL by swapping the database name to "<name>_audit" on the SAME
	// server; the derived default reuses DATABASE_URL's (owner) credentials, so
	// the seal is NOT enforced on it — set an explicit URL with the restricted
	// role to enforce the seal. An explicit URL may point at another server.
	AuditDatabaseURL string
	// AuditAdminDatabaseURL is the ADMIN/owner identity for the audit database
	// (RD-1147): it runs the lean audit migrations at startup and performs
	// retention prune (DELETE), which the restricted runtime role cannot. When
	// unset it is DERIVED from DATABASE_URL the same way as AuditDatabaseURL
	// ("<name>_audit" on the same server, DATABASE_URL credentials). The app
	// NEVER runs CREATE DATABASE — infra must have provisioned the audit database
	// already; the app only connects and migrates it.
	AuditAdminDatabaseURL string
	ExplorerDatabaseURL   string
	// IndexerURL, when non-empty, enables the gRPC chain-indexer backend for
	// explorer reads. Methods not yet ported to gRPC fall back to direct
	// SQL on the explorer postgres. Leave empty to use SQL exclusively.
	// Set this (and point it at the chain-indexer service) to start the
	// RD-855 Phase 3 cutover.
	IndexerURL       string
	PrivadoRPCURL    string
	IPFSGateway      string
	JWTSecret        string
	JWTRefreshSecret string
	// Previous JWT secrets accepted for validation only (never signing), for
	// hitless secret rotation (RD-1164 #15). Comma-separated; empty = no window.
	JWTSecretPrevious        []string // JWT_SECRET_PREVIOUS
	JWTRefreshSecretPrevious []string // JWT_REFRESH_SECRET_PREVIOUS
	VerifierID               string   // DID or identifier of the verifier
	BaseURL                  string   // Base URL for callback (e.g., https://api.example.com)
	Port                     string   // Server port (e.g., "8080")
	Environment              string   // "production" or "development"
	BillionsIssuerDID        string   // Billions issuer DID for ProofOfHumanity verification
	RequireProofOfHumanity   bool     // Opt-in enforcement of Path B (credential check). Default: false in every environment.

	// iden3 network resolvers. The verifier resolves each wallet's DID to its
	// on-chain identity state via a per-network resolver keyed
	// "blockchain:network". PrivadoRPCURL + PrivadoStateContract back the
	// privado:main resolver; the two below back billions:main so wallets created
	// in the Billions app (DIDs anchored on the Billions chain, chainID 45056)
	// can authenticate. Unlike Path B below, these are always consulted — basic
	// DID-ownership auth needs the resolver regardless of ProofOfHumanity. RD-943.
	BillionsRPCURL        string // env BILLIONS_RPC_URL — RPC for the Billions identity chain
	BillionsStateContract string // env BILLIONS_STATE_CONTRACT — Billions on-chain identity state contract

	// Path B (ProofOfHumanity / Billions) configuration. Only consulted when RequireProofOfHumanity=true.
	PrivadoStateContract        string         // env PRIVADO_STATE_CONTRACT — on-chain identity state contract
	PrivadoCircuitID            string         // env PRIVADO_CIRCUIT_ID — iden3 circuit (e.g. credentialAtomicQueryMTPV2)
	BillionsCredentialSchemaURL string         // env BILLIONS_CREDENTIAL_SCHEMA_URL — JSON-LD schema URL for the credential
	BillionsCredentialType      string         // env BILLIONS_CREDENTIAL_TYPE — credential type name declared by the schema
	BillionsCredentialQueryFile string         // env BILLIONS_CREDENTIAL_QUERY_FILE — path to JSON file with the credential query
	BillionsCredentialQuery     map[string]any // Parsed from BillionsCredentialQueryFile at startup

	AdminAPIToken          string              // Shared token required for admin API access (required in production). FULL super-admin: reads + writes + platform/fleet. Held by trusted ops / MCP.
	OperatorAPIToken       string              // RD-1132: optional restricted "operator/onboarder" token. Platform-only — create/manage orgs + mint org admins; NO per-org tenant reads or mutations. For a 3rd-party onboarder that should not see/touch tenant data.
	ENSResolverURL         string              // Ethereum mainnet RPC URL for ENS resolution
	CORSAllowedOrigins     string              // Comma-separated list of allowed origins, or "*" for all (default: "*" in dev)
	MockSignatures         bool                // If true, accept any signature without verification (dev/demo only, NEVER in production)
	AllowMockLogin         bool                // If true, accept mock JWZ tokens for testing (dev/demo only, NEVER in production)
	OAuthFirstPartyClients map[string]string   // RD-993 + RD-1006: client_id → bcrypt-hashed client_secret. Each first-party client must carry a secret; the proxy verifies it at /oauth/token. Empty map = no client gets silent SSO; falls back to interactive Privado flow.
	DemoAutoAuthDelay      time.Duration       // Auto-complete auth sessions for demo recording (0 = disabled, forced off in production)
	ExtraRPCNamespacesFile string              // Path to JSON file with additional RPC method namespaces (e.g. Linea's linea_*)
	ExtraRPCNamespaces     *ExtraRPCNamespaces // Parsed from ExtraRPCNamespacesFile

	// Runtime tracing configuration
	TraceCacheTTL         time.Duration // TTL for trace result cache (default: 10s)
	TraceTimeout          time.Duration // Timeout for debug_traceCall requests (default: 30s)
	TraceTieredValidation bool          // If true, skip trace for known org addresses (default: true)
	// RuntimeTracingEthCallEnabled controls runtime tracing of eth_call
	// requests for cross-org isolation (RD-915). Default true; only flip
	// to false as a documented sev-1 rollback path. Has no effect when
	// runtime tracing is globally off.
	RuntimeTracingEthCallEnabled bool
	// EthCallTraceTimeout caps how long the proxy will wait for the
	// upstream debug_traceCall on the eth_call validation path. Distinct
	// from the send-side TraceTimeout so a slow upstream cannot fill the
	// concurrency-limiter quota for read-heavy callers (RD-915 KD on
	// per-call timeout). Default 5s.
	EthCallTraceTimeout time.Duration
	// RuntimeTracingIntraOrgGrantsEnabled controls whether runtime tracing
	// additionally enforces intra-org contract-grant scoping on internal
	// CALL/STATICCALL/DELEGATECALL frames (RD-1053). When true, a frame into
	// a contract owned by one of the user's orgs is allowed only if the
	// caller has a contract-level grant for it (mirrors the entry-point
	// CheckAccess); when false (default), internal frames are gated by org
	// ownership alone. Cross-org isolation is enforced regardless of this
	// flag. Has no effect when runtime tracing is globally off. Governs the
	// read side (eth_call / debug_traceCall) and the send side
	// (eth_sendTransaction / eth_sendRawTransaction / deploy).
	RuntimeTracingIntraOrgGrantsEnabled bool

	// Travel rule compliance configuration
	EnableTravelRule   bool          // If true, enable travel rule enforcement (default: false)
	TravelRecordExpiry time.Duration // How long travel rule records stay valid (default: 24h)
	// ComplianceDefaultMode is the cluster-wide default enforcement mode
	// ("enforce" | "monitor") for orgs that have not set a per-org mode.
	// Default "enforce" (fail-closed). Per-org config overrides it; surfaced
	// in /status. (RD-1044)
	ComplianceDefaultMode string

	// Auto-KYC provisioning policy (RD-1131). When true, a NEWLY provisioned
	// identity of the given class is created KYC-verified, skipping the manual
	// KYC gate. Default false (fail-safe). RELAXES A COMPLIANCE CONTROL — enabling
	// requires Compliance/Legal sign-off. Never affects existing users: KYC stays
	// admin-managed once a row exists (see rbac.EnsureUserExists).
	AutoKYCPrivado               bool // AUTO_KYC_PRIVADO
	AutoKYCAzureUser             bool // AUTO_KYC_AZURE_USER
	AutoKYCAzureServicePrincipal bool // AUTO_KYC_AZURE_SERVICE_PRINCIPAL

	// Token price fetching configuration
	PriceFetchInterval      time.Duration // How often to fetch prices from CoinGecko (default: 5m)
	PriceStalenessThreshold time.Duration // After this duration, prices are considered stale (default: 15m)
	DisableCoinGecko        bool          // If true, disable CoinGecko price fetching (default: false)

	// Audit configuration
	AuditLogParams bool // If true, log redacted request parameters in access_logs (default: false)

	// OrgAdminViewUserTxs, when true, lets org admins see user↔user transaction
	// rows (both-sides-private transfers, deploys, internal txs) in the explorer
	// with value/amount preserved. Counterparty addresses still render as
	// [PRIVATE] — this grants a volume/timing audit view, NOT real-address
	// visibility (that is deferred to a dedicated compliance role). Default
	// false = strict privacy (such rows are dropped). Every request that
	// actually reveals a row under this flag is written to rbac_audit_log.
	OrgAdminViewUserTxs bool

	// Retention policy configuration (0 = keep forever)
	RetentionAccessLogs      time.Duration // Retention for access_logs (default: 90 days)
	RetentionComplianceLogs  time.Duration // Retention for compliance_logs (default: 7 years)
	RetentionRBACAuditLogs   time.Duration // Retention for rbac_audit_log (default: 1 year)
	RetentionTravelRecords   time.Duration // Retention for used travel_rule_records (default: 7 years)
	RetentionCleanupInterval time.Duration // How often retention cleanup runs (default: 1 hour)
	// MaxAccessLogRows caps the access_logs table at this row count using a
	// FIFO sweep that runs alongside the time-based prune. 0 = unlimited
	// (time-based retention only). The hash chain anchor table preserves the
	// chain seed across both prune paths.
	MaxAccessLogRows int64

	// SIEM webhook configuration
	SIEMWebhookURL      string        // SIEM webhook endpoint (empty = disabled)
	SIEMAuthHeader      string        // Authorization header for SIEM webhook
	SIEMBatchSize       int           // Events per SIEM batch (default: 100)
	SIEMFlushInterval   time.Duration // Max time before flushing SIEM batch (default: 10s)
	SIEMFallbackLogPath string        // If set, failed SIEM batches written here as JSON lines (M4 fix)

	// Audit hash-chain integrity worker (RD-858)
	AuditIntegrityVerifyInterval time.Duration // How often the scheduled verifier walks the chains (default: 15m; 0 = disabled).
	AuditTamperWebhookURL        string        // Optional generic webhook POSTed when the verifier detects tampering. Subject to the same SSRF guard as SIEMWebhookURL. Empty = disabled (SIEM-only notification path).

	// Hide the auto-created dev-admin org from the admin dashboard (for demos)
	HideDevAdminOrg bool

	// Tunnel URL file path — cloudflared writes the public URL here (auto-detected)
	TunnelURLFile string

	// Trusted Proxies for X-Forwarded-For trust
	TrustedProxies []string // List of IPs/CIDRs to trust for client IP extraction

	// Additional CIDRs allowed to access internal APIs (explorer, admin).
	// Appended to the default private-network allowlist (localhost, Docker, RFC1918, Tailscale).
	// Use for Kubernetes pod CIDRs, cloud VPC ranges, or custom networks.
	TrustedInternalCIDRs []string

	// Frontend URL for OAuth redirect (e.g., http://localhost:5173)
	// When set, /oauth/authorize redirects browsers to the React login page instead of serving inline HTML.
	FrontendURL string

	// RPC API key for upstream RPC proxy authentication
	RPCAPIKey                      string // RPC_API_KEY — global fallback when no group-specific key is set
	RPCAPIKeyHeader                string // RPC_API_KEY_HEADER — header name used to send the RPC API key (default "Authorization", which sends "Bearer <key>"); any other value sends the raw key under that header
	RPCAPIKeyEncryptionKey         []byte // RPC_API_KEY_ENCRYPTION_KEY — 32-byte hex key for AES-256 encryption of RPC API keys at rest
	ExplorerPseudonymKey           []byte // EXPLORER_PSEUDONYM_KEY — HMAC key for explorer address pseudonyms (non-reversible, non-enumerable). Optional; set in production.
	MaxConcurrentRequests          int    // MAX_CONCURRENT_REQUESTS — per-user concurrency cap (default: 50)
	MaxConcurrentAnonymousRequests int    // MAX_CONCURRENT_ANONYMOUS_REQUESTS — shared concurrency cap for anonymous /rpc traffic (default: = MaxConcurrentRequests; 0 disables)

	// Azure AD / Microsoft Entra ID authentication
	AzureADClientID     string // AZURE_AD_CLIENT_ID
	AzureADClientSecret string // AZURE_AD_CLIENT_SECRET
	AzureADTenantID     string // AZURE_AD_TENANT_ID (default: "common" for multi-tenant)
	// AzureADSPAudience is the expected `aud` for service-principal
	// (client-credentials) access tokens at /api/v1/auth/azure/service-principal
	// (RD-1120). Empty defaults to AzureADClientID. Set this when the client
	// requests the token for a distinct API resource (e.g. api://<app-id>).
	AzureADSPAudience string // AZURE_AD_SP_AUDIENCE

	// Redis URL for shared state stores (e.g., "redis://localhost:6379").
	// Empty means fall back to in-memory stores.
	RedisURL string
}

func Load() *Config {
	// Load the optional structured config file (CONFIG_FILE) before reading any
	// setting, so its values are available as a fallback layer to every getEnv
	// call below. A bad/unsupported file is recorded and surfaced by Validate()
	// so startup fails fast rather than silently using environment defaults.
	// No file configured => pure-environment mode (backwards compatible). (RD-1130)
	fileConfigErr = loadConfigFile()

	env := getEnv("ENVIRONMENT", "development")
	// RequireProofOfHumanity is opt-in in every environment. Admin must explicitly
	// set REQUIRE_PROOF_OF_HUMANITY=true AND fill the Path B config (issuer DID,
	// schema URL, credential type, circuit ID, query file). Until then, login is
	// plain DID-ownership proof (Path A). This keeps prod from booting with
	// placeholder credential values that would break login for every user.
	requirePoHBool := getEnv("REQUIRE_PROOF_OF_HUMANITY", "") == "true"

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

	// Extra RPC namespaces (chain-specific method extensions, loaded from file)
	extraRPCNamespacesFile := getEnv("EXTRA_RPC_NAMESPACES_FILE", "")
	var extraRPCNamespaces *ExtraRPCNamespaces
	if extraRPCNamespacesFile != "" {
		raw, err := os.ReadFile(extraRPCNamespacesFile)
		if err != nil {
			panic(fmt.Sprintf("EXTRA_RPC_NAMESPACES_FILE: failed to read %s: %v", extraRPCNamespacesFile, err))
		}
		var parsed ExtraRPCNamespaces
		if err := json.Unmarshal(raw, &parsed); err != nil {
			panic(fmt.Sprintf("EXTRA_RPC_NAMESPACES_FILE: invalid JSON in %s: %v", extraRPCNamespacesFile, err))
		}
		if parsed.Version != 1 && parsed.Version != 2 {
			panic(fmt.Sprintf("EXTRA_RPC_NAMESPACES_FILE: unsupported version %d in %s (expected 1 or 2)", parsed.Version, extraRPCNamespacesFile))
		}
		extraRPCNamespaces = &parsed
	}

	// Runtime tracing configuration
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
	ethCallTracingEnabled := getEnv("RUNTIME_TRACING_ETH_CALL_ENABLED", "true") != "false"
	// RD-1053: intra-org contract-grant scoping on internal trace frames.
	// Defaults OFF — org ownership stays the structural isolation boundary;
	// operators opt in when they want grants to gate composition within an
	// org too. Cross-org isolation is unaffected either way.
	intraOrgGrantsTracingEnabled := getEnv("RUNTIME_TRACING_INTRA_ORG_GRANTS_ENABLED", "false") == "true"
	ethCallTraceTimeout := 5 * time.Second
	if t := getEnv("ETH_CALL_TRACE_TIMEOUT", ""); t != "" {
		if d, err := time.ParseDuration(t); err == nil {
			ethCallTraceTimeout = d
		}
	}

	// Travel rule compliance configuration
	enableTravelRule := getEnv("ENABLE_TRAVEL_RULE", "false") == "true"
	travelRecordExpiry := 24 * time.Hour
	if expiryStr := getEnv("TRAVEL_RECORD_EXPIRY", ""); expiryStr != "" {
		if d, err := time.ParseDuration(expiryStr); err == nil {
			travelRecordExpiry = d
		}
	}

	// COMPLIANCE_DEFAULT_MODE: cluster-wide default enforcement mode for orgs
	// without a per-org setting. Invalid values fall back to the safe default
	// (enforce) silently — fail-safe per RD-1044.
	complianceDefaultMode := strings.ToLower(getEnv("COMPLIANCE_DEFAULT_MODE", "enforce"))
	if complianceDefaultMode != "enforce" && complianceDefaultMode != "monitor" {
		complianceDefaultMode = "enforce"
	}

	// Auto-KYC provisioning policy (RD-1131). Default false everywhere — a newly
	// provisioned identity is created KYC-verified ONLY if its class is explicitly
	// opted in. This relaxes the KYC compliance gate, so warn loudly at startup
	// when any class is enabled (change-management / Compliance visibility).
	autoKYCPrivado := getEnv("AUTO_KYC_PRIVADO", "false") == "true"
	autoKYCAzureUser := getEnv("AUTO_KYC_AZURE_USER", "false") == "true"
	autoKYCAzureSP := getEnv("AUTO_KYC_AZURE_SERVICE_PRINCIPAL", "false") == "true"
	if autoKYCPrivado || autoKYCAzureUser || autoKYCAzureSP {
		slog.Warn("auto-KYC is ENABLED — newly provisioned identities of the selected classes are created KYC-verified, bypassing the manual KYC gate; ensure this is covered by Compliance/Legal sign-off",
			"privado", autoKYCPrivado, "azure_user", autoKYCAzureUser, "azure_service_principal", autoKYCAzureSP)
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

	disableCoinGecko := getEnv("DISABLE_COINGECKO", "false") == "true"

	// Audit configuration
	auditLogParams := getEnv("AUDIT_LOG_PARAMS", "false") == "true"

	// Org-admin elevated transaction visibility (default off = strict privacy).
	orgAdminViewUserTxs := getEnv("ORG_ADMIN_VIEW_USER_TXS", "false") == "true"

	// Retention policy configuration
	retentionAccessLogs := parseDurationEnv("RETENTION_ACCESS_LOGS", 90*24*time.Hour)            // 90 days
	retentionComplianceLogs := parseDurationEnv("RETENTION_COMPLIANCE_LOGS", 7*365*24*time.Hour) // ~7 years
	retentionRBACAuditLogs := parseDurationEnv("RETENTION_RBAC_AUDIT_LOGS", 365*24*time.Hour)    // 1 year
	retentionTravelRecords := parseDurationEnv("RETENTION_TRAVEL_RECORDS", 7*365*24*time.Hour)   // ~7 years
	retentionCleanupInterval := parseDurationEnv("RETENTION_CLEANUP_INTERVAL", 1*time.Hour)

	// FIFO row cap on access_logs (0 = unlimited).
	var maxAccessLogRows int64
	if maxStr := getEnv("MAX_ACCESS_LOG_ROWS", ""); maxStr != "" {
		if n, err := strconv.ParseInt(maxStr, 10, 64); err == nil && n >= 0 {
			maxAccessLogRows = n
		}
	}

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

	// RD-858: scheduled audit-chain integrity verifier.
	auditIntegrityInterval := parseDurationEnv("AUDIT_INTEGRITY_VERIFY_INTERVAL", 15*time.Minute)
	auditTamperWebhookURL := getEnv("AUDIT_TAMPER_WEBHOOK_URL", "")

	// Per-user concurrency cap (default 50)
	maxConcurrentRequests := 50
	if mcStr := getEnv("MAX_CONCURRENT_REQUESTS", ""); mcStr != "" {
		if n, err := strconv.Atoi(mcStr); err == nil && n > 0 {
			maxConcurrentRequests = n
		}
	}

	// Shared concurrency cap for anonymous /rpc traffic (RD-1164 #3). The
	// per-user cap above is keyed by DID and cannot bound anonymous callers
	// (no identity), so anonymous floods were previously uncapped and still did
	// JWT/RBAC/compliance DB work per request. All anonymous requests draw from
	// one shared bucket (not per-IP: IPs are spoofable and shared behind the
	// ingress, so per-IP would let one client starve the rest). Defaults to the
	// per-user cap; set 0 to disable.
	maxConcurrentAnonymousRequests := maxConcurrentRequests
	if maStr := getEnv("MAX_CONCURRENT_ANONYMOUS_REQUESTS", ""); maStr != "" {
		if n, err := strconv.Atoi(maStr); err == nil && n >= 0 {
			maxConcurrentAnonymousRequests = n
		}
	}

	// iden3 network resolver config for the Billions identity chain. The RPC
	// URL has NO default: an unreachable default registers a resolver that
	// cannot work and turns a missing config value into an opaque dial failure
	// during proof verification (RD-1241). Unset means billions:main is not
	// registered, Billions DIDs are rejected immediately and legibly, and the
	// login UI stops advertising the network. The state contract keeps its
	// default because it stays correct once the RPC is supplied, so enabling
	// Billions is a one-variable change.
	billionsRPCURL := getEnv("BILLIONS_RPC_URL", "")
	billionsStateContract := getEnv("BILLIONS_STATE_CONTRACT", auth.BillionsMainnetStateContract)

	// Path B (ProofOfHumanity) configuration with current hardcoded values as defaults.
	privadoStateContract := getEnv("PRIVADO_STATE_CONTRACT", auth.PrivadoMainnetStateContract)
	privadoCircuitID := getEnv("PRIVADO_CIRCUIT_ID", "credentialAtomicQueryMTPV2")
	billionsSchemaURL := getEnv("BILLIONS_CREDENTIAL_SCHEMA_URL", "https://raw.githubusercontent.com/0xPolygonID/tutorial-examples/main/credential-schema/schemas-examples/proof-of-humanity/proof-of-humanity.jsonld")
	billionsCredType := getEnv("BILLIONS_CREDENTIAL_TYPE", "ProofOfHumanity")

	// Credential query loaded from a JSON file — supports multi-field predicates.
	// Failure to read/parse when the env var is set is a hard error: misconfigured
	// prod should not boot silently.
	billionsQueryFile := getEnv("BILLIONS_CREDENTIAL_QUERY_FILE", "")
	var billionsQuery map[string]any
	if billionsQueryFile != "" {
		raw, err := os.ReadFile(billionsQueryFile)
		if err != nil {
			panic(fmt.Sprintf("BILLIONS_CREDENTIAL_QUERY_FILE: failed to read %s: %v", billionsQueryFile, err))
		}
		if err := json.Unmarshal(raw, &billionsQuery); err != nil {
			panic(fmt.Sprintf("BILLIONS_CREDENTIAL_QUERY_FILE: invalid JSON in %s: %v", billionsQueryFile, err))
		}
	}

	// RPC API key encryption key (hex-encoded 32 bytes for AES-256).
	// RD-1164 #2: fail fast on a set-but-invalid key. Previously an invalid value
	// was silently ignored, leaving the key nil — which disables encryption and
	// stores RPC API keys in plaintext at rest while the operator believes
	// encryption is on. A misconfigured prod must not boot silently.
	var rpcAPIKeyEncKey []byte
	if hexKey := getEnv("RPC_API_KEY_ENCRYPTION_KEY", ""); hexKey != "" {
		decoded, err := hex.DecodeString(hexKey)
		if err != nil {
			panic(fmt.Sprintf("RPC_API_KEY_ENCRYPTION_KEY: invalid hex: %v", err))
		}
		if len(decoded) != 32 {
			panic(fmt.Sprintf("RPC_API_KEY_ENCRYPTION_KEY: must decode to 32 bytes (AES-256), got %d", len(decoded)))
		}
		rpcAPIKeyEncKey = decoded
	}

	// Explorer pseudonym HMAC key (hex-encoded, any length). Keys the address
	// pseudonyms shown to viewers so they are non-reversible and non-enumerable
	// (RD-1164 #8). Optional: when unset, pseudonyms are still HMAC-derived (never
	// the old reversible scheme) but, without a secret, can be recomputed from a
	// candidate address — set this in production. Fail fast on invalid hex.
	var pseudonymKey []byte
	if hexKey := getEnv("EXPLORER_PSEUDONYM_KEY", ""); hexKey != "" {
		decoded, err := hex.DecodeString(hexKey)
		if err != nil {
			panic(fmt.Sprintf("EXPLORER_PSEUDONYM_KEY: invalid hex: %v", err))
		}
		pseudonymKey = decoded
	}

	// RPC API key header name. Default "Authorization" preserves Bearer token
	// behaviour. Any other value (e.g. "X-API-Key") is sent verbatim. We
	// validate the format here so a misconfigured value cannot inject CRLF
	// or arbitrary header content downstream.
	rpcAPIKeyHeader := getEnv("RPC_API_KEY_HEADER", proxy.DefaultAPIKeyHeader)
	if !proxy.ValidAPIKeyHeader(rpcAPIKeyHeader) {
		panic(fmt.Sprintf("RPC_API_KEY_HEADER %q is invalid: must match ^[A-Za-z0-9-]+$", rpcAPIKeyHeader))
	}

	dbMaxOpen := getEnvInt("DB_MAX_OPEN_CONNS", 50)
	dbMaxIdle := getEnvInt("DB_MAX_IDLE_CONNS", dbMaxOpen) // default = MaxOpen to avoid connection churn
	dbConnMaxLifetime := parseDurationEnv("DB_CONN_MAX_LIFETIME", 5*time.Minute)
	nodeMaxIdleConns := getEnvInt("NODE_HTTP_MAX_IDLE_CONNS", 512)
	nodeMaxIdleConnsPerHost := getEnvInt("NODE_HTTP_MAX_IDLE_CONNS_PER_HOST", 256)
	nodeMaxConnsPerHost := getEnvInt("NODE_HTTP_MAX_CONNS_PER_HOST", 0)
	nodeIdleConnTimeout := parseDurationEnv("NODE_HTTP_IDLE_CONN_TIMEOUT", 90*time.Second)

	// RD-1147: access_logs ALWAYS lives in a separate audit database. When the
	// two audit DSNs are unset, DERIVE them from DATABASE_URL by swapping the
	// database name to "<name>_audit" on the same server (reusing DATABASE_URL's
	// credentials). An explicit URL overrides (and may point at another server).
	databaseURL := getEnv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/privacy_proxy?sslmode=disable")
	auditDatabaseURL := getEnv("AUDIT_DATABASE_URL", "")
	if auditDatabaseURL == "" {
		auditDatabaseURL = deriveAuditDatabaseURL(databaseURL)
	}
	auditAdminDatabaseURL := getEnv("AUDIT_ADMIN_DATABASE_URL", "")
	if auditAdminDatabaseURL == "" {
		auditAdminDatabaseURL = deriveAuditDatabaseURL(databaseURL)
	}

	return &Config{
		NodeURL:                             getEnv("NODE_URL", "http://localhost:8545"),
		DatabaseURL:                         databaseURL,
		DBMaxOpenConns:                      dbMaxOpen,
		DBMaxIdleConns:                      dbMaxIdle,
		DBConnMaxLifetime:                   dbConnMaxLifetime,
		NodeMaxIdleConns:                    nodeMaxIdleConns,
		NodeMaxIdleConnsPerHost:             nodeMaxIdleConnsPerHost,
		NodeMaxConnsPerHost:                 nodeMaxConnsPerHost,
		NodeIdleConnTimeout:                 nodeIdleConnTimeout,
		AuditBufferDir:                      getEnv("AUDIT_BUFFER_DIR", ""),
		AuditCheckpointKey:                  getEnv("AUDIT_CHECKPOINT_KEY", ""),
		AuditCheckpointInterval:             parseDurationEnv("AUDIT_CHECKPOINT_INTERVAL", time.Minute),
		AuditChainName:                      getEnv("AUDIT_CHAIN_NAME", "access_logs"),
		PrivadoRPCURL:                       getEnv("PRIVADO_RPC_URL", "https://rpc-mainnet.privado.id"),
		IPFSGateway:                         getEnv("IPFS_GATEWAY", "https://ipfs-proxy-cache.privado.id"), // IPFS gateway for schema resolution
		JWTSecret:                           getEnv("JWT_SECRET", ""),                                      // If empty, will be auto-generated (dev only)
		JWTRefreshSecret:                    getEnv("JWT_REFRESH_SECRET", ""),                              // If empty, will be auto-generated (dev only)
		JWTSecretPrevious:                   getSliceEnv("JWT_SECRET_PREVIOUS", ","),
		JWTRefreshSecretPrevious:            getSliceEnv("JWT_REFRESH_SECRET_PREVIOUS", ","),
		VerifierID:                          getEnv("VERIFIER_ID", ""),                   // Required in production
		BaseURL:                             getEnv("BASE_URL", "http://localhost:8080"), // Base URL for callback
		Port:                                getEnv("PORT", "8080"),                      // Server port
		Environment:                         env,
		BillionsIssuerDID:                   getEnv("BILLIONS_ISSUER_DID", ""), // Billions issuer DID for PoH
		RequireProofOfHumanity:              requirePoHBool,
		BillionsRPCURL:                      billionsRPCURL,
		BillionsStateContract:               billionsStateContract,
		PrivadoStateContract:                privadoStateContract,
		PrivadoCircuitID:                    privadoCircuitID,
		BillionsCredentialSchemaURL:         billionsSchemaURL,
		BillionsCredentialType:              billionsCredType,
		BillionsCredentialQueryFile:         billionsQueryFile,
		BillionsCredentialQuery:             billionsQuery,
		AdminAPIToken:                       getEnv("ADMIN_API_TOKEN", ""),
		OperatorAPIToken:                    getEnv("OPERATOR_API_TOKEN", ""),
		ENSResolverURL:                      getEnv("ENS_RESOLVER_URL", "https://eth.llamarpc.com"), // Public mainnet RPC
		CORSAllowedOrigins:                  corsOrigins,
		MockSignatures:                      mockSigs,
		AllowMockLogin:                      allowMockLogin,
		OAuthFirstPartyClients:              parseFirstPartyClients(getEnv("OAUTH_FIRST_PARTY_CLIENTS", "")),
		DemoAutoAuthDelay:                   demoDelay,
		ExtraRPCNamespacesFile:              extraRPCNamespacesFile,
		ExtraRPCNamespaces:                  extraRPCNamespaces,
		TraceCacheTTL:                       traceCacheTTL,
		TraceTimeout:                        traceTimeout,
		TraceTieredValidation:               traceTiered,
		RuntimeTracingEthCallEnabled:        ethCallTracingEnabled,
		EthCallTraceTimeout:                 ethCallTraceTimeout,
		RuntimeTracingIntraOrgGrantsEnabled: intraOrgGrantsTracingEnabled,
		EnableTravelRule:                    enableTravelRule,
		TravelRecordExpiry:                  travelRecordExpiry,
		ComplianceDefaultMode:               complianceDefaultMode,
		AutoKYCPrivado:                      autoKYCPrivado,
		AutoKYCAzureUser:                    autoKYCAzureUser,
		AutoKYCAzureServicePrincipal:        autoKYCAzureSP,
		PriceFetchInterval:                  priceFetchInterval,
		PriceStalenessThreshold:             priceStalenessThreshold,
		DisableCoinGecko:                    disableCoinGecko,
		AuditLogParams:                      auditLogParams,
		OrgAdminViewUserTxs:                 orgAdminViewUserTxs,
		RetentionAccessLogs:                 retentionAccessLogs,
		RetentionComplianceLogs:             retentionComplianceLogs,
		RetentionRBACAuditLogs:              retentionRBACAuditLogs,
		RetentionTravelRecords:              retentionTravelRecords,
		RetentionCleanupInterval:            retentionCleanupInterval,
		MaxAccessLogRows:                    maxAccessLogRows,
		SIEMWebhookURL:                      siemWebhookURL,
		SIEMAuthHeader:                      siemAuthHeader,
		SIEMBatchSize:                       siemBatchSize,
		SIEMFlushInterval:                   siemFlushInterval,
		SIEMFallbackLogPath:                 getEnv("SIEM_FALLBACK_LOG_PATH", ""),
		AuditIntegrityVerifyInterval:        auditIntegrityInterval,
		AuditTamperWebhookURL:               auditTamperWebhookURL,
		AuditDatabaseURL:                    auditDatabaseURL,
		AuditAdminDatabaseURL:               auditAdminDatabaseURL,
		ExplorerDatabaseURL:                 getEnv("EXPLORER_DATABASE_URL", ""),
		IndexerURL:                          getEnv("INDEXER_URL", ""),
		TunnelURLFile:                       getEnv("TUNNEL_URL_FILE", ""),
		HideDevAdminOrg:                     getEnv("HIDE_DEV_ADMIN_ORG", "false") == "true",
		TrustedProxies:                      getSliceEnv("TRUSTED_PROXIES", ","),
		TrustedInternalCIDRs:                getSliceEnv("TRUSTED_INTERNAL_CIDRS", ","),
		FrontendURL:                         getEnv("FRONTEND_URL", ""),
		RPCAPIKey:                           getEnv("RPC_API_KEY", ""),
		RPCAPIKeyHeader:                     rpcAPIKeyHeader,
		RPCAPIKeyEncryptionKey:              rpcAPIKeyEncKey,
		ExplorerPseudonymKey:                pseudonymKey,
		MaxConcurrentRequests:               maxConcurrentRequests,
		MaxConcurrentAnonymousRequests:      maxConcurrentAnonymousRequests,
		AzureADClientID:                     getEnv("AZURE_AD_CLIENT_ID", ""),
		AzureADClientSecret:                 getEnv("AZURE_AD_CLIENT_SECRET", ""),
		AzureADTenantID:                     getEnv("AZURE_AD_TENANT_ID", "common"),
		AzureADSPAudience:                   getEnv("AZURE_AD_SP_AUDIENCE", ""),
		RedisURL:                            getEnv("REDIS_URL", ""),
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

// parseFirstPartyClients parses OAUTH_FIRST_PARTY_CLIENTS into a {clientID:
// bcryptHash} map. Format: comma-separated <clientID>:<bcryptHash> entries.
// Fails closed: a malformed entry (missing :<hash>) panics at startup rather
// than silently degrading silent SSO to "no client authentication" (RD-1006).
// Empty raw → empty map → silent SSO disabled for every client.
func parseFirstPartyClients(raw string) map[string]string {
	out := map[string]string{}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return out
	}
	for _, e := range strings.Split(raw, ",") {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		id, hash, ok := strings.Cut(e, ":")
		id = strings.TrimSpace(id)
		hash = strings.TrimSpace(hash)
		if !ok || id == "" || hash == "" {
			panic(fmt.Sprintf("OAUTH_FIRST_PARTY_CLIENTS: entry %q must be <client_id>:<bcrypt_hash> (RD-1006). Generate a hash with: htpasswd -bnBC 12 \"\" \"$SECRET\" | tr -d ':\\n'", e))
		}
		out[id] = hash
	}
	return out
}

// IsProduction returns true if running in production mode
func (c *Config) IsProduction() bool {
	return c.Environment == "production"
}

// IsFirstPartyOAuthClient reports whether the given OAuth client_id is on
// the configured first-party allowlist (RD-993). First-party clients are
// eligible for the silent-SSO path (`prompt=none` semantics) which skips
// the interactive Privado / login UI when the caller already has an active
// PP session AND is the initiator of the OAuth flow. An empty allowlist
// means no client gets silent SSO — every flow falls back to interactive.
// Case-sensitive match against the trimmed env-supplied list.
func (c *Config) IsFirstPartyOAuthClient(clientID string) bool {
	if clientID == "" {
		return false
	}
	_, ok := c.OAuthFirstPartyClients[clientID]
	return ok
}

// VerifyFirstPartyClientSecret reports whether clientID is on the first-party
// allowlist AND the provided plaintext secret matches its registered bcrypt
// hash (RD-1006). Verification happens at the /oauth/token endpoint so the
// secret travels server-to-server, never through a browser context. Returns
// false for unknown clients, empty secrets, or any bcrypt mismatch.
func (c *Config) VerifyFirstPartyClientSecret(clientID, secret string) bool {
	if clientID == "" || secret == "" {
		return false
	}
	hash, ok := c.OAuthFirstPartyClients[clientID]
	if !ok {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(secret)) == nil
}

// AzureADEnabled returns true if Azure AD authentication is configured.
// Requires all three: client ID, client secret, and tenant ID.
func (c *Config) AzureADEnabled() bool {
	return c.AzureADClientID != "" && c.AzureADClientSecret != "" && c.AzureADTenantID != ""
}

// Validate checks that required configuration is present.
// In production, certain values must be explicitly configured.
// When RequireProofOfHumanity is enabled, Path B configuration is validated
// regardless of environment — misconfiguring Path B breaks login for everyone.
func (c *Config) Validate() error {
	// A configured-but-unreadable CONFIG_FILE is a fatal misconfiguration: the
	// operator intended to use it, so fail fast instead of silently ignoring it.
	if fileConfigErr != nil {
		return fileConfigErr
	}

	if c.RequireProofOfHumanity {
		if err := c.validateProofOfHumanity(); err != nil {
			return err
		}
	}

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
	if c.NodeURL == "" {
		return errors.New("NODE_URL is required in production (Ethereum node JSON-RPC endpoint)")
	}
	if c.BaseURL == "" {
		return errors.New("BASE_URL is required in production (public URL for OAuth callbacks)")
	}

	// Validate SIEM webhook URL against SSRF if configured.
	if c.SIEMWebhookURL != "" {
		if err := audit.ValidateWebhookURL(c.SIEMWebhookURL); err != nil {
			return err
		}
	}

	// RD-858: same SSRF guard for the audit tamper webhook.
	if c.AuditTamperWebhookURL != "" {
		if err := audit.ValidateWebhookURL(c.AuditTamperWebhookURL); err != nil {
			return fmt.Errorf("AUDIT_TAMPER_WEBHOOK_URL: %w", err)
		}
	}

	// Validate FrontendURL if set: must be HTTPS in production (localhost exempt).
	if c.FrontendURL != "" {
		parsed, err := url.Parse(c.FrontendURL)
		if err != nil || parsed.Host == "" {
			return errors.New("FRONTEND_URL must be a valid URL (e.g. https://proxy.example.com)")
		}
		isLocal := isPrivateOrLocalhost(parsed.Hostname())
		if parsed.Scheme != "https" && !isLocal {
			return errors.New("FRONTEND_URL must use HTTPS in production (localhost and private networks are exempt)")
		}
	}

	// Production hardening warnings (RD-1164 #8/#20/#18). These are safer-by-default
	// controls that are not hard-required (a deliberate single-replica or
	// infra-provisioned deployment may legitimately omit them), so they warn
	// loudly rather than fail — belt-and-suspenders over the shipped prod compose.
	if len(c.ExplorerPseudonymKey) == 0 {
		slog.Warn("EXPLORER_PSEUDONYM_KEY is not set in production: explorer address pseudonyms are unkeyed — non-reversible but offline-ENUMERABLE (an attacker with a candidate address set can correlate pseudonyms back to real addresses). Set EXPLORER_PSEUDONYM_KEY to a 32-byte hex key (RD-1164 #8).")
	}
	if c.RedisURL == "" {
		slog.Warn("REDIS_URL is not set in production: state stores fall back to in-memory, which is NOT safe across multiple replicas (rate-limit counters, sessions and caches are per-process). Configure Redis for any multi-replica deployment (RD-1164 #20).")
	}
	if getEnv("AUDIT_DATABASE_URL", "") == "" {
		slog.Warn("AUDIT_DATABASE_URL is not set in production: the append-only audit database is DERIVED on the same server reusing DATABASE_URL's owner credentials, so the INSERT-only seal is not enforced. Provision a separate audit DB and set AUDIT_DATABASE_URL to its restricted-role DSN (RD-1164 #18).")
	}

	return nil
}

// validateProofOfHumanity checks Path B configuration required when
// RequireProofOfHumanity=true. All values must be non-empty and the parsed
// credential query must contain a non-empty 'credentialSubject' object.
func (c *Config) validateProofOfHumanity() error {
	if c.BillionsIssuerDID == "" {
		return errors.New("BILLIONS_ISSUER_DID is required when REQUIRE_PROOF_OF_HUMANITY=true")
	}
	if c.PrivadoStateContract == "" {
		return errors.New("PRIVADO_STATE_CONTRACT must not be empty when REQUIRE_PROOF_OF_HUMANITY=true")
	}
	if c.PrivadoCircuitID == "" {
		return errors.New("PRIVADO_CIRCUIT_ID must not be empty when REQUIRE_PROOF_OF_HUMANITY=true")
	}
	if c.BillionsCredentialSchemaURL == "" {
		return errors.New("BILLIONS_CREDENTIAL_SCHEMA_URL must not be empty when REQUIRE_PROOF_OF_HUMANITY=true")
	}
	if c.BillionsCredentialType == "" {
		return errors.New("BILLIONS_CREDENTIAL_TYPE must not be empty when REQUIRE_PROOF_OF_HUMANITY=true")
	}
	if c.BillionsCredentialQueryFile == "" {
		return errors.New("BILLIONS_CREDENTIAL_QUERY_FILE is required when REQUIRE_PROOF_OF_HUMANITY=true")
	}
	cs, ok := c.BillionsCredentialQuery["credentialSubject"].(map[string]any)
	if !ok || len(cs) == 0 {
		return fmt.Errorf("BILLIONS_CREDENTIAL_QUERY_FILE %q must contain a non-empty 'credentialSubject' object", c.BillionsCredentialQueryFile)
	}
	return nil
}

// isPrivateOrLocalhost returns true if the hostname is localhost, loopback, or a private network IP.
// HTTP is safe on these networks — no public internet transit.
func isPrivateOrLocalhost(hostname string) bool {
	if hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1" {
		return true
	}
	ip := net.ParseIP(hostname)
	if ip == nil {
		return false
	}
	// RFC1918 + RFC4193 (IPv6 ULA) + link-local
	privateRanges := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"100.64.0.0/10", // Tailscale / CGNAT
		"fc00::/7",      // IPv6 ULA
		"fe80::/10",     // IPv6 link-local
	}
	for _, cidr := range privateRanges {
		_, subnet, _ := net.ParseCIDR(cidr)
		if subnet != nil && subnet.Contains(ip) {
			return true
		}
	}
	return false
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	// Fall back to the optional config file (CONFIG_FILE) before the built-in
	// default. Environment variables always win (checked first above), so file
	// values form a base layer the environment can override. (RD-1130)
	if fileConfig != nil {
		if value, ok := fileConfig[key]; ok && value != "" {
			return value
		}
	}
	return defaultValue
}

// getEnvInt reads an environment variable as an int, returning defaultValue if
// the variable is unset or not a valid integer.
func getEnvInt(key string, defaultValue int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
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

// deriveAuditDatabaseURL derives the default audit-database DSN from the main
// DATABASE_URL by swapping the database name to "<name>_audit" on the SAME
// server, reusing DATABASE_URL's credentials (RD-1147). This is the default when
// AUDIT_DATABASE_URL / AUDIT_ADMIN_DATABASE_URL are unset. An explicit URL always
// overrides (and may point at a different server / role).
//
// It supports the URL form (postgres://user:pass@host:port/dbname?params), which
// is what DATABASE_URL uses everywhere in this codebase. If parsing fails or the
// path has no database name, it returns "" — the caller then has no derived
// default and the (missing) audit DB will fail loudly at startup, which is the
// correct fail-closed behaviour for an unparseable DATABASE_URL.
//
// NOTE: the derived default reuses DATABASE_URL's credentials (the owner role),
// so the append-only INSERT-only seal is NOT enforced on it — the seal bites
// only when AUDIT_DATABASE_URL is set explicitly to connect as the restricted
// privacy_proxy_app role. See docs/configuration.
func deriveAuditDatabaseURL(databaseURL string) string {
	u, err := url.Parse(databaseURL)
	if err != nil || u.Host == "" {
		return ""
	}
	name := strings.TrimPrefix(u.Path, "/")
	if name == "" {
		return ""
	}
	u.Path = "/" + name + "_audit"
	return u.String()
}
