package config

import (
	"bytes"
	"log/slog"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestLoad_Defaults(t *testing.T) {
	// Clear relevant environment variables
	envVars := []string{
		"NODE_URL", "DATABASE_URL", "PRIVADO_RPC_URL",
		"IPFS_GATEWAY", "JWT_SECRET", "JWT_REFRESH_SECRET", "VERIFIER_ID",
		"BASE_URL", "PORT", "ENVIRONMENT", "BILLIONS_ISSUER_DID",
		"REQUIRE_PROOF_OF_HUMANITY", "BILLIONS_RPC_URL", "BILLIONS_STATE_CONTRACT",
	}

	// Save and clear env vars
	savedEnv := make(map[string]string)
	for _, env := range envVars {
		savedEnv[env] = os.Getenv(env)
		os.Unsetenv(env)
	}

	// Restore env vars after test
	defer func() {
		for env, val := range savedEnv {
			if val != "" {
				os.Setenv(env, val)
			}
		}
	}()

	cfg := Load()

	tests := []struct {
		name     string
		got      string
		expected string
	}{
		{"NodeURL", cfg.NodeURL, "http://localhost:8545"},
		{"DatabaseURL", cfg.DatabaseURL, "postgres://postgres:postgres@localhost:5432/privacy_proxy?sslmode=disable"},
		{"PrivadoRPCURL", cfg.PrivadoRPCURL, "https://rpc-mainnet.privado.id"},
		{"IPFSGateway", cfg.IPFSGateway, "https://ipfs-proxy-cache.privado.id"},
		{"JWTSecret", cfg.JWTSecret, ""},
		{"JWTRefreshSecret", cfg.JWTRefreshSecret, ""},
		{"VerifierID", cfg.VerifierID, ""},
		{"BaseURL", cfg.BaseURL, "http://localhost:8080"},
		{"Port", cfg.Port, "8080"},
		{"Environment", cfg.Environment, "development"},
		{"BillionsIssuerDID", cfg.BillionsIssuerDID, ""},
		// RD-1241: there is deliberately NO default. The previous default
		// (billions-rpc.eu-north-2.gateway.fm) lost its DNS record, which
		// registered a billions:main resolver that could never be reached, so
		// every Billions sign-in failed on a dial deep inside proof
		// verification. Empty means the network is simply not registered and a
		// Billions DID is rejected immediately and legibly instead.
		{"BillionsRPCURL", cfg.BillionsRPCURL, ""},
		{"BillionsStateContract", cfg.BillionsStateContract, "0x3C9acB2205Aa72A05F6D77d708b5Cf85FCa3a896"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.expected {
				t.Errorf("%s = %q, want %q", tt.name, tt.got, tt.expected)
			}
		})
	}

	// RequireProofOfHumanity is opt-in in every environment — defaults to false.
	if cfg.RequireProofOfHumanity {
		t.Error("RequireProofOfHumanity should default to false")
	}
}

func TestLoad_EnvOverride(t *testing.T) {
	// Set environment variables
	testEnv := map[string]string{
		"NODE_URL":                "http://custom-node:8545",
		"DATABASE_URL":            "postgres://user:pass@db:5432/test",
		"PRIVADO_RPC_URL":         "https://custom-rpc.privado.id",
		"IPFS_GATEWAY":            "https://custom-ipfs.io",
		"ADMIN_API_TOKEN":         "admin-token",
		"JWT_SECRET":              "super-secret-jwt",
		"JWT_REFRESH_SECRET":      "super-secret-refresh",
		"VERIFIER_ID":             "did:test:verifier",
		"BASE_URL":                "https://api.example.com",
		"PORT":                    "3000",
		"ENVIRONMENT":             "staging",
		"BILLIONS_ISSUER_DID":     "did:test:billions",
		"BILLIONS_RPC_URL":        "https://billions.example/rpc",
		"BILLIONS_STATE_CONTRACT": "0x00000000000000000000000000000000DeaDBeef",
	}

	// Save current env and set test values
	savedEnv := make(map[string]string)
	for key, val := range testEnv {
		savedEnv[key] = os.Getenv(key)
		os.Setenv(key, val)
	}

	// Restore env vars after test
	defer func() {
		for key, val := range savedEnv {
			if val != "" {
				os.Setenv(key, val)
			} else {
				os.Unsetenv(key)
			}
		}
	}()

	cfg := Load()

	tests := []struct {
		name     string
		got      string
		expected string
	}{
		{"NodeURL", cfg.NodeURL, testEnv["NODE_URL"]},
		{"DatabaseURL", cfg.DatabaseURL, testEnv["DATABASE_URL"]},
		{"PrivadoRPCURL", cfg.PrivadoRPCURL, testEnv["PRIVADO_RPC_URL"]},
		{"IPFSGateway", cfg.IPFSGateway, testEnv["IPFS_GATEWAY"]},
		{"AdminAPIToken", cfg.AdminAPIToken, testEnv["ADMIN_API_TOKEN"]},
		{"JWTSecret", cfg.JWTSecret, testEnv["JWT_SECRET"]},
		{"JWTRefreshSecret", cfg.JWTRefreshSecret, testEnv["JWT_REFRESH_SECRET"]},
		{"VerifierID", cfg.VerifierID, testEnv["VERIFIER_ID"]},
		{"BaseURL", cfg.BaseURL, testEnv["BASE_URL"]},
		{"Port", cfg.Port, testEnv["PORT"]},
		{"Environment", cfg.Environment, testEnv["ENVIRONMENT"]},
		{"BillionsIssuerDID", cfg.BillionsIssuerDID, testEnv["BILLIONS_ISSUER_DID"]},
		{"BillionsRPCURL", cfg.BillionsRPCURL, testEnv["BILLIONS_RPC_URL"]},
		{"BillionsStateContract", cfg.BillionsStateContract, testEnv["BILLIONS_STATE_CONTRACT"]},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.expected {
				t.Errorf("%s = %q, want %q", tt.name, tt.got, tt.expected)
			}
		})
	}
}

func TestLoad_ProductionMode(t *testing.T) {
	// Save and set env vars
	savedEnv := os.Getenv("ENVIRONMENT")
	savedPoH := os.Getenv("REQUIRE_PROOF_OF_HUMANITY")
	os.Setenv("ENVIRONMENT", "production")
	os.Unsetenv("REQUIRE_PROOF_OF_HUMANITY")

	defer func() {
		if savedEnv != "" {
			os.Setenv("ENVIRONMENT", savedEnv)
		} else {
			os.Unsetenv("ENVIRONMENT")
		}
		if savedPoH != "" {
			os.Setenv("REQUIRE_PROOF_OF_HUMANITY", savedPoH)
		}
	}()

	cfg := Load()

	if cfg.Environment != "production" {
		t.Errorf("Environment = %q, want %q", cfg.Environment, "production")
	}

	// RequireProofOfHumanity is now opt-in in every environment — Path B must
	// be explicitly enabled AND have the full config populated. See decisions.md §5.
	if cfg.RequireProofOfHumanity {
		t.Error("RequireProofOfHumanity should default to false in production (opt-in)")
	}
}

func TestLoad_RequireProofOfHumanity_ExplicitOverride(t *testing.T) {
	tests := []struct {
		name        string
		environment string
		pohSetting  string
		expected    bool
	}{
		{
			name:        "production with explicit false",
			environment: "production",
			pohSetting:  "false",
			expected:    false,
		},
		{
			name:        "development with explicit true",
			environment: "development",
			pohSetting:  "true",
			expected:    true,
		},
		{
			name:        "production with explicit true",
			environment: "production",
			pohSetting:  "true",
			expected:    true,
		},
		{
			name:        "development with explicit false",
			environment: "development",
			pohSetting:  "false",
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save env vars
			savedEnv := os.Getenv("ENVIRONMENT")
			savedPoH := os.Getenv("REQUIRE_PROOF_OF_HUMANITY")

			os.Setenv("ENVIRONMENT", tt.environment)
			os.Setenv("REQUIRE_PROOF_OF_HUMANITY", tt.pohSetting)

			defer func() {
				if savedEnv != "" {
					os.Setenv("ENVIRONMENT", savedEnv)
				} else {
					os.Unsetenv("ENVIRONMENT")
				}
				if savedPoH != "" {
					os.Setenv("REQUIRE_PROOF_OF_HUMANITY", savedPoH)
				} else {
					os.Unsetenv("REQUIRE_PROOF_OF_HUMANITY")
				}
			}()

			cfg := Load()

			if cfg.RequireProofOfHumanity != tt.expected {
				t.Errorf("RequireProofOfHumanity = %v, want %v", cfg.RequireProofOfHumanity, tt.expected)
			}
		})
	}
}

func TestConfig_IsProduction(t *testing.T) {
	tests := []struct {
		name        string
		environment string
		expected    bool
	}{
		{"production", "production", true},
		{"development", "development", false},
		{"staging", "staging", false},
		{"empty", "", false},
		{"prod (partial)", "prod", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Environment: tt.environment,
			}

			if got := cfg.IsProduction(); got != tt.expected {
				t.Errorf("IsProduction() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestConfig_Validate_ProductionWarnings covers RD-1164 #8/#20/#18: in
// production, missing hardening controls emit a loud slog warning (but do NOT
// fail startup). All required prod fields are set so Validate reaches the
// warning block and returns nil.
func TestConfig_Validate_ProductionWarnings(t *testing.T) {
	base := func() *Config {
		return &Config{
			Environment:      "production",
			JWTSecret:        "secret",
			JWTRefreshSecret: "refresh-secret",
			VerifierID:       "did:test:verifier",
			AdminAPIToken:    "admin-token",
			NodeURL:          "https://node.example.com",
			BaseURL:          "https://api.example.com",
		}
	}

	capture := func(t *testing.T, c *Config) string {
		t.Helper()
		var buf bytes.Buffer
		prev := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		defer slog.SetDefault(prev)
		if err := c.Validate(); err != nil {
			t.Fatalf("Validate() returned error: %v", err)
		}
		return buf.String()
	}

	t.Run("warns when hardening controls are unset", func(t *testing.T) {
		t.Setenv("AUDIT_DATABASE_URL", "") // derived/co-located
		out := capture(t, base())          // pseudonym key + Redis unset
		for _, want := range []string{"EXPLORER_PSEUDONYM_KEY", "REDIS_URL", "AUDIT_DATABASE_URL"} {
			if !strings.Contains(out, want) {
				t.Errorf("expected a production warning mentioning %s, got:\n%s", want, out)
			}
		}
	})

	t.Run("no warnings when all hardening controls are set", func(t *testing.T) {
		t.Setenv("AUDIT_DATABASE_URL", "postgres://audit:pw@auditdb:5432/audit?sslmode=disable")
		c := base()
		c.ExplorerPseudonymKey = []byte("0123456789abcdef0123456789abcdef")
		c.RedisURL = "redis://:pw@redis:6379/0"
		out := capture(t, c)
		if strings.Contains(out, "WARN") {
			t.Errorf("expected no production warnings when hardening controls are set, got:\n%s", out)
		}
	})

	t.Run("development mode emits no hardening warnings", func(t *testing.T) {
		c := base()
		c.Environment = "development"
		out := capture(t, c)
		if strings.Contains(out, "WARN") {
			t.Errorf("development mode should not emit production hardening warnings, got:\n%s", out)
		}
	})
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "development mode allows empty secrets",
			config: &Config{
				Environment:      "development",
				JWTSecret:        "",
				JWTRefreshSecret: "",
				AdminAPIToken:    "",
				VerifierID:       "",
			},
			expectError: false,
		},
		{
			name: "production mode requires JWT_SECRET",
			config: &Config{
				Environment:      "production",
				JWTSecret:        "",
				JWTRefreshSecret: "secret",
				AdminAPIToken:    "admin-token",
				VerifierID:       "did:test:verifier",
			},
			expectError: true,
			errorMsg:    "JWT_SECRET is required in production",
		},
		{
			name: "production mode requires JWT_REFRESH_SECRET",
			config: &Config{
				Environment:      "production",
				JWTSecret:        "secret",
				JWTRefreshSecret: "",
				AdminAPIToken:    "admin-token",
				VerifierID:       "did:test:verifier",
			},
			expectError: true,
			errorMsg:    "JWT_REFRESH_SECRET is required in production",
		},
		{
			name: "production mode requires VERIFIER_ID",
			config: &Config{
				Environment:      "production",
				JWTSecret:        "secret",
				JWTRefreshSecret: "refresh-secret",
				AdminAPIToken:    "admin-token",
				VerifierID:       "",
			},
			expectError: true,
			errorMsg:    "VERIFIER_ID is required in production for authentication",
		},
		{
			name: "production mode requires ADMIN_API_TOKEN",
			config: &Config{
				Environment:      "production",
				JWTSecret:        "secret",
				JWTRefreshSecret: "refresh-secret",
				AdminAPIToken:    "",
				VerifierID:       "did:test:verifier",
			},
			expectError: true,
			errorMsg:    "ADMIN_API_TOKEN is required in production for admin API authentication",
		},
		{
			name: "production mode requires NODE_URL",
			config: &Config{
				Environment:      "production",
				JWTSecret:        "secret",
				JWTRefreshSecret: "refresh-secret",
				AdminAPIToken:    "admin-token",
				VerifierID:       "did:test:verifier",
				NodeURL:          "",
			},
			expectError: true,
			errorMsg:    "NODE_URL is required in production (Ethereum node JSON-RPC endpoint)",
		},
		{
			name: "production mode requires BASE_URL",
			config: &Config{
				Environment:      "production",
				JWTSecret:        "secret",
				JWTRefreshSecret: "refresh-secret",
				AdminAPIToken:    "admin-token",
				VerifierID:       "did:test:verifier",
				NodeURL:          "http://node:8545",
				BaseURL:          "",
			},
			expectError: true,
			errorMsg:    "BASE_URL is required in production (public URL for OAuth callbacks)",
		},
		{
			name: "production mode with all required values passes",
			config: &Config{
				Environment:      "production",
				JWTSecret:        "secret",
				JWTRefreshSecret: "refresh-secret",
				AdminAPIToken:    "admin-token",
				VerifierID:       "did:test:verifier",
				NodeURL:          "http://node:8545",
				BaseURL:          "https://proxy.example.com",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError {
				if err == nil {
					t.Errorf("Validate() expected error containing %q, got nil", tt.errorMsg)
				} else if err.Error() != tt.errorMsg {
					t.Errorf("Validate() error = %q, want %q", err.Error(), tt.errorMsg)
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			}
		})
	}
}

// validPoHConfig returns a Config with all Path B fields populated so other
// validation branches don't fire.
func validPoHConfig(t *testing.T) *Config {
	t.Helper()
	return &Config{
		Environment:                 "development",
		RequireProofOfHumanity:      true,
		BillionsIssuerDID:           "did:privado:issuer:billions",
		PrivadoStateContract:        "0x3C9acB2205Aa72A05F6D77d708b5Cf85FCa3a896",
		PrivadoCircuitID:            "credentialAtomicQueryMTPV2",
		BillionsCredentialSchemaURL: "https://example.com/schema.jsonld",
		BillionsCredentialType:      "ProofOfHumanity",
		BillionsCredentialQueryFile: "/tmp/query.json",
		BillionsCredentialQuery: map[string]any{
			"credentialSubject": map[string]any{
				"isHuman": map[string]any{"$eq": 1},
			},
		},
	}
}

func TestConfig_ValidateProofOfHumanity(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(c *Config)
		wantErr string
	}{
		{
			name:    "all Path B fields populated passes",
			mutate:  func(c *Config) {},
			wantErr: "",
		},
		{
			name:    "missing issuer DID",
			mutate:  func(c *Config) { c.BillionsIssuerDID = "" },
			wantErr: "BILLIONS_ISSUER_DID is required",
		},
		{
			name:    "missing state contract",
			mutate:  func(c *Config) { c.PrivadoStateContract = "" },
			wantErr: "PRIVADO_STATE_CONTRACT must not be empty",
		},
		{
			name:    "missing circuit ID",
			mutate:  func(c *Config) { c.PrivadoCircuitID = "" },
			wantErr: "PRIVADO_CIRCUIT_ID must not be empty",
		},
		{
			name:    "missing schema URL",
			mutate:  func(c *Config) { c.BillionsCredentialSchemaURL = "" },
			wantErr: "BILLIONS_CREDENTIAL_SCHEMA_URL must not be empty",
		},
		{
			name:    "missing credential type",
			mutate:  func(c *Config) { c.BillionsCredentialType = "" },
			wantErr: "BILLIONS_CREDENTIAL_TYPE must not be empty",
		},
		{
			name:    "missing query file path",
			mutate:  func(c *Config) { c.BillionsCredentialQueryFile = "" },
			wantErr: "BILLIONS_CREDENTIAL_QUERY_FILE is required",
		},
		{
			name:    "query missing credentialSubject key",
			mutate:  func(c *Config) { c.BillionsCredentialQuery = map[string]any{"foo": "bar"} },
			wantErr: "credentialSubject",
		},
		{
			name: "credentialSubject not an object",
			mutate: func(c *Config) {
				c.BillionsCredentialQuery = map[string]any{"credentialSubject": "not-a-map"}
			},
			wantErr: "credentialSubject",
		},
		{
			name: "credentialSubject empty object",
			mutate: func(c *Config) {
				c.BillionsCredentialQuery = map[string]any{"credentialSubject": map[string]any{}}
			},
			wantErr: "credentialSubject",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validPoHConfig(t)
			tt.mutate(cfg)

			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Validate() error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestConfig_Validate_SkipsPathBWhenDisabled(t *testing.T) {
	// When RequireProofOfHumanity=false, Path B fields can all be empty.
	cfg := &Config{
		Environment:            "development",
		RequireProofOfHumanity: false,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
}

func TestLoad_BillionsCredentialQueryFile(t *testing.T) {
	// Clear env that might interfere
	for _, k := range []string{"BILLIONS_CREDENTIAL_QUERY_FILE", "REQUIRE_PROOF_OF_HUMANITY"} {
		orig := os.Getenv(k)
		os.Unsetenv(k)
		defer func(k, v string) {
			if v != "" {
				os.Setenv(k, v)
			} else {
				os.Unsetenv(k)
			}
		}(k, orig)
	}

	t.Run("valid JSON loads into Query map", func(t *testing.T) {
		dir := t.TempDir()
		path := dir + "/query.json"
		content := `{"credentialSubject":{"isHuman":{"$eq":1}}}`
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatalf("write temp query file: %v", err)
		}
		os.Setenv("BILLIONS_CREDENTIAL_QUERY_FILE", path)
		defer os.Unsetenv("BILLIONS_CREDENTIAL_QUERY_FILE")

		cfg := Load()
		if cfg.BillionsCredentialQueryFile != path {
			t.Errorf("BillionsCredentialQueryFile = %q, want %q", cfg.BillionsCredentialQueryFile, path)
		}
		cs, ok := cfg.BillionsCredentialQuery["credentialSubject"].(map[string]any)
		if !ok {
			t.Fatalf("credentialSubject not parsed as map: %#v", cfg.BillionsCredentialQuery["credentialSubject"])
		}
		if _, ok := cs["isHuman"]; !ok {
			t.Errorf("credentialSubject missing 'isHuman': %#v", cs)
		}
	})

	t.Run("invalid JSON panics", func(t *testing.T) {
		dir := t.TempDir()
		path := dir + "/bad.json"
		if err := os.WriteFile(path, []byte("{not json"), 0600); err != nil {
			t.Fatalf("write: %v", err)
		}
		os.Setenv("BILLIONS_CREDENTIAL_QUERY_FILE", path)
		defer os.Unsetenv("BILLIONS_CREDENTIAL_QUERY_FILE")

		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("expected panic on invalid JSON")
			}
			if msg, ok := r.(string); ok && !strings.Contains(msg, "invalid JSON") {
				t.Errorf("unexpected panic message: %s", msg)
			}
		}()
		_ = Load()
	})

	t.Run("missing file panics", func(t *testing.T) {
		os.Setenv("BILLIONS_CREDENTIAL_QUERY_FILE", "/does/not/exist.json")
		defer os.Unsetenv("BILLIONS_CREDENTIAL_QUERY_FILE")

		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("expected panic on missing file")
			}
		}()
		_ = Load()
	})
}

func TestLoad_PathBDefaults(t *testing.T) {
	// With no Path B env vars set, string fields have current-as-defaults so
	// existing deployments don't see behavior changes when PoH is off.
	for _, k := range []string{
		"PRIVADO_STATE_CONTRACT", "PRIVADO_CIRCUIT_ID",
		"BILLIONS_CREDENTIAL_SCHEMA_URL", "BILLIONS_CREDENTIAL_TYPE",
		"BILLIONS_CREDENTIAL_QUERY_FILE",
	} {
		orig := os.Getenv(k)
		os.Unsetenv(k)
		defer func(k, v string) {
			if v != "" {
				os.Setenv(k, v)
			}
		}(k, orig)
	}

	cfg := Load()

	if cfg.PrivadoStateContract == "" {
		t.Error("PrivadoStateContract should have a default value")
	}
	if cfg.PrivadoCircuitID != "credentialAtomicQueryMTPV2" {
		t.Errorf("PrivadoCircuitID = %q, want credentialAtomicQueryMTPV2", cfg.PrivadoCircuitID)
	}
	if cfg.BillionsCredentialType != "ProofOfHumanity" {
		t.Errorf("BillionsCredentialType = %q, want ProofOfHumanity", cfg.BillionsCredentialType)
	}
	if cfg.BillionsCredentialSchemaURL == "" {
		t.Error("BillionsCredentialSchemaURL should have a default value")
	}
	if cfg.BillionsCredentialQueryFile != "" {
		t.Errorf("BillionsCredentialQueryFile should default to empty, got %q", cfg.BillionsCredentialQueryFile)
	}
}

func TestGetEnv(t *testing.T) {
	tests := []struct {
		name         string
		key          string
		defaultValue string
		envValue     string
		setEnv       bool
		expected     string
	}{
		{
			name:         "returns env value when set",
			key:          "TEST_VAR_1",
			defaultValue: "default",
			envValue:     "custom",
			setEnv:       true,
			expected:     "custom",
		},
		{
			name:         "returns default when not set",
			key:          "TEST_VAR_2",
			defaultValue: "default",
			envValue:     "",
			setEnv:       false,
			expected:     "default",
		},
		{
			name:         "returns env value even if empty string when explicitly set",
			key:          "TEST_VAR_3",
			defaultValue: "default",
			envValue:     "",
			setEnv:       true,
			expected:     "default", // Empty string counts as unset
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear env var first
			os.Unsetenv(tt.key)

			if tt.setEnv && tt.envValue != "" {
				os.Setenv(tt.key, tt.envValue)
			}

			defer os.Unsetenv(tt.key)

			got := getEnv(tt.key, tt.defaultValue)
			if got != tt.expected {
				t.Errorf("getEnv(%q, %q) = %q, want %q", tt.key, tt.defaultValue, got, tt.expected)
			}
		})
	}
}

// TestLoad_RPCAPIKeyHeader covers the env-var loading branch for
// RPC_API_KEY_HEADER: a valid value passes through, an unset value falls
// back to proxy.DefaultAPIKeyHeader ("Authorization"), and any value that
// fails the proxy.ValidAPIKeyHeader regex panics so a misconfigured deploy
// fails fast at boot rather than silently injecting bad header content.
func TestLoad_RPCAPIKeyHeader(t *testing.T) {
	t.Run("valid header passes through", func(t *testing.T) {
		t.Setenv("RPC_API_KEY_HEADER", "X-API-Key")
		cfg := Load()
		if cfg.RPCAPIKeyHeader != "X-API-Key" {
			t.Errorf("RPCAPIKeyHeader = %q, want %q", cfg.RPCAPIKeyHeader, "X-API-Key")
		}
	})

	t.Run("unset defaults to Authorization", func(t *testing.T) {
		// t.Setenv with empty string sets to "", but getEnv treats empty
		// as unset and returns the default. Explicitly clear via Setenv
		// then Unsetenv to ensure no inherited value bleeds in.
		t.Setenv("RPC_API_KEY_HEADER", "")
		os.Unsetenv("RPC_API_KEY_HEADER")
		cfg := Load()
		if cfg.RPCAPIKeyHeader != "Authorization" {
			t.Errorf("RPCAPIKeyHeader = %q, want %q (proxy.DefaultAPIKeyHeader)", cfg.RPCAPIKeyHeader, "Authorization")
		}
	})

	invalidCases := []struct {
		name  string
		value string
	}{
		{"value with space", "has space"},
		{"value with CRLF injection", "Auth\r\nInjection"},
		{"value with colon", "Foo:Bar"},
		{"value with tab", "Foo\tBar"},
	}
	for _, tc := range invalidCases {
		t.Run("invalid panics: "+tc.name, func(t *testing.T) {
			t.Setenv("RPC_API_KEY_HEADER", tc.value)
			defer func() {
				r := recover()
				if r == nil {
					t.Fatalf("expected panic for invalid RPC_API_KEY_HEADER %q, got none", tc.value)
				}
				msg, ok := r.(string)
				if !ok {
					t.Fatalf("expected string panic, got %T: %v", r, r)
				}
				if !strings.Contains(msg, "RPC_API_KEY_HEADER") {
					t.Errorf("panic message should mention RPC_API_KEY_HEADER, got: %s", msg)
				}
			}()
			_ = Load()
		})
	}
}

// TestLoad_AuditDatabaseURL_DerivedAndOverride locks the RD-1147 audit-DSN
// resolution: when AUDIT_DATABASE_URL / AUDIT_ADMIN_DATABASE_URL are unset they
// are DERIVED from DATABASE_URL as "<name>_audit" on the same server; an explicit
// value overrides.
func TestLoad_AuditDatabaseURL_DerivedAndOverride(t *testing.T) {
	t.Run("derived from DATABASE_URL when unset", func(t *testing.T) {
		t.Setenv("DATABASE_URL", "postgres://u:p@dbhost:5432/privacy_proxy?sslmode=disable")
		t.Setenv("AUDIT_DATABASE_URL", "")
		os.Unsetenv("AUDIT_DATABASE_URL")
		t.Setenv("AUDIT_ADMIN_DATABASE_URL", "")
		os.Unsetenv("AUDIT_ADMIN_DATABASE_URL")
		cfg := Load()
		want := "postgres://u:p@dbhost:5432/privacy_proxy_audit?sslmode=disable"
		if cfg.AuditDatabaseURL != want {
			t.Errorf("AuditDatabaseURL = %q, want derived %q", cfg.AuditDatabaseURL, want)
		}
		if cfg.AuditAdminDatabaseURL != want {
			t.Errorf("AuditAdminDatabaseURL = %q, want derived %q", cfg.AuditAdminDatabaseURL, want)
		}
	})

	t.Run("explicit values override the derived default", func(t *testing.T) {
		t.Setenv("DATABASE_URL", "postgres://u:p@dbhost:5432/privacy_proxy?sslmode=disable")
		t.Setenv("AUDIT_DATABASE_URL", "postgres://privacy_proxy_app:sekret@audithost:5432/audit?sslmode=require")
		t.Setenv("AUDIT_ADMIN_DATABASE_URL", "postgres://owner:sekret@audithost:5432/audit?sslmode=require")
		cfg := Load()
		if cfg.AuditDatabaseURL != "postgres://privacy_proxy_app:sekret@audithost:5432/audit?sslmode=require" {
			t.Errorf("explicit AUDIT_DATABASE_URL not honored: %q", cfg.AuditDatabaseURL)
		}
		if cfg.AuditAdminDatabaseURL != "postgres://owner:sekret@audithost:5432/audit?sslmode=require" {
			t.Errorf("explicit AUDIT_ADMIN_DATABASE_URL not honored: %q", cfg.AuditAdminDatabaseURL)
		}
	})
}

// TestDeriveAuditDatabaseURL pins the derivation helper directly.
func TestDeriveAuditDatabaseURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"postgres://u:p@h:5432/privacy_proxy?sslmode=disable", "postgres://u:p@h:5432/privacy_proxy_audit?sslmode=disable"},
		{"postgres://u:p@h:5432/db", "postgres://u:p@h:5432/db_audit"},
		{"not a url with spaces", ""},  // unparseable host → no derived default
		{"postgres://u:p@h:5432/", ""}, // no db name → no derived default
	}
	for _, c := range cases {
		if got := deriveAuditDatabaseURL(c.in); got != c.want {
			t.Errorf("deriveAuditDatabaseURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestExtraRPCNamespaces_UnmarshalJSON(t *testing.T) {
	t.Run("valid config with aliases", func(t *testing.T) {
		input := `{
			"version": 1,
			"namespaces": {
				"Linea": [
					{"method": "linea_estimateGas", "alias": "eth_estimateGas"},
					{"method": "linea_getProof", "alias": "eth_getProof"}
				]
			}
		}`
		var cfg ExtraRPCNamespaces
		if err := cfg.UnmarshalJSON([]byte(input)); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Version != 1 {
			t.Errorf("Version = %d, want 1", cfg.Version)
		}
		methods := cfg.Namespaces["Linea"].Explicit
		if len(methods) != 2 {
			t.Fatalf("expected 2 methods, got %d", len(methods))
		}
		if methods[0].Method != "linea_estimateGas" || methods[0].Alias != "eth_estimateGas" {
			t.Errorf("method[0] = %+v, want linea_estimateGas/eth_estimateGas", methods[0])
		}
		if cfg.Namespaces["Linea"].Wildcard != nil {
			t.Errorf("expected nil wildcard for v1 array form, got %+v", cfg.Namespaces["Linea"].Wildcard)
		}
	})

	t.Run("plain string rejected — alias required", func(t *testing.T) {
		input := `{
			"version": 1,
			"namespaces": {
				"Linea": ["linea_estimateGas"]
			}
		}`
		var cfg ExtraRPCNamespaces
		err := cfg.UnmarshalJSON([]byte(input))
		if err == nil {
			t.Fatal("expected error for plain string method (no alias), got nil")
		}
	})

	t.Run("object without alias rejected", func(t *testing.T) {
		input := `{
			"version": 1,
			"namespaces": {
				"Linea": [{"method": "linea_estimateGas"}]
			}
		}`
		var cfg ExtraRPCNamespaces
		err := cfg.UnmarshalJSON([]byte(input))
		if err == nil {
			t.Fatal("expected error for method without alias, got nil")
		}
		if !strings.Contains(err.Error(), "missing 'alias'") {
			t.Errorf("error should mention missing alias, got: %v", err)
		}
	})

	t.Run("aliases helper", func(t *testing.T) {
		input := `{
			"version": 1,
			"namespaces": {
				"Linea": [
					{"method": "linea_estimateGas", "alias": "eth_estimateGas"},
					{"method": "linea_getProof", "alias": "eth_getProof"}
				]
			}
		}`
		var cfg ExtraRPCNamespaces
		if err := cfg.UnmarshalJSON([]byte(input)); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		aliases := cfg.Aliases()
		if aliases["linea_estimateGas"] != "eth_estimateGas" {
			t.Errorf("alias for linea_estimateGas = %q, want eth_estimateGas", aliases["linea_estimateGas"])
		}
		if aliases["linea_getProof"] != "eth_getProof" {
			t.Errorf("alias for linea_getProof = %q, want eth_getProof", aliases["linea_getProof"])
		}
	})

	// ----- v2 schema -----

	t.Run("v2 array form (no wildcard) parses identically to v1", func(t *testing.T) {
		input := `{
			"version": 2,
			"namespaces": {
				"Linea": [
					{"method": "linea_estimateGas", "alias": "eth_estimateGas"}
				]
			}
		}`
		var cfg ExtraRPCNamespaces
		if err := cfg.UnmarshalJSON([]byte(input)); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Namespaces["Linea"].Wildcard != nil {
			t.Errorf("expected nil wildcard for array-form namespace, got %+v", cfg.Namespaces["Linea"].Wildcard)
		}
		if got := len(cfg.Namespaces["Linea"].Explicit); got != 1 {
			t.Errorf("expected 1 explicit method, got %d", got)
		}
	})

	t.Run("v2 object form with explicit + wildcard", func(t *testing.T) {
		input := `{
			"version": 2,
			"namespaces": {
				"Linea": {
					"explicit": [
						{"method": "linea_estimateGas", "alias": "eth_estimateGas"}
					],
					"wildcard": {
						"prefix": "linea_",
						"deny": ["linea_sendTransaction", "linea_sign*"]
					}
				}
			}
		}`
		var cfg ExtraRPCNamespaces
		if err := cfg.UnmarshalJSON([]byte(input)); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		nc := cfg.Namespaces["Linea"]
		if len(nc.Explicit) != 1 || nc.Explicit[0].Method != "linea_estimateGas" {
			t.Errorf("explicit[0] = %+v, want linea_estimateGas", nc.Explicit)
		}
		if nc.Wildcard == nil {
			t.Fatal("expected non-nil wildcard")
		}
		if nc.Wildcard.Prefix != "linea_" {
			t.Errorf("wildcard prefix = %q, want linea_", nc.Wildcard.Prefix)
		}
		if len(nc.Wildcard.Deny) != 2 {
			t.Errorf("wildcard deny count = %d, want 2", len(nc.Wildcard.Deny))
		}
		// Aliases() still only enumerates explicit methods.
		if cfg.Aliases()["linea_estimateGas"] != "eth_estimateGas" {
			t.Error("explicit alias missing from Aliases() result")
		}
		// Wildcards() returns the wildcard config keyed by namespace.
		ws := cfg.Wildcards()
		if ws["Linea"] == nil || ws["Linea"].Prefix != "linea_" {
			t.Errorf("Wildcards() = %+v, want Linea→linea_", ws)
		}
	})

	t.Run("v2 wildcard-only namespace (empty explicit) is valid", func(t *testing.T) {
		input := `{
			"version": 2,
			"namespaces": {
				"Trace": {
					"explicit": [],
					"wildcard": {"prefix": "trace_"}
				}
			}
		}`
		var cfg ExtraRPCNamespaces
		if err := cfg.UnmarshalJSON([]byte(input)); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		nc := cfg.Namespaces["Trace"]
		if len(nc.Explicit) != 0 {
			t.Errorf("expected empty explicit, got %d entries", len(nc.Explicit))
		}
		if nc.Wildcard == nil || nc.Wildcard.Prefix != "trace_" {
			t.Errorf("wildcard not parsed: %+v", nc.Wildcard)
		}
	})

	t.Run("v2 missing prefix on wildcard fails", func(t *testing.T) {
		input := `{
			"version": 2,
			"namespaces": {
				"Linea": {"explicit": [], "wildcard": {"deny": ["foo"]}}
			}
		}`
		var cfg ExtraRPCNamespaces
		err := cfg.UnmarshalJSON([]byte(input))
		if err == nil || !strings.Contains(err.Error(), "'prefix' is required") {
			t.Fatalf("expected prefix-required error, got %v", err)
		}
	})

	t.Run("v1 object form rejected (object requires v2)", func(t *testing.T) {
		input := `{
			"version": 1,
			"namespaces": {
				"Linea": {"explicit": [], "wildcard": {"prefix": "linea_"}}
			}
		}`
		var cfg ExtraRPCNamespaces
		err := cfg.UnmarshalJSON([]byte(input))
		if err == nil || !strings.Contains(err.Error(), "requires version >= 2") {
			t.Fatalf("expected version-mismatch error, got %v", err)
		}
	})
}

// RD-1006: per-entry client_secret verification for the first-party allowlist.

func bcryptHashFor(t *testing.T, secret string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt hash: %v", err)
	}
	return string(h)
}

func TestParseFirstPartyClients(t *testing.T) {
	t.Run("empty raw returns empty map", func(t *testing.T) {
		got := parseFirstPartyClients("")
		if len(got) != 0 {
			t.Fatalf("expected empty map, got %v", got)
		}
	})

	t.Run("single entry parses", func(t *testing.T) {
		hash := bcryptHashFor(t, "s3cret")
		got := parseFirstPartyClients("explorer:" + hash)
		if got["explorer"] != hash {
			t.Fatalf("expected hash for explorer, got %q", got["explorer"])
		}
	})

	t.Run("multiple entries parse, whitespace tolerated", func(t *testing.T) {
		h1 := bcryptHashFor(t, "one")
		h2 := bcryptHashFor(t, "two")
		got := parseFirstPartyClients("  a:" + h1 + " , b:" + h2 + "  ")
		if got["a"] != h1 || got["b"] != h2 {
			t.Fatalf("missing entries: %v", got)
		}
	})

	t.Run("malformed entry without colon panics fail-closed", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Fatalf("expected panic, got nil")
			}
		}()
		_ = parseFirstPartyClients("explorer")
	})

	t.Run("empty hash panics fail-closed", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Fatalf("expected panic, got nil")
			}
		}()
		_ = parseFirstPartyClients("explorer:")
	})
}

func TestConfig_VerifyFirstPartyClientSecret(t *testing.T) {
	hash := bcryptHashFor(t, "correct-horse-battery-staple")
	c := &Config{OAuthFirstPartyClients: map[string]string{
		"explorer-test": hash,
	}}

	if !c.IsFirstPartyOAuthClient("explorer-test") {
		t.Fatalf("IsFirstPartyOAuthClient: known client returned false")
	}
	if c.IsFirstPartyOAuthClient("unknown") {
		t.Fatalf("IsFirstPartyOAuthClient: unknown client returned true")
	}

	if !c.VerifyFirstPartyClientSecret("explorer-test", "correct-horse-battery-staple") {
		t.Fatalf("expected valid secret to verify")
	}
	if c.VerifyFirstPartyClientSecret("explorer-test", "wrong") {
		t.Fatalf("wrong secret should not verify")
	}
	if c.VerifyFirstPartyClientSecret("unknown-client", "anything") {
		t.Fatalf("unknown client should not verify")
	}
	if c.VerifyFirstPartyClientSecret("explorer-test", "") {
		t.Fatalf("empty secret should not verify")
	}
	if c.VerifyFirstPartyClientSecret("", "anything") {
		t.Fatalf("empty client_id should not verify")
	}
}
