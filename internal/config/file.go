package config

import (
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

// SupportedConfigVersion is the config-file schema version this build understands.
// A config file MUST declare a top-level `version` equal to this value. Bump it
// (and document the migration) only when the file schema changes in a way that an
// older file can no longer be read correctly. Versioning from day one lets us
// detect a stale operator file instead of silently mis-reading it. (RD-1130)
const SupportedConfigVersion = 1

// configFileEnvVar names the environment variable that, when set, points at an
// optional TOML configuration file. Unset (the default) keeps the proxy in
// pure-environment mode — fully backwards compatible.
const configFileEnvVar = "CONFIG_FILE"

// fileConfig holds settings parsed from CONFIG_FILE, keyed by the canonical
// environment-variable name (e.g. "DATABASE_URL"). It is consulted by getEnv
// AFTER os.Getenv, so an environment variable ALWAYS overrides the file. This
// preserves 12-factor behaviour and, critically, lets secrets keep being
// injected via the environment / secrets manager regardless of the file.
// nil when no file is configured.
var fileConfig map[string]string

// fileConfigErr records a fatal problem loading CONFIG_FILE (unparseable,
// missing/unsupported version, unsupported value type). It is surfaced by
// Validate() so a bad file fails startup fast rather than silently falling
// back to environment defaults. nil when the file loaded cleanly or none was
// configured.
var fileConfigErr error

// secretKeys are settings that must NEVER be sourced from a plaintext config
// file — they belong in the environment or a secrets manager (org policy: AWS
// Secrets Manager via IRSA/CSI). If any of these appears in the file,
// loadConfigFile REJECTS it (fail-closed) and the proxy refuses to start. A
// secret in a file that can be committed, backed up, or shipped to logs is a
// foot-gun we close structurally rather than rely on someone noticing a
// warning. Inject secrets via the environment, which overrides the file anyway.
var secretKeys = map[string]bool{
	"JWT_SECRET":                           true,
	"JWT_REFRESH_SECRET":                   true,
	"JWT_SECRET_PREVIOUS":                  true, // rotation-window validation secrets (RD-1164 #15)
	"JWT_REFRESH_SECRET_PREVIOUS":          true,
	"ADMIN_API_TOKEN":                      true,
	"OPERATOR_API_TOKEN":                   true, // restricted admin bearer token (X-Admin-Token); grants org create + org-admin minting (RD-1132)
	"CROSS_ORG_AUTHORIZATION_ORACLE_TOKEN": true,
	"AZURE_AD_CLIENT_SECRET":               true,
	"DATABASE_URL":                         true, // bears a password in the DSN
	"AUDIT_DATABASE_URL":                   true, // separate append-only audit DB, restricted-role DSN (RD-1147)
	"AUDIT_ADMIN_DATABASE_URL":             true, // separate append-only audit DB, admin/owner DSN (RD-1147)
	"EXPLORER_DATABASE_URL":                true, // bears a password in the DSN
	"REDIS_URL":                            true, // bears a password in the DSN
	"REDIS_PASSWORD":                       true,
	"POSTGRES_PASSWORD":                    true,
	"RPC_API_KEY":                          true,
	"RPC_API_KEY_ENCRYPTION_KEY":           true,
	"EXPLORER_PSEUDONYM_KEY":               true, // HMAC key for explorer address pseudonyms (RD-1164 #8)
	"OAUTH_FIRST_PARTY_CLIENTS":            true, // client_id:bcrypt-hash pairs
	"AUDIT_CHECKPOINT_KEY":                 true, // HMAC key signing audit-chain checkpoints (RD-1112)
	"SIEM_AUTH_HEADER":                     true, // verbatim outbound Authorization header to the SIEM webhook (RD-1141)
}

// loadConfigFile reads the optional TOML file named by CONFIG_FILE into the
// package-level fileConfig map, keyed by canonical environment-variable name.
// Precedence (enforced in getEnv) is: environment variable > file value >
// built-in default.
//
// It resets the package state on every call (idempotent across reloads) and is
// a no-op returning nil when CONFIG_FILE is unset. It returns an error — and
// leaves fileConfig nil — on: a file that cannot be read/parsed, a missing or
// unsupported `version`, a non-scalar value, or a secret-class key (secrets
// must come from the environment, not the file). Callers (Load) record the
// error in fileConfigErr; Validate turns it into a fatal startup error.
func loadConfigFile() error {
	fileConfig = nil

	path := os.Getenv(configFileEnvVar)
	if path == "" {
		return nil // pure-environment mode (backwards compatible)
	}

	var raw map[string]any
	if _, err := toml.DecodeFile(path, &raw); err != nil {
		return fmt.Errorf("config file %q: %w", path, err)
	}

	verRaw, ok := raw["version"]
	if !ok {
		return fmt.Errorf("config file %q must declare a top-level `version` (this build supports version %d)", path, SupportedConfigVersion)
	}
	ver, ok := verRaw.(int64)
	if !ok || int(ver) != SupportedConfigVersion {
		return fmt.Errorf("config file %q: unsupported version %v (this build supports version %d)", path, verRaw, SupportedConfigVersion)
	}
	delete(raw, "version")

	m := make(map[string]string, len(raw))
	var secretsFound []string
	for key, val := range raw {
		// Secrets must never be sourced from the file — reject fail-closed
		// regardless of the value, so a stray secret key can't slip through.
		if secretKeys[key] {
			secretsFound = append(secretsFound, key)
			continue
		}
		s, ok := scalarToString(val)
		if !ok {
			return fmt.Errorf("config file %q: key %q has unsupported value type %T — only scalar string/bool/integer/float values are allowed (nested tables and arrays are not supported in version %d)", path, key, val, SupportedConfigVersion)
		}
		m[key] = s
	}
	if len(secretsFound) > 0 {
		sort.Strings(secretsFound)
		return fmt.Errorf("config file %q must not contain secrets, found: %s — set these in the environment or your secrets manager instead (the environment overrides the file anyway)", path, strings.Join(secretsFound, ", "))
	}

	fileConfig = m
	slog.Info("loaded configuration file", "file", path, "version", ver, "keys", len(m))
	return nil
}

// scalarToString renders a TOML scalar in the string form getEnv consumers
// expect (the same form the equivalent environment variable would carry).
// Returns ok=false for non-scalar values (tables, arrays, datetimes), which the
// caller rejects.
func scalarToString(v any) (string, bool) {
	switch val := v.(type) {
	case string:
		return val, true
	case bool:
		return strconv.FormatBool(val), true
	case int64:
		return strconv.FormatInt(val, 10), true
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64), true
	default:
		return "", false
	}
}
