package config

import (
	"strings"
	"testing"

	"privacy-proxy/internal/rbac"
)

// PRIVACY_READ_PROFILE (RD-1299): standard by default, strict on request, and an
// unknown value refuses to start rather than silently picking a policy.
func TestLoad_ReadProfile(t *testing.T) {
	t.Run("default is standard", func(t *testing.T) {
		t.Setenv("PRIVACY_READ_PROFILE", "")
		cfg := Load()
		if cfg.ReadProfile != rbac.ReadProfileStandard {
			t.Fatalf("ReadProfile = %v, want standard", cfg.ReadProfile)
		}
	})
	t.Run("strict", func(t *testing.T) {
		t.Setenv("PRIVACY_READ_PROFILE", "strict")
		cfg := Load()
		if cfg.ReadProfile != rbac.ReadProfileStrict {
			t.Fatalf("ReadProfile = %v, want strict", cfg.ReadProfile)
		}
	})
	t.Run("explicit standard", func(t *testing.T) {
		t.Setenv("PRIVACY_READ_PROFILE", "standard")
		cfg := Load()
		if cfg.ReadProfile != rbac.ReadProfileStandard {
			t.Fatalf("ReadProfile = %v, want standard", cfg.ReadProfile)
		}
	})
	// The compose files pass an empty value when the host does not set one, so
	// a CONFIG_FILE setting is not overridden by a hard-coded default.
	t.Run("CONFIG_FILE strict applies when the environment is empty", func(t *testing.T) {
		resetFileConfig(t)
		t.Setenv("CONFIG_FILE", writeConfigFile(t, "version = 1\nPRIVACY_READ_PROFILE = \"strict\"\n"))
		t.Setenv("PRIVACY_READ_PROFILE", "")
		cfg := Load()
		if cfg.ReadProfile != rbac.ReadProfileStrict {
			t.Fatalf("ReadProfile = %v, want strict from CONFIG_FILE", cfg.ReadProfile)
		}
	})
	t.Run("whitespace-only value refuses to start", func(t *testing.T) {
		t.Setenv("PRIVACY_READ_PROFILE", "  ")
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected Load to panic on a whitespace-only PRIVACY_READ_PROFILE")
			}
		}()
		_ = Load()
	})
	t.Run("unknown value refuses to start", func(t *testing.T) {
		t.Setenv("PRIVACY_READ_PROFILE", "permissive")
		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("expected Load to panic on an unknown PRIVACY_READ_PROFILE")
			}
			if msg, ok := r.(string); !ok || !strings.Contains(msg, "PRIVACY_READ_PROFILE") {
				t.Fatalf("unexpected panic: %v", r)
			}
		}()
		_ = Load()
	})
}
