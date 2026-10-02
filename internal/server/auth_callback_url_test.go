package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"privacy-proxy/internal/config"
	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestServerWithConfig creates a minimal Server with only the config set.
// No DB, session store, or other dependencies — suitable for pure URL logic tests.
func newTestServerWithConfig(cfg *config.Config) *Server {
	return &Server{config: cfg}
}

// newGinContext creates a *gin.Context backed by the given HTTP request.
func newGinContext(req *http.Request) *gin.Context {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	return c
}

// writeTunnelFile creates a temp file containing the tunnel URL and returns its path.
func writeTunnelFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "tunnel-url")
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))
	return path
}

// ---------------------------------------------------------------------------
// isLocalOrigin
// ---------------------------------------------------------------------------

func TestLocalOrigin(t *testing.T) {
	s := newTestServerWithConfig(&config.Config{ReadProfile: rbac.ReadProfileStandard})

	tests := []struct {
		name   string
		origin string
		want   bool
	}{
		{name: "localhost with port", origin: "http://localhost:5173", want: true},
		{name: "127.0.0.1 with port", origin: "http://127.0.0.1:5173", want: true},
		{name: "IPv6 loopback with port", origin: "http://[::1]:5173", want: true},
		{name: "localhost no port", origin: "http://localhost", want: true},
		{name: "localhost uppercase", origin: "http://LOCALHOST:5173", want: true},
		{name: "LAN IP is NOT local", origin: "http://192.168.1.100:5173", want: false},
		{name: "tunnel URL is NOT local", origin: "https://abc123.trycloudflare.com", want: false},
		{name: "empty string", origin: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.isLocalOrigin(tt.origin)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// getPublicURL
// ---------------------------------------------------------------------------

func TestPublicURL(t *testing.T) {
	tests := []struct {
		name        string
		cfg         *config.Config
		fwdProto    string // X-Forwarded-Proto header
		fwdHost     string // X-Forwarded-Host header
		reqHost     string // Host header (via req.Host)
		want        string
	}{
		{
			name: "explicit BASE_URL not default",
			cfg:  &config.Config{ReadProfile: rbac.ReadProfileStandard, BaseURL: "https://proxy.example.com", Port: "8080"},
			want: "https://proxy.example.com",
		},
		{
			name:     "BASE_URL always respected even if localhost",
			cfg:      &config.Config{ReadProfile: rbac.ReadProfileStandard, BaseURL: "http://localhost:8080", Port: "8080", Environment: "development"},
			fwdProto: "https",
			fwdHost:  "tunnel.example.com",
			want:     "http://localhost:8080",
		},
		{
			name:     "empty BASE_URL falls through to X-Forwarded headers",
			cfg:      &config.Config{ReadProfile: rbac.ReadProfileStandard, BaseURL: "", Port: "8080"},
			fwdProto: "https",
			fwdHost:  "proxy.example.com",
			want:     "https://proxy.example.com",
		},
		{
			name:    "empty BASE_URL + no headers + production uses https",
			cfg:     &config.Config{ReadProfile: rbac.ReadProfileStandard, BaseURL: "", Port: "8080", Environment: "production"},
			reqHost: "proxy.example.com:8080",
			want:    "https://proxy.example.com:8080",
		},
		{
			name:    "empty BASE_URL + no headers + dev uses http",
			cfg:     &config.Config{ReadProfile: rbac.ReadProfileStandard, BaseURL: "", Port: "8080", Environment: "development"},
			reqHost: "myhost:8080",
			want:    "http://myhost:8080",
		},
		{
			name:    "host with port swaps to backend port",
			cfg:     &config.Config{ReadProfile: rbac.ReadProfileStandard, BaseURL: "", Port: "9090", Environment: "development"},
			reqHost: "myhost:5173",
			want:    "http://myhost:9090",
		},
		{
			name:    "host without port no port in result",
			cfg:     &config.Config{ReadProfile: rbac.ReadProfileStandard, BaseURL: "", Port: "8080", Environment: "development"},
			reqHost: "tunnel.example.com",
			want:    "http://tunnel.example.com",
		},
		{
			name:    "IPv6 host with port",
			cfg:     &config.Config{ReadProfile: rbac.ReadProfileStandard, BaseURL: "", Port: "8080", Environment: "development"},
			reqHost: "[::1]:8080",
			want:    "http://[::1]:8080",
		},
		{
			name:    "IPv6 host without port",
			cfg:     &config.Config{ReadProfile: rbac.ReadProfileStandard, BaseURL: "", Port: "8080", Environment: "development"},
			reqHost: "[::1]",
			want:    "http://[::1]",
		},
		// NOTE: httptest.NewRequest always sets Host to "example.com" from the
		// URL, so we test the final fallback (host == "") separately below.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestServerWithConfig(tt.cfg)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.fwdProto != "" {
				req.Header.Set("X-Forwarded-Proto", tt.fwdProto)
			}
			if tt.fwdHost != "" {
				req.Header.Set("X-Forwarded-Host", tt.fwdHost)
			}
			if tt.reqHost != "" {
				req.Host = tt.reqHost
			}

			c := newGinContext(req)
			got := s.getPublicURL(c)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPublicURL_NoHostFallsBackToBaseURL(t *testing.T) {
	s := newTestServerWithConfig(&config.Config{
		ReadProfile: rbac.ReadProfileStandard,
		BaseURL:     "http://localhost:8080",
		Port:        "8080",
		Environment: "development",
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// httptest.NewRequest sets Host from the URL; explicitly clear it to
	// simulate a request with no Host header at all.
	req.Host = ""
	c := newGinContext(req)

	got := s.getPublicURL(c)
	assert.Equal(t, "http://localhost:8080", got)
}

// ---------------------------------------------------------------------------
// getCallbackBaseURL
// ---------------------------------------------------------------------------

func TestCallbackURL(t *testing.T) {
	tunnelFile := writeTunnelFile(t, "https://abc123.trycloudflare.com\n")

	tests := []struct {
		name           string
		cfg            *config.Config
		callbackOrigin string
		reqHost        string // Host header on the underlying request
		fwdProto       string
		fwdHost        string
		want           string
	}{
		// --- Local origin cases ---
		{
			name:           "local origin + tunnel configured returns tunnel URL",
			cfg:            &config.Config{ReadProfile: rbac.ReadProfileStandard, TunnelURLFile: tunnelFile, Port: "8080"},
			callbackOrigin: "http://localhost:5173",
			want:           "https://abc123.trycloudflare.com",
		},
		{
			name:           "local origin + no tunnel + explicit BASE_URL returns BASE_URL",
			cfg:            &config.Config{ReadProfile: rbac.ReadProfileStandard, BaseURL: "https://ngrok.example.com", Port: "8080"},
			callbackOrigin: "http://localhost:5173",
			want:           "https://ngrok.example.com",
		},
		{
			name:           "local origin + no tunnel + BASE_URL set returns BASE_URL",
			cfg:            &config.Config{ReadProfile: rbac.ReadProfileStandard, BaseURL: "http://localhost:8080", Port: "8080", Environment: "development"},
			callbackOrigin: "http://localhost:5173",
			fwdProto:       "https",
			fwdHost:        "detected.example.com",
			want:           "http://localhost:8080",
		},

		// --- Non-local origin cases ---
		{
			name:           "non-local origin with port swaps to backend port",
			cfg:            &config.Config{ReadProfile: rbac.ReadProfileStandard, Port: "8080"},
			callbackOrigin: "http://192.168.1.100:5173",
			want:           "http://192.168.1.100:8080",
		},
		{
			name:           "non-local origin without port returns as-is",
			cfg:            &config.Config{ReadProfile: rbac.ReadProfileStandard, Port: "8080"},
			callbackOrigin: "https://tunnel.example.com",
			want:           "https://tunnel.example.com",
		},

		// --- Empty origin ---
		{
			name:           "empty origin falls through to getPublicURL",
			cfg:            &config.Config{ReadProfile: rbac.ReadProfileStandard, BaseURL: "https://proxy.example.com", Port: "8080"},
			callbackOrigin: "",
			want:           "https://proxy.example.com",
		},

		// --- Phone-on-same-WiFi scenario ---
		{
			name:           "phone on same WiFi uses origin with port swap",
			cfg:            &config.Config{ReadProfile: rbac.ReadProfileStandard, Port: "8080", BaseURL: "http://localhost:8080", Environment: "development"},
			callbackOrigin: "http://192.168.1.100:5173",
			want:           "http://192.168.1.100:8080",
		},

		// --- Phone on mobile data, tunnel configured ---
		{
			name:           "phone on mobile data with tunnel URL as origin returns tunnel URL as-is",
			cfg:            &config.Config{ReadProfile: rbac.ReadProfileStandard, TunnelURLFile: tunnelFile, Port: "8080"},
			callbackOrigin: "https://abc123.trycloudflare.com",
			want:           "https://abc123.trycloudflare.com",
		},

		// --- Phone on mobile data, no tunnel, public BASE_URL ---
		{
			name:           "phone on mobile data no tunnel public BASE_URL uses origin",
			cfg:            &config.Config{ReadProfile: rbac.ReadProfileStandard, BaseURL: "https://proxy.public.com", Port: "8080"},
			callbackOrigin: "https://proxy.public.com",
			want:           "https://proxy.public.com",
		},

		// --- Port fallback when config.Port is empty ---
		{
			name:           "empty config port defaults to 8080 on port swap",
			cfg:            &config.Config{ReadProfile: rbac.ReadProfileStandard, Port: ""},
			callbackOrigin: "http://192.168.1.100:5173",
			want:           "http://192.168.1.100:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestServerWithConfig(tt.cfg)

			req := httptest.NewRequest(http.MethodPost, "/auth/request", nil)
			if tt.reqHost != "" {
				req.Host = tt.reqHost
			}
			if tt.fwdProto != "" {
				req.Header.Set("X-Forwarded-Proto", tt.fwdProto)
			}
			if tt.fwdHost != "" {
				req.Header.Set("X-Forwarded-Host", tt.fwdHost)
			}

			c := newGinContext(req)
			got := s.getCallbackBaseURL(c, tt.callbackOrigin)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// Tunnel file edge cases
// ---------------------------------------------------------------------------

func TestCallbackURL_TunnelFileEdgeCases(t *testing.T) {
	t.Run("tunnel file does not exist", func(t *testing.T) {
		s := newTestServerWithConfig(&config.Config{
			ReadProfile: rbac.ReadProfileStandard,
			TunnelURLFile: "/nonexistent/path/tunnel-url",
			BaseURL:       "https://fallback.example.com",
			Port:          "8080",
		})
		req := httptest.NewRequest(http.MethodPost, "/auth/request", nil)
		c := newGinContext(req)
		got := s.getCallbackBaseURL(c, "http://localhost:5173")
		assert.Equal(t, "https://fallback.example.com", got)
	})

	t.Run("tunnel file is empty", func(t *testing.T) {
		path := writeTunnelFile(t, "")
		s := newTestServerWithConfig(&config.Config{
			ReadProfile: rbac.ReadProfileStandard,
			TunnelURLFile: path,
			BaseURL:       "https://fallback.example.com",
			Port:          "8080",
		})
		req := httptest.NewRequest(http.MethodPost, "/auth/request", nil)
		c := newGinContext(req)
		got := s.getCallbackBaseURL(c, "http://localhost:5173")
		assert.Equal(t, "https://fallback.example.com", got)
	})

	t.Run("tunnel file contains http not https is rejected", func(t *testing.T) {
		path := writeTunnelFile(t, "http://insecure-tunnel.example.com")
		s := newTestServerWithConfig(&config.Config{
			ReadProfile: rbac.ReadProfileStandard,
			TunnelURLFile: path,
			BaseURL:       "https://fallback.example.com",
			Port:          "8080",
		})
		req := httptest.NewRequest(http.MethodPost, "/auth/request", nil)
		c := newGinContext(req)
		got := s.getCallbackBaseURL(c, "http://localhost:5173")
		assert.Equal(t, "https://fallback.example.com", got)
	})

	t.Run("tunnel file whitespace is trimmed", func(t *testing.T) {
		path := writeTunnelFile(t, "  https://trimmed.trycloudflare.com  \n")
		s := newTestServerWithConfig(&config.Config{
			ReadProfile: rbac.ReadProfileStandard,
			TunnelURLFile: path,
			Port:          "8080",
		})
		req := httptest.NewRequest(http.MethodPost, "/auth/request", nil)
		c := newGinContext(req)
		got := s.getCallbackBaseURL(c, "http://localhost:5173")
		assert.Equal(t, "https://trimmed.trycloudflare.com", got)
	})
}

// ---------------------------------------------------------------------------
// Bug case: BASE_URL explicitly set to the default value
// ---------------------------------------------------------------------------

func TestCallbackURL_BaseURLAlwaysRespected(t *testing.T) {
	// BASE_URL is always used when set, even if it matches what would be the default.
	s := newTestServerWithConfig(&config.Config{
		ReadProfile: rbac.ReadProfileStandard,
		BaseURL:     "http://localhost:8080",
		Port:        "8080",
		Environment: "development",
	})

	req := httptest.NewRequest(http.MethodPost, "/auth/request", nil)
	req.Host = "real-host:8080"
	c := newGinContext(req)

	got := s.getPublicURL(c)
	assert.Equal(t, "http://localhost:8080", got,
		"BASE_URL is respected even when it matches the old default")
}
