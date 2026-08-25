package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIsBatchRequest(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{
			name:     "Single request",
			body:     `{"jsonrpc":"2.0","method":"eth_call","params":[],"id":1}`,
			expected: false,
		},
		{
			name:     "Batch request",
			body:     `[{"jsonrpc":"2.0","method":"eth_call","params":[],"id":1},{"jsonrpc":"2.0","method":"eth_getBalance","params":[],"id":2}]`,
			expected: true,
		},
		{
			name:     "Empty batch",
			body:     `[]`,
			expected: true,
		},
		{
			name:     "Whitespace before array",
			body:     `  [{"jsonrpc":"2.0","method":"eth_call","params":[],"id":1}]`,
			expected: true,
		},
		{
			name:     "Newlines before array",
			body:     "\n\t[{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[],\"id\":1}]",
			expected: true,
		},
		{
			name:     "Whitespace before object",
			body:     `  {"jsonrpc":"2.0","method":"eth_call","params":[],"id":1}`,
			expected: false,
		},
		{
			name:     "Empty body",
			body:     ``,
			expected: false,
		},
		{
			name:     "Whitespace only",
			body:     `   `,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsBatchRequest([]byte(tt.body))
			if result != tt.expected {
				t.Errorf("IsBatchRequest(%q) = %v, expected %v", tt.body, result, tt.expected)
			}
		})
	}
}

func TestParseMethod(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		want    string
		wantErr bool
	}{
		{
			name:    "valid eth_call",
			body:    `{"jsonrpc":"2.0","method":"eth_call","params":[],"id":1}`,
			want:    "eth_call",
			wantErr: false,
		},
		{
			name:    "valid eth_getBalance",
			body:    `{"jsonrpc":"2.0","method":"eth_getBalance","params":["0x123", "latest"],"id":2}`,
			want:    "eth_getBalance",
			wantErr: false,
		},
		{
			name:    "invalid JSON",
			body:    `{"jsonrpc":"2.0","method"`,
			want:    "",
			wantErr: true,
		},
		{
			name:    "missing method",
			body:    `{"jsonrpc":"2.0","params":[],"id":1}`,
			want:    "",
			wantErr: false, // Method will be empty string, not an error
		},
		{
			name:    "batch request should error",
			body:    `[{"jsonrpc":"2.0","method":"eth_call","params":[],"id":1}]`,
			want:    "",
			wantErr: true, // Batch requests return ErrBatchRequest
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method, err := ParseMethod([]byte(tt.body))

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if method != tt.want {
				t.Errorf("got method %q, want %q", method, tt.want)
			}
		})
	}
}

func TestParseRequest(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantMethod string
		wantErr    bool
		errType    error
	}{
		{
			name:       "valid request",
			body:       `{"jsonrpc":"2.0","method":"eth_call","params":[],"id":1}`,
			wantMethod: "eth_call",
			wantErr:    false,
		},
		{
			name:       "request with params",
			body:       `{"jsonrpc":"2.0","method":"eth_getBalance","params":["0x123", "latest"],"id":2}`,
			wantMethod: "eth_getBalance",
			wantErr:    false,
		},
		{
			name:       "invalid JSON",
			body:       `{"jsonrpc":"2.0"`,
			wantMethod: "",
			wantErr:    true,
		},
		{
			name:       "batch request",
			body:       `[{"jsonrpc":"2.0","method":"eth_call","params":[],"id":1}]`,
			wantMethod: "",
			wantErr:    true,
			errType:    ErrBatchRequest,
		},
		{
			name:       "batch request multiple",
			body:       `[{"jsonrpc":"2.0","method":"eth_call","params":[],"id":1},{"jsonrpc":"2.0","method":"eth_getBalance","params":[],"id":2}]`,
			wantMethod: "",
			wantErr:    true,
			errType:    ErrBatchRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method, _, err := ParseRequest([]byte(tt.body))

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errType != nil && err != tt.errType {
					t.Errorf("expected error %v, got %v", tt.errType, err)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if method != tt.wantMethod {
				t.Errorf("got method %q, want %q", method, tt.wantMethod)
			}
		})
	}
}

func TestForward(t *testing.T) {
	// Create a mock server
	mockResponse := JSONRPCResponse{
		JSONRPC: "2.0",
		Result:  "0x123",
		ID:      1,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}

		json.NewEncoder(w).Encode(mockResponse)
	}))
	defer server.Close()

	proxy := New(server.URL)

	requestBody := `{"jsonrpc":"2.0","method":"eth_call","params":[],"id":1}`
	responseBody, statusCode, err := proxy.Forward([]byte(requestBody))

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if statusCode != http.StatusOK {
		t.Errorf("got status %d, want %d", statusCode, http.StatusOK)
	}

	var response JSONRPCResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if response.Result != "0x123" {
		t.Errorf("got result %v, want 0x123", response.Result)
	}
}

func TestForwardContextCancelsRequest(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, _, err := New(server.URL).ForwardContext(ctx, []byte(`{"jsonrpc":"2.0","method":"debug_traceCall","params":[],"id":1}`))
	close(release)
	if err == nil {
		t.Fatal("ForwardContext() error = nil after context timeout")
	}
}

// TestForward_ResponseSizeLimit verifies that the proxy caps upstream JSON-RPC
// responses at maxRPCResponseSize and returns a 502 error when an upstream
// writes more than that. Small responses must still succeed unchanged.
func TestForward_ResponseSizeLimit(t *testing.T) {
	t.Run("small response passes through", func(t *testing.T) {
		small := `{"jsonrpc":"2.0","result":"0xabc","id":1}`
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(small))
		}))
		defer server.Close()

		p := New(server.URL)
		body, status, err := p.Forward([]byte(`{"jsonrpc":"2.0","method":"eth_call","params":[],"id":1}`))
		if err != nil {
			t.Fatalf("unexpected error for small response: %v", err)
		}
		if status != http.StatusOK {
			t.Errorf("got status %d, want 200", status)
		}
		if string(body) != small {
			t.Errorf("got body %q, want %q", body, small)
		}
	})

	t.Run("response over limit is rejected with 502", func(t *testing.T) {
		// Write exactly maxRPCResponseSize + 100 bytes so io.LimitReader(+1)
		// sees more than the cap. Stream the body to avoid a monster
		// intermediate buffer allocation in the test.
		const oversize = maxRPCResponseSize + 100
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			chunk := bytes.Repeat([]byte{'x'}, 1<<20) // 1 MiB
			written := 0
			for written < oversize {
				n := oversize - written
				if n > len(chunk) {
					n = len(chunk)
				}
				if _, err := w.Write(chunk[:n]); err != nil {
					return
				}
				written += n
			}
		}))
		defer server.Close()

		p := New(server.URL)
		body, status, err := p.Forward([]byte(`{"jsonrpc":"2.0","method":"eth_call","params":[],"id":1}`))
		if err == nil {
			t.Fatal("expected error for oversized response, got nil")
		}
		if status != http.StatusBadGateway {
			t.Errorf("got status %d, want 502", status)
		}
		if body != nil {
			t.Errorf("expected nil body on oversize error, got %d bytes", len(body))
		}
		if !strings.Contains(err.Error(), "exceeded") {
			t.Errorf("expected error to mention the limit, got %q", err.Error())
		}
	})

	t.Run("response at exact limit is accepted", func(t *testing.T) {
		const exact = maxRPCResponseSize
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			chunk := bytes.Repeat([]byte{'y'}, 1<<20)
			written := 0
			for written < exact {
				n := exact - written
				if n > len(chunk) {
					n = len(chunk)
				}
				if _, err := w.Write(chunk[:n]); err != nil {
					return
				}
				written += n
			}
		}))
		defer server.Close()

		p := New(server.URL)
		body, status, err := p.Forward([]byte(`{"jsonrpc":"2.0","method":"eth_call","params":[],"id":1}`))
		if err != nil {
			t.Fatalf("unexpected error for exact-limit response: %v", err)
		}
		if status != http.StatusOK {
			t.Errorf("got status %d, want 200", status)
		}
		if len(body) != exact {
			t.Errorf("got body len %d, want %d", len(body), exact)
		}
	})
}

// TestValidAPIKeyHeader covers the regex used to gate header names at every
// trust boundary (config load + admin save).
func TestValidAPIKeyHeader(t *testing.T) {
	cases := []struct {
		name string
		in   string
		ok   bool
	}{
		{"default", "Authorization", true},
		{"x-api-key", "X-API-Key", true},
		{"lowercase", "x-api-key", true},
		{"digits", "API-Key-2", true},
		{"empty", "", false},
		{"with-space", "X API Key", false},
		{"with-colon", "X-API-Key:", false},
		{"with-newline", "X-API-Key\nInjected: yes", false},
		{"with-cr", "X\rAPI", false},
		{"underscore", "X_API_KEY", false}, // RFC 7230 token allows _, but our regex is conservative
		{"empty-with-space", " ", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ValidAPIKeyHeader(tc.in); got != tc.ok {
				t.Errorf("ValidAPIKeyHeader(%q) = %v, want %v", tc.in, got, tc.ok)
			}
		})
	}
}

// TestSetAPIKeyHeader verifies the helper used by the proxy forwarder. The
// rules are: empty key → no header set; "Authorization" (any case) → Bearer
// prefix preserved; other names → raw key value.
func TestSetAPIKeyHeader(t *testing.T) {
	cases := []struct {
		name       string
		headerName string
		apiKey     string
		// expected: map of header → value to assert; empty value means "must not be set"
		want map[string]string
	}{
		{
			name:       "default_authorization_uses_bearer",
			headerName: "Authorization",
			apiKey:     "sk-test-key",
			want:       map[string]string{"Authorization": "Bearer sk-test-key"},
		},
		{
			name:       "default_authorization_lowercase_uses_bearer",
			headerName: "authorization",
			apiKey:     "sk-test-key",
			want:       map[string]string{"Authorization": "Bearer sk-test-key"},
		},
		{
			name:       "empty_header_falls_back_to_authorization",
			headerName: "",
			apiKey:     "sk-test-key",
			want:       map[string]string{"Authorization": "Bearer sk-test-key"},
		},
		{
			name:       "custom_header_sends_raw_key",
			headerName: "X-API-Key",
			apiKey:     "sk-test-key",
			want: map[string]string{
				"X-Api-Key":     "sk-test-key", // canonicalised
				"Authorization": "",            // must NOT be set
			},
		},
		{
			name:       "no_key_no_header",
			headerName: "Authorization",
			apiKey:     "",
			want:       map[string]string{"Authorization": ""},
		},
		{
			name:       "invalid_header_falls_back_to_default",
			headerName: "X API Key",
			apiKey:     "sk-test-key",
			want:       map[string]string{"Authorization": "Bearer sk-test-key"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, "http://example.invalid", nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			SetAPIKeyHeader(req, tc.headerName, tc.apiKey)
			for h, want := range tc.want {
				got := req.Header.Get(h)
				if got != want {
					t.Errorf("header %q = %q, want %q", h, got, want)
				}
			}
		})
	}
}

// TestForwardWithAPIKeyHeader_RoutesToHeader exercises the full forward path
// to confirm headers are written on the outbound HTTP request to the upstream.
func TestForwardWithAPIKeyHeader_RoutesToHeader(t *testing.T) {
	cases := []struct {
		name           string
		headerName     string
		apiKey         string
		wantAuthValue  string
		wantOtherKey   string // header name to also check
		wantOtherValue string
	}{
		{
			name:          "authorization_bearer",
			headerName:    "Authorization",
			apiKey:        "k1",
			wantAuthValue: "Bearer k1",
		},
		{
			name:           "x_api_key_raw",
			headerName:     "X-API-Key",
			apiKey:         "k2",
			wantAuthValue:  "", // Authorization must remain unset
			wantOtherKey:   "X-Api-Key",
			wantOtherValue: "k2",
		},
		{
			name:          "empty_key_no_header",
			headerName:    "X-API-Key",
			apiKey:        "",
			wantAuthValue: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var captured http.Header
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				captured = r.Header.Clone()
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x1"}`))
			}))
			defer srv.Close()

			p := New(srv.URL)
			_, _, err := p.ForwardWithAPIKeyHeader(
				[]byte(`{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}`),
				tc.headerName, tc.apiKey, "",
			)
			if err != nil {
				t.Fatalf("ForwardWithAPIKeyHeader: %v", err)
			}
			if got := captured.Get("Authorization"); got != tc.wantAuthValue {
				t.Errorf("Authorization = %q, want %q", got, tc.wantAuthValue)
			}
			if tc.wantOtherKey != "" {
				if got := captured.Get(tc.wantOtherKey); got != tc.wantOtherValue {
					t.Errorf("%s = %q, want %q", tc.wantOtherKey, got, tc.wantOtherValue)
				}
			}
		})
	}
}
