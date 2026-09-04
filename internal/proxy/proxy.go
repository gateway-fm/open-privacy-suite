package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"privacy-proxy/internal/nodehttp"
)

// DefaultAPIKeyHeader is the header name used to attach the upstream RPC API
// key when no explicit override is configured. When this header is selected
// the API key is sent as a Bearer token; any other header sends the raw key.
const DefaultAPIKeyHeader = "Authorization"

// apiKeyHeaderPattern enforces a conservative character set for header names
// to prevent CRLF or whitespace injection: letters, digits, and hyphens only.
// The match is case-insensitive (header names are case-insensitive in HTTP).
var apiKeyHeaderPattern = regexp.MustCompile(`^[A-Za-z0-9-]+$`)

// ValidAPIKeyHeader reports whether name is a syntactically acceptable HTTP
// header name for use as the upstream RPC API-key header. Empty input is
// rejected — callers should normalise to DefaultAPIKeyHeader before calling.
func ValidAPIKeyHeader(name string) bool {
	if name == "" {
		return false
	}
	return apiKeyHeaderPattern.MatchString(name)
}

// SetAPIKeyHeader writes the upstream RPC API key onto req using the given
// header name. When headerName is empty or equals DefaultAPIKeyHeader
// (case-insensitive), the key is sent as "Bearer <key>" under Authorization
// — preserving the historical behaviour. For any other header name the key
// is sent verbatim under that header (no Bearer prefix).
//
// If apiKey is empty no header is set. headerName is validated by the caller;
// SetAPIKeyHeader assumes a previously-vetted name and will silently fall
// back to the default if it's malformed.
func SetAPIKeyHeader(req *http.Request, headerName, apiKey string) {
	if apiKey == "" {
		return
	}
	if headerName == "" || !ValidAPIKeyHeader(headerName) {
		headerName = DefaultAPIKeyHeader
	}
	if strings.EqualFold(headerName, DefaultAPIKeyHeader) {
		req.Header.Set(DefaultAPIKeyHeader, "Bearer "+apiKey)
		return
	}
	req.Header.Set(headerName, apiKey)
}

type Proxy struct {
	targetURL string
	client    *http.Client
}

// DefaultTimeout is the default timeout for HTTP requests to the target node.
const DefaultTimeout = 30 * time.Second

// maxRPCResponseSize caps the size of a single upstream JSON-RPC response body
// that the proxy will buffer. Legitimate eth_getLogs / debug_traceTransaction
// responses can be large but 128 MiB is well beyond any real-world payload;
// a larger response is treated as a misbehaving / malicious upstream and the
// request fails closed with a 502. The same pattern is used (at smaller caps)
// by internal/tracer to protect the tracer RPC client.
const maxRPCResponseSize = 128 << 20 // 128 MiB

func New(targetURL string) *Proxy {
	return NewWithTransport(targetURL, nodehttp.DefaultTransportConfig())
}

// NewWithTransport builds a Proxy with an explicit upstream transport
// configuration. Use this to apply operator-tuned connection-pool sizes; New
// applies sane defaults tuned for a single high-throughput node host.
func NewWithTransport(targetURL string, tc nodehttp.TransportConfig) *Proxy {
	return &Proxy{
		targetURL: targetURL,
		client:    nodehttp.NewClient(DefaultTimeout, tc),
	}
}

type JSONRPCRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      interface{}   `json:"id"`
}

type JSONRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
	ID      interface{} `json:"id"`
}

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Forward forwards a JSON-RPC request to the target node.
func (p *Proxy) Forward(reqBody []byte) ([]byte, int, error) {
	return p.ForwardWithAPIKey(reqBody, "", "")
}

// ForwardContext forwards a JSON-RPC request with caller cancellation.
func (p *Proxy) ForwardContext(ctx context.Context, reqBody []byte) ([]byte, int, error) {
	return p.forwardWithAPIKeyHeaderContext(ctx, reqBody, DefaultAPIKeyHeader, "", "")
}

// ForwardWithAPIKey forwards a JSON-RPC request with an optional API key
// for upstream RPC proxy authentication. If apiKey is non-empty it is sent
// as a Bearer token in the Authorization header. If clientIP is non-empty,
// it is forwarded as an X-Forwarded-For header.
//
// This is a convenience wrapper that pins the header name to "Authorization".
// Callers that need a custom header name should use ForwardWithAPIKeyHeader.
func (p *Proxy) ForwardWithAPIKey(reqBody []byte, apiKey string, clientIP string) ([]byte, int, error) {
	return p.ForwardWithAPIKeyHeader(reqBody, DefaultAPIKeyHeader, apiKey, clientIP)
}

// ForwardWithAPIKeyHeader forwards a JSON-RPC request and attaches the
// upstream RPC API key under the supplied header name. See SetAPIKeyHeader
// for the exact rules — "Authorization" is sent as "Bearer <key>"; any
// other header name sends the raw key value.
func (p *Proxy) ForwardWithAPIKeyHeader(reqBody []byte, headerName, apiKey, clientIP string) ([]byte, int, error) {
	return p.forwardWithAPIKeyHeaderContext(context.Background(), reqBody, headerName, apiKey, clientIP)
}

// ForwardWithAPIKeyHeaderContext forwards a request with an upstream credential
// and caller cancellation.
func (p *Proxy) ForwardWithAPIKeyHeaderContext(ctx context.Context, reqBody []byte, headerName, apiKey, clientIP string) ([]byte, int, error) {
	return p.forwardWithAPIKeyHeaderContext(ctx, reqBody, headerName, apiKey, clientIP)
}

func (p *Proxy) forwardWithAPIKeyHeaderContext(ctx context.Context, reqBody []byte, headerName, apiKey, clientIP string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", p.targetURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	SetAPIKeyHeader(req, headerName, apiKey)
	if clientIP != "" {
		req.Header.Set("X-Forwarded-For", clientIP)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, http.StatusBadGateway, fmt.Errorf("failed to forward request: %w", err)
	}
	defer resp.Body.Close()

	// Read at most maxRPCResponseSize + 1 so we can distinguish a response that
	// exactly fills the limit from one that exceeds it. Anything larger is
	// rejected with 502 so a misbehaving upstream cannot OOM the proxy.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRPCResponseSize+1))
	if err != nil {
		return nil, http.StatusBadGateway, fmt.Errorf("failed to read response: %w", err)
	}
	if len(body) > maxRPCResponseSize {
		return nil, http.StatusBadGateway, fmt.Errorf("upstream RPC response exceeded %d byte limit", maxRPCResponseSize)
	}

	return body, resp.StatusCode, nil
}

// ErrBatchRequest is returned when a batch JSON-RPC request is detected.
// Batch requests are not supported for security reasons.
var ErrBatchRequest = fmt.Errorf("batch JSON-RPC requests are not supported")

// IsBatchRequest checks if the body contains a JSON-RPC batch request (array format).
func IsBatchRequest(body []byte) bool {
	// Trim whitespace and check if it starts with '['
	trimmed := bytes.TrimSpace(body)
	return len(trimmed) > 0 && trimmed[0] == '['
}

// ParseMethod extracts the method name from a JSON-RPC request
func ParseMethod(body []byte) (string, error) {
	// Check for batch request first
	if IsBatchRequest(body) {
		return "", ErrBatchRequest
	}

	var req JSONRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return "", fmt.Errorf("failed to parse JSON-RPC request: %w", err)
	}

	return req.Method, nil
}

// ParseRequest extracts method and params from a JSON-RPC request.
// Returns ErrBatchRequest if the request is a batch (array) request.
func ParseRequest(body []byte) (string, []interface{}, error) {
	// Check for batch request first
	if IsBatchRequest(body) {
		return "", nil, ErrBatchRequest
	}

	var req JSONRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return "", nil, fmt.Errorf("failed to parse JSON-RPC request: %w", err)
	}

	return req.Method, req.Params, nil
}

// HealthStatus contains the health check result for the target node
type HealthStatus struct {
	Status    string `json:"status"`
	URL       string `json:"url"`
	LatencyMs int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
}

// CheckHealth performs a health check on the target node by calling eth_blockNumber
func (p *Proxy) CheckHealth() HealthStatus {
	start := time.Now()

	// Create eth_blockNumber request
	reqBody, _ := json.Marshal(JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "eth_blockNumber",
		Params:  []interface{}{},
		ID:      1,
	})

	req, err := http.NewRequest("POST", p.targetURL, bytes.NewReader(reqBody))
	if err != nil {
		return HealthStatus{
			Status: "error",
			URL:    p.targetURL,
			Error:  fmt.Sprintf("failed to create request: %v", err),
		}
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	latency := time.Since(start).Milliseconds()

	if err != nil {
		return HealthStatus{
			Status:    "disconnected",
			URL:       p.targetURL,
			LatencyMs: latency,
			Error:     fmt.Sprintf("failed to connect: %v", err),
		}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return HealthStatus{
			Status:    "error",
			URL:       p.targetURL,
			LatencyMs: latency,
			Error:     fmt.Sprintf("failed to read response: %v", err),
		}
	}

	// Parse response to check for errors
	var rpcResp JSONRPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return HealthStatus{
			Status:    "error",
			URL:       p.targetURL,
			LatencyMs: latency,
			Error:     fmt.Sprintf("invalid JSON-RPC response: %v", err),
		}
	}

	if rpcResp.Error != nil {
		return HealthStatus{
			Status:    "error",
			URL:       p.targetURL,
			LatencyMs: latency,
			Error:     rpcResp.Error.Message,
		}
	}

	return HealthStatus{
		Status:    "connected",
		URL:       p.targetURL,
		LatencyMs: latency,
	}
}

// TargetURL returns the target URL for the proxy
func (p *Proxy) TargetURL() string {
	return p.targetURL
}
