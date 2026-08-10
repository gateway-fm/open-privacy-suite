package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type httpClient struct {
	baseURL    *url.URL
	adminToken string
	http       *http.Client
}

func newHTTPClient(rawURL, adminToken string) (*httpClient, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("base URL must be http or https, got %q", u.Scheme)
	}
	return &httpClient{
		baseURL:    u,
		adminToken: adminToken,
		http: &http.Client{
			Timeout: 15 * time.Second,
			// SSRF mitigation: never follow redirects. The configured base host
			// is trusted, but a redirect response could otherwise steer a request
			// to an internal/loopback/metadata endpoint (e.g. 169.254.169.254).
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (c *httpClient) get(path string) (json.RawMessage, error) {
	return c.doAs(http.MethodGet, path, nil, "")
}

// getAs issues a GET with a viewer JWT in the Authorization header. Explorer
// endpoints resolve the viewer identity ONLY from a validated JWT (RD-1164 #7),
// so privacy-filtered responses need the user's token — the admin token alone
// yields the anonymous (empty/redacted) view.
func (c *httpClient) getAs(path, viewerJWT string) (json.RawMessage, error) {
	return c.doAs(http.MethodGet, path, nil, viewerJWT)
}

func (c *httpClient) post(path string, payload any) (json.RawMessage, error) {
	return c.do(http.MethodPost, path, payload)
}

func (c *httpClient) put(path string, payload any) (json.RawMessage, error) {
	return c.do(http.MethodPut, path, payload)
}

func (c *httpClient) del(path string) (json.RawMessage, error) {
	return c.do(http.MethodDelete, path, nil)
}

func (c *httpClient) do(method, path string, payload any) (json.RawMessage, error) {
	return c.doAs(method, path, payload, "")
}

// rejectDotSegments guards the caller-supplied portion of a request path.
// doAs pins scheme/host/userinfo to the configured base, so a caller can never
// retarget a different origin. It could still climb out of the intended
// /api/v1/... namespace with a "../" segment, because url.JoinPath resolves dot
// segments before the request is sent — reaching an unrelated endpoint on the
// trusted upstream. Tool arguments (org IDs, addresses, group IDs) are
// interpolated into these paths by the callers in this package, so every
// segment is untrusted. No legitimate API path contains a dot segment.
//
// The path is unescaped before it is split: JoinPath decodes percent-encoded
// separators, so "..%2f..%2fdebug" is one literal segment here but three
// segments by the time the request goes out. Checking the decoded form is what
// makes the guard match what the request actually does.
func rejectDotSegments(path string) error {
	decoded, err := url.PathUnescape(path)
	if err != nil {
		return fmt.Errorf("invalid request path %q: %w", path, err)
	}
	for seg := range strings.SplitSeq(decoded, "/") {
		if seg == "." || seg == ".." {
			return fmt.Errorf("invalid request path %q: dot segments are not allowed", path)
		}
	}
	return nil
}

func (c *httpClient) doAs(method, path string, payload any, viewerJWT string) (json.RawMessage, error) {
	pathOnly := path
	if i := strings.Index(pathOnly, "?"); i >= 0 {
		pathOnly = pathOnly[:i]
	}
	if err := rejectDotSegments(pathOnly); err != nil {
		return nil, err
	}

	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshaling request: %w", err)
		}
		body = bytes.NewReader(data)
	}

	target := c.baseURL.JoinPath(path)
	if strings.Contains(path, "?") {
		parts := strings.SplitN(path, "?", 2)
		target = c.baseURL.JoinPath(parts[0])
		target.RawQuery = parts[1]
	}
	// SSRF mitigation: pin the request to the configured base host. JoinPath
	// preserves the base scheme/host/userinfo, but re-asserting them here ensures
	// a caller-supplied path can only ever address the trusted upstream and can
	// never redirect the request to another scheme, host, or credential.
	target.Scheme = c.baseURL.Scheme
	target.Host = c.baseURL.Host
	target.User = c.baseURL.User
	req, err := http.NewRequest(method, target.String(), body)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if c.adminToken != "" {
		req.Header.Set("X-Admin-Token", c.adminToken)
	}
	if viewerJWT != "" {
		req.Header.Set("Authorization", "Bearer "+viewerJWT)
	}

	resp, err := c.http.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(respBody), 500))
	}

	return json.RawMessage(respBody), nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
