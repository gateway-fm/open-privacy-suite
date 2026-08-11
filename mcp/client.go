package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
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

// apiPath is a request path that is safe to send. Its underlying type is string,
// so an untyped constant — a literal path like "/api/v1/admin/orgs" — still assigns
// to it directly and needs no ceremony. A *typed* string does not, which means
// `client.get(fmt.Sprintf(...))` no longer compiles: interpolating an untrusted
// value into a path is now a build error rather than a review question. Use pathf.
type apiPath string

// pathf builds a request path, percent-escaping every string argument so a tool
// argument stays inside the path segment it was interpolated into.
//
// This is the whole fix. url.PathEscape turns "/" into %2F, "?" into %3F and "#"
// into %23, and JoinPath preserves those, so a hostile org ID can no longer add
// segments, truncate the path, or start a query. Non-string arguments (%d limits
// and offsets) pass through untouched.
//
// Dot segments are NOT escapable — url.PathEscape leaves "." and ".." alone
// because they are unreserved characters, and JoinPath then resolves them. They are
// rejected in doAs instead, on the decoded path, where one check covers every call.
func pathf(format string, args ...any) apiPath {
	escaped := make([]any, len(args))
	for i, a := range args {
		if s, ok := a.(string); ok {
			escaped[i] = url.PathEscape(s)
			continue
		}
		escaped[i] = a
	}
	return apiPath(fmt.Sprintf(format, escaped...))
}

// pageQuery is the limit/offset pair almost every list endpoint takes. Building it
// here rather than formatting "?limit=%d&offset=%d" into the path keeps the query a
// structured value that url.Values escapes on encode.
func pageQuery(limit, offset int) url.Values {
	q := url.Values{}
	q.Set("limit", strconv.Itoa(limit))
	if offset != 0 {
		q.Set("offset", strconv.Itoa(offset))
	}
	return q
}

func (c *httpClient) get(path apiPath, query ...url.Values) (json.RawMessage, error) {
	return c.doAs(http.MethodGet, path, firstQuery(query), nil, "")
}

// getAs issues a GET with a viewer JWT in the Authorization header. Explorer
// endpoints resolve the viewer identity ONLY from a validated JWT (RD-1164 #7),
// so privacy-filtered responses need the user's token — the admin token alone
// yields the anonymous (empty/redacted) view.
func (c *httpClient) getAs(path apiPath, viewerJWT string, query ...url.Values) (json.RawMessage, error) {
	return c.doAs(http.MethodGet, path, firstQuery(query), nil, viewerJWT)
}

func (c *httpClient) post(path apiPath, payload any) (json.RawMessage, error) {
	return c.do(http.MethodPost, path, payload)
}

func (c *httpClient) put(path apiPath, payload any) (json.RawMessage, error) {
	return c.do(http.MethodPut, path, payload)
}

func (c *httpClient) del(path apiPath) (json.RawMessage, error) {
	return c.do(http.MethodDelete, path, nil)
}

func (c *httpClient) do(method string, path apiPath, payload any) (json.RawMessage, error) {
	return c.doAs(method, path, nil, payload, "")
}

func firstQuery(q []url.Values) url.Values {
	if len(q) == 0 {
		return nil
	}
	return q[0]
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

// rejectEncodedSeparators refuses a path in which a dynamic argument contained a
// path separator.
//
// Escaping is not enough for this one. pathf turns "victim/contracts" into
// "victim%2Fcontracts", which is correct on the wire — but net/http decodes %2F back
// into URL.Path, and this upstream runs Gin with the default UseRawPath=false, so it
// routes on the decoded form. The request therefore matches
// /orgs/:org_id/contracts instead of the intended endpoint, with the admin token
// attached. Percent-encoding a separator only hides it from the client, not from the
// router.
//
// Checked here rather than in pathf because pathf has no error return and every call
// funnels through doAs anyway. It is precise: %2F and %5C only ever appear in a path
// built by pathf when an argument really did contain a separator — no hand-written
// literal path in this package contains an encoded slash.
func rejectEncodedSeparators(path string) error {
	lower := strings.ToLower(path)
	for _, enc := range []string{"%2f", "%5c"} {
		if strings.Contains(lower, enc) {
			return fmt.Errorf("invalid request path %q: a path argument must not contain a separator", path)
		}
	}
	return nil
}

func (c *httpClient) doAs(method string, path apiPath, query url.Values, payload any, viewerJWT string) (json.RawMessage, error) {
	if err := rejectEncodedSeparators(string(path)); err != nil {
		return nil, err
	}
	if err := rejectDotSegments(string(path)); err != nil {
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

	// The query is a separate, structured argument. It used to be smuggled inside
	// the path string and recovered by splitting on the first "?", which is exactly
	// how a tool argument containing "?" could truncate the path and retarget the
	// request at a different endpoint. net/url escapes "?" inside a path for free;
	// the split was undoing that.
	target := c.baseURL.JoinPath(string(path))
	if len(query) > 0 {
		target.RawQuery = query.Encode()
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
