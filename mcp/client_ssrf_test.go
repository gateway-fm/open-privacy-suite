package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

// SEC-1325 regression tests for the SSRF mitigations in client.go (PR #343).
//
// The MCP admin client talks to a single, operator-configured upstream
// (Open Privacy Suite). Two mitigations keep a caller-supplied path (a tool
// argument) from steering a request off that trusted upstream toward an
// internal/loopback/metadata endpoint (e.g. http://169.254.169.254/...):
//
//  1. CheckRedirect returns http.ErrUseLastResponse, so the shared *http.Client
//     never FOLLOWS a redirect — a 30x from the upstream is surfaced as-is and
//     no second request is issued to the Location target.
//  2. do() re-asserts Scheme/Host/User from the trusted base URL on every call,
//     so the outbound request can only ever address the configured upstream.
//  3. doAs() rejects dot segments in the caller-supplied path, so a tool
//     argument interpolated into a path (org ID, address, group ID) cannot
//     climb out of the intended /api/v1/... namespace via "../" — url.JoinPath
//     resolves dot segments, so without this the request would still land on
//     the trusted host but at an unrelated endpoint.
//
// These tests exercise the real request path (get()/do(), the lowest-level
// methods that drive the shared client) and assert the metadata sentinel is
// never contacted.

// TestSSRF_RedirectNotFollowed is mitigation (1): a 302 whose Location points at
// a metadata sentinel must NOT be followed. The client surfaces the redirect
// response itself (302 < 400, so do() returns no error and an empty body) and
// never issues a request to the sentinel.
//
// Verified load-bearing: with CheckRedirect removed from newHTTPClient, the Go
// default client follows the 302, the sentinel is hit, and the leaked body is
// returned to the caller — i.e. this test fails without the fix.
func TestSSRF_RedirectNotFollowed(t *testing.T) {
	var sentinelHits int32
	sentinel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&sentinelHits, 1)
		// Stand in for the IMDS payload an SSRF would try to exfiltrate.
		_, _ = w.Write([]byte(`{"AccessKeyId":"LEAKED","Token":"LEAKED"}`))
	}))
	defer sentinel.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Upstream tries to bounce the client onto the metadata endpoint.
		w.Header().Set("Location", sentinel.URL+"/latest/meta-data/iam/security-credentials/")
		w.WriteHeader(http.StatusFound) // 302
	}))
	defer upstream.Close()

	client, err := newHTTPClient(upstream.URL, "test-admin-token")
	if err != nil {
		t.Fatalf("newHTTPClient: %v", err)
	}

	body, err := client.get("/api/v1/admin/orgs")
	if err != nil {
		// A 302 is < 400, so do() must NOT treat it as an HTTP error. If the
		// redirect were followed and the sentinel 200'd, err would also be nil
		// but the sentinel-hit assertion below would fire.
		t.Fatalf("get returned error on a 302 (redirect should be surfaced, not followed): %v", err)
	}

	if hits := atomic.LoadInt32(&sentinelHits); hits != 0 {
		t.Fatalf("SSRF: redirect was followed to the metadata sentinel (%d hit(s)) — CheckRedirect mitigation missing", hits)
	}

	// The 302 body is empty; the leaked credential payload must never reach the caller.
	if string(body) == `{"AccessKeyId":"LEAKED","Token":"LEAKED"}` {
		t.Fatalf("SSRF: leaked metadata body surfaced to caller: %q", string(body))
	}
}

// TestSSRF_HostRepinned is mitigation (2): no caller-supplied path — absolute
// URL, scheme-relative //host, or embedded credentials — may move the outbound
// request off the configured base host/scheme. We record the request the
// upstream actually receives and assert it stayed on the trusted host, and that
// a separate "evil" host is never contacted.
func TestSSRF_HostRepinned(t *testing.T) {
	var evilHits int32
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&evilHits, 1)
		_, _ = w.Write([]byte(`{"reached":"evil"}`))
	}))
	defer evil.Close()
	evilURL, _ := url.Parse(evil.URL)
	evilHost := evilURL.Host // e.g. 127.0.0.1:NNNNN

	var gotHost string
	var reqCount int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&reqCount, 1)
		gotHost = r.Host
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)
	wantHost := upstreamURL.Host

	client, err := newHTTPClient(upstream.URL, "test-admin-token")
	if err != nil {
		t.Fatalf("newHTTPClient: %v", err)
	}

	// Each of these tries, in a different way, to escape the configured upstream
	// and address the evil host instead.
	maliciousPaths := []string{
		"http://" + evilHost + "/latest/meta-data/",  // absolute URL with attacker host
		"https://" + evilHost + "/x",                 // absolute https URL
		"//" + evilHost + "/x",                       // scheme-relative authority
		"/api/v1/admin/orgs?next=http://" + evilHost, // attacker host smuggled in query
		"user:pass@" + evilHost + "/x",               // embedded credentials + host
	}

	for _, p := range maliciousPaths {
		t.Run(p, func(t *testing.T) {
			gotHost = ""
			// We don't care about the response here, only where the request went.
			_, _ = client.get(apiPath(p))

			if gotHost != wantHost {
				t.Fatalf("SSRF: request for path %q reached host %q, want trusted upstream %q", p, gotHost, wantHost)
			}
		})
	}

	if hits := atomic.LoadInt32(&evilHits); hits != 0 {
		t.Fatalf("SSRF: the attacker-controlled host was contacted %d time(s) — host re-pinning missing", hits)
	}
	if atomic.LoadInt32(&reqCount) == 0 {
		t.Fatal("test bug: upstream received no requests; the malicious paths never exercised do()")
	}
}

// TestSSRF_NewClientNeverFollowsRedirect locks the constructor contract directly:
// the shared client must install a CheckRedirect that refuses to follow. This is
// a fast, unit-level guard against a future refactor silently dropping the hook.
func TestSSRF_NewClientNeverFollowsRedirect(t *testing.T) {
	client, err := newHTTPClient("https://upstream.invalid", "")
	if err != nil {
		t.Fatalf("newHTTPClient: %v", err)
	}
	if client.http.CheckRedirect == nil {
		t.Fatal("SSRF: shared http.Client has no CheckRedirect hook — redirects would be followed")
	}
	// The hook must instruct net/http to use the last response (i.e. not follow).
	req, _ := http.NewRequest(http.MethodGet, "https://upstream.invalid/x", nil)
	if err := client.http.CheckRedirect(req, nil); err != http.ErrUseLastResponse {
		t.Fatalf("CheckRedirect returned %v, want http.ErrUseLastResponse (do-not-follow)", err)
	}
}

// TestSSRF_PathConfinedToNamespace is mitigation (3). Host re-pinning keeps the
// request on the trusted upstream, but the path is still assembled from tool
// arguments — e.g. fmt.Sprintf("/api/v1/admin/orgs/%s/compliance/config",
// args.OrgID) in compliance.go. url.JoinPath resolves dot segments, so an OrgID
// of "../.." would rewrite the request onto a different endpoint of the same
// (privileged, admin-token-bearing) upstream. The request must be refused
// before it is issued.
func TestSSRF_PathConfinedToNamespace(t *testing.T) {
	var reqPaths []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqPaths = append(reqPaths, r.URL.Path)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	client, err := newHTTPClient(upstream.URL, "test-admin-token")
	if err != nil {
		t.Fatalf("newHTTPClient: %v", err)
	}

	// Each entry is a path built from a hostile tool argument.
	traversals := []string{
		"/api/v1/admin/orgs/../../../internal/debug",  // climb out of the admin namespace
		"/api/v1/admin/orgs/..%2f..%2fdebug/config",   // percent-encoded dot segments
		"/api/v1/admin/orgs/./././secret",             // single-dot segments
		"/api/v1/admin/orgs/../x/compliance?limit=10", // traversal alongside a query string
	}

	for _, p := range traversals {
		t.Run(p, func(t *testing.T) {
			if _, err := client.get(apiPath(p)); err == nil {
				t.Fatalf("path %q was accepted; a dot segment must be refused before the request is issued", p)
			}
		})
	}

	if len(reqPaths) != 0 {
		t.Fatalf("upstream received %d request(s) %v — traversal paths must never reach the network", len(reqPaths), reqPaths)
	}

	// A legitimate path with the same shape must still work: the guard rejects
	// dot segments only, not ordinary IDs, queries or hyphenated segments.
	for _, p := range []string{
		"/api/v1/admin/orgs/org-123/compliance/config",
		"/api/v1/admin/orgs/org-123/compliance/logs?limit=10&offset=0",
	} {
		if _, err := client.get(apiPath(p)); err != nil {
			t.Fatalf("legitimate path %q was rejected: %v", p, err)
		}
	}
	if len(reqPaths) != 2 {
		t.Fatalf("upstream received %d legitimate request(s), want 2", len(reqPaths))
	}
}

// TestSSRF_PathConfinement is the regression test for the review findings on #439.
//
// It asserts on r.URL.Path — the DECODED path, which is what a router matches on.
// An earlier version of this test compared against the escaped form and therefore
// passed while "victim/contracts" was still reaching a different endpoint: %2F is
// decoded by net/http, and this upstream runs Gin with the default UseRawPath=false,
// so the router sees a real separator. Escaping alone never confined that case.
func TestSSRF_PathConfinement(t *testing.T) {
	var gotPath, gotQuery string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// r.URL.Path, not RawPath: this is the value Gin routes on.
		gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	client, err := newHTTPClient(upstream.URL, "test-admin-token")
	if err != nil {
		t.Fatalf("newHTTPClient: %v", err)
	}

	// Confined: escaping keeps these inside their segment, and the escaping survives
	// decoding because none of them decode to a separator.
	confined := []string{
		"victim?ignored",     // would truncate the path and demote the rest to a query
		"victim?a=b",         // same, but parses as a real key=value pair
		"victim#frag",        // fragment
		"vic tim",            // space
		"victim%2Fcontracts", // caller pre-encoded a slash: double-encoded, stays one segment
	}
	for _, orgID := range confined {
		t.Run("confined/"+orgID, func(t *testing.T) {
			gotPath, gotQuery = "", ""
			if _, err := client.get(pathf("/api/v1/admin/orgs/%s/compliance/config", orgID)); err != nil {
				t.Fatalf("request failed: %v", err)
			}
			want := "/api/v1/admin/orgs/" + orgID + "/compliance/config"
			if gotPath != want {
				t.Fatalf("endpoint confinement broken:\n  router saw %q\n  want        %q", gotPath, want)
			}
			if gotQuery != "" {
				t.Fatalf("hostile segment leaked into the query: %q", gotQuery)
			}
		})
	}

	// Rejected: a separator cannot be made safe by escaping, because the server
	// decodes it back before routing. These must never reach the network at all.
	rejected := []string{
		"victim/contracts",                 // would match /orgs/:org_id/contracts instead
		"victim?ignored/compliance/config", // the original review payload: "?" plus separators
		"victim?a=b/rest",                  // key=value shape, still carries a separator
		"victim\\contracts",                // backslash
		"..",                               // dot segment
		"../../debug",                      // traversal
	}
	for _, orgID := range rejected {
		t.Run("rejected/"+orgID, func(t *testing.T) {
			gotPath = ""
			if _, err := client.get(pathf("/api/v1/admin/orgs/%s/compliance/config", orgID)); err == nil {
				t.Fatalf("argument %q was accepted; the router would have seen %q", orgID, gotPath)
			}
			if gotPath != "" {
				t.Fatalf("request reached the upstream despite rejection: %q", gotPath)
			}
		})
	}

	// A legitimate structured query must still arrive intact.
	t.Run("legitimate query survives", func(t *testing.T) {
		gotPath, gotQuery = "", ""
		if _, err := client.get("/api/v1/admin/orgs", pageQuery(10, 20)); err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if gotPath != "/api/v1/admin/orgs" {
			t.Fatalf("path = %q", gotPath)
		}
		if gotQuery != "limit=10&offset=20" {
			t.Fatalf("query = %q, want limit=10&offset=20", gotQuery)
		}
	})
}
