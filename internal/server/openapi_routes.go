package server

import (
	"sort"
	"strings"

	"github.com/gin-gonic/gin"

	"privacy-proxy/internal/config"
	"privacy-proxy/internal/metrics"
)

// This file is the tooling seam for the generated OpenAPI pipeline (RD-1166):
// it enumerates the real gin route table so `make api-inventory` and the
// route↔spec coverage gate (openapi_coverage_test.go) always work from what
// the server actually registers, never from a hand-maintained list.

// RouteEntry is one registered HTTP route, with the path in OpenAPI brace
// style ({param} instead of gin's :param / *param).
type RouteEntry struct {
	Method  string
	Path    string
	Handler string
}

// RoutesForSpec returns the proxy's full HTTP route table by constructing a
// minimal, never-run Server and registering its routes. Registration only
// builds middleware closures — it must not touch the DB, network, or chain
// (handlers are referenced, not invoked). includeDev enumerates with a
// non-production config (AllowMockLogin on), which is a strict superset of
// the production table: it adds the dev-gated routes (/auth/verify mounts,
// /api/v1/dev/test-identities).
func RoutesForSpec(includeDev bool) []RouteEntry {
	router, stop := specRouter(includeDev)
	defer stop()

	routes := router.Routes()
	entries := make([]RouteEntry, 0, len(routes))
	for _, r := range routes {
		entries = append(entries, RouteEntry{
			Method:  r.Method,
			Path:    ginPathToOpenAPI(r.Path),
			Handler: strings.TrimSuffix(strings.TrimPrefix(r.Handler, "privacy-proxy/internal/server."), "-fm"),
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Path != entries[j].Path {
			return entries[i].Path < entries[j].Path
		}
		return entries[i].Method < entries[j].Method
	})
	return entries
}

// specRouter builds the full route table on a minimal, never-run Server (see
// RoutesForSpec). The returned engine carries the real middleware chains —
// with the admin token gate ARMED (a non-empty AdminAPIToken) — so spec
// tooling can also probe pre-handler behavior (the anonymous-denial authz
// gate in openapi_authz_test.go). Handlers must not be reached with a real
// principal: everything behind the middleware is nil.
func specRouter(includeDev bool) (router *gin.Engine, stop func()) {
	prevMode := gin.Mode()
	gin.SetMode(gin.TestMode)
	defer gin.SetMode(prevMode)

	env := "production"
	if includeDev {
		env = "development"
	}
	s := &Server{
		config: &config.Config{
			Environment:        env,
			AllowMockLogin:     includeDev,
			CORSAllowedOrigins: "*",
			AdminAPIToken:      "spec-router-armed-admin-gate",
		},
		metrics:         metrics.NewNoop(),
		authRateLimiter: NewAuthRateLimiter(DevAuthRateLimiterConfig()),
	}
	return s.setupRouter(), s.authRateLimiter.Stop
}

// ginPathToOpenAPI converts gin path parameters (:id, *rest) to OpenAPI
// brace style ({id}, {rest}).
func ginPathToOpenAPI(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if strings.HasPrefix(s, ":") || strings.HasPrefix(s, "*") {
			segs[i] = "{" + s[1:] + "}"
		}
	}
	return strings.Join(segs, "/")
}

// Route kinds returned by CanonicalizeRoute.
const (
	RouteKindCanonical          = "canonical"           // documented under its own path
	RouteKindAlias              = "alias"               // supported alternate mount of a canonical path
	RouteKindDeprecatedAlias    = "deprecated-alias"    // legacy /api/* mount (X-Deprecated header)
	RouteKindImpersonationMount = "impersonation-mount" // RD-928 read-only mirror under /api/v1/admin/impersonate
	RouteKindRejectSurface      = "reject-surface"      // registered only to return an explicit 400/405-style refusal
)

// RouteClass says where a registered route is documented in the OpenAPI spec.
type RouteClass struct {
	Canonical string // canonical path whose spec entry covers this route
	Kind      string
}

// prefixAlias rewrites one mount prefix to its canonical prefix.
type prefixAlias struct {
	from, to, kind string
}

// Ordering matters: more specific prefixes first.
var prefixAliases = []prefixAlias{
	// RD-928/RD-994 impersonation mirrors: the explorer/rpc surface re-mounted
	// under an admin-gated, GET-only, per-request-audited prefix. Covered by
	// the canonical explorer/rpc spec entries; the mount semantics are
	// documented in the spec's "Admin: impersonation" tag description.
	{"/api/v1/admin/impersonate/{target_did}/in/{org_id}/api/v1/explorer", "/api/v1/explorer", RouteKindImpersonationMount},
	{"/api/v1/admin/impersonate/{target_did}/in/{org_id}/rpc", "/rpc", RouteKindImpersonationMount},
	// Legacy unversioned /api mounts (deprecationMiddleware adds X-Deprecated).
	{"/api/admin", "/api/v1/admin", RouteKindDeprecatedAlias},
	{"/api/eth", "/api/v1/eth", RouteKindDeprecatedAlias},
	{"/api/auth", "/api/v1/auth", RouteKindDeprecatedAlias},
	{"/api/refresh", "/api/v1/refresh", RouteKindDeprecatedAlias},
	{"/api/revoke", "/api/v1/revoke", RouteKindDeprecatedAlias},
	{"/api/introspect", "/api/v1/introspect", RouteKindDeprecatedAlias},
	// Supported alternate mounts.
	{"/eth", "/api/v1/eth", RouteKindAlias},
	{"/auth", "/api/v1/auth", RouteKindAlias},
	{"/refresh", "/api/v1/refresh", RouteKindAlias},
	{"/revoke", "/api/v1/revoke", RouteKindAlias},
	{"/introspect", "/api/v1/introspect", RouteKindAlias},
}

// CanonicalizeRoute maps a registered route path (OpenAPI brace style) to the
// canonical path its documentation lives under. Alias mounts collapse onto
// the canonical entry so the spec documents each logical operation exactly
// once; the coverage gate then requires a spec entry per canonical path.
func CanonicalizeRoute(path string) RouteClass {
	// Bare impersonation mounts (no /in/{org_id}) exist only to reject with an
	// explicit 400 pointing at the org-scoped form. Not separate operations.
	if strings.HasPrefix(path, "/api/v1/admin/impersonate/{target_did}/") &&
		!strings.HasPrefix(path, "/api/v1/admin/impersonate/{target_did}/in/") {
		return RouteClass{Canonical: "/api/v1/admin/impersonate/{target_did}/in/{org_id}", Kind: RouteKindRejectSurface}
	}
	// The root JSON-RPC mount is the same operation as /rpc.
	if path == "/" {
		return RouteClass{Canonical: "/rpc", Kind: RouteKindAlias}
	}
	for _, a := range prefixAliases {
		if path == a.from || strings.HasPrefix(path, a.from+"/") {
			canon := a.to + strings.TrimPrefix(path, a.from)
			// The impersonated JSON-RPC mirror names its org parameter
			// :nested_org_id (the outer :org_id belongs to the mount);
			// canonically the operation is /rpc/{org_id}.
			if canon == "/rpc/{nested_org_id}" {
				canon = "/rpc/{org_id}"
			}
			return RouteClass{Canonical: canon, Kind: a.kind}
		}
	}
	return RouteClass{Canonical: path, Kind: RouteKindCanonical}
}

// AuthForPath describes, for humans reading the generated inventory, which
// authentication gate fronts a canonical path. Derived from the mount points
// in setupRouter; the OpenAPI spec's per-operation security entries are the
// precise machine-readable source.
func AuthForPath(path string) string {
	switch {
	case path == "/api/v1/admin/cross-org-authorization-oracle":
		return "Dedicated cross-org oracle token + private network"
	case strings.HasPrefix(path, "/api/v1/admin"):
		return "Admin token + private network"
	case strings.HasPrefix(path, "/api/v1/explorer"):
		return "Private network only (explorer backend)"
	case strings.HasPrefix(path, "/api/v1/eth"), strings.HasPrefix(path, "/api/v1/me"):
		return "Bearer JWT"
	case strings.HasPrefix(path, "/api/v1/dev"):
		return "None (dev builds only)"
	case strings.HasPrefix(path, "/api/v1/auth"), strings.HasPrefix(path, "/oauth"),
		path == "/api/v1/refresh", path == "/api/v1/revoke", path == "/api/v1/introspect":
		return "Public (rate-limited)"
	case path == "/rpc", strings.HasPrefix(path, "/rpc/"):
		return "Optional Bearer JWT (per-method RBAC)"
	case path == "/health", path == "/openapi.json":
		return "Public"
	case path == "/metrics":
		return "Private network only"
	default:
		return "See spec"
	}
}
