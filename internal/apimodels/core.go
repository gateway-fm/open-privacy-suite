package apimodels

// Spec-only request/response mirror structs for the CORE server handlers
// (RD-1166): the proxied JSON-RPC endpoint, the /api/v1/me/* profile
// endpoints, and the /api/v1/admin ops endpoints (access logs, status,
// test-request).
//
// These types exist ONLY so the swaggo (@Param / @Success / @Failure)
// annotations on handlers that read a raw body or respond with a gin.H /
// anonymous-map shape have a concrete Go type to point at. They are NEVER
// constructed at runtime — annotation references only — and must stay
// byte-for-byte faithful to the wire shape the handler emits or accepts
// (same JSON keys, same element types).
//
// This file must compile standalone with the imports the package already
// has; it introduces no new third-party imports. Element types are
// referenced from their real definitions (internal/db, and same-package
// types such as UserOrgResponse) so the documented shape can never silently
// drift from them. Handlers that already respond with a named exported Go
// struct (StatusResponse, TestRequestResponse, …) reference that struct
// directly and need no mirror here.

import (
	"privacy-proxy/internal/db"
)

// --- JSON-RPC envelope (POST /rpc, POST /rpc/{org_id}) ---------------------
//
// The proxy forwards standard Ethereum JSON-RPC. The runtime request path
// reads the body via ParseAndValidateBody (single object only — batch arrays
// are rejected), so there is no runtime struct that carries the on-the-wire
// request shape including the RD-1163 top-level `visibleTo`/`privateFor`
// extension; these mirrors document it.

// JSONRPCRequestEnvelope is the request body of POST /rpc and
// POST /rpc/{org_id}: a single JSON-RPC 2.0 request object. Batch requests
// (a top-level JSON array) are rejected with 400.
//
// For the transaction-sending methods (eth_sendTransaction /
// eth_sendRawTransaction) the object may additionally carry a top-level
// `visibleTo` array (alias: `privateFor`) of viewer identifiers — DIDs
// and/or linked ETH addresses — granting those viewers per-transaction
// visibility of the resulting event logs (RD-1163). It is accepted only for
// contract calls that emit logs (rejected for simple value transfers) and is
// capped in length.
type JSONRPCRequestEnvelope struct {
	// JSONRPC is the protocol version; always "2.0".
	JSONRPC string `json:"jsonrpc" example:"2.0"`
	// ID is the client-chosen request id echoed back on the response. May be a
	// string, a number, or null per the JSON-RPC spec.
	ID interface{} `json:"id" swaggertype:"primitive,integer" example:"1"`
	// Method is the JSON-RPC method name (e.g. eth_blockNumber, eth_call,
	// eth_sendTransaction). Anonymous callers are limited to the anonymous
	// method allowlist.
	Method string `json:"method" example:"eth_blockNumber"`
	// Params are the positional method parameters. Shape is method-specific.
	Params []interface{} `json:"params"`
	// VisibleTo is the optional RD-1163 per-transaction visibility list (DIDs
	// and/or linked ETH addresses). Only meaningful for log-emitting contract
	// sends. Alias: privateFor.
	VisibleTo []string `json:"visibleTo,omitempty" example:"did:example:alice,0x0000000000000000000000000000000000000001"`
	// PrivateFor is an accepted alias for VisibleTo (union of both is applied).
	PrivateFor []string `json:"privateFor,omitempty"`
}

// JSONRPCError is the error member of a JSON-RPC 2.0 response. Present on
// JSON-RPC-level failures returned by the upstream node (the HTTP status is
// still 200 in that case).
type JSONRPCError struct {
	Code    int    `json:"code" example:"-32601"`
	Message string `json:"message" example:"method not found"`
}

// JSONRPCResponseEnvelope is the response body of POST /rpc and
// POST /rpc/{org_id}: a single JSON-RPC 2.0 response object. Exactly one of
// result / error is populated. A JSON-RPC-level error (e.g. bad params, node
// error) is still returned with HTTP 200 and carries the error member; the
// non-200 HTTP statuses are reserved for transport / access / rate-limit
// failures that never reach the node (see the handler's @Failure list).
//
// On success, result may be redacted for authenticated callers per the
// per-method response-filtering rules.
type JSONRPCResponseEnvelope struct {
	// JSONRPC is the protocol version; always "2.0".
	JSONRPC string `json:"jsonrpc" example:"2.0"`
	// ID echoes the request id.
	ID interface{} `json:"id" swaggertype:"primitive,integer" example:"1"`
	// Result is the method result on success. Shape is method-specific;
	// omitted when error is set.
	Result interface{} `json:"result,omitempty"`
	// Error is set on a JSON-RPC-level failure; omitted on success.
	Error *JSONRPCError `json:"error,omitempty"`
}

// --- /api/v1/me/* (Profile) -----------------------------------------------

// MyOrganizationsResponse is the GET /api/v1/me/orgs body: the organizations
// the authenticated user belongs to, de-duplicated across memberships.
// Emitted via gin.H{"organizations": [...]}.
type MyOrganizationsResponse struct {
	Organizations []UserOrgResponse `json:"organizations"`
}

// MyAdminStatusResponse is the GET /api/v1/me/admin-status body: whether the
// authenticated user has org-admin (tier-2) or read-only-admin privileges,
// and in which organizations. Contract admins (tier-3, "admin" claim only)
// get is_admin=false — they have no admin-dashboard access. Emitted via
// gin.H. On the normal path admin_org_ids / readonly_admin_org_ids are
// always present as arrays (never null); the degenerate "user not in DB yet"
// path returns only {is_admin:false, admin_org_ids:[]}.
type MyAdminStatusResponse struct {
	IsAdmin             bool     `json:"is_admin" example:"true"`
	AdminOrgIDs         []string `json:"admin_org_ids"`
	IsReadonlyAdmin     bool     `json:"is_readonly_admin" example:"false"`
	ReadonlyAdminOrgIDs []string `json:"readonly_admin_org_ids"`
}

// --- /api/v1/admin/logs (Admin: ops) --------------------------------------

// AdminLogsResponse is the GET /api/v1/admin/logs body: a page of access-log
// rows plus the pagination echo. Emitted via
// gin.H{"data","total","limit","offset"}. total is -1 when the count query
// failed (UI falls back to "load more"). Rows are org-scoped for tier-2 admin
// JWTs; the super-admin token sees fleet-wide rows.
type AdminLogsResponse struct {
	Data   []*db.AccessLog `json:"data"`
	Total  int             `json:"total" example:"1"`
	Limit  int             `json:"limit" example:"100"`
	Offset int             `json:"offset" example:"0"`
}
