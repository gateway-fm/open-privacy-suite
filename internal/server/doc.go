// Package server hosts the HTTP surface: the JSON-RPC proxy hot path, the
// auth and OAuth flows, the admin REST API, the explorer API, and the wiring
// that assembles them (New / NewWithVerifier, both package-level) plus the
// background workers they depend on.
//
// The package is large, so this map exists to get you to the right file
// without grepping. It lists families, not every file; `Server` methods are
// spread across the handler files and the route table lives in server.go.
//
// Wiring and lifecycle
//   - server.go — Server struct, NewWithVerifier (construction + worker
//     startup), Stop (ordered shutdown), setupRouter and the route table,
//     shared request-size policy (MaxRequestBodySize), status endpoint.
//   - interfaces.go, interface_guards.go — consumer-owned interfaces for the
//     stores and limiters, plus the compile-time `var _` guards that turn a
//     fail-open type assertion into a build failure.
//
// JSON-RPC hot path
//   - jsonrpc_processor.go — JSONRPCProcessor and Process, the per-request
//     pipeline (access check, concurrency gate, compliance, visibleTo,
//     circuit breaker, forward, response filter, audit).
//   - jsonrpc_trace.go — trace-based validation for eth_call / debug_trace*.
//   - response_filter.go, rpc_log_field_redaction.go, event_log_filter.go,
//     processor_event_rules.go — response-side filtering and redaction.
//
// Request-path middleware
//   - internal/server/middleware — correlation ID, body limit, rate limiter,
//     concurrency limiter, circuit breaker. Deliberately free of any
//     dependency on this package (see that package's doc and the gate in
//     internal/archtest).
//   - auth_ratelimit.go — IP-based limiter for the auth endpoints, which is
//     still here because it is specific to those routes.
//
// Auth and identity
//   - auth.go, auth_prod.go, auth_dev*.go — ZK login flows; the dev/mockauth
//     variants are build-tag gated (see token_ttl_dev.go).
//   - auth_azure.go, oauth.go — Azure AD and the OAuth2 provider surface.
//   - eth_link.go — linking Ethereum addresses to a DID.
//   - impersonation.go — tier-2 admin acting as a user.
//
// Admin REST API
//   - admin_rbac*.go — orgs, groups, users, contracts, claims, sessions,
//     Azure tenants, audit views.
//   - admin_scope.go — org scoping for admin routes; admin_system.go —
//     runtime toggles; admin_compliance.go — travel-rule config;
//     admin_dry_run.go — access simulation; admin_audit.go — audit queries.
//
// Explorer API
//   - explorer_api.go — the handlers; explorer_*_resolver.go — the optional
//     resolvers wired into the redaction engine (unwired ⇒ fail-closed);
//     explorer_grants.go, explorer_log_redact.go.
//
// Disclosure
//   - disclosure.go, disclosure_audit_store.go.
//
// OpenAPI
//   - openapi_*.go — swaggo annotation carriers and shared response models;
//     the spec is generated from them (see the REST API Spec section of
//     CLAUDE.md). openapi_routes.go builds a router for the coverage gate.
//
// Background workers
//   - visibility_reconciler.go — the pending-visibility outbox reconciler.
//     Audit sealer, checkpoint and integrity workers live in internal/audit
//     and are started from server.go.
package server
