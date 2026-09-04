// Package middleware holds the request-path middleware and limiters that the
// server mounts on its route groups. Everything here is deliberately free of
// any dependency on the server package or the persistence layer (RD-1265):
// these types are constructed with plain values, so they can be tested and
// reasoned about without a Server, a database, or a config.
//
//   - CorrelationID / GetCorrelationID — per-request correlation ID, extracted
//     from X-Correlation-ID or X-Request-ID and sanitized, else generated.
//   - BodyLimit — request body size cap on a route group (RD-1179). The limit
//     itself is a server policy value and is passed in by the caller.
//   - RateLimiter — per-user requests-per-second and daily quotas.
//   - ConcurrencyLimiter — per-user in-flight request cap, plus a shared bucket
//     for anonymous traffic (RD-1164).
//   - CircuitBreaker — per-API-key cooldown after an upstream 429.
//
// The dependency direction is one-way: server imports middleware, never the
// reverse. internal/archtest enforces that this package stays free of
// privacy-proxy/internal/{server,db,rbac}.
package middleware
