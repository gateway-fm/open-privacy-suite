package server

import (
	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/db"
)

// Compile-time guarantees that the production store (*db.DB) satisfies the
// optional, security-relevant extension interfaces that middleware and access
// control type-assert at runtime (RD-1164 #14).
//
// Both call sites fall OPEN when the assertion fails — the historical-state
// guard allows the query, and OptionalJWTAuthMiddleware skips ban enforcement —
// which is only intended for the minimal mock stores used by test fixtures.
// Anchoring the production type's conformance here turns a dropped or renamed
// method into a build failure, so a security invariant no longer rests solely
// on a runtime type assertion that could silently start failing.
//
// (rbac.OrgAdminChecker's guarantee lives in internal/db, next to IsOrgAdmin;
// auth is not imported by internal/db, so its guard is anchored here in the
// wiring layer instead.)
var _ auth.BannedChecker = (*db.DB)(nil)

// RD-1256: the role-scoped audit handles must keep satisfying every audit
// surface the wiring hands them to. A dropped delegation on db.AuditDB would
// otherwise only surface as a wiring compile error far from the cause (or, for
// the interface-typed paths, at request time).
var (
	_ AccessLogger         = (*db.AuditDB)(nil)
	_ EnhancedAccessLogger = (*db.AuditDB)(nil)
	_ audit.SeedReader     = (*db.AuditDB)(nil)
)
