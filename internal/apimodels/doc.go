// Package apimodels holds the request and response types the published
// OpenAPI document is generated from (RD-1265).
//
// # Why these live in their own package
//
// swag derives each schema key in the published document from the Go package
// that declares the type. While these types lived in internal/server, every
// schema was named internal_server.<Type> — so the *published contract's*
// names were a function of internal package layout, and any refactor that
// moved a handler renamed schemas that generated clients and $ref-keyed
// tooling depend on. `@name` overrides would have decoupled the two, but they
// are not honoured by swag/v2 v2.0.0-rc5 (verified: a deliberately different
// probe name did not change the emitted key).
//
// Keeping the transport types here fixes that at the root. Handlers can now be
// split into feature packages — the remaining steps of RD-1265 — without
// touching the document, because the declaring package no longer moves.
//
// # What belongs here
//
// Types that describe the wire contract: request bodies, response envelopes
// and the spec-only models that mirror gin.H-based responses which have no Go
// type of their own. Handler logic does not belong here, and neither does
// domain logic.
//
// Every type is exported, including the spec-only ones that are never
// constructed at runtime, because a package whose whole purpose is to be
// referenced from elsewhere should not hide its names.
//
// # What this package is deliberately not
//
// It is not a DTO layer. Several types embed domain types directly
// (rbac.Contract, disclosure.Scope, db rows), so this package is not
// dependency-free — it pulls the domain packages those types come from.
// Duplicating them into transport twins with a mapping layer was explicitly
// rejected by the architecture review: single-source-of-truth beats transport
// purity here, and the json:"-" discipline on sensitive fields is enforced by
// review.
//
// The one edge that must never exist is back to internal/server: a handler
// package importing apimodels while apimodels imports server is an import
// cycle. The Go compiler catches it, and internal/archtest pins it explicitly
// for the case where no such import exists yet.
//
// # Annotation references
//
// swaggo resolves an annotation's `apimodels.Type` through the importing
// file's import list, and a reference from a comment is not Go usage — so a
// handler file whose only apimodels references are annotations carries a small
// keeper (`var _ = apimodels.APIError{}`) to hold the import. Removing a
// keeper breaks `make api-spec`, not the build.
//
// # Renaming a type here is a contract change
//
// Because the schema key follows the type name, renaming a type or moving it
// out of this package renames a published schema.
// internal/server/apispec/schema_names_test.go fails on any schema that
// disappears from the document unless it is allowlisted with a reason.
package apimodels
