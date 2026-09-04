// Postgres array binding and scanning (RD-1261).
//
// Every array column in this schema is TEXT[]. There is exactly ONE way to do
// each direction:
//
//   - BIND: pass the Go slice directly — `[]string{...}`, `[]int64{...}`.
//     The pgx stdlib driver implements driver.NamedValueChecker, so it encodes
//     Go slices itself instead of going through database/sql's restrictive
//     default converter. This covers both `= ANY($1)` predicates and writes
//     into TEXT[] columns. Do NOT wrap arguments in a helper.
//
//   - SCAN: wrap the destination in ScanTextArray(&dst). The driver hands
//     TEXT[] back to database/sql as the Postgres *text representation*
//     (`{a,b}`), which database/sql cannot assign to a *[]string, so the value
//     needs a scanner that understands the array grammar.
//
// Both directions produce the same SQL *values* as the lib/pq helpers they
// replaced — not the same bytes on the wire: pgx's ArrayCodec prefers the
// binary format for arrays, where lib/pq's helper sent a text value. What is
// equivalent is the stored array and everything observable from SQL, including
// the two cases that usually diverge between drivers: a nil slice stores SQL
// NULL while an empty slice stores an empty array, and a NULL column scans
// back to a nil slice while an empty array scans to a non-nil empty slice.
// TestTextArrayRoundTrip pins all of it against a real database, and compares
// the driver-written column against an array PostgreSQL builds from scalar
// parameters so the assertion does not depend on the codec it is testing.
package db

import (
	"database/sql"

	"github.com/jackc/pgx/v5/pgtype"
)

// arrayTypeMap decodes Postgres array text into Go slices.
//
// Concurrency: a *pgtype.Map is not generally safe for concurrent use — it
// memoizes *encode* plans in an unguarded map, and TypeForValue lazily builds
// its reflect-type index on first call. The scan path used here
// (SQLScanner -> Map.Scan -> planScan) only reads, and the lazy index is built
// once in init() below, before any request can reach it. That makes this
// instance safe to share, but it is an invariant of pgx's internals rather
// than a documented guarantee, so TestScanTextArrayIsRaceFree hammers it under
// -race: if a pgx upgrade starts memoizing scan plans, that test fails instead
// of the proxy corrupting RBAC data under load.
var arrayTypeMap = pgtype.NewMap()

func init() {
	// Force the lazy reflectTypeToType build (and prove the type is known)
	// while still single-threaded.
	var warm []string
	if _, ok := arrayTypeMap.TypeForValue(&warm); !ok {
		panic("db: pgtype map has no registered type for *[]string; array scanning would fail at runtime")
	}
}

// ScanTextArray returns a sql.Scanner that decodes a TEXT[] column into dst.
//
// A NULL column leaves dst nil; an empty array yields a non-nil empty slice.
// Use it as a Scan destination: rows.Scan(&id, ScanTextArray(&claims)).
func ScanTextArray(dst *[]string) sql.Scanner {
	return arrayTypeMap.SQLScanner(dst)
}
