package db

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

// TestTextArrayRoundTrip pins the bind/scan contract RD-1261 established when
// it dropped the lib/pq array helpers: raw Go slices bind, ScanTextArray
// scans, and the two directions agree with each other and with what lib/pq
// used to produce — in particular for the cases where drivers usually
// disagree (nil vs empty, NULL column, and text-encoding of special
// characters).
func TestTextArrayRoundTrip(t *testing.T) {
	dbURL, cleanup := SetupTestContainer(t)
	defer cleanup()

	database, err := New(dbURL)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer database.Close()
	conn := database.Conn()

	if _, err := conn.Exec(`CREATE TABLE array_roundtrip (id TEXT PRIMARY KEY, vals TEXT[])`); err != nil {
		t.Fatalf("create table: %v", err)
	}

	t.Run("nil binds NULL, empty binds empty array", func(t *testing.T) {
		if _, err := conn.Exec(`INSERT INTO array_roundtrip VALUES ('nil', $1)`, []string(nil)); err != nil {
			t.Fatalf("bind nil: %v", err)
		}
		if _, err := conn.Exec(`INSERT INTO array_roundtrip VALUES ('empty', $1)`, []string{}); err != nil {
			t.Fatalf("bind empty: %v", err)
		}

		var nilIsNull, emptyIsNull bool
		if err := conn.QueryRow(`SELECT vals IS NULL FROM array_roundtrip WHERE id='nil'`).Scan(&nilIsNull); err != nil {
			t.Fatal(err)
		}
		if err := conn.QueryRow(`SELECT vals IS NULL FROM array_roundtrip WHERE id='empty'`).Scan(&emptyIsNull); err != nil {
			t.Fatal(err)
		}
		if !nilIsNull {
			t.Error("a nil slice must store SQL NULL")
		}
		if emptyIsNull {
			t.Error("an empty slice must store an empty array, not NULL")
		}
	})

	t.Run("NULL scans to nil, empty array scans to non-nil empty", func(t *testing.T) {
		var fromNull []string
		if err := conn.QueryRow(`SELECT vals FROM array_roundtrip WHERE id='nil'`).Scan(ScanTextArray(&fromNull)); err != nil {
			t.Fatalf("scan NULL: %v", err)
		}
		if fromNull != nil {
			t.Errorf("NULL column must scan to a nil slice, got %#v", fromNull)
		}

		var fromEmpty []string
		if err := conn.QueryRow(`SELECT vals FROM array_roundtrip WHERE id='empty'`).Scan(ScanTextArray(&fromEmpty)); err != nil {
			t.Fatalf("scan empty: %v", err)
		}
		if fromEmpty == nil {
			t.Error("an empty array must scan to a non-nil empty slice")
		}
		if len(fromEmpty) != 0 {
			t.Errorf("expected length 0, got %#v", fromEmpty)
		}
	})

	t.Run("special characters survive the round trip", func(t *testing.T) {
		// Every element here is a case the Postgres array text format has to
		// quote or escape; a hand-rolled encoder/parser typically breaks on
		// at least one of them.
		want := []string{
			`plain`,
			`a,b`,
			`has "quotes"`,
			`back\slash`,
			`{braces}`,
			``,
			`NULL`,
			`null`,
			`  leading and trailing  `,
			`tab	inside`,
			`unicode ✓ ключ`,
			`0x000000000000000000000000abcdef`,
		}
		if _, err := conn.Exec(`INSERT INTO array_roundtrip VALUES ('tricky', $1)`, want); err != nil {
			t.Fatalf("bind tricky: %v", err)
		}

		var got []string
		if err := conn.QueryRow(`SELECT vals FROM array_roundtrip WHERE id='tricky'`).Scan(ScanTextArray(&got)); err != nil {
			t.Fatalf("scan tricky: %v", err)
		}
		if len(got) != len(want) {
			t.Fatalf("length mismatch: got %d want %d (%#v)", len(got), len(want), got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("element %d: got %q want %q", i, got[i], want[i])
			}
		}
	})

	t.Run("stored value matches a server-built array", func(t *testing.T) {
		// The other subtests write and read through the same pgx array codec,
		// so a defect that mangles encoding and decoding symmetrically would
		// still round-trip cleanly and prove nothing about what is actually
		// stored. This subtest builds the expected array from *scalar*
		// parameters, so PostgreSQL — not the array codec — constructs it, and
		// compares the two server-side. That is an oracle the codec cannot
		// fake in either direction.
		want := []string{
			`plain`,
			`a,b`,
			`has "quotes"`,
			`back\slash`,
			`{braces}`,
			``,
			`NULL`,
			`  spaced  `,
			`tab	inside`,
			`unicode ✓ ключ`,
		}
		if _, err := conn.Exec(`INSERT INTO array_roundtrip VALUES ('oracle', $1)`, want); err != nil {
			t.Fatalf("bind oracle row: %v", err)
		}
		// Own row for the empty case, so this subtest does not depend on an
		// earlier one having run (it must survive `-run` filtering).
		if _, err := conn.Exec(`INSERT INTO array_roundtrip VALUES ('oracle_empty', $1)`, []string{}); err != nil {
			t.Fatalf("bind oracle empty row: %v", err)
		}

		// serverArrayExpr renders ARRAY[$2::text,$3::text,...] and the matching
		// args, so every element crosses the wire as a plain string.
		serverArrayExpr := func(id string, elems []string) (string, []any) {
			placeholders := make([]string, len(elems))
			args := make([]any, 0, len(elems)+1)
			args = append(args, id)
			for i, e := range elems {
				placeholders[i] = fmt.Sprintf("$%d::text", i+2)
				args = append(args, e)
			}
			return "ARRAY[" + strings.Join(placeholders, ",") + "]", args
		}

		expr, args := serverArrayExpr("oracle", want)
		var equal bool
		q := fmt.Sprintf(`SELECT vals = %s FROM array_roundtrip WHERE id = $1`, expr)
		if err := conn.QueryRow(q, args...).Scan(&equal); err != nil {
			t.Fatalf("server-side compare: %v", err)
		}
		if !equal {
			// Surface the stored text so a failure is diagnosable.
			var stored string
			_ = conn.QueryRow(`SELECT vals::text FROM array_roundtrip WHERE id='oracle'`).Scan(&stored)
			t.Errorf("driver-written array differs from the server-built array; stored=%s", stored)
		}

		// Negative control: the oracle has to be able to fail. Comparing the
		// stored array against a deliberately altered expectation must report
		// inequality — otherwise the check above is vacuous.
		mangled := append([]string(nil), want...)
		mangled[3] = `backslash` // drops the backslash that needs escaping
		expr, args = serverArrayExpr("oracle", mangled)
		q = fmt.Sprintf(`SELECT vals = %s FROM array_roundtrip WHERE id = $1`, expr)
		if err := conn.QueryRow(q, args...).Scan(&equal); err != nil {
			t.Fatalf("server-side compare (negative control): %v", err)
		}
		if equal {
			t.Error("negative control passed: the server-side comparison cannot distinguish a wrong array, so the positive assertion proves nothing")
		}

		// The empty array is worth its own server-built comparison, since it
		// is the case where a driver is most likely to emit NULL instead.
		if err := conn.QueryRow(`SELECT vals = ARRAY[]::text[] FROM array_roundtrip WHERE id='oracle_empty'`).Scan(&equal); err != nil {
			t.Fatalf("server-side compare (empty): %v", err)
		}
		if !equal {
			t.Error("an empty slice must store an array equal to ARRAY[]::text[]")
		}
	})

	t.Run("ANY predicate accepts raw slices", func(t *testing.T) {
		var n int
		if err := conn.QueryRow(`SELECT count(*) FROM array_roundtrip WHERE id = ANY($1)`, []string{"nil", "empty", "absent"}).Scan(&n); err != nil {
			t.Fatalf("ANY []string: %v", err)
		}
		if n != 2 {
			t.Errorf("ANY []string matched %d, want 2", n)
		}

		// An empty slice must match nothing rather than error — several
		// callers pass a filter list that can legitimately be empty.
		if err := conn.QueryRow(`SELECT count(*) FROM array_roundtrip WHERE id = ANY($1)`, []string{}).Scan(&n); err != nil {
			t.Fatalf("ANY empty []string: %v", err)
		}
		if n != 0 {
			t.Errorf("ANY empty []string matched %d, want 0", n)
		}

		// int64 slices are used for block-number filters in the explorer.
		if _, err := conn.Exec(`CREATE TABLE array_roundtrip_nums (n BIGINT)`); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Exec(`INSERT INTO array_roundtrip_nums VALUES (1),(2),(3)`); err != nil {
			t.Fatal(err)
		}
		if err := conn.QueryRow(`SELECT count(*) FROM array_roundtrip_nums WHERE n = ANY($1)`, []int64{1, 3, 99}).Scan(&n); err != nil {
			t.Fatalf("ANY []int64: %v", err)
		}
		if n != 2 {
			t.Errorf("ANY []int64 matched %d, want 2", n)
		}
	})
}

// TestScanTextArrayIsRaceFree guards the shared-pgtype-map invariant that
// arrays.go documents: the scan path must not mutate arrayTypeMap. pgx does
// memoize *encode* plans in an unguarded map, so if a future pgx upgrade adds
// the same memoization to the scan path, this test fails under -race instead
// of the proxy silently corrupting RBAC arrays under concurrent load.
func TestScanTextArrayIsRaceFree(t *testing.T) {
	dbURL, cleanup := SetupTestContainer(t)
	defer cleanup()

	database, err := New(dbURL)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer database.Close()
	conn := database.Conn()

	if _, err := conn.Exec(`CREATE TABLE array_race (id INT PRIMARY KEY, vals TEXT[])`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	const rows = 8
	for i := 0; i < rows; i++ {
		if _, err := conn.Exec(`INSERT INTO array_race VALUES ($1, $2)`, i,
			[]string{fmt.Sprintf("a%d", i), fmt.Sprintf("b%d", i)}); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}

	const goroutines = 24
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < rows; i++ {
				var got []string
				if err := conn.QueryRow(`SELECT vals FROM array_race WHERE id=$1`, i).Scan(ScanTextArray(&got)); err != nil {
					errs <- fmt.Errorf("goroutine %d row %d: %w", g, i, err)
					return
				}
				if len(got) != 2 || got[0] != fmt.Sprintf("a%d", i) || got[1] != fmt.Sprintf("b%d", i) {
					errs <- fmt.Errorf("goroutine %d row %d: wrong value %#v", g, i, got)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
