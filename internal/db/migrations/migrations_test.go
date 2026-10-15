package migrations

import (
	"fmt"
	"io/fs"
	"testing"
)

// Tern versions migrations by sorted position. Reusing a number can silently
// change which SQL runs when an existing database advances from that version.
func TestMigrationSequence(t *testing.T) {
	names, err := fs.Glob(FS, "*.sql")
	if err != nil {
		t.Fatal(err)
	}
	for i, name := range names {
		var number int
		if _, err := fmt.Sscanf(name, "%d_", &number); err != nil || number != i+1 {
			t.Fatalf("migration %s occupies version %d; numbers must be unique and contiguous", name, i+1)
		}
	}
}
