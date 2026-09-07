package db

// TEMPORARY CI diagnostic — NOT for merge. Dumps what tern's FindMigrations
// sees in the embedded migrations.FS, with no DB needed. Reveals the phantom
// duplicate 070 that CI reports but local runs do not.
import (
	"io/fs"
	"sort"
	"testing"

	"privacy-proxy/internal/db/migrations"

	"github.com/jackc/tern/v2/migrate"
)

func TestZZDumpMigrations(t *testing.T) {
	var files []string
	fs.WalkDir(migrations.FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			files = append(files, p)
		}
		return nil
	})
	sort.Strings(files)
	for _, f := range files {
		t.Logf("FS file: %s", f)
	}
	t.Logf("FS file count=%d", len(files))

	paths, err := migrate.FindMigrations(migrations.FS)
	if err != nil {
		t.Logf("FindMigrations ERROR: %v", err)
	} else {
		for i, p := range paths {
			t.Logf("migration seq=%d path=%s", i+1, p)
		}
		t.Logf("FindMigrations count=%d", len(paths))
	}
}
