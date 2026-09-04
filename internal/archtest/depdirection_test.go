// Package archtest holds executable architecture gates. Like the OpenAPI
// route↔spec coverage gate, these are plain Go tests: `make test-unit` and the
// CI Go Tests job (`go test ./internal/...`) fail on drift, with no extra CI
// wiring to maintain.
package archtest

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	// Blank-import every package this gate polices. The assertions below run
	// `go list` as a subprocess, whose file reads the Go test cache cannot
	// see — without these imports a cached "ok" would be replayed even after
	// a forbidden import was added. With them, any change to a policed
	// package (or its dependency tree) invalidates the cache and re-runs the
	// gate.
	_ "privacy-proxy/internal/audit"
	_ "privacy-proxy/internal/config"
	_ "privacy-proxy/internal/netguard"
	_ "privacy-proxy/internal/server/middleware"
)

// TestDependencyDirection locks the dependency-direction invariants
// (RD-1255):
//
//   - internal/config must not depend, even transitively, on internal/audit
//     or internal/db. Config is the most widely imported package; the old
//     config→audit→db edge dragged ~744 transitive packages (the entire
//     persistence layer) into every importer of config.
//   - internal/audit must not depend on internal/db. Store implementations
//     over *db.DB belong to the consumer (see the checkpoint store note in
//     audit/checkpoint_worker.go and internal/server/retention_audit_store.go).
//   - internal/server/middleware must not depend on internal/server, db,
//     rbac or config (RD-1265). The middleware was extracted from the server
//     package precisely because it needs none of them; a new edge back would
//     undo the split and re-couple the request-path middleware to the
//     persistence layer. config is in the list because the package doc
//     promises these types are constructed from plain values and so are
//     testable without a config — an invariant the gate has to pin, not just
//     the doc assert.
func TestDependencyDirection(t *testing.T) {
	rules := []struct {
		pkg       string
		forbidden []string
	}{
		{
			pkg:       "privacy-proxy/internal/config",
			forbidden: []string{"privacy-proxy/internal/audit", "privacy-proxy/internal/db"},
		},
		{
			pkg:       "privacy-proxy/internal/audit",
			forbidden: []string{"privacy-proxy/internal/db"},
		},
		{
			pkg: "privacy-proxy/internal/server/middleware",
			forbidden: []string{
				"privacy-proxy/internal/server",
				"privacy-proxy/internal/db",
				"privacy-proxy/internal/rbac",
				"privacy-proxy/internal/config",
			},
		},
	}

	root := moduleRoot(t)
	for _, rule := range rules {
		deps := transitiveDeps(t, root, rule.pkg)
		for _, forbidden := range rule.forbidden {
			if deps[forbidden] {
				t.Errorf("%s must not depend on %s (dependency-direction invariant, RD-1255); "+
					"run `go list -deps %s` to find the import chain",
					rule.pkg, forbidden, rule.pkg)
			}
		}
	}
}

// TestNetguardIsStdlibOnly locks netguard's leaf-package contract: its doc
// promises "importing only the standard library", and packages like config
// rely on that to stay light. Anything non-stdlib in its transitive deps
// (other than netguard itself) fails the gate.
func TestNetguardIsStdlibOnly(t *testing.T) {
	const pkg = "privacy-proxy/internal/netguard"
	root := moduleRoot(t)
	cmd := exec.Command("go", "list", "-deps",
		"-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", pkg)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps %s: %v\n%s", pkg, err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == pkg {
			continue
		}
		t.Errorf("%s must import only the standard library, but transitively depends on %s (RD-1255)", pkg, line)
	}
}

// transitiveDeps returns the transitive (non-test) dependency set of pkg.
func transitiveDeps(t *testing.T, root, pkg string) map[string]bool {
	t.Helper()
	cmd := exec.Command("go", "list", "-deps", pkg)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps %s: %v\n%s", pkg, err, out)
	}
	deps := make(map[string]bool)
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			deps[line] = true
		}
	}
	return deps
}

// moduleRoot locates the repo root via the active go.mod, so the test works
// from any working directory (go test sets CWD to the package dir).
func moduleRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		t.Fatalf("go env GOMOD: %v", err)
	}
	gomod := strings.TrimSpace(string(out))
	if gomod == "" || gomod == "/dev/null" {
		t.Fatal("no active go.mod found")
	}
	return filepath.Dir(gomod)
}
