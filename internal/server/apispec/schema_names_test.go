// Package apispec holds the generated OpenAPI document plus the gates that
// protect it. This file guards the one kind of drift the generic
// regenerate-and-diff CI check cannot distinguish: a *client-visible rename*.
//
// `make api-spec` + the CI drift gate fail on ANY change to the document, which
// is what you want for catching an un-regenerated spec — but it treats adding
// an endpoint and renaming every schema as the same event, and the fix in both
// cases is "commit the regenerated file". Schema component names propagate into
// generated clients and into anything keyed on $ref strings, so removing or
// renaming one is a contract decision, not a regeneration artifact.
//
// This gate therefore compares the committed document against a baseline list
// of schema names. Additions pass silently. Removals and renames fail unless
// listed in schema_names_allowlist.txt with a reason, which forces the change
// to be deliberate and reviewable.
//
// Why names are coupled to package layout at all: swag derives each schema key
// from the declaring Go package, and `@name` overrides are not honoured by
// swag/v2 v2.0.0-rc5 (verified — a deliberately different probe name did not
// change the emitted key). Keeping the transport types in one package
// (internal/apimodels, RD-1265) is what stops a handler refactor from
// renaming published schemas.
package apispec

import (
	"bufio"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"
)

const (
	specPath      = "swagger.json"
	baselinePath  = "schema_names_baseline.txt"
	allowlistPath = "schema_names_allowlist.txt"
)

func TestSchemaNamesHaveNotDrifted(t *testing.T) {
	current := currentSchemaNames(t)
	baseline := readNameList(t, baselinePath)
	allowed := readNameList(t, allowlistPath)

	for name := range baseline {
		if current[name] {
			continue
		}
		if allowed[name] {
			continue
		}
		t.Errorf("schema %q disappeared from the published document.\n"+
			"That is a client-visible rename or removal, not a regeneration artifact:\n"+
			"  - if it was renamed on purpose, add the OLD name to %s with a reason and\n"+
			"    refresh %s from the regenerated spec;\n"+
			"  - if you did not intend it, a type was moved between packages — swag names\n"+
			"    schemas after the declaring package, so moving a transport type out of\n"+
			"    internal/apimodels renames its schema.",
			name, allowlistPath, baselinePath)
	}

	// A stale allowlist entry is itself drift: it means a name came back, or the
	// entry was never needed. Keeping it would let a future real rename hide.
	for name := range allowed {
		if current[name] {
			t.Errorf("allowlist entry %q names a schema that is present again — remove the entry from %s",
				name, allowlistPath)
		}
		if !baseline[name] {
			t.Errorf("allowlist entry %q is not in the baseline, so it guards nothing — remove it from %s",
				name, allowlistPath)
		}
	}
}

// TestSchemaNameBaselineIsCurrent keeps the baseline honest in the additive
// direction: a new schema must be recorded, otherwise the next rename of it
// would pass unnoticed (it would never have been in the baseline to disappear
// from).
func TestSchemaNameBaselineIsCurrent(t *testing.T) {
	current := currentSchemaNames(t)
	baseline := readNameList(t, baselinePath)

	var missing []string
	for name := range current {
		if !baseline[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d schema(s) are in the document but not in %s: %v\n"+
			"Add them so a later rename is detectable.",
			len(missing), baselinePath, missing)
	}
}

func currentSchemaNames(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("read %s: %v", specPath, err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}
	if len(doc.Components.Schemas) == 0 {
		t.Fatalf("%s declares no component schemas — the gate would pass vacuously", specPath)
	}
	out := make(map[string]bool, len(doc.Components.Schemas))
	for name := range doc.Components.Schemas {
		out[name] = true
	}
	return out
}

// readNameList reads one name per line; blank lines and `#` comments ignored.
// A missing allowlist is normal (nothing renamed yet); a missing baseline is not.
func readNameList(t *testing.T, path string) map[string]bool {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) && path == allowlistPath {
			return map[string]bool{}
		}
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	out := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Allow "name  # reason" so an allowlist entry carries its rationale.
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		out[line] = true
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return out
}
