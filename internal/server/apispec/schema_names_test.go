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
// # What the gate enforces
//
// schema_names_baseline.txt records the published schema names. Three rules,
// all of which must hold:
//
//   - Every baselined name is still in the document, or is listed in
//     schema_names_allowlist.txt with a reason. Catches an *accidental* rename.
//   - Every name in the document is in the baseline. Additions therefore do
//     NOT pass silently: adding a schema requires recording it, otherwise a
//     later rename of that schema would be undetectable (it would never have
//     been in the baseline to disappear from).
//   - The baseline is append-only with respect to the base revision: a name
//     recorded there must still be recorded here, or be allowlisted. This is
//     the rule that makes the gate un-launderable — see below.
//
// # Why the append-only rule exists
//
// The first two rules compare the document against a baseline that lives in the
// same checkout, so on their own they can be satisfied by renaming a schema and
// editing the baseline to match, with no allowlist entry — skipping precisely
// the deliberate, reviewable step the gate exists to force. The third rule
// reads the baseline as committed at the base revision, which a branch cannot
// rewrite, so dropping a name is what a same-commit baseline edit cannot hide.
// TestLaunderedRenameIsCaught in schema_names_rules_test.go pins that.
//
// # Why names are coupled to package layout at all
//
// swag derives each schema key from the declaring Go package, and `@name`
// overrides are not honoured by swag/v2 v2.0.0-rc5 (verified — a deliberately
// different probe name did not change the emitted key). Keeping the transport
// types in one package (internal/apimodels, RD-1265) is what stops a handler
// refactor from renaming published schemas.
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

	// baseRef is the published branch the baseline must not lose names against.
	baseRef = "origin/main"
)

func TestSchemaNamesHaveNotDrifted(t *testing.T) {
	spec := currentSchemaNames(t)
	baseline := readNameList(t, baselinePath)
	allowed := readNameList(t, allowlistPath)

	for _, name := range missingFromSpec(baseline, spec, allowed) {
		t.Errorf("schema %q disappeared from the published document.\n"+
			"That is a client-visible rename or removal, not a regeneration artifact:\n"+
			"  - if it was renamed on purpose, add the OLD name to %s with a reason and\n"+
			"    refresh %s from the regenerated spec;\n"+
			"  - if you did not intend it, a type was moved between packages — swag names\n"+
			"    schemas after the declaring package, so moving a transport type out of\n"+
			"    internal/apimodels renames its schema.",
			name, allowlistPath, baselinePath)
	}
}

// TestSchemaNameBaselineIsCurrent keeps the baseline honest in the additive
// direction: a new schema must be recorded, otherwise the next rename of it
// would pass unnoticed (it would never have been in the baseline to disappear
// from).
func TestSchemaNameBaselineIsCurrent(t *testing.T) {
	spec := currentSchemaNames(t)
	baseline := readNameList(t, baselinePath)

	if missing := unrecordedAdditions(spec, baseline); len(missing) > 0 {
		t.Errorf("%d schema(s) are in the document but not in %s: %v\n"+
			"Add them so a later rename is detectable.",
			len(missing), baselinePath, missing)
	}
}

// TestSchemaNameBaselineIsAppendOnly is the rule a same-commit baseline edit
// cannot satisfy by itself: it reads the baseline as published at the base
// revision, so a name dropped from the working copy has to be declared in the
// allowlist rather than quietly deleted.
func TestSchemaNameBaselineIsAppendOnly(t *testing.T) {
	if !inGitWorkTree() {
		// Outside a work tree (module cache, source tarball) there is no
		// published history to compare against. Inside one, every git failure
		// below is fatal rather than skipped: a shallow CI checkout that cannot
		// see the base branch would otherwise turn this gate into a silent pass.
		t.Skip("not a git work tree, so there is no base revision to compare the baseline against")
	}

	base, err := readAtBaseRev(baseRef, baselinePath)
	if err != nil {
		t.Fatalf("cannot read %s at %s: %v\n"+
			"This gate needs the base branch in the local history. In CI, check out with\n"+
			"fetch-depth: 0 (a shallow clone has neither the ref nor the common\n"+
			"ancestor); locally, run `git fetch origin main`.",
			baselinePath, baseRef, err)
	}

	// The file not existing at the base revision is the bootstrap case: the
	// commit that introduces the baseline has nothing to be append-only to, and
	// its contents are what review covers. Established positively by ls-tree,
	// never inferred from a git error — see readAtBaseRev.
	baseNames := map[string]bool{}
	if base.found {
		baseNames = parseNameList([]byte(base.content))
	}

	spec := currentSchemaNames(t)
	baseline := readNameList(t, baselinePath)
	allowed := readNameList(t, allowlistPath)

	for _, name := range droppedFromBaseline(baseNames, baseline, allowed) {
		t.Errorf("schema %q is recorded as published at %s but is no longer in %s.\n"+
			"Editing the baseline is not how a name is retired: add it to %s with a\n"+
			"reason, so the client-visible removal is reviewed rather than absorbed\n"+
			"into a regeneration diff.",
			name, baseRef, baselinePath, allowlistPath)
	}

	present, pointless := staleAllowlistEntries(allowed, spec, baseline, baseNames)
	for _, name := range present {
		t.Errorf("allowlist entry %q names a schema that is present again — remove the entry from %s",
			name, allowlistPath)
	}
	for _, name := range pointless {
		t.Errorf("allowlist entry %q was never published — absent from %s both here and at %s — so it guards nothing; remove it from %s",
			name, baselinePath, baseRef, allowlistPath)
	}
}

// missingFromSpec returns baselined names the document no longer publishes and
// which no allowlist entry accounts for.
func missingFromSpec(baseline, spec, allowed map[string]bool) []string {
	var out []string
	for name := range baseline {
		if spec[name] || allowed[name] {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// droppedFromBaseline returns names recorded at the base revision that the
// working baseline no longer records and which no allowlist entry accounts for.
func droppedFromBaseline(base, baseline, allowed map[string]bool) []string {
	var out []string
	for name := range base {
		if baseline[name] || allowed[name] {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// unrecordedAdditions returns document names absent from the baseline.
func unrecordedAdditions(spec, baseline map[string]bool) []string {
	var out []string
	for name := range spec {
		if !baseline[name] {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// staleAllowlistEntries splits dead allowlist entries into those whose schema
// is published again and those that never guarded anything. Either kind would
// let a future real rename hide behind a pre-existing entry.
//
// An entry legitimately names something absent from the working baseline — that
// is what retiring a name looks like — so "guards nothing" means the name is in
// neither the working baseline nor the base revision's.
func staleAllowlistEntries(allowed, spec, baseline, base map[string]bool) (present, pointless []string) {
	for name := range allowed {
		switch {
		case spec[name]:
			present = append(present, name)
		case !baseline[name] && !base[name]:
			pointless = append(pointless, name)
		}
	}
	sort.Strings(present)
	sort.Strings(pointless)
	return present, pointless
}

func currentSchemaNames(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("read %s: %v", specPath, err)
	}
	return parseSchemaNames(t, specPath, raw)
}

func parseSchemaNames(t *testing.T, source string, raw []byte) map[string]bool {
	t.Helper()
	var doc struct {
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", source, err)
	}
	if len(doc.Components.Schemas) == 0 {
		t.Fatalf("%s declares no component schemas — the gate would pass vacuously", source)
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
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) && path == allowlistPath {
			return map[string]bool{}
		}
		t.Fatalf("read %s: %v", path, err)
	}
	return parseNameList(raw)
}

func parseNameList(raw []byte) map[string]bool {
	out := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
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
	return out
}
