// Package skills holds consistency checks for the committed Claude Code skills
// under .claude/skills/. It has no production code — the skills are Markdown,
// and these tests are what stop them drifting away from the repo they describe.
//
// A skill is a navigator: its value is that its pointers are correct. A moved
// doc or a renamed MCP tool turns it into confident misdirection, and nothing
// else in CI would notice. These checks run in the normal `go test ./...`
// sweep, so they cannot be forgotten the way scripts/verify-*.sh were.
package skills

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// repoRoot resolves the repository root from this package's directory
// (internal/skills), so the tests work regardless of where `go test` is invoked.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolving repo root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repo root %q has no go.mod — the test's assumed layout changed: %v", root, err)
	}
	return root
}

// skillFile is one discovered SKILL.md.
type skillFile struct {
	name string // skill directory name, e.g. "ops"
	path string // absolute path
	body string // full file contents
}

// discoverSkills returns every .claude/skills/*/SKILL.md in the repo.
func discoverSkills(t *testing.T) []skillFile {
	t.Helper()
	root := repoRoot(t)
	matches, err := filepath.Glob(filepath.Join(root, ".claude", "skills", "*", "SKILL.md"))
	if err != nil {
		t.Fatalf("globbing skills: %v", err)
	}
	skills := make([]skillFile, 0, len(matches))
	for _, m := range matches {
		raw, err := os.ReadFile(m)
		if err != nil {
			t.Fatalf("reading %s: %v", m, err)
		}
		skills = append(skills, skillFile{
			name: filepath.Base(filepath.Dir(m)),
			path: m,
			body: string(raw),
		})
	}
	return skills
}

// TestOperatorSkillExists pins the deliverable itself. The other tests in this
// file are properties over whatever skills happen to exist, so without this one
// deleting the operator skill would make them all pass vacuously.
func TestOperatorSkillExists(t *testing.T) {
	for _, s := range discoverSkills(t) {
		if s.name == "ops" {
			return
		}
	}
	t.Fatal(".claude/skills/ops/SKILL.md is missing — the operator skill is what gives a fresh clone the setup knowledge; without it an operator has to be told where to look")
}

var frontmatterField = func(field string) *regexp.Regexp {
	return regexp.MustCompile(`(?m)^` + field + `:[ \t]*(\S.*)$`)
}

// TestSkillFrontmatter checks that every skill declares a name and a
// description. Claude Code reads the description to decide whether a skill is
// relevant, so a skill missing one silently never fires — a failure mode that
// looks exactly like the skill not existing, and is invisible until someone
// wonders why it never triggers.
func TestSkillFrontmatter(t *testing.T) {
	skills := discoverSkills(t)
	if len(skills) == 0 {
		t.Fatal("no skills found under .claude/skills/*/SKILL.md")
	}

	for _, s := range skills {
		t.Run(s.name, func(t *testing.T) {
			if !strings.HasPrefix(s.body, "---\n") {
				t.Fatalf("%s: does not open with a `---` YAML frontmatter block; the skill will not load", s.path)
			}
			end := strings.Index(s.body[4:], "\n---")
			if end < 0 {
				t.Fatalf("%s: frontmatter block is never closed with `---`; the skill will not load", s.path)
			}
			front := s.body[4 : 4+end]

			for _, field := range []string{"name", "description"} {
				m := frontmatterField(field).FindStringSubmatch(front)
				if m == nil || strings.TrimSpace(m[1]) == "" {
					t.Errorf("%s: frontmatter has no non-empty %q; Claude Code needs it to load and match the skill", s.path, field)
					continue
				}
				if field == "name" && strings.TrimSpace(m[1]) != s.name {
					t.Errorf("%s: frontmatter name %q does not match its directory %q", s.path, strings.TrimSpace(m[1]), s.name)
				}
			}
		})
	}
}

var (
	backticked      = regexp.MustCompile("`([^`\n]+)`")
	markdownLink    = regexp.MustCompile(`\[[^\]]*\]\(([^)]+)\)`)
	trackedFileExts = []string{".md", ".mdx", ".go", ".sql", ".sh", ".yml", ".yaml", ".json", ".toml", ".example"}
)

// gitignoredByDesign are paths a skill legitimately names but which do not
// exist in a clean checkout, because the operator creates them. Keep this list
// short and justified — it is an escape hatch, not a dumping ground.
var gitignoredByDesign = map[string]bool{
	".mcp.json":       true, // created by copying .mcp.json.example; gitignored
	".env":            true, // operator-supplied
	".env.quickstart": true, // written by the quickstart script
}

func hasTrackedExt(tok string) bool {
	for _, ext := range trackedFileExts {
		if strings.HasSuffix(tok, ext) {
			return true
		}
	}
	return false
}

// pathRef is a candidate path reference and how strictly it can be checked.
type pathRef struct {
	tok        string
	exactMatch bool // true: must exist at this exact path; false: basename must exist somewhere
}

// classifyPathRef decides whether a token is a checkable repo path reference.
//
// The rules are deliberately conservative, because a skill's prose is full of
// slash-bearing tokens that are not repo paths at all — GitHub repo slugs
// (`gateway-fm/open-privacy-suite`), Docker image names
// (`gatewayfm/privacy-proxy-backend`), docs-site routes (`/docs/rbac`) and glob
// patterns (`internal/config/*.go`). Enforcing those would make the check noise
// rather than a guard.
//
//   - Globs and placeholders are skipped: they name a shape, not a file.
//   - A slash-bearing token is enforced exactly only when it also carries a
//     tracked file extension — that combination is unambiguously a repo file.
//   - A bare filename with a tracked extension is enforced by basename anywhere
//     in the repo. Weaker than an exact path, but it still catches the failure
//     that matters (the file was deleted or renamed) without tripping over
//     workflow files referenced by name rather than full path.
func classifyPathRef(tok string) (pathRef, bool) {
	if tok == "" || strings.ContainsAny(tok, " \t") {
		return pathRef{}, false
	}
	if strings.ContainsAny(tok, "*?<>{}") {
		return pathRef{}, false // glob or placeholder
	}
	if strings.HasPrefix(tok, "/") || strings.HasPrefix(tok, "http://") || strings.HasPrefix(tok, "https://") {
		return pathRef{}, false // docs-site route or external URL
	}
	if !hasTrackedExt(tok) {
		return pathRef{}, false // repo slug, image name, directory — too ambiguous
	}
	return pathRef{tok: tok, exactMatch: strings.Contains(tok, "/")}, true
}

// collectReferencedPaths pulls candidate repo path references out of a skill:
// backticked tokens plus relative markdown link targets.
func collectReferencedPaths(body string) []pathRef {
	seen := map[string]bool{}
	var out []pathRef
	add := func(tok string) {
		tok = strings.TrimSpace(tok)
		tok = strings.TrimSuffix(tok, ".") // trailing sentence punctuation
		if seen[tok] || gitignoredByDesign[tok] {
			return
		}
		ref, ok := classifyPathRef(tok)
		if !ok {
			return
		}
		seen[tok] = true
		out = append(out, ref)
	}
	for _, m := range backticked.FindAllStringSubmatch(body, -1) {
		add(m[1])
	}
	for _, m := range markdownLink.FindAllStringSubmatch(body, -1) {
		add(m[1])
	}
	return out
}

// basenameExists reports whether any file in the repo carries this basename,
// ignoring vendored and VCS directories.
func basenameExists(t *testing.T, root, base string) bool {
	t.Helper()
	found := false
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || found {
			return nil //nolint:nilerr // unreadable subtrees are not a test failure
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == base {
			found = true
		}
		return nil
	})
	return found
}

// TestSkillReferencedPathsExist is the anti-rot check. A navigator skill is
// only worth having if its pointers land; when a doc moves, this fails instead
// of the skill quietly sending the next operator to a file that is gone.
func TestSkillReferencedPathsExist(t *testing.T) {
	root := repoRoot(t)
	for _, s := range discoverSkills(t) {
		t.Run(s.name, func(t *testing.T) {
			for _, ref := range collectReferencedPaths(s.body) {
				if ref.exactMatch {
					if _, err := os.Stat(filepath.Join(root, ref.tok)); err != nil {
						t.Errorf("%s references %q, which does not exist at that path — the file moved or was renamed; update the skill (or add it to gitignoredByDesign if the operator creates it)", s.path, ref.tok)
					}
					continue
				}
				if !basenameExists(t, root, ref.tok) {
					t.Errorf("%s references %q, and no file with that name exists anywhere in the repo — it was deleted or renamed; update the skill (or add it to gitignoredByDesign if the operator creates it)", s.path, ref.tok)
				}
			}
		})
	}
}

// mcpToolNames extracts every tool registered with the MCP server, by reading
// the Name field of each mcp.AddTool call in mcp/*.go. Parsing registrations
// rather than a hand-kept list is the point: a renamed tool changes this set
// automatically, and any skill still naming the old one fails.
func mcpToolNames(t *testing.T) map[string]bool {
	t.Helper()
	root := repoRoot(t)
	files, err := filepath.Glob(filepath.Join(root, "mcp", "*.go"))
	if err != nil {
		t.Fatalf("globbing mcp sources: %v", err)
	}

	nameField := regexp.MustCompile(`^\s*Name:\s*"([^"]+)"`)
	tools := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("reading %s: %v", f, err)
		}
		lines := strings.Split(string(raw), "\n")
		for i, line := range lines {
			if !strings.Contains(line, "mcp.AddTool") {
				continue
			}
			// The Name field follows the AddTool call within a few lines.
			for j := i + 1; j < len(lines) && j <= i+4; j++ {
				if m := nameField.FindStringSubmatch(lines[j]); m != nil {
					tools[m[1]] = true
					break
				}
			}
		}
	}
	if len(tools) == 0 {
		t.Fatal("no MCP tools parsed from mcp/*.go — the registration pattern changed and this check has stopped guarding anything")
	}
	return tools
}

// notMCPTools are snake_case identifiers a skill may legitimately mention that
// are database columns, request fields or config keys rather than MCP tools.
// Kept explicit so a genuinely renamed tool cannot hide behind a broad rule.
var notMCPTools = map[string]bool{
	"allowed_methods":       true, // group_access column
	"is_org_admin":          true, // groups column
	"is_org_readonly_admin": true, // groups column
	"is_system":             true, // groups / organizations column
	"group_access":          true, // table
	"contract_grants":       true, // table
	"org_id":                true, // request/path parameter
	"group_id":              true, // request/path parameter
	"user_id":               true, // request/path parameter
	"expires_at":            true, // request field
	"method_not_found":      true, // wire error text

	// JSON-RPC method names are a separate namespace from MCP tool names.
	// Listed individually rather than excluded by an `eth_` prefix rule,
	// because `eth_address_collisions` really is an MCP tool and a blanket
	// prefix would stop this check noticing if it were renamed.
	"eth_call": true,
}

// snakeIdent matches multi-word snake_case tokens — the shape MCP tool names
// take (list_orgs, set_group_access). Single words are excluded because prose
// legitimately backticks things like `latest` or `admin`.
var snakeIdent = regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)+$`)

// TestSkillMCPToolsExist guards the other half of a navigator's promise: if a
// skill tells an operator to call a tool, that tool has to be there. Tool names
// are the most rename-prone thing a skill can reference, and a wrong one is
// silent — the agent simply reports no such tool.
func TestSkillMCPToolsExist(t *testing.T) {
	tools := mcpToolNames(t)
	for _, s := range discoverSkills(t) {
		t.Run(s.name, func(t *testing.T) {
			for _, m := range backticked.FindAllStringSubmatch(s.body, -1) {
				tok := strings.TrimSpace(m[1])
				if !snakeIdent.MatchString(tok) || notMCPTools[tok] || tools[tok] {
					continue
				}
				t.Errorf("%s references %q, which is not a registered MCP tool (mcp/*.go) — if the tool was renamed, update the skill; if this is a column or request field rather than a tool, add it to notMCPTools", s.path, tok)
			}
		})
	}
}
