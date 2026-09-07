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

	"gopkg.in/yaml.v3"
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

// skillFrontmatter is the typed shape a SKILL.md header must unmarshal into.
// Parsing into a struct rather than pattern-matching lines is deliberate: a
// header like `description: [unterminated` matches any reasonable regex but is
// not valid YAML, so a regex check would pass a skill that Claude Code refuses
// to load — the precise failure this test exists to catch.
type skillFrontmatter struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
}

// splitFrontmatter returns the YAML block delimited by a leading `---` line and
// the next line that is exactly `---`. Requiring an exact delimiter matters:
// a closing line such as `---garbage` does not end a YAML front matter block,
// so accepting it would again pass a skill that will not load.
func splitFrontmatter(body string) (string, bool) {
	lines := strings.Split(body, "\n")
	if len(lines) == 0 || strings.TrimRight(lines[0], "\r") != "---" {
		return "", false
	}
	for i := 1; i < len(lines); i++ {
		if strings.TrimRight(lines[i], "\r") == "---" {
			return strings.Join(lines[1:i], "\n"), true
		}
	}
	return "", false
}

// TestSkillFrontmatter checks that every skill's header is valid YAML and
// declares a name and a description. Claude Code reads the description to
// decide whether a skill is relevant, so a skill whose header is malformed or
// missing a field silently never fires — a failure mode indistinguishable from
// the skill not existing, and invisible until someone wonders why it never
// triggers.
func TestSkillFrontmatter(t *testing.T) {
	skills := discoverSkills(t)
	if len(skills) == 0 {
		t.Fatal("no skills found under .claude/skills/*/SKILL.md")
	}

	for _, s := range skills {
		t.Run(s.name, func(t *testing.T) {
			block, ok := splitFrontmatter(s.body)
			if !ok {
				t.Fatalf("%s: has no YAML frontmatter delimited by a leading `---` line and a closing line that is exactly `---`; the skill will not load", s.path)
			}

			var front skillFrontmatter
			if err := yaml.Unmarshal([]byte(block), &front); err != nil {
				t.Fatalf("%s: frontmatter is not valid YAML (%v); the skill will not load", s.path, err)
			}

			if strings.TrimSpace(front.Name) == "" {
				t.Errorf("%s: frontmatter has no non-empty `name`; Claude Code needs it to load the skill", s.path)
			} else if strings.TrimSpace(front.Name) != s.name {
				t.Errorf("%s: frontmatter name %q does not match its directory %q", s.path, front.Name, s.name)
			}
			if strings.TrimSpace(front.Description) == "" {
				t.Errorf("%s: frontmatter has no non-empty `description`; without it the skill never matches and so never fires", s.path)
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

// pathRef is a candidate path reference, how strictly it can be checked, and
// what it is relative to.
type pathRef struct {
	tok        string
	exactMatch bool // true: must exist at this exact path; false: basename must exist somewhere
	// fromLink marks a Markdown link target. Those resolve relative to the
	// containing SKILL.md, not the repo root, so they are checked against the
	// skill's own directory — otherwise a perfectly ordinary link such as
	// `references/setup.md` would be reported missing at <repo>/references/setup.md.
	fromLink bool
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
func classifyPathRef(tok string, fromLink bool) (pathRef, bool) {
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
	// A link target is always checked exactly, against the skill's directory:
	// falling back to a basename-anywhere search would let a broken link pass
	// merely because some unrelated file shares its name.
	return pathRef{tok: tok, exactMatch: fromLink || strings.Contains(tok, "/"), fromLink: fromLink}, true
}

// collectReferencedPaths pulls candidate repo path references out of a skill:
// backticked tokens (repo-root relative by convention) plus relative Markdown
// link targets (relative to the skill file, per Markdown semantics).
func collectReferencedPaths(body string) []pathRef {
	seen := map[string]bool{}
	var out []pathRef
	add := func(tok string, fromLink bool) {
		tok = strings.TrimSpace(tok)
		tok = strings.TrimSuffix(tok, ".") // trailing sentence punctuation
		if fromLink {
			// Strip the fragment/query a link may carry: `setup.md#step-2`
			// points at a real file, and the anchor is not part of the path.
			if i := strings.IndexAny(tok, "#?"); i >= 0 {
				tok = tok[:i]
			}
		}
		key := tok
		if fromLink {
			key = "link:" + tok
		}
		if tok == "" || seen[key] || gitignoredByDesign[tok] {
			return
		}
		ref, ok := classifyPathRef(tok, fromLink)
		if !ok {
			return
		}
		seen[key] = true
		out = append(out, ref)
	}
	for _, m := range backticked.FindAllStringSubmatch(body, -1) {
		add(m[1], false)
	}
	for _, m := range markdownLink.FindAllStringSubmatch(body, -1) {
		add(m[1], true)
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
					// Markdown links resolve against the file that contains
					// them; backticked repo paths against the repo root.
					base := root
					kind := "that path"
					if ref.fromLink {
						base = filepath.Dir(s.path)
						kind = "that path relative to the skill"
					}
					if _, err := os.Stat(filepath.Join(base, ref.tok)); err != nil {
						t.Errorf("%s links to %q, which does not exist at %s — the file moved or was renamed; update the skill (or add it to gitignoredByDesign if the operator creates it)", s.path, ref.tok, kind)
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
