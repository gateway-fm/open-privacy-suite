package apispec

// Git plumbing for the schema-name gate in schema_names_test.go. Test-only, so
// os/exec stays out of the production dependency set of this package.
//
// The distinction this file exists to keep sharp: "the baseline did not exist at
// the base revision" (a legitimate bootstrap — the gate has nothing to compare
// against) is NOT the same as "git could not answer" (a broken environment).
// Collapsing the two silently disables the gate, which is the failure mode the
// gate itself is about. Absence is therefore established positively with
// ls-tree, and every other git failure is returned as an error to fail on.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// baseLookup is the outcome of reading a file at the base revision.
type baseLookup struct {
	// content of the file at the base revision; empty when absent.
	content string
	// found is true when the path exists in the base revision's tree.
	found bool
}

// inGitWorkTree reports whether the tests are running inside a git work tree.
// Outside one (module cache, source tarball) there is no published history to
// compare against.
func inGitWorkTree() bool {
	out, err := git("rev-parse", "--is-inside-work-tree")
	return err == nil && strings.TrimSpace(out) == "true"
}

// readAtBaseRev returns the contents of a repository path as committed at the
// base revision. pathInPkg is relative to the calling package's directory.
func readAtBaseRev(baseRef, pathInPkg string) (baseLookup, error) {
	rev, err := resolveBaseRev(baseRef)
	if err != nil {
		return baseLookup{}, err
	}

	repoPath, err := repoRelPath(pathInPkg)
	if err != nil {
		return baseLookup{}, err
	}

	// `git show <rev>:<path>` resolves <path> from the repository root, not the
	// working directory, so the repo-relative path is required here — passing the
	// bare filename fails, and treating that failure as "absent" is what silently
	// turned this gate off in an earlier revision of it.
	//
	// ls-tree needs --full-tree to match that same root-relative pathspec: by
	// default it scopes patterns to the working directory, which for `go test`
	// is the package directory, and would report every path as absent.
	listed, err := git("ls-tree", "-r", "--full-tree", "--name-only", rev, "--", repoPath)
	if err != nil {
		return baseLookup{}, fmt.Errorf("git ls-tree %s -- %s: %s", rev, repoPath, gitReason(listed, err))
	}
	if strings.TrimSpace(listed) == "" {
		return baseLookup{found: false}, nil
	}

	content, err := git("show", rev+":"+repoPath)
	if err != nil {
		return baseLookup{}, fmt.Errorf("git show %s:%s: %s", rev, repoPath, gitReason(content, err))
	}
	return baseLookup{content: content, found: true}, nil
}

// repoRelPath converts a path relative to the current directory into one
// relative to the repository root.
func repoRelPath(pathInPkg string) (string, error) {
	out, err := git("rev-parse", "--show-prefix")
	if err != nil {
		return "", fmt.Errorf("git rev-parse --show-prefix: %s", gitReason(out, err))
	}
	return strings.TrimSpace(out) + pathInPkg, nil
}

// resolveBaseRev prefers the merge base, so a branch is judged against the
// surface it forked from rather than whatever the base branch has published
// since; it falls back to the base tip when the merge base is unavailable (a
// shallow clone can hold the ref without holding the common ancestor).
func resolveBaseRev(baseRef string) (string, error) {
	if out, err := git("merge-base", "HEAD", baseRef); err == nil {
		return strings.TrimSpace(out), nil
	}
	out, err := git("rev-parse", "--verify", baseRef)
	if err != nil {
		return "", errors.New(gitReason(out, err))
	}
	return strings.TrimSpace(out), nil
}

// gitLocationEnvVars point git at a specific repository instead of letting it
// discover one from the working directory. `git push` exports GIT_DIR when it
// runs the pre-push hook, and that alone breaks this plumbing: with GIT_DIR set
// git treats the *current* directory as the top of the work tree, so
// `rev-parse --show-prefix` returns empty, the repo-relative path collapses to a
// bare filename, ls-tree reports it absent, and the append-only rule goes
// vacuous. Discovery from the working directory is exactly what is wanted here,
// so these are stripped from the subprocess environment.
var gitLocationEnvVars = []string{
	"GIT_DIR",
	"GIT_WORK_TREE",
	"GIT_COMMON_DIR",
	"GIT_INDEX_FILE",
	"GIT_OBJECT_DIRECTORY",
	"GIT_ALTERNATE_OBJECT_DIRECTORIES",
	"GIT_PREFIX",
	"GIT_NAMESPACE",
}

func git(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Env = withoutGitLocation(os.Environ())
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// withoutGitLocation removes the repository-location variables from an
// environment, leaving everything else untouched.
func withoutGitLocation(env []string) []string {
	kept := make([]string, 0, len(env))
	for _, entry := range env {
		name, _, _ := strings.Cut(entry, "=")
		if slices.Contains(gitLocationEnvVars, name) {
			continue
		}
		kept = append(kept, entry)
	}
	return kept
}

func gitReason(out string, err error) string {
	msg := strings.TrimSpace(out)
	if msg == "" && err != nil {
		msg = err.Error()
	}
	if msg == "" {
		msg = "unknown git failure"
	}
	return msg
}

// TestBaseRevLookupCanReadTheBaseline is a liveness check on the plumbing
// above, using HEAD as a revision that is always resolvable and always has the
// baseline committed. Without it the gate can silently die: an earlier revision
// passed the bare filename to `git show`, which resolves paths from the
// repository root, so the lookup failed, the failure was read as "absent at the
// base revision", and the append-only rule went vacuous while still reporting
// PASS.
func TestBaseRevLookupCanReadTheBaseline(t *testing.T) {
	if !inGitWorkTree() {
		t.Skip("not a git work tree")
	}

	got, err := readAtBaseRev("HEAD", baselinePath)
	if err != nil {
		t.Fatalf("readAtBaseRev(HEAD, %s): %v", baselinePath, err)
	}
	if !got.found {
		t.Fatalf("%s reported absent at HEAD, but it is committed there — the path is not "+
			"being resolved relative to the repository root, so the append-only rule is vacuous", baselinePath)
	}
	if len(parseNameList([]byte(got.content))) == 0 {
		t.Errorf("%s at HEAD parsed to zero names — the append-only rule would be vacuous", baselinePath)
	}
}

// TestBaseRevLookupSurvivesGitHookEnvironment pins a defect that made this gate
// break every `git push` while passing when run on its own. Hooks inherit
// GIT_DIR (and friends) from git, which redefines where the work tree root is;
// the lookup then could not find the baseline it had just committed. Reproducing
// the hook environment is the only way this stays fixed, since the ordinary test
// run does not have these variables set.
func TestBaseRevLookupSurvivesGitHookEnvironment(t *testing.T) {
	if !inGitWorkTree() {
		t.Skip("not a git work tree")
	}

	// The value git itself would export: this worktree's git directory.
	gitDir, err := git("rev-parse", "--absolute-git-dir")
	if err != nil {
		t.Fatalf("git rev-parse --absolute-git-dir: %s", gitReason(gitDir, err))
	}
	for _, name := range []string{"GIT_DIR", "GIT_INDEX_FILE", "GIT_PREFIX"} {
		t.Setenv(name, strings.TrimSpace(gitDir))
	}

	got, err := readAtBaseRev("HEAD", baselinePath)
	if err != nil {
		t.Fatalf("readAtBaseRev(HEAD, %s) under a hook environment: %v", baselinePath, err)
	}
	if !got.found {
		t.Fatalf("%s reported absent at HEAD under a hook environment, but it is "+
			"committed there. The repository-location variables git exports to "+
			"hooks are leaking into the subprocess: %v", baselinePath, gitLocationEnvVars)
	}
	if strings.TrimSpace(got.content) == "" {
		t.Fatal("baseline read as empty under a hook environment")
	}
}

func TestWithoutGitLocation(t *testing.T) {
	in := []string{
		"PATH=/usr/bin",
		"GIT_DIR=/somewhere/.git",
		"GIT_AUTHOR_NAME=keep me",
		"GIT_WORK_TREE=/somewhere",
		"HOME=/home/u",
		"GIT_INDEX_FILE=/somewhere/.git/index",
	}
	want := []string{"PATH=/usr/bin", "GIT_AUTHOR_NAME=keep me", "HOME=/home/u"}

	got := withoutGitLocation(in)
	if !slices.Equal(got, want) {
		t.Errorf("withoutGitLocation() = %q, want %q", got, want)
	}
}
