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
	"os/exec"
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

func git(args ...string) (string, error) {
	out, err := exec.Command("git", args...).CombinedOutput()
	return string(out), err
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
