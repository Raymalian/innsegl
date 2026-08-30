// SPDX-License-Identifier: Apache-2.0

package reconciler_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/reconciler"
)

// The git half of the join, against real repositories. No docker and no
// network: what is under test is which commits a repository holds, and git
// answers that itself.

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=innsegl test", "GIT_AUTHOR_EMAIL=test@innsegl.invalid",
		"GIT_COMMITTER_NAME=innsegl test", "GIT_COMMITTER_EMAIL=test@innsegl.invalid",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// commitInto writes a file, commits it, and returns (commit, tree).
func commitInto(t *testing.T, worktree, name, body, message string) (string, string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(worktree, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	git(t, worktree, "add", name)
	git(t, worktree, "commit", "-q", "-m", message)
	return git(t, worktree, "rev-parse", "HEAD"), git(t, worktree, "rev-parse", "HEAD^{tree}")
}

// newRepo builds <root>/<repo> as a git working tree and returns both paths.
func newRepo(t *testing.T, repo string) (string, string) {
	t.Helper()
	root := t.TempDir()
	worktree := filepath.Join(root, filepath.FromSlash(repo))
	if err := os.MkdirAll(worktree, 0o700); err != nil {
		t.Fatal(err)
	}
	git(t, worktree, "init", "-q", "-b", "main")
	git(t, worktree, "config", "user.name", "innsegl test")
	git(t, worktree, "config", "user.email", "test@innsegl.invalid")
	git(t, worktree, "config", "commit.gpgsign", "false")
	return root, worktree
}

func TestTheGitWorkspaceFindsOnlySignedCommitsHoldingTheIntentsTree(t *testing.T) {
	const repo = "github.com/innsegl/demo"
	root, worktree := newRepo(t, repo)

	// An UNSIGNED commit holding a tree. This is the state a plain `git
	// commit` leaves, and it is the state that would make a repair a
	// fabrication if the signature were not checked.
	unsigned, unsignedTree := commitInto(t, worktree, "a.txt", "one\n", "unsigned")

	// A commit carrying a gpgsig header, planted rather than made: what a real
	// signature looks like to this reader is a header, and a real one is made
	// by a real gitsign in the integration case.
	signed, signedTree := plantSignedCommit(t, worktree, "b.txt", "two\n")

	ws, err := reconciler.NewGitWorkspace(root)
	if err != nil {
		t.Fatalf("NewGitWorkspace: %v", err)
	}
	ctx := context.Background()

	got, err := ws.SignedCommitsWithTree(ctx, repo, signedTree)
	if err != nil {
		t.Fatalf("SignedCommitsWithTree: %v", err)
	}
	if len(got) != 1 || got[0] != signed {
		t.Fatalf("the signed tree resolved to %v, want [%s]", got, signed)
	}

	got, err = ws.SignedCommitsWithTree(ctx, repo, unsignedTree)
	if err != nil {
		t.Fatalf("SignedCommitsWithTree: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("the unsigned commit %s was reported as a candidate: %v", unsigned, got)
	}
}

func TestTheGitWorkspaceFindsACommitNoBranchPointsAt(t *testing.T) {
	const repo = "github.com/innsegl/orphan"
	root, worktree := newRepo(t, repo)
	commitInto(t, worktree, "base.txt", "base\n", "base")
	lost, lostTree := plantSignedCommit(t, worktree, "lost.txt", "lost\n")
	// The commit object survives; nothing points at it any more. A crash
	// between Phase B and Phase C followed by a reset leaves exactly this, and
	// a reader that walked refs would call the signature nonexistent.
	git(t, worktree, "reset", "-q", "--hard", "HEAD~1")

	ws, err := reconciler.NewGitWorkspace(root)
	if err != nil {
		t.Fatalf("NewGitWorkspace: %v", err)
	}
	got, err := ws.SignedCommitsWithTree(context.Background(), repo, lostTree)
	if err != nil {
		t.Fatalf("SignedCommitsWithTree: %v", err)
	}
	if len(got) != 1 || got[0] != lost {
		t.Fatalf("the unreachable commit resolved to %v, want [%s]", got, lost)
	}
}

func TestTheGitWorkspaceRefusesWhatIsNotARepoOrNotATree(t *testing.T) {
	root, _ := newRepo(t, "github.com/innsegl/demo")
	ws, err := reconciler.NewGitWorkspace(root)
	if err != nil {
		t.Fatalf("NewGitWorkspace: %v", err)
	}
	ctx := context.Background()

	for name, tc := range map[string]struct{ repo, tree string }{
		"not a repo grammar": {"../etc", strings.Repeat("a", 40)},
		"escaping segment":   {"github.com/../etc", strings.Repeat("a", 40)},
		"not an object id":   {"github.com/innsegl/demo", "zzzz"},
		"no such repository": {"github.com/innsegl/absent", strings.Repeat("a", 40)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ws.SignedCommitsWithTree(ctx, tc.repo, tc.tree); err == nil {
				t.Fatalf("SignedCommitsWithTree(%q, %q) was accepted", tc.repo, tc.tree)
			}
		})
	}
}

func TestAnEmptyRepositoryHasNoCandidates(t *testing.T) {
	const repo = "github.com/innsegl/empty"
	root, _ := newRepo(t, repo)
	ws, err := reconciler.NewGitWorkspace(root)
	if err != nil {
		t.Fatalf("NewGitWorkspace: %v", err)
	}
	got, err := ws.SignedCommitsWithTree(context.Background(), repo, strings.Repeat("a", 40))
	if err != nil {
		t.Fatalf("SignedCommitsWithTree: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("an empty repository produced candidates %v", got)
	}
}

func TestNewGitWorkspaceRefusesARootItCannotUse(t *testing.T) {
	if _, err := reconciler.NewGitWorkspace(""); err == nil {
		t.Fatal("an empty root was accepted")
	}
	file := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.NewGitWorkspace(file); err == nil {
		t.Fatal("a regular file was accepted as a workspace root")
	}
}

// writeFileAt creates <root>/<rel> as a regular file.
func writeFileAt(t *testing.T, root, rel, body string) error {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(body), 0o600)
}

// writeDirAt creates <root>/<rel> as an empty directory.
func writeDirAt(t *testing.T, root, rel string) error {
	t.Helper()
	return os.MkdirAll(filepath.Join(root, filepath.FromSlash(rel)), 0o700)
}

// plantSignedCommit writes a commit object carrying a `gpgsig` header, using
// git's own plumbing, and moves the branch to it.
//
// The header is what a reader can see without trusting anything: verifying the
// signature is `innsegl verify`'s job (RM-037) and Rekor's, and this reader's
// only use for it is to skip commits nobody ever tried to sign. A REAL gitsign
// signature is put through the same code path by the integration case.
func plantSignedCommit(t *testing.T, worktree, name, body string) (string, string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(worktree, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	git(t, worktree, "add", name)
	tree := git(t, worktree, "write-tree")
	parent := git(t, worktree, "rev-parse", "HEAD")

	raw := "tree " + tree + "\n" +
		"parent " + parent + "\n" +
		"author innsegl test <test@innsegl.invalid> 1756544400 +0000\n" +
		"committer innsegl test <test@innsegl.invalid> 1756544400 +0000\n" +
		"gpgsig -----BEGIN SIGNED MESSAGE-----\n" +
		" MIIBogYJKoZIhvcNAQcCoIIBkzCCAY8CAQExDTALBglghkgBZQMEAgEwCwYJKoZI\n" +
		" -----END SIGNED MESSAGE-----\n" +
		"\n" +
		"a commit that claims to be signed\n"

	cmd := exec.CommandContext(t.Context(), "git",
		"-C", worktree, "hash-object", "-t", "commit", "-w", "--stdin")
	cmd.Stdin = strings.NewReader(raw)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git hash-object: %v: %s", err, out)
	}
	commit := strings.TrimSpace(string(out))
	git(t, worktree, "reset", "-q", "--hard", commit)
	return commit, tree
}
