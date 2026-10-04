// SPDX-License-Identifier: Apache-2.0

package reconciler_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/reconciler"
)

// The reconciler reads repositories from the core's mirror (ADR-0065 decision
// 1), not from a working tree on the core's disk. The mirror is
// <root>/<host>/<org>/<name>.git, a bare repository a client pushes to.
//
// One rule is different from a working tree, and it is the one that matters
// for I4: a client pushes a commit's objects BEFORE it is signed, and pushes
// the signed commit later, if at all. A mirror that lacks a signed commit has
// therefore not shown that the commit was never signed. So the mirror never
// answers "no signed commit holds this tree" — it answers "could not tell",
// and the intent stays open rather than being expired by a record that cannot
// be taken back.

// mirrorOf pushes worktree's object database into a bare mirror of repo under
// a new root, the layout internal/mirror keeps, and returns the root.
func mirrorOf(t *testing.T, repo, worktree string, refs ...string) string {
	t.Helper()
	root := t.TempDir()
	bare := filepath.Join(root, filepath.FromSlash(repo)+".git")
	if err := os.MkdirAll(filepath.Dir(bare), 0o700); err != nil {
		t.Fatal(err)
	}
	git(t, root, "init", "-q", "--bare", bare)
	for _, ref := range refs {
		git(t, worktree, "push", "-q", "--no-verify", bare, ref)
	}
	return root
}

func TestTheMirrorFindsASignedCommitAClientPushed(t *testing.T) {
	const repo = "github.com/innsegl/demo"
	_, worktree := newRepo(t, repo)
	commitInto(t, worktree, "a.txt", "one\n", "base")
	signed, signedTree := plantSignedCommit(t, worktree, "b.txt", "two\n")
	root := mirrorOf(t, repo, worktree, "main:refs/heads/main")

	repos, err := reconciler.NewMirrorRepos(root)
	if err != nil {
		t.Fatalf("NewMirrorRepos: %v", err)
	}
	got, err := repos.SignedCommitsWithTree(context.Background(), repo, signedTree)
	if err != nil {
		t.Fatalf("SignedCommitsWithTree: %v", err)
	}
	if len(got) != 1 || got[0] != signed {
		t.Fatalf("the signed tree resolved to %v, want [%s]", got, signed)
	}
	// The rebase pass walks a branch the mirror holds.
	commits, err := repos.CommitsOnBranch(context.Background(), repo, "main")
	if err != nil || len(commits) != 2 {
		t.Fatalf("CommitsOnBranch = %v %v, want the two commits on main", commits, err)
	}
	blobs, err := repos.TreeBlobs(context.Background(), repo, signedTree)
	if err != nil || len(blobs) != 2 {
		t.Fatalf("TreeBlobs = %v %v, want two blobs", blobs, err)
	}
	reach, err := repos.ReachableBlobs(context.Background(), repo)
	if err != nil {
		t.Fatalf("ReachableBlobs: %v", err)
	}
	for blob := range blobs {
		if _, ok := reach[blob]; !ok {
			t.Errorf("ReachableBlobs lacks %s, which the signed tree on main holds", blob)
		}
	}
}

func TestTheMirrorNeverSaysASignatureIsAbsent(t *testing.T) {
	const repo = "github.com/innsegl/demo"
	_, worktree := newRepo(t, repo)
	// The client pushed the change's objects (an unsigned commit holding the
	// tree, as the commit path stages it) and never pushed the signed commit.
	_, stagedTree := commitInto(t, worktree, "a.txt", "one\n", "staged")
	root := mirrorOf(t, repo, worktree, "main:refs/innsegl/staging/x")

	repos, err := reconciler.NewMirrorRepos(root)
	if err != nil {
		t.Fatalf("NewMirrorRepos: %v", err)
	}
	got, err := repos.SignedCommitsWithTree(context.Background(), repo, stagedTree)
	if err == nil {
		t.Fatalf("SignedCommitsWithTree answered %v with no error; a mirror that lacks the "+
			"signed commit has not shown it was never signed", got)
	}
	if !strings.Contains(err.Error(), "mirror") {
		t.Errorf("the error does not say the mirror lacks it: %v", err)
	}

	// A repository no client has pushed is unknown in the same way.
	if _, err := repos.SignedCommitsWithTree(context.Background(), "github.com/innsegl/absent",
		strings.Repeat("a", 40)); err == nil {
		t.Fatal("a repository the mirror does not hold answered with no error")
	}
	// And a name doc 02 §5 does not admit is never a path.
	if _, err := repos.SignedCommitsWithTree(context.Background(), "../etc", stagedTree); err == nil {
		t.Fatal("a malformed repository was accepted")
	}
}

// A commit's landing is a question about a branch the developer moves; the
// mirror holds no such branch, so it is never asked. Every landing finding is
// "not checked" rather than a false "not landed".
func TestTheMirrorDoesNotAnswerWhetherACommitLanded(t *testing.T) {
	root := t.TempDir()
	repos, err := reconciler.NewMirrorRepos(root)
	if err != nil {
		t.Fatalf("NewMirrorRepos: %v", err)
	}
	if _, ok := any(repos).(interface {
		CommitReachable(context.Context, string, string) (bool, error)
	}); ok {
		t.Fatal("the mirror reader offers a reachability check; landing would read its refs as the developer's")
	}
}

func TestNewMirrorReposRefusesARootItCannotUse(t *testing.T) {
	if _, err := reconciler.NewMirrorRepos(""); err == nil {
		t.Fatal("an empty root was accepted")
	}
	if _, err := reconciler.NewMirrorRepos(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("a missing root was accepted")
	}
}
