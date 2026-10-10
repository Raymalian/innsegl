// SPDX-License-Identifier: Apache-2.0

package mirror

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/commitpath"
)

// The refs a client pushes besides staging (ADR-0065 decision 2 and 3):
// its branches after a signed commit and at session end (#465, SNAP-006),
// and its workspace snapshots (#467, SNAP-007). The mirror is evidence: a
// branch only moves forward, a snapshot ref is written once, and nothing is
// deleted.

// tAdvance makes a new commit on the client's branch and answers it.
func tAdvance(t *testing.T, dir, name string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(name+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tGit(t, dir, "add", name)
	tGit(t, dir, "-c", "commit.gpgsign=false", "commit", "-q", "-m", name)
	return tGit(t, dir, "rev-parse", "HEAD")
}

// SNAP-006: a branch reaches the mirror and moves only forward.
func TestSNAP006ABranchReachesTheMirrorAndOnlyMovesForward(t *testing.T) {
	store := newStore(t)
	srv := served(t, store, tInstallation, scope{tInstallation, tRepo, nil}, 0)
	dir, _, _ := clientRepo(t)
	first := tAdvance(t, dir, "one.txt")
	url := remoteURL(srv, tRepo)

	if out, err := tGitErr(t, dir, "push", "--no-verify", url, first+":refs/heads/main"); err != nil {
		t.Fatalf("a branch push was refused: %v: %s", err, out)
	}
	if got, ok := refIn(t, store, "refs/heads/main"); !ok || got != first {
		t.Fatalf("mirror's main = %q (present %v), want %s", got, ok, first)
	}

	second := tAdvance(t, dir, "two.txt")
	if out, err := tGitErr(t, dir, "push", "--no-verify", url, second+":refs/heads/main"); err != nil {
		t.Fatalf("a fast-forward was refused: %v: %s", err, out)
	}

	// A rewritten branch does not replace what the mirror holds, even forced.
	tGit(t, dir, "reset", "-q", "--hard", first)
	rewritten := tAdvance(t, dir, "other.txt")
	if out, err := tGitErr(t, dir, "push", "--no-verify", url, "+"+rewritten+":refs/heads/main"); err == nil {
		t.Fatalf("a forced non-fast-forward was accepted: %s", out)
	}
	if got, _ := refIn(t, store, "refs/heads/main"); got != second {
		t.Fatalf("mirror's main = %s after a refused rewrite, want %s", got, second)
	}

	// No branch is deleted.
	if out, err := tGitErr(t, dir, "push", "--no-verify", url, ":refs/heads/main"); err == nil || !strings.Contains(out, "403") {
		t.Fatalf("a branch delete was not refused with the endpoint's 403: %v: %s", err, out)
	}
}

// SNAP-006: a staging ref is moved by force on purpose, so it never shares a
// push with a branch, whose rule is fast-forward only.
func TestSNAP006AStagingRefNeverSharesAPushWithABranch(t *testing.T) {
	store := newStore(t)
	srv := served(t, store, tInstallation, scope{tInstallation, tRepo, nil}, 0)
	dir, commit, _ := clientRepo(t)
	head := tGit(t, dir, "rev-parse", "HEAD")
	out, err := tGitErr(t, dir, "push", "--no-verify", remoteURL(srv, tRepo),
		"+"+commit+":"+commitpath.StagingRef(tInstallation, tToolUseID), head+":refs/heads/main")
	if err == nil || !strings.Contains(out, "403") {
		t.Fatalf("a push mixing staging and a branch was not refused with 403: %v: %s", err, out)
	}
	if _, ok := refIn(t, store, "refs/heads/main"); ok {
		t.Fatal("the branch was written by a refused push")
	}
}

// SNAP-007: a snapshot ref is the installation's own, named by the tool
// call, and written once.
func TestSNAP007ASnapshotRefIsWrittenOnceAndNeverMoved(t *testing.T) {
	store := newStore(t)
	srv := served(t, store, tInstallation, scope{tInstallation, tRepo, nil}, 0)
	dir, commit, tree := clientRepo(t)
	ref := commitpath.SnapshotRef(tInstallation, tToolUseID)
	url := remoteURL(srv, tRepo)

	if out, err := tGitErr(t, dir, "push", "--no-verify", url, commit+":"+ref); err != nil {
		t.Fatalf("a snapshot push was refused: %v: %s", err, out)
	}
	got, ok, err := store.SnapshotTree(t.Context(), tRepo, tInstallation, tToolUseID)
	if err != nil || !ok || got != tree {
		t.Fatalf("SnapshotTree = %q %v %v, want %s", got, ok, err, tree)
	}

	other := tAdvance(t, dir, "later.txt")
	if out, err := tGitErr(t, dir, "push", "--no-verify", url, "+"+other+":"+ref); err == nil || !strings.Contains(out, "403") {
		t.Fatalf("moving a snapshot ref was not refused with 403: %v: %s", err, out)
	}
	if got, _ := refIn(t, store, ref); got != commit {
		t.Fatalf("the snapshot ref moved to %s", got)
	}

	for _, bad := range []string{
		commitpath.SnapshotRef(tOtherInst, tToolUseID),
		commitpath.SnapshotRef(tInstallation, "not-a-tool-call"),
		commitpath.SnapshotRef(tInstallation, tToolUseID) + "/x",
	} {
		if out, err := tGitErr(t, dir, "push", "--no-verify", url, commit+":"+bad); err == nil || !strings.Contains(out, "403") {
			t.Fatalf("a push to %s was not refused with 403: %v: %s", bad, err, out)
		}
	}
}

// SNAP-008's read: the mirror answers a snapshot's tree only when it holds
// the ref, and says plainly when it does not.
func TestSNAP008SnapshotTreeAnswersOnlyForAHeldRef(t *testing.T) {
	store := newStore(t)
	if _, ok, err := store.SnapshotTree(t.Context(), tRepo, tInstallation, tToolUseID); ok || err != nil {
		t.Fatalf("SnapshotTree with no mirror = %v %v, want not held and no error", ok, err)
	}
	if _, err := store.Ensure(t.Context(), tRepo); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := store.SnapshotTree(t.Context(), tRepo, tInstallation, tToolUseID); ok || err != nil {
		t.Fatalf("SnapshotTree with no ref = %v %v, want not held and no error", ok, err)
	}
	if _, _, err := store.SnapshotTree(t.Context(), tRepo, tInstallation, "nope"); err == nil {
		t.Fatal("SnapshotTree accepted a malformed tool call id")
	}
	if _, _, err := store.SnapshotTree(t.Context(), tRepo, "nope", tToolUseID); err == nil {
		t.Fatal("SnapshotTree accepted a malformed installation")
	}
	if _, _, err := store.SnapshotTree(t.Context(), "not/a", tInstallation, tToolUseID); err == nil {
		t.Fatal("SnapshotTree accepted a malformed repository")
	}
}
