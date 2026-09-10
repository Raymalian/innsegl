// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/event"
)

// MCP-033 and MCP-034 (proposed for doc 07; doc 07 is not modified here) —
// RM-120, #192.
//
// # What a patch id is for here
//
// A gitsign signature covers a commit OBJECT, so it names the commit's parents
// and its tree. GitHub's rebase rewrites both, and the signature does not
// survive: measured on throwaway branches, a rebased commit arrives on `main`
// with the trailers intact and nothing left to verify them against. Squash is
// worse — it substitutes GitHub's own PGP key and inserts a `Co-authored-by`
// that ADR-0028 §5 forbids.
//
// What DOES survive a rebase is the change itself, and `git patch-id` is git's
// own name for it. So ADR-0047 anchors attribution to the change: the ledger
// records the patch id beside the commit SHA, and a verifier that cannot find
// the SHA can still find the change.
//
// # --verbatim, never --stable
//
// The default normalises whitespace, so `hello world` and `hello   world`
// produce one id. In Python, YAML, Go struct tags and a Makefile those are two
// different programs, and an identity that cannot tell them apart is not an
// identity. `--verbatim` hashes the lines as they are.

// TestMCP033ThePatchIDIsGitsOwn. Not a hash this package invents: the value
// recorded is exactly what `git patch-id --verbatim` prints, because that is
// what anyone auditing the ledger will run.
func TestMCP033ThePatchIDIsGitsOwn(t *testing.T) {
	dir := t.TempDir()
	patchIDInit(t, dir)
	patchIDWrite(t, dir, "a.txt", "one\ntwo\nthree\n")
	patchIDGit(t, dir, "add", "-A")

	got, err := GitRepos{}.StagedPatchID(t.Context(), dir)
	if err != nil {
		t.Fatalf("StagedPatchID: %v", err)
	}
	if want := patchIDByHand(t, dir); got != want {
		t.Errorf("StagedPatchID = %q, want %q — the value in the ledger must be the "+
			"one an auditor gets from git", got, want)
	}
	if len(got) != 40 || strings.Trim(got, "0123456789abcdef") != "" {
		t.Errorf("StagedPatchID = %q, which is not a 40-hex object id", got)
	}

	t.Run("the commit's patch id is the staged one", func(t *testing.T) {
		patchIDGit(t, dir, "commit", "-m", "one")
		sha := patchIDGit(t, dir, "rev-parse", "HEAD")
		fromCommit, cerr := GitRepos{}.CommitPatchID(t.Context(), dir, sha)
		if cerr != nil {
			t.Fatalf("CommitPatchID: %v", cerr)
		}
		if fromCommit != got {
			t.Errorf("the committed change has patch id %q but the staged change had "+
				"%q; sign_commit records the first in commit_intent and the second in "+
				"commit_recorded, and a mismatch means they are not the same change",
				fromCommit, got)
		}
	})

	t.Run("nothing staged has no patch id, and says so", func(t *testing.T) {
		_, err := GitRepos{}.StagedPatchID(t.Context(), dir)
		if err == nil {
			t.Fatal("an empty diff produced a patch id; git prints nothing for one, " +
				"and an empty member would reach the ledger")
		}
		if !strings.Contains(err.Error(), "no change") {
			t.Errorf("said %q, which does not say what is missing", err)
		}
	})
}

// TestMCP034ThePatchIDSurvivesARebase is ADR-0047's whole claim, measured
// rather than asserted.
//
// The same change is replayed onto a different base, exactly as GitHub's rebase
// button replays it. The commit SHA changes, the tree changes, the parents
// change, and the signature — if there were one — would be gone. The patch id
// does not move, which is why it is what attribution is anchored to.
func TestMCP034ThePatchIDSurvivesARebase(t *testing.T) {
	dir := t.TempDir()
	patchIDInit(t, dir)
	patchIDWrite(t, dir, "base.txt", "base\n")
	patchIDGit(t, dir, "add", "-A")
	patchIDGit(t, dir, "commit", "-m", "base")

	// The agent's change, on a branch.
	patchIDGit(t, dir, "checkout", "-q", "-b", "feature")
	patchIDWrite(t, dir, "feature.txt", "the agent's work\n")
	patchIDGit(t, dir, "add", "-A")
	patchIDGit(t, dir, "commit", "-m", "the agent's work")
	original := patchIDGit(t, dir, "rev-parse", "HEAD")
	before, err := GitRepos{}.CommitPatchID(t.Context(), dir, original)
	if err != nil {
		t.Fatalf("CommitPatchID before: %v", err)
	}

	// main moves on underneath it, which is what makes a rebase necessary.
	patchIDGit(t, dir, "checkout", "-q", "main")
	patchIDWrite(t, dir, "other.txt", "somebody else\n")
	patchIDGit(t, dir, "add", "-A")
	patchIDGit(t, dir, "commit", "-m", "somebody else")

	patchIDGit(t, dir, "checkout", "-q", "feature")
	patchIDGit(t, dir, "rebase", "main")

	rebased := patchIDGit(t, dir, "rev-parse", "HEAD")
	if rebased == original {
		t.Fatal("the rebase did not rewrite the commit, so this proves nothing " +
			"about surviving one")
	}
	after, err := GitRepos{}.CommitPatchID(t.Context(), dir, rebased)
	if err != nil {
		t.Fatalf("CommitPatchID after: %v", err)
	}
	if after != before {
		t.Errorf("the patch id changed across a rebase: %s -> %s.\nThe commit SHA "+
			"changed too (%s -> %s), which is expected; if BOTH move there is nothing "+
			"left that identifies the agent's change after a merge.",
			before, after, original[:12], rebased[:12])
	}
}

func patchIDInit(t *testing.T, dir string) {
	t.Helper()
	patchIDGit(t, dir, "init", "-q", "-b", "main")
	patchIDGit(t, dir, "config", "user.email", "t@t")
	patchIDGit(t, dir, "config", "user.name", "t")
}

func patchIDWrite(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func patchIDGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_DATE=2026-01-01T00:00:00Z",
		"GIT_COMMITTER_DATE=2026-01-01T00:00:00Z")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// patchIDByHand computes the expected value with a shell pipeline, the way an
// auditor would. Deliberately not through this package: a value checked against
// the code that produced it proves only that the code agrees with itself.
func patchIDByHand(t *testing.T, dir string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "sh", "-c",
		"git diff --cached --no-color | git patch-id --verbatim")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("the by-hand pipeline failed: %v", err)
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		t.Fatal("the by-hand pipeline printed nothing")
	}
	return fields[0]
}

// TestMCP035ACommitWhoseChangeIsNotTheIntentsIsRefused.
//
// Phase C recomputes the patch id from the commit object rather than reusing
// Phase A's. Reusing it would record the same claim twice and check nothing;
// recomputing asks a question with a real wrong answer — a hook that rewrote
// the tree between the phases, a signer pointed at the wrong worktree, an index
// that moved. It sits beside the tree-hash check that closes the same window.
func TestMCP035ACommitWhoseChangeIsNotTheIntentsIsRefused(t *testing.T) {
	w := newSCWiring()
	w.repos.patchID = strings.Repeat("a", 40)
	w.repos.commitPatchID = strings.Repeat("b", 40)

	_, err := w.call(t, scIn())
	requireClass(t, err, ClassInvariantViolation)
	if !strings.Contains(err.Error(), "not the change that was intended") {
		t.Errorf("said %q, which does not say what disagreed", err)
	}

	// The intent stands. It is a record of what was attempted, and I4 keeps it
	// whether or not the attempt succeeded — the reconciler's evidence that a
	// signature may exist for a change no `commit_recorded` claims.
	var recorded int
	for _, rec := range w.ledger.records {
		if rec[event.FieldEventType] == event.EventTypeCommitRecorded {
			recorded++
		}
	}
	if recorded != 0 {
		t.Errorf("%d commit_recorded events were appended for a commit that is not "+
			"the intended change", recorded)
	}
}

// TestMCP036TheRecordedPatchIDIsTheCommitsOwn. The happy path, so that the
// check above cannot pass by refusing everything.
func TestMCP036TheRecordedPatchIDIsTheCommitsOwn(t *testing.T) {
	w := newSCWiring()
	w.repos.patchID = strings.Repeat("e", 40)

	if _, err := w.call(t, scIn()); err != nil {
		t.Fatalf("sign_commit: %v", err)
	}
	seen := map[string]string{}
	for _, rec := range w.ledger.records {
		et, isString := rec[event.FieldEventType].(string)
		if !isString {
			t.Fatalf("an appended event has no string event_type: %#v", rec[event.FieldEventType])
		}
		if id, isString := rec[event.FieldPatchID].(string); isString {
			seen[et] = id
		}
	}
	for _, et := range []string{event.EventTypeCommitIntent, event.EventTypeCommitRecorded} {
		if seen[et] != strings.Repeat("e", 40) {
			t.Errorf("%s recorded patch_id %q, want the change's own id", et, seen[et])
		}
	}
}
