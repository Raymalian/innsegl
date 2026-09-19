// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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

// TestMCP037EveryErrorReturnOfThePatchIDPath is IP §2's branch floor, which is
// a merge gate and not a preference: "100% branch on ... every error-return
// path of every MCP tool".
//
// Each case drives one condition to the side the happy path never reaches. A
// branch nothing has ever taken is a branch nobody has read; these are the
// paths that run on the day something is already wrong, and they are the worst
// place to discover a typo.
func TestMCP037EveryErrorReturnOfThePatchIDPath(t *testing.T) {
	t.Run("a git that is not there", func(t *testing.T) {
		// `gitPath == ""` false, and the diff command fails: two conditions in
		// one, both reached only when git cannot run.
		dir := t.TempDir()
		patchIDInit(t, dir)
		_, err := GitRepos{GitPath: "/nonexistent/git"}.StagedPatchID(t.Context(), dir)
		if err == nil {
			t.Fatal("a git binary that does not exist produced a patch id")
		}
	})

	t.Run("a directory that is not a repository", func(t *testing.T) {
		_, err := GitRepos{}.StagedPatchID(t.Context(), t.TempDir())
		if err == nil {
			t.Fatal("a directory with no repository produced a patch id")
		}
	})

	t.Run("a commit id that is not one", func(t *testing.T) {
		dir := t.TempDir()
		patchIDInit(t, dir)
		for _, bad := range []string{"", "HEAD", "nope", strings.Repeat("z", 40)} {
			if _, err := (GitRepos{}).CommitPatchID(t.Context(), dir, bad); err == nil {
				t.Errorf("CommitPatchID(%q) was accepted; a revision that is not an "+
					"object id names whatever the repository happens to resolve it to,"+
					" which is not the same commit everywhere", bad)
			}
		}
	})

	t.Run("a commit the repository does not hold", func(t *testing.T) {
		dir := t.TempDir()
		patchIDInit(t, dir)
		absent := strings.Repeat("a", 40)
		if _, err := (GitRepos{}).CommitPatchID(t.Context(), dir, absent); err == nil {
			t.Fatal("a commit that is not in the repository produced a patch id")
		}
	})

	t.Run("a cancelled context stops the pipeline", func(t *testing.T) {
		dir := t.TempDir()
		patchIDInit(t, dir)
		patchIDWrite(t, dir, "a.txt", "one\n")
		patchIDGit(t, dir, "add", "-A")

		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := (GitRepos{}).StagedPatchID(ctx, dir); err == nil {
			t.Fatal("a cancelled context produced a patch id")
		}
	})
}

// TestMCP039EveryErrorReturnSignCommitAddedForADR0047 — IP §2's branch floor
// over the tool's own error paths.
func TestMCP039EveryErrorReturnSignCommitAddedForADR0047(t *testing.T) {
	t.Run("the staged change has no patch id", func(t *testing.T) {
		// Phase A cannot name the change, so nothing is appended and nothing
		// is signed: the refusal happens before the intent exists.
		w := newSCWiring()
		w.repos.patchErr = errors.New("git is not on PATH")

		_, err := w.call(t, scIn())
		requireClass(t, err, ClassInvariantViolation)
		if !strings.Contains(err.Error(), "patch id") {
			t.Errorf("said %q, which does not say what could not be computed", err)
		}
		if got := len(w.ledger.records); got != 0 {
			t.Errorf("%d events were appended for a change that could not be identified", got)
		}
	})

	t.Run("task_ref cannot be resolved without a run directory", func(t *testing.T) {
		// The seam a harness reaches when it asks the server to fill in the
		// task: no directory, no answer, and a refusal rather than a blank
		// that would reach the Agent-Task trailer.
		c := &signCommitService{}
		if _, err := c.taskRefOf(t.Context(), "run-42"); err == nil {
			t.Fatal("task_ref was resolved with no run directory configured")
		}
	})
}

// gitShim writes a `git` that delegates to the real one except for the
// subcommands named, which it fails or silences.
//
// It exists for one reason: `patch-id` runs AFTER a diff has already
// succeeded, so its error return and its empty-output return are unreachable
// while both commands are the same working binary. A shim is the only way to
// make the second fail without the first, and those two branches are what runs
// when a deployment's git is older, sandboxed, or broken in exactly one place.
func gitShim(t *testing.T, mode string) string {
	t.Helper()
	return gitShimOn(t, "patch-id", mode)
}

// gitShimOn is gitShim with the subcommand named, because RM-145 (#229) put a
// SECOND command in front of the diff — `rev-list --parents` — and its own
// failure has to be reachable without the diff failing too.
func gitShimOn(t *testing.T, subcommand, mode string) string {
	t.Helper()
	dir := t.TempDir()
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skipf("no git on PATH: %v", err)
	}
	path := filepath.Join(dir, "git")
	script := "#!/bin/sh\nfor a in \"$@\"; do case \"$a\" in\n" +
		"  " + subcommand + ") " + mode + " ;;\n" +
		"esac; done\nexec " + gitBin + " \"$@\"\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestMCP044WhenPatchIDItselfFails covers the two conditions that only the
// second command in the pipeline can reach.
func TestMCP044WhenPatchIDItselfFails(t *testing.T) {
	stage := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		patchIDInit(t, dir)
		patchIDWrite(t, dir, "a.txt", "one\n")
		patchIDGit(t, dir, "add", "-A")
		return dir
	}

	t.Run("patch-id exits non-zero", func(t *testing.T) {
		dir := stage(t)
		_, err := GitRepos{GitPath: gitShim(t, "exit 3")}.StagedPatchID(t.Context(), dir)
		if err == nil {
			t.Fatal("a failing patch-id produced an identity")
		}
		if !strings.Contains(err.Error(), "patch-id") {
			t.Errorf("said %q, which does not name the command that failed", err)
		}
	})

	t.Run("patch-id prints nothing for a diff that is not empty", func(t *testing.T) {
		// Anomalous, and refused rather than shrugged at: the diff above it
		// was NOT empty, so silence here is git failing to identify a change
		// that exists. Returning "" would put an empty patch_id in the ledger,
		// and the caller cannot tell that from "this commit changes nothing".
		dir := stage(t)
		_, err := GitRepos{GitPath: gitShim(t, "exit 0")}.StagedPatchID(t.Context(), dir)
		if !errors.Is(err, ErrNoChange) {
			t.Fatalf("err = %v, want one wrapping ErrNoChange", err)
		}
	})
}

// TestMCP046TheLastErrorReturnsOfSignCommit — IP §2's floor, finished.
func TestMCP046TheLastErrorReturnsOfSignCommit(t *testing.T) {
	t.Run("the signed commit's change cannot be identified", func(t *testing.T) {
		// Phase C's own refusal: the commit exists and is signed, and git
		// cannot say what change it makes. The intent stands (I4); no
		// commit_recorded is written, so the reconciler sees an open intent
		// rather than a completed one it cannot check.
		w := newSCWiring()
		w.repos.commitPatchErr = errors.New("git patch-id: broken pipe")

		_, err := w.call(t, scIn())
		requireClass(t, err, ClassInvariantViolation)
		var recorded int
		for _, rec := range w.ledger.records {
			if rec[event.FieldEventType] == event.EventTypeCommitRecorded {
				recorded++
			}
		}
		if recorded != 0 {
			t.Errorf("%d commit_recorded events for a commit whose change is unknown", recorded)
		}
	})

	t.Run("an absolute worktree the server cannot resolve", func(t *testing.T) {
		// fillFromWorktree's error, through the tool: the caller said "work it
		// out" about a directory that is not a working tree.
		w := newSCWiring()
		in := scIn()
		in.Worktree = t.TempDir()
		if _, err := w.call(t, in); err == nil {
			t.Fatal("an absolute worktree that is not a git tree was accepted")
		}
	})

	t.Run("a run the directory cannot answer for", func(t *testing.T) {
		c := &signCommitService{runs: &scRuns{err: errors.New("the ledger is unreachable")}}
		if _, err := c.taskRefOf(t.Context(), "run-42"); err == nil {
			t.Fatal("a run directory that could not answer produced a task_ref")
		}
	})

	t.Run("a run the directory does not hold", func(t *testing.T) {
		c := &signCommitService{runs: &scRuns{found: false}}
		_, err := c.taskRefOf(t.Context(), "run-nobody")
		if err == nil {
			t.Fatal("an unknown run produced a task_ref; the Agent-Task trailer would " +
				"carry a blank")
		}
		if !strings.Contains(err.Error(), "run-nobody") {
			t.Errorf("said %q, which does not name the run", err)
		}
	})

	t.Run("a request with no task_ref is refused by name", func(t *testing.T) {
		// Reached only when nothing filled it in: no worktree to derive from
		// and no run directory to ask.
		in := scIn()
		in.TaskRef = ""
		w := newSCWiring()
		w.runs = &scRuns{}
		_, err := w.call(t, in)
		if err == nil {
			t.Fatal("a request with no task_ref was accepted")
		}
		if !strings.Contains(err.Error(), "task_ref") {
			t.Errorf("said %q, which does not name the missing argument", err)
		}
	})
}

// TestMCP048SignReachesItsOwnRefusals covers the two conditions inside sign(),
// which phases() bypasses: the worktree fill and the task_ref it may leave
// empty.
func TestMCP048SignReachesItsOwnRefusals(t *testing.T) {
	t.Run("an absolute worktree the server cannot work out", func(t *testing.T) {
		w := newSCWiring()
		in := scIn()
		in.Worktree = t.TempDir() // absolute, and not a git working tree
		if _, err := w.service(t).sign(t.Context(), in); err == nil {
			t.Fatal("sign accepted a worktree it could not resolve")
		}
	})

	t.Run("a run that IS held returns its task", func(t *testing.T) {
		// The side an unknown run never reaches. taskRefOf is the one source
		// of task_ref (see its comment), so the path that SUCCEEDS is as much
		// a merge-gate surface as the two that refuse.
		c := &signCommitService{runs: &scRuns{found: true, run: CredentialRun{
			RunID: scRunID, TaskID: "jira-118",
		}}}
		got, err := c.taskRefOf(t.Context(), scRunID)
		if err != nil {
			t.Fatalf("taskRefOf: %v", err)
		}
		if got != "jira-118" {
			t.Errorf("task_ref = %q, want the run's own task", got)
		}
	})

	t.Run("a request with no task_ref is refused by name", func(t *testing.T) {
		// Reached when nothing filled it in. Checked against the validator
		// directly: the surrounding service would need a ledger, and this
		// condition is about the argument, not about the deployment.
		in := scIn()
		in.TaskRef = ""
		err := signCommitCheckRequest(in)
		if err == nil {
			t.Fatal("a request with no task_ref was accepted")
		}
		if !strings.Contains(err.Error(), "task_ref") {
			t.Errorf("said %q, which does not name the missing argument", err)
		}
	})
}

// A MERGE commit gets a patch id, and it is the one its branch contributed
// (RM-145, #229).
//
// # What this measures, and why the obvious fix is not the fix
//
// `git diff-tree -p` prints NOTHING for a commit with more than one parent, so
// before RM-145 every merge failed Phase C's invariant with "no change to
// identify" — on a commit that is perfectly ordinary and, in this repository's
// own workflow, the NORMAL way work reaches `main`: the rule is "sign after the
// final rebase", and merging rather than rebasing is what preserves another
// agent's signature. The one commit shape the signer could not handle was the
// shape the workflow depends on.
//
// `--cc` looks like the answer and is not, which this test pins so nobody
// reaches for it again: on a merge that resolved no conflicts it emits the
// commit sha and no patch at all, and `git patch-id` returns nothing for that.
// The empty-diff error would move one step later rather than go away.
//
// First-parent is not a workaround chosen to make the check pass. Phase A runs
// `git diff --cached`, which compares the index against HEAD — and when a merge
// is committed, HEAD *is* the first parent. Both phases were always asking the
// same question; only Phase C had no way to say it.
func TestMCP067AMergeCommitHasThePatchIDItsBranchBrought(t *testing.T) {
	dir := t.TempDir()
	patchIDInit(t, dir)
	patchIDWrite(t, dir, "base.txt", "base\n")
	patchIDGit(t, dir, "add", "-A")
	patchIDGit(t, dir, "commit", "-m", "base")
	base := patchIDGit(t, dir, "rev-parse", "HEAD")

	// A branch with one commit, whose patch id is what the merge must report.
	patchIDGit(t, dir, "checkout", "-b", "topic")
	patchIDWrite(t, dir, "topic.txt", "from the topic branch\n")
	patchIDGit(t, dir, "add", "-A")
	patchIDGit(t, dir, "commit", "-m", "topic")
	topic := patchIDGit(t, dir, "rev-parse", "HEAD")

	topicID, err := GitRepos{}.CommitPatchID(t.Context(), dir, topic)
	if err != nil {
		t.Fatalf("CommitPatchID(topic): %v", err)
	}

	// Back to the trunk and merge with --no-ff, which is how this repository
	// lands signed work: a fast-forward would produce no merge commit at all.
	patchIDGit(t, dir, "checkout", "-")
	patchIDGit(t, dir, "merge", "--no-ff", "-m", "Merge branch 'topic'", "topic")
	merge := patchIDGit(t, dir, "rev-parse", "HEAD")

	if parents := patchIDGit(t, dir, "rev-list", "--parents", "-n", "1", merge); len(strings.Fields(parents)) != 3 {
		t.Fatalf("the fixture did not produce a merge: rev-list --parents said %q", parents)
	}

	mergeID, err := GitRepos{}.CommitPatchID(t.Context(), dir, merge)
	if err != nil {
		t.Fatalf("CommitPatchID(merge) refused: %v\n\n"+
			"This is RM-145 (#229). A merge commit reaching Phase C with no patch id fails the "+
			"invariant, the commit stays at HEAD carrying its trailers, and nothing "+
			"reaches the ledger.", err)
	}
	if mergeID != topicID {
		t.Errorf("the merge reports patch id %q; the branch it brought in has %q.\n"+
			"They must agree: the merge's change, seen from the trunk, IS the branch's "+
			"change, and Phase A computed exactly that with `git diff --cached`.",
			mergeID, topicID)
	}

	t.Run("--cc would not have fixed it", func(t *testing.T) {
		out, cerr := exec.CommandContext(t.Context(), "git", "-C", dir,
			"diff-tree", "-p", "--root", "--no-color", "--no-ext-diff", "--cc", merge).Output()
		if cerr != nil {
			t.Fatalf("git diff-tree --cc: %v", cerr)
		}
		// One line: the commit sha. No patch follows it, so `git patch-id` has
		// nothing to hash and the empty-diff check would fire one step later.
		if body := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(out)), merge)); body != "" {
			t.Skipf("this git emits a combined diff for a clean merge (%d bytes of body); "+
				"the first-parent route is still correct, but the reason recorded in "+
				"CommitPatchID's comment no longer holds on this version", len(body))
		}
	})

	t.Run("a non-merge is computed exactly as before", func(t *testing.T) {
		// Every patch id already in the ledger came from this invocation. If
		// the merge branch changed it for ordinary commits too, history would
		// disagree with itself.
		want := patchIDOfCommitByHand(t, dir, topic)
		if topicID != want {
			t.Errorf("CommitPatchID(non-merge) = %q, want %q — the value an auditor "+
				"gets from `git diff-tree -p --root … | git patch-id --verbatim`",
				topicID, want)
		}
		if base == topic {
			t.Fatal("fixture error: base and topic are the same commit")
		}
	})
}

// patchIDOfCommitByHand is the two-command pipeline an auditor would run,
// spelled out rather than shared with the implementation so the test cannot
// agree with a bug by construction.
func patchIDOfCommitByHand(t *testing.T, dir, sha string) string {
	t.Helper()
	diff, err := exec.CommandContext(t.Context(), "git", "-C", dir,
		"diff-tree", "-p", "--root", "--no-color", "--no-ext-diff", sha).Output()
	if err != nil {
		t.Fatalf("git diff-tree: %v", err)
	}
	id := exec.CommandContext(t.Context(), "git", "-C", dir, "patch-id", "--verbatim")
	id.Stdin = strings.NewReader(string(diff))
	out, err := id.Output()
	if err != nil {
		t.Fatalf("git patch-id: %v", err)
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		t.Fatalf("git patch-id produced nothing for %s", sha)
	}
	return fields[0]
}

// TestMCP068ARootCommitStillYieldsAPatchID — the case `--root` was there for,
// pinned now that a parent lookup runs before it (RM-145, #229).
//
// The first commit in a repository has NO parent, so `diff-tree -p` without
// `--root` prints nothing for it and Phase C would refuse the one commit a
// fresh repository can make. That was already handled; what is new is that
// `CommitPatchID` now asks about parents first, and a lookup that mistook
// "no parent" for "one parent" would take the two-tree route with nothing to
// put on the left of it. So this asserts the answer AND the agreement Phase A
// and Phase C have to keep: the id computed from the index before the commit
// and the id computed from the commit object afterwards are the same value.
func TestMCP068ARootCommitStillYieldsAPatchID(t *testing.T) {
	dir := t.TempDir()
	patchIDInit(t, dir)
	patchIDWrite(t, dir, "first.txt", "the very first line\n")
	patchIDGit(t, dir, "add", "-A")

	// Phase A's value, taken in a repository that has no HEAD at all.
	staged, err := GitRepos{}.StagedPatchID(t.Context(), dir)
	if err != nil {
		t.Fatalf("StagedPatchID in a repository with no HEAD: %v", err)
	}

	patchIDGit(t, dir, "commit", "-m", "root")
	root := patchIDGit(t, dir, "rev-parse", "HEAD")
	if parents := patchIDGit(t, dir, "rev-list", "--parents", "-n", "1", root); len(strings.Fields(parents)) != 1 {
		t.Fatalf("the fixture did not produce a ROOT commit: rev-list --parents said %q", parents)
	}

	got, err := GitRepos{}.CommitPatchID(t.Context(), dir, root)
	if err != nil {
		t.Fatalf("CommitPatchID(root) refused: %v\n\n"+
			"A root commit has no parent to diff against, which is why the "+
			"invocation carries --root. A parent lookup that reported one anyway "+
			"would have sent it down the two-tree route.", err)
	}
	if want := patchIDOfCommitByHand(t, dir, root); got != want {
		t.Errorf("CommitPatchID(root) = %q, want %q — the value an auditor gets from "+
			"`git diff-tree -p --root … | git patch-id --verbatim`", got, want)
	}
	if got != staged {
		t.Errorf("Phase C reports %q for the root commit and Phase A recorded %q.\n"+
			"They are the same change: `git diff --cached` with no HEAD diffs against "+
			"the empty tree, and --root makes diff-tree do the same.", got, staged)
	}
}

// TestMCP069EveryErrorReturnOfTheFirstParentLookup — IP §2's 100%-branch floor
// over the code RM-145 (#229) added.
//
// `firstParentOfMerge` has one error return and two ways to reach the rest of
// it, and none of them is exercised by the happy path: a git that cannot run,
// a commit the repository does not hold, and a configured `GitPath` rather
// than the default. The last matters more than it looks — the lookup resolves
// its own binary, so a deployment that sets `GitPath` and a lookup that
// ignored it would run two different gits inside one patch id.
func TestMCP069EveryErrorReturnOfTheFirstParentLookup(t *testing.T) {
	t.Run("git cannot be run at all", func(t *testing.T) {
		dir := t.TempDir()
		patchIDInit(t, dir)
		_, err := GitRepos{GitPath: "/nonexistent/git"}.CommitPatchID(
			t.Context(), dir, strings.Repeat("a", 40))
		if err == nil {
			t.Fatal("a git binary that does not exist produced a patch id")
		}
		if !strings.Contains(err.Error(), "rev-list") {
			t.Errorf("said %q, which does not name the command that failed. The "+
				"parent lookup runs before the diff, so an operator reading this "+
				"must not be sent to diff-tree", err)
		}
	})

	t.Run("a commit the repository does not hold", func(t *testing.T) {
		// Well-formed and absent: the lookup is the first thing that touches
		// the object store, so this is where it is caught now.
		dir := t.TempDir()
		patchIDInit(t, dir)
		_, err := GitRepos{}.CommitPatchID(t.Context(), dir, strings.Repeat("b", 40))
		if err == nil {
			t.Fatal("a commit that is not in the repository produced a patch id")
		}
		if !strings.Contains(err.Error(), "rev-list") {
			t.Errorf("said %q, which does not name the command that failed", err)
		}
	})

	t.Run("the lookup runs under the configured git, not the one on PATH", func(t *testing.T) {
		// The shim fails `rev-list` and delegates everything else, so a lookup
		// that resolved its own binary the way the diff does fails here and a
		// lookup that reached for PATH does not: with PATH's git the parents
		// would be found, the diff and the id would both run through the shim
		// untouched, and a patch id would come back. Two gits inside one patch
		// id is a deployment that computes a different identity from the one
		// it is configured to compute.
		dir := t.TempDir()
		patchIDInit(t, dir)
		patchIDWrite(t, dir, "base.txt", "base\n")
		patchIDGit(t, dir, "add", "-A")
		patchIDGit(t, dir, "commit", "-m", "base")
		patchIDGit(t, dir, "checkout", "-b", "topic")
		patchIDWrite(t, dir, "topic.txt", "topic\n")
		patchIDGit(t, dir, "add", "-A")
		patchIDGit(t, dir, "commit", "-m", "topic")
		patchIDGit(t, dir, "checkout", "-")
		patchIDGit(t, dir, "merge", "--no-ff", "-m", "Merge branch 'topic'", "topic")
		merge := patchIDGit(t, dir, "rev-parse", "HEAD")

		_, err := GitRepos{GitPath: gitShimOn(t, "rev-list", "exit 3")}.CommitPatchID(
			t.Context(), dir, merge)
		if err == nil {
			t.Fatal("the configured git cannot run rev-list, and a patch id came " +
				"back anyway — the parent lookup used a different binary from the " +
				"one the diff uses")
		}
		if !strings.Contains(err.Error(), "rev-list") {
			t.Errorf("said %q, which does not name the command that failed", err)
		}
	})
}

// TestMCP070TheSignersRefusalSaysWhetherACommitWasMade — RM-145 (#229),
// the half of it that is worse than the patch id.
//
// # What the old sentence claimed, and what it cost
//
// `scripts/innsegl-commit.sh` read `commit_sha` out of the answer and, when
// there was none, said "sign_commit refused — nothing was committed". That is
// true for every failure before Phase A and FALSE for every failure after
// Phase B. sign_commit's own header states the window: "BETWEEN B AND C a
// commit object exists, Rekor holds its entry, and no `commit_recorded` does
// … Both are narrow BY ORDERING and not by cleanup." Nothing rolls back. The
// commit is at HEAD with its identity trailers and the ledger is missing one
// record.
//
// An operator who believes "nothing was committed" commits again — a second
// signed commit for one change — or resets, destroying a commit whose Rekor
// entry is already public and permanent. The repair exists: REC-002 has the
// reconciler match the Rekor entry to the intent and append the missing
// `commit_recorded`. The message was sending them away from it.
//
// So the refusal asks git what is actually there. This asserts the TEXT of
// both answers, because the text is the whole defect — a script that took the
// right branch and printed the old sentence would fix nothing.
//
// # Why this drives the real script rather than a copy of its logic
//
// The claim is about what an operator reads. A test over an extracted shell
// function would assert that a sentence exists somewhere and leave the
// question of whether the signer prints it unanswered. So the script is run,
// against a stub that speaks the transport and makes the commit for real in
// the second case — which is exactly what sign_commit does before Phase C can
// fail.
func TestMCP070TheSignersRefusalSaysWhetherACommitWasMade(t *testing.T) {
	for _, need := range []string{"sh", "curl", "python3", "shasum", "git"} {
		if _, err := exec.LookPath(need); err != nil {
			t.Skipf("%s is not on PATH, and the signer script needs it: %v", need, err)
		}
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "innsegl-commit.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("the signer script is not where this test expects it: %v", err)
	}

	t.Run("the commit was made and only the ledger record is missing", func(t *testing.T) {
		var committed string
		ctx := t.Context()
		dir, stderr, runErr := runSigner(t, script, func(dir string) {
			// Phase B has happened: sign_commit created the commit. Phase C
			// is what fails below, so nothing undoes this.
			committed = signerCommit(ctx, t, dir)
		})
		if runErr == nil {
			t.Fatal("the signer exited 0 on a refusal")
		}
		if committed == "" {
			t.Fatal("the stub never reached sign_commit, so the window under test was never entered")
		}

		// Printed, not only asserted: the defect was a sentence, so the
		// sentence is evidence and `go test -v` is where an auditor reads it.
		t.Logf("the refusal reads:\n%s", stderr)

		short := strings.TrimSpace(patchIDGit(t, dir, "rev-parse", "--short", "HEAD"))
		if short == "" {
			t.Fatal("no HEAD after the commit the stub made")
		}
		for _, want := range []string{
			short,       // the commit, by name: there is something to go and look at
			"ledger",    // what is actually missing
			"reconcile", // where the repair lives — REC-002, `innsegl reconcile`
		} {
			if !strings.Contains(stderr, want) {
				t.Errorf("the refusal does not contain %q.\n\nIt said:\n%s", want, stderr)
			}
		}
		if strings.Contains(strings.ToLower(stderr), "nothing was committed") {
			t.Errorf("the refusal says nothing was committed, and %s is at HEAD with "+
				"its identity trailers. That sentence is what makes an operator commit "+
				"again or reset a commit Rekor already holds.\n\nIt said:\n%s", short, stderr)
		}
	})

	t.Run("nothing was committed, and it says so", func(t *testing.T) {
		// A refusal BEFORE Phase A — the request rejected, the run retired,
		// the credential unavailable. Here the old sentence was correct and
		// must survive: a signer that hedged on every failure would be as
		// useless as one that lied on every failure.
		before := ""
		ctx := t.Context()
		dir, stderr, runErr := runSigner(t, script, func(dir string) {
			before = strings.TrimSpace(gitIn(ctx, t, dir, "rev-parse", "HEAD"))
		})
		if runErr == nil {
			t.Fatal("the signer exited 0 on a refusal")
		}
		if got := strings.TrimSpace(gitIn(ctx, t, dir, "rev-parse", "HEAD")); got != before {
			t.Fatalf("HEAD moved from %s to %s without a commit being made", before, got)
		}
		if !strings.Contains(strings.ToLower(stderr), "nothing was committed") {
			t.Errorf("no commit was made and the refusal does not say so.\n\nIt said:\n%s", stderr)
		}
		if strings.Contains(strings.ToLower(stderr), "reconcile") {
			t.Errorf("nothing was committed, and the refusal sends the operator to the "+
				"reconciler anyway. There is no dangling signature to repair.\n\nIt said:\n%s",
				stderr)
		}
	})
}

// runSigner drives scripts/innsegl-commit.sh over a staged change against a
// stub MCP, and returns the fixture, the script's stderr and its exit status.
//
// onSign runs inside the sign_commit handler, before it answers — the only
// place from which the two states this test distinguishes can be produced,
// because they differ by what sign_commit did before it failed.
func runSigner(t *testing.T, script string, onSign func(dir string)) (string, string, error) {
	t.Helper()

	dir := t.TempDir()
	patchIDInit(t, dir)
	patchIDWrite(t, dir, "base.txt", "base\n")
	patchIDGit(t, dir, "add", "-A")
	patchIDGit(t, dir, "commit", "-m", "base")
	patchIDWrite(t, dir, "changed.txt", "the change being signed\n")
	patchIDGit(t, dir, "add", "-A")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		// The transport's own requirement: the session id comes back as a
		// header on `initialize` and is echoed on every call after it.
		w.Header().Set("Mcp-Session-Id", "sess-innsegl-commit")
		w.Header().Set("Content-Type", "text/event-stream")

		// Both failures below mean the stub was sent something this test does
		// not model, which would otherwise surface as the script reporting a
		// transport it could not reach -- the one message this test must never
		// confuse with the messages it is asserting.
		body, rerr := io.ReadAll(r.Body)
		if rerr != nil {
			http.Error(w, "the stub could not read the request", http.StatusBadRequest)
			return
		}
		if uerr := json.Unmarshal(body, &req); uerr != nil {
			http.Error(w, "the stub could not parse the request", http.StatusBadRequest)
			return
		}

		switch req.Method {
		case "initialize":
			signerSSE(w, `{"protocolVersion":"2025-11-25"}`, false)
			return
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
			return
		}

		switch req.Params.Name {
		case "sign_commit":
			if onSign != nil {
				onSign(dir)
			}
			// A Phase C refusal, in the shape `field` reads: isError, and a
			// plain sentence rather than JSON.
			// Deliberately says nothing the assertions look for: the text
			// under test is the SCRIPT's, and a refusal that happened to use
			// the same words would satisfy them for free.
			signerSSE(w, "INVARIANT_VIOLATION: the record could not be appended", true)
		case "register_agent":
			signerSSE(w, `{"run_id":"run-stub"}`, false)
		default: // retire_agent, from the script's EXIT trap
			signerSSE(w, `{"ok":true}`, false)
		}
	}))
	t.Cleanup(srv.Close)

	// `-p changed.txt` is the one path this fixture stages, named out loud.
	// Since #280 a caller committing its own work has to say which paths the
	// commit is of — the index belongs to the working tree rather than to the
	// caller, and a commit that named none would carry whatever anybody else
	// staged. The fixture is a private t.TempDir() with exactly one staged
	// path, so naming it changes nothing this test is about and keeps the
	// script under test on its ordinary path rather than its -r exemption.
	cmd := exec.CommandContext(t.Context(), "sh", script,
		"-p", "changed.txt", "-m", "fix(thing): the change being signed")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"INNSEGL_MCP_ADMIN_URL="+srv.URL+"/",
		"INNSEGL_MCP_URL="+srv.URL+"/",
		// Neither may be discovered from the machine this runs on: the
		// fixture has no origin remote, and a real runs directory would hand
		// the script somebody else's run.
		"INNSEGL_REPO_ID=git.example/org/fixture",
		"INNSEGL_RUNS_DIR="+filepath.Join(t.TempDir(), "runs"),
		"GIT_AUTHOR_DATE=2026-01-01T00:00:00Z",
		"GIT_COMMITTER_DATE=2026-01-01T00:00:00Z",
	)
	var errBuf strings.Builder
	cmd.Stdout = io.Discard
	cmd.Stderr = &errBuf
	err := cmd.Run()
	return dir, errBuf.String(), err
}

// signerSSE writes one tool result the way the transport delivers it: a single
// `data:` line, which is what the script's `sed` reads.
func signerSSE(w http.ResponseWriter, text string, isError bool) {
	b, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"result": map[string]any{
			"content": []any{map[string]any{"type": "text", "text": text}},
			"isError": isError,
		},
	})
	if err != nil {
		return
	}
	fmt.Fprintf(w, "data: %s\n\n", b)
}

// signerCommit makes the commit sign_commit would have made: the staged tree,
// under a message carrying the three identity trailers doc 02 §5 requires.
// Returns its full object id.
func signerCommit(ctx context.Context, t *testing.T, dir string) string {
	t.Helper()
	msg := "fix(thing): the change being signed\n\n" +
		"Agent-Identity: spiffe://innsegl.test/agent/orchestrator/task/main/run/run-stub\n" +
		"Agent-Run: run-stub\n" +
		"Agent-Task: main\n"
	gitIn(ctx, t, dir, "commit", "-m", msg)
	return strings.TrimSpace(gitIn(ctx, t, dir, "rev-parse", "HEAD"))
}

// gitIn is patchIDGit without the t.Fatal: it runs on the stub's goroutine,
// where a failed assertion would be reported against the wrong test. The
// context is passed rather than taken from t, for the same reason.
func gitIn(ctx context.Context, t *testing.T, dir string, args ...string) string {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_DATE=2026-01-01T00:00:00Z",
		"GIT_COMMITTER_DATE=2026-01-01T00:00:00Z")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("git %s in the fixture: %v: %s", strings.Join(args, " "), err, out)
		return ""
	}
	return strings.TrimSpace(string(out))
}
