// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
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
	dir := t.TempDir()
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skipf("no git on PATH: %v", err)
	}
	path := filepath.Join(dir, "git")
	script := "#!/bin/sh\nfor a in \"$@\"; do case \"$a\" in\n" +
		"  patch-id) " + mode + " ;;\n" +
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
