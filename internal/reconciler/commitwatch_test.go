// SPDX-License-Identifier: Apache-2.0

package reconciler_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/reconciler"
)

// RM-244 (#389). The test ID this file drives, from doc 07:
//
//	CMT-017  A git commit tool call that made no commit (nothing to commit,
//	         refused by a hook, lost the ref lock), and one whose commit WAS
//	         signed, raise nothing. Table-driven over the REAL bytes `git
//	         commit` prints for each case, captured from an actual git
//	         subprocess rather than hand-written, so the parser this pass
//	         relies on is proven against git's own output and not against a
//	         guess at its shape.
//
// CMT-016 — the positive case, a commit git DID make with nothing recorded
// for it — is commitwatchintegration_test.go's: it needs a real Postgres
// ledger and is the one case this pass exists for, so it runs against the
// package's real integration harness rather than the in-memory one below.

// bypassCommand is the shape ADR-0059's own context names: a harness's `git
// commit`, made to bypass the signing path entirely rather than merely fail
// to reach it.
const bypassCommand = `git -c commit.gpgsign=false -c core.hooksPath=/dev/null commit -m "bypass"`

// ---------------------------------------------------------------------------
// Real git, captured — never a hand-written stand-in for its own output.
// ---------------------------------------------------------------------------

// commitWatchGitEnv isolates one throwaway repository from the operator's own
// git identity, config and hooks: HOME and GIT_CONFIG_GLOBAL point inside a
// temp directory nothing else reads.
func commitWatchGitEnv(home string) []string {
	return append(os.Environ(),
		"HOME="+home,
		"GIT_CONFIG_GLOBAL="+filepath.Join(home, ".gitconfig"),
		"GIT_CONFIG_NOSYSTEM=1",
	)
}

func commitWatchRunGit(t *testing.T, dir string, env []string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", args...)
	cmd.Dir = dir
	cmd.Env = env
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

// commitWatchMustGit runs git and fails t on any error — for the SETUP steps
// of a scenario, never for the one `commit` invocation whose own output a
// case captures.
func commitWatchMustGit(t *testing.T, dir string, env []string, args ...string) string {
	t.Helper()
	out, err := commitWatchRunGit(t, dir, env, args...)
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// commitWatchRepo makes a fresh, isolated repository with a committer
// identity and no commits.
func commitWatchRepo(t *testing.T) (dir string, env []string) {
	t.Helper()
	dir = t.TempDir()
	env = commitWatchGitEnv(t.TempDir())
	commitWatchMustGit(t, dir, env, "init", "-q", "-b", "main")
	commitWatchMustGit(t, dir, env, "config", "user.name", "innsegl commitwatch test")
	commitWatchMustGit(t, dir, env, "config", "user.email", "agent@innsegl.invalid")
	return dir, env
}

// gitNothingToCommit: a fresh repository with nothing staged. Git refuses
// before ever calling print_summary, so no commit-summary line is printed.
func gitNothingToCommit(t *testing.T) (result string, isError bool) {
	t.Helper()
	dir, env := commitWatchRepo(t)
	out, err := commitWatchRunGit(t, dir, env,
		"-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
		"commit", "-m", "innsegl commitwatch test: nothing to commit")
	if err == nil {
		t.Fatal("git commit with nothing staged and no history succeeded")
	}
	return out, true
}

// gitHookRefusal: a real pre-commit hook that refuses. Git aborts before
// writing any commit object and prints the hook's own stderr, never a
// commit-summary line.
func gitHookRefusal(t *testing.T) (result string, isError bool) {
	t.Helper()
	dir, env := commitWatchRepo(t)
	hooks := filepath.Join(dir, ".git", "hooks")
	if err := os.MkdirAll(hooks, 0o755); err != nil {
		t.Fatal(err)
	}
	hook := "#!/bin/sh\necho 'refused by test hook' >&2\nexit 1\n"
	if err := os.WriteFile(filepath.Join(hooks, "pre-commit"), []byte(hook), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("one\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	commitWatchMustGit(t, dir, env, "add", "a.txt")
	// core.hooksPath deliberately NOT overridden here: the whole point of
	// this case is that the hook actually runs.
	out, err := commitWatchRunGit(t, dir, env,
		"-c", "commit.gpgsign=false",
		"commit", "-m", "innsegl commitwatch test: refused by hook")
	if err == nil {
		t.Fatal("git commit succeeded despite the refusing hook")
	}
	return out, true
}

// gitLostTheRefLock: a repository with one commit already on `main`, a
// second change staged, and the branch's own lock file already held — the
// real condition git's single-writer serialization produces when two commits
// race for one ref (ADR-0059's own case 4). The commit object IS written
// (that happens before the ref update); the branch does not move, and git
// never reaches print_summary, because that only runs after the ref update
// itself succeeds.
func gitLostTheRefLock(t *testing.T) (result string, isError bool) {
	t.Helper()
	dir, env := commitWatchRepo(t)
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("one\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	commitWatchMustGit(t, dir, env, "add", "a.txt")
	commitWatchMustGit(t, dir, env,
		"-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
		"commit", "-m", "innsegl commitwatch test: seed")

	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("two\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	commitWatchMustGit(t, dir, env, "add", "a.txt")

	lock := filepath.Join(dir, ".git", "refs", "heads", "main.lock")
	if err := os.WriteFile(lock, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(lock) })

	out, err := commitWatchRunGit(t, dir, env,
		"-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
		"commit", "-m", "innsegl commitwatch test: lost the ref lock")
	if err == nil {
		t.Fatal("git commit succeeded with the ref lock already held")
	}
	return out, true
}

// gitSignedCommit: an ordinary successful commit. "Signed" is never gpgsig
// here — no real signer is under test — it is that the run's ledger
// separately carries a commit_recorded naming the SAME sha this call
// produces, which is all this pass ever reads to decide the question.
func gitSignedCommit(t *testing.T) (result, sha string) {
	t.Helper()
	dir, env := commitWatchRepo(t)
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("one\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	commitWatchMustGit(t, dir, env, "add", "a.txt")
	out, err := commitWatchRunGit(t, dir, env,
		"-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
		"commit", "-m", "innsegl commitwatch test: signed")
	if err != nil {
		t.Fatalf("git commit: %v\n%s", err, out)
	}
	sha = strings.TrimSpace(commitWatchMustGit(t, dir, env, "rev-parse", "HEAD"))
	return out, sha
}

// ---------------------------------------------------------------------------
// Seeding the in-memory chain and the body store.
// ---------------------------------------------------------------------------

// plantCommitWatchBody writes raw where the pass will look for it — the SAME
// (run, digest) layout readRunBody reads (writes.go) — and returns the
// digest the chain must carry.
func plantCommitWatchBody(t *testing.T, dir, runID string, raw []byte) string {
	t.Helper()
	digest := event.Digest(raw)
	hex := strings.TrimPrefix(digest, event.HashPrefix)
	if err := os.MkdirAll(filepath.Join(dir, runID), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, runID, hex+".json"), raw, 0o644); err != nil {
		t.Fatalf("writing the body: %v", err)
	}
	return digest
}

// commitWatchPlant writes one Bash tool_call body — internal/gateway/
// record.go's own gatewayToolCallBody shape, field for field — and appends
// the matching tool_call event. Returns the event_id.
func commitWatchPlant(
	t *testing.T, m *memLedger, dir, runID, command, resultText string, isError bool,
) string {
	t.Helper()
	inputRaw, err := json.Marshal(map[string]any{"command": command})
	if err != nil {
		t.Fatal(err)
	}
	resultRaw, err := json.Marshal(resultText)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{
		"tool":            "Bash",
		"input":           json.RawMessage(inputRaw),
		"result_observed": true,
		"result":          json.RawMessage(resultRaw),
		"is_error":        isError,
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := plantCommitWatchBody(t, dir, runID, raw)

	record, aerr := m.Append(context.Background(), event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeToolCall,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          runID,
		event.FieldSpiffeID:       spiffeIDFor(runID),
		event.FieldIdempotencyKey: "tool/" + runID + "/" + digest[7:19],
		event.FieldToolName:       "Bash",
		event.FieldPayloadDigest:  digest,
	})
	if aerr != nil {
		t.Fatalf("seed tool_call: %v", aerr)
	}
	return str(record, event.FieldEventID)
}

// commitWatchSeedRecorded appends a commit_recorded naming sha on runID —
// what makes a shown commit "signed" as far as this pass is concerned.
func commitWatchSeedRecorded(t *testing.T, m *memLedger, runID, sha string) {
	t.Helper()
	if _, err := m.Append(context.Background(), event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeCommitRecorded,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          runID,
		event.FieldSpiffeID:       spiffeIDFor(runID),
		event.FieldIdempotencyKey: "sign_commit/recorded/" + runID,
		event.FieldRepo:           testRepo,
		event.FieldTreeHash:       testTree,
		event.FieldPatchID:        strings.Repeat("e", 40),
		event.FieldCommitSHA:      sha,
		event.FieldIntentEventID:  "01a047a5-cc41-7c45-86fd-a88c8c2b5320",
		event.FieldRekorEntryUUID: strings.Repeat("d", 64),
		event.FieldRekorLogIndex:  int64(1),
	}); err != nil {
		t.Fatalf("seed commit_recorded: %v", err)
	}
}

// runCommitWatchPass builds a reconciler with only CommitWatch configured and
// runs one cycle.
func runCommitWatchPass(t *testing.T, m *memLedger, logDir string) reconciler.CommitWatchReport {
	t.Helper()
	r, err := reconciler.New(reconciler.Config{
		Ledger:      m,
		Appender:    m,
		Repos:       &fakeRepos{},
		Log:         &fakeLog{entries: map[string]reconciler.LogEntry{}},
		TrustDomain: testTrustDomain,
		Now:         rebaseClock,
		Alert:       func(context.Context, reconciler.Finding) {},
		Observe:     func(reconciler.Result, error) {},
		CommitWatch: &reconciler.CommitWatchConfig{LogDir: logDir},
	})
	if err != nil {
		t.Fatalf("reconciler.New: %v", err)
	}
	result, err := r.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	return result.CommitWatch
}

// ---------------------------------------------------------------------------
// CMT-017.
// ---------------------------------------------------------------------------

// TestCMT017NoCommitAndASignedCommitRaiseNoAlert is CMT-017: a git commit
// tool call that made no commit — nothing to commit, refused by a hook, lost
// the ref lock — and one whose commit WAS signed, raise nothing. Every
// scenario's `result` text is what a REAL git subprocess printed; none is
// written by hand.
func TestCMT017NoCommitAndASignedCommitRaiseNoAlert(t *testing.T) {
	const runID = "run-cmt-017"

	noCommitCases := []struct {
		name    string
		capture func(t *testing.T) (string, bool)
	}{
		{"nothing to commit", gitNothingToCommit},
		{"refused by a hook", gitHookRefusal},
		{"lost the ref lock", gitLostTheRefLock},
	}

	for _, tc := range noCommitCases {
		t.Run(tc.name, func(t *testing.T) {
			result, isError := tc.capture(t)
			t.Logf("captured git output (%s), is_error=%v:\n%s", tc.name, isError, result)

			m := newMemLedger(rebaseClock)
			seedRun(t, m, runID)
			logDir := t.TempDir()
			commitWatchPlant(t, m, logDir, runID, bypassCommand, result, isError)

			report := runCommitWatchPass(t, m, logDir)
			if !report.Enabled {
				t.Fatal("the pass reported itself disabled with a CommitWatchConfig given")
			}
			if report.Checked != 1 {
				t.Errorf("checked %d, want 1", report.Checked)
			}
			if report.Unchecked != 0 {
				t.Errorf("unchecked %d, want 0 — a readable, untruncated body with an "+
					"observed result must be judged, not set aside", report.Unchecked)
			}
			if report.Signed != 1 {
				t.Errorf("signed %d, want 1 — no commit-summary line means a definite "+
					"verdict of nothing to alert on", report.Signed)
			}
			if report.Unsigned != 0 {
				t.Errorf("unsigned %d, want 0: %+v", report.Unsigned, report.Findings)
			}
			if len(report.Appended) != 0 {
				t.Errorf("appended %v, want none", report.Appended)
			}
		})
	}

	t.Run("a commit that was signed", func(t *testing.T) {
		result, sha := gitSignedCommit(t)
		t.Logf("captured git output (signed), commit %s:\n%s", sha, result)

		m := newMemLedger(rebaseClock)
		seedRun(t, m, runID)
		logDir := t.TempDir()
		commitWatchPlant(t, m, logDir, runID, bypassCommand, result, false)
		commitWatchSeedRecorded(t, m, runID, sha)

		report := runCommitWatchPass(t, m, logDir)
		if report.Checked != 1 {
			t.Errorf("checked %d, want 1", report.Checked)
		}
		if report.Signed != 1 {
			t.Errorf("signed %d, want 1", report.Signed)
		}
		if report.Unsigned != 0 {
			t.Errorf("unsigned %d, want 0: %+v", report.Unsigned, report.Findings)
		}
		if len(report.Appended) != 0 {
			t.Errorf("appended %v, want none", report.Appended)
		}
	})
}

// ---------------------------------------------------------------------------
// Behaviour CMT-017 does not name but this pass must still hold: bodies it
// cannot read are never a finding.
// ---------------------------------------------------------------------------

// TestCommitWatchNeverAlertsOnWhatItCannotRead covers the Unchecked paths: no
// body on disk, a truncated result, a truncated input, and a tool_use whose
// result was never observed at all. None of these says a commit was made
// without one; all of them are counted, never alerted on.
func TestCommitWatchNeverAlertsOnWhatItCannotRead(t *testing.T) {
	const runID = "run-cmt-unchecked"

	cases := []struct {
		name string
		body map[string]any
		// plant is false for the "missing body" case: the tool_call names a
		// digest nothing on disk answers to.
		plant bool
	}{
		{
			name: "no body on disk",
			body: map[string]any{
				"tool": "Bash", "input": map[string]any{"command": bypassCommand},
				"result_observed": true, "result": "[main abc1234] x",
			},
			plant: false,
		},
		{
			name: "result truncated",
			body: map[string]any{
				"tool": "Bash", "input": map[string]any{"command": bypassCommand},
				"result_observed": true, "result_truncated": true,
			},
			plant: true,
		},
		{
			name: "input truncated",
			body: map[string]any{
				"tool": "Bash", "input_truncated": true,
				"result_observed": true, "result": "[main abc1234] x",
			},
			plant: true,
		},
		{
			name: "result never observed (evicted)",
			body: map[string]any{
				"tool": "Bash", "input": map[string]any{"command": bypassCommand},
				"result_observed": false,
			},
			plant: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newMemLedger(rebaseClock)
			seedRun(t, m, runID)
			logDir := t.TempDir()

			raw, err := json.Marshal(tc.body)
			if err != nil {
				t.Fatal(err)
			}
			var digest string
			if tc.plant {
				digest = plantCommitWatchBody(t, logDir, runID, raw)
			} else {
				digest = event.Digest(raw) // named, never written to logDir
			}
			record, aerr := m.Append(context.Background(), event.Fields{
				event.FieldSchemaVersion:  event.SchemaVersion,
				event.FieldEventType:      event.EventTypeToolCall,
				event.FieldSource:         event.SourceMCP,
				event.FieldRunID:          runID,
				event.FieldSpiffeID:       spiffeIDFor(runID),
				event.FieldIdempotencyKey: "tool/" + runID + "/" + digest[7:19],
				event.FieldToolName:       "Bash",
				event.FieldPayloadDigest:  digest,
			})
			if aerr != nil {
				t.Fatalf("seed tool_call: %v", aerr)
			}
			_ = record

			report := runCommitWatchPass(t, m, logDir)
			if report.Unchecked != 1 {
				t.Errorf("unchecked %d, want 1", report.Unchecked)
			}
			if report.Checked != 0 || report.Signed != 0 || report.Unsigned != 0 {
				t.Errorf("checked=%d signed=%d unsigned=%d, want all zero — nothing here "+
					"was read, so nothing here may be judged",
					report.Checked, report.Signed, report.Unsigned)
			}
			if len(report.Appended) != 0 {
				t.Errorf("appended %v, want none", report.Appended)
			}
		})
	}
}

// TestCommitWatchConfigWithNoLogDirIsRefused is DriftConfig.validate's own
// discipline (drift.go), held here: a half-configured detector is refused
// rather than silently reporting agreement it never checked.
func TestCommitWatchConfigWithNoLogDirIsRefused(t *testing.T) {
	_, err := reconciler.New(reconciler.Config{
		Ledger: newMemLedger(rebaseClock), Appender: newMemLedger(rebaseClock),
		Repos: &fakeRepos{}, Log: &fakeLog{entries: map[string]reconciler.LogEntry{}},
		TrustDomain: testTrustDomain,
		CommitWatch: &reconciler.CommitWatchConfig{},
	})
	if err == nil {
		t.Fatal("reconciler.New accepted a CommitWatchConfig with no LogDir")
	}
}

// TestCommitWatchIsOffAndSaysSoWhenNotConfigured is the same discipline
// Result.Drift.Enabled and Result.Writes.Enabled hold: a reader must never
// mistake "not run" for "nothing to find".
func TestCommitWatchIsOffAndSaysSoWhenNotConfigured(t *testing.T) {
	m := newMemLedger(rebaseClock)
	r, err := reconciler.New(reconciler.Config{
		Ledger: m, Appender: m, Repos: &fakeRepos{},
		Log: &fakeLog{entries: map[string]reconciler.LogEntry{}}, TrustDomain: testTrustDomain,
	})
	if err != nil {
		t.Fatalf("reconciler.New: %v", err)
	}
	result, err := r.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.CommitWatch.Enabled {
		t.Fatal("CommitWatch reported itself enabled with no CommitWatchConfig given")
	}
}
