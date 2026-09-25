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
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
)

// ADP-009 — the shipped SignCommitAdoption, ADR-0051, #298.
//
// Two reads, each against the real thing it stands for: the run's state
// through the same CredentialRun.State every other tool uses, and the staged
// bytes out of a real git index, byte for byte.

type adpRuns struct {
	run   CredentialRun
	found bool
	err   error
}

func (r adpRuns) CredentialRun(context.Context, string) (CredentialRun, bool, error) {
	return r.run, r.found, r.err
}

type adpEvents struct {
	events []event.Fields
	err    error
}

func (e adpEvents) EventsForRun(context.Context, string) ([]event.Fields, error) {
	return e.events, e.err
}

func (e adpEvents) AdoptionsOf(context.Context, string) ([]ledger.Adoption, error) {
	return []ledger.Adoption{{EventID: "e"}}, e.err
}

func adpGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", append([]string{"-C", dir}, args...)...)
	cmd.Env = signCommitGitEnv(dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
	}
}

func adpRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	adpGit(t, dir, "init", "-q")
	adpGit(t, dir, "-c", "user.name=t", "-c", "user.email=t@innsegl.invalid",
		"commit", "-q", "--allow-empty", "-m", "root")
	return dir
}

func TestADP009TheLedgerAdoptionReadsTheRunsStateAndItsEvents(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	evs := []event.Fields{{event.FieldEventType: event.EventTypeToolCall}}
	retired := CredentialRun{RunID: "run-41", RetiredAt: now.Add(-time.Hour)}

	a := LedgerAdoption{Runs: adpRuns{run: retired, found: true}, Events: adpEvents{events: evs},
		Bodies: "/bodies", Now: func() time.Time { return now }}
	state, got, err := a.AdoptionEvidence(t.Context(), "run-41")
	if err != nil || state != "retired" || len(got) != 1 {
		t.Errorf("evidence = %q, %d events, %v; want retired, 1, nil", state, len(got), err)
	}
	if a.BodyDir() != "/bodies" {
		t.Errorf("BodyDir = %q", a.BodyDir())
	}
	if prior, perr := a.Adoptions(t.Context(), "run-41"); perr != nil || len(prior) != 1 {
		t.Errorf("Adoptions = %v, %v; want the ledger's answer passed through", prior, perr)
	}

	active := a
	active.Runs = adpRuns{run: CredentialRun{RunID: "run-41"}, found: true}
	if state, _, aerr := active.AdoptionEvidence(t.Context(), "run-41"); aerr != nil || state != "active" {
		t.Errorf("a run with no ending reads %q, %v; want active", state, aerr)
	}

	// No clock configured reads the real one: a run retired an hour before
	// the fixed clock is retired now too.
	realClock := a
	realClock.Now = nil
	if state, _, rerr := realClock.AdoptionEvidence(t.Context(), "run-41"); rerr != nil || state != "retired" {
		t.Errorf("with the real clock = %q, %v; want retired", state, rerr)
	}

	unknown := a
	unknown.Runs = adpRuns{}
	if state, got, err := unknown.AdoptionEvidence(t.Context(), "run-41"); state != "" || got != nil || err != nil {
		t.Errorf("an unknown run reads %q, %v, %v; want nothing", state, got, err)
	}

	for name, broken := range map[string]LedgerAdoption{
		"the run directory": {Runs: adpRuns{err: errors.New("down")}, Events: adpEvents{}},
		"the events":        {Runs: adpRuns{run: retired, found: true}, Events: adpEvents{err: errors.New("down")}},
	} {
		if _, _, err := broken.AdoptionEvidence(t.Context(), "run-41"); err == nil {
			t.Errorf("%s failing was not an error", name)
		}
	}
}

func TestADP009StagedFilesAreTheIndexBytesExactly(t *testing.T) {
	dir := adpRepo(t)
	content := "line one\r\nno trailing newline"
	if err := os.MkdirAll(filepath.Join(dir, "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pkg", "a.go"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	adpGit(t, dir, "add", "pkg/a.go")
	// Changed in the tree after staging: the index is what gets committed.
	if err := os.WriteFile(filepath.Join(dir, "pkg", "a.go"), []byte("unstaged\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := LedgerAdoption{}.StagedFiles(t.Context(), dir)
	if err != nil {
		t.Fatalf("StagedFiles: %v", err)
	}
	if len(got) != 1 || string(got["pkg/a.go"]) != content {
		t.Errorf("staged = %q, want exactly the index bytes of pkg/a.go", got)
	}
}

func TestADP009AStagedDeletionCannotBeAdopted(t *testing.T) {
	dir := adpRepo(t)
	if err := os.WriteFile(filepath.Join(dir, "gone.go"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	adpGit(t, dir, "add", "gone.go")
	adpGit(t, dir, "-c", "user.name=t", "-c", "user.email=t@innsegl.invalid", "commit", "-q", "-m", "add")
	adpGit(t, dir, "rm", "-q", "gone.go")

	if _, err := (LedgerAdoption{}).StagedFiles(t.Context(), dir); err == nil ||
		!strings.Contains(err.Error(), "gone.go") {
		t.Errorf("err = %v, want a staged deletion refused by name", err)
	}
	if _, err := (LedgerAdoption{}).StagedFiles(t.Context(), filepath.Join(dir, "no-such")); err == nil {
		t.Error("a directory that is not a repository was read")
	}
}

// fakeGitFailing is git, except that any call whose arguments contain fail
// exits non-zero.
func fakeGitFailing(t *testing.T, fail string) string {
	t.Helper()
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no git")
	}
	p := filepath.Join(t.TempDir(), "git")
	script := "#!/bin/sh\ncase \"$*\" in *'" + fail + "'*) echo refused >&2; exit 42 ;; esac\nexec " + gitBin + " \"$@\"\n"
	if err := os.WriteFile(p, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestADP009EveryGitFailureInStagedFilesAnswers(t *testing.T) {
	dir := adpRepo(t)
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte("a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	adpGit(t, dir, "add", "a.go")
	for name, fail := range map[string]string{
		"the staged paths cannot be listed": "--name-only -z",
		"a staged blob cannot be read":      "cat-file blob",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := (LedgerAdoption{GitPath: fakeGitFailing(t, fail)}).StagedFiles(t.Context(), dir); err == nil {
				t.Error("a failing git was read as an answer")
			}
		})
	}
}
