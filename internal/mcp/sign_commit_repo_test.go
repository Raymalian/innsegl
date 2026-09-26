// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"os/exec"
	"strings"
	"testing"
)

// RM-188 (#308): a run is registered for one repository, and sign_commit signs
// only in that one. I2: an identity attributes only the work it was issued for.

const rm188OtherRepo = "github.com/innsegl/elsewhere"

// rm188Run is the fixture run with a registered repository, as a run
// registered under schema 2 carries.
func rm188Run(repo string) CredentialRun {
	run := scRun()
	run.Repo = repo
	return run
}

func TestRM188SignCommitRefusesARepositoryTheRunWasNotRegisteredFor(t *testing.T) {
	w := newSCWiring()
	w.runs.run = rm188Run(scRepo)

	in := scIn()
	in.Repo = rm188OtherRepo
	_, err := w.call(t, in)

	e := requireClassed(t, err, ClassInvariantViolation)
	for _, name := range []string{scRepo, rm188OtherRepo} {
		if !strings.Contains(e.Message, name) {
			t.Errorf("the refusal does not name %q: %s", name, e.Message)
		}
	}
	if got := len(w.ledger.records); got != 0 {
		t.Errorf("%d events were appended for a repository the run was not registered for", got)
	}
	if w.signer.calls != 0 {
		t.Errorf("the signer was reached %d times for a repository the run was not registered for", w.signer.calls)
	}
}

// The control: the run's own repository still signs.
func TestRM188SignCommitSignsInTheRunsOwnRepository(t *testing.T) {
	w := newSCWiring()
	w.runs.run = rm188Run(scRepo)

	if _, err := w.call(t, scIn()); err != nil {
		t.Fatalf("the run's own repository was refused: %v", err)
	}
	if w.signer.calls != 1 {
		t.Errorf("the signer was reached %d times, want 1", w.signer.calls)
	}
}

// A run registered under schema 1 recorded no repository; it keeps the
// behaviour it had before RM-188.
func TestRM188SignCommitKeepsSchema1RunsWithNoRepository(t *testing.T) {
	w := newSCWiring()
	w.runs.run = rm188Run("")

	in := scIn()
	in.Repo = rm188OtherRepo
	if _, err := w.call(t, in); err != nil {
		t.Fatalf("a run with no recorded repository was refused: %v", err)
	}
}

// The repository derived from `worktree` (#199) is compared in the same
// spelling the registration recorded: a remote written with an uppercase host,
// a scheme and a `.git` suffix is still the run's own repository, and a remote
// for another repository is still refused.
func TestRM188SignCommitComparesTheRepositoryDerivedFromTheWorktree(t *testing.T) {
	for _, tc := range []struct {
		name   string
		origin string
		refuse bool
	}{
		{"the run's own repository", "https://GitHub.com/innsegl/innsegl.git", false},
		{"the run's own repository over ssh", "git@github.com:innsegl/innsegl.git", false},
		{"another repository", "https://github.com/innsegl/elsewhere.git", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, args := range [][]string{
				{"init", "-q", dir},
				{"-C", dir, "remote", "add", "origin", tc.origin},
			} {
				if out, err := exec.CommandContext(t.Context(), "git", args...).CombinedOutput(); err != nil {
					t.Fatalf("git %v: %v\n%s", args, err, out)
				}
			}

			w := newSCWiring()
			w.runs.run = rm188Run(scRepo)

			in := scIn()
			in.Repo = ""
			in.Worktree = dir
			filled, err := fillFromWorktree(t.Context(), in, nil)
			if err != nil {
				t.Fatalf("fillFromWorktree: %v", err)
			}

			_, err = w.call(t, filled)
			if tc.refuse {
				requireClass(t, err, ClassInvariantViolation)
				if got := len(w.ledger.records); got != 0 {
					t.Errorf("%d events were appended for another repository", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("the derived repository %q was refused: %v", filled.Repo, err)
			}
		})
	}
}
