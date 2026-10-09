// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// ADP-009, re-homed (ADR-0079): the shipped evidence reads a commit's change
// from its own tree and parent, byte for byte, and the parent's blobs an Edit
// is replayed on.

func TestADP009OnTheCommitPathTheChangeIsTheTreesBytesExactly(t *testing.T) {
	dir := t.TempDir()
	scGit(t, dir, "init", "-q", "-b", "main")
	scStage(t, dir, "kept.txt", "kept\n")
	scStage(t, dir, "edited.txt", "before\n")
	scGit(t, dir, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "base")
	parent := scGit(t, dir, "rev-parse", "HEAD")
	scStage(t, dir, "edited.txt", "after\r\nno final newline")
	scStage(t, dir, "new.txt", "new\n")
	tree := scGit(t, dir, "write-tree")

	a := LedgerAdoption{}
	got, err := a.ChangedFiles(t.Context(), dir, tree, parent)
	if err != nil {
		t.Fatalf("ChangedFiles: %v", err)
	}
	if len(got) != 2 || string(got["edited.txt"]) != "after\r\nno final newline" || string(got["new.txt"]) != "new\n" {
		t.Errorf("changed = %q, want exactly the two changed paths, byte for byte", got)
	}

	// A root commit's change is everything in its tree.
	root, err := a.ChangedFiles(t.Context(), dir, tree, "")
	if err != nil || len(root) != 3 {
		t.Errorf("a root commit's change = %d paths, %v; want all three", len(root), err)
	}

	b, ok, err := a.ParentFile(t.Context(), dir, parent, "edited.txt")
	if err != nil || !ok || string(b) != "before\n" {
		t.Errorf("ParentFile(edited.txt) = %q, %v, %v; want the parent's bytes", b, ok, err)
	}
	if _, ok, err = a.ParentFile(t.Context(), dir, parent, "new.txt"); ok || err != nil {
		t.Errorf("a path the parent does not hold = %v, %v; want absent, no error", ok, err)
	}
	if _, ok, err = a.ParentFile(t.Context(), dir, "", "edited.txt"); ok || err != nil {
		t.Errorf("no parent = %v, %v; want absent", ok, err)
	}
}

func TestADP009OnTheCommitPathADeletionCannotBeAdopted(t *testing.T) {
	dir := t.TempDir()
	scGit(t, dir, "init", "-q", "-b", "main")
	scStage(t, dir, "gone.txt", "g\n")
	scGit(t, dir, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "base")
	parent := scGit(t, dir, "rev-parse", "HEAD")
	scGit(t, dir, "rm", "-q", "gone.txt")
	scStage(t, dir, "other.txt", "o\n")
	tree := scGit(t, dir, "write-tree")
	if _, err := (LedgerAdoption{}).ChangedFiles(t.Context(), dir, tree, parent); err == nil ||
		!strings.Contains(err.Error(), "gone.txt") {
		t.Errorf("err = %v, want the deletion refused by name", err)
	}
	for _, fail := range []string{"--diff-filter=D", "-z", "cat-file"} {
		if _, err := (LedgerAdoption{GitPath: fakeGitFailing(t, fail)}).ChangedFiles(t.Context(), dir, tree, parent); err == nil {
			t.Errorf("git failing on %s still answered a change", fail)
		}
	}
}

type deadRunsFake struct {
	runs []string
	err  error
}

func (d deadRunsFake) DeadRunsForRepo(context.Context, string, time.Time, int) ([]string, error) {
	return d.runs, d.err
}

func TestADP009OnTheCommitPathTheCandidatesAreTheLedgers(t *testing.T) {
	ctx := t.Context()
	if got, err := (LedgerAdoption{}).DeadRuns(ctx, "r", time.Now(), 1); err != nil || got != nil {
		t.Errorf("no candidate source = %v, %v; want none", got, err)
	}
	a := LedgerAdoption{Candidates: deadRunsFake{runs: []string{"run-a"}}}
	if got, err := a.DeadRuns(ctx, "r", time.Now(), 1); err != nil || !slices.Equal(got, []string{"run-a"}) {
		t.Errorf("DeadRuns = %v, %v", got, err)
	}
	a.Candidates = deadRunsFake{err: errors.New("down")}
	if _, err := a.DeadRuns(ctx, "r", time.Now(), 1); err == nil {
		t.Error("a ledger that cannot be read answered candidates")
	}
}
