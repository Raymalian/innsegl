// SPDX-License-Identifier: Apache-2.0

package reconciler_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/reconciler"
)

// REC-009 through REC-011 (proposed for doc 07; doc 07 is not modified here) —
// RM-122, #194, ADR-0047 decision 4.
//
// # What is broken without this
//
// After a merge the commit on `main` has a new SHA and the ledger has the old
// one, so every lookup by SHA fails — the dashboard's Verify page, the proof
// API, `innsegl verify`. The content is still findable by patch id (#193), but
// finding it means recomputing a patch id for every candidate on every read.
//
// ADR-0047 decision 4: "the reconciler walks the branch, computes each
// commit's patch-id, and on a match appends a SUPERSEDING `commit_recorded`
// carrying the new SHA. doc 02 §2's `supersedes` exists for exactly this and
// `segment_sealed` already uses it for anchoring; the original event is never
// modified (I4). This makes lookup by SHA work again, and turns the rewrite
// into a recorded fact rather than an inference."
//
// # It records, it does not assert
//
// The match is one any reader can recompute from the repository. That is the
// difference between a claim and a receipt, and it is why this pass is allowed
// to write at all.

// rebaseRepo is a repository the pass walks.
type rebaseRepo struct {
	commits []reconciler.RepoCommit
	err     error
	walked  []string
}

func (r *rebaseRepo) SignedCommitsWithTree(context.Context, string, string) ([]string, error) {
	return nil, nil
}

func (r *rebaseRepo) TreeBlobs(context.Context, string, string) (map[string]struct{}, error) {
	return nil, nil
}

func (r *rebaseRepo) CommitsOnBranch(_ context.Context, repo, branch string) ([]reconciler.RepoCommit, error) {
	r.walked = append(r.walked, repo+"@"+branch)
	if r.err != nil {
		return nil, r.err
	}
	return r.commits, nil
}

// TestREC009ARebasedCommitGetsASupersedingRecord.
func TestREC009ARebasedCommitGetsASupersedingRecord(t *testing.T) {
	const (
		patch   = "5e4c6c1f0a2d9b3e8f7a1c4d6b0e9f2a3c5d7e81"
		oldSHA  = "1111111111111111111111111111111111111111"
		newSHA  = "2222222222222222222222222222222222222222"
		theRun  = "run-42"
		theRepo = "github.com/acme/api"
	)
	m := newMemLedger(rebaseClock)
	seedRun(t, m, theRun)
	recorded := seedRecorded(t, m, theRun, theRepo, patch, oldSHA)

	repos := &rebaseRepo{commits: []reconciler.RepoCommit{{
		SHA:     newSHA,
		PatchID: patch,
		RunID:   theRun,
	}}}

	report, err := runRebasePass(t, m, repos, theRepo)
	if err != nil {
		t.Fatalf("the rebase pass failed: %v", err)
	}
	if report.Recorded != 1 {
		t.Fatalf("recorded %d supersessions, want 1: %+v", report.Recorded, report)
	}

	sup := supersedingFor(t, m, newSHA)
	if got := sup[event.FieldSupersedes]; got != recorded {
		t.Errorf("supersedes = %v, want the original event %s; the record has to point "+
			"at what it corrects or it is a second answer rather than a correction",
			got, recorded)
	}
	if got := sup[event.FieldRunID]; got != theRun {
		t.Errorf("run_id = %v, want %s: the rewrite does not change who made the change",
			got, theRun)
	}
	if got := sup[event.FieldPatchID]; got != patch {
		t.Errorf("patch_id = %v, want %s: it is the join between the two records", got, patch)
	}
	if got := sup[event.FieldSource]; got != event.SourceReconciler {
		t.Errorf("source = %v, want %s (doc 02 §3)", got, event.SourceReconciler)
	}

	// I4: the original is untouched.
	original := eventByID(t, m, recorded)
	if got := original[event.FieldCommitSHA]; got != oldSHA {
		t.Errorf("the original record now says commit_sha %v; I4 forbids modifying it, "+
			"and a superseding event exists precisely so it need not be", got)
	}

	t.Run("a second pass appends nothing", func(t *testing.T) {
		before := len(m.records)
		again, err := runRebasePass(t, m, repos, theRepo)
		if err != nil {
			t.Fatalf("second pass: %v", err)
		}
		if again.Recorded != 0 {
			t.Errorf("the second pass recorded %d supersessions; the chain would then "+
				"carry one per cycle, forever", again.Recorded)
		}
		if now := len(m.records); now != before {
			t.Errorf("the chain grew from %d to %d events on a repeat", before, now)
		}
	})
}

// TestREC010ItMatchesOnTheChangeAndTheRunTogether is #193's rule applied to the
// write side, where getting it wrong is worse: a wrong read gives a wrong
// answer once, and a wrong write puts it in the chain forever.
func TestREC010ItMatchesOnTheChangeAndTheRunTogether(t *testing.T) {
	const (
		patch   = "5e4c6c1f0a2d9b3e8f7a1c4d6b0e9f2a3c5d7e81"
		oldSHA  = "1111111111111111111111111111111111111111"
		newSHA  = "2222222222222222222222222222222222222222"
		theRepo = "github.com/acme/api"
	)

	t.Run("the right change, claimed by another run", func(t *testing.T) {
		m := newMemLedger(rebaseClock)
		seedRun(t, m, "run-42")
		seedRecorded(t, m, "run-42", theRepo, patch, oldSHA)
		repos := &rebaseRepo{commits: []reconciler.RepoCommit{{
			SHA: newSHA, PatchID: patch, RunID: "run-impostor",
		}}}

		report, err := runRebasePass(t, m, repos, theRepo)
		if err != nil {
			t.Fatalf("the rebase pass failed: %v", err)
		}
		if report.Recorded != 0 {
			t.Error("a supersession was recorded for a commit claiming a run that never " +
				"made the change; patch id alone cannot say who, and this writes the " +
				"answer into an append-only chain")
		}
	})

	t.Run("the right run, on a change it never made", func(t *testing.T) {
		m := newMemLedger(rebaseClock)
		seedRun(t, m, "run-42")
		seedRecorded(t, m, "run-42", theRepo, patch, oldSHA)
		repos := &rebaseRepo{commits: []reconciler.RepoCommit{{
			SHA: newSHA, PatchID: strings.Repeat("f", 40), RunID: "run-42",
		}}}

		report, err := runRebasePass(t, m, repos, theRepo)
		if err != nil {
			t.Fatalf("the rebase pass failed: %v", err)
		}
		if report.Recorded != 0 {
			t.Error("a supersession was recorded for a change no run made")
		}
	})
}

// TestREC011WhatItLeavesAlone. A pass that writes to an append-only chain has
// to be quiet about everything it is not certain of.
func TestREC011WhatItLeavesAlone(t *testing.T) {
	const (
		patch   = "5e4c6c1f0a2d9b3e8f7a1c4d6b0e9f2a3c5d7e81"
		sha     = "1111111111111111111111111111111111111111"
		theRepo = "github.com/acme/api"
	)

	t.Run("the commit the ledger already holds", func(t *testing.T) {
		// Not a rewrite: the same SHA, still on the branch. A supersession here
		// would record that a commit was replaced by itself.
		m := newMemLedger(rebaseClock)
		seedRun(t, m, "run-42")
		seedRecorded(t, m, "run-42", theRepo, patch, sha)
		repos := &rebaseRepo{commits: []reconciler.RepoCommit{{SHA: sha, PatchID: patch, RunID: "run-42"}}}

		report, err := runRebasePass(t, m, repos, theRepo)
		if err != nil {
			t.Fatalf("the rebase pass failed: %v", err)
		}
		if report.Recorded != 0 {
			t.Error("a supersession was recorded for a commit that was never rewritten")
		}
	})

	t.Run("a squashed branch matches nothing, and says so", func(t *testing.T) {
		// Squash writes ONE commit whose diff is every change at once, so its
		// patch id is a change no run ever made. ADR-0047: squash "is the only
		// operation that severs the link completely, and nothing recovers it".
		m := newMemLedger(rebaseClock)
		seedRun(t, m, "run-42")
		seedRecorded(t, m, "run-42", theRepo, patch, sha)
		repos := &rebaseRepo{commits: []reconciler.RepoCommit{{
			SHA:     "3333333333333333333333333333333333333333",
			PatchID: strings.Repeat("9", 40),
			RunID:   "run-42",
		}}}

		report, err := runRebasePass(t, m, repos, theRepo)
		if err != nil {
			t.Fatalf("the rebase pass failed: %v", err)
		}
		if report.Recorded != 0 {
			t.Errorf("recorded %d supersessions for a squashed branch", report.Recorded)
		}
		if report.Unmatched != 1 {
			t.Errorf("Unmatched = %d, want 1: a commit claiming a run whose change is "+
				"nowhere on the branch is a finding, not silence", report.Unmatched)
		}
	})

	t.Run("a repository it cannot read is reported, never expired", func(t *testing.T) {
		m := newMemLedger(rebaseClock)
		seedRun(t, m, "run-42")
		seedRecorded(t, m, "run-42", theRepo, patch, sha)
		repos := &rebaseRepo{err: errors.New("no such remote")}

		report, err := runRebasePass(t, m, repos, theRepo)
		if err != nil {
			t.Fatalf("an unreadable repository failed the whole pass: %v", err)
		}
		if len(report.Unreadable) != 1 {
			t.Errorf("Unreadable = %v, want the one repository that could not be read; "+
				"a pass that went quiet would look like a branch with no rewrites",
				report.Unreadable)
		}
		if report.Recorded != 0 {
			t.Error("something was recorded from a repository that could not be read")
		}
	})
}

// seedRecorded appends a `commit_recorded` and returns its event id: the
// original record a rewrite later supersedes.
func seedRecorded(t *testing.T, m *memLedger, runID, repo, patchID, sha string) string {
	t.Helper()
	record, err := m.Append(context.Background(), event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeCommitRecorded,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          runID,
		event.FieldSpiffeID:       spiffeIDFor(runID),
		event.FieldIdempotencyKey: "sign_commit/recorded/" + runID + "/" + sha[:8],
		event.FieldRepo:           repo,
		event.FieldTreeHash:       strings.Repeat("a", 40),
		event.FieldPatchID:        patchID,
		event.FieldCommitSHA:      sha,
		event.FieldIntentEventID:  "01a047a5-cc41-7c45-86fd-a88c8c2b5320",
		event.FieldRekorEntryUUID: strings.Repeat("d", 64),
		event.FieldRekorLogIndex:  int64(1),
	})
	if err != nil {
		t.Fatalf("seed commit_recorded: %v", err)
	}
	return str(record, event.FieldEventID)
}

// supersedingFor returns the superseding record naming a commit SHA.
func supersedingFor(t *testing.T, m *memLedger, sha string) event.Fields {
	t.Helper()
	for _, rec := range m.records {
		if str(rec, event.FieldEventType) != event.EventTypeCommitRecorded {
			continue
		}
		if str(rec, event.FieldCommitSHA) == sha && str(rec, event.FieldSupersedes) != "" {
			return rec
		}
	}
	t.Fatalf("no superseding commit_recorded names %s", sha)
	return nil
}

// eventByID returns one stored event.
func eventByID(t *testing.T, m *memLedger, id string) event.Fields {
	t.Helper()
	for _, rec := range m.records {
		if str(rec, event.FieldEventID) == id {
			return rec
		}
	}
	t.Fatalf("no event %s", id)
	return nil
}

// rebaseClock is the fixed clock these cases run against. Fixed rather than
// time.Now, because a pass that behaved differently at different times of day
// would be a pass nobody could reproduce.
func rebaseClock() time.Time { return time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC) }

// runRebasePass runs one reconciler cycle with ADR-0047's pass turned on and
// returns what it recorded.
//
// Through the public API rather than the unexported body, which is this
// package's convention for every other test and the reason it can be: a pass
// only reachable from inside is a pass whose wiring nothing checks.
func runRebasePass(t *testing.T, m *memLedger, repos reconciler.Repos, repoID string) (reconciler.RebaseReport, error) {
	t.Helper()
	r, err := reconciler.New(reconciler.Config{
		Ledger:      m,
		Appender:    m,
		Repos:       repos,
		Log:         &fakeLog{entries: map[string]reconciler.LogEntry{}},
		TrustDomain: testTrustDomain,
		Now:         rebaseClock,
		Alert:       func(context.Context, reconciler.Finding) {},
		Observe:     func(reconciler.Result, error) {},
		Rebase: &reconciler.RebaseConfig{
			Branch: "main",
			Repos:  []string{repoID},
		},
	})
	if err != nil {
		t.Fatalf("reconciler.New: %v", err)
	}
	result, err := r.Reconcile(context.Background())
	return result.Rebase, err
}
