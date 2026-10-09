// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"errors"
	"slices"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
)

// ADP-020 (PROPOSED for doc 07) — the runs a commit may adopt from, read off
// a real chain (ADR-0079 decision 3).
//
// The candidates are the runs registered for the committing run's repository
// that the ledger does not call active, whose last activity is inside the
// window, most recent first and capped. The read is a prefilter: each
// candidate's state is asked again, the one way every tool asks it, before
// anything is proved against it.
func TestADP020DeadRunsForRepoAreTheRepositorysEndedRunsMostRecentFirst(t *testing.T) {
	s, _ := newStore(t)
	ctx := testCtx(t, 60*time.Second)
	const repo = "example.test/org/name"
	n := 0
	appendAll := func(bodies ...event.Fields) {
		t.Helper()
		for _, b := range bodies {
			if _, err := s.Append(ctx, b); err != nil {
				t.Fatalf("append %v: %v", b[event.FieldEventType], err)
			}
		}
	}
	registered := func(runID, inRepo string) event.Fields {
		n++
		b := childBody(runID, "", n)
		b[event.FieldRepo] = inRepo
		return b
	}
	toolCall := func(runID string) event.Fields {
		n++
		return runScopedBody(runID, event.EventTypeToolCall, n)
	}
	withdrawn := func(runID string) event.Fields {
		n++
		b := runScopedBody(runID, event.EventTypeRunExpired, n)
		b[event.FieldSource] = event.SourceReaper
		return b
	}

	// Oldest first: retired, then lapsed, then a run still working, then a
	// retired run of another repository.
	appendAll(registered("run-retired", repo), toolCall("run-retired"),
		runScopedBody("run-retired", event.EventTypeRunRetired, 0))
	appendAll(registered("run-lapsed", repo), toolCall("run-lapsed"), withdrawn("run-lapsed"))
	appendAll(registered("run-active", repo), toolCall("run-active"))
	appendAll(registered("run-elsewhere", "example.test/org/other"), toolCall("run-elsewhere"),
		runScopedBody("run-elsewhere", event.EventTypeRunRetired, 0))
	// A run withdrawn and then heard from again is active, not lapsed.
	appendAll(registered("run-back", repo), withdrawn("run-back"), toolCall("run-back"))

	since := time.Now().Add(-time.Hour)
	got, err := s.DeadRunsForRepo(ctx, repo, since, 10)
	if err != nil {
		t.Fatalf("DeadRunsForRepo: %v", err)
	}
	if want := []string{"run-lapsed", "run-retired"}; !slices.Equal(got, want) {
		t.Errorf("got %v, want %v: the repository's ended runs, most recent first", got, want)
	}

	if got, err = s.DeadRunsForRepo(ctx, repo, since, 1); err != nil || !slices.Equal(got, []string{"run-lapsed"}) {
		t.Errorf("capped at one = %v, %v; want only the most recent", got, err)
	}
	if got, err = s.DeadRunsForRepo(ctx, repo, time.Now().Add(time.Hour), 10); err != nil || len(got) != 0 {
		t.Errorf("a window no run was active in = %v, %v; want none", got, err)
	}
	if got, err = s.DeadRunsForRepo(ctx, "example.test/org/none", since, 10); err != nil || len(got) != 0 {
		t.Errorf("a repository with no runs = %v, %v; want none", got, err)
	}

	var se *StoreError
	if _, err = s.DeadRunsForRepo(ctx, "", since, 10); !errors.As(err, &se) || se.Class != ClassInvariantViolation {
		t.Errorf("an empty repository = %v, want INVARIANT_VIOLATION", err)
	}
	if _, err = s.DeadRunsForRepo(ctx, repo, since, 0); !errors.As(err, &se) || se.Class != ClassInvariantViolation {
		t.Errorf("a cap of zero = %v, want INVARIANT_VIOLATION", err)
	}
}
