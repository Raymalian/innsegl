// SPDX-License-Identifier: Apache-2.0

package api

import (
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
)

// API-030 through API-033 (proposed for doc 07; doc 07 is not modified here).
//
// The four lifecycle states of #256, derived and never stored.
//
// # What these cases are actually holding down
//
// Three words could not tell a QUIET run from an OVER one, and the word they
// collapsed into read as death. Four words can, but only if each one is a
// consequence of recorded facts rather than a guess with better manners. So
// every case below states its run's whole record as events and asserts the
// word that falls out of them — and API-031 asserts the EVIDENCE beside the
// word, because a page that states a conclusion has to be able to state what
// it concluded from.
//
// # Why the horizon is swapped rather than the clock
//
// Lapsed and Abandoned are the same run. Nothing distinguishes them but one
// comparison between a recorded withdrawal and a horizon, and the ledger
// stamps `ts` itself (internal/ledger/postgres.go), so a test cannot backdate
// a withdrawal by thirty days without reaching into the ledger's own clock.
//
// It does not need to. Moving the HORIZON moves the same comparison, and doing
// it that way asserts something the other route would not: that the only thing
// standing between "restorable" and "abandoned" is a number this deployment
// chose — which is precisely why every response carries that number.

// horizonBeyondFixture is longer than any test's events are old, so every
// withdrawal in the fixture is still inside it.
const horizonBeyondFixture = 30 * 24 * time.Hour

// horizonAlreadyPassed is shorter than the age of any event that has already
// been appended, so every withdrawal in the fixture is outside it. A
// nanosecond rather than zero: zero means "no horizon at all", which is the
// third arm and is asserted separately.
const horizonAlreadyPassed = time.Nanosecond

// lifecycleFixture writes the four records the states are derived from and
// returns the read-only store.
//
//   - alive         registered, then working. Never withdrawn.
//   - resumed       registered, withdrawn, then working again.
//   - quiet         registered, withdrawn, and nothing since.
//   - ended         registered, retired, and then a straggling call.
//
// `ended` carries the straggler deliberately: a retirement is a decision
// somebody stated, so noise after it must not resurrect the run the way noise
// after a withdrawal does.
func lifecycleFixture(t *testing.T) *Store {
	t.Helper()
	owner, _, readerDSN := migrated(t)
	ctx := t.Context()

	mk := func(runID, eventType, source string) event.Fields {
		f := event.Fields{
			event.FieldEventType: eventType,
			event.FieldRunID:     runID,
			event.FieldSpiffeID:  "spiffe://innsegl.dev/agent/fix-ci/jira-1/" + runID,
			event.FieldSource:    source,
		}
		switch eventType {
		case event.EventTypeRunRegistered:
			// ADR-0004: only the registration carries a key. run_retired and
			// run_expired are refused outright if given one.
			f[event.FieldIdempotencyKey] = runID + "-register"
			f[event.FieldAgentType] = "fix-ci"
			f[event.FieldTaskRef] = "JIRA-1"
			f[event.FieldRepo] = "github.com/innsegl/one"
			f[event.FieldBranch] = "main"
		case event.EventTypeToolCall:
			f[event.FieldToolName] = "observe_tool_call"
			f[event.FieldIdempotencyKey] = runID + "-call"
		}
		return f
	}

	for _, run := range []struct {
		id    string
		steps []struct{ typ, src string }
	}{
		{"run-alive", []struct{ typ, src string }{
			{event.EventTypeRunRegistered, event.SourceMCP},
			{event.EventTypeToolCall, event.SourceMCP},
		}},
		{"run-resumed", []struct{ typ, src string }{
			{event.EventTypeRunRegistered, event.SourceMCP},
			{event.EventTypeRunExpired, event.SourceReaper},
			{event.EventTypeToolCall, event.SourceMCP},
		}},
		{"run-quiet", []struct{ typ, src string }{
			{event.EventTypeRunRegistered, event.SourceMCP},
			{event.EventTypeRunExpired, event.SourceReaper},
		}},
		{"run-ended", []struct{ typ, src string }{
			{event.EventTypeRunRegistered, event.SourceMCP},
			{event.EventTypeRunRetired, event.SourceMCP},
			{event.EventTypeToolCall, event.SourceMCP},
		}},
	} {
		for _, step := range run.steps {
			appendOrFail(ctx, t, owner, mk(run.id, step.typ, step.src))
		}
	}

	s, _ := readStore(t, readerDSN)
	return s
}

// statuses reads the four fixture runs out of one page.
func statuses(t *testing.T, s *Store) map[string]string {
	t.Helper()
	page, err := s.ListRuns(t.Context(), RunFilter{Limit: MaxPageSize})
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	got := map[string]string{}
	for _, r := range page.Runs {
		got[r.RunID] = r.Status
	}
	return got
}

// TestAPI030TheFourStatesFallOutOfTheRecord.
func TestAPI030TheFourStatesFallOutOfTheRecord(t *testing.T) {
	s := lifecycleFixture(t)

	t.Run("inside the horizon, a withdrawn run is lapsed", func(t *testing.T) {
		s.SetRestoreHorizon(horizonBeyondFixture)
		want := map[string]string{
			"run-alive":   StatusActive,
			"run-resumed": StatusActive,
			"run-quiet":   StatusLapsed,
			"run-ended":   StatusRetired,
		}
		got := statuses(t, s)
		for id, expect := range want {
			if got[id] != expect {
				t.Errorf("%s: status = %q, want %q", id, got[id], expect)
			}
		}
	})

	t.Run("past the horizon, the same run is abandoned", func(t *testing.T) {
		s.SetRestoreHorizon(horizonAlreadyPassed)
		want := map[string]string{
			// Unchanged: neither of these has a withdrawal that stands, so
			// the horizon is not a question their state can turn on.
			"run-alive":   StatusActive,
			"run-resumed": StatusActive,
			"run-quiet":   StatusAbandoned,
			"run-ended":   StatusRetired,
		}
		got := statuses(t, s)
		for id, expect := range want {
			if got[id] != expect {
				t.Errorf("%s: status = %q, want %q", id, got[id], expect)
			}
		}
	})

	t.Run("with no horizon, nothing is ever abandoned", func(t *testing.T) {
		// Zero is a setting a deployment can choose: a withdrawn run then
		// stays restorable until something retires it. It must not be reachable
		// by a typo, which is restoreHorizonFromEnv's job — and it must mean
		// this when it is chosen, which is this one's.
		s.SetRestoreHorizon(0)
		if got := statuses(t, s)["run-quiet"]; got != StatusLapsed {
			t.Errorf("with no horizon run-quiet reads %q, want %q — nothing can "+
				"be past a horizon that does not exist", got, StatusLapsed)
		}
	})

	t.Run("the four are the only words the filter accepts", func(t *testing.T) {
		s.SetRestoreHorizon(horizonBeyondFixture)
		for _, status := range RunStatuses {
			if _, err := s.ListRuns(t.Context(), RunFilter{Status: status}); err != nil {
				t.Errorf("ListRuns(status=%q): %v", status, err)
			}
		}
		// The word this replaced. It is the `run_expired` EVENT's name and
		// never a run's state, and a filter that still accepted it would be a
		// second vocabulary nobody maintains.
		for _, gone := range []string{"expired", "dead", "unknown", ""} {
			if gone == "" {
				continue
			}
			if _, err := s.ListRuns(t.Context(), RunFilter{Status: gone}); err == nil {
				t.Errorf("status=%q was accepted; the set is closed and reaches SQL", gone)
			}
		}
	})
}

// TestAPI031TheAnswerCarriesItsOwnEvidence.
//
// doc 06 P1: the claim and the material it rests on travel together. Every
// member asserted here is a recorded instant, a recorded id, or arithmetic
// over the two — there is nothing in the response that a reader has to take on
// this server's word.
func TestAPI031TheAnswerCarriesItsOwnEvidence(t *testing.T) {
	s := lifecycleFixture(t)
	s.SetRestoreHorizon(horizonBeyondFixture)
	ctx := t.Context()

	t.Run("a withdrawn run states when, and until when", func(t *testing.T) {
		d, err := s.Run(ctx, "run-quiet")
		if err != nil {
			t.Fatalf("Run(run-quiet): %v", err)
		}
		if d.Status != StatusLapsed {
			t.Fatalf("status = %q, want %q", d.Status, StatusLapsed)
		}
		if d.WithdrawnAt == nil {
			t.Fatal("a run reported lapsed carries no withdrawal instant; the page " +
				"would be stating a conclusion it cannot show the reason for")
		}
		if d.RestorableUntil == nil {
			t.Fatal("a lapsed run carries no restorable-until; 'lapsed' means " +
				"'restorable for now' and does not say until when")
		}
		if want := d.WithdrawnAt.Add(horizonBeyondFixture); !d.RestorableUntil.Equal(want) {
			t.Errorf("RestorableUntil = %s, want withdrawal + horizon = %s",
				d.RestorableUntil, want)
		}
		if d.RestoreHorizonSeconds != int64(horizonBeyondFixture.Seconds()) {
			t.Errorf("RestoreHorizonSeconds = %d, want %d — the horizon the answer "+
				"was computed with is the one fact that separates lapsed from abandoned",
				d.RestoreHorizonSeconds, int64(horizonBeyondFixture.Seconds()))
		}
		// The withdrawal stays in the timeline under its own name whatever the
		// state is called. The event is a protected string (doc 02 §3).
		var sawWithdrawal bool
		for _, e := range d.Timeline {
			if e.EventType == event.EventTypeRunExpired {
				sawWithdrawal = true
			}
		}
		if !sawWithdrawal {
			t.Error("the run_expired event is not in the timeline; renaming the STATE " +
				"must not remove the EVENT the state is derived from")
		}
	})

	t.Run("a run that came back states the lapse it came back from", func(t *testing.T) {
		d, err := s.Run(ctx, "run-resumed")
		if err != nil {
			t.Fatalf("Run(run-resumed): %v", err)
		}
		if d.Status != StatusActive {
			t.Fatalf("status = %q, want %q", d.Status, StatusActive)
		}
		if d.WithdrawnAt == nil {
			t.Fatal("an active run that was once withdrawn hides its withdrawal; " +
				"the lapse is a fact and reading active must not erase it")
		}
		if d.LastActivityAt == nil {
			t.Fatal("no last activity on a run whose newest fact is a tool call")
		}
		if !d.LastActivityAt.After(*d.WithdrawnAt) {
			t.Errorf("LastActivityAt %s is not after WithdrawnAt %s, yet the run "+
				"reads active — the two facts do not support the word",
				d.LastActivityAt, d.WithdrawnAt)
		}
	})

	t.Run("a run that was never withdrawn omits what it has no answer for", func(t *testing.T) {
		d, err := s.Run(ctx, "run-alive")
		if err != nil {
			t.Fatalf("Run(run-alive): %v", err)
		}
		// Absent, not zero. A zero time marshals as "0001-01-01T00:00:00Z",
		// which a reader has every right to read as a timestamp.
		if d.WithdrawnAt != nil {
			t.Errorf("WithdrawnAt = %s on a run the reaper never touched", d.WithdrawnAt)
		}
		if d.RestorableUntil != nil {
			t.Errorf("RestorableUntil = %s on a run that was never withdrawn", d.RestorableUntil)
		}
		if d.ParentRunID != "" {
			t.Errorf("ParentRunID = %q on a run whose registration recorded none", d.ParentRunID)
		}
	})

	t.Run("the evidence is on the table row too, not only the detail", func(t *testing.T) {
		page, err := s.ListRuns(ctx, RunFilter{Limit: MaxPageSize})
		if err != nil {
			t.Fatalf("ListRuns: %v", err)
		}
		if page.RestoreHorizonSeconds != int64(horizonBeyondFixture.Seconds()) {
			t.Errorf("page RestoreHorizonSeconds = %d, want %d",
				page.RestoreHorizonSeconds, int64(horizonBeyondFixture.Seconds()))
		}
		for _, r := range page.Runs {
			if r.RunID != "run-quiet" {
				continue
			}
			if r.WithdrawnAt == nil || r.RestorableUntil == nil {
				t.Error("the runs table serves a lapsed row with no withdrawal and no " +
					"restorable-until; the row and the detail must agree")
			}
		}
	})
}

// TestAPI032TheOverviewCountsLapsedAndAbandonedApartFromActive.
func TestAPI032TheOverviewCountsLapsedAndAbandonedApartFromActive(t *testing.T) {
	s := lifecycleFixture(t)
	ctx := t.Context()

	s.SetRestoreHorizon(horizonBeyondFixture)
	inside, err := s.Overview(ctx)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	// run-alive and run-resumed. run-resumed is active because its newest fact
	// is its own tool call, not the reaper's withdrawal.
	if inside.ActiveRuns != 2 {
		t.Errorf("ActiveRuns = %d, want 2", inside.ActiveRuns)
	}
	if inside.LapsedRuns != 1 {
		t.Errorf("LapsedRuns = %d, want 1", inside.LapsedRuns)
	}
	if inside.AbandonedRuns != 0 {
		t.Errorf("AbandonedRuns = %d, want 0 inside the horizon", inside.AbandonedRuns)
	}
	if inside.RetiredRuns != 1 {
		t.Errorf("RetiredRuns = %d, want 1", inside.RetiredRuns)
	}
	if inside.RestoreHorizonSeconds != int64(horizonBeyondFixture.Seconds()) {
		t.Errorf("RestoreHorizonSeconds = %d, want %d",
			inside.RestoreHorizonSeconds, int64(horizonBeyondFixture.Seconds()))
	}

	s.SetRestoreHorizon(horizonAlreadyPassed)
	past, err := s.Overview(ctx)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	if past.LapsedRuns != 0 || past.AbandonedRuns != 1 {
		t.Errorf("past the horizon: lapsed = %d, abandoned = %d; want 0 and 1",
			past.LapsedRuns, past.AbandonedRuns)
	}
	// The one that matters to an operator reading the landing page: neither
	// bucket is counted as active, in either arm.
	if past.ActiveRuns != inside.ActiveRuns {
		t.Errorf("the active count moved with the horizon (%d then %d); a withdrawn "+
			"run is not active on either side of it", inside.ActiveRuns, past.ActiveRuns)
	}

	// And the overview agrees with the table it sits above. The two derive the
	// state in two statements, so this is the assertion that keeps them one
	// rule — a landing page saying "0 lapsed" over a table listing one is the
	// failure the shared comment in overviewSQL exists to prevent.
	s.SetRestoreHorizon(horizonBeyondFixture)
	byStatus := map[string]int{}
	for _, status := range RunStatuses {
		page, perr := s.ListRuns(ctx, RunFilter{Status: status, Limit: MaxPageSize})
		if perr != nil {
			t.Fatalf("ListRuns(status=%s): %v", status, perr)
		}
		byStatus[status] = page.Total
	}
	for _, pair := range []struct {
		status string
		count  int
	}{
		{StatusActive, inside.ActiveRuns},
		{StatusLapsed, inside.LapsedRuns},
		{StatusAbandoned, inside.AbandonedRuns},
		{StatusRetired, inside.RetiredRuns},
	} {
		if byStatus[pair.status] != pair.count {
			t.Errorf("the table reports %d %s runs and the overview reports %d",
				byStatus[pair.status], pair.status, pair.count)
		}
	}
}

// TestAPI033TheHorizonIsReadOnceAndReportedAsItWasRead.
//
// No database. These are the three arms of the horizon's own arithmetic, and
// they are here rather than inside the cases above because IP §2's branch
// floor is about paths, and two of these are reachable only by configuration
// no fixture would produce by accident.
func TestAPI033TheHorizonIsReadOnceAndReportedAsItWasRead(t *testing.T) {
	t.Run("the environment names it", func(t *testing.T) {
		t.Setenv(EnvRestoreHorizon, "72h")
		if got := restoreHorizonFromEnv(); got != 72*time.Hour {
			t.Errorf("restoreHorizonFromEnv() = %s, want 72h", got)
		}
	})

	t.Run("zero is a choice and is honoured", func(t *testing.T) {
		t.Setenv(EnvRestoreHorizon, "0")
		if got := restoreHorizonFromEnv(); got != 0 {
			t.Errorf("restoreHorizonFromEnv() = %s, want 0 — a deployment may "+
				"legitimately keep every withdrawn run restorable", got)
		}
	})

	for _, bad := range []string{"", "thirty days", "30", "-1h"} {
		t.Run("a value that is not a duration falls back: "+bad, func(t *testing.T) {
			t.Setenv(EnvRestoreHorizon, bad)
			if got := restoreHorizonFromEnv(); got != DefaultRestoreHorizon {
				t.Errorf("restoreHorizonFromEnv(%q) = %s, want the default %s — a typo "+
					"must not silently switch the horizon off", bad, got, DefaultRestoreHorizon)
			}
		})
	}

	t.Run("no horizon means no cutoff and no restorable-until", func(t *testing.T) {
		now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
		if abandonedBefore(0, now) != nil {
			t.Error("a zero horizon produced a cutoff; nothing can be past a horizon " +
				"that does not exist")
		}
		withdrawn := now.Add(-time.Hour)
		if restorableUntil(&withdrawn, 0) != nil {
			t.Error("a zero horizon produced a restorable-until; there is no instant " +
				"after which an unbounded restore stops being possible")
		}
		if restorableUntil(nil, DefaultRestoreHorizon) != nil {
			t.Error("a run that was never withdrawn was given a restorable-until")
		}
	})

	t.Run("a horizon puts the cutoff that far back", func(t *testing.T) {
		now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
		cutoff := abandonedBefore(48*time.Hour, now)
		if cutoff == nil {
			t.Fatal("a positive horizon produced no cutoff")
		}
		if want := now.Add(-48 * time.Hour); !cutoff.Equal(want) {
			t.Errorf("cutoff = %s, want %s", cutoff, want)
		}
	})

	t.Run("a negative horizon is refused rather than inverted", func(t *testing.T) {
		s := &Store{}
		s.SetRestoreHorizon(-time.Hour)
		if s.RestoreHorizon() != 0 {
			t.Errorf("RestoreHorizon() = %s after a negative was set; a negative "+
				"horizon would make every withdrawal abandoned before it happened",
				s.RestoreHorizon())
		}
	})
}
