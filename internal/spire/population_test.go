// SPDX-License-Identifier: Apache-2.0

package spire

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
)

// RM-181 (#289) — the sweep's population, and the line it prints about it.
//
// The measured defect: the ledger reported four runs active while SPIRE held
// entries for three of them. The reaper's population was the entry list, so the
// fourth was invisible to the sweep and could never be expired whatever its
// state, and the line the reaper printed every minute —
//
//	reap at …: 3 entries in the agent subtree, 3 live, 0 expired, 0 skipped, 0 failed
//
// — read as a count of agents beside a ledger that held four.
//
// What is NOT under test here is the reaper's verdict, which was checked
// against every entry it could see and is right: SPI-011 and SPI-012 hold it
// and neither is touched. These cases are about the SET, and every one of them
// carries the control that would catch a "fix" that made the reaper more
// eager — a run that is working is never expired, entry or no entry.

// ---------------------------------------------------------------------------
// Fixture: a chain, a SPIRE listing, and an activity source that answers per
// run rather than once for all of them.
// ---------------------------------------------------------------------------

// runActivity is ActivitySource and ActivityPositionSource over a map, because
// every case here needs two runs to get DIFFERENT answers in one sweep: a
// single-answer stub cannot express "this one is working and that one is gone",
// which is the only assertion that distinguishes a reconciled population from a
// wider net.
type runActivity struct {
	at    map[string]time.Time
	err   error
	asked []string
}

func (a *runActivity) LastActivity(_ context.Context, runID string) (time.Time, bool, error) {
	a.asked = append(a.asked, runID)
	if a.err != nil {
		return time.Time{}, false, a.err
	}
	at, known := a.at[runID]
	return at, known, nil
}

func (a *runActivity) LastActivityAt(ctx context.Context, runID string) (time.Time, int64, bool, error) {
	at, known, err := a.LastActivity(ctx, runID)
	// The position is a constant: these cases are about the POPULATION, and
	// SPI-014/SPI-015 already hold the per-lapse key.
	return at, 7, known, err
}

// chainSink is the fakeLedger read as a ledger: appended events land in the
// same chain the run source walks.
//
// That join is what makes idempotence observable rather than asserted. A
// deployment has ONE store, so the `run_expired` a sweep appends is read back
// by the next sweep's population read — and the run stops being active, which
// is the property this file claims costs no dedupe set.
type chainSink struct{ chain *fakeLedger }

func (c chainSink) EventByIdempotencyKey(_ context.Context, key string) (event.Fields, bool, error) {
	for _, rec := range c.chain.records {
		k, ok := rec[event.FieldIdempotencyKey].(string)
		if ok && k != "" && k == key {
			return rec, true, nil
		}
	}
	return nil, false, nil
}

func (c chainSink) Append(ctx context.Context, body event.Fields) (event.Fields, error) {
	stamped := body.Clone()
	if _, ok := stamped[event.FieldTS]; !ok {
		// The real store stamps `ts` (doc 02 §2). Without it the appended
		// withdrawal would be undateable and the rule would go on reading the
		// run as active, which would hide the very property under test.
		stamped[event.FieldTS] = event.NewTimestamp(time.Now().UTC()).String()
	}
	return c.chain.Append(ctx, stamped)
}

// unentriedFixture is the measured shape: some runs the ledger calls active
// with an entry, some without, and one the ledger has closed.
type unentriedFixture struct {
	chain    *fakeLedger
	entries  *stubEntries
	activity *runActivity
	reaper   *Reaper
}

func newUnentriedFixture(t *testing.T, grace time.Duration, held ...string) *unentriedFixture {
	t.Helper()
	chain := &fakeLedger{}
	act := &runActivity{at: map[string]time.Time{}}
	list := make([]*types.Entry, 0, len(held))
	for _, runID := range held {
		// Two hours old with a sixty-second TTL: comfortably past its own
		// deadline, so the entried runs reach the ledger question rather than
		// being spared by their TTL. That is the shape SPI-013 uses.
		list = append(list, wireEntry(fakeSPIFFEID(runID), 60, time.Now().Add(-2*time.Hour)))
	}
	entries := &stubEntries{list: list}

	source, err := NewLedgerRunSource(chain)
	if err != nil {
		t.Fatalf("NewLedgerRunSource: %v", err)
	}
	return &unentriedFixture{
		chain:    chain,
		entries:  entries,
		activity: act,
		reaper: &Reaper{
			client:   &Client{entries: entries, trustDomain: "innsegl.dev", timeout: 5 * time.Second},
			ledger:   chainSink{chain: chain},
			grace:    grace,
			activity: act,
			runs:     source,
		},
	}
}

// run adds a registered run to the chain and says when it last worked.
func (f *unentriedFixture) run(t *testing.T, runID string, lastActive time.Time) {
	t.Helper()
	f.chain.registered("01a047a5-cc41-7c45-86fd-"+pad(len(f.chain.records)+1), runID)
	f.chain.workedAt("01a047a5-cc41-7c45-86fd-"+pad(len(f.chain.records)+1), runID, lastActive)
	f.activity.at[runID] = lastActive
}

func expiredRun(t *testing.T, report *SweepReport, runID string) Expiry {
	t.Helper()
	e, ok := report.FindExpired(runID)
	if !ok {
		t.Fatalf("%s is not in the report's Expired list:\n%s", runID, report)
	}
	return e
}

// ---------------------------------------------------------------------------
// SPI-017 — the sweep's population is SPIRE's entries UNION the ledger's
// active runs, and a run with no entry is reachable by the decision.
// ---------------------------------------------------------------------------

func TestSPI017ARunActiveInTheLedgerWithNoEntryIsReachedBySweep(t *testing.T) {
	now := time.Now().UTC()
	grace := 5 * time.Minute

	// run-entried is the measured majority: active, with an entry, working.
	// run-gone is the hole: active in the ledger, no entry, silent past grace.
	// run-busy is THE CONTROL: active in the ledger, no entry, working now. A
	//   change that swept the ledger more eagerly instead of more widely kills
	//   it, and that is the 2026-09-08 failure with a wider net.
	// run-closed is the second control: the ledger has withdrawn from it, so it
	//   is not active and must not enter this population at all.
	f := newUnentriedFixture(t, grace, "run-entried")
	f.run(t, "run-entried", now.Add(-3*time.Second))
	f.run(t, "run-gone", now.Add(-13*time.Hour))
	f.run(t, "run-busy", now.Add(-3*time.Second))
	f.run(t, "run-closed", now.Add(-13*time.Hour))
	f.chain.closedAt("01a047a5-cc41-7c45-86fd-"+pad(len(f.chain.records)+1),
		"run-closed", event.EventTypeRunExpired, now.Add(-time.Hour))

	report, err := f.reaper.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	if !report.LedgerRunsRead {
		t.Error("the sweep reports that it did not read the ledger's active runs, " +
			"although a run source was configured")
	}
	if report.Examined != 1 {
		t.Errorf("Examined = %d, want 1 entry in the agent subtree:\n%s", report.Examined, report)
	}
	if report.Unentried != 2 {
		t.Errorf("Unentried = %d, want 2 (run-gone and run-busy). A withdrawn run is "+
			"not active and must not enter this population:\n%s", report.Unentried, report)
	}
	if report.Considered() != 3 {
		t.Errorf("Considered() = %d, want 3 — the number the ledger would report "+
			"active. A sweep whose leading number is the entry count is the line that "+
			"read as a count of agents:\n%s", report.Considered(), report)
	}

	// The hole, closed: the run with no entry is reachable by the decision.
	gone := expiredRun(t, report, "run-gone")
	if !gone.Unentried {
		t.Error("run-gone was expired but is not marked unentried; the report cannot " +
			"then say that nothing was deleted because there was nothing to delete")
	}
	if !gone.Recorded {
		t.Error("run-gone's withdrawal was not recorded by this sweep")
	}
	if gone.Deleted {
		t.Error("the sweep reports deleting an entry for a run SPIRE holds none for")
	}
	if gone.Entry.SPIFFEID != fakeSPIFFEID("run-gone") {
		t.Errorf("the expiry names %q, want the ledger's identity %q",
			gone.Entry.SPIFFEID, fakeSPIFFEID("run-gone"))
	}

	// THE CONTROL. A live, working run is never expired, whatever its entry
	// looks like — this is the assertion that must be driven hardest.
	if _, ok := report.FindExpired("run-busy"); ok {
		t.Fatal("run-busy was expired: it has no SPIRE entry, but it recorded work " +
			"three seconds ago. This is the 2026-09-08 failure aimed at a wider " +
			"population, and it is the one outcome this change must not produce")
	}
	busy, ok := report.FindLive("run-busy")
	if !ok {
		t.Fatalf("run-busy is neither live nor expired; a run in the population must "+
			"be judged:\n%s", report)
	}
	if !busy.Unentried || busy.LastActivity.IsZero() {
		t.Errorf("run-busy is live but the report does not say it was spared by its own "+
			"work (unentried=%v last-active=%v)", busy.Unentried, busy.LastActivity)
	}

	// The SPIRE half is untouched: an entried run past its deadline that is
	// still working is still live, and its entry is still there.
	if _, ok := report.FindLive("run-entried"); !ok {
		t.Errorf("run-entried is no longer live; the ledger half changed the entry "+
			"half's verdict:\n%s", report)
	}
	if len(f.entries.deleted) != 0 {
		t.Errorf("the sweep deleted %v; nothing in this fixture is an orphan with an "+
			"entry to delete", f.entries.deleted)
	}
	// The closed run never enters the population.
	if _, ok := report.FindExpired("run-closed"); ok {
		t.Error("run-closed was withdrawn from a second time; the ledger does not call " +
			"it active and it is not this population's")
	}

	// Exactly one withdrawal per run, and only for the run that went quiet.
	// run-closed's own withdrawal was in the fixture before the sweep, so the
	// count is per run rather than over the whole chain.
	withdrawals := map[string][]event.Fields{}
	for _, rec := range f.chain.records {
		if rec[event.FieldEventType] == event.EventTypeRunExpired &&
			rec[event.FieldSource] == event.SourceReaper {
			runID, ok := rec[event.FieldRunID].(string)
			if !ok {
				continue
			}
			withdrawals[runID] = append(withdrawals[runID], rec)
		}
	}
	for _, runID := range []string{"run-entried", "run-busy"} {
		if n := len(withdrawals[runID]); n != 0 {
			t.Errorf("%s was withdrawn from %d time(s); it is working", runID, n)
		}
	}
	if n := len(withdrawals["run-closed"]); n != 1 {
		t.Errorf("run-closed has %d withdrawal(s), want the 1 it arrived with", n)
	}
	if len(withdrawals["run-gone"]) != 1 {
		t.Fatalf("run-gone has %d withdrawal(s), want exactly 1", len(withdrawals["run-gone"]))
	}
	if got := withdrawals["run-gone"][0][event.FieldSpiffeID]; got != fakeSPIFFEID("run-gone") {
		t.Errorf("the withdrawal carries spiffe_id %v, want %q", got, fakeSPIFFEID("run-gone"))
	}
}

// SPI-017, second half: the withdrawal is not repeated, and it takes nothing
// away that speaking again does not return.
//
// # Why both halves are one case
//
// The operator's rule is that silence is ambiguous and must wait. This is what
// the waiting buys: the sweep's whole effect on an unentried run is a ledger
// fact, because there is no entry to delete — and the moment the run speaks,
// internal/ledger's rule reads its activity as newer than the withdrawal and
// the run is active again (REC-017). Nothing is destroyed and nothing is
// permanent, which is why widening the POPULATION does not widen what is lost.
func TestSPI017TheUnentriedWithdrawalIsNotRepeatedAndIsReversible(t *testing.T) {
	now := time.Now().UTC()
	f := newUnentriedFixture(t, 5*time.Minute)
	f.run(t, "run-gone", now.Add(-13*time.Hour))

	first, err := f.reaper.Sweep(context.Background())
	if err != nil {
		t.Fatalf("first Sweep: %v", err)
	}
	expiredRun(t, first, "run-gone")
	appendsAfterFirst := len(f.chain.records)

	// A second sweep over the same chain. The run is now withdrawn from, so the
	// one rule no longer reads it active and it is not in the population.
	second, err := f.reaper.Sweep(context.Background())
	if err != nil {
		t.Fatalf("second Sweep: %v", err)
	}
	if second.Unentried != 0 {
		t.Errorf("the second sweep still counts %d unentried run(s); a withdrawn run is "+
			"lapsed, not active, so it leaves this population without a dedupe set:\n%s",
			second.Unentried, second)
	}
	if _, ok := second.FindExpired("run-gone"); ok {
		t.Error("run-gone was withdrawn from twice for one silence")
	}
	if len(f.chain.records) != appendsAfterFirst {
		t.Errorf("the second sweep appended %d more event(s); one lapse is one withdrawal",
			len(f.chain.records)-appendsAfterFirst)
	}

	// And it is reversible: the run speaks, and the ledger calls it active
	// again. The withdrawal was a fact about authorisation, not a death.
	//
	// A second after the withdrawal, not the same instant: doc 02 §2 holds `ts`
	// to millisecond precision, so an activity stamped inside the same
	// millisecond as the withdrawal is not AFTER it and the rule would rightly
	// go on reading the withdrawal as standing.
	f.chain.workedAt("01a047a5-cc41-7c45-86fd-"+pad(len(f.chain.records)+1),
		"run-gone", time.Now().UTC().Add(time.Second))
	source, err := NewLedgerRunSource(f.chain)
	if err != nil {
		t.Fatalf("NewLedgerRunSource: %v", err)
	}
	active, err := source.ActiveRuns(context.Background(), time.Now().UTC())
	if err != nil {
		t.Fatalf("ActiveRuns: %v", err)
	}
	found := false
	for _, run := range active {
		if run.RunID == "run-gone" {
			found = true
		}
	}
	if !found {
		t.Errorf("a run that spoke after its withdrawal is not active again; the "+
			"withdrawal has become an ending, which is what retirement is for and "+
			"expiry is not (REC-017). ActiveRuns = %+v", active)
	}
}

// ---------------------------------------------------------------------------
// SPI-018 — the decision over an unentried run is the SAME predicate, over the
// same grace, and a working run survives it.
// ---------------------------------------------------------------------------

func TestSPI018AnUnentriedRunIsJudgedByTheSameSilenceRule(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	grace := 12 * time.Hour

	for _, tc := range []struct {
		name     string
		last     time.Time
		known    bool
		orphaned bool
		skipped  bool
	}{
		{name: "working seconds ago", last: now.Add(-3 * time.Second), known: true},
		{name: "quiet for an hour", last: now.Add(-time.Hour), known: true},
		// The measured session: idle, not gone, and well inside a twelve-hour
		// grace. Expiring this was the wrong call the issue withdrew, and a
		// change that shortens the wait fails right here.
		{name: "idle but alive, eleven hours", last: now.Add(-11 * time.Hour), known: true},
		{name: "silent just inside the grace", last: now.Add(-grace + time.Minute), known: true},
		// The positive control for the whole table: without this row every
		// other row passes against a predicate that never expires anything.
		{name: "silent just past the grace", last: now.Add(-grace - time.Minute), known: true, orphaned: true},
		{name: "silent for days", last: now.Add(-96 * time.Hour), known: true, orphaned: true},
		// No entry AND no recorded activity is no evidence at all. The entried
		// path falls back to the deadline here; there is no deadline here.
		{name: "nothing the ledger can date it by", known: false, skipped: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			act := &runActivity{at: map[string]time.Time{}}
			if tc.known {
				act.at["run-x"] = tc.last
			}
			r := &Reaper{grace: grace, activity: act}
			cand := Candidate{
				Entry:     Entry{SPIFFEID: fakeSPIFFEID("run-x")},
				Run:       RunRef{RunID: "run-x"},
				Unentried: true,
			}

			reap, skip := r.orphanedUnentried(context.Background(), now, &cand)
			if (skip != nil) != tc.skipped {
				t.Fatalf("skip = %v, want skipped=%v", skip, tc.skipped)
			}
			if reap != tc.orphaned {
				t.Fatalf("orphaned = %v, want %v — the grace is the only duration in "+
					"this decision and it is unchanged", reap, tc.orphaned)
			}
			if tc.known && !tc.skipped && !cand.LastActivity.Equal(tc.last) {
				t.Errorf("LastActivity = %v, want %v recorded on the candidate so the "+
					"report can say WHY the run survived", cand.LastActivity, tc.last)
			}
		})
	}

	t.Run("a ledger that cannot answer withdraws nothing", func(t *testing.T) {
		r := &Reaper{grace: grace, activity: &runActivity{err: errors.New("connection refused")}}
		cand := Candidate{
			Entry:     Entry{SPIFFEID: fakeSPIFFEID("run-x")},
			Run:       RunRef{RunID: "run-x"},
			Unentried: true,
		}
		reap, skip := r.orphanedUnentried(context.Background(), now, &cand)
		if reap {
			t.Fatal("a run was withdrawn from on an unreadable ledger; the reaper had " +
				"no basis to call it gone")
		}
		if skip == nil || !strings.Contains(skip.Reason, "connection refused") {
			t.Fatalf("skip = %v; the operator cannot see a reaper that stopped judging "+
				"unless the report carries the ledger's own error", skip)
		}
	})
}

func TestNewReaperRefusesARunSourceItCannotJudge(t *testing.T) {
	source, err := NewLedgerRunSource(&fakeLedger{})
	if err != nil {
		t.Fatalf("NewLedgerRunSource: %v", err)
	}
	_, err = NewReaper(ReaperConfig{
		Client: &Client{}, Ledger: &fakeSink{}, Runs: source,
	})
	if err == nil {
		t.Fatal("a reaper was built with a run source and no activity source. A run " +
			"with no entry has no deadline, so such a reaper would withdraw from " +
			"every active run at once")
	}
	if class, _ := ClassOf(err); class != ClassInvariantViolation {
		t.Errorf("class = %v, want %v", class, ClassInvariantViolation)
	}
	// The positive control: the same configuration WITH an activity source is
	// accepted, so the refusal is about the missing half and not about the
	// run source existing at all.
	if _, err := NewReaper(ReaperConfig{
		Client: &Client{}, Ledger: &fakeSink{}, Runs: source,
		Activity: &runActivity{at: map[string]time.Time{}},
	}); err != nil {
		t.Errorf("a reaper with both halves was refused: %v", err)
	}
	if _, err := NewLedgerRunSource(nil); err == nil {
		t.Error("a run source with no chain to read was accepted; it would report " +
			"that no run is active, which is a silent answer and not a true one")
	}
}

// ---------------------------------------------------------------------------
// SPI-019 — the line says what the sweep did NOT look at.
// ---------------------------------------------------------------------------

func TestSPI019TheSweepLineSaysWhatItDidNotLookAt(t *testing.T) {
	report := &SweepReport{
		StartedAt:      time.Unix(0, 0).UTC(),
		Examined:       3,
		Unentried:      1,
		Outside:        12,
		LedgerRunsRead: true,
		Live: []Candidate{
			{Entry: Entry{ID: "e1", SPIFFEID: fakeSPIFFEID("run-a")}, Run: RunRef{RunID: "run-a"}},
			{Entry: Entry{SPIFFEID: fakeSPIFFEID("run-d")}, Run: RunRef{RunID: "run-d"},
				Unentried: true, LastActivity: time.Unix(0, 0).UTC()},
		},
	}
	line := report.String()

	// The leading number is RUNS, and it agrees with what the ledger reports
	// active — three entries beside a ledger holding four is the misreading.
	for _, want := range []string{
		"4 runs considered",
		"3 entries in the agent subtree",
		"1 active in the ledger with no entry",
		"2 live",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("the sweep line does not say %q:\n%s", want, line)
		}
	}
	// And it says what it did not look at.
	for _, want := range []string{"not looked at", "12 entries outside the agent subtree"} {
		if !strings.Contains(line, want) {
			t.Errorf("the sweep line does not say %q:\n%s", want, line)
		}
	}
	// "live" must not be readable as "agents observed running".
	if !strings.Contains(line, "recorded activity") {
		t.Errorf("the sweep line does not say that \"live\" is recorded activity rather "+
			"than an agent seen running; that is the misreading #289 was filed over:\n%s", line)
	}
	// The unentried run is visibly unentried in its own line.
	if !strings.Contains(line, "entry=none") {
		t.Errorf("a run with no SPIRE entry is printed as though it had one:\n%s", line)
	}

	// The positive control for every assertion above: a sweep that did NOT
	// read the ledger says so, rather than printing a number that looks like
	// the whole population.
	unread := &SweepReport{StartedAt: time.Unix(0, 0).UTC(), Examined: 3}
	if got := unread.String(); !strings.Contains(got, "were not read") {
		t.Errorf("a sweep with no run source does not say the ledger's active runs "+
			"were not read; its counts then look like the whole population:\n%s", got)
	}
}

func TestSPI019ALedgerThatCannotBeReadIsSaidAndDoesNotStopTheSweep(t *testing.T) {
	now := time.Now().UTC()
	f := newUnentriedFixture(t, 5*time.Minute, "run-orphan")
	f.run(t, "run-orphan", now.Add(-13*time.Hour))
	f.reaper.runs = failingRunSource{err: errors.New("the ledger is unreachable")}

	report, err := f.reaper.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if report.LedgerRunsRead {
		t.Error("the sweep claims it read the ledger's active runs; the read failed")
	}
	if len(report.Skipped) != 1 || !strings.Contains(report.Skipped[0].Reason, "unreachable") {
		t.Fatalf("the failure is not reported as a skip carrying the ledger's own "+
			"error:\n%s", report)
	}
	// The SPIRE half is still swept: its orphans are still orphans.
	if _, ok := report.FindExpired("run-orphan"); !ok {
		t.Errorf("an entried orphan went unreaped because the LEDGER half failed; one "+
			"half's outage is not the other's:\n%s", report)
	}
	if !strings.Contains(report.String(), "were not read") {
		t.Errorf("the line does not say the ledger's active runs were not read:\n%s", report)
	}
}

type failingRunSource struct{ err error }

func (f failingRunSource) ActiveRuns(context.Context, time.Time) ([]UnentriedRun, error) {
	return nil, f.err
}

// ActiveRuns answers with internal/ledger's rule and no other, which is what
// keeps the reaper's population and the read API's count the same number.
func TestActiveRunsSpeaksTheOneRule(t *testing.T) {
	now := time.Now().UTC()
	chain := &fakeLedger{}
	chain.registered("01a047a5-cc41-7c45-86fd-000000000001", "run-active")
	chain.registered("01a047a5-cc41-7c45-86fd-000000000002", "run-retired")
	chain.closedAt("01a047a5-cc41-7c45-86fd-000000000003", "run-retired",
		event.EventTypeRunRetired, now.Add(-time.Hour))
	chain.registered("01a047a5-cc41-7c45-86fd-000000000004", "run-lapsed")
	chain.closedAt("01a047a5-cc41-7c45-86fd-000000000005", "run-lapsed",
		event.EventTypeRunExpired, now.Add(-time.Hour))
	chain.registered("01a047a5-cc41-7c45-86fd-000000000006", "run-restored")
	chain.closedAt("01a047a5-cc41-7c45-86fd-000000000007", "run-restored",
		event.EventTypeRunExpired, now.Add(-2*time.Hour))
	chain.workedAt("01a047a5-cc41-7c45-86fd-000000000008", "run-restored", now.Add(-time.Minute))
	// An entry-less tool call for an identity the chain never registered is
	// not a run this source believes in: AB-11's shape, and the reconciler's
	// DriftEntryUnattributed, not the reaper's to withdraw.
	chain.workedAt("01a047a5-cc41-7c45-86fd-000000000009", "run-unregistered", now.Add(-time.Minute))

	source, err := NewLedgerRunSource(chain)
	if err != nil {
		t.Fatalf("NewLedgerRunSource: %v", err)
	}
	got, err := source.ActiveRuns(context.Background(), now)
	if err != nil {
		t.Fatalf("ActiveRuns: %v", err)
	}
	var ids []string
	for _, run := range got {
		ids = append(ids, run.RunID)
		if run.SPIFFEID != fakeSPIFFEID(run.RunID) {
			t.Errorf("%s carries spiffe_id %q, want the ledger's %q",
				run.RunID, run.SPIFFEID, fakeSPIFFEID(run.RunID))
		}
	}
	want := []string{"run-active", "run-restored"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Errorf("ActiveRuns = %v, want %v — retired and lapsed are not active, a "+
			"restored run is, and an unregistered identity is not this reaper's", ids, want)
	}

	// The rule is internal/ledger's, held against it directly rather than
	// restated: two components that decide `active` on different grounds is
	// the defect RM-155 (#258) closed.
	if ledger.RunStateOf(ledger.RunFacts{RegisteredAt: now}, now, ledger.DefaultRestoreHorizon) != ledger.RunActive {
		t.Error("this file's fixture no longer matches internal/ledger's rule")
	}
}
