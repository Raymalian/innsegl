// SPDX-License-Identifier: Apache-2.0

package spire

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
)

// SPI-008 (doc 07, layer I) — SPIRE entry reconciliation.
//
// NOT YET IN DOC 07. Issue #27 (RM-019) carries the acceptance criterion "new
// TC needed", and docs/ is local-only to the implementing agent, so the row
// below is written here and must be added to doc 07 §TC-SPI by a human:
//
//	| SPI-008 | I | Out-of-band SPIRE entry planted on the local admin socket;
//	  entry for an active run deleted out of band | Both detected within one
//	  reconciler cycle; a legitimate run's entry raises nothing; a second cycle
//	  over the same state appends nothing | AB-11, AB-10 residual (ADR-0012),
//	  I1, IP §6.10 |
//
// WHAT THIS CLOSES
//
// Threat model AB-11: "Tamper with SPIRE entries directly to widen a run's
// identity", mitigation "Entry reconciliation + alert", status "open — add TC".
// Doc 04's SPIRE deployment section spells the mechanism out: "entries mutated
// out-of-band → periodic reconciliation of expected-vs-actual entries; alert on
// unexplained entries".
//
// Both directions are load-bearing and both are tested here:
//
//   - SPIRE holds an entry the ledger does not explain. That is AB-11. It is
//     planted the way an attacker with a foothold on the SPIRE server host
//     would plant it — on the unauthenticated local admin socket ADR-0011
//     contains but does not authorize, the same socket SPI-005 uses as its
//     control.
//   - The ledger says a run is active and SPIRE holds no entry for it. That is
//     the hole ADR-0012 names and cannot close: BatchDeleteEntry carries opaque
//     entry IDs, rego cannot resolve one to a SPIFFE ID, so a stolen admin
//     credential can delete any entry in the trust domain. Detection is the
//     only control there is.
//
// THE VACUOUS PASS THIS IS SHAPED AGAINST
//
// "An unexplained entry was detected" passes for a reconciler that alerts on
// everything. So every integration case here registers a LEGITIMATE run first,
// through the ordinary admin path with its ledger event, and asserts that run
// raises nothing — in the drift list and in the ledger both. That assertion was
// observed failing against a deliberately over-alerting stub before the real
// implementation existed; see the issue report for the verbatim red.

// ---------------------------------------------------------------------------
// Ledger helpers. This package does not write the ledger in production — the
// MCP pairs an entry with its `run_registered` event (IP §6.5, E4) — so the
// test writes the events the MCP would have written and then reconciles.
// ---------------------------------------------------------------------------

// registerInLedger appends the `run_registered` event the MCP would append for
// run, and returns its event_id.
func registerInLedger(t *testing.T, store *ledger.Store, run RunRef) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	spiffeID, err := run.SPIFFEID(testTrustDomain)
	if err != nil {
		t.Fatalf("SPIFFEID(%+v): %v", run, err)
	}
	rec, err := store.Append(ctx, event.Fields{
		event.FieldEventType:      event.EventTypeRunRegistered,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          run.RunID,
		event.FieldSpiffeID:       spiffeID,
		event.FieldIdempotencyKey: "reg-" + run.RunID,
		event.FieldAgentType:      run.AgentType,
		event.FieldTaskRef:        strings.ToUpper(run.TaskID),
	})
	if err != nil {
		t.Fatalf("append run_registered for %s: %v", spiffeID, err)
	}
	id := recordString(rec, event.FieldEventID)
	if id == "" {
		t.Fatalf("run_registered came back without an event_id: %v", rec)
	}
	return id
}

// retireInLedger appends the `run_retired` event and returns its event_id.
func retireInLedger(t *testing.T, store *ledger.Store, run RunRef) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	spiffeID, err := run.SPIFFEID(testTrustDomain)
	if err != nil {
		t.Fatalf("SPIFFEID(%+v): %v", run, err)
	}
	rec, err := store.Append(ctx, event.Fields{
		event.FieldEventType: event.EventTypeRunRetired,
		event.FieldSource:    event.SourceMCP,
		event.FieldRunID:     run.RunID,
		event.FieldSpiffeID:  spiffeID,
	})
	if err != nil {
		t.Fatalf("append run_retired for %s: %v", spiffeID, err)
	}
	return recordString(rec, event.FieldEventID)
}

// driftEvents reads back every `ledger_drift_detected` in the chain.
func driftEvents(t *testing.T, store *ledger.Store) []event.Fields {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	n, err := store.Count(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if n == 0 {
		return nil
	}
	records, err := store.Events(ctx, 1, n)
	if err != nil {
		t.Fatalf("Events(1,%d): %v", n, err)
	}
	var out []event.Fields
	for _, rec := range records {
		if recordString(rec, event.FieldEventType) == event.EventTypeLedgerDriftDetected {
			out = append(out, rec)
		}
	}
	return out
}

// newReconcilerFor builds a reconciler over a real SPIRE client and a real
// ledger, collecting the drifts the schema cannot record.
//
// minAge is Config.MinAge, passed explicitly rather than left at
// DefaultMinAge (six minutes): SPI-008's cases construct a state that is
// already, fully, the thing being detected — an entry deleted or replanted out
// of band — and asserting that immediately is what proves the detection logic
// itself. Waiting out DefaultMinAge is #108/RM-075's own test's job, not
// SPI-008's; see TestSPI009 and TestSPI010 below.
func newReconcilerFor(t *testing.T, c *Client, store *ledger.Store, minAge time.Duration) (*Reconciler, *[]Drift) {
	t.Helper()
	var loud []Drift
	rec, err := NewReconciler(ReconcilerConfig{
		Entries:  c,
		Ledger:   store,
		Appender: store,
		MinAge:   minAge,
		Alert: func(_ context.Context, d Drift) {
			loud = append(loud, d)
		},
	})
	if err != nil {
		t.Fatalf("NewReconciler: %v", err)
	}
	return rec, &loud
}

// driftsFor returns the drifts naming one SPIFFE ID.
func driftsFor(result Result, spiffeID string) []Drift {
	var out []Drift
	for _, d := range result.Drifts {
		if d.SPIFFEID == spiffeID {
			out = append(out, d)
		}
	}
	return out
}

// plantEntry creates a registration entry on the unauthenticated local admin
// socket — out of band, with no MCP call and no ledger event. This is AB-11's
// attacker: someone who reached the SPIRE server host. ADR-0011 states plainly
// that the local socket keeps full admin and is contained by mount, not by
// authorization, which is exactly why detection has to exist.
func plantEntry(t *testing.T, s *stack, spiffeID string, selectors ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if len(selectors) == 0 {
		// unix:uid:0 is the weak selector doc 04 names: every container on the
		// node matches it. Widening, in one argument.
		selectors = []string{"unix:uid:0"}
	}
	args := []string{"entry", "create", "-parentID", s.parentID, "-spiffeID", spiffeID}
	for _, sel := range selectors {
		args = append(args, "-selector", sel)
	}
	args = append(args, "-x509SVIDTTL", "300", "-jwtSVIDTTL", "300")

	out, err := s.spireLocal(ctx, args...)
	if err != nil {
		t.Fatalf("plant %s on the local socket: %v", spiffeID, err)
	}
	entryID := fieldAfter(out, "Entry ID")
	if entryID == "" {
		t.Fatalf("local entry create for %s returned no entry ID:\n%s", spiffeID, out)
	}
	t.Cleanup(func() { deleteEntryLocally(t, s, entryID) })
	return entryID
}

// deleteEntryLocally removes an entry on the local socket. Used both to clean
// up a planted entry and to simulate the BatchDeleteEntry hole of ADR-0012:
// the entry vanishes while the ledger still says the run is active.
func deleteEntryLocally(t *testing.T, s *stack, entryID string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := s.spireLocal(ctx, "entry", "delete", "-entryID", entryID); err != nil {
		// Already gone is the normal case for the cleanup path.
		if !strings.Contains(err.Error(), "not found") {
			t.Logf("warning: deleting entry %s on the local socket: %v", entryID, err)
		}
	}
}

// ---------------------------------------------------------------------------
// SPI-008, direction one: an entry SPIRE has that the ledger does not explain.
// ---------------------------------------------------------------------------

func TestSPI008UnexplainedEntryIsDetectedAndALegitimateRunIsNot(t *testing.T) {
	s := requireStack(t)
	store := requireLedger(t)
	c := s.adminClient(t)

	// The negative control, established first: a run registered the ordinary
	// way, entry in SPIRE and event in the ledger. Nothing about it is drift.
	legit := newRun(t, "fix-ci", "jira-118")
	registerForTest(t, c, s, legit)
	registerInLedger(t, store, legit)
	legitID, err := legit.SPIFFEID(testTrustDomain)
	if err != nil {
		t.Fatalf("SPIFFEID: %v", err)
	}

	// AB-11: an entry planted out of band, with a widened selector, for an
	// identity the ledger has never heard of.
	rogue := "spiffe://" + testTrustDomain + "/agent/fix-ci/jira-118/run-planted-" +
		fmt.Sprint(nameSeq.Add(1))
	plantedEntryID := plantEntry(t, s, rogue)

	rec, loud := newReconcilerFor(t, c, store, time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	result, err := rec.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	t.Logf("cycle: %d ledger runs (%d active), %d SPIRE entries, %d drift(s)",
		result.LedgerRuns, result.ActiveRuns, result.SPIREEntries, len(result.Drifts))

	// --- the AB-11 assertion ---
	planted := driftsFor(result, rogue)
	if len(planted) != 1 {
		t.Fatalf("planted entry %s (entry %s) produced %d drifts, want exactly 1: %+v",
			rogue, plantedEntryID, len(planted), result.Drifts)
	}
	if planted[0].Kind != DriftEntryUnattributed {
		t.Errorf("planted entry produced kind %q, want %q", planted[0].Kind, DriftEntryUnattributed)
	}
	if !slices.Contains(planted[0].EntryIDs, plantedEntryID) {
		t.Errorf("drift for %s names entries %v, want the planted entry %s",
			rogue, planted[0].EntryIDs, plantedEntryID)
	}

	// --- the negative control: a legitimate run raises nothing ---
	if got := driftsFor(result, legitID); len(got) != 0 {
		t.Errorf("the legitimate run %s raised %d drift(s); a reconciler that "+
			"alerts on every entry passes the assertion above and fails here: %+v",
			legitID, len(got), got)
	}
	for _, d := range driftEvents(t, store) {
		if recordString(d, event.FieldSpiffeID) == legitID {
			t.Errorf("the legitimate run %s was recorded as drift in the ledger: %v", legitID, d)
		}
	}

	// --- the alert is loud, and it is loud out of band ---
	//
	// doc 02 §3 is a closed schema and has no event for an identity that the
	// ledger cannot account for: `ledger_drift_detected` requires a
	// `subject_event_id`, and a planted entry has no subject event. So this
	// drift reaches the operator through the alert sink, and the reconciler
	// reports it as unrecordable rather than inventing a subject.
	if len(result.Unrecordable) == 0 {
		t.Fatalf("the planted entry was not reported as unrecordable; "+
			"result: %+v", result)
	}
	var sawRogue bool
	for _, d := range *loud {
		if d.SPIFFEID == rogue {
			sawRogue = true
		}
		if d.SPIFFEID == legitID {
			t.Errorf("the alert sink was handed the legitimate run %s", legitID)
		}
	}
	if !sawRogue {
		t.Errorf("the alert sink was never handed the planted entry %s; it saw %+v", rogue, *loud)
	}
}

// ---------------------------------------------------------------------------
// SPI-008, direction two: a run the ledger says is active with no SPIRE entry.
// ADR-0012's BatchDeleteEntry hole, and the schema fits it exactly.
// ---------------------------------------------------------------------------

func TestSPI008DeletedEntryForAnActiveRunIsRecordedAndIsIdempotent(t *testing.T) {
	s := requireStack(t)
	store := requireLedger(t)
	c := s.adminClient(t)

	// The negative control again: this run keeps its entry throughout.
	legit := newRun(t, "fix-ci", "jira-200")
	registerForTest(t, c, s, legit)
	registerInLedger(t, store, legit)
	legitID, err := legit.SPIFFEID(testTrustDomain)
	if err != nil {
		t.Fatalf("SPIFFEID: %v", err)
	}

	// The victim: registered the ordinary way, then its entry deleted out of
	// band. The ledger still says it is active.
	victim := newRun(t, "fix-ci", "jira-201")
	victimEntry := registerForTest(t, c, s, victim)
	victimRegistered := registerInLedger(t, store, victim)
	victimID, err := victim.SPIFFEID(testTrustDomain)
	if err != nil {
		t.Fatalf("SPIFFEID: %v", err)
	}
	deleteEntryLocally(t, s, victimEntry.ID)

	rec, _ := newReconcilerFor(t, c, store, time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	result, err := rec.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	got := driftsFor(result, victimID)
	if len(got) != 1 || got[0].Kind != DriftEntryMissing {
		t.Fatalf("deleting %s out of band produced %+v, want one %s drift",
			victimID, got, DriftEntryMissing)
	}
	if got[0].SubjectEventID != victimRegistered {
		t.Errorf("drift names subject %q, want the run_registered event %q",
			got[0].SubjectEventID, victimRegistered)
	}
	if len(driftsFor(result, legitID)) != 0 {
		t.Errorf("the legitimate run %s raised drift while only %s was deleted", legitID, victimID)
	}

	// The alert is a ledger event, and it names the run.
	alerts := driftEvents(t, store)
	if len(alerts) != 1 {
		t.Fatalf("ledger holds %d ledger_drift_detected events, want 1: %+v", len(alerts), alerts)
	}
	if subject := recordString(alerts[0], event.FieldSubjectEventID); subject != victimRegistered {
		t.Errorf("ledger_drift_detected subject_event_id is %q, want %q", subject, victimRegistered)
	}
	if runID := recordString(alerts[0], event.FieldRunID); runID != victim.RunID {
		t.Errorf("ledger_drift_detected run_id is %q, want %q", runID, victim.RunID)
	}
	if source := recordString(alerts[0], event.FieldSource); source != event.SourceReconciler {
		t.Errorf("ledger_drift_detected source is %q, want %q", source, event.SourceReconciler)
	}
	if len(result.Appended) != 1 {
		t.Errorf("cycle reported %d appended events, want 1: %v", len(result.Appended), result.Appended)
	}

	// Idempotent: a second cycle over the same state appends nothing (REC-005's
	// rule, applied to SPIRE drift).
	t.Run("SecondCycleAppendsNothing", func(t *testing.T) {
		second, serr := rec.Reconcile(ctx)
		if serr != nil {
			t.Fatalf("second Reconcile: %v", serr)
		}
		if len(second.Appended) != 0 {
			t.Errorf("second cycle appended %v, want nothing", second.Appended)
		}
		if after := driftEvents(t, store); len(after) != 1 {
			t.Errorf("ledger holds %d ledger_drift_detected events after two cycles, want 1", len(after))
		}
	})

	// And a reconciler with no memory of the first cycle appends nothing
	// either: the dedupe is the ledger's own record, not an in-process set.
	t.Run("FreshReconcilerAppendsNothing", func(t *testing.T) {
		fresh, _ := newReconcilerFor(t, c, store, time.Millisecond)
		third, terr := fresh.Reconcile(ctx)
		if terr != nil {
			t.Fatalf("third Reconcile: %v", terr)
		}
		if len(third.Appended) != 0 {
			t.Errorf("a fresh reconciler appended %v, want nothing", third.Appended)
		}
	})
}

// ---------------------------------------------------------------------------
// SPI-008, direction one again, with a subject event: a retired run whose entry
// came back. This is the AB-11 shape the closed schema DOES fit, because the
// `run_retired` event is a ledger claim ("SPIRE entry deleted") that the SPIRE
// state contradicts.
// ---------------------------------------------------------------------------

func TestSPI008ReplantedEntryForARetiredRunIsRecorded(t *testing.T) {
	s := requireStack(t)
	store := requireLedger(t)
	c := s.adminClient(t)

	run := newRun(t, "fix-ci", "jira-300")
	registerForTest(t, c, s, run)
	registerInLedger(t, store, run)
	spiffeID, err := run.SPIFFEID(testTrustDomain)
	if err != nil {
		t.Fatalf("SPIFFEID: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if _, err = c.RetireRun(ctx, run); err != nil {
		t.Fatalf("RetireRun: %v", err)
	}
	retiredEvent := retireInLedger(t, store, run)

	// The attacker puts it back, on the socket the MCP never touches.
	plantEntry(t, s, spiffeID, "unix:uid:0")

	rec, _ := newReconcilerFor(t, c, store, time.Millisecond)
	result, err := rec.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	got := driftsFor(result, spiffeID)
	if len(got) != 1 || got[0].Kind != DriftEntryNotDeleted {
		t.Fatalf("replanting %s produced %+v, want one %s drift",
			spiffeID, got, DriftEntryNotDeleted)
	}
	if got[0].SubjectEventID != retiredEvent {
		t.Errorf("drift names subject %q, want the run_retired event %q",
			got[0].SubjectEventID, retiredEvent)
	}
	alerts := driftEvents(t, store)
	if len(alerts) != 1 {
		t.Fatalf("ledger holds %d ledger_drift_detected events, want 1", len(alerts))
	}
}

// ---------------------------------------------------------------------------
// Unit cases. Fakes here, real SPIRE above: these exist to reach the branches an
// integration case cannot force — a ledger that errors, a SPIRE that errors, an
// append that fails — not to stand in for the integration cases.
// ---------------------------------------------------------------------------

type fakeEntries struct {
	td      string
	entries []Entry
	err     error
	calls   int
}

func (f *fakeEntries) TrustDomain() string { return f.td }

func (f *fakeEntries) ListAgentEntries(_ context.Context) ([]Entry, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return slices.Clone(f.entries), nil
}

// fakeLedger is an in-memory chain: the records as appended, in position order.
type fakeLedger struct {
	records   []event.Fields
	countErr  error
	eventsErr error
	appendErr error
	nextID    int
}

func (f *fakeLedger) Count(_ context.Context) (int64, error) {
	if f.countErr != nil {
		return 0, f.countErr
	}
	return int64(len(f.records)), nil
}

func (f *fakeLedger) Events(_ context.Context, from, to int64) ([]event.Fields, error) {
	if f.eventsErr != nil {
		return nil, f.eventsErr
	}
	if from < 1 || to < from || to > int64(len(f.records)) {
		return nil, fmt.Errorf("range %d..%d outside 1..%d", from, to, len(f.records))
	}
	return slices.Clone(f.records[from-1 : to]), nil
}

func (f *fakeLedger) Append(_ context.Context, body event.Fields) (event.Fields, error) {
	if f.appendErr != nil {
		return nil, f.appendErr
	}
	f.nextID++
	rec := body.Clone()
	rec[event.FieldEventID] = fmt.Sprintf("01a047a5-cc41-7c45-86fd-%012x", f.nextID)
	rec[event.FieldChainPosition] = int64(len(f.records) + 1)
	f.records = append(f.records, rec)
	return rec, nil
}

// add appends a record directly, bypassing Append's bookkeeping.
func (f *fakeLedger) add(eventID string, fields event.Fields) *fakeLedger {
	rec := fields.Clone()
	rec[event.FieldEventID] = eventID
	f.records = append(f.records, rec)
	return f
}

func fakeSPIFFEID(runID string) string {
	return "spiffe://innsegl.dev/agent/fix-ci/jira-1/" + runID
}

// wellPastMinAge is comfortably older than DefaultMinAge, so a fixture built
// with it is never mistaken for a call still inside the ADR-0018 window
// (#108, RM-075) — the state every pre-existing test in this file means to
// construct: a registration or a closure that is already, unambiguously, old
// news.
var wellPastMinAge = time.Now().Add(-DefaultMinAge - time.Hour)

// registered appends the run_registered event the MCP would append for run,
// dated wellPastMinAge. Use registeredAt directly to date one otherwise.
func (f *fakeLedger) registered(eventID, runID string) *fakeLedger {
	return f.registeredAt(eventID, runID, wellPastMinAge)
}

// registeredAt is registered with an explicit `ts`, for a test that cares
// where a run sits relative to Config.MinAge.
func (f *fakeLedger) registeredAt(eventID, runID string, at time.Time) *fakeLedger {
	return f.add(eventID, event.Fields{
		event.FieldEventType: event.EventTypeRunRegistered,
		event.FieldSource:    event.SourceMCP,
		event.FieldRunID:     runID,
		event.FieldSpiffeID:  fakeSPIFFEID(runID),
		event.FieldTS:        event.NewTimestamp(at).String(),
	})
}

// closed appends a run_retired/run_expired event dated wellPastMinAge. Use
// closedAt directly to date one otherwise.
func (f *fakeLedger) closed(eventID, runID, eventType string) *fakeLedger {
	return f.closedAt(eventID, runID, eventType, wellPastMinAge)
}

// closedAt is closed with an explicit `ts`.
func (f *fakeLedger) closedAt(eventID, runID, eventType string, at time.Time) *fakeLedger {
	return f.add(eventID, event.Fields{
		event.FieldEventType: eventType,
		event.FieldSource:    event.SourceMCP,
		event.FieldRunID:     runID,
		event.FieldSpiffeID:  fakeSPIFFEID(runID),
		event.FieldTS:        event.NewTimestamp(at).String(),
	})
}

func fakeEntry(id, spiffeID string) Entry {
	return Entry{
		ID:        id,
		SPIFFEID:  spiffeID,
		ParentID:  "spiffe://innsegl.dev/spire/agent/x509pop/node",
		Selectors: []Selector{{Type: "unix", Value: "uid:10001"}},
		TTL:       DefaultRunTTL,
	}
}

func newUnitReconciler(t *testing.T, src *fakeEntries, led *fakeLedger) (*Reconciler, *[]Drift) {
	t.Helper()
	var loud []Drift
	r, err := NewReconciler(ReconcilerConfig{
		Entries:  src,
		Ledger:   led,
		Appender: led,
		Alert:    func(_ context.Context, d Drift) { loud = append(loud, d) },
	})
	if err != nil {
		t.Fatalf("NewReconciler: %v", err)
	}
	return r, &loud
}

// TestReconcileClassifiesEveryDriftKind walks the four states the comparison
// can produce, and — the part that matters — the two it must not report.
func TestReconcileClassifiesEveryDriftKind(t *testing.T) {
	led := &fakeLedger{}
	led.registered("01a047a5-cc41-7c45-86fd-000000000001", "run-clean")
	led.registered("01a047a5-cc41-7c45-86fd-000000000002", "run-missing")
	led.registered("01a047a5-cc41-7c45-86fd-000000000003", "run-dup")
	led.registered("01a047a5-cc41-7c45-86fd-000000000004", "run-retired")
	led.closed("01a047a5-cc41-7c45-86fd-000000000005", "run-retired", event.EventTypeRunRetired)
	led.registered("01a047a5-cc41-7c45-86fd-000000000006", "run-expired")
	led.closed("01a047a5-cc41-7c45-86fd-000000000007", "run-expired", event.EventTypeRunExpired)

	src := &fakeEntries{
		td: "innsegl.dev",
		entries: []Entry{
			// clean: one entry, one active registration. No drift.
			fakeEntry("e-clean", fakeSPIFFEID("run-clean")),
			// duplicated: two entries for one active run.
			fakeEntry("e-dup-1", fakeSPIFFEID("run-dup")),
			fakeEntry("e-dup-2", fakeSPIFFEID("run-dup")),
			// not deleted: the run is retired and the entry is back.
			fakeEntry("e-retired", fakeSPIFFEID("run-retired")),
			// unattributed: no ledger run at all.
			fakeEntry("e-rogue", fakeSPIFFEID("run-rogue")),
			// run-missing has no entry, and run-expired correctly has none.
		},
	}

	r, loud := newUnitReconciler(t, src, led)
	result, err := r.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	want := map[string]DriftKind{
		fakeSPIFFEID("run-missing"): DriftEntryMissing,
		fakeSPIFFEID("run-dup"):     DriftEntryDuplicated,
		fakeSPIFFEID("run-retired"): DriftEntryNotDeleted,
		fakeSPIFFEID("run-rogue"):   DriftEntryUnattributed,
	}
	got := map[string]DriftKind{}
	for _, d := range result.Drifts {
		if _, dup := got[d.SPIFFEID]; dup {
			t.Errorf("two drifts for %s", d.SPIFFEID)
		}
		got[d.SPIFFEID] = d.Kind
	}
	for id, kind := range want {
		if got[id] != kind {
			t.Errorf("drift for %s is %q, want %q", id, got[id], kind)
		}
	}
	// The negative control, in unit form: the clean run and the correctly
	// retired run are absent. A reconciler that alerts on everything fails
	// here and passes every assertion above.
	for _, quiet := range []string{fakeSPIFFEID("run-clean"), fakeSPIFFEID("run-expired")} {
		if kind, present := got[quiet]; present {
			t.Errorf("%s raised a %q drift; it is in agreement", quiet, kind)
		}
	}
	if len(result.Drifts) != len(want) {
		t.Errorf("cycle reported %d drifts, want %d: %+v", len(result.Drifts), len(want), result.Drifts)
	}

	// Three of the four carry a subject event and become ledger events; the
	// unattributed one cannot and goes to the sink instead.
	if len(result.Appended) != 3 {
		t.Errorf("appended %d events, want 3: %v", len(result.Appended), result.Appended)
	}
	if len(result.Unrecordable) != 1 || result.Unrecordable[0].Kind != DriftEntryUnattributed {
		t.Errorf("unrecordable is %+v, want one %s", result.Unrecordable, DriftEntryUnattributed)
	}
	if len(*loud) != 1 || (*loud)[0].SPIFFEID != fakeSPIFFEID("run-rogue") {
		t.Errorf("alert sink saw %+v, want only the unattributed entry", *loud)
	}
}

// ---------------------------------------------------------------------------
// SPI-009 and SPI-010 (#108, RM-075) — the age gate on DriftEntryMissing.
//
// NOT YET IN DOC 07, the same footnote SPI-008 carries above: docs/ is
// local-only to the implementing agent, so the rows are written here and must
// be added to doc 07 §TC-SPI by a human:
//
//	| SPI-009 | U | run_registered with no SPIRE entry, inside Config.MinAge |
//	  No drift; a later cycle over the same unaged state is still quiet | #108,
//	  RM-075, ADR-0018 |
//	| SPI-010 | U | run_registered with no SPIRE entry, past Config.MinAge, and
//	  the idempotency key never replayed | ledger_drift_detected, naming the
//	  run_registered event, appended exactly once across repeated cycles | I3,
//	  I4, #108, RM-075 |
//
// # The caller that does not replay
//
// register_agent's mint() (internal/mcp/register_agent.go) appends
// run_registered and then creates the SPIRE entry. Simulating a caller that
// crashed in between means writing the first half only — the ledger event —
// and never the second: no RegisterRun, no LookupRun, and critically no
// second call under the same idempotency_key, because that is what ADR-0018
// documents as the only thing that closes this window today, and it is
// exactly the case OPS-003 found closing for nothing. Neither test below ever
// constructs a second call. That absence is the whole of what makes this a
// caller that has died for good rather than one still retrying — the same
// distinction the file comment above draws between MCP-011/REC-002 (a caller
// that comes back) and this one (a caller that does not).
//
// # The failing red this fix was driven by
//
// Before Config.MinAge existed (added by this change), compareEntries had no
// notion of age at all: DriftEntryMissing fired for ANY run_registered with no
// entry, the instant a cycle observed it — including one appended a
// millisecond earlier. TestSPI009RegistrationInsideTheWindowRaisesNoDrift is
// that red, verbatim, against the pre-fix compareEntries(view, entries)
// two-argument form:
//
//	reconcile_test.go:NNN: a run 1s into its legitimate register_agent window
//	  was reported as spire_entry_missing: {Kind:spire_entry_missing
//	  SPIFFEID:spiffe://innsegl.dev/agent/fix-ci/jira-1/run-inflight
//	  RunID:run-inflight EntryIDs:[] SubjectEventID:...
//	  Reason:spire_entry_missing: the ledger shows this run registered and not
//	  retired or expired, and SPIRE holds no registration entry for it}
//
// That is a false accusation against a run doing nothing wrong — RM-018 and
// RM-065 are this project's standing reminder that convicting a healthy
// system is worse than the gap being closed.

// TestSPI009RegistrationInsideTheWindowRaisesNoDrift proves the negative that
// matters most: a run mid-registration, well inside Config.MinAge, is never
// swept, on the first cycle or any later one that still finds it unaged.
func TestSPI009RegistrationInsideTheWindowRaisesNoDrift(t *testing.T) {
	base := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)

	led := &fakeLedger{}
	led.registeredAt("01a047a5-cc41-7c45-86fd-000000000001", "run-inflight", base)
	src := &fakeEntries{td: "innsegl.dev"} // no entry: register_agent has not created it yet.

	for _, elapsed := range []time.Duration{0, time.Second, DefaultMinAge - time.Second} {
		t.Run(elapsed.String(), func(t *testing.T) {
			r, err := NewReconciler(ReconcilerConfig{
				Entries: src, Ledger: led, Appender: led,
				Now: func() time.Time { return base.Add(elapsed) },
			})
			if err != nil {
				t.Fatalf("NewReconciler: %v", err)
			}
			result, err := r.Reconcile(context.Background())
			if err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			if got := driftsFor(result, fakeSPIFFEID("run-inflight")); len(got) != 0 {
				t.Fatalf("a run %s into its legitimate register_agent window was reported as "+
					"%+v", elapsed, got)
			}
			if len(result.Appended) != 0 {
				t.Errorf("appended %v over a run still inside its window", result.Appended)
			}
		})
	}

	// Live and healthy is not a one-shot property: a second cycle that still
	// finds the registration unaged must be exactly as quiet as the first.
	r, err := NewReconciler(ReconcilerConfig{
		Entries: src, Ledger: led, Appender: led,
		Now: func() time.Time { return base.Add(time.Second) },
	})
	if err != nil {
		t.Fatalf("NewReconciler: %v", err)
	}
	for i := range 3 {
		result, rerr := r.Reconcile(context.Background())
		if rerr != nil {
			t.Fatalf("cycle %d: %v", i, rerr)
		}
		if got := driftsFor(result, fakeSPIFFEID("run-inflight")); len(got) != 0 {
			t.Fatalf("cycle %d: still inside the window and reported as %+v", i, got)
		}
	}
}

// TestSPI010OrphanedRegistrationPastTheWindowIsRecordedAndNeverReplayed is the
// positive: the same shape, aged past Config.MinAge, with the caller's
// idempotency key never replayed (see the file comment). It must be recorded
// exactly once, however many cycles run afterward — REC-005's rule, applied
// to the state OPS-003 found.
func TestSPI010OrphanedRegistrationPastTheWindowIsRecordedAndNeverReplayed(t *testing.T) {
	base := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	registeredEvent := "01a047a5-cc41-7c45-86fd-000000000001"

	led := &fakeLedger{}
	led.registeredAt(registeredEvent, "run-orphan", base)
	src := &fakeEntries{td: "innsegl.dev"} // no entry, ever: the caller died before creating one.

	now := base.Add(DefaultMinAge + time.Minute)
	newReconciler := func(t *testing.T) *Reconciler {
		t.Helper()
		r, err := NewReconciler(ReconcilerConfig{
			Entries: src, Ledger: led, Appender: led,
			Now: func() time.Time { return now },
		})
		if err != nil {
			t.Fatalf("NewReconciler: %v", err)
		}
		return r
	}

	first, err := newReconciler(t).Reconcile(context.Background())
	if err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	got := driftsFor(first, fakeSPIFFEID("run-orphan"))
	if len(got) != 1 || got[0].Kind != DriftEntryMissing {
		t.Fatalf("an orphaned registration %s past MinAge produced %+v, want one %s",
			DefaultMinAge+time.Minute, got, DriftEntryMissing)
	}
	if got[0].SubjectEventID != registeredEvent {
		t.Errorf("drift names subject %q, want the run_registered event %q",
			got[0].SubjectEventID, registeredEvent)
	}
	if len(first.Appended) != 1 {
		t.Fatalf("first cycle appended %v, want the one ledger_drift_detected", first.Appended)
	}
	body := led.records[len(led.records)-1]
	if et := recordString(body, event.FieldEventType); et != event.EventTypeLedgerDriftDetected {
		t.Fatalf("appended a %s, want %s", et, event.EventTypeLedgerDriftDetected)
	}
	if subj := recordString(body, event.FieldSubjectEventID); subj != registeredEvent {
		t.Errorf("appended event names subject %q, want %q", subj, registeredEvent)
	}

	// No replay ever happens — see the file comment — so nothing but this
	// control's own idempotency should ever produce a second event, across as
	// many cycles as run afterward, fresh reconciler or not.
	t.Run("SecondCycleAppendsNothing", func(t *testing.T) {
		second, serr := newReconciler(t).Reconcile(context.Background())
		if serr != nil {
			t.Fatalf("second Reconcile: %v", serr)
		}
		if len(second.Appended) != 0 {
			t.Errorf("second cycle appended %v, want nothing", second.Appended)
		}
		if got := driftsFor(second, fakeSPIFFEID("run-orphan")); len(got) != 1 {
			t.Errorf("the orphan stopped being reported once recorded: %+v", got)
		}
	})
	if n := len(led.records); n != 2 {
		t.Errorf("ledger holds %d records after two cycles, want 2 (registration + one drift alert)", n)
	}
}

// TestReconcileAppendsAValidLedgerDriftEvent holds the appended body to the
// closed schema rather than to this package's idea of it.
func TestReconcileAppendsAValidLedgerDriftEvent(t *testing.T) {
	led := &fakeLedger{}
	led.registered("01a047a5-cc41-7c45-86fd-000000000001", "run-missing")
	src := &fakeEntries{td: "innsegl.dev"}

	r, _ := newUnitReconciler(t, src, led)
	if _, err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(led.records) != 2 {
		t.Fatalf("ledger holds %d records, want 2", len(led.records))
	}
	body := led.records[1].Clone()
	// The store assigns these; the fake stands in for it.
	body[event.FieldTS] = "2026-08-28T09:14:03.201Z"
	body[event.FieldSchemaVersion] = event.SchemaVersion
	body[event.FieldPrevEventHash] = "sha256:" + strings.Repeat("0", 64)
	if err := event.ValidateEvent(body); err != nil {
		t.Errorf("the appended drift event is not a valid %s: %v\n%v",
			event.EventTypeLedgerDriftDetected, err, body)
	}
}

// TestReconcileOmitsARunItCannotNameInTheAlert covers the one case where the
// alert drops the attribution to keep the alert: a ledger whose record of the
// run does not satisfy doc 02 §5's SPIFFE ID grammar. Naming it would make the
// event unappendable, and an alert nobody can write is worse than an alert that
// says only what it can prove.
func TestReconcileOmitsARunItCannotNameInTheAlert(t *testing.T) {
	led := &fakeLedger{}
	led.add("01a047a5-cc41-7c45-86fd-000000000001", event.Fields{
		event.FieldEventType: event.EventTypeRunRegistered,
		event.FieldSource:    event.SourceMCP,
		event.FieldRunID:     "run-a",
		// Three path segments, not four: not a run identity.
		event.FieldSpiffeID: "spiffe://innsegl.dev/agent/fix-ci",
		event.FieldTS:       event.NewTimestamp(wellPastMinAge).String(),
	})
	src := &fakeEntries{td: "innsegl.dev"}

	r, _ := newUnitReconciler(t, src, led)
	result, err := r.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(result.Appended) != 1 {
		t.Fatalf("appended %v, want the alert anyway", result.Appended)
	}
	body := led.records[1]
	for _, omitted := range []string{event.FieldRunID, event.FieldSpiffeID} {
		if _, present := body[omitted]; present {
			t.Errorf("the alert carries %s=%v, which the ledger would refuse", omitted, body[omitted])
		}
	}
	staged := body.Clone()
	staged[event.FieldTS] = "2026-08-28T09:14:03.201Z"
	staged[event.FieldSchemaVersion] = event.SchemaVersion
	staged[event.FieldPrevEventHash] = "sha256:" + strings.Repeat("0", 64)
	if verr := event.ValidateEvent(staged); verr != nil {
		t.Errorf("the alert is not a valid event: %v\n%v", verr, staged)
	}
}

// TestDriftReasonsFitTheSchema keeps the reason vocabulary inside doc 02's
// bound for the one free-text member in the schema.
func TestDriftReasonsFitTheSchema(t *testing.T) {
	for _, kind := range []DriftKind{
		DriftEntryMissing, DriftEntryNotDeleted, DriftEntryDuplicated, DriftEntryUnattributed,
	} {
		reason := driftReason(kind)
		if reason == "" {
			t.Errorf("%s has no reason text", kind)
		}
		if len(reason) > event.MaxTextBytes {
			t.Errorf("%s reason is %d bytes, over the %d-byte bound on reason",
				kind, len(reason), event.MaxTextBytes)
		}
		if !strings.HasPrefix(reason, string(kind)) {
			t.Errorf("%s reason %q does not begin with the kind", kind, reason)
		}
	}
	// A kind this package does not know has no reason, and so cannot be
	// recorded as an alert whose text says nothing.
	if reason := driftReason(DriftKind("not-a-kind")); reason != "" {
		t.Errorf("an unknown drift kind produced the reason %q", reason)
	}
}

// TestReconcileIsIdempotentAgainstTheLedgersOwnRecord is the unit half of
// REC-005 applied here: the dedupe key is (subject_event_id, reason) read back
// from the chain, so a fresh reconciler over the same state is silent.
func TestReconcileIsIdempotentAgainstTheLedgersOwnRecord(t *testing.T) {
	led := &fakeLedger{}
	led.registered("01a047a5-cc41-7c45-86fd-000000000001", "run-missing")
	src := &fakeEntries{td: "innsegl.dev"}

	first, _ := newUnitReconciler(t, src, led)
	r1, err := first.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	if len(r1.Appended) != 1 {
		t.Fatalf("first cycle appended %v, want one event", r1.Appended)
	}

	second, _ := newUnitReconciler(t, src, led)
	r2, err := second.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if len(r2.Appended) != 0 {
		t.Errorf("a fresh reconciler appended %v over unchanged state", r2.Appended)
	}
	if len(r2.Drifts) != 1 {
		t.Errorf("the drift stopped being reported once recorded: %+v", r2.Drifts)
	}
	if len(led.records) != 2 {
		t.Errorf("ledger holds %d records after two cycles, want 2", len(led.records))
	}
}

// TestReconcileAlertSinkDoesNotRepeatWithinAProcess covers the one dedupe that
// cannot be ledger-backed, because the drift it guards has no ledger event.
func TestReconcileAlertSinkDoesNotRepeatWithinAProcess(t *testing.T) {
	led := &fakeLedger{}
	src := &fakeEntries{
		td:      "innsegl.dev",
		entries: []Entry{fakeEntry("e-rogue", fakeSPIFFEID("run-rogue"))},
	}
	r, loud := newUnitReconciler(t, src, led)
	for i := range 3 {
		if _, err := r.Reconcile(context.Background()); err != nil {
			t.Fatalf("cycle %d: %v", i, err)
		}
	}
	if len(*loud) != 1 {
		t.Errorf("alert sink fired %d times over three identical cycles, want 1: %+v", len(*loud), *loud)
	}
}

func TestReconcileErrorPaths(t *testing.T) {
	sentinel := errors.New("boom")

	t.Run("SPIREUnreachable", func(t *testing.T) {
		r, _ := newUnitReconciler(t, &fakeEntries{td: "innsegl.dev", err: sentinel}, &fakeLedger{})
		if _, err := r.Reconcile(context.Background()); !errors.Is(err, sentinel) {
			t.Errorf("Reconcile returned %v, want the SPIRE failure", err)
		}
	})

	t.Run("LedgerCountFails", func(t *testing.T) {
		r, _ := newUnitReconciler(t, &fakeEntries{td: "innsegl.dev"}, &fakeLedger{countErr: sentinel})
		if _, err := r.Reconcile(context.Background()); !errors.Is(err, sentinel) {
			t.Errorf("Reconcile returned %v, want the ledger failure", err)
		}
	})

	t.Run("LedgerReadFails", func(t *testing.T) {
		led := &fakeLedger{eventsErr: sentinel}
		led.registered("01a047a5-cc41-7c45-86fd-000000000001", "run-a")
		r, _ := newUnitReconciler(t, &fakeEntries{td: "innsegl.dev"}, led)
		if _, err := r.Reconcile(context.Background()); !errors.Is(err, sentinel) {
			t.Errorf("Reconcile returned %v, want the ledger failure", err)
		}
	})

	t.Run("AppendFails", func(t *testing.T) {
		led := &fakeLedger{appendErr: sentinel}
		led.registered("01a047a5-cc41-7c45-86fd-000000000001", "run-missing")
		r, _ := newUnitReconciler(t, &fakeEntries{td: "innsegl.dev"}, led)
		result, err := r.Reconcile(context.Background())
		if !errors.Is(err, sentinel) {
			t.Errorf("Reconcile returned %v, want the append failure", err)
		}
		// The drift is still reported: failing to record it must not also hide
		// it (I3 — a record the ledger refused is not a reason to go quiet).
		if len(result.Drifts) != 1 {
			t.Errorf("a failed append lost the drift: %+v", result)
		}
	})
}

func TestNewReconcilerRejectsAnIncompleteConfig(t *testing.T) {
	src := &fakeEntries{td: "innsegl.dev"}
	led := &fakeLedger{}
	for name, cfg := range map[string]ReconcilerConfig{
		"NoEntrySource": {Ledger: led, Appender: led},
		"NoLedger":      {Entries: src, Appender: led},
		"NoAppender":    {Entries: src, Ledger: led},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewReconciler(cfg); err == nil {
				t.Errorf("NewReconciler accepted a config with no %s", name)
			}
		})
	}
}

func TestRunReconcilesPeriodicallyUntilTheContextIsDone(t *testing.T) {
	src := &fakeEntries{td: "innsegl.dev"}
	led := &fakeLedger{}
	seen := make(chan struct{}, 8)
	r, err := NewReconciler(ReconcilerConfig{
		Entries:  src,
		Ledger:   led,
		Appender: led,
		Observe:  func(Result, error) { seen <- struct{}{} },
	})
	if err != nil {
		t.Fatalf("NewReconciler: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx, time.Millisecond) }()

	for i := range 3 {
		select {
		case <-seen:
		case <-time.After(10 * time.Second):
			cancel()
			t.Fatalf("only %d cycles observed", i)
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}

func TestRunRejectsANonPositiveInterval(t *testing.T) {
	src := &fakeEntries{td: "innsegl.dev"}
	led := &fakeLedger{}
	r, err := NewReconciler(ReconcilerConfig{Entries: src, Ledger: led, Appender: led})
	if err != nil {
		t.Fatalf("NewReconciler: %v", err)
	}
	if err := r.Run(context.Background(), 0); err == nil {
		t.Error("Run accepted a zero interval")
	}
}
