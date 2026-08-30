// SPDX-License-Identifier: Apache-2.0

package rundir

import (
	"context"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
)

// pgRunID is held to doc 02 §5's identifier grammar: it becomes a component of
// a SPIFFE ID.
const (
	pgRunID    = "run-earliest-retirement"
	pgOtherRun = "run-other"
	pgAgent    = "fix-ci"
	pgTask     = "jira-118"
)

func pgSPIFFEID(runID string) string {
	return "spiffe://innsegl.dev/agent/" + pgAgent + "/" + pgTask + "/" + runID
}

func appendRegistered(t *testing.T, store *ledger.Store, runID, key string) event.Fields {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rec, err := store.Append(ctx, event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeRunRegistered,
		event.FieldRunID:          runID,
		event.FieldSpiffeID:       pgSPIFFEID(runID),
		event.FieldSource:         event.SourceMCP,
		event.FieldIdempotencyKey: key,
		event.FieldAgentType:      pgAgent,
		event.FieldTaskRef:        pgTask,
	})
	if err != nil {
		t.Fatalf("append run_registered for %s: %v", runID, err)
	}
	return rec
}

// appendRetired appends one `run_retired`. It carries no idempotency_key:
// ADR-0004 forbids the member on this event type, which is the whole reason
// two concurrent first retirements can both land.
func appendRetired(t *testing.T, store *ledger.Store, runID string) event.Fields {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rec, err := store.Append(ctx, event.Fields{
		event.FieldSchemaVersion: event.SchemaVersion,
		event.FieldEventType:     event.EventTypeRunRetired,
		event.FieldRunID:         runID,
		event.FieldSpiffeID:      pgSPIFFEID(runID),
		event.FieldSource:        event.SourceMCP,
	})
	if err != nil {
		t.Fatalf("append run_retired for %s: %v", runID, err)
	}
	return rec
}

func tsOf(t *testing.T, rec event.Fields) time.Time {
	t.Helper()
	raw, ok := rec[event.FieldTS].(string)
	if !ok {
		t.Fatalf("the appended record carries no ts: %#v", rec)
	}
	ts, err := event.ParseTimestamp(raw)
	if err != nil {
		t.Fatalf("ParseTimestamp(%q): %v", raw, err)
	}
	return ts.Time()
}

// TestTheEarliestRunRetiredWinsOnARealChain is ADR-0020 §5 against a chain
// that really carries several `run_retired` events for one run.
//
// The situation is the ADR's own: a check-then-append cannot be atomic,
// because ADR-0004 forbids `run_retired` an idempotency_key, so two concurrent
// FIRST retirements both find no record and both append. This test creates
// four, spaced far enough apart that the ledger's millisecond-precision `ts`
// separates them, and then requires the directory to answer with the first
// one — which is what makes "retiring a retired run returns success with the
// original timestamp" (IP §4) true for every caller and not just for the one
// that happened to win.
func TestTheEarliestRunRetiredWinsOnARealChain(t *testing.T) {
	store := newLedger(t)
	appendRegistered(t, store, pgRunID, "register-"+pgRunID)

	// A second run, retired between the first run's retirements, so that a
	// reader whose scoping is wrong reports ITS instant and fails here.
	appendRegistered(t, store, pgOtherRun, "register-"+pgOtherRun)

	var retirements []time.Time
	for i := range 4 {
		if i == 2 {
			appendRetired(t, store, pgOtherRun)
		}
		retirements = append(retirements, tsOf(t, appendRetired(t, store, pgRunID)))
		// The ledger assigns `ts` at millisecond precision inside the
		// serialized append, so four appends in a burst can share an instant.
		// Separating them is what gives the word "earliest" something to mean.
		time.Sleep(3 * time.Millisecond)
	}

	first := retirements[0]
	for i, at := range retirements[1:] {
		if !at.After(first) {
			t.Fatalf("retirement %d landed at %s, not after the first at %s; "+
				"the chain does not carry four distinct instants and this case would "+
				"pass without proving anything",
				i+1, event.NewTimestamp(at), event.NewTimestamp(first))
		}
	}

	d, err := New(Config{Events: store})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	run, found, err := d.CredentialRun(context.Background(), pgRunID)
	if err != nil {
		t.Fatalf("CredentialRun: %v", err)
	}
	if !found {
		t.Fatal("the run is registered on the chain and was not found")
	}
	if !run.Retired() {
		t.Fatal("a run with four run_retired events on the chain is reported live")
	}
	if !run.RetiredAt.Equal(first) {
		t.Fatalf("RetiredAt is %s, want the earliest of %d retirements, %s (ADR-0020 §5)",
			event.NewTimestamp(run.RetiredAt), len(retirements), event.NewTimestamp(first))
	}
	t.Logf("four run_retired events on the chain at %v; the directory answers %s",
		retirements, event.NewTimestamp(run.RetiredAt))
}

// TestTheDirectoryReadsOnlyItsOwnRunOffARealChain. The scoping is a SQL
// predicate over a nullable column and an index; only a real chain can say
// whether it holds.
func TestTheDirectoryReadsOnlyItsOwnRunOffARealChain(t *testing.T) {
	store := newLedger(t)
	appendRegistered(t, store, pgRunID, "register-"+pgRunID)
	appendRegistered(t, store, pgOtherRun, "register-"+pgOtherRun)
	appendRetired(t, store, pgOtherRun)

	d, err := New(Config{Events: store})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	run, found, err := d.CredentialRun(context.Background(), pgRunID)
	if err != nil {
		t.Fatalf("CredentialRun: %v", err)
	}
	if !found {
		t.Fatal("the run was not found")
	}
	if run.Retired() {
		t.Fatalf("run %s is reported retired at %s; it was %s that was retired",
			pgRunID, event.NewTimestamp(run.RetiredAt), pgOtherRun)
	}
	if run.SPIFFEID != pgSPIFFEID(pgRunID) {
		t.Errorf("SPIFFEID is %q, want %q", run.SPIFFEID, pgSPIFFEID(pgRunID))
	}
	if run.AgentType != pgAgent || run.TaskID != pgTask {
		t.Errorf("the run is (%q, %q), want (%q, %q)", run.AgentType, run.TaskID, pgAgent, pgTask)
	}

	other, found, err := d.CredentialRun(context.Background(), pgOtherRun)
	if err != nil {
		t.Fatalf("CredentialRun(%s): %v", pgOtherRun, err)
	}
	if !found || !other.Retired() {
		t.Fatalf("%s is found=%v retired=%v; it was registered and retired", pgOtherRun, found, other.Retired())
	}
}

// TestAnUnregisteredRunIsUnknownOnARealChain.
func TestAnUnregisteredRunIsUnknownOnARealChain(t *testing.T) {
	store := newLedger(t)
	appendRegistered(t, store, pgOtherRun, "register-"+pgOtherRun)

	d, err := New(Config{Events: store})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, found, err := d.CredentialRun(context.Background(), pgRunID)
	if err != nil {
		t.Fatalf("CredentialRun: %v", err)
	}
	if found {
		t.Fatal("a run that was never registered was found on a real chain")
	}
}
