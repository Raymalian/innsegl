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
		event.FieldRepo:           "github.com/acme/api",
		event.FieldBranch:         "main",
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

// The real-chain case for ADR-0020 §5's "earliest retirement wins" USED TO BE
// here, appending four `run_retired` events for one run. migrations/0004 makes
// that impossible — a partial unique index refuses a second retirement, because
// MCP-011 measured a crash producing two and IP §6.6 forbids it — so the test
// began failing on its own precondition:
//
//	append run_retired for run-earliest-retirement:
//	INVARIANT_VIOLATION: the run is already retired
//
// It is not replaced here. The rule is about chains written BEFORE the
// constraint, which the reader must still resolve because records are never
// rewritten (I4), and that is a property of the reader rather than of Postgres.
// TestTheEarliestRunRetiredWinsWhenSeveralArePresent in directory_test.go
// already holds it, with the retirements deliberately out of order. Two tests
// for one property is one too many.

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
