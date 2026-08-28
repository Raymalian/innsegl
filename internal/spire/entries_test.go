// SPDX-License-Identifier: Apache-2.0

package spire

import (
	"context"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
)

// SPI-001 (doc 07, layer I)
//
//	register creates entry; workload with matching selectors fetches SVID
//	→ SVID SPIFFE ID equals spiffe://innsegl.dev/agent/{type}/{task}/{run}
//	→ proves I1, "no identity without attestation"
//
// The assertion is byte-exact against a locally constructed string, not against
// whatever the client happened to build: the SPIFFE ID scheme is a protected
// string (doc 01 §1) and a test that compared the client to itself would
// ratify a rename instead of catching it.
func TestSPI001RegisterCreatesEntryAndWorkloadFetchesItsSVID(t *testing.T) {
	s := requireStack(t)
	c := s.adminClient(t)
	run := newRun(t, "demo", "rm-015")

	want := "spiffe://" + testTrustDomain + "/agent/" + run.AgentType + "/" + run.TaskID + "/" + run.RunID

	entry := registerForTest(t, c, s, run)

	if entry.SPIFFEID != want {
		t.Errorf("entry SPIFFE ID = %q, want %q", entry.SPIFFEID, want)
	}
	if entry.ID == "" {
		t.Error("RegisterRun returned no entry ID")
	}
	if entry.ParentID != s.parentID {
		t.Errorf("entry parent = %q, want the attested node %q", entry.ParentID, s.parentID)
	}
	// IP §1: one entry per run, short TTL.
	if entry.TTL != DefaultRunTTL {
		t.Errorf("entry TTL = %s, want %s", entry.TTL, DefaultRunTTL)
	}

	// One entry per run, checked at the server rather than inferred from the
	// create call: SPIRE is the authority on how many entries exist.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	shown, err := s.spireLocal(ctx, "entry", "show", "-spiffeID", want)
	if err != nil {
		t.Fatalf("entry show: %v", err)
	}
	if n := strings.Count(shown, "Entry ID"); n != 1 {
		t.Errorf("SPIRE holds %d entries for %s, want exactly 1:\n%s", n, want, shown)
	}

	// The identity itself: a container carrying the run's selectors, fetching
	// its own SVID over the Workload API.
	got := s.probeUntilIssued(t, run, 90*time.Second)
	if got.Outcome.SPIFFEID != want {
		t.Errorf("workload SVID = %q, want %q (raw probe output: %s)",
			got.Outcome.SPIFFEID, want, got.Raw)
	}
	if got.Outcome.Class != "" {
		t.Errorf("workload fetch reported class %q, want none", got.Outcome.Class)
	}
	if got.Outcome.ExpiresAt == "" {
		t.Error("workload SVID carried no expiry")
	}
}

// SPI-004 (doc 07, layer I)
//
//	retire_agent deletes entry
//	→ Immediate credential refusal; ledger events for the run remain readable
//	→ proves I4 and IP §6.2
//
// # Where the immediacy comes from, measured rather than assumed
//
// SPIRE's own refusal is NOT immediate and this test does not pretend it is.
// RM-014 measured 3–7 seconds for a deleted entry to fall out of the server's
// and then the agent's caches, and re-measuring it here is one of the things
// this case does. IP §6.2 asks for something else and says so precisely:
//
//	"Test that retirement is effective immediately (no cached-credential grace
//	 path *through the MCP*)."
//
// Through the MCP. The immediacy is an obligation on us, and the primitive that
// discharges it is Client.RequireActiveRun: it asks the SPIRE *server*, whose
// datastore has no entry the instant the delete returns, rather than asking an
// agent cache. So the assertions are in three parts, each labelled:
//
//	IMMEDIATE, server-side  the entry is gone and RequireActiveRun refuses, with
//	                        no sleep anywhere between the delete and the check;
//	EVENTUAL, SPIRE-side    the workload keeps its already-minted SVID for a few
//	                        seconds; the test measures how long and reports it;
//	UNTOUCHED, ledger-side  the run's events are still there and still verify.
func TestSPI004RetireDeletesEntryAndLeavesTheLedgerAlone(t *testing.T) {
	s := requireStack(t)
	c := s.adminClient(t)
	store := requireLedger(t)
	run := newRun(t, "demo", "rm-015")

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	spiffeID, err := run.SPIFFEID(testTrustDomain)
	if err != nil {
		t.Fatalf("RunRef.SPIFFEID: %v", err)
	}

	entry := registerForTest(t, c, s, run)
	// The run is live before it is retired — otherwise "refused after
	// retirement" would be true of a run that never had an identity.
	s.probeUntilIssued(t, run, 90*time.Second)
	if activeErr := c.RequireActiveRun(ctx, run); activeErr != nil {
		t.Fatalf("RequireActiveRun before retirement: %v", activeErr)
	}

	// The ledger record of the run, written the way the MCP will write it
	// (IP §6.5 makes the pairing atomic; that is E4's, not this package's).
	registered := appendEvent(t, store, ledgerEvent{
		eventType:      event.EventTypeRunRegistered,
		runID:          run.RunID,
		spiffeID:       spiffeID,
		idempotencyKey: "register:" + run.RunID,
		extra: event.Fields{
			event.FieldAgentType: run.AgentType,
			event.FieldTaskRef:   "RM-015",
		},
	})

	// --- retirement -------------------------------------------------------
	retirement, err := c.RetireRun(ctx, run)
	if err != nil {
		t.Fatalf("RetireRun: %v", err)
	}
	if !retirement.Deleted {
		t.Error("RetireRun reported nothing deleted, but the run had an entry")
	}
	if retirement.EntryID != entry.ID {
		t.Errorf("RetireRun deleted entry %q, want %q", retirement.EntryID, entry.ID)
	}

	// --- IMMEDIATE, server-side: no sleep, no polling ---------------------
	refusal := c.RequireActiveRun(ctx, run)
	if refusal == nil {
		t.Fatal("RequireActiveRun succeeded immediately after retirement: " +
			"that is the cached-credential grace path IP §6.2 forbids")
	}
	if class, ok := ClassOf(refusal); !ok || class != ClassRunNotFound {
		t.Errorf("RequireActiveRun after retirement: class %q (ok=%v), want %s",
			class, ok, ClassRunNotFound)
	}
	if IsRetryable(refusal) {
		t.Error("refusal after retirement is marked retryable; retrying cannot un-retire a run")
	}
	if _, found, lookupErr := c.LookupRun(ctx, run); lookupErr != nil {
		t.Fatalf("LookupRun after retirement: %v", lookupErr)
	} else if found {
		t.Error("SPIRE still holds an entry for the run immediately after retirement")
	}

	// Retirement is idempotent (IP §4): retiring a retired run is a success.
	second, err := c.RetireRun(ctx, run)
	if err != nil {
		t.Fatalf("second RetireRun: %v", err)
	}
	if second.Deleted {
		t.Error("second RetireRun claims to have deleted an entry that was already gone")
	}

	// --- UNTOUCHED, ledger-side: I4 ---------------------------------------
	retired := appendEvent(t, store, ledgerEvent{
		eventType: event.EventTypeRunRetired,
		runID:     run.RunID,
		spiffeID:  spiffeID,
	})
	count, err := store.Count(ctx)
	if err != nil {
		t.Fatalf("count the run's events: %v", err)
	}
	records, err := store.Events(ctx, 1, count)
	if err != nil {
		t.Fatalf("read the run's events back: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("ledger holds %d events for the retired run, want 2", len(records))
	}
	if got := records[0][event.EventHashField]; got != registered[event.EventHashField] {
		t.Errorf("run_registered event_hash changed across retirement: %v, want %v",
			got, registered[event.EventHashField])
	}
	if got := records[1][event.EventHashField]; got != retired[event.EventHashField] {
		t.Errorf("run_retired event_hash mismatch: %v, want %v",
			got, retired[event.EventHashField])
	}
	for i, rec := range records {
		if rec[event.FieldSpiffeID] != spiffeID {
			t.Errorf("event %d names %v, want the retired run's %s",
				i, rec[event.FieldSpiffeID], spiffeID)
		}
	}
	if _, err := ledger.Verify(records); err != nil {
		t.Errorf("the retired run's chain no longer verifies: %v", err)
	}

	// --- EVENTUAL, SPIRE-side: measured, never called immediate -----------
	//
	// The workload keeps the SVID the agent already minted until the deletion
	// has propagated through the server's entry cache and the agent's. This
	// loop reports how long that took on this stack. It is a floor the MCP sits
	// on, not the immediacy IP §6.2 asks for — that was asserted above, with no
	// sleep, against the server.
	started := time.Now()
	converged := false
	for attempt := 1; time.Since(started) < 2*time.Minute; attempt++ {
		got := s.runProbe(t, run, run)
		if got.ExitCode != 0 {
			t.Logf("SPIRE converged on refusal %s after the delete "+
				"(%d probe attempt(s)); class=%s retryable=%v. "+
				"This is eventual by construction — see the comment above.",
				time.Since(started).Round(time.Millisecond), attempt,
				got.Outcome.Class, got.Outcome.Retryable)
			if got.Outcome.Class != ClassAttestationFailed {
				t.Errorf("post-retirement workload fetch: class %q, want %s",
					got.Outcome.Class, ClassAttestationFailed)
			}
			converged = true
			break
		}
		time.Sleep(2 * time.Second)
	}
	if !converged {
		t.Error("SPIRE was still issuing SVIDs for a deleted entry after 2 minutes")
	}
}

// TestRegisterRunRefusesOutsideTheAgentSubtree is the client-side half of the
// same rule SPI-005 tests at the server. It is defence in depth and is labelled
// as such: it proves the client will not *ask*, and proves nothing at all about
// what a stolen credential could do. SPI-005 is the test that matters.
func TestRegisterRunRefusesOutsideTheAgentSubtree(t *testing.T) {
	s := requireStack(t)
	c := s.adminClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	for _, bad := range []RunRef{
		{AgentType: "", TaskID: "rm-015", RunID: "run-1"},
		{AgentType: "demo", TaskID: "", RunID: "run-1"},
		{AgentType: "demo", TaskID: "rm-015", RunID: ""},
		{AgentType: "demo/../..", TaskID: "rm-015", RunID: "run-1"},
		{AgentType: "DEMO", TaskID: "rm-015", RunID: "run-1"},
	} {
		_, err := c.RegisterRun(ctx, Registration{
			Run:       bad,
			ParentID:  s.parentID,
			Selectors: runSelectors(bad),
		})
		if err == nil {
			t.Errorf("RegisterRun(%+v) succeeded; it must not build a SPIFFE ID outside the scheme", bad)
			continue
		}
		if class, ok := ClassOf(err); !ok || class != ClassInvariantViolation {
			t.Errorf("RegisterRun(%+v): class %q (ok=%v), want %s", bad, class, ok, ClassInvariantViolation)
		}
	}
}

// TestRegisterRunIsOneEntryPerRun asserts the second registration of the same
// run is reported as a duplicate rather than silently making a second identity.
// IP §4: "Same idempotency_key → same run, never a second identity."
func TestRegisterRunIsOneEntryPerRun(t *testing.T) {
	s := requireStack(t)
	c := s.adminClient(t)
	run := newRun(t, "demo", "rm-015")

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	registerForTest(t, c, s, run)

	_, err := c.RegisterRun(ctx, Registration{
		Run:       run,
		ParentID:  s.parentID,
		Selectors: runSelectors(run),
	})
	if err == nil {
		t.Fatal("a second RegisterRun for the same run succeeded; that is a second identity")
	}
	if class, ok := ClassOf(err); !ok || class != ClassDuplicateRequest {
		t.Errorf("second RegisterRun: class %q (ok=%v), want %s", class, ok, ClassDuplicateRequest)
	}

	spiffeID, err := run.SPIFFEID(testTrustDomain)
	if err != nil {
		t.Fatalf("RunRef.SPIFFEID: %v", err)
	}
	shown, err := s.spireLocal(ctx, "entry", "show", "-spiffeID", spiffeID)
	if err != nil {
		t.Fatalf("entry show: %v", err)
	}
	if n := strings.Count(shown, "Entry ID"); n != 1 {
		t.Errorf("SPIRE holds %d entries for %s after a duplicate registration, want 1", n, spiffeID)
	}
}

// TestRetireRunOnAnUnknownRunIsIdempotent covers the other retirement path:
// IP §4 makes retirement idempotent, so a run SPIRE never knew is a success
// with nothing deleted, not an error.
func TestRetireRunOnAnUnknownRunIsIdempotent(t *testing.T) {
	s := requireStack(t)
	c := s.adminClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	got, err := c.RetireRun(ctx, newRun(t, "demo", "rm-015"))
	if err != nil {
		t.Fatalf("RetireRun on an unknown run: %v", err)
	}
	if got.Deleted || got.EntryID != "" {
		t.Errorf("RetireRun on an unknown run = %+v, want nothing deleted", got)
	}
}

// ---------------------------------------------------------------------------
// Ledger helpers, local to this file.
// ---------------------------------------------------------------------------

type ledgerEvent struct {
	eventType string
	runID     string
	spiffeID  string
	// idempotencyKey is set only for the event types whose MCP tool takes one.
	// ADR-0004 scopes the key to those tools, and the schema refuses it on the
	// others — retire_agent among them.
	idempotencyKey string
	extra          event.Fields
}

// appendEvent writes one event and returns the stored record.
func appendEvent(t *testing.T, store *ledger.Store, e ledgerEvent) event.Fields {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// event_id, ts, chain_position, prev_event_hash and event_hash are all
	// ledger-assigned (doc 02 §2); supplying any of them is refused.
	body := event.Fields{
		event.FieldSchemaVersion: event.SchemaVersion,
		event.FieldEventType:     e.eventType,
		event.FieldRunID:         e.runID,
		event.FieldSpiffeID:      e.spiffeID,
		event.FieldSource:        event.SourceMCP,
	}
	if e.idempotencyKey != "" {
		body[event.FieldIdempotencyKey] = e.idempotencyKey
	}
	for k, v := range e.extra {
		body[k] = v
	}
	rec, err := store.Append(ctx, body)
	if err != nil {
		t.Fatalf("ledger append %s: %v", e.eventType, err)
	}
	return rec
}
