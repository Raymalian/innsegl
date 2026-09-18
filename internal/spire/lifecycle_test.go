// SPDX-License-Identifier: Apache-2.0

package spire

import (
	"context"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
)

// RM-151 (#254) — two defects in the run lifecycle, pinned and left failing.
//
// These two cases are written to FAIL. RM-152 (#255) and RM-155 (#258) are what
// make them pass; this issue's whole product is a red that names the defect
// precisely enough that the fix cannot be mistaken for something else. Neither
// case may be quieted by changing the fixture — each one constructs a state the
// deployment really reaches, drives the shipped code over it, and asserts the
// property the invariant requires.
//
// # ID COLLISION, for a human to settle
//
// This issue's acceptance criteria name SPI-014 for "second lapse records a
// second withdrawal". `internal/spire/reconcile_test.go` already claims SPI-014
// for SPIRE entry reconciliation (RM-019, #27), in a header that says the row
// is "NOT YET IN DOC 07" and must be added by a human. Doc 07 §TC-SPI still
// stops at SPI-007, so neither claim is in the catalogue and neither can be
// resolved by reading it. The ID here is the one the issue asked for; the
// collision is reported rather than silently renumbered.

// ---------------------------------------------------------------------------
// SPI-014 — a run that lapses twice is recorded twice.
//
//	A run lapses, is restored, works, and lapses again
//	→ a SECOND `run_expired` is appended, and the entry is never deleted
//	  without one
//	→ I3, IP §6.7
//
// # The defect
//
// `ExpiryKey` (reaper.go) is derived from the run id ALONE, so one run has one
// expiry key for its entire life. `record` reads that key, finds the first
// lapse's event, and returns `appended=false`. `reap` then calls `deleteEntry`
// UNCONDITIONALLY. A run that lapses a second time therefore has its identity
// deleted with nothing appended: an action with no record, which is exactly
// what I3 forbids.
//
// The stability that key buys is real and is not in dispute — two reapers
// looking at one orphan must not write two events for ONE lapse, and SPI-003
// already pins that. What this case says is that the second LAPSE is not a
// second pass over the first: an entry was created again, used again, and
// deleted again, and the chain records only the first of those deletions.
//
// # How it is kept from passing vacuously
//
//  1. THE RESTORE HAS TO HAVE HAPPENED. The entry is re-created and SPIRE is
//     asked whether it holds it, before the second wait begins. A test whose
//     restore silently did nothing would be sweeping an empty subtree.
//  2. THE RUN HAS TO HAVE WORKED. A `credential_issued` is appended between
//     the restore and the second lapse — the event get_credential writes when
//     it releases a credential to a restored run, and the one that makes this
//     a resumed run rather than a re-registered corpse. The reaper is
//     configured with the ledger as its ActivitySource (silence.go), so that
//     activity is a fact the reaper itself reads and not a decoration.
//  3. THE SECOND LAPSE HAS TO BE A LAPSE. The second sweep must report the run
//     expired and its entry deleted. Only then is "and it appended nothing"
//     the I3 violation rather than an entry the sweep never reached.
// ---------------------------------------------------------------------------

func TestSPI008SecondLapseRecordsASecondWithdrawal(t *testing.T) {
	s := requireStack(t)
	c := s.adminClient(t)
	store := requireLedger(t)

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	run := newRun(t, "demo", "rm-151")
	spiffeID := mustSPIFFEID(t, run)
	registerInLedger(t, store, run)

	// Grace 0 and a real, very short TTL, for SPI-003's reason: the elapsed
	// time is real and the grace is the only knob, so setting it to zero
	// shortens the wait without inventing a lapse that did not happen.
	reaper, err := NewReaper(ReaperConfig{Client: c, Ledger: store, Grace: 0, Activity: store})
	if err != nil {
		t.Fatalf("NewReaper: %v", err)
	}

	// --- lapse one -------------------------------------------------------
	firstRegistered := time.Now()
	registerWithTTL(t, c, s, run, shortRunTTL)
	waitPast(t, firstRegistered.Add(shortRunTTL+2*time.Second))

	first, err := reaper.Sweep(ctx)
	if err != nil {
		t.Fatalf("first Sweep: %v", err)
	}
	firstLapse, swept := first.FindExpired(run.RunID)
	if !swept {
		t.Fatalf("the first lapse of %s was not swept at all; this case proves nothing "+
			"about a second lapse until there has been a first.\n%s", spiffeID, first)
	}
	if !firstLapse.Recorded {
		t.Fatalf("the first lapse appended no run_expired, so the count below would be "+
			"measuring the wrong thing: %+v", firstLapse)
	}
	if n := countExpiries(t, store, run.RunID); n != 1 {
		t.Fatalf("after one lapse the ledger holds %d run_expired events for %s, want 1",
			n, run.RunID)
	}

	// --- the run comes back ----------------------------------------------
	//
	// This is the restore path of internal/mcp/get_credential.go, performed
	// the way the wiring layer's runRestorer performs it: the same run, the
	// same identity, a new entry. Nothing about it is out of band.
	secondRegistered := time.Now()
	registerWithTTL(t, c, s, run, shortRunTTL)
	if active := c.RequireActiveRun(ctx, run); active != nil {
		t.Fatalf("the restore left SPIRE holding no entry for %s: %v — the second "+
			"lapse below would then be a sweep over nothing", spiffeID, active)
	}
	// And it works: the credential release the restore exists to allow.
	issueInLedger(t, store, run, spiffeID)

	// --- lapse two -------------------------------------------------------
	waitPast(t, secondRegistered.Add(shortRunTTL+2*time.Second))

	second, err := reaper.Sweep(ctx)
	if err != nil {
		t.Fatalf("second Sweep: %v", err)
	}
	secondLapse, sweptAgain := second.FindExpired(run.RunID)
	if !sweptAgain {
		t.Fatalf("the restored entry for %s outlived its TTL a second time and the sweep "+
			"did not expire it.\n%s", spiffeID, second)
	}
	if !secondLapse.Deleted {
		t.Fatalf("the second lapse deleted no entry, so there is no action here for a "+
			"record to be missing from: %+v", secondLapse)
	}

	// The assertion. An entry was created, used and deleted a second time; the
	// chain has to say so.
	if !secondLapse.Recorded {
		t.Errorf("the reaper deleted %s's entry a SECOND time and appended nothing "+
			"(I3: no action without a record). ExpiryKey is derived from the run id "+
			"alone, so the first lapse's event answers for every lapse afterwards, "+
			"and reap() deletes regardless: %+v", spiffeID, secondLapse)
	}
	if n := countExpiries(t, store, run.RunID); n != 2 {
		t.Fatalf("the ledger holds %d run_expired events for %s after TWO lapses, want 2. "+
			"A run that lapsed, was restored, released a credential and lapsed again "+
			"reads as one withdrawal, and its newest recorded fact is still later than "+
			"its only expiry — so it reads active for ever", n, run.RunID)
	}
}

// ---------------------------------------------------------------------------
// REC-017 — a restored run raises no drift alert.
//
//	Reconcile a run whose newest recorded activity is later than its
//	`run_expired`, and whose SPIRE entry the restore path re-created
//	→ no `spire_entry_not_deleted` drift, in the result or in the chain
//	→ I3, IP §6.10, AB-11
//
// # The defect
//
// `ledgerView.observe` (reconcile.go) marks a run CLOSED on `run_retired` OR
// `run_expired` and never re-opens it on anything that happens afterwards.
// `compareEntries` then reports any entry for a closed run, once the closing
// event is older than MinAge, as DriftEntryNotDeleted — "the ledger says this
// entry was deleted and SPIRE still holds it".
//
// For a retired run that is exactly right, and TestSPI008ReplantedEntryFor-
// ARetiredRunIsRecorded is what proves it: retirement is final, so an entry
// that came back is AB-11. Expiry is not retirement. It withdraws the
// authorisation of a run that went quiet, and internal/mcp/get_credential.go
// re-creates that entry on the run's next call, by design and through the
// admin path. The reconciler reports that legitimate repair as tampering.
//
// # Why the false positive is the thing being pinned, not the missed detection
//
// RM-065 is this project's standing note that convicting a healthy system is
// worse than the gap being closed. An operator who is shown
// `spire_entry_not_deleted` every time an agent resumes learns to ignore the
// one that matters. TestSPI008ReplantedEntryForARetiredRunIsRecorded stays
// exactly as it is: this case must not be made to pass by making that one fail.
// ---------------------------------------------------------------------------

func TestREC017ARestoredRunRaisesNoDriftAlert(t *testing.T) {
	s := requireStack(t)
	store := requireLedger(t)
	c := s.adminClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	run := newRun(t, "fix-ci", "rm-151")
	spiffeID := mustSPIFFEID(t, run)

	registerForTest(t, c, s, run)
	registerInLedger(t, store, run)

	// The run goes quiet and the reaper withdraws its authorisation, in I3's
	// order: the record, then the deletion.
	expiredEvent := expireInLedger(t, store, run)
	if _, err := c.RetireRun(ctx, run); err != nil {
		t.Fatalf("deleting the entry the reaper would have deleted: %v", err)
	}

	// The agent was never dead. It calls get_credential, gate 4 finds no
	// entry, and the restore path re-creates this exact entry through the
	// admin client — the same call register_agent makes, not a planted one.
	registerForTest(t, c, s, run)
	issuedEvent := issueInLedger(t, store, run, spiffeID)

	// MinAge a millisecond, for the reason newReconcilerFor states: the state
	// here is already fully formed, and waiting out DefaultMinAge would only
	// re-test #108.
	rec, loud := newReconcilerFor(t, c, store, time.Millisecond)
	result, err := rec.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if got := driftsFor(result, spiffeID); len(got) != 0 {
		t.Errorf("a run whose newest recorded fact is the credential_issued %s — later "+
			"than the run_expired %s it is being judged against — and whose entry the "+
			"restore path legitimately re-created was reported as %+v.\n"+
			"Expiry is a withdrawal, not an ending: an entry that comes back after one "+
			"is the repair working, and reporting it as %s teaches an operator to "+
			"ignore the alert that means tampering",
			issuedEvent, expiredEvent, got, DriftEntryNotDeleted)
	}
	if alerts := driftEvents(t, store); len(alerts) != 0 {
		t.Errorf("the reconciler appended %d ledger_drift_detected event(s) over a "+
			"restored run: %v. An alert is permanent (I4), so a false one is a false "+
			"accusation nobody can withdraw", len(alerts), alerts)
	}
	if len(*loud) != 0 {
		t.Errorf("the reconciler raised %d out-of-band alert(s) over a restored run: %+v",
			len(*loud), *loud)
	}
}

// ---------------------------------------------------------------------------
// Helpers local to this file. The package does not write the ledger in
// production — pairing an entry with its event is the MCP's (IP §6.5, E4) — so
// these write what the reaper and the MCP would have written.
// ---------------------------------------------------------------------------

// expireInLedger appends the `run_expired` event the reaper appends, under the
// reaper's own idempotency key, and returns its event_id.
func expireInLedger(t *testing.T, store *ledger.Store, run RunRef) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rec, err := store.Append(ctx, event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeRunExpired,
		event.FieldSource:         event.SourceReaper,
		event.FieldRunID:          run.RunID,
		event.FieldSpiffeID:       mustSPIFFEID(t, run),
		event.FieldIdempotencyKey: ExpiryKey(run.RunID),
	})
	if err != nil {
		t.Fatalf("append run_expired for %s: %v", run.RunID, err)
	}
	id := recordString(rec, event.FieldEventID)
	if id == "" {
		t.Fatalf("run_expired came back without an event_id: %v", rec)
	}
	return id
}

// issueInLedger appends the `credential_issued` event get_credential appends
// when it releases a credential to a run, and returns its event_id. It is this
// file's "the run is working": doc 02 §3 calls it "a JWT/X.509-SVID was
// released to the run", and nothing that is not running asks for one.
func issueInLedger(t *testing.T, store *ledger.Store, run RunRef, spiffeID string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rec, err := store.Append(ctx, event.Fields{
		event.FieldSchemaVersion:    event.SchemaVersion,
		event.FieldEventType:        event.EventTypeCredentialIssued,
		event.FieldSource:           event.SourceMCP,
		event.FieldRunID:            run.RunID,
		event.FieldSpiffeID:         spiffeID,
		event.FieldAudience:         "sigstore",
		event.FieldCredentialExpiry: event.NewTimestamp(time.Now().Add(5 * time.Minute)).String(),
	})
	if err != nil {
		t.Fatalf("append credential_issued for %s: %v", run.RunID, err)
	}
	id := recordString(rec, event.FieldEventID)
	if id == "" {
		t.Fatalf("credential_issued came back without an event_id: %v", rec)
	}
	return id
}
