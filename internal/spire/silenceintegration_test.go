// SPDX-License-Identifier: Apache-2.0

package spire

import (
	"context"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
)

// activityGrace is how long a run may be silent before this case calls it
// orphaned. Short, because the wait is real; long enough that the working run's
// tool_call and the sweep that follows it cannot fall on opposite sides of it.
const activityGrace = 5 * time.Second

// SPI-013 (proposed for doc 07; doc 07 is not modified here) — the regression
// gate for #180, against a real SPIRE and a real ledger.
//
// # What went wrong, exactly
//
// The reaper was switched on for one minute on 2026-09-08 and expired two runs
// that were alive and working:
//
//	reap at 13:15:52Z: 2 entries in the agent subtree, 0 live, 2 expired
//
// 183 and 130 recorded tool calls between them, the last in the same second
// their entries were deleted. Both then lost the ability to obtain a credential
// and could sign nothing for the rest of their tasks. The reaper has been off
// since, which leaves IP §6.7 unenforced in the other direction: a run that
// dies without `retire_agent` stays Active forever.
//
// # The two runs below are the whole of the fix
//
// They are identical in every way the OLD reaper could see: the same agent
// type, the same short TTL, registered in the same second, both long past their
// deadline when the sweep runs. Age cannot separate them, so a reaper that
// still judged by age would either reap both — the 2026-09-08 failure — or
// reap neither, and IP §6.7 would stay unenforced.
//
// One of them appends a `tool_call` just before the sweep. That is the only
// difference, it is the difference an agent at work actually makes, and it is
// what has to decide.
//
// # Not vacuous
//
//  1. THE WORKING RUN WAS NOT SPARED BY ITS TTL. Asserted directly: its
//     deadline must be in the past at the instant the sweep started. If it were
//     merely still inside its lifetime, this case would prove nothing.
//  2. THE SWEEP DID NOTHING AT ALL. Closed by the silent run, which must be
//     reaped by the same sweep — the reaper is still doing its job.
//  3. THE ENTRY SURVIVED BUT THE IDENTITY DID NOT. Closed by asking SPIRE for
//     the working run's entry after the sweep, which is the capability the two
//     agents lost: no entry, no credential, no signature.
//  4. THE EXPIRY WAS RECORDED FOR THE WRONG RUN. Closed by reading the chain:
//     exactly one `run_expired`, naming the silent run.
func TestSPI013AWorkingRunKeepsItsIdentityPastItsTTL(t *testing.T) {
	s := requireStack(t)
	c := s.adminClient(t)
	store := requireLedger(t)

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	busy := newRun(t, "demo", "rm-125")
	silent := newRun(t, "demo", "rm-125")

	registeredAt := time.Now()
	registerWithTTL(t, c, s, busy, shortRunTTL)
	registerWithTTL(t, c, s, silent, shortRunTTL)

	// Both runs exist in the ledger from this instant. For the silent one this
	// is the last thing it ever does, which is precisely what a crash looks
	// like from here.
	registerInLedger(t, store, busy)
	registerInLedger(t, store, silent)

	reaper, err := NewReaper(ReaperConfig{
		Client:   c,
		Ledger:   store,
		Grace:    activityGrace,
		Activity: store,
	})
	if err != nil {
		t.Fatalf("NewReaper: %v", err)
	}

	// Real elapsed time, past both entries' real TTLs, and past the grace as
	// well — so the silent run is orphaned on any reading, and the busy one is
	// saved by nothing but its own work.
	waitPast(t, registeredAt.Add(shortRunTTL+activityGrace+2*time.Second))

	// The agent at work. One tool call, of the kind record_event appends for
	// every observed call (#171).
	toolCallInLedger(t, store, busy)

	sweepStart := time.Now()
	report, err := reaper.Sweep(ctx)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	t.Logf("%s", report.String())

	// --- (1) the working run survived, and not because of its TTL ----------
	live, ok := report.FindLive(busy.RunID)
	if !ok {
		if _, reaped := report.FindExpired(busy.RunID); reaped {
			t.Fatal("the reaper expired a run that had just made a tool call. " +
				"This is the 2026-09-08 failure exactly: the agent has lost its " +
				"identity mid-task and can sign nothing for the rest of its work")
		}
		t.Fatalf("the working run is in neither list; the sweep did not examine it:\n%s",
			report.String())
	}
	if !sweepStart.After(live.Deadline) {
		t.Fatalf("the working run's deadline %s had not passed at the sweep %s, "+
			"so it was spared by its TTL and this case proves nothing about silence",
			live.Deadline.UTC().Format(time.RFC3339), sweepStart.UTC().Format(time.RFC3339))
	}
	if live.LastActivity.IsZero() {
		t.Error("the report does not say when the run was last active, so an " +
			"operator cannot tell a working agent from a broken reaper")
	}

	// --- (3) and its identity still works ----------------------------------
	if err := c.RequireActiveRun(ctx, busy); err != nil {
		t.Fatalf("the working run has no SPIRE entry after the sweep: %v. "+
			"The entry is the credential; without it the agent cannot sign", err)
	}

	// --- (2) the silent run was still reaped -------------------------------
	expired, ok := report.FindExpired(silent.RunID)
	if !ok {
		t.Fatalf("the silent run was not reaped; IP §6.7 is unenforced and every "+
			"crashed run stays Active forever:\n%s", report.String())
	}
	if !expired.Recorded {
		t.Error("the silent run's expiry was not appended by this sweep")
	}
	if !expired.Deleted {
		t.Error("the silent run's SPIRE entry was not deleted")
	}

	// --- (4) exactly one expiry, for the right run -------------------------
	var expiries []string
	for _, rec := range allEvents(t, store) {
		if rec[event.FieldEventType] == event.EventTypeRunExpired {
			expiries = append(expiries, recordString(rec, event.FieldRunID))
		}
	}
	if len(expiries) != 1 || expiries[0] != silent.RunID {
		t.Errorf("the chain holds run_expired for %v, want exactly [%s]",
			expiries, silent.RunID)
	}
}

// toolCallInLedger appends one `tool_call` for a run: the signal that the run
// is still working, and the only difference between SPI-013's two runs.
func toolCallInLedger(t *testing.T, store interface {
	Append(context.Context, event.Fields) (event.Fields, error)
}, run RunRef) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	spiffeID, err := run.SPIFFEID(testTrustDomain)
	if err != nil {
		t.Fatalf("SPIFFEID(%+v): %v", run, err)
	}
	if _, err := store.Append(ctx, event.Fields{
		event.FieldEventType:      event.EventTypeToolCall,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          run.RunID,
		event.FieldSpiffeID:       spiffeID,
		event.FieldIdempotencyKey: "tool-" + run.RunID,
		event.FieldToolName:       "record_event",
		event.FieldPayloadDigest: "sha256:" +
			"0000000000000000000000000000000000000000000000000000000000000000",
	}); err != nil {
		t.Fatalf("append tool_call for %s: %v", spiffeID, err)
	}
}
