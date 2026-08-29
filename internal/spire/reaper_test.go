// SPDX-License-Identifier: Apache-2.0

package spire

import (
	"context"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
)

// shortRunTTL is the TTL the crashed run in SPI-003 is registered with.
//
// SPI-003 says "clock advanced". SPIRE TTLs are real seconds against a real
// clock and there is no seam to advance: the entry's created_at is written by
// the SPIRE server, the SVID's NotAfter is written by the SPIRE CA, and a fake
// clock in this process would move neither. So the clock is advanced the only
// honest way — a genuinely short TTL on a real entry, and real elapsed time —
// and the test then waits it out. Nothing about SPIRE is mocked to make expiry
// happen; the entry really does outlive the identity lifetime it was
// registered with.
//
// 20 seconds is long enough for a probe container to start and be issued an
// SVID from the entry (the positive control below), and short enough that the
// wait afterwards is bounded.
const shortRunTTL = 20 * time.Second

// SPI-003 (doc 07, layer I)
//
//	Entry TTL expiry (clock advanced)
//	→ get_credential fails; reaper deletes entry; `run_expired` (not
//	  `run_retired`) appended
//	→ IP §6.7
//
// # The distinction this case exists to protect
//
// doc 01 §6.7 is one sentence and every clause of it is load-bearing: "Agent
// crashes without retire_agent → SPIRE entry TTL expires it; a reaper deletes
// expired entries and appends run_expired (distinct from run_retired)."
// Retired means the agent finished and said so. Expired means it died. An
// auditor reading the ledger can tell a clean shutdown from a crash only if the
// two are different event types, so collapsing them is not a tidy-up, it is the
// loss of the only signal §6.7 exists to preserve. The assertions below check
// the event type and the source against their literal protected spellings, not
// against the Go constants, so a rename cannot make this pass.
//
// # How this case is kept from passing vacuously
//
// "The reaper appended run_expired" passes if the reaper ran over an empty set
// and the event came from somewhere else. Four holes, each closed by an
// assertion rather than a comment:
//
//  1. THE ENTRY NEVER EXISTED. Closed by registering it and then watching a
//     real container be issued an SVID from it (probeUntilIssued) before
//     anything is reaped. If the identity was never live the test fails there,
//     before the reaper is ever called.
//
//  2. THE ENTRY WAS NOT ACTUALLY EXPIRED. Closed twice. The test refuses to
//     sweep until real time has passed created_at + TTL, and it then asserts
//     the deadline the reaper computed is in the past relative to the instant
//     the sweep started. A reaper that deleted the entry for any other reason
//     fails that assertion.
//
//  3. THE REAPER DELETED EVERYTHING UNDER /agent/. Closed by a second run,
//     registered at the same time with the ordinary five-minute TTL, that must
//     survive the same sweep — and must appear in the sweep's live list, which
//     is also what proves the sweep enumerated a non-empty set at all.
//
//  4. THE EVENT CAME FROM SOMEWHERE ELSE. The ledger is a database of this
//     test's own, created empty. Every event in it is asserted: exactly one
//     run_expired, carrying this run's id and the SPIFFE ID SPIRE held for it,
//     no run_expired for the live run, and no run_retired anywhere at all.
func TestSPI003OrphanedEntryIsExpiredAndRecorded(t *testing.T) {
	s := requireStack(t)
	c := s.adminClient(t)
	store := requireLedger(t)

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	// The run that crashes: a real entry with a real, very short TTL.
	orphan := newRun(t, "demo", "rm-017")
	// The run that is still working. Registered alongside so that "the reaper
	// deleted the entry" cannot be satisfied by deleting every entry it sees.
	live := newRun(t, "demo", "rm-017")

	orphanID := mustSPIFFEID(t, orphan)

	registeredAt := time.Now()
	orphanEntry := registerWithTTL(t, c, s, orphan, shortRunTTL)
	liveEntry := registerWithTTL(t, c, s, live, DefaultRunTTL)

	// (1) The identity existed and was being issued. This is the crash's
	// precondition: an agent that never had an identity cannot orphan one.
	issued := s.probeUntilIssued(t, orphan, 90*time.Second)
	if issued.Outcome.SPIFFEID != orphanID {
		t.Fatalf("positive control fetched %q, want %q", issued.Outcome.SPIFFEID, orphanID)
	}
	if err := c.RequireActiveRun(ctx, live); err != nil {
		t.Fatalf("the live run has no entry before the sweep: %v", err)
	}

	// The agent now crashes: nothing calls RetireRun, and the entry is left
	// behind. That is the whole of the crash — there is no other state to
	// simulate, because a crashed agent is exactly an agent that stopped
	// calling the MCP.

	reaper, err := NewReaper(ReaperConfig{
		Client: c,
		Ledger: store,
		// Grace 0: the policy is at its most aggressive, so an entry is
		// orphaned the instant it outlives the TTL it was registered with. The
		// TTL itself is real and so is the elapsed time; the grace is the only
		// knob, and setting it to zero shortens the wait without inventing an
		// expiry that did not happen.
		Grace: 0,
	})
	if err != nil {
		t.Fatalf("NewReaper: %v", err)
	}

	// (2) Real elapsed time, past the entry's real TTL. Two extra seconds
	// cover the millisecond-scale difference between this process's clock and
	// the SPIRE server's created_at.
	waitPast(t, registeredAt.Add(shortRunTTL+2*time.Second))

	sweepStart := time.Now()
	report, err := reaper.Sweep(ctx)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if report == nil {
		t.Fatal("Sweep returned no report")
	}

	// --- the reaper deleted the entry ------------------------------------
	got, ok := report.FindExpired(orphan.RunID)
	if !ok {
		t.Fatalf("the reaper did not expire the orphaned entry for %s "+
			"(entry %s, TTL %s, registered %s ago).\n%s",
			orphanID, orphanEntry.ID, shortRunTTL,
			time.Since(registeredAt).Round(time.Second), report)
	}
	if got.Entry.ID != orphanEntry.ID {
		t.Errorf("expired entry id = %q, want %q", got.Entry.ID, orphanEntry.ID)
	}
	if got.Entry.SPIFFEID != orphanID {
		t.Errorf("expired entry SPIFFE ID = %q, want %q", got.Entry.SPIFFEID, orphanID)
	}
	if !got.Deleted {
		t.Error("the reaper recorded the expiry but did not delete the entry")
	}
	if !got.Recorded {
		t.Error("the reaper deleted the entry without appending run_expired (I3)")
	}
	// (2): it was reaped for having passed its deadline, not for any other
	// reason. A deadline at or after the sweep means the entry was still
	// inside its identity lifetime when it was deleted.
	if !got.Deadline.Before(sweepStart) {
		t.Errorf("the entry was reaped with deadline %s, which is not before the "+
			"sweep at %s: it had not expired", got.Deadline, sweepStart)
	}
	if got.CreatedAt.IsZero() {
		t.Error("the reaper reaped an entry whose creation time it did not know")
	}

	// (3): the live run survived the same sweep, and the sweep saw it.
	if unexpected, alsoExpired := report.FindExpired(live.RunID); alsoExpired {
		t.Errorf("the reaper expired %s, which is still inside its %s TTL "+
			"(deadline %s): it is deleting entries rather than expired entries",
			live.RunID, DefaultRunTTL, unexpected.Deadline)
	}
	stillLive, sawLive := report.FindLive(live.RunID)
	if !sawLive {
		t.Fatalf("the sweep never examined the live run %s; it saw %d entries "+
			"and this case proves nothing about a non-empty set.\n%s",
			live.RunID, report.Examined, report)
	}
	if stillLive.Entry.ID != liveEntry.ID {
		t.Errorf("live entry id = %q, want %q", stillLive.Entry.ID, liveEntry.ID)
	}
	if !stillLive.Deadline.After(sweepStart) {
		t.Errorf("the live run's deadline %s is not after the sweep at %s",
			stillLive.Deadline, sweepStart)
	}
	if len(report.Failures) != 0 {
		t.Errorf("sweep reported %d failure(s): %v", len(report.Failures), report.Failures)
	}

	// --- SPIRE no longer holds the entry ----------------------------------
	if _, found, lerr := c.LookupRun(ctx, orphan); lerr != nil {
		t.Fatalf("LookupRun after the sweep: %v", lerr)
	} else if found {
		t.Error("SPIRE still holds an entry for the expired run")
	}
	if lerr := c.RequireActiveRun(ctx, live); lerr != nil {
		t.Errorf("the live run lost its entry to the sweep: %v", lerr)
	}

	// --- get_credential fails ---------------------------------------------
	//
	// Immediately at the server, which is what the MCP asks (IP §6.2), with no
	// sleep between the sweep and the check.
	refusal := c.RequireActiveRun(ctx, orphan)
	if refusal == nil {
		t.Fatal("RequireActiveRun succeeded for a run whose entry the reaper deleted")
	}
	if class, classOK := ClassOf(refusal); !classOK || class != ClassRunNotFound {
		t.Errorf("RequireActiveRun after expiry: class %q (ok=%v), want %s",
			class, classOK, ClassRunNotFound)
	}

	// --- the ledger shows the expiry, and shows it as an expiry -----------
	records := allEvents(t, store)
	if len(records) == 0 {
		t.Fatal("the ledger is empty; the reaper appended nothing")
	}
	if _, verr := ledger.Verify(records); verr != nil {
		t.Errorf("the chain the reaper appended to no longer verifies: %v", verr)
	}

	var expiries []event.Fields
	for _, rec := range records {
		// PROTECTED STRINGS (doc 02 §3): spelled out, not taken from the Go
		// constants, so that a rename fails here instead of passing.
		if rec[event.FieldEventType] == "run_retired" {
			t.Errorf("the reaper appended run_retired: %v.\n"+
				"Retired means the agent finished cleanly and expired means it "+
				"died; collapsing them loses the only signal IP §6.7 exists to "+
				"preserve", rec)
		}
		if rec[event.FieldEventType] != "run_expired" {
			continue
		}
		if rec[event.FieldRunID] == live.RunID {
			t.Errorf("the ledger records the live run %s as expired: %v", live.RunID, rec)
		}
		if rec[event.FieldRunID] == orphan.RunID {
			expiries = append(expiries, rec)
		}
	}
	if len(expiries) != 1 {
		t.Fatalf("the ledger holds %d run_expired events for %s, want exactly 1",
			len(expiries), orphan.RunID)
	}
	expired := expiries[0]
	if expired[event.FieldSource] != "reaper" {
		t.Errorf("run_expired source = %v, want %q (doc 02 §3: the reaper is not the MCP)",
			expired[event.FieldSource], "reaper")
	}
	if expired[event.FieldSpiffeID] != orphanID {
		t.Errorf("run_expired spiffe_id = %v, want %q", expired[event.FieldSpiffeID], orphanID)
	}
	if got.EventID != "" && expired[event.FieldEventID] != got.EventID {
		t.Errorf("the sweep reported event %q; the ledger holds %v",
			got.EventID, expired[event.FieldEventID])
	}

	// --- idempotency -------------------------------------------------------
	//
	// Two passes, because they fail differently.
	before := countExpiries(t, store, orphan.RunID)

	second, err := reaper.Sweep(ctx)
	if err != nil {
		t.Fatalf("second Sweep: %v", err)
	}
	if _, again := second.FindExpired(orphan.RunID); again {
		t.Error("the second sweep expired the same run again")
	}

	// The harder pass: one that still sees the entry. RM-015 measured SPIRE's
	// deletion as eventual on the agent side, and an HA server could serve a
	// stale read, so a second reaper — or the same one after a restart — may
	// hand this exact candidate to reap() again. It must not append a second
	// run_expired, and a delete of an entry that is already gone is not an
	// error.
	replay, err := reaper.reap(ctx, got.Candidate)
	if err != nil {
		t.Fatalf("replaying reap over an entry SPIRE has already deleted: %v", err)
	}
	if replay.Recorded {
		t.Error("a second pass over an already-reaped entry appended a second run_expired")
	}
	if after := countExpiries(t, store, orphan.RunID); after != before {
		t.Errorf("run_expired count went from %d to %d across two more passes; "+
			"the reaper is not idempotent", before, after)
	}

	// --- credentialing fails at the workload too, eventually --------------
	//
	// Measured, never called immediate: the agent keeps serving the SVID it
	// already minted until the deletion propagates. Reported, like SPI-004
	// reports it, rather than asserted as instant.
	started := time.Now()
	converged := false
	for attempt := 1; time.Since(started) < 2*time.Minute; attempt++ {
		probe := s.runProbe(t, orphan, orphan)
		if probe.ExitCode != 0 {
			t.Logf("get_credential refused %s after the reaper deleted the entry "+
				"(%d probe attempt(s)); class=%s retryable=%v",
				time.Since(started).Round(time.Millisecond), attempt,
				probe.Outcome.Class, probe.Outcome.Retryable)
			if probe.Outcome.Class != ClassAttestationFailed {
				t.Errorf("post-expiry workload fetch: class %q, want %s",
					probe.Outcome.Class, ClassAttestationFailed)
			}
			converged = true
			break
		}
		time.Sleep(2 * time.Second)
	}
	if !converged {
		t.Error("SPIRE was still issuing SVIDs for the expired run after 2 minutes")
	}
}

// ---------------------------------------------------------------------------
// Helpers local to this file.
// ---------------------------------------------------------------------------

func mustSPIFFEID(t *testing.T, run RunRef) string {
	t.Helper()
	id, err := run.SPIFFEID(testTrustDomain)
	if err != nil {
		t.Fatalf("RunRef.SPIFFEID(%+v): %v", run, err)
	}
	return id
}

// registerWithTTL registers a run with an explicit TTL and cleans the entry up
// afterwards. It is registerForTest with the TTL exposed: SPI-003 needs an
// entry whose identity lifetime is measured in seconds.
func registerWithTTL(t *testing.T, c *Client, s *stack, run RunRef, ttl time.Duration) Entry {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	entry, err := c.RegisterRun(ctx, Registration{
		Run:       run,
		ParentID:  s.parentID,
		Selectors: runSelectors(run),
		TTL:       ttl,
	})
	if err != nil {
		t.Fatalf("RegisterRun(%+v, ttl=%s): %v", run, ttl, err)
	}
	if entry.TTL != ttl {
		t.Fatalf("SPIRE registered a TTL of %s, asked for %s: the entry this "+
			"case expires is not the entry it registered", entry.TTL, ttl)
	}
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanCancel()
		if _, err := c.RetireRun(cleanCtx, run); err != nil {
			t.Errorf("cleaning up the entry for %+v: %v", run, err)
		}
	})
	return entry
}

// waitPast sleeps until the wall clock is past when, reporting how long it
// waited. Real time, because the TTL it is waiting out is real.
func waitPast(t *testing.T, when time.Time) {
	t.Helper()
	d := time.Until(when)
	if d <= 0 {
		t.Logf("already %s past the entry's TTL; no wait needed", (-d).Round(time.Millisecond))
		return
	}
	t.Logf("waiting %s for the entry to outlive its TTL", d.Round(time.Millisecond))
	time.Sleep(d)
}

// allEvents reads the whole chain.
func allEvents(t *testing.T, store *ledger.Store) []event.Fields {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	count, err := store.Count(ctx)
	if err != nil {
		t.Fatalf("count events: %v", err)
	}
	if count == 0 {
		return nil
	}
	records, err := store.Events(ctx, 1, count)
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	return records
}

// countExpiries counts the run_expired events recorded for one run.
func countExpiries(t *testing.T, store *ledger.Store, runID string) int {
	t.Helper()
	n := 0
	for _, rec := range allEvents(t, store) {
		if rec[event.FieldEventType] == "run_expired" && rec[event.FieldRunID] == runID {
			n++
		}
	}
	return n
}
