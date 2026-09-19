// SPDX-License-Identifier: Apache-2.0

package spire

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
)

// RM-152 (#255) — one withdrawal per lapse, and never a deletion without one.
//
// SPI-014 (internal/spire/lifecycle_test.go) is the case that matters and it
// runs against the real stack: a run that lapses twice is recorded twice. These
// two are the halves a single integration run cannot reach — a chain written by
// the code that shipped BEFORE this change, and a ledger that refuses the
// append — and each one ends in "do not delete this identity", which is where an
// untaken branch costs an identity.
//
// NOT YET IN DOC 07. §TC-SPI catalogues SPI-014 and stops; SPI-015 and SPI-016
// are the ids #255 names for these two, and the rows are a human's to add. The
// ids are used here rather than invented afresh so that the catalogue and the
// code do not diverge further than they already have (see the SPI-008 note in
// doc 07 §TC-SPI).

// The shipped ActivitySource really is position-aware, so a deployment takes
// the per-lapse path rather than quietly keeping the pre-#255 behaviour. This
// is the one assertion in this file that is about the WIRING and not about a
// decision, and it is a compile-time one.
var (
	_ ActivitySource         = (*ledger.Store)(nil)
	_ ActivityPositionSource = (*ledger.Store)(nil)
)

// ---------------------------------------------------------------------------
// SPI-015 — a run whose withdrawal was recorded under the single key gains no
// duplicate.
//
//	Sweep a run whose chain carries a `run_expired` under the pre-#255
//	idempotency key, with no activity newer than it
//	→ nothing is appended; the reaper resolves to the event already there
//	→ I3, I4, ADR-0014
//
// # Why this is not covered by SPI-014
//
// #255 changes the key NEW events are written under. Events already on the
// chain keep the key they were hashed with for ever (I4), and there are runs in
// this shape in live data: the reaper ran, wrote `reaper:run_expired:{run}`,
// and either failed its delete or had the entry restored under it afterwards. A
// fix that looked only under the new key would read every one of those runs as
// never withdrawn and append a second event for a lapse already recorded.
//
// # The discriminator, and why it is the right one
//
// A single-key event is dated by its own chain position. `position` is the
// newest thing the RUN did. If the event is newer than that activity, nothing
// has happened since it was written, so the silence it recorded is the silence
// being swept now: same lapse, nothing to append. If the run worked after it,
// the old event belongs to an earlier lapse and this one has never been
// recorded. Both directions are asserted; a fix that always deduplicated
// against the old key would pass the first and fail the second, and would be
// SPI-014's defect wearing a new key.
// ---------------------------------------------------------------------------

func TestSPI015ALegacyKeyedWithdrawalGainsNoDuplicate(t *testing.T) {
	cand := Candidate{
		Entry: Entry{ID: "entry-1", SPIFFEID: "spiffe://innsegl.dev/agent/demo/rm-152/run-1", TTL: time.Minute},
		Run:   RunRef{AgentType: "demo", TaskID: "rm-152", RunID: "run-1"},
	}
	const legacyEventID = "01a04a16-db86-7f2e-9bb5-23822b92285a"
	legacy := ExpiryKey(cand.Run.RunID)

	// The chain as the pre-#255 reaper left it: one `run_expired` at chain
	// position 7, under the key derived from the run id alone.
	storedLegacy := func() map[string]event.Fields {
		return map[string]event.Fields{legacy: {
			event.FieldEventType:     event.EventTypeRunExpired,
			event.FieldRunID:         cand.Run.RunID,
			event.FieldEventID:       legacyEventID,
			event.FieldChainPosition: int64(7),
		}}
	}

	t.Run("the same lapse appends nothing", func(t *testing.T) {
		// The run's newest work is at position 5, BEFORE the withdrawal at 7.
		// It has done nothing since; this is still that silence.
		sink := &fakeSink{stored: storedLegacy()}
		r := &Reaper{ledger: sink, activity: &positionStub{position: 5, known: true}}

		id, appended, err := r.record(context.Background(), cand)
		if err != nil {
			t.Fatalf("record: %v", err)
		}
		if appended {
			t.Error("the reaper appended a second run_expired for a lapse the chain " +
				"already records under the single-key form; I4 keeps that event for " +
				"ever, so the duplicate is permanent")
		}
		if id != legacyEventID {
			t.Errorf("record resolved to event %q, want the one already on the chain, %q",
				id, legacyEventID)
		}
		if len(sink.appended) != 0 {
			t.Errorf("the sink holds %d appended event(s), want 0", len(sink.appended))
		}
	})

	t.Run("a later lapse is recorded under its own key", func(t *testing.T) {
		// The run worked at position 9, AFTER the withdrawal at 7: it was
		// restored, it did something, and it has now gone quiet again. That is
		// a second lapse and a second deletion, and I3 wants a record of it.
		sink := &fakeSink{stored: storedLegacy()}
		r := &Reaper{ledger: sink, activity: &positionStub{position: 9, known: true}}

		id, appended, err := r.record(context.Background(), cand)
		if err != nil {
			t.Fatalf("record: %v", err)
		}
		if !appended {
			t.Fatal("a run that worked AFTER its recorded withdrawal and went quiet " +
				"again had its second lapse answered by the first one's event")
		}
		if id == legacyEventID {
			t.Errorf("record reported the old event %q for a new lapse", id)
		}
		if len(sink.appended) != 1 {
			t.Fatalf("the sink holds %d appended event(s), want 1", len(sink.appended))
		}
		body := sink.appended[0]
		want := ExpiryKeyAfter(cand.Run.RunID, 9)
		if got := body[event.FieldIdempotencyKey]; got != want {
			t.Errorf("idempotency_key = %v, want %q", got, want)
		}
		// Protected spellings, as literals: #255 changes a key, and nothing
		// else about this event may move with it (doc 08).
		if body[event.FieldEventType] != "run_expired" {
			t.Errorf("event_type = %v, want run_expired", body[event.FieldEventType])
		}
		if body[event.FieldSource] != "reaper" {
			t.Errorf("source = %v, want reaper", body[event.FieldSource])
		}
		if body[event.FieldRunID] != cand.Run.RunID {
			t.Errorf("run_id = %v, want %q", body[event.FieldRunID], cand.Run.RunID)
		}
		if body[event.FieldSpiffeID] != cand.Entry.SPIFFEID {
			t.Errorf("spiffe_id = %v, want the id SPIRE held, %q",
				body[event.FieldSpiffeID], cand.Entry.SPIFFEID)
		}
	})

	t.Run("two reapers over one lapse still write one event", func(t *testing.T) {
		// The property the single-key form was chosen for, and the one #255 may
		// not lose. Both reapers read the same last activity, so both compute
		// the same key, and the second resolves to the first's event.
		sink := &fakeSink{}
		first := &Reaper{ledger: sink, activity: &positionStub{position: 9, known: true}}
		second := &Reaper{ledger: sink, activity: &positionStub{position: 9, known: true}}

		id, appended, err := first.record(context.Background(), cand)
		if err != nil || !appended {
			t.Fatalf("first record: id=%q appended=%v err=%v", id, appended, err)
		}
		again, appendedAgain, err := second.record(context.Background(), cand)
		if err != nil {
			t.Fatalf("second record: %v", err)
		}
		if appendedAgain {
			t.Error("a second reaper over ONE lapse wrote a second run_expired")
		}
		if again != id {
			t.Errorf("the second reaper reported event %q, the first wrote %q", again, id)
		}
		if len(sink.appended) != 1 {
			t.Errorf("the sink holds %d events after two reapers, want 1", len(sink.appended))
		}
	})

	t.Run("a legacy event whose chain position cannot be read stops the reap", func(t *testing.T) {
		// Which lapse it records cannot be decided, so whether deleting this
		// entry would be recorded cannot be decided either. The entry stays.
		broken := storedLegacy()
		delete(broken[legacy], event.FieldChainPosition)
		sink := &fakeSink{stored: broken}
		r := &Reaper{ledger: sink, activity: &positionStub{position: 5, known: true}}

		_, appended, err := r.record(context.Background(), cand)
		if err == nil {
			t.Fatal("record proceeded over a stored expiry it could not date")
		}
		if appended {
			t.Error("record reported an append alongside the error")
		}
		if class, ok := ClassOf(err); !ok || class != ClassInvariantViolation {
			t.Errorf("class = %q (ok=%v), want %s", class, ok, ClassInvariantViolation)
		}
		if len(sink.appended) != 0 {
			t.Error("record appended anyway")
		}
	})

	t.Run("an activity source that cannot answer stops the reap", func(t *testing.T) {
		sink := &fakeSink{stored: storedLegacy()}
		r := &Reaper{ledger: sink, activity: &positionStub{err: errors.New("connection refused")}}

		if _, _, err := r.record(context.Background(), cand); err == nil {
			t.Fatal("record chose a key without knowing which lapse it was recording")
		} else if !IsRetryable(err) {
			t.Error("an unreachable ledger must be retryable; the orphan is still there")
		}
		if len(sink.appended) != 0 {
			t.Error("record appended despite failing to read the run's activity")
		}
	})

	t.Run("a run the chain knows nothing about keeps the single-key form", func(t *testing.T) {
		// And so does a deployment with no activity source at all: with nothing
		// to tell one lapse from another, naming them all the same is exactly
		// what every deployment before #255 did.
		for name, activity := range map[string]ActivitySource{
			"unknown run":          &positionStub{},
			"no activity source":   nil,
			"instants only source": &activityStub{known: true},
		} {
			t.Run(name, func(t *testing.T) {
				sink := &fakeSink{}
				r := &Reaper{ledger: sink, activity: activity}
				if _, _, err := r.record(context.Background(), cand); err != nil {
					t.Fatalf("record: %v", err)
				}
				if len(sink.appended) != 1 {
					t.Fatalf("the sink holds %d events, want 1", len(sink.appended))
				}
				if got := sink.appended[0][event.FieldIdempotencyKey]; got != legacy {
					t.Errorf("idempotency_key = %v, want the single-key form %q", got, legacy)
				}
			})
		}
	})
}

// TestExpiryKeyFormsCannotBeConfused pins the two spellings against each other.
//
// The single-key form is a PREFIX of the per-lapse form, so the only thing
// keeping a legacy key for one run from colliding with a lapse key for another
// is that `@` cannot occur in a run id (doc 02 §2). That is asserted here rather
// than trusted, and so is doc 02 §2's 128-byte bound at the longest run id the
// grammar admits.
func TestExpiryKeyFormsCannotBeConfused(t *testing.T) {
	const runID = "run-1"
	legacy := ExpiryKey(runID)
	lapse := ExpiryKeyAfter(runID, 42)

	if !strings.HasSuffix(legacy, runID) {
		t.Errorf("ExpiryKey(%q) = %q, want it to end in the run id", runID, legacy)
	}
	if legacy == lapse {
		t.Fatal("the per-lapse key is the single key; one run would have one expiry again")
	}
	if !strings.HasPrefix(lapse, legacy+"@") {
		t.Errorf("ExpiryKeyAfter = %q, want the single key plus @position", lapse)
	}
	if ExpiryKeyAfter(runID, 42) != lapse {
		t.Error("ExpiryKeyAfter is not a function of its arguments alone; two reapers " +
			"over one lapse would write two events")
	}
	if ExpiryKeyAfter(runID, 43) == lapse {
		t.Error("two different lapses share a key")
	}

	// No run id can spell another run's key, because `@` is outside the
	// identifier grammar ValidateIdentifier enforces.
	if err := event.ValidateIdentifier("run-1@42"); err == nil {
		t.Error("a run id may contain '@'; the two key forms are then ambiguous and " +
			"the separator has to change")
	}

	// The longest key the grammar can produce still fits doc 02 §2's bound.
	longest := ExpiryKeyAfter(strings.Repeat("r", 63), 1<<62)
	if err := event.ValidateIdentifier(strings.Repeat("r", 63)); err != nil {
		t.Fatalf("the 63-character run id used for the bound is not a run id: %v", err)
	}
	if len(longest) > event.MaxIdempotencyKeyBytes {
		t.Errorf("the longest per-lapse key is %d bytes, over doc 02 §2's %d: %q",
			len(longest), event.MaxIdempotencyKeyBytes, longest)
	}
}

// ---------------------------------------------------------------------------
// SPI-016 — an append that fails leaves the entry alone, and the sweep says so.
//
//	Sweep an orphan whose `run_expired` cannot be appended
//	→ SPIRE is never asked to delete the entry, and the sweep reports the
//	  failure rather than reporting the run expired
//	→ I3, IP §6.7
//
// # What this is really asserting
//
// "Record first, delete second" is the file's stated order, and an order is not
// an invariant until something fails in the middle of it. The assertion is not
// that reap returns an error — it is that BatchDeleteEntry was never called, so
// the identity is still there for the next sweep, and that the operator's
// account of the sweep names the entry as failed instead of silently omitting
// it. A reaper that reported the run expired while the append had failed would
// be a reaper whose report is not evidence of anything.
// ---------------------------------------------------------------------------

func TestSPI016AFailedAppendLeavesTheEntryAndIsReported(t *testing.T) {
	const spiffeID = "spiffe://innsegl.dev/agent/demo/rm-152/run-1"
	created := time.Now().Add(-2 * time.Hour)

	entries := &stubEntries{list: []*types.Entry{wireEntry(spiffeID, 60, created)}}
	sink := &fakeSink{appendErr: errors.New("the ledger is read-only")}
	r := &Reaper{
		client:   &Client{entries: entries, trustDomain: "innsegl.dev", timeout: 5 * time.Second},
		ledger:   sink,
		activity: &positionStub{position: 4, known: true},
	}

	report, err := r.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	// The identity is still there.
	if len(entries.deleted) != 0 {
		t.Errorf("the reaper deleted %v after failing to append the withdrawal. I3 is "+
			"no action without a record, and this is the action", entries.deleted)
	}
	// And the sweep says so, rather than counting it as reaped.
	if len(report.Expired) != 0 {
		t.Errorf("the report lists %d run(s) as expired although nothing was recorded "+
			"or deleted: %+v", len(report.Expired), report.Expired)
	}
	if report.OK() {
		t.Error("OK() is true over a sweep that could not reap the orphan it found; " +
			"that is what an operator gates on")
	}
	if len(report.Failures) != 1 {
		t.Fatalf("the report holds %d failure(s), want 1:\n%s", len(report.Failures), report)
	}
	failure := report.Failures[0]
	if failure.SPIFFEID != spiffeID {
		t.Errorf("the failure names %q, want %q", failure.SPIFFEID, spiffeID)
	}
	if failure.Err == nil {
		t.Fatal("the failure carries no error, so the report says an entry failed and " +
			"not why")
	}
	if !IsRetryable(failure.Err) {
		t.Error("a ledger that would not take the append is retryable; the orphan is " +
			"still there and the next sweep must try again")
	}
	// The rendered report is the operator-facing artifact, so the entry has to
	// be findable in it by the two things an operator has: its identity and the
	// word that says it was not reaped.
	for _, want := range []string{"FAILED", spiffeID, "read-only"} {
		if !strings.Contains(report.String(), want) {
			t.Errorf("the report does not mention %q:\n%s", want, report)
		}
	}
	// And the retry is not a double-record: the next sweep over the same lapse
	// computes the same key.
	sink.appendErr = nil
	retry, err := r.Sweep(context.Background())
	if err != nil {
		t.Fatalf("retry Sweep: %v", err)
	}
	if !retry.OK() || len(retry.Expired) != 1 || !retry.Expired[0].Recorded {
		t.Fatalf("the retry did not reap the orphan it left behind:\n%s", retry)
	}
	if len(sink.appended) != 1 {
		t.Errorf("the ledger holds %d run_expired events after a failure and a retry, "+
			"want 1", len(sink.appended))
	}
	if len(entries.deleted) != 1 || entries.deleted[0] != "entry-for-"+spiffeID {
		t.Errorf("the retry deleted %v, want the one entry it recorded", entries.deleted)
	}
}

// TestReapNeverDeletesWithoutAnEventID is reap's own guard, asserted where it
// lives.
//
// record returns an event id on every success path, so the branch is
// unreachable through record — which is exactly why it is worth having and
// worth pinning: the thing on the other side of it is an identity deleted with
// nothing on the chain saying it went. A client that would panic if it were
// called is the assertion that it is not.
func TestReapNeverDeletesWithoutAnEventID(t *testing.T) {
	cand := Candidate{
		Entry: Entry{ID: "entry-1", SPIFFEID: "spiffe://innsegl.dev/agent/demo/rm-152/run-1"},
		Run:   RunRef{RunID: "run-1"},
	}
	// appendResult carries no event_id, and record refuses it; reap must
	// therefore never reach deleteEntry, which a nil client would panic in.
	r := &Reaper{
		ledger: &fakeSink{appendResult: event.Fields{
			event.FieldEventType: event.EventTypeRunExpired,
			event.FieldRunID:     "run-1",
		}},
	}

	out, err := r.reap(context.Background(), cand)
	if err == nil {
		t.Fatal("reap proceeded with no event id for the withdrawal")
	}
	if out.Deleted {
		t.Error("reap reported a deletion it did not record")
	}
	if out.EventID != "" {
		t.Errorf("reap reported event %q alongside the error", out.EventID)
	}
}

// ---------------------------------------------------------------------------
// Fakes.
// ---------------------------------------------------------------------------

// positionStub is an ActivitySource that also answers where in the chain the
// run's last activity sits — the shape *ledger.Store has.
type positionStub struct {
	position int64
	known    bool
	err      error
	at       time.Time
}

func (p *positionStub) LastActivity(ctx context.Context, runID string) (time.Time, bool, error) {
	at, _, known, err := p.LastActivityAt(ctx, runID)
	return at, known, err
}

func (p *positionStub) LastActivityAt(_ context.Context, _ string) (time.Time, int64, bool, error) {
	if p.err != nil {
		return time.Time{}, 0, false, p.err
	}
	at := p.at
	if at.IsZero() {
		// Long enough ago that the deadline gate above this one calls the run
		// silent; this stub is about the KEY, not about the verdict.
		at = time.Now().Add(-24 * time.Hour)
	}
	return at, p.position, p.known, nil
}

// stubEntries is SPIRE's entry API, reduced to the two calls a sweep makes. The
// embedded interface is nil on purpose: a sweep that called anything else would
// panic rather than quietly pass.
type stubEntries struct {
	entryv1.EntryClient
	list    []*types.Entry
	deleted []string
}

func (s *stubEntries) ListEntries(_ context.Context, _ *entryv1.ListEntriesRequest,
	_ ...grpc.CallOption) (*entryv1.ListEntriesResponse, error) {
	return &entryv1.ListEntriesResponse{Entries: s.list}, nil
}

func (s *stubEntries) BatchDeleteEntry(_ context.Context, in *entryv1.BatchDeleteEntryRequest,
	_ ...grpc.CallOption) (*entryv1.BatchDeleteEntryResponse, error) {
	results := make([]*entryv1.BatchDeleteEntryResponse_Result, 0, len(in.GetIds()))
	for _, id := range in.GetIds() {
		s.deleted = append(s.deleted, id)
		results = append(results, &entryv1.BatchDeleteEntryResponse_Result{Id: id})
	}
	return &entryv1.BatchDeleteEntryResponse{Results: results}, nil
}
