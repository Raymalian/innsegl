// SPDX-License-Identifier: Apache-2.0

package segment

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
)

// SEG-004 (doc 07, layer F): "Rekor unreachable at anchoring time →
// retry/backoff, alert emitted, appends to next segment continue; heartbeat lag
// exposed via API." (IP §6.4)
//
// IP §6.4 states the property this file has to establish, and it is a
// statement about what anchoring is *not* allowed to cost:
//
//	"Rekor anchoring of a sealed segment fails → retry with backoff and alert;
//	 appends to the *next* segment continue (anchoring lag is a monitored,
//	 bounded degradation — it delays public tamper-evidence, it does not lose
//	 or weaken records). Dashboard heartbeat must show the lag."
//
// Two failure modes of a test like this are worth naming, because this project
// has been bitten by both:
//
//   - The vacuous retry. A backoff test passes trivially if nothing was ever
//     attempted. So the log here is the real RekorClient pointed at a real,
//     closed TCP port, and the round trips are counted on the wire: the
//     assertion is that N connection attempts genuinely happened and every one
//     of them failed, not that some error came back from somewhere.
//   - The vacuous "appends continue". Asserting that no error was raised
//     proves nothing if nothing was appended. So the appends here go through
//     ledger.Append — the real chain code — while the anchorer is provably
//     mid-retry, and the whole chain is re-verified afterwards.

// deadRekor returns a RekorClient pointed at a port nothing is listening on,
// together with a counter of the connection attempts it actually made.
//
// A closed port rather than a stub server: "Rekor unreachable" is a network
// condition, and a handler that returns 503 is a different failure with
// different retry semantics. Nothing about Rekor is being faked here — Rekor
// is simply absent, which is the scenario.
func deadRekor(t *testing.T) (*RekorClient, *attemptCounter) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	port, err := rekorFreeHostPort(ctx)
	if err != nil {
		t.Fatalf("reserve a port to leave closed: %v", err)
	}

	counter := &attemptCounter{inner: http.DefaultTransport}
	signer, err := GenerateAnchorSigner()
	if err != nil {
		t.Fatalf("GenerateAnchorSigner: %v", err)
	}
	client := &RekorClient{
		BaseURL: "http://127.0.0.1:" + port,
		HTTP:    &http.Client{Transport: counter, Timeout: 5 * time.Second},
		Signer:  signer,
	}
	return client, counter
}

// attemptCounter counts round trips and records whether each one failed.
type attemptCounter struct {
	inner http.RoundTripper

	mu        sync.Mutex
	attempts  int
	successes int
}

func (a *attemptCounter) RoundTrip(r *http.Request) (*http.Response, error) {
	a.mu.Lock()
	a.attempts++
	a.mu.Unlock()

	resp, err := a.inner.RoundTrip(r)
	if err == nil {
		a.mu.Lock()
		a.successes++
		a.mu.Unlock()
	}
	return resp, err
}

func (a *attemptCounter) count() (attempts, successes int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.attempts, a.successes
}

// testClock is a hand-advanced clock, so that a lag assertion is an equality
// and not a tolerance.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock(t *testing.T, at string) *testClock {
	t.Helper()
	ts, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		t.Fatalf("parse clock start: %v", err)
	}
	return &testClock{now: ts}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// testChain is a real hash chain built with the real ledger code.
//
// internal/ledger's Append and Correct are pure functions over a head, so the
// chain a test builds here is assembled by the same code that assembles the
// one in Postgres — including the correction path that a superseding
// segment_sealed event travels down.
type testChain struct {
	head    ledger.Head
	records []event.Fields
}

func (c *testChain) append(t *testing.T, body event.Fields) event.Fields {
	t.Helper()
	record, head, err := ledger.Append(c.head, body)
	if err != nil {
		t.Fatalf("ledger.Append: %v", err)
	}
	if verr := event.ValidateEvent(record); verr != nil {
		t.Fatalf("ledger.Append produced a record the schema refuses: %v", verr)
	}
	c.head = head
	c.records = append(c.records, record)
	return record
}

func (c *testChain) correct(t *testing.T, original, body event.Fields) event.Fields {
	t.Helper()
	record, head, err := ledger.Correct(c.head, original, body)
	if err != nil {
		t.Fatalf("ledger.Correct: %v", err)
	}
	if verr := event.ValidateEvent(record); verr != nil {
		t.Fatalf("ledger.Correct produced a record the schema refuses: %v", verr)
	}
	c.head = head
	c.records = append(c.records, record)
	return record
}

func (c *testChain) verify(t *testing.T) {
	t.Helper()
	if _, err := ledger.Verify(c.records); err != nil {
		t.Fatalf("the chain does not verify: %v", err)
	}
}

func newEventID(t *testing.T) string {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("uuid.NewV7: %v", err)
	}
	return id.String()
}

func mustTS(t *testing.T, s string) event.Timestamp {
	t.Helper()
	ts, err := event.ParseTimestamp(s)
	if err != nil {
		t.Fatalf("ParseTimestamp(%q): %v", s, err)
	}
	return ts
}

// sealAndAppend seals a segment and appends its segment_sealed event, which is
// what the sealer does for every segment whether or not anchoring is working.
func sealAndAppend(t *testing.T, sealer *Sealer, chain *testChain, first int64, n int, at string) (*Sealed, event.Fields) {
	t.Helper()
	sealed, err := sealer.Seal(Request{Records: seededRecords(first, n)})
	if err != nil {
		t.Fatalf("Seal(%d..%d): %v", first, first+int64(n)-1, err)
	}
	body, err := sealed.Event(EventMeta{EventID: newEventID(t), TS: mustTS(t, at)})
	if err != nil {
		t.Fatalf("Sealed.Event: %v", err)
	}
	return sealed, chain.append(t, body)
}

const (
	seg004SealedAt = "2026-08-28T10:00:00.000Z"
	seg004Now      = "2026-08-28T10:01:30.000Z" // ninety seconds later
)

func TestSEG004RekorUnreachableRetriesAndAppendsContinue(t *testing.T) {
	client, counter := deadRekor(t)
	clock := newTestClock(t, seg004Now)

	store := newMemStore()
	sealer := &Sealer{Store: store}
	chain := &testChain{}
	_, sealedRecord := sealAndAppend(t, sealer, chain, 1, 8, seg004SealedAt)

	var (
		mu         sync.Mutex
		sleeps     []time.Duration
		firstSleep = make(chan struct{})
		released   = make(chan struct{})
		once       sync.Once
	)

	anchorer := &Anchorer{
		Log:    client,
		Policy: RetryPolicy{Attempts: 4, Base: 5 * time.Millisecond, Max: 20 * time.Millisecond, Multiplier: 2},
		Bound:  60 * time.Second,
		Now:    clock.Now,
		Sleep: func(_ context.Context, d time.Duration) error {
			mu.Lock()
			sleeps = append(sleeps, d)
			mu.Unlock()
			// Hold the first backoff open so the rest of the test runs while
			// anchoring is demonstrably still in flight and still failing.
			once.Do(func() {
				close(firstSleep)
				<-released
			})
			return nil
		},
	}

	type result struct {
		anchor Anchor
		err    error
	}
	done := make(chan result, 1)
	go func() {
		anchor, err := anchorer.Anchor(context.Background(), sealedRecord)
		done <- result{anchor, err}
	}()

	select {
	case <-firstSleep:
	case r := <-done:
		t.Fatalf("Anchor returned before it ever backed off: %+v", r)
	case <-time.After(30 * time.Second):
		t.Fatal("Anchor never reached its first backoff")
	}

	// The anchorer is now parked in a backoff, having already failed at least
	// once against a port nothing is listening on.
	inflight, successes := counter.count()
	if inflight < 1 {
		t.Fatalf("no connection was attempted before the first backoff: %d attempts", inflight)
	}
	if successes != 0 {
		t.Fatalf("a connection to a closed port succeeded %d times", successes)
	}

	t.Run("appends_to_the_next_segment_continue", func(t *testing.T) {
		// The whole claim of IP §6.4: an unanchored segment delays public
		// tamper-evidence and costs nothing else. Two more segments are sealed
		// and their events appended, through the real chain code, while the
		// anchor above is still retrying.
		before := chain.head.Position
		_, second := sealAndAppend(t, sealer, chain, 9, 8, "2026-08-28T10:02:00.000Z")
		_, third := sealAndAppend(t, sealer, chain, 17, 8, "2026-08-28T10:04:00.000Z")

		if got := chain.head.Position; got != before+2 {
			t.Fatalf("chain head is at %d, want %d: appends did not continue", got, before+2)
		}
		for _, record := range []event.Fields{second, third} {
			if err := event.ValidateEvent(record); err != nil {
				t.Fatalf("a segment sealed during the outage is not a valid event: %v", err)
			}
			if _, present := record[event.FieldAnchorRekorLogIndex]; present {
				t.Fatal("a segment sealed during the outage claims an anchor it does not have")
			}
		}
		chain.verify(t)

		if attempts, _ := counter.count(); attempts < inflight {
			t.Fatalf("attempt count went backwards: %d then %d", inflight, attempts)
		}
	})

	close(released)
	r := <-done

	t.Run("retries_with_backoff_and_every_attempt_really_happened", func(t *testing.T) {
		if !errors.Is(r.err, ErrAnchorUnavailable) {
			t.Fatalf("Anchor error is %v, want one wrapping ErrAnchorUnavailable", r.err)
		}
		attempts, successes := counter.count()
		if attempts != 4 {
			t.Fatalf("%d connection attempts reached the transport, the policy allows 4", attempts)
		}
		if successes != 0 {
			t.Fatalf("%d connections to a closed port succeeded", successes)
		}

		mu.Lock()
		got := append([]time.Duration(nil), sleeps...)
		mu.Unlock()

		want := []time.Duration{5 * time.Millisecond, 10 * time.Millisecond, 20 * time.Millisecond}
		if len(got) != len(want) {
			t.Fatalf("backed off %d times between 4 attempts, want %d: %v", len(got), len(want), got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("backoff %d is %v, want %v (exponential from Base, capped at Max)", i, got[i], want[i])
			}
		}
	})

	t.Run("lag_is_exposed_as_a_value_with_a_timestamp", func(t *testing.T) {
		snap := anchorer.Lag()

		if snap.ObservedAt != clock.Now() {
			t.Fatalf("snapshot ObservedAt is %v, want the clock's %v", snap.ObservedAt, clock.Now())
		}
		if snap.Anchored {
			t.Fatal("the snapshot claims the segment is anchored")
		}
		// FD §3.1 renders "anchored M min ago" and turns amber past the bound:
		// a boolean cannot say how far behind the log is.
		if snap.LagSeconds != 90 {
			t.Fatalf("lag is %v seconds, want 90 (sealed at %s, now %s)",
				snap.LagSeconds, seg004SealedAt, seg004Now)
		}
		if snap.Lag() != 90*time.Second {
			t.Fatalf("Lag() is %v, want 90s", snap.Lag())
		}
		if !snap.OverBound {
			t.Fatalf("lag of %vs is not over a bound of %vs", snap.LagSeconds, snap.BoundSeconds)
		}
		if snap.BoundSeconds != 60 {
			t.Fatalf("bound is %v seconds, want 60", snap.BoundSeconds)
		}
		if snap.PendingSegments != 1 {
			t.Fatalf("%d segments pending, want 1", snap.PendingSegments)
		}
		if snap.PendingSince != mustTS(t, seg004SealedAt).Time() {
			t.Fatalf("PendingSince is %v, want the seal time %s", snap.PendingSince, seg004SealedAt)
		}
		if snap.Attempts != 4 {
			t.Fatalf("snapshot reports %d attempts, want 4", snap.Attempts)
		}
		if snap.LastFailure == "" {
			t.Fatal("the snapshot hides why anchoring failed")
		}

		// The heartbeat is never hidden (FD §3.1): the lag keeps growing while
		// the segment stays unanchored, rather than freezing at the last
		// attempt.
		clock.advance(30 * time.Second)
		if later := anchorer.Lag(); later.LagSeconds != 120 {
			t.Fatalf("lag is %v seconds thirty seconds later, want 120", later.LagSeconds)
		}
	})

	t.Run("alert_is_emitted_and_is_appendable", func(t *testing.T) {
		body, err := AnchorAlert(AlertMeta{
			EventID: newEventID(t),
			TS:      mustTS(t, "2026-08-28T10:05:00.000Z"),
		}, sealedRecord, r.err)
		if err != nil {
			t.Fatalf("AnchorAlert: %v", err)
		}
		if got := body[event.FieldEventType]; got != event.EventTypeLedgerDriftDetected {
			t.Fatalf("alert event_type is %v, want %s", got, event.EventTypeLedgerDriftDetected)
		}
		if got := body[event.FieldSubjectEventID]; got != sealedRecord[event.FieldEventID] {
			t.Fatalf("alert names subject %v, want the sealed event %v",
				got, sealedRecord[event.FieldEventID])
		}
		if got := body[event.FieldSource]; got != event.SourceSystem {
			t.Fatalf("alert source is %v, want %s (the sealer emits it)", got, event.SourceSystem)
		}

		record := chain.append(t, body)
		if err := event.ValidateEvent(record); err != nil {
			t.Fatalf("the alert is not appendable: %v", err)
		}
		chain.verify(t)
	})

	t.Run("the_original_sealed_event_is_untouched", func(t *testing.T) {
		// I4. Everything above happened around this record; none of it is
		// allowed to have changed a byte of it.
		got, err := sealedRecord.EventHash()
		if err != nil {
			t.Fatalf("EventHash: %v", err)
		}
		if got != sealedRecord[event.EventHashField] {
			t.Fatalf("the original sealed event no longer hashes to %v",
				sealedRecord[event.EventHashField])
		}
		if _, present := sealedRecord[event.FieldAnchorRekorLogIndex]; present {
			t.Fatal("anchoring members were written onto the original event")
		}
		if _, present := sealedRecord[event.FieldSupersedes]; present {
			t.Fatal("supersedes was written onto the original event")
		}
	})
}

func TestSEG004SingleAttemptPolicyMakesExactlyOneAttempt(t *testing.T) {
	client, counter := deadRekor(t)
	clock := newTestClock(t, seg004Now)

	store := newMemStore()
	chain := &testChain{}
	_, sealedRecord := sealAndAppend(t, &Sealer{Store: store}, chain, 1, 4, seg004SealedAt)

	var sleeps int
	anchorer := &Anchorer{
		Log:    client,
		Policy: RetryPolicy{Attempts: 1, Base: time.Millisecond},
		Bound:  time.Minute,
		Now:    clock.Now,
		Sleep:  func(context.Context, time.Duration) error { sleeps++; return nil },
	}

	if _, err := anchorer.Anchor(context.Background(), sealedRecord); !errors.Is(err, ErrAnchorUnavailable) {
		t.Fatalf("Anchor error is %v, want one wrapping ErrAnchorUnavailable", err)
	}
	attempts, _ := counter.count()
	if attempts != 1 {
		t.Fatalf("%d connection attempts, want exactly 1", attempts)
	}
	if sleeps != 0 {
		t.Fatalf("backed off %d times with no retry left", sleeps)
	}
}

func TestSEG004CancellationStopsRetrying(t *testing.T) {
	client, counter := deadRekor(t)
	clock := newTestClock(t, seg004Now)

	store := newMemStore()
	chain := &testChain{}
	_, sealedRecord := sealAndAppend(t, &Sealer{Store: store}, chain, 1, 4, seg004SealedAt)

	ctx, cancel := context.WithCancel(context.Background())
	anchorer := &Anchorer{
		Log:    client,
		Policy: RetryPolicy{Attempts: 50, Base: time.Millisecond},
		Bound:  time.Minute,
		Now:    clock.Now,
		Sleep: func(context.Context, time.Duration) error {
			cancel()
			return context.Canceled
		},
	}

	_, err := anchorer.Anchor(ctx, sealedRecord)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Anchor error is %v, want one wrapping context.Canceled", err)
	}
	if attempts, _ := counter.count(); attempts != 1 {
		t.Fatalf("%d connection attempts after cancellation in the first backoff, want 1", attempts)
	}
}

func TestRetryPolicyBackoffIsExponentialAndCapped(t *testing.T) {
	p := RetryPolicy{Attempts: 6, Base: 100 * time.Millisecond, Max: 400 * time.Millisecond, Multiplier: 2}
	want := []time.Duration{
		100 * time.Millisecond,
		200 * time.Millisecond,
		400 * time.Millisecond,
		400 * time.Millisecond,
		400 * time.Millisecond,
	}
	for i, w := range want {
		if got := p.Backoff(i + 1); got != w {
			t.Errorf("Backoff(%d) = %v, want %v", i+1, got, w)
		}
	}

	// A zero policy is the documented default rather than an instant, endless
	// retry loop, and an attempt number below one is the first attempt.
	if got := (RetryPolicy{}).Backoff(0); got != defaultAnchorBase {
		t.Errorf("the zero policy's first backoff is %v, want %v", got, defaultAnchorBase)
	}
	if got := (RetryPolicy{}).withDefaults().Attempts; got != defaultAnchorAttempts {
		t.Errorf("the zero policy allows %d attempts, want %d", got, defaultAnchorAttempts)
	}
	// A cap below the base is a misconfiguration, not an instruction to wait
	// less than the base.
	if got := (RetryPolicy{Base: time.Second, Max: time.Millisecond}).Backoff(1); got != time.Second {
		t.Errorf("a Max below Base gave %v, want the Base %v", got, time.Second)
	}
}
