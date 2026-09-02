// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/segment"
)

// The sealer engine, which is the half of `innsegl seal` that decides what to
// seal and when to stop.
//
// Proposed doc 07 IDs, all layer F except where noted (the catalogue has no
// entry for a wired sealer; SEG-001..006 cover internal/segment's mechanism
// and SEG-007 is the rebuild oracle):
//
//	SEG-008  a full segment is sealed into the object store, its segment_sealed
//	         event appended, anchored in the log, and the superseding anchored
//	         event appended.
//	SEG-009  a second cycle over the same range writes no second object and no
//	         second event, and exits 0.
//	SEG-010  a cycle that would seal a DIFFERENT range from the same first
//	         position is refused, not overwritten.
//	SEG-011  anchoring fails: the segment stays sealed, one ledger_drift_detected
//	         alert is appended, the cycle reports UNANCHORED, and the next cycle
//	         anchors it without re-sealing.
//	SEG-012  (U) the rollover policy: full segments seal; a partial segment seals
//	         once it has aged out; a partial range consisting only of the
//	         sealer's own bookkeeping never does.
//	SEG-013  (U) the operator surface — see seal_test.go.

// ---------------------------------------------------------------------------
// Fakes.
//
// The chain fake is not a stub: it runs the real ledger.Append, so every
// record it holds is hash-chained by the shipped chain code, and it enforces
// LED-008's idempotency contract the way internal/ledger/postgres.go does —
// a replay of the same request returns the stored record, a different request
// under the same key is refused. The sealer's whole idempotency story rests on
// that contract, so a fake that did not keep it would prove nothing.
// ---------------------------------------------------------------------------

// errIdempotencyConflict mirrors ledger.ErrIdempotencyKeyConflict's role: a
// key already used by a different request.
var errIdempotencyConflict = errors.New("idempotency_key conflict")

// assignedMembers are the members the real store assigns and refuses from a
// caller. The fake refuses them too, so a body the sealer builds wrongly fails
// here exactly as it would against Postgres.
var assignedMembers = []string{
	event.FieldChainPosition, event.FieldPrevEventHash, event.EventHashField,
	event.FieldEventID,
}

type fakeChain struct {
	mu      sync.Mutex
	head    ledger.Head
	records []event.Fields
	byKey   map[string]event.Fields

	clock time.Time

	// Injected failures. Each is consumed by the next call when set.
	headErr   error
	eventsErr error
	appendErr error

	appends int
	reads   int
	seeded  int
}

func newFakeChain(clock time.Time) *fakeChain {
	return &fakeChain{byKey: map[string]event.Fields{}, clock: clock}
}

func (c *fakeChain) Head(context.Context) (ledger.Head, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.headErr != nil {
		return ledger.Head{}, c.headErr
	}
	return c.head, nil
}

func (c *fakeChain) Events(_ context.Context, from, to int64) ([]event.Fields, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.eventsErr != nil {
		return nil, c.eventsErr
	}
	if from < 1 || to < from {
		return nil, fmt.Errorf("range %d..%d is not a 1-based ascending range", from, to)
	}
	c.reads++
	out := make([]event.Fields, 0, 8)
	for _, r := range c.records {
		p, ok := r[event.FieldChainPosition].(int64)
		if ok && p >= from && p <= to {
			out = append(out, r.Clone())
		}
	}
	return out, nil
}

func (c *fakeChain) Append(_ context.Context, body event.Fields) (event.Fields, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.appendErr != nil {
		return nil, c.appendErr
	}
	for _, name := range assignedMembers {
		if _, present := body[name]; present {
			return nil, fmt.Errorf("%s is assigned by the ledger (doc 02 §2)", name)
		}
	}

	key := recordString(body, event.FieldIdempotencyKey)
	if key != "" {
		if stored, ok := c.byKey[key]; ok {
			if err := sameRequest(stored, body); err != nil {
				return nil, err
			}
			return stored.Clone(), nil
		}
	}

	staged := body.Clone()
	staged[event.FieldEventID] = newTestEventID()
	staged[event.FieldTS] = event.NewTimestamp(c.clock).String()

	record, head, err := ledger.Append(c.head, staged)
	if err != nil {
		return nil, err
	}
	c.head = head
	c.records = append(c.records, record)
	c.appends++
	if key != "" {
		c.byKey[key] = record
	}
	return record.Clone(), nil
}

// sameRequest is postgres.go's replay rule: identical on every member the
// caller supplies, compared over canonical bytes.
func sameRequest(stored, staged event.Fields) error {
	subset := stored.Clone()
	for _, name := range assignedMembers {
		delete(subset, name)
	}
	delete(subset, event.FieldTS)

	have, err := event.Canonicalize(subset)
	if err != nil {
		return err
	}
	replay := staged.Clone()
	delete(replay, event.FieldTS)
	want, err := event.Canonicalize(replay)
	if err != nil {
		return err
	}
	if string(have) != string(want) {
		return fmt.Errorf("%w: stored %s, replayed %s", errIdempotencyConflict, have, want)
	}
	return nil
}

// seed appends n ordinary tool_call events, the shape doc 02 §3 records with a
// payload digest only.
func (c *fakeChain) seed(t *testing.T, n int) {
	t.Helper()
	for range n {
		c.mu.Lock()
		c.seeded++
		nth := c.seeded
		c.mu.Unlock()
		body := event.Fields{
			event.FieldSchemaVersion:  event.SchemaVersion,
			event.FieldEventType:      event.EventTypeToolCall,
			event.FieldRunID:          "run-seal-test",
			event.FieldSpiffeID:       "spiffe://innsegl.dev/agent/sealer-test/task/run-seal-test",
			event.FieldSource:         event.SourceMCP,
			event.FieldIdempotencyKey: fmt.Sprintf("seed-%08d", nth),
			event.FieldToolName:       "record_event",
			event.FieldPayloadDigest: "sha256:" +
				"0000000000000000000000000000000000000000000000000000000000000000",
		}
		if _, err := c.Append(context.Background(), body); err != nil {
			t.Fatalf("seeding event %d: %v", nth, err)
		}
	}
}

func (c *fakeChain) countOfType(eventType string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, r := range c.records {
		if recordString(r, event.FieldEventType) == eventType {
			n++
		}
	}
	return n
}

func (c *fakeChain) recordsOfType(eventType string) []event.Fields {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := []event.Fields{}
	for _, r := range c.records {
		if recordString(r, event.FieldEventType) == eventType {
			out = append(out, r.Clone())
		}
	}
	return out
}

func newTestEventID() string {
	id, err := uuid.NewV7()
	if err != nil {
		panic(err)
	}
	return id.String()
}

// fakeStore is the object store: content-addressed, write-once, atomic.
type fakeStore struct {
	mu      sync.Mutex
	objects map[string][]byte
	putErr  error
	puts    int
}

func newFakeStore() *fakeStore { return &fakeStore{objects: map[string][]byte{}} }

func (s *fakeStore) Get(name string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.objects[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", segment.ErrObjectNotFound, name)
	}
	return append([]byte(nil), data...), nil
}

func (s *fakeStore) Put(name string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.putErr != nil {
		return s.putErr
	}
	s.objects[name] = append([]byte(nil), data...)
	s.puts++
	return nil
}

func (s *fakeStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.objects)
}

// fakeLog is the transparency log. Submitting a root already in it returns the
// same entry, which is what a real Rekor does and what makes a re-anchor
// harmless.
type fakeLog struct {
	mu      sync.Mutex
	byRoot  map[string]segment.Anchor
	next    int64
	err     error
	calls   int
	clock   time.Time
	rootErr map[string]error
}

func newFakeLog(clock time.Time) *fakeLog {
	return &fakeLog{byRoot: map[string]segment.Anchor{}, clock: clock, rootErr: map[string]error{}}
}

func (l *fakeLog) AnchorRoot(_ context.Context, merkleRoot string) (segment.Anchor, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	if l.err != nil {
		return segment.Anchor{}, l.err
	}
	if err, ok := l.rootErr[merkleRoot]; ok {
		return segment.Anchor{}, err
	}
	if a, ok := l.byRoot[merkleRoot]; ok {
		return a, nil
	}
	l.next++
	a := segment.Anchor{
		MerkleRoot:   merkleRoot,
		LogIndex:     l.next,
		EntryUUID:    fmt.Sprintf("%064x", l.next),
		IntegratedAt: l.clock,
	}
	l.byRoot[merkleRoot] = a
	return a, nil
}

func (l *fakeLog) InclusionProof(context.Context, string) (segment.InclusionProof, error) {
	return segment.InclusionProof{}, errors.New("not used by the sealer")
}

// ---------------------------------------------------------------------------
// Engine fixture.
// ---------------------------------------------------------------------------

type engineFixture struct {
	chain  *fakeChain
	store  *fakeStore
	log    *fakeLog
	engine *sealEngine
	clock  time.Time
}

func newEngineFixture(t *testing.T, mutate func(*sealOptions)) *engineFixture {
	t.Helper()
	clock := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	chain := newFakeChain(clock)
	store := newFakeStore()
	log := newFakeLog(clock)

	opts := defaultSealOptions()
	opts.segmentEvents = 4
	opts.maxSegmentAge = 10 * time.Minute
	opts.scanWindow = 1000
	// The shipped backoff is seconds-to-minutes, which is right in production
	// and would make this file a five-minute test. What the fixture must NOT
	// do is turn the retry off: SEG-011 depends on the anchorer exhausting a
	// real budget before the alert is raised.
	opts.anchorAttempts = 3
	opts.anchorBase = time.Millisecond
	if mutate != nil {
		mutate(&opts)
	}

	f := &engineFixture{chain: chain, store: store, log: log, clock: clock}
	f.engine = f.newEngine(chain, opts)
	return f
}

// newEngine builds an engine over the fixture's store and log. A fresh one
// stands in for a restarted process: it carries no cached watermark and has to
// find everything again from the chain.
func (f *engineFixture) newEngine(chain sealChain, opts sealOptions) *sealEngine {
	return &sealEngine{
		chain:  chain,
		sealer: &segment.Sealer{Store: f.store},
		anchorer: &segment.Anchorer{
			Log:    f.log,
			Policy: segment.RetryPolicy{Attempts: opts.anchorAttempts, Base: opts.anchorBase},
			Bound:  opts.anchorBound,
			Now:    f.nowFn(),
		},
		opts: opts,
		now:  f.nowFn(),
	}
}

func (f *engineFixture) nowFn() func() time.Time {
	return func() time.Time { return f.clock }
}

func (f *engineFixture) advance(d time.Duration) {
	f.clock = f.clock.Add(d)
	f.chain.mu.Lock()
	f.chain.clock = f.clock
	f.chain.mu.Unlock()
	f.log.mu.Lock()
	f.log.clock = f.clock
	f.log.mu.Unlock()
}

// ---------------------------------------------------------------------------
// SEG-008 — a segment reaches the object store and the log.
// ---------------------------------------------------------------------------

func TestSEG008CycleSealsAFullSegmentAndAnchorsIt(t *testing.T) {
	f := newEngineFixture(t, nil)
	f.chain.seed(t, 4)

	result, err := f.engine.Cycle(context.Background())
	if err != nil {
		t.Fatalf("Cycle: %v", err)
	}

	if len(result.Sealed) != 1 {
		t.Fatalf("sealed %d segments, want 1: %+v", len(result.Sealed), result.Sealed)
	}
	got := result.Sealed[0]
	if got.First != 1 || got.Last != 4 {
		t.Errorf("segment covers %d..%d, want 1..4", got.First, got.Last)
	}
	if !got.Anchored {
		t.Errorf("segment %s was not anchored: %s", got.SegmentID, got.Failure)
	}
	if len(result.Unanchored) != 0 {
		t.Errorf("unanchored = %+v, want none", result.Unanchored)
	}

	// The object is in the store, under its content address.
	if f.store.count() != 1 {
		t.Fatalf("object store holds %d objects, want 1", f.store.count())
	}
	object, err := f.store.Get(got.SegmentID)
	if err != nil {
		t.Fatalf("the sealed object is not in the store under its segment id: %v", err)
	}
	if event.Digest(object) != got.SegmentID {
		t.Errorf("the stored object hashes to %s, the segment id is %s",
			event.Digest(object), got.SegmentID)
	}

	// The root the sealer reported is the root the object carries.
	opened, err := segment.Open(f.store, got.SegmentID)
	if err != nil {
		t.Fatalf("segment.Open: %v", err)
	}
	if opened.Object.MerkleRoot != got.MerkleRoot {
		t.Errorf("stored root %s, reported root %s", opened.Object.MerkleRoot, got.MerkleRoot)
	}
	if opened.Object.FirstPosition != got.First || opened.Object.LastPosition != got.Last {
		t.Errorf("the stored object covers %d..%d, the event claims %d..%d",
			opened.Object.FirstPosition, opened.Object.LastPosition, got.First, got.Last)
	}

	// Two segment_sealed events: the seal, then the superseding anchored one.
	sealedRecords := f.chain.recordsOfType(event.EventTypeSegmentSealed)
	if len(sealedRecords) != 2 {
		t.Fatalf("chain holds %d segment_sealed events, want 2 (seal then anchored)",
			len(sealedRecords))
	}
	if _, present := sealedRecords[0][event.FieldAnchorRekorEntryUUID]; present {
		t.Errorf("the first segment_sealed carries an anchor; doc 02 §3 attaches it in a "+
			"superseding event and leaves the original untouched: %v", sealedRecords[0])
	}
	uuidValue, present := sealedRecords[1][event.FieldAnchorRekorEntryUUID]
	if !present {
		t.Fatalf("the superseding segment_sealed carries no %s",
			event.FieldAnchorRekorEntryUUID)
	}
	if uuidValue != got.EntryUUID {
		t.Errorf("the superseding event names entry %v, the cycle reported %s",
			uuidValue, got.EntryUUID)
	}
	if sealedRecords[1][event.FieldSupersedes] != sealedRecords[0][event.FieldEventID] {
		t.Errorf("the superseding event supersedes %v, the seal is %v",
			sealedRecords[1][event.FieldSupersedes], sealedRecords[0][event.FieldEventID])
	}
}

// ---------------------------------------------------------------------------
// SEG-009 — a second run is idempotent.
// ---------------------------------------------------------------------------

func TestSEG009SecondCycleOverTheSameRangeChangesNothing(t *testing.T) {
	f := newEngineFixture(t, nil)
	f.chain.seed(t, 4)

	first, err := f.engine.Cycle(context.Background())
	if err != nil {
		t.Fatalf("first Cycle: %v", err)
	}
	objectsAfterFirst := f.store.count()
	appendsAfterFirst := f.chain.appends
	logCallsAfterFirst := f.log.calls

	// A fresh engine, because an operator who runs the command twice gets a
	// fresh process with no memory of the first run.
	second := f.newEngine(f.chain, f.engine.opts)
	result, err := second.Cycle(context.Background())
	if err != nil {
		t.Fatalf("second Cycle: %v", err)
	}

	if len(result.Sealed) != 0 {
		t.Errorf("the second cycle sealed %d segments, want 0: %+v",
			len(result.Sealed), result.Sealed)
	}
	if len(result.Unanchored) != 0 {
		t.Errorf("the second cycle reported %d unanchored segments, want 0", len(result.Unanchored))
	}
	if f.store.count() != objectsAfterFirst {
		t.Errorf("object store holds %d objects after the second cycle, held %d after the first",
			f.store.count(), objectsAfterFirst)
	}
	if f.chain.appends != appendsAfterFirst {
		t.Errorf("the second cycle appended %d events, want 0",
			f.chain.appends-appendsAfterFirst)
	}
	if f.log.calls != logCallsAfterFirst {
		t.Errorf("the second cycle submitted %d entries to the log, want 0",
			f.log.calls-logCallsAfterFirst)
	}
	if result.Watermark != first.Watermark {
		t.Errorf("watermark moved from %d to %d with nothing new appended",
			first.Watermark, result.Watermark)
	}
}

// ---------------------------------------------------------------------------
// SEG-010 — a conflicting range at the same first position is refused.
// ---------------------------------------------------------------------------

func TestSEG010ConflictingSegmentSizeIsRefusedNotOverwritten(t *testing.T) {
	f := newEngineFixture(t, nil)
	f.chain.seed(t, 8)

	if _, err := f.engine.Cycle(context.Background()); err != nil {
		t.Fatalf("first Cycle: %v", err)
	}
	sealedBefore := f.chain.countOfType(event.EventTypeSegmentSealed)

	// The operator restarts with a different segment size. Position 1 is
	// already sealed under a four-event segment; a two-event segment from the
	// same start is a different claim about the same range.
	rerun := newEngineFixture(t, func(o *sealOptions) { o.segmentEvents = 2 })
	rerun.chain = f.chain
	rerun.store = f.store
	rerun.log = f.log
	rerun.engine = f.newEngine(f.chain, rerun.engine.opts)
	// Force the engine to start from position 1 as a fresh process with a
	// smaller segment would only if the chain held no seal at all; here the
	// chain does hold one, so the survey must find it and the sizes must not
	// collide. The collision this case is about is the one a *concurrent*
	// sealer with a different size produces, so the range is offered directly.
	_, err := rerun.engine.sealRange(context.Background(), 1, 2)

	if err == nil {
		t.Fatalf("sealing 1..2 over a chain that already sealed 1..4 succeeded; "+
			"want a refusal. chain now holds %d segment_sealed events",
			f.chain.countOfType(event.EventTypeSegmentSealed))
	}
	if !strings.Contains(err.Error(), "1") {
		t.Errorf("the refusal does not name the first position: %v", err)
	}
	if got := f.chain.countOfType(event.EventTypeSegmentSealed); got != sealedBefore {
		t.Errorf("the refused seal appended events: %d segment_sealed now, %d before",
			got, sealedBefore)
	}
}

// ---------------------------------------------------------------------------
// SEG-011 — an anchor failure leaves a recoverable state.
// ---------------------------------------------------------------------------

func TestSEG011AnchorFailureAlertsAndTheNextCycleRecovers(t *testing.T) {
	f := newEngineFixture(t, func(o *sealOptions) {
		o.anchorAttempts = 2
		o.anchorBase = time.Millisecond
	})
	f.chain.seed(t, 4)
	f.log.err = errors.New("connection refused")

	result, err := f.engine.Cycle(context.Background())
	if err != nil {
		t.Fatalf("Cycle returned an error; an anchoring failure is a reported outcome, "+
			"not a cycle that could not run: %v", err)
	}
	if len(result.Sealed) != 1 {
		t.Fatalf("sealed %d segments, want 1", len(result.Sealed))
	}
	if len(result.Unanchored) != 1 {
		t.Fatalf("unanchored = %d, want 1", len(result.Unanchored))
	}
	if f.store.count() != 1 {
		t.Errorf("the object store holds %d objects; a failed anchor must not undo the seal",
			f.store.count())
	}
	if got := f.chain.countOfType(event.EventTypeLedgerDriftDetected); got != 1 {
		t.Fatalf("chain holds %d ledger_drift_detected events, want exactly 1", got)
	}
	if got := f.chain.countOfType(event.EventTypeSegmentSealed); got != 1 {
		t.Errorf("chain holds %d segment_sealed events, want 1 (the seal, unanchored)", got)
	}

	// A second failing cycle must not raise a second alert: the key is stable.
	if _, cerr := f.engine.Cycle(context.Background()); cerr != nil {
		t.Fatalf("second Cycle: %v", cerr)
	}
	if got := f.chain.countOfType(event.EventTypeLedgerDriftDetected); got != 1 {
		t.Errorf("chain holds %d ledger_drift_detected events after two failing cycles, want 1", got)
	}

	// The log comes back. A fresh process must anchor the sealed segment
	// without re-sealing it.
	f.log.err = nil
	recovered := f.newEngine(f.chain, f.engine.opts)
	third, err := recovered.Cycle(context.Background())
	if err != nil {
		t.Fatalf("third Cycle: %v", err)
	}
	if len(third.Sealed) != 0 {
		t.Errorf("the recovery cycle re-sealed %d segments, want 0", len(third.Sealed))
	}
	if len(third.Anchored) != 1 {
		t.Fatalf("the recovery cycle anchored %d segments, want 1: %+v",
			len(third.Anchored), third.Anchored)
	}
	if len(third.Unanchored) != 0 {
		t.Errorf("still unanchored after recovery: %+v", third.Unanchored)
	}
	if f.store.count() != 1 {
		t.Errorf("the recovery wrote %d objects; the segment is content-addressed and "+
			"a re-seal adopts the object already there", f.store.count())
	}
	if got := f.chain.countOfType(event.EventTypeSegmentSealed); got != 2 {
		t.Errorf("chain holds %d segment_sealed events, want 2 (seal then anchored)", got)
	}
}

// ---------------------------------------------------------------------------
// SEG-012 — the rollover policy.
// ---------------------------------------------------------------------------

func TestSEG012PartialSegmentIsNotSealedBeforeItAges(t *testing.T) {
	f := newEngineFixture(t, nil)
	f.chain.seed(t, 3)

	result, err := f.engine.Cycle(context.Background())
	if err != nil {
		t.Fatalf("Cycle: %v", err)
	}
	if len(result.Sealed) != 0 {
		t.Fatalf("sealed %d segments from 3 of 4 events with nothing aged out", len(result.Sealed))
	}
	if f.store.count() != 0 {
		t.Errorf("the object store holds %d objects, want 0", f.store.count())
	}
	if result.Pending != 3 {
		t.Errorf("pending = %d, want 3", result.Pending)
	}
}

func TestSEG012PartialSegmentSealsOnceItHasAgedOut(t *testing.T) {
	f := newEngineFixture(t, nil)
	f.chain.seed(t, 3)

	f.advance(11 * time.Minute)

	result, err := f.engine.Cycle(context.Background())
	if err != nil {
		t.Fatalf("Cycle: %v", err)
	}
	if len(result.Sealed) != 1 {
		t.Fatalf("sealed %d segments after the range aged out, want 1", len(result.Sealed))
	}
	if got := result.Sealed[0]; got.First != 1 || got.Last != 3 {
		t.Errorf("aged segment covers %d..%d, want 1..3", got.First, got.Last)
	}
}

func TestSEG012AgedRangeOfOnlySealerBookkeepingIsNeverSealed(t *testing.T) {
	f := newEngineFixture(t, nil)
	f.chain.seed(t, 4)

	if _, err := f.engine.Cycle(context.Background()); err != nil {
		t.Fatalf("first Cycle: %v", err)
	}
	// Positions 5 and 6 are now the sealer's own segment_sealed pair. Age them
	// out well past the rollover window and run again: sealing them would
	// append two more events of the same kind, which would age out, which
	// would be sealed... A sealer that ratchets on its own bookkeeping never
	// stops, and every turn of the ratchet costs a Rekor entry.
	for range 5 {
		f.advance(11 * time.Minute)
		result, err := f.engine.Cycle(context.Background())
		if err != nil {
			t.Fatalf("Cycle: %v", err)
		}
		if len(result.Sealed) != 0 {
			t.Fatalf("sealed %d segments from a range holding only the sealer's own "+
				"segment_sealed events: %+v", len(result.Sealed), result.Sealed)
		}
	}
	if got := f.chain.countOfType(event.EventTypeSegmentSealed); got != 2 {
		t.Errorf("chain holds %d segment_sealed events, want the original 2", got)
	}

	// One real event arrives. Now the range is worth sealing, and the
	// bookkeeping goes with it.
	f.chain.seed(t, 1)
	f.advance(11 * time.Minute)
	result, err := f.engine.Cycle(context.Background())
	if err != nil {
		t.Fatalf("Cycle after a real append: %v", err)
	}
	if len(result.Sealed) != 1 {
		t.Fatalf("sealed %d segments once a real event joined the range, want 1", len(result.Sealed))
	}
	if got := result.Sealed[0]; got.First != 5 || got.Last != 7 {
		t.Errorf("segment covers %d..%d, want 5..7", got.First, got.Last)
	}
}

func TestSEG012SealsEveryFullSegmentInOneCycle(t *testing.T) {
	f := newEngineFixture(t, nil)
	f.chain.seed(t, 12)

	result, err := f.engine.Cycle(context.Background())
	if err != nil {
		t.Fatalf("Cycle: %v", err)
	}
	if len(result.Sealed) != 3 {
		t.Fatalf("sealed %d segments from 12 events at 4 per segment, want 3", len(result.Sealed))
	}
	wantRanges := [][2]int64{{1, 4}, {5, 8}, {9, 12}}
	for i, want := range wantRanges {
		got := result.Sealed[i]
		if got.First != want[0] || got.Last != want[1] {
			t.Errorf("segment %d covers %d..%d, want %d..%d", i, got.First, got.Last, want[0], want[1])
		}
	}
	if result.Watermark != 12 {
		t.Errorf("watermark = %d, want 12", result.Watermark)
	}
	if f.store.count() != 3 {
		t.Errorf("object store holds %d objects, want 3", f.store.count())
	}
}

// ---------------------------------------------------------------------------
// The survey.
// ---------------------------------------------------------------------------

func TestSurveyFindsTheWatermarkAcrossPageBoundaries(t *testing.T) {
	// A scan window smaller than the chain forces the backwards walk to page,
	// which is the branch a single-page fixture never reaches.
	f := newEngineFixture(t, func(o *sealOptions) { o.scanWindow = 2 })
	f.chain.seed(t, 12)

	result, err := f.engine.Cycle(context.Background())
	if err != nil {
		t.Fatalf("Cycle: %v", err)
	}
	if result.Watermark != 12 {
		t.Fatalf("watermark = %d, want 12", result.Watermark)
	}

	fresh := f.newEngine(f.chain, f.engine.opts)
	survey, err := fresh.survey(context.Background())
	if err != nil {
		t.Fatalf("survey: %v", err)
	}
	if survey.watermark != 12 {
		t.Errorf("a fresh process surveyed the watermark as %d, want 12", survey.watermark)
	}
	if len(survey.backlog) != 0 {
		t.Errorf("backlog = %+v, want empty; every segment is anchored", survey.backlog)
	}
}

func TestSurveyOnAnEmptyChainReportsNothingSealed(t *testing.T) {
	f := newEngineFixture(t, nil)

	survey, err := f.engine.survey(context.Background())
	if err != nil {
		t.Fatalf("survey: %v", err)
	}
	if survey.watermark != 0 || survey.head.Position != 0 {
		t.Errorf("survey of an empty chain = watermark %d head %d, want 0 and 0",
			survey.watermark, survey.head.Position)
	}

	result, err := f.engine.Cycle(context.Background())
	if err != nil {
		t.Fatalf("Cycle on an empty chain: %v", err)
	}
	if len(result.Sealed) != 0 || result.Pending != 0 {
		t.Errorf("cycle on an empty chain sealed %d and reports %d pending",
			len(result.Sealed), result.Pending)
	}
}

// ---------------------------------------------------------------------------
// Error paths. Every one of them is a way an operator learns nothing was
// sealed, and each must say so rather than exit quietly.
// ---------------------------------------------------------------------------

func TestCycleReportsAnUnreadableHead(t *testing.T) {
	f := newEngineFixture(t, nil)
	f.chain.headErr = errors.New("connection refused")

	if _, err := f.engine.Cycle(context.Background()); err == nil {
		t.Fatal("Cycle over an unreadable head returned no error")
	}
}

func TestCycleReportsAnUnreadableChain(t *testing.T) {
	f := newEngineFixture(t, nil)
	f.chain.seed(t, 4)
	f.chain.eventsErr = errors.New("connection reset")

	if _, err := f.engine.Cycle(context.Background()); err == nil {
		t.Fatal("Cycle over an unreadable chain returned no error")
	}
}

func TestCycleReportsAStoreThatWillNotAcceptTheObject(t *testing.T) {
	f := newEngineFixture(t, nil)
	f.chain.seed(t, 4)
	f.store.putErr = errors.New("access denied")

	if _, err := f.engine.Cycle(context.Background()); err == nil {
		t.Fatal("Cycle against a store that refuses writes returned no error")
	}
	if got := f.chain.countOfType(event.EventTypeSegmentSealed); got != 0 {
		t.Errorf("chain holds %d segment_sealed events after a failed write; "+
			"an event claiming a segment nobody stored is the one thing a "+
			"sealer must never append", got)
	}
}

func TestCycleReportsALedgerThatWillNotAcceptTheSealEvent(t *testing.T) {
	f := newEngineFixture(t, nil)
	f.chain.seed(t, 4)
	f.chain.appendErr = errors.New("ledger unavailable")

	if _, err := f.engine.Cycle(context.Background()); err == nil {
		t.Fatal("Cycle against a ledger that refuses appends returned no error")
	}
}

func TestAnchorFailureThatCannotBeAlertedIsStillReported(t *testing.T) {
	f := newEngineFixture(t, func(o *sealOptions) {
		o.anchorAttempts = 1
		o.anchorBase = time.Millisecond
	})
	f.chain.seed(t, 4)

	// The seal appends; the anchor fails; the alert cannot be appended either.
	f.log.err = errors.New("connection refused")
	f.engine.chain = &appendFailsAfter{fakeChain: f.chain, after: f.chain.appends + 1}

	result, err := f.engine.Cycle(context.Background())
	if err == nil {
		t.Fatal("a cycle whose alert could not be appended returned no error")
	}
	if len(result.Unanchored) != 1 {
		t.Errorf("unanchored = %d, want 1 even though the alert failed", len(result.Unanchored))
	}
}

// appendFailsAfter lets n more appends through, then refuses.
type appendFailsAfter struct {
	*fakeChain
	after int
}

func (a *appendFailsAfter) Append(ctx context.Context, body event.Fields) (event.Fields, error) {
	if a.appends >= a.after {
		return nil, errors.New("ledger unavailable")
	}
	return a.fakeChain.Append(ctx, body)
}

func TestCycleRefusesASegmentSizeItCannotHonour(t *testing.T) {
	f := newEngineFixture(t, func(o *sealOptions) { o.segmentEvents = 0 })
	f.chain.seed(t, 4)

	if _, err := f.engine.Cycle(context.Background()); err == nil {
		t.Fatal("a cycle with a non-positive segment size returned no error")
	}
}

func TestCycleReportsTheAnchoringHeartbeat(t *testing.T) {
	f := newEngineFixture(t, nil)
	f.chain.seed(t, 4)

	result, err := f.engine.Cycle(context.Background())
	if err != nil {
		t.Fatalf("Cycle: %v", err)
	}
	if result.Lag.ObservedAt.IsZero() {
		t.Error("the cycle reported no heartbeat; FD §3.1 says it is never hidden")
	}
	if !result.Lag.Anchored {
		t.Errorf("heartbeat says not anchored after a clean cycle: %+v", result.Lag)
	}
}

// ---------------------------------------------------------------------------
// The readers, and what they do with a record they cannot make sense of.
//
// These are not hypothetical. The sealer decides what to seal from members it
// reads out of other events, and a member it silently misreads would make it
// seal an overlapping range or skip one — which is worse than refusing,
// because the ledger would then hold two contradictory claims about the same
// positions and I4 makes both permanent.
// ---------------------------------------------------------------------------

func TestRecordInt64ReadsEveryEncodingAndRefusesTheRest(t *testing.T) {
	name := event.FieldLastPosition
	for label, value := range map[string]any{
		"int64":   int64(7),
		"int":     7,
		"float64": float64(7),
	} {
		t.Run(label, func(t *testing.T) {
			got, err := recordInt64(event.Fields{name: value}, name)
			if err != nil || got != 7 {
				t.Errorf("recordInt64(%v) = %d, %v; want 7, nil", value, got, err)
			}
		})
	}
	for label, value := range map[string]any{
		"fractional": 7.5,
		"string":     "7",
		"absent":     nil,
	} {
		t.Run(label, func(t *testing.T) {
			fields := event.Fields{}
			if value != nil {
				fields[name] = value
			}
			if _, err := recordInt64(fields, name); err == nil {
				t.Errorf("recordInt64(%v) accepted a %T", value, value)
			}
		})
	}
}

func TestSurveyRefusesASegmentSealedItCannotReadTheRangeOf(t *testing.T) {
	f := newEngineFixture(t, nil)
	f.chain.seed(t, 2)
	// A segment_sealed whose range members are unreadable. The fake appends it
	// without complaint precisely so the survey has to be the thing that
	// refuses; the shipped store would reject it at ValidateEvent, and a chain
	// that ever held one is a chain nothing should seal over.
	if _, err := f.chain.Append(context.Background(), event.Fields{
		event.FieldSchemaVersion:     event.SchemaVersion,
		event.FieldEventType:         event.EventTypeSegmentSealed,
		event.FieldSource:            event.SourceSystem,
		event.FieldSegmentID:         "sha256:" + strings.Repeat("a", 64),
		event.FieldSegmentMerkleRoot: "sha256:" + strings.Repeat("b", 64),
		event.FieldFirstPosition:     "one",
		event.FieldLastPosition:      "two",
	}); err != nil {
		t.Fatalf("appending the malformed record: %v", err)
	}

	if _, err := f.engine.survey(context.Background()); err == nil {
		t.Fatal("the survey read a segment_sealed with no readable range and carried on")
	}
}

func TestShouldSealRefusesARangeItCannotDateOrWasToldNotTo(t *testing.T) {
	f := newEngineFixture(t, nil)
	foreign := event.Fields{event.FieldIdempotencyKey: "seed-1"}

	t.Run("age rollover off", func(t *testing.T) {
		off := newEngineFixture(t, func(o *sealOptions) { o.maxSegmentAge = 0 })
		if off.engine.shouldSeal([]event.Fields{foreign}) {
			t.Error("a partial range sealed with -max-segment-age 0")
		}
	})
	t.Run("ts absent", func(t *testing.T) {
		if f.engine.shouldSeal([]event.Fields{foreign}) {
			t.Error("a range whose first event carries no ts was dated and sealed")
		}
	})
	t.Run("ts unparseable", func(t *testing.T) {
		bad := event.Fields{event.FieldIdempotencyKey: "seed-1", event.FieldTS: "yesterday"}
		if f.engine.shouldSeal([]event.Fields{bad}) {
			t.Error("a range whose first event carries an unreadable ts was sealed")
		}
	})
	t.Run("empty", func(t *testing.T) {
		if f.engine.shouldSeal(nil) {
			t.Error("an empty range was sealed")
		}
	})
}

func TestAnchorRefusesASealRecordWithNoEventID(t *testing.T) {
	f := newEngineFixture(t, nil)
	seg := surveyedSegment{
		first: 1, last: 4,
		segmentID:  "sha256:" + strings.Repeat("a", 64),
		merkleRoot: "sha256:" + strings.Repeat("b", 64),
		record:     event.Fields{event.FieldEventType: event.EventTypeSegmentSealed},
	}

	// The anchorer refuses it first, and then the alert cannot name a subject.
	view, err := f.engine.anchor(context.Background(), seg)
	if err == nil {
		t.Fatal("anchoring a record with no event_id returned no error")
	}
	if view.Anchored {
		t.Error("the view claims the segment is anchored")
	}
}

func TestAnchoredBodyRefusesASealRecordWithNoEventID(t *testing.T) {
	f := newEngineFixture(t, nil)
	seg := surveyedSegment{record: event.Fields{}}

	if _, err := f.engine.anchoredBody(seg, segment.Anchor{}); err == nil {
		t.Fatal("anchoredBody built a superseding event with nothing to supersede")
	}
}

func TestAnchorReportsALedgerThatWillNotTakeTheSupersedingEvent(t *testing.T) {
	f := newEngineFixture(t, nil)
	f.chain.seed(t, 4)

	seg, serr := f.engine.sealRange(context.Background(), 1, 4)
	if serr != nil {
		t.Fatalf("sealRange: %v", serr)
	}
	f.engine.chain = &appendFailsAfter{fakeChain: f.chain, after: f.chain.appends}

	view, err := f.engine.anchor(context.Background(), seg)
	if err == nil {
		t.Fatal("anchoring returned no error when the superseding append failed")
	}
	if view.Anchored {
		t.Error("the view claims the segment is anchored, but nothing recorded the entry")
	}
}

// ---------------------------------------------------------------------------
// The remaining branches. Each is a way the cycle stops, and a sealer that
// stopped without saying why is indistinguishable from one that had nothing
// to do — which is exactly the state #112 found the deployment in.
// ---------------------------------------------------------------------------

// readFailsAfter lets n more range reads through, then refuses. It is how a
// failure reached inside the seal pass rather than during the survey.
type readFailsAfter struct {
	*fakeChain
	after int
	seen  int
}

func (r *readFailsAfter) Events(ctx context.Context, from, to int64) ([]event.Fields, error) {
	r.seen++
	if r.seen > r.after {
		return nil, errors.New("connection reset mid-cycle")
	}
	return r.fakeChain.Events(ctx, from, to)
}

func TestSealPassReportsAReadThatFailsAfterTheSurvey(t *testing.T) {
	f := newEngineFixture(t, nil)
	f.chain.seed(t, 4)
	f.engine.chain = &readFailsAfter{fakeChain: f.chain, after: 1}

	if _, err := f.engine.Cycle(context.Background()); err == nil {
		t.Fatal("a read that failed inside the seal pass returned no error")
	}
}

func TestSealRangeReportsAReadItCannotMake(t *testing.T) {
	f := newEngineFixture(t, nil)
	f.chain.seed(t, 8)
	f.engine.chain = &readFailsAfter{fakeChain: f.chain, after: 0}

	if _, err := f.engine.sealRange(context.Background(), 5, 8); err == nil {
		t.Fatal("sealRange returned no error when the range could not be read")
	}
}

func TestSealRangeSealsARangeThatDoesNotStartAtOne(t *testing.T) {
	// The second and later segments are the ordinary case, and a sealRange
	// that only ever worked from position 1 would still pass every case above.
	f := newEngineFixture(t, nil)
	f.chain.seed(t, 8)

	seg, err := f.engine.sealRange(context.Background(), 5, 8)
	if err != nil {
		t.Fatalf("sealRange(5, 8): %v", err)
	}
	if seg.first != 5 || seg.last != 8 {
		t.Errorf("sealed %d..%d, want 5..8", seg.first, seg.last)
	}
	if recordString(seg.record, event.FieldIdempotencyKey) != sealedKey(5) {
		t.Errorf("the seal event carries key %q, want %q",
			recordString(seg.record, event.FieldIdempotencyKey), sealedKey(5))
	}
}

// shortReader answers a range with fewer records than it spans, which is what
// a gap in the chain would look like from here.
type shortReader struct{ *fakeChain }

func (s *shortReader) Events(ctx context.Context, from, to int64) ([]event.Fields, error) {
	records, err := s.fakeChain.Events(ctx, from, to)
	if err != nil || len(records) == 0 {
		return records, err
	}
	return records[:len(records)-1], nil
}

func TestSealPassRefusesAShortRead(t *testing.T) {
	f := newEngineFixture(t, nil)
	f.chain.seed(t, 4)
	f.engine.chain = &shortReader{fakeChain: f.chain}

	_, err := f.engine.Cycle(context.Background())
	if err == nil {
		t.Fatal("a short read was sealed as if it were the whole range")
	}
	if !strings.Contains(err.Error(), "gap in the chain") {
		t.Errorf("error = %v, want it to say a short read is a gap", err)
	}
	if f.store.count() != 0 {
		t.Errorf("a short read produced %d objects; a segment whose first_position and "+
			"last_position lie about what it holds must never be written", f.store.count())
	}
}

func TestBacklogAnchoringStopsWhenTheAlertCannotBeAppended(t *testing.T) {
	f := newEngineFixture(t, nil)
	f.chain.seed(t, 4)
	f.log.err = errors.New("connection refused")

	// Cycle one seals and fails to anchor, raising the alert.
	if _, err := f.engine.Cycle(context.Background()); err != nil {
		t.Fatalf("first Cycle: %v", err)
	}
	// A fresh process inherits the segment as backlog. This time the alert
	// cannot be appended either, so the cycle stops and says so.
	fresh := f.newEngine(&appendFailsAfter{fakeChain: f.chain, after: f.chain.appends},
		f.engine.opts)

	result, err := fresh.Cycle(context.Background())
	if err == nil {
		t.Fatal("a backlog cycle whose alert could not be appended returned no error")
	}
	if len(result.Unanchored) != 1 {
		t.Errorf("unanchored = %d, want the backlogged segment reported", len(result.Unanchored))
	}
}

func TestAlertRefusesARecordThatIsNotASegmentSeal(t *testing.T) {
	f := newEngineFixture(t, nil)
	notASeal := event.Fields{
		event.FieldEventID:   newTestEventID(),
		event.FieldEventType: event.EventTypeToolCall,
	}

	if _, err := f.engine.alert(context.Background(), notASeal, errors.New("cause")); err == nil {
		t.Fatal("an anchoring alert was built for an event that is not a segment_sealed")
	}
}

func TestAnchoredBodyRefusesAnAnchorThatDoesNotMatch(t *testing.T) {
	f := newEngineFixture(t, nil)
	f.chain.seed(t, 4)
	seg, err := f.engine.sealRange(context.Background(), 1, 4)
	if err != nil {
		t.Fatalf("sealRange: %v", err)
	}

	_, err = f.engine.anchoredBody(seg, segment.Anchor{
		MerkleRoot: "sha256:" + strings.Repeat("0", 64),
		EntryUUID:  strings.Repeat("1", 64),
	})
	if err == nil {
		t.Fatal("a superseding event was built from an anchor for a different root")
	}
}

// idFailure is a mint that never succeeds, which is the one failure the two
// event builders in internal/segment can hand back before anything is written.
func idFailure() (string, error) { return "", errors.New("no entropy") }

func TestAnEventIDThatCannotBeMintedStopsBeforeAnythingIsWritten(t *testing.T) {
	t.Run("seal", func(t *testing.T) {
		f := newEngineFixture(t, nil)
		f.chain.seed(t, 4)
		f.engine.newID = idFailure

		if _, err := f.engine.Cycle(context.Background()); err == nil {
			t.Fatal("the cycle carried on with no event id")
		}
		if f.chain.countOfType(event.EventTypeSegmentSealed) != 0 {
			t.Error("a segment_sealed was appended without an id being minted for it")
		}
	})
	t.Run("anchor", func(t *testing.T) {
		f := newEngineFixture(t, nil)
		f.chain.seed(t, 4)
		seg, err := f.engine.sealRange(context.Background(), 1, 4)
		if err != nil {
			t.Fatalf("sealRange: %v", err)
		}
		f.engine.newID = idFailure

		if _, err := f.engine.anchor(context.Background(), seg); err == nil {
			t.Fatal("the superseding event was built with no id")
		}
	})
	t.Run("alert", func(t *testing.T) {
		f := newEngineFixture(t, nil)
		f.chain.seed(t, 4)
		seg, err := f.engine.sealRange(context.Background(), 1, 4)
		if err != nil {
			t.Fatalf("sealRange: %v", err)
		}
		f.log.err = errors.New("connection refused")
		f.engine.newID = idFailure

		if _, err := f.engine.anchor(context.Background(), seg); err == nil {
			t.Fatal("the alert was built with no id")
		}
	})
}

func TestSurveyFallsBackToTheDefaultWindow(t *testing.T) {
	// The flag layer refuses a non-positive window, so an engine can only hold
	// one through a programming mistake. It must not read a range of zero
	// events forever.
	f := newEngineFixture(t, func(o *sealOptions) { o.scanWindow = 0 })
	f.chain.seed(t, 4)

	survey, err := f.engine.survey(context.Background())
	if err != nil {
		t.Fatalf("survey: %v", err)
	}
	if survey.head.Position != 4 {
		t.Errorf("head = %d, want 4", survey.head.Position)
	}
}

func TestSurveyOrdersTheBacklogOldestFirst(t *testing.T) {
	f := newEngineFixture(t, nil)
	f.chain.seed(t, 8)
	f.log.err = errors.New("connection refused")

	if _, err := f.engine.Cycle(context.Background()); err != nil {
		t.Fatalf("Cycle: %v", err)
	}

	fresh := f.newEngine(f.chain, f.engine.opts)
	survey, err := fresh.survey(context.Background())
	if err != nil {
		t.Fatalf("survey: %v", err)
	}
	if len(survey.backlog) != 2 {
		t.Fatalf("backlog = %d segments, want 2", len(survey.backlog))
	}
	if survey.backlog[0].first != 1 || survey.backlog[1].first != 5 {
		t.Errorf("backlog starts at %d then %d, want 1 then 5 — the older evidence first",
			survey.backlog[0].first, survey.backlog[1].first)
	}
}

func TestCollectSealsRefusesAnUnreadableLastPosition(t *testing.T) {
	records := []event.Fields{{
		event.FieldEventType:     event.EventTypeSegmentSealed,
		event.FieldFirstPosition: int64(1),
		event.FieldLastPosition:  "four",
	}}
	watermark := int64(0)

	if err := collectSeals(records, map[int64]surveyedSegment{}, map[int64]bool{}, &watermark); err == nil {
		t.Fatal("collectSeals read a segment_sealed with no readable last_position")
	}
}

func TestCollectSealsKeepsTheFirstSealItSeesForASegment(t *testing.T) {
	// Two unanchored seals for one starting position cannot arise through the
	// idempotency key, but the survey must not depend on that: it takes one
	// and moves on rather than growing a backlog entry per duplicate.
	seal := func(id string) event.Fields {
		return event.Fields{
			event.FieldEventType:         event.EventTypeSegmentSealed,
			event.FieldFirstPosition:     int64(1),
			event.FieldLastPosition:      int64(4),
			event.FieldSegmentID:         id,
			event.FieldSegmentMerkleRoot: "sha256:" + strings.Repeat("b", 64),
		}
	}
	seals := map[int64]surveyedSegment{}
	watermark := int64(0)

	if err := collectSeals(
		[]event.Fields{seal("sha256:" + strings.Repeat("a", 64)), seal("sha256:" + strings.Repeat("c", 64))},
		seals, map[int64]bool{}, &watermark,
	); err != nil {
		t.Fatalf("collectSeals: %v", err)
	}
	if len(seals) != 1 {
		t.Errorf("collectSeals kept %d seals for one starting position, want 1", len(seals))
	}
	if watermark != 4 {
		t.Errorf("watermark = %d, want 4", watermark)
	}
}
