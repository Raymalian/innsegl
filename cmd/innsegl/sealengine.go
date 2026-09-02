// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/google/uuid"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/segment"
)

// The sealer engine: the half of `innsegl seal` that decides what to seal,
// when to stop, and what to do when the transparency log will not take an
// anchor. The mechanism it drives is internal/segment — the Merkle tree, the
// content address, the WORM write and the Rekor submission are all there and
// are what SEG-001..006 prove. Nothing in this file reimplements any of it.
//
// # The three things a cycle does, in this order
//
//  1. Survey. Walk the chain backwards from the head and find the sealed
//     watermark — the highest last_position any segment_sealed event claims —
//     along with the anchoring state of the segments in that span.
//  2. Anchor the backlog. Every surveyed segment that is sealed but carries no
//     anchor is retried first, before any new segment is sealed. That is what
//     makes IP §6.4's "retry with backoff and alert" a thing that actually
//     happens more than once.
//  3. Seal forward. From watermark+1, seal each full segment; then, if the
//     oldest unsealed event has been waiting longer than the rollover age,
//     seal the partial one.
//
// # Why the survey walks backwards, and why it terminates
//
// A `segment_sealed` event is appended *after* the range it seals, so an event
// at chain position p has last_position ≤ p-1. Walking backwards in pages and
// tracking the highest last_position seen, once the next unread position is at
// or below that high-water mark, no unread event can beat it — every one of
// them is at a position below the mark and therefore seals a range that ends
// below the mark. So the walk stops, and in a deployment that is keeping up it
// stops after one page.
//
// The one thing it does not do is find a segment that was sealed but never
// anchored a very long time ago, because it stops before reaching it. That is
// the honest limit of a bounded scan and -scan-window is where an operator
// sets it. Such a segment is not lost: its `segment_sealed` event is in the
// chain and its `ledger_drift_detected` alert was raised when the anchoring
// budget was spent.
//
// # Why the sealer refuses to seal its own bookkeeping
//
// Sealing appends two events (the seal, then the superseding anchored one).
// If the age-based rollover treated those like any other events, an idle
// deployment would seal them, which would append two more, which would age
// out, which would be sealed — a ratchet that never stops and costs a Rekor
// entry every turn. So the age rollover fires only when the range holds at
// least one event the sealer did not itself append, which it can tell because
// every event it appends carries an idempotency key under the `sealer:`
// prefix. A *full* segment always seals, whatever it holds: a size rollover
// cannot ratchet, because it consumes more events than it produces.

// Idempotency keys, in the house shape `<component>:<event_type>:<subject>`
// (internal/reconciler/reconcile.go, internal/spire/reaper.go).
//
// The subject is the segment's FIRST POSITION rather than its segment id, and
// that choice is what gives the command the property an operator needs: a
// second run over the same range rebuilds the identical body and the ledger
// returns the original event (LED-008), while a run that would seal a
// *different* range from the same starting position is refused by the
// idempotency-key conflict rather than quietly appending a second, overlapping
// claim about the same positions.
const (
	sealerKeyPrefix   = "sealer:"
	sealedKeyPrefix   = sealerKeyPrefix + "segment_sealed:"
	anchoredKeyPrefix = sealerKeyPrefix + "segment_anchored:"
	driftKeyPrefix    = sealerKeyPrefix + "ledger_drift_detected:"
)

func sealedKey(first int64) string   { return sealedKeyPrefix + strconv.FormatInt(first, 10) }
func anchoredKey(first int64) string { return anchoredKeyPrefix + strconv.FormatInt(first, 10) }
func driftKey(subjectEventID string) string {
	return driftKeyPrefix + subjectEventID
}

// sealChain is the ledger surface the sealer needs. It is an interface so the
// engine's decisions are testable without a Postgres; *ledger.Store is the
// production implementation.
type sealChain interface {
	Head(ctx context.Context) (ledger.Head, error)
	Events(ctx context.Context, from, to int64) ([]event.Fields, error)
	Append(ctx context.Context, body event.Fields) (event.Fields, error)
}

// segmentSealer is *segment.Sealer's one method.
type segmentSealer interface {
	Seal(req segment.Request) (*segment.Sealed, error)
}

// segmentAnchorer is *segment.Anchorer's two.
type segmentAnchorer interface {
	Anchor(ctx context.Context, sealed event.Fields) (segment.Anchor, error)
	Lag() segment.LagSnapshot
}

// sealEngine runs one cycle at a time.
type sealEngine struct {
	chain    sealChain
	sealer   segmentSealer
	anchorer segmentAnchorer
	opts     sealOptions
	now      func() time.Time
	// newID mints the UUIDv7 the two builders in internal/segment ask for.
	// The ledger assigns the real event_id, so this value never reaches the
	// chain; it is a field so the one failure path it has is reachable from a
	// test.
	newID func() (string, error)

	// watermark is what the last cycle sealed through. It is a floor for the
	// next survey and nothing else: a fresh process starts at zero and finds
	// the same answer from the chain, only more slowly.
	watermark int64
}

// sealedSegment is one segment as this command reports it.
type sealedSegment struct {
	SegmentID  string
	MerkleRoot string
	First      int64
	Last       int64
	Events     int
	Resumed    bool

	Anchored  bool
	LogIndex  int64
	EntryUUID string
	// Failure is why the anchor is missing, when it is.
	Failure string
	// Alerted reports that a ledger_drift_detected was appended for it.
	Alerted bool
}

// sealCycle is everything one cycle observed.
type sealCycle struct {
	// Head is the chain tip the cycle worked against.
	Head int64
	// Watermark is the position the cold tier covers through at cycle end.
	Watermark int64
	// Pending is how many appended events are not yet in any segment.
	Pending int64

	// Sealed is what this cycle sealed; Anchored is what it anchored out of
	// the backlog it inherited; Unanchored is everything still sealed with no
	// entry in the log, whichever list it came from.
	Sealed     []sealedSegment
	Anchored   []sealedSegment
	Unanchored []sealedSegment

	Lag segment.LagSnapshot
}

// sealSurvey is what the backwards walk found.
type sealSurvey struct {
	head      ledger.Head
	watermark int64
	backlog   []surveyedSegment
}

// surveyedSegment is a segment_sealed event the survey read, and the seal
// record itself — which is what the anchorer and doc 02 §3's superseding event
// are both built from.
type surveyedSegment struct {
	first      int64
	last       int64
	segmentID  string
	merkleRoot string
	record     event.Fields
}

// Cycle surveys, anchors the backlog, and seals forward.
//
// An anchoring failure is a reported outcome, not an error: IP §6.4 requires
// that "appends to the next segment continue", so a log that is down must not
// stop the cold tier from growing. The error return is for a cycle that could
// not do its work at all — an unreadable chain, a store that will not take an
// object, a ledger that will not take the event — and the partially filled
// result is returned alongside it so the operator sees how far it got.
func (e *sealEngine) Cycle(ctx context.Context) (sealCycle, error) {
	if e.opts.segmentEvents < 1 {
		return sealCycle{}, fmt.Errorf(
			"a segment of %d events is not a segment; set -segment-events above zero",
			e.opts.segmentEvents)
	}

	survey, err := e.survey(ctx)
	if err != nil {
		return sealCycle{}, err
	}

	cycle := sealCycle{Head: survey.head.Position, Watermark: survey.watermark}

	// The backlog first. A segment that has been waiting for an anchor is
	// older evidence than one that has not been sealed yet.
	for _, seg := range survey.backlog {
		view, aerr := e.anchor(ctx, seg)
		if view.Anchored {
			cycle.Anchored = append(cycle.Anchored, view)
		} else {
			cycle.Unanchored = append(cycle.Unanchored, view)
		}
		if aerr != nil {
			return e.finish(cycle), aerr
		}
	}

	if err := e.sealForward(ctx, survey, &cycle); err != nil {
		return e.finish(cycle), err
	}
	return e.finish(cycle), nil
}

// finish stamps the heartbeat and the pending count onto a cycle, and caches
// the watermark for the next one. Every return from Cycle goes through it, so
// a cycle that failed halfway still reports the heartbeat FD §3.1 says is
// never hidden.
func (e *sealEngine) finish(cycle sealCycle) sealCycle {
	if cycle.Head > cycle.Watermark {
		cycle.Pending = cycle.Head - cycle.Watermark
	}
	cycle.Lag = e.anchorer.Lag()
	e.watermark = cycle.Watermark
	return cycle
}

// sealForward seals every full segment above the watermark, and then the
// partial one if it has aged out.
func (e *sealEngine) sealForward(ctx context.Context, survey sealSurvey, cycle *sealCycle) error {
	first := survey.watermark + 1
	for first <= survey.head.Position {
		last := first + e.opts.segmentEvents - 1
		if last > survey.head.Position {
			last = survey.head.Position
		}

		records, err := e.chain.Events(ctx, first, last)
		if err != nil {
			return fmt.Errorf("reading positions %d..%d to seal them: %w", first, last, err)
		}
		if int64(len(records)) != last-first+1 {
			return fmt.Errorf(
				"the ledger returned %d records for positions %d..%d; a short read here "+
					"is a gap in the chain, not a slow reader", len(records), first, last)
		}
		if !e.shouldSeal(records) {
			return nil
		}

		seg, err := e.sealRecords(ctx, first, last, records)
		if err != nil {
			return err
		}
		view, aerr := e.anchor(ctx, seg)
		cycle.Sealed = append(cycle.Sealed, view)
		if !view.Anchored {
			cycle.Unanchored = append(cycle.Unanchored, view)
		}
		cycle.Watermark = seg.last
		if aerr != nil {
			return aerr
		}
		first = seg.last + 1
	}
	return nil
}

// shouldSeal is the rollover policy. A full segment always seals; a partial
// one seals only once its oldest event has waited out the rollover age AND the
// range holds something the sealer did not append itself.
func (e *sealEngine) shouldSeal(records []event.Fields) bool {
	if int64(len(records)) >= e.opts.segmentEvents {
		return true
	}
	if e.opts.maxSegmentAge <= 0 || len(records) == 0 {
		return false
	}
	raw := recordString(records[0], event.FieldTS)
	if raw == "" {
		return false
	}
	ts, err := event.ParseTimestamp(raw)
	if err != nil {
		return false
	}
	if e.now().Sub(ts.Time()) < e.opts.maxSegmentAge {
		return false
	}
	return holdsForeignEvent(records)
}

// holdsForeignEvent reports whether a range contains anything the sealer did
// not append. See the ratchet note at the top of this file.
func holdsForeignEvent(records []event.Fields) bool {
	for _, r := range records {
		if !hasPrefix(recordString(r, event.FieldIdempotencyKey), sealerKeyPrefix) {
			return true
		}
	}
	return false
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// sealRange seals positions first..last and appends the `segment_sealed` event
// that records it.
//
// The object goes to the store before the event goes to the ledger, and that
// order is not negotiable: the event names a segment_id, and an event naming a
// segment nobody stored is a claim with nothing behind it — which is the exact
// shape of the problem this whole command exists to fix. The reverse failure
// is benign: an object written but never named is an immutable orphan that
// costs storage and proves nothing, and the next cycle re-derives the same
// content address and adopts it.
func (e *sealEngine) sealRange(ctx context.Context, first, last int64) (surveyedSegment, error) {
	records, err := e.chain.Events(ctx, first, last)
	if err != nil {
		return surveyedSegment{}, fmt.Errorf("reading positions %d..%d to seal them: %w", first, last, err)
	}
	return e.sealRecords(ctx, first, last, records)
}

// sealRecords is sealRange over records the caller has already read. The seal
// pass has them in hand from the rollover decision, and reading a segment out
// of Postgres twice to reach the same bytes is a cost with nothing behind it.
func (e *sealEngine) sealRecords(
	ctx context.Context, first, last int64, records []event.Fields,
) (surveyedSegment, error) {
	sealed, err := e.sealer.Seal(segment.Request{Records: records})
	if err != nil {
		return surveyedSegment{}, fmt.Errorf("sealing positions %d..%d: %w", first, last, err)
	}

	body, err := e.sealedBody(sealed)
	if err != nil {
		return surveyedSegment{}, err
	}

	record, err := e.chain.Append(ctx, body)
	if err != nil {
		return surveyedSegment{}, fmt.Errorf(
			"appending the segment_sealed event for positions %d..%d (segment %s): %w",
			first, last, sealed.SegmentID, err)
	}
	return surveyedSegment{
		first: sealed.FirstPosition, last: sealed.LastPosition,
		segmentID: sealed.SegmentID, merkleRoot: sealed.MerkleRoot, record: record,
	}, nil
}

// sealedBody builds the `segment_sealed` body doc 02 §3 defines.
//
// segment.Sealed.Event is the production builder and is used as such; the two
// members it fills that the ledger owns are then removed, because the store
// assigns event_id and doc 02 §2 says a client ts "is ignored". The
// idempotency key is this command's, and is what makes a second run a replay.
func (e *sealEngine) sealedBody(sealed *segment.Sealed) (event.Fields, error) {
	id, err := e.eventID()
	if err != nil {
		return nil, err
	}
	body, err := sealed.Event(segment.EventMeta{EventID: id, TS: event.NewTimestamp(e.now())})
	if err != nil {
		return nil, fmt.Errorf("building the segment_sealed body for %s: %w", sealed.SegmentID, err)
	}
	delete(body, event.FieldEventID)
	delete(body, event.FieldTS)
	body[event.FieldIdempotencyKey] = sealedKey(sealed.FirstPosition)
	return body, nil
}

// anchor submits one sealed segment's Merkle root to the transparency log and,
// on success, appends the superseding `segment_sealed` event that carries the
// entry (doc 02 §3, I4: the original is never rewritten).
//
// The returned error is reserved for a failure that stops the cycle. A log
// that refused or never answered is reported in the view, alerted on, and
// returned with a nil error — IP §6.4 makes that a bounded degradation, not a
// halt.
func (e *sealEngine) anchor(ctx context.Context, seg surveyedSegment) (sealedSegment, error) {
	view := sealedSegment{
		SegmentID: seg.segmentID, MerkleRoot: seg.merkleRoot,
		First: seg.first, Last: seg.last, Events: int(seg.last - seg.first + 1),
	}

	anchor, err := e.anchorer.Anchor(ctx, seg.record)
	if err != nil {
		view.Failure = err.Error()
		alerted, aerr := e.alert(ctx, seg.record, err)
		view.Alerted = alerted
		return view, aerr
	}

	body, err := e.anchoredBody(seg, anchor)
	if err != nil {
		view.Failure = err.Error()
		return view, err
	}
	if _, err := e.chain.Append(ctx, body); err != nil {
		view.Failure = err.Error()
		return view, fmt.Errorf(
			"appending the anchored segment_sealed event for %s: %w", seg.segmentID, err)
	}

	view.Anchored = true
	view.LogIndex = anchor.LogIndex
	view.EntryUUID = anchor.EntryUUID
	return view, nil
}

// anchoredBody builds the superseding event. ledger.Correct owns `supersedes`
// when the chain is walked in memory; the Postgres store has no Correct, so
// the link is set here from the record being superseded and from nowhere else.
func (e *sealEngine) anchoredBody(seg surveyedSegment, anchor segment.Anchor) (event.Fields, error) {
	// The superseded event_id is read before anything is built: a correction
	// with nothing to point at is not a correction, and doc 02 §2 makes
	// `supersedes` the whole of the link.
	superseded, ok := seg.record[event.FieldEventID].(string)
	if !ok {
		return nil, fmt.Errorf("the segment_sealed record for %s has no readable %s",
			seg.segmentID, event.FieldEventID)
	}
	id, err := e.eventID()
	if err != nil {
		return nil, err
	}
	body, err := segment.AnchorEvent(
		segment.EventMeta{EventID: id, TS: event.NewTimestamp(e.now())}, seg.record, anchor)
	if err != nil {
		return nil, fmt.Errorf("building the anchored segment_sealed body for %s: %w",
			seg.segmentID, err)
	}
	delete(body, event.FieldEventID)
	delete(body, event.FieldTS)
	body[event.FieldSupersedes] = superseded
	body[event.FieldIdempotencyKey] = anchoredKey(seg.first)
	return body, nil
}

// alert appends the `ledger_drift_detected` a spent anchoring budget raises
// (segment.AnchorAlert). The key is the subject event and nothing else, so a
// log that stays down for a hundred cycles produces one alert per segment
// rather than a hundred.
func (e *sealEngine) alert(ctx context.Context, sealedRecord event.Fields, cause error) (bool, error) {
	subject, ok := sealedRecord[event.FieldEventID].(string)
	if !ok {
		return false, fmt.Errorf("the segment_sealed record has no readable %s",
			event.FieldEventID)
	}
	id, err := e.eventID()
	if err != nil {
		return false, err
	}
	body, err := segment.AnchorAlert(
		segment.AlertMeta{EventID: id, TS: event.NewTimestamp(e.now()), SubjectEventID: subject},
		sealedRecord, cause)
	if err != nil {
		return false, fmt.Errorf("building the anchoring alert for %s: %w", subject, err)
	}
	delete(body, event.FieldEventID)
	delete(body, event.FieldTS)
	body[event.FieldIdempotencyKey] = driftKey(subject)

	if _, err := e.chain.Append(ctx, body); err != nil {
		return false, fmt.Errorf(
			"appending the anchoring alert for %s: %w. The segment is sealed and "+
				"stored; nothing in the ledger says its root is unproved", subject, err)
	}
	return true, nil
}

// survey walks the chain backwards for the sealed watermark and the segments
// that have no anchor. See the termination argument at the top of this file.
func (e *sealEngine) survey(ctx context.Context) (sealSurvey, error) {
	head, err := e.chain.Head(ctx)
	if err != nil {
		return sealSurvey{}, fmt.Errorf("reading the chain head: %w", err)
	}
	out := sealSurvey{head: head, watermark: e.watermark}
	if head.Position == 0 {
		return out, nil
	}

	window := e.opts.scanWindow
	if window < 1 {
		window = defaultScanWindow
	}
	// The watermark is never negative — it starts at zero and is only ever set
	// from a last_position the schema bounds at 1 — so the floor is always a
	// valid 1-based position.
	floor := e.watermark + 1

	seals := map[int64]surveyedSegment{}
	anchored := map[int64]bool{}

	for to := head.Position; to >= floor; {
		from := to - window + 1
		if from < floor {
			from = floor
		}
		records, err := e.chain.Events(ctx, from, to)
		if err != nil {
			return sealSurvey{}, fmt.Errorf("surveying positions %d..%d: %w", from, to, err)
		}
		if err := collectSeals(records, seals, anchored, &out.watermark); err != nil {
			return sealSurvey{}, err
		}
		if from <= floor || out.watermark >= from-1 {
			break
		}
		to = from - 1
	}

	for first, seg := range seals {
		if !anchored[first] {
			out.backlog = append(out.backlog, seg)
		}
	}
	sort.Slice(out.backlog, func(i, j int) bool { return out.backlog[i].first < out.backlog[j].first })
	return out, nil
}

// collectSeals reads one page for segment_sealed events. A record carrying the
// anchoring members marks its segment anchored; one without is a candidate for
// the backlog. Records arrive in ascending position order and pages descend, so
// a segment's superseding event is always read before its original.
func collectSeals(
	records []event.Fields, seals map[int64]surveyedSegment, anchored map[int64]bool,
	watermark *int64,
) error {
	for _, r := range records {
		if recordString(r, event.FieldEventType) != event.EventTypeSegmentSealed {
			continue
		}
		first, err := recordInt64(r, event.FieldFirstPosition)
		if err != nil {
			return err
		}
		last, err := recordInt64(r, event.FieldLastPosition)
		if err != nil {
			return err
		}
		if last > *watermark {
			*watermark = last
		}
		if _, hasAnchor := r[event.FieldAnchorRekorEntryUUID]; hasAnchor {
			anchored[first] = true
			continue
		}
		if _, already := seals[first]; already {
			continue
		}
		seals[first] = surveyedSegment{
			first: first, last: last, record: r,
			segmentID:  recordString(r, event.FieldSegmentID),
			merkleRoot: recordString(r, event.FieldSegmentMerkleRoot),
		}
	}
	return nil
}

// recordString reads a string member of a stored record. Absence and a member
// of the wrong type are both the empty string, which is a value the schema
// does not otherwise admit — the same rule internal/reconciler reads records
// by.
func recordString(record event.Fields, name string) string {
	value, ok := record[name].(string)
	if !ok {
		return ""
	}
	return value
}

// recordInt64 reads an integer member of a stored record. The ledger writes
// them as int64; a record that has been through a JSON round trip may carry an
// int or a float64.
func recordInt64(record event.Fields, name string) (int64, error) {
	switch n := record[name].(type) {
	case int64:
		return n, nil
	case int:
		return int64(n), nil
	case float64:
		if float64(int64(n)) != n {
			return 0, fmt.Errorf("%s is %v, which is not an integer", name, n)
		}
		return int64(n), nil
	default:
		return 0, fmt.Errorf(
			"a %s event carries %s as %T; the sealer cannot tell what range it covers "+
				"and will not seal over it", event.EventTypeSegmentSealed, name, record[name])
	}
}

// eventID mints the UUIDv7 the two event builders in internal/segment ask for.
// The ledger assigns the real one; this satisfies the builder's own validation
// and is removed before the append.
func (e *sealEngine) eventID() (string, error) {
	if e.newID != nil {
		return e.newID()
	}
	return newEventID()
}

func newEventID() (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("minting an event id: %w", err)
	}
	return id.String(), nil
}

// errNoCycler guards the production wiring against a nil engine reaching the
// reporter, which would turn a configuration mistake into a panic.
var errNoCycler = errors.New("the sealer was opened but produced nothing to run")
