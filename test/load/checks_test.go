// SPDX-License-Identifier: Apache-2.0

package load

import (
	"fmt"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/segment"
)

// The OPS-002 assertions, as pure functions over what the run observed.
//
// They are pure and separate for one reason: an assertion embedded in a
// container-backed test is an assertion that can only be exercised when the
// containers are up, and an assertion nobody has watched fail is an assertion
// nobody has checked. checksbite_test.go feeds each of these a deliberately
// corrupt input and requires it to convict — no Docker, no stack, every run.

// positionGap is one break in the chain's positions.
//
// A gap is an I1/I2 violation and never a flake: doc 02 §2 assigns
// chain_position "under serialized append", so positions 1..N with nothing
// missing is not a statistical property of the append path, it is the
// definition of it. If this type is ever non-empty in a real run, that is the
// finding, and re-running until it disappears is the one response that is
// always wrong.
type positionGap struct {
	After  int64 // the last position seen before the break
	Before int64 // the first position seen after it
}

func (g positionGap) String() string {
	missing := g.Before - g.After - 1
	return fmt.Sprintf("%d position(s) missing between %d and %d", missing, g.After, g.Before)
}

// chainScan is what walking every record in the chain found.
type chainScan struct {
	Count      int
	First      int64
	Last       int64
	Gaps       []positionGap
	Duplicates []int64
	Unordered  []int64
}

// OK reports a chain whose positions are exactly 1..Count.
func (s chainScan) OK() bool {
	return len(s.Gaps) == 0 && len(s.Duplicates) == 0 && len(s.Unordered) == 0 &&
		s.First == 1 && s.Last == int64(s.Count)
}

// scanPositions walks records in the order the ledger returned them and
// reports every way the sequence departs from 1..N.
//
// It reports all of them rather than the first: under sustained load the
// interesting failure is a pattern — every Nth position missing, or one
// worker's whole batch — and a scan that stops at the first break cannot show
// one.
func scanPositions(records []event.Fields) (chainScan, error) {
	scan := chainScan{Count: len(records)}
	seen := make(map[int64]struct{}, len(records))
	var previous int64
	for i, record := range records {
		position, err := positionOf(record)
		if err != nil {
			return scan, fmt.Errorf("record %d: %w", i, err)
		}
		if i == 0 {
			scan.First = position
		}
		scan.Last = position

		if _, already := seen[position]; already {
			scan.Duplicates = append(scan.Duplicates, position)
		}
		seen[position] = struct{}{}

		switch {
		case i == 0:
		case position <= previous:
			scan.Unordered = append(scan.Unordered, position)
		case position > previous+1:
			scan.Gaps = append(scan.Gaps, positionGap{After: previous, Before: position})
		}
		previous = position
	}
	return scan, nil
}

func positionOf(record event.Fields) (int64, error) {
	raw, present := record[event.FieldChainPosition]
	if !present {
		return 0, fmt.Errorf("no %s", event.FieldChainPosition)
	}
	switch n := raw.(type) {
	case int64:
		return n, nil
	case int:
		return int64(n), nil
	default:
		return 0, fmt.Errorf("%s is %T, want an integer", event.FieldChainPosition, raw)
	}
}

// heartbeatSample is one reading of the anchoring heartbeat, bracketed by what
// the driver had done before and after it was taken.
//
// The brackets are what make the reading checkable. The sampler runs
// concurrently with the sealer, so there is no single "true" pending count to
// compare against — but there is a true *window*: a segment cannot be pending
// before it was submitted, and cannot still be pending after it completed.
type heartbeatSample struct {
	// At and AtEnd bracket the Lag() call on the test's own clock. Lag reads
	// its own clock once, somewhere inside that interval, so the two bounds
	// are what makes the reported lag checkable without assuming the sampling
	// goroutine was never descheduled — which on a loaded CI runner is not an
	// assumption worth making.
	At    time.Time
	AtEnd time.Time
	// SubmittedBefore/CompletedBefore are read immediately before Lag(),
	// SubmittedAfter/CompletedAfter immediately after it.
	SubmittedBefore int
	CompletedBefore int
	SubmittedAfter  int
	CompletedAfter  int
	Snap            segment.LagSnapshot
}

// anchoredWall is the test's own clock reading of when a segment finished
// anchoring, kept independently of the Anchorer's. Checking the heartbeat's
// lag against the Anchorer's own AnchoredAt would be checking a subtraction
// against itself.
type anchoredWall struct {
	SegmentID string
	At        time.Time
	Last      int64
}

// heartbeatTolerance is how far outside the bracket the reported lag may sit.
//
// The bracket already absorbs the sampling goroutine being descheduled, so
// what is left for the tolerance to cover is the gap between the Anchorer
// recording an anchor and the driver reading its own clock a few instructions
// later. It is not permission for the heartbeat to be approximately right:
// 250 ms against FD §3.1's 15-minute default bound is 0.03% of the quantity
// being reported.
const heartbeatTolerance = 250 * time.Millisecond

// checkHeartbeat returns every way the sampled heartbeat was not an accurate
// report of what the driver was doing. An empty return is an accurate one.
func checkHeartbeat(samples []heartbeatSample, bound time.Duration, anchored []anchoredWall) []string {
	var bad []string
	report := func(i int, format string, a ...any) {
		bad = append(bad, fmt.Sprintf("sample %d: %s", i, fmt.Sprintf(format, a...)))
	}

	byID := make(map[string]anchoredWall, len(anchored))
	for _, a := range anchored {
		byID[a.SegmentID] = a
	}

	var previousLast int64
	for i, s := range samples {
		snap := s.Snap

		if snap.ObservedAt.IsZero() {
			report(i, "no observed_at; FD §3.1 says the heartbeat is never hidden, "+
				"and a reading with no time on it is hidden")
		}
		if snap.BoundSeconds != bound.Seconds() {
			report(i, "bound_seconds is %v, the anchorer was configured with %v",
				snap.BoundSeconds, bound.Seconds())
		}
		if snap.LagSeconds < 0 {
			report(i, "lag_seconds is %v", snap.LagSeconds)
		}
		if want := snap.LagSeconds > snap.BoundSeconds; snap.OverBound != want {
			report(i, "over_bound is %v with lag %.3fs against bound %.3fs",
				snap.OverBound, snap.LagSeconds, snap.BoundSeconds)
		}
		if snap.Anchored && snap.PendingSegments != 0 {
			report(i, "claims anchored with %d segment(s) pending", snap.PendingSegments)
		}
		if snap.Anchored && snap.SegmentID == "" {
			report(i, "claims anchored and names no segment")
		}

		if snap.PendingSegments > 0 && snap.PendingSince.IsZero() {
			report(i, "reports %d pending and no pending_since; FD §3.1 renders "+
				"\"anchored M min ago\" from that instant", snap.PendingSegments)
		}

		// The pending count has to lie inside the window the brackets allow.
		//
		// Only the upper bound is checked, and the missing lower bound is a
		// soundness limit rather than an oversight: the Anchorer removes a
		// segment from its pending set inside Anchor, strictly before Anchor
		// returns, so between that removal and the driver's own "completed"
		// increment there is a sub-microsecond window in which a truthful
		// reading of zero pending would look like an under-report. A lower
		// bound checked here would be a flake generator. What replaces it is
		// stronger and deterministic: OPS-002 watches one whole anchor at
		// microsecond resolution and requires the heartbeat to have shown the
		// segment pending while it was in flight. See anchorAndWatch.
		if high := s.SubmittedAfter - s.CompletedBefore; snap.PendingSegments > high {
			report(i, "reports %d pending; at most %d had been submitted and not yet "+
				"completed when the reading was taken", snap.PendingSegments, high)
		}

		if snap.LastPosition < previousLast {
			report(i, "the heartbeat walked backwards: last_position %d after %d",
				snap.LastPosition, previousLast)
		}
		previousLast = snap.LastPosition

		// Accuracy, against a clock the anchorer does not own.
		if snap.SegmentID == "" || snap.PendingSegments != 0 {
			continue
		}
		wall, known := byID[snap.SegmentID]
		if !known {
			report(i, "names segment %s as anchored; the driver never anchored it",
				snap.SegmentID)
			continue
		}
		if snap.LastPosition != wall.Last {
			report(i, "names segment %s ending at position %d; it ends at %d",
				snap.SegmentID, snap.LastPosition, wall.Last)
		}
		lowLag := s.At.Sub(wall.At).Seconds() - heartbeatTolerance.Seconds()
		highLag := s.AtEnd.Sub(wall.At).Seconds() + heartbeatTolerance.Seconds()
		if snap.LagSeconds < lowLag || snap.LagSeconds > highLag {
			report(i, "reports %.3fs of lag for segment %s; the test's own clock "+
				"brackets it at %.3fs..%.3fs (tolerance %.3fs either side)",
				snap.LagSeconds, snap.SegmentID, lowLag, highLag,
				heartbeatTolerance.Seconds())
		}
	}
	return bad
}

// segmentsNamed is the set of segments the heartbeat named as anchored across
// a trace.
//
// A heartbeat that froze on the first segment it ever anchored is inaccurate
// in the way that matters most — it reports public tamper-evidence as current
// when it has stopped advancing — and every per-sample rule above would still
// pass, because each individual reading would be internally consistent.
func segmentsNamed(samples []heartbeatSample) map[string]struct{} {
	out := map[string]struct{}{}
	for _, s := range samples {
		if s.Snap.SegmentID != "" {
			out[s.Snap.SegmentID] = struct{}{}
		}
	}
	return out
}
