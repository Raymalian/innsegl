// SPDX-License-Identifier: Apache-2.0

package load

import (
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/segment"
)

// The OPS-002 assertions, convicted of being able to fail.
//
// Proposed doc 07 IDs: OPS-002a (the position scan) and OPS-002b (the
// heartbeat checker), both layer U. ADR-0039 carries the proposed rows; doc 07
// is normative and is not edited from here.
//
// A load test's assertions are the easiest thing in a repository to write
// vacuously: "no gaps" passes when nothing was appended, and "the heartbeat is
// accurate" passes when the heartbeat was never read. So every check in
// checks_test.go is fed a deliberately corrupt input here and required to
// convict, and the honest input is required to pass. These run on every
// machine, Docker or not.

func positionsAt(positions ...int64) []event.Fields {
	out := make([]event.Fields, 0, len(positions))
	for _, p := range positions {
		out = append(out, event.Fields{event.FieldChainPosition: p})
	}
	return out
}

// OPS-002a.
func TestScanPositionsConvictsAGapADuplicateAndAReversal(t *testing.T) {
	t.Run("a contiguous run is clean", func(t *testing.T) {
		scan, err := scanPositions(positionsAt(1, 2, 3, 4, 5))
		if err != nil {
			t.Fatalf("scanPositions: %v", err)
		}
		if !scan.OK() {
			t.Fatalf("1..5 is not clean: %+v", scan)
		}
	})

	t.Run("one missing position is a gap", func(t *testing.T) {
		scan, err := scanPositions(positionsAt(1, 2, 4, 5))
		if err != nil {
			t.Fatalf("scanPositions: %v", err)
		}
		if scan.OK() {
			t.Fatal("a chain missing position 3 scanned clean; the OPS-002 gap check " +
				"cannot convict an I1/I2 violation")
		}
		if len(scan.Gaps) != 1 || scan.Gaps[0].After != 2 || scan.Gaps[0].Before != 4 {
			t.Fatalf("gaps = %v, want one gap between 2 and 4", scan.Gaps)
		}
		if got := scan.Gaps[0].String(); !strings.Contains(got, "1 position(s) missing") {
			t.Errorf("gap renders as %q, which does not say how much is missing", got)
		}
	})

	t.Run("a whole missing batch is one gap with a width", func(t *testing.T) {
		scan, err := scanPositions(positionsAt(1, 2, 20, 21))
		if err != nil {
			t.Fatalf("scanPositions: %v", err)
		}
		if len(scan.Gaps) != 1 {
			t.Fatalf("gaps = %v, want one", scan.Gaps)
		}
		if got := scan.Gaps[0].String(); !strings.Contains(got, "17 position(s) missing") {
			t.Errorf("gap renders as %q, want 17 missing", got)
		}
	})

	t.Run("a repeated position is a duplicate", func(t *testing.T) {
		scan, err := scanPositions(positionsAt(1, 2, 2, 3))
		if err != nil {
			t.Fatalf("scanPositions: %v", err)
		}
		if scan.OK() || len(scan.Duplicates) != 1 || scan.Duplicates[0] != 2 {
			t.Fatalf("duplicates = %v on 1,2,2,3", scan.Duplicates)
		}
	})

	t.Run("an out-of-order position is reported", func(t *testing.T) {
		scan, err := scanPositions(positionsAt(1, 3, 2, 4))
		if err != nil {
			t.Fatalf("scanPositions: %v", err)
		}
		if len(scan.Unordered) != 1 || scan.Unordered[0] != 2 {
			t.Fatalf("unordered = %v on 1,3,2,4", scan.Unordered)
		}
	})

	t.Run("a chain that does not start at 1 is not clean", func(t *testing.T) {
		scan, err := scanPositions(positionsAt(2, 3, 4))
		if err != nil {
			t.Fatalf("scanPositions: %v", err)
		}
		if scan.OK() {
			t.Fatal("a chain starting at position 2 scanned clean; doc 02 §4.4 puts " +
				"the genesis event at position 1")
		}
	})

	t.Run("a record with no position is an error, not a pass", func(t *testing.T) {
		if _, err := scanPositions([]event.Fields{{}}); err == nil {
			t.Fatal("a record with no chain_position scanned without error; a scan " +
				"that cannot read a position must say so rather than count it as fine")
		}
	})
}

// honestSamples is one accurate heartbeat trace: nothing sealed, then a
// segment pending, then that segment anchored and its lag growing.
func honestSamples(t0 time.Time, bound time.Duration) ([]heartbeatSample, []anchoredWall) {
	anchoredAt := t0.Add(2 * time.Second)
	wall := []anchoredWall{{SegmentID: "sha256:aa", At: anchoredAt, Last: 64}}
	return []heartbeatSample{
		{
			At: t0, AtEnd: t0,
			SubmittedBefore: 0, CompletedBefore: 0, SubmittedAfter: 0, CompletedAfter: 0,
			Snap: segment.LagSnapshot{ObservedAt: t0, BoundSeconds: bound.Seconds()},
		},
		{
			At: t0.Add(time.Second), AtEnd: t0.Add(time.Second),
			SubmittedBefore: 1, CompletedBefore: 0,
			SubmittedAfter: 1, CompletedAfter: 0,
			Snap: segment.LagSnapshot{
				ObservedAt: t0.Add(time.Second), BoundSeconds: bound.Seconds(),
				PendingSegments: 1, PendingSince: t0, LagSeconds: 1,
			},
		},
		{
			At: anchoredAt.Add(3 * time.Second), AtEnd: anchoredAt.Add(3 * time.Second),
			SubmittedBefore: 1, CompletedBefore: 1,
			SubmittedAfter: 1, CompletedAfter: 1,
			Snap: segment.LagSnapshot{
				ObservedAt: anchoredAt.Add(3 * time.Second), BoundSeconds: bound.Seconds(),
				Anchored: true, SegmentID: "sha256:aa", FirstPosition: 1, LastPosition: 64,
				AnchoredAt: anchoredAt, LagSeconds: 3,
			},
		},
	}, wall
}

// OPS-002b.
func TestCheckHeartbeatConvictsEveryWayItCouldBeWrong(t *testing.T) {
	const bound = 15 * time.Minute
	t0 := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)

	t.Run("an accurate trace is accepted", func(t *testing.T) {
		samples, wall := honestSamples(t0, bound)
		if bad := checkHeartbeat(samples, bound, wall); len(bad) != 0 {
			t.Fatalf("an accurate heartbeat trace was convicted: %v", bad)
		}
	})

	for _, tc := range []struct {
		name    string
		corrupt func(s []heartbeatSample, w []anchoredWall) ([]heartbeatSample, []anchoredWall)
		want    string
	}{
		{
			name: "anchored while a segment is pending",
			corrupt: func(s []heartbeatSample, w []anchoredWall) ([]heartbeatSample, []anchoredWall) {
				s[1].Snap.Anchored = true
				return s, w
			},
			want: "pending",
		},
		{
			name: "over_bound false while the lag exceeds the bound",
			corrupt: func(s []heartbeatSample, w []anchoredWall) ([]heartbeatSample, []anchoredWall) {
				s[2].Snap.LagSeconds = bound.Seconds() + 60
				s[2].Snap.OverBound = false
				return s, w
			},
			want: "over_bound",
		},
		{
			name: "more pending than were ever submitted",
			corrupt: func(s []heartbeatSample, w []anchoredWall) ([]heartbeatSample, []anchoredWall) {
				s[1].Snap.PendingSegments = 4
				return s, w
			},
			want: "at most",
		},
		{
			name: "a pending segment with no pending_since",
			corrupt: func(s []heartbeatSample, w []anchoredWall) ([]heartbeatSample, []anchoredWall) {
				s[1].Snap.PendingSince = time.Time{}
				return s, w
			},
			want: "pending_since",
		},
		{
			name: "the heartbeat walks backwards",
			corrupt: func(s []heartbeatSample, w []anchoredWall) ([]heartbeatSample, []anchoredWall) {
				s = append(s, s[2])
				s[3].Snap.LastPosition = 8
				return s, w
			},
			want: "backwards",
		},
		{
			name: "a lag the test's own clock contradicts",
			corrupt: func(s []heartbeatSample, w []anchoredWall) ([]heartbeatSample, []anchoredWall) {
				s[2].Snap.LagSeconds = 0.001
				return s, w
			},
			want: "brackets it at",
		},
		{
			name: "a segment the driver never anchored",
			corrupt: func(s []heartbeatSample, w []anchoredWall) ([]heartbeatSample, []anchoredWall) {
				s[2].Snap.SegmentID = "sha256:bb"
				return s, w
			},
			want: "never anchored it",
		},
		{
			name: "the wrong position range for the segment named",
			corrupt: func(s []heartbeatSample, w []anchoredWall) ([]heartbeatSample, []anchoredWall) {
				s[2].Snap.LastPosition = 999
				return s, w
			},
			want: "it ends at",
		},
		{
			name: "a bound that is not the one configured",
			corrupt: func(s []heartbeatSample, w []anchoredWall) ([]heartbeatSample, []anchoredWall) {
				s[0].Snap.BoundSeconds = 1
				return s, w
			},
			want: "bound_seconds",
		},
		{
			name: "a reading with no time on it",
			corrupt: func(s []heartbeatSample, w []anchoredWall) ([]heartbeatSample, []anchoredWall) {
				s[0].Snap.ObservedAt = time.Time{}
				return s, w
			},
			want: "observed_at",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			samples, wall := tc.corrupt(honestSamples(t0, bound))
			bad := checkHeartbeat(samples, bound, wall)
			if len(bad) == 0 {
				t.Fatalf("checkHeartbeat accepted %q; the OPS-002 heartbeat "+
					"assertion cannot convict this", tc.name)
			}
			if !strings.Contains(strings.Join(bad, "\n"), tc.want) {
				t.Errorf("convicted for the wrong reason: want a report containing %q, got %v",
					tc.want, bad)
			}
		})
	}
}

// segmentsNamed is what catches a heartbeat frozen on an old segment, so it
// too is required to be able to notice.
// OPS-002b, the stall half.
func TestSegmentsNamedSeesTheHeartbeatAdvanceAndSeesItStall(t *testing.T) {
	const bound = 15 * time.Minute
	t0 := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	samples, _ := honestSamples(t0, bound)

	if got := segmentsNamed(samples); len(got) != 1 {
		t.Fatalf("segmentsNamed = %v over a trace that anchored one segment", got)
	}

	frozen := append([]heartbeatSample{}, samples...)
	advanced := frozen[2]
	advanced.Snap.SegmentID = "sha256:bb"
	frozen = append(frozen, advanced)
	if got := segmentsNamed(frozen); len(got) != 2 {
		t.Fatalf("segmentsNamed = %v over a trace that named two segments; a check "+
			"that cannot see the heartbeat advance cannot see it stall either", got)
	}
}
