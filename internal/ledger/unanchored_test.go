// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
)

// RM-204 (#327). The sealer's survey walks back only as far as the latest
// seal, so a segment sealed before that and never anchored was never retried.
// UnanchoredSeals is the one query that finds every such segment, however old.

func sealedBody(first, last int64, root byte) event.Fields {
	return event.Fields{
		event.FieldSchemaVersion:     event.SchemaVersion,
		event.FieldEventType:         event.EventTypeSegmentSealed,
		event.FieldSource:            event.SourceSystem,
		event.FieldSegmentID:         event.HashPrefix + strings.Repeat(string(root), 64),
		event.FieldSegmentMerkleRoot: event.HashPrefix + strings.Repeat(string(root), 64),
		event.FieldFirstPosition:     first,
		event.FieldLastPosition:      last,
	}
}

// anchoredBody is the superseding segment_sealed doc 02 §3 appends once the
// log confirms: the original's members plus the two anchoring ones.
func anchoredBody(original event.Fields, supersedes string, logIndex int64) event.Fields {
	body := event.Fields{}
	for _, name := range []string{
		event.FieldSchemaVersion, event.FieldEventType, event.FieldSource,
		event.FieldSegmentID, event.FieldSegmentMerkleRoot,
		event.FieldFirstPosition, event.FieldLastPosition,
	} {
		body[name] = original[name]
	}
	body[event.FieldSupersedes] = supersedes
	body[event.FieldAnchorRekorLogIndex] = logIndex
	body[event.FieldAnchorRekorEntryUUID] = fmt.Sprintf("%064x", logIndex)
	return body
}

func TestRM204UnanchoredSealsReturnsExactlyTheSealsWithNoAnchor(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	ctx := testCtx(t, 2*time.Minute)

	// Empty chain: nothing, and not an error.
	none, err := s.UnanchoredSeals(ctx)
	if err != nil {
		t.Fatalf("UnanchoredSeals on an empty chain: %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("an empty chain has %d unanchored seals", len(none))
	}

	// Segment 1..2 sealed and never anchored: the case the survey misses.
	stuck := appendOrFailLedger(ctx, t, s, sealedBody(1, 2, 'a'))
	// A drift alert about it: not a seal, never returned.
	appendOrFailLedger(ctx, t, s, driftAlertBody(memberString(t, stuck, event.FieldEventID), "rm-204-drift"))
	// Segment 3..4 sealed, then anchored by a superseding event.
	anchored := appendOrFailLedger(ctx, t, s, sealedBody(3, 4, 'b'))
	appendOrFailLedger(ctx, t, s,
		anchoredBody(anchored, memberString(t, anchored, event.FieldEventID), 1))
	// Segment 7..8 sealed and not yet anchored.
	recent := appendOrFailLedger(ctx, t, s, sealedBody(7, 8, 'c'))

	got, err := s.UnanchoredSeals(ctx)
	if err != nil {
		t.Fatalf("UnanchoredSeals: %v", err)
	}
	want := []string{
		memberString(t, stuck, event.FieldEventID),
		memberString(t, recent, event.FieldEventID),
	}
	if len(got) != len(want) {
		t.Fatalf("UnanchoredSeals returned %d records, want %d: %+v", len(got), len(want), got)
	}
	for i, id := range want {
		if got[i][event.FieldEventID] != id {
			t.Errorf("record %d is %v, want %s (oldest first)", i, got[i][event.FieldEventID], id)
		}
		if got[i][event.FieldEventType] != event.EventTypeSegmentSealed {
			t.Errorf("record %d is a %v, want segment_sealed", i, got[i][event.FieldEventType])
		}
		if _, has := got[i][event.FieldAnchorRekorEntryUUID]; has {
			t.Errorf("record %d carries an anchor", i)
		}
	}
	// Records come back whole, as Events returns them: the sealer builds the
	// superseding event from this record, so its chain position must be there.
	if _, ok := got[0][event.FieldChainPosition].(int64); !ok {
		t.Errorf("the returned record carries no chain_position: %+v", got[0])
	}

	// Anchoring the stuck segment removes it.
	appendOrFailLedger(ctx, t, s,
		anchoredBody(stuck, memberString(t, stuck, event.FieldEventID), 2))
	after, err := s.UnanchoredSeals(ctx)
	if err != nil {
		t.Fatalf("UnanchoredSeals after anchoring: %v", err)
	}
	if len(after) != 1 || after[0][event.FieldEventID] != want[1] {
		t.Errorf("after anchoring the oldest, got %+v, want only %s", after, want[1])
	}
}

func TestRM204UnanchoredSealsReportsALedgerItCannotRead(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	ctx := testCtx(t, time.Minute)
	s.Close()
	if _, err := s.UnanchoredSeals(ctx); err == nil {
		t.Fatal("UnanchoredSeals succeeded over a closed store")
	}
}
