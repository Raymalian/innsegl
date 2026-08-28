// SPDX-License-Identifier: Apache-2.0

package segment

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
)

// SEG-002 — "Kill sealer at every step boundary (parameterized), rerun.
// Resumes; final segment hash identical to no-crash run." (doc 07, IP §6.4)
//
// Sealing is a fixed, ordered list of steps precisely so that "every step
// boundary" is a finite, enumerable set rather than a figure of speech. Steps()
// is that list; AfterStep is the seam a kill is injected at. The matrix below
// aborts at each of the len(Steps())+1 boundaries — before the first step and
// after each one — and re-runs against the same store.

// sealTestRecords is the segment the SEG-002 matrix seals: eleven events, which
// promotes an odd node at three levels of the tree, over positions 7..17.
func sealTestRecords() []event.Fields { return seededRecords(7, 11) }

func TestStepsAreEnumerableAndOrdered(t *testing.T) {
	steps := Steps()
	want := []Step{StepPlan, StepBuildTree, StepEncodeObject, StepWriteObject, StepVerifyObject}
	if !slices.Equal(steps, want) {
		t.Fatalf("Steps() = %v, want %v", steps, want)
	}
	seen := map[string]bool{}
	for _, s := range steps {
		name := s.String()
		if name == "" || strings.HasPrefix(name, "Step(") {
			t.Errorf("step %d has no name", int(s))
		}
		if seen[name] {
			t.Errorf("two steps are both called %q", name)
		}
		seen[name] = true
	}
	if got := Step(0).String(); got == "" {
		t.Errorf("an unknown step must still render, got %q", got)
	}
}

// TestSEG002SealIsDeterministic is the "identical segment hash" half, with no
// crash anywhere: two independent seals of the same events agree byte for byte.
func TestSEG002SealIsDeterministic(t *testing.T) {
	first := mustSeal(t, newMemStore(), sealTestRecords())
	second := mustSeal(t, newMemStore(), sealTestRecords())

	if first.SegmentID != second.SegmentID {
		t.Errorf("segment id differs between runs:\n %s\n %s", first.SegmentID, second.SegmentID)
	}
	if first.MerkleRoot != second.MerkleRoot {
		t.Errorf("merkle root differs between runs:\n %s\n %s", first.MerkleRoot, second.MerkleRoot)
	}
	if string(first.Object) != string(second.Object) {
		t.Errorf("segment object differs between runs:\n %s\n %s", first.Object, second.Object)
	}
	// The segment id is the object's content address: it is derived, not
	// chosen, so a re-run cannot pick a different one.
	if got := digestOf(first.Object); got != first.SegmentID {
		t.Errorf("segment id %s is not the digest of the object it names (%s)", first.SegmentID, got)
	}
	if first.FirstPosition != 7 || first.LastPosition != 17 {
		t.Errorf("sealed range %d..%d, want 7..17", first.FirstPosition, first.LastPosition)
	}
	if first.Resumed {
		t.Error("a first seal into an empty store reports Resumed")
	}
}

// TestSEG002KillAtEveryStepBoundary is the matrix. Each case kills the sealer
// at one boundary, then re-runs against the same store and requires the same
// segment hash the uninterrupted run produced.
func TestSEG002KillAtEveryStepBoundary(t *testing.T) {
	reference := mustSeal(t, newMemStore(), sealTestRecords())

	// Boundary 0 is "before any step ran"; boundary n is "after step n".
	for boundary := 0; boundary <= len(Steps()); boundary++ {
		name := "before_any_step"
		if boundary > 0 {
			name = "after_" + Steps()[boundary-1].String()
		}
		t.Run(name, func(t *testing.T) {
			for _, how := range []string{"error", "panic"} {
				t.Run(how, func(t *testing.T) {
					store := newMemStore()
					runKilled(t, store, boundary, how)

					// The re-run is a fresh Sealer over the same store, the way
					// a restarted process would be.
					resumed := mustSeal(t, store, sealTestRecords())
					if resumed.SegmentID != reference.SegmentID {
						t.Errorf("after a kill at boundary %d the segment hash is %s, the no-crash run gives %s",
							boundary, resumed.SegmentID, reference.SegmentID)
					}
					if string(resumed.Object) != string(reference.Object) {
						t.Errorf("after a kill at boundary %d the object bytes differ from the no-crash run", boundary)
					}
					names := store.names()
					if len(names) != 1 || names[0] != reference.SegmentID {
						t.Errorf("store holds %v, want exactly [%s]", names, reference.SegmentID)
					}
					// And what is stored is what was sealed.
					stored, err := store.Get(reference.SegmentID)
					if err != nil {
						t.Fatalf("Get: %v", err)
					}
					if string(stored) != string(reference.Object) {
						t.Errorf("stored object differs from the sealed object")
					}
				})
			}
		})
	}
}

// runKilled runs a seal that is stopped at the given boundary. boundary 0 means
// the sealer never gets to run at all.
func runKilled(t *testing.T, store Store, boundary int, how string) {
	t.Helper()
	if boundary == 0 {
		return
	}
	killed := errors.New("killed")
	sealer := &Sealer{Store: store, AfterStep: func(s Step) error {
		if int(s) != boundary {
			return nil
		}
		if how == "panic" {
			// An abrupt kill: Seal's own error handling never runs.
			panic(killed)
		}
		return killed
	}}

	if how == "panic" {
		defer func() {
			r := recover()
			if r == nil {
				t.Errorf("the sealer was not killed at boundary %d", boundary)
			}
		}()
		if _, err := sealer.Seal(Request{Records: sealTestRecords()}); err != nil {
			t.Errorf("expected a panic at boundary %d, got error %v", boundary, err)
		}
		return
	}

	_, err := sealer.Seal(Request{Records: sealTestRecords()})
	if !errors.Is(err, killed) {
		t.Errorf("Seal aborted at boundary %d with %v, want the injected kill", boundary, err)
	}
}

// TestSEG002ResumeDoesNotRewrite proves the resume path is a resume and not a
// second write: the object is already there, and the store sees no further Put.
func TestSEG002ResumeDoesNotRewrite(t *testing.T) {
	store := newMemStore()
	first := mustSeal(t, store, sealTestRecords())
	if store.puts != 1 {
		t.Fatalf("first seal issued %d puts, want 1", store.puts)
	}

	second := mustSeal(t, store, sealTestRecords())
	if !second.Resumed {
		t.Error("a seal that found its object already stored does not report Resumed")
	}
	if store.puts != 1 {
		t.Errorf("the resumed seal issued %d puts in total, want 1", store.puts)
	}
	if second.SegmentID != first.SegmentID {
		t.Errorf("resumed segment id %s, first %s", second.SegmentID, first.SegmentID)
	}
}

// TestSEG002ResumeRefusesADifferentObject is the case where resuming would be
// wrong: something else already sits at the content address.
func TestSEG002ResumeRefusesADifferentObject(t *testing.T) {
	store := newMemStore()
	sealed := mustSeal(t, store, sealTestRecords())

	if err := store.tamper(sealed.SegmentID, func(b []byte) []byte {
		out := append([]byte(nil), b...)
		out[10] ^= 0xff
		return out
	}); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	sealer := &Sealer{Store: store}
	_, err := sealer.Seal(Request{Records: sealTestRecords()})
	var terr *TamperError
	if !errors.As(err, &terr) {
		t.Fatalf("Seal over a tampered object: error = %v, want a *TamperError", err)
	}
	if terr.SegmentID != sealed.SegmentID {
		t.Errorf("TamperError names %s, want %s", terr.SegmentID, sealed.SegmentID)
	}
}

// TestSealRefusesWhatItCannotSeal covers every refusal the sealer owns.
func TestSealRefusesWhatItCannotSeal(t *testing.T) {
	valid := sealTestRecords()

	cases := []struct {
		name    string
		sealer  *Sealer
		records []event.Fields
		want    error
	}{
		{"no store", &Sealer{}, valid, ErrNoStore},
		{"no records", &Sealer{Store: newMemStore()}, nil, ErrEmptySegment},
		{
			"non-consecutive positions",
			&Sealer{Store: newMemStore()},
			[]event.Fields{
				{event.FieldChainPosition: int64(1), event.EventHashField: seededDigests(2)[0]},
				{event.FieldChainPosition: int64(3), event.EventHashField: seededDigests(2)[1]},
			},
			ErrRange,
		},
		{
			"positions out of order",
			&Sealer{Store: newMemStore()},
			[]event.Fields{
				{event.FieldChainPosition: int64(2), event.EventHashField: seededDigests(2)[0]},
				{event.FieldChainPosition: int64(1), event.EventHashField: seededDigests(2)[1]},
			},
			ErrRange,
		},
		{
			"position below 1",
			&Sealer{Store: newMemStore()},
			[]event.Fields{{event.FieldChainPosition: int64(0), event.EventHashField: seededDigests(1)[0]}},
			ErrRange,
		},
		{
			"missing chain_position",
			&Sealer{Store: newMemStore()},
			[]event.Fields{{event.EventHashField: seededDigests(1)[0]}},
			ErrRange,
		},
		{
			"chain_position is not an integer",
			&Sealer{Store: newMemStore()},
			[]event.Fields{{event.FieldChainPosition: "1", event.EventHashField: seededDigests(1)[0]}},
			ErrRange,
		},
		{
			"missing event_hash",
			&Sealer{Store: newMemStore()},
			[]event.Fields{{event.FieldChainPosition: int64(1)}},
			ErrInvalidDigest,
		},
		{
			"event_hash is not a string",
			&Sealer{Store: newMemStore()},
			[]event.Fields{{event.FieldChainPosition: int64(1), event.EventHashField: 7}},
			ErrInvalidDigest,
		},
		{
			"event_hash is malformed",
			&Sealer{Store: newMemStore()},
			[]event.Fields{{event.FieldChainPosition: int64(1), event.EventHashField: "sha256:zz"}},
			ErrInvalidDigest,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.sealer.Seal(Request{Records: tc.records})
			if !errors.Is(err, tc.want) {
				t.Errorf("Seal error = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestSealSurfacesStoreFailures: the write and the read-back both have to be
// able to fail, and both have to say so.
func TestSealSurfacesStoreFailures(t *testing.T) {
	t.Run("put fails", func(t *testing.T) {
		store := &failingStore{memStore: newMemStore(), failPut: 1}
		sealer := &Sealer{Store: store}
		if _, err := sealer.Seal(Request{Records: sealTestRecords()}); !errors.Is(err, errStoreDown) {
			t.Errorf("Seal error = %v, want the store failure", err)
		}
	})
	t.Run("read-back fails", func(t *testing.T) {
		// Get 1 is the resume probe, Get 2 is the read-back after the write.
		store := &failingStore{memStore: newMemStore(), failGet: 2}
		sealer := &Sealer{Store: store}
		if _, err := sealer.Seal(Request{Records: sealTestRecords()}); !errors.Is(err, errStoreDown) {
			t.Errorf("Seal error = %v, want the store failure", err)
		}
	})
	t.Run("resume probe fails for a reason other than absence", func(t *testing.T) {
		store := &failingStore{memStore: newMemStore(), failGet: 1}
		sealer := &Sealer{Store: store}
		if _, err := sealer.Seal(Request{Records: sealTestRecords()}); !errors.Is(err, errStoreDown) {
			t.Errorf("Seal error = %v, want the store failure", err)
		}
	})
}

// TestSealedEventCarriesDoc02Section3 checks the segment_sealed body against
// the row in doc 02 §3, including that the anchoring members are absent: they
// arrive later, in a superseding event, and that is RM-012's work.
func TestSealedEventCarriesDoc02Section3(t *testing.T) {
	sealed := mustSeal(t, newMemStore(), sealTestRecords())

	const eventID = "01a047cf-dd00-7421-a65c-da3e8a0b98c0"
	ts, err := event.ParseTimestamp("2026-08-28T10:00:00.000Z")
	if err != nil {
		t.Fatalf("ParseTimestamp: %v", err)
	}
	body, err := sealed.Event(EventMeta{EventID: eventID, TS: ts})
	if err != nil {
		t.Fatalf("Event: %v", err)
	}

	want := event.Fields{
		event.FieldSchemaVersion:     event.SchemaVersion,
		event.FieldEventID:           eventID,
		event.FieldEventType:         event.EventTypeSegmentSealed,
		event.FieldTS:                "2026-08-28T10:00:00.000Z",
		event.FieldSource:            event.SourceSystem,
		event.FieldSegmentID:         sealed.SegmentID,
		event.FieldSegmentMerkleRoot: sealed.MerkleRoot,
		event.FieldFirstPosition:     int64(7),
		event.FieldLastPosition:      int64(17),
	}
	if len(body) != len(want) {
		t.Errorf("body has %d members, want %d:\n got  %v\n want %v", len(body), len(want), body, want)
	}
	for name, value := range want {
		if body[name] != value {
			t.Errorf("body[%q] = %v, want %v", name, body[name], value)
		}
	}
	for _, absent := range []string{
		event.FieldAnchorRekorLogIndex, event.FieldAnchorRekorEntryUUID,
		event.FieldRunID, event.FieldSpiffeID, event.FieldIdempotencyKey,
		event.FieldChainPosition, event.FieldPrevEventHash, event.EventHashField,
	} {
		if _, present := body[absent]; present {
			t.Errorf("body carries %s, which the sealer must not set", absent)
		}
	}

	// And it is an event the ledger would accept once it has stamped the three
	// members it assigns (doc 02 §2).
	record := body.Clone()
	record[event.FieldChainPosition] = sealed.LastPosition + 1
	record[event.FieldPrevEventHash] = event.GenesisPrevEventHash()
	if err := event.ValidateEvent(record); err != nil {
		t.Errorf("the sealed event is not appendable: %v", err)
	}
}

// TestSealedEventRefusesBadMetadata covers the event builder's error paths.
func TestSealedEventRefusesBadMetadata(t *testing.T) {
	sealed := mustSeal(t, newMemStore(), sealTestRecords())
	ts := event.NewTimestamp(time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC))

	cases := []struct {
		name string
		meta EventMeta
	}{
		{"no event_id", EventMeta{TS: ts}},
		{"event_id is not a uuidv7", EventMeta{EventID: "nope", TS: ts}},
		{"no ts", EventMeta{EventID: "01a047cf-dd00-7421-a65c-da3e8a0b98c0"}},
		{"unknown source", EventMeta{EventID: "01a047cf-dd00-7421-a65c-da3e8a0b98c0", TS: ts, Source: "cron"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := sealed.Event(tc.meta); err == nil {
				t.Error("Event accepted metadata it should have refused")
			}
		})
	}

	// An explicit source is honoured.
	body, err := sealed.Event(EventMeta{
		EventID: "01a047cf-dd00-7421-a65c-da3e8a0b98c0",
		TS:      ts,
		Source:  event.SourceReconciler,
	})
	if err != nil {
		t.Fatalf("Event: %v", err)
	}
	if body[event.FieldSource] != event.SourceReconciler {
		t.Errorf("source = %v, want %s", body[event.FieldSource], event.SourceReconciler)
	}
}

// TestSealedTreeIsTheSealedTree: the tree handed back proves inclusion for
// every event in the segment.
func TestSealedTreeIsTheSealedTree(t *testing.T) {
	records := sealTestRecords()
	sealed := mustSeal(t, newMemStore(), records)
	tree := sealed.Tree()
	if tree == nil {
		t.Fatal("Sealed.Tree() is nil")
	}
	if tree.Root() != sealed.MerkleRoot {
		t.Errorf("tree root %s, sealed root %s", tree.Root(), sealed.MerkleRoot)
	}
	if tree.Size() != len(records) {
		t.Fatalf("tree has %d leaves, segment has %d events", tree.Size(), len(records))
	}
	for i, record := range records {
		proof, err := tree.Proof(i)
		if err != nil {
			t.Fatalf("Proof(%d): %v", i, err)
		}
		digest, ok := record[event.EventHashField].(string)
		if !ok {
			t.Fatalf("record %d has no event_hash", i)
		}
		if err := VerifyProof(sealed.MerkleRoot, digest, proof); err != nil {
			t.Errorf("event at position %v does not prove into the sealed root: %v",
				record[event.FieldChainPosition], err)
		}
	}
}

// mustSeal seals with a plain Sealer and no injected failures.
func mustSeal(t *testing.T, store Store, records []event.Fields) *Sealed {
	t.Helper()
	sealer := &Sealer{Store: store}
	sealed, err := sealer.Seal(Request{Records: records})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if sealed == nil {
		t.Fatal("Seal returned no result and no error")
	}
	return sealed
}
