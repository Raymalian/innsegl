// SPDX-License-Identifier: Apache-2.0

package segment

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/event"
)

// SEG-006 — "Tamper with a sealed segment object in storage. Segment hash
// mismatch detected on read; alert-level event." (doc 07, invariant I4)
//
// The segment id IS the object's content address, so the ledger's own
// segment_sealed event carries everything a reader needs to detect the tamper:
// fetch the object the event names, hash it, and see that it is no longer the
// object that was named. Nothing outside the ledger has to be trusted for that.

const (
	alertEventID   = "01a047d0-57d2-7ebd-bd10-406ab171a29e"
	subjectEventID = "01a047cf-dd00-7421-a65c-da3e8a0b98c0"
)

func alertTS(t *testing.T) event.Timestamp {
	t.Helper()
	ts, err := event.ParseTimestamp("2026-08-28T10:00:31.442Z")
	if err != nil {
		t.Fatalf("ParseTimestamp: %v", err)
	}
	return ts
}

// TestSEG006TamperedObjectIsDetectedOnRead is the mismatch itself.
func TestSEG006TamperedObjectIsDetectedOnRead(t *testing.T) {
	// Every byte offset of the object gets its turn: a change anywhere in it
	// must be caught, not only one in the event hashes.
	reference := mustSeal(t, newMemStore(), sealTestRecords())
	for _, offset := range []int{0, 1, 17, len(reference.Object) / 2, len(reference.Object) - 2, len(reference.Object) - 1} {
		t.Run(fmt.Sprintf("offset_%d", offset), func(t *testing.T) {
			store := newMemStore()
			sealed := mustSeal(t, store, sealTestRecords())

			// Read cleanly first. A test whose only assertion is a failure can
			// pass against an implementation that fails everything.
			seg, err := Open(store, sealed.SegmentID)
			if err != nil {
				t.Fatalf("the untampered object must open: %v", err)
			}
			if seg.Object.MerkleRoot != sealed.MerkleRoot {
				t.Fatalf("opened root %s, sealed root %s", seg.Object.MerkleRoot, sealed.MerkleRoot)
			}

			if terr := store.tamper(sealed.SegmentID, func(b []byte) []byte {
				b[offset] ^= 0x20
				return b
			}); terr != nil {
				t.Fatalf("tamper: %v", terr)
			}

			_, err = Open(store, sealed.SegmentID)
			var terr *TamperError
			if !errors.As(err, &terr) {
				t.Fatalf("Open of a tampered object: error = %v, want a *TamperError", err)
			}
			if terr.SegmentID != sealed.SegmentID {
				t.Errorf("TamperError names segment %s, want %s", terr.SegmentID, sealed.SegmentID)
			}
			if terr.Want != sealed.SegmentID {
				t.Errorf("TamperError wants %s, want the segment id %s", terr.Want, sealed.SegmentID)
			}
			stored, gerr := store.Get(sealed.SegmentID)
			if gerr != nil {
				t.Fatalf("Get: %v", gerr)
			}
			if terr.Got != digestOf(stored) {
				t.Errorf("TamperError got %s, the tampered bytes hash to %s", terr.Got, digestOf(stored))
			}
			if !strings.Contains(terr.Error(), sealed.SegmentID) {
				t.Errorf("TamperError message %q does not name the segment", terr.Error())
			}
		})
	}
}

// TestSEG006TamperRaisesAnAlertLevelEvent is the second half of SEG-006: the
// mismatch becomes a record, because a detection nobody can read afterwards is
// not a detection (I3).
func TestSEG006TamperRaisesAnAlertLevelEvent(t *testing.T) {
	store := newMemStore()
	sealed := mustSeal(t, store, sealTestRecords())
	if err := store.tamper(sealed.SegmentID, func(b []byte) []byte {
		b[len(b)-3] ^= 0x01
		return b
	}); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	_, cause := Open(store, sealed.SegmentID)
	if cause == nil {
		t.Fatal("the tampered object opened cleanly")
	}

	body, err := DriftEvent(AlertMeta{
		EventID:        alertEventID,
		TS:             alertTS(t),
		SubjectEventID: subjectEventID,
	}, cause)
	if err != nil {
		t.Fatalf("DriftEvent: %v", err)
	}

	if body[event.FieldEventType] != event.EventTypeLedgerDriftDetected {
		t.Errorf("event_type = %v, want %s", body[event.FieldEventType], event.EventTypeLedgerDriftDetected)
	}
	if body[event.FieldSubjectEventID] != subjectEventID {
		t.Errorf("subject_event_id = %v, want %s", body[event.FieldSubjectEventID], subjectEventID)
	}
	if body[event.FieldSource] != event.SourceReconciler {
		t.Errorf("source = %v, want %s by default (doc 02 §3)", body[event.FieldSource], event.SourceReconciler)
	}
	reason, ok := body[event.FieldReason].(string)
	if !ok || reason == "" {
		t.Fatalf("reason = %v, want a description of the drift", body[event.FieldReason])
	}
	if !strings.Contains(reason, sealed.SegmentID) {
		t.Errorf("reason %q does not name the segment that failed", reason)
	}
	for _, absent := range []string{event.FieldRunID, event.FieldSpiffeID, event.FieldChainPosition} {
		if _, present := body[absent]; present {
			t.Errorf("the alert carries %s; it references no run and the ledger assigns the position", absent)
		}
	}

	record := body.Clone()
	record[event.FieldChainPosition] = int64(99)
	record[event.FieldPrevEventHash] = event.GenesisPrevEventHash()
	if err := event.ValidateEvent(record); err != nil {
		t.Errorf("the alert is not appendable: %v", err)
	}
}

// TestDriftEventBoundsItsReason: an alert must stay appendable however long
// the underlying error message is (doc 02 §5's bound on `reason`).
func TestDriftEventBoundsItsReason(t *testing.T) {
	long := errors.New(strings.Repeat("drift ", 400))
	body, err := DriftEvent(AlertMeta{
		EventID:        alertEventID,
		TS:             alertTS(t),
		SubjectEventID: subjectEventID,
	}, long)
	if err != nil {
		t.Fatalf("DriftEvent: %v", err)
	}
	reason, ok := body[event.FieldReason].(string)
	if !ok {
		t.Fatalf("reason is %T, want string", body[event.FieldReason])
	}
	if len(reason) > event.MaxTextBytes {
		t.Errorf("reason is %d bytes, the schema allows %d", len(reason), event.MaxTextBytes)
	}
	if !strings.HasSuffix(reason, truncationMarker) {
		t.Errorf("a truncated reason must say so; got %q", reason[max(0, len(reason)-40):])
	}

	record := body.Clone()
	record[event.FieldChainPosition] = int64(99)
	record[event.FieldPrevEventHash] = event.GenesisPrevEventHash()
	if err := event.ValidateEvent(record); err != nil {
		t.Errorf("the truncated alert is not appendable: %v", err)
	}
}

// TestDriftEventRefusesBadMetadata covers the alert builder's error paths.
func TestDriftEventRefusesBadMetadata(t *testing.T) {
	ts := alertTS(t)
	cause := errors.New("something drifted")
	cases := []struct {
		name string
		meta AlertMeta
		err  error
	}{
		{"no event_id", AlertMeta{TS: ts, SubjectEventID: subjectEventID}, cause},
		{"bad event_id", AlertMeta{EventID: "x", TS: ts, SubjectEventID: subjectEventID}, cause},
		{"no subject", AlertMeta{EventID: alertEventID, TS: ts}, cause},
		{"bad subject", AlertMeta{EventID: alertEventID, TS: ts, SubjectEventID: "x"}, cause},
		{"no ts", AlertMeta{EventID: alertEventID, SubjectEventID: subjectEventID}, cause},
		{"bad source", AlertMeta{EventID: alertEventID, TS: ts, SubjectEventID: subjectEventID, Source: "cron"}, cause},
		{"no cause", AlertMeta{EventID: alertEventID, TS: ts, SubjectEventID: subjectEventID}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DriftEvent(tc.meta, tc.err); err == nil {
				t.Error("DriftEvent accepted metadata it should have refused")
			}
		})
	}
}

// TestSEG006InconsistentObjectIsDetected is the second line of defence: an
// object that hashes to the id it is stored under, but whose recorded root is
// not the root of its own leaves. Content addressing alone cannot see this —
// the object is exactly what its address says it is — so the root is re-derived
// on every read.
func TestSEG006InconsistentObjectIsDetected(t *testing.T) {
	honest, err := Root(seededDigests(5))
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	obj := Object{
		EventHashes:   seededDigests(5),
		FirstPosition: 1,
		LastPosition:  5,
		FormatVersion: ObjectFormatVersion,
		MerkleRoot:    seededDigests(1)[0], // a well-formed digest, and not the root
	}
	if obj.MerkleRoot == honest {
		t.Fatal("the planted root is the honest one; the test would prove nothing")
	}
	raw, err := obj.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	store := newMemStore()
	name := digestOf(raw)
	if perr := store.Put(name, raw); perr != nil {
		t.Fatalf("Put: %v", perr)
	}

	_, err = Open(store, name)
	var terr *TamperError
	if !errors.As(err, &terr) {
		t.Fatalf("Open of an internally inconsistent object: error = %v, want a *TamperError", err)
	}
	if terr.Want != obj.MerkleRoot || terr.Got != honest {
		t.Errorf("TamperError reports want=%s got=%s, expected want=%s got=%s",
			terr.Want, terr.Got, obj.MerkleRoot, honest)
	}
}

// TestOpenRefusesWhatIsNotASegment covers the read path's other refusals.
func TestOpenRefusesWhatIsNotASegment(t *testing.T) {
	store := newMemStore()
	sealed := mustSeal(t, store, sealTestRecords())

	t.Run("missing", func(t *testing.T) {
		if _, err := Open(store, seededDigests(1)[0]); !errors.Is(err, ErrObjectNotFound) {
			t.Errorf("error = %v, want ErrObjectNotFound", err)
		}
	})
	t.Run("id is not a digest", func(t *testing.T) {
		if _, err := Open(store, "seg-000001"); !errors.Is(err, ErrSegmentIDShape) {
			t.Errorf("error = %v, want ErrSegmentIDShape", err)
		}
	})
	t.Run("no store", func(t *testing.T) {
		if _, err := Open(nil, sealed.SegmentID); !errors.Is(err, ErrNoStore) {
			t.Errorf("error = %v, want ErrNoStore", err)
		}
	})

	notCanonical := map[string][]byte{
		"not json":       []byte("{"),
		"not an object":  []byte("[]"),
		"unknown member": []byte(`{"event_hashes":[],"first_position":1,"last_position":1,"segment_format_version":"1","segment_merkle_root":"x","surprise":1}`),
		"members out of order": []byte(`{"segment_merkle_root":"` + sealed.MerkleRoot +
			`","event_hashes":[],"first_position":1,"last_position":1,"segment_format_version":"1"}`),
		"whitespace": []byte(`{ "event_hashes":[],"first_position":1,"last_position":1,"segment_format_version":"1","segment_merkle_root":"x" }`),
	}
	for name, raw := range notCanonical {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeObject(raw); !errors.Is(err, ErrObjectFormat) {
				t.Errorf("DecodeObject error = %v, want ErrObjectFormat", err)
			}
			id := digestOf(raw)
			if err := store.Put(id, raw); err != nil {
				t.Fatalf("Put: %v", err)
			}
			if _, err := Open(store, id); !errors.Is(err, ErrObjectFormat) {
				t.Errorf("Open error = %v, want ErrObjectFormat", err)
			}
		})
	}

	t.Run("empty segment object", func(t *testing.T) {
		obj := Object{
			EventHashes:   nil,
			FirstPosition: 1,
			LastPosition:  1,
			FormatVersion: ObjectFormatVersion,
			MerkleRoot:    sealed.MerkleRoot,
		}
		if err := obj.Validate(); !errors.Is(err, ErrEmptySegment) {
			t.Errorf("Validate error = %v, want ErrEmptySegment", err)
		}
	})
	t.Run("range disagrees with the leaf count", func(t *testing.T) {
		obj := Object{
			EventHashes:   seededDigests(5),
			FirstPosition: 1,
			LastPosition:  9,
			FormatVersion: ObjectFormatVersion,
			MerkleRoot:    sealed.MerkleRoot,
		}
		if err := obj.Validate(); !errors.Is(err, ErrRange) {
			t.Errorf("Validate error = %v, want ErrRange", err)
		}
	})
	t.Run("unknown object format version", func(t *testing.T) {
		obj := Object{
			EventHashes:   seededDigests(5),
			FirstPosition: 1,
			LastPosition:  5,
			FormatVersion: "2",
			MerkleRoot:    sealed.MerkleRoot,
		}
		if err := obj.Validate(); !errors.Is(err, ErrObjectFormat) {
			t.Errorf("Validate error = %v, want ErrObjectFormat", err)
		}
	})
	t.Run("malformed leaf digest", func(t *testing.T) {
		obj := Object{
			EventHashes:   []string{"sha256:zz"},
			FirstPosition: 1,
			LastPosition:  1,
			FormatVersion: ObjectFormatVersion,
			MerkleRoot:    sealed.MerkleRoot,
		}
		if err := obj.Validate(); !errors.Is(err, ErrInvalidDigest) {
			t.Errorf("Validate error = %v, want ErrInvalidDigest", err)
		}
	})
}

// TestSegmentVerifyAgainstTheLedgerClaim closes the loop: the object in storage
// and the segment_sealed event in the ledger have to agree, member for member.
func TestSegmentVerifyAgainstTheLedgerClaim(t *testing.T) {
	store := newMemStore()
	sealed := mustSeal(t, store, sealTestRecords())
	body, err := sealed.Event(EventMeta{EventID: subjectEventID, TS: alertTS(t)})
	if err != nil {
		t.Fatalf("Event: %v", err)
	}
	seg, err := Open(store, sealed.SegmentID)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := seg.VerifyAgainst(body); err != nil {
		t.Fatalf("the object and the event it was sealed with must agree: %v", err)
	}

	edits := map[string]any{
		event.FieldSegmentID:         seededDigests(1)[0],
		event.FieldSegmentMerkleRoot: seededDigests(2)[1],
		event.FieldFirstPosition:     int64(1),
		event.FieldLastPosition:      int64(99),
	}
	for name, value := range edits {
		t.Run("claims a different "+name, func(t *testing.T) {
			claim := body.Clone()
			claim[name] = value
			if err := seg.VerifyAgainst(claim); !errors.Is(err, ErrObjectMismatch) {
				t.Errorf("VerifyAgainst error = %v, want ErrObjectMismatch", err)
			}
		})
	}
	for _, name := range []string{
		event.FieldSegmentID, event.FieldSegmentMerkleRoot,
		event.FieldFirstPosition, event.FieldLastPosition,
	} {
		t.Run("claim is missing "+name, func(t *testing.T) {
			claim := body.Clone()
			delete(claim, name)
			if err := seg.VerifyAgainst(claim); !errors.Is(err, ErrObjectMismatch) {
				t.Errorf("VerifyAgainst error = %v, want ErrObjectMismatch", err)
			}
		})
	}
	t.Run("claim is not a segment_sealed event", func(t *testing.T) {
		claim := body.Clone()
		claim[event.FieldEventType] = event.EventTypeToolCall
		if err := seg.VerifyAgainst(claim); !errors.Is(err, ErrObjectMismatch) {
			t.Errorf("VerifyAgainst error = %v, want ErrObjectMismatch", err)
		}
	})
}

// TestSegmentProofByPosition: a reader with the object and a chain position can
// prove that event was in the segment.
func TestSegmentProofByPosition(t *testing.T) {
	store := newMemStore()
	sealed := mustSeal(t, store, sealTestRecords())
	seg, err := Open(store, sealed.SegmentID)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if seg.Tree() == nil {
		t.Fatal("Segment.Tree() is nil")
	}
	digests := seededDigests(11)
	for i, position := range []int64{7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17} {
		proof, perr := seg.ProofForPosition(position)
		if perr != nil {
			t.Fatalf("ProofForPosition(%d): %v", position, perr)
		}
		if err := VerifyProof(sealed.MerkleRoot, digests[i], proof); err != nil {
			t.Errorf("position %d does not prove into the root: %v", position, err)
		}
	}
	for _, outside := range []int64{6, 18, 0, -1} {
		if _, err := seg.ProofForPosition(outside); !errors.Is(err, ErrLeafOutOfRange) {
			t.Errorf("ProofForPosition(%d) error = %v, want ErrLeafOutOfRange", outside, err)
		}
	}
}
