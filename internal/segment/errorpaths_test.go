// SPDX-License-Identifier: Apache-2.0

package segment

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"innsegl.dev/innsegl/internal/event"
)

// IP §2 puts a 100% branch floor on segment sealing. Go measures statements,
// not branches, so the gap has to be closed by hand: this file drives the
// error returns that the behavioural tests reach only on their happy side, so
// that every conditional in the package is taken in both directions.
//
// Two of them are unreachable while the rest of the package is correct — a hex
// decode after the digest grammar has already accepted the string, and an
// RFC 8785 serializer failing on a value domain it cannot fail on. Both sit
// behind a seam for exactly that reason, the same way internal/event guards
// jcs.Transform, and the two tests below are what make them reachable.

// TestDecodeLeafRejectsWhatTheGrammarLetThrough drives the decode failure under
// decodeLeaf by disabling the grammar check in front of it.
func TestDecodeLeafRejectsWhatTheGrammarLetThrough(t *testing.T) {
	original := validateDigest
	t.Cleanup(func() { validateDigest = original })
	validateDigest = func(string) error { return nil }

	// 64 characters, none of them hex.
	if _, err := Root([]string{event.HashPrefix + strings.Repeat("z", 64)}); !errors.Is(err, ErrInvalidDigest) {
		t.Errorf("Root error = %v, want ErrInvalidDigest", err)
	}
}

// TestCanonicalizerFailureIsReported drives every branch that propagates a
// canonical-serialization failure.
func TestCanonicalizerFailureIsReported(t *testing.T) {
	original := canonicalize
	t.Cleanup(func() { canonicalize = original })

	broken := errors.New("canonicalizer unavailable")
	canonicalize = func(any) ([]byte, error) { return nil, broken }

	object := Object{
		EventHashes:   seededDigests(3),
		FirstPosition: 1,
		LastPosition:  3,
		FormatVersion: ObjectFormatVersion,
		MerkleRoot:    seededDigests(1)[0],
	}
	if _, err := object.Encode(); !errors.Is(err, broken) {
		t.Errorf("Encode error = %v, want the canonicalizer failure", err)
	}
	if _, err := DecodeObject([]byte(`{"event_hashes":["` + seededDigests(1)[0] +
		`"],"first_position":1,"last_position":1,"segment_format_version":"1","segment_merkle_root":"` +
		seededDigests(1)[0] + `"}`)); !errors.Is(err, ErrObjectFormat) {
		t.Errorf("DecodeObject error = %v, want ErrObjectFormat", err)
	}
	sealer := &Sealer{Store: newMemStore()}
	if _, err := sealer.Seal(Request{Records: sealTestRecords()}); !errors.Is(err, broken) {
		t.Errorf("Seal error = %v, want the canonicalizer failure", err)
	}
}

// TestWriteAllPanicsOnAHashThatFails: crypto/sha256 never fails a write, so
// this drives the guard with something that does. A hash that silently drops
// data would produce a wrong root, which must never be a quiet outcome.
func TestWriteAllPanicsOnAHashThatFails(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("writeAll returned normally on a failing hash")
		}
	}()
	writeAll(brokenHash{}, []byte{0x00})
}

type brokenHash struct{}

func (brokenHash) Write([]byte) (int, error) { return 0, errors.New("hash unavailable") }

// TestVerifyProofRejectsAShortPathOnTheLeftSide covers the other side of the
// path-shape check: a leaf at an odd index takes its sibling from the left.
func TestVerifyProofRejectsAShortPathOnTheLeftSide(t *testing.T) {
	digests := seededDigests(7)
	tree, err := NewTree(digests)
	if err != nil {
		t.Fatalf("NewTree: %v", err)
	}
	proof, err := tree.Proof(3) // odd index: step 0's sibling is on the left
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}
	if err := VerifyProof(tree.Root(), digests[3], proof); err != nil {
		t.Fatalf("the honest proof must verify first: %v", err)
	}
	if proof.Path[0].SiblingIsRight {
		t.Fatalf("leaf 3's first sibling should be on the left")
	}

	forged := proof
	forged.Path = append([]ProofNode(nil), proof.Path...)
	forged.Path[0].SiblingIsRight = true
	if err := VerifyProof(tree.Root(), digests[3], forged); !errors.Is(err, ErrProofShape) {
		t.Errorf("error = %v, want ErrProofShape", err)
	}

	negative := proof
	negative.Index = -1
	if err := VerifyProof(tree.Root(), digests[3], negative); !errors.Is(err, ErrProofShape) {
		t.Errorf("error = %v, want ErrProofShape", err)
	}

	truncated := proof
	truncated.Path = nil
	if err := VerifyProof(tree.Root(), digests[3], truncated); !errors.Is(err, ErrProofShape) {
		t.Errorf("error = %v, want ErrProofShape", err)
	}
}

// TestObjectValidateCoversItsRemainingRefusals.
func TestObjectValidateCoversItsRemainingRefusals(t *testing.T) {
	t.Run("malformed merkle root", func(t *testing.T) {
		object := Object{
			EventHashes:   seededDigests(2),
			FirstPosition: 1,
			LastPosition:  2,
			FormatVersion: ObjectFormatVersion,
			MerkleRoot:    "not-a-digest",
		}
		if err := object.Validate(); !errors.Is(err, ErrInvalidDigest) {
			t.Errorf("Validate error = %v, want ErrInvalidDigest", err)
		}
	})
	t.Run("first position below 1", func(t *testing.T) {
		object := Object{
			EventHashes:   seededDigests(2),
			FirstPosition: 0,
			LastPosition:  1,
			FormatVersion: ObjectFormatVersion,
			MerkleRoot:    seededDigests(1)[0],
		}
		if err := object.Validate(); !errors.Is(err, ErrRange) {
			t.Errorf("Validate error = %v, want ErrRange", err)
		}
	})
}

// TestEncodeRefusesAnObjectThatCouldNeverBeStored: the content address of an
// invalid object would name something no reader will accept, so it is never
// computed in the first place.
func TestEncodeRefusesAnObjectThatCouldNeverBeStored(t *testing.T) {
	if _, err := (Object{}).Encode(); !errors.Is(err, ErrObjectFormat) {
		t.Errorf("Encode error = %v, want ErrObjectFormat", err)
	}
}

// TestDecodeObjectRejectsANonCanonicalEncodingOfAValidObject is the byte
// comparison itself: the object decodes, validates, and is still refused
// because these are not the bytes that object is written as.
func TestDecodeObjectRejectsANonCanonicalEncodingOfAValidObject(t *testing.T) {
	sealed := mustSeal(t, newMemStore(), sealTestRecords())

	// One space after the opening brace. Every member, value and ordering is
	// untouched, so it decodes to exactly the object that was sealed.
	spaced := append([]byte("{ "), sealed.Object[1:]...)
	object, err := DecodeObject(spaced)
	if !errors.Is(err, ErrObjectFormat) {
		t.Fatalf("DecodeObject error = %v, want ErrObjectFormat", err)
	}
	if object.MerkleRoot != "" {
		t.Errorf("a refused decode returned an object anyway: %+v", object)
	}
	// And the same bytes are refused through the read path, stored at their own
	// content address so that only the canonical-form check can catch them.
	store := newMemStore()
	if err := store.Put(digestOf(spaced), spaced); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := Open(store, digestOf(spaced)); !errors.Is(err, ErrObjectFormat) {
		t.Errorf("Open error = %v, want ErrObjectFormat", err)
	}
}

// TestVerifyAgainstRejectsUnreadableClaims covers the claim reader's type and
// absence branches.
func TestVerifyAgainstRejectsUnreadableClaims(t *testing.T) {
	store := newMemStore()
	sealed := mustSeal(t, store, sealTestRecords())
	seg, err := Open(store, sealed.SegmentID)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	body, err := sealed.Event(EventMeta{EventID: subjectEventID, TS: alertTS(t)})
	if err != nil {
		t.Fatalf("Event: %v", err)
	}
	if err := seg.VerifyAgainst(body); err != nil {
		t.Fatalf("the honest claim must verify first: %v", err)
	}

	edits := map[string]any{
		event.FieldEventType:         int64(1),
		event.FieldSegmentID:         int64(1),
		event.FieldSegmentMerkleRoot: int64(1),
		event.FieldFirstPosition:     "7",
		event.FieldLastPosition:      "17",
	}
	for name, value := range edits {
		t.Run(name+" has the wrong type", func(t *testing.T) {
			claim := body.Clone()
			claim[name] = value
			if err := seg.VerifyAgainst(claim); !errors.Is(err, ErrObjectMismatch) {
				t.Errorf("VerifyAgainst error = %v, want ErrObjectMismatch", err)
			}
		})
	}
	t.Run("claim has no event_type", func(t *testing.T) {
		claim := body.Clone()
		delete(claim, event.FieldEventType)
		if err := seg.VerifyAgainst(claim); !errors.Is(err, ErrObjectMismatch) {
			t.Errorf("VerifyAgainst error = %v, want ErrObjectMismatch", err)
		}
	})
}

// TestBoundReasonKeepsTheAlertRecordable: whatever the error message was, the
// alert has to be appendable, because a detection nobody can record is not a
// detection (I3).
func TestBoundReasonKeepsTheAlertRecordable(t *testing.T) {
	cases := map[string]error{
		"empty message":                      errors.New(""),
		"invalid utf-8":                      errors.New("segment \xff\xfe broke"),
		"multi-byte at the truncation point": errors.New(strings.Repeat("é", 400)),
		"exactly at the bound":               errors.New(strings.Repeat("a", event.MaxTextBytes)),
		"one over the bound":                 errors.New(strings.Repeat("a", event.MaxTextBytes+1)),
	}
	for name, cause := range cases {
		t.Run(name, func(t *testing.T) {
			body, err := DriftEvent(AlertMeta{
				EventID:        alertEventID,
				TS:             alertTS(t),
				SubjectEventID: subjectEventID,
			}, cause)
			if err != nil {
				t.Fatalf("DriftEvent: %v", err)
			}
			reason, ok := body[event.FieldReason].(string)
			if !ok {
				t.Fatalf("reason is %T, want string", body[event.FieldReason])
			}
			if reason == "" {
				t.Error("reason is empty; doc 02 §1 has no empty-string placeholders")
			}
			if len(reason) > event.MaxTextBytes {
				t.Errorf("reason is %d bytes, the schema allows %d", len(reason), event.MaxTextBytes)
			}
			if !utf8.ValidString(reason) {
				t.Error("reason is not valid UTF-8")
			}

			record := body.Clone()
			record[event.FieldChainPosition] = int64(99)
			record[event.FieldPrevEventHash] = event.GenesisPrevEventHash()
			if err := event.ValidateEvent(record); err != nil {
				t.Errorf("the alert is not appendable: %v", err)
			}
		})
	}
}

// TestSealedEventRefusesAHandBuiltSealed: Sealed is an exported struct with
// exported members, so a caller can build one that never came out of Seal. The
// body it would produce is not a valid event, and is refused rather than
// handed to the ledger.
func TestSealedEventRefusesAHandBuiltSealed(t *testing.T) {
	empty := &Sealed{}
	if _, err := empty.Event(EventMeta{EventID: subjectEventID, TS: alertTS(t)}); err == nil {
		t.Error("Event built a segment_sealed body from a Sealed with no segment in it")
	}
}

// TestPlanReadsAnIntegerPositionOfEitherWidth: a record that has been through a
// JSON round trip can carry an int where the ledger wrote an int64.
func TestPlanReadsAnIntegerPositionOfEitherWidth(t *testing.T) {
	digests := seededDigests(2)
	records := []event.Fields{
		{event.FieldChainPosition: 4, event.EventHashField: digests[0]},
		{event.FieldChainPosition: 5, event.EventHashField: digests[1]},
	}
	sealed := mustSeal(t, newMemStore(), records)
	if sealed.FirstPosition != 4 || sealed.LastPosition != 5 {
		t.Errorf("sealed range %d..%d, want 4..5", sealed.FirstPosition, sealed.LastPosition)
	}

	wide := []event.Fields{
		{event.FieldChainPosition: int64(4), event.EventHashField: digests[0]},
		{event.FieldChainPosition: int64(5), event.EventHashField: digests[1]},
	}
	same := mustSeal(t, newMemStore(), wide)
	if same.SegmentID != sealed.SegmentID {
		t.Errorf("an int and an int64 position sealed to %s and %s", sealed.SegmentID, same.SegmentID)
	}
}
