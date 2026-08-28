// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"testing"

	"innsegl.dev/innsegl/internal/event"
)

// testEventID renders a lowercase UUIDv7 for n. Only the shape matters here:
// the chain is type-agnostic and never reads an event_id except to carry it
// into a correction's supersedes.
func testEventID(n int) string {
	return fmt.Sprintf("01a047a5-cc41-7c45-86fd-%012x", n)
}

// testBody returns an event body: everything the caller supplies, and none of
// the three members the ledger assigns (chain_position, prev_event_hash,
// event_hash).
func testBody(n int) event.Fields {
	return event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventID:        testEventID(n),
		event.FieldEventType:      "tool_call",
		event.FieldTS:             "2026-08-28T09:14:03.201Z",
		event.FieldRunID:          "run-42",
		event.FieldSpiffeID:       "spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42",
		event.FieldSource:         event.SourceMCP,
		event.FieldIdempotencyKey: fmt.Sprintf("idem-%d", n),
		"tool_name":               "git-commit",
	}
}

// appendChain appends n events and returns the records and the resulting head.
func appendChain(t *testing.T, n int) ([]event.Fields, Head) {
	t.Helper()
	var (
		head    Head
		records []event.Fields
	)
	for i := 1; i <= n; i++ {
		rec, next, err := Append(head, testBody(i))
		if err != nil {
			t.Fatalf("Append #%d: %v", i, err)
		}
		records = append(records, rec)
		head = next
	}
	if len(records) != n || head.Position != int64(n) {
		t.Fatalf("built %d records ending at position %d, want %d of each",
			len(records), head.Position, n)
	}
	return records, head
}

// memberString reads a string member, failing rather than panicking.
func memberString(t *testing.T, f event.Fields, name string) string {
	t.Helper()
	v, ok := f[name].(string)
	if !ok {
		t.Fatalf("member %q is %T, want string", name, f[name])
	}
	return v
}

// canonicalBytes is the byte-for-byte record used by the "original untouched"
// assertions. It is the same serialization a verifier re-derives.
func canonicalBytes(t *testing.T, f event.Fields) []byte {
	t.Helper()
	b, err := event.Canonicalize(f)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	return b
}

// TestLED001AppendSingleEvent is LED-001: a single append lands at
// chain_position 1, carries the genesis constant as prev_event_hash, and its
// event_hash is the digest of its own canonical preimage (doc 02 §4.3, §4.4).
func TestLED001AppendSingleEvent(t *testing.T) {
	body := testBody(1)
	before := maps.Clone(body)

	rec, head, err := Append(Head{}, body)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	if got := rec[event.FieldChainPosition]; got != int64(1) {
		t.Errorf("%s = %#v, want int64(1)", event.FieldChainPosition, got)
	}
	if got, want := memberString(t, rec, event.FieldPrevEventHash), event.GenesisPrevEventHash(); got != want {
		t.Errorf("%s = %s, want the genesis constant %s", event.FieldPrevEventHash, got, want)
	}

	// event_hash derived independently of Append: canonicalize the record
	// without event_hash and digest those bytes (doc 02 §4.1-4.3).
	preimage := rec.Clone()
	delete(preimage, event.EventHashField)
	want := event.Digest(canonicalBytes(t, preimage))
	if got := memberString(t, rec, event.EventHashField); got != want {
		t.Errorf("%s = %s, want %s", event.EventHashField, got, want)
	}
	if err := rec.Verify(); err != nil {
		t.Errorf("record does not verify against its own preimage: %v", err)
	}

	if head.Position != 1 || head.EventHash != want {
		t.Errorf("head = %+v, want {Position:1 EventHash:%s}", head, want)
	}
	if !reflect.DeepEqual(map[string]any(before), map[string]any(body)) {
		t.Errorf("Append mutated the caller's body\n before %#v\n after  %#v", before, body)
	}
}

// TestLED002AppendNSequentially is LED-002: N appends produce strictly
// consecutive positions and every prev_event_hash is the predecessor's
// event_hash (doc 02 §4.5).
func TestLED002AppendNSequentially(t *testing.T) {
	const n = 25
	records, head := appendChain(t, n)

	if len(records) != n {
		t.Fatalf("appended %d records, want %d", len(records), n)
	}
	for i, rec := range records {
		wantPos := int64(i + 1)
		if got := rec[event.FieldChainPosition]; got != wantPos {
			t.Errorf("record %d: %s = %#v, want int64(%d)", i, event.FieldChainPosition, got, wantPos)
		}
		wantPrev := event.GenesisPrevEventHash()
		if i > 0 {
			wantPrev = memberString(t, records[i-1], event.EventHashField)
		}
		if got := memberString(t, rec, event.FieldPrevEventHash); got != wantPrev {
			t.Errorf("record %d: %s = %s, want %s", i, event.FieldPrevEventHash, got, wantPrev)
		}
		if err := rec.Verify(); err != nil {
			t.Errorf("record %d does not verify: %v", i, err)
		}
	}

	got, err := Verify(records)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != head {
		t.Errorf("Verify head = %+v, want %+v", got, head)
	}
	if err := VerifyTip(records, head); err != nil {
		t.Errorf("VerifyTip: %v", err)
	}
}

// TestLED004Correction is LED-004: a correction is a new event carrying
// supersedes, and the superseded event is untouched byte-for-byte (I4).
func TestLED004Correction(t *testing.T) {
	records, head := appendChain(t, 3)
	original := records[0]
	originalBytes := canonicalBytes(t, original)
	originalCopy := maps.Clone(original)

	correction, next, err := Correct(head, original, testBody(99))
	if err != nil {
		t.Fatalf("Correct: %v", err)
	}

	wantSupersedes := memberString(t, original, event.FieldEventID)
	if got := memberString(t, correction, event.FieldSupersedes); got != wantSupersedes {
		t.Errorf("%s = %s, want %s", event.FieldSupersedes, got, wantSupersedes)
	}
	if got := correction[event.FieldChainPosition]; got != int64(4) {
		t.Errorf("correction %s = %#v, want int64(4)", event.FieldChainPosition, got)
	}

	// The original is untouched: same members, same canonical bytes, still
	// verifying against its own preimage.
	if !reflect.DeepEqual(map[string]any(originalCopy), map[string]any(original)) {
		t.Errorf("the superseded event was mutated\n before %#v\n after  %#v", originalCopy, original)
	}
	if got := canonicalBytes(t, original); !bytes.Equal(originalBytes, got) {
		t.Errorf("the superseded event's canonical bytes changed\n before %s\n after  %s", originalBytes, got)
	}
	if err := original.Verify(); err != nil {
		t.Errorf("the superseded event no longer verifies: %v", err)
	}

	// The correction is an append: nothing was removed, and the chain with it
	// still verifies end to end.
	full := append(append([]event.Fields{}, records...), correction)
	if len(full) != 4 {
		t.Fatalf("chain has %d records after a correction, want 4", len(full))
	}
	if err := VerifyTip(full, next); err != nil {
		t.Errorf("VerifyTip after correction: %v", err)
	}
}

// TestLED004CorrectionRejectsBadOriginal covers the error branches of Correct.
func TestLED004CorrectionRejectsBadOriginal(t *testing.T) {
	records, head := appendChain(t, 1)
	original := records[0]

	noID := original.Clone()
	delete(noID, event.FieldEventID)

	wrongType := original.Clone()
	wrongType[event.FieldEventID] = int64(7)

	badID := original.Clone()
	badID[event.FieldEventID] = "not-a-uuid"

	withSupersedes := testBody(2)
	withSupersedes[event.FieldSupersedes] = testEventID(1)

	tests := []struct {
		name     string
		original event.Fields
		body     event.Fields
		want     error
	}{
		{"missing event_id", noID, testBody(2), ErrMissingMember},
		{"event_id wrong type", wrongType, testBody(2), ErrMemberType},
		{"event_id not a uuidv7", badID, testBody(2), event.ErrInvalidEventID},
		{"body already supersedes", original, withSupersedes, ErrSupersedesPresent},
		{"body carries an assigned member", original, original, ErrLedgerAssignedMember},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := Correct(head, tc.original, tc.body); !errors.Is(err, tc.want) {
				t.Fatalf("Correct error = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestAppendRejectsLedgerAssignedMembers: the three members the ledger assigns
// are never caller input. doc 02 §2 assigns chain_position and prev_event_hash
// "by the ledger under serialized append"; event_hash is derived, never given.
func TestAppendRejectsLedgerAssignedMembers(t *testing.T) {
	for _, name := range []string{
		event.FieldChainPosition, event.FieldPrevEventHash, event.EventHashField,
	} {
		t.Run(name, func(t *testing.T) {
			body := testBody(1)
			if name == event.FieldChainPosition {
				body[name] = int64(1)
			} else {
				body[name] = event.GenesisPrevEventHash()
			}
			_, _, err := Append(Head{}, body)
			if !errors.Is(err, ErrLedgerAssignedMember) {
				t.Fatalf("Append error = %v, want %v", err, ErrLedgerAssignedMember)
			}
		})
	}
}

// TestAppendRejectsInvalidHead covers every invalid Head shape.
func TestAppendRejectsInvalidHead(t *testing.T) {
	tests := []struct {
		name string
		head Head
	}{
		{"negative position", Head{Position: -1}},
		{"empty position with a hash", Head{Position: 0, EventHash: event.GenesisPrevEventHash()}},
		{"position without a hash", Head{Position: 1}},
		{"position with a malformed hash", Head{Position: 1, EventHash: "sha256:nope"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := Append(tc.head, testBody(1)); !errors.Is(err, ErrInvalidHead) {
				t.Fatalf("Append error = %v, want %v", err, ErrInvalidHead)
			}
		})
	}
}

// TestAppendRejectsUnhashableBody: a body outside the canonical value domain
// cannot be hashed, so it cannot be appended.
func TestAppendRejectsUnhashableBody(t *testing.T) {
	body := testBody(1)
	body["broken"] = 1.5
	if _, _, err := Append(Head{}, body); !errors.Is(err, event.ErrUnsupportedType) {
		t.Fatalf("Append error = %v, want %v", err, event.ErrUnsupportedType)
	}
}

// TestAppendContinuesFromAHead: appending onto a non-empty head links to it.
func TestAppendContinuesFromAHead(t *testing.T) {
	records, head := appendChain(t, 2)
	rec, next, err := Append(head, testBody(3))
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if got := memberString(t, rec, event.FieldPrevEventHash); got != memberString(t, records[1], event.EventHashField) {
		t.Errorf("prev_event_hash = %s, want the previous event_hash", got)
	}
	if next.Position != 3 {
		t.Errorf("head position = %d, want 3", next.Position)
	}
}

// TestHeadNext pins the genesis rule (doc 02 §4.4) and the successor rule.
func TestHeadNext(t *testing.T) {
	pos, prev := Head{}.Next()
	if pos != 1 || prev != event.GenesisPrevEventHash() {
		t.Errorf("Head{}.Next() = (%d, %s), want (1, %s)", pos, prev, event.GenesisPrevEventHash())
	}
	if !(Head{}).IsEmpty() {
		t.Error("Head{}.IsEmpty() = false, want true")
	}

	h := Head{Position: 7, EventHash: event.GenesisPrevEventHash()}
	pos, prev = h.Next()
	if pos != 8 || prev != h.EventHash {
		t.Errorf("Next() = (%d, %s), want (8, %s)", pos, prev, h.EventHash)
	}
	if h.IsEmpty() {
		t.Error("a head at position 7 reports IsEmpty")
	}
}

// TestRecordHead covers every branch of reading a head off a record.
func TestRecordHead(t *testing.T) {
	records, _ := appendChain(t, 1)
	good := records[0]

	drop := func(name string) event.Fields {
		f := good.Clone()
		delete(f, name)
		return f
	}
	set := func(name string, v any) event.Fields {
		f := good.Clone()
		f[name] = v
		return f
	}

	tests := []struct {
		name   string
		record event.Fields
		want   error
	}{
		{"missing chain_position", drop(event.FieldChainPosition), ErrMissingMember},
		{"chain_position wrong type", set(event.FieldChainPosition, "1"), ErrMemberType},
		{"chain_position below one", set(event.FieldChainPosition, int64(0)), ErrInvalidHead},
		{"missing event_hash", drop(event.EventHashField), ErrMissingMember},
		{"event_hash wrong type", set(event.EventHashField, int64(1)), ErrMemberType},
		{"event_hash malformed", set(event.EventHashField, "sha256:nope"), event.ErrInvalidDigest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := RecordHead(tc.record); !errors.Is(err, tc.want) {
				t.Fatalf("RecordHead error = %v, want %v", err, tc.want)
			}
		})
	}

	head, err := RecordHead(good)
	if err != nil {
		t.Fatalf("RecordHead: %v", err)
	}
	if head.Position != 1 || head.EventHash != memberString(t, good, event.EventHashField) {
		t.Errorf("RecordHead = %+v, want the record's position and event_hash", head)
	}
}

// TestVerifyWalksToTheFirstMismatch covers each way a walk can fail, and the
// position it reports (doc 02 §4.5).
func TestVerifyWalksToTheFirstMismatch(t *testing.T) {
	records, _ := appendChain(t, 4)

	corrupt := func(i int, name string, v any) []event.Fields {
		out := make([]event.Fields, len(records))
		copy(out, records)
		f := records[i].Clone()
		if v == nil {
			delete(f, name)
		} else {
			f[name] = v
		}
		out[i] = f
		return out
	}

	tests := []struct {
		name     string
		records  []event.Fields
		wantPos  int64
		wantErrs []error
	}{
		{
			"position skipped",
			corrupt(2, event.FieldChainPosition, int64(9)),
			3, []error{ErrPositionMismatch},
		},
		{
			"prev_event_hash missing",
			corrupt(2, event.FieldPrevEventHash, nil),
			3, []error{ErrMissingMember},
		},
		{
			"prev_event_hash wrong type",
			corrupt(2, event.FieldPrevEventHash, int64(3)),
			3, []error{ErrMemberType},
		},
		{
			"prev_event_hash relinked",
			corrupt(2, event.FieldPrevEventHash, event.GenesisPrevEventHash()),
			3, []error{ErrPrevHashMismatch},
		},
		{
			"event_hash rewritten",
			corrupt(3, event.EventHashField, event.GenesisPrevEventHash()),
			4, []error{event.ErrEventHashMismatch},
		},
		{
			"record unreadable",
			corrupt(1, event.FieldChainPosition, nil),
			2, []error{ErrMissingMember},
		},
		{
			"member tampered",
			corrupt(0, "tool_name", "rm -rf"),
			1, []error{event.ErrEventHashMismatch},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Verify(tc.records)
			if err == nil {
				t.Fatalf("Verify succeeded on a broken chain")
			}
			var verr *VerificationError
			if !errors.As(err, &verr) {
				t.Fatalf("error %v is not a *VerificationError", err)
			}
			if verr.Position != tc.wantPos {
				t.Errorf("failed at position %d, want %d", verr.Position, tc.wantPos)
			}
			for _, want := range tc.wantErrs {
				if !errors.Is(err, want) {
					t.Errorf("error %v does not wrap %v", err, want)
				}
			}
			if verr.Error() == "" {
				t.Error("VerificationError.Error() is empty")
			}
			if errors.Unwrap(verr) == nil {
				t.Error("VerificationError.Unwrap() is nil")
			}
		})
	}
}

// TestVerifyFromRejectsAnInvalidStart: a walk cannot begin from a head that
// could never have existed.
func TestVerifyFromRejectsAnInvalidStart(t *testing.T) {
	records, _ := appendChain(t, 1)
	if _, err := VerifyFrom(Head{Position: 4}, records); !errors.Is(err, ErrInvalidHead) {
		t.Fatalf("VerifyFrom error = %v, want %v", err, ErrInvalidHead)
	}
}

// TestVerifyFromMidChain: a segment verifies against the head it follows.
func TestVerifyFromMidChain(t *testing.T) {
	records, head := appendChain(t, 5)
	start, err := RecordHead(records[1])
	if err != nil {
		t.Fatalf("RecordHead: %v", err)
	}
	got, err := VerifyFrom(start, records[2:])
	if err != nil {
		t.Fatalf("VerifyFrom: %v", err)
	}
	if got != head {
		t.Errorf("VerifyFrom head = %+v, want %+v", got, head)
	}
}

// TestVerifyEmptyChain: no events is a chain that vacuously verifies, and its
// tip is the empty head.
func TestVerifyEmptyChain(t *testing.T) {
	head, err := Verify(nil)
	if err != nil {
		t.Fatalf("Verify(nil): %v", err)
	}
	if !head.IsEmpty() {
		t.Errorf("Verify(nil) head = %+v, want the empty head", head)
	}
	if err := VerifyTip(nil, Head{}); err != nil {
		t.Errorf("VerifyTip(nil, Head{}): %v", err)
	}
}

// TestVerifyTipDetectsTruncation: a walk alone cannot see a chain that has had
// its tail removed, because a prefix of a valid chain is a valid chain. The
// expected tip is what makes truncation visible (doc 02 §4.5 walks 1..n; n
// itself has to come from outside the records).
func TestVerifyTipDetectsTruncation(t *testing.T) {
	records, head := appendChain(t, 4)

	if _, err := Verify(records[:3]); err != nil {
		t.Fatalf("a truncated chain still walks green, as expected: %v", err)
	}
	err := VerifyTip(records[:3], head)
	if !errors.Is(err, ErrTipMismatch) {
		t.Fatalf("VerifyTip error = %v, want %v", err, ErrTipMismatch)
	}

	// A broken chain fails the walk before the tip is ever compared.
	broken := make([]event.Fields, len(records))
	copy(broken, records)
	f := records[1].Clone()
	f["tool_name"] = "tampered"
	broken[1] = f
	if err := VerifyTip(broken, head); !errors.Is(err, event.ErrEventHashMismatch) {
		t.Fatalf("VerifyTip error = %v, want %v", err, event.ErrEventHashMismatch)
	}
}
