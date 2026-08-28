// SPDX-License-Identifier: Apache-2.0

package segment

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"innsegl.dev/innsegl/internal/event"
)

// The sealed segment object.
//
// Doc 02 fixes the Merkle construction (§4.6) and the members the ledger
// records about a sealed segment (§3). It does not fix the bytes of the object
// those members describe — IP §1 says only that segments are content-addressed
// and written to object storage under WORM. This file is that format, and
// ADR-0006 records why it looks like this:
//
//   - It is serialized with the same RFC 8785 canonicalizer as events, so
//     there is one canonical form in the system rather than two.
//   - Its content address — SHA-256 of those canonical bytes, rendered the way
//     every other digest is — is the segment's `segment_id`. The ledger's
//     segment_sealed event therefore names the object cryptographically, and a
//     reader with nothing but the ledger can detect a tampered object (SEG-006).
//   - It carries the leaves, so a third party can re-derive the root and prove
//     any event's inclusion without asking this system for anything (I5).
const (
	// ObjectFormatVersion is the version of this object format. Changing the
	// bytes below changes every segment id ever computed, so it is a version
	// bump and a migration, never an edit.
	ObjectFormatVersion = "1"

	// Object member names. The four that also appear on the segment_sealed
	// event are taken from internal/event rather than restated, so the object
	// and the event cannot drift apart. These two are the object's own.
	FieldSegmentFormatVersion = "segment_format_version"
	FieldEventHashes          = "event_hashes"
)

// truncationMarker ends a `reason` that did not fit doc 02 §5's bound.
const truncationMarker = " […truncated]"

var (
	// ErrObjectFormat reports bytes that are not a canonical segment object.
	ErrObjectFormat = errors.New("segment object is not in the canonical format")

	// ErrObjectMismatch reports a segment object that does not match what the
	// ledger's segment_sealed event says about it.
	ErrObjectMismatch = errors.New("segment object does not match the ledger claim")
)

// canonicalize is event.Canonicalize behind a seam, so that its error return —
// unreachable over the value domain this package feeds it — can be reached
// from a test. It is never reassigned outside tests. internal/event guards
// jcs.Transform with the same idiom for the same reason.
var canonicalize = event.Canonicalize

// Object is the sealed segment as it is written to storage.
//
// It deliberately does not carry its own segment_id: the id is the digest of
// these bytes, and a value cannot contain its own hash.
type Object struct {
	EventHashes   []string `json:"event_hashes"`
	FirstPosition int64    `json:"first_position"`
	LastPosition  int64    `json:"last_position"`
	FormatVersion string   `json:"segment_format_version"`
	MerkleRoot    string   `json:"segment_merkle_root"`
}

// checked validates the object and returns its Merkle tree.
//
// Whether the recorded root is the root of these leaves is not checked here —
// that is a question about the object's truthfulness rather than its shape,
// and Open asks it on every read.
func (o Object) checked() (*Tree, error) {
	if o.FormatVersion != ObjectFormatVersion {
		return nil, fmt.Errorf("%w: %s is %q, this build writes and reads %q",
			ErrObjectFormat, FieldSegmentFormatVersion, o.FormatVersion, ObjectFormatVersion)
	}
	// NewTree is the one definition of a well-formed leaf set: non-empty, and
	// every member a doc 02 §1 digest.
	tree, err := NewTree(o.EventHashes)
	if err != nil {
		return nil, err
	}
	if err := validateDigest(o.MerkleRoot); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrInvalidDigest, event.FieldSegmentMerkleRoot, err)
	}
	if o.FirstPosition < 1 {
		return nil, fmt.Errorf("%w: %s is %d; positions are 1-based (doc 02 §2)",
			ErrRange, event.FieldFirstPosition, o.FirstPosition)
	}
	if o.LastPosition-o.FirstPosition+1 != int64(len(o.EventHashes)) {
		return nil, fmt.Errorf("%w: positions %d..%d span %d events, the object holds %d",
			ErrRange, o.FirstPosition, o.LastPosition,
			o.LastPosition-o.FirstPosition+1, len(o.EventHashes))
	}
	return tree, nil
}

// Validate reports whether the object is well formed: a contiguous, non-empty
// run of well-formed event hashes under a known format version.
func (o Object) Validate() error {
	_, err := o.checked()
	return err
}

// Encode returns the object's canonical bytes — the preimage of its segment id.
func (o Object) Encode() ([]byte, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	return canonicalize(o)
}

// DecodeObject reads a segment object from storage bytes.
//
// The bytes must be *exactly* the canonical encoding of what they decode to.
// That one rule subsumes unknown members, duplicate members, member ordering,
// insignificant whitespace and number spelling: for a content-addressed object
// there is only one byte string that means a given segment, and anything else
// is either corruption or an attempt to find two encodings of one address.
func DecodeObject(raw []byte) (Object, error) {
	o, _, err := decodeObject(raw)
	return o, err
}

// decodeObject is DecodeObject, returning the Merkle tree it had to build to
// validate the leaves. Open needs that tree; building it twice would be a
// second construction of the same thing, and the whole point of this package
// is that there is only ever one.
func decodeObject(raw []byte) (Object, *Tree, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()

	var o Object
	if err := dec.Decode(&o); err != nil {
		return Object{}, nil, fmt.Errorf("%w: %w", ErrObjectFormat, err)
	}

	// An object that could never have been written is refused here rather than
	// on first use.
	tree, err := o.checked()
	if err != nil {
		return Object{}, nil, fmt.Errorf("%w: %w", ErrObjectFormat, err)
	}
	round, err := canonicalize(o)
	if err != nil {
		return Object{}, nil, fmt.Errorf("%w: %w", ErrObjectFormat, err)
	}
	if !bytes.Equal(raw, round) {
		return Object{}, nil, fmt.Errorf(
			"%w: the stored bytes are not the canonical encoding of the object they decode to",
			ErrObjectFormat)
	}
	return o, tree, nil
}

// TamperError reports a sealed segment that is not what the ledger says it is
// (SEG-006, invariant I4).
type TamperError struct {
	// SegmentID is the segment the ledger named.
	SegmentID string
	// Detail says which check failed.
	Detail string
	// Want and Got are the two values that disagree.
	Want string
	Got  string
}

func (e *TamperError) Error() string {
	return fmt.Sprintf("segment %s: %s: expected %s, found %s",
		e.SegmentID, e.Detail, e.Want, e.Got)
}

// Segment is a sealed segment read back out of storage and checked.
type Segment struct {
	// ID is the segment's content address, which is also its segment_id.
	ID     string
	Object Object

	tree *Tree
}

// Open reads the segment object the ledger named and verifies it.
//
// Two checks, and both have to hold:
//
//  1. The bytes hash to the segment id they are stored under. This is what
//     makes any edit to a stored object detectable with nothing but the
//     ledger's own segment_sealed event (SEG-006).
//  2. The root recorded inside the object is the root of the leaves it
//     carries. Content addressing cannot see a lie an author told at sealing
//     time, so the root is re-derived on every read rather than trusted.
func Open(store Store, segmentID string) (*Segment, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: cannot read segment %s", ErrNoStore, segmentID)
	}
	if err := validateDigest(segmentID); err != nil {
		return nil, fmt.Errorf("%w: %w; the segment id is the object's content address",
			ErrSegmentIDShape, err)
	}

	raw, err := store.Get(segmentID)
	if err != nil {
		return nil, fmt.Errorf("read segment %s: %w", segmentID, err)
	}
	if got := event.Digest(raw); got != segmentID {
		return nil, &TamperError{
			SegmentID: segmentID,
			Detail:    "the stored bytes are not the object this id names",
			Want:      segmentID,
			Got:       got,
		}
	}

	object, tree, err := decodeObject(raw)
	if err != nil {
		return nil, fmt.Errorf("segment %s: %w", segmentID, err)
	}
	if tree.Root() != object.MerkleRoot {
		return nil, &TamperError{
			SegmentID: segmentID,
			Detail:    "the recorded root is not the root of the events in the object",
			Want:      object.MerkleRoot,
			Got:       tree.Root(),
		}
	}

	return &Segment{ID: segmentID, Object: object, tree: tree}, nil
}

// Tree returns the segment's Merkle tree.
func (s *Segment) Tree() *Tree { return s.tree }

// ProofForPosition returns the inclusion proof for the event at a chain
// position inside the segment.
func (s *Segment) ProofForPosition(position int64) (Proof, error) {
	if position < s.Object.FirstPosition || position > s.Object.LastPosition {
		return Proof{}, fmt.Errorf("%w: position %d is outside the segment's %d..%d",
			ErrLeafOutOfRange, position, s.Object.FirstPosition, s.Object.LastPosition)
	}
	return s.tree.Proof(int(position - s.Object.FirstPosition))
}

// VerifyAgainst checks the object against the ledger's segment_sealed event.
//
// This is the check that makes the drift alert meaningful: the object in
// storage is one artefact, the event in the ledger is another, and a claim
// that cannot be substantiated by the artefact it names is drift (doc 02 §3).
func (s *Segment) VerifyAgainst(record event.Fields) error {
	eventType, err := claimString(record, event.FieldEventType)
	if err != nil {
		return err
	}
	if eventType != event.EventTypeSegmentSealed {
		return fmt.Errorf("%w: the claim is a %s, not a %s",
			ErrObjectMismatch, eventType, event.EventTypeSegmentSealed)
	}

	stringClaims := []struct {
		name string
		want string
	}{
		{event.FieldSegmentID, s.ID},
		{event.FieldSegmentMerkleRoot, s.Object.MerkleRoot},
	}
	for _, c := range stringClaims {
		got, cerr := claimString(record, c.name)
		if cerr != nil {
			return cerr
		}
		if got != c.want {
			return fmt.Errorf("%w: the ledger claims %s %s, the object is %s",
				ErrObjectMismatch, c.name, got, c.want)
		}
	}

	integerClaims := []struct {
		name string
		want int64
	}{
		{event.FieldFirstPosition, s.Object.FirstPosition},
		{event.FieldLastPosition, s.Object.LastPosition},
	}
	for _, c := range integerClaims {
		got, cerr := claimInteger(record, c.name)
		if cerr != nil {
			return cerr
		}
		if got != c.want {
			return fmt.Errorf("%w: the ledger claims %s %d, the object is %d",
				ErrObjectMismatch, c.name, got, c.want)
		}
	}
	return nil
}

func claimString(record event.Fields, name string) (string, error) {
	raw, present := record[name]
	if !present {
		return "", fmt.Errorf("%w: the claim has no %s", ErrObjectMismatch, name)
	}
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%w: %s is %T, want string", ErrObjectMismatch, name, raw)
	}
	return value, nil
}

func claimInteger(record event.Fields, name string) (int64, error) {
	raw, present := record[name]
	if !present {
		return 0, fmt.Errorf("%w: the claim has no %s", ErrObjectMismatch, name)
	}
	value, ok := toInt64(raw)
	if !ok {
		return 0, fmt.Errorf("%w: %s is %T, want an integer", ErrObjectMismatch, name, raw)
	}
	return value, nil
}

// AlertMeta is what the caller supplies for a drift alert: the ledger assigns
// nothing but the position and the hashes, so identity and clock come from
// outside this package.
type AlertMeta struct {
	EventID string
	TS      event.Timestamp
	// Source defaults to reconciler, which is who doc 02 §3 says emits a
	// ledger_drift_detected event.
	Source string
	// SubjectEventID is the event_id of the segment_sealed event whose claim
	// could not be substantiated.
	SubjectEventID string
}

// DriftEvent builds the alert-level event a failed segment read raises
// (SEG-006): a `ledger_drift_detected` body naming the segment_sealed event
// whose claim the storage layer could not substantiate.
//
// It returns a body, not a record: chain_position, prev_event_hash and
// event_hash are assigned by the ledger under serialized append (doc 02 §2).
func DriftEvent(m AlertMeta, cause error) (event.Fields, error) {
	if cause == nil {
		return nil, errors.New("drift alert without a cause")
	}
	if err := event.ValidateEventID(m.EventID); err != nil {
		return nil, fmt.Errorf("%s: %w", event.FieldEventID, err)
	}
	if err := event.ValidateEventID(m.SubjectEventID); err != nil {
		return nil, fmt.Errorf("%s: %w", event.FieldSubjectEventID, err)
	}
	if m.TS.IsZero() {
		return nil, fmt.Errorf("%s is required and is assigned by the server (doc 02 §2)", event.FieldTS)
	}
	source := m.Source
	if source == "" {
		source = event.SourceReconciler
	}
	if err := event.ValidateSource(source); err != nil {
		return nil, err
	}

	body := event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventID:        m.EventID,
		event.FieldEventType:      event.EventTypeLedgerDriftDetected,
		event.FieldTS:             m.TS.String(),
		event.FieldSource:         source,
		event.FieldSubjectEventID: m.SubjectEventID,
		event.FieldReason:         boundReason(cause.Error()),
	}
	// Every member above was validated where it entered, and boundReason
	// guarantees `reason` is non-empty, valid UTF-8 and inside its bound. The
	// test asserts the finished body passes event.ValidateEvent once the ledger
	// has stamped the members it assigns.
	return body, nil
}

// boundReason fits an error message into doc 02 §5's bound on `reason`.
//
// An alert must stay appendable however long the underlying error was: a
// detection nobody can record is not a detection (I3). So the message is
// truncated on a rune boundary and marked, rather than the alert being
// refused.
func boundReason(message string) string {
	if message == "" {
		return "segment read failed with an error carrying no message"
	}
	// An error message is arbitrary bytes from wherever the failure came from.
	// doc 02 §1 requires UTF-8, and refusing the alert over the encoding of its
	// own explanation would lose the detection entirely.
	if !utf8.ValidString(message) {
		message = strings.ToValidUTF8(message, "\uFFFD")
	}
	if len(message) <= event.MaxTextBytes {
		return message
	}
	// ToValidUTF8 with an empty replacement drops the partial rune the cut may
	// have left at the end, and nothing else: the message is valid UTF-8 by
	// the time it gets here.
	cut := event.MaxTextBytes - len(truncationMarker)
	return strings.ToValidUTF8(message[:cut], "") + truncationMarker
}
