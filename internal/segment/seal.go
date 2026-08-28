// SPDX-License-Identifier: Apache-2.0

package segment

import (
	"bytes"
	"errors"
	"fmt"

	"innsegl.dev/innsegl/internal/event"
)

var (
	// ErrObjectNotFound is what a Store returns for a name it does not hold.
	ErrObjectNotFound = errors.New("segment object not found")

	// ErrNoStore reports a sealer or reader with nowhere to put a segment.
	ErrNoStore = errors.New("no object store")

	// ErrRange reports events that are not a contiguous, ascending run of
	// chain positions.
	ErrRange = errors.New("segment range is not a contiguous run of positions")

	// ErrSegmentIDShape reports a segment id that is not a content address.
	ErrSegmentIDShape = errors.New("segment id is not a content address")
)

// Store is the object storage a segment is sealed into.
//
// Two requirements the sealer relies on, and that RM-011's WORM writer has to
// keep:
//
//   - Put publishes atomically. An object is either wholly there or not there
//     at all; a store that can publish half an object cannot be resumed
//     against, only re-sealed from scratch.
//   - Put is write-once. Names are content addresses, so the only legitimate
//     second write of a name is a write of identical bytes.
//
// Get returns an error satisfying errors.Is(err, ErrObjectNotFound) when the
// name is absent, and that case is not a failure: it is how the sealer tells
// "not written yet" from "the store is broken".
type Store interface {
	Get(name string) ([]byte, error)
	Put(name string, data []byte) error
}

// Step is one step of sealing.
//
// IP §6.4 requires sealing to be resumable and requires the test to "kill the
// sealer at every step boundary". That is only a finite obligation if the
// steps are a finite, enumerable list — so they are one, in sealPipeline
// below, and Steps() is the list. Adding a step to the pipeline adds a case to
// the SEG-002 matrix automatically.
type Step int

const (
	// StepPlan reads the range out of the records: positions and event hashes.
	StepPlan Step = iota + 1
	// StepBuildTree builds the Merkle tree and takes the root (doc 02 §4.6).
	StepBuildTree
	// StepEncodeObject canonicalizes the segment object and derives the
	// content address that is its segment_id.
	StepEncodeObject
	// StepWriteObject puts the object in the store, or resumes onto the one
	// already there.
	StepWriteObject
	// StepVerifyObject reads it back and checks it, so a seal is never
	// reported on the strength of a write nobody confirmed.
	StepVerifyObject
)

func (s Step) String() string {
	switch s {
	case StepPlan:
		return "plan"
	case StepBuildTree:
		return "build_tree"
	case StepEncodeObject:
		return "encode_object"
	case StepWriteObject:
		return "write_object"
	case StepVerifyObject:
		return "verify_object"
	default:
		return fmt.Sprintf("unknown_step_%d", int(s))
	}
}

// sealPipeline is the ordered list of steps a seal is made of.
var sealPipeline = []struct {
	step Step
	run  func(*sealState) error
}{
	{StepPlan, (*sealState).plan},
	{StepBuildTree, (*sealState).buildTree},
	{StepEncodeObject, (*sealState).encodeObject},
	{StepWriteObject, (*sealState).writeObject},
	{StepVerifyObject, (*sealState).verifyObject},
}

// Steps returns the steps a seal runs, in order. The boundaries a crash can
// fall on are the len(Steps())+1 gaps between and around them.
func Steps() []Step {
	out := make([]Step, len(sealPipeline))
	for i, s := range sealPipeline {
		out[i] = s.step
	}
	return out
}

// Request is a segment to seal: the ledger records of one contiguous run of
// chain positions, in position order.
//
// There is no segment id to supply. The id is the object's content address, so
// it is derived from these records and nothing else — which is the property
// that makes a re-run after a crash produce the identical segment hash.
type Request struct {
	Records []event.Fields
}

// Sealer seals segments into a Store.
type Sealer struct {
	Store Store

	// AfterStep, when set, is called after each completed step. A non-nil
	// return aborts the seal at that boundary. It is the failure-injection
	// seam SEG-002 drives the kill matrix through, and is nil in production.
	AfterStep func(Step) error
}

// Sealed is a completed seal.
type Sealed struct {
	// SegmentID is the object's content address, and the value the ledger's
	// segment_sealed event carries as segment_id.
	SegmentID string
	// MerkleRoot is doc 02 §4.6's root over the segment's event hashes.
	MerkleRoot string

	FirstPosition int64
	LastPosition  int64

	// Object is the canonical bytes stored under SegmentID.
	Object []byte

	// Resumed reports that the object was already in the store and this seal
	// adopted it rather than writing it.
	Resumed bool

	tree *Tree
}

// Tree returns the segment's Merkle tree, for producing inclusion proofs.
func (s *Sealed) Tree() *Tree { return s.tree }

// sealState is the work in progress a step operates on.
type sealState struct {
	sealer  *Sealer
	records []event.Fields

	digests []string
	first   int64
	last    int64

	tree    *Tree
	object  Object
	encoded []byte
	id      string
	resumed bool
}

// Seal seals a segment, and is safe to re-run after a crash at any point.
//
// Every step is a pure function of the request except the write, and the write
// is addressed by content — so a re-run recomputes the identical bytes, finds
// them already stored, and adopts them (IP §6.4).
func (s *Sealer) Seal(req Request) (*Sealed, error) {
	if s.Store == nil {
		return nil, fmt.Errorf("%w: nothing to seal into", ErrNoStore)
	}

	state := &sealState{sealer: s, records: req.Records}
	for _, stage := range sealPipeline {
		if err := stage.run(state); err != nil {
			return nil, fmt.Errorf("seal: %s: %w", stage.step, err)
		}
		if s.AfterStep != nil {
			if err := s.AfterStep(stage.step); err != nil {
				return nil, fmt.Errorf("seal aborted after %s: %w", stage.step, err)
			}
		}
	}

	return &Sealed{
		SegmentID:     state.id,
		MerkleRoot:    state.tree.Root(),
		FirstPosition: state.first,
		LastPosition:  state.last,
		Object:        state.encoded,
		Resumed:       state.resumed,
		tree:          state.tree,
	}, nil
}

// plan reads the two members of each record the segment is built from:
// chain_position, which fixes the order and the range, and event_hash, which
// is the leaf.
//
// It does not verify the hash chain. That is ledger.Verify's walk, and a second
// implementation of the chain rule here would be a second thing that can
// disagree with it (doc 04 §5.4). What it does enforce is that the records are
// one contiguous ascending run, because a segment with a gap in it would seal
// a range whose first_position and last_position lie about what it contains.
func (s *sealState) plan() error {
	if len(s.records) == 0 {
		return fmt.Errorf("%w: nothing to seal", ErrEmptySegment)
	}

	s.digests = make([]string, len(s.records))
	for i, record := range s.records {
		position, ok := toInt64(record[event.FieldChainPosition])
		if !ok {
			return fmt.Errorf("%w: record %d has no readable %s (%T)",
				ErrRange, i, event.FieldChainPosition, record[event.FieldChainPosition])
		}
		switch {
		case i == 0:
			if position < 1 {
				return fmt.Errorf("%w: %s is %d; positions are 1-based (doc 02 §2)",
					ErrRange, event.FieldChainPosition, position)
			}
			s.first = position
		case position != s.last+1:
			return fmt.Errorf("%w: record %d is at position %d, the previous one is at %d",
				ErrRange, i, position, s.last)
		}
		s.last = position

		digest, ok := record[event.EventHashField].(string)
		if !ok {
			return fmt.Errorf("%w: record %d has no readable %s (%T)",
				ErrInvalidDigest, i, event.EventHashField, record[event.EventHashField])
		}
		s.digests[i] = digest
	}
	return nil
}

// buildTree is doc 02 §4.6. It is also where a malformed event_hash is caught,
// because NewTree is the one place that decides what a leaf is.
func (s *sealState) buildTree() error {
	tree, err := NewTree(s.digests)
	if err != nil {
		return err
	}
	s.tree = tree
	return nil
}

// encodeObject builds the object and derives the content address that is the
// segment's id.
func (s *sealState) encodeObject() error {
	s.object = Object{
		EventHashes:   s.digests,
		FirstPosition: s.first,
		LastPosition:  s.last,
		FormatVersion: ObjectFormatVersion,
		MerkleRoot:    s.tree.Root(),
	}
	encoded, err := s.object.Encode()
	if err != nil {
		return err
	}
	s.encoded = encoded
	s.id = event.Digest(encoded)
	return nil
}

// writeObject stores the object, or resumes onto the one already there.
//
// The three cases are the whole of what "idempotent and resumable" means: the
// object is absent and is written; the object is present and identical, which
// is a completed earlier attempt and is adopted; or the object is present and
// different, which cannot happen by re-running the same seal and is reported
// as tampering rather than overwritten.
func (s *sealState) writeObject() error {
	existing, err := s.sealer.Store.Get(s.id)
	switch {
	case err == nil:
		if !bytes.Equal(existing, s.encoded) {
			return &TamperError{
				SegmentID: s.id,
				Detail:    "an object with different bytes is already stored under this content address",
				Want:      s.id,
				Got:       event.Digest(existing),
			}
		}
		s.resumed = true
		return nil
	case errors.Is(err, ErrObjectNotFound):
		return s.sealer.Store.Put(s.id, s.encoded)
	default:
		return err
	}
}

// verifyObject reads the segment back and checks it the way any other reader
// would. A seal is not reported on the strength of a write nobody confirmed.
func (s *sealState) verifyObject() error {
	if _, err := Open(s.sealer.Store, s.id); err != nil {
		return err
	}
	return nil
}

// EventMeta is what the caller supplies for the segment_sealed event: the
// ledger assigns the position and the hashes, and the clock and the event_id
// come from outside this package.
type EventMeta struct {
	EventID string
	TS      event.Timestamp
	// Source defaults to system, which is who doc 02 §3 says emits a
	// segment_sealed event.
	Source string
}

// Event builds the segment_sealed body for this seal (doc 02 §3).
//
// The two anchoring members are absent, and deliberately so: they arrive in a
// *superseding* segment_sealed event once Rekor confirms, leaving this one
// untouched (doc 02 §3, I4). Attaching them is RM-012's work, not this call's.
//
// It returns a body, not a record: chain_position, prev_event_hash and
// event_hash are assigned by the ledger under serialized append (doc 02 §2).
func (s *Sealed) Event(m EventMeta) (event.Fields, error) {
	if err := event.ValidateEventID(m.EventID); err != nil {
		return nil, fmt.Errorf("%s: %w", event.FieldEventID, err)
	}
	if m.TS.IsZero() {
		return nil, fmt.Errorf("%s is required and is assigned by the server (doc 02 §2)", event.FieldTS)
	}
	source := m.Source
	if source == "" {
		source = event.SourceSystem
	}
	if err := event.ValidateSource(source); err != nil {
		return nil, err
	}

	body := event.Fields{
		event.FieldSchemaVersion:     event.SchemaVersion,
		event.FieldEventID:           m.EventID,
		event.FieldEventType:         event.EventTypeSegmentSealed,
		event.FieldTS:                m.TS.String(),
		event.FieldSource:            source,
		event.FieldSegmentID:         s.SegmentID,
		event.FieldSegmentMerkleRoot: s.MerkleRoot,
		event.FieldFirstPosition:     s.FirstPosition,
		event.FieldLastPosition:      s.LastPosition,
	}
	if err := body.Validate(); err != nil {
		return nil, err
	}
	return body, nil
}

// toInt64 reads an integer member. The ledger writes chain_position as an
// int64; a record that has been through a JSON round trip may carry an int.
func toInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	default:
		return 0, false
	}
}
