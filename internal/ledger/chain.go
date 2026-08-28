// SPDX-License-Identifier: Apache-2.0

// Package ledger implements the innsegl hash chain: the append rule, the
// verification walk, and corrections by supersession (doc 02 §4, IP I4).
//
// # What lives here, and what deliberately does not
//
// The chain is type-agnostic. It does not know what an event means: no
// event_type enum, no per-type required members, no envelope rules. Those
// belong to internal/event, which owns the schema. This package's whole
// concern is the three members the ledger assigns — chain_position,
// prev_event_hash and event_hash — and the rule that links them.
//
// Hashing and canonical serialization are not reimplemented here. Every hash
// this package produces or checks comes from internal/event. A second
// implementation of the canonical form is a second thing that can disagree
// with the first, and two verifiers that disagree about a hash is exactly the
// drift doc 04 §5.4 describes.
//
// # There is no mutating call
//
// Nothing here edits or removes a record. Append returns a new record and
// leaves its input untouched; a correction is another append carrying
// supersedes, and the superseded event is never read for anything but its
// event_id (I4). That is not left to convention: TestNoMutatingSurface parses
// this file and fails on an exported name that reads like a mutation.
package ledger

import (
	"errors"
	"fmt"
	"maps"

	"innsegl.dev/innsegl/internal/event"
)

var (
	// ErrLedgerAssignedMember is returned when a caller supplies one of the
	// members the ledger assigns under serialized append (doc 02 §2).
	ErrLedgerAssignedMember = errors.New("ledger-assigned member supplied by the caller")

	// ErrSupersedesPresent is returned when a correction body already names a
	// superseded event.
	ErrSupersedesPresent = errors.New("supersedes already present")

	// ErrMissingMember and ErrMemberType report a record that cannot be read
	// as a chain link at all.
	ErrMissingMember = errors.New("required member missing")
	ErrMemberType    = errors.New("member has the wrong type")

	// ErrInvalidHead reports a chain head that could never have existed.
	ErrInvalidHead = errors.New("invalid chain head")

	// ErrPositionMismatch and ErrPrevHashMismatch are the two halves of the
	// chain rule (doc 02 §4.5).
	ErrPositionMismatch = errors.New("chain_position is not consecutive")
	ErrPrevHashMismatch = errors.New("prev_event_hash does not match the previous event_hash")

	// ErrTipMismatch reports a chain that walks cleanly but does not end where
	// it was expected to — the only way a walk can see a truncation.
	ErrTipMismatch = errors.New("chain tip does not match the expected tip")
)

// ledgerAssignedMembers are the three members a caller never supplies:
// chain_position and prev_event_hash are "assigned by the ledger under
// serialized append" (doc 02 §2), and event_hash is derived from the other
// two rather than given (doc 02 §4.1).
var ledgerAssignedMembers = []string{
	event.FieldChainPosition,
	event.FieldPrevEventHash,
	event.EventHashField,
}

// Head is the tip of a chain: the position and event_hash of its last event.
// The zero Head is an empty chain, whose next event is position 1 carrying the
// genesis constant (doc 02 §4.4).
type Head struct {
	Position  int64
	EventHash string
}

// IsEmpty reports whether the chain has no events yet.
func (h Head) IsEmpty() bool { return h.Position == 0 && h.EventHash == "" }

// Next returns the chain_position and prev_event_hash the next event carries.
func (h Head) Next() (int64, string) {
	if h.IsEmpty() {
		return 1, event.GenesisPrevEventHash()
	}
	return h.Position + 1, h.EventHash
}

// validate rejects a head that no append could have produced.
func (h Head) validate() error {
	if h.IsEmpty() {
		return nil
	}
	if h.Position < 1 {
		return fmt.Errorf("%w: position %d carries %s %q; the empty head is the only head below position 1",
			ErrInvalidHead, h.Position, event.EventHashField, h.EventHash)
	}
	if err := event.ValidateDigest(h.EventHash); err != nil {
		return fmt.Errorf("%w at position %d: %w", ErrInvalidHead, h.Position, err)
	}
	return nil
}

// VerificationError reports where a chain walk failed. Position is the
// chain_position the walk had reached and was checking — the first mismatch,
// because the walk stops there (doc 02 §4.5).
type VerificationError struct {
	Position int64
	Err      error
}

func (e *VerificationError) Error() string {
	return fmt.Sprintf("chain verification failed at position %d: %v", e.Position, e.Err)
}

func (e *VerificationError) Unwrap() error { return e.Err }

// failAt wraps a cause with the position the walk was checking.
func failAt(position int64, err error) error {
	return &VerificationError{Position: position, Err: err}
}

// Append stamps the ledger-assigned members onto a copy of body and hashes it,
// returning the finished record and the head it becomes.
//
// body carries everything the caller supplies and none of chain_position,
// prev_event_hash or event_hash; supplying one of those is an error rather
// than a value that gets overwritten, because a silently ignored client
// chain_position is a client that believes it chose one.
//
// body is never modified. The record returned is a fresh map.
func Append(head Head, body event.Fields) (event.Fields, Head, error) {
	if err := head.validate(); err != nil {
		return nil, Head{}, err
	}
	for _, name := range ledgerAssignedMembers {
		if _, present := body[name]; present {
			return nil, Head{}, fmt.Errorf(
				"%w: %s is assigned by the ledger under serialized append (doc 02 §2)",
				ErrLedgerAssignedMember, name)
		}
	}

	position, prev := head.Next()

	// A fresh map rather than a clone of body, so a nil body is an empty
	// record and not a panic, and so the caller's map is never aliased.
	staged := make(event.Fields, len(body)+len(ledgerAssignedMembers))
	maps.Copy(staged, body)
	staged[event.FieldChainPosition] = position
	staged[event.FieldPrevEventHash] = prev

	// EventHash canonicalizes the record without event_hash and digests it
	// (doc 02 §4.1-4.3). The hash is attached afterwards, which is what
	// "excluded from its own preimage" means.
	hash, err := staged.EventHash()
	if err != nil {
		return nil, Head{}, err
	}
	staged[event.EventHashField] = hash

	return staged, Head{Position: position, EventHash: hash}, nil
}

// Correct appends a correction: a new event carrying supersedes set to the
// event_id of original (doc 02 §2, I4).
//
// original is read for its event_id and for nothing else. It is not modified,
// not re-hashed, and not replaced — a superseded event stays in the chain
// byte for byte, and a reader that stops at it sees exactly what was recorded
// at the time.
func Correct(head Head, original, body event.Fields) (event.Fields, Head, error) {
	raw, present := original[event.FieldEventID]
	if !present {
		return nil, Head{}, fmt.Errorf("%w: the superseded event has no %s",
			ErrMissingMember, event.FieldEventID)
	}
	id, ok := raw.(string)
	if !ok {
		return nil, Head{}, fmt.Errorf("%w: %s of the superseded event is %T, want string",
			ErrMemberType, event.FieldEventID, raw)
	}
	if err := event.ValidateEventID(id); err != nil {
		return nil, Head{}, fmt.Errorf("superseded %s: %w", event.FieldEventID, err)
	}
	if _, present := body[event.FieldSupersedes]; present {
		return nil, Head{}, fmt.Errorf(
			"%w: a correction supersedes the event passed to Correct and nothing else",
			ErrSupersedesPresent)
	}

	correction := make(event.Fields, len(body)+1)
	maps.Copy(correction, body)
	correction[event.FieldSupersedes] = id

	return Append(head, correction)
}

// RecordHead reads the head an appended record represents. It checks that the
// two members are readable and well formed, not that the record hashes to what
// it claims — that is the walk's job.
func RecordHead(record event.Fields) (Head, error) {
	rawPosition, present := record[event.FieldChainPosition]
	if !present {
		return Head{}, fmt.Errorf("%w: %s", ErrMissingMember, event.FieldChainPosition)
	}
	position, ok := rawPosition.(int64)
	if !ok {
		return Head{}, fmt.Errorf("%w: %s is %T, want int64",
			ErrMemberType, event.FieldChainPosition, rawPosition)
	}
	if position < 1 {
		return Head{}, fmt.Errorf("%w: %s is %d; positions are 1-based (doc 02 §2)",
			ErrInvalidHead, event.FieldChainPosition, position)
	}

	rawHash, present := record[event.EventHashField]
	if !present {
		return Head{}, fmt.Errorf("%w: %s", ErrMissingMember, event.EventHashField)
	}
	hash, ok := rawHash.(string)
	if !ok {
		return Head{}, fmt.Errorf("%w: %s is %T, want string",
			ErrMemberType, event.EventHashField, rawHash)
	}
	if err := event.ValidateDigest(hash); err != nil {
		return Head{}, fmt.Errorf("%s: %w", event.EventHashField, err)
	}
	return Head{Position: position, EventHash: hash}, nil
}

// VerifyFrom walks records forward from start and returns the head reached.
//
// The walk is 1 to n and stops at the first mismatch, reporting the position
// it failed at in a *VerificationError (doc 02 §4.5). Each record must sit at
// the next consecutive position, carry the previous record's event_hash as its
// prev_event_hash, and hash to the event_hash it carries.
func VerifyFrom(start Head, records []event.Fields) (Head, error) {
	if err := start.validate(); err != nil {
		return Head{}, err
	}

	head := start
	for _, record := range records {
		position, prev := head.Next()

		rawPrev, present := record[event.FieldPrevEventHash]
		if !present {
			return Head{}, failAt(position,
				fmt.Errorf("%w: %s", ErrMissingMember, event.FieldPrevEventHash))
		}
		havePrev, ok := rawPrev.(string)
		if !ok {
			return Head{}, failAt(position, fmt.Errorf("%w: %s is %T, want string",
				ErrMemberType, event.FieldPrevEventHash, rawPrev))
		}

		next, err := RecordHead(record)
		if err != nil {
			return Head{}, failAt(position, err)
		}
		if next.Position != position {
			return Head{}, failAt(position, fmt.Errorf(
				"%w: the walk expected %d here and the record is at %d",
				ErrPositionMismatch, position, next.Position))
		}
		if havePrev != prev {
			return Head{}, failAt(position, fmt.Errorf(
				"%w: the record carries %s, the previous event hashes to %s",
				ErrPrevHashMismatch, havePrev, prev))
		}
		if err := record.Verify(); err != nil {
			return Head{}, failAt(position, err)
		}

		head = next
	}
	return head, nil
}

// Verify walks records from the genesis constant (doc 02 §4.4) and returns the
// head reached. An empty chain verifies vacuously and yields the empty head.
func Verify(records []event.Fields) (Head, error) { return VerifyFrom(Head{}, records) }

// VerifyTip walks records from genesis and then checks that the walk ended at
// tip.
//
// The walk alone cannot see a chain that has had its tail removed: a prefix of
// a valid chain is a valid chain, and every link in it still holds. Truncation
// is only visible against a tip recorded elsewhere — a sealed segment, a Rekor
// anchor, or a stored head. That is what tip is for.
func VerifyTip(records []event.Fields, tip Head) error {
	head, err := Verify(records)
	if err != nil {
		return err
	}
	if head != tip {
		return fmt.Errorf("%w: the walk ends at position %d with %q, expected position %d with %q",
			ErrTipMismatch, head.Position, head.EventHash, tip.Position, tip.EventHash)
	}
	return nil
}
