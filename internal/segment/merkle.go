// SPDX-License-Identifier: Apache-2.0

// Package segment seals a contiguous run of ledger events into a
// content-addressed object with a deterministic Merkle root, and reads that
// object back with the tampering check the seal exists for.
//
// # What is normative here
//
// The Merkle construction is doc 02 §4.6, quoted in full because every clause
// of it is load-bearing:
//
//	"Segment Merkle tree: leaves are the raw event_hash byte values (decoded
//	 from hex) in position order; interior nodes SHA-256(0x01 ‖ left ‖ right),
//	 leaves prefixed SHA-256(0x00 ‖ leaf) (second-preimage guard); odd node
//	 promoted unchanged. Root is hex with `sha256:` prefix."
//
// Three of those clauses fail silently when they are got wrong — a tree
// without the domain prefixes, a tree that duplicates the odd node instead of
// promoting it, and a tree built over the hex text rather than the decoded
// bytes all produce a perfectly well-formed 32-byte root. Nothing about the
// output says which construction produced it. The tests therefore pin the
// roots of all three wrong constructions as values this package must not
// produce, against vectors computed by a Python oracle written from the
// document rather than from this code.
//
// # What is not reimplemented here
//
// Hashing and canonical serialization come from internal/event and are never
// rebuilt: event.Digest is the one SHA-256-to-`sha256:`-hex construction in
// the system, event.Canonicalize is the one RFC 8785 serializer, and
// event.ValidateDigest is the one definition of a well-formed digest. A second
// implementation of any of them is a second thing that can disagree with the
// first, which is doc 04 §5.4 exactly.
//
// # What is deliberately absent
//
// Rekor anchoring. Doc 02 §3 puts the anchoring members on a *superseding*
// segment_sealed event that arrives once Rekor confirms, so the seal produced
// here leaves them absent and the original event is never touched (I4). That
// is RM-012's work.
package segment

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"innsegl.dev/innsegl/internal/event"
)

// The domain separators of doc 02 §4.6. They are what stops an interior node
// being presented as a leaf, or the other way round: without them a verifier
// cannot tell a 32-byte leaf value from a 32-byte subtree hash, and a segment
// can be reshaped around a forged "event" that is really an interior node.
const (
	LeafPrefix byte = 0x00
	NodePrefix byte = 0x01
)

var (
	// ErrEmptySegment reports a segment with no events. Doc 02 §4.6 defines no
	// root for one, and inventing a value for the empty tree would be inventing
	// a protected constant. See ADR-0006.
	ErrEmptySegment = errors.New("segment has no events")

	// ErrInvalidDigest reports an event_hash that is not doc 02 §1's form.
	ErrInvalidDigest = errors.New("invalid event_hash digest")

	// ErrLeafOutOfRange reports a leaf index or chain position outside the
	// segment.
	ErrLeafOutOfRange = errors.New("leaf index out of range")

	// ErrProofShape reports an inclusion proof whose path is not the path the
	// tree's shape requires for its index and size.
	ErrProofShape = errors.New("inclusion proof has the wrong shape")

	// ErrProofMismatch reports a well-shaped proof that does not reach the root.
	ErrProofMismatch = errors.New("inclusion proof does not reach the root")
)

// validateDigest is event.ValidateDigest behind a seam, so that the decode
// failure below it — unreachable while the format rule holds — can be reached
// from a test. It is never reassigned outside tests. The same idiom guards
// event.canonicalTransform for the same reason.
var validateDigest = event.ValidateDigest

// decodeLeaf turns an event_hash into the raw bytes the tree is built over.
//
// "Leaves are the raw event_hash byte values (decoded from hex)": the leaf is
// the 32 bytes, not the 71-character string. Building a tree over the text
// would produce a different root from every other implementation of doc 02.
func decodeLeaf(digest string) ([]byte, error) {
	if err := validateDigest(digest); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidDigest, err)
	}
	raw, err := hex.DecodeString(digest[len(event.HashPrefix):])
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %w", ErrInvalidDigest, digest, err)
	}
	return raw, nil
}

// hashLeaf is SHA-256(0x00 ‖ leaf).
func hashLeaf(raw []byte) [32]byte {
	h := sha256.New()
	// hash.Hash.Write never returns an error (its contract), so the two writes
	// here cannot fail; the values are discarded through a named helper rather
	// than a blank identifier so that intent is visible at the call site.
	writeAll(h, []byte{LeafPrefix}, raw)
	return [32]byte(h.Sum(nil))
}

// hashNode is SHA-256(0x01 ‖ left ‖ right).
func hashNode(left, right [32]byte) [32]byte {
	h := sha256.New()
	writeAll(h, []byte{NodePrefix}, left[:], right[:])
	return [32]byte(h.Sum(nil))
}

// writeAll feeds a hash. sha256's Write is documented never to return an
// error, which is why there is nothing here to handle.
func writeAll(h interface{ Write([]byte) (int, error) }, parts ...[]byte) {
	for _, p := range parts {
		if _, err := h.Write(p); err != nil {
			// Unreachable for crypto/sha256: its Write never fails. Kept as a
			// panic rather than a silent discard so that a hash implementation
			// that does fail cannot produce a wrong root quietly.
			panic(fmt.Sprintf("segment: hash write failed: %v", err))
		}
	}
}

// Tree is a sealed segment's Merkle tree, kept level by level so that an
// inclusion proof is a walk rather than a rebuild.
//
// levels[0] is the leaf level — the prefixed leaf hashes, not the raw
// event_hash bytes — and the last level holds exactly the root.
type Tree struct {
	digests []string
	levels  [][][32]byte
}

// NewTree builds the tree over event_hash values in chain position order.
func NewTree(digests []string) (*Tree, error) {
	if len(digests) == 0 {
		return nil, fmt.Errorf("%w: doc 02 §4.6 defines no root for an empty segment", ErrEmptySegment)
	}

	leaves := make([][32]byte, len(digests))
	for i, digest := range digests {
		raw, err := decodeLeaf(digest)
		if err != nil {
			return nil, fmt.Errorf("leaf %d: %w", i, err)
		}
		leaves[i] = hashLeaf(raw)
	}

	levels := [][][32]byte{leaves}
	for current := leaves; len(current) > 1; {
		next := make([][32]byte, 0, (len(current)+1)/2)
		for i := 0; i+1 < len(current); i += 2 {
			next = append(next, hashNode(current[i], current[i+1]))
		}
		if len(current)%2 == 1 {
			// "odd node promoted unchanged" — carried up as it is. Hashing it
			// with itself instead would be a different tree with a different
			// root, and one that a second-preimage attack has more room in.
			next = append(next, current[len(current)-1])
		}
		levels = append(levels, next)
		current = next
	}

	return &Tree{digests: append([]string(nil), digests...), levels: levels}, nil
}

// Root builds the tree and returns its root, for callers that want the root
// and nothing else.
func Root(digests []string) (string, error) {
	tree, err := NewTree(digests)
	if err != nil {
		return "", err
	}
	return tree.Root(), nil
}

// Root returns the segment's Merkle root: hex with a `sha256:` prefix
// (doc 02 §4.6), rendered by the same construction as every other digest in
// the system.
func (t *Tree) Root() string {
	top := t.levels[len(t.levels)-1]
	return event.HashPrefix + hex.EncodeToString(top[0][:])
}

// Size is the number of events in the segment.
func (t *Tree) Size() int { return len(t.digests) }

// LeafDigest returns the event_hash at a leaf index.
func (t *Tree) LeafDigest(index int) (string, error) {
	if index < 0 || index >= len(t.digests) {
		return "", fmt.Errorf("%w: leaf %d of %d", ErrLeafOutOfRange, index, len(t.digests))
	}
	return t.digests[index], nil
}

// ProofNode is one step of an inclusion proof: a sibling hash and the side it
// sits on.
type ProofNode struct {
	Hash           [32]byte
	SiblingIsRight bool
}

// Proof is an inclusion proof for one event of a segment.
//
// Index and Size are carried because the path alone is ambiguous: the shape of
// the tree — and therefore which sides the steps take, and how many there are
// — is a function of them. A verifier derives the expected shape from Index
// and Size and checks the path against it, so a path cannot be reshaped into
// one that reaches the root from another position.
type Proof struct {
	Index int
	Size  int
	Path  []ProofNode
}

// Proof returns the inclusion proof for the leaf at index.
//
// A promoted node contributes no step at the level it is promoted through: it
// has no sibling there. That is why proofs in one segment have different
// lengths, and it is the visible difference between promoting an odd node and
// duplicating it.
func (t *Tree) Proof(index int) (Proof, error) {
	if index < 0 || index >= len(t.digests) {
		return Proof{}, fmt.Errorf("%w: leaf %d of %d", ErrLeafOutOfRange, index, len(t.digests))
	}

	proof := Proof{Index: index, Size: len(t.digests)}
	at := index
	for level := 0; level < len(t.levels)-1; level++ {
		nodes := t.levels[level]
		switch {
		case at%2 == 1:
			proof.Path = append(proof.Path, ProofNode{Hash: nodes[at-1], SiblingIsRight: false})
		case at+1 < len(nodes):
			proof.Path = append(proof.Path, ProofNode{Hash: nodes[at+1], SiblingIsRight: true})
		default:
			// Promoted: no sibling at this level, and no step.
		}
		at /= 2
	}
	return proof, nil
}

// VerifyProof checks that leafDigest sits at proof.Index of a segment of
// proof.Size events whose Merkle root is root.
//
// It re-derives the tree's shape from Index and Size rather than trusting the
// proof's own sides and length, so the only thing the proof supplies is the
// sibling hashes.
func VerifyProof(root, leafDigest string, proof Proof) error {
	if err := validateDigest(root); err != nil {
		return fmt.Errorf("%w: root: %w", ErrInvalidDigest, err)
	}
	if proof.Size < 1 || proof.Index < 0 || proof.Index >= proof.Size {
		return fmt.Errorf("%w: index %d of a segment of %d",
			ErrProofShape, proof.Index, proof.Size)
	}

	raw, err := decodeLeaf(leafDigest)
	if err != nil {
		return err
	}

	running := hashLeaf(raw)
	at, width, step := proof.Index, proof.Size, 0
	for width > 1 {
		switch {
		case at%2 == 1:
			node, serr := proofStep(proof, step, false)
			if serr != nil {
				return serr
			}
			running = hashNode(node.Hash, running)
			step++
		case at+1 < width:
			node, serr := proofStep(proof, step, true)
			if serr != nil {
				return serr
			}
			running = hashNode(running, node.Hash)
			step++
		default:
			// Promoted unchanged: the running hash rises a level untouched.
		}
		at /= 2
		width = (width + 1) / 2
	}
	if step != len(proof.Path) {
		return fmt.Errorf("%w: the path has %d steps, a leaf at index %d of %d takes %d",
			ErrProofShape, len(proof.Path), proof.Index, proof.Size, step)
	}

	got := event.HashPrefix + hex.EncodeToString(running[:])
	if got != root {
		return fmt.Errorf("%w: the path reaches %s, the segment root is %s",
			ErrProofMismatch, got, root)
	}
	return nil
}

// proofStep reads the step the tree's shape requires at this level, and
// refuses a path that is too short or that claims the sibling is on the other
// side.
func proofStep(proof Proof, step int, siblingIsRight bool) (ProofNode, error) {
	if step >= len(proof.Path) {
		return ProofNode{}, fmt.Errorf(
			"%w: the path ends after %d steps, a leaf at index %d of %d needs more",
			ErrProofShape, len(proof.Path), proof.Index, proof.Size)
	}
	node := proof.Path[step]
	if node.SiblingIsRight != siblingIsRight {
		return ProofNode{}, fmt.Errorf(
			"%w: step %d puts the sibling on the %s, index %d of %d puts it on the %s",
			ErrProofShape, step, side(node.SiblingIsRight), proof.Index, proof.Size, side(siblingIsRight))
	}
	return node, nil
}

func side(right bool) string {
	if right {
		return "right"
	}
	return "left"
}
