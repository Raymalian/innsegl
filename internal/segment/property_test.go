// SPDX-License-Identifier: Apache-2.0

package segment

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"pgregory.net/rapid"

	"innsegl.dev/innsegl/internal/event"
)

// IP §2 requires property tests on Merkle proofs: "any single-byte mutation of
// any event in any position must break verification". These are them.
//
// Leaves are generated as SHA-256(seed ‖ index) rather than as raw random
// bytes, so they are distinct by construction and a property that depends on
// distinctness cannot pass by accident on a run where two leaves collided.

func genLeaves(t *rapid.T, minLen, maxLen int) []string {
	n := rapid.IntRange(minLen, maxLen).Draw(t, "leaf_count")
	seed := rapid.SliceOfN(rapid.Byte(), 4, 8).Draw(t, "seed")

	out := make([]string, n)
	seen := make(map[string]bool, n)
	for i := range out {
		sum := sha256.Sum256(fmt.Appendf(append([]byte(nil), seed...), "/%d", i))
		out[i] = event.HashPrefix + hex.EncodeToString(sum[:])
		seen[out[i]] = true
	}
	// Vacuity guard: the properties below distinguish one leaf from another,
	// and prove nothing over a set that is not actually distinct.
	if len(seen) != n {
		t.Fatalf("generated %d leaves but only %d distinct values", n, len(seen))
	}
	return out
}

// TestPropRootIsDeterministic: the same leaves always give the same root, and
// the root is a well-formed digest.
func TestPropRootIsDeterministic(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		leaves := genLeaves(rt, 1, 64)

		first, err := Root(leaves)
		if err != nil {
			rt.Fatalf("Root: %v", err)
		}
		second, err := Root(append([]string(nil), leaves...))
		if err != nil {
			rt.Fatalf("Root again: %v", err)
		}
		if first != second {
			rt.Fatalf("two constructions of the same leaves gave %s and %s", first, second)
		}
		if verr := event.ValidateDigest(first); verr != nil {
			rt.Fatalf("root is not a digest: %v", verr)
		}

		tree, err := NewTree(leaves)
		if err != nil {
			rt.Fatalf("NewTree: %v", err)
		}
		if tree.Root() != first {
			rt.Fatalf("Tree.Root() = %s, Root() = %s", tree.Root(), first)
		}
	})
}

// TestPropEveryProofVerifies: every leaf proves into the root, and no leaf
// proves into another leaf's position.
func TestPropEveryProofVerifies(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		leaves := genLeaves(rt, 1, 40)
		tree, err := NewTree(leaves)
		if err != nil {
			rt.Fatalf("NewTree: %v", err)
		}
		root := tree.Root()

		for i := range leaves {
			proof, perr := tree.Proof(i)
			if perr != nil {
				rt.Fatalf("Proof(%d): %v", i, perr)
			}
			if err := VerifyProof(root, leaves[i], proof); err != nil {
				rt.Fatalf("leaf %d of %d does not verify: %v", i, len(leaves), err)
			}
			for j := range leaves {
				if j == i {
					continue
				}
				if err := VerifyProof(root, leaves[j], proof); err == nil {
					rt.Fatalf("leaf %d's proof also verified leaf %d", i, j)
				}
			}
		}
	})
}

// TestPropAnySingleByteMutationBreaksVerification is IP §2's property, applied
// to the leaf values a segment commits to.
func TestPropAnySingleByteMutationBreaksVerification(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		leaves := genLeaves(rt, 1, 32)
		tree, err := NewTree(leaves)
		if err != nil {
			rt.Fatalf("NewTree: %v", err)
		}
		root := tree.Root()

		index := rapid.IntRange(0, len(leaves)-1).Draw(rt, "leaf_index")
		byteAt := rapid.IntRange(0, 31).Draw(rt, "byte_index")
		delta := rapid.ByteRange(1, 255).Draw(rt, "delta")

		proof, err := tree.Proof(index)
		if err != nil {
			rt.Fatalf("Proof(%d): %v", index, err)
		}
		// Positive first: an implementation that rejects everything must not
		// be able to pass this property by rejecting the mutation too.
		if verr := VerifyProof(root, leaves[index], proof); verr != nil {
			rt.Fatalf("the unmutated leaf %d does not verify: %v", index, verr)
		}

		raw, err := hex.DecodeString(leaves[index][len(event.HashPrefix):])
		if err != nil {
			rt.Fatalf("decode leaf: %v", err)
		}
		raw[byteAt] ^= delta
		mutated := event.HashPrefix + hex.EncodeToString(raw)
		if mutated == leaves[index] {
			rt.Fatalf("the mutation changed nothing at byte %d", byteAt)
		}

		if verr := VerifyProof(root, mutated, proof); verr == nil {
			rt.Fatalf("leaf %d verified against the root after one byte changed", index)
		}

		altered := append([]string(nil), leaves...)
		altered[index] = mutated
		moved, err := Root(altered)
		if err != nil {
			rt.Fatalf("Root: %v", err)
		}
		if moved == root {
			rt.Fatalf("changing one byte of leaf %d left the root at %s", index, root)
		}
	})
}

// TestPropSealRoundTrips: whatever the segment, sealing it and reading it back
// agree — and every event in it proves into the root the ledger records.
func TestPropSealRoundTrips(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		leaves := genLeaves(rt, 1, 24)
		first := rapid.Int64Range(1, 1<<40).Draw(rt, "first_position")

		records := make([]event.Fields, len(leaves))
		for i, leaf := range leaves {
			records[i] = event.Fields{
				event.FieldChainPosition: first + int64(i),
				event.EventHashField:     leaf,
			}
		}

		store := newMemStore()
		sealer := &Sealer{Store: store}
		sealed, err := sealer.Seal(Request{Records: records})
		if err != nil {
			rt.Fatalf("Seal: %v", err)
		}
		if sealed.SegmentID != digestOf(sealed.Object) {
			rt.Fatalf("segment id %s is not the digest of its object", sealed.SegmentID)
		}

		// A second seal into the same store resumes onto the same object.
		again, err := (&Sealer{Store: store}).Seal(Request{Records: records})
		if err != nil {
			rt.Fatalf("re-seal: %v", err)
		}
		if again.SegmentID != sealed.SegmentID || !again.Resumed {
			rt.Fatalf("re-seal gave %s (resumed=%v), first gave %s",
				again.SegmentID, again.Resumed, sealed.SegmentID)
		}

		seg, err := Open(store, sealed.SegmentID)
		if err != nil {
			rt.Fatalf("Open: %v", err)
		}
		body, err := sealed.Event(EventMeta{EventID: subjectEventID, TS: alertTS(t)})
		if err != nil {
			rt.Fatalf("Event: %v", err)
		}
		if err := seg.VerifyAgainst(body); err != nil {
			rt.Fatalf("VerifyAgainst: %v", err)
		}
		for i := range leaves {
			position := first + int64(i)
			proof, perr := seg.ProofForPosition(position)
			if perr != nil {
				rt.Fatalf("ProofForPosition(%d): %v", position, perr)
			}
			if err := VerifyProof(sealed.MerkleRoot, leaves[i], proof); err != nil {
				rt.Fatalf("position %d does not prove into the sealed root: %v", position, err)
			}
		}
	})
}
