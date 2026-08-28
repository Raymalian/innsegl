// SPDX-License-Identifier: Apache-2.0

package segment

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/event"
)

// SEG-001 — "Seal segment of K events; verify Merkle root and per-event
// inclusion proofs. All proofs verify; root deterministic." (doc 07)
//
// # Where the expected values come from
//
// Not from this package. Every root pinned in this file was produced by a
// Python oracle written from the text of doc 02 §4.6 alone, before this
// package computed anything:
//
//	def leaf(raw):    return sha256(b"\x00" + raw).digest()
//	def node(l, r):   return sha256(b"\x01" + l + r).digest()
//	level = [leaf(bytes.fromhex(d.split(":")[1])) for d in digests]
//	while len(level) > 1:
//	    nxt = [node(level[i], level[i+1]) for i in range(0, len(level)-1, 2)]
//	    if len(level) % 2: nxt.append(level[-1])      # promoted, NOT duplicated
//	    level = nxt
//	root = "sha256:" + level[0].hex()
//
// The two constructions doc 02 §4.6 rules out — duplicating an odd node, and
// omitting the domain prefixes — are pinned too, as values the implementation
// must NOT produce. Both of them still yield a plausible-looking root, which is
// exactly why asserting only "some root came back" would prove nothing.

// seedPrefix generates leaf digests the oracle can reproduce: the i-th leaf is
// SHA-256(UTF-8("innsegl-merkle-test/<i>")), rendered as an event_hash.
const seedPrefix = "innsegl-merkle-test/"

func seededDigests(n int) []string {
	out := make([]string, n)
	for i := range out {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s%d", seedPrefix, i)))
		out[i] = event.HashPrefix + hex.EncodeToString(sum[:])
	}
	return out
}

// oracleRoots are the roots the Python oracle produced for seededDigests(K).
var oracleRoots = map[int]string{
	1:  "sha256:f2a1d29a964d4c943a2d5310ae05fe506376381f85606fc091b2bc7cab53cdcf",
	2:  "sha256:f50fd7e6c990e5402ca874475a867c4539c588e171ad2014a01103cccd84cc85",
	3:  "sha256:723f70afeccadc65d41855654006abe194d4b69bfa90ea379204c4a6930a7593",
	4:  "sha256:a41a8a5ba3143123e25c3825c822c4cd5829de1a419f1ef9824baf0d64e9241d",
	5:  "sha256:2c17c557cf608c4da73ef061f0519377ac4660a8ad1a484f2cb11961e4d8c1be",
	6:  "sha256:3347cdf5c813fbe7d8d30d37a1565e32e5d89efe78ffecbca23899fbd77d1152",
	7:  "sha256:d002f43a4b9efa58bf6767fc65bf2992675dcaa8baed95856c2bd2cb274144f9",
	8:  "sha256:6ebf3ea235cefda097de4e83ab639725b5d31513022168296d57e1ae3cbbaa82",
	11: "sha256:f262e437059d9402d5801ff53ef89e0997cb7da49cec84a974589a2399bd970e",
	14: "sha256:6aa0923eb33935546939d6716c1d4b603481556b40291678e85cc265e2b762f5",
	16: "sha256:38ab91c6a363a9be317adc7d33ea0ac9bd2e63acc07daaf81a06f6696610c2fc",
	17: "sha256:43c78ab25dac405bb4a3a2b30baa39499eed100a56fb2cf1201efe631d17cee9",
}

// TestSEG001RootMatchesTheOracle is the root half of SEG-001: K odd, K even,
// K = 1, and K = 5, 11 and 17, each of which promotes an odd node at more than
// one level of the tree.
func TestSEG001RootMatchesTheOracle(t *testing.T) {
	for _, k := range []int{1, 2, 3, 4, 5, 6, 7, 8, 11, 14, 16, 17} {
		t.Run(fmt.Sprintf("K=%d", k), func(t *testing.T) {
			want := oracleRoots[k]

			got, err := Root(seededDigests(k))
			if err != nil {
				t.Fatalf("Root(K=%d): %v", k, err)
			}
			if got != want {
				t.Errorf("root\n got  %s\n want %s (Python oracle, doc 02 §4.6)", got, want)
			}

			// Deterministic: a second, independent construction of the same
			// leaves reaches the same root.
			again, err := NewTree(seededDigests(k))
			if err != nil {
				t.Fatalf("NewTree(K=%d): %v", k, err)
			}
			if again.Root() != want {
				t.Errorf("Tree.Root() = %s, want %s", again.Root(), want)
			}
			if again.Size() != k {
				t.Errorf("Tree.Size() = %d, want %d", again.Size(), k)
			}
		})
	}
}

// TestSEG001OddNodeIsPromotedNotDuplicated pins the difference doc 02 §4.6
// turns on. Both constructions produce a well-formed 32-byte root; only one of
// them is the one this ledger's verifiers will re-derive.
func TestSEG001OddNodeIsPromotedNotDuplicated(t *testing.T) {
	duplicating := map[int]string{
		3:  "sha256:ef336fc14c8668c629941115f8c7f6f093786395d836bc1368b98d4b57085108",
		5:  "sha256:15dd0eaa7a9609d2241670779fb8a12756e2aa8bb4bc72d11b7236541f15f779",
		11: "sha256:6ec2efb3ccd88e7c19502943405e0e91c45bbe5e0c84d1ab9f94ca8087700949",
	}
	for k, wrong := range duplicating {
		t.Run(fmt.Sprintf("K=%d", k), func(t *testing.T) {
			got, err := Root(seededDigests(k))
			if err != nil {
				t.Fatalf("Root: %v", err)
			}
			if got != oracleRoots[k] {
				t.Fatalf("root %s, want %s", got, oracleRoots[k])
			}
			if got == wrong {
				t.Errorf("root %s is the duplicate-the-odd-node root; doc 02 §4.6 promotes it unchanged", got)
			}
		})
	}
}

// TestSEG001PrefixesAreTheSecondPreimageGuard pins the other silent failure:
// dropping the 0x00/0x01 domain separators still produces a root, and destroys
// the property they exist for.
func TestSEG001PrefixesAreTheSecondPreimageGuard(t *testing.T) {
	unprefixed := map[int]string{
		3:  "sha256:0a0edab58325f58049b7c4133dad2f60bfff6f46f32d2f7128735b7278d5a96c",
		5:  "sha256:ba679df1bc6a6f1484e4e7fcf76d139a547101752f60d951661fb90d4758ecee",
		11: "sha256:23f5c6744c032495a7f8c30e9aaf63456e23698c2d0c7a88f437215ba086ed2b",
	}
	for k, wrong := range unprefixed {
		t.Run(fmt.Sprintf("K=%d", k), func(t *testing.T) {
			got, err := Root(seededDigests(k))
			if err != nil {
				t.Fatalf("Root: %v", err)
			}
			if got != oracleRoots[k] {
				t.Fatalf("root %s, want %s", got, oracleRoots[k])
			}
			if got == wrong {
				t.Errorf("root %s is the unprefixed root; doc 02 §4.6 prefixes leaves 0x00 and interior nodes 0x01", got)
			}
		})
	}

	// And the prefixes are the documented constants, not an accident of the
	// implementation: a single leaf's root is SHA-256(0x00 ‖ leaf) exactly.
	if LeafPrefix != 0x00 || NodePrefix != 0x01 {
		t.Fatalf("prefixes are 0x%02x/0x%02x, doc 02 §4.6 says 0x00/0x01", LeafPrefix, NodePrefix)
	}
	one := seededDigests(1)
	raw, err := hex.DecodeString(strings.TrimPrefix(one[0], event.HashPrefix))
	if err != nil {
		t.Fatalf("decode seeded leaf: %v", err)
	}
	sum := sha256.Sum256(append([]byte{LeafPrefix}, raw...))
	want := event.HashPrefix + hex.EncodeToString(sum[:])
	got, err := Root(one)
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	if got != want {
		t.Errorf("single-leaf root %s, want SHA-256(0x00 ‖ leaf) = %s", got, want)
	}
}

// TestSEG001EveryProofVerifies is the inclusion-proof half of SEG-001.
func TestSEG001EveryProofVerifies(t *testing.T) {
	for _, k := range []int{1, 2, 3, 4, 5, 6, 7, 8, 11, 14, 16, 17} {
		t.Run(fmt.Sprintf("K=%d", k), func(t *testing.T) {
			digests := seededDigests(k)
			tree, err := NewTree(digests)
			if err != nil {
				t.Fatalf("NewTree: %v", err)
			}
			root := tree.Root()
			for i := range digests {
				proof, perr := tree.Proof(i)
				if perr != nil {
					t.Fatalf("Proof(%d): %v", i, perr)
				}
				if proof.Index != i || proof.Size != k {
					t.Errorf("Proof(%d) = index %d size %d, want index %d size %d",
						i, proof.Index, proof.Size, i, k)
				}
				if err := VerifyProof(root, digests[i], proof); err != nil {
					t.Errorf("VerifyProof(leaf %d of %d): %v", i, k, err)
				}
				// The proof must be for THIS leaf and no other.
				other := (i + 1) % k
				if k > 1 {
					if err := VerifyProof(root, digests[other], proof); err == nil {
						t.Errorf("leaf %d's proof also verified leaf %d", i, other)
					}
				}
			}
		})
	}
}

// TestSEG001ProofPathMatchesTheOracle pins the shape of the path for K=5,
// where leaf 4 is promoted twice and reaches the root in a single step while
// every other leaf takes three. A tree that duplicated the odd node instead
// would give all five leaves a three-step path.
func TestSEG001ProofPathMatchesTheOracle(t *testing.T) {
	type step struct {
		right bool
		hash  string
	}
	want := [][]step{
		0: {
			{true, "3fa2eedb9d9d5b3ddb4615915247c33fb7568e52cf1d58be9defa07f5764c39c"},
			{true, "62a8dcf5618f1f6f5920f9267119a55ff40ca1486af5e3271cf9ea9b555c7079"},
			{true, "2c32fb58cacee935781e9ac7c0c452775dc1702bbd0fd643932b34221e45b632"},
		},
		1: {
			{false, "f2a1d29a964d4c943a2d5310ae05fe506376381f85606fc091b2bc7cab53cdcf"},
			{true, "62a8dcf5618f1f6f5920f9267119a55ff40ca1486af5e3271cf9ea9b555c7079"},
			{true, "2c32fb58cacee935781e9ac7c0c452775dc1702bbd0fd643932b34221e45b632"},
		},
		2: {
			{true, "89ef77ece589fa1d4a8b12dc11a513b72133d5b1274b7fcdecff1226a8b5ceb7"},
			{false, "f50fd7e6c990e5402ca874475a867c4539c588e171ad2014a01103cccd84cc85"},
			{true, "2c32fb58cacee935781e9ac7c0c452775dc1702bbd0fd643932b34221e45b632"},
		},
		3: {
			{false, "0520e97c6c17c2fc525ed85e45134c10ffab1ed419db71bbbacf3d1e92e80ad4"},
			{false, "f50fd7e6c990e5402ca874475a867c4539c588e171ad2014a01103cccd84cc85"},
			{true, "2c32fb58cacee935781e9ac7c0c452775dc1702bbd0fd643932b34221e45b632"},
		},
		4: {
			{false, "a41a8a5ba3143123e25c3825c822c4cd5829de1a419f1ef9824baf0d64e9241d"},
		},
	}

	tree, err := NewTree(seededDigests(5))
	if err != nil {
		t.Fatalf("NewTree: %v", err)
	}
	for i, wantPath := range want {
		proof, perr := tree.Proof(i)
		if perr != nil {
			t.Fatalf("Proof(%d): %v", i, perr)
		}
		if len(proof.Path) != len(wantPath) {
			t.Errorf("leaf %d path has %d steps, oracle says %d", i, len(proof.Path), len(wantPath))
			continue
		}
		for j, s := range wantPath {
			gotHash := hex.EncodeToString(proof.Path[j].Hash[:])
			if gotHash != s.hash || proof.Path[j].SiblingIsRight != s.right {
				t.Errorf("leaf %d step %d = (right=%v, %s), oracle says (right=%v, %s)",
					i, j, proof.Path[j].SiblingIsRight, gotHash, s.right, s.hash)
			}
		}
	}
}

// TestSEG001TamperedLeafBreaksItsProof is the property the tree exists for.
func TestSEG001TamperedLeafBreaksItsProof(t *testing.T) {
	const k = 11
	digests := seededDigests(k)
	tree, err := NewTree(digests)
	if err != nil {
		t.Fatalf("NewTree: %v", err)
	}
	root := tree.Root()

	for i := range digests {
		proof, perr := tree.Proof(i)
		if perr != nil {
			t.Fatalf("Proof(%d): %v", i, perr)
		}
		// Positive first, so a stub that fails everything cannot pass this
		// test by failing the negative assertion below.
		if err := VerifyProof(root, digests[i], proof); err != nil {
			t.Fatalf("the untampered proof for leaf %d must verify: %v", i, err)
		}

		tampered := flipDigestNibble(t, digests[i])
		if tampered == digests[i] {
			t.Fatalf("leaf %d was not actually altered", i)
		}
		if err := VerifyProof(root, tampered, proof); err == nil {
			t.Errorf("leaf %d verified against the root after being altered", i)
		}

		// And the root itself moves.
		altered := append([]string(nil), digests...)
		altered[i] = tampered
		moved, rerr := Root(altered)
		if rerr != nil {
			t.Fatalf("Root of the altered leaves: %v", rerr)
		}
		if moved == root {
			t.Errorf("altering leaf %d left the root at %s", i, root)
		}
	}
}

// flipDigestNibble changes exactly one hex digit of a digest.
func flipDigestNibble(t *testing.T, digest string) string {
	t.Helper()
	body := strings.TrimPrefix(digest, event.HashPrefix)
	b := []byte(body)
	if b[7] == '0' {
		b[7] = '1'
	} else {
		b[7] = '0'
	}
	return event.HashPrefix + string(b)
}

// TestMerkleRejectsWhatItCannotHash covers the refusal paths.
func TestMerkleRejectsWhatItCannotHash(t *testing.T) {
	t.Run("empty segment", func(t *testing.T) {
		if _, err := Root(nil); !errors.Is(err, ErrEmptySegment) {
			t.Errorf("Root(nil) error = %v, want ErrEmptySegment", err)
		}
		if _, err := NewTree([]string{}); !errors.Is(err, ErrEmptySegment) {
			t.Errorf("NewTree([]) error = %v, want ErrEmptySegment", err)
		}
	})

	bad := map[string]string{
		"no prefix":      strings.TrimPrefix(seededDigests(1)[0], event.HashPrefix),
		"wrong prefix":   "sha512:" + strings.TrimPrefix(seededDigests(1)[0], event.HashPrefix),
		"short":          event.HashPrefix + "abcdef",
		"uppercase hex":  strings.ToUpper(seededDigests(1)[0]),
		"not hex":        event.HashPrefix + strings.Repeat("z", 64),
		"empty":          "",
		"trailing space": seededDigests(1)[0] + " ",
	}
	for name, digest := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := Root([]string{digest}); !errors.Is(err, ErrInvalidDigest) {
				t.Errorf("Root(%q) error = %v, want ErrInvalidDigest", digest, err)
			}
		})
	}
}

// TestProofIndexBounds covers the out-of-range paths.
func TestProofIndexBounds(t *testing.T) {
	tree, err := NewTree(seededDigests(3))
	if err != nil {
		t.Fatalf("NewTree: %v", err)
	}
	for _, i := range []int{-1, 3, 99} {
		if _, perr := tree.Proof(i); !errors.Is(perr, ErrLeafOutOfRange) {
			t.Errorf("Proof(%d) error = %v, want ErrLeafOutOfRange", i, perr)
		}
		if _, lerr := tree.LeafDigest(i); !errors.Is(lerr, ErrLeafOutOfRange) {
			t.Errorf("LeafDigest(%d) error = %v, want ErrLeafOutOfRange", i, lerr)
		}
	}
	got, err := tree.LeafDigest(2)
	if err != nil {
		t.Fatalf("LeafDigest(2): %v", err)
	}
	if want := seededDigests(3)[2]; got != want {
		t.Errorf("LeafDigest(2) = %s, want %s", got, want)
	}
}

// TestVerifyProofRejectsAForgedShape is what stops a proof being reshaped into
// one that reaches the root from somewhere else in the tree.
func TestVerifyProofRejectsAForgedShape(t *testing.T) {
	const k = 7
	digests := seededDigests(k)
	tree, err := NewTree(digests)
	if err != nil {
		t.Fatalf("NewTree: %v", err)
	}
	root := tree.Root()
	proof, err := tree.Proof(2)
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}
	if err := VerifyProof(root, digests[2], proof); err != nil {
		t.Fatalf("the honest proof must verify first: %v", err)
	}

	clone := func() Proof {
		p := proof
		p.Path = append([]ProofNode(nil), proof.Path...)
		return p
	}

	t.Run("flipped side", func(t *testing.T) {
		p := clone()
		p.Path[0].SiblingIsRight = !p.Path[0].SiblingIsRight
		if err := VerifyProof(root, digests[2], p); !errors.Is(err, ErrProofShape) {
			t.Errorf("error = %v, want ErrProofShape", err)
		}
	})
	t.Run("dropped step", func(t *testing.T) {
		p := clone()
		p.Path = p.Path[:len(p.Path)-1]
		if err := VerifyProof(root, digests[2], p); !errors.Is(err, ErrProofShape) {
			t.Errorf("error = %v, want ErrProofShape", err)
		}
	})
	t.Run("extra step", func(t *testing.T) {
		p := clone()
		p.Path = append(p.Path, ProofNode{})
		if err := VerifyProof(root, digests[2], p); !errors.Is(err, ErrProofShape) {
			t.Errorf("error = %v, want ErrProofShape", err)
		}
	})
	t.Run("index outside size", func(t *testing.T) {
		p := clone()
		p.Index = k
		if err := VerifyProof(root, digests[2], p); !errors.Is(err, ErrProofShape) {
			t.Errorf("error = %v, want ErrProofShape", err)
		}
	})
	t.Run("size zero", func(t *testing.T) {
		p := clone()
		p.Size = 0
		if err := VerifyProof(root, digests[2], p); !errors.Is(err, ErrProofShape) {
			t.Errorf("error = %v, want ErrProofShape", err)
		}
	})
	t.Run("substituted sibling", func(t *testing.T) {
		p := clone()
		p.Path[0].Hash[0] ^= 0xff
		if err := VerifyProof(root, digests[2], p); !errors.Is(err, ErrProofMismatch) {
			t.Errorf("error = %v, want ErrProofMismatch", err)
		}
	})
	t.Run("wrong root", func(t *testing.T) {
		other, oerr := Root(seededDigests(k + 1))
		if oerr != nil {
			t.Fatalf("Root: %v", oerr)
		}
		if err := VerifyProof(other, digests[2], proof); !errors.Is(err, ErrProofMismatch) {
			t.Errorf("error = %v, want ErrProofMismatch", err)
		}
	})
	t.Run("malformed root", func(t *testing.T) {
		if err := VerifyProof("not-a-digest", digests[2], proof); !errors.Is(err, ErrInvalidDigest) {
			t.Errorf("error = %v, want ErrInvalidDigest", err)
		}
	})
	t.Run("malformed leaf", func(t *testing.T) {
		if err := VerifyProof(root, "not-a-digest", proof); !errors.Is(err, ErrInvalidDigest) {
			t.Errorf("error = %v, want ErrInvalidDigest", err)
		}
	})
}
