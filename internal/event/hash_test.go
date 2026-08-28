// SPDX-License-Identifier: Apache-2.0

package event

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// TestSER001GenesisConstantIsDerived is doc 02 §4.4: "Compute it; do not
// hardcode without a test deriving it."
//
// The derivation is spelled out here from the seed string rather than copied
// from the implementation, so the test would still catch the constant being
// replaced by a literal that happens to look right.
func TestSER001GenesisConstantIsDerived(t *testing.T) {
	const seed = "innsegl-genesis-v1"

	if GenesisSeed != seed {
		t.Fatalf("GenesisSeed = %q, want %q — this is a protected string (doc 02 §4.4)",
			GenesisSeed, seed)
	}

	sum := sha256.Sum256([]byte(seed))
	want := "sha256:" + hex.EncodeToString(sum[:])

	if got := GenesisPrevEventHash(); got != want {
		t.Errorf("GenesisPrevEventHash() = %s, want %s", got, want)
	}

	// And the same value, frozen as a fixture.
	if got := string(readFixtureFile(t, "genesis.hash")); got != want {
		t.Errorf("genesis.hash fixture = %s, want %s", got, want)
	}

	// Shape, independently of the value: doc 02 §1.
	if err := ValidateDigest(want); err != nil {
		t.Errorf("the genesis constant is not a well-formed digest: %v", err)
	}
	if want != strings.ToLower(want) {
		t.Error("the genesis constant is not lowercase hex")
	}
}

// TestSER001Digest covers the one hash construction every other digest in the
// system is built from (doc 02 §4.3).
func TestSER001Digest(t *testing.T) {
	for _, in := range [][]byte{nil, {}, []byte("a"), []byte("innsegl")} {
		sum := sha256.Sum256(in)
		want := HashPrefix + hex.EncodeToString(sum[:])
		if got := Digest(in); got != want {
			t.Errorf("Digest(%q) = %s, want %s", in, got, want)
		}
	}

	// The empty-input digest, spelled out: a wrong prefix or a hex-case slip
	// would otherwise pass a self-consistent test.
	if got := Digest(nil); got !=
		"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("Digest(nil) = %s", got)
	}
}
