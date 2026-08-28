// SPDX-License-Identifier: Apache-2.0

package event

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

// GenesisSeed is hashed to produce the prev_event_hash of chain_position 1
// (doc 02 §4.4). Protected string: changing it re-roots every chain that has
// ever been written, which is a major schema version and nothing less.
const GenesisSeed = "innsegl-genesis-v1"

// Digest returns HashPrefix followed by the lowercase hex SHA-256 of b — the
// one hash construction every digest in the system is built from (doc 02 §1
// and §4.3).
func Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return HashPrefix + hex.EncodeToString(sum[:])
}

// genesisPrevEventHash is computed, never written down. Doc 02 §4.4: "Compute
// it; do not hardcode without a test deriving it." The value is additionally
// frozen as the golden fixture genesis.hash, which TestSER001 checks against
// an independent derivation from the seed string.
var genesisPrevEventHash = sync.OnceValue(func() string {
	return Digest([]byte(GenesisSeed))
})

// GenesisPrevEventHash returns the prev_event_hash carried by the event at
// chain_position 1 (doc 02 §4.4).
func GenesisPrevEventHash() string { return genesisPrevEventHash() }
