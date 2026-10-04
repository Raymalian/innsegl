// SPDX-License-Identifier: Apache-2.0

package mirror

import (
	"crypto/sha1"
	"encoding/hex"
	"strconv"
	"testing"
)

// The signed commit itself reaches the mirror: the client pushes a commit's
// objects before it is signed, and nothing pushed the signed commit after,
// so a core reading only its mirror held no signed commit to prove. The
// core writes the signed commit object it built, under a ref that keeps it.
func TestStoreSignedKeepsTheSignedCommit(t *testing.T) {
	store := newStore(t)
	if _, err := store.Ensure(t.Context(), tRepo); err != nil {
		t.Fatal(err)
	}
	body := []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
		"author a <a@example.invalid> 0 +0000\ncommitter a <a@example.invalid> 0 +0000\n" +
		"gpgsig -----BEGIN SIGNED MESSAGE-----\n x\n -----END SIGNED MESSAGE-----\n\nmessage\n")
	sum := sha1.Sum(append([]byte("commit "+strconv.Itoa(len(body))+"\x00"), body...))
	sha := hex.EncodeToString(sum[:])

	if err := store.StoreSigned(t.Context(), tRepo, sha, body); err != nil {
		t.Fatalf("StoreSigned: %v", err)
	}
	if got, ok := refIn(t, store, SignedRefPrefix+sha); !ok || got != sha {
		t.Fatalf("ref %s = %q, %v; want %s", SignedRefPrefix+sha, got, ok, sha)
	}

	wrong := "0000000000000000000000000000000000000001"
	if err := store.StoreSigned(t.Context(), tRepo, wrong, body); err == nil {
		t.Fatal("StoreSigned kept bytes whose id is not the signed commit's")
	}
	if err := store.StoreSigned(t.Context(), "not/a", sha, body); err == nil {
		t.Fatal("StoreSigned accepted a malformed repository")
	}
}
