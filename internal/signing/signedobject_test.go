// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"crypto/sha1"
	"encoding/hex"
	"strconv"
	"testing"
)

// The signed commit object handed back is exactly the bytes whose id is the
// commit SHA: the core writes it into its mirror (ADR-0065), and a byte that
// differed would be a different commit.
func TestSignedCommitObjectHashesToTheCommitSHA(t *testing.T) {
	payload := []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
		"author a <a@example.invalid> 0 +0000\ncommitter a <a@example.invalid> 0 +0000\n\nmessage\n")
	signature := []byte("-----BEGIN SIGNED MESSAGE-----\nabc\n-----END SIGNED MESSAGE-----\n")

	body, sha, err := signedCommitOf(payload, signature)
	if err != nil {
		t.Fatal(err)
	}
	want, err := commitSHAOf(payload, signature)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha1.Sum(append([]byte("commit "+strconv.Itoa(len(body))+"\x00"), body...))
	if got := hex.EncodeToString(sum[:]); got != sha || sha != want {
		t.Fatalf("object hashes to %s, signedCommitOf says %s, commitSHAOf says %s", got, sha, want)
	}
}
