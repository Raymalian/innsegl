// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/base64"
	"strings"
	"testing"
)

// tamperSignature changes a compact JWS's signature: one bit of its first
// byte, which base64url encodes in full (a last character also carries
// padding bits a decoder may ignore), re-encoded. It fails the test if the
// token did not change.
func tamperSignature(t *testing.T, token string) string {
	t.Helper()
	i := strings.LastIndexByte(token, '.')
	if i < 0 {
		t.Fatalf("%q is not a compact JWS", token)
	}
	sig, err := base64.RawURLEncoding.DecodeString(token[i+1:])
	if err != nil || len(sig) == 0 {
		t.Fatalf("the signature of %q does not decode: %v", token, err)
	}
	sig[0] ^= 0x01
	out := token[:i+1] + base64.RawURLEncoding.EncodeToString(sig)
	if out == token {
		t.Fatal("tampering left the token unchanged")
	}
	return out
}

// MCP-087's tampered case must be tampered whatever the signature is: a
// signature already ending in "AA" was left unchanged by replacing its last
// two characters with "AA", and the "tampered" token verified (a flake seen
// in CI).
func TestMCP087TamperingAlwaysChangesTheSignature(t *testing.T) {
	sig := strings.Repeat("B", 84) + "AA" // an ES256 signature's length, ending in "AA"
	token := "eyJhbGciOiJFUzI1NiJ9.eyJhIjoxfQ." + sig
	got := tamperSignature(t, token)
	if got == token {
		t.Fatal("tampering left the token unchanged")
	}
	head, _, _ := strings.Cut(got, ".")
	if !strings.HasPrefix(token, head+".") || len(got) != len(token) {
		t.Fatalf("tampering changed more than the signature: %q", got)
	}
}
