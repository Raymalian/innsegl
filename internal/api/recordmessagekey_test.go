// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// E19 (the operator's decision, addressed on top of #395-#397): a brief or
// a reply whose retained body hashes — keyed by the derived, check-only
// key gateway.go's own writeMessageKeyFile wrote — to the ledger's own
// digest reads Available: true; one that does not, or whose key id has no
// key file at all, reads Available: false. Never guessed either way.

func writeTestMessageKey(t *testing.T, dir, keyID, key string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, keyID), []byte(key), 0o400); err != nil {
		t.Fatal(err)
	}
}

// realKeyedDigest computes ADR-0061 decision 2's own construction directly
// — hmac.New(sha256.New, []byte(key)), mac.Write(body) — mirroring
// internal/mcp/agentmessage.go's own keyedDigest byte for byte, so this
// test's own fixture digest is produced the SAME way the recorder produces
// one, never by calling this package's own keyedDigestOf (which is the
// function under test here).
func realKeyedDigest(key, keyID string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(body)
	return "hmac-sha256:" + keyID + ":" + hex.EncodeToString(mac.Sum(nil))
}

func TestParseKeyedDigest(t *testing.T) {
	keyID, hexPart, ok := parseKeyedDigest("hmac-sha256:gateway-v1:" + hex64(t, "x"))
	if !ok || keyID != "gateway-v1" || hexPart != hex64(t, "x") {
		t.Errorf("parseKeyedDigest = %q, %q, %v", keyID, hexPart, ok)
	}
	if _, _, ok := parseKeyedDigest("sha256:" + hex64(t, "x")); ok {
		t.Error("a PLAIN digest must not parse as a keyed one")
	}
	if _, _, ok := parseKeyedDigest("not a digest at all"); ok {
		t.Error("garbage must not parse")
	}
}

func hex64(t *testing.T, seed string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])
}

func TestReadMessageKeyExactBytesNoTrim(t *testing.T) {
	dir := t.TempDir()
	writeTestMessageKey(t, dir, "gateway-v1", "the-derived-key-hex")
	got, ok := readMessageKey(dir, "gateway-v1")
	if !ok || got != "the-derived-key-hex" {
		t.Errorf("readMessageKey = %q, %v; want the exact bytes written", got, ok)
	}
	if _, ok := readMessageKey(dir, "no-such-key-id"); ok {
		t.Error("a key id with no file should answer not found")
	}
	if _, ok := readMessageKey("", "gateway-v1"); ok {
		t.Error("an unconfigured directory should answer not found")
	}
}

func TestVerifyAgentMessageMatched(t *testing.T) {
	dir := t.TempDir()
	const keyID = "gateway-v1"
	const key = "abc123derivedkey"
	writeTestMessageKey(t, dir, keyID, key)

	briefText := "add a health endpoint"
	digest := realKeyedDigest(key, keyID, []byte(briefText))

	candidates := [][]byte{
		[]byte(`{"tool":"Bash"}`), // an unrelated tool_call body in the same directory
		[]byte(briefText),
	}
	text, available := verifyAgentMessage(dir, digest, candidates)
	if !available || text != briefText {
		t.Errorf("verifyAgentMessage = %q, %v; want %q, true", text, available, briefText)
	}
}

func TestVerifyAgentMessageNoMatchingBody(t *testing.T) {
	dir := t.TempDir()
	const keyID = "gateway-v1"
	writeTestMessageKey(t, dir, keyID, "abc123derivedkey")

	digest := realKeyedDigest("abc123derivedkey", keyID, []byte("the real brief"))
	candidates := [][]byte{[]byte("not the brief at all")}

	text, available := verifyAgentMessage(dir, digest, candidates)
	if available || text != "" {
		t.Errorf("verifyAgentMessage = %q, %v; want unavailable — no candidate body produced this digest", text, available)
	}
}

func TestVerifyAgentMessageNoKeyFileForThatKeyID(t *testing.T) {
	dir := t.TempDir()
	// A key file exists, but under a DIFFERENT id than the digest names.
	writeTestMessageKey(t, dir, "gateway-v1", "abc123derivedkey")

	digest := realKeyedDigest("some-other-key", "gateway-v2", []byte("brief"))
	text, available := verifyAgentMessage(dir, digest, [][]byte{[]byte("brief")})
	if available || text != "" {
		t.Errorf("verifyAgentMessage = %q, %v; want unavailable — no key file for key id %q", text, available, "gateway-v2")
	}
}

func TestVerifyAgentMessageNoMessageKeyDirConfiguredAtAll(t *testing.T) {
	digest := realKeyedDigest("key", "gateway-v1", []byte("brief"))
	text, available := verifyAgentMessage("", digest, [][]byte{[]byte("brief")})
	if available || text != "" {
		t.Errorf("verifyAgentMessage with no dir = %q, %v; want unavailable", text, available)
	}
}

func TestVerifyAgentMessageMalformedDigest(t *testing.T) {
	dir := t.TempDir()
	writeTestMessageKey(t, dir, "gateway-v1", "key")
	text, available := verifyAgentMessage(dir, "not-a-keyed-digest", [][]byte{[]byte("brief")})
	if available || text != "" {
		t.Errorf("verifyAgentMessage(malformed) = %q, %v; want unavailable", text, available)
	}
}

func TestRunBodyCandidatesReadsEveryFile(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run-x")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "aaa.json"), []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "bbb.json"), []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := runBodyCandidates(dir, "run-x")
	if len(got) != 2 {
		t.Fatalf("got %d candidates, want 2: %v", len(got), got)
	}

	seen := map[string]bool{}
	for _, c := range got {
		seen[string(c)] = true
	}
	if !seen["one"] || !seen["two"] {
		t.Errorf("candidates = %v, want both file contents", got)
	}
}

func TestRunBodyCandidatesMissingDirectoryAnswersNoneNotAnError(t *testing.T) {
	got := runBodyCandidates(t.TempDir(), "run-does-not-exist")
	if got != nil {
		t.Errorf("got %v, want nil for a run directory that does not exist", got)
	}
}
