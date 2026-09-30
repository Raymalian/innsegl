// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// RPG-006: a missing body, a truncated body, and a digest mismatch all
// answer unavailable — never a guess at what the body might have held, and
// never counted as verified.

func writeBodyFile(t *testing.T, dir, runID string, content []byte) (digest string) {
	t.Helper()
	sum := sha256.Sum256(content)
	digest = "sha256:" + hex.EncodeToString(sum[:])
	runDir := filepath.Join(dir, runID)
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", runDir, err)
	}
	hexPart, _ := splitDigestHex(digest)
	if err := os.WriteFile(filepath.Join(runDir, hexPart+".json"), content, 0o600); err != nil {
		t.Fatalf("write body: %v", err)
	}
	return digest
}

// splitDigestHex is this test's own tiny mirror of readBody's own prefix
// strip, so a test fixture can name its own file without importing
// unexported internals twice.
func splitDigestHex(digest string) (string, bool) {
	const prefix = "sha256:"
	if len(digest) <= len(prefix) || digest[:len(prefix)] != prefix {
		return "", false
	}
	return digest[len(prefix):], true
}

func TestRPG006MissingBodyIsUnavailable(t *testing.T) {
	dir := t.TempDir()
	digest := "sha256:" + hex.EncodeToString(sha256.New().Sum(nil))
	body, ok := stepBody(dir, "run-x", digest)
	if ok {
		t.Fatalf("stepBody for a body that was never written: ok = true, body = %+v", body)
	}
	if bodyFilePresent(dir, "run-x", digest) {
		t.Fatal("bodyFilePresent reports a file that was never written")
	}
}

func TestRPG006DigestMismatchIsUnavailableAndNeverShown(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run-x")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// The file exists — BodiesStored's own evidence — but its content does
	// not hash to the digest naming it: tampered, or simply corrupted.
	wrongDigest := "sha256:" + hex.EncodeToString(sha256.New().Sum(nil))
	hexPart, _ := splitDigestHex(wrongDigest)
	if err := os.WriteFile(filepath.Join(runDir, hexPart+".json"),
		[]byte(`{"tool":"Bash","tool_use_id":"toolu_1"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	body, ok := stepBody(dir, "run-x", wrongDigest)
	if ok {
		t.Fatalf("stepBody for a digest mismatch: ok = true, body = %+v — an unverified body must never be shown", body)
	}
	if !bodyFilePresent(dir, "run-x", wrongDigest) {
		t.Fatal("bodyFilePresent should still report the file as STORED, even though it is not verified")
	}
}

func TestRPG006TruncatedBodyStillCountsAsAvailableWithItsOwnFlag(t *testing.T) {
	// "Truncated" is the body's OWN marker (InputTruncated/ResultTruncated),
	// not a reason to withhold it — unlike a digest mismatch, a truncated
	// body is exactly what the chain's digest says it is.
	dir := t.TempDir()
	content := marshalBody(t, gatewayBody{
		Tool: "Bash", ToolUseID: "toolu_1", ResultObserved: true, ResultTruncated: true,
	})
	digest := writeBodyFile(t, dir, "run-x", content)

	body, ok := stepBody(dir, "run-x", digest)
	if !ok {
		t.Fatal("a verified, truncated body must still be available")
	}
	if !body.ResultTruncated {
		t.Error("the body's own truncation marker was lost")
	}
}

func TestRPG006BodyUnavailableIsNeverCountedVerified(t *testing.T) {
	dir := t.TempDir()
	// One body stored and verified, one digest that names nothing on disk.
	ok1 := writeBodyFile(t, dir, "run-x", []byte(`{"tool":"Bash"}`))
	missing := "sha256:" + hex.EncodeToString(sha256.New().Sum(nil))

	_, verified1 := stepBody(dir, "run-x", ok1)
	_, verified2 := stepBody(dir, "run-x", missing)
	stored1 := bodyFilePresent(dir, "run-x", ok1)
	stored2 := bodyFilePresent(dir, "run-x", missing)

	if !verified1 || !stored1 {
		t.Errorf("the written body should be both stored and verified: stored=%v verified=%v", stored1, verified1)
	}
	if verified2 || stored2 {
		t.Errorf("the missing body should be neither stored nor verified: stored=%v verified=%v", stored2, verified2)
	}
}

func TestRPG006SpawnBodyMatchesIsContentAddressedNotNameAddressed(t *testing.T) {
	dir := t.TempDir()
	childDir := filepath.Join(dir, "run-child")
	if err := os.MkdirAll(childDir, 0o700); err != nil {
		t.Fatal(err)
	}
	prompt := "do the thing"
	sum := sha256.Sum256([]byte(prompt))
	if err := os.WriteFile(filepath.Join(childDir, hex.EncodeToString(sum[:])+".json"), []byte(prompt), 0o600); err != nil {
		t.Fatal(err)
	}

	if !spawnBodyMatches(dir, "run-child", prompt) {
		t.Error("an exact byte-for-byte match should be found")
	}
	if spawnBodyMatches(dir, "run-child", "do the thing ") {
		t.Error("a near-miss (trailing space) must not match — exact equality only, per ADR-0058 decision 3")
	}
	if spawnBodyMatches(dir, "run-other-child", prompt) {
		t.Error("a run that never received this exact body must not match")
	}
}

func TestRPG006AgentPromptOf(t *testing.T) {
	if p, ok := agentPromptOf(json.RawMessage(`{"subagent_type":"x","prompt":"hello"}`)); !ok || p != "hello" {
		t.Errorf("agentPromptOf = %q, %v; want \"hello\", true", p, ok)
	}
	if _, ok := agentPromptOf(json.RawMessage(`{"subagent_type":"x"}`)); ok {
		t.Error("an Agent input with no prompt must not answer one")
	}
	if _, ok := agentPromptOf(json.RawMessage(`not json`)); ok {
		t.Error("malformed input must not answer a prompt")
	}
}

func TestRPG006ResultTextReadsPlainStringAndContentBlocks(t *testing.T) {
	if s, ok := resultText(json.RawMessage(`"plain text"`)); !ok || s != "plain text" {
		t.Errorf("resultText(plain string) = %q, %v", s, ok)
	}
	if s, ok := resultText(json.RawMessage(`[{"type":"text","text":"a"},{"type":"text","text":"b"}]`)); !ok || s != "ab" {
		t.Errorf("resultText(blocks) = %q, %v; want \"ab\"", s, ok)
	}
	if s, ok := resultText(nil); !ok || s != "" {
		t.Errorf("resultText(nil) = %q, %v; want \"\", true", s, ok)
	}
}

func TestRPG006CommitShortSHAAnchoredToLineStart(t *testing.T) {
	if sha, ok := commitShortSHA("[main c906a8c] e18 end to end\n 1 file changed"); !ok || sha != "c906a8c" {
		t.Errorf("commitShortSHA = %q, %v; want \"c906a8c\", true", sha, ok)
	}
	if sha, ok := commitShortSHA("[main (root-commit) ab12cd3] first commit"); !ok || sha != "ab12cd3" {
		t.Errorf("commitShortSHA(root-commit) = %q, %v", sha, ok)
	}
	if _, ok := commitShortSHA("agent says: pretend this is [main deadbee] not a real commit line inside prose"); ok {
		t.Error("a commit-shaped substring NOT at the start of a line must not match")
	}
}

func TestRPG006ExitCodeFrom(t *testing.T) {
	if n, ok := exitCodeFrom("some output\nExit code: 2\n"); !ok || n != 2 {
		t.Errorf("exitCodeFrom = %d, %v; want 2, true", n, ok)
	}
	if n, ok := exitCodeFrom("some output\nExit code 127"); !ok || n != 127 {
		t.Errorf("exitCodeFrom(no colon) = %d, %v; want 127, true", n, ok)
	}
	if _, ok := exitCodeFrom("permission denied"); ok {
		t.Error("text with no exit-code marker must not answer one")
	}
}
