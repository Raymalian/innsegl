// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// ---------------------------------------------------------------------------
// RM-273 (#436): a run recorded through the PreToolUse/PostToolUse hook
// retains the harness's own PostToolUse payload instead of a gatewayBody.
// stepBody must read both shapes, mapping the hook payload onto the same
// fields outcomeOf and summaryOf already read — never showing a hook-
// recorded step as an empty, unknown, failed-looking one just because its
// body does not parse as a gateway body.
//
// Each body below is the harness's own real shape (RM-273's own issue:
// session_id, transcript_path, cwd, scratchpad_dir, prompt_id,
// permission_mode, agent_id, agent_type, effort, hook_event_name,
// tool_name, tool_input, tool_response, tool_use_id, duration_ms — measured
// across 145 bodies of one real run), including every member this mapping
// does NOT use, so these tests also prove the extra harness bookkeeping is
// read past without tripping the mapping up.
// ---------------------------------------------------------------------------

const hookBodyEnvelope = `{
	"session_id": "sess-1",
	"transcript_path": "/tmp/transcript.jsonl",
	"cwd": "/repo",
	"scratchpad_dir": "/tmp/scratch",
	"prompt_id": "prompt-1",
	"permission_mode": "default",
	"agent_id": "agent-1",
	"agent_type": "general-purpose",
	"effort": "medium",
	"hook_event_name": "PostToolUse",
	"tool_use_id": %q,
	"tool_name": %q,
	"tool_input": %s,
	"tool_response": %s,
	"duration_ms": 1234
}`

func TestRM273HookBodyBashSuccess(t *testing.T) {
	dir := t.TempDir()
	raw := []byte(fmtHookBody(t, "toolu_bash1", "Bash",
		`{"command":"echo hi"}`,
		`{"stdout":"hi\n","stderr":"","interrupted":false,"isImage":false,"noOutputExpected":false}`))
	digest := writeBodyFile(t, dir, "run-x", raw)

	body, ok := stepBody(dir, "run-x", digest)
	if !ok {
		t.Fatal("a well-formed hook body must be available")
	}
	if body.Tool != "Bash" {
		t.Errorf("Tool = %q, want Bash", body.Tool)
	}
	if body.ToolUseID != "toolu_bash1" {
		t.Errorf("ToolUseID = %q, want toolu_bash1", body.ToolUseID)
	}
	if got := summaryOf("Bash", body); got != "echo hi" {
		t.Errorf("summaryOf = %q, want \"echo hi\"", got)
	}
	text, ok := resultText(body.Result)
	if !ok || text != "hi\n" {
		t.Errorf("resultText(Result) = %q, %v; want \"hi\\n\", true", text, ok)
	}
	out := outcomeOf("Bash", body)
	if out.Kind != "ok" || out.ExitCode != nil {
		t.Errorf("outcomeOf = %+v, want Kind=ok and no exit code (the hook payload carries none)", out)
	}
}

func TestRM273HookBodyBashInterruptedIsFailedNotUnknown(t *testing.T) {
	dir := t.TempDir()
	raw := []byte(fmtHookBody(t, "toolu_bash2", "Bash",
		`{"command":"sleep 100"}`,
		`{"stdout":"partial output","stderr":"","interrupted":true,"isImage":false,"noOutputExpected":false}`))
	digest := writeBodyFile(t, dir, "run-x", raw)

	body, ok := stepBody(dir, "run-x", digest)
	if !ok {
		t.Fatal("a well-formed hook body must be available")
	}
	text, _ := resultText(body.Result)
	if text != "partial output" {
		t.Errorf("resultText(Result) = %q, want the captured stdout even though interrupted", text)
	}
	out := outcomeOf("Bash", body)
	if out.Kind != "error" || out.ExitCode != nil {
		t.Errorf("outcomeOf(interrupted) = %+v, want Kind=error and no invented exit code", out)
	}
	if !body.isError() {
		t.Error("isError() should be true for an interrupted Bash call")
	}
}

func TestRM273HookBodyEdit(t *testing.T) {
	dir := t.TempDir()
	raw := []byte(fmtHookBody(t, "toolu_edit1", "Edit",
		`{"file_path":"a.go","old_string":"old","new_string":"new"}`,
		`{"filePath":"a.go","oldString":"old","newString":"new","originalFile":"package a\nold\n",`+
			`"structuredPatch":[{"oldStart":1,"oldLines":1,"newStart":1,"newLines":1}],"userModified":false,"replaceAll":false}`))
	digest := writeBodyFile(t, dir, "run-x", raw)

	body, ok := stepBody(dir, "run-x", digest)
	if !ok {
		t.Fatal("a well-formed hook body must be available")
	}
	if body.Tool != "Edit" {
		t.Errorf("Tool = %q, want Edit", body.Tool)
	}
	if got := summaryOf("Edit", body); got != "a.go" {
		t.Errorf("summaryOf = %q, want \"a.go\"", got)
	}
	text, ok := resultText(body.Result)
	if !ok || text == "" {
		t.Fatalf("resultText(Result) = %q, %v; want a non-empty rendering", text, ok)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(text), &decoded); err != nil {
		t.Fatalf("Output is not valid JSON: %v (%q)", err, text)
	}
	if decoded["filePath"] != "a.go" {
		t.Errorf("rendered Output = %v, want filePath a.go", decoded)
	}
	out := outcomeOf("Edit", body)
	if out.Kind != "ok" {
		t.Errorf("outcomeOf(Edit) = %+v, want Kind=ok — structuredPatch shows the write happened", out)
	}
	if out.ExitCode != nil {
		t.Errorf("outcomeOf(Edit).ExitCode = %v, want nil — exit codes are Bash-only", out.ExitCode)
	}
}

func TestRM273HookBodyWrite(t *testing.T) {
	dir := t.TempDir()
	raw := []byte(fmtHookBody(t, "toolu_write1", "Write",
		`{"file_path":"b.go","content":"package main\n"}`,
		`{"type":"create","filePath":"b.go","content":"package main\n"}`))
	digest := writeBodyFile(t, dir, "run-x", raw)

	body, ok := stepBody(dir, "run-x", digest)
	if !ok {
		t.Fatal("a well-formed hook body must be available")
	}
	if body.Tool != "Write" {
		t.Errorf("Tool = %q, want Write", body.Tool)
	}
	if got := summaryOf("Write", body); got != "b.go" {
		t.Errorf("summaryOf = %q, want \"b.go\"", got)
	}
	out := outcomeOf("Write", body)
	if out.Kind != "ok" {
		t.Errorf("outcomeOf(Write) = %+v, want Kind=ok — the type:create shape shows the write happened", out)
	}
}

func TestRM273HookBodyStringResponseNeverGuessesAnOutcome(t *testing.T) {
	dir := t.TempDir()
	raw := []byte(fmtHookBody(t, "toolu_glob1", "Glob",
		`{"pattern":"*.go"}`,
		`"a.go\nb.go\nc.go"`))
	digest := writeBodyFile(t, dir, "run-x", raw)

	body, ok := stepBody(dir, "run-x", digest)
	if !ok {
		t.Fatal("a well-formed hook body must be available")
	}
	if body.Tool != "Glob" {
		t.Errorf("Tool = %q, want Glob", body.Tool)
	}
	text, ok := resultText(body.Result)
	if !ok || text != "a.go\nb.go\nc.go" {
		t.Errorf("resultText(Result) = %q, %v; want the plain string verbatim", text, ok)
	}
	out := outcomeOf("Glob", body)
	if out.Kind != "unknown" {
		t.Errorf("outcomeOf(plain string, no success marker) = %+v, want Kind=unknown — never a guessed ok or failed", out)
	}
}

func TestRM273HookBodyExplicitSuccessField(t *testing.T) {
	dir := t.TempDir()

	okRaw := []byte(fmtHookBody(t, "toolu_ok1", "SomeTool", `{}`, `{"success":true,"message":"done"}`))
	okDigest := writeBodyFile(t, dir, "run-x", okRaw)
	okBody, ok := stepBody(dir, "run-x", okDigest)
	if !ok {
		t.Fatal("a well-formed hook body must be available")
	}
	if out := outcomeOf("SomeTool", okBody); out.Kind != "ok" {
		t.Errorf("outcomeOf(success:true) = %+v, want Kind=ok", out)
	}

	failRaw := []byte(fmtHookBody(t, "toolu_fail1", "SomeTool", `{}`, `{"success":false,"message":"nope"}`))
	failDigest := writeBodyFile(t, dir, "run-x", failRaw)
	failBody, ok := stepBody(dir, "run-x", failDigest)
	if !ok {
		t.Fatal("a well-formed hook body must be available")
	}
	if out := outcomeOf("SomeTool", failBody); out.Kind != "error" {
		t.Errorf("outcomeOf(success:false) = %+v, want Kind=error", out)
	}
	if !failBody.isError() {
		t.Error("isError() should be true when the shape states success:false")
	}
}

func TestRM273GatewayBodyIsNeverMisdetectedAsHookShape(t *testing.T) {
	dir := t.TempDir()
	raw := marshalBody(t, gatewayBody{
		Tool: "Bash", ToolUseID: "toolu_gw1", Input: json.RawMessage(`{"command":"echo hi"}`),
		ResultObserved: true, Result: json.RawMessage(`"hi\n"`), IsError: false,
	})
	digest := writeBodyFile(t, dir, "run-x", raw)

	body, ok := stepBody(dir, "run-x", digest)
	if !ok {
		t.Fatal("a well-formed gateway body must be available")
	}
	if body.hookShape {
		t.Error("a genuine gateway body must never classify as hook-shape")
	}
	out := outcomeOf("Bash", body)
	if out.Kind != "ok" || out.ExitCode == nil || *out.ExitCode != 0 {
		t.Errorf("outcomeOf(gateway body) = %+v, want unchanged ok/0 behaviour", out)
	}
}

func TestRM273HookResultTextEdgeCases(t *testing.T) {
	if got := hookResultText("Bash", nil); got != "" {
		t.Errorf("hookResultText(nil) = %q, want empty", got)
	}
	if got := hookResultText("Bash", json.RawMessage(`null`)); got != "" {
		t.Errorf("hookResultText(null) = %q, want empty", got)
	}
	if got := hookResultText("Bash", json.RawMessage(`{"stdout":"","stderr":"boom"}`)); got != "boom" {
		t.Errorf("hookResultText(stderr only) = %q, want \"boom\"", got)
	}
	if got := hookResultText("Bash", json.RawMessage(`{"stdout":"out","stderr":"err"}`)); got != "out\nerr" {
		t.Errorf("hookResultText(stdout+stderr) = %q, want \"out\\nerr\"", got)
	}
	// Not valid JSON at all: hookResultText is never handed bytes like this
	// through the real stepBody pipeline (isHookBody's own probe already
	// requires valid JSON), but it must still answer the raw bytes rather
	// than panic or silently drop them.
	if got := hookResultText("Other", json.RawMessage(`not json`)); got != "not json" {
		t.Errorf("hookResultText(invalid json) = %q, want the raw bytes verbatim", got)
	}
}

func TestRM273HookOutcomeOfEdgeCases(t *testing.T) {
	if out := hookOutcomeOf("Bash", nil); out.Kind != "unknown" {
		t.Errorf("hookOutcomeOf(nil) = %+v, want unknown", out)
	}
	if out := hookOutcomeOf("Bash", json.RawMessage(`null`)); out.Kind != "unknown" {
		t.Errorf("hookOutcomeOf(null) = %+v, want unknown", out)
	}
	// Structured, but none of the recognised success markers: a tool this
	// mapping does not specifically understand must answer unknown, never a
	// guessed ok or failed.
	out := hookOutcomeOf("SomeOtherTool", json.RawMessage(`{"message":"did a thing"}`))
	if out.Kind != "unknown" {
		t.Errorf("hookOutcomeOf(unrecognised shape) = %+v, want unknown", out)
	}
}

func TestRM273IsHookBodyDetection(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{"PostToolUse event name", `{"hook_event_name":"PostToolUse","tool_name":"Bash"}`, true},
		{"tool_name alone", `{"tool_name":"Edit"}`, true},
		{"tool_response alone", `{"tool_response":{"stdout":"x"}}`, true},
		{"gateway shape", `{"tool":"Bash","tool_use_id":"x","result_observed":true}`, false},
		{"malformed json", `not json`, false},
		{"empty object", `{}`, false},
	}
	for _, c := range cases {
		if got := isHookBody([]byte(c.raw)); got != c.want {
			t.Errorf("%s: isHookBody = %v, want %v", c.name, got, c.want)
		}
	}
}

// fmtHookBody fills hookBodyEnvelope with a scenario's own tool name, input
// and response, so each test above states only what it is actually
// asserting on rather than the harness's own unrelated bookkeeping.
func fmtHookBody(t *testing.T, toolUseID, toolName, input, response string) string {
	t.Helper()
	return fmt.Sprintf(hookBodyEnvelope, toolUseID, toolName, input, response)
}

// TestStepBodyIsCachedAndStillCatchesAChangedFile — #442. Stored bodies are
// content-addressed, so a parsed, verified body can be reused; the cache is
// keyed on the file's size and modification time as well, so a body changed
// or removed after it was cached is read and checked again, never served.
func TestStepBodyIsCachedAndStillCatchesAChangedFile(t *testing.T) {
	dir := t.TempDir()
	raw := marshalBody(t, gatewayBody{Tool: "Bash", ToolUseID: "toolu_cache1", Input: json.RawMessage(`{"command":"true"}`)})
	digest := writeRunBody(t, dir, "run-cache", raw)

	before := bodyFileReads.Load()
	for i := 0; i < 3; i++ {
		if _, ok := stepBody(dir, "run-cache", digest); !ok {
			t.Fatal("a stored, matching body must be available")
		}
	}
	if got := bodyFileReads.Load() - before; got != 1 {
		t.Errorf("three reads of one unchanged body opened the file %d times, want 1", got)
	}

	path := filepath.Join(dir, "run-cache", strings.TrimPrefix(digest, "sha256:")+".json")
	if err := os.WriteFile(path, append(raw, ' '), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := stepBody(dir, "run-cache", digest); ok {
		t.Error("a body changed after it was cached was still served")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, ok := stepBody(dir, "run-cache", digest); ok {
		t.Error("a body removed after it was cached was still served")
	}
}
