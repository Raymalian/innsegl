// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/event"
)

// GID-006 (docs/07-innsegl-test-catalog.md, TC-GID): request facts are read
// once per request, bounded; brief, first assistant turn, working
// directory and tool result ids extracted from a recorded shape.

// loadModelRequestBodyFixture returns the synthetic-but-realistic Claude
// Code 2.1 request body fixture this file owns
// (testdata/harness/claude-code-2.1/model-request-body.json), and the
// assistant content array it embeds, decoded, for computing an
// independently-derived expectation.
func loadModelRequestBodyFixture(t *testing.T) (raw []byte, assistantContent any) {
	t.Helper()
	raw, err := os.ReadFile("testdata/harness/claude-code-2.1/bodies/model-request-body.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	var decoded struct {
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decoding fixture: %v", err)
	}
	for _, m := range decoded.Messages {
		if m.Role != "assistant" {
			continue
		}
		if err := json.Unmarshal(m.Content, &assistantContent); err != nil {
			t.Fatalf("decoding fixture's assistant content: %v", err)
		}
		return raw, assistantContent
	}
	t.Fatal("fixture has no assistant message")
	return nil, nil
}

func newFactsRequest(t *testing.T, body []byte) *http.Request {
	t.Helper()
	return httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/messages", strings.NewReader(string(body)))
}

// TestExtractRequestFactsFromFixture drives ExtractRequestFacts against
// this file's own recorded-shape fixture and checks every field the
// contract names: Brief (reminders stripped), WorkingDirectory (read from
// inside the reminder), FirstAssistant (canonically encoded) and
// ToolResultIDs.
func TestExtractRequestFactsFromFixture(t *testing.T) {
	raw, assistantContent := loadModelRequestBodyFixture(t)
	req := newFactsRequest(t, raw)

	facts := ExtractRequestFacts(req)

	const wantBrief = "Fix the failing test in pkg/widget."
	if facts.Brief != wantBrief {
		t.Errorf("Brief = %q, want %q", facts.Brief, wantBrief)
	}

	const wantDir = "/workspace/example-repo"
	if facts.WorkingDirectory != wantDir {
		t.Errorf("WorkingDirectory = %q, want %q", facts.WorkingDirectory, wantDir)
	}

	wantAssistant, err := event.Canonicalize(assistantContent)
	if err != nil {
		t.Fatalf("computing expected canonical form: %v", err)
	}
	if string(facts.FirstAssistant) != string(wantAssistant) {
		t.Errorf("FirstAssistant = %s, want %s", facts.FirstAssistant, wantAssistant)
	}

	wantToolResultIDs := []string{"toolu_01ExampleTool"}
	if len(facts.ToolResultIDs) != len(wantToolResultIDs) || facts.ToolResultIDs[0] != wantToolResultIDs[0] {
		t.Errorf("ToolResultIDs = %v, want %v", facts.ToolResultIDs, wantToolResultIDs)
	}
}

// TestExtractRequestFactsEmptyFirstAssistantBeforeAnyAssistantTurn: an
// agent's very first request has no assistant turn yet, so FirstAssistant
// must be empty rather than some canonicalisation of nothing.
func TestExtractRequestFactsEmptyFirstAssistantBeforeAnyAssistantTurn(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}]}`)
	facts := ExtractRequestFacts(newFactsRequest(t, body))
	if len(facts.FirstAssistant) != 0 {
		t.Fatalf("FirstAssistant = %q, want empty: no assistant turn exists yet", facts.FirstAssistant)
	}
}

// TestExtractRequestFactsRestoresBodyForForwarding: whatever this
// extractor read, the request's body still reads back byte for byte
// afterward -- GW-001's contract extended to a component that now sits
// ahead of the proxy's own forwarding.
func TestExtractRequestFactsRestoresBodyForForwarding(t *testing.T) {
	raw, _ := loadModelRequestBodyFixture(t)
	req := newFactsRequest(t, raw)

	_ = ExtractRequestFacts(req)

	got, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("reading restored body: %v", err)
	}
	if string(got) != string(raw) {
		t.Fatalf("restored body differs from the original\noriginal: %s\nrestored: %s", raw, got)
	}
}

// TestExtractRequestFactsOverCapLeavesFactsEmptyButForwards: a body past
// maxRequestFactsBodyBytes yields an entirely empty RequestFacts -- never a
// partial guess -- and the request still forwards with its body intact.
// The identity guard, not this extractor, decides what happens to a
// request with no usable facts.
func TestExtractRequestFactsOverCapLeavesFactsEmptyButForwards(t *testing.T) {
	// The valid, complete, parseable JSON document comes FIRST, followed by
	// enough trailing whitespace to push the body's total size past the
	// cap. encoding/json tolerates trailing whitespace after a complete top
	// -level value, so the first maxRequestFactsBodyBytes+1 bytes this
	// extractor ever reads decode successfully on their own -- proving that
	// an empty RequestFacts here comes from the cap itself, never from a
	// truncated, unparseable fragment (which a naive over-sized-body test
	// cannot tell apart from the cap doing its job).
	validJSON := `{"messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}]}`
	padding := strings.Repeat(" ", maxRequestFactsBodyBytes+1024)
	body := []byte(validJSON + padding)
	req := newFactsRequest(t, body)

	facts := ExtractRequestFacts(req)
	if facts.Brief != "" || facts.WorkingDirectory != "" || facts.FirstAssistant != nil || facts.ToolResultIDs != nil {
		t.Fatalf("facts over the cap must be entirely empty, got %+v", facts)
	}

	got, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("reading restored body: %v", err)
	}
	if len(got) != len(body) {
		t.Fatalf("restored body length = %d, want %d", len(got), len(body))
	}
	if string(got) != string(body) {
		t.Fatal("restored body over the cap does not match the original byte for byte")
	}
}

// TestRequestFactsGuardAttachesFactsToContext: the Guard never refuses, and
// hands the next Guard or observer facts through the context, the same
// pattern harness.go's HarnessGuard already uses for Identification.
func TestRequestFactsGuardAttachesFactsToContext(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}]}`)
	req := newFactsRequest(t, body)

	guard := NewRequestFactsGuard()
	next, refusal := guard.Check(req)
	if refusal != nil {
		t.Fatalf("RequestFactsGuard refused: %+v", refusal)
	}
	if next == nil {
		t.Fatal("RequestFactsGuard returned a nil request with no refusal")
	}

	facts, ok := RequestFactsFromContext(next.Context())
	if !ok {
		t.Fatal("no RequestFacts attached to the returned request's context")
	}
	if facts.Brief != "hello" {
		t.Fatalf("Brief = %q, want %q", facts.Brief, "hello")
	}

	got, err := io.ReadAll(next.Body)
	if err != nil || string(got) != string(body) {
		t.Fatalf("restored body mismatch: err=%v got=%q want=%q", err, got, body)
	}
}

// TestWithRequestFactsRoundTrip and TestRequestFactsFromContextAbsent cover
// the context helpers directly.
func TestWithRequestFactsRoundTrip(t *testing.T) {
	facts := RequestFacts{Brief: "b", WorkingDirectory: "/workspace/x", ToolResultIDs: []string{"a"}}
	ctx := WithRequestFacts(context.Background(), facts)
	got, ok := RequestFactsFromContext(ctx)
	if !ok {
		t.Fatal("RequestFactsFromContext found nothing")
	}
	if got.Brief != facts.Brief || got.WorkingDirectory != facts.WorkingDirectory {
		t.Fatalf("got %+v, want %+v", got, facts)
	}
}

func TestRequestFactsFromContextAbsent(t *testing.T) {
	if _, ok := RequestFactsFromContext(context.Background()); ok {
		t.Fatal("RequestFactsFromContext found something on a bare context")
	}
}

// TestComputeFingerprintEmptyWithoutAssistantTurn: Fingerprint's own doc
// comment (lifecycle_contract.go) -- "empty until the conversation has a
// first assistant turn".
func TestComputeFingerprintEmptyWithoutAssistantTurn(t *testing.T) {
	facts := RequestFacts{Brief: "hello"}
	if fp := ComputeFingerprint(facts); fp != "" {
		t.Fatalf("Fingerprint = %q, want empty with no assistant turn yet", fp)
	}
}

// TestExtractRequestFactsMalformedBodyLeavesFactsEmpty: a body that is not
// JSON at all -- well under the cap -- yields entirely empty facts, the
// same "drop what cannot be parsed" posture as the over-cap case, and the
// body still restores byte for byte.
func TestExtractRequestFactsMalformedBodyLeavesFactsEmpty(t *testing.T) {
	body := []byte("this is not json")
	req := newFactsRequest(t, body)

	facts := ExtractRequestFacts(req)
	if facts.Brief != "" || facts.WorkingDirectory != "" || facts.FirstAssistant != nil || facts.ToolResultIDs != nil {
		t.Fatalf("malformed body should yield entirely empty facts, got %+v", facts)
	}

	got, err := io.ReadAll(req.Body)
	if err != nil || string(got) != string(body) {
		t.Fatalf("restored body mismatch: err=%v got=%q want=%q", err, got, body)
	}
}

// TestExtractRequestFactsMalformedContentIsSkipped: a user message whose
// content is neither a string nor a content-block array is skipped rather
// than guessed at, leaving Brief and WorkingDirectory empty.
func TestExtractRequestFactsMalformedContentIsSkipped(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":42}]}`)
	facts := ExtractRequestFacts(newFactsRequest(t, body))
	if facts.Brief != "" || facts.WorkingDirectory != "" {
		t.Fatalf("malformed content should leave Brief/WorkingDirectory empty, got %+v", facts)
	}
}

// TestExtractRequestFactsAssistantMessageWithNoContentLeavesFirstAssistantEmpty:
// an assistant message with no content field at all (a real shape, not
// only a malformed one -- a stop-reason-only turn) leaves FirstAssistant
// empty rather than the canonical encoding of nothing.
func TestExtractRequestFactsAssistantMessageWithNoContentLeavesFirstAssistantEmpty(t *testing.T) {
	body := []byte(`{"messages":[
		{"role":"user","content":[{"type":"text","text":"hi"}]},
		{"role":"assistant"}
	]}`)
	facts := ExtractRequestFacts(newFactsRequest(t, body))
	if len(facts.FirstAssistant) != 0 {
		t.Fatalf("FirstAssistant = %q, want empty for an assistant message with no content field", facts.FirstAssistant)
	}
}

// TestStripSystemRemindersDropsUnterminatedBlock: an opening
// <system-reminder> tag with no matching close is dropped along with
// everything after it, never guessed at.
func TestStripSystemRemindersDropsUnterminatedBlock(t *testing.T) {
	got := stripSystemReminders("keep this <system-reminder>never closes")
	if want := "keep this"; got != want {
		t.Fatalf("stripSystemReminders(...) = %q, want %q", got, want)
	}
}

// spyCloser records whether Close was called on it.
type spyCloser struct{ closed bool }

func (s *spyCloser) Close() error { s.closed = true; return nil }

// TestRestoredBodyCloseDelegatesToOriginal: restoredBody.Close must close
// the ORIGINAL body, not be a no-op -- otherwise the connection a request
// arrived on is never released.
func TestRestoredBodyCloseDelegatesToOriginal(t *testing.T) {
	spy := &spyCloser{}
	rb := &restoredBody{Reader: strings.NewReader(""), closer: spy}
	if err := rb.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !spy.closed {
		t.Fatal("restoredBody.Close did not delegate to the original closer")
	}
}

// TestComputeFingerprintDeterministicAndSplitSensitive: the same facts
// fingerprint identically every time, and two DIFFERENT (Brief,
// FirstAssistant) splits of the SAME concatenated bytes must not collide --
// the reason ComputeFingerprint length-prefixes each part.
func TestComputeFingerprintDeterministicAndSplitSensitive(t *testing.T) {
	facts := RequestFacts{Brief: "hello", FirstAssistant: []byte(`{"a":1}`)}

	fp := ComputeFingerprint(facts)
	if fp == "" {
		t.Fatal("Fingerprint is empty despite a first assistant turn")
	}
	if fp2 := ComputeFingerprint(facts); fp2 != fp {
		t.Fatalf("Fingerprint is not deterministic: %q vs %q", fp, fp2)
	}

	// "hel"+"lo"+`{"a":1}` concatenates to the exact same bytes as
	// "hello"+`{"a":1}` above, split differently between the two fields.
	split := RequestFacts{Brief: "hel", FirstAssistant: []byte(`lo{"a":1}`)}
	if fpSplit := ComputeFingerprint(split); fpSplit == fp {
		t.Fatal("Fingerprint collided across a different split of the same concatenated bytes")
	}
}

// TestRequestFactsReadTheRealClaudeCode2_1Shape holds the shape measured from
// Claude Code 2.1.283's own first request on 2026-09-29 (a live run through
// the gateway was refused because this was read wrongly): the first user
// message carries several system-reminder blocks and then the prompt as its
// last block, and the environment statement naming the working directory
// arrives in a SEPARATE message whose role is "system", after it. Paths are
// synthetic; the structure is the measured one.
func TestRequestFactsReadTheRealClaudeCode2_1Shape(t *testing.T) {
	body := `{"model":"m","messages":[
	  {"role":"user","content":[
	    {"type":"text","text":"<system-reminder>\nCodebase and user instructions are shown below.\n</system-reminder>"},
	    {"type":"text","text":"<system-reminder>\nAs you answer the user's questions, you can use the following context.\n</system-reminder>"},
	    {"type":"text","text":"<system-reminder>\nThe following skills are available.\n</system-reminder>"},
	    {"type":"text","text":"Run this shell command: echo PROBE-SUB\n\nReport back the exact output."}
	  ]},
	  {"role":"system","content":[
	    {"type":"text","text":"<system-reminder>\n# Environment\nYou have been invoked in the following environment: \n - Primary working directory: /workspace/example-repo\n - Is a git repository: true\n</system-reminder>"}
	  ]}
	]}`
	facts := parseRequestFacts([]byte(body))
	if facts.WorkingDirectory != "/workspace/example-repo" {
		t.Errorf("WorkingDirectory = %q, want the one the system-role environment message states", facts.WorkingDirectory)
	}
	if want := "Run this shell command: echo PROBE-SUB\n\nReport back the exact output."; facts.Brief != want {
		t.Errorf("Brief = %q, want %q (the prompt block, reminders stripped)", facts.Brief, want)
	}
}

// TestRequestFactsIgnoreAWorkingDirectoryStatedAfterTheFirstAssistantTurn
// keeps the scan to the conversation's opening: a directory named later (for
// example inside a tool result) never becomes the agent's workspace.
func TestRequestFactsIgnoreAWorkingDirectoryStatedAfterTheFirstAssistantTurn(t *testing.T) {
	body := `{"messages":[
	  {"role":"user","content":[{"type":"text","text":"do the thing"}]},
	  {"role":"assistant","content":[{"type":"text","text":"ok"}]},
	  {"role":"user","content":[{"type":"text","text":" - Primary working directory: /workspace/elsewhere"}]}
	]}`
	if got := parseRequestFacts([]byte(body)).WorkingDirectory; got != "" {
		t.Fatalf("WorkingDirectory = %q, want empty: a later message must not name the workspace", got)
	}
}
