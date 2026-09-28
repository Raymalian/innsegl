// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/mcp"
)

// messages_test.go — RM-237 (#382), E16 (#358). Doc 07 TC-GREC:
//
//	GREC-004 (I, shared with #381) Only new turns are recorded.
//	GREC-005 (I) An agent's brief and its own text.
//
// This file's own half of both: MessageRecorder's claim bookkeeping and its
// extraction of assistant text out of a request's resent history. The
// actual recording call (a body-store write and a keyed ledger append) is
// internal/mcp/agentmessage_test.go's own GREC-005; here that call is a
// fake, because what this package is answerable for is WHICH brief and
// WHICH turns it decides to dispatch, and how many times — never whether
// internal/mcp can append an event, which it cannot fake its way past.

// ---------------------------------------------------------------------------
// Fixture.
// ---------------------------------------------------------------------------

type fakeAgentMessageCall struct {
	runID, role string
	body        []byte
}

// fakeAgentMessageRecorder is AgentMessageRecorder, plus a channel a test
// can wait on: MessageRecorder.dispatch runs on its own goroutine
// deliberately (this file's own doc comment on why), so a test that wants
// to assert what was recorded has to wait for it rather than read
// immediately after Check returns.
type fakeAgentMessageRecorder struct {
	mu    sync.Mutex
	calls []fakeAgentMessageCall
	done  chan struct{}
	err   error
}

func newFakeAgentMessageRecorder() *fakeAgentMessageRecorder {
	return &fakeAgentMessageRecorder{done: make(chan struct{}, 4096)}
}

func (f *fakeAgentMessageRecorder) RecordAgentMessage(_ context.Context, runID, role string, body []byte) (string, error) {
	f.mu.Lock()
	f.calls = append(f.calls, fakeAgentMessageCall{runID, role, append([]byte(nil), body...)})
	err := f.err
	f.mu.Unlock()
	f.done <- struct{}{}
	if err != nil {
		return "", err
	}
	return "fake-digest", nil
}

// waitForCalls blocks until n dispatches have completed (in either order —
// dispatch is concurrent by design), or fails the test after timeout.
func (f *fakeAgentMessageRecorder) waitForCalls(t *testing.T, n int, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for i := 0; i < n; i++ {
		select {
		case <-f.done:
		case <-deadline:
			t.Fatalf("timed out waiting for dispatched call %d/%d (got %d so far)", i+1, n, len(f.snapshot()))
		}
	}
}

func (f *fakeAgentMessageRecorder) snapshot() []fakeAgentMessageCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeAgentMessageCall(nil), f.calls...)
}

const msgWaitTimeout = 5 * time.Second

var _ AgentMessageRecorder = (*fakeAgentMessageRecorder)(nil)

// contentBlock is the Anthropic Messages content block shape facts.go's own
// rawContentBlock already decodes; kept minimal here to exactly what this
// test needs to build a request body with.
type contentBlock struct {
	Type  string          `json:"type"`
	Text  string          `json:"text,omitempty"`
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`
}

type historyMessage struct {
	Role    string         `json:"role"`
	Content []contentBlock `json:"content"`
}

// historyRequest builds a POST request whose body is an Anthropic Messages
// request carrying brief (the first user message, or none if empty) and one
// assistant message per entry of assistantTurns — a pure tool_use block
// (no text at all) for an empty string, a text block otherwise. This is the
// resent-history shape Claude Code sends on every request (facts.go's own
// doc comment); extractAssistantTexts reads it a second time, independent
// of whatever RequestFacts already carries.
func historyRequest(t *testing.T, brief string, assistantTurns []string) *http.Request {
	t.Helper()
	var messages []historyMessage
	if brief != "" {
		messages = append(messages, historyMessage{
			Role: "user", Content: []contentBlock{{Type: "text", Text: brief}},
		})
	}
	for _, turn := range assistantTurns {
		if turn == "" {
			messages = append(messages, historyMessage{
				Role: "assistant",
				Content: []contentBlock{{
					Type: "tool_use", ID: "toolu_01", Name: "Bash", Input: json.RawMessage(`{"command":"ls"}`),
				}},
			})
			continue
		}
		messages = append(messages, historyMessage{
			Role: "assistant", Content: []contentBlock{{Type: "text", Text: turn}},
		})
	}
	buf, err := json.Marshal(map[string]any{"messages": messages})
	if err != nil {
		t.Fatalf("marshalling the fixture request body: %v", err)
	}
	return httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/messages", bytes.NewReader(buf))
}

// withIdentity attaches runID (and, when facts.Brief is non-empty or this
// call is explicitly asked to, RequestFacts) to r's context, the same shape
// identity.go's own IdentityGuard.Check leaves behind for every request it
// permits.
func withIdentity(r *http.Request, runID string, facts RequestFacts, haveFacts bool) *http.Request {
	ctx := r.Context()
	if haveFacts {
		ctx = WithRequestFacts(ctx, facts)
	}
	ctx = WithRunID(ctx, runID)
	return r.WithContext(ctx)
}

// ---------------------------------------------------------------------------
// extractAssistantTexts.
// ---------------------------------------------------------------------------

func TestExtractAssistantTextsReadsEveryAssistantTurnInOrder(t *testing.T) {
	req := historyRequest(t, "fix the bug", []string{"looked into it", "", "fixed and tested"})
	texts := extractAssistantTexts(req)
	want := []string{"looked into it", "", "fixed and tested"}
	if len(texts) != len(want) {
		t.Fatalf("got %d texts %q, want %d %q", len(texts), texts, len(want), want)
	}
	for i := range want {
		if texts[i] != want[i] {
			t.Errorf("turn %d: got %q, want %q", i, texts[i], want[i])
		}
	}
}

func TestExtractAssistantTextsIgnoresNonAssistantRoles(t *testing.T) {
	req := historyRequest(t, "the brief", []string{"one reply"})
	texts := extractAssistantTexts(req)
	if len(texts) != 1 || texts[0] != "one reply" {
		t.Fatalf("got %q, want exactly one turn, %q", texts, "one reply")
	}
}

// TestExtractAssistantTextsRestoresTheBody: GW-001's byte-for-byte contract
// — reading the body for this Guard's own purposes must never consume it
// for whatever forwards the request afterwards.
func TestExtractAssistantTextsRestoresTheBody(t *testing.T) {
	req := historyRequest(t, "the brief", []string{"a reply"})
	original, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("reading the fixture body once to capture it: %v", err)
	}
	req.Body = io.NopCloser(bytes.NewReader(original))

	_ = extractAssistantTexts(req)

	after, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("reading the body after extraction: %v", err)
	}
	if !bytes.Equal(after, original) {
		t.Errorf("the body changed: got %d bytes, want the original %d bytes", len(after), len(original))
	}
}

func TestExtractAssistantTextsOnANilBodyIsEmpty(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.Body = nil
	if texts := extractAssistantTexts(req); texts != nil {
		t.Errorf("got %v, want nil for a request with no body", texts)
	}
}

func TestExtractAssistantTextsOnMalformedJSONIsEmpty(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/messages", bytes.NewReader([]byte("not json")))
	if texts := extractAssistantTexts(req); texts != nil {
		t.Errorf("got %v, want nil for a body that is not JSON", texts)
	}
}

// ---------------------------------------------------------------------------
// The bounded claim table.
// ---------------------------------------------------------------------------

func TestClaimBriefIsTrueOnlyOncePerRun(t *testing.T) {
	rec, err := NewMessageRecorder(MessageRecorderConfig{Recorder: newFakeAgentMessageRecorder()})
	if err != nil {
		t.Fatalf("NewMessageRecorder: %v", err)
	}
	if !rec.claimBrief("run-a") {
		t.Error("the first claim for a run must succeed")
	}
	if rec.claimBrief("run-a") {
		t.Error("a second claim for the same run must not succeed")
	}
	if !rec.claimBrief("run-b") {
		t.Error("the first claim for a DIFFERENT run must succeed")
	}
}

func TestClaimNewAssistantTurnsSkipsEmptyTextButStillCountsIt(t *testing.T) {
	rec, err := NewMessageRecorder(MessageRecorderConfig{Recorder: newFakeAgentMessageRecorder()})
	if err != nil {
		t.Fatalf("NewMessageRecorder: %v", err)
	}
	// Turn 0 is pure tool_use (empty text), turn 1 has text.
	req := historyRequest(t, "", []string{"", "hello"})

	got := rec.claimNewAssistantTurns("run-a", req)
	if len(got) != 2 || got[0] != "" || got[1] != "hello" {
		t.Fatalf("first claim: got %q, want [\"\" \"hello\"]", got)
	}

	// The SAME two turns again (a resent, unchanged history): both already
	// claimed, so nothing new comes back.
	if got := rec.claimNewAssistantTurns("run-a", historyRequest(t, "", []string{"", "hello"})); len(got) != 0 {
		t.Errorf("a replay of the same history returned %q, want none", got)
	}

	// A third turn appears: only it is new.
	if got := rec.claimNewAssistantTurns("run-a", historyRequest(t, "", []string{"", "hello", "goodbye"})); len(got) != 1 || got[0] != "goodbye" {
		t.Errorf("got %q, want exactly the one new turn %q", got, "goodbye")
	}
}

func TestNewMessageRecorderRefusesANilRecorder(t *testing.T) {
	_, err := NewMessageRecorder(MessageRecorderConfig{})
	if err == nil {
		t.Fatal("NewMessageRecorder accepted a configuration with no AgentMessageRecorder")
	}
}

// TestMessageRecorderTableEvictsTheOldestRunFirst: bounded memory — a table
// asked to track more runs than its CacheSize forgets the oldest one, the
// same insertion-order rule identity.go's own identityCache already uses.
// This is not a correctness gap for MessageRecorder's own callers (see
// messages.go's doc comment); it is what THIS file asserts as the bound
// actually holding.
func TestMessageRecorderTableEvictsTheOldestRunFirst(t *testing.T) {
	rec, err := NewMessageRecorder(MessageRecorderConfig{
		Recorder: newFakeAgentMessageRecorder(), CacheSize: 2,
	})
	if err != nil {
		t.Fatalf("NewMessageRecorder: %v", err)
	}
	rec.claimBrief("run-1")
	rec.claimBrief("run-2")
	rec.claimBrief("run-3") // over CacheSize=2: evicts run-1's entry, the oldest

	// run-2 and run-3 are still tracked: neither's brief is claimable again.
	if rec.claimBrief("run-2") {
		t.Error("run-2's tracking entry should still be present (not the oldest)")
	}
	if rec.claimBrief("run-3") {
		t.Error("run-3's tracking entry should still be present (just inserted)")
	}
	// run-1's entry was evicted, so a run this process is still actually
	// serving (a harness retried, or the run resumed) has its brief
	// dispatched again rather than silently skipped forever — the
	// "redundant call, never a duplicate event" trade this file's own doc
	// comment describes, made safe by internal/mcp's own idempotency key.
	if !rec.claimBrief("run-1") {
		t.Error("run-1's tracking entry should have been evicted, so its brief is claimable again")
	}
}

// ---------------------------------------------------------------------------
// MessageRecorder.Check — the Guard.
// ---------------------------------------------------------------------------

func TestMessageRecorderNeverRefuses(t *testing.T) {
	fake := newFakeAgentMessageRecorder()
	fake.err = errors.New("the recorder is unavailable")
	rec, err := NewMessageRecorder(MessageRecorderConfig{Recorder: fake})
	if err != nil {
		t.Fatalf("NewMessageRecorder: %v", err)
	}

	req := withIdentity(historyRequest(t, "the brief", nil), "run-1", RequestFacts{Brief: "the brief"}, true)
	out, refusal := rec.Check(req)
	if refusal != nil {
		t.Fatalf("Check refused: %+v", refusal)
	}
	if out == nil {
		t.Fatal("Check returned a nil request")
	}
	fake.waitForCalls(t, 1, msgWaitTimeout)
}

func TestMessageRecorderDoesNothingWithoutAResolvedRunID(t *testing.T) {
	fake := newFakeAgentMessageRecorder()
	rec, err := NewMessageRecorder(MessageRecorderConfig{Recorder: fake})
	if err != nil {
		t.Fatalf("NewMessageRecorder: %v", err)
	}

	req := historyRequest(t, "the brief", []string{"a reply"}) // no WithRunID at all
	out, refusal := rec.Check(req)
	if refusal != nil {
		t.Fatalf("Check refused: %+v", refusal)
	}
	if out != req {
		t.Error("Check must return the SAME request, unchanged, when no run id was resolved")
	}
	select {
	case <-fake.done:
		t.Fatal("a dispatch happened with no resolved run id")
	case <-time.After(200 * time.Millisecond):
	}
}

// TestMessageRecorderRecordsTheBriefOnceAndEachNewAssistantTurn is
// GREC-004's and GREC-005's own case, driven across several requests of one
// growing, resent conversation — exactly how Claude Code's own traffic
// looks (facts.go's doc comment).
func TestMessageRecorderRecordsTheBriefOnceAndEachNewAssistantTurn(t *testing.T) {
	fake := newFakeAgentMessageRecorder()
	rec, err := NewMessageRecorder(MessageRecorderConfig{Recorder: fake})
	if err != nil {
		t.Fatalf("NewMessageRecorder: %v", err)
	}
	const runID = "run-growing"
	const brief = "add a health endpoint"
	facts := RequestFacts{Brief: brief}

	// Request 1: brief only, no assistant turn yet.
	req1 := withIdentity(historyRequest(t, brief, nil), runID, facts, true)
	if _, refusal := rec.Check(req1); refusal != nil {
		t.Fatalf("Check refused: %+v", refusal)
	}
	fake.waitForCalls(t, 1, msgWaitTimeout)

	// Request 2: the brief is resent (Claude Code resends the whole
	// history) plus one new assistant turn.
	req2 := withIdentity(historyRequest(t, brief, []string{"added GET /health"}), runID, facts, true)
	if _, refusal := rec.Check(req2); refusal != nil {
		t.Fatalf("Check refused: %+v", refusal)
	}
	fake.waitForCalls(t, 1, msgWaitTimeout)

	// Request 3: brief and turn 1 resent, one MORE new turn.
	req3 := withIdentity(historyRequest(t, brief, []string{"added GET /health", "wrote a test for it"}), runID, facts, true)
	if _, refusal := rec.Check(req3); refusal != nil {
		t.Fatalf("Check refused: %+v", refusal)
	}
	fake.waitForCalls(t, 1, msgWaitTimeout)

	// Request 4: the identical history again (a retried or duplicated
	// request) — nothing new to dispatch.
	req4 := withIdentity(historyRequest(t, brief, []string{"added GET /health", "wrote a test for it"}), runID, facts, true)
	if _, refusal := rec.Check(req4); refusal != nil {
		t.Fatalf("Check refused: %+v", refusal)
	}

	calls := fake.snapshot()
	if len(calls) != 3 {
		t.Fatalf("got %d dispatched calls, want exactly 3: %+v", len(calls), calls)
	}
	var briefs, assistants int
	for _, c := range calls {
		if c.runID != runID {
			t.Errorf("call %+v names run %q, want %q", c, c.runID, runID)
		}
		switch c.role {
		case mcp.AgentMessageRoleBrief:
			briefs++
			if string(c.body) != brief {
				t.Errorf("brief call body is %q, want %q", c.body, brief)
			}
		case mcp.AgentMessageRoleAssistant:
			assistants++
		default:
			t.Errorf("call %+v has an unexpected role", c)
		}
	}
	if briefs != 1 {
		t.Errorf("the brief was dispatched %d times, want exactly 1", briefs)
	}
	if assistants != 2 {
		t.Errorf("%d assistant turns were dispatched, want exactly 2", assistants)
	}

	bodies := map[string]bool{}
	for _, c := range calls {
		if c.role == mcp.AgentMessageRoleAssistant {
			bodies[string(c.body)] = true
		}
	}
	for _, want := range []string{"added GET /health", "wrote a test for it"} {
		if !bodies[want] {
			t.Errorf("assistant turn %q was never dispatched; got %v", want, bodies)
		}
	}
}

// TestMessageRecorderRecordsAssistantTurnsEvenWithoutRequestFacts: the
// brief comes from RequestFacts (this Guard has no other source for it),
// but every assistant turn is read straight off the request body
// (extractAssistantTexts) independent of whether RequestFacts was ever
// attached at all.
func TestMessageRecorderRecordsAssistantTurnsEvenWithoutRequestFacts(t *testing.T) {
	fake := newFakeAgentMessageRecorder()
	rec, err := NewMessageRecorder(MessageRecorderConfig{Recorder: fake})
	if err != nil {
		t.Fatalf("NewMessageRecorder: %v", err)
	}

	req := withIdentity(historyRequest(t, "", []string{"a reply with no facts on the context"}), "run-nofacts", RequestFacts{}, false)
	if _, refusal := rec.Check(req); refusal != nil {
		t.Fatalf("Check refused: %+v", refusal)
	}
	fake.waitForCalls(t, 1, msgWaitTimeout)

	calls := fake.snapshot()
	if len(calls) != 1 || calls[0].role != mcp.AgentMessageRoleAssistant {
		t.Fatalf("got %+v, want exactly one assistant-role call", calls)
	}
}

// TestMessageRecorderSkipsAnEmptyBrief: RequestFacts.Brief is "" on a
// request whose harness sent nothing recognisable as a first user message
// (facts.go's own "empty when absent"); there is nothing to record.
func TestMessageRecorderSkipsAnEmptyBrief(t *testing.T) {
	fake := newFakeAgentMessageRecorder()
	rec, err := NewMessageRecorder(MessageRecorderConfig{Recorder: fake})
	if err != nil {
		t.Fatalf("NewMessageRecorder: %v", err)
	}

	req := withIdentity(historyRequest(t, "", nil), "run-x", RequestFacts{Brief: ""}, true)
	if _, refusal := rec.Check(req); refusal != nil {
		t.Fatalf("Check refused: %+v", refusal)
	}
	select {
	case <-fake.done:
		t.Fatal("a dispatch happened for an empty brief")
	case <-time.After(200 * time.Millisecond):
	}
}

var _ Guard = (*MessageRecorder)(nil)

// TestMessageRecorderCheckSkipsAnEmptyAssistantTurnButRecordsALaterOne
// drives the "text == \"\"" branch through Check itself (rather than
// through claimNewAssistantTurns directly, which
// TestClaimNewAssistantTurnsSkipsEmptyTextButStillCountsIt already does):
// a pure tool_use turn is claimed and never dispatched, and a later turn
// with real text is dispatched on its own.
func TestMessageRecorderCheckSkipsAnEmptyAssistantTurnButRecordsALaterOne(t *testing.T) {
	fake := newFakeAgentMessageRecorder()
	rec, err := NewMessageRecorder(MessageRecorderConfig{Recorder: fake})
	if err != nil {
		t.Fatalf("NewMessageRecorder: %v", err)
	}

	req := withIdentity(historyRequest(t, "", []string{"", "a real reply"}), "run-empty-turn", RequestFacts{}, false)
	if _, refusal := rec.Check(req); refusal != nil {
		t.Fatalf("Check refused: %+v", refusal)
	}
	fake.waitForCalls(t, 1, msgWaitTimeout)

	calls := fake.snapshot()
	if len(calls) != 1 || string(calls[0].body) != "a real reply" {
		t.Fatalf("got %+v, want exactly one dispatched call for the non-empty turn", calls)
	}
}

// ---------------------------------------------------------------------------
// extractAssistantTexts — the two remaining refusal-shaped branches.
// ---------------------------------------------------------------------------

// TestExtractAssistantTextsOnAnOversizedBodyIsEmpty mirrors facts_test.go's
// own TestExtractRequestFactsOverCapLeavesFactsEmptyButForwards technique
// exactly: the complete, valid JSON document comes first, so encoding/json
// would decode the first maxRequestFactsBodyBytes+1 bytes on their own —
// proving an empty result here comes from the bound itself, never from a
// truncated fragment.
func TestExtractAssistantTextsOnAnOversizedBodyIsEmpty(t *testing.T) {
	validJSON := `{"messages":[{"role":"assistant","content":[{"type":"text","text":"hello"}]}]}`
	padding := strings.Repeat(" ", maxRequestFactsBodyBytes+1024)
	body := []byte(validJSON + padding)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/messages", bytes.NewReader(body))

	if texts := extractAssistantTexts(req); texts != nil {
		t.Fatalf("got %v, want nil for a body over the bound", texts)
	}

	got, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("reading the restored body: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Error("the restored body over the bound does not match the original byte for byte")
	}
}

// TestExtractAssistantTextsSkipsAnAssistantMessageWithMalformedContent: an
// assistant message whose content is neither a bare string nor an array of
// blocks (contentBlocks' own "ok is false" case, facts.go) contributes
// nothing and does not stop the rest of the history from being read.
func TestExtractAssistantTextsSkipsAnAssistantMessageWithMalformedContent(t *testing.T) {
	body := `{"messages":[
		{"role":"assistant","content":42},
		{"role":"assistant","content":[{"type":"text","text":"a real turn"}]}
	]}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/messages", bytes.NewReader([]byte(body)))

	texts := extractAssistantTexts(req)
	if len(texts) != 1 || texts[0] != "a real turn" {
		t.Fatalf("got %q, want exactly one turn, %q", texts, "a real turn")
	}
}

// ---------------------------------------------------------------------------
// MCPAgentMessageRecorder — the default AgentMessageRecorder every
// deployment wires.
// ---------------------------------------------------------------------------

// TestMCPAgentMessageRecorderDelegatesToTheInProcessWrapper: no fake here —
// MCPAgentMessageRecorder calls straight into
// mcp.RecordAgentMessageForGateway (agentmessage.go's own doc comment,
// mirrored from MCPRegistrar's identical shape for register_agent). This
// process's internal/mcp package has nothing configured, so the call
// reaches exactly the same "not configured" refusal
// internal/mcp/agentmessage_test.go's own
// TestAgentMessageIsNotServedUntilItIsConfigured measures directly — proof
// that this type is not its own, second implementation of anything.
func TestMCPAgentMessageRecorderDelegatesToTheInProcessWrapper(t *testing.T) {
	rec := NewMCPAgentMessageRecorder()
	_, err := rec.RecordAgentMessage(context.Background(), "run-x", mcp.AgentMessageRoleBrief, []byte("hi"))
	if err == nil {
		t.Fatal("RecordAgentMessage succeeded with internal/mcp's agent-message recorder never configured in this process")
	}
}
