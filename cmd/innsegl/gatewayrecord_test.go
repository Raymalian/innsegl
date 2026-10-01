// SPDX-License-Identifier: Apache-2.0

package main

// gatewayrecord_test.go — #381 (RM-236), E16. Doc 07 TC-GREC: GREC-001,
// GREC-002, GREC-003, GREC-004 and GREC-007, each end to end through the
// REAL, production openGateway — the same real listener, real HTTP round
// trips and real Postgres this file's own sibling
// gatewayidentity_test.go already drives, extended here with
// observe_tool_call configured on the SAME chain (mcp.ConfigureObserveToolCall),
// which is what lets internal/mcp/gatewayrecord.go's RecordGatewayToolCall
// actually append anything when internal/gateway/record.go's own
// ToolCallRecorder calls it.
//
// This file reuses gatewayidentity_test.go's own fixture and helpers —
// newGWIdentityFixture, gwIdentityPool, configureGWIdentityWorkspace,
// startGWIdentityGateway, queryGWIdentityMapping — rather than building a
// second one; the only thing this issue's own tests add on top is
// observe_tool_call's own configuration and a fake upstream that streams
// tool_use blocks and reads tool_result blocks back, which no existing
// fixture needed before.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/rundir"
)

// ---------------------------------------------------------------------------
// Wiring observe_tool_call onto the SAME real chain gatewayidentity_test.go's
// own fixture already opened.
// ---------------------------------------------------------------------------

// configureGRECObserveToolCall configures observe_tool_call on f's own
// chain — the SAME database register_agent and retire_agent are already
// wired onto (newGWIdentityFixture) — and returns the body-store directory
// it was given, so a test can read a recorded body straight off disk.
func configureGRECObserveToolCall(t *testing.T, f *gwIdentityFixture) (bodyDir string) {
	t.Helper()
	pool := gwIdentityPool(t, f.dsn)
	idem := mcp.NewIdempotencyStore(pool)
	dir, err := rundir.New(rundir.Config{Events: f.store})
	if err != nil {
		t.Fatalf("rundir.New: %v", err)
	}
	bodyDir = t.TempDir()
	restore, err := mcp.ConfigureObserveToolCall(mcp.ObserveToolCallConfig{
		Runs: dir, Ledger: f.store, Idempotency: idem, BodyDir: bodyDir,
	})
	if err != nil {
		t.Fatalf("ConfigureObserveToolCall: %v", err)
	}
	t.Cleanup(restore)
	return bodyDir
}

// grecBodyPath is observe_tool_call's own ported layout (observe.go): one
// directory per run, one file per digest, the digest's hex as the file
// name.
func grecBodyPath(bodyDir, runID, digest string) string {
	return filepath.Join(bodyDir, runID, strings.TrimPrefix(digest, event.HashPrefix)+".json")
}

// ---------------------------------------------------------------------------
// A conversation, grown one turn at a time — the shape Claude Code itself
// sends: every request carries the WHOLE history, never a delta.
// ---------------------------------------------------------------------------

type grecBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text,omitempty"`
	ID        string          `json:"id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
	ToolUseID string          `json:"tool_use_id,omitempty"`
	Content   json.RawMessage `json:"content,omitempty"`
	IsError   bool            `json:"is_error,omitempty"`
}

type grecMessage struct {
	Role    string      `json:"role"`
	Content []grecBlock `json:"content"`
}

type grecConversation struct {
	messages []grecMessage
}

func (c *grecConversation) addUserBrief(t *testing.T, workdir, brief string) {
	t.Helper()
	// The directory is stated in the prose too, as the harness does; the
	// gateway ignores it and reads stateGatewayDirectory's statement.
	text := "<system-reminder>\n# Environment\nPrimary working directory: " + workdir +
		"\n</system-reminder>\n\n" + brief
	c.messages = append(c.messages, grecMessage{Role: "user", Content: []grecBlock{{Type: "text", Text: text}}})
}

func (c *grecConversation) addAssistantToolUses(uses ...grecBlock) {
	c.messages = append(c.messages, grecMessage{Role: "assistant", Content: uses})
}

func (c *grecConversation) addUserToolResults(results ...grecBlock) {
	c.messages = append(c.messages, grecMessage{Role: "user", Content: results})
}

func (c *grecConversation) body(t *testing.T) string {
	t.Helper()
	b, err := json.Marshal(struct {
		Messages []grecMessage `json:"messages"`
	}{Messages: c.messages})
	if err != nil {
		t.Fatalf("marshal conversation: %v", err)
	}
	return string(b)
}

func grecToolUse(t *testing.T, id, name string, input any) grecBlock {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshal tool_use input: %v", err)
	}
	return grecBlock{Type: "tool_use", ID: id, Name: name, Input: raw}
}

func grecToolResult(t *testing.T, toolUseID string, content any, isError bool) grecBlock {
	t.Helper()
	raw, err := json.Marshal(content)
	if err != nil {
		t.Fatalf("marshal tool_result content: %v", err)
	}
	return grecBlock{Type: "tool_result", ToolUseID: toolUseID, Content: raw, IsError: isError}
}

// ---------------------------------------------------------------------------
// Sending a request through the real gateway, and a fake upstream that
// streams whatever SSE content a test hands it, one canned reply per hit.
// ---------------------------------------------------------------------------

// sendAndDrainGREC sends body through the real gateway at addr, over https
// using client (gatewayTrustingClient's own return from
// startGWIdentityGateway, the one client in each test that trusts THAT
// gateway's own CA, RM-246 #391), and reads its reply to completion,
// closing the response itself rather than handing it back — the same
// single-function send-then-close shape gatewayidentity_test.go's own
// sendAndDrainGWIdentityMessage already uses, so a streamed reply's own
// content_block_stop events have already been processed by the server
// side, synchronously, before this call returns.
func sendAndDrainGREC(t *testing.T, addr string, client *http.Client, sessionID, body string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		"https://"+addr+"/v1/messages", strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	req.Header.Set("X-Claude-Code-Session-Id", sessionID)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request through the gateway: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatalf("drain response: %v", err)
	}
}

// writeGRECToolUseSSE writes one complete content_block_start/delta/stop
// triple per tool_use in uses, in order, flushing after every event — the
// minimal recorded shape sse.go's own messagesInterpreter reads
// (writeGWIdentitySSEToolUse's own sibling, generalised to any number of
// blocks and any tool name/input rather than one hard-coded Agent spawn).
func writeGRECToolUseSSE(t *testing.T, w http.ResponseWriter, uses ...grecBlock) {
	t.Helper()
	flusher, ok := w.(http.Flusher)
	if !ok {
		t.Fatal("upstream: ResponseWriter is not a Flusher")
	}
	write := func(event, data string) {
		if _, err := io.WriteString(w, "event: "+event+"\ndata: "+data+"\n\n"); err != nil {
			t.Errorf("write SSE event %q: %v", event, err)
		}
		flusher.Flush()
	}
	for i, u := range uses {
		write("content_block_start", fmt.Sprintf(
			`{"type":"content_block_start","index":%d,"content_block":{"type":"tool_use","id":%q,"name":%q,"input":{}}}`,
			i, u.ID, u.Name))
		partial, err := json.Marshal(string(u.Input))
		if err != nil {
			t.Fatalf("marshal partial_json: %v", err)
		}
		write("content_block_delta", fmt.Sprintf(
			`{"type":"content_block_delta","index":%d,"delta":{"type":"input_json_delta","partial_json":%s}}`,
			i, partial))
		write("content_block_stop", fmt.Sprintf(`{"type":"content_block_stop","index":%d}`, i))
	}
}

// writeGRECTextSSE writes one complete text content block — the shape a
// final, tool-free reply takes.
func writeGRECTextSSE(t *testing.T, w http.ResponseWriter, text string) {
	t.Helper()
	flusher, ok := w.(http.Flusher)
	if !ok {
		t.Fatal("upstream: ResponseWriter is not a Flusher")
	}
	write := func(event, data string) {
		if _, err := io.WriteString(w, "event: "+event+"\ndata: "+data+"\n\n"); err != nil {
			t.Errorf("write SSE event %q: %v", event, err)
		}
		flusher.Flush()
	}
	write("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`)
	textJSON, err := json.Marshal(text)
	if err != nil {
		t.Fatalf("marshal text: %v", err)
	}
	write("content_block_delta", fmt.Sprintf(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":%s}}`, textJSON))
	write("content_block_stop", `{"type":"content_block_stop","index":0}`)
}

// newGRECUpstream serves one canned reply per request, in order — replies
// beyond len(replies) get an empty 200 (no further tool_use, no further
// text): a harmless default for a test that stops caring what the
// upstream says once its own assertions are done.
func newGRECUpstream(t *testing.T, replies ...func(t *testing.T, w http.ResponseWriter)) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	hit := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		idx := hit
		hit++
		mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		if idx < len(replies) {
			replies[idx](t, w)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// ---------------------------------------------------------------------------
// Reading the recorded state back.
// ---------------------------------------------------------------------------

// waitForToolCallEvents polls f's own chain until runID carries at least
// want tool_call events, or fails t after ten seconds — recording is
// always asynchronous (record.go's own doc comment, "witness, never a
// gate"), so every assertion below waits for it this way rather than
// assuming a drained response means the recording behind it has already
// landed.
func waitForToolCallEvents(t *testing.T, f *gwIdentityFixture, runID string, want int) []event.Fields {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		recs, err := f.store.EventsForRun(ctx, runID)
		cancel()
		if err != nil {
			t.Fatalf("EventsForRun(%q): %v", runID, err)
		}
		var calls []event.Fields
		for _, r := range recs {
			if r[event.FieldEventType] == event.EventTypeToolCall {
				calls = append(calls, r)
			}
		}
		if len(calls) >= want {
			return calls
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d tool_call events on run %q; got %d: %+v",
				want, runID, len(calls), calls)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// assertToolCallEventCountStaysAt polls f's own chain, once every 20ms, for
// the whole of window, failing t IMMEDIATELY the moment more than want
// tool_call events are found on runID — the deterministic replacement for
// a fixed time.Sleep(...) followed by one look at the end: a
// wrongly-fired recording (GREC-004's own resend case) is caught the
// instant this poll observes it landing in Postgres, whenever that is
// inside window, rather than however long after a blind sleep happened to
// run before the single check that followed it. The correct case still
// has to run out the whole window — there is no way to prove an absence
// over a real, asynchronous round trip any sooner than that — but a buggy
// one fails as soon as it is observed, never later than window would have
// let it anyway.
func assertToolCallEventCountStaysAt(t *testing.T, f *gwIdentityFixture, runID string, want int, window time.Duration) {
	t.Helper()
	deadline := time.Now().Add(window)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		recs, err := f.store.EventsForRun(ctx, runID)
		cancel()
		if err != nil {
			t.Fatalf("EventsForRun(%q): %v", runID, err)
		}
		count := 0
		for _, r := range recs {
			if r[event.FieldEventType] == event.EventTypeToolCall {
				count++
			}
		}
		if count > want {
			t.Fatalf("%d tool_call events after a pure resend, want still exactly %d", count, want)
		}
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func grecRunID(t *testing.T, dsn, sessionID string) string {
	t.Helper()
	m := queryGWIdentityMapping(t, dsn, sessionID, "main")
	if !m.found {
		t.Fatalf("no mapping row for session %q's root agent", sessionID)
	}
	return m.runID
}

// ---------------------------------------------------------------------------
// GREC-001, GREC-002, GREC-004: a tool call and its result — success,
// failure and refusal — each becomes its own tool_call, and a repeated
// history grows the ledger only on genuinely new turns.
// ---------------------------------------------------------------------------

func TestGREC001GREC002GREC004EndToEndThroughRealOpenGateway(t *testing.T) {
	f := newGWIdentityFixture(t)
	bodyDir := configureGRECObserveToolCall(t, f)
	_, repo := configureGWIdentityWorkspace(t)

	upstream := newGRECUpstream(t,
		// Hit 0 (request 1's reply): three tool calls in one turn.
		func(t *testing.T, w http.ResponseWriter) {
			writeGRECToolUseSSE(t, w,
				grecToolUse(t, "toolu_ok", "Read", map[string]string{"file_path": "/w/a.go"}),
				grecToolUse(t, "toolu_fail", "Bash", map[string]string{"command": "go test ./..."}),
				grecToolUse(t, "toolu_refused", "Bash", map[string]string{"command": "rm -rf /"}),
			)
		},
		// Hit 1 (request 2's reply): one more tool call, its own result not
		// sent until request 4.
		func(t *testing.T, w http.ResponseWriter) {
			writeGRECToolUseSSE(t, w, grecToolUse(t, "toolu_extra", "Write", map[string]string{"file_path": "/w/b.go"}))
		},
		// Hit 2 (request 3's reply, a pure resend of request 2's own
		// history): nothing new.
		func(t *testing.T, w http.ResponseWriter) { writeGRECTextSSE(t, w, "still thinking") },
		// Hit 3 (request 4's reply): done.
		func(t *testing.T, w http.ResponseWriter) { writeGRECTextSSE(t, w, "done") },
	)

	addr, client, stop := startGWIdentityGateway(t, f.dsn, upstream.URL, upstream.Client())
	defer stop()

	const session = "d5a6a1a0-0000-4000-8000-0000000003ec"
	conv := &grecConversation{}
	conv.addUserBrief(t, repo, "please clean up the repository")
	stateGatewayDirectory(t, addr, client, session, "", repo)

	// Request 1: registers the run; the reply carries three tool_use
	// blocks this recorder now holds pending.
	sendAndDrainGREC(t, addr, client, session, conv.body(t))
	runID := grecRunID(t, f.dsn, session)

	// Request 2: carries the three results — success, failure, refusal.
	conv.addAssistantToolUses(
		grecToolUse(t, "toolu_ok", "Read", map[string]string{"file_path": "/w/a.go"}),
		grecToolUse(t, "toolu_fail", "Bash", map[string]string{"command": "go test ./..."}),
		grecToolUse(t, "toolu_refused", "Bash", map[string]string{"command": "rm -rf /"}),
	)
	conv.addUserToolResults(
		grecToolResult(t, "toolu_ok", map[string]string{"content": "package a"}, false),
		grecToolResult(t, "toolu_fail", map[string]string{"stderr": "FAIL"}, true),
		grecToolResult(t, "toolu_refused", map[string]string{"stderr": "permission denied by policy"}, true),
	)
	sendAndDrainGREC(t, addr, client, session, conv.body(t))

	calls := waitForToolCallEvents(t, f, runID, 3)
	if got := len(calls); got != 3 {
		t.Fatalf("%d tool_call events after request 2, want exactly 3: %+v", got, calls)
	}

	// GREC-001/GREC-002: each recorded call's own body, read back off the
	// SAME body store observe_tool_call already writes to, carries the
	// tool name, its input, its result and is_error, and the digest names
	// exactly those bytes.
	byTool := map[string]event.Fields{}
	for _, c := range calls {
		byTool[fmt.Sprint(c[event.FieldToolName])] = c
	}
	assertRecordedBody := func(tool, wantSubstring string, wantIsError bool) {
		c, ok := byTool[tool]
		if !ok {
			t.Fatalf("no tool_call recorded for tool %q; recorded tools: %v", tool, byTool)
		}
		digest, ok := c[event.FieldPayloadDigest].(string)
		if !ok || digest == "" {
			t.Fatalf("tool_call for %q carries no payload_digest: %+v", tool, c)
		}
		raw, err := os.ReadFile(grecBodyPath(bodyDir, runID, digest))
		if err != nil {
			t.Fatalf("reading the stored body for %q: %v", tool, err)
		}
		if !strings.Contains(string(raw), wantSubstring) {
			t.Errorf("stored body for %q = %q, want it to contain %q", tool, raw, wantSubstring)
		}
		var decoded map[string]any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatalf("stored body for %q is not JSON: %v", tool, err)
		}
		gotIsError, present := decoded["is_error"].(bool)
		if !present {
			gotIsError = false // absent means false, matching json's own omitempty
		}
		if gotIsError != wantIsError {
			t.Errorf("stored body for %q has is_error = %v, want %v", tool, decoded["is_error"], wantIsError)
		}
	}
	assertRecordedBody("Read", "package a", false)

	// toolu_fail and toolu_refused are BOTH named "Bash" (ADR-0021's
	// tool_name is the tool invoked, not a made-up per-call label), so
	// byTool's own one-row-per-tool-name map cannot tell them apart --
	// checked instead by CONTENT, over every Bash call this request
	// produced, in whatever order recording's own asynchronous goroutines
	// happened to land them (record.go's own doc comment: recording is
	// never ordered relative to another pair's).
	var sawFail, sawRefused int
	for _, c := range calls {
		if c[event.FieldToolName] != "Bash" {
			continue
		}
		digest, ok := c[event.FieldPayloadDigest].(string)
		if !ok {
			t.Fatalf("a Bash tool_call carries no payload_digest: %+v", c)
		}
		raw, err := os.ReadFile(grecBodyPath(bodyDir, runID, digest))
		if err != nil {
			t.Fatalf("reading a Bash call's stored body: %v", err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatalf("a Bash call's stored body is not JSON: %v", err)
		}
		if decoded["is_error"] != true {
			t.Errorf("a Bash call's is_error = %v, want true (both toolu_fail and toolu_refused are errors)",
				decoded["is_error"])
		}
		switch {
		case strings.Contains(string(raw), "FAIL"):
			sawFail++
		case strings.Contains(string(raw), "permission denied by policy"):
			sawRefused++
		}
	}
	if sawFail != 1 || sawRefused != 1 {
		t.Errorf("saw %d failed and %d refused Bash calls, want exactly one each", sawFail, sawRefused)
	}

	// GREC-004, part one: request 3 resends request 2's own history,
	// unchanged — no result in it is new, so nothing more is recorded.
	sendAndDrainGREC(t, addr, client, session, conv.body(t))
	assertToolCallEventCountStaysAt(t, f, runID, 3, 200*time.Millisecond)

	// GREC-004, part two: request 4 carries a genuinely new result — the
	// ledger grows by exactly one more.
	conv.addAssistantToolUses(grecToolUse(t, "toolu_extra", "Write", map[string]string{"file_path": "/w/b.go"}))
	conv.addUserToolResults(grecToolResult(t, "toolu_extra", map[string]bool{"success": true}, false))
	sendAndDrainGREC(t, addr, client, session, conv.body(t))

	final := waitForToolCallEvents(t, f, runID, 4)
	if got := len(final); got != 4 {
		t.Fatalf("%d tool_call events after a new turn, want exactly 4: %+v", got, final)
	}
	var sawExtra bool
	for _, c := range final {
		if c[event.FieldToolName] == "Write" {
			sawExtra = true
		}
	}
	if !sawExtra {
		t.Error("no tool_call recorded for the new Write call")
	}
}

// ---------------------------------------------------------------------------
// GREC-003: the tool_call carries workspace_tree_hash from the snapshot
// witness, and it changes as the working tree changes.
// ---------------------------------------------------------------------------

func TestGREC003EndToEndTheToolCallCarriesTheWorkspaceTreeHashThroughRealOpenGateway(t *testing.T) {
	f := newGWIdentityFixture(t)
	bodyDir := configureGRECObserveToolCall(t, f)
	projects, repo := configureGWIdentityWorkspace(t)

	// Both roots the production Snapshotter defaults its own ProjectRoots
	// to (mcp.ProjectMountRoots) when cmd/innsegl/gateway.go's own
	// newGatewaySnapshotter builds it -- this is what lets this test's
	// working tree actually be snapshottable at all.
	t.Setenv(mcp.EnvHostProjects, projects)
	// The SAME body-store volume observe_tool_call is configured onto
	// (envObserveBodyDir), so newGatewaySnapshotter finds a store root to
	// build the snapshot store under.
	t.Setenv(envObserveBodyDir, bodyDir)

	upstream := newGRECUpstream(t,
		func(t *testing.T, w http.ResponseWriter) {
			writeGRECToolUseSSE(t, w, grecToolUse(t, "toolu_snap1", "Write", map[string]string{"file_path": "b.go"}))
		},
		func(t *testing.T, w http.ResponseWriter) {
			writeGRECToolUseSSE(t, w, grecToolUse(t, "toolu_snap2", "Write", map[string]string{"file_path": "c.go"}))
		},
		func(t *testing.T, w http.ResponseWriter) { writeGRECTextSSE(t, w, "done") },
	)

	addr, client, stop := startGWIdentityGateway(t, f.dsn, upstream.URL, upstream.Client())
	defer stop()

	const session = "d5a6a1a0-0000-4000-8000-0000000003ee"
	conv := &grecConversation{}
	conv.addUserBrief(t, repo, "write two files")
	stateGatewayDirectory(t, addr, client, session, "", repo)
	sendAndDrainGREC(t, addr, client, session, conv.body(t))
	runID := grecRunID(t, f.dsn, session)

	// Between the tool_use being observed and its result reaching the
	// gateway, the file it names is actually written -- this is the tree
	// state the snapshot taken "before this request is forwarded"
	// (ADR-0060 decision 5) must capture.
	if err := os.WriteFile(filepath.Join(repo, "b.go"), []byte("package a\n"), 0o644); err != nil {
		t.Fatalf("writing b.go: %v", err)
	}

	conv.addAssistantToolUses(grecToolUse(t, "toolu_snap1", "Write", map[string]string{"file_path": "b.go"}))
	conv.addUserToolResults(grecToolResult(t, "toolu_snap1", map[string]bool{"success": true}, false))
	sendAndDrainGREC(t, addr, client, session, conv.body(t))
	first := waitForToolCallEvents(t, f, runID, 1)

	firstHash, ok := first[0][event.FieldWorkspaceTreeHash].(string)
	if !ok || firstHash == "" {
		t.Fatalf("tool_call carries no workspace_tree_hash: %+v", first[0])
	}
	if len(firstHash) != 40 {
		t.Errorf("workspace_tree_hash %q is not a 40-hex git object id", firstHash)
	}

	// A second change, a second tool call: the snapshot must move.
	if err := os.WriteFile(filepath.Join(repo, "c.go"), []byte("package a\n\nvar x = 1\n"), 0o644); err != nil {
		t.Fatalf("writing c.go: %v", err)
	}
	conv.addAssistantToolUses(grecToolUse(t, "toolu_snap2", "Write", map[string]string{"file_path": "c.go"}))
	conv.addUserToolResults(grecToolResult(t, "toolu_snap2", map[string]bool{"success": true}, false))
	sendAndDrainGREC(t, addr, client, session, conv.body(t))
	second := waitForToolCallEvents(t, f, runID, 2)

	var secondHash string
	for _, c := range second {
		if c[event.FieldToolName] == "Write" {
			if h, hok := c[event.FieldWorkspaceTreeHash].(string); hok && h != firstHash {
				secondHash = h
			}
		}
	}
	if secondHash == "" {
		t.Fatal("no second tool_call carries a workspace_tree_hash different from the first")
	}
	if len(secondHash) != 40 {
		t.Errorf("second workspace_tree_hash %q is not a 40-hex git object id", secondHash)
	}
}

// ---------------------------------------------------------------------------
// GREC-007: a result over the size bound is recorded with the truncation
// stated, never as partial content presented as complete.
// ---------------------------------------------------------------------------

func TestGREC007EndToEndATruncatedResultIsRecordedWithTheTruncationStatedThroughRealOpenGateway(t *testing.T) {
	f := newGWIdentityFixture(t)
	bodyDir := configureGRECObserveToolCall(t, f)
	_, repo := configureGWIdentityWorkspace(t)

	upstream := newGRECUpstream(t, func(t *testing.T, w http.ResponseWriter) {
		writeGRECToolUseSSE(t, w, grecToolUse(t, "toolu_huge", "Bash", map[string]string{"command": "cat huge.log"}))
	})
	addr, client, stop := startGWIdentityGateway(t, f.dsn, upstream.URL, upstream.Client())
	defer stop()

	const session = "d5a6a1a0-0000-4000-8000-0000000003ef"
	conv := &grecConversation{}
	conv.addUserBrief(t, repo, "cat the huge log")
	stateGatewayDirectory(t, addr, client, session, "", repo)
	sendAndDrainGREC(t, addr, client, session, conv.body(t))
	runID := grecRunID(t, f.dsn, session)

	// One byte over this package's own maxToolResultContentBytes bound
	// (record.go), well under this test process's own memory budget.
	huge := strings.Repeat("a", 8<<20+1)

	conv.addAssistantToolUses(grecToolUse(t, "toolu_huge", "Bash", map[string]string{"command": "cat huge.log"}))
	conv.addUserToolResults(grecToolResult(t, "toolu_huge", map[string]string{"stdout": huge}, false))
	sendAndDrainGREC(t, addr, client, session, conv.body(t))

	calls := waitForToolCallEvents(t, f, runID, 1)
	digest, ok := calls[0][event.FieldPayloadDigest].(string)
	if !ok || digest == "" {
		t.Fatalf("tool_call carries no payload_digest: %+v", calls[0])
	}
	raw, err := os.ReadFile(grecBodyPath(bodyDir, runID, digest))
	if err != nil {
		t.Fatalf("reading the stored body: %v", err)
	}
	if len(raw) > 1<<20 {
		t.Errorf("stored body is %d bytes, want it bounded rather than carrying the full result", len(raw))
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("stored body is not JSON: %v", err)
	}
	if decoded["result_truncated"] != true {
		t.Errorf("result_truncated = %v, want true", decoded["result_truncated"])
	}
	if strings.Contains(string(raw), huge) {
		t.Error("the stored body carries the full, untruncated result")
	}
}
