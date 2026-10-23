// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"innsegl.dev/innsegl/internal/mcp"
)

const responsesBody = `{"input":[{"role":"developer","content":[{"type":"input_text","text":"context"}]},{"role":"user","content":[{"type":"input_text","text":"inspect files"}]},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"checking"}]},{"type":"custom_tool_call_output","call_id":"call_exec1","output":"exit code 1"},{"type":"function_call_output","call_id":"call_fn1","output":"done"}]}`

func responseRequest(body []byte) *http.Request {
	return httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/backend-api/codex/responses", bytes.NewReader(body))
}

type responsesOrderWriter struct {
	http.ResponseWriter
	seen *bool
	bad  bool
}

func (w *responsesOrderWriter) Write(p []byte) (int, error) {
	if !*w.seen {
		w.bad = true
	}
	return w.ResponseWriter.Write(p)
}

func (w *responsesOrderWriter) Flush() {}

// OAI-006: the observed parent spawn must be registered before the child
// request can reach the core and pass its independent-parent guard.
func TestOAI006ResponsesObservesSpawnBeforeForwardingReply(t *testing.T) {
	seen := false
	p := &Proxy{ToolUse: ToolUseObserverFunc(func(call ToolUse) {
		if call.ID == "call_spawn" {
			seen = true
		}
	})}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/responses", nil)
	r.Header.Set("Content-Type", "text/event-stream")
	resp := &http.Response{
		Header: http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:   io.NopCloser(strings.NewReader("data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"function_call\",\"call_id\":\"call_spawn\",\"name\":\"collaboration.spawn_agent\",\"arguments\":\"{\\\"task_name\\\":\\\"child\\\",\\\"message\\\":\\\"task\\\"}\"}}\n\n")),
	}
	base := httptest.NewRecorder()
	w := &responsesOrderWriter{ResponseWriter: base, seen: &seen}
	p.stream(w, r, resp)
	if w.bad || !seen {
		t.Fatalf("reply forwarded before spawn observation completed: bad=%v seen=%v", w.bad, seen)
	}
}

// OAI-001/004: decoding is observation only, including repeated consumers.
func TestOAI001ResponsesFactsPreserveCompressedWireBytes(t *testing.T) {
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer encoder.Close()
	wire := encoder.EncodeAll([]byte(responsesBody), nil)
	r := responseRequest(wire)
	r.Header.Set("Content-Encoding", "zstd")
	facts := ExtractRequestFacts(r)
	if facts.Brief != "inspect files" || len(facts.FirstAssistant) == 0 || strings.Join(facts.ToolResultIDs, ",") != "call_exec1,call_fn1" {
		t.Fatalf("facts: %+v", facts)
	}
	results := extractToolResults(r)
	if len(results) != 2 || results[0].ToolUseID != "call_exec1" {
		t.Fatalf("results: %+v", results)
	}
	if texts := extractAssistantTexts(r); len(texts) != 1 || texts[0] != "checking" {
		t.Fatalf("texts: %v", texts)
	}
	got, err := io.ReadAll(r.Body)
	if err != nil || !bytes.Equal(got, wire) {
		t.Fatal("changed forwarded compressed request")
	}
	if r.Header.Get("Content-Encoding") != "zstd" {
		t.Fatal("changed encoding header")
	}
}

// OAI-004: output text is not an authoritative success/error flag.
func TestOAI004ResponsesResultRecordsUnknownOutcome(t *testing.T) {
	r := responseRequest([]byte(responsesBody))
	results := extractToolResults(r)
	if len(results) != 2 {
		t.Fatalf("got %d results", len(results))
	}
	body := buildToolCallBody("call_exec1", pendingCall{tool: "exec", input: json.RawMessage(`{"script":"x"}`)}, &results[0])
	var record map[string]any
	if err := json.Unmarshal(body, &record); err != nil {
		t.Fatal(err)
	}
	if record["error_signal"] != "unknown" {
		t.Fatalf("fabricated known outcome: %s", body)
	}
}

// OAI-003/017: observe complete calls before stream completion, once only;
// custom input is free text, not necessarily JSON.
func TestOAI003ResponsesStreamObservesCallsAndCompletedText(t *testing.T) {
	var calls []ToolUse
	p := &Proxy{ToolUse: ToolUseObserverFunc(func(c ToolUse) { calls = append(calls, c) })}
	r := responseRequest(nil)
	observer := p.replyObserver(r, "text/event-stream")
	if observer == nil {
		t.Fatal("no observer")
	}
	events := []string{
		`{"type":"response.output_item.done","item":{"type":"custom_tool_call","call_id":"call_exec1","name":"exec","input":"const x = 1;"}}`,
		`{"type":"response.output_item.done","item":{"type":"function_call","call_id":"call_fn1","name":"read","arguments":"{\"file\":\"a\"}"}}`,
	}
	for _, e := range events {
		for _, b := range []byte("data: " + e + "\n\n") {
			if _, err := observer.Write([]byte{b}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(calls) != 2 || calls[0].ID != "call_exec1" || calls[0].Name != "exec" || !json.Valid(calls[0].Input) {
		t.Fatalf("calls: %+v", calls)
	}
	discardWriteError(observer.Write([]byte("data: " + events[0] + "\n\n")))
	if len(calls) != 2 {
		t.Fatal("duplicate call observed")
	}
}

// OAI-008: a Messages body on a Responses route is not interpreted as Messages.
func TestOAI008ResponsesRouteDoesNotSniffMessagesBody(t *testing.T) {
	r := responseRequest([]byte(`{"messages":[{"role":"user","content":"wrong format"}]}`))
	if got := ExtractRequestFacts(r); got.Brief != "" {
		t.Fatalf("cross-format facts: %+v", got)
	}
}

// OAI-002: unreadable requests are explicit gaps, not complete capture;
// the forwarded request is retained byte for byte for the approved path.
func TestOAI002UnreadableRequestIsAnExplicitCaptureGap(t *testing.T) {
	for _, encoding := range []string{"zstd", "gzip", "identity"} {
		t.Run(encoding, func(t *testing.T) {
			raw := []byte(`{"messages":[]}`)
			if encoding == "zstd" {
				raw = []byte("bad zstd frame")
			}
			r := responseRequest(raw)
			r.Header.Set("Content-Encoding", encoding)
			_ = ExtractRequestFacts(r)
			if observationProblem(r.Context()) == "" {
				t.Fatal("missing capture gap")
			}
			ctx := WithRunID(r.Context(), "run-test")
			if got := recordedValue(ctx); got != "false" {
				t.Fatalf("capture marked %q", got)
			}
			got, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, raw) {
				t.Fatal("changed original request")
			}
		})
	}
}

// OAI-005: the CLI's standalone environment context is not the task brief.
func TestOAI005CodexEnvironmentContextIsNotTheBrief(t *testing.T) {
	r := responseRequest([]byte(`{"input":[{"role":"user","content":[{"type":"input_text","text":"<environment_context>\n<cwd>/workspace</cwd>\n</environment_context>"}]},{"role":"user","content":[{"type":"input_text","text":"inspect files"}]}]}`))
	if got := ExtractRequestFacts(r).Brief; got != "inspect files" {
		t.Fatalf("brief=%q", got)
	}
}

// OAI-004: exercise reply observation and next-request pairing through the
// same recorder used by production, without claiming identity-service proof.
func TestOAI004ResponsesReplayPairsCallWithNextRequest(t *testing.T) {
	recorded := make(chan mcp.GatewayToolCallInput, 1)
	recorder := NewToolCallRecorder(ToolCallRecorderConfig{record: func(_ context.Context, in mcp.GatewayToolCallInput) (mcp.GatewayToolCallOutput, error) {
		recorded <- in
		return mcp.GatewayToolCallOutput{}, nil
	}})
	proxy := &Proxy{ToolUse: recorder, Guards: []Guard{NewToolCallRecordGuard(recorder)}}
	r := responseRequest([]byte(`{"input":"qa"}`))
	r = r.WithContext(WithRunID(r.Context(), "run-test"))
	proxy.Replay(r, "text/plain; charset=utf-8", []byte("data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"custom_tool_call\",\"name\":\"exec\",\"call_id\":\"call_qa\",\"input\":\"text(await tools.exec_command({cmd: 'exit 7'}))\"}}\n\n"))
	if recorder.PendingCount() != 1 {
		t.Fatalf("pending=%d", recorder.PendingCount())
	}
	r = responseRequest([]byte(`{"input":[{"type":"custom_tool_call_output","call_id":"call_qa","output":"exit code 7"}]}`))
	r = r.WithContext(WithRunID(r.Context(), "run-test"))
	proxy.Replay(r, "text/event-stream", nil)
	select {
	case in := <-recorded:
		if in.Tool != "exec" || !bytes.Contains(in.Body, []byte(`"error_signal":"unknown"`)) {
			t.Fatalf("record: %s", in.Body)
		}
	case <-time.After(time.Second):
		t.Fatal("result not paired")
	}
}

func TestOAI003PlainStreamExceptionIsLimitedToBackendRoute(t *testing.T) {
	p := &Proxy{ToolUse: ToolUseObserverFunc(func(ToolUse) {})}
	for _, path := range []string{"/v1/messages", "/v1/responses", "/backend-api/codex/responses/extra"} {
		r := responseRequest(nil)
		r.URL.Path = path
		if p.replyObserver(r, "text/plain; charset=utf-8") != nil {
			t.Errorf("plaintext exception reached %s", path)
		}
	}
}

// OAI-003: the backend can omit Content-Type entirely. HTTP forwarding can
// then add text/plain, so replaying only the downstream MIME misses this case.
func TestOAI003BackendStreamWithMissingMIMEStillObservesCalls(t *testing.T) {
	event := "data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"custom_tool_call\",\"name\":\"exec\",\"call_id\":\"call_qa\",\"input\":\"text(1)\"}}\n\n"
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header()["Content-Type"] = nil // suppress the server's automatic MIME sniffing
		discardWriteError(io.WriteString(w, event))
	}))
	defer provider.Close()
	up, err := NewUpstream(provider.URL, provider.Client())
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	p := &Proxy{Upstream: up, Guards: []Guard{}, ToolUse: ToolUseObserverFunc(func(ToolUse) { calls++ })}
	w := httptest.NewRecorder()
	p.ServeHTTP(w, responseRequest([]byte(`{"input":"qa"}`)))
	if w.Code != http.StatusOK || w.Body.String() != event {
		t.Fatal("forwarded stream changed")
	}
	if calls != 1 {
		t.Fatalf("calls=%d", calls)
	}
	for _, path := range []string{"/v1/messages", "/v1/responses"} {
		r := responseRequest(nil)
		r.URL.Path = path
		if p.replyObserver(r, "") != nil {
			t.Fatalf("missing MIME accepted on %s", path)
		}
	}
}
