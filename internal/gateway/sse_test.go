// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// writeSSEEvent writes one SSE event and flushes it immediately, failing
// the test rather than the handler goroutine on a write error.
func writeSSEEvent(t *testing.T, w http.ResponseWriter, flusher http.Flusher, event, data string) {
	t.Helper()
	if _, err := io.WriteString(w, "event: "+event+"\ndata: "+data+"\n\n"); err != nil {
		t.Errorf("write SSE event %q: %v", event, err)
	}
	flusher.Flush()
}

// GW-003: a tool_use content block is available to the observer at its
// content_block_stop event -- before the reply's stream ends, not batched
// up and delivered once it has been read to completion. The fixture below
// is recorded-shape: two tool_use blocks, the first with its input split
// across two input_json_delta fragments.
func TestGW003ToolUseBlocksAvailableAtContentBlockStopBeforeStreamEnd(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("upstream: ResponseWriter is not a Flusher")
		}
		write := func(event, data string) { writeSSEEvent(t, w, flusher, event, data) }

		write("message_start", `{"type":"message_start"}`)

		write("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`)
		write("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"looking that up"}}`)
		write("content_block_stop", `{"type":"content_block_stop","index":0}`)

		// Tool call 1: its input arrives fragmented across two deltas.
		write("content_block_start", `{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_01A","name":"get_weather","input":{}}}`)
		write("content_block_delta", `{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"location\": \"San Fra"}}`)
		write("content_block_delta", `{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"ncisco\"}"}}`)
		write("content_block_stop", `{"type":"content_block_stop","index":1}`)

		// Held open here: nothing further is sent until the test releases
		// it. The observer must already have the first tool call by now.
		<-release

		// Tool call 2: whole input in one delta.
		write("content_block_start", `{"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"toolu_02B","name":"get_time","input":{}}}`)
		write("content_block_delta", `{"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"zone\":\"UTC\"}"}}`)
		write("content_block_stop", `{"type":"content_block_stop","index":2}`)
		write("message_delta", `{"type":"message_delta","delta":{"stop_reason":"tool_use"}}`)
		write("message_stop", `{"type":"message_stop"}`)
	}))
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
		upstream.Close()
	}()

	up, err := NewUpstream(upstream.URL, upstream.Client())
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}

	seen := make(chan ToolUse, 4)
	p := &Proxy{
		Upstream: up,
		ToolUse:  ToolUseObserverFunc(func(tu ToolUse) { seen <- tu }),
	}
	gw := httptest.NewServer(p)
	defer gw.Close()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, gw.URL+"/v1/messages", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	// A recognised harness shape (GW-011's default guard, #374).
	req.Header.Set(headerClaudeCodeSessionID, validSessionID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Drained concurrently so the proxy's own io.Copy keeps making
	// progress: this test is about the OBSERVER's timing, not the client's.
	go func() { discardCopyError(io.Copy(io.Discard, resp.Body)) }()

	var first ToolUse
	select {
	case first = <-seen:
	case <-time.After(5 * time.Second):
		t.Fatal("no tool_use observed within 5s; the upstream is still blocked before the second call")
	}

	if first.ID != "toolu_01A" || first.Name != "get_weather" {
		t.Fatalf("first tool_use = %+v, want id=toolu_01A name=get_weather", first)
	}
	var input map[string]any
	if err := json.Unmarshal(first.Input, &input); err != nil {
		t.Fatalf("first tool_use input %s did not parse: %v", first.Input, err)
	}
	if input["location"] != "San Francisco" {
		t.Fatalf("first tool_use input = %v, want location=San Francisco "+
			"(the fragmented input_json_delta must be reassembled)", input)
	}

	// The upstream is still blocked on <-release: the second tool_use must
	// not have arrived yet.
	select {
	case tu := <-seen:
		t.Fatalf("second tool_use %+v observed before the upstream sent it", tu)
	default:
	}

	close(release)

	select {
	case second := <-seen:
		if second.ID != "toolu_02B" || second.Name != "get_time" {
			t.Fatalf("second tool_use = %+v, want id=toolu_02B name=get_time", second)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second tool_use never observed")
	}
}

// TestSSEScannerIgnoresLeadingBlankLinesAndComments. A blank line with
// nothing accumulated yet, and a comment line (per the spec, one starting
// with ':'), must dispatch nothing.
func TestSSEScannerIgnoresLeadingBlankLinesAndComments(t *testing.T) {
	var dispatched int
	s := newSSEScanner(func(string, string) { dispatched++ })

	s.write([]byte("\n\n:keepalive\n\ndata: hello\n\n"))

	if dispatched != 1 {
		t.Fatalf("dispatched = %d, want 1 (leading blanks and the comment line must not dispatch)", dispatched)
	}
}

// TestSSEScannerHandlesFragmentedWrites pins the scanner's own contract
// directly: an SSE event split across arbitrarily small Write calls -- as
// the network is free to deliver it -- dispatches exactly once, with the
// data field reassembled, and only once the terminating blank line arrives.
func TestSSEScannerHandlesFragmentedWrites(t *testing.T) {
	type got struct{ event, data string }
	var events []got
	s := newSSEScanner(func(event, data string) {
		events = append(events, got{event, data})
	})

	raw := "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n"
	for i := 0; i < len(raw); i++ {
		s.write([]byte{raw[i]})
		if i < len(raw)-1 {
			if len(events) != 0 {
				t.Fatalf("dispatched before the terminating blank line, at byte %d", i)
			}
		}
	}

	if len(events) != 1 {
		t.Fatalf("got %d events, want 1: %+v", len(events), events)
	}
	if events[0].event != "content_block_stop" {
		t.Errorf("event = %q, want content_block_stop", events[0].event)
	}
	if events[0].data != `{"type":"content_block_stop","index":1}` {
		t.Errorf("data = %q", events[0].data)
	}
}

// TestMessagesInterpreterIgnoresMalformedOrUnrelatedEvents pins every early
// return in handleStart/handleDelta/handleStop: malformed JSON, a delta or
// a stop naming an index nothing started, and a delta whose own type is not
// input_json_delta. None of it may panic or produce a spurious observation.
func TestMessagesInterpreterIgnoresMalformedOrUnrelatedEvents(t *testing.T) {
	var seen []ToolUse
	m := newMessagesInterpreter(ToolUseObserverFunc(func(tu ToolUse) { seen = append(seen, tu) }))

	m.handleEvent("content_block_start", "not json")
	m.handleEvent("content_block_delta", "not json")
	m.handleEvent("content_block_stop", "not json")
	m.handleEvent("content_block_delta", `{"index":9,"delta":{"type":"input_json_delta","partial_json":"{}"}}`)
	m.handleEvent("content_block_stop", `{"index":9}`)
	m.handleEvent("message_stop", `{"type":"message_stop"}`)

	m.handleEvent("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_x","name":"x","input":{}}}`)
	m.handleEvent("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"ignored"}}`)
	m.handleEvent("content_block_stop", `{"type":"content_block_stop","index":0}`)

	if len(seen) != 1 {
		t.Fatalf("got %d tool_use blocks, want exactly 1 (empty input defaults to {}): %+v", len(seen), seen)
	}
	if string(seen[0].Input) != "{}" {
		t.Errorf("input = %s, want {} (no input_json_delta arrived for this block)", seen[0].Input)
	}
}

// TestIsEventStream pins the Content-Type match, parameters and all, and
// its failure modes.
func TestIsEventStream(t *testing.T) {
	for _, tc := range []struct {
		contentType string
		want        bool
	}{
		{"text/event-stream", true},
		{"text/event-stream; charset=utf-8", true},
		{"application/json", false},
		{"", false},
		{";;;not a media type", false},
	} {
		if got := isEventStream(tc.contentType); got != tc.want {
			t.Errorf("isEventStream(%q) = %v, want %v", tc.contentType, got, tc.want)
		}
	}
}

// TestMessagesInterpreterDropsAToolUseWhoseInputNeverParses. A malformed
// reassembly must not reach the observer as something it is not, and must
// not panic or otherwise disrupt the interpreter's own state for the next
// content block.
func TestMessagesInterpreterDropsAToolUseWhoseInputNeverParses(t *testing.T) {
	var seen []ToolUse
	m := newMessagesInterpreter(ToolUseObserverFunc(func(tu ToolUse) { seen = append(seen, tu) }))

	events := []struct{ event, data string }{
		{"content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_bad","name":"broken","input":{}}}`},
		{"content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"not json"}}`},
		{"content_block_stop", `{"type":"content_block_stop","index":0}`},
		{"content_block_start", `{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_ok","name":"fine","input":{}}}`},
		{"content_block_delta", `{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"ok\":true}"}}`},
		{"content_block_stop", `{"type":"content_block_stop","index":1}`},
	}
	for _, e := range events {
		m.handleEvent(e.event, e.data)
	}

	if len(seen) != 1 {
		t.Fatalf("got %d tool_use blocks, want 1 (the malformed one dropped, the next one unaffected): %+v", len(seen), seen)
	}
	if seen[0].ID != "toolu_ok" {
		t.Errorf("observed tool_use id = %q, want toolu_ok", seen[0].ID)
	}
}

// TestGW014ToolUseInputBoundedAndReportedTruncated pins the first of
// GW-014's three bounds (#405): a tool_use block whose input_json_delta
// fragments keep arriving without ever reaching a content_block_stop must
// not grow this interpreter's held memory past maxToolUseInputBytes. Past
// that bound the fragments held so far are dropped, not reassembled, and
// the eventual content_block_stop reports the block to the observer as
// truncated rather than guessing at what its input was.
func TestGW014ToolUseInputBoundedAndReportedTruncated(t *testing.T) {
	var seen []ToolUse
	m := newMessagesInterpreter(ToolUseObserverFunc(func(tu ToolUse) { seen = append(seen, tu) }))

	m.handleEvent("content_block_start",
		`{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_big","name":"write_file","input":{}}}`)

	// Fragments well past the bound, a chunk at a time, so the check is
	// exercised on every delta rather than skipped by one huge write.
	chunk := strings.Repeat("a", 64*1024)
	deltaJSON, err := json.Marshal(map[string]any{
		"type": "content_block_delta", "index": 0,
		"delta": map[string]any{"type": "input_json_delta", "partial_json": chunk},
	})
	if err != nil {
		t.Fatalf("marshal delta fixture: %v", err)
	}
	for fed := 0; fed <= maxToolUseInputBytes+len(chunk); fed += len(chunk) {
		m.handleEvent("content_block_delta", string(deltaJSON))

		if got := m.pending[0].input.Len(); got > maxToolUseInputBytes {
			t.Fatalf("pending tool_use input held %d bytes after feeding %d, want <= maxToolUseInputBytes (%d)",
				got, fed+len(chunk), maxToolUseInputBytes)
		}
	}

	m.handleEvent("content_block_stop", `{"type":"content_block_stop","index":0}`)

	if len(seen) != 1 {
		t.Fatalf("got %d tool_use observations, want 1: %+v", len(seen), seen)
	}
	if !seen[0].Truncated {
		t.Fatalf("tool_use %+v not marked Truncated after exceeding maxToolUseInputBytes", seen[0])
	}
	if seen[0].ID != "toolu_big" || seen[0].Name != "write_file" {
		t.Fatalf("truncated tool_use = %+v, want id=toolu_big name=write_file", seen[0])
	}
	if seen[0].Input != nil {
		t.Fatalf("truncated tool_use Input = %q, want nil (never guessed at)", seen[0].Input)
	}
}

// TestGW014ToolUseInputTruncationDoesNotAffectRelayedBytes pins that the
// bound above is enforced only on what this interpreter itself holds: it
// rides alongside the forwarded bytes (see messagesInterpreter's own doc
// comment) and must never make the relay to the caller anything but
// byte-for-byte, however far over maxToolUseInputBytes the reply runs.
func TestGW014ToolUseInputTruncationDoesNotAffectRelayedBytes(t *testing.T) {
	m := newMessagesInterpreter(ToolUseObserverFunc(func(ToolUse) {}))
	var client bytes.Buffer
	dst := io.MultiWriter(&client, m) // client write first, as Proxy.stream constructs it

	var raw bytes.Buffer
	raw.WriteString("event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_big\",\"name\":\"write_file\",\"input\":{}}}\n\n")

	chunk := strings.Repeat("a", 64*1024)
	deltaJSON, err := json.Marshal(map[string]any{
		"type": "content_block_delta", "index": 0,
		"delta": map[string]any{"type": "input_json_delta", "partial_json": chunk},
	})
	if err != nil {
		t.Fatalf("marshal delta fixture: %v", err)
	}
	for fed := 0; fed <= maxToolUseInputBytes+len(chunk); fed += len(chunk) {
		raw.WriteString("event: content_block_delta\ndata: " + string(deltaJSON) + "\n\n")
	}
	raw.WriteString("event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n")

	n, err := dst.Write(raw.Bytes())
	if err != nil {
		t.Fatalf("Write returned an error: %v (the interpreter must never error the MultiWriter)", err)
	}
	if n != raw.Len() {
		t.Fatalf("Write reported n = %d, want %d", n, raw.Len())
	}
	if !bytes.Equal(client.Bytes(), raw.Bytes()) {
		t.Fatalf("relayed bytes differ from what was written: got %d bytes, want %d", client.Len(), raw.Len())
	}
}

// TestGW014SSEScannerLineBounded pins the second of GW-014's three bounds
// (#405): a line that never reaches its terminating '\n' must not grow the
// scanner's buffer past maxSSELineBytes. Past that bound what is held is
// dropped, and the scanner resynchronises at the next event boundary
// rather than treating whatever follows as a continuation of the
// abandoned line.
func TestGW014SSEScannerLineBounded(t *testing.T) {
	type got struct{ event, data string }
	var events []got
	s := newSSEScanner(func(event, data string) {
		events = append(events, got{event, data})
	})

	chunk := bytes.Repeat([]byte("x"), 64*1024) // never a '\n': one line, growing without end
	for fed := 0; fed <= maxSSELineBytes+len(chunk); fed += len(chunk) {
		s.write(chunk)

		if held := len(s.buf); held > maxSSELineBytes {
			t.Fatalf("scanner held %d bytes of one unterminated line after feeding %d, want <= maxSSELineBytes (%d)",
				held, fed+len(chunk), maxSSELineBytes)
		}
	}

	// End the abandoned line, then the blank line that is its event's
	// boundary, then one well-formed event: the scanner must have
	// resynchronised, not stayed stuck discarding everything.
	s.write([]byte("\n\n"))
	s.write([]byte("event: content_block_stop\ndata: {\"index\":9}\n\n"))

	if len(events) != 1 {
		t.Fatalf("got %d events after resynchronising, want 1: %+v", len(events), events)
	}
	if events[0].event != "content_block_stop" {
		t.Errorf("event = %q, want content_block_stop", events[0].event)
	}
	if events[0].data != `{"index":9}` {
		t.Errorf("data = %q, want {\"index\":9}", events[0].data)
	}
}

// TestGW014SSEScannerEventDataBounded pins the third of GW-014's three
// bounds (#405): an event's data: lines accumulating without the blank
// line that ends the event must not grow the scanner's held data past
// maxSSEEventDataBytes. Past that bound what is held is dropped, and the
// scanner resynchronises at the next event boundary rather than
// dispatching a reassembly it knows is incomplete.
func TestGW014SSEScannerEventDataBounded(t *testing.T) {
	type got struct{ event, data string }
	var events []got
	s := newSSEScanner(func(event, data string) {
		events = append(events, got{event, data})
	})

	s.write([]byte("event: content_block_delta\n"))

	// Many complete data: lines, each well under maxSSELineBytes on its
	// own, but never followed by the blank line that would dispatch the
	// event -- this exercises the event-data bound, not the line bound.
	line := []byte("data: " + strings.Repeat("y", 64*1024) + "\n")
	for fed := 0; fed <= maxSSEEventDataBytes+len(line); fed += len(line) {
		s.write(line)

		if held := s.curDataLen; held > maxSSEEventDataBytes {
			t.Fatalf("scanner held %d bytes of one event's data after feeding %d, want <= maxSSEEventDataBytes (%d)",
				held, fed+len(line), maxSSEEventDataBytes)
		}
	}

	s.write([]byte("\n")) // the blank line: nothing to dispatch, the event was abandoned
	if len(events) != 0 {
		t.Fatalf("got %d events dispatched from an abandoned event, want 0: %+v", len(events), events)
	}

	s.write([]byte("event: content_block_stop\ndata: {\"index\":9}\n\n"))
	if len(events) != 1 {
		t.Fatalf("got %d events after resynchronising, want 1: %+v", len(events), events)
	}
	if events[0].event != "content_block_stop" {
		t.Errorf("event = %q, want content_block_stop", events[0].event)
	}
}

// Claude Code 2.1.283 asks for a compressed reply, and an upstream that gets
// that ask compresses its event stream. Relayed as asked, the observer parses
// gzip bytes and sees no tool_use at all: the live test of 2026-09-30 recorded
// every run's brief and not one tool call. The gateway asks upstream for an
// uncompressed reply instead, which every client accepts.
func TestGatewayObservesToolUseWhenTheClientAsksForACompressedReply(t *testing.T) {
	var sawEncoding string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawEncoding = r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Type", "text/event-stream")
		var out io.Writer = w
		if strings.Contains(sawEncoding, "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			zw := gzip.NewWriter(w)
			defer func() { _ = zw.Close() }()
			out = zw
		}
		w.WriteHeader(http.StatusOK)
		if _, err := io.WriteString(out, "event: content_block_start\ndata: "+
			`{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_01A","name":"Bash","input":{}}}`+"\n\n"+
			"event: content_block_delta\ndata: "+
			`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"false\"}"}}`+"\n\n"+
			"event: content_block_stop\ndata: "+`{"type":"content_block_stop","index":0}`+"\n\n"); err != nil {
			t.Errorf("upstream write: %v", err)
		}
	}))
	defer upstream.Close()

	up, err := NewUpstream(upstream.URL, upstream.Client())
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	seen := make(chan ToolUse, 1)
	gw := httptest.NewServer(&Proxy{Upstream: up, ToolUse: ToolUseObserverFunc(func(tu ToolUse) { seen <- tu })})
	defer gw.Close()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, gw.URL+"/v1/messages", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	req.Header.Set(headerClaudeCodeSessionID, validSessionID)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway request: %v", err)
	}
	discardCopyError(io.Copy(io.Discard, resp.Body))
	_ = resp.Body.Close()

	select {
	case tu := <-seen:
		if tu.ID != "toolu_01A" {
			t.Errorf("observed tool_use %q, want toolu_01A", tu.ID)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("no tool_use observed; upstream was asked for Accept-Encoding %q", sawEncoding)
	}
}
