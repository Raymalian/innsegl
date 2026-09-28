// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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
