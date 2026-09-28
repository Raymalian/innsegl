// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"strings"
)

// ToolUse is one tool_use content block, observed as soon as its
// content_block_stop event arrives while an Anthropic Messages reply
// streams -- never batched up and delivered once the stream ends.
type ToolUse struct {
	ID   string
	Name string
	// Input is the tool call's input, exactly as the model produced it,
	// reassembled from the reply's input_json_delta events -- which may
	// arrive as a single fragment or split across several. It is always
	// valid JSON; a tool call with no input is "{}", never empty or nil.
	Input json.RawMessage
}

// ToolUseObserver is notified of each ToolUse as it completes. An
// implementation must return quickly: it runs synchronously on the same
// path that is forwarding the reply's bytes to the caller (though strictly
// after they have already been written and flushed -- see Proxy.stream),
// and a slow observer is a slow gateway. A consumer that might block hands
// off to a channel or a goroutine of its own rather than doing the work
// here.
type ToolUseObserver interface {
	OnToolUse(ToolUse)
}

// ToolUseObserverFunc adapts an ordinary func to a ToolUseObserver.
type ToolUseObserverFunc func(ToolUse)

// OnToolUse calls f.
func (f ToolUseObserverFunc) OnToolUse(t ToolUse) { f(t) }

// messagesInterpreter reads a COPY of an Anthropic Messages SSE reply --
// never the bytes being forwarded themselves -- and calls its observer as
// each tool_use content block completes. Its Write is part of the streamed
// byte path only in the sense that it rides alongside it (see
// Proxy.stream's io.MultiWriter); it never returns an error and so never
// aborts or slows forwarding, and whatever it cannot parse it silently
// drops. This is a witness on top of the forwarded bytes, not a gate in
// front of them: nothing it does changes what the caller receives.
type messagesInterpreter struct {
	observer ToolUseObserver
	scanner  *sseScanner
	pending  map[int]*pendingToolUse
}

// pendingToolUse accumulates one tool_use content block's input_json_delta
// fragments between its content_block_start and its content_block_stop.
type pendingToolUse struct {
	id, name string
	input    bytes.Buffer
}

func newMessagesInterpreter(observer ToolUseObserver) *messagesInterpreter {
	m := &messagesInterpreter{observer: observer, pending: make(map[int]*pendingToolUse)}
	m.scanner = newSSEScanner(m.handleEvent)
	return m
}

// Write always reports success: see the type's own doc comment for why.
func (m *messagesInterpreter) Write(p []byte) (int, error) {
	m.scanner.write(p)
	return len(p), nil
}

// contentBlockStartEvent is the shape of a content_block_start event's data.
// Only the fields a tool_use block needs are read; everything else in the
// event -- a text or thinking block's own shape -- is not this
// interpreter's concern and is dropped by encoding/json on its own.
type contentBlockStartEvent struct {
	Index        int `json:"index"`
	ContentBlock struct {
		Type string `json:"type"`
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"content_block"`
}

type contentBlockDeltaEvent struct {
	Index int `json:"index"`
	Delta struct {
		Type        string `json:"type"`
		PartialJSON string `json:"partial_json"`
	} `json:"delta"`
}

type contentBlockStopEvent struct {
	Index int `json:"index"`
}

func (m *messagesInterpreter) handleEvent(event, data string) {
	switch event {
	case "content_block_start":
		m.handleStart(data)
	case "content_block_delta":
		m.handleDelta(data)
	case "content_block_stop":
		m.handleStop(data)
	}
}

func (m *messagesInterpreter) handleStart(data string) {
	var evt contentBlockStartEvent
	if err := json.Unmarshal([]byte(data), &evt); err != nil {
		return
	}
	if evt.ContentBlock.Type != "tool_use" {
		return
	}
	m.pending[evt.Index] = &pendingToolUse{id: evt.ContentBlock.ID, name: evt.ContentBlock.Name}
}

func (m *messagesInterpreter) handleDelta(data string) {
	var evt contentBlockDeltaEvent
	if err := json.Unmarshal([]byte(data), &evt); err != nil {
		return
	}
	if evt.Delta.Type != "input_json_delta" {
		return
	}
	p, ok := m.pending[evt.Index]
	if !ok {
		return
	}
	p.input.WriteString(evt.Delta.PartialJSON)
}

func (m *messagesInterpreter) handleStop(data string) {
	var evt contentBlockStopEvent
	if err := json.Unmarshal([]byte(data), &evt); err != nil {
		return
	}
	p, ok := m.pending[evt.Index]
	if !ok {
		return
	}
	delete(m.pending, evt.Index)

	input := p.input.Bytes()
	if len(bytes.TrimSpace(input)) == 0 {
		input = []byte("{}")
	}
	if !json.Valid(input) {
		// A tool call whose reassembled input is not valid JSON is not this
		// package's to repair or to guess at -- it is dropped rather than
		// handed to the observer as something it is not. The forwarded
		// bytes are unaffected either way (this is a witness, not a gate).
		return
	}
	if m.observer == nil {
		return
	}
	// Copy the buffer's bytes before handing them out: bytes.Buffer.Bytes
	// aliases its own internal storage, and p is discarded here but json.RawMessage
	// escaping this function must not alias memory this interpreter could
	// still be holding a reference to.
	input = append([]byte(nil), input...)
	m.observer.OnToolUse(ToolUse{ID: p.id, Name: p.name, Input: input})
}

// sseScanner incrementally parses a server-sent-events stream -- RFC-less
// but stable: https://html.spec.whatwg.org/multipage/server-sent-events.html
// -- dispatching one (event, data) pair per blank line, regardless of where
// write boundaries fall. It never blocks and never errors: a line it
// cannot make sense of is dropped, never grown across writes, so a
// malformed fragment loses at most the field it was on, not the reader's
// own state.
type sseScanner struct {
	onEvent func(event, data string)

	buf      []byte // bytes received but not yet resolved into a full line
	curEvent string
	curData  []string
}

func newSSEScanner(onEvent func(event, data string)) *sseScanner {
	return &sseScanner{onEvent: onEvent}
}

func (s *sseScanner) write(p []byte) {
	s.buf = append(s.buf, p...)
	for {
		i := bytes.IndexByte(s.buf, '\n')
		if i < 0 {
			return
		}
		line := bytes.TrimSuffix(s.buf[:i], []byte("\r"))
		s.buf = s.buf[i+1:]
		s.handleLine(string(line))
	}
}

func (s *sseScanner) handleLine(line string) {
	switch {
	case line == "":
		s.dispatch()
	case strings.HasPrefix(line, ":"):
		// A comment line, per the spec. Ignored.
	case strings.HasPrefix(line, "event:"):
		s.curEvent = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
	case strings.HasPrefix(line, "data:"):
		s.curData = append(s.curData, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
	default:
		// id:, retry:, or anything this interpreter has no use for.
	}
}

func (s *sseScanner) dispatch() {
	if s.curEvent == "" && len(s.curData) == 0 {
		return
	}
	event, data := s.curEvent, strings.Join(s.curData, "\n")
	s.curEvent, s.curData = "", nil
	if s.onEvent != nil {
		s.onEvent(event, data)
	}
}
