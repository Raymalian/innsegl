// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
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
	// valid JSON; a tool call with no input is "{}", never empty or nil --
	// except when Truncated is true, when it is always nil: a fragment cut
	// short at maxToolUseInputBytes (GW-014, #405) is dropped, not
	// reassembled and handed out as though it were complete.
	Input json.RawMessage
	// Truncated is true when this block's input_json_delta fragments
	// together exceeded maxToolUseInputBytes before its content_block_stop
	// arrived. The bytes forwarded to the caller are unaffected either way
	// -- this interpreter is a witness on a copy of them, never a gate --
	// only this observation of the tool call's input is incomplete.
	Truncated bool
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
// ReplyTextObserver is handed a reply's own text: every text block, joined
// the way a resent turn's text is (facts.go's joinText), once the message
// ends with message_stop. A reply with no text, or a stream cut before it
// ended, hands nothing. ctx is the request's own, so the observer can read
// the run it was resolved to.
type ReplyTextObserver interface {
	OnReplyText(ctx context.Context, text string)
}

type ToolUseObserverFunc func(ToolUse)

// OnToolUse calls f.
func (f ToolUseObserverFunc) OnToolUse(t ToolUse) { f(t) }

// GW-014 (#405): three buffers below this line grow with the reply as it
// streams -- a tool call's input, a line, and an event's data -- and none
// of them may grow without bound, because the observer that reads them is
// always attached in production and a reply that never closes a block,
// never sends a newline, or never ends an event must not be able to grow
// this gateway's memory for as long as it stays open. Each constant below
// bounds one of them; past it, whatever that buffer is holding is dropped
// -- never reassembled and delivered as though it were complete, since
// that would be guessing -- and parsing resynchronises at the next event
// boundary. The bytes being relayed to the caller are never touched by any
// of this: this interpreter reads a copy (see its own doc comment) and
// this package's job here is only to stop holding on to it.
const (
	// maxToolUseInputBytes bounds how much of one tool_use content
	// block's input this interpreter holds across its input_json_delta
	// fragments, between the block's content_block_start and its
	// content_block_stop. It sits generously above any realistic tool
	// call -- a Write tool call can carry a whole file -- so it is sized
	// in the low tens of megabytes rather than at the size of a typical
	// delta fragment.
	maxToolUseInputBytes = 8 << 20 // 8 MiB

	// maxSSELineBytes bounds how many bytes of one line the scanner below
	// holds while waiting for the '\n' that ends it. Same order as
	// maxToolUseInputBytes, and for the same reason: a single data: line
	// can itself carry a whole input_json_delta fragment.
	maxSSELineBytes = 8 << 20 // 8 MiB

	// maxSSEEventDataBytes bounds the total size of one event's data:
	// lines, accumulated between whatever line named the event and the
	// blank line that ends it. Same order again: an event's data as a
	// whole is where a tool_use delta's JSON actually lives.
	maxSSEEventDataBytes = 8 << 20 // 8 MiB

	// maxReplyTextBytes bounds the text one reply collects for its
	// ReplyTextObserver. A reply over it hands nothing rather than a part
	// presented as the whole (GREC-007).
	maxReplyTextBytes = 8 << 20 // 8 MiB
)

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

	// onText, when set, is handed the reply's text at message_stop.
	onText       func(string)
	texts        map[int]*strings.Builder
	textOrder    []int
	textLen      int
	textOverflow bool
}

// pendingToolUse accumulates one tool_use content block's input_json_delta
// fragments between its content_block_start and its content_block_stop.
type pendingToolUse struct {
	id, name string
	input    bytes.Buffer
	// truncated is set once input's fragments together would exceed
	// maxToolUseInputBytes. From that point on input is left empty and
	// every further fragment for this block is dropped too: the block is
	// reported to the observer as truncated at its content_block_stop
	// (see handleStop), not reassembled from what is left.
	truncated bool
}

func newMessagesInterpreter(observer ToolUseObserver) *messagesInterpreter {
	m := &messagesInterpreter{observer: observer, pending: make(map[int]*pendingToolUse), texts: make(map[int]*strings.Builder)}
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
		Text        string `json:"text"`
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
	case "message_stop":
		m.handleMessageStop()
	}
}

func (m *messagesInterpreter) handleStart(data string) {
	var evt contentBlockStartEvent
	if err := json.Unmarshal([]byte(data), &evt); err != nil {
		return
	}
	if evt.ContentBlock.Type == "text" {
		if _, seen := m.texts[evt.Index]; !seen {
			m.texts[evt.Index] = &strings.Builder{}
			m.textOrder = append(m.textOrder, evt.Index)
		}
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
	if evt.Delta.Type == "text_delta" {
		m.addText(evt.Index, evt.Delta.Text)
		return
	}
	if evt.Delta.Type != "input_json_delta" {
		return
	}
	p, ok := m.pending[evt.Index]
	if !ok {
		return
	}
	if p.truncated {
		// Already over maxToolUseInputBytes for this block: further
		// fragments are dropped too, not appended past the bound.
		return
	}
	if p.input.Len()+len(evt.Delta.PartialJSON) > maxToolUseInputBytes {
		// Over the bound (GW-014, #405): stop holding this block's input.
		// What was held is dropped outright, not kept as a truncated
		// prefix -- reassembling part of a cut-short fragment would be
		// guessing, not observing. handleStop reports the block to the
		// observer as truncated instead.
		p.input.Reset()
		p.truncated = true
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

	if p.truncated {
		if m.observer != nil {
			m.observer.OnToolUse(ToolUse{ID: p.id, Name: p.name, Truncated: true})
		}
		return
	}

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
//
// Two of its buffers are bounded rather than left to grow with a reply
// that never sends a newline or never ends an event (GW-014, #405): buf,
// by maxSSELineBytes, and curData, by maxSSEEventDataBytes. Past either
// bound the event in progress is abandoned -- see abandonEvent -- and the
// scanner discards lines until the next blank line realigns it, rather
// than dispatching a reassembly it knows is incomplete.
// addText appends one text_delta to its block, bounded by maxReplyTextBytes
// across the whole reply.
func (m *messagesInterpreter) addText(index int, text string) {
	b, ok := m.texts[index]
	if !ok || m.textOverflow {
		return
	}
	if m.textLen+len(text) > maxReplyTextBytes {
		m.textOverflow = true
		return
	}
	m.textLen += len(text)
	b.WriteString(text)
}

// handleMessageStop hands the reply's text over, joined as joinText joins a
// resent turn's blocks: in block order, empty blocks skipped, "\n\n" between.
func (m *messagesInterpreter) handleMessageStop() {
	if m.onText == nil || m.textOverflow {
		return
	}
	var parts []string
	for _, i := range m.textOrder {
		if t := m.texts[i].String(); t != "" {
			parts = append(parts, t)
		}
	}
	if len(parts) == 0 {
		return
	}
	m.onText(strings.Join(parts, "\n\n"))
}

type sseScanner struct {
	onEvent func(event, data string)

	buf      []byte // bytes received but not yet resolved into a full line
	curEvent string
	curData  []string
	// curDataLen is the total length already held in curData, tracked
	// separately so the maxSSEEventDataBytes bound does not require
	// re-summing curData on every line.
	curDataLen int
	// resync is true while the scanner is discarding lines because
	// maxSSELineBytes or maxSSEEventDataBytes was exceeded, until the next
	// blank line (the event boundary) realigns it.
	resync bool
}

func newSSEScanner(onEvent func(event, data string)) *sseScanner {
	return &sseScanner{onEvent: onEvent}
}

func (s *sseScanner) write(p []byte) {
	s.buf = append(s.buf, p...)
	for {
		i := bytes.IndexByte(s.buf, '\n')
		if i < 0 {
			if len(s.buf) > maxSSELineBytes {
				// No '\n' in sight and the line so far is already over
				// the bound (GW-014, #405): drop what is held -- a line
				// abandoned mid-way cannot be trusted to resume as a
				// clean field on the far side of whatever '\n' eventually
				// arrives, so the whole event it belongs to is abandoned
				// too, and the scanner discards lines up to the next
				// blank line rather than just this one.
				s.abandonEvent()
				s.buf = nil
			}
			return
		}
		line := bytes.TrimSuffix(s.buf[:i], []byte("\r"))
		s.buf = s.buf[i+1:]
		if s.resync {
			if len(line) == 0 {
				s.resync = false // the event boundary: realigned
			}
			continue
		}
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
		d := strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " ")
		if s.curDataLen+len(d) > maxSSEEventDataBytes {
			// Over the bound (GW-014, #405) for this event's data as a
			// whole: drop it and resynchronise at the next blank line
			// rather than dispatching a reassembly known to be short.
			s.abandonEvent()
			return
		}
		s.curData = append(s.curData, d)
		s.curDataLen += len(d)
	default:
		// id:, retry:, or anything this interpreter has no use for.
	}
}

func (s *sseScanner) dispatch() {
	if s.curEvent == "" && len(s.curData) == 0 {
		return
	}
	event, data := s.curEvent, strings.Join(s.curData, "\n")
	s.curEvent, s.curData, s.curDataLen = "", nil, 0
	if s.onEvent != nil {
		s.onEvent(event, data)
	}
}

// abandonEvent drops whatever the current event has accumulated -- its
// event: field and its data: lines -- and marks the scanner to discard
// every line up to and including the next blank line, rather than
// dispatching a reassembly it knows is incomplete. It is what
// maxSSELineBytes and maxSSEEventDataBytes fall back on (GW-014, #405).
func (s *sseScanner) abandonEvent() {
	s.curEvent, s.curData, s.curDataLen = "", nil, 0
	s.resync = true
}
