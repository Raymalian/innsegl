// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
)

// ResponsesWebSocketMessageObserver consumes complete, bounded JSON
// messages sent by Codex on a Responses WebSocket. It is used for tool
// results in response.create input; implementations must not retain the
// raw message beyond their call.
type ResponsesWebSocketMessageObserver interface {
	OnResponsesWebSocketMessage(context.Context, []byte)
}

// responsesWebSocketObserver reassembles bounded WebSocket text messages.
// Upstream event objects feed the same interpreter used by HTTP SSE; client
// response.create messages supply tool results. The frame relay remains
// byte-for-byte and never depends on this parser.
type responsesWebSocketObserver struct {
	mu          sync.Mutex
	observer    ToolUseObserver
	frames      FrameObserver
	onText      func(string)
	messages    ResponsesWebSocketMessageObserver
	ctx         context.Context
	current     *responsesInterpreter
	fragments   map[Direction]*responsesWSFragments
	preObserved map[Direction]bool
	finished    bool
}

type responsesWSFragments struct {
	message   bytes.Buffer
	opcode    Opcode
	direction Direction
	dropping  bool
}

func newResponsesWebSocketObserver(observer ToolUseObserver) *responsesWebSocketObserver {
	o := &responsesWebSocketObserver{observer: observer, fragments: map[Direction]*responsesWSFragments{
		ClientToUpstream: {}, UpstreamToClient: {},
	}, preObserved: map[Direction]bool{}}
	o.resetInterpreter()
	return o
}

func (o *responsesWebSocketObserver) resetInterpreter() {
	o.current = newResponsesInterpreter(o.observer)
	o.current.onText = o.onText
}

func (o *responsesWebSocketObserver) OnFrame(frame Frame) {
	if o == nil {
		return
	}
	if o.frames != nil {
		o.frames.OnFrame(frame)
	}
	o.mu.Lock()
	if o.finished {
		o.mu.Unlock()
		return
	}
	if o.preObserved[frame.Direction] {
		delete(o.preObserved, frame.Direction)
		o.mu.Unlock()
		return
	}
	o.processFrameLocked(frame)
	o.mu.Unlock()
}

// OnFrameBeforeForward observes a bounded frame before the peer can consume
// it. A completed Responses call is registered before Codex can execute it
// or start its child. OnFrame still receives the post-relay witness callback.
func (o *responsesWebSocketObserver) OnFrameBeforeForward(frame Frame) {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.finished {
		return
	}
	o.processFrameLocked(frame)
	o.preObserved[frame.Direction] = true
}

func (o *responsesWebSocketObserver) processFrameLocked(frame Frame) {
	state := o.fragments[frame.Direction]
	if state == nil {
		return
	}
	switch frame.Opcode {
	case OpcodeText:
		state.message.Reset()
		state.dropping = frame.Truncated
		state.opcode = OpcodeText
		state.direction = frame.Direction
		if !state.dropping {
			o.append(state, frame.Payload)
		}
		if !frame.Truncated && frame.Fin {
			o.finishMessage(state)
		}
	case OpcodeContinuation:
		if state.opcode != OpcodeText {
			return
		}
		if frame.Truncated {
			state.dropping = true
		}
		if !state.dropping {
			o.append(state, frame.Payload)
		}
		if frame.Fin {
			o.finishMessage(state)
		}
	}
}

func (o *responsesWebSocketObserver) append(state *responsesWSFragments, payload []byte) {
	if state.message.Len()+len(payload) > maxSSEEventDataBytes {
		state.dropping = true
		state.message.Reset()
		return
	}
	_, _ = state.message.Write(payload)
}

func (o *responsesWebSocketObserver) finishMessage(state *responsesWSFragments) {
	defer func() {
		state.message.Reset()
		state.dropping = false
		state.opcode = 0
	}()
	if state.dropping || state.message.Len() == 0 {
		return
	}
	payload := state.message.Bytes()
	if state.direction == ClientToUpstream {
		if o.messages != nil {
			o.messages.OnResponsesWebSocketMessage(o.ctx, payload)
		}
		return
	}
	var terminal struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(payload, &terminal) != nil {
		terminal.Type = ""
	}
	discardWriteError(o.current.Write(append(append([]byte("data: "), payload...), '\n', '\n')))
	if terminal.Type == "response.completed" || terminal.Type == "response.failed" || terminal.Type == "response.incomplete" {
		o.resetInterpreter()
	}
}

func (o *responsesWebSocketObserver) Finish() {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.finished {
		return
	}
	o.finished = true
	o.current.Finish()
}
