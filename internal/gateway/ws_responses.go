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
	mu                 sync.Mutex
	observer           ToolUseObserver
	frames             FrameObserver
	onText             func(string)
	messages           ResponsesWebSocketMessageObserver
	ctx                context.Context
	current            *responsesInterpreter
	history            *responseContextHistory
	scope              string
	activeID           string
	responses          map[string]*responseObservation
	responseOrder      []string
	requests           []responseRequestContext
	requestContextLost bool
	fallbackUnknown    bool
	fragments          map[Direction]*responsesWSFragments
	preObserved        map[Direction]bool
	finished           bool
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
	o.history = newResponseContextHistory()
	o.responses = make(map[string]*responseObservation)
	o.resetInterpreter()
	return o
}

func (o *responsesWebSocketObserver) resetInterpreter() {
	if o.current != nil {
		o.current.Finish()
	}
	o.current = newResponsesInterpreter(o.contextObserver(!o.fallbackUnknown, !o.fallbackUnknown))
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
		if state.direction == ClientToUpstream {
			o.noteUnknownRequest()
		}
		return
	}
	payload := state.message.Bytes()
	if state.direction == ClientToUpstream {
		o.noteRequest(payload)
		if o.messages != nil {
			o.messages.OnResponsesWebSocketMessage(o.ctx, payload)
		}
		return
	}
	o.observeServerMessage(payload)
}

func (o *responsesWebSocketObserver) observeServerMessage(payload []byte) {
	var envelope struct {
		Type       string `json:"type"`
		ResponseID string `json:"response_id"`
		Response   struct {
			ID       string `json:"id"`
			Previous string `json:"previous_response_id"`
			Status   string `json:"status"`
		} `json:"response"`
	}
	if json.Unmarshal(payload, &envelope) != nil {
		return
	}
	id, _ := boundedResponseContextID(envelope.ResponseID)
	terminal := envelope.Type == "response.completed" || envelope.Type == "response.failed" || envelope.Type == "response.incomplete"
	if envelope.Type == "response.created" {
		createdID, invalidID := boundedResponseContextID(envelope.Response.ID)
		if createdID == "" {
			return
		}
		parent, invalidParent := boundedResponseContextID(envelope.Response.Previous)
		unknown := invalidID || invalidParent || o.requestContextLost
		if len(o.requests) > 0 {
			request := o.requests[0]
			o.requests = o.requests[1:]
			unknown = unknown || request.unknown || (parent != "" && request.parent != "" && parent != request.parent)
			if parent == "" {
				parent = request.parent
			}
		}
		if !o.history.closed(o.scope, createdID) {
			o.startResponse(createdID, parent, unknown)
		}
		o.activeID = createdID
		return
	}
	if terminal && envelope.Response.ID != "" {
		terminalID, _ := boundedResponseContextID(envelope.Response.ID)
		if id != "" && id != terminalID {
			return
		}
		id = terminalID
	}
	if id == "" && len(o.responses) > 1 {
		// Multiple responses are in flight. An event without its response
		// identifier cannot be assigned to the most recently created one.
		if !o.fallbackUnknown {
			o.fallbackUnknown = true
			o.resetInterpreter()
		}
	} else if id == "" {
		id = o.activeID
	}
	interp := o.current
	if id != "" {
		if o.history.closed(o.scope, id) {
			return
		}
		observation := o.responses[id]
		if observation == nil {
			observation = o.startResponse(id, "", true)
		}
		interp = observation.interpreter
	}
	discardWriteError(interp.Write(append(append([]byte("data: "), payload...), '\n', '\n')))
	if terminal {
		interp.Finish()
		if id != "" {
			o.history.finish(o.scope, id, envelope.Type == "response.completed" && envelope.Response.Status == "completed")
			o.forgetResponse(id)
			if o.activeID == id {
				o.activeID = ""
			}
		}
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
	for id, observation := range o.responses {
		observation.interpreter.Finish()
		o.history.finish(o.scope, id, false)
	}
	o.responses = nil
	o.responseOrder = nil
	o.current.Finish()
}
