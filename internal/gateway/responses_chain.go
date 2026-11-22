// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
)

const maxResponseContexts = 128
const maxResponseContextIDBytes = 256
const missingResponseContext = "the previous Responses context was not observed"

var responseHistoryInit sync.Mutex

type responseParentProblemKey struct{}

func (p *Proxy) markMissingResponseParent(r *http.Request, body wireBody) *http.Request {
	if body.problem != "" {
		return r
	}
	var request struct {
		Previous string `json:"previous_response_id"`
	}
	if json.Unmarshal(body.decoded, &request) != nil || request.Previous == "" {
		return r
	}
	runID, ok := RunIDFromContext(r.Context())
	if !ok || runID == "" {
		return r
	}
	installation, _ := InstallationFromContext(r.Context())
	parent, invalid := boundedResponseContextID(request.Previous)
	history := p.responseContextHistory()
	history.mu.Lock()
	fact, found := history.entries[responseContextKey{installation + "\x00" + runID + "\x00" + r.URL.Path, parent}]
	known := found && fact.known && fact.terminal && !invalid
	history.mu.Unlock()
	if !known {
		return r.WithContext(context.WithValue(r.Context(), responseParentProblemKey{}, missingResponseContext))
	}
	return r
}

func (p *Proxy) responseContextHistory() *responseContextHistory {
	responseHistoryInit.Lock()
	defer responseHistoryInit.Unlock()
	if p.responsesHistory == nil {
		p.responsesHistory = newResponseContextHistory()
	}
	return p.responsesHistory
}

type responseContextKey struct {
	scope string
	id    string
}

type responseContextFact struct {
	known    bool
	terminal bool
}

// responseContextHistory remembers only bounded identifiers and completeness.
// Eviction or restart makes a parent unknown; neither reconstructs provider
// state or supplies a parent run. Scope is the resolved installation/run
// and exact Responses route, so the two route families cannot borrow history.
type responseContextHistory struct {
	mu      sync.Mutex
	entries map[responseContextKey]responseContextFact
	order   []responseContextKey
}

func newResponseContextHistory() *responseContextHistory {
	return &responseContextHistory{entries: make(map[responseContextKey]responseContextFact)}
}

func (h *responseContextHistory) put(key responseContextKey, fact responseContextFact) {
	if _, exists := h.entries[key]; !exists {
		if len(h.order) >= maxResponseContexts {
			delete(h.entries, h.order[0])
			h.order = h.order[1:]
		}
		h.order = append(h.order, key)
	}
	h.entries[key] = fact
}

func (h *responseContextHistory) closed(scope, id string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.entries[responseContextKey{scope, id}].terminal
}

func (h *responseContextHistory) start(scope, id, parent string, unknown bool) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	key := responseContextKey{scope, id}
	known := !unknown
	if parent != "" {
		fact, found := h.entries[responseContextKey{scope, parent}]
		known = known && found && fact.terminal && fact.known
	}
	if prior, exists := h.entries[key]; exists {
		prior.known = prior.known && known
		h.put(key, prior)
		return prior.known
	}
	h.put(key, responseContextFact{known: known})
	return known
}

func (h *responseContextHistory) finish(scope, id string, complete bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	key := responseContextKey{scope, id}
	fact := h.entries[key]
	fact.known = fact.known && complete
	fact.terminal = true
	h.put(key, fact)
}

type responseRequestContext struct {
	parent  string
	unknown bool
}

type responseObservation struct {
	interpreter *responsesInterpreter
}

func boundedResponseContextID(id string) (string, bool) {
	if len(id) <= maxResponseContextIDBytes && !strings.ContainsRune(id, '\x00') {
		return id, false
	}
	sum := sha256.Sum256([]byte(id))
	// This is only an internal deny-only cache key, never a response or run
	// identity. A valid provider id cannot alias this reserved domain.
	return "\x00unsupported-" + hex.EncodeToString(sum[:]), true
}

func (o *responsesWebSocketObserver) noteRequest(payload []byte) {
	var req struct {
		Type     string `json:"type"`
		Previous string `json:"previous_response_id"`
		Response struct {
			Previous string `json:"previous_response_id"`
		} `json:"response"`
	}
	if json.Unmarshal(payload, &req) != nil {
		o.noteUnknownRequest()
		return
	}
	if req.Type != "response.create" {
		return
	}
	if req.Previous == "" {
		req.Previous = req.Response.Previous
	}
	parent, unknown := boundedResponseContextID(req.Previous)
	if len(o.requests) >= maxResponseContexts {
		o.requestContextLost = true
		o.requests = o.requests[1:]
	}
	o.requests = append(o.requests, responseRequestContext{parent: parent, unknown: unknown})
	o.fallbackUnknown = o.requestContextLost || unknown || parent != ""
	o.resetInterpreter()
}

func (o *responsesWebSocketObserver) noteUnknownRequest() {
	o.requestContextLost = true
	o.fallbackUnknown = true
	o.resetInterpreter()
	if len(o.requests) >= maxResponseContexts {
		o.requests = o.requests[1:]
	}
	o.requests = append(o.requests, responseRequestContext{unknown: true})
}

func (o *responsesWebSocketObserver) contextObserver(known, trustedAssociation bool) ToolUseObserver {
	return ToolUseObserverFunc(func(call ToolUse) {
		if call.ObservationIncomplete {
			noteReplayProblem(o.ctx, "the Responses stream ended before a complete tool call was observed")
		}
		if o.observer == nil {
			return
		}
		if !known {
			noteReplayProblem(o.ctx, missingResponseContext)
			call.ContextIncomplete = true
			call.ObservationGap = missingResponseContext
			if !trustedAssociation {
				call.Input = nil
				call.ObservationIncomplete = true
				call.ObservationGap = "the Responses association could not be established; recorded with input unknown"
			}
		}
		o.observer.OnToolUse(call)
	})
}

func (o *responsesWebSocketObserver) startResponse(id, parent string, unknown bool) *responseObservation {
	if observation := o.responses[id]; observation != nil {
		return observation
	}
	if len(o.responses) >= maxResponseContexts {
		// Finish in observation order, not map iteration order. A bounded
		// eviction preserves partial calls as gaps and cannot grant authority.
		oldest := o.responseOrder[0]
		o.responseOrder = o.responseOrder[1:]
		o.responses[oldest].interpreter.Finish()
		delete(o.responses, oldest)
		o.history.finish(o.scope, oldest, false)
	}
	known := o.history.start(o.scope, id, parent, unknown)
	if !known {
		noteReplayProblem(o.ctx, missingResponseContext)
	}
	observer := o.contextObserver(known, !unknown)
	interp := newResponsesInterpreter(observer)
	interp.onText = o.onText
	observation := &responseObservation{interpreter: interp}
	o.responses[id] = observation
	o.responseOrder = append(o.responseOrder, id)
	return observation
}

func (o *responsesWebSocketObserver) forgetResponse(id string) {
	delete(o.responses, id)
	for i, prior := range o.responseOrder {
		if prior == id {
			o.responseOrder = append(o.responseOrder[:i], o.responseOrder[i+1:]...)
			break
		}
	}
}
