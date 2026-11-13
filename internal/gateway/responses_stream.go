// SPDX-License-Identifier: Apache-2.0

package gateway

import "encoding/json"

// responsesStreamObserver feeds HTTP SSE and imported journal replies through
// the same bounded response-context observer as the WebSocket transport.
type responsesStreamObserver struct {
	scanner *sseScanner
	context *responsesWebSocketObserver
}

func newResponsesStreamObserver(context *responsesWebSocketObserver) *responsesStreamObserver {
	s := &responsesStreamObserver{context: context}
	s.scanner = newSSEScanner(func(event, data string) {
		var envelope struct {
			Type string `json:"type"`
		}
		if json.Unmarshal([]byte(data), &envelope) != nil ||
			(event != "" && envelope.Type != "" && event != envelope.Type) {
			return
		}
		payload := []byte(data)
		if envelope.Type == "" && event != "" {
			var object map[string]json.RawMessage
			if json.Unmarshal(payload, &object) != nil || object == nil {
				return
			}
			value, err := json.Marshal(event)
			if err != nil {
				return
			}
			object["type"] = value
			payload, err = json.Marshal(object)
			if err != nil {
				return
			}
		}
		context.observeServerMessage(payload)
	})
	return s
}

func (s *responsesStreamObserver) Write(p []byte) (int, error) {
	s.context.mu.Lock()
	defer s.context.mu.Unlock()
	if !s.context.finished {
		s.scanner.write(p)
	}
	return len(p), nil
}

func (s *responsesStreamObserver) Finish() { s.context.Finish() }

func (o *responsesWebSocketObserver) noteHTTPRequest(body wireBody) {
	if body.problem != "" {
		o.noteUnknownRequest()
		return
	}
	var request struct {
		Previous string `json:"previous_response_id"`
	}
	if json.Unmarshal(body.decoded, &request) != nil {
		o.noteUnknownRequest()
		return
	}
	parent, unknown := boundedResponseContextID(request.Previous)
	o.requests = append(o.requests, responseRequestContext{parent: parent, unknown: unknown})
	o.fallbackUnknown = unknown || parent != ""
	o.resetInterpreter()
}
