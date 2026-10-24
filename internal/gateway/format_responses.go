// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"mime"
	"net/http"
	"strings"
)

type responsesFormat struct{}
type responseItem struct {
	Type      string          `json:"type"`
	Role      string          `json:"role"`
	ID        string          `json:"id"`
	CallID    string          `json:"call_id"`
	Name      string          `json:"name"`
	Namespace string          `json:"namespace"`
	Arguments string          `json:"arguments"`
	Input     string          `json:"input"`
	Output    json.RawMessage `json:"output"`
	Content   json.RawMessage `json:"content"`
}

func responseItems(b []byte) ([]responseItem, error) {
	var body struct {
		Input    json.RawMessage `json:"input"`
		Response struct {
			Input json.RawMessage `json:"input"`
		} `json:"response"`
	}
	if json.Unmarshal(b, &body) != nil {
		return nil, errResponsesShape
	}
	if len(body.Input) == 0 {
		body.Input = body.Response.Input
	}
	if len(body.Input) == 0 {
		return nil, errResponsesShape
	}
	var text string
	if json.Unmarshal(body.Input, &text) == nil {
		return []responseItem{{Role: "user", Content: body.Input}}, nil
	}
	var items []responseItem
	if json.Unmarshal(body.Input, &items) != nil {
		return nil, errResponsesShape
	}
	return items, nil
}

func responseText(content json.RawMessage) string {
	var text string
	if json.Unmarshal(content, &text) == nil {
		return text
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(content, &blocks) != nil {
		return ""
	}
	var parts []string
	for _, b := range blocks {
		if (b.Type == "input_text" || b.Type == "output_text") && b.Text != "" {
			parts = append(parts, b.Text)
		}
	}
	return strings.Join(parts, "\n\n")
}

func (responsesFormat) facts(b []byte) RequestFacts {
	items, err := responseItems(b)
	if err != nil {
		return RequestFacts{}
	}
	var f RequestFacts
	user, assistant := false, false
	for _, item := range items {
		if item.Role == "user" && !user {
			text := responseText(item.Content)
			trimmed := strings.TrimSpace(text)
			if strings.HasPrefix(trimmed, "<environment_context>") && strings.HasSuffix(trimmed, "</environment_context>") {
				continue
			}
			f.Brief = text
			user = true
		}
		if item.Role == "assistant" && !assistant {
			f.FirstAssistant, _ = canonicalizeContent(item.Content)
			assistant = true
		}
		if (item.Type == "function_call_output" || item.Type == "custom_tool_call_output") && item.CallID != "" {
			f.ToolResultIDs = append(f.ToolResultIDs, item.CallID)
		}
	}
	return f
}

func (responsesFormat) results(b []byte) []observedToolResult {
	items, err := responseItems(b)
	if err != nil {
		return nil
	}
	var out []observedToolResult
	for _, item := range items {
		if (item.Type != "function_call_output" && item.Type != "custom_tool_call_output") || item.CallID == "" {
			continue
		}
		content := item.Output
		truncated := len(content) > maxToolResultContentBytes
		if truncated {
			content = nil
		}
		out = append(out, observedToolResult{ToolUseID: item.CallID, Content: content, Truncated: truncated, ErrorSignal: "unknown"})
	}
	return out
}

func (responsesFormat) texts(b []byte) []string {
	items, err := responseItems(b)
	if err != nil {
		return nil
	}
	var out []string
	for _, item := range items {
		if item.Role == "assistant" {
			out = append(out, responseText(item.Content))
		}
	}
	return out
}

// responsesInterpreter consumes SSE on a copy after forwarding. A completed
// item is the authoritative whole call; deltas never become partial inputs.
type responsesInterpreter struct {
	scanner    *sseScanner
	observer   ToolUseObserver
	onText     func(string)
	seen       map[string]bool
	partial    map[string]responseItem
	partialIDs []string
	completed  bool
}

func newResponsesInterpreter(observer ToolUseObserver) *responsesInterpreter {
	r := &responsesInterpreter{observer: observer, seen: map[string]bool{}, partial: map[string]responseItem{}}
	r.scanner = newSSEScanner(r.event)
	return r
}
func (r *responsesInterpreter) Write(p []byte) (int, error) { r.scanner.write(p); return len(p), nil }
func (r *responsesInterpreter) Finish() {
	if !r.completed {
		r.finishPartial()
		r.completed = true
	}
}
func (r *responsesInterpreter) event(event, data string) {
	if r.completed {
		return
	}
	var e struct {
		Type     string       `json:"type"`
		Item     responseItem `json:"item"`
		Response struct {
			Status string         `json:"status"`
			Output []responseItem `json:"output"`
		} `json:"response"`
	}
	if json.Unmarshal([]byte(data), &e) != nil {
		return
	}
	if e.Type != "" {
		if event != "" && event != e.Type {
			return
		}
		event = e.Type
	}
	switch event {
	case "response.output_item.added":
		r.addPartial(e.Item)
	case "response.output_item.done":
		if r.call(e.Item, false) {
			delete(r.partial, e.Item.CallID)
		}
	case "response.completed":
		if e.Response.Status != "completed" {
			return
		}
		r.completed = true
		var parts []string
		size := 0
		for _, item := range e.Response.Output {
			if r.call(item, false) {
				delete(r.partial, item.CallID)
			}
			if item.Role == "assistant" {
				text := responseText(item.Content)
				size += len(text)
				if size > maxReplyTextBytes {
					return
				}
				if text != "" {
					parts = append(parts, text)
				}
			}
		}
		if r.onText != nil && len(parts) > 0 {
			r.onText(strings.Join(parts, "\n\n"))
		}
		r.finishPartial()
	case "response.failed", "response.incomplete":
		r.finishPartial()
		r.completed = true
	}
}
func (r *responsesInterpreter) addPartial(item responseItem) {
	if item.CallID == "" || item.Name == "" || (item.Type != "function_call" && item.Type != "custom_tool_call") || r.seen[item.CallID] {
		return
	}
	if _, exists := r.partial[item.CallID]; !exists {
		if len(r.partial) >= 4096 {
			return
		}
		r.partialIDs = append(r.partialIDs, item.CallID)
	}
	r.partial[item.CallID] = item
}

func (r *responsesInterpreter) finishPartial() {
	for _, id := range r.partialIDs {
		if item, ok := r.partial[id]; ok {
			r.call(item, true)
			delete(r.partial, id)
		}
	}
	r.partialIDs = nil
}

func (r *responsesInterpreter) call(item responseItem, observationIncomplete bool) bool {
	if (item.Type != "function_call" && item.Type != "custom_tool_call") || item.CallID == "" || item.Name == "" || r.seen[item.CallID] {
		return r.seen[item.CallID]
	}
	// Bound deduplication state as well as the scanner's frame buffers.
	if len(r.seen) >= 4096 {
		return false
	}
	var input json.RawMessage
	truncated := observationIncomplete
	switch {
	case observationIncomplete:
		input = nil
	case item.Type == "custom_tool_call":
		if len(item.Input) > maxToolUseInputBytes {
			truncated = true
		} else {
			var err error
			input, err = json.Marshal(map[string]string{"input": item.Input})
			if err != nil {
				return false
			}
		}
	default:
		switch {
		case len(item.Arguments) > maxToolUseInputBytes:
			truncated = true
		case !json.Valid([]byte(item.Arguments)):
			return false
		default:
			input = json.RawMessage(item.Arguments)
		}
	}
	r.seen[item.CallID] = true
	if r.observer != nil {
		name := item.Name
		if item.Type == "function_call" && item.Namespace != "" {
			name = item.Namespace + "." + name
		}
		r.observer.OnToolUse(ToolUse{WireType: item.Type, ID: item.CallID, Name: name, Namespace: item.Namespace, Input: input, Truncated: truncated, ObservationIncomplete: observationIncomplete})
	}
	return true
}

// The Codex backend can omit Content-Type on Responses SSE; a relay may
// then supply text/plain. This measured exception belongs to its exact
// route; it does not widen Messages parsing or sniff another wire format.
func isResponsesBackendStream(r *http.Request, contentType string) bool {
	if r.URL.Path != "/backend-api/codex/responses" {
		return false
	}
	if strings.TrimSpace(contentType) == "" {
		return true
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	return err == nil && mediaType == "text/plain"
}
