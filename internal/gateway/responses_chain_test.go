// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

// OAI-019/021: losing historical conversation context does not erase a
// complete current call independently relayed on an already resolved run.
func TestOAI019MissingHistoryPreservesCurrentCommandEvidence(t *testing.T) {
	recorded := &fakeRecordCalls{}
	rec := NewToolCallRecorder(ToolCallRecorderConfig{record: recorded.fn})
	ctx := WithIdentification(WithRunID(context.Background(), "run-current"), Identification{Harness: "codex"})
	o := newResponsesWebSocketObserver(ToolUseObserverFunc(func(call ToolUse) { rec.OnToolUseContext(ctx, call) }))
	responseWSFrame(o, ClientToUpstream, `{"type":"response.create","previous_response_id":"resp_unseen","input":"continue"}`)
	responseWSFrame(o, UpstreamToClient, `{"type":"response.created","response":{"id":"resp_current"}}`)
	responseWSFrame(o, UpstreamToClient, `{"type":"response.output_item.done","item":{"type":"function_call","call_id":"call_current_observed","name":"exec_command","arguments":"{\"cmd\":\"git commit -m current\"}"}}`)
	if call, ok := rec.LookupPending("call_current_observed"); !ok || string(call.Input) != `{"cmd":"git commit -m current"}` {
		t.Fatalf("missing history erased an independently observed current command: %+v, %v", call, ok)
	}
	rec.HandleResults(ctx, "run-current", RequestFacts{}, []observedToolResult{recResult("call_current_observed", `"done"`, false)})
	waitForCalls(t, recorded, 1)
	var body gatewayToolCallBody
	if err := json.Unmarshal(recorded.snapshot()[0].Body, &body); err != nil {
		t.Fatal(err)
	}
	if body.ObservationIncomplete || !body.ContextIncomplete || body.Note == "" || len(body.Input) == 0 {
		t.Fatalf("recorded body conflated missing history with current facts: %+v", body)
	}
}

func responseWSFrame(o *responsesWebSocketObserver, direction Direction, data string) {
	o.OnFrame(Frame{Direction: direction, Opcode: OpcodeText, Fin: true, Payload: []byte(data), Length: uint64(len(data))})
}

// OAI-019/022: a retried terminal event must not finalize another response
// or reintroduce an already completed call.
func TestOAI022DuplicateTerminalDoesNotEndTheNextResponse(t *testing.T) {
	var calls []ToolUse
	o := newResponsesWebSocketObserver(ToolUseObserverFunc(func(c ToolUse) { calls = append(calls, c) }))
	responseWSFrame(o, UpstreamToClient, `{"type":"response.created","response":{"id":"resp_first"}}`)
	responseWSFrame(o, UpstreamToClient, `{"type":"response.output_item.done","item":{"type":"function_call","call_id":"call_first_response","name":"exec_command","arguments":"{}"}}`)
	responseWSFrame(o, UpstreamToClient, `{"type":"response.completed","response":{"id":"resp_first","status":"completed","output":[]}}`)
	responseWSFrame(o, UpstreamToClient, `{"type":"response.created","response":{"id":"resp_second"}}`)
	responseWSFrame(o, UpstreamToClient, `{"type":"response.output_item.added","item":{"type":"function_call","call_id":"call_second_response","name":"exec_command","arguments":"{"}}`)
	responseWSFrame(o, UpstreamToClient, `{"type":"response.completed","response":{"id":"resp_first","status":"completed","output":[{"type":"function_call","call_id":"call_first_response","name":"exec_command","arguments":"{}"}]}}`)
	responseWSFrame(o, UpstreamToClient, `{"type":"response.output_item.done","item":{"type":"function_call","call_id":"call_second_response","name":"exec_command","arguments":"{}"}}`)
	responseWSFrame(o, UpstreamToClient, `{"type":"response.completed","response":{"id":"resp_second","status":"completed","output":[]}}`)
	o.Finish()
	if len(calls) != 2 || calls[0].ID != "call_first_response" || calls[1].ID != "call_second_response" || calls[1].ObservationIncomplete {
		t.Fatalf("duplicate terminal changed response attribution: %+v", calls)
	}
}

// OAI-019/022: an unseen continuation leaves history unknown while retaining
// the complete current item observed on this response.
func TestOAI022UnknownPreviousResponseKeepsCurrentFactsAndContextGap(t *testing.T) {
	var calls []ToolUse
	o := newResponsesWebSocketObserver(ToolUseObserverFunc(func(c ToolUse) { calls = append(calls, c) }))
	responseWSFrame(o, ClientToUpstream, `{"type":"response.create","previous_response_id":"resp_missing","input":"continue"}`)
	responseWSFrame(o, UpstreamToClient, `{"type":"response.created","response":{"id":"resp_next","previous_response_id":"resp_missing"}}`)
	responseWSFrame(o, UpstreamToClient, `{"type":"response.output_item.done","item":{"type":"function_call","call_id":"call_missing_parent","name":"exec_command","arguments":"{\"cmd\":\"private command\"}"}}`)
	o.Finish()
	if len(calls) != 1 || calls[0].ObservationIncomplete || !calls[0].ContextIncomplete || calls[0].ObservationGap == "" || len(calls[0].Input) == 0 {
		t.Fatalf("unknown history erased current facts or lost the context gap: %+v", calls)
	}
}

func TestOAI022KnownPreviousResponseRetainsCompleteObservation(t *testing.T) {
	var calls []ToolUse
	o := newResponsesWebSocketObserver(ToolUseObserverFunc(func(c ToolUse) { calls = append(calls, c) }))
	responseWSFrame(o, UpstreamToClient, `{"type":"response.created","response":{"id":"resp_known"}}`)
	responseWSFrame(o, UpstreamToClient, `{"type":"response.completed","response":{"id":"resp_known","status":"completed","output":[]}}`)
	responseWSFrame(o, ClientToUpstream, `{"type":"response.create","response":{"previous_response_id":"resp_known","input":"continue"}}`)
	responseWSFrame(o, UpstreamToClient, `{"type":"response.created","response":{"id":"resp_next","previous_response_id":"resp_known"}}`)
	responseWSFrame(o, UpstreamToClient, `{"type":"response.output_item.done","item":{"type":"function_call","call_id":"call_known_parent","name":"exec_command","arguments":"{}"}}`)
	responseWSFrame(o, UpstreamToClient, `{"type":"response.completed","response":{"id":"resp_next","status":"completed","output":[]}}`)
	o.Finish()
	if len(calls) != 1 || calls[0].ObservationIncomplete || len(calls[0].Input) == 0 {
		t.Fatalf("known response continuation lost its complete observation: %+v", calls)
	}
}

// OAI-019/022: reconnects share known context only within the resolved run.
func TestOAI022ReconnectContextIsScopedToTheResolvedRun(t *testing.T) {
	var calls []ToolUse
	p := &Proxy{ToolUse: ToolUseObserverFunc(func(c ToolUse) { calls = append(calls, c) })}
	open := func(run string) *responsesWebSocketObserver {
		r := responseRequest(nil)
		r = r.WithContext(WithRunID(r.Context(), run))
		observer, ok := p.responsesWebSocketObserver(r).(*responsesWebSocketObserver)
		if !ok {
			t.Fatal("missing Responses WebSocket observer")
		}
		return observer
	}
	first := open("run-parent")
	responseWSFrame(first, UpstreamToClient, `{"type":"response.created","response":{"id":"resp_before_reconnect"}}`)
	responseWSFrame(first, UpstreamToClient, `{"type":"response.completed","response":{"id":"resp_before_reconnect","status":"completed","output":[]}}`)
	first.Finish()
	next := open("run-parent")
	responseWSFrame(next, ClientToUpstream, `{"type":"response.create","previous_response_id":"resp_before_reconnect","input":"continue"}`)
	responseWSFrame(next, UpstreamToClient, `{"type":"response.created","response":{"id":"resp_reconnected"}}`)
	responseWSFrame(next, UpstreamToClient, `{"type":"response.output_item.done","item":{"type":"function_call","call_id":"call_reconnected","name":"exec_command","arguments":"{}"}}`)
	next.Finish()
	other := open("run-other")
	responseWSFrame(other, ClientToUpstream, `{"type":"response.create","previous_response_id":"resp_before_reconnect","input":"continue"}`)
	responseWSFrame(other, UpstreamToClient, `{"type":"response.created","response":{"id":"resp_cross_run"}}`)
	responseWSFrame(other, UpstreamToClient, `{"type":"response.output_item.done","item":{"type":"function_call","call_id":"call_cross_run","name":"exec_command","arguments":"{}"}}`)
	other.Finish()
	if len(calls) != 2 || calls[0].ContextIncomplete || !calls[1].ContextIncomplete || calls[1].ObservationIncomplete || len(calls[1].Input) == 0 {
		t.Fatalf("reconnect lost scoped context or current facts: %+v", calls)
	}
}

func TestOAI022OversizedResponseIDsCannotSupplyKnownContext(t *testing.T) {
	var calls []ToolUse
	o := newResponsesWebSocketObserver(ToolUseObserverFunc(func(c ToolUse) { calls = append(calls, c) }))
	long := strings.Repeat("x", 4096)
	responseWSFrame(o, UpstreamToClient, `{"type":"response.created","response":{"id":"`+long+`"}}`)
	responseWSFrame(o, UpstreamToClient, `{"type":"response.output_item.done","item":{"type":"function_call","call_id":"call_oversized_context","name":"exec_command","arguments":"{}"}}`)
	o.Finish()
	if len(calls) != 1 || !calls[0].ObservationIncomplete || calls[0].Input != nil {
		t.Fatalf("oversized response context acquired command facts: %+v", calls)
	}
	for key := range o.history.entries {
		if len(key.id) > 256 {
			t.Fatal("oversized response id retained in bounded history")
		}
	}
}

// OAI-019: HTTP/SSE continuation follows the same known/unknown context
// contract as WebSockets; a transport choice cannot grant extra authority.
func TestOAI019HTTPContinuationReportsUnobservedParent(t *testing.T) {
	var calls []ToolUse
	p := &Proxy{ToolUse: ToolUseObserverFunc(func(c ToolUse) { calls = append(calls, c) })}
	r := responseRequest([]byte(`{"previous_response_id":"resp_missing_http","input":"continue"}`))
	r = r.WithContext(WithRunID(r.Context(), "run-http"))
	observer := p.replyObserver(r, "text/event-stream")
	stream := "data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_http\"}}\n\n" +
		"data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"function_call\",\"call_id\":\"call_http_unknown_parent\",\"name\":\"exec_command\",\"arguments\":\"{}\"}}\n\n" +
		"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_http\",\"status\":\"completed\",\"output\":[]}}\n\n"
	if _, err := io.WriteString(observer, stream); err != nil {
		t.Fatal(err)
	}
	finisher, ok := observer.(interface{ Finish() })
	if !ok {
		t.Fatal("response observer cannot finalize")
	}
	finisher.Finish()
	if len(calls) != 1 || calls[0].ObservationIncomplete || !calls[0].ContextIncomplete || len(calls[0].Input) == 0 {
		t.Fatalf("HTTP continuation inferred unknown context: %+v", calls)
	}
}

func TestOAI022RequestQueueEvictionCannotGuessTheParent(t *testing.T) {
	var calls []ToolUse
	o := newResponsesWebSocketObserver(ToolUseObserverFunc(func(c ToolUse) { calls = append(calls, c) }))
	responseWSFrame(o, ClientToUpstream, `{"type":"response.create","previous_response_id":"resp_unknown","input":"continue"}`)
	for range maxResponseContexts {
		responseWSFrame(o, ClientToUpstream, `{"type":"response.create","input":"fresh"}`)
	}
	responseWSFrame(o, UpstreamToClient, `{"type":"response.created","response":{"id":"resp_after_overflow"}}`)
	responseWSFrame(o, UpstreamToClient, `{"type":"response.output_item.done","item":{"type":"function_call","call_id":"call_after_context_overflow","name":"exec_command","arguments":"{}"}}`)
	o.Finish()
	if len(calls) != 1 || !calls[0].ObservationIncomplete || calls[0].Input != nil {
		t.Fatalf("bounded queue guessed lost context: %+v", calls)
	}
	if len(o.requests) > maxResponseContexts {
		t.Fatal("request-context queue exceeded its bound")
	}
}

func TestOAI022InterleavedResponseWithoutIDCannotGuessAssociation(t *testing.T) {
	var calls []ToolUse
	o := newResponsesWebSocketObserver(ToolUseObserverFunc(func(c ToolUse) { calls = append(calls, c) }))
	responseWSFrame(o, UpstreamToClient, `{"type":"response.created","response":{"id":"resp_interleaved_a"}}`)
	responseWSFrame(o, UpstreamToClient, `{"type":"response.created","response":{"id":"resp_interleaved_b"}}`)
	responseWSFrame(o, UpstreamToClient, `{"type":"response.output_item.done","item":{"type":"function_call","call_id":"call_ambiguous_response","name":"exec_command","arguments":"{\"cmd\":\"git commit -m ambiguous\"}"}}`)
	o.Finish()
	if len(calls) != 1 || !calls[0].ObservationIncomplete || calls[0].Input != nil {
		t.Fatalf("interleaved event guessed the most recent response: %+v", calls)
	}
}

func TestOAI022ExplicitIDsPreserveInterleavedCurrentCalls(t *testing.T) {
	var calls []ToolUse
	o := newResponsesWebSocketObserver(ToolUseObserverFunc(func(c ToolUse) { calls = append(calls, c) }))
	responseWSFrame(o, UpstreamToClient, `{"type":"response.created","response":{"id":"resp_explicit_a"}}`)
	responseWSFrame(o, UpstreamToClient, `{"type":"response.created","response":{"id":"resp_explicit_b"}}`)
	responseWSFrame(o, UpstreamToClient, `{"type":"response.output_item.done","response_id":"resp_explicit_a","item":{"type":"function_call","call_id":"call_explicit_a","name":"exec_command","arguments":"{\"cmd\":\"echo a\"}"}}`)
	responseWSFrame(o, UpstreamToClient, `{"type":"response.output_item.done","response_id":"resp_explicit_b","item":{"type":"function_call","call_id":"call_explicit_b","name":"exec_command","arguments":"{\"cmd\":\"echo b\"}"}}`)
	o.Finish()
	if len(calls) != 2 || calls[0].ObservationIncomplete || calls[1].ObservationIncomplete || calls[0].ID != "call_explicit_a" || calls[1].ID != "call_explicit_b" {
		t.Fatalf("explicit response associations lost current facts: %+v", calls)
	}
}

func TestOAI022CachedResponseCannotOverrideLostRequestAssociation(t *testing.T) {
	history := newResponseContextHistory()
	if !history.start("run-scope", "resp_cached", "", false) {
		t.Fatal("fresh observed response was not known")
	}
	if history.start("run-scope", "resp_cached", "", true) {
		t.Fatal("cached response overrode a lost request association")
	}
}

func TestOAI022ResponseHistoryDoesNotCrossRouteFamilies(t *testing.T) {
	var calls []ToolUse
	p := &Proxy{ToolUse: ToolUseObserverFunc(func(call ToolUse) { calls = append(calls, call) })}
	open := func(path string) *responsesWebSocketObserver {
		r := responseRequest(nil)
		r.URL.Path = path
		r = r.WithContext(WithRunID(r.Context(), "run-same-thread"))
		return p.newResponsesObservation(r)
	}
	api := open("/v1/responses")
	responseWSFrame(api, UpstreamToClient, `{"type":"response.created","response":{"id":"resp_route_scoped"}}`)
	responseWSFrame(api, UpstreamToClient, `{"type":"response.completed","response":{"id":"resp_route_scoped","status":"completed","output":[]}}`)
	api.Finish()
	chatgpt := open("/backend-api/codex/responses")
	responseWSFrame(chatgpt, ClientToUpstream, `{"type":"response.create","previous_response_id":"resp_route_scoped","input":"continue"}`)
	responseWSFrame(chatgpt, UpstreamToClient, `{"type":"response.created","response":{"id":"resp_other_route"}}`)
	responseWSFrame(chatgpt, UpstreamToClient, `{"type":"response.output_item.done","item":{"type":"function_call","call_id":"call_other_route","name":"exec_command","arguments":"{}"}}`)
	chatgpt.Finish()
	if len(calls) != 1 || !calls[0].ContextIncomplete || calls[0].ObservationIncomplete {
		t.Fatalf("response history crossed route families or erased the current item: %+v", calls)
	}
}
