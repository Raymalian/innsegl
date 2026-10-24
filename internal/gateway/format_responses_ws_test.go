// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
)

type observedBeforeForwardWriter struct {
	bytes.Buffer
	seen *bool
}

func (w *observedBeforeForwardWriter) Write(p []byte) (int, error) {
	if !*w.seen {
		return 0, errors.New("WebSocket frame forwarded before the Responses observer")
	}
	return w.Buffer.Write(p)
}

func TestOAI022ResponsesWebSocketObservesCompleteAndFragmentedCalls(t *testing.T) {
	var calls []ToolUse
	observer := newResponsesWebSocketObserver(ToolUseObserverFunc(func(call ToolUse) { calls = append(calls, call) }))
	first := []byte(`{"type":"response.output_item.done","item":{"type":"function_call","call_id":"call_ws1234567890","name":"exec_command","arguments":"{}"}}`)
	observer.OnFrame(Frame{Direction: UpstreamToClient, Opcode: OpcodeText, Fin: true, Payload: first, Length: uint64(len(first))})
	completed := []byte(`{"type":"response.completed","response":{"status":"completed","output":[]}}`)
	observer.OnFrame(Frame{Direction: UpstreamToClient, Opcode: OpcodeText, Fin: true, Payload: completed, Length: uint64(len(completed))})
	secondA := []byte(`{"type":"response.output_item.done","item":{"type":"custom_tool_call","call_id":"call_wsabcdefghij","name":"exec","input":"const `)
	secondB := []byte(`x = 1;"}}`)
	observer.OnFrame(Frame{Direction: UpstreamToClient, Opcode: OpcodeText, Payload: secondA, Length: uint64(len(secondA))})
	observer.OnFrame(Frame{Direction: UpstreamToClient, Opcode: OpcodePing, Fin: true, Payload: []byte("interleaved"), Length: 11})
	observer.OnFrame(Frame{Direction: UpstreamToClient, Opcode: OpcodeContinuation, Fin: true, Payload: secondB, Length: uint64(len(secondB))})
	observer.OnFrame(Frame{Direction: ClientToUpstream, Opcode: OpcodeText, Payload: []byte(`{"type":"ignored"}`), Length: 18})
	observer.Finish()
	if len(calls) != 2 || calls[0].ID != "call_ws1234567890" || calls[1].ID != "call_wsabcdefghij" || calls[1].Truncated || calls[1].ObservationIncomplete {
		t.Fatalf("observed calls: %+v", calls)
	}
	var input map[string]string
	if err := json.Unmarshal(calls[1].Input, &input); err != nil || input["input"] != "const x = 1;" {
		t.Fatalf("fragmented custom input=%s err=%v", calls[1].Input, err)
	}
}

func TestOAI022ResponsesWebSocketDisconnectRecordsKnownCallAsIncomplete(t *testing.T) {
	var calls []ToolUse
	observer := newResponsesWebSocketObserver(ToolUseObserverFunc(func(call ToolUse) { calls = append(calls, call) }))
	data := []byte(`{"type":"response.output_item.added","item":{"type":"function_call","call_id":"call_partial123456","name":"exec_command","arguments":"{\"cmd\":"}}`)
	observer.OnFrame(Frame{Direction: UpstreamToClient, Opcode: OpcodeText, Fin: true, Payload: data, Length: uint64(len(data))})
	observer.Finish()
	if len(calls) != 1 || !calls[0].ObservationIncomplete || calls[0].Input != nil {
		t.Fatalf("partial call was not input-free and marked incomplete: %+v", calls)
	}
}

func TestOAI022ResponsesWebSocketDropsOverLimitMessage(t *testing.T) {
	var calls []ToolUse
	observer := newResponsesWebSocketObserver(ToolUseObserverFunc(func(call ToolUse) { calls = append(calls, call) }))
	data := make([]byte, maxObservedFramePayload+1)
	observer.OnFrame(Frame{Direction: UpstreamToClient, Opcode: OpcodeText, Payload: data[:maxObservedFramePayload], Length: uint64(len(data)), Truncated: true})
	observer.OnFrame(Frame{Direction: UpstreamToClient, Opcode: OpcodeContinuation, Payload: []byte(`{"type":"response.output_item.done"}`), Length: 34})
	observer.Finish()
	if len(calls) != 0 {
		t.Fatalf("truncated WebSocket message produced calls: %+v", calls)
	}
}

type wsMessageCapture struct {
	mu  sync.Mutex
	got []string
}

func (c *wsMessageCapture) OnResponsesWebSocketMessage(_ context.Context, payload []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = append(c.got, string(payload))
}

func (*wsMessageCapture) OnToolUse(ToolUse) {}

func (c *wsMessageCapture) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.got...)
}

func TestOAI022ResponsesWebSocketObservesClientToolResults(t *testing.T) {
	capture := &wsMessageCapture{}
	observer := newResponsesWebSocketObserver(nil)
	observer.messages = capture
	observer.ctx = context.Background()
	message := []byte(`{"type":"response.create","response":{"input":[{"type":"function_call_output","call_id":"call_result1234567","output":"done"}]}}`)
	observer.OnFrame(Frame{Direction: ClientToUpstream, Opcode: OpcodeText, Fin: true, Payload: message, Length: uint64(len(message))})
	got := capture.snapshot()
	if len(got) != 1 || got[0] != string(message) {
		t.Fatalf("client message observations=%q", got)
	}
	results := (responsesFormat{}).results([]byte(got[0]))
	if len(results) != 1 || results[0].ToolUseID != "call_result1234567" || results[0].ErrorSignal != "unknown" {
		t.Fatalf("nested response.create results=%+v", results)
	}
}

func TestOAI022ResponsesWebSocketKeepsFragmentsSeparateByDirection(t *testing.T) {
	var calls []ToolUse
	capture := &wsMessageCapture{}
	observer := newResponsesWebSocketObserver(ToolUseObserverFunc(func(call ToolUse) { calls = append(calls, call) }))
	observer.messages = capture
	observer.ctx = context.Background()
	first := []byte(`{"type":"response.output_item.done","item":{"type":"function_call","call_id":"call_split12345678","name":"exec_command","arguments":"{}"}}`)
	half := len(first) / 2
	observer.OnFrame(Frame{Direction: UpstreamToClient, Opcode: OpcodeText, Payload: first[:half], Length: uint64(half)})
	client := []byte(`{"type":"response.create","response":{"input":[{"type":"function_call_output","call_id":"call_split12345678","output":"ok"}]}}`)
	observer.OnFrame(Frame{Direction: ClientToUpstream, Opcode: OpcodeText, Fin: true, Payload: client, Length: uint64(len(client))})
	observer.OnFrame(Frame{Direction: UpstreamToClient, Opcode: OpcodeContinuation, Fin: true, Payload: first[half:], Length: uint64(len(first) - half)})
	observer.Finish()
	if len(calls) != 1 || calls[0].ID != "call_split12345678" {
		t.Fatalf("upstream fragmented call was lost or corrupted: %+v", calls)
	}
	if got := capture.snapshot(); len(got) != 1 || got[0] != string(client) {
		t.Fatalf("client message was lost or corrupted: %q", got)
	}
}

func TestOAI022ResponsesWebSocketObservesCallBeforeForwardingFrame(t *testing.T) {
	seen := false
	observer := newResponsesWebSocketObserver(ToolUseObserverFunc(func(ToolUse) { seen = true }))
	payload := []byte(`{"type":"response.output_item.done","item":{"type":"function_call","call_id":"call_beforeforward123","name":"exec_command","arguments":"{}"}}`)
	header := wsFrameHeader{opcode: OpcodeText, fin: true, length: uint64(len(payload))}
	raw := []byte{0x81, byte(len(payload))}
	dst := &observedBeforeForwardWriter{seen: &seen}
	if err := relayOneFrame(UpstreamToClient, header, raw, bufio.NewReader(bytes.NewReader(payload)), dst, observer); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dst.Bytes(), append(raw, payload...)) {
		t.Fatal("observer ordering changed the relayed WebSocket frame")
	}
}

func TestOAI022ResponsesWebSocketDoesNotObserveClientFramesWhenTheyAreTruncated(t *testing.T) {
	capture := &wsMessageCapture{}
	observer := newResponsesWebSocketObserver(nil)
	observer.messages = capture
	observer.ctx = context.Background()
	observer.OnFrame(Frame{Direction: ClientToUpstream, Opcode: OpcodeText, Payload: []byte(`{"type":"response.create"}`), Length: uint64(maxObservedFramePayload + 1), Truncated: true})
	observer.Finish()
	if got := capture.snapshot(); len(got) != 0 {
		t.Fatalf("truncated client message observed: %q", got)
	}
}

func BenchmarkOAI022ResponsesWebSocketObserver(b *testing.B) {
	var calls int
	observer := newResponsesWebSocketObserver(ToolUseObserverFunc(func(ToolUse) { calls++ }))
	payload := []byte(`{"type":"response.output_item.done","item":{"type":"function_call","call_id":"call_bench12345678","name":"exec_command","arguments":"{\"cmd\":\"git status --short\"}"}}`)
	terminal := []byte(`{"type":"response.completed","response":{"status":"completed","output":[]}}`)
	frame := Frame{Direction: UpstreamToClient, Opcode: OpcodeText, Fin: true, Payload: payload, Length: uint64(len(payload))}
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		observer.OnFrame(frame)
		observer.OnFrame(Frame{Direction: UpstreamToClient, Opcode: OpcodeText, Fin: true, Payload: terminal, Length: uint64(len(terminal))})
	}
	observer.Finish()
	if calls != b.N {
		b.Fatalf("calls=%d, want %d", calls, b.N)
	}
}
