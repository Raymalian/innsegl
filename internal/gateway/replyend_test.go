// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"io"
	"net/http"
	"testing"
)

// The gateway sees a subagent finish: its last reply ends with stop_reason
// end_turn and asks for no tool, and the subagent sends nothing after it
// (a resumed one does, and that cancels the mark). It marks the subagent
// ended itself, with no hook needed; a main agent's end_turn is only a turn
// waiting for the person, and marks nothing.

const endTurnReply = "event: message_start\ndata: {\"type\":\"message_start\"}\n\n" +
	"event: content_block_start\ndata: {\"index\":0,\"content_block\":{\"type\":\"text\"}}\n\n" +
	"event: content_block_delta\ndata: {\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"PONG\"}}\n\n" +
	"event: content_block_stop\ndata: {\"index\":0}\n\n" +
	"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"}}\n\n" +
	"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"

const toolUseReply = "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"}}\n\n" +
	"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"

type endRecorder struct{ ended [][2]string }

func (e *endRecorder) SubagentEnded(_ context.Context, sessionID, agentID string) error {
	e.ended = append(e.ended, [2]string{sessionID, agentID})
	return nil
}

func replyFor(t *testing.T, p *Proxy, agentID, body string) {
	t.Helper()
	ctx := WithIdentification(context.Background(), Identification{SessionID: "s1", AgentID: agentID})
	w := p.replyEndWriter(ctx)
	if w == nil {
		t.Fatal("no reply-end writer for a configured proxy")
	}
	if _, err := w.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
}

func TestASubagentsFinalReplyMarksItEnded(t *testing.T) {
	rec := &endRecorder{}
	p := &Proxy{SubagentEnds: rec}
	replyFor(t, p, "a1", endTurnReply)
	if len(rec.ended) != 1 || rec.ended[0] != [2]string{"s1", "a1"} {
		t.Fatalf("ended %v, want subagent a1 of s1", rec.ended)
	}
}

func TestAToolCallOrAMainAgentTurnMarksNothing(t *testing.T) {
	rec := &endRecorder{}
	p := &Proxy{SubagentEnds: rec}
	replyFor(t, p, "a1", toolUseReply)
	replyFor(t, p, mainAgentID, endTurnReply)
	if len(rec.ended) != 0 {
		t.Fatalf("ended %v, want nothing", rec.ended)
	}
}

// replyEndWriter is the reply observer for ctx's request, for tests.
func (p *Proxy) replyEndWriter(ctx context.Context) io.Writer {
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, "/v1/messages", nil)
	if err != nil {
		return nil
	}
	return p.replyObserver(r, "text/event-stream")
}
