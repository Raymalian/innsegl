// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/commitpath"
)

// OAI-016: a repeated identifier across runs is ambiguous, even when both
// commands are byte-identical. A signer must not select an arbitrary run.
func TestOAI016AmbiguousPendingCallCannotAuthorizeSigning(t *testing.T) {
	rec := NewToolCallRecorder(ToolCallRecorderConfig{})
	for _, run := range []string{"run-a", "run-b"} {
		ctx := WithIdentification(WithRunID(context.Background(), run), Identification{Harness: "codex"})
		rec.OnToolUseContext(ctx, recToolUse("call_duplicate", "exec_command", `{"cmd":"git commit -m same"}`))
	}
	if call, ok := rec.LookupPending("call_duplicate"); ok {
		t.Fatalf("ambiguous id resolved to %+v", call)
	}
	rec.HandleResults(context.Background(), "run-a", RequestFacts{}, []observedToolResult{recResult("call_duplicate", `"done"`, false)})
	if _, ok := rec.LookupPending("call_duplicate"); ok {
		t.Fatal("ambiguity disappeared when another run completed")
	}

}

// OAI-013/021: the direct shell namespace is part of independently
// observed evidence; a same-named function in another namespace differs.
func TestOAI013ResponsesPreservesFunctionNamespace(t *testing.T) {
	var got []ToolUse
	r := newResponsesInterpreter(ToolUseObserverFunc(func(c ToolUse) { got = append(got, c) }))
	r.event("response.output_item.done", `{"item":{"type":"function_call","namespace":"functions","name":"exec_command","call_id":"call_direct","arguments":"{\"cmd\":\"git commit -m change\"}"}}`)
	r.event("response.output_item.done", `{"item":{"type":"function_call","namespace":"mcp_tools","name":"exec_command","call_id":"call_foreign","arguments":"{\"cmd\":\"git commit -m change\"}"}}`)
	if len(got) != 2 || got[0].Name != "functions.exec_command" || got[1].Name != "mcp_tools.exec_command" {
		t.Fatalf("namespace lost: %+v", got)
	}
}

// OAI-021: a bare function name cannot impersonate a namespaced shell tool.
func TestOAI021BareFunctionCannotAuthorizeSigning(t *testing.T) {
	rec := NewToolCallRecorder(ToolCallRecorderConfig{})
	ctx := WithIdentification(WithRunID(context.Background(), "run-direct"), Identification{Harness: "codex"})
	r := newResponsesInterpreter(ToolUseObserverFunc(func(c ToolUse) { rec.OnToolUseContext(ctx, c) }))
	r.event("response.output_item.done", `{"item":{"type":"function_call","name":"functions.exec_command","call_id":"call_fake","arguments":"{\"cmd\":\"git commit -m change\"}"}}`)
	if _, err := commitpath.Resolve(rec, "call_fake", time.Now()); err == nil {
		t.Fatal("bare function impersonated shell namespace")
	}
}

// OAI-014: provenance survives the parser/recorder boundary rather than
// accepting only hand-built resolver fixtures.
func TestOAI014DirectFunctionProvenanceReachesSigningGate(t *testing.T) {
	rec := NewToolCallRecorder(ToolCallRecorderConfig{})
	ctx := WithIdentification(WithRunID(context.Background(), "run-direct"), Identification{Harness: "codex"})
	r := newResponsesInterpreter(ToolUseObserverFunc(func(c ToolUse) { rec.OnToolUseContext(ctx, c) }))
	r.event("response.output_item.done", `{"item":{"type":"function_call","namespace":"functions","name":"exec_command","call_id":"call_direct","arguments":"{\"cmd\":\"git commit -m change\"}"}}`)
	call, err := commitpath.Resolve(rec, "call_direct", time.Now())
	if err != nil || call.RunID != "run-direct" {
		t.Fatalf("direct provenance lost: %+v %v", call, err)
	}
}

// OAI-016: replay cannot replace evidence or extend its signing lifetime.
func TestOAI016SameRunReplayPreservesSigningEvidence(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		t.Run(fmt.Sprint(conflict), func(t *testing.T) {
			rec := NewToolCallRecorder(ToolCallRecorderConfig{})
			call := ToolUse{ID: "call_replay", Name: "functions.exec_command", Namespace: "functions", Input: json.RawMessage(`{"cmd":"git commit -m first"}`)}
			rec.addPending("run-a", "", "", "", "", "codex", call, CodexThreadIdentity{})
			key := pendingKey{runID: "run-a", toolUseID: call.ID}
			old := time.Now().Add(-time.Hour)
			original := rec.pending[key]
			original.observedAt = old
			rec.pending[key] = original
			if conflict {
				call.Input = json.RawMessage(`{"cmd":"git commit -m replacement"}`)
			}
			rec.addPending("run-a", "", "", "", "", "codex", call, CodexThreadIdentity{})
			if conflict {
				if _, ok := rec.LookupPending(call.ID); ok {
					t.Fatal("conflicting replay remained eligible")
				}
			} else if got := rec.pending[key].observedAt; !got.Equal(old) {
				t.Fatal("identical replay renewed signing lifetime")
			}
		})
	}
}

// OAI-014/021: the live CLI emits flat function names without a namespace.
// Preserve the wire kind so a same-named custom call cannot impersonate it.
func TestOAI014LiveFlatFunctionReachesSigningGate(t *testing.T) {
	for _, kind := range []string{"function_call", "custom_tool_call"} {
		t.Run(kind, func(t *testing.T) {
			rec := NewToolCallRecorder(ToolCallRecorderConfig{})
			ctx := WithIdentification(WithRunID(context.Background(), "run-flat"), Identification{Harness: "codex"})
			parser := newResponsesInterpreter(ToolUseObserverFunc(func(c ToolUse) { rec.OnToolUseContext(ctx, c) }))
			parser.event("response.output_item.done", fmt.Sprintf(`{"item":{"type":%q,"name":"exec_command","call_id":"call_flat","arguments":"{\"cmd\":\"git commit --allow-empty -m change\"}","input":"{\"cmd\":\"git commit --allow-empty -m change\"}"}}`, kind))
			_, err := commitpath.Resolve(rec, "call_flat", time.Now())
			if (err == nil) != (kind == "function_call") {
				t.Fatalf("kind=%s resolve=%v", kind, err)
			}
		})
	}
}

// OAI-006/021: commit scope must come from the recognized wire context.
func TestOAI006RecorderPreservesCodexThreadForCommitScope(t *testing.T) {
	const session = "11111111-1111-4111-8111-111111111111"
	const child = "22222222-2222-4222-8222-222222222222"
	rec := NewToolCallRecorder(ToolCallRecorderConfig{})
	ctx := WithIdentification(WithRunID(context.Background(), "run-child"), Identification{Harness: "codex", SessionID: session, AgentID: child})
	ctx = context.WithValue(ctx, codexThreadContextKey{}, CodexThreadIdentity{SessionID: session, ThreadID: child})
	parser := newResponsesInterpreter(ToolUseObserverFunc(func(c ToolUse) { rec.OnToolUseContext(ctx, c) }))
	parser.event("response.output_item.done", `{"item":{"type":"function_call","name":"exec_command","call_id":"call_child_scoped","arguments":"{\"cmd\":\"git commit -m change\"}"}}`)
	if _, err := commitpath.Resolve(commitpath.ThreadScopedResolver(rec, session, child), "call_child_scoped", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := commitpath.Resolve(commitpath.ThreadScopedResolver(rec, session, session), "call_child_scoped", time.Now()); err == nil {
		t.Fatal("parent borrowed child call")
	}
}
