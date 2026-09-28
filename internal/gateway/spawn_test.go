// SPDX-License-Identifier: Apache-2.0

package gateway

// spawn_test.go — RM-235 (#380): SpawnRecorder (identity.go), feeding
// TreeLinker.RecordSpawn from a parent's own Agent/Task tool_use, with the
// PARENT's run id read off the request's context (proxy.go's
// ContextToolUseObserver).

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// guardFunc adapts a plain func to a Guard, for a test double that does not
// warrant its own named type.
type guardFunc func(r *http.Request) (*http.Request, *Refusal)

func (f guardFunc) Check(r *http.Request) (*http.Request, *Refusal) { return f(r) }

func fixedClock(at time.Time) func() time.Time { return func() time.Time { return at } }

func spawnCtx(sessionID, runID string) context.Context {
	ctx := WithIdentification(context.Background(), Identification{SessionID: sessionID, AgentID: mainAgentID})
	return WithRunID(ctx, runID)
}

func TestSpawnRecorderRecordsAnAgentToolUseAsAPendingSpawn(t *testing.T) {
	tree := &fakeTreeLinker{}
	rec := NewSpawnRecorder(tree, fixedClock(time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)))

	rec.OnToolUseContext(spawnCtx("s1", "run-parent"), ToolUse{
		ID: "toolu_1", Name: "Agent", Input: []byte(`{"prompt":"do the subtask"}`),
	})

	if len(tree.spawns) != 1 {
		t.Fatalf("recorded %d spawns, want 1", len(tree.spawns))
	}
	got := tree.spawns[0]
	if got.ParentRunID != "run-parent" || got.SessionID != "s1" || got.Prompt != "do the subtask" {
		t.Errorf("recorded spawn = %+v, want parent=run-parent session=s1 prompt=%q", got, "do the subtask")
	}
}

func TestSpawnRecorderRecordsATaskToolUseToo(t *testing.T) {
	tree := &fakeTreeLinker{}
	rec := NewSpawnRecorder(tree, nil)

	rec.OnToolUseContext(spawnCtx("s1", "run-parent"), ToolUse{
		ID: "toolu_1", Name: "Task", Input: []byte(`{"prompt":"do the other subtask"}`),
	})

	if len(tree.spawns) != 1 {
		t.Fatalf("recorded %d spawns, want 1", len(tree.spawns))
	}
}

func TestSpawnRecorderIgnoresAnUnrelatedToolName(t *testing.T) {
	tree := &fakeTreeLinker{}
	rec := NewSpawnRecorder(tree, nil)

	rec.OnToolUseContext(spawnCtx("s1", "run-parent"), ToolUse{
		ID: "toolu_1", Name: "Bash", Input: []byte(`{"prompt":"do the subtask"}`),
	})

	if len(tree.spawns) != 0 {
		t.Fatalf("recorded %d spawns for a non-spawning tool, want 0", len(tree.spawns))
	}
}

func TestSpawnRecorderIgnoresATruncatedToolUse(t *testing.T) {
	tree := &fakeTreeLinker{}
	rec := NewSpawnRecorder(tree, nil)

	rec.OnToolUseContext(spawnCtx("s1", "run-parent"), ToolUse{
		ID: "toolu_1", Name: "Agent", Truncated: true,
	})

	if len(tree.spawns) != 0 {
		t.Fatalf("recorded %d spawns for a truncated tool_use, want 0", len(tree.spawns))
	}
}

func TestSpawnRecorderIgnoresAToolUseWithNoPrompt(t *testing.T) {
	tree := &fakeTreeLinker{}
	rec := NewSpawnRecorder(tree, nil)

	rec.OnToolUseContext(spawnCtx("s1", "run-parent"), ToolUse{
		ID: "toolu_1", Name: "Agent", Input: []byte(`{"description":"no prompt field"}`),
	})

	if len(tree.spawns) != 0 {
		t.Fatalf("recorded %d spawns with no prompt, want 0", len(tree.spawns))
	}
}

func TestSpawnRecorderIgnoresAMalformedInput(t *testing.T) {
	tree := &fakeTreeLinker{}
	rec := NewSpawnRecorder(tree, nil)

	rec.OnToolUseContext(spawnCtx("s1", "run-parent"), ToolUse{
		ID: "toolu_1", Name: "Agent", Input: []byte(`not json`),
	})

	if len(tree.spawns) != 0 {
		t.Fatalf("recorded %d spawns for malformed input, want 0", len(tree.spawns))
	}
}

func TestSpawnRecorderIgnoresAContextWithNoIdentification(t *testing.T) {
	tree := &fakeTreeLinker{}
	rec := NewSpawnRecorder(tree, nil)

	rec.OnToolUseContext(WithRunID(context.Background(), "run-parent"), ToolUse{
		ID: "toolu_1", Name: "Agent", Input: []byte(`{"prompt":"do the subtask"}`),
	})

	if len(tree.spawns) != 0 {
		t.Fatalf("recorded %d spawns with no Identification on the context, want 0", len(tree.spawns))
	}
}

func TestSpawnRecorderIgnoresAContextWithNoRunID(t *testing.T) {
	tree := &fakeTreeLinker{}
	rec := NewSpawnRecorder(tree, nil)

	rec.OnToolUseContext(WithIdentification(context.Background(), Identification{SessionID: "s1", AgentID: mainAgentID}), ToolUse{
		ID: "toolu_1", Name: "Agent", Input: []byte(`{"prompt":"do the subtask"}`),
	})

	if len(tree.spawns) != 0 {
		t.Fatalf("recorded %d spawns with no run id on the context, want 0", len(tree.spawns))
	}
}

// OnToolUse (the plain, context-less path) never records anything: without
// a request context there is no parent run id, and this package never
// guesses one.
func TestSpawnRecorderOnToolUsePlainIsANoOp(t *testing.T) {
	tree := &fakeTreeLinker{}
	rec := NewSpawnRecorder(tree, nil)
	rec.OnToolUse(ToolUse{Name: "Agent", Input: []byte(`{"prompt":"x"}`)})
	if len(tree.spawns) != 0 {
		t.Fatalf("OnToolUse recorded %d spawns, want 0", len(tree.spawns))
	}
}

// TestSpawnRecorderEndToEndThroughProxyReceivesTheParentsRunID proves the
// full wire-up (proxy.go's boundToolUseObserver): a SpawnRecorder set as
// Proxy.ToolUse, on a request the identity guard (stood in for here by a
// bare Guard attaching a run id, since this is proxy.go's own plumbing
// under test, not the identity guard's decision logic) has already
// resolved, sees the PARENT's run id when the parent's own reply streams an
// Agent tool_use.
func TestSpawnRecorderEndToEndThroughProxyReceivesTheParentsRunID(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("upstream: ResponseWriter is not a Flusher")
		}
		write := func(event, data string) { writeSSEEvent(t, w, flusher, event, data) }
		write("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"Agent","input":{}}}`)
		write("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"prompt\": \"do the subtask\"}"}}`)
		write("content_block_stop", `{"type":"content_block_stop","index":0}`)
	}))
	defer upstream.Close()

	up, err := NewUpstream(upstream.URL, upstream.Client())
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}

	tree := &fakeTreeLinker{}
	recorder := NewSpawnRecorder(tree, nil)

	// A stand-in identity guard, attaching a fixed run id -- exactly what
	// IdentityGuard.Check does for a permitted request, isolated here so
	// this test is about the proxy/observer wiring and not about lifecycle
	// decisions (identity_test.go already covers those).
	attachRunID := guardFunc(func(r *http.Request) (*http.Request, *Refusal) {
		return r.WithContext(WithRunID(r.Context(), "run-parent")), nil
	})

	p := &Proxy{
		Upstream: up,
		ToolUse:  recorder,
		Guards:   []Guard{NewHarnessGuard(), attachRunID},
	}
	gw := httptest.NewServer(p)
	defer gw.Close()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, gw.URL+"/v1/messages", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	req.Header.Set(headerClaudeCodeSessionID, validSessionID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatalf("read reply: %v", err)
	}

	if len(tree.spawns) != 1 {
		t.Fatalf("recorded %d spawns, want 1", len(tree.spawns))
	}
	got := tree.spawns[0]
	if got.ParentRunID != "run-parent" {
		t.Errorf("ParentRunID = %q, want run-parent", got.ParentRunID)
	}
	if got.SessionID != validSessionID {
		t.Errorf("SessionID = %q, want %q", got.SessionID, validSessionID)
	}
	if got.Prompt != "do the subtask" {
		t.Errorf("Prompt = %q, want %q", got.Prompt, "do the subtask")
	}
}
