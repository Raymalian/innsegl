// SPDX-License-Identifier: Apache-2.0

package commitpath_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/commitpath"
	"innsegl.dev/innsegl/internal/gateway"
)

func observeCommit(rec *gateway.ToolCallRecorder, run, installation, workspace, id string) {
	ctx := gateway.WithRunID(context.Background(), run)
	ctx = gateway.WithInstallation(ctx, installation)
	ctx = gateway.WithIdentification(ctx, gateway.Identification{Harness: "codex"})
	ctx = gateway.WithRequestFacts(ctx, gateway.RequestFacts{WorkingDirectory: workspace})
	rec.OnToolUseContext(ctx, gateway.ToolUse{ID: id, Name: "functions.exec_command", Namespace: "functions", WireType: "function_call", Input: json.RawMessage(`{"cmd":"git commit -m change"}`)})
}

// OAI-016: concurrent child observations retain their own run and workspace;
// installation scoping excludes other clients. This does not establish that
// callers sharing an installation are independently authenticated children.
func TestOAI016ConcurrentChildCommitProvenance(t *testing.T) {
	rec := gateway.NewToolCallRecorder(gateway.ToolCallRecorderConfig{})
	var wg sync.WaitGroup
	for _, child := range []struct{ run, workspace, id string }{
		{"child-a", "/workspace/a", "call_child_a"},
		{"child-b", "/workspace/b", "call_child_b"},
	} {
		wg.Add(1)
		go func() { defer wg.Done(); observeCommit(rec, child.run, "installation-a", child.workspace, child.id) }()
	}
	wg.Wait()
	for _, child := range []struct{ run, workspace, id string }{
		{"child-a", "/workspace/a", "call_child_a"},
		{"child-b", "/workspace/b", "call_child_b"},
	} {
		got, err := commitpath.Resolve(commitpath.ScopedResolver(rec, "installation-a"), child.id, time.Now())
		if err != nil || got.RunID != child.run || got.WorkingDirectory != child.workspace {
			t.Fatalf("child provenance = %+v, %v", got, err)
		}
		if _, err := commitpath.Resolve(commitpath.ScopedResolver(rec, "installation-b"), child.id, time.Now()); err == nil {
			t.Fatal("another installation resolved child call")
		}
	}
}

// OAI-016: a duplicate identifier cannot arbitrarily select one child's run,
// including after one duplicate has completed.
func TestOAI016DuplicateChildCallStaysIneligibleAfterCompletion(t *testing.T) {
	rec := gateway.NewToolCallRecorder(gateway.ToolCallRecorderConfig{})
	observeCommit(rec, "child-a", "installation-a", "/workspace/a", "call_shared")
	observeCommit(rec, "child-b", "installation-a", "/workspace/b", "call_shared")
	if _, err := commitpath.Resolve(rec, "call_shared", time.Now()); err == nil {
		t.Fatal("duplicate selected a child")
	}
	completeCommit(t, rec, "child-a", "call_shared")
	if _, err := commitpath.Resolve(rec, "call_shared", time.Now()); err == nil {
		t.Fatal("completion made duplicate eligible")
	}
}

// OAI-014/016: only the originating run's result completes an eligible call.
func TestOAI016CompletionIsBoundToOriginatingChildRun(t *testing.T) {
	rec := gateway.NewToolCallRecorder(gateway.ToolCallRecorderConfig{})
	observeCommit(rec, "child-a", "installation-a", "/workspace/a", "call_complete")
	completeCommit(t, rec, "child-b", "call_complete")
	if _, err := commitpath.Resolve(rec, "call_complete", time.Now()); err != nil {
		t.Fatalf("sibling result removed call: %v", err)
	}
	completeCommit(t, rec, "child-a", "call_complete")
	if _, err := commitpath.Resolve(rec, "call_complete", time.Now()); err == nil {
		t.Fatal("completed call still authorizes commit")
	}
}

func completeCommit(t *testing.T, rec *gateway.ToolCallRecorder, run, id string) {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/responses", strings.NewReader(`{"input":[{"type":"function_call_output","call_id":"`+id+`","output":"done"}]}`))
	req = req.WithContext(gateway.WithRunID(req.Context(), run))
	if _, refusal := gateway.NewToolCallRecordGuard(rec).Check(req); refusal != nil {
		t.Fatal("record guard refused result")
	}
}
