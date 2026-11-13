// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"innsegl.dev/innsegl/internal/erasure"
	"innsegl.dev/innsegl/internal/mcp"
)

func TestOAI018RepositoryErasureRemovesPersistedCallInputs(t *testing.T) {
	bodyRoot := filepath.Join(t.TempDir(), "bodies")
	store, err := NewCallStateStore(bodyRoot)
	if err != nil {
		t.Fatal(err)
	}
	if saveErr := store.save(stateFromPending(recTestRunID, "call_erased_input", pendingCall{
		tool: "exec_command", input: json.RawMessage(`{"cmd":"repository private input"}`),
	})); saveErr != nil {
		t.Fatal(saveErr)
	}
	if _, removeErr := erasure.RemoveBodies(bodyRoot, []string{recTestRunID}); removeErr != nil {
		t.Fatal(removeErr)
	}
	state, err := store.load(recTestRunID, "call_erased_input")
	if err != nil || state != nil {
		t.Fatalf("repository erasure retained a private command copy: present=%v err=%v", state != nil, err)
	}
}

func TestOAI018CallStateRefusesRedirectedOrInvalidRunDirectories(t *testing.T) {
	bodyRoot := filepath.Join(t.TempDir(), "bodies")
	store, err := NewCallStateStore(bodyRoot)
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if linkErr := os.Symlink(outside, filepath.Join(bodyRoot, recTestRunID)); linkErr != nil {
		t.Fatal(linkErr)
	}
	for _, run := range []string{recTestRunID, "../outside", "/absolute", "run/child"} {
		saveErr := store.save(stateFromPending(run, "call_directory_guard", pendingCall{
			tool: "exec_command", input: json.RawMessage(`{"cmd":"private command"}`),
		}))
		if saveErr == nil {
			t.Fatalf("accepted redirected or invalid run directory %q", run)
		}
	}
	files, err := os.ReadDir(outside)
	if err != nil || len(files) != 0 {
		t.Fatalf("persisted a private input outside the run directory: %v %v", files, err)
	}
}

// OAI-018: a completed import may contain the command while a later import
// contains its result. Restarting between them must retain their association
// without reopening a current signing window.
func TestOAI018PendingImportSurvivesRecorderRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "states")
	store, err := NewCallStateStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	calls := &fakeRecordCalls{}
	first := NewToolCallRecorder(ToolCallRecorderConfig{CallStates: store, record: calls.fn})
	ctx := WithReplay(WithRunID(context.Background(), recTestRunID))
	ctx = WithIdentification(ctx, Identification{Harness: "codex"})
	first.OnToolUseContext(ctx, ToolUse{ID: "call_restart_pair", Name: "exec_command", WireType: "function_call", Input: json.RawMessage(`{"cmd":"echo retained"}`)})
	store, err = NewCallStateStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	restarted := NewToolCallRecorder(ToolCallRecorderConfig{CallStates: store, record: calls.fn})
	restarted.HandleResults(ctx, recTestRunID, RequestFacts{}, []observedToolResult{recResult("call_restart_pair", `"retained"`, false)})
	waitForCalls(t, calls, 1)
	var body gatewayToolCallBody
	if err := json.Unmarshal(calls.snapshot()[0].Body, &body); err != nil {
		t.Fatal(err)
	}
	if !body.ResultObserved || string(body.Input) != `{"cmd":"echo retained"}` || string(body.Result) != `"retained"` {
		t.Fatalf("restart lost call/result association: %+v", body)
	}
	restarted.OnToolUseContext(ctx, ToolUse{ID: "call_restart_pair", Name: "exec_command", WireType: "function_call", Input: json.RawMessage(`{"cmd":"echo retained"}`)})
	if _, ok := restarted.LookupPending("call_restart_pair"); ok {
		t.Fatal("restored historical observation reopened signing")
	}
	restarted.HandleResults(ctx, recTestRunID, RequestFacts{}, []observedToolResult{recResult("call_restart_pair", `"retained"`, false)})
	if got := len(calls.snapshot()); got != 1 {
		t.Fatalf("repeated import appended another observation: %d", got)
	}
}

func TestOAI018UnreadableCallStateCannotAuthorizeSigning(t *testing.T) {
	for _, corrupt := range []string{"malformed", "symlink"} {
		t.Run(corrupt, func(t *testing.T) {
			store, err := NewCallStateStore(filepath.Join(t.TempDir(), "states"))
			if err != nil {
				t.Fatal(err)
			}
			path := store.path(recTestRunID, "call_unreadable_state")
			if mkdirErr := os.MkdirAll(filepath.Dir(path), 0700); mkdirErr != nil {
				t.Fatal(mkdirErr)
			}
			if corrupt == "symlink" {
				err = os.Symlink(filepath.Join(t.TempDir(), "absent"), path)
			} else {
				err = os.WriteFile(path, []byte("{"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			rec := NewToolCallRecorder(ToolCallRecorderConfig{CallStates: store, record: (&fakeRecordCalls{}).fn})
			ctx := WithReplay(WithRunID(context.Background(), recTestRunID))
			rec.OnToolUseContext(ctx, ToolUse{ID: "call_unreadable_state", Name: "exec_command", WireType: "function_call", Input: json.RawMessage(`{"cmd":"git commit -m invalid"}`)})
			if _, ok := rec.LookupPending("call_unreadable_state"); ok {
				t.Fatal("unreadable prior evidence opened a signing window")
			}
			if rec.FailedRecordings() != 1 {
				t.Fatal("unreadable observation storage was not reported")
			}
		})
	}
}

// OAI-018: a crash after the ledger accepted a write but before the recorder
// received its acknowledgement retries the exact body/digest, not a new
// snapshot or newly rendered result.
func TestOAI018RecordingRetryRetainsCanonicalPayload(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "states")
	store, err := NewCallStateStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	var attempts []mcp.GatewayToolCallInput
	record := func(_ context.Context, in mcp.GatewayToolCallInput) (mcp.GatewayToolCallOutput, error) {
		attempts = append(attempts, in)
		if len(attempts) == 1 {
			return mcp.GatewayToolCallOutput{}, errors.New("acknowledgement lost")
		}
		return mcp.GatewayToolCallOutput{}, nil
	}
	ctx := WithReplay(WithRunID(context.Background(), recTestRunID))
	first := NewToolCallRecorder(ToolCallRecorderConfig{CallStates: store, record: record})
	call := ToolUse{ID: "call_canonical_retry", Name: "exec_command", Input: json.RawMessage(`{"cmd":"echo first"}`)}
	first.OnToolUseContext(ctx, call)
	first.HandleResults(ctx, recTestRunID, RequestFacts{}, []observedToolResult{recResult(call.ID, `"first output"`, false)})
	reopened, err := NewCallStateStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	next := NewToolCallRecorder(ToolCallRecorderConfig{CallStates: reopened, record: record})
	next.HandleResults(ctx, recTestRunID, RequestFacts{}, []observedToolResult{recResult(call.ID, `"different retried output"`, false)})
	if len(attempts) != 2 || !bytes.Equal(attempts[0].Body, attempts[1].Body) || attempts[0].WorkspaceTreeHash != attempts[1].WorkspaceTreeHash {
		t.Fatalf("retry changed the canonical recording: %+v", attempts)
	}
}

func TestOAI018UnfinishedGapWriteIsRecoveredAfterRestart(t *testing.T) {
	states, err := NewCallStateStore(filepath.Join(t.TempDir(), "states"))
	if err != nil {
		t.Fatal(err)
	}
	// This is the durable boundary just before the initial gap-recording
	// worker runs. A crash here must not turn its persisted denial into
	// a permanently invisible gap.
	if err := states.save(stateFromPending(recTestRunID, "call_unfinished_gap", pendingCall{
		tool: "exec_command", observationIncomplete: true, recorded: true,
	})); err != nil {
		t.Fatal(err)
	}
	calls := &fakeRecordCalls{}
	rec := NewToolCallRecorder(ToolCallRecorderConfig{CallStates: states, record: calls.fn})
	ctx := WithReplay(WithRunID(context.Background(), recTestRunID))
	rec.OnToolUseContext(ctx, ToolUse{ID: "call_unfinished_gap", Name: "exec_command", Input: json.RawMessage(`{"cmd":"must not become complete"}`)})
	if len(calls.snapshot()) != 1 {
		t.Fatal("persisted unfinished gap was never recorded after restart")
	}
	var body gatewayToolCallBody
	if err := json.Unmarshal(calls.snapshot()[0].Body, &body); err != nil {
		t.Fatal(err)
	}
	if !body.ObservationIncomplete || len(body.Input) != 0 {
		t.Fatalf("recovered gap gained command input: %+v", body)
	}
}
