// SPDX-License-Identifier: Apache-2.0

package gateway

// record_test.go — #381 (RM-236), E16: unit-level coverage of the pairing,
// eviction, "only new turns" and snapshot-triggering logic in record.go,
// against a fake recording function and a fake snapshot witness — neither
// a real ledger, a real body store, nor a real git repository. The
// end-to-end claim through the real openGateway (GREC-001..004, GREC-007)
// is cmd/innsegl/gatewayrecord_test.go's own.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/commitpath"
	"innsegl.dev/innsegl/internal/mcp"
)

// ---------------------------------------------------------------------------
// A fake recording function and a fake snapshot witness.
// ---------------------------------------------------------------------------

// fakeRecordCalls collects every call the fake record function received,
// safe for concurrent use — every call this package's own ToolCallRecorder
// makes into it runs on a goroutine of its own (record.go's own doc
// comment, "witness, never a gate").
type fakeRecordCalls struct {
	mu    sync.Mutex
	calls []mcp.GatewayToolCallInput
	err   error
}

func (f *fakeRecordCalls) fn(_ context.Context, in mcp.GatewayToolCallInput) (mcp.GatewayToolCallOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, in)
	if f.err != nil {
		return mcp.GatewayToolCallOutput{}, f.err
	}
	return mcp.GatewayToolCallOutput{Digest: "sha256:" + strings.Repeat("a", 64), Stored: true}, nil
}

func (f *fakeRecordCalls) snapshot() []mcp.GatewayToolCallInput {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]mcp.GatewayToolCallInput(nil), f.calls...)
}

func (f *fakeRecordCalls) fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

// waitForCalls polls calls until it holds at least want entries, or fails
// t after five seconds. Recording is always asynchronous (record.go's own
// doc comment, "witness, never a gate"), so every test below that expects
// a recording to have happened waits for it this way rather than
// assuming it has already run by the time an OnToolUseContext or
// HandleResults call returns.
func waitForCalls(t *testing.T, calls *fakeRecordCalls, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if got := len(calls.snapshot()); got >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d recorded calls; got %d", want, len(calls.snapshot()))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waitForRecorded blocks until n signals have arrived on recorded (fed by
// ToolCallRecorderConfig's own onRecorded hook, which fires once for every
// recordAsync attempt this recorder completes, success or failure), or
// fails t after timeout — the same channel-plus-deadline idiom
// messages_test.go's own fakeAgentMessageRecorder.waitForCalls already
// uses, reused here rather than reinvented.
func waitForRecorded(t *testing.T, recorded <-chan struct{}, n int, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for i := 0; i < n; i++ {
		select {
		case <-recorded:
		case <-deadline:
			t.Fatalf("timed out waiting for onRecorded signal %d/%d", i+1, n)
		}
	}
}

// waitForNoFurtherRecording fails t immediately if a signal arrives on
// recorded within window — the deterministic replacement for a fixed
// time.Sleep(...) followed by one look at a recorded-calls slice: a
// wrongly-dispatched recording is caught the instant its own completion
// hook fires, whenever that is inside window, rather than however long
// after a blind sleep happened to run before the single check that
// followed it. The correct case still has to run out the whole window —
// there is no way to prove an absence sooner than that — but a buggy one
// fails as soon as it is observed, never later than window would have
// anyway, and the failure names what actually happened rather than a
// count that merely grew.
func waitForNoFurtherRecording(t *testing.T, recorded <-chan struct{}, window time.Duration) {
	t.Helper()
	select {
	case <-recorded:
		t.Fatal("a recording completed when none should have been dispatched")
	case <-time.After(window):
	}
}

// waitForPendingCount polls rec until its pending table holds exactly
// want entries, or fails t after five seconds — used where a test needs
// to observe a pending-side effect (an eviction) that carries no separate
// recorded call of its own to poll on instead.
func waitForPendingCount(t *testing.T, rec *ToolCallRecorder, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if got := rec.PendingCount(); got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for PendingCount = %d; got %d", want, rec.PendingCount())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// fakeSnapshotWitness is snapshotWitness, faked: it never touches git or a
// filesystem, and records what it was called with. Snapshot and
// SnapshotBaseline (#437, RM-274) keep entirely separate call counts and
// outcomes, since record.go calls them from two different places for two
// different reasons — a test that only configures outcome (Snapshot's own)
// sees baselineOutcome default to its zero value, SnapshotOutcome{}, which
// Snapshotted() reads as success with an empty tree hash: harmless, since
// nothing asserts on it unless a test sets baselineOutcome itself.
type fakeSnapshotWitness struct {
	mu      sync.Mutex
	outcome SnapshotOutcome
	calls   int
	lastDir string

	baselineOutcome SnapshotOutcome
	baselineCalls   int
	lastBaselineDir string
	lastBaselineRun string
}

func (f *fakeSnapshotWitness) Snapshot(_ context.Context, workingDirectory string) SnapshotOutcome {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastDir = workingDirectory
	return f.outcome
}

func (f *fakeSnapshotWitness) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeSnapshotWitness) SnapshotBaseline(_ context.Context, workingDirectory, runID string) SnapshotOutcome {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.baselineCalls++
	f.lastBaselineDir = workingDirectory
	f.lastBaselineRun = runID
	return f.baselineOutcome
}

func (f *fakeSnapshotWitness) baselineCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.baselineCalls
}

// ---------------------------------------------------------------------------
// Pairing and "only new turns".
// ---------------------------------------------------------------------------

const recTestRunID = "run-rm236-record"

func recToolUse(id, name string, input string) ToolUse {
	return ToolUse{ID: id, Name: name, Input: json.RawMessage(input)}
}

func recResult(toolUseID, content string, isError bool) observedToolResult {
	return observedToolResult{ToolUseID: toolUseID, Content: json.RawMessage(content), IsError: isError}
}

// TestGREC001RecorderPairsAPendingToolUseWithItsResultAndRecordsItOnce is
// this file's own version of GREC-001 (doc 07): a tool_use observed on the
// reply and the tool_result the next request carries for it are recorded
// as one call, carrying the tool name, the input and the result together.
func TestGREC001RecorderPairsAPendingToolUseWithItsResultAndRecordsItOnce(t *testing.T) {
	calls := &fakeRecordCalls{}
	rec := NewToolCallRecorder(ToolCallRecorderConfig{record: calls.fn})

	ctx := WithRunID(context.Background(), recTestRunID)
	rec.OnToolUseContext(ctx, recToolUse("toolu_1", "Bash", `{"command":"echo hi"}`))
	if got := rec.PendingCount(); got != 1 {
		t.Fatalf("PendingCount = %d, want 1", got)
	}

	rec.HandleResults(context.Background(), recTestRunID, RequestFacts{},
		[]observedToolResult{recResult("toolu_1", `{"stdout":"hi\n"}`, false)})
	waitForCalls(t, calls, 1)

	if got := rec.PendingCount(); got != 0 {
		t.Errorf("PendingCount after pairing = %d, want 0", got)
	}
	got := calls.snapshot()
	if len(got) != 1 {
		t.Fatalf("%d recorded calls, want 1: %+v", len(got), got)
	}
	if got[0].RunID != recTestRunID {
		t.Errorf("RunID = %q, want %q", got[0].RunID, recTestRunID)
	}
	if got[0].Tool != "Bash" {
		t.Errorf("Tool = %q, want %q", got[0].Tool, "Bash")
	}
	var body map[string]any
	if err := json.Unmarshal(got[0].Body, &body); err != nil {
		t.Fatalf("recorded body is not JSON: %v", err)
	}
	if body["result_observed"] != true {
		t.Errorf("result_observed = %v, want true", body["result_observed"])
	}
	if body["is_error"] == true {
		t.Errorf("is_error = true, want false/absent")
	}
	if body["tool_use_id"] != "toolu_1" {
		t.Errorf("tool_use_id = %v, want %q (#392, OTW's own join key)", body["tool_use_id"], "toolu_1")
	}
	if !strings.Contains(string(got[0].Body), "echo hi") {
		t.Errorf("recorded body does not carry the input: %s", got[0].Body)
	}
	if !strings.Contains(string(got[0].Body), "hi\\n") && !strings.Contains(string(got[0].Body), `hi\n`) {
		t.Errorf("recorded body does not carry the result: %s", got[0].Body)
	}
}

// TestGREC002RecorderRecordsAFailedResultWithIsErrorTrue. Doc 07 GREC-002.
func TestGREC002RecorderRecordsAFailedResultWithIsErrorTrue(t *testing.T) {
	calls := &fakeRecordCalls{}
	rec := NewToolCallRecorder(ToolCallRecorderConfig{record: calls.fn})

	ctx := WithRunID(context.Background(), recTestRunID)
	rec.OnToolUseContext(ctx, recToolUse("toolu_2", "Bash", `{"command":"false"}`))
	rec.HandleResults(context.Background(), recTestRunID, RequestFacts{},
		[]observedToolResult{recResult("toolu_2", `{"stderr":"exit 1"}`, true)})
	waitForCalls(t, calls, 1)

	got := calls.snapshot()
	if len(got) != 1 {
		t.Fatalf("%d recorded calls, want 1", len(got))
	}
	var body map[string]any
	if err := json.Unmarshal(got[0].Body, &body); err != nil {
		t.Fatalf("recorded body is not JSON: %v", err)
	}
	if body["is_error"] != true {
		t.Errorf("is_error = %v, want true", body["is_error"])
	}
}

// TestGREC004RecorderRecordsOnlyNewTurns. Doc 07 GREC-004: a resent history
// carrying the SAME tool_result a second time (Claude Code resends the
// whole conversation on every request, facts.go's own doc comment) records
// nothing a second time.
func TestGREC004RecorderRecordsOnlyNewTurns(t *testing.T) {
	calls := &fakeRecordCalls{}
	recorded := make(chan struct{}, 8)
	rec := NewToolCallRecorder(ToolCallRecorderConfig{
		record:     calls.fn,
		onRecorded: func() { recorded <- struct{}{} },
	})

	ctx := WithRunID(context.Background(), recTestRunID)
	rec.OnToolUseContext(ctx, recToolUse("toolu_3", "Read", `{"file_path":"/w/a.go"}`))

	results := []observedToolResult{recResult("toolu_3", `{"content":"package a"}`, false)}
	rec.HandleResults(context.Background(), recTestRunID, RequestFacts{}, results)
	waitForRecorded(t, recorded, 1, 5*time.Second)

	// The SAME request, resent (or a later request still carrying the
	// same tool_result in its history): the pending entry is already gone,
	// so this must dispatch nothing more. Each resend is followed by
	// waitForNoFurtherRecording rather than a fixed sleep: recording is
	// asynchronous (this file's own doc comment), so a wrongly-fired
	// second recording is caught the instant its own completion hook
	// fires, deterministically, rather than however long a blind sleep
	// happened to run before a single check that followed it.
	rec.HandleResults(context.Background(), recTestRunID, RequestFacts{}, results)
	waitForNoFurtherRecording(t, recorded, 200*time.Millisecond)
	rec.HandleResults(context.Background(), recTestRunID, RequestFacts{}, results)
	waitForNoFurtherRecording(t, recorded, 200*time.Millisecond)

	if got := len(calls.snapshot()); got != 1 {
		t.Errorf("%d recorded calls after three requests carrying the same result, want 1", got)
	}
}

// TestGREC004RecorderRecordsNothingForAResultWithNoPendingToolUse. A
// tool_use this recorder never observed (a truncated or dropped
// content_block_stop, or simply not this recorder's own run) leaves no
// tool name to record under; ADR-0021 requires one, so nothing is
// recorded rather than guessed.
func TestGREC004RecorderRecordsNothingForAResultWithNoPendingToolUse(t *testing.T) {
	calls := &fakeRecordCalls{}
	recorded := make(chan struct{}, 8)
	rec := NewToolCallRecorder(ToolCallRecorderConfig{
		record:     calls.fn,
		onRecorded: func() { recorded <- struct{}{} },
	})

	rec.HandleResults(context.Background(), recTestRunID, RequestFacts{},
		[]observedToolResult{recResult("toolu-unknown", `{}`, false)})

	// No pairing means no goroutine is ever spawned; waitForNoFurtherRecording
	// is what a wrongly-dispatched recording would have to fire to be
	// caught, deterministically, rather than a fixed sleep guessed to be
	// long enough.
	waitForNoFurtherRecording(t, recorded, 200*time.Millisecond)
	if got := len(calls.snapshot()); got != 0 {
		t.Errorf("%d recorded calls for a result with no pending tool_use, want 0", got)
	}
}

// TestToolCallRecorderPendingIsPerRun. Two runs sharing no tool_use ids by
// construction (this recorder's own key is (run id, tool_use id)) do not
// pair across each other.
func TestToolCallRecorderPendingIsPerRun(t *testing.T) {
	calls := &fakeRecordCalls{}
	rec := NewToolCallRecorder(ToolCallRecorderConfig{record: calls.fn})

	ctx := WithRunID(context.Background(), "run-a")
	rec.OnToolUseContext(ctx, recToolUse("toolu_shared", "Bash", `{}`))

	// A different run naming the SAME tool_use id finds nothing pending
	// under ITS key.
	rec.HandleResults(context.Background(), "run-b", RequestFacts{},
		[]observedToolResult{recResult("toolu_shared", `{}`, false)})
	time.Sleep(50 * time.Millisecond)
	if got := len(calls.snapshot()); got != 0 {
		t.Fatalf("%d recorded calls for the wrong run, want 0", got)
	}

	// The owning run's own request pairs it.
	rec.HandleResults(context.Background(), "run-a", RequestFacts{},
		[]observedToolResult{recResult("toolu_shared", `{}`, false)})
	waitForCalls(t, calls, 1)
	if got := len(calls.snapshot()); got != 1 {
		t.Errorf("%d recorded calls, want 1", got)
	}
}

// ---------------------------------------------------------------------------
// Bounded memory: eviction records input-only.
// ---------------------------------------------------------------------------

// TestToolCallRecorderEvictsTheOldestPendingEntryAndRecordsItInputOnly.
// This issue's own bounded-memory requirement: a pending table at its cap
// evicts the oldest entry rather than growing without bound, and the
// evicted entry is not silently dropped — it is recorded, input-only, with
// that fact stated in the body.
func TestToolCallRecorderEvictsTheOldestPendingEntryAndRecordsItInputOnly(t *testing.T) {
	calls := &fakeRecordCalls{}
	rec := NewToolCallRecorder(ToolCallRecorderConfig{
		MaxPending: 2, record: calls.fn,
	})

	ctx := WithRunID(context.Background(), recTestRunID)
	rec.OnToolUseContext(ctx, recToolUse("toolu_old", "Bash", `{"command":"one"}`))
	rec.OnToolUseContext(ctx, recToolUse("toolu_mid", "Bash", `{"command":"two"}`))
	if got := rec.PendingCount(); got != 2 {
		t.Fatalf("PendingCount = %d, want 2", got)
	}

	// A third entry, over the cap: the oldest (toolu_old) is evicted and
	// recorded input-only.
	rec.OnToolUseContext(ctx, recToolUse("toolu_new", "Bash", `{"command":"three"}`))
	waitForCalls(t, calls, 1)

	if got := rec.PendingCount(); got != 2 {
		t.Errorf("PendingCount after eviction = %d, want 2", got)
	}
	got := calls.snapshot()
	if len(got) != 1 {
		t.Fatalf("%d recorded calls, want 1 (the eviction): %+v", len(got), got)
	}
	if !strings.Contains(string(got[0].Body), "one") {
		t.Errorf("the evicted call's own input did not reach the recorded body: %s", got[0].Body)
	}
	var body map[string]any
	if err := json.Unmarshal(got[0].Body, &body); err != nil {
		t.Fatalf("recorded body is not JSON: %v", err)
	}
	if body["result_observed"] == true {
		t.Errorf("result_observed = true for an eviction, want false/absent")
	}
	note, ok := body["note"].(string)
	if !ok || !strings.Contains(note, "evicted") {
		t.Errorf("note = %q (present: %v), want it to state the eviction", note, ok)
	}

	// The two entries still pending are the mid and new ones, not the
	// evicted old one — its own later result now pairs with nothing.
	calls2 := &fakeRecordCalls{}
	rec.record = calls2.fn
	rec.HandleResults(context.Background(), recTestRunID, RequestFacts{},
		[]observedToolResult{recResult("toolu_mid", `{}`, false)})
	waitForCalls(t, calls2, 1)
	if got := len(calls2.snapshot()); got != 1 {
		t.Errorf("%d recorded calls for the surviving mid entry, want 1", got)
	}
}

// TestToolCallRecorderEvictionKeepsOrderConsistentWithNormalPairing proves
// removePendingKey's own reason for existing: a normally-paired entry is
// removed from BOTH the map and the eviction order, so a later eviction
// still evicts the entry that is genuinely oldest among what remains, not
// a stale reference to one already gone.
func TestToolCallRecorderEvictionKeepsOrderConsistentWithNormalPairing(t *testing.T) {
	calls := &fakeRecordCalls{}
	rec := NewToolCallRecorder(ToolCallRecorderConfig{
		MaxPending: 2, record: calls.fn,
	})

	ctx := WithRunID(context.Background(), recTestRunID)
	rec.OnToolUseContext(ctx, recToolUse("toolu_a", "Bash", `{"command":"a"}`))
	rec.OnToolUseContext(ctx, recToolUse("toolu_b", "Bash", `{"command":"b"}`))

	// toolu_a is paired normally (not evicted) and removed from pending.
	rec.HandleResults(context.Background(), recTestRunID, RequestFacts{},
		[]observedToolResult{recResult("toolu_a", `{}`, false)})
	waitForCalls(t, calls, 1)

	// Two more arrive. If order still held a stale reference to toolu_a,
	// the SECOND of these would evict it — but it is already gone, so the
	// eviction must fall on toolu_b instead, the genuinely oldest survivor.
	rec.OnToolUseContext(ctx, recToolUse("toolu_c", "Bash", `{"command":"c"}`))
	rec.OnToolUseContext(ctx, recToolUse("toolu_d", "Bash", `{"command":"d"}`))
	waitForCalls(t, calls, 2) // the toolu_a pairing, plus toolu_b's own eviction
	waitForPendingCount(t, rec, 2)

	// toolu_c and toolu_d must both still be pending (b was evicted, not
	// a, c or d); pairing both proves it.
	rec.HandleResults(context.Background(), recTestRunID, RequestFacts{}, []observedToolResult{
		recResult("toolu_c", `{}`, false), recResult("toolu_d", `{}`, false),
	})
	waitForCalls(t, calls, 4)

	var sawB, sawC, sawD int
	for _, c := range calls.snapshot() {
		switch {
		case strings.Contains(string(c.Body), `"command":"b"`):
			sawB++
		case strings.Contains(string(c.Body), `"command":"c"`):
			sawC++
		case strings.Contains(string(c.Body), `"command":"d"`):
			sawD++
		}
	}
	if sawB != 1 || sawC != 1 || sawD != 1 {
		t.Errorf("saw b=%d c=%d d=%d, want exactly one recorded call each", sawB, sawC, sawD)
	}
}

// ---------------------------------------------------------------------------
// GREC-003: the workspace snapshot witness.
// ---------------------------------------------------------------------------

// TestGREC003RecorderAttachesTheWorkspaceTreeHashWhenTheTriggerFires. Doc 07
// GREC-003.
func TestGREC003RecorderAttachesTheWorkspaceTreeHashWhenTheTriggerFires(t *testing.T) {
	calls := &fakeRecordCalls{}
	witness := &fakeSnapshotWitness{outcome: SnapshotOutcome{TreeHash: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"}}
	rec := NewToolCallRecorder(ToolCallRecorderConfig{
		record:    calls.fn,
		Snapshots: witness, Trigger: NewSnapshotTrigger(),
	})

	ctx := WithRunID(context.Background(), recTestRunID)
	rec.OnToolUseContext(ctx, recToolUse("toolu_snap", "Write", `{"file_path":"/w/x.go"}`))
	facts := RequestFacts{WorkingDirectory: "/w", ToolResultIDs: []string{"toolu_snap"}}
	rec.HandleResults(context.Background(), recTestRunID, facts,
		[]observedToolResult{recResult("toolu_snap", `{}`, false)})
	waitForCalls(t, calls, 1)

	got := calls.snapshot()
	if len(got) != 1 {
		t.Fatalf("%d recorded calls, want 1", len(got))
	}
	if got[0].WorkspaceTreeHash != witness.outcome.TreeHash {
		t.Errorf("WorkspaceTreeHash = %q, want %q", got[0].WorkspaceTreeHash, witness.outcome.TreeHash)
	}
	if witness.callCount() != 1 {
		t.Errorf("the snapshot witness was called %d times, want exactly 1 per request", witness.callCount())
	}
	if witness.lastDir != "/w" {
		t.Errorf("the witness was called with working directory %q, want %q", witness.lastDir, "/w")
	}
}

// TestGREC003RecorderRecordsWithoutATreeHashWhenTheSnapshotFails. Doc 07
// GREC-003: "a snapshot failure records the tool call without it, never
// blocks".
func TestGREC003RecorderRecordsWithoutATreeHashWhenTheSnapshotFails(t *testing.T) {
	calls := &fakeRecordCalls{}
	var failures []string
	witness := &fakeSnapshotWitness{outcome: SnapshotOutcome{Reason: "workspace snapshot: not a git working tree"}}
	rec := NewToolCallRecorder(ToolCallRecorderConfig{
		record:    calls.fn,
		Snapshots: witness, Trigger: NewSnapshotTrigger(),
		OnRecordFailure: func(err error) { failures = append(failures, err.Error()) },
	})

	ctx := WithRunID(context.Background(), recTestRunID)
	rec.OnToolUseContext(ctx, recToolUse("toolu_snapfail", "Write", `{}`))
	facts := RequestFacts{WorkingDirectory: "/not-a-repo", ToolResultIDs: []string{"toolu_snapfail"}}
	rec.HandleResults(context.Background(), recTestRunID, facts,
		[]observedToolResult{recResult("toolu_snapfail", `{}`, false)})
	waitForCalls(t, calls, 1)

	got := calls.snapshot()
	if len(got) != 1 {
		t.Fatalf("%d recorded calls, want 1", len(got))
	}
	if got[0].WorkspaceTreeHash != "" {
		t.Errorf("WorkspaceTreeHash = %q, want empty after a snapshot failure", got[0].WorkspaceTreeHash)
	}
	if len(failures) == 0 {
		t.Fatal("OnRecordFailure was never called for the snapshot failure")
	}
	if !strings.Contains(failures[0], "not a git working tree") {
		t.Errorf("failure = %q, want it to name the snapshot's own reason", failures[0])
	}
}

// TestGREC003RecorderNeverSnapshotsWithoutASnapshotterOrTrigger.
func TestGREC003RecorderNeverSnapshotsWithoutASnapshotterOrTrigger(t *testing.T) {
	calls := &fakeRecordCalls{}
	rec := NewToolCallRecorder(ToolCallRecorderConfig{record: calls.fn})

	ctx := WithRunID(context.Background(), recTestRunID)
	rec.OnToolUseContext(ctx, recToolUse("toolu_nosnap", "Write", `{}`))
	rec.HandleResults(context.Background(), recTestRunID,
		RequestFacts{WorkingDirectory: "/w", ToolResultIDs: []string{"toolu_nosnap"}},
		[]observedToolResult{recResult("toolu_nosnap", `{}`, false)})
	waitForCalls(t, calls, 1)

	got := calls.snapshot()
	if len(got) != 1 || got[0].WorkspaceTreeHash != "" {
		t.Errorf("recorded calls = %+v, want one call with no tree hash", got)
	}
}

// TestGREC003RecorderDoesNotSnapshotWhenTheTriggerDoesNotFire: a request
// whose tool results this trigger has already seen for this run fires
// nothing a second time (snapshot.go's own SnapshotTrigger.Fire), so a
// repeated request pairs nothing new here either — see
// TestGREC004RecorderRecordsOnlyNewTurns for the pairing half of that; this
// asserts the witness itself is not re-invoked.
func TestGREC003RecorderDoesNotSnapshotWhenTheTriggerDoesNotFire(t *testing.T) {
	calls := &fakeRecordCalls{}
	witness := &fakeSnapshotWitness{outcome: SnapshotOutcome{TreeHash: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"}}
	trigger := NewSnapshotTrigger()
	rec := NewToolCallRecorder(ToolCallRecorderConfig{
		record: calls.fn, Snapshots: witness, Trigger: trigger,
	})

	// Fire the trigger once, directly, for a tool result this recorder was
	// never asked to pair (as an earlier request already would have) —
	// proving the SAME (run, tool_use id) pair never fires the witness
	// twice, independent of pairing.
	trigger.Fire(recTestRunID, RequestFacts{ToolResultIDs: []string{"toolu_seen"}})

	ctx := WithRunID(context.Background(), recTestRunID)
	rec.OnToolUseContext(ctx, recToolUse("toolu_seen", "Write", `{}`))
	rec.HandleResults(context.Background(), recTestRunID,
		RequestFacts{WorkingDirectory: "/w", ToolResultIDs: []string{"toolu_seen"}},
		[]observedToolResult{recResult("toolu_seen", `{}`, false)})
	waitForCalls(t, calls, 1)

	if witness.callCount() != 0 {
		t.Errorf("the witness was called %d times for a result the trigger had already seen, want 0", witness.callCount())
	}
}

// ---------------------------------------------------------------------------
// The baseline snapshot: #437 (RM-274). A run's first step has no earlier
// snapshot of its own to call its own "before" unless one is taken before
// that step's tool ever runs — snapshotIfTriggered's own witness only ever
// fires AFTER a tool_result arrives, which is necessarily after the tool it
// answers for already ran. baselineIfNeeded (record.go) is the fix: it
// fires SnapshotBaseline the first time this recorder ever sees a tool_use
// for a run, from OnToolUseContext — before the harness that will run it
// has even received the model's reply in full.
// ---------------------------------------------------------------------------

// waitForBaselined blocks until n signals have arrived on baselined (fed by
// ToolCallRecorderConfig's own onBaselined hook), or fails t after timeout —
// waitForRecorded's own idiom, restated for the separate goroutine
// baselineIfNeeded fires.
func waitForBaselined(t *testing.T, baselined <-chan struct{}, n int, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for i := 0; i < n; i++ {
		select {
		case <-baselined:
		case <-deadline:
			t.Fatalf("timed out waiting for onBaselined signal %d/%d", i+1, n)
		}
	}
}

// TestBaselineSnapshotFiresOnceOnTheFirstToolUseOfARun proves the core
// claim: the FIRST tool_use this recorder ever sees for a run fires
// SnapshotBaseline exactly once, carrying that request's own working
// directory and the run id — and every LATER tool_use for the SAME run,
// whatever request it arrives on, fires it no further.
func TestBaselineSnapshotFiresOnceOnTheFirstToolUseOfARun(t *testing.T) {
	calls := &fakeRecordCalls{}
	witness := &fakeSnapshotWitness{baselineOutcome: SnapshotOutcome{TreeHash: strings.Repeat("a", 40)}}
	baselined := make(chan struct{}, 8)
	rec := NewToolCallRecorder(ToolCallRecorderConfig{
		record: calls.fn, Snapshots: witness, Trigger: NewSnapshotTrigger(),
		onBaselined: func() { baselined <- struct{}{} },
	})

	ctx := WithRunID(WithRequestFacts(context.Background(), RequestFacts{WorkingDirectory: "/w/repo"}), recTestRunID)
	rec.OnToolUseContext(ctx, recToolUse("toolu_base1", "Write", `{"file_path":"e18.txt"}`))
	waitForBaselined(t, baselined, 1, 5*time.Second)

	if got := witness.baselineCallCount(); got != 1 {
		t.Fatalf("baseline calls after the first tool_use = %d, want 1", got)
	}
	if witness.lastBaselineDir != "/w/repo" {
		t.Errorf("baseline working directory = %q, want %q", witness.lastBaselineDir, "/w/repo")
	}
	if witness.lastBaselineRun != recTestRunID {
		t.Errorf("baseline run id = %q, want %q", witness.lastBaselineRun, recTestRunID)
	}

	// A second, and a third, tool_use for the SAME run: no further baseline.
	rec.OnToolUseContext(ctx, recToolUse("toolu_base2", "Bash", `{"command":"true"}`))
	rec.OnToolUseContext(ctx, recToolUse("toolu_base3", "Bash", `{"command":"true"}`))
	// baselineIfNeeded's own claim-then-spawn is synchronous up to the
	// claim (claimBaseline runs on THIS goroutine, before the "go" that
	// would fire a second SnapshotBaseline), so there is nothing further to
	// wait for here: a second signal arriving on baselined before this
	// assertion runs would itself be the bug this test exists to catch.
	if got := witness.baselineCallCount(); got != 1 {
		t.Errorf("baseline calls after three tool_use blocks on one run = %d, want 1", got)
	}
}

// TestBaselineSnapshotIsPerRunNotGlobal proves two different runs each get
// their OWN baseline — the claim is keyed by run id, never a package-wide
// "has this recorder ever baselined anything" flag.
func TestBaselineSnapshotIsPerRunNotGlobal(t *testing.T) {
	calls := &fakeRecordCalls{}
	witness := &fakeSnapshotWitness{baselineOutcome: SnapshotOutcome{TreeHash: strings.Repeat("b", 40)}}
	baselined := make(chan struct{}, 8)
	rec := NewToolCallRecorder(ToolCallRecorderConfig{
		record: calls.fn, Snapshots: witness, Trigger: NewSnapshotTrigger(),
		onBaselined: func() { baselined <- struct{}{} },
	})

	withDir := WithRequestFacts(context.Background(), RequestFacts{WorkingDirectory: "/w/repo"})
	rec.OnToolUseContext(WithRunID(withDir, "run-baseline-a"), recToolUse("toolu_a1", "Write", `{}`))
	rec.OnToolUseContext(WithRunID(withDir, "run-baseline-b"), recToolUse("toolu_b1", "Write", `{}`))
	waitForBaselined(t, baselined, 2, 5*time.Second)

	if got := witness.baselineCallCount(); got != 2 {
		t.Fatalf("baseline calls across two different runs = %d, want 2", got)
	}
}

// TestBaselineSnapshotNeverFiresWithoutASnapshotter: the zero-value and
// "Snapshots left unset" configs (ToolCallRecorderConfig's own doc comment
// on why a typed-nil *Snapshotter must never be assigned there instead)
// both mean no baseline is ever attempted, the same as they already mean no
// per-step snapshot is.
func TestBaselineSnapshotNeverFiresWithoutASnapshotter(t *testing.T) {
	calls := &fakeRecordCalls{}
	rec := NewToolCallRecorder(ToolCallRecorderConfig{record: calls.fn})

	ctx := WithRunID(context.Background(), recTestRunID)
	rec.OnToolUseContext(ctx, recToolUse("toolu_nobase", "Write", `{}`))
	rec.HandleResults(context.Background(), recTestRunID, RequestFacts{},
		[]observedToolResult{recResult("toolu_nobase", `{}`, false)})
	waitForCalls(t, calls, 1) // did not panic, recorded normally
}

// TestBaselineSnapshotFailureIsReportedButNeverBlocks: a baseline snapshot
// that cannot be taken is reported through OnRecordFailure — the same
// "logged loudly" channel the per-step witness already uses
// (TestGREC003RecorderRecordsWithoutATreeHashWhenTheSnapshotFails) — and
// never turns into a panic, a refused tool_use, or a failed recording of
// the pair itself.
func TestBaselineSnapshotFailureIsReportedButNeverBlocks(t *testing.T) {
	calls := &fakeRecordCalls{}
	var failures []string
	var mu sync.Mutex
	witness := &fakeSnapshotWitness{
		baselineOutcome: SnapshotOutcome{Reason: "workspace snapshot: not a git working tree"},
	}
	baselined := make(chan struct{}, 1)
	rec := NewToolCallRecorder(ToolCallRecorderConfig{
		record: calls.fn, Snapshots: witness, Trigger: NewSnapshotTrigger(),
		OnRecordFailure: func(err error) {
			mu.Lock()
			defer mu.Unlock()
			failures = append(failures, err.Error())
		},
		onBaselined: func() { baselined <- struct{}{} },
	})

	ctx := WithRunID(WithRequestFacts(context.Background(), RequestFacts{WorkingDirectory: "/w/repo"}), recTestRunID)
	rec.OnToolUseContext(ctx, recToolUse("toolu_basefail", "Write", `{}`))
	waitForBaselined(t, baselined, 1, 5*time.Second)

	mu.Lock()
	got := append([]string(nil), failures...)
	mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("%d failures reported, want 1: %v", len(got), got)
	}
	if !strings.Contains(got[0], "not a git working tree") {
		t.Errorf("failure = %q, want it to name the baseline's own reason", got[0])
	}
	if !strings.Contains(got[0], "baseline") {
		t.Errorf("failure = %q, want it to name itself as a baseline failure, distinct from an ordinary snapshot failure", got[0])
	}

	// The pair itself still records normally -- a baseline failure never
	// blocks the recording this file's own doc comment promises it never
	// would.
	rec.HandleResults(context.Background(), recTestRunID,
		RequestFacts{WorkingDirectory: "/w", ToolResultIDs: []string{"toolu_basefail"}},
		[]observedToolResult{recResult("toolu_basefail", `{}`, false)})
	waitForCalls(t, calls, 1)
}

// ---------------------------------------------------------------------------
// Recording failures: logged loudly and counted.
// ---------------------------------------------------------------------------

// failureCollector gathers every error a ToolCallRecorderConfig.
// OnRecordFailure callback received, safe for concurrent use — the
// callback always runs on the recorder's own asynchronous goroutine.
type failureCollector struct {
	mu     sync.Mutex
	errors []error
}

func (f *failureCollector) add(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errors = append(f.errors, err)
}

func (f *failureCollector) snapshot() []error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]error(nil), f.errors...)
}

func waitForFailures(t *testing.T, fc *failureCollector, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if got := len(fc.snapshot()); got >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d reported failures; got %d", want, len(fc.snapshot()))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestToolCallRecorderCountsAndReportsAFailedRecording.
func TestToolCallRecorderCountsAndReportsAFailedRecording(t *testing.T) {
	calls := &fakeRecordCalls{}
	calls.fail(fmt.Errorf("the ledger is unavailable"))
	failures := &failureCollector{}
	rec := NewToolCallRecorder(ToolCallRecorderConfig{
		record:          calls.fn,
		OnRecordFailure: failures.add,
	})

	ctx := WithRunID(context.Background(), recTestRunID)
	rec.OnToolUseContext(ctx, recToolUse("toolu_fail", "Bash", `{}`))
	rec.HandleResults(context.Background(), recTestRunID, RequestFacts{},
		[]observedToolResult{recResult("toolu_fail", `{}`, false)})
	waitForFailures(t, failures, 1)

	if got := rec.FailedRecordings(); got != 1 {
		t.Errorf("FailedRecordings = %d, want 1", got)
	}
	reported := failures.snapshot()
	if len(reported) != 1 {
		t.Fatalf("%d failures reported, want 1", len(reported))
	}
	if !strings.Contains(reported[0].Error(), "ledger is unavailable") {
		t.Errorf("reported error = %q, want it to carry the underlying cause", reported[0])
	}
}

// TestToolCallRecorderDefaultsMaxPendingAndNilOnRecordFailure proves the
// zero-value config is safe to build and use: DefaultMaxPendingToolCalls
// applies, and a nil OnRecordFailure never panics on a failure.
func TestToolCallRecorderDefaultsMaxPendingAndNilOnRecordFailure(t *testing.T) {
	calls := &fakeRecordCalls{}
	calls.fail(fmt.Errorf("boom"))
	rec := NewToolCallRecorder(ToolCallRecorderConfig{record: calls.fn})
	if rec.max != DefaultMaxPendingToolCalls {
		t.Errorf("max = %d, want %d", rec.max, DefaultMaxPendingToolCalls)
	}

	ctx := WithRunID(context.Background(), recTestRunID)
	rec.OnToolUseContext(ctx, recToolUse("toolu_defcfg", "Bash", `{}`))
	rec.HandleResults(context.Background(), recTestRunID, RequestFacts{},
		[]observedToolResult{recResult("toolu_defcfg", `{}`, false)})
	waitForCalls(t, calls, 1) // did not panic

	if got := rec.FailedRecordings(); got != 1 {
		t.Errorf("FailedRecordings = %d, want 1", got)
	}
}

// TestToolCallRecorderOnToolUseWithoutContextIsANoOp: the plain
// ToolUseObserver method carries no context and therefore no run id, so it
// records nothing pending — proxy.go's own boundToolUseObserver always
// prefers OnToolUseContext when it is available, which every production
// wiring of this recorder gives it (CombineToolUseObservers).
func TestToolCallRecorderOnToolUseWithoutContextIsANoOp(t *testing.T) {
	rec := NewToolCallRecorder(ToolCallRecorderConfig{})
	rec.OnToolUse(recToolUse("toolu_nocontext", "Bash", `{}`))
	if got := rec.PendingCount(); got != 0 {
		t.Errorf("PendingCount = %d, want 0", got)
	}
}

// TestToolCallRecorderOnToolUseContextIgnoresATooUseWithNoID: sse.go's own
// contract says an ordinary tool_use always carries one; this is the
// defensive branch for whatever does not.
func TestToolCallRecorderOnToolUseContextIgnoresAToolUseWithNoID(t *testing.T) {
	rec := NewToolCallRecorder(ToolCallRecorderConfig{})
	ctx := WithRunID(context.Background(), recTestRunID)
	rec.OnToolUseContext(ctx, ToolUse{Name: "Bash"})
	if got := rec.PendingCount(); got != 0 {
		t.Errorf("PendingCount = %d, want 0", got)
	}
}

// TestToolCallRecorderOnToolUseContextWithoutARunIDIsANoOp: a request the
// identity guard never ran on at all (this package's own tests exercising
// the observer in isolation) carries no run id, so there is nothing to key
// a pending entry on.
func TestToolCallRecorderOnToolUseContextWithoutARunIDIsANoOp(t *testing.T) {
	rec := NewToolCallRecorder(ToolCallRecorderConfig{})
	rec.OnToolUseContext(context.Background(), recToolUse("toolu_norun", "Bash", `{}`))
	if got := rec.PendingCount(); got != 0 {
		t.Errorf("PendingCount = %d, want 0", got)
	}
}

// TestOTW001BuildToolCallBodyCarriesToolUseID drives #392 (RM-247), E18: the
// gateway's own tool_call body must carry the SAME tool_use_id the model
// API, the harness's hooks and the harness's own OTLP telemetry all carry
// for the identical call, so the reconciler's witness cross-check
// (internal/reconciler/witness.go) can join the two witnesses exactly. This
// is a body field, never an event field — doc 02's schema is unchanged.
func TestOTW001BuildToolCallBodyCarriesToolUseID(t *testing.T) {
	call := pendingCall{tool: "Bash", input: json.RawMessage(`{"command":"echo hi"}`)}
	result := observedToolResult{ToolUseID: "toolu_join_key", Content: json.RawMessage(`{"stdout":"hi\n"}`)}
	body := buildToolCallBody("toolu_join_key", call, &result)

	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if got := decoded["tool_use_id"]; got != "toolu_join_key" {
		t.Errorf("tool_use_id = %v, want %q", got, "toolu_join_key")
	}
}

// TestBuildToolCallBodyMarksInputTruncation. GREC-007 (doc 07): a truncated
// tool_use's input is stated, never reassembled and presented as complete.
func TestBuildToolCallBodyMarksInputTruncation(t *testing.T) {
	call := pendingCall{tool: "Write", input: nil, truncated: true}
	body := buildToolCallBody("toolu_input_trunc", call, nil)
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if decoded["input_truncated"] != true {
		t.Errorf("input_truncated = %v, want true", decoded["input_truncated"])
	}
	if _, present := decoded["input"]; present {
		t.Errorf("input = %v, want absent for a truncated block", decoded["input"])
	}
}

// TestBuildToolCallBodyMarksResultTruncation. GREC-007.
func TestBuildToolCallBodyMarksResultTruncation(t *testing.T) {
	call := pendingCall{tool: "Read", input: json.RawMessage(`{"file_path":"/w/a.go"}`)}
	result := observedToolResult{ToolUseID: "toolu_big", Content: nil, Truncated: true}
	body := buildToolCallBody("toolu_big", call, &result)
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if decoded["result_truncated"] != true {
		t.Errorf("result_truncated = %v, want true", decoded["result_truncated"])
	}
	if decoded["result_observed"] != true {
		t.Errorf("result_observed = %v, want true (a truncated result is still an observed one)", decoded["result_observed"])
	}
}

// ---------------------------------------------------------------------------
// extractToolResults.
// ---------------------------------------------------------------------------

func recRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/messages", strings.NewReader(body))
	return req
}

func drainAndClose(t *testing.T, r *http.Request) []byte {
	t.Helper()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("reading the restored body: %v", err)
	}
	if err := r.Body.Close(); err != nil {
		t.Fatalf("closing the restored body: %v", err)
	}
	return b
}

func TestExtractToolResultsFindsBlocksAnywhereInTheRequestAndRestoresTheBody(t *testing.T) {
	raw := `{"messages":[
		{"role":"user","content":[{"type":"text","text":"hi"}]},
		{"role":"assistant","content":[
			{"type":"tool_use","id":"toolu_x","name":"Bash","input":{}},
			{"type":"text","text":"working on it"}
		]},
		{"role":"user","content":[
			{"type":"tool_result","tool_use_id":"toolu_x","content":"ok","is_error":false}
		]}
	]}`
	r := recRequest(t, raw)
	results := extractToolResults(r)
	if len(results) != 1 {
		t.Fatalf("%d results, want 1: %+v", len(results), results)
	}
	if results[0].ToolUseID != "toolu_x" {
		t.Errorf("ToolUseID = %q, want toolu_x", results[0].ToolUseID)
	}
	if results[0].IsError {
		t.Errorf("IsError = true, want false")
	}
	if got := drainAndClose(t, r); string(got) != raw {
		t.Errorf("the restored body differs from the original:\ngot:  %s\nwant: %s", got, raw)
	}
}

func TestExtractToolResultsCapturesIsErrorTrue(t *testing.T) {
	raw := `{"messages":[{"role":"user","content":[
		{"type":"tool_result","tool_use_id":"toolu_y","content":"permission denied","is_error":true}
	]}]}`
	results := extractToolResults(recRequest(t, raw))
	if len(results) != 1 || !results[0].IsError {
		t.Fatalf("results = %+v, want one result with IsError true", results)
	}
}

func TestExtractToolResultsTruncatesOversizedContent(t *testing.T) {
	huge := `"` + strings.Repeat("a", maxToolResultContentBytes+1) + `"`
	raw := `{"messages":[{"role":"user","content":[
		{"type":"tool_result","tool_use_id":"toolu_big","content":` + huge + `}
	]}]}`
	results := extractToolResults(recRequest(t, raw))
	if len(results) != 1 {
		t.Fatalf("%d results, want 1", len(results))
	}
	if !results[0].Truncated {
		t.Error("Truncated = false, want true for oversized content")
	}
	if results[0].Content != nil {
		t.Errorf("Content = %s, want nil for a dropped, truncated block", results[0].Content)
	}
}

func TestExtractToolResultsIgnoresBlocksWithNoToolUseID(t *testing.T) {
	raw := `{"messages":[{"role":"user","content":[
		{"type":"tool_result","content":"orphaned"}
	]}]}`
	results := extractToolResults(recRequest(t, raw))
	if len(results) != 0 {
		t.Errorf("%d results, want 0 for a tool_result with no tool_use_id", len(results))
	}
}

func TestExtractToolResultsIsEmptyForMalformedOrOversizedBodiesAndStillRestores(t *testing.T) {
	cases := map[string]string{
		"not json":            "not json at all",
		"bare-string content": `{"messages":[{"role":"user","content":"plain text, no blocks"}]}`,
		"empty messages":      `{"messages":[]}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			r := recRequest(t, raw)
			if got := extractToolResults(r); len(got) != 0 {
				t.Errorf("%d results, want 0", len(got))
			}
			if got := drainAndClose(t, r); string(got) != raw {
				t.Errorf("the restored body differs from the original:\ngot:  %s\nwant: %s", got, raw)
			}
		})
	}
}

func TestExtractToolResultsOverTheBoundExtractsNothingAndStillRestores(t *testing.T) {
	huge := strings.Repeat("x", maxToolCallRecordBodyBytes+1)
	raw := `{"padding":"` + huge + `"}`
	r := recRequest(t, raw)
	if got := extractToolResults(r); len(got) != 0 {
		t.Errorf("%d results over the bound, want 0", len(got))
	}
	got := drainAndClose(t, r)
	if len(got) != len(raw) {
		t.Errorf("restored body is %d bytes, want %d", len(got), len(raw))
	}
}

func TestExtractToolResultsWithNoBody(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/messages", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	req.Body = nil
	if got := extractToolResults(req); got != nil {
		t.Errorf("results = %+v, want nil for a request with no body", got)
	}
}

// ---------------------------------------------------------------------------
// ToolCallRecordGuard: never refuses, and does nothing without a run id.
// ---------------------------------------------------------------------------

func TestToolCallRecordGuardDoesNothingWithoutARunID(t *testing.T) {
	calls := &fakeRecordCalls{}
	rec := NewToolCallRecorder(ToolCallRecorderConfig{record: calls.fn})
	guard := NewToolCallRecordGuard(rec)

	r := recRequest(t, `{"messages":[{"role":"user","content":[
		{"type":"tool_result","tool_use_id":"toolu_z","content":"x"}
	]}]}`)
	next, refusal := guard.Check(r)
	if refusal != nil {
		t.Fatalf("refusal = %+v, want nil", refusal)
	}
	if next != nil {
		t.Errorf("next = %v, want nil (no run id to attach)", next)
	}
	time.Sleep(20 * time.Millisecond)
	if got := len(calls.snapshot()); got != 0 {
		t.Errorf("%d recorded calls without a run id, want 0", got)
	}
}

func TestToolCallRecordGuardWithANilRecorderDoesNothing(t *testing.T) {
	guard := NewToolCallRecordGuard(nil)
	r := recRequest(t, `{"messages":[]}`)
	r = r.WithContext(WithRunID(r.Context(), recTestRunID))
	next, refusal := guard.Check(r)
	if refusal != nil {
		t.Fatalf("refusal = %+v, want nil", refusal)
	}
	if next != nil {
		t.Errorf("next = %v, want nil", next)
	}
}

func TestToolCallRecordGuardForwardsUnchangedWithNoToolResults(t *testing.T) {
	calls := &fakeRecordCalls{}
	rec := NewToolCallRecorder(ToolCallRecorderConfig{record: calls.fn})
	guard := NewToolCallRecordGuard(rec)

	r := recRequest(t, `{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)
	r = r.WithContext(WithRunID(r.Context(), recTestRunID))
	next, refusal := guard.Check(r)
	if refusal != nil {
		t.Fatalf("refusal = %+v, want nil", refusal)
	}
	if next != r {
		t.Errorf("next = %v, want the same request returned unchanged", next)
	}
}

func TestToolCallRecordGuardPairsAResultUsingContextFacts(t *testing.T) {
	calls := &fakeRecordCalls{}
	rec := NewToolCallRecorder(ToolCallRecorderConfig{record: calls.fn})
	guard := NewToolCallRecordGuard(rec)

	ctx := WithRunID(context.Background(), recTestRunID)
	rec.OnToolUseContext(ctx, recToolUse("toolu_guard", "Bash", `{"command":"pwd"}`))

	r := recRequest(t, `{"messages":[{"role":"user","content":[
		{"type":"tool_result","tool_use_id":"toolu_guard","content":"/w","is_error":false}
	]}]}`)
	rctx := WithRequestFacts(WithRunID(r.Context(), recTestRunID), RequestFacts{WorkingDirectory: "/w"})
	r = r.WithContext(rctx)

	next, refusal := guard.Check(r)
	if refusal != nil {
		t.Fatalf("refusal = %+v, want nil", refusal)
	}
	if next == nil {
		t.Fatal("next = nil, want the request returned for forwarding")
	}
	waitForCalls(t, calls, 1)

	got := calls.snapshot()
	if len(got) != 1 {
		t.Fatalf("%d recorded calls, want 1", len(got))
	}
	if got[0].RunID != recTestRunID {
		t.Errorf("RunID = %q, want %q", got[0].RunID, recTestRunID)
	}
}

// ---------------------------------------------------------------------------
// CombineToolUseObservers. ChainGuards (this file used to test it here) is
// gone: guard.go's own Guards function now takes every witness directly,
// as its own variadic parameter -- see that function's own doc comment.
// ---------------------------------------------------------------------------

type fakeToolUseObserver struct {
	mu   sync.Mutex
	seen []ToolUse
}

func (f *fakeToolUseObserver) OnToolUse(t ToolUse) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, t)
}

func (f *fakeToolUseObserver) snapshot() []ToolUse {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ToolUse(nil), f.seen...)
}

func TestCombineToolUseObserversNotifiesEachAndSkipsNil(t *testing.T) {
	a, b := &fakeToolUseObserver{}, &fakeToolUseObserver{}
	combined := CombineToolUseObservers(a, nil, b)
	combined.OnToolUse(ToolUse{ID: "toolu_combined"})

	for _, o := range []*fakeToolUseObserver{a, b} {
		if got := o.snapshot(); len(got) != 1 || got[0].ID != "toolu_combined" {
			t.Errorf("observer saw %+v, want one ToolUse with id toolu_combined", got)
		}
	}
}

func TestCombineToolUseObserversDispatchesContextToEachObserverThatWantsIt(t *testing.T) {
	calls := &fakeRecordCalls{}
	rec := NewToolCallRecorder(ToolCallRecorderConfig{record: calls.fn})
	plain := &fakeToolUseObserver{}
	combined := CombineToolUseObservers(plain, rec)

	ctx := WithRunID(context.Background(), recTestRunID)
	bound := boundToolUseObserver(ctx, combined)
	bound.OnToolUse(recToolUse("toolu_dispatch", "Bash", `{}`))

	if got := plain.snapshot(); len(got) != 1 {
		t.Errorf("the plain observer saw %d calls, want 1", len(got))
	}
	if got := rec.PendingCount(); got != 1 {
		t.Fatalf("PendingCount = %d, want 1 (the context-aware observer received the run id)", got)
	}

	rec.HandleResults(context.Background(), recTestRunID, RequestFacts{},
		[]observedToolResult{recResult("toolu_dispatch", `{}`, false)})
	waitForCalls(t, calls, 1)
	if got := len(calls.snapshot()); got != 1 {
		t.Errorf("%d recorded calls, want 1", got)
	}
}

func TestCombineToolUseObserversWithNoObserversReturnsNil(t *testing.T) {
	if got := CombineToolUseObservers(); got != nil {
		t.Errorf("CombineToolUseObservers() = %v, want nil", got)
	}
	if got := CombineToolUseObservers(nil, nil); got != nil {
		t.Errorf("CombineToolUseObservers(nil, nil) = %v, want nil", got)
	}
}

func TestCombineToolUseObserversOnToolUseWithoutContextCallsPlainOnToolUse(t *testing.T) {
	a := &fakeToolUseObserver{}
	combined := CombineToolUseObservers(a)
	// The plain interface method, exercised directly rather than through
	// boundToolUseObserver, for the caller sse.go itself uses when no
	// request context is available at all.
	combined.OnToolUse(ToolUse{ID: "toolu_plain_path"})
	if got := a.snapshot(); len(got) != 1 {
		t.Errorf("%d calls, want 1", len(got))
	}
}

// The commit path's resolver (ADR-0059 decision 4): a tool call is found by
// its id while it runs, with the run it was relayed on, and is gone once its
// result arrives.
func TestRecorderLooksUpARunningToolCallUntilItsResultArrives(t *testing.T) {
	calls := &fakeRecordCalls{}
	rec := NewToolCallRecorder(ToolCallRecorderConfig{record: calls.fn})
	var _ commitpath.Resolver = rec

	before := time.Now()
	rec.OnToolUseContext(WithRunID(context.Background(), recTestRunID),
		recToolUse("toolu_1", "Bash", `{"command":"git commit -m x"}`))

	got, ok := rec.LookupPending("toolu_1")
	if !ok {
		t.Fatal("a running tool call was not found")
	}
	if got.RunID != recTestRunID || got.Tool != "Bash" || string(got.Input) != `{"command":"git commit -m x"}` || got.ObservedAt.Before(before) {
		t.Errorf("LookupPending = %+v", got)
	}
	if _, ok := rec.LookupPending("toolu_other"); ok {
		t.Error("an id never relayed was found")
	}

	rec.HandleResults(context.Background(), recTestRunID, RequestFacts{},
		[]observedToolResult{recResult("toolu_1", `"done"`, false)})
	waitForCalls(t, calls, 1)
	if _, ok := rec.LookupPending("toolu_1"); ok {
		t.Error("a tool call was still found after its result arrived")
	}
}

// The commit path reads the commit's objects from the repository the agent
// works in, so a relayed tool call keeps the working directory its request
// stated.
func TestRecorderKeepsTheWorkingDirectoryOfARunningToolCall(t *testing.T) {
	rec := NewToolCallRecorder(ToolCallRecorderConfig{record: (&fakeRecordCalls{}).fn})
	ctx := WithRequestFacts(WithRunID(context.Background(), recTestRunID),
		RequestFacts{WorkingDirectory: "/workspace/example-repo"})
	rec.OnToolUseContext(ctx, recToolUse("toolu_1", "Bash", `{"command":"git commit -m x"}`))

	got, ok := rec.LookupPending("toolu_1")
	if !ok || got.WorkingDirectory != "/workspace/example-repo" {
		t.Errorf("LookupPending = %+v, %v; want the request's working directory", got, ok)
	}
}

// TestBaselineSnapshotFiresOnTheRunsFirstRequest — #437. Measured on
// 2026-10-01: taken on the first tool_use, the baseline raced the harness,
// which starts a tool while the reply is still streaming, and captured the
// workspace after step 1 had written its file. The run's first request
// reaches the gateway before the model has answered at all, so the baseline
// is started there; a request with no working directory claims nothing, so a
// later one that has it still can.
func TestBaselineSnapshotFiresOnTheRunsFirstRequest(t *testing.T) {
	calls := &fakeRecordCalls{}
	witness := &fakeSnapshotWitness{baselineOutcome: SnapshotOutcome{TreeHash: strings.Repeat("a", 40)}}
	baselined := make(chan struct{}, 8)
	rec := NewToolCallRecorder(ToolCallRecorderConfig{
		record: calls.fn, Snapshots: witness, Trigger: NewSnapshotTrigger(),
		onBaselined: func() { baselined <- struct{}{} },
	})
	guard := NewToolCallRecordGuard(rec)
	body := `{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`

	r := recRequest(t, body)
	r = r.WithContext(WithRunID(r.Context(), recTestRunID))
	if _, refusal := guard.Check(r); refusal != nil {
		t.Fatalf("refusal = %+v", refusal)
	}
	if got := witness.baselineCallCount(); got != 0 {
		t.Fatalf("baseline calls with no working directory = %d, want 0", got)
	}

	r = recRequest(t, body)
	r = r.WithContext(WithRunID(WithRequestFacts(r.Context(), RequestFacts{WorkingDirectory: "/w/repo"}), recTestRunID))
	if _, refusal := guard.Check(r); refusal != nil {
		t.Fatalf("refusal = %+v", refusal)
	}
	waitForBaselined(t, baselined, 1, 5*time.Second)
	if witness.lastBaselineDir != "/w/repo" || witness.lastBaselineRun != recTestRunID {
		t.Errorf("baseline = (%q, %q), want (/w/repo, %s)", witness.lastBaselineDir, witness.lastBaselineRun, recTestRunID)
	}
}

// RM-309 (#489): a relayed tool call remembers which installation's request
// carried it, so the commit path can refuse another installation's call.
func TestRecorderKeepsTheInstallationThatRelayedATool(t *testing.T) {
	rec := NewToolCallRecorder(ToolCallRecorderConfig{record: (&fakeRecordCalls{}).fn})
	ctx := WithInstallation(WithRunID(context.Background(), recTestRunID), "0123456789abcdef0123456789abcdef")
	rec.OnToolUseContext(ctx, recToolUse("toolu_inst", "Bash", `{"command":"git commit -m x"}`))

	got, ok := rec.LookupPending("toolu_inst")
	if !ok || got.Installation != "0123456789abcdef0123456789abcdef" {
		t.Errorf("LookupPending = %+v, %v; want the relaying installation", got, ok)
	}
}
