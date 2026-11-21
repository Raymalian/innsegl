// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// OAI-017/018/021: eviction and process replacement must not promote an
// incomplete observation into executable signing evidence.
func TestOAI018IncompleteObservationSurvivesEvictionAndRestart(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private-history")
	for _, restart := range []bool{false, true} {
		name := map[bool]string{false: "eviction", true: "restart"}[restart]
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(root, name)
			history, err := NewIncompleteCallStore(dir)
			if err != nil {
				t.Fatal(err)
			}
			calls := &fakeRecordCalls{}
			recorded := make(chan struct{}, 8)
			newRecorder := func(store *IncompleteCallStore) *ToolCallRecorder {
				return NewToolCallRecorder(ToolCallRecorderConfig{MaxPending: 1, IncompleteCalls: store, record: calls.fn, onRecorded: func() { recorded <- struct{}{} }})
			}
			recorder := newRecorder(history)
			ctx := WithRunID(context.Background(), recTestRunID)
			recorder.OnToolUseContext(ctx, ToolUse{ID: "call_durable_incomplete", Name: "exec_command", ObservationIncomplete: true})
			waitForRecorded(t, recorded, 1, 5*time.Second)
			if restart {
				reopened, openErr := NewIncompleteCallStore(dir)
				if openErr != nil {
					t.Fatal(openErr)
				}
				recorder = newRecorder(reopened)
			} else {
				recorder.OnToolUseContext(ctx, recToolUse("call_other_complete", "exec_command", `{"cmd":"pwd"}`))
			}
			recorder.OnToolUseContext(ctx, recToolUse("call_durable_incomplete", "exec_command", `{"cmd":"git commit"}`))
			if _, ok := recorder.LookupPending("call_durable_incomplete"); ok {
				t.Fatal("replayed incomplete call acquired signing authority")
			}
			recorder.HandleResults(ctx, recTestRunID, RequestFacts{}, []observedToolResult{recResult("call_durable_incomplete", `"late result"`, false)})
			waitForNoFurtherRecording(t, recorded, 100*time.Millisecond)
			if got := len(calls.snapshot()); got != 1 {
				t.Fatalf("recordings=%d, want only original incomplete observation", got)
			}
		})
	}
}

// OAI-018: the persistent index contains only opaque tombstones; run/call
// scope is distinct and malformed or redirected storage is not trusted.
func TestOAI018IncompleteStoreScopesAndValidatesTombstones(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private-history")
	store, openErr := NewIncompleteCallStore(root)
	if openErr != nil {
		t.Fatal(openErr)
	}
	if err := store.Remember("run-one", "call-one"); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{"run-one", "call-one"}, {"run-two", "call-one"}, {"run-one", "call-two"}} {
		got, err := store.Contains(pair[0], pair[1])
		want := pair == [2]string{"run-one", "call-one"}
		if err != nil || got != want {
			t.Fatalf("Contains(%v)=%v,%v", pair, got, err)
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 {
		t.Fatalf("tombstones=%v: %v", entries, err)
	}
	marker := filepath.Join(root, entries[0].Name())
	if err := os.WriteFile(marker, []byte("untrusted state"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Contains("run-one", "call-one"); err == nil {
		t.Fatal("accepted malformed tombstone")
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "missing"), marker); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Contains("run-one", "call-one"); err == nil {
		t.Fatal("followed a tombstone symlink")
	}
}

func TestOAI018UnreadableHistoryCannotAuthorizeACommand(t *testing.T) {
	store, err := NewIncompleteCallStore(filepath.Join(t.TempDir(), "private-history"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Remember(recTestRunID, "call_untrusted_history"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.path(recTestRunID, "call_untrusted_history"), []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	calls := &fakeRecordCalls{}
	recorded := make(chan struct{}, 1)
	recorder := NewToolCallRecorder(ToolCallRecorderConfig{
		IncompleteCalls: store, record: calls.fn,
		onRecorded: func() { recorded <- struct{}{} },
	})
	ctx := WithRunID(t.Context(), recTestRunID)
	recorder.OnToolUseContext(ctx, recToolUse("call_untrusted_history", "exec_command", `{"cmd":"private command"}`))
	waitForRecorded(t, recorded, 1, 5*time.Second)
	if _, ok := recorder.LookupPending("call_untrusted_history"); ok {
		t.Fatal("unreadable observation history granted signing authority")
	}
	if recorder.FailedRecordings() != 1 {
		t.Fatal("history failure was not counted")
	}
	got := calls.snapshot()
	if len(got) != 1 || strings.Contains(string(got[0].Body), "private command") ||
		!strings.Contains(string(got[0].Body), `"observation_incomplete":true`) {
		t.Fatalf("history failure was not retained as an input-free gap: %+v", got)
	}
}
