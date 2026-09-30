// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
)

func TestLooksLikeRefLockFailure(t *testing.T) {
	positive := []string{
		"error: cannot lock ref 'refs/heads/main': is at abc but expected def",
		"fatal: Unable to create '.git/refs/heads/main.lock': File exists.",
		"failed to lock ref for update",
	}
	for _, text := range positive {
		if !looksLikeRefLockFailure(text) {
			t.Errorf("looksLikeRefLockFailure(%q) = false, want true", text)
		}
	}
	if looksLikeRefLockFailure("permission denied") {
		t.Error("an ordinary failure must not read as a ref-lock failure")
	}
}

func TestRefLockFailureFound(t *testing.T) {
	dir := t.TempDir()
	body := marshalBody(t, gatewayBody{
		Tool: "Bash", Input: json.RawMessage(`{"command":"git commit -m x"}`),
		ResultObserved: true, IsError: true,
		Result: json.RawMessage(`"error: cannot lock ref 'refs/heads/main': is at a but expected b"`),
	})
	digest := writeRunBody(t, dir, "run-x", body)

	claims := []recordEventRow{mkRow(event.EventTypeToolCall, time.Now(), map[string]any{
		toolCallToolNameField: "Bash", toolCallDigestField: digest,
	})}
	if !refLockFailureFound(dir, "run-x", claims) {
		t.Error("refLockFailureFound should find the ref-lock text in the retained body")
	}

	// A claim whose body carries no ref-lock text at all.
	body2 := marshalBody(t, gatewayBody{
		Tool: "Bash", Input: json.RawMessage(`{"command":"git commit -m x"}`),
		ResultObserved: true, IsError: true, Result: json.RawMessage(`"some other failure"`),
	})
	digest2 := writeRunBody(t, dir, "run-y", body2)
	claims2 := []recordEventRow{mkRow(event.EventTypeToolCall, time.Now(), map[string]any{
		toolCallToolNameField: "Bash", toolCallDigestField: digest2,
	})}
	if refLockFailureFound(dir, "run-y", claims2) {
		t.Error("refLockFailureFound must not report one that is not there")
	}

	if refLockFailureFound(dir, "run-x", nil) {
		t.Error("no claims at all should answer false")
	}
}

func TestSplitRenameArrowWholePath(t *testing.T) {
	old, nw, ok := splitRenameArrow("old-name.txt => new-name.txt")
	if !ok || old != "old-name.txt" || nw != "new-name.txt" {
		t.Errorf("splitRenameArrow = %q, %q, %v", old, nw, ok)
	}
}

func TestSplitRenameArrowDirectoryForm(t *testing.T) {
	old, nw, ok := splitRenameArrow("src/{a => b}/file.go")
	if !ok || old != "src/a/file.go" || nw != "src/b/file.go" {
		t.Errorf("splitRenameArrow(directory form) = %q, %q, %v; want src/a/file.go, src/b/file.go, true", old, nw, ok)
	}
}

func TestSplitRenameArrowOrdinaryPathIsNotARename(t *testing.T) {
	if _, _, ok := splitRenameArrow("ordinary/path.go"); ok {
		t.Error("an ordinary path must not be read as a rename")
	}
}

// A signed commit that did not land says why when this run's own git commit
// result shows git's ref-lock failure (the approved mockup's "lost git's ref
// lock to a parallel commit"), and says nothing it cannot read.
func TestNotLandedReason(t *testing.T) {
	dir := t.TempDir()
	lost := marshalBody(t, gatewayBody{
		Tool: "Bash", Input: json.RawMessage(`{"command":"git commit -m x"}`),
		ResultObserved: true, IsError: true,
		Result: json.RawMessage(`"error: cannot lock ref 'refs/heads/main': is at a but expected b"`),
	})
	claims := []recordEventRow{mkRow(event.EventTypeToolCall, time.Now(), map[string]any{
		toolCallToolNameField: "Bash", toolCallDigestField: writeRunBody(t, dir, "run-x", lost),
	})}
	if got := notLandedReason(dir, "run-x", claims); got != "ref_lock" {
		t.Errorf("notLandedReason with a ref-lock failure = %q, want ref_lock", got)
	}
	if got := notLandedReason(dir, "run-x", nil); got != "" {
		t.Errorf("notLandedReason with nothing to read = %q, want empty", got)
	}
	if got := notLandedReason("", "run-x", claims); got != "" {
		t.Errorf("notLandedReason with no body store = %q, want empty", got)
	}
}
