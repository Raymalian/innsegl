// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

// ADP-019 (PROPOSED for doc 07) — ADR-0079 decision 4: the rebuild reads the
// bodies the gateway records.
//
// A gateway body carries the tool's input and its text result, never the file
// as it was before an Edit. So an Edit is replayed on the bytes the run's own
// earlier calls left, or on the path's blob in the parent commit when the run
// never wrote it before. A failed call changed nothing; a call whose result was
// never observed may or may not have run, so its path cannot be proved.

func (f *adpFixture) gwCall(tool string, input map[string]any, result string, isError, observed bool) string {
	f.t.Helper()
	in, err := json.Marshal(input)
	if err != nil {
		f.t.Fatal(err)
	}
	body := map[string]any{
		"tool": tool, "tool_use_id": "toolu_01" + strings.Repeat("x", 20),
		"input": json.RawMessage(in), "result_observed": observed,
	}
	if observed {
		body["result"] = result
		body["is_error"] = isError
	}
	return f.call(f.runID, tool, body)
}

func (f *adpFixture) gwWrite(path, content string) string {
	return f.gwCall("Write", map[string]any{"file_path": adpTop + "/" + path, "content": content},
		"File created successfully", false, true)
}

func (f *adpFixture) gwEdit(path, oldS, newS string, all bool) string {
	return f.gwCall("Edit", map[string]any{"file_path": adpTop + "/" + path,
		"old_string": oldS, "new_string": newS, "replace_all": all},
		"The file has been updated.", false, true)
}

func baseOf(files map[string]string) func(string) ([]byte, bool) {
	return func(path string) ([]byte, bool) {
		b, ok := files[path]
		return []byte(b), ok
	}
}

func TestADP019AGatewayWriteIsRebuilt(t *testing.T) {
	f := newADPFixture(t)
	last := f.gwWrite("a.go", "package a\n")
	got, err := rebuildLeftBytes(f.events, f.bodyDir, f.runID, []string{"a.go"}, nil)
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if string(got["a.go"].Bytes) != "package a\n" || got["a.go"].ToolCall != last {
		t.Errorf("got %q by %s, want the write's content proved by %s", got["a.go"].Bytes, got["a.go"].ToolCall, last)
	}
}

func TestADP019AGatewayEditIsReplayedOnWhatCameBefore(t *testing.T) {
	t.Run("on the run's own earlier write", func(t *testing.T) {
		f := newADPFixture(t)
		f.gwWrite("b.go", "x := 1\ny := 2\n")
		last := f.gwEdit("b.go", "y := 2", "y := 3", false)
		got, err := rebuildLeftBytes(f.events, f.bodyDir, f.runID, []string{"b.go"}, nil)
		if err != nil {
			t.Fatalf("rebuild: %v", err)
		}
		if string(got["b.go"].Bytes) != "x := 1\ny := 3\n" || got["b.go"].ToolCall != last {
			t.Errorf("got %q by %s", got["b.go"].Bytes, got["b.go"].ToolCall)
		}
	})

	t.Run("on the parent commit's blob", func(t *testing.T) {
		f := newADPFixture(t)
		f.gwEdit("c.go", "a", "b", true)
		f.gwEdit("c.go", "b b", "c", false)
		got, err := rebuildLeftBytes(f.events, f.bodyDir, f.runID, []string{"c.go"},
			baseOf(map[string]string{"c.go": "a a a\n"}))
		if err != nil {
			t.Fatalf("rebuild: %v", err)
		}
		if string(got["c.go"].Bytes) != "c b\n" {
			t.Errorf("bytes = %q, want both edits replayed on the parent's blob", got["c.go"].Bytes)
		}
	})

	t.Run("a failed call changed nothing", func(t *testing.T) {
		f := newADPFixture(t)
		last := f.gwWrite("d.go", "kept\n")
		f.gwCall("Write", map[string]any{"file_path": adpTop + "/d.go", "content": "never written\n"},
			"permission denied", true, true)
		got, err := rebuildLeftBytes(f.events, f.bodyDir, f.runID, []string{"d.go"}, nil)
		if err != nil {
			t.Fatalf("rebuild: %v", err)
		}
		if string(got["d.go"].Bytes) != "kept\n" || got["d.go"].ToolCall != last {
			t.Errorf("got %q by %s, want the failed write skipped", got["d.go"].Bytes, got["d.go"].ToolCall)
		}
	})
}

func TestADP019WhatAGatewayBodyCannotProveIsRefused(t *testing.T) {
	t.Run("an edit with no earlier bytes and no parent blob", func(t *testing.T) {
		f := newADPFixture(t)
		f.gwEdit("e.go", "a", "b", false)
		if _, err := rebuildLeftBytes(f.events, f.bodyDir, f.runID, []string{"e.go"}, nil); err == nil ||
			!strings.Contains(err.Error(), "e.go") {
			t.Errorf("err = %v, want e.go refused", err)
		}
		// Control: the same edit on a parent blob rebuilds.
		if _, err := rebuildLeftBytes(f.events, f.bodyDir, f.runID, []string{"e.go"},
			baseOf(map[string]string{"e.go": "a\n"})); err != nil {
			t.Errorf("control: %v", err)
		}
	})

	t.Run("a call whose result was never observed", func(t *testing.T) {
		f := newADPFixture(t)
		f.gwWrite("f.go", "one\n")
		f.gwCall("Write", map[string]any{"file_path": adpTop + "/f.go", "content": "two\n"}, "", false, false)
		if _, err := rebuildLeftBytes(f.events, f.bodyDir, f.runID, []string{"f.go"}, nil); err == nil ||
			!strings.Contains(err.Error(), "f.go") {
			t.Errorf("err = %v, want f.go refused", err)
		}
	})

	t.Run("an edit after a call that cannot be known keeps that reason", func(t *testing.T) {
		f := newADPFixture(t)
		f.gwCall("Write", map[string]any{"file_path": adpTop + "/k.go", "content": "a\n"}, "", false, false)
		f.gwEdit("k.go", "a", "b", false)
		_, err := rebuildLeftBytes(f.events, f.bodyDir, f.runID, []string{"k.go"}, nil)
		if err == nil || !strings.Contains(err.Error(), "never observed") {
			t.Errorf("err = %v, want the unobserved call named", err)
		}
	})

	t.Run("a call recorded with its input cut short", func(t *testing.T) {
		f := newADPFixture(t)
		in, err := json.Marshal(map[string]any{"file_path": adpTop + "/t.go", "content": "par"})
		if err != nil {
			t.Fatal(err)
		}
		f.call(f.runID, "Write", map[string]any{"tool": "Write", "input": json.RawMessage(in),
			"input_truncated": true, "result_observed": true, "result": "ok"})
		if _, err := rebuildLeftBytes(f.events, f.bodyDir, f.runID, []string{"t.go"}, nil); err == nil ||
			!strings.Contains(err.Error(), "cut short") {
			t.Errorf("err = %v, want a truncated input refused", err)
		}
	})

	t.Run("a body that names no file refuses the whole adoption", func(t *testing.T) {
		f := newADPFixture(t)
		f.gwWrite("ok.go", "k\n")
		f.gwCall("Write", map[string]any{"content": "x\n"}, "ok", false, true)
		if _, err := rebuildLeftBytes(f.events, f.bodyDir, f.runID, []string{"ok.go"}, nil); err == nil ||
			!strings.Contains(err.Error(), "names no file") {
			t.Errorf("err = %v, want a body naming no file refused", err)
		}
	})

	t.Run("an edit whose old string is not there", func(t *testing.T) {
		f := newADPFixture(t)
		f.gwWrite("g.go", "abc\n")
		f.gwEdit("g.go", "zzz", "y", false)
		if _, err := rebuildLeftBytes(f.events, f.bodyDir, f.runID, []string{"g.go"}, nil); err == nil {
			t.Error("an edit that cannot be replayed was rebuilt")
		}
	})

	t.Run("an edit whose old string is ambiguous", func(t *testing.T) {
		f := newADPFixture(t)
		f.gwWrite("h.go", "a\na\n")
		f.gwEdit("h.go", "a", "b", false)
		if _, err := rebuildLeftBytes(f.events, f.bodyDir, f.runID, []string{"h.go"}, nil); err == nil {
			t.Error("an edit matching twice without replace_all was rebuilt")
		}
	})
}
