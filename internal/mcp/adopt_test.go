// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/event"
)

// ADP-001..003 — #298 (RM-187), ADR-0051 decision 2.
//
// An adoption is only as good as its proof, and the proof is this: the bytes
// staged for a path are the bytes the dead run's LAST Write or Edit left there,
// rebuilt from a body whose digest is the one on the chain. Nothing the caller
// says enters it. Each refusal below is paired with the same fixture changed
// in one thing that does rebuild, so a function that refused everything, or
// accepted everything, fails here.

const adpTop = "/host/checkout"

// adpFixture is a run's tool calls as the chain holds them, with their bodies
// on disk the way observe_tool_call writes them.
type adpFixture struct {
	t       *testing.T
	bodyDir string
	runID   string
	events  []event.Fields
	n       int
}

func newADPFixture(t *testing.T) *adpFixture {
	t.Helper()
	return &adpFixture{t: t, bodyDir: t.TempDir(), runID: "run-" + strings.Repeat("a", 32)}
}

// call records one tool call by run, with body stored under its digest, and
// returns the event's hash.
func (f *adpFixture) call(run, tool string, body map[string]any) string {
	f.t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		f.t.Fatal(err)
	}
	digest := event.Digest(raw)
	dir := filepath.Join(f.bodyDir, run)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, strings.TrimPrefix(digest, event.HashPrefix)+observeBodyExt),
		raw, 0o600); err != nil {
		f.t.Fatal(err)
	}
	f.n++
	hash := "sha256:" + strings.Repeat("0", 63) + string(rune('0'+f.n%10))
	f.events = append(f.events, event.Fields{
		event.FieldEventType:     event.EventTypeToolCall,
		event.FieldRunID:         run,
		event.FieldToolName:      tool,
		event.FieldPayloadDigest: digest,
		event.EventHashField:     hash,
	})
	return hash
}

func (f *adpFixture) write(path, content string) string {
	return f.call(f.runID, "Write", map[string]any{
		"tool_name":  "Write",
		"tool_input": map[string]any{"file_path": adpTop + "/" + path, "content": content},
	})
}

func (f *adpFixture) edit(path, original, oldS, newS string, all bool) string {
	return f.call(f.runID, "Edit", map[string]any{
		"tool_name": "Edit",
		"tool_input": map[string]any{"file_path": adpTop + "/" + path,
			"old_string": oldS, "new_string": newS, "replace_all": all},
		"tool_response": map[string]any{"filePath": adpTop + "/" + path, "originalFile": original,
			"oldString": oldS, "newString": newS, "replaceAll": all},
	})
}

func (f *adpFixture) rebuild(staged ...string) (map[string]adoptedPath, error) {
	return rebuildLeftBytes(f.events, f.bodyDir, f.runID, staged)
}

func TestADP001AWriteIsRebuiltByteForByte(t *testing.T) {
	f := newADPFixture(t)
	f.write("a.go", "first\n")
	last := f.write("a.go", "package a\n\nfunc A() {}\n")

	got, err := f.rebuild("a.go")
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	p := got["a.go"]
	if string(p.Bytes) != "package a\n\nfunc A() {}\n" {
		t.Errorf("bytes = %q, want the LAST write's content", p.Bytes)
	}
	if p.ToolCall != last {
		t.Errorf("proved by %s, want the last write's event %s", p.ToolCall, last)
	}
	if p.SHA256 != strings.TrimPrefix(event.Digest(p.Bytes), event.HashPrefix) {
		t.Errorf("sha256 %s is not the digest of the rebuilt bytes", p.SHA256)
	}
}

func TestADP002AnEditIsRebuiltFromTheFileItEdited(t *testing.T) {
	t.Run("one occurrence", func(t *testing.T) {
		f := newADPFixture(t)
		f.write("b.go", "unused\n")
		last := f.edit("b.go", "x := 1\ny := 2\n", "y := 2", "y := 3", false)
		got, err := f.rebuild("b.go")
		if err != nil {
			t.Fatalf("rebuild: %v", err)
		}
		if string(got["b.go"].Bytes) != "x := 1\ny := 3\n" || got["b.go"].ToolCall != last {
			t.Errorf("got %q by %s, want the edit applied to its original, proved by %s",
				got["b.go"].Bytes, got["b.go"].ToolCall, last)
		}
	})

	t.Run("replace_all", func(t *testing.T) {
		f := newADPFixture(t)
		f.edit("c.go", "a a a\n", "a", "b", true)
		got, err := f.rebuild("c.go")
		if err != nil {
			t.Fatalf("rebuild: %v", err)
		}
		if string(got["c.go"].Bytes) != "b b b\n" {
			t.Errorf("bytes = %q, want every occurrence replaced", got["c.go"].Bytes)
		}
	})
}

func TestADP003WhatCannotBeProvedIsRefusedByName(t *testing.T) {
	t.Run("a path the run never wrote through Write or Edit", func(t *testing.T) {
		f := newADPFixture(t)
		f.write("mine.go", "x\n")
		f.call(f.runID, "Bash", map[string]any{"tool_name": "Bash",
			"tool_input": map[string]any{"command": "echo y > shell.go"}})
		if _, err := f.rebuild("mine.go"); err != nil {
			t.Fatalf("control: the written path did not rebuild: %v", err)
		}
		_, err := f.rebuild("mine.go", "shell.go")
		if err == nil || !strings.Contains(err.Error(), "shell.go") {
			t.Errorf("err = %v, want a refusal naming shell.go", err)
		}
	})

	t.Run("another run's write", func(t *testing.T) {
		f := newADPFixture(t)
		f.call("run-"+strings.Repeat("b", 32), "Write", map[string]any{"tool_name": "Write",
			"tool_input": map[string]any{"file_path": adpTop + "/theirs.go", "content": "t\n"}})
		_, err := f.rebuild("theirs.go")
		if err == nil || !strings.Contains(err.Error(), "theirs.go") {
			t.Errorf("err = %v, want another run's write refused", err)
		}
	})

	t.Run("a body missing from the volume", func(t *testing.T) {
		f := newADPFixture(t)
		f.write("gone.go", "g\n")
		if err := os.RemoveAll(filepath.Join(f.bodyDir, f.runID)); err != nil {
			t.Fatal(err)
		}
		_, err := f.rebuild("gone.go")
		if err == nil || !strings.Contains(err.Error(), "gone.go") {
			t.Errorf("err = %v, want a missing body refused", err)
		}
	})

	t.Run("a body that no longer matches its digest", func(t *testing.T) {
		f := newADPFixture(t)
		f.write("tampered.go", "honest\n")
		dir := filepath.Join(f.bodyDir, f.runID)
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 1 {
			t.Fatalf("expected one body: %v %v", entries, err)
		}
		path := filepath.Join(dir, entries[0].Name())
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			t.Fatal(rerr)
		}
		if err = os.WriteFile(path, []byte(strings.Replace(string(raw), "honest", "forged", 1)), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err = f.rebuild("tampered.go")
		if err == nil || !strings.Contains(err.Error(), "digest") {
			t.Errorf("err = %v, want a tampered body refused on its digest", err)
		}
	})

	t.Run("a body that is not a tool call", func(t *testing.T) {
		f := newADPFixture(t)
		f.write("ok.go", "k\n")
		raw := []byte("not json")
		digest := event.Digest(raw)
		if err := os.WriteFile(filepath.Join(f.bodyDir, f.runID,
			strings.TrimPrefix(digest, event.HashPrefix)+observeBodyExt), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		f.events = append(f.events, event.Fields{event.FieldEventType: event.EventTypeToolCall,
			event.FieldRunID: f.runID, event.FieldToolName: "Write", event.FieldPayloadDigest: digest})
		_, err := f.rebuild("ok.go")
		if err == nil || !strings.Contains(err.Error(), "not a tool call") {
			t.Errorf("err = %v, want an unreadable body to refuse the adoption", err)
		}
	})

	t.Run("an edit whose old string is not in its original", func(t *testing.T) {
		f := newADPFixture(t)
		f.edit("e.go", "abc\n", "zzz", "y", false)
		if _, err := f.rebuild("e.go"); err == nil {
			t.Error("an edit that cannot be replayed was rebuilt")
		}
	})

	t.Run("an edit whose old string is ambiguous", func(t *testing.T) {
		f := newADPFixture(t)
		f.edit("amb.go", "a\na\n", "a", "b", false)
		if _, err := f.rebuild("amb.go"); err == nil {
			t.Error("an edit matching twice without replace_all was rebuilt")
		}
	})

	t.Run("bodies naming two different checkouts", func(t *testing.T) {
		f := newADPFixture(t)
		f.write("one.go", "1\n")
		f.call(f.runID, "Write", map[string]any{"tool_name": "Write",
			"tool_input": map[string]any{"file_path": "/elsewhere/two.go", "content": "2\n"}})
		if _, err := f.rebuild("one.go"); err != nil {
			t.Fatalf("control: %v", err)
		}
		if _, err := f.rebuild("one.go", "two.go"); err == nil {
			t.Error("paths from two checkouts were adopted as one tree")
		}
	})
}
