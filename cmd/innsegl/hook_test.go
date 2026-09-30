// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/commitpath"
)

// hookOutput mirrors the JSON shape the hook must print, read back generically
// so a test can also assert that nothing else is present (CMT-003).
type hookOutput struct {
	HookSpecificOutput struct {
		HookEventName string                     `json:"hookEventName"`
		UpdatedInput  map[string]json.RawMessage `json:"updatedInput"`
	} `json:"hookSpecificOutput"`
}

// runHook feeds body (already-marshalled hook JSON) to runHookPreToolUse and
// returns its exit code and what it wrote to stdout and stderr.
func runHook(t *testing.T, body string) (code int, stdout, stderr string) {
	t.Helper()
	var outBuf, errBuf bytes.Buffer
	code = runHookPreToolUse(strings.NewReader(body), &outBuf, &errBuf)
	return code, outBuf.String(), errBuf.String()
}

// hookJSON builds the harness's PreToolUse stdin: tool_name, a tool_input
// object built from extra plus "command", and tool_use_id.
func hookJSON(t *testing.T, toolName, command, toolUseID string, extra map[string]any) string {
	t.Helper()
	input := map[string]any{}
	for k, v := range extra {
		input[k] = v
	}
	input["command"] = command
	body := map[string]any{
		"tool_name":   toolName,
		"tool_input":  input,
		"tool_use_id": toolUseID,
		// A field the hook must ignore and never echo back.
		"session_id": "session-should-be-ignored",
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal hook input: %v", err)
	}
	return string(raw)
}

// writeFakeGit puts a `git` on PATH (returned) whose only behaviour is
// printing INNSEGL_TOOL_USE_ID from its own environment, so a test can prove
// the value a real shell handed to a real child process, not just read JSON
// text.
func writeFakeGit(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\nprintf '%s' \"$" + commitpath.EnvToolUseID + "\"\n"
	path := filepath.Join(dir, "git")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake git: %v", err)
	}
	return dir
}

// runShell runs command through `sh -c`, with fakeGitDir prepended to PATH so
// the command's `git` resolves to writeFakeGit's stub, and returns combined
// output.
func runShell(t *testing.T, command, fakeGitDir string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "sh", "-c", command)
	cmd.Env = append(os.Environ(), "PATH="+fakeGitDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sh -c %q: %v\noutput: %s", command, err, out)
	}
	return string(out)
}

// decodeHookOutput parses stdout as the hook's JSON shape.
func decodeHookOutput(t *testing.T, stdout string) hookOutput {
	t.Helper()
	var out hookOutput
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("stdout is not the expected JSON shape: %v\nstdout: %s", err, stdout)
	}
	return out
}

// updatedCommand extracts updatedInput.command as a plain string.
func updatedCommand(t *testing.T, out hookOutput) string {
	t.Helper()
	raw, ok := out.HookSpecificOutput.UpdatedInput["command"]
	if !ok {
		t.Fatalf("updatedInput has no command field: %+v", out.HookSpecificOutput.UpdatedInput)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("updatedInput.command is not a string: %v", err)
	}
	return s
}

// TestCMT001 — CMT-001 U: the hook sees a Bash git commit -> the command runs
// with INNSEGL_TOOL_USE_ID set to this tool call's own id; the command is
// otherwise unchanged.
func TestCMT001HookInjectsThisToolCallsIDIntoAGitCommit(t *testing.T) {
	const toolUseID = "toolu_01ABCDEFghij0123"

	t.Run("the printed shape and the untouched fields", func(t *testing.T) {
		body := hookJSON(t, "Bash", `git commit -m "add notes"`, toolUseID, map[string]any{
			"description": "commit the notes",
			"timeout":     5000,
			"nested":      map[string]any{"a": 1, "b": []any{"x", "y"}},
		})
		code, stdout, stderr := runHook(t, body)
		if code != 0 {
			t.Fatalf("exit = %d, want 0", code)
		}
		if stderr != "" {
			t.Fatalf("stderr = %q, want empty", stderr)
		}
		out := decodeHookOutput(t, stdout)
		if out.HookSpecificOutput.HookEventName != "PreToolUse" {
			t.Errorf("hookEventName = %q, want PreToolUse", out.HookSpecificOutput.HookEventName)
		}

		got := updatedCommand(t, out)
		want := fmt.Sprintf("export %s=%s; %s", commitpath.EnvToolUseID, toolUseID, `git commit -m "add notes"`)
		if got != want {
			t.Errorf("updatedInput.command = %q, want %q", got, want)
		}

		// Every other field survives untouched, byte for byte.
		for key, wantRaw := range map[string]string{
			"description": `"commit the notes"`,
			"timeout":     `5000`,
			"nested":      `{"a":1,"b":["x","y"]}`,
		} {
			gotRaw, ok := out.HookSpecificOutput.UpdatedInput[key]
			if !ok {
				t.Errorf("updatedInput missing field %q", key)
				continue
			}
			var gotNorm, wantNorm any
			if err := json.Unmarshal(gotRaw, &gotNorm); err != nil {
				t.Fatalf("unmarshal got[%q]: %v", key, err)
			}
			if err := json.Unmarshal([]byte(wantRaw), &wantNorm); err != nil {
				t.Fatalf("unmarshal want[%q]: %v", key, err)
			}
			gj, err := json.Marshal(gotNorm)
			if err != nil {
				t.Fatalf("marshal got[%q]: %v", key, err)
			}
			wj, err := json.Marshal(wantNorm)
			if err != nil {
				t.Fatalf("marshal want[%q]: %v", key, err)
			}
			if string(gj) != string(wj) {
				t.Errorf("updatedInput[%q] = %s, want %s", key, gotRaw, wantRaw)
			}
		}

		// Nothing outside tool_input leaked through.
		if len(out.HookSpecificOutput.UpdatedInput) != 4 { // command, description, timeout, nested
			t.Errorf("updatedInput has %d fields, want exactly 4: %+v", len(out.HookSpecificOutput.UpdatedInput), out.HookSpecificOutput.UpdatedInput)
		}
	})

	t.Run("the id actually reaches the child process", func(t *testing.T) {
		fakeGit := writeFakeGit(t)
		body := hookJSON(t, "Bash", "git commit -m x", toolUseID, nil)
		_, stdout, _ := runHook(t, body)
		out := decodeHookOutput(t, stdout)
		got := runShell(t, updatedCommand(t, out), fakeGit)
		if got != toolUseID {
			t.Fatalf("child saw INNSEGL_TOOL_USE_ID=%q, want %q", got, toolUseID)
		}
	})

	t.Run("the id reaches the child when the commit is the second half of a && b", func(t *testing.T) {
		fakeGit := writeFakeGit(t)
		body := hookJSON(t, "Bash", "echo staged && git commit -m x", toolUseID, nil)
		_, stdout, _ := runHook(t, body)
		out := decodeHookOutput(t, stdout)
		got := runShell(t, updatedCommand(t, out), fakeGit)
		if !strings.Contains(got, toolUseID) {
			t.Fatalf("child output %q does not contain the tool call id %q", got, toolUseID)
		}
	})
}

// TestCMT002 — CMT-002 U: any other command or tool -> no change to the tool
// input. The hook must print nothing at all, so the harness has nothing to
// apply.
func TestCMT002HookLeavesEverythingElseUnchanged(t *testing.T) {
	const toolUseID = "toolu_01ABCDEFghij0123"

	cases := map[string]string{
		"a Bash command that never touches git": hookJSON(t, "Bash", "npm test", toolUseID, nil),
		"a Bash git command that is not commit": hookJSON(t, "Bash", "git status", toolUseID, nil),
		"the Write tool, not Bash":              hookJSON(t, "Write", "", toolUseID, nil),
		"an id with the wrong shape":            hookJSON(t, "Bash", "git commit -m x", "not-a-tool-call-id", nil),
		"a missing tool_use_id":                 hookJSON(t, "Bash", "git commit -m x", "", nil),
		"malformed JSON on stdin":               `{"tool_name": "Bash", "tool_input": {`,
		"empty stdin":                           "",
		"a JSON array instead of an object":     `[]`,
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := runHook(t, body)
			if code != 0 {
				t.Errorf("exit = %d, want 0", code)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want empty (no change to the tool input)", stdout)
			}
			if stderr != "" {
				t.Errorf("stderr = %q, want empty", stderr)
			}
		})
	}
}

// TestCMT003 — CMT-003 U: the hook's output grants no permission. Even on the
// one path that rewrites the command, the JSON it prints must never carry a
// permissionDecision or any other field that could grant one; the harness's
// own permission rules still decide.
func TestCMT003HookOutputGrantsNoPermission(t *testing.T) {
	body := hookJSON(t, "Bash", "git commit -m x", "toolu_01ABCDEFghij0123", nil)
	_, stdout, _ := runHook(t, body)

	var generic map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stdout), &generic); err != nil {
		t.Fatalf("stdout is not a JSON object: %v\nstdout: %s", err, stdout)
	}
	if len(generic) != 1 {
		t.Fatalf("top-level object has %d fields, want exactly hookSpecificOutput: %s", len(generic), stdout)
	}
	hso, ok := generic["hookSpecificOutput"]
	if !ok {
		t.Fatalf("no hookSpecificOutput field: %s", stdout)
	}

	var inner map[string]json.RawMessage
	if err := json.Unmarshal(hso, &inner); err != nil {
		t.Fatalf("hookSpecificOutput is not a JSON object: %v", err)
	}
	for _, forbidden := range []string{"permissionDecision", "permissionDecisionReason", "decision", "systemMessage"} {
		if _, present := inner[forbidden]; present {
			t.Errorf("hookSpecificOutput carries %q, which can grant permission: %s", forbidden, stdout)
		}
	}
	for key := range inner {
		if key != "hookEventName" && key != "updatedInput" {
			t.Errorf("hookSpecificOutput carries unexpected field %q: %s", key, stdout)
		}
	}

	// And nowhere at the top level either.
	for _, forbidden := range []string{"permissionDecision", "permissionDecisionReason", "decision", "continue", "suppressOutput"} {
		if _, present := generic[forbidden]; present {
			t.Errorf("top-level output carries %q, which can grant permission: %s", forbidden, stdout)
		}
	}
}
