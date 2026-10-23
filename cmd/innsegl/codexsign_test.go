// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// OAI-014/025: only a rewritten linked commit receives the Codex-required
// allow decision. The ordinary hook's CMT-003 behavior stays unchanged.
func TestOAI014CodexHookRewritesCommitWithAllow(t *testing.T) {
	dir := t.TempDir()
	statedRunGit(t, dir, "init", "-q", "-b", "main")
	markLinked(t, dir)
	body := strings.ReplaceAll(hookBodyIn(t, dir, "git commit -m change"), "toolu_cmt019fixture01", "call_direct")
	var out, errs bytes.Buffer
	code := runCodexPreToolUse(strings.NewReader(body), &out, &errs, func(string) string { return "http://127.0.0.1:28495" })
	if code != exitOK {
		t.Fatalf("exit%d %s", code, errs.String())
	}
	var v struct {
		HookSpecificOutput struct {
			Permission string `json:"permissionDecision"`
			Input      struct {
				Command string `json:"command"`
			} `json:"updatedInput"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatal(err, out.String())
	}
	if v.HookSpecificOutput.Permission != "allow" || !strings.Contains(v.HookSpecificOutput.Input.Command, "INNSEGL_TOOL_USE_ID=call_direct") || !strings.Contains(v.HookSpecificOutput.Input.Command, "INNSEGL_CORE_URL=") {
		t.Fatal(out.String())
	}
	out.Reset()
	body = strings.ReplaceAll(body, "git commit -m change", "git status")
	runCodexPreToolUse(strings.NewReader(body), &out, &errs, func(string) string { return "http://127.0.0.1:28495" })
	if out.Len() != 0 {
		t.Fatal("non-commit received permission", out.String())
	}
}

func TestOAI021CodexHookDoesNotAllowForeignCallIDs(t *testing.T) {
	dir := t.TempDir()
	statedRunGit(t, dir, "init", "-q", "-b", "main")
	markLinked(t, dir)
	var out, errs bytes.Buffer
	runCodexPreToolUse(strings.NewReader(hookBodyIn(t, dir, "git commit -m change")), &out, &errs, func(string) string { return "http://127.0.0.1:28495" })
	if strings.Contains(out.String(), `"allow"`) {
		t.Fatal("foreign ID received allow", out.String())
	}
}
