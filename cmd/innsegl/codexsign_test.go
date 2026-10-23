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
	body := strings.ReplaceAll(strings.Replace(hookBodyIn(t, dir, "git commit -m change"), "{", `{"session_id":"11111111-1111-4111-8111-111111111111",`, 1), "toolu_cmt019fixture01", "call_direct")
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

// OAI-006/021: the trusted hook binds signing to the originating CLI thread.
func TestOAI006CodexHookBindsCallingThread(t *testing.T) {
	const session = "11111111-1111-4111-8111-111111111111"
	const child = "22222222-2222-4222-8222-222222222222"
	dir := t.TempDir()
	statedRunGit(t, dir, "init", "-q", "-b", "main")
	markLinked(t, dir)
	for _, tc := range []struct {
		name, session, agent, thread string
		block                        bool
	}{
		{"root", session, "", session, false}, {"child", session, child, child, false},
		{"missing session", "", child, "", true}, {"invalid child", session, "worker;false", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body map[string]any
			if err := json.Unmarshal([]byte(hookBodyIn(t, dir, "git commit -m change")), &body); err != nil {
				t.Fatal(err)
			}
			body["tool_use_id"] = "call_thread"
			body["session_id"] = tc.session
			body["agent_id"] = tc.agent
			raw, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			var out, errs bytes.Buffer
			code := runCodexPreToolUse(bytes.NewReader(raw), &out, &errs, func(string) string { return "http://127.0.0.1:28495" })
			if tc.block {
				if code != exitBlock {
					t.Fatalf("invalid thread allowed: %d %s", code, out.String())
				}
				return
			}
			var v struct {
				HookSpecificOutput struct {
					Input struct {
						Command string `json:"command"`
					} `json:"updatedInput"`
				} `json:"hookSpecificOutput"`
			}
			if err := json.Unmarshal(out.Bytes(), &v); err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"INNSEGL_CODEX_SESSION_ID='" + session + "'", "INNSEGL_CODEX_THREAD_ID='" + tc.thread + "'"} {
				if !strings.Contains(v.HookSpecificOutput.Input.Command, want) {
					t.Fatalf("missing %s in %s", want, out.String())
				}
			}
		})
	}
}
