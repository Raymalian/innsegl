// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// An agent's commit is signed or not made. When signing is refused, the way
// out is the cause (an unlinked repository, an unreachable core), never a
// commit with signing turned off. Measured 2026-10-02: after the core refused
// to sign, an agent ran `git commit --no-gpg-sign` and the commit carried an
// agent author and no attribution. The hook now refuses that one command and
// says why; every other command runs.
func TestHookRefusesACommitWithSigningTurnedOff(t *testing.T) {
	for _, cmd := range []string{
		"git commit --no-gpg-sign -m x",
		"cd /w && git commit --no-gpg-sign -F msg.txt",
		"git -c commit.gpgsign=false commit -m x",
		"git -c commit.gpgSign=0 commit -m x",
		"git -C repo -c commit.gpgsign=no commit -m x",
		"git config commit.gpgsign false",
		"git config --local commit.gpgsign off",
	} {
		t.Run(cmd, func(t *testing.T) {
			code, stdout, _ := runHook(t, hookJSON(t, "Bash", cmd, "toolu_01ABCDEFghij0123", nil))
			if code != exitOK {
				t.Fatalf("exit %d", code)
			}
			var out struct {
				HookSpecificOutput struct {
					PermissionDecision       string `json:"permissionDecision"`
					PermissionDecisionReason string `json:"permissionDecisionReason"`
				} `json:"hookSpecificOutput"`
			}
			if err := json.Unmarshal([]byte(stdout), &out); err != nil {
				t.Fatalf("stdout %q: %v", stdout, err)
			}
			if out.HookSpecificOutput.PermissionDecision != "deny" {
				t.Fatalf("decision %q, want deny", out.HookSpecificOutput.PermissionDecision)
			}
			if !strings.Contains(out.HookSpecificOutput.PermissionDecisionReason, "signed") {
				t.Errorf("reason %q does not say commits must be signed", out.HookSpecificOutput.PermissionDecisionReason)
			}
		})
	}
}

// Signing that is on, or a mention that is not a setting, is left alone.
func TestHookLeavesSignedCommitsAndLookalikesAlone(t *testing.T) {
	for _, cmd := range []string{
		"git commit -m 'explain --no-gpg-sign in the docs'",
		"git -c commit.gpgsign=true commit -m x",
		"git log --no-gpg-sign-whatever",
		"grep -r commit.gpgsign .",
		"git config --get commit.gpgsign",
	} {
		t.Run(cmd, func(t *testing.T) {
			_, stdout, _ := runHook(t, hookJSON(t, "Bash", cmd, "toolu_01ABCDEFghij0123", nil))
			if strings.Contains(stdout, `"deny"`) {
				t.Fatalf("refused %q", cmd)
			}
		})
	}
}
