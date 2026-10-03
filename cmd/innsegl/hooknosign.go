// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"io"
	"regexp"
	"strings"
)

// An agent's commit is signed or not made (ADR-0059; signing is fail-closed).
// A refused signature has a cause -- a repository that is not linked yet, a
// core that cannot be reached -- and the way out is the cause, never a commit
// with signing turned off: that commit carries the agent's author and no
// attribution. So the PreToolUse hook refuses exactly the git commands that
// turn signing off, and says why. Every other command runs.

var (
	// quotedSpan is a single- or double-quoted span. One holding whitespace
	// is prose (a commit message) and is dropped before matching; one
	// without is a quoted argument and is unquoted.
	quotedSpan = regexp.MustCompile(`'[^']*'|"[^"]*"`)
	noGPGSign  = regexp.MustCompile(`(^|[\s;&|(])--no-gpg-sign($|[\s;&|)])`)
	gpgsignOff = regexp.MustCompile(`(?i)(^|[\s;&|(])-c\s*commit\.gpgsign=(false|0|no|off)($|[\s;&|)])`)
	configOff  = regexp.MustCompile(`(?i)(^|[\s;&|(])git(\s+-\S+(\s+\S+)?)*\s+config(\s+--\S+)*\s+commit\.gpgsign\s+(false|0|no|off)($|[\s;&|)])`)
)

// unquotedForMatch is command with prose removed and bare quoted arguments
// unquoted, so a flag inside a commit message is not read as a flag.
func unquotedForMatch(command string) string {
	return quotedSpan.ReplaceAllStringFunc(command, func(s string) string {
		inner := s[1 : len(s)-1]
		if strings.ContainsAny(inner, " \t\n") {
			return " "
		}
		return inner
	})
}

// turnsSigningOff reports whether command commits with signing off, or sets
// signing off for later commits.
func turnsSigningOff(command string) bool {
	c := unquotedForMatch(command)
	if configOff.MatchString(c) {
		return true
	}
	if !strings.Contains(c, "commit") {
		return false
	}
	return noGPGSign.MatchString(c) || gpgsignOff.MatchString(c)
}

// unsignedCommitReason is what the agent reads when the command is refused.
const unsignedCommitReason = "innsegl: an agent's commits must be signed, so a commit with signing turned off " +
	"(--no-gpg-sign, commit.gpgsign=false) is refused. If signing itself failed, fix its cause instead: " +
	"run `innsegl link <repository>` when the core says the message lacks the run's trailers, and check " +
	"`curl -s http://127.0.0.1:28195/_client/status` when the core cannot be reached. Then commit normally."

// writeDeny writes the harness's PreToolUse refusal for this one command.
func writeDeny(stdout io.Writer, reason string) {
	var out struct {
		HookSpecificOutput struct {
			HookEventName            string `json:"hookEventName"`
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	out.HookSpecificOutput.HookEventName = "PreToolUse"
	out.HookSpecificOutput.PermissionDecision = "deny"
	out.HookSpecificOutput.PermissionDecisionReason = reason
	// A write failure has nothing to fall back to; the command then runs.
	_ = json.NewEncoder(stdout).Encode(out) //nolint:errcheck // see above
}
