// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"io"

	"innsegl.dev/innsegl/internal/commitpath"
)

// runHookPreToolUse is the harness's PreToolUse hook, ADR-0059 decision 1: it
// injects the tool call's own identifier into the exact `git commit`
// invocation the model asked for, as an environment variable on that one
// child process. RM-239 (#384).
//
// # What it does, and what it deliberately does not
//
// stdin is the harness's PreToolUse JSON: tool_name, tool_input and
// tool_use_id among other fields. When tool_name is "Bash", tool_input.command
// satisfies commitpath.IsGitCommitCommand, and tool_use_id satisfies
// commitpath.IsToolUseID, this prints exactly one JSON object naming an
// updatedInput whose command is prefixed with
// `export INNSEGL_TOOL_USE_ID=<id>; `. The id is safe to interpolate directly
// into the shell command — no quoting, no escaping — only because
// commitpath.IsToolUseID was checked first: it accepts nothing but
// "toolu_" followed by letters, digits and underscores, which contains no
// shell metacharacter.
//
// Every other field of tool_input survives byte for byte: this decodes it as
// map[string]json.RawMessage, replaces only the "command" entry, and
// re-encodes the map, rather than parsing tool_input's shape at all. It does
// not know or care what else a Bash tool call carries.
//
// It never sets permissionDecision or any other field a harness could read as
// a grant (CMT-003, ADR-0059 §5): the harness's own permission rules decide
// whether this rewritten `git commit` is allowed to run at all. This hook
// only decides what environment it runs in if it is allowed to run.
//
// # Why every other case is fail-open
//
// Anything else — a different tool, a Bash command that is not a git commit,
// a missing or malformed tool_use_id, or stdin that will not parse as the
// expected JSON at all — prints nothing and exits 0. That is safe, not
// careless: prepare-commit-msg and gpg.x509.program (ADR-0059 decisions 2 and
// 3) each refuse a commit whose payload carries no resolvable tool call id
// (ADR-0059 decision 7), so a `git commit` this hook left untouched is
// refused downstream rather than silently landing unattributed. This hook
// exists to make the ordinary, attributed path work — not to be the gate; the
// gate is git aborting the commit when the later steps have nothing to
// resolve.
//
// The return is always exitOK: a hook that refused to run would be a second,
// competing gate on top of the one ADR-0059 decision 7 already places
// downstream, so every path here — matched or not, well-formed or not —
// exits clean and lets the harness proceed. stdout carries the only signal
// this hook ever gives; stderr is unused for the same reason nothing is
// printed on the fail-open paths: there is nothing for this hook to say that
// the commit path itself will not say more precisely if it matters.
func runHookPreToolUse(stdin io.Reader, stdout, stderr io.Writer) int { //nolint:unparam // see the comment above: this hook never fails, only advises
	// internal/gateway bounds request bodies the same way; a PreToolUse
	// payload is never legitimately this large.
	const maxHookStdinBytes = 8 << 20 // 8 MiB

	data, err := io.ReadAll(io.LimitReader(stdin, maxHookStdinBytes+1))
	if err != nil || len(data) > maxHookStdinBytes {
		return exitOK
	}

	var event struct {
		ToolName  string          `json:"tool_name"`
		ToolInput json.RawMessage `json:"tool_input"`
		ToolUseID string          `json:"tool_use_id"`
	}
	if json.Unmarshal(data, &event) != nil || event.ToolName != "Bash" {
		return exitOK
	}

	var input map[string]json.RawMessage
	if json.Unmarshal(event.ToolInput, &input) != nil {
		return exitOK
	}
	var command string
	if raw, ok := input["command"]; !ok || json.Unmarshal(raw, &command) != nil {
		return exitOK
	}

	if !commitpath.IsGitCommitCommand(command) || !commitpath.IsToolUseID(event.ToolUseID) {
		return exitOK
	}

	// Safe to interpolate with no quoting: IsToolUseID above admits nothing
	// but "toolu_" followed by letters, digits and underscores, so
	// event.ToolUseID contains no shell metacharacter for the child shell to
	// misread.
	rewritten, err := json.Marshal("export " + commitpath.EnvToolUseID + "=" + event.ToolUseID + "; " + command)
	if err != nil {
		return exitOK
	}
	input["command"] = rewritten

	updatedInput, err := json.Marshal(input)
	if err != nil {
		return exitOK
	}

	output := struct {
		HookSpecificOutput struct {
			HookEventName string          `json:"hookEventName"`
			UpdatedInput  json.RawMessage `json:"updatedInput"`
		} `json:"hookSpecificOutput"`
	}{}
	output.HookSpecificOutput.HookEventName = "PreToolUse"
	output.HookSpecificOutput.UpdatedInput = updatedInput

	// A write failure here has nothing left to fall back to; the harness
	// reads whatever reached stdout, and exitOK is unconditional regardless.
	if err = json.NewEncoder(stdout).Encode(output); err != nil {
		return exitOK
	}
	return exitOK
}
