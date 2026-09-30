// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

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
// updatedInput whose command is prefixed with an `export` statement carrying
// INNSEGL_TOOL_USE_ID=<id>, and — this is the operator's decision of
// 2026-09-30 (RM-245, #390): a human's own `git commit` in a linked
// repository is left completely alone, so the signing configuration must
// travel WITH an agent's commit rather than live in the repository's own git
// config — the same one `export` statement extended with git's own
// GIT_CONFIG_COUNT / GIT_CONFIG_KEY_n / GIT_CONFIG_VALUE_n mechanism
// (measured to work with no `-c` flag and no repository config write; see
// hook_test.go's TestENF005…): commit.gpgsign=true, gpg.format=x509, and
// gpg.x509.program set to the resolved, absolute path of this same running
// innsegl binary — the one a linked repository's git then invokes directly
// as its signing program (cli.go's --status-fd/--verify dispatch, decision 2
// of the operator's plan). The id, and every literal git config key and
// value here, are safe to interpolate directly into the shell command — no
// quoting, no escaping — only because commitpath.IsToolUseID was checked
// first (it accepts nothing but "toolu_" followed by letters, digits and
// underscores) and the resolved binary path is checked by
// isShellSafeForInterpolation before it is ever used: a path outside that
// conservative set is refused (see that function's own comment), and the
// signing configuration is simply omitted for that one commit rather than
// pasted in unquoted. The same omission happens, for a different reason,
// when the command itself already assigns GIT_CONFIG_COUNT — see
// commandAlreadySetsGitConfigCount's comment for why this hook cannot safely
// merge into it from a shell prefix alone. Neither omission drops the tool
// call id: an agent's commit that lands unsigned this way is still
// attributed, and is caught by the reconciler's own unsigned-commit alert
// (CMT-016), which is the documented limitation this decision accepts.
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
	assignments := []string{commitpath.EnvToolUseID + "=" + event.ToolUseID}
	if bin, binErr := innseglBinaryPath(); binErr == nil && isShellSafeForInterpolation(bin) &&
		!commandAlreadySetsGitConfigCount(command) {
		assignments = append(assignments, gitConfigSigningAssignments(bin)...)
	}
	// Nothing above is fatal to this branch: an unresolved binary path, an
	// unsafe one, or a command that already claims GIT_CONFIG_COUNT each just
	// leave assignments holding only the tool call id, exactly the export
	// this hook always produced before RM-245 — see the package doc above for
	// why that is still safe rather than merely convenient.
	rewritten, err := json.Marshal("export " + strings.Join(assignments, " ") + "; " + command)
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

// innseglBinaryPath resolves the absolute path of the currently running
// innsegl binary — this process, right now, running this hook — which is
// exactly the binary a linked repository's git will later invoke directly as
// gpg.x509.program (cli.go's --status-fd/--verify dispatch, RM-245). Symlinks
// are resolved (os.Executable's own documented caveat) so the value handed to
// git is a real, stable path rather than one that might not exist by the time
// git reads it.
func innseglBinaryPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

// isShellSafeForInterpolation reports whether s can be pasted into a shell
// command with no quoting and no escaping: letters, digits, and "/._-" only.
// This hook's whole strategy for the tool call id (ADR-0059 decision 1)
// already depends on interpolating a value with nothing that needs quoting —
// commitpath.IsToolUseID's own fixed shape — and the resolved binary path has
// no such fixed shape (it is wherever an operator installed it), so it is
// checked here instead, conservatively, before ever reaching the exported
// command text. A path with a space, a shell metacharacter, or anything else
// outside this set is refused rather than pasted in unquoted and risking the
// child shell reading part of it as syntax; the signing configuration is
// simply omitted for that one commit when this happens (see the package doc
// above), not worked around by quoting a value this function has not proven
// safe.
func isShellSafeForInterpolation(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '/' || r == '.' || r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}

// gitConfigCountAssignment matches a literal GIT_CONFIG_COUNT= assignment
// anywhere in a command, as a shell word rather than merely a substring — the
// character immediately before the match (or the start of the command) must
// not itself be part of an identifier, so "MY_GIT_CONFIG_COUNT=1" does not
// false-positive.
var gitConfigCountAssignment = regexp.MustCompile(`(^|[^A-Za-z0-9_])GIT_CONFIG_COUNT=`)

// commandAlreadySetsGitConfigCount reports whether cmd's own text assigns
// GIT_CONFIG_COUNT anywhere — a per-command prefix on the git invocation
// itself (`GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=... git commit`) or an earlier
// `export` in a composite command.
//
// This hook cannot safely add its own entries on top of that from a shell
// prefix alone, in either direction: a POSIX shell's temporary, per-command
// variable assignments override the general (exported) environment for the
// duration of that one command, so a `GIT_CONFIG_COUNT=1 ... git commit`
// written directly on the command line beats anything this hook exports
// beforehand, silently dropping the signing configuration entirely rather
// than merging with it; and if the command instead exports GIT_CONFIG_COUNT
// itself later in a `&&`-joined sequence, that later export overwrites
// whatever this hook exported first. Counting the command's own entries by
// text and appending after them does not fix either case — the count this
// hook could read is not necessarily the count the shell will actually see
// applied to the git invocation, without a full shell parse this hook does
// not attempt. So when this is true, the exported assignments carry only the
// tool call id: no GIT_CONFIG_* entry from this hook, clobbering nothing and
// clobbered by nothing. The commit this produces is still attributed (the id
// is untouched) but may land unsigned, which is exactly what the reconciler's
// CMT-016 alert exists to catch — the documented limitation RM-245 accepts
// rather than a shell-level merge this function cannot prove safe.
func commandAlreadySetsGitConfigCount(cmd string) bool {
	return gitConfigCountAssignment.MatchString(cmd)
}

// gitConfigSigningEntries is the git configuration RM-245's host decision
// carries onto one child git process, in order: git.commit's own contract for
// `gpg.format=x509` plus ADR-0059 decision 3's signing program. The program
// path itself is not fixed, so it is not in this table — see
// gitConfigSigningAssignments.
var gitConfigSigningEntries = [][2]string{
	{"commit.gpgsign", "true"},
	{"gpg.format", "x509"},
}

// gitConfigSigningAssignments builds the GIT_CONFIG_COUNT / GIT_CONFIG_KEY_n
// / GIT_CONFIG_VALUE_n environment assignments (git's own mechanism, measured
// against a real git by hook_test.go's TestENF005… to work with no `-c` flag
// and no write to any repository's config file) that configure exactly the
// three keys ADR-0059 decision 3 needs on the one process a `git commit` tool
// call is about to become: commit.gpgsign, gpg.format, and gpg.x509.program
// set to programPath. The caller is responsible for having already proven
// programPath safe to interpolate unquoted (isShellSafeForInterpolation).
func gitConfigSigningAssignments(programPath string) []string {
	entries := append(append([][2]string{}, gitConfigSigningEntries...), [2]string{"gpg.x509.program", programPath})
	out := make([]string, 0, 1+2*len(entries))
	out = append(out, fmt.Sprintf("GIT_CONFIG_COUNT=%d", len(entries)))
	for i, kv := range entries {
		out = append(out, fmt.Sprintf("GIT_CONFIG_KEY_%d=%s", i, kv[0]), fmt.Sprintf("GIT_CONFIG_VALUE_%d=%s", i, kv[1]))
	}
	return out
}
