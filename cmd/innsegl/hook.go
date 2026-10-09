// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"innsegl.dev/innsegl/internal/client"
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
// config — the signing configuration placed inside the git invocation
// itself, as git's own `-c key=value` options immediately before the
// subcommand word (commitpath.InsertGitOptions; `git -C dir commit` becomes
// `git -C dir -c … commit`): commit.gpgsign=true, gpg.format=x509, and
// gpg.x509.program set to the resolved, absolute path of this same running
// innsegl binary — the one a linked repository's git then invokes directly
// as its signing program (cli.go's --status-fd/--verify dispatch, decision 2
// of the operator's plan). Options, not environment: the harness's own
// worktree-isolation guard refuses any command that sets GIT_CONFIG_COUNT,
// GIT_CONFIG_PARAMETERS or GIT_CONFIG_GLOBAL, so an earlier version of this
// hook, which carried the same three keys as GIT_CONFIG_COUNT /
// GIT_CONFIG_KEY_n / GIT_CONFIG_VALUE_n in the export, had every isolated
// agent's commit refused outright; the guard reads `-c` per key and allows
// these three (CMT-018). Placing them after the command's own options also
// settles precedence without parsing anything: git reads the last `-c` for
// a key, and reads any `-c` over a GIT_CONFIG_* variable, so a command that
// carries its own `-c` or its own GIT_CONFIG_COUNT entries still signs
// (ENF-012; hook_test.go measures both against a real git). The id, and
// every literal git config key and value here, are safe to interpolate
// directly into the shell command — no quoting, no escaping — only because
// commitpath.IsToolUseID was checked first (it accepts nothing but "toolu_"
// followed by letters, digits and underscores) and the resolved binary path
// is checked by isShellSafeForInterpolation before it is ever used: a path
// outside that conservative set is refused (see that function's own
// comment), and the signing configuration is simply omitted for that one
// commit rather than pasted in unquoted. The omission does not drop the tool
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
// exits clean and lets the harness proceed. stdout carries the hook's
// signal. stderr carries one note only: an operator-mode repository with no
// usable noreply address, whose commit goes ahead as the agent (ENF-013) —
// the one case the commit path itself would never mention, because nothing
// downstream is refused.
func runHookPreToolUse(stdin io.Reader, stdout, stderr io.Writer) int {
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
		Cwd       string          `json:"cwd"`
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

	if turnsSigningOff(command) {
		writeDeny(stdout, unsignedCommitReason)
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
	// The repository the commit is in: what signing is bound to (signrepo.go)
	// and what the per-repository author setting is keyed by.
	var repo string
	if event.Cwd != "" {
		if r, rerr := gitCommonDir(context.Background(), event.Cwd); rerr == nil {
			repo = r
		}
	}
	// Decided on the command as the model wrote it, before anything is
	// placed inside it.
	addIdentity := !commandAlreadySetsAuthorIdentity(command)
	if bin, binErr := innseglBinaryPath(); binErr == nil && isShellSafeForInterpolation(bin) {
		// The signing configuration goes inside each commit-creating git
		// invocation as `-c` options, never into the export (see the doc
		// comment above); the command is otherwise byte for byte the one
		// the model asked for.
		command = commitpath.InsertGitOptions(command, gitConfigSigningOptions(bin))
		// A commit in any other repository, made by something else in the
		// same command, is refused.
		if isShellSafeForInterpolation(repo) {
			assignments = append(assignments, envSignRepo+"="+repo)
		}
	}
	if addIdentity {
		assignments = append(assignments, authorIdentityAssignments(repo, event.Cwd, stderr)...)
	}
	// Nothing above is fatal to this branch: an unresolved binary path or an
	// unsafe one just leaves the command without its `-c` options and the
	// export without INNSEGL_SIGN_REPO — the tool call id and the identity
	// still travel — see the package doc above for why that is still safe
	// rather than merely convenient.
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

// gitConfigSigningEntries is the git configuration RM-245's host decision
// carries onto one child git process, in order: git.commit's own contract for
// `gpg.format=x509` plus ADR-0059 decision 3's signing program. The program
// path itself is not fixed, so it is not in this table — see
// gitConfigSigningOptions.
var gitConfigSigningEntries = [][2]string{
	{"commit.gpgsign", "true"},
	{"gpg.format", "x509"},
}

// gitConfigSigningOptions builds the `-c key=value` option words (git's own
// per-invocation configuration, which it reads last — over the repository's
// config, over any GIT_CONFIG_* variable, and over an earlier `-c` for the
// same key; measured against a real git by hook_test.go's TestENF005… and
// TestHookSigningOptionsWin…) that configure exactly the three keys ADR-0059
// decision 3 needs on the one process a `git commit` tool call is about to
// become: commit.gpgsign, gpg.format, and gpg.x509.program set to
// programPath. commitpath.InsertGitOptions places them. The caller is
// responsible for having already proven programPath safe to interpolate
// unquoted (isShellSafeForInterpolation).
func gitConfigSigningOptions(programPath string) []string {
	entries := append(append([][2]string{}, gitConfigSigningEntries...), [2]string{"gpg.x509.program", programPath})
	out := make([]string, 0, 2*len(entries))
	for _, kv := range entries {
		out = append(out, "-c", kv[0]+"="+kv[1])
	}
	return out
}

// agentAuthorName and agentAuthorEmail are the identity a commit made through
// this hook carries (RM-315). The email must equal the core's I6 author
// policy (INNSEGL_SIGN_AUTHOR_EMAIL in deploy/compose/innsegl.yml, checked by
// signing.CheckAuthor); the client cannot read the core's configuration, so it
// is a constant here. Both are shell-safe, so they need no quoting.
const (
	agentAuthorName  = "Innsegl"
	agentAuthorEmail = "agent@innsegl.invalid"
)

// agentIdentityAssignments builds the four environment assignments that make
// a git commit author and committer the agent identity.
func agentIdentityAssignments() []string {
	return []string{
		"GIT_AUTHOR_NAME=" + agentAuthorName,
		"GIT_AUTHOR_EMAIL=" + agentAuthorEmail,
		"GIT_COMMITTER_NAME=" + agentAuthorName,
		"GIT_COMMITTER_EMAIL=" + agentAuthorEmail,
	}
}

// authorIdentityAssignments is the agent identity, unless the operator set
// this repository to author agent commits as the operator (ENF-010,
// internal/client/authors.go). Then it is the operator's identity, which I6
// allows; the trailers and the signature still name the agent.
//
// The operator's identity is read from the repository itself (ENF-013): its
// git user.email, when that is a GitHub noreply address, with the address's
// login as the name. Nothing is typed, and user.name is never read. A typed
// identity (`innsegl author operator`) overrides it. A repository with no
// usable address keeps the agent identity and says so on stderr; the commit
// is never blocked for it.
//
// The values are single-quoted: a noreply login and address hold no quote,
// and client.Authors stores no typed identity holding a quote or a control
// character, so nothing inside needs escaping.
func authorIdentityAssignments(repo, cwd string, stderr io.Writer) []string {
	if repo == "" {
		return agentIdentityAssignments()
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return agentIdentityAssignments()
	}
	authors, err := client.ReadAuthors(client.ClientPaths(home))
	if err != nil || !authors.IsOperator(repo) {
		return agentIdentityAssignments()
	}
	name, email, ok := authors.OperatorFor(repo)
	if !ok {
		name, email, err = client.NoreplyIdentity(context.Background(), cwd)
		if err != nil {
			fprintf(stderr, "innsegl hook: this repository is in operator mode, but %v; "+
				"this commit is authored as the agent\n", err)
			return agentIdentityAssignments()
		}
	}
	quoted := func(s string) string { return "'" + s + "'" }
	return []string{
		"GIT_AUTHOR_NAME=" + quoted(name),
		"GIT_AUTHOR_EMAIL=" + quoted(email),
		"GIT_COMMITTER_NAME=" + quoted(name),
		"GIT_COMMITTER_EMAIL=" + quoted(email),
	}
}

// gitIdentityAssignment matches an assignment of any of the four identity
// variables in a command's own text, as a shell word rather than merely a
// substring: the character immediately before the match (or the start of
// the command) must not itself be part of an identifier, so
// "MY_GIT_AUTHOR_NAME=x" does not false-positive.
var gitIdentityAssignment = regexp.MustCompile(`(^|[^A-Za-z0-9_])GIT_(AUTHOR|COMMITTER)_(NAME|EMAIL)=`)

// commandAlreadySetsAuthorIdentity reports whether cmd assigns any of
// GIT_AUTHOR_NAME, GIT_AUTHOR_EMAIL, GIT_COMMITTER_NAME or GIT_COMMITTER_EMAIL.
// An explicit choice is respected: the hook then adds none of the four.
func commandAlreadySetsAuthorIdentity(cmd string) bool {
	return gitIdentityAssignment.MatchString(cmd)
}
