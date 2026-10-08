// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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

// hookExpectSelfBinary resolves the same absolute, symlink-free path
// runHookPreToolUse resolves internally (innseglBinaryPath: os.Executable,
// then filepath.EvalSymlinks) — the currently running test binary — so a
// test can build the exact string the hook is expected to produce without
// hardcoding a path that differs across machines and CI.
func hookExpectSelfBinary(t *testing.T) string {
	t.Helper()
	bin, err := innseglBinaryPath()
	if err != nil {
		t.Fatalf("innseglBinaryPath: %v", err)
	}
	return bin
}

// hookWantExport builds the export statement runHookPreToolUse is expected
// to prefix an ordinary git commit with: the tool call id plus the agent
// identity (RM-315). The signing configuration is not here: it travels as
// git's own `-c` options inside the command (hookWantSigningOptions).
func hookWantExport(t *testing.T, toolUseID string) string {
	t.Helper()
	return fmt.Sprintf(
		"export %s=%s GIT_AUTHOR_NAME=Innsegl GIT_AUTHOR_EMAIL=agent@innsegl.invalid "+
			"GIT_COMMITTER_NAME=Innsegl GIT_COMMITTER_EMAIL=agent@innsegl.invalid; ",
		commitpath.EnvToolUseID, toolUseID)
}

// hookWantSigningOptions builds the `-c` options runHookPreToolUse is
// expected to place before the subcommand word of a safe-path git commit:
// the full signing configuration (RM-245), naming this same binary.
func hookWantSigningOptions(t *testing.T) string {
	t.Helper()
	return "-c commit.gpgsign=true -c gpg.format=x509 -c gpg.x509.program=" + hookExpectSelfBinary(t)
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
		want := hookWantExport(t, toolUseID) + "git " + hookWantSigningOptions(t) + ` commit -m "add notes"`
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

// ---------------------------------------------------------------------------
// RM-245 (#390): the signing configuration travels with the one child git
// process, as git's own `-c key=value` options placed before the subcommand
// word (ENF-012), never through the repository's own config and never as a
// GIT_CONFIG_* environment variable (CMT-018).
// ---------------------------------------------------------------------------

func TestIsShellSafeForInterpolation(t *testing.T) {
	cases := []struct {
		name string
		s    string
		want bool
	}{
		{"empty", "", false},
		{"ordinary absolute path", "/usr/local/bin/innsegl", true},
		{"digits, dots, dashes, underscores", "/opt/innsegl-v1.2_3/bin/innsegl", true},
		{"a space", "/path with space/innsegl", false},
		{"a semicolon", "/path/innsegl; rm -rf /", false},
		{"a dollar sign", "/path/$HOME/innsegl", false},
		{"a backtick", "/path/`whoami`/innsegl", false},
		{"a newline", "/path/innsegl\nrm -rf /", false},
		{"a single quote", "/path/innsegl'", false},
		{"a double quote", "/path/innsegl\"", false},
		{"an ampersand", "/path/innsegl&", false},
		{"a pipe", "/path/innsegl|cat", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isShellSafeForInterpolation(c.s); got != c.want {
				t.Errorf("isShellSafeForInterpolation(%q) = %v, want %v", c.s, got, c.want)
			}
		})
	}
}

func TestGitConfigSigningOptions(t *testing.T) {
	got := gitConfigSigningOptions("/opt/innsegl/bin/innsegl")
	want := []string{
		"-c", "commit.gpgsign=true",
		"-c", "gpg.format=x509",
		"-c", "gpg.x509.program=/opt/innsegl/bin/innsegl",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("gitConfigSigningOptions = %v, want %v", got, want)
	}
}

// TestHookSigningOptionsWinOverTheCommandsOwnGitConfigCount (ENF-012,
// PROPOSED): a command that carries its own GIT_CONFIG_COUNT entries — here
// one turning signing off — still gets the hook's `-c` options, and git reads
// a `-c` over any GIT_CONFIG_* variable, so the commit is signed. Measured
// off a real git's committed object, not off the command text.
func TestHookSigningOptionsWinOverTheCommandsOwnGitConfigCount(t *testing.T) {
	git := ghGitOrSkip(t)
	home := t.TempDir()
	repo := filepath.Join(home, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	env := ghIsolatedEnv(home)
	ghRun(t, git, repo, env, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "a.txt"), []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ghRun(t, git, repo, env, "add", "a.txt")

	const toolUseID = "toolu_precount000001"
	const command = `GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=commit.gpgsign GIT_CONFIG_VALUE_0=false git commit -m x`
	_, stdout, _ := runHook(t, hookJSON(t, "Bash", command, toolUseID, nil))
	rewritten := updatedCommand(t, decodeHookOutput(t, stdout))
	want := hookWantExport(t, toolUseID) +
		`GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=commit.gpgsign GIT_CONFIG_VALUE_0=false git ` + hookWantSigningOptions(t) + ` commit -m x`
	if rewritten != want {
		t.Fatalf("updatedInput.command = %q, want %q", rewritten, want)
	}

	sh := exec.CommandContext(t.Context(), "sh", "-c", rewritten)
	sh.Dir = repo
	sh.Env = append(append([]string{}, env...), hookFakeSignEnv+"=1")
	if out, err := sh.CombinedOutput(); err != nil {
		t.Fatalf("sh -c %q: %v\n%s", rewritten, err, out)
	}
	got := ghRun(t, git, repo, env, "cat-file", "commit", "HEAD")
	if !strings.Contains(got, "gpgsig "+hookFakeSignature) {
		t.Errorf("the command's own commit.gpgsign=false won over the hook's -c; object:\n%s", got)
	}
}

// TestCMT018HookRewriteCarriesNoGitConfigVariable (CMT-018, PROPOSED): the
// rewritten command assigns no GIT_CONFIG_* variable at all, in the export
// prefix or anywhere else. A harness that isolates an agent's worktree
// refuses any command that sets GIT_CONFIG_COUNT, GIT_CONFIG_PARAMETERS or
// GIT_CONFIG_GLOBAL, so a hook that added one would have every such agent's
// commit refused; the signing configuration travels as `-c` options instead.
func TestCMT018HookRewriteCarriesNoGitConfigVariable(t *testing.T) {
	for _, command := range []string{
		`git commit -m "add notes"`,
		`git -C /some/dir merge --no-ff feature`,
		`cd sub && git pull origin main`,
		`git rebase main`,
	} {
		_, stdout, _ := runHook(t, hookJSON(t, "Bash", command, "toolu_cmt018fixture01", nil))
		got := updatedCommand(t, decodeHookOutput(t, stdout))
		if strings.Contains(got, "GIT_CONFIG_") {
			t.Errorf("%q: the rewritten command sets a GIT_CONFIG_ variable: %q", command, got)
		}
		if !strings.Contains(got, " -c gpg.x509.program=") {
			t.Errorf("%q: the rewritten command carries no -c gpg.x509.program: %q", command, got)
		}
	}
}

// hookFakeSignEnv switches this test binary into acting as a trivial
// gpg.x509.program instead of running the test suite, so a real git process
// TestENF005… drives — through the exact rewritten command runHookPreToolUse
// produced, via `sh -c` — really does invoke this same binary (the one
// innseglBinaryPath resolves to, in production and in this test) and really
// does receive a signature from it. It deliberately does not implement
// ADR-0059 decision 3's real client (commitpathcli.go's signCommand has its
// own tests, sign_test.go); this only has to prove that git actually invoked
// the program the hook's `-c gpg.x509.program=` named, using x509 signing to
// do it. Never set except by the real-git hook tests, and never true during
// an ordinary `go test` run.
const hookFakeSignEnv = "INNSEGL_HOOK_TEST_FAKE_SIGN"

// hookFakeSignature is what the fake signing program writes to stdout;
// TestENF005… looks for it verbatim in the resulting commit object's gpgsig
// header.
const hookFakeSignature = "ENF005FAKESIGNATURE"

// discardCopyResult lets a copy's return values be discarded through a call
// rather than a blank assignment — errcheck's check-blank setting (this
// project's own policy, .golangci.yml) still flags `_, _ = io.Copy(...)`, and
// this fake signing program's own stdin has nothing worth checking an error
// against.
func discardCopyResult(int64, error) {}

func init() {
	if os.Getenv(hookFakeSignEnv) != "1" {
		return
	}
	discardCopyResult(io.Copy(io.Discard, os.Stdin))
	_, _ = os.Stdout.WriteString(hookFakeSignature)
	_, _ = os.Stderr.WriteString("[GNUPG:] SIG_CREATED S 0 9 00 0 1 0 enf005\n")
	os.Exit(0)
}

// TestENF005HookCarriesToolCallIDAndSigningConfigForOneGitProcessOnly is
// ENF-005 (U): the hook sees an agent's `git commit` -> the command carries
// the tool call id and the signing configuration for that one git process;
// nothing is written to the repository's config. Driven against a REAL git,
// through the hook's own rewritten command run by `sh -c`: what proves the
// `-c` options actually took effect is x509 signing having actually
// happened, measured off the committed object itself and off .git/config's
// own bytes before and after — not merely that the command text looks right.
func TestENF005HookCarriesToolCallIDAndSigningConfigForOneGitProcessOnly(t *testing.T) {
	git := ghGitOrSkip(t)
	home := t.TempDir()
	repo := filepath.Join(home, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	env := ghIsolatedEnv(home)
	ghRun(t, git, repo, env, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "a.txt"), []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ghRun(t, git, repo, env, "add", "a.txt")

	configPath := filepath.Join(repo, ".git", "config")
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read .git/config before: %v", err)
	}

	const toolUseID = "toolu_enf005fixture001"
	body := hookJSON(t, "Bash", `git commit -m "enf-005"`, toolUseID, nil)
	_, stdout, _ := runHook(t, body)
	out := decodeHookOutput(t, stdout)
	rewritten := updatedCommand(t, out)
	if !strings.Contains(rewritten, " -c gpg.x509.program="+hookExpectSelfBinary(t)+" commit ") {
		t.Fatalf("rewritten command carries no -c gpg.x509.program option before the subcommand: %q", rewritten)
	}

	cmdEnv := append(append([]string{}, env...), hookFakeSignEnv+"=1")
	sh := exec.CommandContext(t.Context(), "sh", "-c", rewritten)
	sh.Dir = repo
	sh.Env = cmdEnv
	if shOut, shErr := sh.CombinedOutput(); shErr != nil {
		t.Fatalf("sh -c %q: %v\n%s", rewritten, shErr, shOut)
	}

	got := ghRun(t, git, repo, env, "cat-file", "commit", "HEAD")
	if !strings.Contains(got, "gpgsig "+hookFakeSignature) {
		t.Errorf("commit carries no gpgsig %q from the configured x509 program; object:\n%s", hookFakeSignature, got)
	}

	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read .git/config after: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf(".git/config changed:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// TestHookInjectsAgentIdentityIntoAGitCommit (RM-315): the export carries the
// four author/committer variables with the agent values the core's I6 policy
// admits.
func TestHookInjectsAgentIdentityIntoAGitCommit(t *testing.T) {
	_, stdout, _ := runHook(t, hookJSON(t, "Bash", `git commit -m x`, "toolu_ident0000001", nil))
	got := updatedCommand(t, decodeHookOutput(t, stdout))
	for _, v := range []string{
		"GIT_AUTHOR_NAME=Innsegl", "GIT_AUTHOR_EMAIL=agent@innsegl.invalid",
		"GIT_COMMITTER_NAME=Innsegl", "GIT_COMMITTER_EMAIL=agent@innsegl.invalid",
	} {
		if !strings.Contains(got, " "+v) {
			t.Errorf("rewritten command lacks %q: %q", v, got)
		}
	}
}

// TestHookDoesNotOverrideAnExplicitAuthorIdentity (RM-315): a command that
// already sets any of the four variables keeps its own choice; the hook adds
// none of the four.
func TestHookDoesNotOverrideAnExplicitAuthorIdentity(t *testing.T) {
	for _, name := range []string{"GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL"} {
		command := name + `=Bob git commit -m x`
		_, stdout, _ := runHook(t, hookJSON(t, "Bash", command, "toolu_ident0000002", nil))
		got := updatedCommand(t, decodeHookOutput(t, stdout))
		prefix, _, _ := strings.Cut(got, "; ")
		if strings.Contains(prefix, "GIT_AUTHOR_") || strings.Contains(prefix, "GIT_COMMITTER_") {
			t.Errorf("%s: hook overrode an explicit identity: %q", name, got)
		}
		if !strings.Contains(got, " -c gpg.x509.program=") {
			t.Errorf("%s: signing config should still be injected: %q", name, got)
		}
	}
}

func TestCommandAlreadySetsAuthorIdentity(t *testing.T) {
	cases := []struct {
		cmd  string
		want bool
	}{
		{`git commit -m x`, false},
		{`GIT_AUTHOR_EMAIL=a@b git commit`, true},
		{`export GIT_COMMITTER_NAME=x && git commit`, true},
		{`MY_GIT_AUTHOR_NAME=x git commit`, false},
	}
	for _, c := range cases {
		if got := commandAlreadySetsAuthorIdentity(c.cmd); got != c.want {
			t.Errorf("commandAlreadySetsAuthorIdentity(%q) = %v, want %v", c.cmd, got, c.want)
		}
	}
}

// TestHookCommitIsAuthoredByTheAgent (RM-315, end to end): a real git run
// through the hook's rewritten command, with a user identity configured that
// the core would refuse, produces a commit authored and committed by
// agent@innsegl.invalid.
func TestHookCommitIsAuthoredByTheAgent(t *testing.T) {
	git := ghGitOrSkip(t)
	home := t.TempDir()
	repo := filepath.Join(home, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	env := ghIsolatedEnv(home)
	ghRun(t, git, repo, env, "init", "-q", "-b", "main")
	ghRun(t, git, repo, env, "config", "user.name", "Human")
	ghRun(t, git, repo, env, "config", "user.email", "human@users.noreply.github.com")
	if err := os.WriteFile(filepath.Join(repo, "a.txt"), []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ghRun(t, git, repo, env, "add", "a.txt")

	_, stdout, _ := runHook(t, hookJSON(t, "Bash", `git commit -m "rm-315"`, "toolu_rm315fixture001", nil))
	rewritten := updatedCommand(t, decodeHookOutput(t, stdout))
	sh := exec.CommandContext(t.Context(), "sh", "-c", rewritten)
	sh.Dir = repo
	sh.Env = append(append([]string{}, env...), hookFakeSignEnv+"=1")
	if out, err := sh.CombinedOutput(); err != nil {
		t.Fatalf("sh -c %q: %v\n%s", rewritten, err, out)
	}
	got := ghRun(t, git, repo, env, "cat-file", "commit", "HEAD")
	for _, role := range []string{"author Innsegl <agent@innsegl.invalid>", "committer Innsegl <agent@innsegl.invalid>"} {
		if !strings.Contains(got, role) {
			t.Errorf("commit lacks %q; object:\n%s", role, got)
		}
	}
}

// TestHookGivesEveryCommitCreatingGitCommandTheAgentIdentity (#536): a
// `git merge` is authored as whoever git is configured as, and the core
// refuses to sign a commit that is not the agent's (I6). Every subcommand that
// writes a commit object gets the same four variables a `git commit` does.
func TestHookGivesEveryCommitCreatingGitCommandTheAgentIdentity(t *testing.T) {
	for _, command := range []string{
		`git merge feature`,
		`git -C /some/dir merge --no-ff feature`,
		`git pull origin main`,
		`git revert HEAD`,
		`git cherry-pick abc123`,
		`git rebase main`,
		`git commit -m x`,
	} {
		_, stdout, _ := runHook(t, hookJSON(t, "Bash", command, "toolu_ident0000003", nil))
		got := updatedCommand(t, decodeHookOutput(t, stdout))
		for _, v := range []string{"GIT_AUTHOR_NAME=Innsegl", "GIT_AUTHOR_EMAIL=agent@innsegl.invalid",
			"GIT_COMMITTER_NAME=Innsegl", "GIT_COMMITTER_EMAIL=agent@innsegl.invalid"} {
			if !strings.Contains(got, " "+v) {
				t.Errorf("%q: rewritten command lacks %q: %q", command, v, got)
			}
		}
	}
}

// TestHookedGitMergeIsAuthoredAsTheAgent runs a real `git merge` under the
// identity the hook injects, in a repository whose own git identity is the
// operator's, and reads the merge commit back (#536).
func TestHookedGitMergeIsAuthoredAsTheAgent(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("git is not on PATH: %v", err)
	}
	dir := t.TempDir()
	env := append(os.Environ(),
		"HOME="+dir, "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_AUTHOR_NAME=Operator", "GIT_AUTHOR_EMAIL=operator@example.invalid",
		"GIT_COMMITTER_NAME=Operator", "GIT_COMMITTER_EMAIL=operator@example.invalid")
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), "git", args...)
		cmd.Dir = dir
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q", "-b", "main")
	git("commit", "-q", "--allow-empty", "-m", "base")
	git("checkout", "-q", "-b", "feature")
	git("commit", "-q", "--allow-empty", "-m", "on feature")
	git("checkout", "-q", "main")
	git("commit", "-q", "--allow-empty", "-m", "on main")

	_, stdout, _ := runHook(t, hookJSON(t, "Bash", "git merge --no-ff -m merged feature", "toolu_ident0000004", nil))
	rewritten := updatedCommand(t, decodeHookOutput(t, stdout))
	// Only the identity part of the export: the signing configuration would
	// call this test binary as the signing program.
	var identity []string
	for _, f := range strings.Fields(strings.TrimSuffix(strings.SplitN(rewritten, "; ", 2)[0], ";")) {
		if strings.HasPrefix(f, "GIT_AUTHOR_") || strings.HasPrefix(f, "GIT_COMMITTER_") {
			identity = append(identity, f)
		}
	}
	if len(identity) != 4 {
		t.Fatalf("want four identity assignments in %q, got %v", rewritten, identity)
	}
	cmd := exec.CommandContext(t.Context(), "sh", "-c", "export "+strings.Join(identity, " ")+"; git merge --no-ff -m merged feature")
	cmd.Dir = dir
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("hooked git merge: %v\n%s", err, out)
	}
	if got := git("log", "-1", "--format=%an <%ae> / %cn <%ce>"); got != "Innsegl <agent@innsegl.invalid> / Innsegl <agent@innsegl.invalid>" {
		t.Errorf("merge commit authored as %q, want the agent identity", got)
	}
}
