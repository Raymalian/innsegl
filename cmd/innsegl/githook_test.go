// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/commitpath"
)

// Test catalog IDs this file drives:
//
//	CMT-004 | I | prepare-commit-msg with no tool call id (a human commit) ->
//	          the message is untouched and git commits exactly as it would
//	          without innsegl; an agent commit without an id is caught by
//	          CMT-016 (operator decision, 2026-09-30, RM-245 #390).
//	CMT-005 | I | with a relayed git commit tool call id -> the message gains
//	          the three trailers of the run that tool call was relayed on,
//	          placed by ADR-0028's render; the rest is unchanged.

// ---------------------------------------------------------------------------
// Unit-level: a fake core, no real git.
// ---------------------------------------------------------------------------

type ghFakeClient struct {
	resp    commitpath.TrailersResponse
	err     error
	calls   int
	lastReq commitpath.TrailersRequest
}

func (c *ghFakeClient) Trailers(_ context.Context, req commitpath.TrailersRequest) (commitpath.TrailersResponse, error) {
	c.calls++
	c.lastReq = req
	if c.err != nil {
		return commitpath.TrailersResponse{}, c.err
	}
	return c.resp, nil
}

func ghGetenv(values map[string]string) func(string) string {
	return func(k string) string { return values[k] }
}

func ghMsgFile(t *testing.T, contents string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "COMMIT_EDITMSG")
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatalf("write message file: %v", err)
	}
	return path
}

func TestRunGitHookPrepareCommitMsgRefusesWithNoMessageFileArgument(t *testing.T) {
	client := &ghFakeClient{}
	var stderr bytes.Buffer
	code := runGitHookPrepareCommitMsg(t.Context(), t.TempDir(), nil, ghGetenv(nil), &stderr, client)
	if code == 0 {
		t.Fatal("exit code 0 with no message file argument")
	}
	if client.calls != 0 {
		t.Errorf("the core was called %d times with no message file to read", client.calls)
	}
	if stderr.Len() == 0 {
		t.Error("no refusal reached stderr")
	}
}

// TestRunGitHookPrepareCommitMsgWithNoToolUseIDLeavesTheMessageUntouched is
// CMT-004's unit-level half (RM-245, operator decision 2026-09-30): with no
// tool call id, this is a human's own commit in a linked repository, not an
// agent's — the hook does nothing at all, on stdout, on stderr, or to the
// message file, and exits 0 so git commits exactly as it would with no
// innsegl hook installed.
func TestRunGitHookPrepareCommitMsgWithNoToolUseIDLeavesTheMessageUntouched(t *testing.T) {
	const original = "subject\n\nbody.\n"
	path := ghMsgFile(t, original, 0o644)
	client := &ghFakeClient{}
	var stderr bytes.Buffer

	code := runGitHookPrepareCommitMsg(t.Context(), t.TempDir(), []string{path}, ghGetenv(nil), &stderr, client)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (a human commit, nothing to attribute)", code)
	}
	if client.calls != 0 {
		t.Errorf("the core was called %d times with no tool call id", client.calls)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty: a human commit is not a refusal", stderr.String())
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back message file: %v", err)
	}
	if string(got) != original {
		t.Errorf("the message file changed: %q", got)
	}
}

func TestRunGitHookPrepareCommitMsgRefusesWhenTheFileDoesNotExist(t *testing.T) {
	client := &ghFakeClient{}
	var stderr bytes.Buffer
	env := ghGetenv(map[string]string{commitpath.EnvToolUseID: "toolu_abc123"})
	code := runGitHookPrepareCommitMsg(t.Context(), t.TempDir(), []string{filepath.Join(t.TempDir(), "nope")}, env, &stderr, client)
	if code == 0 {
		t.Fatal("exit code 0 for a message file that does not exist")
	}
	if client.calls != 0 {
		t.Errorf("the core was called %d times for a message file that does not exist", client.calls)
	}
}

func TestRunGitHookPrepareCommitMsgRefusesWhenTheFileCannotBeRead(t *testing.T) {
	// A directory in the message file's place: os.Stat succeeds (it names
	// something), and reading it as a file fails.
	dir := t.TempDir()
	client := &ghFakeClient{}
	var stderr bytes.Buffer
	env := ghGetenv(map[string]string{commitpath.EnvToolUseID: "toolu_abc123"})
	code := runGitHookPrepareCommitMsg(t.Context(), t.TempDir(), []string{dir}, env, &stderr, client)
	if code == 0 {
		t.Fatal("exit code 0 for a message file that cannot be read")
	}
	if client.calls != 0 {
		t.Errorf("the core was called %d times for a message file that cannot be read", client.calls)
	}
}

func TestRunGitHookPrepareCommitMsgRefusesWhenTheCoreRefuses(t *testing.T) {
	const original = "subject\n\nbody.\n"
	path := ghMsgFile(t, original, 0o644)
	client := &ghFakeClient{err: fmt.Errorf("innsegl: the core refused (403): run is retired")}
	var stderr bytes.Buffer
	env := ghGetenv(map[string]string{commitpath.EnvToolUseID: "toolu_abc123"})

	code := runGitHookPrepareCommitMsg(t.Context(), t.TempDir(), []string{path}, env, &stderr, client)
	if code == 0 {
		t.Fatal("exit code 0 when the core refused")
	}
	if stderr.Len() == 0 {
		t.Error("no refusal reached stderr")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back message file: %v", err)
	}
	if string(got) != original {
		t.Errorf("the message file changed even though the core refused: %q", got)
	}
}

func TestRunGitHookPrepareCommitMsgWritesTheAnsweredMessageBackAndPreservesMode(t *testing.T) {
	const original = "subject\n\nbody.\n"
	const mode = os.FileMode(0o640)
	path := ghMsgFile(t, original, mode)
	const answered = "subject\n\nbody.\n\nAgent-Identity: spiffe://innsegl.dev/agent/a/b/c\n" +
		"Agent-Run: c\nAgent-Task: b\n"
	client := &ghFakeClient{resp: commitpath.TrailersResponse{Message: answered}}
	var stderr bytes.Buffer
	env := ghGetenv(map[string]string{commitpath.EnvToolUseID: "toolu_abc123"})

	code := runGitHookPrepareCommitMsg(t.Context(), t.TempDir(), []string{path, "message"}, env, &stderr, client)
	if code != 0 {
		t.Fatalf("exit code %d, stderr %q", code, stderr.String())
	}
	if client.calls != 1 {
		t.Fatalf("the core was called %d times, want 1", client.calls)
	}
	if client.lastReq.ToolUseID != "toolu_abc123" || client.lastReq.Message != original {
		t.Errorf("the core was asked %+v", client.lastReq)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back message file: %v", err)
	}
	if string(got) != answered {
		t.Errorf("message file = %q, want %q", got, answered)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat message file: %v", err)
	}
	if info.Mode().Perm() != mode {
		t.Errorf("mode = %v, want %v", info.Mode().Perm(), mode)
	}
}

// TestRunGitHookPrepareCommitMsgIgnoresSourceAndSha pins that a --amend's
// extra arguments (source, sha) change nothing about which message is asked
// about: the same trailers apply whatever produced the file's current
// content.
func TestRunGitHookPrepareCommitMsgIgnoresSourceAndSha(t *testing.T) {
	path := ghMsgFile(t, "subject\n\nbody.\n", 0o644)
	client := &ghFakeClient{resp: commitpath.TrailersResponse{Message: "subject\n\nbody.\n\nAgent-Run: r\n"}}
	var stderr bytes.Buffer
	env := ghGetenv(map[string]string{commitpath.EnvToolUseID: "toolu_abc123"})

	code := runGitHookPrepareCommitMsg(t.Context(), t.TempDir(), []string{path, "commit", "abcdef1234"}, env, &stderr, client)
	if code != 0 {
		t.Fatalf("exit code %d, stderr %q", code, stderr.String())
	}
	if client.calls != 1 {
		t.Fatalf("the core was called %d times, want 1", client.calls)
	}
}

// ---------------------------------------------------------------------------
// Real git: CMT-004 and CMT-005.
//
// A temp repo, core.hooksPath pointing at a directory holding a POSIX sh
// prepare-commit-msg script that re-execs THIS test binary in helper-process
// mode (os.Args[0] + GO_WANT_HELPER_PROCESS, the standard os/exec_test.go
// pattern) against a real httptest server running commitTrailersHandler.
// ---------------------------------------------------------------------------

func ghGitOrSkip(t *testing.T) string {
	t.Helper()
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skipf("skipping: no git on PATH (%v)", err)
	}
	return git
}

// ghEnv isolates HOME and every configuration source git will read, the same
// neutering internal/signing's own gitOrSkip-driven tests use (ADR-0028's
// SIG-006 differential): no system, no global, no config above this tree.
func ghIsolatedEnv(home string) []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + filepath.Join(home, "nonexistent-gitconfig"),
		"GIT_CEILING_DIRECTORIES=" + home,
		"HOME=" + home,
		"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@innsegl.invalid",
		"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@innsegl.invalid",
	}
}

func ghRun(t *testing.T, git, dir string, env []string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), git, args...)
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", git, strings.Join(args, " "), err, out)
	}
	return string(out)
}

// ghRepo builds an isolated repository with the trailers hook already
// installed via core.hooksPath, and returns the repo path and the env every
// git invocation against it should run under.
func ghRepo(t *testing.T, git string) (repo string, env []string) {
	t.Helper()
	home := t.TempDir()
	repo = filepath.Join(home, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	env = ghIsolatedEnv(home)
	ghRun(t, git, repo, env, "init", "-q")

	hooksDir := filepath.Join(home, "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	bin, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	script := "#!/bin/sh\n" +
		"exec " + shQuote(bin) + " -test.run=TestHelperProcess -test.v=false -- prepare-commit-msg \"$@\"\n"
	hookPath := filepath.Join(hooksDir, "prepare-commit-msg")
	if err := os.WriteFile(hookPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	ghRun(t, git, repo, env, "config", "core.hooksPath", hooksDir)

	if err := os.WriteFile(filepath.Join(repo, "a.txt"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ghRun(t, git, repo, env, "add", "a.txt")
	return repo, env
}

// TestCMT004NoToolCallIDLeavesMessageUntouchedAndGitCreatesTheCommit is
// CMT-004(I), the new rule (RM-245, operator decision 2026-09-30): a human's
// own `git commit` in a linked repository is left completely alone — no
// trailers, no innsegl signing, git's own configuration decides. With no
// INNSEGL_TOOL_USE_ID, the installed prepare-commit-msg hook still runs (it
// is what proves the repository is linked) but does nothing, and git commits
// the message exactly as given.
func TestCMT004NoToolCallIDLeavesMessageUntouchedAndGitCreatesTheCommit(t *testing.T) {
	git := ghGitOrSkip(t)
	repo, env := ghRepo(t, git)

	commitEnv := append(append([]string{}, env...), "GO_WANT_HELPER_PROCESS=1")
	// INNSEGL_TOOL_USE_ID deliberately absent.
	cmd := exec.CommandContext(t.Context(), git, "commit", "-m", "fix: thing")
	cmd.Dir = repo
	cmd.Env = commitEnv
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git commit: %v\n%s", err, out)
	}

	msg := ghRun(t, git, repo, env, "log", "-1", "--format=%B")
	if strings.TrimRight(msg, "\n") != "fix: thing" {
		t.Errorf("commit message = %q, want the original message untouched", msg)
	}
	for _, trailer := range []string{"Agent-Identity:", "Agent-Run:", "Agent-Task:"} {
		if strings.Contains(msg, trailer) {
			t.Errorf("commit message carries %q; a human commit must gain no trailer:\n%s", trailer, msg)
		}
	}
}

// TestCMT005ARelayedGitCommitToolCallGainsTheThreeTrailers is CMT-005(I).
func TestCMT005ARelayedGitCommitToolCallGainsTheThreeTrailers(t *testing.T) {
	git := ghGitOrSkip(t)
	repo, env := ghRepo(t, git)

	now := time.Now()
	resolver := newCTResolver()
	resolver.relay(ctRunID, now)
	handler := commitTrailersHandler(resolver, ctClaimFor(ctClaim, nil), ctNow(now))
	srv := httptest.NewServer(handler)
	defer srv.Close()

	commitEnv := append(append([]string{}, env...),
		"GO_WANT_HELPER_PROCESS=1",
		commitpath.EnvToolUseID+"="+ctToolUseID,
		commitpath.EnvCoreURL+"="+srv.URL,
	)
	cmd := exec.CommandContext(t.Context(), git, "commit", "-m", "fix: thing")
	cmd.Dir = repo
	cmd.Env = commitEnv
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git commit: %v\n%s", err, out)
	}

	msg := ghRun(t, git, repo, env, "log", "-1", "--format=%B")
	for _, line := range []string{
		"Agent-Identity: " + ctClaim.Identity,
		"Agent-Run: " + ctClaim.Run,
		"Agent-Task: " + ctClaim.Task,
	} {
		if !strings.Contains(msg, line) {
			t.Errorf("commit message does not carry %q:\n%s", line, msg)
		}
	}
	if !strings.Contains(msg, "fix: thing") {
		t.Errorf("commit message lost its original subject:\n%s", msg)
	}
}

// TestHelperProcess is not a test. Following os/exec_test.go's own pattern,
// it is a no-op unless GO_WANT_HELPER_PROCESS=1, in which case it IS the
// prepare-commit-msg hook: it re-execs as this binary (ghRepo's generated
// script), reads git's own argv after the "prepare-commit-msg" marker that
// script inserts, and calls the real runGitHookPrepareCommitMsg against a
// real commitpath.Client pointed at INNSEGL_CORE_URL — the same client
// production code builds (commitpath.ClientFromEnv), so this drives the real
// hook end to end rather than a substitute for it.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	args := os.Args
	for len(args) > 0 && args[0] != "--" {
		args = args[1:]
	}
	if len(args) > 0 {
		args = args[1:]
	}
	if len(args) < 1 || args[0] != "prepare-commit-msg" {
		fmt.Fprintln(os.Stderr, "innsegl test helper process: unrecognised mode")
		os.Exit(2)
	}
	client := commitpath.ClientFromEnv(os.Getenv)
	os.Exit(runGitHookPrepareCommitMsg(context.Background(), ".", args[1:], os.Getenv, os.Stderr, client))
}
