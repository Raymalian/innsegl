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
	"sort"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/commitpath"
)

// Test catalog IDs this file drives:
//
//	CMT-004 | I | prepare-commit-msg with no tool call id -> the hook exits
//	          non-zero and git creates no commit.
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
	code := runGitHookPrepareCommitMsg(t.Context(), nil, ghGetenv(nil), &stderr, client)
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

// TestRunGitHookPrepareCommitMsgRefusesAnEmptyToolUseID is CMT-004's
// unit-level half: EnvToolUseID unset (or empty) refuses before the core is
// ever asked, and leaves the message file exactly as it found it.
func TestRunGitHookPrepareCommitMsgRefusesAnEmptyToolUseID(t *testing.T) {
	const original = "subject\n\nbody.\n"
	path := ghMsgFile(t, original, 0o644)
	client := &ghFakeClient{}
	var stderr bytes.Buffer

	code := runGitHookPrepareCommitMsg(t.Context(), []string{path}, ghGetenv(nil), &stderr, client)
	if code == 0 {
		t.Fatal("exit code 0 with no tool call id")
	}
	if client.calls != 0 {
		t.Errorf("the core was called %d times with no tool call id", client.calls)
	}
	if !strings.Contains(stderr.String(), commitpath.EnvToolUseID) {
		t.Errorf("refusal %q does not name %s", stderr.String(), commitpath.EnvToolUseID)
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
	code := runGitHookPrepareCommitMsg(t.Context(), []string{filepath.Join(t.TempDir(), "nope")}, env, &stderr, client)
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
	code := runGitHookPrepareCommitMsg(t.Context(), []string{dir}, env, &stderr, client)
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

	code := runGitHookPrepareCommitMsg(t.Context(), []string{path}, env, &stderr, client)
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

	code := runGitHookPrepareCommitMsg(t.Context(), []string{path, "message"}, env, &stderr, client)
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

	code := runGitHookPrepareCommitMsg(t.Context(), []string{path, "commit", "abcdef1234"}, env, &stderr, client)
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

// shQuote wraps s in POSIX sh single quotes, safe for the one use this file
// has for it: embedding an absolute path in a generated hook script.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
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

// ghObjects lists every object git knows about in repo, sorted, so a test
// can prove NOTHING new was created rather than merely that HEAD did not
// move — a signed object that never became reachable would still show up
// here.
func ghObjects(t *testing.T, git, repo string, env []string) []string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), git, "cat-file", "--batch-all-objects", "--batch-check")
	cmd.Dir = repo
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git cat-file --batch-all-objects --batch-check: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	sort.Strings(lines)
	return lines
}

// ghCommitObjects returns the set of object hashes `git cat-file
// --batch-all-objects --batch-check` reported as type "commit" — the one
// object kind that only exists once a commit was actually created. git's own
// preparation for `commit -m` writes a tree (and, for a first commit, blob)
// object from the index before prepare-commit-msg ever runs, regardless of
// whether the hook goes on to refuse; those are expected and are not what
// CMT-004 is about.
func ghCommitObjects(lines []string) map[string]bool {
	out := map[string]bool{}
	for _, l := range lines {
		fields := strings.Fields(l)
		if len(fields) >= 2 && fields[1] == "commit" {
			out[fields[0]] = true
		}
	}
	return out
}

// TestCMT004NoToolCallIDExitsNonZeroAndCreatesNoCommit is CMT-004(I).
func TestCMT004NoToolCallIDExitsNonZeroAndCreatesNoCommit(t *testing.T) {
	git := ghGitOrSkip(t)
	repo, env := ghRepo(t, git)

	before := ghCommitObjects(ghObjects(t, git, repo, env))

	commitEnv := append(append([]string{}, env...), "GO_WANT_HELPER_PROCESS=1")
	// INNSEGL_TOOL_USE_ID deliberately absent.
	cmd := exec.CommandContext(t.Context(), git, "commit", "-m", "fix: thing")
	cmd.Dir = repo
	cmd.Env = commitEnv
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatal("git commit succeeded with no tool call id")
	}
	if stderr.Len() == 0 {
		t.Error("no refusal reached stderr")
	}

	after := ghCommitObjects(ghObjects(t, git, repo, env))
	for sha := range after {
		if !before[sha] {
			t.Errorf("git created commit object %s despite the hook's refusal", sha)
		}
	}
	headCmd := exec.CommandContext(t.Context(), git, "rev-parse", "--verify", "-q", "HEAD")
	headCmd.Dir = repo
	headCmd.Env = env
	if headErr := headCmd.Run(); headErr == nil {
		t.Error("HEAD resolves to something; git created a commit despite the hook's refusal")
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
	os.Exit(runGitHookPrepareCommitMsg(context.Background(), args[1:], os.Getenv, os.Stderr, client))
}
