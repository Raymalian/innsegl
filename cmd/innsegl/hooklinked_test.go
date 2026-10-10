// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"innsegl.dev/innsegl/internal/commitpath"
)

// CMT-019 / CMT-020 (PROPOSED for doc 07) — the PreToolUse hook acts only in
// a repository linked to innsegl (#575).
//
// MEASURED: an agent committed in a local repository with no remote that had
// never been linked. The hook added the signing options anyway, the signing
// program ran, and the repository's objects were pushed to the core. A
// repository is linked when it carries the prepare-commit-msg hook `innsegl
// link` installs, or is one innsegl links on first use (a working tree with a
// usable origin, hooksession.go). Any other repository's commits are not
// innsegl's to touch: no signing options, no refusal, nothing sent.

// markLinked links repo for the hook's purposes with a prepare-commit-msg
// that carries innsegl's marker and does nothing, so a test that then
// commits there does not run this test binary as its hook.
func markLinked(t *testing.T, repo string) {
	t.Helper()
	hookPath, _, err := linkHookPaths(t.Context(), repo)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(hookPath), 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\n# " + linkHookMarker + " (a test's stand-in)\nexit 0\n"
	if err := os.WriteFile(hookPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

// hookBodyIn is a Bash tool call running command in cwd.
func hookBodyIn(t *testing.T, cwd, command string) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"tool_name":   "Bash",
		"tool_input":  map[string]any{"command": command},
		"tool_use_id": "toolu_cmt019fixture01",
		"cwd":         cwd,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// countingCore is a core that counts every request it is sent.
func countingCore(t *testing.T) (url string, calls *atomic.Int64) {
	t.Helper()
	calls = &atomic.Int64{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "this test's core takes nothing", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, calls
}

func TestCMT019AnUnlinkedRepositoryIsLeftAlone(t *testing.T) {
	repo, env := linkRepo(t)
	git := ghGitOrSkip(t)
	if err := os.WriteFile(filepath.Join(repo, "a.txt"), []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ghRun(t, git, repo, env, "add", "a.txt")
	core, calls := countingCore(t)
	t.Setenv(commitpath.EnvCoreURL, core)

	for _, command := range []string{
		`git commit -m "private work"`,
		`git commit --no-gpg-sign -m "private work"`,
		`git config commit.gpgsign false`,
	} {
		code, stdout, stderr := runHook(t, hookBodyIn(t, repo, command))
		if code != exitOK || stdout != "" || stderr != "" {
			t.Errorf("%q in an unlinked repository: exit %d, stdout %q, stderr %q; want nothing at all",
				command, code, stdout, stderr)
		}
	}

	// The command runs as the model wrote it, and commits unsigned.
	cmd := exec.CommandContext(t.Context(), "sh", "-c", `git commit -q -m "private work"`)
	cmd.Dir = repo
	cmd.Env = append(append([]string{}, env...), commitpath.EnvCoreURL+"="+core)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the untouched commit: %v\n%s", err, out)
	}
	if sig := ghRun(t, git, repo, env, "log", "-1", "--format=%G?"); strings.TrimSpace(sig) != "N" {
		t.Errorf("the commit carries a signature (%q); an unlinked repository's commit is not signed", sig)
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("the core was sent %d requests for an unlinked repository", n)
	}
}

func TestCMT020ALinkedRepositoryAndItsWorktreesAreStillRewritten(t *testing.T) {
	repo, env := linkRepo(t)
	git := ghGitOrSkip(t)
	// Committed before linking: the linked hook runs this test binary.
	ghRun(t, git, repo, env, "commit", "-q", "--allow-empty", "-m", "base")
	if code, _, stderr := runLink(t, repo); code != exitOK {
		t.Fatalf("innsegl link: %s", stderr)
	}
	// The harness's isolated worktree (#554): its own directory, the
	// repository's hooks.
	wt := filepath.Join(filepath.Dir(repo), "wt")
	ghRun(t, git, repo, env, "worktree", "add", "-q", "-b", "agent", wt)

	for _, dir := range []string{repo, wt} {
		code, stdout, _ := runHook(t, hookBodyIn(t, dir, `git commit -m "agent work"`))
		if code != exitOK || stdout == "" {
			t.Fatalf("%s: exit %d, no rewrite; a linked repository's commit must carry the signing options", dir, code)
		}
		got := updatedCommand(t, decodeHookOutput(t, stdout))
		if !strings.Contains(got, "-c commit.gpgsign=true") || !strings.Contains(got, commitpath.EnvToolUseID+"=") {
			t.Errorf("%s: rewritten to %q; want the tool call id and the signing options", dir, got)
		}
		if strings.Contains(got, "GIT_CONFIG_") {
			t.Errorf("%s: %q carries a GIT_CONFIG_ variable the worktree guard refuses (CMT-018)", dir, got)
		}
		_, deny, _ := runHook(t, hookBodyIn(t, dir, `git commit --no-gpg-sign -m x`))
		if !strings.Contains(deny, `"deny"`) {
			t.Errorf("%s: a commit with signing off was not refused in a linked repository: %q", dir, deny)
		}
	}
}

// A repository innsegl links on first use is acted on, and linked, even when
// no session hook linked it first: record every agent.
func TestCMT020ARepositoryWithAnOriginIsLinkedOnFirstUse(t *testing.T) {
	repo, env := linkRepo(t)
	git := ghGitOrSkip(t)
	ghRun(t, git, repo, env, "remote", "add", "origin", "https://github.com/innsegl-test/cmt020.git")
	_, stdout, _ := runHook(t, hookBodyIn(t, repo, `git commit -m "agent work"`))
	if !strings.Contains(stdout, "commit.gpgsign=true") {
		t.Fatalf("a repository with an origin was not acted on: %q", stdout)
	}
	hook, err := os.ReadFile(filepath.Join(repo, ".git", "hooks", "prepare-commit-msg"))
	if err != nil || !strings.Contains(string(hook), linkHookMarker) {
		t.Errorf("the repository was not linked on first use (%v)", err)
	}
}
