// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/commitpath"
)

// The agent's signing is for the agent's repository. The hook exports it for
// the whole Bash command, so a test or tool in that command that makes its
// own commits in a scratch repository inherits it. Measured 2026-10-03: a
// command that ran `go test ./cmd/innsegl` and then committed had the tests'
// scratch commits signed by the core under the agent's run -- a transparency
// log entry with no commit behind it (unattributed_signature_detected) -- and
// the tests failed. The hook now names the repository (its git common
// directory, so every worktree of it counts), and sign refuses any other one
// before it reaches the core.

func gitInitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cmd := exec.CommandContext(t.Context(), "git", "init", "-q", dir)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	return dir
}

func signRepoGetenv(toolUseID, repo string) func(string) string {
	return func(k string) string {
		switch k {
		case commitpath.EnvToolUseID:
			return toolUseID
		case envSignRepo:
			return repo
		}
		return ""
	}
}

func TestRunSignRefusesACommitOutsideTheAgentsRepository(t *testing.T) {
	agent := gitInitRepo(t)
	scratch := gitInitRepo(t)
	common, err := gitCommonDir(t.Context(), agent)
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(scratch)
	client := &fakeSignClient{}
	var stdout, stderr bytes.Buffer
	code := runSign(t.Context(), []string{"--status-fd=2", "-bsau", "key"}, strings.NewReader("payload"),
		&stdout, &stderr, signRepoGetenv("toolu_01Example000000000000000", common), client)
	if code == 0 || client.calls != 0 {
		t.Fatalf("exit %d, core calls %d: a commit outside the agent's repository was sent to be signed", code, client.calls)
	}
	if !strings.Contains(stderr.String(), "not the repository") {
		t.Errorf("stderr %q does not say why", stderr.String())
	}
}

func TestRunSignSignsInTheAgentsRepository(t *testing.T) {
	agent := gitInitRepo(t)
	common, err := gitCommonDir(t.Context(), agent)
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(agent)
	client := &fakeSignClient{resp: commitpath.SignResponse{Signature: []byte("SIG"), Status: []byte("status")}}
	var stdout, stderr bytes.Buffer
	code := runSign(t.Context(), []string{"--status-fd=2", "-bsau", "key"}, strings.NewReader("payload"),
		&stdout, &stderr, signRepoGetenv("toolu_01Example000000000000000", common), client)
	if code != 0 || client.calls != 1 {
		t.Fatalf("exit %d, core calls %d: %s", code, client.calls, stderr.String())
	}
}

// The hook names the repository of the tool call's own directory.
func TestHookNamesTheAgentsRepositoryForSigning(t *testing.T) {
	agent := gitInitRepo(t)
	common, err := gitCommonDir(t.Context(), agent)
	if err != nil {
		t.Fatal(err)
	}
	in, err := json.Marshal(map[string]any{"tool_name": "Bash", "tool_use_id": "toolu_01Example000000000000000",
		"cwd": agent, "tool_input": map[string]string{"command": "git commit -m x"}})
	if err != nil {
		t.Fatal(err)
	}
	_, stdout, _ := runHook(t, string(in))
	if !strings.Contains(stdout, envSignRepo+"="+common) {
		t.Fatalf("the hook did not name %s; output %s", common, stdout)
	}
	if filepath.IsAbs(common) == false {
		t.Fatalf("the common dir %q is not absolute", common)
	}
}

// gitCommonDir runs git on a directory the harness's hook input names, as
// one argument to -C with no shell. What is not a directory git can enter --
// a missing path, or a value shaped like an option -- answers an error, not a
// repository (the guard gosec's G702 note in signrepo.go relies on).
func TestGitCommonDirRefusesWhatIsNotADirectory(t *testing.T) {
	for _, dir := range []string{"no/such/dir", "-c", "--exec-path=/tmp", filepath.Join(t.TempDir(), "missing")} {
		if got, err := gitCommonDir(t.Context(), dir); err == nil {
			t.Errorf("gitCommonDir(%q) = %q, want an error", dir, got)
		}
	}
}
