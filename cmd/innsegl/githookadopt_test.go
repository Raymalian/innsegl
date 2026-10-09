// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/commitpath"
)

// ADR-0079 decision 2: prepare-commit-msg sends the core the commit about to
// be made — the index's tree and HEAD — so the core can ask whether it is a
// dead run's work. A message from an existing commit or a merge sends
// neither: that commit's parent is not HEAD. A hosted client pushes the
// objects first, as the signing program does.

type ghStagingClient struct {
	ghFakeClient
	staged  []byte
	stageID string
}

func (c *ghStagingClient) Stage(_ context.Context, _, toolUseID string, payload []byte) error {
	c.staged, c.stageID = payload, toolUseID
	return nil
}

func ghCommitRepo(t *testing.T) (dir string, env []string, git string) {
	t.Helper()
	git = ghGitOrSkip(t)
	home := t.TempDir()
	dir = filepath.Join(home, "repo")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	env = ghIsolatedEnv(home)
	ghRun(t, git, dir, env, "init", "-q")
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ghRun(t, git, dir, env, "add", "a.txt")
	return dir, env, git
}

func TestADR0079PrepareCommitMsgSendsTheTreeAndParent(t *testing.T) {
	dir, env, git := ghCommitRepo(t)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(t.TempDir(), "none"))
	tree := strings.TrimSpace(ghRun(t, git, dir, env, "write-tree"))
	getenv := ghGetenv(map[string]string{commitpath.EnvToolUseID: "toolu_abc123"})

	for _, tc := range []struct {
		source   []string
		wantTree bool
	}{
		{nil, true},
		{[]string{"message"}, true},
		{[]string{"template"}, true},
		{[]string{"commit", "HEAD"}, false},
		{[]string{"merge"}, false},
		{[]string{"squash"}, false},
	} {
		client := &ghStagingClient{ghFakeClient: ghFakeClient{resp: commitpath.TrailersResponse{Message: "m\n"}}}
		var stderr bytes.Buffer
		args := append([]string{ghMsgFile(t, "m\n", 0o644)}, tc.source...)
		if code := runGitHookPrepareCommitMsg(t.Context(), dir, args, getenv, &stderr, client); code != 0 {
			t.Fatalf("source %v: exit %d, %s", tc.source, code, stderr.String())
		}
		got := client.lastReq
		if !tc.wantTree {
			if got.Tree != "" || got.Parents != nil || client.staged != nil {
				t.Errorf("source %v sent tree %q parents %v staged %q; want nothing", tc.source, got.Tree, got.Parents, client.staged)
			}
			continue
		}
		if got.Tree != tree || len(got.Parents) != 0 {
			t.Errorf("source %v sent tree %q parents %v; want %s and no parent (a root commit)", tc.source, got.Tree, got.Parents, tree)
		}
		if string(client.staged) != "tree "+tree+"\n" || client.stageID != "toolu_abc123" {
			t.Errorf("staged %q under %q; want the tree, before asking", client.staged, client.stageID)
		}
	}

	// With a commit behind it, HEAD is the parent.
	ghRun(t, git, dir, env, "commit", "-q", "-m", "base")
	head := strings.TrimSpace(ghRun(t, git, dir, env, "rev-parse", "HEAD"))
	client := &ghFakeClient{resp: commitpath.TrailersResponse{Message: "m\n"}}
	var stderr bytes.Buffer
	if code := runGitHookPrepareCommitMsg(t.Context(), dir, []string{ghMsgFile(t, "m\n", 0o644)}, getenv, &stderr, client); code != 0 {
		t.Fatalf("exit %d, %s", code, stderr.String())
	}
	if len(client.lastReq.Parents) != 1 || client.lastReq.Parents[0] != head {
		t.Errorf("parents = %v, want HEAD %s", client.lastReq.Parents, head)
	}
}

// Outside a repository there is no tree to send, and the hook still asks for
// the trailers: adoption is never a reason a commit fails.
func TestADR0079PrepareCommitMsgOutsideARepositorySendsNoTree(t *testing.T) {
	client := &ghFakeClient{resp: commitpath.TrailersResponse{Message: "m\n"}}
	var stderr bytes.Buffer
	getenv := ghGetenv(map[string]string{commitpath.EnvToolUseID: "toolu_abc123"})
	if code := runGitHookPrepareCommitMsg(t.Context(), t.TempDir(), []string{ghMsgFile(t, "m\n", 0o644)}, getenv, &stderr, client); code != 0 {
		t.Fatalf("exit %d, %s", code, stderr.String())
	}
	if client.calls != 1 || client.lastReq.Tree != "" {
		t.Errorf("calls %d tree %q; want the trailers asked for with no tree", client.calls, client.lastReq.Tree)
	}
}

// End to end through real git: the tree the core is told about is the tree
// git then commits.
func TestADR0079ARealCommitTellsTheCoreItsOwnTree(t *testing.T) {
	git := ghGitOrSkip(t)
	repo, env := ghRepo(t, git)

	now := time.Now()
	resolver := newCTResolver()
	resolver.relay(ctRunID, now)
	var gotTree string
	adoptFor := func(_ context.Context, _ commitpath.RelayedCall, tree string, _ []string) (string, error) {
		gotTree = tree
		return "", nil
	}
	srv := httptest.NewServer(commitTrailersHandlerAdopting(resolver, ctClaimFor(ctClaim, nil), adoptFor, ctNow(now)))
	defer srv.Close()

	cmd := exec.CommandContext(t.Context(), git, "commit", "-m", "fix: thing")
	cmd.Dir = repo
	cmd.Env = append(append([]string{}, env...), "GO_WANT_HELPER_PROCESS=1",
		commitpath.EnvToolUseID+"="+ctToolUseID, commitpath.EnvCoreURL+"="+srv.URL)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v\n%s", err, out)
	}
	if want := strings.TrimSpace(ghRun(t, git, repo, env, "log", "-1", "--format=%T")); gotTree != want {
		t.Errorf("the core was told tree %q, and git committed %q", gotTree, want)
	}
}
