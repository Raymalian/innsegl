// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/commitpath"
)

// The client hooks of #465 and #467 in process: every case they send
// nothing for, and the detached push itself.

// SNAP-006: the post-commit hook sends nothing without a tool call id, a
// client service, a signature, or a repository.
func TestSNAP006PostCommitSendsNothingWithoutAToolCallASignatureOrAClientService(t *testing.T) {
	core := newSlowCore(t, 0)
	dir, env := pushTestRepo(t)
	if out, err := signGit(t, dir, env, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "unsigned"); err != nil {
		t.Fatalf("git commit: %v: %s", err, out)
	}
	agent := map[string]string{commitpath.EnvToolUseID: pushToolUseID, commitpath.EnvCoreURL: core.srv.URL}
	for _, tc := range []struct {
		name   string
		dir    string
		getenv func(string) string
	}{
		{"no tool call id", dir, env2(map[string]string{commitpath.EnvCoreURL: core.srv.URL})},
		{"a single-host core", dir, env2(map[string]string{commitpath.EnvToolUseID: pushToolUseID, commitpath.EnvCoreURL: "https://127.0.0.1:1"})},
		{"an unsigned commit", dir, env2(agent)},
		{"not in a repository", t.TempDir(), env2(agent)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var errOut bytes.Buffer
			if code := runGitHookPostCommit(t.Context(), tc.dir, tc.getenv, &errOut); code != exitOK {
				t.Fatalf("exit %d: %s", code, errOut.String())
			}
		})
	}
	time.Sleep(time.Second)
	if n := core.gits.Load(); n != 0 {
		t.Fatalf("%d git requests reached the core", n)
	}
}

// SNAP-006: the detached push sends the branch, and says when it cannot.
func TestSNAP006PushMirrorPushesABranchAndReportsItsFailure(t *testing.T) {
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")
	core := newSlowCore(t, 0)
	dir, env := pushTestRepo(t)
	if out, err := signGit(t, dir, env, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "work"); err != nil {
		t.Fatalf("git commit: %v: %s", err, out)
	}
	out, err := signGit(t, dir, env, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	head := strings.TrimSpace(out)
	var errOut bytes.Buffer
	if code := runGitHookPushMirror([]string{dir, "branch", core.srv.URL, "main", head}, &errOut); code != exitOK {
		t.Fatalf("push-mirror exit %d: %s", code, errOut.String())
	}
	if got := core.ref(t, "refs/heads/main"); got != head {
		t.Fatalf("mirror's main = %q, want %s", got, head)
	}
	if code := runGitHookPushMirror([]string{dir, "branch", core.srv.URL, "main", "nope"}, &errOut); code != 1 {
		t.Fatalf("a malformed commit: exit %d, want 1", code)
	}
	if code := runGitHookPushMirror([]string{dir, "snapshot", core.srv.URL, "nope", head, head, dir}, &errOut); code != 1 {
		t.Fatalf("a malformed snapshot: exit %d, want 1", code)
	}
	if code := runGitHookPushMirror([]string{dir, "other"}, &errOut); code != exitUsage {
		t.Fatalf("an unknown push: exit %d, want %d", code, exitUsage)
	}
}

// SNAP-007: the post-tool-use hook ignores input it cannot use, and a
// single-host core.
func TestSNAP007PostToolUseIgnoresWhatItCannotUse(t *testing.T) {
	core := newSlowCore(t, 0)
	getenv := env2(map[string]string{commitpath.EnvCoreURL: core.srv.URL})
	for _, in := range []string{"not json", `{"tool_use_id":"nope","cwd":"/x"}`, postToolUseInput("", pushToolUseID)} {
		if code := runHookPostToolUse(strings.NewReader(in), &bytes.Buffer{}, getenv); code != exitOK {
			t.Fatalf("%q: exit %d", in, code)
		}
	}
	single := env2(map[string]string{commitpath.EnvCoreURL: "https://127.0.0.1:1"})
	if code := runHookPostToolUse(strings.NewReader(postToolUseInput(t.TempDir(), pushToolUseID)), &bytes.Buffer{}, single); code != exitOK {
		t.Fatalf("single-host: exit %d", code)
	}
	if n := core.gits.Load(); n != 0 {
		t.Fatalf("%d git requests reached the core", n)
	}
}
