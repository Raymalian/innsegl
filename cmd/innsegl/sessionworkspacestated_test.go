// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// RM-282 (#458): the handler accepts and validates the client's derivation.

const statedBody = `{"session_id":"` + testSessionID + `","cwd":"/client/repo",` +
	`"repo":"github.com/example-org/example-repo","worktree":"wt","branch":"dev/rm282-x","task":"rm282",` +
	`"head":"0123456789abcdef0123456789abcdef01234567"}`

func TestSessionWorkspaceHandlerRecordsAStatedWorkspace(t *testing.T) {
	h, ws := sessionWorkspaceTestHandler(t)
	rec := httptest.NewRecorder()
	h(rec, sessionWorkspaceRequest(t, http.MethodPost, "127.0.0.1:40000", statedBody))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204. body: %s", rec.Code, rec.Body.String())
	}
	got, ok := ws.LookupStated(testSessionID, "main")
	if !ok || got.Repo != "github.com/example-org/example-repo" || got.Branch != "dev/rm282-x" ||
		got.Task != "rm282" || got.Worktree != "wt" || got.Head != "0123456789abcdef0123456789abcdef01234567" ||
		got.Cwd != "/client/repo" {
		t.Fatalf("LookupStated = %+v, %v", got, ok)
	}
}

func TestSessionWorkspaceHandlerAcceptsASha256Head(t *testing.T) {
	h, _ := sessionWorkspaceTestHandler(t)
	rec := httptest.NewRecorder()
	body := strings.Replace(statedBody, "0123456789abcdef0123456789abcdef01234567", strings.Repeat("ab", 32), 1)
	h(rec, sessionWorkspaceRequest(t, http.MethodPost, "127.0.0.1:40000", body))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204. body: %s", rec.Code, rec.Body.String())
	}
}

func TestSessionWorkspaceHandlerRefusesAMalformedStatedWorkspace(t *testing.T) {
	const pre = `{"session_id":"` + testSessionID + `","cwd":"/client/repo",`
	for name, body := range map[string]string{
		"repo with two segments":  pre + `"repo":"example-org/example-repo","branch":"b","task":"t"}`,
		"repo with a scheme":      pre + `"repo":"https://github.com/o/r","branch":"b","task":"t"}`,
		"repo with a space":       pre + `"repo":"github.com/o/r r","branch":"b","task":"t"}`,
		"repo without a branch":   pre + `"repo":"github.com/o/r","task":"t"}`,
		"repo without a task":     pre + `"repo":"github.com/o/r","branch":"b"}`,
		"overlong branch":         pre + `"repo":"github.com/o/r","branch":"` + strings.Repeat("b", 256) + `","task":"t"}`,
		"overlong task":           pre + `"repo":"github.com/o/r","branch":"b","task":"` + strings.Repeat("t", 64) + `"}`,
		"task outside grammar":    pre + `"repo":"github.com/o/r","branch":"b","task":"Not A Task"}`,
		"short head":              pre + `"repo":"github.com/o/r","branch":"b","task":"t","head":"abc123"}`,
		"uppercase head":          pre + `"repo":"github.com/o/r","branch":"b","task":"t","head":"` + strings.Repeat("A", 40) + `"}`,
		"non-hex head":            pre + `"repo":"github.com/o/r","branch":"b","task":"t","head":"` + strings.Repeat("g", 40) + `"}`,
		"absolute worktree":       pre + `"repo":"github.com/o/r","branch":"b","task":"t","worktree":"/abs"}`,
		"escaping worktree":       pre + `"repo":"github.com/o/r","branch":"b","task":"t","worktree":"../x"}`,
		"branch without a repo":   pre + `"branch":"b"}`,
		"head without a repo":     pre + `"head":"` + strings.Repeat("a", 40) + `"}`,
		"worktree without a repo": pre + `"worktree":"wt"}`,
	} {
		t.Run(name, func(t *testing.T) {
			h, ws := sessionWorkspaceTestHandler(t)
			rec := httptest.NewRecorder()
			h(rec, sessionWorkspaceRequest(t, http.MethodPost, "127.0.0.1:40000", body))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", rec.Code)
			}
			if _, ok := ws.Lookup(testSessionID, "main"); ok {
				t.Error("a refused statement was recorded")
			}
		})
	}
}

// ---- the hook derives and states it ----

func statedRunGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	full := append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.com",
		"-c", "commit.gpgsign=false"}, args...)
	if out, err := exec.CommandContext(t.Context(), "git", full...).CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func hookInputFor(cwd string) string {
	return `{"session_id":"7dc5d783-9896-4aef-84d9-a82114505fff","cwd":"` + cwd + `","hook_event_name":"UserPromptSubmit"}`
}

func TestHookSessionStatesTheDerivedWorkspaceForAGitDirectory(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	statedRunGit(t, dir, "init", "-q", "-b", "dev/rm282-hook")
	statedRunGit(t, dir, "remote", "add", "origin", "git@github.com:Example-Org/Example-Repo.git")
	statedRunGit(t, dir, "commit", "-q", "--allow-empty", "-m", "first")
	posts, post := capturePosts(nil)

	code := runHookSession(strings.NewReader(hookInputFor(dir)), &bytes.Buffer{}, &bytes.Buffer{}, env(nil), post)

	if code != exitOK || len(*posts) != 1 {
		t.Fatalf("exit = %d, posts = %d", code, len(*posts))
	}
	b := (*posts)[0].body
	if b["cwd"] != dir || b["repo"] != "github.com/Example-Org/Example-Repo" || b["branch"] != "dev/rm282-hook" ||
		b["task"] != "rm282" || b["worktree"] != "" || len(b["head"]) != 40 {
		t.Errorf("body = %v", b)
	}
}

func TestHookSessionStatesOnlyTheDirectoryOutsideAGitWorkingTree(t *testing.T) {
	posts, post := capturePosts(nil)
	dir := t.TempDir()

	code := runHookSession(strings.NewReader(hookInputFor(dir)), &bytes.Buffer{}, &bytes.Buffer{}, env(nil), post)

	if code != exitOK || len(*posts) != 1 {
		t.Fatalf("exit = %d, posts = %d; the hook must never fail on a plain directory", code, len(*posts))
	}
	b := (*posts)[0].body
	if b["cwd"] != dir {
		t.Errorf("cwd = %q", b["cwd"])
	}
	for _, k := range []string{"repo", "worktree", "branch", "task", "head"} {
		if v, present := b[k]; present && v != "" {
			t.Errorf("%s = %q, want none for a directory that is not a working tree", k, v)
		}
	}
}

func TestHookSessionStatesOnlyTheDirectoryWhenTheTreeHasNoOrigin(t *testing.T) {
	dir := t.TempDir()
	statedRunGit(t, dir, "init", "-q")
	posts, post := capturePosts(nil)

	runHookSession(strings.NewReader(hookInputFor(dir)), &bytes.Buffer{}, &bytes.Buffer{}, env(nil), post)

	if len(*posts) != 1 || (*posts)[0].body["repo"] != "" {
		t.Fatalf("posts = %+v, want one with no repo", *posts)
	}
}
