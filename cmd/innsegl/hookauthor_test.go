// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/client"
)

// ENF-010 (PROPOSED for doc 07) — in a repository the operator set to
// operator mode, an agent commit is authored as the operator; everywhere
// else it stays the unlinked agent address.
//
// MEASURED: a private repository whose deploy host builds only commits
// authored by a member of its team refused two agent commits authored as
// `Innsegl <agent@innsegl.invalid>`. I6 allows the operator as the author; the
// agent stays in the trailers and the signature, which this hook does not
// touch.

const enf010Operator = "Op Erator <1+op@users.noreply.github.com>"

// enf010Repo makes a git repository under home with one staged file, and
// returns its path and the isolated environment the commit runs in.
func enf010Repo(t *testing.T, home string) (repo string, env []string) {
	t.Helper()
	git := ghGitOrSkip(t)
	repo = filepath.Join(home, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	env = ghIsolatedEnv(home)
	ghRun(t, git, repo, env, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "a.txt"), []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ghRun(t, git, repo, env, "add", "a.txt")
	return repo, env
}

// enf010Hook runs the hook for `git commit` in cwd and returns the rewritten
// command.
func enf010Hook(t *testing.T, cwd string) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"tool_name":   "Bash",
		"tool_input":  map[string]any{"command": `git commit -m "enf-010"`},
		"tool_use_id": "toolu_enf010fixture01",
		"cwd":         cwd,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, stdout, _ := runHook(t, string(body))
	return updatedCommand(t, decodeHookOutput(t, stdout))
}

func enf010SetOperatorMode(t *testing.T, home, repo string) {
	t.Helper()
	commonDir, err := gitCommonDir(t.Context(), repo)
	if err != nil {
		t.Fatalf("gitCommonDir: %v", err)
	}
	a, err := client.Authors{}.SetOperator(enf010Operator)
	if err != nil {
		t.Fatal(err)
	}
	if a, err = a.SetRepo(commonDir, client.AuthorOperator); err != nil {
		t.Fatal(err)
	}
	if err := client.WriteAuthors(client.ClientPaths(home), a); err != nil {
		t.Fatal(err)
	}
}

func TestENF010AnOperatorModeRepositoryIsAuthoredAsTheOperator(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	repo, env := enf010Repo(t, home)
	enf010SetOperatorMode(t, home, repo)

	rewritten := enf010Hook(t, repo)
	if strings.Contains(rewritten, "agent@innsegl.invalid") {
		t.Fatalf("an operator-mode repository still gets the agent address: %q", rewritten)
	}
	sh := exec.CommandContext(t.Context(), "sh", "-c", rewritten)
	sh.Dir = repo
	sh.Env = append(append([]string{}, env...), hookFakeSignEnv+"=1")
	if out, err := sh.CombinedOutput(); err != nil {
		t.Fatalf("sh -c %q: %v\n%s", rewritten, err, out)
	}
	got := ghRun(t, ghGitOrSkip(t), repo, env, "cat-file", "commit", "HEAD")
	for _, role := range []string{"author " + enf010Operator, "committer " + enf010Operator} {
		if !strings.Contains(got, role) {
			t.Errorf("commit lacks %q; object:\n%s", role, got)
		}
	}
}

func TestENF010ARepositoryNobodySetStaysTheAgent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	repo, _ := enf010Repo(t, home)
	other := filepath.Join(home, "other")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	ghRun(t, ghGitOrSkip(t), other, ghIsolatedEnv(home), "init", "-q", "-b", "main")
	enf010SetOperatorMode(t, home, other)

	rewritten := enf010Hook(t, repo)
	for _, v := range []string{"GIT_AUTHOR_EMAIL=agent@innsegl.invalid", "GIT_COMMITTER_EMAIL=agent@innsegl.invalid"} {
		if !strings.Contains(rewritten, v) {
			t.Errorf("a repository nobody set lacks %q: %q", v, rewritten)
		}
	}
}
