// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/client"
)

// ENF-013 (PROPOSED for doc 07) — in an operator-mode repository the agent
// commit is authored as the repository's own GitHub noreply address, with
// nothing typed and no personal name (#545).
//
// Who the operator pushes as is already in git. Only user.email is read, and
// only a GitHub noreply address is used; the display name is that address's
// login. user.name is never read: it is a person's name, and an author line
// is published. A repository with no usable address falls back to the agent
// address, and says so; the commit is never blocked for it.

func enf013OperatorModeOnly(t *testing.T, home, repo string) {
	t.Helper()
	commonDir, err := gitCommonDir(t.Context(), repo)
	if err != nil {
		t.Fatalf("gitCommonDir: %v", err)
	}
	a, err := client.Authors{}.SetRepo(commonDir, client.AuthorOperator)
	if err != nil {
		t.Fatalf("operator mode with no typed identity: %v", err)
	}
	if err := client.WriteAuthors(client.ClientPaths(home), a); err != nil {
		t.Fatal(err)
	}
}

func enf013Body(t *testing.T, cwd string) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"tool_name":   "Bash",
		"tool_input":  map[string]any{"command": `git commit -m "enf-013"`},
		"tool_use_id": "toolu_enf013fixture01",
		"cwd":         cwd,
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

const enf013PersonalName = "Personal Fixture Name"

func TestENF013TheRepositorysNoreplyAddressAuthorsTheCommit(t *testing.T) {
	home := t.TempDir()
	isolateGit(t, home)
	repo, env := enf010Repo(t, home)
	git := ghGitOrSkip(t)
	const email = "12345+alpha-op@users.noreply.github.com"
	ghRun(t, git, repo, env, "config", "user.name", enf013PersonalName)
	ghRun(t, git, repo, env, "config", "user.email", email)
	enf013OperatorModeOnly(t, home, repo)

	_, stdout, _ := runHook(t, string(enf013Body(t, repo)))
	rewritten := updatedCommand(t, decodeHookOutput(t, stdout))
	if strings.Contains(rewritten, "agent@innsegl.invalid") {
		t.Fatalf("an operator-mode repository still gets the agent address: %q", rewritten)
	}
	if strings.Contains(rewritten, enf013PersonalName) {
		t.Fatalf("the hook used user.name: %q", rewritten)
	}
	sh := exec.CommandContext(t.Context(), "sh", "-c", rewritten)
	sh.Dir = repo
	// env sets GIT_AUTHOR_* to a test identity: the hook's own assignments
	// must win over an inherited one.
	sh.Env = append(append([]string{}, env...), hookFakeSignEnv+"=1")
	if out, err := sh.CombinedOutput(); err != nil {
		t.Fatalf("sh -c %q: %v\n%s", rewritten, err, out)
	}
	got := ghRun(t, git, repo, env, "cat-file", "commit", "HEAD")
	want := "alpha-op <" + email + ">"
	for _, role := range []string{"author " + want, "committer " + want} {
		if !strings.Contains(got, role) {
			t.Errorf("commit lacks %q; object:\n%s", role, got)
		}
	}
	if strings.Contains(got, enf013PersonalName) {
		t.Fatalf("the commit carries user.name:\n%s", got)
	}
}

func TestENF013NoUsableAddressStaysTheAgent(t *testing.T) {
	for desc, email := range map[string]string{
		"no user.email":          "",
		"not a noreply address":  "alpha@example.com",
		"noreply with no number": "alpha@users.noreply.github.com",
	} {
		t.Run(desc, func(t *testing.T) {
			home := t.TempDir()
			isolateGit(t, home)
			repo, env := enf010Repo(t, home)
			git := ghGitOrSkip(t)
			ghRun(t, git, repo, env, "config", "user.name", enf013PersonalName)
			if email != "" {
				ghRun(t, git, repo, env, "config", "user.email", email)
			}
			enf013OperatorModeOnly(t, home, repo)

			_, stdout, stderr := runHook(t, string(enf013Body(t, repo)))
			rewritten := updatedCommand(t, decodeHookOutput(t, stdout))
			if !strings.Contains(rewritten, "GIT_AUTHOR_EMAIL=agent@innsegl.invalid") {
				t.Fatalf("want the agent address, got %q", rewritten)
			}
			if strings.Contains(rewritten, enf013PersonalName) {
				t.Fatalf("the hook used user.name: %q", rewritten)
			}
			if !strings.Contains(stderr, "noreply") {
				t.Fatalf("the fallback is not said: stderr %q", stderr)
			}
		})
	}
}
