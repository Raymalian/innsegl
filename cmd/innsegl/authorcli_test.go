// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/client"
)

// ENF-011 (PROPOSED for doc 07) — `innsegl author` is how the operator sets
// a repository's mode; the hook only reads what it wrote. Setting operator
// mode reads the repository's own noreply address and reports it to the
// core, which pins it (#545); nothing is typed.

func runAuthorCLI(t *testing.T, home string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var o, e bytes.Buffer
	code = runAuthor(t.Context(), args, &o, &e, home)
	return code, o.String(), e.String()
}

// isolateGit keeps git from reading the developer's own configuration: an
// operator's real address must never reach a test.
func isolateGit(t *testing.T, home string) {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(home, "nonexistent-gitconfig"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg"))
}

// recordReports replaces the call to the core, recording what it was sent
// and answering err.
func recordReports(t *testing.T, err error) *[][2]string {
	t.Helper()
	var sent [][2]string
	previous := reportOperatorAuthor
	reportOperatorAuthor = func(_ context.Context, _ client.Paths, name, email string) error {
		sent = append(sent, [2]string{name, email})
		return err
	}
	t.Cleanup(func() { reportOperatorAuthor = previous })
	return &sent
}

func TestENF011AuthorCommandSetsARepositoryToOperatorMode(t *testing.T) {
	home := t.TempDir()
	isolateGit(t, home)
	repo, env := enf010Repo(t, home)
	sent := recordReports(t, nil)

	if code, _, errOut := runAuthorCLI(t, home, "repo", repo, "operator"); code == exitOK ||
		!strings.Contains(errOut, "noreply") {
		t.Fatalf("operator mode with no noreply address: exit %d, stderr %q", code, errOut)
	}
	git := ghGitOrSkip(t)
	ghRun(t, git, repo, env, "config", "user.name", enf013PersonalName)
	ghRun(t, git, repo, env, "config", "user.email", "12345+alpha-op@users.noreply.github.com")
	if code, _, errOut := runAuthorCLI(t, home, "repo", repo, "operator"); code != exitOK {
		t.Fatalf("author repo operator: exit %d: %s", code, errOut)
	}
	if len(*sent) != 1 || (*sent)[0] != [2]string{"alpha-op", "12345+alpha-op@users.noreply.github.com"} {
		t.Fatalf("the core was told %v, want one report of the address's login and address", *sent)
	}
	commonDir, err := gitCommonDir(t.Context(), repo)
	if err != nil {
		t.Fatal(err)
	}
	a, err := client.ReadAuthors(client.ClientPaths(home))
	if err != nil {
		t.Fatal(err)
	}
	if !a.IsOperator(commonDir) {
		t.Fatalf("the repository is not in operator mode after `author repo %s operator`", repo)
	}
	code, out, _ := runAuthorCLI(t, home)
	if code != exitOK || !strings.Contains(out, commonDir) || !strings.Contains(out, "operator") {
		t.Fatalf("`innsegl author` does not list the repository: exit %d\n%s", code, out)
	}
	if strings.Contains(out, enf013PersonalName) {
		t.Fatalf("`innsegl author` prints user.name:\n%s", out)
	}
	if code, _, errOut := runAuthorCLI(t, home, "repo", repo, "agent"); code != exitOK {
		t.Fatalf("author repo agent: exit %d: %s", code, errOut)
	}
	if a, err = client.ReadAuthors(client.ClientPaths(home)); err != nil || len(a.Repos) != 0 {
		t.Fatalf("the repository is still listed after `author repo %s agent`: %v", repo, a.Repos)
	}
}

func TestENF011ACoreRefusalLeavesTheRepositoryInAgentMode(t *testing.T) {
	for desc, answer := range map[string]error{
		"pinned to another identity": fmt.Errorf("%w: run on the core host: innsegl accounts author-reset x", client.ErrOperatorAuthorPinned),
		"the core cannot be reached": errors.New("dial tcp: connection refused"),
	} {
		t.Run(desc, func(t *testing.T) {
			home := t.TempDir()
			isolateGit(t, home)
			repo, env := enf010Repo(t, home)
			ghRun(t, ghGitOrSkip(t), repo, env, "config", "user.email", "12345+alpha-op@users.noreply.github.com")
			recordReports(t, answer)

			code, _, errOut := runAuthorCLI(t, home, "repo", repo, "operator")
			if code == exitOK {
				t.Fatal("operator mode was set although the core did not pin the address")
			}
			if !strings.Contains(errOut, answer.Error()) {
				t.Fatalf("stderr does not carry the core's answer: %q", errOut)
			}
			a, err := client.ReadAuthors(client.ClientPaths(home))
			if err != nil || len(a.Repos) != 0 {
				t.Fatalf("the repository was saved in operator mode: %v %v", a.Repos, err)
			}
		})
	}
}

func TestENF011AuthorCommandRefusesWhatIsNotARepositoryOrAnIdentity(t *testing.T) {
	home := t.TempDir()
	isolateGit(t, home)
	recordReports(t, nil)
	if code, _, _ := runAuthorCLI(t, home, "operator", "O'Brien <1+ob@users.noreply.github.com>"); code != exitUsage {
		t.Fatalf("an identity with a quote: exit %d, want %d", code, exitUsage)
	}
	if code, _, _ := runAuthorCLI(t, home, "operator", enf010Operator); code != exitOK {
		t.Fatal("author operator failed")
	}
	notRepo := filepath.Join(home, "plain")
	if err := os.MkdirAll(notRepo, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CEILING_DIRECTORIES", home)
	if code, _, _ := runAuthorCLI(t, home, "repo", notRepo, "operator"); code == exitOK {
		t.Fatal("a directory that is not a git repository was set to operator mode")
	}
	if code, _, _ := runAuthorCLI(t, home, "repo"); code != exitUsage {
		t.Fatalf("`author repo` with no path: exit %d, want %d", code, exitUsage)
	}
}
