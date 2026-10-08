// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/client"
)

// ENF-011 (PROPOSED for doc 07) — `innsegl author` is how the operator sets
// the identity and a repository's mode; the hook only reads what it wrote.

func runAuthorCLI(t *testing.T, home string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var o, e bytes.Buffer
	code = runAuthor(t.Context(), args, &o, &e, home)
	return code, o.String(), e.String()
}

func TestENF011AuthorCommandSetsARepositoryToOperatorMode(t *testing.T) {
	home := t.TempDir()
	repo, _ := enf010Repo(t, home)

	if code, _, errOut := runAuthorCLI(t, home, "repo", repo, "operator"); code == exitOK {
		t.Fatalf("operator mode was set before any operator identity; stderr: %s", errOut)
	}
	if code, _, errOut := runAuthorCLI(t, home, "operator", enf010Operator); code != exitOK {
		t.Fatalf("author operator: exit %d: %s", code, errOut)
	}
	if code, _, errOut := runAuthorCLI(t, home, "repo", repo, "operator"); code != exitOK {
		t.Fatalf("author repo operator: exit %d: %s", code, errOut)
	}
	commonDir, err := gitCommonDir(t.Context(), repo)
	if err != nil {
		t.Fatal(err)
	}
	a, err := client.ReadAuthors(client.ClientPaths(home))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := a.OperatorFor(commonDir); !ok {
		t.Fatalf("the repository is not in operator mode after `author repo %s operator`", repo)
	}
	code, out, _ := runAuthorCLI(t, home)
	if code != exitOK || !strings.Contains(out, commonDir) || !strings.Contains(out, "operator") {
		t.Fatalf("`innsegl author` does not list the repository: exit %d\n%s", code, out)
	}
	if code, _, errOut := runAuthorCLI(t, home, "repo", repo, "agent"); code != exitOK {
		t.Fatalf("author repo agent: exit %d: %s", code, errOut)
	}
	if a, err = client.ReadAuthors(client.ClientPaths(home)); err != nil || len(a.Repos) != 0 {
		t.Fatalf("the repository is still listed after `author repo %s agent`: %v", repo, a.Repos)
	}
}

func TestENF011AuthorCommandRefusesWhatIsNotARepositoryOrAnIdentity(t *testing.T) {
	home := t.TempDir()
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
