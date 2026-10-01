// SPDX-License-Identifier: Apache-2.0

package workspace

import (
	"errors"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
)

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	full := append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.com",
		"-c", "commit.gpgsign=false"}, args...)
	if out, err := exec.CommandContext(t.Context(), "git", full...).CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// newRepo makes a repository on branch main with origin set and one commit.
func newRepo(t *testing.T, origin string) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	git(t, dir, "init", "-q", "-b", "main")
	if origin != "" {
		git(t, dir, "remote", "add", "origin", origin)
	}
	git(t, dir, "commit", "-q", "--allow-empty", "-m", "first")
	return dir
}

var hexHead = regexp.MustCompile(`^[0-9a-f]{40}$|^[0-9a-f]{64}$`)

func TestDeriveReadsTheRepositoryFromOrigin(t *testing.T) {
	for name, origin := range map[string]string{
		"https": "https://GitHub.com/Example-Org/Example-Repo.git",
		"scp":   "git@github.com:Example-Org/Example-Repo.git",
		"ssh":   "ssh://git@github.com/Example-Org/Example-Repo",
	} {
		t.Run(name, func(t *testing.T) {
			dir := newRepo(t, origin)
			got, err := Derive(t.Context(), dir)
			if err != nil {
				t.Fatalf("Derive: %v", err)
			}
			if got.Repo != "github.com/Example-Org/Example-Repo" {
				t.Errorf("Repo = %q", got.Repo)
			}
			if got.Branch != "main" || got.Task != "main" || got.Worktree != "" {
				t.Errorf("Branch/Task/Worktree = %q/%q/%q", got.Branch, got.Task, got.Worktree)
			}
			if got.Main != dir {
				t.Errorf("Main = %q, want %q", got.Main, dir)
			}
			if !hexHead.MatchString(got.Head) {
				t.Errorf("Head = %q, want a full object id", got.Head)
			}
		})
	}
}

func TestDeriveFromALinkedWorktreeNamesItsOwnBranchAndTheMainRepository(t *testing.T) {
	main := newRepo(t, "https://github.com/example-org/example-repo")
	linked := filepath.Join(main, "wt")
	git(t, main, "worktree", "add", "-q", "-b", "dev/rm282-derive", linked)

	got, err := Derive(t.Context(), linked)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if got.Repo != "github.com/example-org/example-repo" || got.Main != main {
		t.Errorf("Repo/Main = %q/%q", got.Repo, got.Main)
	}
	if got.Worktree != "wt" || got.Branch != "dev/rm282-derive" || got.Task != "rm282" {
		t.Errorf("Worktree/Branch/Task = %q/%q/%q", got.Worktree, got.Branch, got.Task)
	}
}

func TestDeriveFromASubdirectoryIsRelativeToTheRepository(t *testing.T) {
	dir := newRepo(t, "https://github.com/example-org/example-repo")
	got, err := Derive(t.Context(), dir)
	if err != nil || got.Worktree != "" {
		t.Fatalf("root: %+v, %v", got, err)
	}
}

func TestDeriveFallsBackFromAThrowawayBranchToTheMainWorktrees(t *testing.T) {
	main := newRepo(t, "https://github.com/example-org/example-repo")
	linked := filepath.Join(main, "agent")
	git(t, main, "worktree", "add", "-q", "-b", "worktree-agent-abc", linked)
	got, err := Derive(t.Context(), linked)
	if err != nil {
		t.Fatal(err)
	}
	if got.Branch != "main" {
		t.Errorf("Branch = %q, want main", got.Branch)
	}
}

func TestDeriveDetachedHead(t *testing.T) {
	dir := newRepo(t, "https://github.com/example-org/example-repo")
	git(t, dir, "checkout", "-q", "--detach")
	got, err := Derive(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Branch != "detached" || got.Task != "detached" {
		t.Errorf("Branch/Task = %q/%q", got.Branch, got.Task)
	}
}

func TestDeriveUnbornBranchHasNoHead(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	git(t, dir, "init", "-q", "-b", "feature")
	git(t, dir, "remote", "add", "origin", "https://github.com/example-org/example-repo")
	got, err := Derive(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Branch != "feature" || got.Head != "" {
		t.Errorf("Branch/Head = %q/%q, want feature and no head", got.Branch, got.Head)
	}
}

func TestDeriveRefusals(t *testing.T) {
	t.Run("not a working tree", func(t *testing.T) {
		if _, err := Derive(t.Context(), t.TempDir()); err == nil {
			t.Fatal("want an error")
		}
	})
	t.Run("no origin", func(t *testing.T) {
		_, err := Derive(t.Context(), newRepo(t, ""))
		if !errors.Is(err, ErrNoOrigin) {
			t.Fatalf("err = %v, want ErrNoOrigin", err)
		}
	})
	t.Run("origin that is not host/org/name", func(t *testing.T) {
		if _, err := Derive(t.Context(), newRepo(t, "https://example.com/just-one")); err == nil {
			t.Fatal("want an error")
		}
	})
}

func TestTask(t *testing.T) {
	for branch, want := range map[string]string{
		"main":                  "main",
		"dev/rm126-describe":    "rm126",
		"dev/rm1-and-rm22-both": "rm22",
		"Feature/Some_Thing":    "feature-some-thing",
		"///":                   "unnamed",
	} {
		if got := Task(branch); got != want {
			t.Errorf("Task(%q) = %q, want %q", branch, got, want)
		}
	}
	long := ""
	for range 80 {
		long += "a"
	}
	if got := Task(long); len(got) != 63 {
		t.Errorf("len(Task(long)) = %d, want 63", len(got))
	}
}

func TestRelative(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Relative(root, root); err != nil || got != "" {
		t.Errorf("same dir = %q, %v", got, err)
	}
	if got, err := Relative(root, filepath.Join(root, "a", "b")); err != nil || got != filepath.Join("a", "b") {
		t.Errorf("child = %q, %v", got, err)
	}
	if _, err := Relative(filepath.Join(root, "a"), root); err == nil {
		t.Error("outside the repository must be refused")
	}
}
