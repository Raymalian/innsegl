// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// MCP-039..MCP-043 — describe_workspace (RM-126, #205, E11), doc 07.
//
// The tool is a pure derivation: it answers what `derive_task` in
// scripts/hooks/subagent-identity.sh answers, in the MCP rather than in one
// harness's shell. So these tests are written against TWO specifications at
// once — doc 07's five rows, and the shell itself, which MCP-043 runs side by
// side with the Go and refuses a disagreement.
//
// The refusals are the point of the other four. A harness reports its OWN host
// path; the MCP sees the same tree under a different root and cannot translate
// without being told what its mount corresponds to. Every way that translation
// can fail produces a refusal with its own message, because the alternative —
// a guess — describes the wrong repository confidently, and the answer goes
// into an append-only record.

// workspaceTree is a projects root with one repository under it, which is the
// shape the /projects mount has: the mount is the directory repositories live
// in, never a repository itself.
type workspaceTree struct {
	// projects is the directory the container's mount corresponds to.
	projects string
	// repo is the main working tree of the one repository under it.
	repo string
}

// newWorkspaceTree builds that shape with one commit, so linked worktrees can
// be added to it.
func newWorkspaceTree(t *testing.T, remote string) workspaceTree {
	t.Helper()
	projects := t.TempDir()
	repo := filepath.Join(projects, "example-repo")
	if err := os.Mkdir(repo, 0o755); err != nil {
		t.Fatalf("creating the repository directory: %v", err)
	}
	gitInit(t, repo, remote)
	if err := os.WriteFile(filepath.Join(repo, "seed"), []byte("x\n"), 0o644); err != nil {
		t.Fatalf("seeding a file: %v", err)
	}
	run(t, repo, "add", "seed")
	run(t, repo, "commit", "-q", "-m", "seed", "--no-gpg-sign")
	return workspaceTree{projects: projects, repo: repo}
}

// configureWorkspace installs one host-root/mount pair for the duration of a
// test. host and projects are the same directory in these tests wherever the
// translation itself is not what is under test: the tree has to exist for git
// to be able to read it, and a container path does not exist on the host.
func configureWorkspace(t *testing.T, host, projects string) {
	t.Helper()
	restore, err := ConfigureDescribeWorkspace(DescribeWorkspaceConfig{
		HostProjects: host,
		Projects:     projects,
	})
	if err != nil {
		t.Fatalf("ConfigureDescribeWorkspace(%q, %q): %v", host, projects, err)
	}
	t.Cleanup(restore)
}

// describeAt calls the tool the way the transport does.
func describeAt(t *testing.T, cwd string) (describeWorkspaceOut, error) {
	t.Helper()
	return describeWorkspace(t.Context(), nil, describeWorkspaceIn{CWD: cwd})
}

// refusalMessage fails the test unless describing cwd is refused, and returns
// the refusal's message. It also checks the class is one of IP §4's eleven:
// the vocabulary is closed (doc 08 §3), and a new tool may not widen it.
func refusalMessage(t *testing.T, cwd, what string) string {
	t.Helper()
	out, err := describeAt(t, cwd)
	if err == nil {
		t.Fatalf("%s was accepted and answered %+v; a guess in an append-only "+
			"record is worse than a refusal", what, out)
	}
	var classified *Error
	if !errors.As(err, &classified) {
		t.Fatalf("%s failed with %T (%v), not an IP §4 classified error", what, err, err)
	}
	if !classified.Class.Valid() {
		t.Errorf("%s was refused with %q, which is not one of IP §4's eleven classes",
			what, string(classified.Class))
	}
	return classified.Message
}

// MCP-039: a linked worktree, a sibling worktree and the main tree each
// resolve to themselves.
//
// This is the measurement the shell already carries, one level out. Four
// subagents in four worktrees all registered `branch: main` because the
// derivation read the MAIN worktree's branch for every one of them; the ledger
// then said every agent was working on the trunk while not one of them was.
// The answer has to be about the tree the caller is standing in.
//
// `repo`, by contrast, is the REPOSITORY's and is read from the main tree's
// origin — three segments, host lowercased, org and name left alone — and is
// never synthesised from a directory name. "example-repo" is deliberately not
// what the remote says, so a synthesised answer fails here.
func TestMCP039DescribeWorkspaceResolvesEachTreeToItself(t *testing.T) {
	tree := newWorkspaceTree(t, "git@github.com:Example-Org/Example-Repo.git")
	run(t, tree.repo, "worktree", "add", "-b", "dev/rm126-a", ".worktrees/a")
	run(t, tree.repo, "worktree", "add", "-b", "dev/rm126-b", ".worktrees/b")
	configureWorkspace(t, tree.projects, tree.projects)

	const wantRepo = "github.com/Example-Org/Example-Repo"
	for _, tc := range []struct {
		name     string
		cwd      string
		worktree string
		branch   string
		task     string
		linked   bool
	}{
		{"the main tree", tree.repo, "", "main", "main", false},
		{
			"a linked worktree", filepath.Join(tree.repo, ".worktrees", "a"),
			".worktrees/a", "dev/rm126-a", "rm126", true,
		},
		{
			"its sibling", filepath.Join(tree.repo, ".worktrees", "b"),
			".worktrees/b", "dev/rm126-b", "rm126", true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := describeAt(t, tc.cwd)
			if err != nil {
				t.Fatalf("describe_workspace(%s): %v", tc.cwd, err)
			}
			if got.Repo != wantRepo {
				t.Errorf("repo = %q, want %q (the origin's, never the directory's)", got.Repo, wantRepo)
			}
			if got.Worktree != tc.worktree {
				t.Errorf("worktree = %q, want %q", got.Worktree, tc.worktree)
			}
			if got.Branch != tc.branch {
				t.Errorf("branch = %q, want %q — the branch this tree's commits land on",
					got.Branch, tc.branch)
			}
			if got.Task != tc.task {
				t.Errorf("task = %q, want %q", got.Task, tc.task)
			}
			if got.IsLinkedWorktree != tc.linked {
				t.Errorf("is_linked_worktree = %v, want %v", got.IsLinkedWorktree, tc.linked)
			}
		})
	}

	// The translation itself, with a host root that is not the mount. A
	// harness names a path on the host; the tool answers about the same tree
	// under the mount, and nothing else in the answer changes.
	t.Run("a host path is translated onto the mount", func(t *testing.T) {
		configureWorkspace(t, "/host/projects", tree.projects)
		got, err := describeAt(t, "/host/projects/example-repo/.worktrees/a")
		if err != nil {
			t.Fatalf("a host path under the configured root was refused: %v", err)
		}
		if got.Repo != wantRepo || got.Worktree != ".worktrees/a" || got.Branch != "dev/rm126-a" {
			t.Errorf("translated answer = %+v, want the same tree as the container path", got)
		}
	})
}

// MCP-040: with INNSEGL_HOST_PROJECTS unset, the tool refuses and names the
// missing configuration. It never guesses a translation.
func TestMCP040DescribeWorkspaceRefusesWithoutHostProjects(t *testing.T) {
	tree := newWorkspaceTree(t, "git@github.com:Example-Org/Example-Repo.git")

	t.Run("configured with no host root", func(t *testing.T) {
		configureWorkspace(t, "", tree.projects)
		msg := refusalMessage(t, tree.repo, "a call with no host root configured")
		if !strings.Contains(msg, EnvHostProjects) {
			t.Errorf("the refusal is %q; it does not name %s, so an operator cannot act on it",
				msg, EnvHostProjects)
		}
	})

	t.Run("unwired, with the variable unset", func(t *testing.T) {
		t.Setenv(EnvHostProjects, "")
		msg := refusalMessage(t, tree.repo, "a call with the variable unset")
		if !strings.Contains(msg, EnvHostProjects) {
			t.Errorf("the refusal is %q; it does not name %s", msg, EnvHostProjects)
		}
	})

	t.Run("a relative host root in the environment is refused", func(t *testing.T) {
		t.Setenv(EnvHostProjects, "relative/projects")
		msg := refusalMessage(t, tree.repo, "a relative host root")
		if !strings.Contains(msg, EnvHostProjects) || !strings.Contains(msg, "absolute") {
			t.Errorf("the refusal is %q; it does not say which value is not an absolute path", msg)
		}
	})

	t.Run("a configuration that cannot be true is refused at start-up", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			cfg  DescribeWorkspaceConfig
			says string
		}{
			{"a relative mount", DescribeWorkspaceConfig{Projects: "projects"}, "projects"},
			{
				"a relative host root",
				DescribeWorkspaceConfig{HostProjects: "projects", Projects: "/projects"},
				EnvHostProjects,
			},
		} {
			restore, err := ConfigureDescribeWorkspace(tc.cfg)
			if err == nil {
				restore()
				t.Errorf("%s was installed; an operator finds out at start-up, not at an "+
					"agent's first call", tc.name)
				continue
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("%s was refused with %q, which does not name %q", tc.name, err, tc.says)
			}
		}
	})

	t.Run("an unnamed mount is the container's own", func(t *testing.T) {
		restore, err := ConfigureDescribeWorkspace(DescribeWorkspaceConfig{HostProjects: tree.projects})
		if err != nil {
			t.Fatalf("configuring with no mount named: %v", err)
		}
		t.Cleanup(restore)
		msg := refusalMessage(t, tree.repo, "a call against the default mount")
		if !strings.Contains(msg, DefaultProjectsMount) {
			t.Errorf("the refusal is %q; it does not name the default mount %s",
				msg, DefaultProjectsMount)
		}
	})

	t.Run("the environment supplies it when nothing is wired", func(t *testing.T) {
		t.Setenv(EnvHostProjects, tree.projects)
		// The mount defaults to the container's, which does not exist on the
		// host, so this still refuses — but for the PATH and not for the
		// configuration. That difference is the whole assertion.
		msg := refusalMessage(t, tree.repo, "a call with the variable set")
		if strings.Contains(msg, EnvHostProjects+" is unset") {
			t.Errorf("the refusal is %q; the variable was set and was not read", msg)
		}
	})
}

// MCP-041: a host path outside the mount is refused. The tool never describes
// a repository it cannot address.
func TestMCP041DescribeWorkspaceRefusesAPathOutsideTheMount(t *testing.T) {
	tree := newWorkspaceTree(t, "git@github.com:Example-Org/Example-Repo.git")
	configureWorkspace(t, tree.projects, tree.projects)

	for _, tc := range []struct{ name, cwd, says string }{
		{"a path beside the mount", filepath.Join(tree.projects, "..", "elsewhere"), tree.projects},
		{"an unrelated absolute path", "/elsewhere/example-repo", tree.projects},
		{"a relative path", "example-repo", "relative"},
		{"no path at all", "", "cwd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := refusalMessage(t, tc.cwd, tc.name)
			if !strings.Contains(msg, tc.says) {
				t.Errorf("the refusal is %q; it does not say %q", msg, tc.says)
			}
		})
	}
}

// MCP-042: a path that is not a git working tree is refused, with the worktree
// resolver's own message.
//
// The second case is the same refusal one step further in: the tree IS a git
// working tree, and it is a LINKED one whose path cannot be expressed under
// the repository it belongs to. sign_commit reads an empty `worktree` as "the
// repository itself" (MCP-029), so answering with an empty one here would send
// the next call to the wrong tree — a guess wearing a successful reply.
func TestMCP042DescribeWorkspaceRefusesWhatIsNotAWorkingTree(t *testing.T) {
	tree := newWorkspaceTree(t, "git@github.com:Example-Org/Example-Repo.git")
	configureWorkspace(t, tree.projects, tree.projects)

	t.Run("a directory that is not a git tree", func(t *testing.T) {
		plain := filepath.Join(tree.projects, "not-a-repo")
		if err := os.Mkdir(plain, 0o755); err != nil {
			t.Fatalf("creating a plain directory: %v", err)
		}
		msg := refusalMessage(t, plain, "a plain directory")
		if !strings.Contains(msg, "not a git working tree") {
			t.Errorf("the refusal is %q; it is not the worktree resolver's own message", msg)
		}
	})

	t.Run("a directory that does not exist", func(t *testing.T) {
		msg := refusalMessage(t, filepath.Join(tree.projects, "absent"), "an absent directory")
		if !strings.Contains(msg, "not a git working tree") {
			t.Errorf("the refusal is %q; it is not the worktree resolver's own message", msg)
		}
	})

	t.Run("the mount root itself", func(t *testing.T) {
		// The projects root is the directory repositories live in, never a
		// repository. The refusal has to name the CONTAINER path, which is
		// how this also shows the root translated to the mount rather than to
		// something under it.
		configureWorkspace(t, "/host/projects", tree.projects)
		msg := refusalMessage(t, "/host/projects", "the mount root itself")
		if !strings.Contains(msg, tree.projects) {
			t.Errorf("the refusal is %q; it does not name %q, so the root was not "+
				"translated onto the mount", msg, tree.projects)
		}
	})

	t.Run("a linked worktree outside its own repository", func(t *testing.T) {
		beside := filepath.Join(tree.projects, "beside")
		run(t, tree.repo, "worktree", "add", "-b", "dev/rm126-beside", beside)
		msg := refusalMessage(t, beside, "a worktree beside the repository")
		if !strings.Contains(msg, "outside the repository") {
			t.Errorf("the refusal is %q; it does not say the tree is not under its repository", msg)
		}
	})

	t.Run("a working tree with no origin", func(t *testing.T) {
		orphan := filepath.Join(tree.projects, "orphan")
		if err := os.Mkdir(orphan, 0o755); err != nil {
			t.Fatalf("creating the orphan directory: %v", err)
		}
		gitInit(t, orphan, "")
		msg := refusalMessage(t, orphan, "a repository with no origin")
		if !strings.Contains(msg, "origin") {
			t.Errorf("the refusal is %q; it does not say what is missing", msg)
		}
	})

	t.Run("an origin that is not host/org/name", func(t *testing.T) {
		local := filepath.Join(tree.projects, "local-clone")
		if err := os.Mkdir(local, 0o755); err != nil {
			t.Fatalf("creating the local clone directory: %v", err)
		}
		gitInit(t, local, "/srv/git/bare.git")
		msg := refusalMessage(t, local, "an origin that is not host/org/name")
		if !strings.Contains(msg, "repo") && !strings.Contains(msg, "host/org/name") {
			t.Errorf("the refusal is %q; it does not name the grammar it refused against", msg)
		}
	})
}

// MCP-043: branch and task derivation agrees with the reference shim's
// `derive_task`, for every case the shell covers.
//
// The shell is the specification, so this runs it. A port that agreed with its
// author's reading of the shell and not with the shell would put a different
// task in the ledger depending on which harness registered the run, which is
// the opposite of what E11 exists to do.
func TestMCP043DescribeWorkspaceAgreesWithTheReferenceShim(t *testing.T) {
	hook, err := filepath.Abs(filepath.Join("..", "..", "scripts", "hooks", "subagent-identity.sh"))
	if err != nil {
		t.Fatalf("resolving the reference shim: %v", err)
	}
	if _, serr := os.Stat(hook); serr != nil {
		t.Fatalf("the reference shim is not where this test expects it: %v", serr)
	}

	tree := newWorkspaceTree(t, "git@github.com:Example-Org/Example-Repo.git")

	// Every shape the shell's comments name, plus the two the grammar rules
	// out: a slash, and a branch that carries no RM number at all.
	branches := []string{
		"dev/rm126-describe-workspace",
		"dev/e11-wave2",
		"Feature/RM-99_Thing",
		"RM126-Upper",
		"rm12-and-rm34",
		"wip_-_thing",
		"worktree-agent-deadbeefdeadbeef",
	}
	dirs := map[string]string{"main": tree.repo}
	for i, b := range branches {
		dir := filepath.Join(tree.repo, ".worktrees", "wt"+string(rune('a'+i)))
		run(t, tree.repo, "worktree", "add", "-b", b, dir)
		dirs[b] = dir
	}

	// A detached HEAD, which has no branch and must not be given one.
	detached := filepath.Join(tree.repo, ".worktrees", "detached")
	run(t, tree.repo, "worktree", "add", "--detach", detached)
	dirs["a detached HEAD"] = detached

	// An UNBORN branch: a repository whose first commit has not been made.
	// `rev-parse` fails there and `symbolic-ref` does not, which is the reason
	// the shell asks in that order.
	unborn := filepath.Join(tree.projects, "unborn")
	if merr := os.Mkdir(unborn, 0o755); merr != nil {
		t.Fatalf("creating the unborn repository: %v", merr)
	}
	gitInit(t, unborn, "git@github.com:Example-Org/Unborn.git")
	dirs["an unborn branch"] = unborn

	for name, dir := range dirs {
		t.Run(name, func(t *testing.T) {
			wantBranch, wantTask := shimDeriveTask(t, hook, dir)
			gotBranch := describeWorkspaceBranch(t.Context(), dir, mainOf(t, dir))
			gotTask := describeWorkspaceTask(gotBranch)
			if gotBranch != wantBranch {
				t.Errorf("branch = %q, the shim says %q", gotBranch, wantBranch)
			}
			if gotTask != wantTask {
				t.Errorf("task = %q, the shim says %q", gotTask, wantTask)
			}
		})
	}

	// The two rules the shell states and no real branch name can reach: a
	// branch that folds to nothing, and the 63-character bound of doc 02 §5.
	t.Run("a branch that folds to nothing is unnamed", func(t *testing.T) {
		if got := describeWorkspaceTask("///"); got != "unnamed" {
			t.Errorf("task = %q, want %q", got, "unnamed")
		}
	})
	t.Run("a folded task is bounded at 63 characters", func(t *testing.T) {
		got := describeWorkspaceTask(strings.Repeat("a", 200))
		if len(got) != 63 {
			t.Errorf("task is %d characters, doc 02 §5 admits at most 63", len(got))
		}
	})
}

// mainOf is the repository a working tree belongs to, as git reports it.
func mainOf(t *testing.T, dir string) string {
	t.Helper()
	main, err := mainWorktreeOf(t.Context(), dir)
	if err != nil {
		t.Fatalf("resolving the main worktree of %s: %v", dir, err)
	}
	return main
}

// shimDeriveTask sources the reference shim as a library and returns BRANCH
// and TASK as its `derive_task` sets them for an agent standing in dir.
//
// INNSEGL_HOOK_LIB is the shim's own test seam: with it set, sourcing defines
// the functions and dispatches no event, so this needs no harness, no MCP and
// no network.
func shimDeriveTask(t *testing.T, hook, dir string) (branch, task string) {
	t.Helper()
	const script = `. "$1" ; CWD="$2" ; derive_task ; printf '%s\n%s\n' "$BRANCH" "$TASK"`
	cmd := exec.CommandContext(t.Context(), "sh", "-c", script, "sh", hook, dir)
	cmd.Env = append(os.Environ(), "INNSEGL_HOOK_LIB=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("running the shim's derive_task in %s: %v\n%s", dir, err, out)
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("derive_task printed %q, want a branch line and a task line", out)
	}
	return lines[len(lines)-2], lines[len(lines)-1]
}
