// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The branch a subagent registers must be the branch its commits land on.
//
// doc 02 stores `branch` verbatim in an append-only record and ADR-0045 made it
// a member of `run_registered`, so a wrong value is not a wrong log line — it is
// a permanent wrong answer to "what was this agent working on".
//
// Measured 2026-09-10 on the running ledger: four subagents, each in its own
// worktree on its own feature branch, all registered `branch: main`. The hook
// read the MAIN worktree's branch for every agent. `task_ref` is folded from
// `branch`, so the same four rows named the wrong task too.
//
// The reason it was written that way is real and is preserved by the last case
// below: Claude Code's own worktree isolation puts a subagent on a throwaway
// branch `worktree-agent-<id>` that nobody works on and that is deleted with the
// agent. Recording THAT gave every agent its own junk task. So it, and only it,
// still falls back to the main worktree's branch.

// hookDeriveTask sources the hook as a library and returns BRANCH and TASK as
// derive_task sets them when the agent is standing in dir.
func hookDeriveTask(t *testing.T, hook, dir string) (branch, task string) {
	t.Helper()
	script := `. "$1" ; CWD="$2" ; derive_task ; printf '%s\n%s\n' "$BRANCH" "$TASK"`
	cmd := exec.CommandContext(context.Background(), "sh", "-c", script, "sh", hook, dir)
	cmd.Env = append(os.Environ(), "INNSEGL_HOOK_LIB=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sourcing the hook and running derive_task in %s: %v\n%s", dir, err, out)
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("derive_task printed %q, want a branch line and a task line", out)
	}
	return lines[len(lines)-2], lines[len(lines)-1]
}

func gitAt(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), "git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s in %s: %v\n%s", strings.Join(args, " "), dir, err, out)
	}
}

func TestHookRegistersTheBranchTheAgentIsActuallyOn(t *testing.T) {
	hook, err := filepath.Abs("../../scripts/hooks/subagent-identity.sh")
	if err != nil {
		t.Fatalf("resolving the hook: %v", err)
	}
	if _, err := os.Stat(hook); err != nil {
		t.Fatalf("the hook is not where this test expects it: %v", err)
	}

	root := t.TempDir()
	main := filepath.Join(root, "repo")
	gitAt(t, root, "init", "-q", "-b", "main", "repo")
	if err := os.WriteFile(filepath.Join(main, "f"), []byte("x\n"), 0o644); err != nil {
		t.Fatalf("seeding a file: %v", err)
	}
	gitAt(t, main, "add", "f")
	gitAt(t, main, "commit", "-q", "-m", "seed", "--no-gpg-sign")

	// The operator's shape: a real feature branch cut into its own worktree.
	feature := filepath.Join(root, "wt-se-001")
	gitAt(t, main, "worktree", "add", "-q", "-b", "feat/apts-se-001", feature)

	// Claude Code's shape: a throwaway isolation branch.
	iso := filepath.Join(root, "wt-agent")
	gitAt(t, main, "worktree", "add", "-q", "-b", "worktree-agent-af9a60aaad38", iso)

	for _, c := range []struct {
		name       string
		dir        string
		wantBranch string
		wantTask   string
		why        string
	}{
		{
			name: "the main worktree names itself", dir: main,
			wantBranch: "main", wantTask: "main",
			why: "unchanged behaviour where the agent is in the main checkout",
		},
		{
			name: "a real feature branch in a linked worktree names itself", dir: feature,
			wantBranch: "feat/apts-se-001", wantTask: "feat-apts-se-001",
			why: "this is the case that was recording `main` for every agent",
		},
		{
			name: "Claude Code's throwaway isolation branch falls back", dir: iso,
			wantBranch: "main", wantTask: "main",
			why: "measured 2026-09-07: recording it gave every agent its own junk task",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			branch, task := hookDeriveTask(t, hook, c.dir)
			if branch != c.wantBranch {
				t.Errorf("derive_task in %s set BRANCH=%q, want %q — %s",
					c.dir, branch, c.wantBranch, c.why)
			}
			if task != c.wantTask {
				t.Errorf("derive_task in %s set TASK=%q, want %q — task_ref is folded "+
					"from the branch, so a wrong branch is a wrong task too",
					c.dir, task, c.wantTask)
			}
		})
	}
}
