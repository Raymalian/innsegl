// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// MCP-031 (proposed for doc 07; doc 07 is not modified here).
//
// The server answers what the server knows.
//
// # The measurement this exists for
//
// An agent in another repository signed one commit through six refusals, and
// five were the same refusal: it had to guess a value this server already held.
//
//	repo as host/org/name       the server resolves repositories
//	run_id                      the harness issued it
//	task_ref                    it is in the run's own ledger row
//	staged_ref from write-tree  the server can read the index
//	host lowercase, org not     the server knows how it stores them
//
// It found the run id by reading a hook log and the case rule by running
// `docker exec innsegl-mcp find /work`. Neither was in its brief. That is good
// debugging and it should not have been necessary.
//
// # Why this is a tool and not a better error message
//
// A refusal names a value and leaves the caller to reconstruct it from
// documentation. A tool hands it over. The first is a guessing game with the
// answer in the error text.
//
// It also decides whether any of this works outside Claude Code. Identity must
// come from the harness — a model that declares its own identity defeats
// IP §6.1 — but everything needed to SIGN can come from here, and then a
// harness integration is one call rather than four hook types.
//
// # What it must not do
//
// Answer for a run that is not live, or for a tree outside the repository the
// run named. Both are refusals, not empty answers: a caller that gets a blank
// where it expected a repository will pass the blank on.
func TestMCP031TheServerResolvesWhatTheCallerWouldGuess(t *testing.T) {
	repoRoot := t.TempDir()
	gitInit(t, repoRoot, "git@github.com:Example-Org/Example-Repo.git")

	t.Run("the repository identifier is canonical, not as typed", func(t *testing.T) {
		got, err := repoIDFromWorktree(t.Context(), repoRoot)
		if err != nil {
			t.Fatalf("repoIDFromWorktree: %v", err)
		}
		// HOST lowercased, org and name left alone. This is the fifth refusal:
		// the agent guessed `github.com/example-org/example-repo` and was refused,
		// then discovered the rule by listing the server's own workspace.
		const want = "github.com/Example-Org/Example-Repo"
		if got != want {
			t.Errorf("repoIDFromWorktree = %q, want %q", got, want)
		}
	})

	t.Run("an ssh url, an https url and a bare path agree", func(t *testing.T) {
		for _, remote := range []string{
			"git@github.com:Example-Org/Example-Repo.git",
			"https://github.com/Example-Org/Example-Repo.git",
			"https://github.com/Example-Org/Example-Repo",
		} {
			dir := t.TempDir()
			gitInit(t, dir, remote)
			got, err := repoIDFromWorktree(t.Context(), dir)
			if err != nil {
				t.Fatalf("%s: %v", remote, err)
			}
			if got != "github.com/Example-Org/Example-Repo" {
				t.Errorf("%s resolved to %q", remote, got)
			}
		}
	})

	t.Run("a tree with no origin is refused by name", func(t *testing.T) {
		dir := t.TempDir()
		gitInit(t, dir, "")
		_, err := repoIDFromWorktree(t.Context(), dir)
		if err == nil {
			t.Fatal("a worktree with no origin was accepted; there is no repository " +
				"identifier to record and a guess would be worse than a refusal")
		}
		if !strings.Contains(err.Error(), "origin") {
			t.Errorf("said %q, which does not say what is missing", err)
		}
	})

	t.Run("the staged tree is the index, not HEAD", func(t *testing.T) {
		if err := os.WriteFile(filepath.Join(repoRoot, "a.txt"), []byte("one\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		run(t, repoRoot, "add", "-A")
		staged, err := stagedTreeOf(t.Context(), repoRoot)
		if err != nil {
			t.Fatalf("stagedTreeOf: %v", err)
		}
		if len(staged) != 40 {
			t.Fatalf("staged tree %q is not a full object id", staged)
		}
		// The sixth refusal: the agent passed HEAD's tree and was told the
		// index holds a different one. `git commit` commits the index, so the
		// index is the only answer.
		want := strings.TrimSpace(out(t, repoRoot, "write-tree"))
		if staged != want {
			t.Errorf("stagedTreeOf = %q, want the index tree %q", staged, want)
		}
	})
}

func gitInit(t *testing.T, dir, remote string) {
	t.Helper()
	run(t, dir, "init", "-q", "-b", "main")
	run(t, dir, "config", "user.email", "t@t")
	run(t, dir, "config", "user.name", "t")
	if remote != "" {
		run(t, dir, "remote", "add", "origin", remote)
	}
}

func run(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", args...)
	cmd.Dir = dir
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, b)
	}
}

func out(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", args...)
	cmd.Dir = dir
	b, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %s: %v", strings.Join(args, " "), err)
	}
	return string(b)
}

// TestMCP032AnUnresolvableRunIsStillRefused. Making task_ref derivable must not
// make it optional in effect: a run the server cannot resolve has no task, and
// answering with an empty one would put a blank in the Agent-Task trailer.
func TestMCP032AnUnresolvableRunIsStillRefused(t *testing.T) {
	_, err := fillFromWorktree(t.Context(),
		signCommitIn{RunID: "run-nonexistent", Message: "m"},
		func(_ context.Context, id string) (string, error) {
			return "", fmt.Errorf("no run %q", id)
		})
	if err == nil {
		t.Fatal("a run the server cannot resolve was accepted; task_ref would be empty " +
			"and the Agent-Task trailer would carry a blank")
	}
	if !strings.Contains(err.Error(), "run-nonexistent") {
		t.Errorf("said %q, which does not name the run", err)
	}
}
