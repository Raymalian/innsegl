// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// IP §2's branch floor over the paths that resolve a caller's worktree
// (RM-125, #199). Every condition here is one the happy path never reaches,
// and each is a refusal — which is exactly the code that runs on the day
// something is already wrong.
//
// The macOS `/private` prefix is why relativeWorktree exists at all: a test
// that only ever ran where the two spellings agree would have passed while the
// function returned eight `..` segments (found writing MCP-038).

func TestMCP041RelativeWorktreeRefusesWhatIsNotUnderTheRepository(t *testing.T) {
	root := t.TempDir()

	t.Run("the repository itself is the empty path", func(t *testing.T) {
		got, err := relativeWorktree(root, root)
		if err != nil || got != "" {
			t.Errorf("relativeWorktree(root, root) = %q, %v; want empty and no error", got, err)
		}
	})

	t.Run("a tree beside the repository is refused, not rendered with ..", func(t *testing.T) {
		outside := t.TempDir()
		_, err := relativeWorktree(root, outside)
		if err == nil {
			t.Fatal("a directory outside the repository was accepted; sign_commit " +
				"would then be handed a path made of `..` segments")
		}
		if !strings.Contains(err.Error(), "outside the repository") {
			t.Errorf("said %q, which does not say why", err)
		}
	})

	t.Run("the parent directory is refused", func(t *testing.T) {
		// `rel == ".."` exactly, which is the boundary the prefix test misses.
		if _, err := relativeWorktree(filepath.Join(root, "child"), root); err == nil {
			t.Fatal("the repository's parent was accepted as one of its trees")
		}
	})

	t.Run("paths that do not exist fall back to Clean rather than failing", func(t *testing.T) {
		// EvalSymlinks errors on both sides. A worktree the server has not
		// created yet is still a path it can reason about, and refusing here
		// would turn a resolvable argument into an error.
		got, err := relativeWorktree(
			filepath.Join(root, "nowhere"), filepath.Join(root, "nowhere", "wt"))
		if err != nil {
			t.Fatalf("relativeWorktree on paths that do not exist: %v", err)
		}
		if got != "wt" {
			t.Errorf("got %q, want %q", got, "wt")
		}
	})

	t.Run("a relative root against an absolute tree cannot be related", func(t *testing.T) {
		// filepath.Rel's own error return: one side rooted, the other not.
		if _, err := relativeWorktree("relative/root", root); err == nil {
			t.Fatal("a relative repository path and an absolute tree were related")
		}
	})
}

// TestMCP042TheRepositoryIdentifierRefusesWhatIsNotOne covers repoIDFromWorktree's
// two remaining refusals: an origin configured with an empty URL, and a remote
// that reduces to something doc 02 §5 has no grammar for.
func TestMCP042TheRepositoryIdentifierRefusesWhatIsNotOne(t *testing.T) {
	t.Run("an origin whose url is empty", func(t *testing.T) {
		dir := t.TempDir()
		gitInit(t, dir, "")
		// `git remote add` refuses an empty URL, so the state is reached the
		// way a hand-edited config reaches it.
		run(t, dir, "config", "remote.origin.url", "")
		if _, err := repoIDFromWorktree(t.Context(), dir); err == nil {
			t.Fatal("an origin with an empty url produced a repository identifier")
		}
	})

	t.Run("a remote that is not host/org/name", func(t *testing.T) {
		dir := t.TempDir()
		gitInit(t, dir, "")
		// A space is outside doc 02 §5's grammar, so ValidateRepo refuses what
		// the reduction produces.
		run(t, dir, "config", "remote.origin.url", "git@github.com:Org/Name with space.git")
		if _, err := repoIDFromWorktree(t.Context(), dir); err == nil {
			t.Fatal("a remote outside doc 02 §5's grammar was accepted")
		}
	})
}

// TestMCP043MainWorktreeOfRefusesOutputThatNamesNoWorktree drives the one
// condition a real git never produces: `worktree list --porcelain` answering
// without a `worktree ` line.
//
// Unreachable through git itself, which is why it is reached through a git
// that is not git. The branch exists because trusting a subprocess's output
// shape is how a parser returns an empty string that later becomes a path.
func TestMCP043MainWorktreeOfRefusesOutputThatNamesNoWorktree(t *testing.T) {
	dir := t.TempDir()
	shim := filepath.Join(dir, "git")
	script := "#!/bin/sh\necho 'branch refs/heads/main'\nexit 0\n"
	if err := os.WriteFile(shim, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	_, err := mainWorktreeOf(t.Context(), dir)
	if err == nil {
		t.Fatal("output with no `worktree ` line was accepted; the caller would " +
			"have joined an empty string to a path")
	}
	if !strings.Contains(err.Error(), "reports no worktree") {
		t.Errorf("said %q", err)
	}
}

// gitOutputShim writes a `git` that answers one subcommand with fixed text and
// delegates everything else to the real binary.
//
// Three conditions below are reachable no other way: they check the SHAPE of
// what git printed, and a working git always prints the right shape. They
// exist because a parser that trusts a subprocess is how an empty string or a
// stray word becomes a tree hash in an append-only record.
func gitOutputShim(t *testing.T, subcommand, output string) string {
	t.Helper()
	bin := t.TempDir()
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skipf("no git on PATH: %v", err)
	}
	path := filepath.Join(bin, "git")
	script := "#!/bin/sh\nfor a in \"$@\"; do case \"$a\" in\n" +
		"  " + subcommand + ") printf '%s\\n' '" + output + "'; exit 0 ;;\n" +
		"esac; done\nexec " + gitBin + " \"$@\"\n"
	if werr := os.WriteFile(path, []byte(script), 0o755); werr != nil {
		t.Fatal(werr)
	}
	// These helpers invoke `git` by name, so the shim goes on PATH.
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return path
}

// TestMCP045TheServerChecksTheSHAPEOfWhatGitPrinted.
func TestMCP045TheServerChecksTheSHAPEOfWhatGitPrinted(t *testing.T) {
	t.Run("an origin that is only whitespace is no origin", func(t *testing.T) {
		// Trimmed to empty. A remote configured with a space is not a URL, and
		// treating it as one would put an empty repo in a ledger row.
		dir := t.TempDir()
		gitInit(t, dir, "")
		run(t, dir, "config", "remote.origin.url", "   ")
		_, err := repoIDFromWorktree(t.Context(), dir)
		if err == nil {
			t.Fatal("a whitespace origin produced a repository identifier")
		}
		if !strings.Contains(err.Error(), "origin") {
			t.Errorf("said %q", err)
		}
	})

	t.Run("a write-tree that is not an object id", func(t *testing.T) {
		dir := t.TempDir()
		gitInit(t, dir, "git@github.com:Example-Org/Example-Repo.git")
		gitOutputShim(t, "write-tree", "not-a-tree")
		if _, err := stagedTreeOf(t.Context(), dir); err == nil {
			t.Fatal("a write-tree answer that is not an object id was accepted as a tree")
		}
	})

	t.Run("an absolute worktree whose index cannot be resolved", func(t *testing.T) {
		// terr on the absolute path: the tree the caller asked the server to
		// work out cannot be worked out, and the refusal happens before any
		// value is filled in.
		dir := t.TempDir()
		gitInit(t, dir, "git@github.com:Example-Org/Example-Repo.git")
		gitOutputShim(t, "write-tree", "not-a-tree")
		_, err := fillFromWorktree(t.Context(),
			signCommitIn{RunID: "run-42", Message: "m", Worktree: dir},
			func(context.Context, string) (string, error) { return "jira-118", nil })
		if err == nil {
			t.Fatal("a worktree whose index does not resolve to a tree was accepted")
		}
	})
}

// TestMCP047TheLastFiveOneDirectionalConditions closes IP §2's floor on this
// surface. Each is reached deliberately, and each is a refusal or a fill that
// the ordinary path never takes.
func TestMCP047TheLastFiveOneDirectionalConditions(t *testing.T) {
	t.Run("an absolute worktree that is not under its own repository", func(t *testing.T) {
		// `git worktree list` is made to answer with a directory the tree is
		// not inside, so the relative expression escapes. Repo and staged_ref
		// are supplied, so this is the ONLY thing left for the server to work
		// out and the only branch that can fail.
		dir := t.TempDir()
		gitInit(t, dir, "git@github.com:Example-Org/Example-Repo.git")
		gitOutputShim(t, "list", "worktree "+t.TempDir())

		_, err := fillFromWorktree(t.Context(), signCommitIn{
			RunID:     "run-42",
			Message:   "m",
			Worktree:  dir,
			Repo:      "github.com/Example-Org/Example-Repo",
			StagedRef: strings.Repeat("a", 40),
		}, func(context.Context, string) (string, error) { return "jira-118", nil })
		if err == nil {
			t.Fatal("a worktree outside the repository its own git reports was accepted")
		}
	})

	t.Run("a patch id that is not an object id", func(t *testing.T) {
		// git cannot print this; a wrapper, a shim or a future flag could.
		// The value goes into an append-only record, so its shape is checked
		// rather than assumed.
		dir := t.TempDir()
		patchIDInit(t, dir)
		patchIDWrite(t, dir, "a.txt", "one\n")
		patchIDGit(t, dir, "add", "-A")
		shim := gitOutputShim(t, "patch-id", "not-an-object-id 0000")

		_, err := GitRepos{GitPath: shim}.StagedPatchID(t.Context(), dir)
		if err == nil {
			t.Fatal("a patch id that is not an object id was accepted")
		}
		if !strings.Contains(err.Error(), "not an object id") {
			t.Errorf("said %q", err)
		}
	})
}
