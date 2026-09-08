// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// MCP-029 (proposed for doc 07; doc 07 is not modified here).
//
// `sign_commit` may name a LINKED WORKTREE of the repository it already
// identified, and may not name anything else.
//
// # Why the argument exists
//
// Measured 2026-09-08 across the whole ledger: subagents had 26 runs, 1979
// recorded tool calls, 314 Edit and 33 Write calls — and zero signed commits.
// Part of that is that a subagent running under worktree isolation CANNOT be
// signed. `sign_commit` runs a real `git commit` in the tree the workspace
// resolves from `repo` (internal/signing/gitsign.go), using that tree's index,
// and `event.ValidateRepo` requires exactly three segments — so the only way to
// reach `.claude/worktrees/agent-x` was to invent a fourth repository name and
// write it into the ledger as if it were a repository that exists.
//
// The identifier stays true and the worktree is named separately.
//
// # Why every refusal below is a refusal and not a clamp
//
// The resolved path is where a commit gets WRITTEN. A caller that can walk out
// of the repository with `..`, an absolute path, or a symlink can make this
// deployment commit into a tree its operator never published — which is exactly
// what Repo's own doc comment says the workspace exists to prevent. Silently
// clamping such a path to the root would sign SOMETHING and report success,
// and the caller would never learn its path was wrong.
func TestMCP029AWorktreeMustStayInsideItsRepository(t *testing.T) {
	root := t.TempDir()
	mustGitDir(t, root)

	inside := filepath.Join(root, ".claude", "worktrees", "agent-af9a60")
	if err := os.MkdirAll(inside, 0o755); err != nil {
		t.Fatal(err)
	}
	// A linked worktree's `.git` is a FILE, not a directory, and Worktree()
	// already turns on exactly that distinction. This is the case that must
	// work, so it is built the way git builds it.
	if err := os.WriteFile(filepath.Join(inside, ".git"),
		[]byte("gitdir: "+filepath.Join(root, ".git", "worktrees", "agent-af9a60")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("a linked worktree resolves", func(t *testing.T) {
		got, err := resolveWorktree(root, ".claude/worktrees/agent-af9a60")
		if err != nil {
			t.Fatalf("resolveWorktree: %v", err)
		}
		// The REAL path, symlinks resolved. On macOS the temp directory is
		// reached through /var, which is a symlink to /private/var, so a
		// literal comparison against the path this test built fails on a
		// difference that is not a difference. resolveWorktree resolves
		// symlinks deliberately — a lexical check cannot tell whether a link
		// inside the repository points out of it.
		want, err := filepath.EvalSymlinks(inside)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("resolveWorktree = %q, want %q", got, want)
		}
	})

	t.Run("empty means the repository itself", func(t *testing.T) {
		got, err := resolveWorktree(root, "")
		if err != nil {
			t.Fatalf("resolveWorktree(%q, \"\"): %v", root, err)
		}
		if got != root {
			t.Errorf("resolveWorktree(root, \"\") = %q, want the root %q — an absent "+
				"worktree must not change where an existing caller signs", got, root)
		}
	})

	escape := filepath.Join(filepath.Dir(root), "elsewhere")
	if err := os.MkdirAll(escape, 0o755); err != nil {
		t.Fatal(err)
	}
	mustGitDir(t, escape)
	if err := os.Symlink(escape, filepath.Join(root, "out")); err != nil {
		t.Fatal(err)
	}

	// The repository itself unresolvable. Rare and not impossible: the
	// workspace resolved a symlink that has since been removed, or a bind mount
	// went away under a running process. Named as its own case because the
	// message must say the REPOSITORY could not be resolved -- blaming the
	// worktree argument would send the reader to look at the wrong string.
	t.Run("a repository that cannot be resolved", func(t *testing.T) {
		gone := filepath.Join(t.TempDir(), "never-existed")
		if _, err := resolveWorktree(gone, "any/where"); err == nil {
			t.Fatal("resolveWorktree accepted a repository path that does not exist")
		} else if !strings.Contains(err.Error(), "resolving the repository") {
			t.Errorf("said %q, which does not name the repository as the thing that failed", err)
		}
	})

	for _, tc := range []struct{ name, sub, want string }{
		{"a parent traversal", "../elsewhere", "escapes"},
		{"a traversal that returns", ".claude/../../elsewhere", "escapes"},
		{"an absolute path", escape, "absolute"},
		{"a symlink out of the repository", "out", "escapes"},
		{"a directory that is not a working tree", ".claude", "not a git working tree"},
		{"a path that does not exist", ".claude/worktrees/agent-nope", "not a git working tree"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveWorktree(root, tc.sub)
			if err == nil {
				t.Fatalf("resolveWorktree(%q) resolved to %q; it must be refused — this path "+
					"is where a commit gets written", tc.sub, got)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("resolveWorktree(%q) said %q, which does not say %q", tc.sub, err, tc.want)
			}
		})
	}
}

func mustGitDir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
}
