// SPDX-License-Identifier: Apache-2.0

package workspace

import (
	"context"
	"os/exec"
)

// Head is the commit HEAD names in dir, or the empty string: an unborn branch
// has none, and that is an honest absence rather than an error.
func Head(ctx context.Context, dir string) string {
	return line(exec.CommandContext(ctx, "git", "-C", dir, "rev-parse", "--verify", "--quiet", "HEAD"))
}

// Workspace is what a client states about the tree it stands in.
type Workspace struct {
	// Repo is doc 02 §5's host/org/name, read from the main worktree's origin.
	Repo string
	// Main is the repository's own (main) worktree as reported by its tooling.
	Main string
	// Worktree is this tree relative to Main, empty when it is Main.
	Worktree string
	// Branch is the branch this tree's commits land on, verbatim.
	Branch string
	// Task is the branch folded into doc 02 §5's identifier grammar.
	Task string
	// Head is the commit HEAD names, empty on an unborn branch.
	Head string
}

// Derive describes the working tree at dir. It fails when dir is not in a
// working tree, is not under its repository, or the repository has no origin
// that forms a valid host/org/name.
func Derive(ctx context.Context, dir string) (Workspace, error) {
	main, err := MainWorktree(ctx, dir)
	if err != nil {
		return Workspace{}, err
	}
	rel, err := Relative(main, dir)
	if err != nil {
		return Workspace{}, err
	}
	repo, err := RepoID(ctx, main)
	if err != nil {
		return Workspace{}, err
	}
	branch := Branch(ctx, dir, main)
	return Workspace{
		Repo: repo, Main: main, Worktree: rel, Branch: branch,
		Task: Task(branch), Head: Head(ctx, dir),
	}, nil
}
