// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"innsegl.dev/innsegl/internal/event"
)

// Resolving what a caller would otherwise have to guess.
//
// # Why this file exists
//
// An agent in another repository signed one commit through SIX refusals, and
// five of them were the same refusal wearing different clothes: it had to
// reconstruct a value this server already held.
//
//	repo as host/org/name        the server resolves repositories
//	run_id                       the harness issued it
//	task_ref                     it is in the run's own ledger row
//	staged_ref from write-tree   the server can read the index
//	host lowercase, org not      the server knows how it stores them
//
// It found the run id by reading a hook log and the last rule by running
// `docker exec innsegl-mcp find /work`. That is good debugging, and needing it
// is a defect in this server rather than a gap in anybody's documentation —
// none of the six refusals was about a rule.
//
// # And it decides whether any of this is portable
//
// Identity has to come from the harness: a model that declares its own identity
// defeats IP §6.1, so that call is irreducibly per-harness. Everything needed
// to SIGN can be answered here. The difference is whether porting to another
// harness means four hook types or one call.

// ErrNoOrigin reports a working tree with no origin remote.
//
// A refusal and not an empty answer: a caller handed a blank repository will
// pass the blank on, and the first place it stops being blank is a ledger row.
var ErrNoOrigin = errors.New("the working tree has no origin remote")

// repoIDFromWorktree reads doc 02 §5's `host/org/name` out of a working tree.
//
// # The case rule, which is the one nobody guesses
//
// doc 02 §5 says "lowercase host". It says nothing about the other two, and
// `event.ValidateRepo` enforces exactly that: the host is lowercased, the org
// and the name keep whatever case the remote uses. So
// `github.com/Example-Org/Example-Repo` is correct and
// `github.com/example-org/example-repo` is refused — which is the shape of the
// fifth refusal, discovered in the field by listing the server's workspace.
//
// Every URL form GitHub hands out reduces to the same identifier: the scheme
// goes, the `git@host:` separator becomes a slash, and `.git` is dropped.
func repoIDFromWorktree(ctx context.Context, worktree string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", worktree, "remote", "get-url", "origin")
	raw, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrNoOrigin, worktree)
	}
	remote := strings.TrimSpace(string(raw))
	if remote == "" {
		return "", fmt.Errorf("%w: %s", ErrNoOrigin, worktree)
	}

	id := remote
	for _, prefix := range []string{"https://", "http://", "ssh://", "git://"} {
		id = strings.TrimPrefix(id, prefix)
	}
	id = strings.TrimPrefix(id, "git@")
	// `git@github.com:org/name` -- the colon is the host separator, and only
	// the first one is: a path may not contain another.
	if host, path, found := strings.Cut(id, ":"); found && !strings.Contains(host, "/") {
		id = host + "/" + path
	}
	id = strings.TrimSuffix(id, ".git")
	id = strings.TrimSuffix(id, "/")

	host, rest, found := strings.Cut(id, "/")
	if !found {
		return "", fmt.Errorf("%w: %q is not host/org/name", event.ErrInvalidRepo, remote)
	}
	id = strings.ToLower(host) + "/" + rest

	// Validated here rather than by the caller. A value this function returns
	// is one the ledger will accept, or it is an error -- there is no third
	// answer for the caller to interpret.
	if err := event.ValidateRepo(id); err != nil {
		return "", err
	}
	return id, nil
}

// stagedTreeOf returns the tree the INDEX holds.
//
// Not HEAD's tree, which is the sixth refusal: `git commit` commits the index,
// so sign_commit requires `staged_ref` to name the index's tree and refuses
// anything else. `write-tree` writes the tree object and touches no ref, so
// asking costs nothing and changes nothing.
func stagedTreeOf(ctx context.Context, worktree string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", worktree, "write-tree")
	raw, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("reading the staged tree of %s: %w", worktree, err)
	}
	tree := strings.TrimSpace(string(raw))
	if err := event.ValidateGitObjectID(tree); err != nil {
		return "", err
	}
	return tree, nil
}

// fillFromWorktree supplies the arguments a caller would otherwise guess.
//
// # The rule for `worktree`
//
// ABSOLUTE means "this is where I am, work the rest out": the server reads that
// tree, derives the repository from its origin, and re-expresses the path
// relative to the repository so the rest of sign_commit is unchanged. RELATIVE
// keeps MCP-029's meaning, a linked worktree of an already-named repository.
//
// The distinction needs no flag because the two cannot be confused: a relative
// path never begins with a separator.
//
// # What stays required
//
// `run_id`, because identity may not be inferred -- a model that picks its own
// run defeats IP §6.1 -- and `message`, which is the one thing only the caller
// knows. Everything else is derivable, and derivable values should be derived.
func fillFromWorktree(
	ctx context.Context, in signCommitIn, taskOf func(context.Context, string) (string, error),
) (signCommitIn, error) {
	if filepath.IsAbs(in.Worktree) {
		root, err := mainWorktreeOf(ctx, in.Worktree)
		if err != nil {
			return in, err
		}
		if in.Repo == "" {
			id, rerr := repoIDFromWorktree(ctx, root)
			if rerr != nil {
				return in, rerr
			}
			in.Repo = id
		}
		if in.StagedRef == "" {
			tree, terr := stagedTreeOf(ctx, in.Worktree)
			if terr != nil {
				return in, terr
			}
			in.StagedRef = tree
		}
		// Re-expressed relative to the repository, or emptied when it IS the
		// repository. sign_commit resolves the repository itself; the argument
		// only ever says "which of its trees".
		rel, err := filepath.Rel(root, in.Worktree)
		if err != nil || rel == "." {
			rel = ""
		}
		in.Worktree = rel
	}

	if in.TaskRef == "" && taskOf != nil {
		task, err := taskOf(ctx, in.RunID)
		if err != nil {
			return in, err
		}
		in.TaskRef = task
	}
	return in, nil
}

// mainWorktreeOf returns the repository a working tree belongs to.
//
// `git worktree list` reports the main worktree first from inside any linked
// one, which is what makes a linked worktree resolvable to the repository whose
// identifier the ledger records.
func mainWorktreeOf(ctx context.Context, worktree string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", worktree, "worktree", "list", "--porcelain")
	raw, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%s is not a git working tree: %w", worktree, err)
	}
	for line := range strings.SplitSeq(string(raw), "\n") {
		if rest, ok := strings.CutPrefix(line, "worktree "); ok {
			return strings.TrimSpace(rest), nil
		}
	}
	return "", fmt.Errorf("%s reports no worktree", worktree)
}
