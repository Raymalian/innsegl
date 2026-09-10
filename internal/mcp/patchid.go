// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"innsegl.dev/innsegl/internal/event"
)

// The change's own identity (RM-120, #192, ADR-0047).
//
// # The problem this is the answer to
//
// A gitsign signature covers a commit OBJECT: its tree, its parents, its
// author and its message. GitHub's rebase button rewrites the parents and the
// tree, and the signature does not survive — measured on throwaway branches, a
// rebased commit lands on `main` with the Agent-* trailers still there and
// nothing left to verify them against. Squash is worse: it substitutes
// GitHub's own PGP key and inserts a `Co-authored-by` trailer that ADR-0028 §5
// forbids. GitHub offers merge, squash and rebase and no fourth option, so
// "always merge" is a policy that one setting change undoes silently.
//
// What survives is the change. `git patch-id` is git's own name for it, and it
// is stable across exactly the rewrites that destroy a signature. So the
// ledger records it beside the commit SHA, and a verifier that cannot find the
// SHA can still find the change (#193 is the verifier's half).
//
// # --verbatim, and why the default is wrong here
//
// `git patch-id` without a flag normalises whitespace, so `hello world` and
// `hello   world` hash the same. In Python that is a different program; in
// YAML a different document; in a Makefile the difference between a rule and a
// syntax error. An attribution record whose identity cannot tell two programs
// apart is not an identity. `--verbatim` hashes the lines as they are.

// ErrNoChange reports a diff with nothing in it.
//
// git prints NOTHING for an empty diff rather than a zero id, so this is a
// refusal and not a value. It should be unreachable through sign_commit —
// StagedTree already refuses an index equal to HEAD, and `git commit` refuses
// an empty commit — which is exactly why it must not be allowed to reach the
// ledger as an empty member if the earlier gate is ever moved.
var ErrNoChange = errors.New("no change to identify")

// StagedPatchID is the patch id of what the index holds against HEAD: the
// change `git commit` is about to make.
//
// This is the value Phase A records, because Phase A names what is ABOUT to be
// signed and the commit object does not exist yet.
func (g GitRepos) StagedPatchID(ctx context.Context, worktree string) (string, error) {
	// --no-color and --no-ext-diff: the id is over the diff text, so a
	// deployment with colour or an external differ configured must not produce
	// a different id from one without. -- ADR-0047's stability claim is about
	// the CHANGE, not about the reader's configuration.
	return g.patchIDOf(ctx, worktree,
		[]string{"diff", "--cached", "--no-color", "--no-ext-diff"})
}

// CommitPatchID is the patch id of one commit's own change.
//
// `diff-tree -p` rather than `show`: it emits the patch and nothing else, so
// the message and the author — the parts a rebase is free to rewrite — are not
// in the input.
//
// `--root` makes the FIRST commit in a repository produce a diff rather than
// nothing. Without it a root commit has no parent to diff against and git
// prints an empty patch, so `commit_recorded` would disagree with the
// `commit_intent` that preceded it — `git diff --cached` in a repository with
// no HEAD diffs against the empty tree, which is what `--root` makes
// diff-tree do too.
func (g GitRepos) CommitPatchID(ctx context.Context, worktree, commit string) (string, error) {
	if err := event.ValidateGitObjectID(commit); err != nil {
		return "", fmt.Errorf("%q is not a commit id: %w", commit, err)
	}
	return g.patchIDOf(ctx, worktree,
		[]string{"diff-tree", "-p", "--root", "--no-color", "--no-ext-diff", commit})
}

// patchIDOf pipes a diff into `git patch-id --verbatim` and reads the id back.
//
// The pipe is here rather than in a shell: a shell would need the worktree path
// quoted into a command string, and this package's whole path discipline is
// that a repository identifier never becomes shell text (SignCommitWorkspace).
func (g GitRepos) patchIDOf(ctx context.Context, worktree string, diffArgs []string) (string, error) {
	path := g.GitPath
	if path == "" {
		path = "git"
	}

	diff := exec.CommandContext(ctx, path, append([]string{"-C", worktree}, diffArgs...)...)
	diff.Env = signCommitGitEnv(worktree)
	patch, err := diff.Output()
	if err != nil {
		return "", fmt.Errorf("git %s in %s: %w",
			strings.Join(diffArgs, " "), worktree, err)
	}
	if len(strings.TrimSpace(string(patch))) == 0 {
		return "", fmt.Errorf("%w: git %s in %s produced an empty diff",
			ErrNoChange, strings.Join(diffArgs, " "), worktree)
	}

	id := exec.CommandContext(ctx, path, "-C", worktree, "patch-id", "--verbatim")
	id.Env = signCommitGitEnv(worktree)
	id.Stdin = strings.NewReader(string(patch))
	out, err := id.Output()
	if err != nil {
		return "", fmt.Errorf("git patch-id --verbatim in %s: %w", worktree, err)
	}

	// "<patch id> <commit id>", and the second is all zeros when the input came
	// from `git diff` rather than from a commit. Only the first is wanted.
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return "", fmt.Errorf("%w: git patch-id printed nothing for the diff in %s",
			ErrNoChange, worktree)
	}
	if err := event.ValidateGitObjectID(fields[0]); err != nil {
		return "", fmt.Errorf("git patch-id returned %q, which is not an object id: %w",
			fields[0], err)
	}
	return fields[0], nil
}
