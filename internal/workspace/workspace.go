// SPDX-License-Identifier: Apache-2.0

// Package workspace derives a working tree's repository, branch, task and head
// from the tree itself. It is pure derivation: it reads git, writes nothing,
// and knows nothing of mounts, hosts or credentials.
//
// It exists so the client (`innsegl hook session`) and the single-host core
// (describe_workspace) derive a workspace with one rule. A second copy would
// let two components describe the same tree differently, and the answer ends
// up in an append-only record.
package workspace

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"innsegl.dev/innsegl/internal/event"
)

// ErrNoOrigin reports a working tree with no origin remote.
//
// A refusal and not an empty answer: a caller handed a blank repository will
// pass the blank on, and the first place it stops being blank is a ledger row.
var ErrNoOrigin = errors.New("the working tree has no origin remote")

const (
	// throwawayPrefix is the one branch shape that is NOT the
	// answer. A harness with worktree isolation of its own puts each subagent
	// on a throwaway branch named `worktree-agent-<id>`, which nobody works on
	// and which is deleted with the agent; recording it gave every agent its
	// own junk task where one shared task belonged. That shape, and only that
	// shape, falls back to the main worktree's branch.
	throwawayPrefix = "worktree-agent-"

	// detached is the honest answer for a HEAD that is on no
	// branch. doc 02 stores `branch` verbatim, so inventing a name would put a
	// branch in the ledger that does not exist.
	detached = "detached"

	// unnamed is the answer for a branch that folds to
	// nothing under doc 02 §5's grammar.
	unnamed = "unnamed"

	// taskBytes is doc 02 §5's bound on an identifier:
	// [a-z0-9][a-z0-9-]{0,62}, so 63 characters.
	taskBytes = 63
)

// rmTask matches this project's own task identifier inside a
// branch name. A branch name is not a task id — doc 02 §5 admits no slash, so
// `dev/rm126-describe-workspace` is refused as it stands — and an RM number is
// preferred over a folded branch wherever the branch carries one.
var rmTask = regexp.MustCompile(`rm[0-9]+`)

// RepoID reads doc 02 §5's `host/org/name` out of a working tree.
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
func RepoID(ctx context.Context, worktree string) (string, error) {
	// G702: an argument list, never shell text, so nothing in worktree is
	// interpreted; worktree is the workspace's join of a validated repository
	// id, or a harness-stated directory this very call exists to check, and
	// the command only reads the origin URL.
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

// Relative expresses a working tree as a path under its repository.
//
// Empty when the two are the same directory. An error when the tree is not
// under the repository at all: that is not a path to be rendered with `..`
// segments, it is a caller naming somewhere sign_commit has no business
// writing, and the refusal says so rather than handing on a path that would
// fail later and further away.
func Relative(root, worktree string) (string, error) {
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		resolvedRoot = filepath.Clean(root)
	}
	resolvedTree, err := filepath.EvalSymlinks(worktree)
	if err != nil {
		resolvedTree = filepath.Clean(worktree)
	}

	rel, err := filepath.Rel(resolvedRoot, resolvedTree)
	if err != nil {
		return "", fmt.Errorf("%s is not under the repository at %s: %w",
			worktree, root, err)
	}
	if rel == "." {
		return "", nil
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%s is outside the repository at %s; a worktree "+
			"argument names one of the repository's own trees", worktree, root)
	}
	return rel, nil
}

// MainWorktree returns the repository a working tree belongs to.
//
// `git worktree list` reports the main worktree first from inside any linked
// one, which is what makes a linked worktree resolvable to the repository whose
// identifier the ledger records.
func MainWorktree(ctx context.Context, worktree string) (string, error) {
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

// Branch is the branch the caller's commits land on.
//
// THE BRANCH IS THE ONE THE TREE IS ACTUALLY ON. doc 02 stores it verbatim in
// an append-only record, so it has to be the branch of the worktree the agent
// is standing in, not the trunk the repository happens to have checked out
// somewhere else. Measured by the reference shim before it was fixed: four
// subagents, each in its own worktree on its own feature branch, all recorded
// `branch: main` — the ledger said every agent was working on the trunk while
// not one of them was, and `task_ref`, folded from the branch, was wrong in
// the same four rows.
//
// The one exception is the throwaway branch a harness's own worktree isolation
// creates; see throwawayPrefix.
func Branch(ctx context.Context, dir, main string) string {
	branch := branchAt(ctx, dir)
	if branch == "" || strings.HasPrefix(branch, throwawayPrefix) {
		branch = branchAt(ctx, main)
	}
	if branch == "" || branch == "HEAD" {
		return detached
	}
	return branch
}

// branchAt names the branch checked out in one worktree, or
// the empty string.
//
// symbolic-ref BEFORE rev-parse, and the order is load-bearing: on an UNBORN
// branch — a repository whose first commit has not been made — rev-parse fails
// and the branch would be recorded as detached, which is not a shrug in a log
// line but a wrong value in an append-only record. symbolic-ref reads the name
// HEAD points at whether or not anything is committed there yet.
func branchAt(ctx context.Context, dir string) string {
	if branch := line(
		exec.CommandContext(ctx, "git", "-C", dir, "symbolic-ref", "--short", "--quiet", "HEAD"),
	); branch != "" {
		return branch
	}
	return line(
		exec.CommandContext(ctx, "git", "-C", dir, "rev-parse", "--abbrev-ref", "HEAD"),
	)
}

// line runs one read-only git query and returns its output as
// a single trimmed line, or the empty string.
//
// A failure is not distinguished from an empty answer because the caller
// treats them the same: both mean "this tree names no branch", and the two
// fallbacks above are what decide what to do about that. The arguments are
// literal at every call site rather than assembled here, so nothing a caller
// supplies can reach git as a flag.
func line(cmd *exec.Cmd) string {
	raw, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// Task folds a branch name into doc 02 §5's identifier
// grammar, [a-z0-9][a-z0-9-]{0,62}.
//
// A branch name is not a task id: `dev/rm126-describe-workspace` is refused
// for the slash. An RM number is this project's own task identifier and is
// preferred wherever the branch carries one — the LAST one, which is what the
// reference shim's greedy match does and is asserted against it by MCP-043.
// Otherwise the branch is folded, and a branch that folds to nothing is named
// rather than left blank.
func Task(branch string) string {
	lower := asciiLower(branch)
	if found := rmTask.FindAllString(lower, -1); len(found) > 0 {
		return found[len(found)-1]
	}
	if folded := fold(lower); folded != "" {
		return folded
	}
	return unnamed
}

// asciiLower is `tr 'A-Z' 'a-z'`, byte for byte.
//
// Not strings.ToLower: that is Unicode-aware, so it can change a string's
// LENGTH, and this is a port whose agreement with the shell is asserted. Every
// byte outside the grammar is replaced below in any case, so nothing is lost
// by lowering only the twenty-six.
func asciiLower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// fold is the shell's four substitutions and its cut, in the
// order the shell applies them: every byte outside [a-z0-9-] becomes a hyphen,
// leading non-alphanumerics go, runs of hyphens collapse, trailing hyphens go,
// and what is left is bounded at 63 bytes. The order matters — the leading
// strip runs before the collapse — and the bound is applied last, exactly as
// `cut` is the last stage of the shell's pipeline.
func fold(lower string) string {
	var b strings.Builder
	b.Grow(len(lower))
	for i := range len(lower) {
		c := lower[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
			b.WriteByte(c)
		default:
			b.WriteByte('-')
		}
	}
	folded := strings.TrimLeft(b.String(), "-")
	for strings.Contains(folded, "--") {
		folded = strings.ReplaceAll(folded, "--", "-")
	}
	folded = strings.TrimRight(folded, "-")
	if len(folded) > taskBytes {
		folded = folded[:taskBytes]
	}
	return folded
}
