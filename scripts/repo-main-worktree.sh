#!/usr/bin/env sh
# SPDX-License-Identifier: Apache-2.0
#
# Print the MAIN working tree of the repository a directory belongs to.
#
# RM-148 (#240). This exists because `git rev-parse --show-toplevel` answers a
# different question than the one the deployment asks. From inside a linked
# worktree it answers the WORKTREE, and bring-up used it to decide which
# directory to make signable — so bringing the stack up from a worktree made
# the worktree signable. The link is a single symlink that EVERY caller on the
# machine resolves through, so one wrong link did not break signing in that
# worktree; it broke signing everywhere, and surfaced later and elsewhere as a
# doubled path in an unrelated caller's error.
#
# `git worktree list` reports the main worktree FIRST from inside any linked
# one, which is the rule mainWorktreeOf uses in internal/mcp/commitcontext.go.
# One rule in one place, so the Makefile and the MCP cannot disagree about
# which tree is the repository.
#
# awk WITHOUT an early exit, deliberately. `head -1`, or awk's own `exit`,
# closes the pipe while git is still writing, and under `set -o pipefail` that
# turns a correct answer into a failure. Measured on 2026-09-16: the same
# mistake in a gate script reported a breach that did not exist, and it is
# machine-dependent, so it passes locally and fails in CI.
#
# USAGE
#   scripts/repo-main-worktree.sh [dir]
#
# Prints nothing and exits 1 when dir is not in a git repository, so a caller
# can tell "no answer" from an answer.

set -u

dir="${1:-.}"

[ -d "$dir" ] || exit 1

main="$(git -C "$dir" worktree list --porcelain 2>/dev/null |
  awk '/^worktree /{if(!f){print substr($0,10);f=1}}')"

[ -n "$main" ] || exit 1

# Physical, so a caller can compare it against its own `pwd -P` without one
# side carrying a symlink the other resolved.
( CDPATH= cd -- "$main" 2>/dev/null && pwd -P ) || exit 1
