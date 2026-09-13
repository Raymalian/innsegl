# SPDX-License-Identifier: Apache-2.0
#
# THE FROZEN DERIVATION. Not part of any harness path, and not an example.
#
# This is `derive_task` as scripts/hooks/subagent-identity.sh carried it before
# RM-129 (#208) moved the derivation into `describe_workspace` (#205). It is
# kept for exactly one reason: MCP-043 compares the Go port against the shell it
# was ported from, and a port whose only specification is its author's reading
# of a deleted file is a port nothing can catch drifting.
#
# DO NOT COPY THIS INTO A SHIM. That is the whole point of E11: a second harness
# that folded its own task would put a different task in the ledger for the same
# branch, and nobody reading the record could explain why. A shim calls
# `describe_workspace` — one call, one answer, one derivation for every harness.
#
# DO NOT "FIX" IT EITHER. It is an oracle, so a change here is a change to what
# the port is measured against. Four field incidents are encoded in these rules
# and each is written down where it applies; if the rules must change, they
# change in internal/mcp/workspace.go and this file follows, never the reverse.
#
# It is sourced only when INNSEGL_HOOK_LIB is set, which no harness sets. It
# reads $CWD and sets BRANCH and TASK, which is all MCP-043 and the hook's own
# branch test read.

# branch_at names the branch checked out in one worktree, or the empty string.
#
# symbolic-ref BEFORE rev-parse, and the order is load-bearing: on an UNBORN
# branch -- a repository whose first commit has not been made -- rev-parse fails
# and the branch would be recorded as "detached", which is not a shrug in a log
# line but a wrong value in an append-only record. symbolic-ref reads the name
# HEAD points at whether or not anything is committed there yet.
branch_at() {
  _b="$(git -C "$1" symbolic-ref --short --quiet HEAD 2>/dev/null)"
  [ -n "$_b" ] || _b="$(git -C "$1" rev-parse --abbrev-ref HEAD 2>/dev/null)"
  printf '%s' "$_b"
}

# derive_task sets BRANCH from the agent's OWN worktree, and TASK from what that
# implies.
derive_task() {
  # `git worktree list` reports the main worktree first, from inside any linked
  # one, so MAIN resolves to the same path wherever this runs.
  MAIN="$(git -C "${CWD:-.}" worktree list --porcelain 2>/dev/null | awk '/^worktree /{print $2; exit}')"
  [ -n "$MAIN" ] || MAIN="${CWD:-.}"

  # THE BRANCH IS THE ONE THE AGENT IS ACTUALLY ON.
  #
  # doc 02 stores `branch` verbatim in an append-only record, so it has to be
  # the branch the agent's commits land on -- the branch of the worktree it is
  # standing in, not the trunk the repository happens to have checked out
  # somewhere else. Measured: four subagents, each in its own worktree on its
  # own feature branch, all registered `branch: main`.
  #
  # The one exception is a harness's OWN worktree isolation: it puts a subagent
  # in a throwaway branch named worktree-agent-<id> that nobody works on and
  # that is deleted with the agent, so recording it gave every agent its own
  # junk task where one shared task belonged. THAT shape, and only that shape,
  # falls back to the main worktree's branch.
  BRANCH="$(branch_at "${CWD:-.}")"
  case "$BRANCH" in
    worktree-agent-*|"") BRANCH="$(branch_at "$MAIN")" ;;
  esac
  # A genuinely detached HEAD has no branch, and "detached" is the honest answer
  # rather than a name: doc 02 stores `branch` verbatim, so inventing one would
  # put a branch in the ledger that does not exist.
  [ -n "$BRANCH" ] && [ "$BRANCH" != "HEAD" ] || BRANCH="detached"

  # A branch name is not a task_id: doc 02 §5 is [a-z0-9][a-z0-9-]{0,62} and a
  # branch carrying a slash is refused as it stands. An RM number is this
  # project's own task identifier and is preferred where the branch carries one;
  # otherwise the branch is folded into the grammar.
  TASK="$(printf '%s' "$BRANCH" | tr 'A-Z' 'a-z' | sed -n 's/.*\(rm[0-9][0-9]*\).*/\1/p')"
  if [ -z "$TASK" ]; then
    TASK="$(printf '%s' "$BRANCH" | tr 'A-Z' 'a-z' \
      | sed -e 's/[^a-z0-9-]/-/g' -e 's/^[^a-z0-9]*//' -e 's/--*/-/g' -e 's/-*$//' \
      | cut -c1-63)"
  fi
  [ -n "$TASK" ] || TASK="unnamed"
}
