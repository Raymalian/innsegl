#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# OPS-040 and OPS-041 — which tree bring-up makes signable, and the refusal
# that stops it being the wrong one.
#
# RM-148 (#240). `git rev-parse --show-toplevel` answers the tree you are
# STANDING IN, and bring-up used it to choose the directory to link. Run from
# inside a linked worktree it therefore linked the worktree. The link is one
# symlink that every caller on the machine resolves through, so the damage was
# never local: signing stopped for every caller, including from the main
# checkout, and the failure appeared later and elsewhere as a doubled path in
# somebody else's signing error. Hit twice on 2026-09-16.
#
# WHY A REFUSAL AS WELL AS A FIX. Bring-up is not the only caller of the link
# step; anything that passes DIR by hand can still name a worktree. The rule
# that picks the right tree and the rule that refuses the wrong one are both
# here, and case 4 is what keeps case 3 honest: a guard that refused every
# path would pass case 3 and be useless.
#
# USAGE
#   scripts/worktree-link-selftest.sh
#
# It needs bash, git and make. No Docker, no MCP, no network: every case exits
# before the link step reaches a container.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
RULE="$ROOT/scripts/repo-main-worktree.sh"

pass=0
fail=0

ok()   { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad()  { fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# A repository with one commit and an origin, and a linked worktree of it. The
# origin matters: the link step reads it before it reaches the guard, so a
# repository without one would be refused for the wrong reason.
REPO="$TMP/example-repo"
mkdir -p "$REPO"
git -C "$REPO" init -q
git -C "$REPO" config user.email "selftest@example.invalid"
git -C "$REPO" config user.name "selftest"
git -C "$REPO" remote add origin "git@github.com:example-org/example-repo.git"
: > "$REPO/seed"
git -C "$REPO" add seed
git -C "$REPO" commit -q -m seed --no-gpg-sign
git -C "$REPO" worktree add -q -b wt "$REPO/.worktrees/a"

REPO_P="$(cd "$REPO" && pwd -P)"
WT_P="$(cd "$REPO/.worktrees/a" && pwd -P)"

echo "OPS-040 — the rule picks the repository, wherever it is asked from"

# 1. From inside the linked worktree. This is the case that was wrong.
got="$("$RULE" "$WT_P")"
if [ "$got" = "$REPO_P" ]; then
  ok "a linked worktree resolves to its repository"
else
  bad "a linked worktree resolves to its repository" "got '$got', want '$REPO_P'"
fi

# 2. From the repository itself, which must not change.
got="$("$RULE" "$REPO_P")"
if [ "$got" = "$REPO_P" ]; then
  ok "the repository resolves to itself"
else
  bad "the repository resolves to itself" "got '$got', want '$REPO_P'"
fi

# 3. The old rule is what this replaces. Asserted so the case cannot quietly
#    stop being a case: if git ever made --show-toplevel answer the repository,
#    this file would be testing nothing and should say so.
old="$(git -C "$WT_P" rev-parse --show-toplevel)"
if [ "$old" != "$REPO_P" ]; then
  ok "git rev-parse --show-toplevel still answers the worktree (the bug is real)"
else
  bad "git rev-parse --show-toplevel still answers the worktree" \
      "it answered '$old'; this selftest no longer proves anything"
fi

# 4. Not a repository at all: no answer, and say so with a status.
if out="$("$RULE" "$TMP" 2>/dev/null)"; then
  bad "a directory outside any repository is refused" "it answered '$out'"
else
  ok "a directory outside any repository is refused"
fi

echo "OPS-041 — the link step refuses a worktree by name"

# 5. The refusal fires, names the repository, and names the command.
out="$(cd "$ROOT" && make --no-print-directory innsegl-link DIR="$WT_P" 2>&1)"
status=$?
if [ "$status" -eq 0 ]; then
  bad "linking a worktree is refused" "it succeeded"
elif ! printf '%s' "$out" | grep -q "is a linked worktree"; then
  bad "linking a worktree is refused" "refused, but not by the guard: $out"
elif ! printf '%s' "$out" | grep -q "DIR=$REPO_P"; then
  bad "the refusal names the repository to link instead" "$out"
else
  ok "linking a worktree is refused, naming the repository and the command"
fi

# 6. THE GUARD IS NOT REFUSING EVERYTHING. A plain repository must get PAST it;
#    it then fails further on for a different reason, which is what this asserts
#    on. Without this, case 5 would pass against a guard that refused every path.
out="$(cd "$ROOT" && make --no-print-directory innsegl-link DIR="$REPO_P" \
        INNSEGL_PROJECTS="$TMP" 2>&1)"
if printf '%s' "$out" | grep -q "is a linked worktree"; then
  bad "a plain repository gets past the guard" "the guard refused it: $out"
else
  ok "a plain repository gets past the guard"
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
