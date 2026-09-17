#!/usr/bin/env sh
# SPDX-License-Identifier: Apache-2.0
#
# Where the transparency log's tree id is pinned, and when minting a new one is
# a mistake — RM-150 (#242).
#
# WHAT WENT WRONG. The pin lives in a GITIGNORED file, so a git worktree is a
# checkout that does not have it. `INNSEGL_REKOR_TLOG_ID` then fell back to its
# default of 0, which is the value that means MINT A NEW TREE, and bring-up run
# from a worktree silently re-pointed Rekor at an empty one. Measured on
# 2026-09-16: a log of 74 entries became a log of 1, and every commit ever
# signed answered `unavailable` for its inclusion proof.
#
# Nothing was lost — the old tree was still in the log database, which bring-up
# never recreates — but recoverable is not the same as safe. The failure is
# silent, it presents as every historical commit going unverifiable at once, and
# the obvious reading of that is that the log has been destroyed.
#
# THE FIX IS TWO RULES, and the second is the one that matters.
#
#   1. The pin is read from the REPOSITORY, not from whichever tree the command
#      runs in. scripts/repo-main-worktree.sh already answers "which tree is the
#      repository" for the link step (RM-148); this is the same question.
#
#   2. Minting is refused when a log already exists. Rule 1 alone would have
#      fixed the case that was hit, and left the class: any way of losing the
#      pin — a `git clean -x`, a fresh clone beside an existing deployment, a
#      restored home directory — puts 0 back in front of a live log. A pin is a
#      cache of a fact the deployment already holds; minting over it is only
#      ever right when there is no log yet, and that is checkable.
#
# USAGE
#   scripts/rekor-tlog-pin.sh path [repo]     print where the pin lives
#   scripts/rekor-tlog-pin.sh read [repo]     print the pinned id, or 0
#   scripts/rekor-tlog-pin.sh guard [repo]    refuse a silent mint; exit 3 if unsafe

set -u

HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
REL="deploy/compose/.rekor-tlog-id"

repo_of() {
  _d="${1:-.}"
  _main="$("${HERE}/repo-main-worktree.sh" "${_d}" 2>/dev/null)"
  # Not in a repository at all: fall back to the given directory rather than
  # refusing. This runs from a Makefile that may be invoked anywhere, and a pin
  # that cannot be located is a separate failure from a tree that cannot be.
  [ -n "${_main}" ] && printf '%s' "${_main}" || printf '%s' "${_d}"
}

pin_path() { printf '%s/%s' "$(repo_of "${1:-.}")" "${REL}"; }

case "${1:-}" in
  path) pin_path "${2:-.}" ;;

  read)
    _p="$(pin_path "${2:-.}")"
    if [ -s "${_p}" ]; then
      # One line, digits only. A pin that is anything else is not passed on:
      # Rekor would read it as a tree id and fail somewhere less obvious.
      _id="$(tr -dc '0-9' <"${_p}" | head -c 32)"
      [ -n "${_id}" ] && printf '%s\n' "${_id}" || printf '0\n'
    else
      printf '0\n'
    fi
    ;;

  guard)
    _repo="$(repo_of "${2:-.}")"
    _p="$(pin_path "${2:-.}")"
    [ -s "${_p}" ] && exit 0            # pinned: nothing to guard against

    # No pin. That is correct on a machine that has never run this, and
    # dangerous on one that has. The log database is the evidence: bring-up
    # never recreates it, so its presence means a tree already exists.
    _vol="${INNSEGL_TRUST_TRILLIAN_DB_VOLUME:-innsegl-trust-trillian-db}"
    if ! command -v docker >/dev/null 2>&1; then
      exit 0
    fi
    if ! docker volume inspect "${_vol}" >/dev/null 2>&1; then
      exit 0                            # no log yet: minting is right
    fi

    cat >&2 <<MSG
rekor-tlog-pin: REFUSING to mint a new transparency-log tree.

  There is no pin at
    ${_p}
  and the log's database volume (${_vol}) already exists, so this
  deployment already has a tree. Passing 0 would mint a SECOND one and point
  Rekor at it, and every commit ever signed here would answer "unavailable"
  for its inclusion proof. Nothing would be destroyed; everything would stop
  being findable, which reads the same from outside.

  The pin is gitignored, so the usual way to arrive here is a checkout that
  does not carry it — a git worktree, a fresh clone, or a \`git clean -x\`.

  If the repository at
    ${_repo}
  has the file, run from there, or copy it across. If the pin is genuinely
  lost, recover the id from the running log:

    make rekor-tlog-id

  and if there is no log to read it from, minting is correct — say so
  explicitly:

    INNSEGL_REKOR_ALLOW_NEW_TREE=1 make sigstore-up
MSG
    exit 3
    ;;

  *)
    sed -n '3,30p' "$0" | sed 's/^# \{0,1\}//' >&2
    exit 2
    ;;
esac
