#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Refuse a commit whose author or committer is a person.
#
# I6 says this repository has no GitHub contributor: agents commit, humans do
# not appear in attribution. The invariant was written about the CONTRIBUTOR
# GRAPH and nothing enforced the same rule on the author and committer fields of
# a commit object, which are the other place a name is published and the one
# that cannot be taken back.
#
# Measured on 2026-09-17 across 347 commits of this repository's history: seven
# distinct identities, of which two were an operator's real name — one of them
# against a real mail address. The mail address never reached the remote. The
# name is on `origin/main` and is there permanently: removing it re-hashes 57
# commits, and 33 of those carry an agent signature whose Rekor entry is bound
# to the SHA the rewrite would destroy. A commit is published the moment it is
# pushed and the log is append-only on purpose; there is no later fix. So the
# gate belongs BEFORE the commit, and nowhere else.
#
# AN ALLOWLIST, NEVER A DENYLIST, and that is not a preference. This repository
# is public. A denylist of forbidden identities would have to write the real
# name and the real mail address into a tracked file, publishing in the gate
# exactly what the gate exists to keep out — and it would still miss every name
# nobody thought of. An allowlist names only what is permitted, is safe to read
# by anyone, and fails closed on identities that do not exist yet.
#
# WHAT IS PERMITTED, and why each one:
#   *@innsegl.invalid              agents. .invalid is reserved by RFC 2606 and
#                                  can never be delivered to a person.
#   *@users.noreply.github.com     GitHub's per-account privacy address. It is
#                                  the account, not the human behind it, and
#                                  GitHub publishes it by design.
#   noreply@github.com             GitHub's own committer on a merge made
#                                  through the web interface.
# THE PERMITTED NAMES ARE NOT IN THIS FILE, and that is the second half of the
# same argument. An allowlist is safe to publish as a MECHANISM; a display name
# is not, whatever else is true about it. The first version of this gate held
# the operator's own name at this line, in a script bound for a public
# repository — closing the hole by publishing a smaller piece of it. The names
# live in an untracked file instead, so that widening the set for a second
# person cannot publish that person.
#
#   INNSEGL_ALLOWED_NAMES_FILE, or .innsegl/allowed-names beside this repository
#
# One entry per line; blank lines and # comments ignored. A MISSING OR EMPTY
# FILE REFUSES EVERY NAME rather than admitting every name: a gate whose
# configuration has gone missing must not silently become a pass. An entry that
# does not parse refuses too, for the same reason — a typo must not become a
# silently narrower allowlist.
#
# AN ENTRY IS EITHER A NAME OR A PINNED PAIR, in git's own identity syntax:
#
#   Innsegl                        a name admitted on any address this gate
#                                  otherwise admits. Agents need this: the local
#                                  part is minted per run and cannot be listed.
#   Fixture Alpha <a@b.example>    a PINNED PAIR. That address admits that name
#                                  and no other; that name is admitted on that
#                                  address and no other.
#
# THE PIN IS WHY THIS FILE CHANGED SHAPE. Measured on this repository on
# 2026-09-18: an operator's real name is the author AND the committer of four
# merge commits on origin/main, and the I6 gate in internal/signing was green
# throughout, because it admitted by ADDRESS ALONE. A flat list of names would
# not have caught it either — the name was on the list, it was simply on an
# address that had no business carrying it. The pair is what makes "this name,
# on this address" answerable.
#
# ONE RULE, ONE PLACE. internal/signing owns it: AuthorPolicy.Operators is a
# pair and CheckIdentity decides. This script cannot call that — it is POSIX sh
# so that it runs wherever git runs — so it CONSUMES the rule: the same syntax,
# the same file, the same fail-closed reading. doc 07 GH-005 drives the same
# identities through both halves and requires the same verdict, so the two
# cannot drift. Where they differ deliberately — this gate also holds a line on
# addresses internal/signing leaves unpinned, because here the name is free text
# in a git config — GH-005 records that as a decision.
#
# A name is allowed only if the set allows it. That is strict on purpose: a new
# name reaching a commit is the event this exists to catch, and answering "is
# this string a real person's name" is not something a script can do.
#
# USAGE
#   scripts/no-personal-identity.sh [repo]          the identity a commit would
#                                                   use here (the hook's path)
#   scripts/no-personal-identity.sh [repo] [range]  every commit in a range
#                                                   (CI, on what was pushed)
#   scripts/no-personal-identity.sh [repo] --audit   EVERY commit this repository
#                                                   can still reach, by any path
#
# THE AUDIT MODE EXISTS BECAUSE A REWRITE DOES NOT REMOVE ANYTHING. Measured on
# 2026-09-17: an earlier session rewrote a real mail address out of this history
# with `git filter-branch` and pushed the clean copy, and the address was still
# on this disk two weeks later. A commit object is immutable, so the rewrite
# built new objects and left the old ones anchored by refs nobody repointed —
# six stale branch tips and `refs/original/refs/heads/main`, which filter-branch
# writes as its own safety net and never removes. Thirteen commits carrying the
# address were reachable the whole time and nothing was looking, because every
# check in this repository asks about HEAD or about a push range.
#
# So the audit sweeps what those miss: every ref in refs/ rather than the three
# familiar namespaces, every reflog, and the unreachable objects that a delete
# leaves behind until a prune. It is the check that would have caught this.
#
# It checks a RANGE and not all of history because all of history is already
# red and cannot be made green: see the 57 commits above. A gate with an
# unexplained permanent failure is a gate people learn to ignore.

# POSIX sh, NOT bash. This repository sets core.hooksPath, so a hook runs
# wherever git runs — including the MCP's Alpine container, which has no bash.
# Measured the hard way on 2026-09-17: a `#!/usr/bin/env bash` gate broke every
# signed commit machine-wide with `env: can't execute 'bash'`. A gate that
# breaks signing is worse than the hole it closes.
set -u

ROOT="${1:-$(cd -- "$(dirname -- "$0")/.." && pwd -P)}"
RANGE="${2:-}"

# The permitted mail suffixes, one per line. Matched as a suffix so that the
# local part is free — every agent run mints its own.
ALLOWED_MAIL='@innsegl.invalid
@users.noreply.github.com
noreply@github.com'

# The permitted display names, read from outside the repository. See above.
NAMES_FILE="${INNSEGL_ALLOWED_NAMES_FILE:-$(cd -- "$(dirname -- "$0")/.." && pwd -P)/.innsegl/allowed-names}"

# US (0x1f) separates the fields of a parsed entry, for the reason the audit
# uses it below: a display name is text a person typed and may contain any
# printable character, so a printable separator could be forged into a second
# field and slip a name past the allowlist.
US="$(printf '\037')"

# Parse once, into one tagged line per entry:
#
#   P<US>address<US>name   a pinned pair
#   F<US>name              a name pinned to no address
#   E<US>the line          an entry that does not parse
#
# awk, not a shell loop, because --audit asks about every identity in the
# history and re-parsing the list per identity was what made the first batched
# audit take 14.7s. It is parsed here, once.
if [ -r "${NAMES_FILE}" ]; then
  ENTRIES="$(awk -v us="${US}" '
    { sub(/#.*/, ""); sub(/^[ \t]+/, ""); sub(/[ \t]+$/, "") }
    $0 == "" { next }
    index($0, "<") || index($0, ">") {
      if ($0 !~ /^[^<>]*[^ \t<>][ \t]*<[^<>@ \t]+@[^<>@ \t]+>$/) { print "E" us $0; next }
      addr = $0; sub(/^[^<]*</, "", addr); sub(/>$/, "", addr)
      name = $0; sub(/[ \t]*<[^<>]*>$/, "", name)
      print "P" us addr us name
      next
    }
    { print "F" us $0 }
  ' "${NAMES_FILE}" || true)"
else
  ENTRIES=""
fi

if [ -z "${ENTRIES}" ]; then
  printf 'refusing: no permitted-identity list at %s\n' "${NAMES_FILE}" >&2
  printf '  A gate whose configuration is missing refuses; it does not pass.\n' >&2
  printf '  One entry per line: a name, or `Name <address>`. Deliberately untracked.\n' >&2
  exit 1
fi

# An entry that does not parse refuses everything. The line itself is NOT
# echoed: it is a permitted identity, and this output reaches a CI log.
if printf '%s\n' "${ENTRIES}" | awk -v us="${US}" 'BEGIN { FS = us } $1 == "E" { found = 1 }
  END { exit found ? 0 : 1 }'; then
  _n="$(printf '%s\n' "${ENTRIES}" | awk -v us="${US}" 'BEGIN { FS = us } $1 == "E"' | wc -l)"
  printf 'refusing: %s has %s entr%s that will not parse.\n' \
    "${NAMES_FILE}" "$(printf '%s' "${_n}" | tr -d ' ')" \
    "$([ "$(printf '%s' "${_n}" | tr -d ' ')" = "1" ] && printf 'y' || printf 'ies')" >&2
  printf '  An entry is a name, or `Name <address>`. A list that cannot be read\n' >&2
  printf '  admits nothing rather than quietly admitting less than it says.\n' >&2
  exit 1
fi

PINNED="$(printf '%s\n' "${ENTRIES}" |
  awk -v us="${US}" 'BEGIN { FS = us; OFS = us } $1 == "P" { print $2, $3 }')"
PINNED_NAME="$(printf '%s\n' "${ENTRIES}" |
  awk -v us="${US}" 'BEGIN { FS = us } $1 == "P" { print $3 }')"
FREE_NAME="$(printf '%s\n' "${ENTRIES}" |
  awk -v us="${US}" 'BEGIN { FS = us } $1 == "F" { print $2 }')"

bad=0

# report prints one refusal. It deliberately echoes NEITHER the offending mail
# address NOR the offending display name: the gate's output lands in CI logs,
# which are as public as the repo, and printing either there would publish what
# the gate just stopped — the gate would become the leak. It does not print the
# PERMITTED name either, for the same reason: "expected X" republishes the list
# that is kept out of the repository on purpose. The role and the commit are
# enough to act on.
report() {
  printf '  %s %s: %s\n' "$1" "$2" "$3" >&2
  bad=1
}

check_ident() {
  # $1 role (author/committer), $2 name, $3 mail, $4 where
  _role="$1"; _name="$2"; _mail="$3"; _where="$4"

  _ok=0
  for _suffix in ${ALLOWED_MAIL}; do
    case "${_mail}" in *"${_suffix}") _ok=1 ;; esac
  done
  [ "${_ok}" -eq 1 ] || report "${_role}" "${_where}" "is not a permitted address"

  # Split on newline only, so a name with a space stays one field.
  _IFS="${IFS}"; IFS='
'
  # Is a name PINNED to this address? If so it is the only one admitted here,
  # and every other permitted name is refused — which is the case the address
  # allowlist alone could never see.
  _pinned=0; _pin=""
  for _entry in ${PINNED}; do
    case "${_entry}" in
      "${_mail}${US}"*) _pinned=1; _pin="${_entry#*${US}}" ;;
    esac
  done

  if [ "${_pinned}" -eq 1 ]; then
    [ "${_name}" = "${_pin}" ] ||
      report "${_role}" "${_where}" "is not the name pinned to this address"
  else
    _ok=0
    for _allowed in ${FREE_NAME}; do
      [ "${_name}" = "${_allowed}" ] && _ok=1
    done
    # A PINNED NAME IS PINNED. It is admitted on its own address and nowhere
    # else, or the pair would be a flat list again and the pin would say
    # nothing.
    for _allowed in ${PINNED_NAME}; do
      [ "${_name}" = "${_allowed}" ] && _ok=0
    done
    [ "${_ok}" -eq 1 ] ||
      report "${_role}" "${_where}" "is not a permitted name on this address"
  fi
  IFS="${_IFS}"
}

if [ "${RANGE}" = "--audit" ]; then
  # EVERYTHING THIS REPOSITORY CAN STILL REACH.
  #
  # `rev-list --all --reflog` covers every ref under refs/ — including the
  # namespaces nobody thinks to look in, such as refs/original — plus every
  # reflog entry, which is where a commit hides after its branch is deleted.
  # fsck then adds the objects that are already unreferenced but not yet pruned:
  # those are still on the disk and still readable by anyone with the SHA.
  _commits="$(
    { git -C "${ROOT}" rev-list --all --reflog 2>/dev/null
      git -C "${ROOT}" fsck --unreachable --no-progress 2>/dev/null |
        awk '$2 == "commit" { print $3 }'
    } | sort -u
  )"
  # ONE git PROCESS, NOT FOUR PER COMMIT. The first version asked git for each
  # field of each commit separately and took 14.7s over this history; a check
  # that slow is one that gets run once and then skipped. `--no-walk --stdin`
  # reads the whole list and prints every field in a single pass.
  #
  # The fields are separated by US (0x1f) rather than by a printable character,
  # because a display name is attacker-controlled text and may contain anything
  # a person can type — a name holding the separator would otherwise be read as
  # a different field and could slip past the allowlist.
  _US="$(printf '\037')"
  # THROUGH A FILE, NOT A PIPE, and that is load-bearing. In POSIX sh the right
  # side of a pipeline runs in a SUBSHELL, so a `bad=1` set inside a `while`
  # that is piped into would be discarded when the subshell exits. Measured on
  # 2026-09-17: the first version of this loop printed all four refusals and
  # then exited 0. A gate that reports a finding and still passes is worse than
  # no gate, because it is believed. Redirecting from a file keeps the loop in
  # this shell, where the variable it sets is the one that is read.
  _tmp="$(mktemp)" || { echo "cannot create a temporary file" >&2; exit 1; }
  trap 'rm -f "${_tmp}"' EXIT HUP INT TERM
  printf '%s\n' ${_commits} |
    git -C "${ROOT}" log --no-walk --stdin \
      --format="%H${_US}%an${_US}%ae${_US}%cn${_US}%ce" 2>/dev/null >"${_tmp}"
  while IFS="${_US}" read -r _c _an _ae _cn _ce; do
    [ -n "${_c}" ] || continue
    _where="$(printf '%s' "${_c}" | cut -c1-8)"
    check_ident author    "${_an}" "${_ae}" "${_where}"
    check_ident committer "${_cn}" "${_ce}" "${_where}"
  done <"${_tmp}"
elif [ -n "${RANGE}" ]; then
  # A range: every commit that is being added.
  for _c in $(git -C "${ROOT}" rev-list "${RANGE}" 2>/dev/null); do
    _an="$(git -C "${ROOT}" log -1 --format='%an' "${_c}")"
    _ae="$(git -C "${ROOT}" log -1 --format='%ae' "${_c}")"
    _cn="$(git -C "${ROOT}" log -1 --format='%cn' "${_c}")"
    _ce="$(git -C "${ROOT}" log -1 --format='%ce' "${_c}")"
    check_ident author    "${_an}" "${_ae}" "$(echo "${_c}" | cut -c1-8)"
    check_ident committer "${_cn}" "${_ce}" "$(echo "${_c}" | cut -c1-8)"
  done
else
  # No range: the identity a commit made HERE, RIGHT NOW would carry. This is
  # what the pre-commit hook asks, and it is the only question that can still
  # be answered before the fact. `git var` resolves the full precedence chain —
  # environment, then local config, then global — so it answers with what git
  # would actually write rather than with what one config file happens to say.
  _a="$(git -C "${ROOT}" var GIT_AUTHOR_IDENT 2>/dev/null)"
  _c="$(git -C "${ROOT}" var GIT_COMMITTER_IDENT 2>/dev/null)"
  # "Name <mail> 1700000000 +0000" -> name, mail
  check_ident author \
    "$(printf '%s' "${_a}" | sed 's/ <.*//')" \
    "$(printf '%s' "${_a}" | sed 's/.*<//; s/>.*//')" "this checkout"
  check_ident committer \
    "$(printf '%s' "${_c}" | sed 's/ <.*//')" \
    "$(printf '%s' "${_c}" | sed 's/.*<//; s/>.*//')" "this checkout"
fi

if [ "${bad}" -ne 0 ]; then
  cat >&2 <<'MSG'

refusing: a commit here would carry an identity this repository does not permit.

I6 keeps humans out of attribution, and a pushed commit cannot be unpublished —
rewriting one that is already signed orphans its Rekor entry. Both halves of the
author line are checked: the address, and the display name beside it. A name is
admitted on the address it is pinned to and on no other.

Set an identity this repository permits:

  git config user.name  "<the name pinned to the address below>"
  git config user.email "<account>@users.noreply.github.com"

The permitted ADDRESS SUFFIXES are at the top of this script. The permitted
NAMES are not, and never will be: a name in a tracked file is a published name.
Widening either is a deliberate edit, not a workaround. The list is at:
MSG
  printf '\n  %s\n' "${NAMES_FILE}" >&2
  exit 1
fi
