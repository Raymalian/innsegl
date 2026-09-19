#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Self-test for scripts/no-personal-identity.sh.
#
# The gate passes on this checkout now that the identity is set, which is
# exactly when a gate can be worthless. So each way a person's name or address
# can reach a commit is reproduced in a fixture and the gate is required to go
# red — and the identities this repository really uses are required to leave it
# green.
#
# Both modes are covered, because they answer different questions and only one
# of them runs at commit time: the no-range mode reads the identity this
# checkout WOULD commit with, and the range mode reads commits that already
# exist.
#
# NOTE ON THE FIXTURES. No fixture contains a real person's name or address.
# The strings below are invented, which is also the proof that the gate works by
# allowlist: it refuses them without ever having been told about them.
#
# AND THAT INCLUDES THE PERMITTED ONES. This file is tracked, so an identity
# written here is published — the exact thing the gate exists to stop. An
# earlier version of this selftest carried the operator's real display name as
# the fixture for "a permitted identity passes", which published a name in the
# course of testing that names are not published. Every permitted identity below
# is invented and is handed to the gate through INNSEGL_ALLOWED_NAMES_FILE.

set -uo pipefail

GATE="$(cd -- "$(dirname -- "$0")" && pwd -P)/no-personal-identity.sh"
pass=0; fail=0
ok()  { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; return 0; }

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

# An invented permitted set, in the syntax internal/signing defines: a bare name
# is admitted on any address the gate otherwise admits; `Name <address>` pins.
PINS="${TMP}/pinned-names"
cat >"${PINS}" <<'LIST'
# invented fixtures; no line here is a person
Innsegl
Fixture Alpha <12345+alpha@users.noreply.github.com>
Fixture Beta <67890+beta@users.noreply.github.com>
LIST

# EVERY case below reads this list unless it deliberately overrides it. The
# selftest must not depend on whatever the machine it runs on happens to
# permit: on a fresh checkout there is no list at all, and a gate that refuses
# everything would make every negative case pass for the wrong reason.
export INNSEGL_ALLOWED_NAMES_FILE="${PINS}"

# fixture NAME AUTHOR_NAME AUTHOR_EMAIL -> a repo with one commit by that identity
fixture() {
  d="${TMP}/$1"; mkdir -p "${d}"
  git -C "${d}" init -q
  git -C "${d}" config user.name "$2"
  git -C "${d}" config user.email "$3"
  printf 'x\n' >"${d}/f"
  git -C "${d}" add -A
  git -C "${d}" commit -q -m seed --no-gpg-sign
  printf '%s' "${d}"
}

# ---- no-range mode: the identity a commit here would carry --------------------

d="$(fixture agent    "Innsegl"    "agent@innsegl.invalid")"
"${GATE}" "${d}" >/dev/null 2>&1 && ok "an agent identity passes" \
  || bad "an agent identity passes" "$("${GATE}" "${d}" 2>&1 | head -2)"

# A GitHub account's noreply address, under the display name pinned to it.
d="$(fixture account "Fixture Alpha" "12345+alpha@users.noreply.github.com")"
"${GATE}" "${d}" >/dev/null 2>&1 \
  && ok "a pinned name on its own address passes" \
  || bad "a pinned name on its own address passes" \
       "$("${GATE}" "${d}" 2>&1 | head -2)"

# THE LEAK RM-159 CLOSED. The address is admitted and the display name is not
# the one pinned to it. The old gate saw the address, found it on the list, and
# passed — which is how a real name reached four merge commits on origin/main
# under a green CI gate.
d="$(fixture pinwrong "Someone Else" "12345+alpha@users.noreply.github.com")"
"${GATE}" "${d}" >/dev/null 2>&1 \
  && bad "a different name on a pinned address is refused" \
  || ok "a different name on a pinned address is refused"

# A PINNED NAME IS PINNED TO ONE ADDRESS. Otherwise the pairs collapse back into
# a flat list of names and the pin says nothing.
d="$(fixture pinelsewhere "Fixture Alpha" "67890+beta@users.noreply.github.com")"
"${GATE}" "${d}" >/dev/null 2>&1 \
  && bad "a pinned name on another operator's address is refused" \
  || ok "a pinned name on another operator's address is refused"

# A BARE NAME IS NOT ADMITTED ON A PINNED ADDRESS EITHER. An agent name is
# admitted where no pin applies; a pinned address admits its own name only.
d="$(fixture freeonpinned "Innsegl" "12345+alpha@users.noreply.github.com")"
"${GATE}" "${d}" >/dev/null 2>&1 \
  && bad "a bare permitted name is refused on a pinned address" \
  || ok "a bare permitted name is refused on a pinned address"

# And the bare name still works where nothing is pinned — the agent case, which
# cannot be pinned at all because the local part is minted per run.
d="$(fixture freeok "Innsegl" "run-7f3a@innsegl.invalid")"
"${GATE}" "${d}" >/dev/null 2>&1 \
  && ok "a bare permitted name passes on an unpinned address" \
  || bad "a bare permitted name passes on an unpinned address" \
       "$("${GATE}" "${d}" 2>&1 | head -2)"

# The leak that actually happened: a real mail address on a real name.
d="$(fixture realmail "Jane Q Person" "jane.person@example.com")"
"${GATE}" "${d}" >/dev/null 2>&1 && bad "a real mail address is refused" \
  || ok "a real mail address is refused"

# The leak that reached origin/main: the noreply address, but a person's name.
d="$(fixture realname "Jane Q Person" "12345+alpha@users.noreply.github.com")"
"${GATE}" "${d}" >/dev/null 2>&1 && bad "a person's name on a permitted address is refused" \
  || ok "a person's name on a permitted address is refused"

# A near-miss domain must not pass by suffix confusion.
d="$(fixture lookalike "Innsegl" "agent@evil-innsegl.invalid.example.com")"
"${GATE}" "${d}" >/dev/null 2>&1 && bad "a lookalike domain is refused" \
  || ok "a lookalike domain is refused"

# The committer is checked as well as the author — a commit carries both, and
# only checking the author would miss a rebase or an amend by someone else.
d="$(fixture committer "Innsegl" "agent@innsegl.invalid")"
GIT_COMMITTER_NAME="Jane Q Person" GIT_COMMITTER_EMAIL="jane@example.com" \
  git -C "${d}" commit -q --allow-empty -m second --no-gpg-sign
"${GATE}" "${d}" "HEAD~1..HEAD" >/dev/null 2>&1 && bad "a person as committer is refused" \
  || ok "a person as committer is refused"

# ---- range mode --------------------------------------------------------------

d="$(fixture rangeok "Innsegl" "agent@innsegl.invalid")"
git -C "${d}" commit -q --allow-empty -m second --no-gpg-sign
"${GATE}" "${d}" "HEAD~1..HEAD" >/dev/null 2>&1 && ok "a clean range passes" \
  || bad "a clean range passes" "$("${GATE}" "${d}" "HEAD~1..HEAD" 2>&1 | head -2)"

d="$(fixture rangebad "Innsegl" "agent@innsegl.invalid")"
GIT_AUTHOR_NAME="Jane Q Person" GIT_AUTHOR_EMAIL="jane@example.com" \
  git -C "${d}" commit -q --allow-empty -m second --no-gpg-sign
"${GATE}" "${d}" "HEAD~1..HEAD" >/dev/null 2>&1 && bad "a dirty range is refused" \
  || ok "a dirty range is refused"

# An empty range is not a pass by vacuity — it has nothing to refuse, and must
# not be mistaken for evidence that a range was checked.
d="$(fixture rangeempty "Innsegl" "agent@innsegl.invalid")"
"${GATE}" "${d}" "HEAD..HEAD" >/dev/null 2>&1 && ok "an empty range passes (nothing to judge)" \
  || bad "an empty range passes (nothing to judge)"

# ---- audit mode: what a rewrite leaves behind ---------------------------------
# These are the cases that actually happened on 2026-09-17 and that no other
# check in this repository asks about.

# A commit whose branch was DELETED is still in the reflog, and still readable.
d="$(fixture auditreflog "Innsegl" "agent@innsegl.invalid")"
git -C "${d}" checkout -q -b doomed
GIT_AUTHOR_NAME="Jane Q Person" GIT_AUTHOR_EMAIL="jane@example.com" \
  git -C "${d}" commit -q --allow-empty -m leak --no-gpg-sign
git -C "${d}" checkout -q -
git -C "${d}" branch -q -D doomed
"${GATE}" "${d}" >/dev/null 2>&1 \
  && ok "a deleted branch's commit is invisible to the commit-time check" \
  || bad "a deleted branch's commit is invisible to the commit-time check"
"${GATE}" "${d}" --audit >/dev/null 2>&1 \
  && bad "the audit finds a commit whose branch was deleted" \
  || ok "the audit finds a commit whose branch was deleted"

# filter-branch's own safety net. This is the exact ref that kept a real mail
# address on this disk for two weeks after the rewrite that removed it.
d="$(fixture auditoriginal "Innsegl" "agent@innsegl.invalid")"
GIT_AUTHOR_NAME="Jane Q Person" GIT_AUTHOR_EMAIL="jane@example.com" \
  git -C "${d}" commit -q --allow-empty -m leak --no-gpg-sign
leaked="$(git -C "${d}" rev-parse HEAD)"
git -C "${d}" update-ref refs/original/refs/heads/main "${leaked}"
git -C "${d}" reset -q --hard HEAD~1
"${GATE}" "${d}" --audit >/dev/null 2>&1 \
  && bad "the audit finds a commit held only by refs/original" \
  || ok "the audit finds a commit held only by refs/original"

# REGRESSION. The first batched audit printed every refusal and still exited 0,
# because a `while` on the right of a pipe runs in a subshell and the flag it
# set was thrown away. Reporting a finding and passing anyway is the worst
# failure a gate has, so the exit status is asserted separately from the output.
d="$(fixture auditexit "Innsegl" "agent@innsegl.invalid")"
GIT_AUTHOR_NAME="Jane Q Person" GIT_AUTHOR_EMAIL="jane@example.com" \
  git -C "${d}" commit -q --allow-empty -m leak --no-gpg-sign
out="$("${GATE}" "${d}" --audit 2>&1)"; rc=$?
if [ "${rc}" -ne 0 ] && printf '%s' "${out}" | grep -q 'not a permitted'; then
  ok "the audit's exit status agrees with its output"
else
  bad "the audit's exit status agrees with its output" "printed findings but exited ${rc}"
fi

# A clean repository must leave the audit green, or every case above passes by
# the audit simply always failing.
d="$(fixture auditclean "Innsegl" "agent@innsegl.invalid")"
"${GATE}" "${d}" --audit >/dev/null 2>&1 \
  && ok "a clean repository passes the audit" \
  || bad "a clean repository passes the audit" "$("${GATE}" "${d}" --audit 2>&1 | head -2)"

# ---- the gate must not publish what it refuses --------------------------------
# The whole reason this is an allowlist: a denylist would have to name the real
# identity in a tracked file in a public repository.
#
# THIS CHECK USED TO BE A DENYLIST ITSELF. It grepped the gate for a fragment of
# the operator's real mail address — writing that fragment into a tracked file
# in a public repository, which is the exact move the gate exists to refuse.
#
# It is BEHAVIOURAL now, which is the only form that can tell a fixture from a
# leak. A tracked file may contain something identity-SHAPED; the fixtures above
# do. What it may not contain is an identity the gate ADMITS. So every
# `Name <address>` written into a tracked half of the gate is put through the
# gate under this machine's real list, and every one of them has to be refused.
REAL_LIST="$(cd -- "$(dirname -- "${GATE}")/.." && pwd -P)/.innsegl/allowed-names"
SELF="$(cd -- "$(dirname -- "$0")" && pwd -P)/no-personal-identity-selftest.sh"
if [ -r "${REAL_LIST}" ]; then
  admitted=""; n=0
  while IFS= read -r ident; do
    [ -n "${ident}" ] || continue
    iname="${ident%%<*}"; iname="$(printf '%s' "${iname}" | sed 's/[[:space:]]*$//')"
    imail="${ident##*<}"; imail="${imail%>}"
    # An address with no name pins nothing, and git refuses an empty ident
    # name, so there is no fixture to drive. The gate rejects that entry at
    # parse time already.
    [ -n "${iname}" ] || continue
    n=$((n + 1))
    d="$(fixture "shaped${n}" "${iname}" "${imail}")"
    if (unset INNSEGL_ALLOWED_NAMES_FILE; "${GATE}" "${d}") >/dev/null 2>&1; then
      admitted="${admitted} ${imail}"
    fi
  done <<EOF
$(grep -ohE '[^[:space:]#/*][^<]*<[^@[:space:]>]+@[^[:space:]>]+>' "${GATE}" "${SELF}" | sort -u)
EOF
  if [ -n "${admitted}" ]; then
    bad "no identity written into the tracked gate is one the gate admits" \
        "admitted:${admitted}"
  else
    ok "no identity written into the tracked gate is one the gate admits (${n} checked)"
  fi
else
  bad "no identity written into the tracked gate is one the gate admits" \
      "no list at ${REAL_LIST}, so this could not be asked"
fi

# AND NOT THE PERMITTED ONES EITHER. An allowlist is safe to publish as a
# mechanism; a display name is not. The first version of this gate held the
# operator's own name in the script, which is a published name whatever else is
# true about it. The list now lives in an untracked file, and this asserts the
# tracked script has not quietly regained it.
NAMES_FILE="$(cd -- "$(dirname -- "${GATE}")/.." && pwd -P)/.innsegl/allowed-names"
if [ -r "${NAMES_FILE}" ]; then
  leaked=""
  while IFS= read -r n; do
    case "${n}" in ''|'#'*) continue ;; esac
    # Only human-shaped names matter here; the agent and bot identities are the
    # deployment's own and are named in the specs already.
    case "${n}" in Innsegl*|GitHub|'dependabot[bot]') continue ;; esac
    # Both tracked halves. The selftest is as published as the gate, and it is
    # where the real name actually was.
    for f in "${GATE}" "$(cd -- "$(dirname -- "$0")" && pwd -P)/no-personal-identity-selftest.sh"; do
      grep -qF "${n}" "${f}" && leaked="${leaked} $(basename "${f}")"
    done
  done <"${NAMES_FILE}"
  if [ -n "${leaked}" ]; then
    # The NAME is not printed. Saying which file is enough to act on; saying
    # which name would publish it a second time.
    bad "the tracked gate holds no permitted display name" "found in:${leaked}"
  else
    ok "the tracked gate holds no permitted display name"
  fi
  # And the list itself must never become tracked.
  if git -C "$(dirname -- "${NAMES_FILE}")/.." check-ignore -q "${NAMES_FILE}" 2>/dev/null; then
    ok "the permitted-name list is gitignored"
  else
    bad "the permitted-name list is gitignored" "it would ship"
  fi
else
  bad "the permitted-name list exists" "not readable at ${NAMES_FILE}"
fi

# A GATE WHOSE CONFIGURATION IS MISSING MUST REFUSE, NOT PASS. Losing the list
# is exactly when a gate is most likely to be trusted and least able to judge.
d="$(fixture nolist "Innsegl" "agent@innsegl.invalid")"
if INNSEGL_ALLOWED_NAMES_FILE=/nonexistent/allowed-names "${GATE}" "${d}" >/dev/null 2>&1; then
  bad "a missing name list refuses rather than passes"
else
  ok "a missing name list refuses rather than passes"
fi
d="$(fixture emptylist "Innsegl" "agent@innsegl.invalid")"
: >"${TMP}/empty-names"
if INNSEGL_ALLOWED_NAMES_FILE="${TMP}/empty-names" "${GATE}" "${d}" >/dev/null 2>&1; then
  bad "an empty name list refuses rather than passes"
else
  ok "an empty name list refuses rather than passes"
fi

# Comments and blank lines in the list are ignored, and a name is matched whole.
printf '# a comment\n\nInnsegl\n' >"${TMP}/tidy-names"
d="$(fixture tidylist "Innsegl" "agent@innsegl.invalid")"
INNSEGL_ALLOWED_NAMES_FILE="${TMP}/tidy-names" "${GATE}" "${d}" >/dev/null 2>&1 \
  && ok "comments and blank lines in the list are ignored" \
  || bad "comments and blank lines in the list are ignored"
d="$(fixture partial "Innseglx" "agent@innsegl.invalid")"
INNSEGL_ALLOWED_NAMES_FILE="${TMP}/tidy-names" "${GATE}" "${d}" >/dev/null 2>&1 \
  && bad "a name is matched whole, not as a prefix" \
  || ok "a name is matched whole, not as a prefix"

# AN ENTRY THAT DOES NOT PARSE REFUSES, for the reason an empty list does: a
# typo must not quietly become a narrower allowlist that nobody notices until
# the day it matters.
d="$(fixture badentry "Innsegl" "agent@innsegl.invalid")"
for broken in 'Fixture Alpha <>' '<12345+alpha@users.noreply.github.com>' 'A Name <a@b> tail'; do
  printf 'Innsegl\n%s\n' "${broken}" >"${TMP}/broken-names"
  if INNSEGL_ALLOWED_NAMES_FILE="${TMP}/broken-names" "${GATE}" "${d}" >/dev/null 2>&1; then
    bad "an unparseable entry refuses rather than passes" "passed on: ${broken}"
  else
    ok "an unparseable entry refuses rather than passes"
  fi
done

# ---- the refusal itself publishes nothing -------------------------------------
# The gate runs in CI, and a CI log is as public as the repository. Printing
# what it refused would make the gate the leak.

# Not the address.
d="$(fixture noechomail "Jane Q Person" "jane.person@example.com")"
if "${GATE}" "${d}" 2>&1 | grep -q 'jane.person@example.com'; then
  bad "the refusal does not echo the address" "it printed the address"
else
  ok "the refusal does not echo the address"
fi

# NOT THE NAME. This is the half RM-159 added: the gate used to print
# "\"<name>\" is not a permitted name", which published the display name it
# had just stopped.
d="$(fixture noechoname "Jane Q Person" "12345+alpha@users.noreply.github.com")"
if "${GATE}" "${d}" 2>&1 | grep -q 'Jane Q Person'; then
  bad "the refusal does not echo the name" "it printed the name it refused"
else
  ok "the refusal does not echo the name"
fi

# AND NOT THE PERMITTED NAME EITHER. "expected Fixture Alpha" would republish
# the list that is kept out of the repository on purpose.
if "${GATE}" "${d}" 2>&1 | grep -q 'Fixture Alpha'; then
  bad "the refusal does not echo the permitted name" "it printed the pinned name"
else
  ok "the refusal does not echo the permitted name"
fi

printf '\n  %d passed, %d failed\n' "${pass}" "${fail}"
[ "${fail}" -eq 0 ]
