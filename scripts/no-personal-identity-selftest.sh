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

set -uo pipefail

GATE="$(cd -- "$(dirname -- "$0")" && pwd -P)/no-personal-identity.sh"
pass=0; fail=0
ok()  { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; return 0; }

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

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

d="$(fixture account  "Kody Mike"  "66436734+KodyMike@users.noreply.github.com")"
"${GATE}" "${d}" >/dev/null 2>&1 && ok "the account's noreply address passes" \
  || bad "the account's noreply address passes" "$("${GATE}" "${d}" 2>&1 | head -2)"

# The leak that actually happened: a real mail address on a real name.
d="$(fixture realmail "Jane Q Person" "jane.person@example.com")"
"${GATE}" "${d}" >/dev/null 2>&1 && bad "a real mail address is refused" \
  || ok "a real mail address is refused"

# The leak that reached origin/main: the noreply address, but a person's name.
d="$(fixture realname "Jane Q Person" "66436734+KodyMike@users.noreply.github.com")"
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
if grep -qiE 'irfan|@gmail\.com' "${GATE}"; then
  bad "the gate names no real personal identity" "the gate contains one"
else
  ok "the gate names no real personal identity"
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
    grep -qF "${n}" "${GATE}" && leaked="${leaked} ${n}"
  done <"${NAMES_FILE}"
  if [ -n "${leaked}" ]; then
    bad "the tracked gate holds no permitted display name" "found:${leaked}"
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

# Its refusal output must not echo the address either — CI logs are public.
d="$(fixture noecho "Jane Q Person" "jane.person@example.com")"
if "${GATE}" "${d}" 2>&1 | grep -q 'jane.person@example.com'; then
  bad "the refusal does not echo the address" "it printed the address"
else
  ok "the refusal does not echo the address"
fi

printf '\n  %d passed, %d failed\n' "${pass}" "${fail}"
[ "${fail}" -eq 0 ]
