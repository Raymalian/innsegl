#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Self-test for scripts/no-published-specs.sh.
#
# The gate passes on this repository and is meant to, which is exactly when a
# gate can be worthless. So each way a spec can become tracked is reproduced in
# a fixture and the gate is required to go red — and the ADRs, which ship on
# purpose, are required to leave it green.
#
# The two bypasses are the ones measured on 2026-09-17 against the real
# repository: `git add -f`, and un-ignoring `docs/*` and adding everything.

set -uo pipefail

GATE="$(cd -- "$(dirname -- "$0")" && pwd -P)/no-published-specs.sh"
pass=0; fail=0
ok()  { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; return 0; }

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

fixture() {
  d="${TMP}/$1"; mkdir -p "${d}/docs/adr" "${d}/scripts"
  git -C "${d}" init -q
  git -C "${d}" config user.email "selftest@example.invalid"
  git -C "${d}" config user.name "selftest"
  printf 'docs/*\n!docs/adr/\n' >"${d}/.gitignore"
  printf '# the threat model\nwhere the keys live\n' >"${d}/docs/04-threat-model.md"
  printf '# ADR-0001\n' >"${d}/docs/adr/0001-a.md"
  printf 'x\n' >"${d}/scripts/thing.sh"
  git -C "${d}" add -A
  git -C "${d}" commit -q -m seed --no-gpg-sign
  printf '%s' "${d}"
}

d="$(fixture clean)"
if "${GATE}" "${d}" >/dev/null 2>&1; then
  ok "a repository with only ADRs tracked passes"
else
  bad "a repository with only ADRs tracked passes" "$("${GATE}" "${d}" 2>&1 | head -3)"
fi

# The ADRs must really be there, or the case above passes by having nothing.
n="$(git -C "${d}" ls-files -- 'docs/adr/' | grep -c .)"
[ "${n}" -ge 1 ] && ok "and it really does ship an ADR (${n})" \
  || bad "and it really does ship an ADR" "none tracked; the clean case proves nothing"

# BYPASS 1 — force-add.
d="$(fixture forceadd)"
git -C "${d}" add -f docs/04-threat-model.md 2>/dev/null
out="$("${GATE}" "${d}" 2>&1)"; rc=$?
if [ "${rc}" -ne 0 ] && printf '%s' "${out}" | grep -q "04-threat-model"; then
  ok "git add -f of a spec is caught, and names it"
else
  bad "git add -f of a spec is caught, and names it" "exit ${rc}: $(printf '%s' "${out}" | head -2)"
fi

# BYPASS 2 — un-ignore, then add everything.
d="$(fixture unignore)"
printf '!docs/adr/\n' >"${d}/.gitignore"
git -C "${d}" add -A 2>/dev/null
out="$("${GATE}" "${d}" 2>&1)"; rc=$?
if [ "${rc}" -ne 0 ] && printf '%s' "${out}" | grep -q "04-threat-model"; then
  ok "un-ignoring docs and adding everything is caught"
else
  bad "un-ignoring docs and adding everything is caught" "exit ${rc}: $(printf '%s' "${out}" | head -2)"
fi

# COMMITTED, not merely staged — the state a push would carry.
d="$(fixture committed)"
git -C "${d}" add -f docs/04-threat-model.md 2>/dev/null
git -C "${d}" commit -q -m "publish a spec" --no-gpg-sign
out="$("${GATE}" "${d}" 2>&1)"; rc=$?
[ "${rc}" -ne 0 ] && ok "a spec already committed is caught" \
  || bad "a spec already committed is caught" "exit ${rc} — this is the state a push carries"

# And docs/decisions/, which is where working notes live.
d="$(fixture decisions)"
mkdir -p "${d}/docs/decisions"
printf 'hosting choice and why\n' >"${d}/docs/decisions/note.md"
git -C "${d}" add -f docs/decisions/note.md 2>/dev/null
out="$("${GATE}" "${d}" 2>&1)"; rc=$?
[ "${rc}" -ne 0 ] && ok "docs/decisions/ is caught too" \
  || bad "docs/decisions/ is caught too" "exit ${rc} — these carry vendor and hosting reasoning"

# THE CONTROL THAT KEEPS THE REST HONEST: adding an ADR must NOT fire, or the
# gate would refuse the one directory that is supposed to ship.
d="$(fixture adr)"
printf '# ADR-0002\n' >"${d}/docs/adr/0002-b.md"
git -C "${d}" add -A 2>/dev/null
if "${GATE}" "${d}" >/dev/null 2>&1; then
  ok "adding an ADR does NOT fire"
else
  bad "adding an ADR does NOT fire" "the gate refuses the one docs directory that ships"
fi

printf '\n%d passed, %d failed\n' "${pass}" "${fail}"
[ "${fail}" -eq 0 ]
