#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Every test id in the code is in doc 07, and every id in doc 07 has a test.
#
# WHY THIS IS NOT A CI GATE, and that is not an oversight. doc 07 is one of the
# eight numbered specs, and those are local only — `docs/*` is gitignored and
# never pushed, so a CI runner has no catalog to check against. This is a
# maintainer's command, run where the documents are.
#
# WHY IT EXISTS AT ALL. #167 and #169 both say it: "nothing in this repository
# enforces test-ID uniqueness, and three collisions have already been caught by
# hand this week." Three more were caught by hand on 2026-09-17 — REC-009, 010
# and 011 were about to be assigned to a second, unrelated set of cases while
# the rebase tests already held them, and the reason nobody noticed is that
# those three had no catalog row to collide with. Both halves of that are what
# this reports.
#
# WHAT IT CANNOT SEE. Two DIFFERENT cases sharing one id, where both are
# catalogued, reads here as one id with several tests — which is also the normal
# and correct shape (REC-004 has five test functions, all facets of one case).
# Telling those apart needs a human who knows what the case is about. What this
# removes is the silent half: an id in code that the catalog has never heard of.
#
# USAGE
#   scripts/test-ids.sh [path-to-doc-07]

set -uo pipefail

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"

# The catalog lives in the REPOSITORY, not in whichever tree this ran from.
# docs/* is gitignored, so a git worktree does not carry it — the same shape as
# RM-148's link and RM-150's log pin, and the same answer: ask which tree is the
# repository. Found by running this from a worktree and getting "no catalog".
CATALOG_REPO="$("$(dirname -- "$0")/repo-main-worktree.sh" "${ROOT}" 2>/dev/null || printf '%s' "${ROOT}")"
DOC="${1:-${INNSEGL_TEST_CATALOG:-${CATALOG_REPO}/docs/07-innsegl-test-catalog.md}}"

if [ ! -f "${DOC}" ]; then
  printf 'test-ids: no catalog at %s\n' "${DOC}" >&2
  printf '  doc 07 is local only (docs/* is gitignored), so this runs where the\n' >&2
  printf '  documents are. Pass the path, or set INNSEGL_TEST_CATALOG.\n' >&2
  exit 2
fi

# Prefixes doc 07 actually uses, read from the catalog rather than hardcoded, so
# a new section does not silently fall outside this.
prefixes="$(grep -ohE '^\| [A-Z]+-[0-9]{3}' "${DOC}" | sed 's/| //; s/-[0-9]*$//' | sort -u)"

rc=0
for p in ${prefixes}; do
  in_code="$(grep -rhoE "func Test${p}[0-9]{3}" --include='*_test.go' "${ROOT}" 2>/dev/null |
    sed "s/func Test${p}/${p}-/" | sort -u)"
  in_doc="$(grep -ohE "^\| ${p}-[0-9]{3}" "${DOC}" | sed 's/| //' | sort -u)"

  # THE REVERSE DIRECTION CANNOT LOOK ONLY FOR GO FUNCTIONS. Shell self-tests
  # carry their ids in comments and headings (OPS-040 lives in
  # worktree-link-selftest.sh), and the frontend's cases are TypeScript. A check
  # that searched for `func Test...` reported thirty FE rows as untested when
  # every one of them is a .test.tsx. So "has a test" is "the id appears
  # anywhere in the tree that is not the catalog itself".
  mentioned="$(grep -rlF "${p}-" "${ROOT}" --include='*.go' --include='*.sh' --include='*.ts' --include='*.tsx' --include='*.yml' 2>/dev/null | head -400)"

  orphan="$(comm -23 <(printf '%s\n' "${in_code}") <(printf '%s\n' "${in_doc}") | grep . || true)"
  unused=""
  for id in ${in_doc}; do
    printf '%s\n' "${in_code}" | grep -qx "${id}" && continue
    printf '%s\n' "${mentioned}" | xargs -r grep -lF "${id}" 2>/dev/null | head -1 | grep -q . && continue
    unused="${unused}${id}
"
  done
  unused="$(printf '%s' "${unused}" | grep . || true)"

  if [ -n "${orphan}" ]; then
    printf '\n%s: in the code, NOT in doc 07 — an id with no catalog row is an id\n' "${p}" >&2
    printf '  the next person can reassign without a collision to notice:\n' >&2
    printf '%s\n' "${orphan}" | sed 's/^/    /' >&2
    rc=1
  fi
  if [ -n "${unused}" ]; then
    printf '\n%s: in doc 07, NO test in the code:\n' "${p}" >&2
    printf '%s\n' "${unused}" | sed 's/^/    /' >&2
    printf '  Either the case is not built yet — which doc 07 records deliberately —\n' >&2
    printf '  or its test was renamed out from under the catalog.\n' >&2
  fi
  printf '  %-4s %3d in code, %3d in doc 07\n' "${p}" \
    "$(printf '%s\n' "${in_code}" | grep -c . || true)" \
    "$(printf '%s\n' "${in_doc}" | grep -c . || true)"
done

[ "${rc}" -eq 0 ] && printf '\ntest-ids: every id in the code has a catalog row\n'
exit "${rc}"
