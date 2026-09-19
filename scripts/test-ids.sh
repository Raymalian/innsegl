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
# WHERE THE PREFIX LIST COMES FROM, and why that was the bug. It used to be
# read from the catalog alone: whatever `| XXX-nnn` rows doc 07 already had.
# A prefix the catalog had never heard of was therefore not reported as debt —
# it was not looked for at all. On 2026-09-19 that hid three whole families:
# API (22 ids in code), ALR (7) and PRI (4), plus CLI, HAR and INIT. The list
# is now the UNION of both sides, so a prefix that exists only in code is the
# loudest thing this prints rather than the one thing it cannot see. RM-161
# (#265). scripts/test-ids-selftest.sh holds that open.
#
# WHAT IT CANNOT SEE. Two DIFFERENT cases sharing one id, where both are
# catalogued, reads here as one id with several tests — which is also the normal
# and correct shape (REC-004 has five test functions, all facets of one case).
# Telling those apart needs a human who knows what the case is about. What this
# removes is the silent half: an id in code that the catalog has never heard of.
#
# USAGE
#   scripts/test-ids.sh [path-to-doc-07]
#
# INNSEGL_TEST_CATALOG   path to doc 07, if not the repository's own
# INNSEGL_TEST_TREE      tree to read test ids FROM, if not the repository. The
#                        selftest points both at a fixture; nothing else should.

set -uo pipefail

ROOT="${INNSEGL_TEST_TREE:-$(cd -- "$(dirname -- "$0")/.." && pwd -P)}"

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

# NOT A TEST-ID PREFIX. `RM` is this repository's ISSUE prefix, and three chaos
# tests are named after the issue that found the bug they pin —
# TestRM092PortRaceRealDockerReproduction is RM-092's reproduction, not a
# catalog id. Reading test ids from the code means reading that too, so the one
# prefix that can never be a test id is named here rather than catalogued as a
# case that does not exist. A row invented to quiet a gate is worse than no row.
NOT_TEST_IDS=" RM "

# Prefixes are the UNION of both sides. From the catalog, so a new section does
# not silently fall outside this; from the code, so a family the catalog has
# never heard of is reported instead of skipped. Either side alone is blind in
# one direction, and it was the code side that was missing.
doc_prefixes="$(grep -ohE '^\| [A-Z]{2,5}-[0-9]{3}' "${DOC}" | sed 's/| //; s/-[0-9]*$//' | sort -u)"
# Exactly three digits: the trailing [^0-9] stops TestSHA2560... being read as
# prefix SHA, id 256. Nothing in the tree is named that way today; the guard is
# what keeps a future one from inventing a family.
code_prefixes="$(grep -rhoE "func Test[A-Z]{2,5}[0-9]{3}[^0-9]" --include='*_test.go' "${ROOT}" 2>/dev/null |
  sed 's/^func Test//; s/[0-9]\{3\}.$//' | sort -u)"
prefixes="$(printf '%s\n%s\n' "${doc_prefixes}" "${code_prefixes}" | grep . | sort -u)"

rc=0
for p in ${prefixes}; do
  case "${NOT_TEST_IDS}" in *" ${p} "*) continue ;; esac

  in_code="$(grep -rhoE "func Test${p}[0-9]{3}[^0-9]" --include='*_test.go' "${ROOT}" 2>/dev/null |
    sed "s/^func Test${p}/${p}-/; s/.$//" | sort -u)"
  # RANGED ROWS ARE ROWS. doc 07 writes one row for a family of cases —
  # `| MCP-001..005 | C | Schema conformance per tool ...` covers five. A reader
  # that took only the first id reported the other four as uncatalogued, which
  # is how this script first claimed 75 orphans; the real number is smaller and
  # the difference was entirely its own parsing.
  in_doc="$(awk -v pre="${p}" '
    match($0, "^\\| " pre "-[0-9][0-9][0-9]\\.\\.[0-9][0-9][0-9]") {
      split(substr($0, RSTART + length(pre) + 3, RLENGTH), _x, "")
      line = substr($0, RSTART, RLENGTH)
      sub("^\\| " pre "-", "", line)
      split(line, r, "\\.\\.")
      for (i = r[1] + 0; i <= r[2] + 0; i++) printf "%s-%03d\n", pre, i
      next
    }
    match($0, "^\\| " pre "-[0-9][0-9][0-9]") {
      print substr($0, RSTART + 2, RLENGTH - 2)
    }' "${DOC}" | sort -u)"

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

  n_doc="$(printf '%s\n' "${in_doc}" | grep -c . || true)"
  if [ "${n_doc}" -eq 0 ]; then
    printf '\n%s: THE CATALOG HAS NO %s ROWS AT ALL — doc 07 has never heard of\n' "${p}" "${p}" >&2
    printf '  this family, so until now nothing here looked for it:\n' >&2
    printf '%s\n' "${orphan}" | sed 's/^/    /' >&2
    rc=1
  elif [ -n "${orphan}" ]; then
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
  printf '  %-5s %3d in code, %3d in doc 07\n' "${p}" \
    "$(printf '%s\n' "${in_code}" | grep -c . || true)" \
    "${n_doc}"
done

[ "${rc}" -eq 0 ] && printf '\ntest-ids: every id in the code has a catalog row\n'
exit "${rc}"
