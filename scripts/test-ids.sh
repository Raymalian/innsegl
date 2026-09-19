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
# WHERE THE TEST LIST COMES FROM, and why that was the same bug one level
# along. It used to be read from Go alone — `func Test<PREFIX><NNN>` in
# `*_test.go`. A case whose test is a SHELL SELFTEST carried its id somewhere
# nothing here looked, so BAK-001..013 lived entirely in
# scripts/backup-ledger-selftest.sh and scripts/backup-service-selftest.sh, had
# no catalog row, and this exited 0 anyway: it cannot report a family it has no
# way to find. Measured 2026-09-19: 43 ids live in shell selftests, against the
# 127 Go-borne ones #265 taught it to see. RM-167 (#271).
#
# WHAT A SHELL CASE NAME LOOKS LIKE. The convention is already consistent, so
# this is a second discovery rule and not a new format. A case names its id
#   - at the head of a comment line, which is where the header block lists the
#     cases and where a section rule sits: `#   BAK-001  a backup of a chain`,
#     `# --- OPS-037 -------`, `# OPS-055 — the log's pin survives a worktree`
#   - at the start of the label it reports under: `ok "BAK-009 an unreachable`,
#     `echo "OPS-047 — no host scheduler"`, `expect 0 "BAK-001 clean dump"`
#   - in parentheses at the END of that label, which is the other house style:
#     `expect red 'a rename fails with no tag in the repository (SER-005)'`
#
# WHAT IT DELIBERATELY DOES NOT READ, because the looser rule is worse than the
# gap it leaves. An id named MID-SENTENCE is a CITATION, not a claim — the
# backup selftest mentions LED-003 to say which case it is not driving, and
# innsegl-commit's mentions OPS-039 as the half it cannot reach. A rule loose
# enough to catch those also reads `"task_ref":"JIRA-118"` out of a fixture
# payload and reports a JIRA family that does not exist: a gate red for
# something that is not a test at all, which is the failure #265 was about.
# Only `*-selftest.sh` is read for the same reason — a production script naming
# the case it satisfies (OPS-031 in scripts/teardown-guard.sh) is citing it.
# doc 07 records the four ids this costs. Selftest case 9 holds the line.
#
# AND NOT ITS OWN SELFTEST. scripts/test-ids-selftest.sh is the one
# `*-selftest.sh` in this tree whose ids are FIXTURES — ZZA and ZZB are planted
# so that a gate run against a fixture tree has something to find, and they are
# claims on nothing. Reading them here would turn this gate red on its own test
# data. The exclusion is by name and cannot hide a fixture case from the cases
# that need it: the selftest points INNSEGL_TEST_TREE at a temp tree whose
# selftests are named otherwise, and those are read exactly like any other.
#
# WHAT IT CANNOT SEE. Two DIFFERENT cases sharing one id, where both are
# catalogued, reads here as one id with several tests — which is also the normal
# and correct shape (REC-004 has five test functions, all facets of one case).
# Telling those apart needs a human who knows what the case is about. What this
# removes is the silent half: an id in code that the catalog has never heard of.
# The frontend is the remaining blind side: `*.test.tsx` is not read yet.
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

# A quote — either kind. Both open a case label, and which one a selftest uses
# is a matter of whether the label interpolates anything.
Q='["'"'"']'

# The three case-name shapes, in one place, so that adding a fourth is one edit
# rather than three. $1 is an ERE for the id: the whole grammar when the
# prefixes are being discovered, one family when a family is being counted.
# Each grep matches the SHAPE — the shape is the evidence that the id names a
# case — and the last one takes the bare id back out of what matched.
shell_case_ids() {
  _sci_id="$1"
  {
    # the head of a comment line: a header list entry, or a section rule
    grep -rhoE "^[[:space:]]*#[-[:space:]]*${_sci_id}"'([^0-9]|$)' \
      --include='*-selftest.sh' --exclude='test-ids-selftest.sh' "${ROOT}" 2>/dev/null
    # the start of the label the case reports under
    grep -rhoE "${Q}${_sci_id}[ :]" \
      --include='*-selftest.sh' --exclude='test-ids-selftest.sh' "${ROOT}" 2>/dev/null
    # or its end, parenthesised — the other house style
    grep -rhoE "[(]${_sci_id}[)]${Q}" \
      --include='*-selftest.sh' --exclude='test-ids-selftest.sh' "${ROOT}" 2>/dev/null
  } | grep -oE "${_sci_id}" | sort -u
}

# Prefixes are the UNION of all three sides. From the catalog, so a new section
# does not silently fall outside this; from the Go tests and from the shell
# selftests, so a family the catalog has never heard of is reported instead of
# skipped. Any side alone is blind in the others' direction, and it was the two
# code sides that were missing.
doc_prefixes="$(grep -ohE '^\| [A-Z]{2,5}-[0-9]{3}' "${DOC}" | sed 's/| //; s/-[0-9]*$//' | sort -u)"
# Exactly three digits: the trailing [^0-9] stops TestSHA2560... being read as
# prefix SHA, id 256. Nothing in the tree is named that way today; the guard is
# what keeps a future one from inventing a family.
code_prefixes="$(grep -rhoE "func Test[A-Z]{2,5}[0-9]{3}[^0-9]" --include='*_test.go' "${ROOT}" 2>/dev/null |
  sed 's/^func Test//; s/[0-9]\{3\}.$//' | sort -u)"
shell_prefixes="$(shell_case_ids '[A-Z]{2,5}-[0-9]{3}' | sed 's/-[0-9]\{3\}$//' | sort -u)"
prefixes="$(printf '%s\n%s\n%s\n' "${doc_prefixes}" "${code_prefixes}" "${shell_prefixes}" |
  grep . | sort -u)"

rc=0
for p in ${prefixes}; do
  case "${NOT_TEST_IDS}" in *" ${p} "*) continue ;; esac

  # "In the code" is both halves: a Go test function name, and a case name in a
  # shell selftest. A family can live entirely in one of them — BAK has no Go
  # test at all, and API no shell one — so reading either alone reports a whole
  # family as untested or, worse, does not report it.
  in_code="$({ grep -rhoE "func Test${p}[0-9]{3}[^0-9]" --include='*_test.go' "${ROOT}" 2>/dev/null |
    sed "s/^func Test${p}/${p}-/; s/.$//"
    shell_case_ids "${p}-[0-9]{3}"; } | sort -u)"
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

  # NO PROCESS SUBSTITUTION HERE. This used to be `comm -23 <(…) <(…)`, which
  # is a bashism: run as `sh scripts/test-ids.sh` — which is how the verify
  # sequence runs it — every iteration died on a syntax error, `orphan` came
  # back empty, and the gate reported "every id in the code has a catalog row"
  # on a tree full of orphans. A gate that is green because it crashed is the
  # failure this whole script is about. Measured 2026-09-19 (RM-167, #271).
  orphan=""
  for id in ${in_code}; do
    printf '%s\n' "${in_doc}" | grep -qx "${id}" && continue
    orphan="${orphan}${id}
"
  done
  orphan="$(printf '%s' "${orphan}" | grep . || true)"
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
