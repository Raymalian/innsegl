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
# NESTED CHECKOUTS ARE NOT THIS TREE, and a plain walk of ROOT read three and
# four copies of every file. A linked worktree lives under `.worktrees` or
# `.claude/worktrees` in this repository and `docs/` is a repository of its own,
# so another branch's `web/src/components/common/AlertBanner.test.tsx` sat in
# the walk beside this branch's. Counting DISTINCT ids hid it completely — the
# copies collapse under `sort -u` — and it hid the reverse direction too: a
# test deleted on this branch still has a copy in a stale worktree, so the
# catalog row it left behind still reads as covered. It surfaced the moment a
# check that cares WHICH FILE claimed an id went red over forty families at
# once, measured 2026-09-19 (RM-177, #282). A nested checkout is a directory
# below ROOT holding a `.git` entry, which is a question a fixture tree with no
# git anywhere can still answer. Selftest case 17 holds it open.
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
# WHERE THE TEST LIST COMES FROM, THE THIRD TIME. `*.test.ts`, `*.test.tsx` and
# `*.pw.ts` under web/ were the remaining blind side: 99 ids live there, 69 of
# them with no catalog row, and this exited 0 over all 69. Same defect a third
# time — the prefix list was read from one place (#265), the test list from one
# language (#271), then from two. Each fix taught it one more place to look and
# none made it ask whether there was a fourth, so the fix this time is also the
# LANGUAGE REPORT it prints before anything else: a gate that lists what it
# looked at cannot silently not-look at a fifth thing, and a rule that has
# rotted shows up as a language reporting zero ids. RM-171 (#276).
#
# WHAT A FRONTEND CASE NAME LOOKS LIKE. Two shapes, not three, and the
# convention was already there to be read. A case names its id
#   - at the head of a comment line, which is where a file's header block
#     states what it drives and where a proposed row is written out:
#     `// FE-017 — navigation: the URL is the state`, `/*`, ` * FE-112 (NEW …`,
#     ` *   FE-070 | U | Overview supplies the header heartbeat …`
#   - at the start of the label the case reports under, in any of the three
#     quote styles: `describe("FE-019 the catalogue is complete…"`,
#     `test.describe("FE-009: axe pass, all six views"`, and the backticked
#     `` test.describe(`FE-001: tri-state … (${mode})` `` that a parameterised
#     Playwright suite needs.
#
# WHAT IT DELIBERATELY DOES NOT READ. The same citation line as the shell side,
# plus three the frontend adds:
#   - a FOUR-digit reference. `ADR-0038` is cited seventy times under web/src;
#     without the trailing non-digit guard every one reports a family `ADR`,
#     id 003, that does not exist.
#   - an id in an INDENTED comment inside a function body. The header
#     convention puts the marker at the head of the line, so an indented `//`
#     is a note about the code beside it. Measured 2026-09-19: reading indented
#     comment lines as well costs VER-006 and RM-050 as false claims and gains
#     no real id.
#   - a parenthesised citation CLOSING a label. This is where the two languages
#     genuinely differ, so the rule differs with them: shell's house style
#     closes a case label with `(SER-005)`, and the frontend's does not — its
#     one instance is `describe("FE-001 … is not a failure (VER-006)")`, whose
#     case is already named at the front, so reading the tail would claim
#     VER-006 as a frontend test.
# `node_modules` is excluded outright: a vendored package's own tests are not
# this repository's cases. Selftest case 12 holds all of that open.
#
# AND NOT ITS OWN SELFTEST. scripts/test-ids-selftest.sh is the one
# `*-selftest.sh` in this tree whose ids are FIXTURES — ZZA and ZZB are planted
# so that a gate run against a fixture tree has something to find, and they are
# claims on nothing. Reading them here would turn this gate red on its own test
# data. The exclusion is by name and cannot hide a fixture case from the cases
# that need it: the selftest points INNSEGL_TEST_TREE at a temp tree whose
# selftests are named otherwise, and those are read exactly like any other.
#
# ONE ID, TWO CASES — the half this now refuses, and the half it still cannot
# see. RM-177 (#282). Three ids each labelled two unrelated SHIPPED tests —
# FE-060, FE-061 and FE-062 — and this gate was green over all three, because
# it counts DISTINCT ids on both sides and both sides agreed. Two checks close
# what can be closed:
#   - ONE ID, TWO CATALOG ROWS. A row names one case, so a second row under the
#     same id — or a plain row swallowed by another row's `002..004` range —
#     leaves every reference to that id describing one of two cases with no way
#     to tell which. `sort -u` on the catalog side is what used to throw that
#     evidence away.
#   - ONE ID, TWO DECLARATIONS. The frontend's house style opens a case's file
#     with the row it PROPOSES for doc 07: `FE-060 (NEW — proposed for doc 07
#     TC-FE; see the report for #56)`. That header is a claim to DEFINE the id,
#     not to cite it, so two files declaring one id are two cases. Measured
#     2026-09-19 across the 42 declarations under web/: exactly FE-060, FE-061
#     and FE-062 are declared twice, and nothing else is.
#
# WHAT IS STILL NOT DECIDABLE, and why the obvious rule was refused. "The same
# id named as a case in two files" is NOT the shape of this bug. Measured the
# same day: 60 ids are named as a case in more than one file and all but three
# are one case with several facets — FE-019 is the shell's, the verification
# component's and the runs view's string catalogues, three files and one case,
# and REC-004 has five test functions. Narrowing it to the comment-head shape
# leaves seventeen, which is no better. A gate red over those would be red for
# something that is not a defect, which is the failure RM-161 was about. Two
# cases sharing an id where neither file declares it still needs a human who
# knows what the case is about. Selftest cases 14, 15 and 16 hold this open.
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

# THE ID GRAMMAR, once. Exactly three digits, and the trailing non-digit guard
# is what stops `TestSHA2560…` being read as prefix SHA id 256 and `ADR-0038`
# as prefix ADR id 003. The second of those is not hypothetical: ADR-0038 is
# cited seventy times under web/src.
ID='[A-Z]{2,5}-[0-9]{3}'

# A quote that opens a case label. The shell uses two; TypeScript adds the
# backtick, which is what a Playwright suite needs when its label interpolates
# the viewport or the colour scheme.
Q='["'"'"']'
TSQ='["'"'"'`]'

# A language's file shapes, held beside its rules so that the report below and
# the search cannot disagree about what was read.
SH_FILES="--include=*-selftest.sh --exclude=test-ids-selftest.sh"
TS_FILES="--include=*.test.ts --include=*.test.tsx --include=*.pw.ts --include=*.pw.tsx --exclude-dir=node_modules"

# --- this tree, and not the checkouts inside it ------------------------------
#
# See the header. Every search below therefore keeps grep's FILENAME — `-o`
# rather than `-ho` — so that these filters have a path to judge, and the id is
# taken back out of the matched text afterwards rather than out of the whole
# line, because a directory named after a case would otherwise claim one.
#
# THE LIST TRAVELS IN THE ENVIRONMENT, not in `awk -v`. One root per line is
# the only separator a filesystem path cannot itself contain, and `-v` reads
# its value as a string literal — a newline in it is `awk: newline in string`
# and every filter below silently passes nothing, which showed up as all three
# languages reporting zero ids. `ENVIRON` takes the value as it is.
INNSEGL_NESTED_CHECKOUTS="$(find "${ROOT}" -mindepth 2 -name node_modules -prune -o -name .git -print 2>/dev/null | sed 's#/\.git$##')"
export INNSEGL_NESTED_CHECKOUTS

# `path:text` on stdin, `text` out, nothing from a nested checkout.
own_matches() {
  awk '
    BEGIN { n = split(ENVIRON["INNSEGL_NESTED_CHECKOUTS"], root, "\n") }
    {
      i = index($0, ":")
      if (i == 0) next
      f = substr($0, 1, i - 1)
      for (j = 1; j <= n; j++)
        if (root[j] != "" && index(f, root[j] "/") == 1) next
      print substr($0, i + 1)
    }'
}

# A path per line in, the ones this tree owns out.
own_paths() {
  awk '
    BEGIN { n = split(ENVIRON["INNSEGL_NESTED_CHECKOUTS"], root, "\n") }
    {
      for (j = 1; j <= n; j++)
        if (root[j] != "" && index($0, root[j] "/") == 1) next
      print
    }'
}

# --- the three test languages ------------------------------------------------
#
# Each of these reads the WHOLE id grammar in one pass and hands back every id
# that language claims. Per-family counting then filters this list rather than
# re-walking the tree twenty-odd times, which is both faster and the only way
# the language report below can state an honest per-language total.

# Go: the test function's own name.
go_case_ids() {
  grep -roE "func Test[A-Z]{2,5}[0-9]{3}[^0-9]" --include='*_test.go' --exclude-dir=node_modules "${ROOT}" 2>/dev/null |
    own_matches |
    sed -E 's/^func Test([A-Z]{2,5})([0-9]{3}).*/\1-\2/' | sort -u
}

# Shell: the three case-name shapes, in one place, so that adding a fourth is
# one edit rather than three. Each grep matches the SHAPE — the shape is the
# evidence that the id names a case — and the last one takes the bare id back
# out of what matched.
shell_case_ids() {
  {
    # the head of a comment line: a header list entry, or a section rule
    # shellcheck disable=SC2086
    grep -roE "^[[:space:]]*#[-[:space:]]*${ID}"'([^0-9]|$)' ${SH_FILES} "${ROOT}" 2>/dev/null
    # the start of the label the case reports under
    # shellcheck disable=SC2086
    grep -roE "${Q}${ID}[ :]" ${SH_FILES} "${ROOT}" 2>/dev/null
    # or its end, parenthesised — the other house style
    # shellcheck disable=SC2086
    grep -roE "[(]${ID}[)]${Q}" ${SH_FILES} "${ROOT}" 2>/dev/null
  } | own_matches | grep -oE "${ID}" | sort -u
}

# TypeScript: two shapes, not three. The comment marker must sit at the HEAD of
# the line — the frontend's header convention puts it there, and an indented
# `//` inside a function body is a note about the code beside it. The
# parenthesised tail the shell reads is deliberately absent; see the header.
frontend_case_ids() {
  {
    # the head of a comment line: a file header block, or a proposed-row list
    # shellcheck disable=SC2086
    grep -roE "^(//|/\*|[ ]?\*)[-*[:space:]]*${ID}"'([^0-9]|$)' ${TS_FILES} "${ROOT}" 2>/dev/null
    # the start of the label the case reports under
    # shellcheck disable=SC2086
    grep -roE "${TSQ}${ID}[ :]" ${TS_FILES} "${ROOT}" 2>/dev/null
  } | own_matches | grep -oE "${ID}" | sort -u
}

# THE FRONTEND'S CASE DECLARATION, which is a narrower thing than a case name.
# A file that DRIVES a case opens with the row it proposes for doc 07 — `FE-060
# (NEW — proposed for doc 07 TC-FE; see the report for #56)`, `FE-105
# (proposed; doc 07 has no id for these — …)`. A file that merely names the same
# case, or cites a different one, does not: `FE-034 (components/common …)` and
# `FE-019 (the shell's catalogue …)` are references, and the parenthesis is
# what tells them apart. `proposed` inside it is therefore the whole rule, and
# `NEW — ` is admitted ahead of it because half the declarations in the tree
# are written that way. Emits `id file` per declaration; the caller looks for
# an id that two files declare.
frontend_declarations() {
  # shellcheck disable=SC2086
  grep -roE "^(//|/\*|[ ]?\*)[-*[:space:]]*${ID} [(](NEW[^)]*)?proposed" ${TS_FILES} "${ROOT}" 2>/dev/null |
    awk '
      BEGIN { n = split(ENVIRON["INNSEGL_NESTED_CHECKOUTS"], root, "\n") }
      {
        i = index($0, ":")
        if (i == 0) next
        f = substr($0, 1, i - 1)
        for (j = 1; j <= n; j++)
          if (root[j] != "" && index(f, root[j] "/") == 1) next
        rest = substr($0, i + 1)
        if (match(rest, "[A-Z][A-Z][A-Z]?[A-Z]?[A-Z]?-[0-9][0-9][0-9]"))
          print substr(rest, RSTART, RLENGTH) " " f
      }' | sort -u
}

go_ids="$(go_case_ids)"
shell_ids="$(shell_case_ids)"
fe_ids="$(frontend_case_ids)"
code_ids="$(printf '%s\n%s\n%s\n' "${go_ids}" "${shell_ids}" "${fe_ids}" | grep . | sort -u)"

# WHAT WAS SEARCHED, SAID OUT LOUD. Three times now this gate has been taught
# one more place to look — the catalog's prefixes (#265), shell selftests
# (#271), the frontend (#276) — and none of the three fixes made it ask whether
# there was a fourth. Printing the list is what stops that: a language whose
# rule has rotted reports zero, and a test language nobody taught it is a line
# that is missing from a list somebody is looking at. RM-171 (#276).
printf 'test-ids: three test languages searched, and the catalog\n'
printf '  %-11s %-46s %3d ids\n' \
  'Go'         '*_test.go — func Test<PREFIX><NNN>'             "$(printf '%s\n' "${go_ids}" | grep -c . || true)" \
  'shell'      '*-selftest.sh — case names'                     "$(printf '%s\n' "${shell_ids}" | grep -c . || true)" \
  'TypeScript' '*.test.ts, *.test.tsx, *.pw.ts — case names'    "$(printf '%s\n' "${fe_ids}" | grep -c . || true)"
printf '  %-11s %s\n' 'catalog' "$(basename "${DOC}") — the rows themselves"

# Prefixes are the UNION of all four sides. From the catalog, so a new section
# does not silently fall outside this; from each of the three languages, so a
# family the catalog has never heard of is reported instead of skipped. Any
# side alone is blind in the others' direction, and it was the code sides that
# were missing.
doc_prefixes="$(grep -ohE '^\| [A-Z]{2,5}-[0-9]{3}' "${DOC}" | sed 's/| //; s/-[0-9]*$//' | sort -u)"
code_prefixes="$(printf '%s\n' "${code_ids}" | grep . | sed 's/-[0-9]\{3\}$//' | sort -u)"
prefixes="$(printf '%s\n%s\n' "${doc_prefixes}" "${code_prefixes}" | grep . | sort -u)"

rc=0

# ONE ID, TWO DECLARATIONS. See the header. A frontend case opens its file with
# the row it proposes for doc 07, and that header DEFINES the id rather than
# citing it, so one id declared in two files is two cases wearing one name.
# This runs ahead of the per-family counts because it is invisible to them:
# both sides of such a collision are catalogued and counted, and the totals
# agree. RM-177 (#282).
declarations="$(frontend_declarations)"
for id in $(printf '%s\n' "${declarations}" | grep . | awk '{ print $1 }' | sort | uniq -d); do
  case "${NOT_TEST_IDS}" in *" ${id%-*} "*) continue ;; esac
  printf '\n%s: ONE ID, TWO CASES — declared as a proposed catalog row by more\n' "${id}" >&2
  printf '  than one test file. A row names one case, so a row for this id\n' >&2
  printf '  describes one of these and there is no way to tell which:\n' >&2
  printf '%s\n' "${declarations}" | awk -v want="${id}" '$1 == want { print "    " $2 }' >&2
  rc=1
done

for p in ${prefixes}; do
  case "${NOT_TEST_IDS}" in *" ${p} "*) continue ;; esac

  # "In the code" is all three languages. A family can live entirely in one of
  # them — BAK has no Go test at all, FE no Go and no shell one, and API
  # neither of the other two — so reading any one alone reports a whole family
  # as untested or, worse, does not report it.
  in_code="$(printf '%s\n' "${code_ids}" | grep -E "^${p}-[0-9]{3}\$" || true)"
  # RANGED ROWS ARE ROWS. doc 07 writes one row for a family of cases —
  # `| MCP-001..005 | C | Schema conformance per tool ...` covers five. A reader
  # that took only the first id reported the other four as uncatalogued, which
  # is how this script first claimed 75 orphans; the real number is smaller and
  # the difference was entirely its own parsing.
  #
  # ONE ROW PER LINE, AND NOT `sort -u` YET. A second row under an id another
  # row already names is exactly what uniqueness throws away, so the rows are
  # kept as they were read and deduplicated only for the comparisons below.
  in_doc_rows="$(awk -v pre="${p}" '
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
    }' "${DOC}")"
  in_doc="$(printf '%s\n' "${in_doc_rows}" | grep . | sort -u)"
  dup_doc="$(printf '%s\n' "${in_doc_rows}" | grep . | sort | uniq -d)"

  # THE REVERSE DIRECTION CANNOT LOOK ONLY FOR GO FUNCTIONS. Shell self-tests
  # carry their ids in comments and headings (OPS-040 lives in
  # worktree-link-selftest.sh), and the frontend's cases are TypeScript. A check
  # that searched for `func Test...` reported thirty FE rows as untested when
  # every one of them is a .test.tsx. So "has a test" is "the id appears
  # anywhere in the tree that is not the catalog itself".
  # `node_modules` is excluded here as it is in the discovery rules: a vendored
  # package that happens to contain the letters of one of our ids is not a test
  # for it, and walking it is most of this script's runtime.
  mentioned="$(grep -rlF "${p}-" "${ROOT}" --include='*.go' --include='*.sh' --include='*.ts' --include='*.tsx' --include='*.yml' --exclude-dir=node_modules 2>/dev/null | own_paths | head -400)"

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

  # ONE ID, TWO CATALOG ROWS. A ranged row counts as a row for every id it
  # expands to, so `| ZZA-002..004 |` beside a later `| ZZA-003 |` is caught
  # too: the second row is what makes the first one's sentence ambiguous,
  # whether it was written as a range or not.
  if [ -n "${dup_doc}" ]; then
    printf '\n%s: ONE ID, TWO CATALOG ROWS — a row names one case, so an id\n' "${p}" >&2
    printf '  with two of them describes one of two cases and there is no way\n' >&2
    printf '  to tell which:\n' >&2
    printf '%s\n' "${dup_doc}" | sed 's/^/    /' >&2
    rc=1
  fi

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
