#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# scripts/test-ids.sh, watched going red — and red for the right reason.
#
# RM-161 (#265). The gate had been red for so long that its exit code carried
# no information: 127 ids existed in code with no catalog row, so "exit 1" was
# the only answer anyone had ever seen from it. Bringing the catalog level
# makes exit 0 mean something again — and immediately raises the opposite
# question, which is the one this answers. A gate that has been green once and
# CANNOT GO RED AGAIN is the same failure in the other direction, and it is the
# harder one to notice, because nothing ever prints.
#
# WHAT THE BUG ACTUALLY WAS. The prefix list was read from the catalog alone.
# An id whose prefix doc 07 already knew was reported as debt; an id whose
# prefix doc 07 had never heard of was not looked for at all. Six whole
# families were invisible that way — API (22 ids), ALR (7), PRI (4), CLI, HAR
# and INIT. Case 4 is that bug, planted: the fixture's catalog knows one
# prefix, the fixture's code carries two. Against the old gate case 4 exits 0,
# measured 2026-09-19 by running the previous revision of the gate against this
# fixture.
#
# WHY CASE 5 EXISTS. A guard that reported EVERY prefix as uncatalogued would
# pass cases 3 and 4 and be worthless. Case 5 gives the gate a clean fixture
# and requires silence, so the red cases are red on merit.
#
# WHY CASE 6 EXISTS. `RM` is the repository's ISSUE prefix and three chaos
# tests are named after the issue they pin, not after a catalog id. The gate
# names it as not-a-test-id. That exclusion is a hole by construction, so it is
# asserted here rather than trusted: case 6 plants an RM-named test and
# requires the gate to stay green, and case 4 — a DIFFERENT code-only prefix
# that must go red — is what stops the hole widening into "ignore everything".
#
# WHY CASES 7, 8 AND 9 EXIST. RM-167 (#271). The gate read its TEST list from
# Go alone — `func Test<PREFIX><NNN>` in `*_test.go` — so a case whose test is a
# shell selftest was invisible to it. BAK-001..013 lived entirely in
# scripts/backup-*-selftest.sh, had no catalog row, and the gate exited 0
# anyway: the same failure as the prefix list, one level along. Case 7 is an id
# in a shell case name under a prefix the catalog knows; case 8 is a whole
# family that exists only in shell. Both are the exit 0, planted.
#
# WHY CASE 9 IS THE EXPENSIVE ONE. Reading ids out of shell means reading prose,
# and the loose rule is worse than the gap. A rule that catches every id in a
# selftest also reads `"task_ref":"JIRA-118"` out of a fixture payload and
# reports a JIRA family that does not exist — a gate red for something that is
# not a test at all, which is the failure RM-161 was about. So only the three
# CASE-NAME shapes count, and case 9 plants one of each near-miss: a payload
# that merely quotes an id, a citation mid-sentence, a citation in parentheses
# that is not a label's, and a production script naming the case it satisfies.
# All four must stay invisible, and the gate must stay green over them.
#
# WHY THE FIXTURE IDS ARE ZZA AND ZZB. The gate's reverse check reads every
# `.sh` in the tree looking for a catalogued id, so a fixture written with real
# prefixes would let THIS FILE stand in as the missing test for a real row and
# silence a true report. Two prefixes nothing else uses cost nothing and cannot
# do that. Reading CASE NAMES out of `*-selftest.sh` gave that the other
# direction — this file is one — so the gate skips its own selftest by name and
# says so. The cases below are unaffected: they build `*-selftest.sh` files
# under the fixture tree, named otherwise, which the gate reads normally.
#
# USAGE
#   scripts/test-ids-selftest.sh
#
# It needs bash and the gate. No git, no Docker, no network, no catalog: every
# case builds its own fixture tree and its own doc 07 under a temp directory,
# and the real docs/ is never read.

set -uo pipefail

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
GATE="${ROOT}/scripts/test-ids.sh"

pass=0
fail=0
ok()  { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/innsegl-test-ids-selftest.XXXXXX")"
trap 'rm -rf "${TMP}"' EXIT

# A fixture catalog in doc 07's shape: a heading, a header row, a plain row and
# a RANGED row. The range is here because the gate's awk expands a `002..004`
# row into three ids, and that expansion is the difference between this
# reporting two orphans and reporting none.
CATALOG="${TMP}/catalog.md"
cat > "${CATALOG}" <<'MD'
# fixture catalog

## TC-ZZA — a family that exists only in this fixture

| ID | L | Case | Expected | Proves |
|---|---|---|---|---|
| ZZA-001 | U | Append one event | It is appended | I3 |
| ZZA-002..004 | U | A family written as one row | All three covered | I4 |
| ZZA-009 | F | A case with no test yet | Recorded deliberately, not built | I3 |
MD

# The fixture tree. Every case adds to or removes from this.
TREE="${TMP}/tree"
mkdir -p "${TREE}/internal/alpha"
cat > "${TREE}/internal/alpha/alpha_test.go" <<'GO'
package alpha

import "testing"

func TestZZA001Append(t *testing.T)        { _ = t }
func TestZZA002Chain(t *testing.T)         { _ = t }
func TestZZA003ChainAgain(t *testing.T)    { _ = t }
func TestZZA004ChainOnceMore(t *testing.T) { _ = t }
GO

run_gate() {
  INNSEGL_TEST_TREE="${TREE}" "${GATE}" "${CATALOG}" 2>&1
}

echo "test-ids-selftest: nine cases"
echo
echo "the fixture is level to start with"

# 1. GREEN ON MERIT. Four ids in code, four rows in the catalog — one of them a
#    range. ZZA-009 has a row and no test, which doc 07 records deliberately and
#    the gate reports without failing.
out="$(run_gate)"; status=$?
if [ "${status}" -ne 0 ]; then
  bad "a level fixture exits 0" "exit ${status}: ${out}"
elif ! printf '%s' "${out}" | grep -q 'every id in the code has a catalog row'; then
  bad "a level fixture exits 0" "exit 0 but said nothing: ${out}"
else
  ok "a level fixture exits 0 — the ranged row ZZA-002..004 covers all three"
fi

# 2. A ROW IN THE CATALOG WITH NO TEST IS NOT A FAILURE. It is the deliberate
#    record of a case not built yet, and the gate must say so without going red,
#    or every planned case would have to be deleted to keep the gate usable.
if ! printf '%s' "${out}" | grep -q 'ZZA-009'; then
  bad "a catalogued id with no test is reported" "ZZA-009 was not mentioned: ${out}"
elif ! printf '%s' "${out}" | grep -q 'in doc 07, NO test in the code'; then
  bad "a catalogued id with no test is reported" "reported, but not as that: ${out}"
else
  ok "a catalogued id with no test is reported and does NOT fail the gate"
fi

echo
echo "an id added in code with no row turns it red"

# 3. THE HALF THAT ALWAYS WORKED. A new id under a prefix the catalog already
#    knows. Kept because it is the case the fix must not break.
cat > "${TREE}/internal/alpha/extra_test.go" <<'GO'
package alpha

import "testing"

func TestZZA077SomethingNew(t *testing.T) { _ = t }
GO
out="$(run_gate)"; status=$?
if [ "${status}" -eq 0 ]; then
  bad "an uncatalogued id under a KNOWN prefix turns the gate red" "it exited 0: ${out}"
elif ! printf '%s' "${out}" | grep -q 'ZZA-077'; then
  bad "an uncatalogued id under a KNOWN prefix turns the gate red" "red, but did not name it: ${out}"
else
  ok "an uncatalogued id under a KNOWN prefix turns the gate red, by name"
fi
rm -f "${TREE}/internal/alpha/extra_test.go"

echo
echo "a prefix the catalog has never heard of turns it red — RM-161's bug"

# 4. THE HALF THAT DID NOT. `ZZB` appears nowhere in the fixture catalog, so
#    the old gate never put it on its prefix list and never looked for it: two
#    ids in code, exit 0, nothing printed. This case is that exit 0, planted.
mkdir -p "${TREE}/internal/beta"
cat > "${TREE}/internal/beta/beta_test.go" <<'GO'
package beta

import "testing"

func TestZZB001Seal(t *testing.T)   { _ = t }
func TestZZB002Anchor(t *testing.T) { _ = t }
GO
out="$(run_gate)"; status=$?
if [ "${status}" -eq 0 ]; then
  bad "a code-only PREFIX turns the gate red" "it exited 0 — this is the RM-161 bug: ${out}"
elif ! printf '%s' "${out}" | grep -q 'ZZB-001'; then
  bad "a code-only PREFIX turns the gate red" "red, but did not name the ids: ${out}"
elif ! printf '%s' "${out}" | grep -q 'HAS NO ZZB ROWS AT ALL'; then
  bad "a code-only PREFIX is reported AS a missing family" "red and named, but not as a whole family: ${out}"
else
  ok "a code-only PREFIX turns the gate red and is named as a whole missing family"
fi
rm -rf "${TREE}/internal/beta"

echo
echo "and it is red on merit, not because it refuses everything"

# 5. THE GUARD IS NOT REPORTING EVERYTHING. Back to the level fixture, which
#    must be silent again. Without this, a gate that flagged every prefix would
#    pass cases 3 and 4 and be useless.
out="$(run_gate)"; status=$?
if [ "${status}" -ne 0 ]; then
  bad "the level fixture is green again once the planted ids are removed" "exit ${status}: ${out}"
elif printf '%s' "${out}" | grep -qE 'NOT in doc 07|ROWS AT ALL'; then
  bad "the level fixture is green again once the planted ids are removed" "it still reports debt: ${out}"
else
  ok "the level fixture is green again — the red cases were red on merit"
fi

# 6. THE NAMED EXCLUSION, ASSERTED. `RM` is the issue prefix, not a test-id
#    prefix: a test named after RM-092 is named after the issue whose bug it
#    pins. The gate skips it deliberately, so the skip is checked here — and
#    case 4, a different code-only prefix that MUST go red, is what keeps the
#    skip from quietly becoming "ignore anything uncatalogued".
mkdir -p "${TREE}/test/chaos"
cat > "${TREE}/test/chaos/partition_test.go" <<'GO'
package chaos

import "testing"

func TestRM092PortRaceRealDockerReproduction(t *testing.T) { _ = t }
GO
out="$(run_gate)"; status=$?
if [ "${status}" -ne 0 ]; then
  bad "a test named after an ISSUE is not read as a test id" "exit ${status}: ${out}"
elif printf '%s' "${out}" | grep -q 'RM-092'; then
  bad "a test named after an ISSUE is not read as a test id" "it catalogued the issue number: ${out}"
else
  ok "a test named after an ISSUE is not read as a test id"
fi
rm -rf "${TREE}/test"

echo
echo "an id that lives in a SHELL selftest is a test too — RM-167's bug"

# 7. THE HALF READ FROM GO ALONE. Three ids named by a shell case and by
#    nothing else. Against the old gate this is exit 0 with nothing printed,
#    because the test list came from `func Test…` in `*_test.go`.
#
#    ONE ID PER SHAPE, and all three demanded. A single id written in all three
#    shapes would keep passing while two of the three rules rotted, which is
#    the shape of bug this whole file exists to refuse.
mkdir -p "${TREE}/scripts"
cat > "${TREE}/scripts/zzalpha-selftest.sh" <<'SH'
#!/usr/bin/env bash
#   ZZA-078  named at the head of a comment line, as a header block lists them
echo "ZZA-079 — named at the start of the label it reports under"
expect red 'a refusal named in parentheses at the end of its label (ZZA-080)'
SH
out="$(run_gate)"; status=$?
missing=""
for id in ZZA-078 ZZA-079 ZZA-080; do
  printf '%s' "${out}" | grep -q "${id}" || missing="${missing}${id} "
done
if [ "${status}" -eq 0 ]; then
  bad "an id named by a SHELL case turns the gate red" "it exited 0 — this is the RM-167 bug: ${out}"
elif [ -n "${missing}" ]; then
  bad "every shell case-name SHAPE is read" "red, but never named ${missing}: ${out}"
else
  ok "an id named by a SHELL case turns the gate red, in each of the three shapes"
fi
rm -f "${TREE}/scripts/zzalpha-selftest.sh"

echo
echo "and a family that exists only in shell is named as a family"

# 8. WHAT BAK ACTUALLY WAS. Thirteen ids, no Go test, no catalog row, and a
#    gate that could not report a family it had no way to find. The prefix is
#    unknown to the fixture catalog AND to its Go tests, so this is red only if
#    the shell side feeds the PREFIX list as well as the id list.
cat > "${TREE}/scripts/zzcharlie-selftest.sh" <<'SH'
#!/usr/bin/env bash
#   ZZC-001  the first case of a family that lives only here
# --- ZZC-002 ----------------------------------------------------------------
echo "ZZC-002 — driven below"
SH
out="$(run_gate)"; status=$?
if [ "${status}" -eq 0 ]; then
  bad "a shell-only FAMILY turns the gate red" "it exited 0 — this is BAK-001..013: ${out}"
elif ! printf '%s' "${out}" | grep -q 'ZZC-001' || ! printf '%s' "${out}" | grep -q 'ZZC-002'; then
  bad "a shell-only FAMILY turns the gate red" "red, but did not name both ids: ${out}"
elif ! printf '%s' "${out}" | grep -q 'HAS NO ZZC ROWS AT ALL'; then
  bad "a shell-only FAMILY is reported AS a missing family" "red and named, but not as a family: ${out}"
else
  ok "a shell-only FAMILY turns the gate red and is named as a whole missing family"
fi
rm -f "${TREE}/scripts/zzcharlie-selftest.sh"

echo
echo "a mention that is not a case name stays invisible, and green"

# 9. THE LINE, HELD. Four near-misses, none of which names a case:
#      - a fixture payload that merely QUOTES an id-shaped string. This is the
#        expensive one: `JIRA-118` is a ticket in a golden event, and a gate
#        that invented a JIRA family off it would be red for something that is
#        not a test — RM-161's failure, re-earned.
#      - a citation mid-sentence, which is how a selftest says which case it is
#        NOT driving (LED-003, OPS-039 and OPS-050 in the real tree).
#      - a parenthesised citation in prose. The parenthesised shape counts only
#        when it CLOSES a case label, so this one must not.
#      - a production script naming the case it satisfies. Only `*-selftest.sh`
#        is read; OPS-031 in scripts/teardown-guard.sh is the real instance.
#    Green here is also the merit check: with the planted cases gone the
#    fixture is level again, so cases 7 and 8 were red on merit.
cat > "${TREE}/scripts/zznoise-selftest.sh" <<'SH'
#!/usr/bin/env bash
# The golden payload below carries a ticket reference, not a test id.
printf '%s' '{"run_id":"run-42","task_ref":"JIRA-118"}' > /dev/null
# The other half of this is ZZD-001, which a different harness drives.
# The deployment's own arm (ZZE-001) is not reachable from here.
SH
cat > "${TREE}/scripts/zztool.sh" <<'SH'
#!/usr/bin/env bash
# A production gate, not a selftest. It cites the case it satisfies.
echo "ZZF-001 — refusing a teardown while the stack is up"
SH
out="$(run_gate)"; status=$?
if [ "${status}" -ne 0 ]; then
  bad "a mention that is not a case name is not read as an id" "exit ${status}: ${out}"
elif printf '%s' "${out}" | grep -qE 'JIRA|ZZD|ZZE|ZZF'; then
  bad "a mention that is not a case name is not read as an id" "it invented a family: ${out}"
elif printf '%s' "${out}" | grep -qE 'NOT in doc 07|ROWS AT ALL'; then
  bad "the fixture is level again once the planted cases are removed" "it still reports debt: ${out}"
else
  ok "a quoted payload, a citation, a parenthesised aside and a production script are all invisible"
fi
rm -f "${TREE}/scripts/zznoise-selftest.sh" "${TREE}/scripts/zztool.sh"

printf '\n%d passed, %d failed\n' "${pass}" "${fail}"
[ "${fail}" -eq 0 ]
