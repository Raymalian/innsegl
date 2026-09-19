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
# WHY THE FIXTURE IDS ARE ZZA AND ZZB. The gate's reverse check reads every
# `.sh` in the tree looking for a catalogued id, so a fixture written with real
# prefixes would let THIS FILE stand in as the missing test for a real row and
# silence a true report. Two prefixes nothing else uses cost nothing and cannot
# do that.
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

echo "test-ids-selftest: six cases"
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

printf '\n%d passed, %d failed\n' "${pass}" "${fail}"
[ "${fail}" -eq 0 ]
