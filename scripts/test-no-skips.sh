#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Run the suite and refuse a skipped test.
#
# Thirty test files skip when Docker is absent, and a Go skip exits zero. CI has
# already required Docker before this runs, so a skip here is a dependency that
# should have been present and was not — most of the integration suite would
# vanish while the job stayed green.
#
# That is the false-green shape this project has hit repeatedly: RM-018 measured
# a cross-test collision producing a *false accusation*, and RM-065 found a
# single invocation passing where two concurrent ones failed. RM-035 measured
# the specific mechanism here: four packages each booting per-process SPIRE and
# Sigstore projects exhaust Docker's predefined address pools, and every
# affected case skips rather than failing.
#
# A coverage floor cannot catch this. internal/verify reads 99.8% with Docker on
# AND off, because the unit tests reach the same statements — so VER-001, the
# case that proves I5, could stop running with every gate still green.

set -uo pipefail

out="${INNSEGL_TEST_JSON:-$(mktemp -t innsegl-gotest-XXXXXX.json)}"

# shellcheck disable=SC2086 # deliberate word splitting of caller-supplied flags
# -count=1 is not optional here. Without it Go serves cached results, and a
# cached PASS means this gate certifies a run that did not happen — the exact
# false-green it exists to prevent. RM-036 hit it: the first run reported six
# skips that were cached from an earlier invocation.
go test ./... -race -count=1 -json ${INNSEGL_TEST_FLAGS:-} >"${out}" 2>&1
rc=$?

# Package-level result lines, so the log still reads like a test run.
awk -F'"' '
  /"Action":"(pass|fail|skip)"/ && !/"Test":/ {
    action = ""; pkg = ""
    for (i = 1; i < NF; i++) {
      if ($i == "Action") action = $(i + 2)
      if ($i == "Package") pkg = $(i + 2)
    }
    if (action != "" && pkg != "") printf "%-5s %s\n", action, pkg
  }
' "${out}" | sort -u

if [ "${rc}" -ne 0 ]; then
  printf '\n--- failures ---\n'
  grep -F '"Action":"fail"' "${out}" | head -40
  printf '\ngo test exited %s\n' "${rc}"
  exit "${rc}"
fi

# Only real test cases count. A package with no test files is also reported as
# "skip" by go test (internal/spire/svidprobe is one), and that is not a
# dependency failure — it is a package that has nothing to run.
#
# ALLOWED holds the skips that are correct by construction. Each needs a reason
# here, and the list must stay short: every entry is a test that will not run
# and nobody will notice.
#
#   TestSEG002CrashChild
#       A child-process helper for TestSEG002KillTheProcessAtEveryStepBoundary.
#       It skips unless its parent invoked it with the step env var set, which
#       is exactly right — run directly it has nothing to do.
#
#   TestMCP011CrashAndReplayUnderFuzzedKillTiming/sign_commit
#       Reports PENDING for RM-072 (#95): MCP-011 does not yet fuzz sign_commit,
#       so IP §6.6's "never a second commit" is untested. Tracked, not forgotten.
#       Remove this line when #95 lands.
ALLOWED='TestSEG002CrashChild|TestMCP011CrashAndReplayUnderFuzzedKillTiming/sign_commit'

unexpected=$(grep -F '"Action":"skip"' "${out}" | grep -F '"Test":' | grep -Ev "\"Test\":\"(${ALLOWED})\"" || true)
skipped=$(printf '%s' "${unexpected}" | grep -c . || true)
skipped=${skipped:-0}
if [ "${skipped}" -gt 0 ]; then
  printf '\n'
  printf 'FAIL: %s test(s) skipped. Every dependency is required here, so a skip\n' "${skipped}"
  printf '      is a missing dependency rather than a pass.\n\n'
  printf '%s\n' "${unexpected}" | head -40
  # The reason matters more than the list: a skip names its missing dependency
  # in the message the test printed just before skipping. Without this the log
  # says what did not run but not why, which is how `gitsign` stayed missing
  # from CI unnoticed.
  printf '\n--- why ---\n'
  grep -F '"Action":"output"' "${out}" \
    | grep -Ei 'skipping:|SKIP:' \
    | sed -e 's/.*"Output":"//' -e 's/\\n"}$//' -e 's/\\t/  /g' \
    | sort -u | head -20
  exit 1
fi

printf '\nno tests skipped\n'
