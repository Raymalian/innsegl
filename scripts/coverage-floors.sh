#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Coverage floor gate for Innsegl.
#
# IP §2 states the floors verbatim:
#
#   "Coverage is a floor, not a goal: 90% line coverage on the MCP server and
#    ledger packages, and 100% branch coverage on: hash-chain append, segment
#    sealing, signature verification, and every error-return path of every MCP
#    tool."
#
# HONEST SCOPE OF THIS SCRIPT
# ---------------------------
# Go's toolchain measures *statement* coverage. It does not measure branch
# (nor condition, nor path) coverage, and `go tool cover` has no mode that
# does. Statement coverage is the closest available proxy for the "line
# coverage" floor, and this script enforces that floor as a hard failure.
#
# The 100% *branch* floor is NOT enforced here and is NOT satisfied by the
# statement floor below. A function can reach 100% statement coverage with an
# untaken `if` branch, which is exactly the case the branch floor exists to
# catch. See the BRANCH FLOOR section at the bottom of this file.
#
# Usage:
#   scripts/coverage-floors.sh                # run the suite, then check the floors
#   scripts/coverage-floors.sh cover.out      # check the floors against an existing profile
#
# Environment:
#   COVERAGE_MODULE_ROOT   module root to operate on (default: this repo)
#   COVERAGE_GO_TEST_FLAGS extra flags for the `go test` invocation
#                          (default: "-race")
#   COVERAGE_REQUIRE_PACKAGES
#                          when "1", a floored package that does not exist on
#                          disk is a failure rather than a skip

set -euo pipefail

# ---------------------------------------------------------------------------
# Line (statement) coverage floors — IP §2.
# One entry per floored package tree: "<path relative to module root> <floor %>"
# The path is matched as a prefix, so "internal/ledger" covers
# internal/ledger/... as the issue requires.
# ---------------------------------------------------------------------------
# Paths excluded from floor measurement: test-helper binaries that exist to be
# compiled into a container and exercised from the outside. They carry no tests
# by design, and counting them understates the package they sit in.
FLOOR_EXCLUDE="internal/spire/svidprobe"

LINE_FLOORS=(
  "internal/ledger 90"
  "internal/mcp 90"
  # Added after E2: these packages sat at 99.8% and 95.4% with nothing holding
  # them there. internal/segment in particular would have dropped to 69.2% if
  # its Docker-backed WORM and Rekor tests stopped running, and nothing would
  # have failed. Floors set below current coverage, not at it, so ordinary
  # refactoring does not trip them.
  "internal/event 95"
  "internal/segment 88"
  "internal/spire 85"
)

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
MODULE_ROOT="${COVERAGE_MODULE_ROOT:-$(cd -- "${SCRIPT_DIR}/.." && pwd)}"
GO_TEST_FLAGS="${COVERAGE_GO_TEST_FLAGS--race}"
REQUIRE_PACKAGES="${COVERAGE_REQUIRE_PACKAGES:-0}"

log()  { printf '%s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; }

# GitHub Actions annotations, no-ops outside CI.
annotate_error() {
  [ -n "${GITHUB_ACTIONS:-}" ] && printf '::error::%s\n' "$*"
  return 0
}
annotate_warning() {
  [ -n "${GITHUB_ACTIONS:-}" ] && printf '::warning::%s\n' "$*"
  return 0
}
summary() {
  [ -n "${GITHUB_STEP_SUMMARY:-}" ] && printf '%s\n' "$*" >>"${GITHUB_STEP_SUMMARY}"
  return 0
}

# ---------------------------------------------------------------------------
# Obtain a coverage profile.
# ---------------------------------------------------------------------------
profile="${1:-}"
cleanup_profile=""

if [ -z "${profile}" ]; then
  if [ ! -f "${MODULE_ROOT}/go.mod" ]; then
    fail "no go.mod at ${MODULE_ROOT}; cannot produce a coverage profile"
    annotate_error "coverage gate: no go.mod at ${MODULE_ROOT}"
    exit 1
  fi
  profile="$(mktemp "${TMPDIR:-/tmp}/innsegl-cover.XXXXXX")"
  cleanup_profile="${profile}"
  trap 'rm -f "${cleanup_profile}"' EXIT
  log "==> go test ./... ${GO_TEST_FLAGS} -covermode=atomic -coverpkg=./... -coverprofile=${profile}"
  # -coverpkg=./... instruments every package in the module, so a package with
  # no test file at all is reported as 0% rather than omitted from the profile.
  # Without it an entirely untested package is invisible to this gate.
  ( cd -- "${MODULE_ROOT}" && go test ./... ${GO_TEST_FLAGS} \
      -covermode=atomic -coverpkg=./... -coverprofile="${profile}" )
elif [ ! -f "${profile}" ]; then
  fail "coverage profile not found: ${profile}"
  annotate_error "coverage gate: profile not found: ${profile}"
  exit 1
fi

# ---------------------------------------------------------------------------
# Compute statement coverage for one package tree from the profile.
#
# Profile lines are "<import-path>/<file>.go:<start>,<end> <numStmts> <count>".
# The same block can appear more than once (one entry per test binary under
# -coverpkg), so blocks are deduplicated by key and their counts summed —
# the same rule `go tool cover` applies.
# ---------------------------------------------------------------------------
package_coverage() {
  local prefix="$1"
  awk -v pat="/${prefix}/" -v excl="${FLOOR_EXCLUDE}" '
    NR == 1 && $1 == "mode:" { next }
    NF != 3 { next }
    index($1, pat) == 0 { next }
    excl != "" && index($1, excl) > 0 { next }
    {
      key = $1
      stmts[key] = $2
      count[key] += $3
    }
    END {
      total = 0; covered = 0
      for (k in stmts) {
        total += stmts[k]
        if (count[k] > 0) covered += stmts[k]
      }
      printf "%d %d\n", total, covered
    }
  ' "${profile}"
}

log ""
log "==> line (statement) coverage floors — IP §2"
printf '%-24s %8s %8s %10s %8s  %s\n' "PACKAGE" "STMTS" "COVERED" "COVERAGE" "FLOOR" "RESULT"

status=0
summary "### Innsegl coverage floors (IP §2)"
summary ""
summary "| package | statements | covered | coverage | floor | result |"
summary "|---|---:|---:|---:|---:|---|"

for entry in "${LINE_FLOORS[@]}"; do
  pkg="${entry%% *}"
  floor="${entry##* }"

  if [ ! -d "${MODULE_ROOT}/${pkg}" ]; then
    if [ "${REQUIRE_PACKAGES}" = "1" ]; then
      printf '%-24s %8s %8s %10s %7s%%  %s\n' "${pkg}/..." "-" "-" "-" "${floor}" "FAIL (absent)"
      fail "${pkg}/ does not exist and COVERAGE_REQUIRE_PACKAGES=1 (IP §2)"
      annotate_error "coverage floor: ${pkg}/ does not exist"
      summary "| \`${pkg}/...\` | - | - | - | ${floor}% | FAIL (absent) |"
      status=1
    else
      printf '%-24s %8s %8s %10s %7s%%  %s\n' "${pkg}/..." "-" "-" "-" "${floor}" "SKIP (absent)"
      annotate_warning "coverage floor for ${pkg}/ not applied: the package does not exist yet"
      summary "| \`${pkg}/...\` | - | - | - | ${floor}% | SKIP (absent) |"
    fi
    continue
  fi

  read -r total covered <<<"$(package_coverage "${pkg}")"

  if [ "${total}" -eq 0 ]; then
    printf '%-24s %8s %8s %10s %7s%%  %s\n' "${pkg}/..." "0" "0" "n/a" "${floor}" "SKIP (no statements)"
    annotate_warning "coverage floor for ${pkg}/ not applied: no instrumented statements in the profile"
    summary "| \`${pkg}/...\` | 0 | 0 | n/a | ${floor}% | SKIP (no statements) |"
    continue
  fi

  pct="$(awk -v c="${covered}" -v t="${total}" 'BEGIN { printf "%.2f", (c * 100) / t }')"
  if awk -v p="${pct}" -v f="${floor}" 'BEGIN { exit !(p + 0 >= f + 0) }'; then
    result="PASS"
  else
    result="FAIL"
    status=1
  fi
  printf '%-24s %8d %8d %9s%% %7s%%  %s\n' \
    "${pkg}/..." "${total}" "${covered}" "${pct}" "${floor}" "${result}"
  if [ "${result}" = "FAIL" ]; then
    fail "${pkg}/... statement coverage ${pct}% is below the ${floor}% floor (IP §2)"
    annotate_error "coverage floor breached: ${pkg}/... at ${pct}%, floor ${floor}% (IP §2)"
  fi
  summary "| \`${pkg}/...\` | ${total} | ${covered} | ${pct}% | ${floor}% | ${result} |"
done

# ---------------------------------------------------------------------------
# BRANCH FLOOR — NOT YET ENFORCED
#
# IP §2 additionally requires 100% *branch* coverage on:
#   * hash-chain append
#   * segment sealing
#   * signature verification
#   * every error-return path of every MCP tool
#
# Enforced by scripts/branch-coverage.sh (gobco), which runs as its own CI job.
# `go test -cover` reports statement
# coverage only; there is no branch mode in the Go toolchain, so nothing above
# measures it. A follow-up issue must select the mechanism (a branch-coverage
# tool such as gobco, or an explicit per-branch test-ID manifest checked
# against the test catalog in doc 07) and turn this section into a hard gate.
# Until that lands, the branch floor is enforced by review, not by CI, and this
# script deliberately says so rather than letting the statement numbers above
# be mistaken for branch numbers.
# ---------------------------------------------------------------------------
log ""
log "==> branch coverage floors — IP §2 — SEE scripts/branch-coverage.sh"
log "    100% branch coverage is required on hash-chain append, segment sealing,"
log "    signature verification, and every error-return path of every MCP tool."
log "    Go measures statements, not branches: the numbers above do NOT satisfy"
log "    that floor. It is enforced separately by scripts/branch-coverage.sh,"
log "    which uses gobco and runs as its own CI job. Two of the four surfaces"
log "    do not exist yet (RM-037, RM-022..025); they report PENDING, never pass."
summary ""
summary "> **Branch floor (IP §2) is NOT enforced.** Go measures statements, not"
summary "> branches; the table above does not satisfy the 100% branch requirement."
summary "> Enforced by \`scripts/branch-coverage.sh\` — see the branch coverage job."
log "    (the branch coverage job enforces this; nothing to warn about here)"

log ""
if [ "${status}" -ne 0 ]; then
  log "coverage floors: BREACHED"
else
  log "coverage floors: OK (line/statement floors only)"
fi
exit "${status}"
