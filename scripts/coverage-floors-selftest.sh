#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Self-test for the coverage floor gate (scripts/coverage-floors.sh).
#
# Issue #10 acceptance criterion: "A deliberately uncovered branch in a floored
# package fails CI." A gate that has never been observed failing is not a gate,
# so this script builds a throwaway module, leaves an error branch in a floored
# package untested, and asserts that scripts/coverage-floors.sh exits
# non-zero. It then covers that branch and asserts the gate goes green.
#
# It needs nothing from this repository except scripts/coverage-floors.sh — in
# particular it does not need the repository's own go.mod — so it runs even
# before the module scaffold exists.
#
# Usage: scripts/coverage-floors-selftest.sh

set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly COVERAGE_SH="${SCRIPT_DIR}/coverage-floors.sh"

if [ ! -x "${COVERAGE_SH}" ]; then
  printf 'FAIL: %s is missing or not executable\n' "${COVERAGE_SH}" >&2
  exit 1
fi

workdir="$(mktemp -d "${TMPDIR:-/tmp}/innsegl-coverage-selftest.XXXXXX")"
trap 'rm -rf "${workdir}"' EXIT

mkdir -p "${workdir}/internal/ledger" "${workdir}/internal/mcp"
( cd -- "${workdir}" && go mod init innsegl.test/coveragefixture >/dev/null )

# A floored package with three error branches and one success branch.
cat >"${workdir}/internal/ledger/chain.go" <<'GO_EOF'
// Package ledger is a coverage-gate fixture, not production code.
package ledger

import "errors"

// ErrEmptyPayload is returned when an empty payload is appended.
var ErrEmptyPayload = errors.New("empty payload")

// ErrNegativePosition is returned for a negative chain position.
var ErrNegativePosition = errors.New("negative position")

// ErrSegmentFull is returned when the segment cannot take another event.
var ErrSegmentFull = errors.New("segment full")

// Append returns the next chain position for payload.
func Append(pos int, payload string) (int, error) {
	if payload == "" {
		return 0, ErrEmptyPayload
	}
	if pos < 0 {
		return 0, ErrNegativePosition
	}
	next := pos + 1
	if next > 1000 {
		return 0, ErrSegmentFull
	}
	return next, nil
}
GO_EOF

# A second floored package, fully covered in both phases, so that only the
# ledger package's coverage differs between red and green.
cat >"${workdir}/internal/mcp/tool.go" <<'GO_EOF'
// Package mcp is a coverage-gate fixture, not production code.
package mcp

// Echo returns its argument.
func Echo(s string) string {
	return s
}
GO_EOF

cat >"${workdir}/internal/mcp/tool_test.go" <<'GO_EOF'
package mcp

import "testing"

func TestEcho(t *testing.T) {
	if got := Echo("a"); got != "a" {
		t.Fatalf("Echo(a) = %q", got)
	}
}
GO_EOF

# --- Phase 1 (red): success path only, three error branches untested. --------
cat >"${workdir}/internal/ledger/chain_test.go" <<'GO_EOF'
package ledger

import "testing"

func TestAppendSuccess(t *testing.T) {
	got, err := Append(0, "payload")
	if err != nil || got != 1 {
		t.Fatalf("Append(0, payload) = %d, %v", got, err)
	}
}
GO_EOF

printf '=== phase 1 (red): uncovered error branches in internal/ledger ===\n'
set +e
COVERAGE_MODULE_ROOT="${workdir}" COVERAGE_GO_TEST_FLAGS="" "${COVERAGE_SH}"
red_status=$?
set -e
printf 'coverage-floors.sh exit status: %d\n' "${red_status}"
if [ "${red_status}" -eq 0 ]; then
  printf 'FAIL: the gate passed a package with uncovered branches below the floor\n' >&2
  exit 1
fi
printf 'OK: the gate failed, as required by issue #10\n\n'

# --- Phase 2 (green): every branch covered. ---------------------------------
cat >>"${workdir}/internal/ledger/chain_test.go" <<'GO_EOF'

func TestAppendErrors(t *testing.T) {
	if _, err := Append(0, ""); err != ErrEmptyPayload {
		t.Fatalf("empty payload: %v", err)
	}
	if _, err := Append(-1, "p"); err != ErrNegativePosition {
		t.Fatalf("negative position: %v", err)
	}
	if _, err := Append(1000, "p"); err != ErrSegmentFull {
		t.Fatalf("segment full: %v", err)
	}
}
GO_EOF

printf '=== phase 2 (green): every branch covered ===\n'
set +e
COVERAGE_MODULE_ROOT="${workdir}" COVERAGE_GO_TEST_FLAGS="" "${COVERAGE_SH}"
green_status=$?
set -e
printf 'coverage-floors.sh exit status: %d\n' "${green_status}"
if [ "${green_status}" -ne 0 ]; then
  printf 'FAIL: the gate rejected a fully covered fixture\n' >&2
  exit 1
fi
printf 'OK: the gate passed\n\n'

printf 'coverage gate self-test: PASS\n'
