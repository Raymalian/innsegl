#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Self-test for the branch coverage gate (scripts/branch-coverage.sh).
#
# RM-064 (#72) acceptance criterion: "The self-test demonstrates red-then-green
# for the branch floor, not only the line floor." scripts/coverage-floors-
# selftest.sh already proves that for the *statement* floor; this is its
# sibling for the *branch* floor ADR-0043 chose gobco to enforce.
#
# A gate that has never been observed failing is not a gate, so this script
# builds a throwaway module with a floored surface (a function shaped exactly
# like scripts/branch-coverage.sh's "internal/ledger/chain.go" entry) and a
# second, always-fully-covered floored surface as a control. It exercises the
# ledger surface with its success path only, asserts that branch-coverage.sh
# reports that ONE surface FAILED and exits non-zero (red), then covers every
# condition and asserts the same surface now reports 100% and the gate exits
# zero (green) — with the control surface passing throughout, so a reader can
# see the gate is discriminating between surfaces rather than failing
# everything or nothing.
#
# It needs nothing from this repository except scripts/branch-coverage.sh and
# a working gobco on PATH or under `go env GOPATH`/bin — in particular it does
# not need the repository's own go.mod — so it runs even before the module
# scaffold exists.
#
# Usage: scripts/branch-coverage-selftest.sh

set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly BRANCH_COVERAGE_SH="${SCRIPT_DIR}/branch-coverage.sh"

if [ ! -x "${BRANCH_COVERAGE_SH}" ]; then
  printf 'FAIL: %s is missing or not executable\n' "${BRANCH_COVERAGE_SH}" >&2
  exit 1
fi

# Resolve gobco exactly the way branch-coverage.sh does. Checked here, up
# front, so a missing tool fails loudly as "gobco not found" rather than being
# misread as phase 1's expected red — branch-coverage.sh exits non-zero for
# BOTH reasons (4 for a missing tool, 1 for a breached floor), and a self-test
# that only checked "non-zero" could pass for the wrong reason.
gobco_bin="${GOBCO:-gobco}"
if ! command -v "${gobco_bin}" >/dev/null 2>&1; then
  gopath_bin="$(go env GOPATH)/bin/gobco"
  if [ -x "${gopath_bin}" ]; then
    gobco_bin="${gopath_bin}"
  else
    printf 'FAIL: gobco not found on PATH or under `go env GOPATH`/bin.\n' >&2
    printf '  Install with: go install github.com/rillig/gobco@latest\n' >&2
    exit 1
  fi
fi

workdir="$(mktemp -d "${TMPDIR:-/tmp}/innsegl-branch-coverage-selftest.XXXXXX")"
trap 'rm -rf "${workdir}"' EXIT

mkdir -p "${workdir}/internal/ledger" "${workdir}/internal/mcp"
( cd -- "${workdir}" && go mod init innsegl.test/branchcoveragefixture >/dev/null )

# The floored surface under test: three conditions, shaped like
# scripts/branch-coverage.sh's own "internal/ledger/chain.go" entry
# (surface 1, "hash-chain append") so the SURFACES table matches it by path
# once branch-coverage.sh is run with this directory as its working directory.
cat >"${workdir}/internal/ledger/chain.go" <<'GO_EOF'
// Package ledger is a branch-coverage-gate fixture, not production code.
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

# A second floored surface (matches "internal/mcp/" — surface 5, "MCP tool
# error paths"), fully covered in both phases and with no conditions of its
# own to instrument, so it reports 100% throughout. Its presence proves the
# gate discriminates between surfaces: only the ledger surface's verdict may
# change between red and green.
cat >"${workdir}/internal/mcp/tool.go" <<'GO_EOF'
// Package mcp is a branch-coverage-gate fixture, not production code.
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

# --- Phase 1 (red): success path only, three conditions untested in both
# directions. ------------------------------------------------------------
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

printf '=== phase 1 (red): uncovered conditions in internal/ledger ===\n'
set +e
red_output="$(cd -- "${workdir}" && GOBCO="${gobco_bin}" "${BRANCH_COVERAGE_SH}" 2>&1)"
red_status=$?
set -e
printf '%s\n' "${red_output}"
printf 'branch-coverage.sh exit status: %d\n' "${red_status}"

if [ "${red_status}" -ne 1 ]; then
  printf 'FAIL: expected exit status 1 (BREACHED), got %d\n' "${red_status}" >&2
  exit 1
fi
if ! printf '%s\n' "${red_output}" | grep -q 'FAIL.*hash-chain append'; then
  printf 'FAIL: the gate did not report hash-chain append as FAILed\n' >&2
  exit 1
fi
if ! printf '%s\n' "${red_output}" | grep -qE 'one-directional condition'; then
  printf 'FAIL: the gate did not name a one-directional condition\n' >&2
  exit 1
fi
if ! printf '%s\n' "${red_output}" | grep -q 'ok.*MCP tool error paths'; then
  printf 'FAIL: the control surface (MCP tool error paths) did not pass — the gate is not discriminating between surfaces\n' >&2
  exit 1
fi
if ! printf '%s\n' "${red_output}" | grep -q 'branch coverage: BREACHED'; then
  printf 'FAIL: the gate did not report BREACHED\n' >&2
  exit 1
fi
printf 'OK: the gate failed on the untaken branch, and only on it, as required by RM-064 (#72)\n\n'

# --- Phase 2 (green): every condition covered in both directions. ----------
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

printf '=== phase 2 (green): every condition covered in both directions ===\n'
set +e
green_output="$(cd -- "${workdir}" && GOBCO="${gobco_bin}" "${BRANCH_COVERAGE_SH}" 2>&1)"
green_status=$?
set -e
printf '%s\n' "${green_output}"
printf 'branch-coverage.sh exit status: %d\n' "${green_status}"

if [ "${green_status}" -ne 0 ]; then
  printf 'FAIL: the gate rejected a fully covered fixture\n' >&2
  exit 1
fi
if ! printf '%s\n' "${green_output}" | grep -q 'ok.*hash-chain append'; then
  printf 'FAIL: hash-chain append did not report ok once fully covered\n' >&2
  exit 1
fi
if ! printf '%s\n' "${green_output}" | grep -q 'branch coverage: OK'; then
  printf 'FAIL: the gate did not report OK\n' >&2
  exit 1
fi
printf 'OK: the gate passed once every branch was covered\n\n'

printf 'branch coverage gate self-test: PASS\n'
