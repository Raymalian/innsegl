#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Self-test for the protected-surfaces gate (scripts/protected-surfaces.sh).
#
# Issue #21 acceptance criterion: "A deliberate fixture change on a patch version
# fails the release." A gate that has never been observed failing is not a gate,
# so this script builds a throwaway repository that satisfies every protected
# surface, then injects one synthetic drift at a time and asserts the gate's exit
# status — red where the policy says red, green where it says green.
#
# Nine phases:
#
#   1. no tag, clean                    -> 0, and says FIRST RUN
#   2. no tag, protected field renamed  -> non-zero   (the tagless path is not a
#                                                      silent pass: SER-005)
#   3. tag, fixture edited, v0.1.1      -> non-zero   (the issue's criterion)
#   4. tag, fixture edited, v1.0.0+ADR  -> non-zero   (fixtures are immutable on
#                                                      EVERY release, doc 08 §3(b))
#   5. tag, vocabulary drift, v0.1.1    -> non-zero
#   6. tag, vocabulary drift, v1.0.0+ADR-> 0          (a MAJOR release may)
#   7. tag, vocabulary drift, v1.0.0    -> non-zero   (…only with the ADR)
#   8. tag, new fixture added, v0.1.1   -> 0          (additions alter nothing)
#   9. tag, clean, v0.1.1               -> 0
#  10. tag, fixture README edited, v0.1.1 -> 0  (the prose beside the vectors is
#                                                not itself a protected surface)
#
# The synthetic repository is built from scratch rather than copied, so this test
# does not depend on the state of internal/ — with one deliberate exception: the
# real VERSIONING.md is copied in, because the gate checks its own copy of the
# protected vocabulary against that file, and a self-test that stubbed it would
# be testing a policy nobody ships.
#
# Portability: bash 3.2 (macOS). No mapfile, no arrays.
#
# Usage: scripts/protected-surfaces-selftest.sh

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
GATE="${SCRIPT_DIR}/protected-surfaces.sh"
REAL_REPO="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

if [ ! -x "${GATE}" ]; then
  printf 'FAIL: %s is missing or not executable\n' "${GATE}" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 | cut -d' ' -f1; }
else
  printf 'FAIL: neither sha256sum nor shasum is available\n' >&2
  exit 1
fi

workdir="$(mktemp -d "${TMPDIR:-/tmp}/innsegl-protected-selftest.XXXXXX")"
trap 'rm -rf "${workdir}"' EXIT
repo="${workdir}/repo"
mkdir -p "${repo}"

# ---------------------------------------------------------------------------
# Build a repository that satisfies all five protected surfaces.
# ---------------------------------------------------------------------------
FIX="${repo}/internal/event/testdata/fixtures/v1"
mkdir -p "${FIX}" "${repo}/internal/event" "${repo}/cmd/innsegl" "${repo}/docs/adr"

cp -- "${REAL_REPO}/VERSIONING.md" "${repo}/VERSIONING.md"

genesis="sha256:$(printf 'innsegl-genesis-v1' | sha256)"
printf '%s' "${genesis}" >"${FIX}/genesis.hash"

# One event fixture: a real JCS-ordered run_registered, minus event_hash.
printf '%s' '{"agent_type":"fix-ci","chain_position":1,"event_id":"01919f2e-8c1a-7d3b-9e4f-1a2b3c4d5e6f","event_type":"run_registered","idempotency_key":"reg-8f21c","payload_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","prev_event_hash":"'"${genesis}"'","run_id":"run-42","schema_version":"1","source":"mcp","spiffe_id":"spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42","supersedes":"01919f2e-8c1a-7d3b-9e4f-1a2b3c4d5e70","task_ref":"JIRA-118","ts":"2026-08-28T09:14:03.201Z"}' \
  >"${FIX}/01-run_registered.canonical.json"
printf 'sha256:%s' "$(sha256 <"${FIX}/01-run_registered.canonical.json")" \
  >"${FIX}/01-run_registered.hash"

# Supporting material that lives in the fixture tree but is not a vector.
printf '# TC-SER golden fixtures\n\nThese files are immutable.\n' >"${FIX}/README.md"

# The serializer format probe, whose digest is frozen a second time in Go.
printf '%s' '{"bool_true":true,"schema_version":"1","serializer_version":"1"}' \
  >"${FIX}/format-probe.canonical.json"
probe_fingerprint="sha256:$(sha256 <"${FIX}/format-probe.canonical.json")"
printf '%s' "${probe_fingerprint}" >"${FIX}/format-probe.hash"

# The shipped source: every protected string spelled once.
cat >"${repo}/internal/event/schema.go" <<GO_EOF
// SPDX-License-Identifier: Apache-2.0

// Package event is a protected-surfaces gate fixture, not production code.
package event

// Envelope and type-specific member names (doc 02 §2-§3).
const (
	FieldAgentType      = "agent_type"
	FieldChainPosition  = "chain_position"
	FieldEventID        = "event_id"
	FieldEventType      = "event_type"
	FieldIdempotencyKey = "idempotency_key"
	FieldPayloadDigest  = "payload_digest"
	FieldPrevEventHash  = "prev_event_hash"
	FieldRunID          = "run_id"
	FieldSchemaVersion  = "schema_version"
	FieldSource         = "source"
	FieldSpiffeID       = "spiffe_id"
	FieldSupersedes     = "supersedes"
	FieldTaskRef        = "task_ref"
	FieldTS             = "ts"
	EventHashField      = "event_hash"
)

// Format-probe members.
const (
	ProbeBoolTrue          = "bool_true"
	ProbeSerializerVersion = "serializer_version"
)

// Enum values (doc 02 §2-§3).
const (
	EventTypeRunRegistered = "run_registered"
	SourceMCP              = "mcp"
)

// formatFingerprintV1 is the serializer format fingerprint, frozen here and as
// testdata/fixtures/v1/format-probe.hash.
const formatFingerprintV1 = "${probe_fingerprint}"

// ValidateSPIFFEID checks the grammar
// spiffe://{trust_domain}/agent/{agent_type}/{task_id}/{run_id}, whose segments
// match [a-z0-9][a-z0-9-]{0,62}.
func ValidateSPIFFEID(s string) bool { return s != "" }

// Commit trailer keys.
const (
	TrailerAgentIdentity = "Agent-Identity"
	TrailerAgentRun      = "Agent-Run"
	TrailerAgentTask     = "Agent-Task"
)

// MCP tool names: register_agent, get_credential, record_event, sign_commit,
// retire_agent.
const (
	ClassLedgerUnavailable  = "LEDGER_UNAVAILABLE"
	ClassInvariantViolation = "INVARIANT_VIOLATION"
	ClassDuplicateRequest   = "DUPLICATE_REQUEST"
)

var _ = formatFingerprintV1
GO_EOF

cat >"${repo}/go.mod" <<'GO_EOF'
module innsegl.dev/innsegl

go 1.27
GO_EOF

cat >"${repo}/Makefile" <<'MK_EOF'
BINARY := innsegl
MK_EOF

cat >"${repo}/cmd/innsegl/main.go" <<'GO_EOF'
// SPDX-License-Identifier: Apache-2.0

package main

func main() {}
GO_EOF

cd -- "${repo}"
git init --quiet .
git config user.email selftest@innsegl.invalid
git config user.name 'protected-surfaces self-test'
git config commit.gpgsign false
git add -A
git commit --quiet -m 'protected-surfaces self-test fixture'

# ---------------------------------------------------------------------------
# Harness.
# ---------------------------------------------------------------------------
phase=0
run_gate() { # <candidate-or-empty>
  set +e
  PROTECTED_SURFACES_REPO_ROOT="${repo}" \
  PROTECTED_SURFACES_CANDIDATE="${1:-}" \
  GITHUB_ACTIONS='' GITHUB_STEP_SUMMARY='' \
    "${GATE}" >"${workdir}/out.${phase}" 2>&1
  gate_status=$?
  set -e
  sed 's/^/      | /' "${workdir}/out.${phase}"
  printf '      exit status: %d\n' "${gate_status}"
}

expect() { # <want: red|green> <description>
  if [ "$1" = red ] && [ "${gate_status}" -eq 0 ]; then
    printf 'FAIL: phase %d (%s): the gate passed, and it must not\n' "${phase}" "$2" >&2
    exit 1
  fi
  if [ "$1" = green ] && [ "${gate_status}" -ne 0 ]; then
    printf 'FAIL: phase %d (%s): the gate failed, and it must not\n' "${phase}" "$2" >&2
    exit 1
  fi
  printf '      OK: %s\n\n' "$2"
}

begin() {
  phase=$((phase + 1))
  printf '=== phase %d: %s ===\n' "${phase}" "$1"
}

reset_tree() {
  git -C "${repo}" reset --quiet --hard HEAD
  git -C "${repo}" clean --quiet -fd
}

# --- phase 1: no tag, clean --------------------------------------------------
begin 'no previous tag, every surface intact -> passes, and says so'
run_gate ''
expect green 'a repository with no tag passes'
grep -q 'FIRST RUN' "${workdir}/out.${phase}" || {
  printf 'FAIL: phase %d: the no-tag path passed without saying FIRST RUN\n' "${phase}" >&2
  exit 1
}
grep -q 'no previous tag' "${workdir}/out.${phase}" || {
  printf 'FAIL: phase %d: the no-tag path did not name the missing baseline\n' "${phase}" >&2
  exit 1
}
printf '      OK: the first-run case is announced, not silent\n\n'

# --- phase 2: no tag, protected field renamed -------------------------------
begin 'no previous tag, a protected field renamed in the source -> fails'
sed -e 's/"prev_event_hash"/"previous_event_hash"/' \
  "${repo}/internal/event/schema.go" >"${workdir}/schema.go.tmp"
mv -- "${workdir}/schema.go.tmp" "${repo}/internal/event/schema.go"
run_gate ''
expect red 'a rename fails with no tag in the repository (SER-005)'
reset_tree

# --- tag the clean state ----------------------------------------------------
git -C "${repo}" tag v0.1.0

# --- phase 3: fixture edited on a patch release -----------------------------
begin 'tagged, a golden fixture deliberately changed, candidate v0.1.1 -> fails'
sed -e 's/"JIRA-118"/"JIRA-119"/' \
  "${FIX}/01-run_registered.canonical.json" >"${workdir}/f.tmp"
printf '%s' "$(cat "${workdir}/f.tmp")" >"${FIX}/01-run_registered.canonical.json"
# Recompute the committed digest so part A stays green and ONLY the tag diff
# fires: this isolates the acceptance criterion instead of tripping over the
# fixture's own self-check.
printf 'sha256:%s' "$(sha256 <"${FIX}/01-run_registered.canonical.json")" \
  >"${FIX}/01-run_registered.hash"
run_gate 'v0.1.1'
expect red 'a deliberate fixture change on a patch version fails the release'

# --- phase 4: same edit, MAJOR release with an ADR --------------------------
begin 'the same fixture change on candidate v1.0.0 with a new ADR -> still fails'
mkdir -p -- "${repo}/docs/adr"
mkdir -p -- "${repo}/docs/adr"
printf '# ADR-0099: selftest\n' >"${repo}/docs/adr/0099-selftest.md"
git -C "${repo}" add docs/adr/0099-selftest.md
run_gate 'v1.0.0'
expect red 'golden fixtures are immutable on a MAJOR release too (doc 08 §3(b), I4)'
reset_tree

# --- phase 5: vocabulary drift on a patch release ---------------------------
begin 'tagged, a protected error class dropped from the source, candidate v0.1.1 -> fails'
sed -e '/ClassLedgerUnavailable/d' \
  "${repo}/internal/event/schema.go" >"${workdir}/schema.go.tmp"
mv -- "${workdir}/schema.go.tmp" "${repo}/internal/event/schema.go"
run_gate 'v0.1.1'
expect red 'a MINOR/PATCH release may not alter the error-class vocabulary'

# --- phase 6: same drift, MAJOR release with an ADR -------------------------
begin 'the same drift on candidate v1.0.0 with a superseding ADR -> passes'
mkdir -p -- "${repo}/docs/adr"
mkdir -p -- "${repo}/docs/adr"
printf '# ADR-0099: selftest\n' >"${repo}/docs/adr/0099-selftest.md"
git -C "${repo}" add docs/adr/0099-selftest.md
run_gate 'v1.0.0'
expect green 'a MAJOR release may change a protected surface'

# --- phase 7: same drift, MAJOR release without an ADR ----------------------
begin 'the same drift on candidate v1.0.0 with no new ADR -> fails'
git -C "${repo}" rm --quiet --cached docs/adr/0099-selftest.md
rm -f -- "${repo}/docs/adr/0099-selftest.md"
run_gate 'v1.0.0'
expect red 'a MAJOR release owes a superseding ADR (doc 08 §3(d))'
reset_tree

# --- phase 8: an addition is not drift --------------------------------------
begin 'tagged, a new golden fixture added, candidate v0.1.1 -> passes'
printf '%s' '{"chain_position":2,"event_id":"01919f2e-8c1a-7d3b-9e4f-1a2b3c4d5e71","event_type":"run_registered","prev_event_hash":"'"${genesis}"'","run_id":"run-43","schema_version":"1","source":"mcp","spiffe_id":"spiffe://innsegl.dev/agent/fix-ci/jira-118/run-43","agent_type":"fix-ci","task_ref":"JIRA-120","ts":"2026-08-28T09:14:04.201Z"}' \
  >"${FIX}/02-run_registered.canonical.json"
printf 'sha256:%s' "$(sha256 <"${FIX}/02-run_registered.canonical.json")" \
  >"${FIX}/02-run_registered.hash"
git -C "${repo}" add internal/event/testdata/fixtures/v1
run_gate 'v0.1.1'
expect green 'adding a fixture does not alter a released surface'
reset_tree

# --- phase 9: clean at the tag ----------------------------------------------
begin 'tagged, nothing changed, candidate v0.1.1 -> passes'
run_gate 'v0.1.1'
expect green 'a clean patch release passes'

# --- phase 10: the fixture README is not a vector -----------------------------
begin 'tagged, the fixture README edited, candidate v0.1.1 -> passes'
printf '# TC-SER golden fixtures\n\nThese files are immutable. Typo fixed.\n' \
  >"${FIX}/README.md"
run_gate 'v0.1.1'
expect green 'the prose beside the vectors is not itself a protected surface'
reset_tree

printf 'protected-surfaces gate self-test: PASS (%d phases)\n' "${phase}"
