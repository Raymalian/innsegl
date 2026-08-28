#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Protected-surfaces drift gate for Innsegl (RM-013, #21; test catalog SER-005).
#
# VERSIONING.md names five PROTECTED SURFACES and one rule about them:
#
#   "MINOR/PATCH releases MUST NOT alter any protected surface. CI enforces
#    this: the golden fixtures (TC-SER) and the contract schemas are diffed
#    against the previous tag; any drift fails the release."
#
# The five surfaces (VERSIONING.md "Protected surfaces"):
#
#   1. the event schema and canonical serialization at schema_version 1
#   2. the commit trailer keys Agent-Identity / Agent-Run / Agent-Task
#   3. the SPIFFE ID grammar
#   4. the MCP tool names and their error-class vocabulary
#   5. the project namespace (server name, package names, CLI binary name)
#
# WHAT THIS SCRIPT DOES, IN THREE PARTS
# -------------------------------------
# A. Self-verification of the golden fixtures. Re-derives, in shell, the genesis
#    constant and every committed digest from the committed canonical bytes, and
#    checks the serializer format fingerprint frozen in Go against the fixture
#    that also freezes it. Needs no baseline: it is a hard gate on the very first
#    run, before any tag exists.
#
# B. Protected-vocabulary presence. Every member name and enum value that appears
#    in a committed golden fixture must still appear verbatim as a string literal
#    in the shipped Go source; the trailer keys, tool names, SPIFFE grammar and
#    namespace must still be spelled the way VERSIONING.md spells them. This is
#    SER-005 at the repository level: renaming a protected string in the source
#    while the immutable fixtures still speak the old name fails the build with
#    no tag needed.
#
# C. Drift against the previous tag. Builds a manifest of every protected surface
#    at the baseline tag and at HEAD and diffs them. Removals and modifications
#    fail a MINOR/PATCH release. Golden-fixture modifications and deletions fail
#    ANY release, MAJOR included: doc 08 §3 requires the old version's fixtures
#    "retained and still asserted", and I4 says no record's bytes ever change.
#    The fixture tree's README and verify.py oracle are tracked as
#    `fixture-support` and are reported rather than fatal: VERSIONING.md protects
#    the vectors, not the prose beside them.
#
# When there is no previous tag — which is the state of this repository today,
# `git tag` returns nothing — part C is skipped with an explicit FIRST RUN
# notice, and parts A and B still run as hard gates. See ADR-0007.
#
# Usage:
#   scripts/protected-surfaces.sh [candidate-version]
#
# Environment:
#   PROTECTED_SURFACES_REPO_ROOT  repository to operate on (default: this repo)
#   PROTECTED_SURFACES_BASELINE   baseline ref, overriding tag discovery
#   PROTECTED_SURFACES_CANDIDATE  candidate version (e.g. v0.2.0); default is
#                                 GITHUB_REF_NAME when the ref is a tag, else
#                                 none, which is treated as MINOR/PATCH (strict)
#   PROTECTED_SURFACES_HEAD       ref to check instead of the working tree
#
# Portability: written for the bash 3.2 that ships with macOS. No `mapfile`, no
# arrays, no `${var,,}`. scripts/spdx-check.sh was rewritten once for exactly
# this reason; this script must not repeat it.

set -euo pipefail

# ---------------------------------------------------------------------------
# The protected vocabulary.
#
# Each line is "<kind>|<literal>|<source>". A literal whose source is
# VERSIONING.md must appear there inside a code span, and the script checks that
# it does: if the policy is reworded, this gate fails until its copy is updated
# in the same change. That is deliberate friction on a protected surface.
#
# The error classes are transcribed from IP §4, which is a local-only document.
# The script is therefore the only shipped enumeration of that vocabulary; see
# ADR-0007.
# ---------------------------------------------------------------------------
PROTECTED_VOCAB='trailer-key|Agent-Identity|VERSIONING.md
trailer-key|Agent-Run|VERSIONING.md
trailer-key|Agent-Task|VERSIONING.md
mcp-tool|register_agent|VERSIONING.md
mcp-tool|get_credential|VERSIONING.md
mcp-tool|record_event|VERSIONING.md
mcp-tool|sign_commit|VERSIONING.md
mcp-tool|retire_agent|VERSIONING.md
error-class|ATTESTATION_FAILED|IP4
error-class|IDENTITY_UNAVAILABLE|IP4
error-class|CREDENTIAL_EXPIRED|IP4
error-class|AUDIENCE_MISMATCH|IP4
error-class|LEDGER_UNAVAILABLE|IP4
error-class|SIGNING_UNAVAILABLE|IP4
error-class|TRANSPARENCY_UNAVAILABLE|IP4
error-class|RUN_NOT_FOUND|IP4
error-class|RUN_ALREADY_RETIRED|IP4
error-class|DUPLICATE_REQUEST|IP4
error-class|INVARIANT_VIOLATION|IP4'

# Kinds whose vocabulary lands as a set: if any member is present in the shipped
# source, all of them must be. That is what catches a rename with no tag to diff
# against. error-class is deliberately absent from this list — the MCP tools that
# return most of those classes are not built yet, so the set is legitimately
# partial today.
STRICT_KINDS='trailer-key mcp-tool'

# Additional VERSIONING.md literals that are not a vocabulary set of their own.
VERSIONING_SPIFFE_GRAMMAR='spiffe://{trust-domain}/agent/{agent-type}/{task-id}/{run-id}'
NAMESPACE='innsegl'
MODULE_PATH='innsegl.dev/innsegl'

# Where each surface lives.
FIXTURE_ROOT='internal/event/testdata/fixtures'
GO_SOURCE_ROOT='internal'
# Contract schemas: JSON schemas for the MCP tool surface. None exist yet
# (RM-022..025 build the tools); the paths are pinned here so they are covered
# the moment they land rather than a year afterwards.
CONTRACT_SCHEMA_PATHS='internal/mcp contracts api/schemas'

# ---------------------------------------------------------------------------
# Plumbing.
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${PROTECTED_SURFACES_REPO_ROOT:-$(cd -- "${SCRIPT_DIR}/.." && pwd)}"

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  sed -n '3,60p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 0
fi

cd -- "${REPO_ROOT}"

status=0
notices=0

log()  { printf '%s\n' "$*"; }
fail() { status=1; printf 'FAIL: %s\n' "$*" >&2; annotate_error "$*"; }
note() { notices=$((notices + 1)); printf 'note: %s\n' "$*"; }

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

if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 | cut -d' ' -f1; }
else
  printf 'FAIL: neither sha256sum nor shasum is available\n' >&2
  exit 1
fi

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/innsegl-protected-surfaces.XXXXXX")"
trap 'rm -rf "${WORKDIR}"' EXIT

if ! git rev-parse --git-dir >/dev/null 2>&1; then
  printf 'FAIL: %s is not a git repository\n' "${REPO_ROOT}" >&2
  exit 1
fi

HEAD_REF="${PROTECTED_SURFACES_HEAD:-WORKTREE}"

# list_at <ref> <pathspec>... — tracked paths under the pathspecs at that ref.
list_at() {
  _ref="$1"
  shift
  if [ "${_ref}" = "WORKTREE" ]; then
    git ls-files -- "$@" 2>/dev/null || true
  else
    git ls-tree -r --name-only "${_ref}" -- "$@" 2>/dev/null || true
  fi
}

# cat_at <ref> <path> — the bytes of that path at that ref.
cat_at() {
  if [ "$1" = "WORKTREE" ]; then
    [ -f "$2" ] && cat -- "$2"
  else
    git show "$1:$2" 2>/dev/null
  fi
  return 0
}

exists_at() {
  if [ "$1" = "WORKTREE" ]; then
    [ -f "$2" ]
  else
    git cat-file -e "$1:$2" 2>/dev/null
  fi
}

# ---------------------------------------------------------------------------
# Baseline and release kind.
#
# The release kind is derived from the tags, never asked of a human: a candidate
# version whose MAJOR component exceeds the baseline's is a MAJOR release and may
# change protected surfaces (with everything doc 08 §3 requires); anything else
# is MINOR/PATCH and may not. A working tree with no candidate version is treated
# as MINOR/PATCH, which is the strict reading — an unreleased branch cannot
# license drift by saying nothing. See ADR-0007.
# ---------------------------------------------------------------------------
semver_major() { printf '%s' "${1#v}" | cut -d. -f1; }

is_semver() {
  printf '%s' "$1" | grep -Eq '^v?[0-9]+\.[0-9]+\.[0-9]+([-+].*)?$'
}

CANDIDATE="${1:-${PROTECTED_SURFACES_CANDIDATE:-}}"
if [ -z "${CANDIDATE}" ] && [ "${GITHUB_REF_TYPE:-}" = "tag" ]; then
  CANDIDATE="${GITHUB_REF_NAME:-}"
fi

BASELINE="${PROTECTED_SURFACES_BASELINE:-}"
if [ -z "${BASELINE}" ]; then
  if [ -n "${CANDIDATE}" ]; then
    BASELINE="$(git tag --sort=-v:refname --merged HEAD 2>/dev/null \
      | grep -Ex 'v?[0-9]+\.[0-9]+\.[0-9]+' | grep -vx "${CANDIDATE}" | head -1 || true)"
  else
    BASELINE="$(git tag --sort=-v:refname --merged HEAD 2>/dev/null \
      | grep -Ex 'v?[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
  fi
fi

if [ -n "${BASELINE}" ] && ! git rev-parse --verify --quiet "${BASELINE}^{commit}" >/dev/null; then
  printf 'FAIL: baseline ref %s does not resolve to a commit\n' "${BASELINE}" >&2
  exit 1
fi

RELEASE_KIND='minor-or-patch'
RELEASE_WHY='no candidate version: an unreleased tree is held to the MINOR/PATCH rule'
if [ -n "${CANDIDATE}" ]; then
  if ! is_semver "${CANDIDATE}"; then
    printf 'FAIL: candidate version %s is not vMAJOR.MINOR.PATCH\n' "${CANDIDATE}" >&2
    exit 1
  fi
  if [ -n "${BASELINE}" ] && is_semver "${BASELINE}"; then
    if [ "$(semver_major "${CANDIDATE}")" -gt "$(semver_major "${BASELINE}")" ]; then
      RELEASE_KIND='major'
      RELEASE_WHY="candidate ${CANDIDATE} raises the MAJOR component over baseline ${BASELINE}"
    else
      RELEASE_WHY="candidate ${CANDIDATE} keeps baseline ${BASELINE}'s MAJOR component"
    fi
  else
    RELEASE_WHY="candidate ${CANDIDATE} with no baseline to compare a MAJOR bump against"
  fi
fi

log '==> protected surfaces — VERSIONING.md, enforced (RM-013 / SER-005)'
log ""
printf '    repository   %s\n' "${REPO_ROOT}"
printf '    head         %s\n' "${HEAD_REF}"
printf '    baseline     %s\n' "${BASELINE:-(none — no previous tag)}"
printf '    candidate    %s\n' "${CANDIDATE:-(none — unreleased working tree)}"
printf '    release kind %s (%s)\n' "${RELEASE_KIND}" "${RELEASE_WHY}"

# ===========================================================================
# Part A — the golden fixtures verify themselves.
# ===========================================================================
log ""
log "==> A. golden fixtures re-derived from their own bytes (no baseline needed)"

fixture_files="${WORKDIR}/fixture-files"
list_at "${HEAD_REF}" "${FIXTURE_ROOT}" | LC_ALL=C sort >"${fixture_files}"
n_fixture_files="$(grep -c . "${fixture_files}" || true)"

if [ "${n_fixture_files}" -eq 0 ]; then
  fail "no golden fixtures under ${FIXTURE_ROOT}/ — surface 1 has no byte-level definition"
else
  printf '    %s tracked files under %s/\n' "${n_fixture_files}" "${FIXTURE_ROOT}"

  # Shipped, non-test Go source: the corpus a protected string must still be
  # spelled in. Built once and reused by parts A3 and B1.
  go_sources="${WORKDIR}/go-sources"
  : >"${go_sources}"
  while IFS= read -r p; do
    [ -n "${p}" ] || continue
    case "${p}" in *_test.go) continue ;; esac
    cat_at "${HEAD_REF}" "${p}" >>"${go_sources}"
    printf '\n' >>"${go_sources}"
  done <<EOT
$(list_at "${HEAD_REF}" "${GO_SOURCE_ROOT}" | grep -E '\.go$' || true)
EOT

  # A1. genesis constant: doc 02 §4.4 says compute it, never hardcode it.
  # Re-derived here in shell, which is a third oracle beside Go and verify.py.
  while IFS= read -r gpath; do
    [ -n "${gpath}" ] || continue
    want="$(cat_at "${HEAD_REF}" "${gpath}")"
    got="sha256:$(printf 'innsegl-genesis-v1' | sha256)"
    if [ "${want}" = "${got}" ]; then
      printf '    genesis constant re-derived from "innsegl-genesis-v1": OK\n'
    else
      fail "${gpath} is ${want}, but SHA-256(\"innsegl-genesis-v1\") is ${got}"
    fi
  done <<EOT
$(grep -E '/genesis\.hash$' "${fixture_files}" || true)
EOT

  # A2. every <name>.hash is SHA-256 of its own <name>.canonical.json.
  rederived=0
  while IFS= read -r cpath; do
    [ -n "${cpath}" ] || continue
    hpath="${cpath%.canonical.json}.hash"
    if ! exists_at "${HEAD_REF}" "${hpath}"; then
      fail "${cpath} has no committed digest at ${hpath}"
      continue
    fi
    want="$(cat_at "${HEAD_REF}" "${hpath}")"
    got="sha256:$(cat_at "${HEAD_REF}" "${cpath}" | sha256)"
    if [ "${want}" = "${got}" ]; then
      rederived=$((rederived + 1))
    else
      fail "${hpath} is ${want}, but SHA-256 of ${cpath} is ${got}"
    fi
  done <<EOT
$(grep -E '\.canonical\.json$' "${fixture_files}" || true)
EOT
  printf '    %s canonical fixtures re-hashed against their committed digests: OK\n' "${rederived}"

  # A3. the serializer format fingerprint is frozen twice — as a constant in
  # canonical.go and as format-probe.hash. They must agree, or the serializer
  # changed under an unchanged version tag, which is SER-005 exactly.
  probe_hash_path="$(grep -E '/format-probe\.hash$' "${fixture_files}" | head -1 || true)"
  if [ -z "${probe_hash_path}" ]; then
    fail "no format-probe.hash under ${FIXTURE_ROOT}/ — the serializer format is unpinned (SER-005)"
  else
    probe_hash="$(cat_at "${HEAD_REF}" "${probe_hash_path}")"
    if grep -qF -- "\"${probe_hash}\"" "${go_sources}"; then
      printf '    serializer format fingerprint %s frozen in both Go and %s: OK\n' \
        "${probe_hash}" "$(basename "${probe_hash_path}")"
    else
      fail "the format fingerprint ${probe_hash} committed in ${probe_hash_path} appears in no ${GO_SOURCE_ROOT}/ Go source — the serializer format moved under an unchanged version tag (SER-005)"
    fi
  fi
fi

# ===========================================================================
# Part B — the shipped source still speaks the protected vocabulary.
# ===========================================================================
log ""
log "==> B. protected vocabulary present in the shipped source (no baseline needed)"

# B0. The script's copy of the VERSIONING.md literals must match the policy.
versioning="${WORKDIR}/VERSIONING.md"
cat_at "${HEAD_REF}" VERSIONING.md >"${versioning}"
if [ ! -s "${versioning}" ]; then
  fail "VERSIONING.md is missing — the policy this gate enforces is not in the tree"
else
  vmismatch=0
  while IFS='|' read -r kind literal src; do
    [ -n "${kind:-}" ] || continue
    [ "${src}" = "VERSIONING.md" ] || continue
    grep -qF -- "\`${literal}\`" "${versioning}" || {
      fail "VERSIONING.md no longer names \`${literal}\`: this gate's copy of the protected vocabulary is stale, or a protected string was renamed in the policy"
      vmismatch=$((vmismatch + 1))
    }
  done <<EOT
${PROTECTED_VOCAB}
EOT
  for lit in "${VERSIONING_SPIFFE_GRAMMAR}" "${NAMESPACE}"; do
    grep -qF -- "\`${lit}\`" "${versioning}" || {
      fail "VERSIONING.md no longer names \`${lit}\`"
      vmismatch=$((vmismatch + 1))
    }
  done
  [ "${vmismatch}" -eq 0 ] && printf '    this gate'"'"'s vocabulary still matches VERSIONING.md verbatim: OK\n'
fi

# The corpus a protected string must still be spelled in: tracked, shipped, not
# prose, and not this script (which names every literal and would otherwise make
# the check pass by talking about itself).
corpus="${WORKDIR}/corpus"
: >"${corpus}"
while IFS= read -r p; do
  [ -n "${p}" ] || continue
  case "${p}" in
    docs/*|*.md|scripts/protected-surfaces.sh|scripts/protected-surfaces-selftest.sh) continue ;;
  esac
  cat_at "${HEAD_REF}" "${p}" >>"${corpus}" 2>/dev/null || true
  printf '\n' >>"${corpus}"
done <<EOT
$(list_at "${HEAD_REF}" . || true)
EOT

# B1. fixture-derived member names and enum values must still be string literals
# in the shipped Go source. The fixtures are immutable, so this is the check that
# makes a silent rename impossible with no tag in the repository (SER-005).
if [ "${n_fixture_files}" -gt 0 ]; then
  fixture_json="${WORKDIR}/fixture-json"
  : >"${fixture_json}"
  while IFS= read -r p; do
    [ -n "${p}" ] || continue
    cat_at "${HEAD_REF}" "${p}" >>"${fixture_json}"
    printf '\n' >>"${fixture_json}"
  done <<EOT
$(grep -E '\.canonical\.json$' "${fixture_files}" || true)
EOT

  serialized_members="${WORKDIR}/serialized-members"
  grep -oa '[{,]"[A-Za-z0-9_~]*":' "${fixture_json}" \
    | sed -e 's/^[{,]"//' -e 's/":$//' | LC_ALL=C sort -u >"${serialized_members}"

  serialized_enums="${WORKDIR}/serialized-enums"
  {
    grep -oa '"event_type":"[A-Za-z0-9_]*"' "${fixture_json}" \
      | sed -e 's/^"event_type":"//' -e 's/"$//' || true
    grep -oa '"source":"[A-Za-z0-9_]*"' "${fixture_json}" \
      | sed -e 's/^"source":"//' -e 's/"$//' || true
  } | LC_ALL=C sort -u >"${serialized_enums}"

  missing=0
  while IFS= read -r name; do
    [ -n "${name}" ] || continue
    grep -qF -- "\"${name}\"" "${go_sources}" || {
      fail "the golden fixtures serialize the member \"${name}\", but no ${GO_SOURCE_ROOT}/ Go source contains that string literal — a protected field name was renamed while the immutable fixtures still carry it (SER-005)"
      missing=$((missing + 1))
    }
  done <"${serialized_members}"
  while IFS= read -r v; do
    [ -n "${v}" ] || continue
    grep -qF -- "\"${v}\"" "${go_sources}" || {
      fail "the golden fixtures carry the enum value \"${v}\", but no ${GO_SOURCE_ROOT}/ Go source contains that string literal — a protected enum value was renamed (SER-005)"
      missing=$((missing + 1))
    }
  done <"${serialized_enums}"
  printf '    %s serialized member names and %s enum values from the fixtures, all present in %s/: %s\n' \
    "$(grep -c . "${serialized_members}" || true)" \
    "$(grep -c . "${serialized_enums}" || true)" \
    "${GO_SOURCE_ROOT}" \
    "$([ "${missing}" -eq 0 ] && echo OK || echo BREACHED)"
fi

# B2. vocabulary sets. Presence is recorded either way; a partially present
# strict set is a rename and fails.
vocab_state="${WORKDIR}/vocab-state"
: >"${vocab_state}"
while IFS='|' read -r kind literal src; do
  [ -n "${kind:-}" ] || continue
  if grep -qF -- "${literal}" "${corpus}"; then
    printf '%s\t%s\tpresent\n' "${kind}" "${literal}" >>"${vocab_state}"
  else
    printf '%s\t%s\tabsent\n' "${kind}" "${literal}" >>"${vocab_state}"
  fi
done <<EOT
${PROTECTED_VOCAB}
EOT

printf '    %-14s %7s %7s  %s\n' "KIND" "PRESENT" "TOTAL" "RESULT"
for kind in trailer-key mcp-tool error-class; do
  total="$(awk -F'\t' -v k="${kind}" '$1 == k' "${vocab_state}" | grep -c . || true)"
  present="$(awk -F'\t' -v k="${kind}" '$1 == k && $3 == "present"' "${vocab_state}" | grep -c . || true)"
  strict=no
  for sk in ${STRICT_KINDS}; do [ "${sk}" = "${kind}" ] && strict=yes; done
  result='not present yet'
  if [ "${present}" -eq "${total}" ]; then
    result='OK'
  elif [ "${present}" -gt 0 ]; then
    if [ "${strict}" = yes ]; then
      result='BREACHED (partial set)'
      fail "${kind}: ${present}/${total} present. A protected string set is never partial; the missing member was renamed or dropped: $(awk -F'\t' -v k="${kind}" '$1 == k && $3 == "absent" { printf "%s ", $2 }' "${vocab_state}")"
    else
      result="partial (${present}/${total}) — allowed, surface incomplete"
      note "${kind}: $((total - present)) of ${total} values are not in the tree yet; the MCP tools that return them are not built (RM-022..025)"
    fi
  else
    note "${kind}: none of the ${total} values are in the tree yet — surface not implemented"
    annotate_warning "protected surface ${kind} is not implemented yet: nothing to pin"
  fi
  printf '    %-14s %7s %7s  %s\n' "${kind}" "${present}" "${total}" "${result}"
done

# B3. SPIFFE ID grammar. Doc 02 §5 and VERSIONING.md spell the placeholders
# differently (underscores against hyphens), so the check is on the parts of the
# grammar that carry meaning: the scheme, the /agent/ path element, the five
# path segments, and the segment grammar itself.
if grep -qF -- 'spiffe://' "${corpus}"; then
  spiffe_ok=yes
  grep -qF -- '/agent/' "${corpus}" || spiffe_ok=no
  grep -qE 'spiffe://\{(trust[_-]domain)\}/agent/\{(agent[_-]type)\}/\{(task[_-]id)\}/\{(run[_-]id)\}' "${corpus}" || spiffe_ok=no
  grep -qF -- '[a-z0-9][a-z0-9-]{0,62}' "${corpus}" || spiffe_ok=no
  if [ "${spiffe_ok}" = yes ]; then
    printf '    SPIFFE ID grammar spiffe://{trust_domain}/agent/{agent_type}/{task_id}/{run_id}: OK\n'
  else
    fail "the shipped source uses spiffe:// but no longer states the grammar spiffe://{trust_domain}/agent/{agent_type}/{task_id}/{run_id} with segments matching [a-z0-9][a-z0-9-]{0,62} (VERSIONING.md surface 3, doc 02 §5)"
  fi
else
  note "SPIFFE ID grammar: no spiffe:// anywhere in the shipped source yet — surface not implemented"
fi

# B4. Namespace: module path, CLI binary name, command directory.
ns_ok=yes
gomod="$(cat_at "${HEAD_REF}" go.mod || true)"
if [ -n "${gomod}" ]; then
  if ! printf '%s\n' "${gomod}" | grep -qx "module ${MODULE_PATH}"; then
    fail "go.mod does not declare module ${MODULE_PATH} (VERSIONING.md surface 5: the package names)"
    ns_ok=no
  fi
else
  note "namespace: no go.mod at ${HEAD_REF}"
  ns_ok=skip
fi
makefile="$(cat_at "${HEAD_REF}" Makefile || true)"
if [ -n "${makefile}" ]; then
  if ! printf '%s\n' "${makefile}" | grep -qE "^BINARY[[:space:]]*:?=[[:space:]]*${NAMESPACE}[[:space:]]*$"; then
    fail "the Makefile no longer builds a binary named ${NAMESPACE} (VERSIONING.md surface 5: the CLI binary name)"
    ns_ok=no
  fi
fi
if [ -n "$(list_at "${HEAD_REF}" "cmd/${NAMESPACE}")" ]; then
  :
else
  fail "cmd/${NAMESPACE}/ does not exist (VERSIONING.md surface 5: the CLI binary name)"
  ns_ok=no
fi
[ "${ns_ok}" = yes ] && printf '    namespace: module %s, binary %s, cmd/%s: OK\n' \
  "${MODULE_PATH}" "${NAMESPACE}" "${NAMESPACE}"

# ===========================================================================
# Part C — drift against the previous tag.
# ===========================================================================
log ""
log "==> C. drift against the previous tag"

# manifest <ref> <out> — one line per protected-surface fact, "kind<TAB>key<TAB>value".
manifest() {
  _ref="$1"
  _out="$2"
  {
    while IFS= read -r p; do
      [ -n "${p}" ] || continue
      # Only the vectors themselves are the protected surface. The README and
      # the verify.py oracle live in the same tree and are supporting material:
      # VERSIONING.md protects "the golden serialization fixtures" and "the
      # contract schemas", not the prose beside them, and a patch release must
      # be able to fix a typo or add a check to the oracle.
      case "${p}" in
        *.canonical.json|*.input.json|*.hash) _kind=fixture ;;
        *) _kind=fixture-support ;;
      esac
      printf '%s\t%s\t%s\n' "${_kind}" "${p}" "$(cat_at "${_ref}" "${p}" | sha256)"
    done <<EOT
$(list_at "${_ref}" "${FIXTURE_ROOT}")
EOT
    while IFS= read -r p; do
      [ -n "${p}" ] || continue
      case "${p}" in *.json) ;; *) continue ;; esac
      printf 'contract-schema\t%s\t%s\n' "${p}" "$(cat_at "${_ref}" "${p}" | sha256)"
    done <<EOT
$(list_at "${_ref}" ${CONTRACT_SCHEMA_PATHS})
EOT
    _json="${WORKDIR}/manifest-json.$$"
    : >"${_json}"
    while IFS= read -r p; do
      [ -n "${p}" ] || continue
      case "${p}" in *.canonical.json) ;; *) continue ;; esac
      cat_at "${_ref}" "${p}" >>"${_json}"
      printf '\n' >>"${_json}"
    done <<EOT
$(list_at "${_ref}" "${FIXTURE_ROOT}")
EOT
    grep -oa '[{,]"[A-Za-z0-9_~]*":' "${_json}" | sed -e 's/^[{,]"//' -e 's/":$//' \
      | LC_ALL=C sort -u | sed 's/^/serialized-member\t/;s/$/\tin-fixtures/' || true
    {
      grep -oa '"event_type":"[A-Za-z0-9_]*"' "${_json}" | sed -e 's/^"event_type":"/event_type=/' -e 's/"$//' || true
      grep -oa '"source":"[A-Za-z0-9_]*"' "${_json}" | sed -e 's/^"source":"/source=/' -e 's/"$//' || true
    } | LC_ALL=C sort -u | sed 's/^/serialized-enum\t/;s/$/\tin-fixtures/'
    rm -f "${_json}"

    _corpus="${WORKDIR}/manifest-corpus.$$"
    : >"${_corpus}"
    while IFS= read -r p; do
      [ -n "${p}" ] || continue
      case "${p}" in
        docs/*|*.md|scripts/protected-surfaces.sh|scripts/protected-surfaces-selftest.sh) continue ;;
      esac
      cat_at "${_ref}" "${p}" >>"${_corpus}" 2>/dev/null || true
      printf '\n' >>"${_corpus}"
    done <<EOT
$(list_at "${_ref}" .)
EOT
    while IFS='|' read -r kind literal src; do
      [ -n "${kind:-}" ] || continue
      if grep -qF -- "${literal}" "${_corpus}"; then
        printf '%s\t%s\tpresent\n' "${kind}" "${literal}"
      else
        printf '%s\t%s\tabsent\n' "${kind}" "${literal}"
      fi
    done <<EOT
${PROTECTED_VOCAB}
EOT
    rm -f "${_corpus}"
  } | LC_ALL=C sort >"${_out}"
}

if [ -z "${BASELINE}" ]; then
  log ""
  log "    FIRST RUN — this repository has no previous tag."
  log ""
  log "    \`git tag\` returns nothing, so there is no released baseline to diff"
  log "    against and part C is not applicable. It is skipped deliberately, not"
  log "    silently: parts A and B above ran as hard gates and would have failed"
  log "    this build on a renamed protected string with no tag in sight. The"
  log "    moment a v*.*.* tag exists, part C begins comparing against it with no"
  log "    change to this script. See ADR-0007."
  log ""
  printf '    surfaces that will be diffed at the next tag:\n'
  head_manifest="${WORKDIR}/head.manifest"
  manifest "${HEAD_REF}" "${head_manifest}"
  for kind in fixture fixture-support contract-schema serialized-member serialized-enum trailer-key mcp-tool error-class; do
    n="$(awk -F'\t' -v k="${kind}" '$1 == k' "${head_manifest}" | grep -c . || true)"
    printf '      %-18s %4s entries\n' "${kind}" "${n}"
  done
  annotate_warning "protected-surfaces: no previous tag, so the tag diff (part C) was skipped; parts A and B still gated this build"
  summary "> **Protected surfaces:** first run — no previous tag, so the tag diff was skipped. The fixture re-derivation and vocabulary checks still ran as hard gates."
else
  base_manifest="${WORKDIR}/base.manifest"
  head_manifest="${WORKDIR}/head.manifest"
  manifest "${BASELINE}" "${base_manifest}"
  manifest "${HEAD_REF}" "${head_manifest}"

  printf '    %s entries at %s, %s at %s\n' \
    "$(grep -c . "${base_manifest}" || true)" "${BASELINE}" \
    "$(grep -c . "${head_manifest}" || true)" "${HEAD_REF}"

  # Classify. Key is kind+key; a key gone is REMOVED, a value changed is
  # CHANGED, a key new is ADDED.
  changes="${WORKDIR}/changes"
  # Two-file merge in awk rather than join(1): join's -o/-a handling differs
  # between BSD and GNU, and this has to behave identically on a contributor's
  # Mac and on CI.
  awk -F'\t' '
      NR == FNR { base[$1 "\034" $2] = $3; seen[$1 "\034" $2] = 1; next }
      {
        k = $1 "\034" $2
        head[k] = $3
        if (!(k in base)) { printf "ADDED\t%s\t%s\t\t%s\n", $1, $2, $3 }
        else if (base[k] != $3) { printf "CHANGED\t%s\t%s\t%s\t%s\n", $1, $2, base[k], $3 }
        delete seen[k]
      }
      END {
        for (k in seen) {
          i = index(k, "\034")
          printf "REMOVED\t%s\t%s\t%s\t\n", substr(k, 1, i - 1), substr(k, i + 1), base[k]
        }
      }' "${base_manifest}" "${head_manifest}" | LC_ALL=C sort >"${changes}"

  n_changes="$(grep -c . "${changes}" || true)"
  if [ "${n_changes}" -eq 0 ]; then
    printf '    no drift on any protected surface since %s: OK\n' "${BASELINE}"
  else
    printf '\n    %-8s %-18s %s\n' "VERDICT" "SURFACE" "KEY"
    breaching=0
    while IFS="$(printf '\t')" read -r verdict kind key was now; do
      [ -n "${verdict}" ] || continue
      printf '    %-8s %-18s %s\n' "${verdict}" "${kind}" "${key}"
      case "${verdict}" in
        ADDED)
          # An addition extends a surface without altering what is already
          # released. A rename shows up as REMOVED + ADDED and is caught by the
          # removal half, so nothing is let through here.
          note "${kind} ${key} is new since ${BASELINE}; additions do not alter a released surface"
          ;;
        REMOVED|CHANGED)
          if [ "${kind}" = "fixture-support" ]; then
            # Supporting material beside the vectors. Reported so the change is
            # visible in the release log, never fatal.
            note "${kind} ${key} was ${verdict} since ${BASELINE}; the fixture README and oracle are not themselves a protected surface"
          elif [ "${kind}" = "fixture" ]; then
            fail "golden fixture ${key} was ${verdict} since ${BASELINE}. Fixtures are immutable once merged, on EVERY release including a MAJOR one: doc 08 §3 requires the old version's fixtures retained and still asserted, and I4 forbids changing bytes already written. A new schema version adds a new fixture directory; it never edits this one."
            breaching=$((breaching + 1))
          elif [ "${RELEASE_KIND}" = "major" ]; then
            note "${kind} ${key} was ${verdict} since ${BASELINE}; permitted on a MAJOR release"
            breaching=$((breaching + 1))
          else
            fail "protected surface drift: ${kind} ${key} was ${verdict} since ${BASELINE} (was \"${was}\", now \"${now}\"). VERSIONING.md: MINOR/PATCH releases MUST NOT alter any protected surface."
            breaching=$((breaching + 1))
          fi
          ;;
      esac
    done <"${changes}"

    # A MAJOR release that actually moves a protected surface owes doc 08 §3(d):
    # a superseding ADR in the same release.
    if [ "${RELEASE_KIND}" = "major" ] && [ "${breaching}" -gt 0 ]; then
      new_adrs="$(git diff --name-only --diff-filter=A "${BASELINE}" -- docs/adr 2>/dev/null | grep -c . || true)"
      if [ "${new_adrs}" -eq 0 ]; then
        fail "a MAJOR release may change protected surfaces only with a superseding ADR in the same release (doc 08 §3(d), VERSIONING.md), and no new file was added under docs/adr/ since ${BASELINE}"
      else
        printf '    MAJOR release carries %s new ADR(s) under docs/adr/ since %s: OK\n' \
          "${new_adrs}" "${BASELINE}"
        note "a MAJOR release must also ship a new schema_version accepted alongside every previous one, new golden fixtures with the old set retained, and a signed migration attestation event marking the cutover position (doc 08 §3(a)-(c)). This gate checks (b)'s retention and (d)'s ADR; (a) and (c) are not mechanically checkable here."
      fi
    fi
  fi
fi

# ===========================================================================
log ""
if [ "${status}" -ne 0 ]; then
  log "protected surfaces: BREACHED"
  summary "**Protected surfaces: BREACHED.** See the job log."
else
  log "protected surfaces: OK (${notices} notice(s))"
fi
exit "${status}"
