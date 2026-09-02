#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Canonical-namespace gate for Innsegl (RM-059, #67; proposed test catalog REL-003).
#
# Doc 04 asset A6 is the namespace itself — `innsegl` on GitHub/npm/PyPI and the
# `innsegl.dev` domain — because squatting or typosquatting the namespace of an
# attribution tool poisons the supply chain of the thing whose entire product is
# supply-chain truth. Abuse case AB-09 is the typosquat.
#
# No test can make a registry refuse a squatter, so the operational half of AB-09
# (the registrations themselves, registrar 2FA, auto-renew) lives in PROCEDURE.md
# and is executed by a human. ADR-0040 says what the checkable half is, and this
# script is that half:
#
#   1. the canonical names are enumerated in exactly one place —
#      namespace/canonical-names.txt — so there is a single thing to defend;
#   2. what this repository actually ships agrees with that enumeration
#      (the Go module path, the CLI binary name, the licence);
#   3. the stub packages that hold the registry names are real links back to
#      this repository — same name, same licence, same repo, same domain, same
#      version — rather than empty shells that assert nothing.
#
# Point 3 is the part worth having. A placeholder that says nothing is squatting
# performed by us; a stub that installs and tells a developer where the real
# implementation lives is a control.
#
# Deliberately offline. It asserts what this repository claims, not what a
# registry currently serves — a network check would make CI depend on npmjs.com
# being up, and would turn an outage into a red build. Proving that the claimed
# registrations resolve is PROCEDURE.md's job, done by a human with an account.
#
# Usage: namespace/verify-namespace.sh
# Exit:  0 all assertions hold; 1 at least one failed.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${NAMESPACE_REPO_ROOT:-$(cd -- "${SCRIPT_DIR}/.." && pwd)}"
NS_DIR="${REPO_ROOT}/namespace"
NAMES="${NS_DIR}/canonical-names.txt"

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  sed -n '3,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 0
fi

cd -- "${REPO_ROOT}"

status=0
checks=0

log()  { printf '%s\n' "$*"; }
ok()   { checks=$((checks + 1)); printf '    %s\n' "$*"; }
fail() {
  status=1
  checks=$((checks + 1))
  printf 'FAIL: %s\n' "$*" >&2
  [ -n "${GITHUB_ACTIONS:-}" ] && printf '::error::%s\n' "$*"
  return 0
}

# The kinds canonical-names.txt must carry. Missing any one of them means the
# enumeration has quietly stopped being complete, which is how a namespace gets
# lost: not by an attack, but by a name nobody was watching.
REQUIRED_KINDS='go-module cli-binary mcp-server npm-package npm-scope pypi-project domain github-repo licence'

# name_of <kind> — the second field of that kind's row, empty if absent.
name_of() {
  awk -F'|' -v k="$1" '!/^#/ && NF>=2 && $1==k { print $2; exit }' "${NAMES}"
}

# ---------------------------------------------------------------------------
# A. The enumeration exists and is complete.
# ---------------------------------------------------------------------------
log "==> A. the canonical names are enumerated in exactly one place"

if [ ! -f "${NAMES}" ]; then
  fail "${NAMES#"${REPO_ROOT}"/} does not exist — the canonical names are enumerated nowhere, so nothing downstream can be checked against them (doc 04 A6, ADR-0040 REL-003)"
  printf '\nnamespace: FAILED (%d check(s), %d failure(s) — enumeration missing)\n' "${checks}" 1 >&2
  exit 1
fi

for kind in ${REQUIRED_KINDS}; do
  if [ -z "$(name_of "${kind}")" ]; then
    fail "canonical-names.txt has no ${kind} row — the enumeration is incomplete (doc 04 A6)"
  fi
done

GO_MODULE="$(name_of go-module)"
CLI_BINARY="$(name_of cli-binary)"
MCP_SERVER="$(name_of mcp-server)"
NPM_PACKAGE="$(name_of npm-package)"
NPM_SCOPE="$(name_of npm-scope)"
PYPI_PROJECT="$(name_of pypi-project)"
DOMAIN="$(name_of domain)"
GITHUB_REPO="$(name_of github-repo)"
LICENCE="$(name_of licence)"

[ "${status}" -eq 0 ] && ok "$(printf '%s\n' ${REQUIRED_KINDS} | wc -l | tr -d ' ') kinds enumerated in namespace/canonical-names.txt: OK"

# The scope is the package name with an @: anything else means one of the two
# moved and the other did not, and a scope nobody owns is a free namespace.
if [ "${NPM_SCOPE}" != "@${NPM_PACKAGE}" ]; then
  fail "npm scope ${NPM_SCOPE} is not @${NPM_PACKAGE}: the org that locks the scope and the package that holds the bare name must be the same word"
else
  ok "npm scope ${NPM_SCOPE} matches the bare package ${NPM_PACKAGE}: OK"
fi

# ---------------------------------------------------------------------------
# B. What this repository ships agrees with the enumeration.
#
# VERSIONING.md surface 5 makes these strings protected; scripts/protected-
# surfaces.sh (SER-005) is the gate that stops them drifting between releases.
# This half asserts something different and narrower: that the enumeration and
# the shipped tree name the same project. Deferring to SER-005 rather than
# re-implementing it is ADR-0040's instruction.
# ---------------------------------------------------------------------------
log ""
log "==> B. the shipped repository agrees with the enumeration"

if ! grep -qx "module ${GO_MODULE}" go.mod; then
  fail "go.mod does not declare module ${GO_MODULE} (canonical-names.txt go-module; VERSIONING.md surface 5)"
else
  ok "go.mod declares module ${GO_MODULE}: OK"
fi

if ! grep -qE "^BINARY[[:space:]]*:?=[[:space:]]*${CLI_BINARY}[[:space:]]*$" Makefile; then
  fail "the Makefile does not build a binary named ${CLI_BINARY} (canonical-names.txt cli-binary)"
elif [ ! -d "cmd/${CLI_BINARY}" ]; then
  fail "cmd/${CLI_BINARY}/ does not exist (canonical-names.txt cli-binary)"
else
  ok "Makefile BINARY and cmd/${CLI_BINARY}/ are ${CLI_BINARY}: OK"
fi

# The Go module path must sit under the domain, or the domain lapsing takes the
# module path with it — the same event, twice.
case "${GO_MODULE}" in
  "${DOMAIN}"/*) ok "module path ${GO_MODULE} is rooted at the owned domain ${DOMAIN}: OK" ;;
  *) fail "module path ${GO_MODULE} is not rooted at ${DOMAIN}: the module path depends on a name the project does not claim" ;;
esac

if ! grep -q 'Apache License' LICENSE || ! grep -q 'Version 2.0' LICENSE; then
  fail "LICENSE is not the Apache License 2.0 text, but canonical-names.txt claims ${LICENCE}"
elif [ "${LICENCE}" != "Apache-2.0" ]; then
  fail "canonical-names.txt licence is ${LICENCE}, but LICENSE is Apache-2.0 and doc 08 §1 fixes Apache-2.0"
else
  ok "LICENSE is Apache-2.0 and matches the enumerated licence: OK"
fi

if ! grep -qF "\`${MCP_SERVER}\`" VERSIONING.md; then
  fail "VERSIONING.md does not name the MCP server ${MCP_SERVER} (canonical-names.txt mcp-server; VERSIONING.md surface 5)"
else
  ok "VERSIONING.md names the MCP server ${MCP_SERVER}: OK"
fi

# ---------------------------------------------------------------------------
# C. The stub packages are genuine links back to this repository.
#
# This is the assertion the issue turns on. A registration held by an empty
# package is a name the project owns and a developer learns nothing from; the
# stub has to survive `npx innsegl` and tell them where the real thing is.
# ---------------------------------------------------------------------------
log ""
log "==> C. the registry stubs link back to this repository"

PKG_JSON="${NS_DIR}/npm/package.json"
PYPROJECT="${NS_DIR}/pypi/pyproject.toml"
NPM_README="${NS_DIR}/npm/README.md"
PYPI_README="${NS_DIR}/pypi/README.md"
PY_INIT="${NS_DIR}/pypi/src/innsegl/__init__.py"

# json_field <file> <key> — the string value of a top-level JSON key. The stub
# package.json is hand-written and flat by design, so a grep is honest here and
# avoids making a shell gate depend on node being installed.
json_field() {
  grep -Eo "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$1" 2>/dev/null \
    | head -1 | sed -E 's/.*:[[:space:]]*"(.*)"$/\1/'
}

# toml_field <file> <key> — the string value of a `key = "value"` line.
toml_field() {
  grep -E "^$2[[:space:]]*=[[:space:]]*\"" "$1" 2>/dev/null \
    | head -1 | sed -E 's/^[^=]*=[[:space:]]*"(.*)".*/\1/'
}

for f in "${PKG_JSON}" "${PYPROJECT}" "${NPM_README}" "${PYPI_README}" "${PY_INIT}"; do
  [ -f "${f}" ] || fail "${f#"${REPO_ROOT}"/} does not exist — the source of a published registry artifact is not in this repository, so the artifact holding ${NPM_PACKAGE} has no reviewable origin"
done

if [ "${status}" -ne 0 ]; then
  printf '\nnamespace: FAILED (%d check(s)) — see failures above\n' "${checks}" >&2
  exit 1
fi

# C1. names.
[ "$(json_field "${PKG_JSON}" name)" = "${NPM_PACKAGE}" ] \
  && ok "npm stub is named ${NPM_PACKAGE}: OK" \
  || fail "npm stub package.json name is $(json_field "${PKG_JSON}" name), not the enumerated ${NPM_PACKAGE}"

[ "$(toml_field "${PYPROJECT}" name)" = "${PYPI_PROJECT}" ] \
  && ok "PyPI stub is named ${PYPI_PROJECT}: OK" \
  || fail "PyPI stub pyproject name is $(toml_field "${PYPROJECT}" name), not the enumerated ${PYPI_PROJECT}"

# C2. licence metadata. A stub carrying the wrong licence is a worse artifact
# than no stub: it is a false statement about the project, published under the
# project's own name, by the project.
[ "$(json_field "${PKG_JSON}" license)" = "${LICENCE}" ] \
  && ok "npm stub declares license ${LICENCE}: OK" \
  || fail "npm stub package.json license is '$(json_field "${PKG_JSON}" license)', not ${LICENCE} (doc 08 §1; must match LICENSE)"

[ "$(toml_field "${PYPROJECT}" license)" = "${LICENCE}" ] \
  && ok "PyPI stub declares license ${LICENCE}: OK" \
  || fail "PyPI stub pyproject license is '$(toml_field "${PYPROJECT}" license)', not ${LICENCE} (doc 08 §1; must match LICENSE)"

# C3. versions agree across the three files that state one. A stub whose
# __init__ says 0.0.1 while its metadata says 0.0.2 publishes a lie about
# itself, from the project whose product is that artifacts do not lie.
NPM_VERSION="$(json_field "${PKG_JSON}" version)"
PYPI_VERSION="$(toml_field "${PYPROJECT}" version)"
PY_VERSION="$(grep -E '^__version__' "${PY_INIT}" | head -1 | sed -E 's/.*"(.*)".*/\1/')"
if [ "${NPM_VERSION}" = "${PYPI_VERSION}" ] && [ "${PYPI_VERSION}" = "${PY_VERSION}" ]; then
  ok "npm, PyPI and __version__ all state ${NPM_VERSION}: OK"
else
  fail "stub versions disagree: npm ${NPM_VERSION}, PyPI ${PYPI_VERSION}, __version__ ${PY_VERSION}"
fi

# C4. every stub artefact names the repository, the domain, and the module path.
# The module path is the load-bearing one: it is the only string in the stub a
# developer can act on to reach real, installable code today.
REPO_URL="https://github.com/${GITHUB_REPO}"
HOME_URL="https://${DOMAIN}"

check_mentions() {
  _file="$1"
  _what="$2"
  _literal="$3"
  if grep -qF -- "${_literal}" "${_file}"; then
    ok "$(basename "$(dirname "${_file}")")/$(basename "${_file}") names ${_what} ${_literal}: OK"
  else
    fail "${_file#"${REPO_ROOT}"/} does not name ${_what} ${_literal} — the stub does not link back to the project it is holding a name for"
  fi
}

check_mentions "${PKG_JSON}"    "the repository"  "${GITHUB_REPO}"
check_mentions "${PKG_JSON}"    "the home page"   "${HOME_URL}"
check_mentions "${PYPROJECT}"   "the repository"  "${REPO_URL}"
check_mentions "${PYPROJECT}"   "the home page"   "${HOME_URL}"
check_mentions "${NPM_README}"  "the repository"  "${REPO_URL}"
check_mentions "${NPM_README}"  "the module path" "${GO_MODULE}"
check_mentions "${PYPI_README}" "the repository"  "${REPO_URL}"
check_mentions "${PYPI_README}" "the module path" "${GO_MODULE}"

# C5. what the stub prints when it is actually executed. `npx innsegl` and
# `uv run --with innsegl innsegl` are the two paths a developer will hit first;
# each must send them somewhere real rather than printing a placeholder.
NPM_ENTRY="${NS_DIR}/npm/index.js"
for pair in "${NPM_ENTRY}|${REPO_URL}" "${NPM_ENTRY}|${GO_MODULE}" "${PY_INIT}|${REPO_URL}" "${PY_INIT}|${GO_MODULE}"; do
  f="${pair%%|*}"
  lit="${pair#*|}"
  if [ ! -f "${f}" ]; then
    fail "${f#"${REPO_ROOT}"/} does not exist — the stub has no executable entry point, so running it teaches a developer nothing"
  elif ! grep -qF -- "${lit}" "${f}"; then
    fail "${f#"${REPO_ROOT}"/} does not print ${lit}: running the stub must send a developer to the real implementation"
  else
    ok "$(basename "${f}") prints ${lit}: OK"
  fi
done

# ---------------------------------------------------------------------------
log ""
if [ "${status}" -eq 0 ]; then
  printf 'namespace: OK (%d checks)\n' "${checks}"
else
  printf 'namespace: FAILED (%d checks) — see failures above\n' "${checks}" >&2
fi
exit "${status}"
