#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The exemptions, as a gate — IP §3 (E1–E8).
#
# WHY A GATE AND NOT A PARAGRAPH. doc 01 §3 says "Do not build these. If you
# find yourself building them, stop." That is a rule about what the repository
# must NOT grow, and a rule of that shape has no failing test to write: nothing
# breaks the day someone adds a policy engine. It stops being true quietly, in
# a pull request that looks like a feature, and the only thing that can notice
# is something that reads the repository on every change.
#
# WHAT IS CHECKABLE, AND WHAT IS NOT. Being honest about the split is most of
# the value here, because a gate that claimed all eight would be claiming two it
# cannot see.
#
#   E1  no authorization policy          CHECKED here, as absence of an engine
#   E2  no agent sandboxing              NOT CHECKABLE — see below
#   E3  no GitHub badge parity           NOT CHECKABLE — see below
#   E4  no payload storage               tested: LED-011, MCP-044..046, and
#                                        TestE4* in internal/mcp
#   E5  no SPIFFE federation             CHECKED here, as absence
#   E6  no blockchain / ledger product   CHECKED here, as absence
#   E7  no backfill of pre-adoption      CHECKED here, as absence
#   E8  no key custody by the MCP        tested: TestE8TheWrapperHoldsNoKeyMaterial
#
# E2 is "attestation proves what a workload is, not that it behaves" — an
# absence of a claim, not of code, and there is no string whose presence would
# mean the claim had been made. E3 is "do not chase the badge": chasing it would
# look like ordinary work on verification, and a grep that tried would fire on
# every mention of GitHub. Both are left to review, and saying so here is better
# than a check that passes for the wrong reason.
#
# COMMENTS ARE NOT CODE. Every rule below skips comment lines, because this
# repository discusses its own exemptions constantly and must be able to: doc 01
# itself says the design "must not preclude federation". A gate that fired on
# the word would make the exemption unmentionable, and the first fix anyone
# reached for would be to delete the explanation.
#
# USAGE
#   scripts/exemptions.sh [dir]
#
# `dir` defaults to this repository and exists so the self-test can point the
# gate at a fixture with a breach planted in it. A gate nobody has watched fail
# is a gate that passes for reasons nobody has checked.
#
# Exits 0 when every checkable exemption holds, 1 on the first breach, naming
# the exemption in the words doc 01 uses.

set -uo pipefail

ROOT="${1:-$(cd -- "$(dirname -- "$0")/.." && pwd -P)}"
cd "${ROOT}" || exit 1

breaches=0

# tracked_code lists the files a rule scans: what SHIPS. Documentation is
# excluded because docs/ never ships and the ADRs are where an exemption is
# discussed by name.
# THIS GATE AND ITS SELF-TEST ARE EXCLUDED, BY EXACT PATH AND NOTHING WIDER.
# The rules below have to contain the strings they look for, and the self-test
# has to plant them; a gate that scanned itself would report four breaches on
# its first run, which it did.
#
# An exclusion is the most dangerous line in a gate — no-operator-paths.sh
# carries the measurement of one that was too wide and produced a false pass in
# the gate whose whole job was to prevent one. So this one is two literal paths
# rather than a directory or a glob, and the self-test plants a breach in a
# DIFFERENT scripts/*.sh file and requires it caught. An exclusion with only one
# test beside it gets widened back by the next person who finds it inconvenient.
tracked_code() {
  git ls-files -- '*.go' '*.sh' '*.sql' '*.yml' '*.yaml' '*.ts' '*.tsx' 'go.mod' \
    ':!:*_test.go' ':!:docs/*' ':!:.github/ISSUE_TEMPLATE/*' \
    ':!:scripts/exemptions.sh' ':!:scripts/exemptions-selftest.sh' 2>/dev/null
}

# strip_comments removes whole-line comments in the three syntaxes this
# repository uses. It does NOT try to handle trailing comments: a rule that
# matched a word after code on the same line is matching code.
strip_comments() {
  sed -E 's@^[[:space:]]*(//|#|--).*$@@'
}

# breach EXEMPTION SENTENCE PATTERN — report every non-comment hit.
breach() {
  _e="$1"; _sentence="$2"; _pattern="$3"
  _hits=""
  for f in $(tracked_code); do
    [ -f "${f}" ] || continue
    _found="$(strip_comments <"${f}" | grep -nEi -- "${_pattern}" 2>/dev/null | head -3)"
    [ -n "${_found}" ] || continue
    _hits="${_hits}$(printf '\n    %s:%s' "${f}" "$(printf '%s' "${_found}" | head -1)")"
  done
  if [ -n "${_hits}" ]; then
    printf '\n%s BREACHED — %s\n' "${_e}" "${_sentence}" >&2
    printf '%s\n' "${_hits}" >&2
    breaches=$((breaches + 1))
    return 1
  fi
  printf '    ok       %-4s %s\n' "${_e}" "${_sentence}"
}

printf '==> exemptions — IP §3\n'

# E1. "No policy engine, no RBAC beyond protecting the MCP admin surface
# itself." An engine is a DEPENDENCY, which is what makes this checkable: the
# named ones are how a policy engine actually arrives in a Go repository.
breach E1 "no authorization policy engine" \
  'open-policy-agent|openpolicyagent|casbin|cedar-policy|ory/keto|oso-security'

# E5. "Single trust domain now." SPIRE's federation surface has specific
# spellings; these are them, in config and in the Go API.
breach E5 "no cross-organization SPIFFE federation" \
  'federates_with|federatesWith|FederatesWith|federation[[:space:]]*\{|BundleEndpointURL|trust_domain_federation'

# E6. "Postgres + object storage + Rekor anchoring only."
breach E6 "no blockchain or ledger-database product" \
  'immudb|amazon-qldb|qldbsession|hyperledger|ethereum|go-ethereum|tendermint|cosmos-sdk|bigchaindb|trillian-ledger'

# E7. "Commits made before adoption are unattributed; do not backfill or
# infer." A backfill arrives as a command or a function that says so.
breach E7 "no repudiation of pre-system history" \
  'func +[A-Za-z]*[Bb]ackfill|"backfill"|import-history|reattribute[A-Za-z]*\(|infer[A-Za-z]*Attribution'

printf '\n    E4 and E8 are covered by tests, not by this gate:\n'
printf '       E4  LED-011, MCP-044..046, TestE4* in internal/mcp\n'
printf '       E8  TestE8TheWrapperHoldsNoKeyMaterial in internal/signing\n'
printf '    E2 and E3 are not checkable; see the header for why.\n'

if [ "${breaches}" -ne 0 ]; then
  printf '\nexemptions: BREACHED (%d)\n' "${breaches}" >&2
  printf 'doc 01 §3: "Do not build these. If you find yourself building them, stop."\n' >&2
  exit 1
fi
printf '\nexemptions: OK (4 checkable, 2 tested elsewhere, 2 by review)\n'
