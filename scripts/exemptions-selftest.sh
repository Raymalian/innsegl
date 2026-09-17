#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Self-test for scripts/exemptions.sh — IP §3.
#
# WHY THIS EXISTS. The gate it tests passes on this repository today and is
# meant to: nothing here builds an exemption. That is exactly the condition in
# which a gate can be quietly worthless — every rule could be misspelled, or
# scanning no files at all, and the output would be identical. So each rule is
# driven against a fixture with that one breach planted in it, and is required
# to go red.
#
# AND THE OTHER HALF: the gate must stay GREEN on a comment that merely mentions
# an exemption. This repository discusses its own exemptions constantly and has
# to be able to — doc 01 itself says the design "must not preclude federation".
# A gate that fired on the word would make the exemption unmentionable, and the
# first fix anyone reached for would be deleting the explanation.
#
# Usage: scripts/exemptions-selftest.sh   (needs git; no Docker, no network)

set -uo pipefail

GATE="$(cd -- "$(dirname -- "$0")" && pwd -P)/exemptions.sh"
pass=0
fail=0
ok()  { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; return 0; }

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

# fixture NAME — a minimal tracked repository with nothing to find in it.
fixture() {
  d="${TMP}/$1"
  mkdir -p "${d}"
  git -C "${d}" init -q
  git -C "${d}" config user.email "selftest@example.invalid"
  git -C "${d}" config user.name "selftest"
  printf 'package main\n\nfunc main() {}\n' >"${d}/main.go"
  printf 'module example.invalid/fixture\n\ngo 1.27\n' >"${d}/go.mod"
  git -C "${d}" add -A
  git -C "${d}" commit -q -m seed --no-gpg-sign
  printf '%s' "${d}"
}

# The clean fixture must pass, or every red below could be the fixture rather
# than the rule.
clean="$(fixture clean)"
if "${GATE}" "${clean}" >/dev/null 2>&1; then
  ok "a repository that builds no exemption passes"
else
  bad "a repository that builds no exemption passes" "$("${GATE}" "${clean}" 2>&1 | tail -3)"
fi

# plant EXEMPTION FILE CONTENT — one breach, and the gate must name it.
plant() {
  e="$1"; file="$2"; content="$3"
  d="$(fixture "breach-${e}")"
  printf '%s\n' "${content}" >>"${d}/${file}"
  git -C "${d}" add -A
  git -C "${d}" commit -q -m "${e}" --no-gpg-sign
  out="$("${GATE}" "${d}" 2>&1)"; rc=$?
  if [ "${rc}" -eq 0 ]; then
    bad "${e} is caught when it is built" "the gate passed: ${content}"
  elif ! printf '%s' "${out}" | grep -q "${e} BREACHED"; then
    bad "${e} is caught when it is built" "it went red for a different rule: $(printf '%s' "${out}" | grep BREACHED | head -1)"
  else
    ok "${e} is caught when it is built"
  fi
}

plant E1 main.go 'import _ "github.com/open-policy-agent/opa/rego"'
plant E5 main.go 'var bundle = spiffeid.FederatesWith("other.example")'
plant E6 go.mod  'require github.com/ethereum/go-ethereum v1.0.0'
plant E7 main.go 'func backfillAttribution() {}'

# THE OTHER HALF. Each exemption named in a COMMENT, in the three syntaxes the
# gate strips, must not fire.
d="$(fixture comments)"
cat >>"${d}/main.go" <<'GO'

// The design must not preclude federation (E5); we simply do not build it.
// No policy engine here: open-policy-agent is an exemption, not a dependency.
// We do not backfill: reattributeHistory( would be exactly the wrong thing.
GO
cat >>"${d}/deploy.yml" <<'YML'
# ethereum and hyperledger are named here only as things this does not use.
# federates_with is deliberately absent from every SPIRE config.
YML
printf -- '-- immudb and amazon-qldb are not used by this schema.\n' >>"${d}/schema.sql"
git -C "${d}" add -A
git -C "${d}" commit -q -m comments --no-gpg-sign
out="$("${GATE}" "${d}" 2>&1)"; rc=$?
if [ "${rc}" -eq 0 ]; then
  ok "an exemption named in a comment is not a breach"
else
  bad "an exemption named in a comment is not a breach" \
      "$(printf '%s' "${out}" | grep BREACHED | head -2)"
fi

# A test file is not shipped code, and naming an exemption in one is how the
# exemption gets TESTED. It must not fire either.
d="$(fixture testfile)"
printf 'package main\n\nfunc TestE7(t *testing.T) { backfillAttribution() }\n' >"${d}/main_test.go"
git -C "${d}" add -A
git -C "${d}" commit -q -m testfile --no-gpg-sign
if "${GATE}" "${d}" >/dev/null 2>&1; then
  ok "a test file naming an exemption is not a breach"
else
  bad "a test file naming an exemption is not a breach" "$("${GATE}" "${d}" 2>&1 | grep BREACHED | head -1)"
fi

# THE EXCLUSION IS TWO PATHS AND NOT A DIRECTORY. The gate skips itself and
# this file because both must contain the strings they hunt for. A breach in any
# OTHER script must still be caught, or the exclusion has quietly become "no
# shell script is checked".
d="$(fixture other-script)"
mkdir -p "${d}/scripts"
printf '#!/bin/sh\nexec opa run --server\n' >"${d}/scripts/policy.sh"
printf '# open-policy-agent is what this runs\nexec open-policy-agent\n' >>"${d}/scripts/policy.sh"
git -C "${d}" add -A
git -C "${d}" commit -q -m other-script --no-gpg-sign
out="$("${GATE}" "${d}" 2>&1)"; rc=$?
if [ "${rc}" -ne 0 ] && printf '%s' "${out}" | grep -q "E1 BREACHED"; then
  ok "a breach in another script is still caught"
else
  bad "a breach in another script is still caught" \
      "the exclusion has widened past its two paths (exit ${rc})"
fi

printf '\n%d passed, %d failed\n' "${pass}" "${fail}"
[ "${fail}" -eq 0 ]
