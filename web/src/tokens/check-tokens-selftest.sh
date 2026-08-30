#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Self-test for the token sheet gate (check-tokens.sh).
#
# A gate that has never been observed failing is not a gate. This script takes
# the shipped sheet, plants one defect at a time — each one a mistake somebody
# will actually make — and asserts that check-tokens.sh exits non-zero AND says
# the right thing. It then asserts the unmutated sheet passes, so a gate that
# has quietly started refusing everything is caught too.
#
# The defects are not hypothetical. Every one of them was observed failing
# against a first draft of tokens.css before the sheet was finished; this
# script is that observation, kept.
#
# Usage: web/src/tokens/check-tokens-selftest.sh

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CHECK_SH="${SCRIPT_DIR}/check-tokens.sh"
TOKENS="${SCRIPT_DIR}/tokens.css"

if [ ! -x "${CHECK_SH}" ]; then
  printf 'FAIL: %s is missing or not executable\n' "${CHECK_SH}" >&2
  exit 1
fi

workdir="$(mktemp -d "${TMPDIR:-/tmp}/innsegl-tokens-selftest.XXXXXX")"
trap 'rm -rf "${workdir}"' EXIT

ncase=0
nbad=0

# expect_refusal <name> <substring the message must contain> <sed program>
expect_refusal() {
  name="$1"; want="$2"; program="$3"
  ncase=$((ncase + 1))
  mutant="${workdir}/${ncase}.css"
  sed "${program}" "${TOKENS}" >"${mutant}"

  if cmp -s "${mutant}" "${TOKENS}"; then
    printf '  BAD  %-34s the mutation changed nothing — the sed program no longer matches the sheet\n' "${name}"
    nbad=$((nbad + 1))
    return
  fi

  set +e
  out="$("${CHECK_SH}" "${mutant}" 2>&1)"
  status=$?
  set -e

  if [ "${status}" -eq 0 ]; then
    printf '  BAD  %-34s gate PASSED a sheet with this defect\n' "${name}"
    nbad=$((nbad + 1))
    return
  fi
  case "${out}" in
    *"${want}"*)
      printf '  ok   %-34s refused, naming "%s"\n' "${name}" "${want}"
      ;;
    *)
      printf '  BAD  %-34s refused, but never mentioned "%s". Output was:\n%s\n' "${name}" "${want}" "${out}"
      nbad=$((nbad + 1))
      ;;
  esac
}

printf '==> Self-test for the token sheet gate\n'
printf '    gate  %s\n' "${CHECK_SH}"
printf '    sheet %s\n\n' "${TOKENS}"

# 1. A raw value escapes the palette. doc 06 §5.1: everything flows through
#    tokens; a hex in the semantic layer is a value a rebrand cannot reach.
expect_refusal "raw hex in the semantic layer" \
  "semantic colour must be light-dark" \
  's|--innsegl-color-text-primary: light-dark(.*)|--innsegl-color-text-primary: #161b1f;|'

# 2. One mode only. This is the defect that stays invisible until somebody
#    switches themes, which is the reason the sheet is built on light-dark().
expect_refusal "colour defined in one mode only" \
  "exactly two light-dark() arms" \
  's|--innsegl-color-status-retired-text: light-dark(\(var([^,]*\)),.*|--innsegl-color-status-retired-text: light-dark(\1);|'

# 3. The one this whole gate exists for: a "success green" for something that
#    is not a cryptographic verification (§5.3, §8.3).
expect_refusal "green for a non-verification" \
  "§5.3 violation" \
  's|--innsegl-color-status-active-surface: light-dark(var(--innsegl-palette-neutral-50), var(--innsegl-palette-neutral-800));|--innsegl-color-status-active-surface: light-dark(var(--innsegl-palette-verification-50), var(--innsegl-palette-verification-900));|'

# 4. The same anti-pattern arriving through the name rather than the value.
expect_refusal "a token named for a claim" \
  'token name contains "success"' \
  's|--innsegl-color-status-active-text:|--innsegl-color-status-success-text:|'

# 5. A var() naming a token that is not there. CSS does not error on this — it
#    renders as `unset` and inherits, so a badge silently takes the wrong
#    colour rather than breaking visibly.
expect_refusal "reference to a missing token" \
  "names a token that does not exist" \
  's|var(--innsegl-palette-verification-700)|var(--innsegl-palette-verification-650)|'

# 6. Contrast, in the mode that is easiest to forget.
expect_refusal "contrast lost in dark mode" \
  "below the required" \
  's|--innsegl-color-text-secondary: light-dark(var(--innsegl-palette-neutral-600), var(--innsegl-palette-neutral-300));|--innsegl-color-text-secondary: light-dark(var(--innsegl-palette-neutral-600), var(--innsegl-palette-neutral-700));|'

# 7. A hue-named semantic token — the door the naming rule closes.
expect_refusal "a token named for its hue" \
  'token name contains "amber"' \
  's|--innsegl-color-degraded-text:|--innsegl-color-amber-text:|'

# 8 and 9. The theme mechanics doc 06 §5.1 asks for: prefers-color-scheme, and
#          a manual override.
expect_refusal "prefers-color-scheme not honoured" \
  "color-scheme: light dark" \
  's|^  color-scheme: light dark;||'

expect_refusal "manual override removed" \
  "manual override" \
  's|:root\[data-theme="dark"\]|:root[data-theme="forced"]|'

# The positive control. Without it, a gate that refuses everything would pass
# every case above and be entirely useless.
ncase=$((ncase + 1))
set +e
out="$("${CHECK_SH}" "${TOKENS}" 2>&1)"
status=$?
set -e
if [ "${status}" -eq 0 ]; then
  printf '  ok   %-34s accepted, as it must be\n' "the shipped sheet"
else
  printf '  BAD  %-34s the shipped sheet does not pass its own gate:\n%s\n' "the shipped sheet" "${out}"
  nbad=$((nbad + 1))
fi

printf '\n'
if [ "${nbad}" -gt 0 ]; then
  printf 'FAIL: %d of %d self-test cases did not hold.\n' "${nbad}" "${ncase}"
  exit 1
fi
printf 'Token gate self-test: OK (%d cases)\n' "${ncase}"
