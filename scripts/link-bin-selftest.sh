#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# OPS-171 (PROPOSED for doc 07) — `make build` puts the binary it wrote on the
# PATH as $HOME/.local/bin/innsegl, a symlink to the checkout's binary
# (scripts/link-bin.sh), so `innsegl status` runs from any directory. Every
# case runs under a temporary HOME; the real ~/.local/bin is never touched.
#
#   OPS-171a  no ~/.local/bin: it is made, and the link points at the binary.
#   OPS-171b  run again: the same link, nothing else changes.
#   OPS-171c  a link to another binary is moved to this one.
#   OPS-171d  a file that is not a link is left exactly as it is, with a
#             warning, and the build still succeeds.
#   OPS-171e  ~/.local/bin not on PATH: a hint says how to add it; on PATH:
#             no hint.
#   OPS-171f  the Makefile's build target runs it on the built binary.
set -uo pipefail

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
SCRIPT="${ROOT}/scripts/link-bin.sh"

pass=0; fail=0
ok()  { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/        | /'; return 0; }

TOP="$(mktemp -d "${TMPDIR:-/tmp}/link-bin-selftest.XXXXXX")"
trap 'rm -rf "${TOP}"' EXIT
TOP="$(cd -- "${TOP}" && pwd -P)"
mkdir -p "${TOP}/checkout" "${TOP}/other"
BIN="${TOP}/checkout/innsegl"
OTHER="${TOP}/other/innsegl"
printf '#!/bin/sh\n' >"${BIN}"; printf '#!/bin/sh\n' >"${OTHER}"
chmod +x "${BIN}" "${OTHER}"

newhome() { HOMEDIR="$(mktemp -d "${TOP}/home.XXXXXX")"; LINK="${HOMEDIR}/.local/bin/innsegl"; }
run() {
  out="$(HOME="${HOMEDIR}" PATH="${1}" "${SCRIPT}" "${BIN}" 2>&1)"
  rc=$?
}
BASEPATH="/usr/bin:/bin"

# OPS-171a
newhome
run "${BASEPATH}"
if [ "${rc}" -eq 0 ] && [ -L "${LINK}" ] && [ "$(readlink "${LINK}")" = "${BIN}" ]; then
  ok "OPS-171a no ~/.local/bin: made, and the link points at the binary"
else
  bad "OPS-171a the link was not made" "exit=${rc} out=${out} link=$(readlink "${LINK}" 2>&1)"
fi

# OPS-171b
before="$(ls -la "${HOMEDIR}/.local/bin")"
run "${BASEPATH}"
if [ "${rc}" -eq 0 ] && [ "$(readlink "${LINK}")" = "${BIN}" ] && [ "$(ls -la "${HOMEDIR}/.local/bin")" = "${before}" ]; then
  ok "OPS-171b run again: the same link"
else
  bad "OPS-171b a second run changed something" "exit=${rc} out=${out}"
fi

# OPS-171c
newhome
mkdir -p "${HOMEDIR}/.local/bin"
ln -s "${OTHER}" "${LINK}"
run "${BASEPATH}"
if [ "${rc}" -eq 0 ] && [ "$(readlink "${LINK}")" = "${BIN}" ] && grep -qF "${OTHER}" <<<"${out}"; then
  ok "OPS-171c a link to another binary is moved to this one, and the old one named"
else
  bad "OPS-171c the link was not moved" "exit=${rc} out=${out} link=$(readlink "${LINK}")"
fi

# OPS-171d
newhome
mkdir -p "${HOMEDIR}/.local/bin"
printf 'mine\n' >"${LINK}"
run "${BASEPATH}"
if [ "${rc}" -eq 0 ] && [ ! -L "${LINK}" ] && [ "$(cat "${LINK}")" = "mine" ] && grep -q "not a link" <<<"${out}"; then
  ok "OPS-171d a file that is not a link is left alone, with a warning"
else
  bad "OPS-171d a non-link file was touched or not warned about" "exit=${rc} out=${out}"
fi

# OPS-171e
newhome
run "${BASEPATH}"
if grep -q 'not on your PATH' <<<"${out}" && grep -qF "${HOMEDIR}/.local/bin" <<<"${out}"; then
  ok "OPS-171e ~/.local/bin not on PATH: a hint says how to add it"
else
  bad "OPS-171e no hint" "${out}"
fi
newhome
run "${HOMEDIR}/.local/bin:${BASEPATH}"
if [ "${rc}" -eq 0 ] && ! grep -q 'not on your PATH' <<<"${out}"; then
  ok "OPS-171e ~/.local/bin on PATH: no hint"
else
  bad "OPS-171e a hint with ~/.local/bin on PATH" "${out}"
fi

# OPS-171f — read from the Makefile itself, recipe lines only.
recipe() { awk -v t="$1:" '$1 == t { on = 1; next } on && /^\t/ { print; next } on { exit }' "${ROOT}/Makefile"; }
if grep -q 'scripts/link-bin.sh $(CURDIR)/$(BINARY)' <<<"$(recipe build)"; then
  ok "OPS-171f make build links the binary it built"
else
  bad "OPS-171f the build target" "$(recipe build)"
fi

out="$("${SCRIPT}" 2>&1)"; rc=$?
if [ "${rc}" -eq 2 ]; then
  ok "no binary named: usage, exit 2"
else
  bad "no binary named: exit ${rc}" "${out}"
fi

printf '\nlink-bin-selftest: %d passed, %d failed\n' "${pass}" "${fail}"
[ "${fail}" -eq 0 ]
