#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# OPS-211 (PROPOSED for doc 07, #599) — `make install-release`
# (scripts/install-release.sh) puts a root-owned copy of the built binary
# where the hooks, the client service and scheduled jobs run it from, through
# one sudo line that checks the copy's SHA-256 before installing it.
#
#   OPS-211a  without a terminal it prints exactly one `sudo sh -c` line,
#             naming the binary's SHA-256 and the destination; it runs no
#             sudo and exits 3, saying the copy is not installed.
#   OPS-211b  the printed line's script, run (without sudo, chown a fake)
#             into a temporary destination, installs the same bytes, mode
#             0755, and gives the folder and the file to uid 0.
#   OPS-211c  a binary changed after the line was printed is refused by the
#             hash check: nothing installed, nothing given to root.
#   OPS-211d  the Makefile's install-release target runs this script on the
#             built binary; build itself installs nothing.
#   OPS-211e  scripts/link-bin.sh says when the installed copy is another
#             build than the one it just linked.
#   OPS-211f  usage: no binary, or one that does not exist, exits 2.
#
# Nothing here runs sudo or writes outside a temporary folder: sudo and chown
# are fakes that record their calls, and the destination is under $TOP.
set -uo pipefail

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
SCRIPT="${ROOT}/scripts/install-release.sh"

pass=0; fail=0
ok()  { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/        | /'; return 0; }

TOP="$(mktemp -d "${TMPDIR:-/tmp}/install-release-selftest.XXXXXX")"
trap 'rm -rf "${TOP}"' EXIT
FAKEBIN="${TOP}/fakebin"
mkdir -p "${FAKEBIN}" "${TOP}/checkout"
BIN="${TOP}/checkout/innsegl"
printf 'build-1\n' >"${BIN}"; chmod 0755 "${BIN}"
DEST="${TOP}/libexec/innsegl"
CALLS="${TOP}/calls"
: >"${CALLS}"

cat >"${FAKEBIN}/sudo" <<EOF
#!/usr/bin/env bash
echo "sudo \$*" >>"${CALLS}"
exit 99
EOF
cat >"${FAKEBIN}/chown" <<EOF
#!/usr/bin/env bash
echo "chown \$*" >>"${CALLS}"
EOF
chmod +x "${FAKEBIN}"/*

sha() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# OPS-211a
out="$(PATH="${FAKEBIN}:${PATH}" INNSEGL_RELEASE_DIR="${DEST}" "${SCRIPT}" "${BIN}" </dev/null 2>&1)"; rc=$?
lines="$(grep -c '^  sudo sh -c ' <<<"${out}")"
line="$(grep '^  sudo sh -c ' <<<"${out}" | head -n 1 | sed 's/^  //')"
if [ "${rc}" -eq 3 ] && [ "${lines}" -eq 1 ] && grep -qF "$(sha "${BIN}")" <<<"${line}" \
  && grep -qF "${DEST}" <<<"${line}" && ! grep -q '^sudo' "${CALLS}" && grep -q 'not installed' <<<"${out}"; then
  ok "OPS-211a without a terminal: one sudo line with the hash and the destination, no sudo run, exit 3"
else
  bad "OPS-211a the printed line" "exit=${rc} lines=${lines}
${out}
calls: $(cat "${CALLS}")"
fi

# The script the line hands to root, unquoted the way sudo's shell would.
root_script="$(sh -c "printf '%s' ${line#sudo sh -c }")"

# OPS-211b
: >"${CALLS}"
PATH="${FAKEBIN}:${PATH}" sh -c "${root_script}" >"${TOP}/b.out" 2>&1; rc=$?
mode="$(ls -l "${DEST}/innsegl" 2>/dev/null | cut -c1-10)"
if [ "${rc}" -eq 0 ] && cmp -s "${BIN}" "${DEST}/innsegl" && [ "${mode}" = "-rwxr-xr-x" ] \
  && grep -qx "chown 0:0 ${DEST}" "${CALLS}" && grep -q "^chown 0:0 ${DEST}/" "${CALLS}" \
  && [ ! -e "${DEST}/.innsegl.new" ]; then
  ok "OPS-211b the line's script installs the same bytes, 0755, folder and file given to uid 0"
else
  bad "OPS-211b the install" "exit=${rc} mode=${mode} $(cat "${TOP}/b.out")
calls: $(cat "${CALLS}")"
fi

# OPS-211c
rm -rf "${DEST}"; : >"${CALLS}"
printf 'build-1 changed by an agent\n' >"${BIN}"
PATH="${FAKEBIN}:${PATH}" sh -c "${root_script}" >"${TOP}/c.out" 2>&1; rc=$?
if [ "${rc}" -ne 0 ] && [ ! -e "${DEST}/innsegl" ] && ! grep -q '^chown' "${CALLS}"; then
  ok "OPS-211c a binary changed after the line was printed is refused by the hash check"
else
  bad "OPS-211c a changed binary was installed" "exit=${rc} $(cat "${TOP}/c.out")
calls: $(cat "${CALLS}")"
fi
printf 'build-1\n' >"${BIN}"

# OPS-211d — read from the Makefile itself, recipe lines only.
recipe() { awk -v t="$1:" '$1 == t { on = 1; next } on && /^\t/ { print; next } on { exit }' "${ROOT}/Makefile"; }
build="$(recipe build)"
install="$(recipe install-release)"
if grep -q 'scripts/install-release.sh \$(CURDIR)/\$(BINARY)' <<<"${install}" \
  && ! grep -qE 'install-release|sudo' <<<"${build}"; then
  ok "OPS-211d make install-release runs this script on the built binary; make build installs nothing"
else
  bad "OPS-211d the Makefile targets" "build:
${build}
install-release:
${install}"
fi

# OPS-211e
mkdir -p "${TOP}/home" "${DEST}"
printf 'build-0\n' >"${DEST}/innsegl"
out="$(HOME="${TOP}/home" INNSEGL_RELEASE_DIR="${DEST}" "${ROOT}/scripts/link-bin.sh" "${BIN}" 2>&1)"
same="$(cp "${BIN}" "${DEST}/innsegl" && HOME="${TOP}/home" INNSEGL_RELEASE_DIR="${DEST}" "${ROOT}/scripts/link-bin.sh" "${BIN}" 2>&1)"
if grep -q 'make install-release' <<<"${out}" && grep -qF "${DEST}/innsegl" <<<"${out}" \
  && ! grep -q 'make install-release' <<<"${same}"; then
  ok "OPS-211e link-bin says when the installed copy is another build, and only then"
else
  bad "OPS-211e link-bin and the installed copy" "differs: ${out}
same: ${same}"
fi

# OPS-211f
out="$("${SCRIPT}" 2>&1)"; rc=$?
out2="$("${SCRIPT}" "${TOP}/nope" 2>&1)"; rc2=$?
if [ "${rc}" -eq 2 ] && [ "${rc2}" -eq 2 ]; then
  ok "OPS-211f no binary, or a missing one: usage, exit 2"
else
  bad "OPS-211f usage" "exit=${rc} ${out}; exit=${rc2} ${out2}"
fi

printf '\ninstall-release-selftest: %d passed, %d failed\n' "${pass}" "${fail}"
[ "${fail}" -eq 0 ]
