#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# OPS-170 (PROPOSED for doc 07) — `make client-restart` (scripts/client-
# restart.sh) restarts this machine's client service only when the service
# runs the binary just built, so a rebuild reaches the service in one step and
# a service that runs another binary is left alone. `make build` itself never
# restarts anything. uname, id, launchctl and systemctl are fakes that record
# every call.
#
#   OPS-170a  macOS, the service runs this binary (named through a symlink
#             too): launchctl kickstart -k gui/<uid>/dev.innsegl.client.
#   OPS-170b  macOS, it runs another binary: no kickstart; says which, exit 1.
#   OPS-170c  macOS, no service loaded: no kickstart; says so, exit 1.
#   OPS-170d  Linux, the unit runs this binary: systemctl --user restart
#             innsegl-client.service; another binary or no unit: left alone.
#   OPS-170e  the Makefile's build target signs and never restarts; the
#             client-restart target runs this script on the built binary.
set -uo pipefail

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
SCRIPT="${ROOT}/scripts/client-restart.sh"

pass=0; fail=0
ok()  { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/        | /'; return 0; }

TOP="$(mktemp -d "${TMPDIR:-/tmp}/client-restart-selftest.XXXXXX")"
trap 'rm -rf "${TOP}"' EXIT
FAKEBIN="${TOP}/bin"
mkdir -p "${FAKEBIN}" "${TOP}/checkout" "${TOP}/other"
BIN="${TOP}/checkout/innsegl"
OTHER="${TOP}/other/innsegl"
: >"${BIN}"; : >"${OTHER}"
ln -s "${TOP}/checkout" "${TOP}/link"

cat >"${FAKEBIN}/uname" <<'EOF'
#!/usr/bin/env bash
echo "${FAKE_UNAME}"
EOF
cat >"${FAKEBIN}/id" <<'EOF'
#!/usr/bin/env bash
[ "$1" = "-u" ] && echo 501
EOF
# launchctl print answers the service as running $FAKE_PROGRAM, or exits
# 113 (not found) when it is empty.
cat >"${FAKEBIN}/launchctl" <<'EOF'
#!/usr/bin/env bash
echo "launchctl $*" >>"${FAKE_CALLS}"
case "$1" in
  print)
    [ -n "${FAKE_PROGRAM}" ] || { echo "Could not find service" >&2; exit 113; }
    printf 'gui/501/dev.innsegl.client = {\n\tactive count = 1\n\tstate = running\n\n\tprogram = %s\n\targuments = {\n\t\t%s\n\t}\n}\n' \
      "${FAKE_PROGRAM}" "${FAKE_PROGRAM}" ;;
esac
EOF
# systemctl --user show answers the unit as running $FAKE_PROGRAM, or as not
# found when it is empty.
cat >"${FAKEBIN}/systemctl" <<'EOF'
#!/usr/bin/env bash
echo "systemctl $*" >>"${FAKE_CALLS}"
case "$*" in
  *"show -p LoadState --value"*) if [ -n "${FAKE_PROGRAM}" ]; then echo loaded; else echo not-found; fi ;;
  *"show -p ExecStart --value"*)
    [ -n "${FAKE_PROGRAM}" ] && echo "{ path=${FAKE_PROGRAM} ; argv[]=${FAKE_PROGRAM} client serve ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }" ;;
esac
EOF
chmod +x "${FAKEBIN}"/*

export FAKE_UNAME FAKE_PROGRAM FAKE_CALLS
run() {
  FAKE_CALLS="$(mktemp "${TOP}/calls.XXXXXX")"
  out="$(PATH="${FAKEBIN}:${PATH}" "${SCRIPT}" "$1" 2>&1)"
  rc=$?
  calls="$(cat "${FAKE_CALLS}")"
}

FAKE_UNAME=Darwin
# OPS-170a
FAKE_PROGRAM="${BIN}" run "${BIN}"
if [ "${rc}" -eq 0 ] && grep -qx "launchctl kickstart -k gui/501/dev.innsegl.client" <<<"${calls}"; then
  ok "OPS-170a macOS: the service runs this binary, so it is kickstarted"
else
  bad "OPS-170a the service running this binary was not restarted" "exit=${rc} out=${out}
${calls}"
fi
FAKE_PROGRAM="${BIN}" run "${TOP}/link/innsegl"
if [ "${rc}" -eq 0 ] && grep -q "kickstart" <<<"${calls}"; then
  ok "OPS-170a the same binary named through a symlink is the same binary"
else
  bad "OPS-170a a symlinked path was taken for another binary" "exit=${rc} out=${out}"
fi

# OPS-170b
FAKE_PROGRAM="${OTHER}" run "${BIN}"
if [ "${rc}" -eq 1 ] && ! grep -q kickstart <<<"${calls}" && grep -qF "${OTHER}" <<<"${out}"; then
  ok "OPS-170b macOS: a service running another binary is left alone, and named"
else
  bad "OPS-170b a service running another binary was touched or not named" "exit=${rc} out=${out}
${calls}"
fi

# OPS-170c
FAKE_PROGRAM="" run "${BIN}"
if [ "${rc}" -eq 1 ] && ! grep -q kickstart <<<"${calls}" && grep -q "not loaded" <<<"${out}"; then
  ok "OPS-170c macOS: no service loaded is said, and nothing is started"
else
  bad "OPS-170c no service loaded" "exit=${rc} out=${out}
${calls}"
fi

FAKE_UNAME=Linux
# OPS-170d
FAKE_PROGRAM="${BIN}" run "${BIN}"
if [ "${rc}" -eq 0 ] && grep -qx "systemctl --user restart innsegl-client.service" <<<"${calls}" \
  && ! grep -q launchctl <<<"${calls}"; then
  ok "OPS-170d Linux: the unit runs this binary, so it is restarted"
else
  bad "OPS-170d the unit running this binary was not restarted" "exit=${rc} out=${out}
${calls}"
fi
FAKE_PROGRAM="${OTHER}" run "${BIN}"
if [ "${rc}" -eq 1 ] && ! grep -q "restart" <<<"${calls}"; then
  ok "OPS-170d Linux: a unit running another binary is left alone"
else
  bad "OPS-170d a unit running another binary was restarted" "exit=${rc} out=${out}
${calls}"
fi
FAKE_PROGRAM="" run "${BIN}"
if [ "${rc}" -eq 1 ] && ! grep -q "restart" <<<"${calls}"; then
  ok "OPS-170d Linux: no unit is said, and nothing is started"
else
  bad "OPS-170d no unit" "exit=${rc} out=${out}
${calls}"
fi

# OPS-170e — read from the Makefile itself, recipe lines only.
recipe() { awk -v t="$1:" '$1 == t { on = 1; next } on && /^\t/ { print; next } on { exit }' "${ROOT}/Makefile"; }
build="$(recipe build)"
restart="$(recipe client-restart)"
if grep -q 'scripts/codesign-cli.sh' <<<"${build}" && ! grep -qE 'launchctl|systemctl|client-restart' <<<"${build}" \
  && grep -q 'scripts/client-restart.sh' <<<"${restart}"; then
  ok "OPS-170e make build signs and restarts nothing; make client-restart runs the restart"
else
  bad "OPS-170e the Makefile targets" "build:
${build}
client-restart:
${restart}"
fi

out="$("${SCRIPT}" 2>&1)"; rc=$?
if [ "${rc}" -eq 2 ]; then
  ok "no binary named: usage, exit 2"
else
  bad "no binary named: exit ${rc}" "${out}"
fi

printf '\nclient-restart-selftest: %d passed, %d failed\n' "${pass}" "${fail}"
[ "${fail}" -eq 0 ]
