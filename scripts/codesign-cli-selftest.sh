#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# OPS-169 (PROPOSED for doc 07) — scripts/codesign-cli.sh, which `make build`
# runs, signs the binary with a Developer ID on macOS and never on Linux.
# uname, security, openssl and codesign are fakes that record every call; the
# real signature is checked on a Mac by `codesign -dv ./innsegl`.
#
#   OPS-169a  not macOS: no keychain asked, nothing signed, nothing said.
#   OPS-169b  no Developer ID identity: unsigned, said once, exit 0.
#   OPS-169c  two Developer ID identities with one name: the newest-issued is
#             used, by its SHA-1, with the identifier dev.innsegl.cli; other
#             kinds of identity are never picked.
#   OPS-169d  $INNSEGL_CODESIGN_IDENTITY picks by hash; one not held is
#             refused, with nothing signed; =none leaves it unsigned.
#   OPS-169e  codesign failing fails the build, saying why.
set -uo pipefail

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
SCRIPT="${ROOT}/scripts/codesign-cli.sh"

pass=0; fail=0
ok()  { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/        | /'; return 0; }

TOP="$(mktemp -d "${TMPDIR:-/tmp}/codesign-cli-selftest.XXXXXX")"
trap 'rm -rf "${TOP}"' EXIT
FAKEBIN="${TOP}/bin"
mkdir -p "${FAKEBIN}"

OLD=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1
NEW=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB2
DEV=CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC3
NAME="Developer ID Application: Example Person (TEAM123456)"

# uname answers $FAKE_UNAME.
cat >"${FAKEBIN}/uname" <<'EOF'
#!/usr/bin/env bash
echo "uname $*" >>"${FAKE_DIR}/calls"
echo "${FAKE_UNAME}"
EOF

# security: find-identity lists $FAKE_DIR/identities; find-certificate prints
# each certificate in $FAKE_DIR/certs/<hash> whose name matches -c.
cat >"${FAKEBIN}/security" <<'EOF'
#!/usr/bin/env bash
echo "security $*" >>"${FAKE_DIR}/calls"
case "$1" in
  find-identity)
    n=0
    while IFS='|' read -r hash name; do
      [ -n "${hash}" ] || continue
      n=$((n + 1)); printf '  %d) %s "%s"\n' "${n}" "${hash}" "${name}"
    done <"${FAKE_DIR}/identities"
    printf '     %d valid identities found\n' "${n}" ;;
  find-certificate)
    want=""; while [ $# -gt 0 ]; do [ "$1" = "-c" ] && want="$2"; shift; done
    for f in "${FAKE_DIR}"/certs/*; do
      [ -f "${f}" ] || continue
      grep -qF "NAME ${want}" "${f}" || continue
      echo "SHA-1 hash: $(basename "${f}")"
      cat "${f}"
    done ;;
esac
EOF

# openssl x509 -startdate: the NOTBEFORE line of the "certificate" on stdin.
cat >"${FAKEBIN}/openssl" <<'EOF'
#!/usr/bin/env bash
echo "openssl $*" >>"${FAKE_DIR}/calls"
sed -n 's/^NOTBEFORE /notBefore=/p'
EOF

# codesign records its arguments and fails when $FAKE_CODESIGN_FAIL is set.
cat >"${FAKEBIN}/codesign" <<'EOF'
#!/usr/bin/env bash
echo "codesign $*" >>"${FAKE_DIR}/calls"
if [ -n "${FAKE_CODESIGN_FAIL:-}" ]; then echo "errSecInternalComponent" >&2; exit 1; fi
EOF
chmod +x "${FAKEBIN}"/*

# fresh — a new fake keychain. Each argument is "<hash>|<name>|<notBefore>".
fresh() {
  FAKE_DIR="$(mktemp -d "${TOP}/case.XXXXXX")"
  export FAKE_DIR
  mkdir -p "${FAKE_DIR}/certs"
  : >"${FAKE_DIR}/identities"
  : >"${FAKE_DIR}/calls"
  local spec hash name when
  for spec in "$@"; do
    IFS='|' read -r hash name when <<<"${spec}"
    printf '%s|%s\n' "${hash}" "${name}" >>"${FAKE_DIR}/identities"
    printf -- '-----BEGIN CERTIFICATE-----\nNAME %s\nNOTBEFORE %s\n-----END CERTIFICATE-----\n' \
      "${name}" "${when}" >"${FAKE_DIR}/certs/${hash}"
  done
  : >"${TOP}/innsegl"
}

run() {
  out="$(PATH="${FAKEBIN}:${PATH}" "${SCRIPT}" "${TOP}/innsegl" 2>&1)"
  rc=$?
  calls="$(cat "${FAKE_DIR}/calls")"
}

export FAKE_UNAME
unset INNSEGL_CODESIGN_IDENTITY FAKE_CODESIGN_FAIL

# OPS-169a
fresh "${OLD}|${NAME}|Jan  2 10:00:00 2024 GMT"
FAKE_UNAME=Linux run
if [ "${rc}" -eq 0 ] && [ -z "${out}" ] && ! grep -qE '^(security|codesign)' <<<"${calls}"; then
  ok "OPS-169a not macOS: no keychain asked, nothing signed, nothing said"
else
  bad "OPS-169a on Linux it did something" "exit=${rc} out=${out}
${calls}"
fi

FAKE_UNAME=Darwin

# OPS-169b
fresh "${DEV}|Apple Development: Example Person (TEAM123456)|Jan  2 10:00:00 2026 GMT"
run
if [ "${rc}" -eq 0 ] && [ "$(grep -c 'unsigned' <<<"${out}")" -eq 1 ] && ! grep -q '^codesign' <<<"${calls}"; then
  ok "OPS-169b no Developer ID identity: unsigned, said once, exit 0"
else
  bad "OPS-169b with no Developer ID identity" "exit=${rc} out=${out}
${calls}"
fi

# OPS-169c — the newer certificate is listed FIRST and its date is a later
# month but an earlier day, so neither list order nor a text sort of the raw
# date picks it by accident.
fresh "${NEW}|${NAME}|Mar  1 09:00:00 2026 GMT" \
  "${DEV}|Apple Development: Example Person (TEAM123456)|Dec 31 23:59:59 2030 GMT" \
  "${OLD}|${NAME}|Feb 28 09:00:00 2026 GMT"
run
if [ "${rc}" -eq 0 ] && grep -qx "codesign -f -s ${NEW} -i dev.innsegl.cli ${TOP}/innsegl" <<<"${calls}" \
  && [ "$(grep -c '^codesign' <<<"${calls}")" -eq 1 ] && grep -q "${NEW}" <<<"${out}"; then
  ok "OPS-169c the newest-issued Developer ID is used, by its SHA-1, as dev.innsegl.cli"
else
  bad "OPS-169c did not sign with the newest Developer ID" "exit=${rc} out=${out}
${calls}"
fi
fresh "${OLD}|${NAME}|Feb 28 09:00:00 2025 GMT" "${NEW}|${NAME}|Jan  5 09:00:00 2026 GMT"
run
if grep -qx "codesign -f -s ${NEW} -i dev.innsegl.cli ${TOP}/innsegl" <<<"${calls}"; then
  ok "OPS-169c a later year wins over a later month"
else
  bad "OPS-169c the year was not compared first" "${calls}"
fi

# OPS-169d
fresh "${NEW}|${NAME}|Mar  1 09:00:00 2026 GMT" "${OLD}|${NAME}|Feb 28 09:00:00 2026 GMT"
INNSEGL_CODESIGN_IDENTITY="${OLD}" run
if [ "${rc}" -eq 0 ] && grep -qx "codesign -f -s ${OLD} -i dev.innsegl.cli ${TOP}/innsegl" <<<"${calls}"; then
  ok "OPS-169d INNSEGL_CODESIGN_IDENTITY picks the identity by its hash"
else
  bad "OPS-169d the identity asked for was not used" "exit=${rc} out=${out}
${calls}"
fi
fresh "${NEW}|${NAME}|Mar  1 09:00:00 2026 GMT"
INNSEGL_CODESIGN_IDENTITY=DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD4 run
if [ "${rc}" -eq 1 ] && ! grep -q '^codesign' <<<"${calls}" && grep -q 'not a code-signing identity' <<<"${out}"; then
  ok "OPS-169d an identity not held is refused, and nothing is signed"
else
  bad "OPS-169d an identity not held was not refused" "exit=${rc} out=${out}
${calls}"
fi
fresh "${NEW}|${NAME}|Mar  1 09:00:00 2026 GMT"
INNSEGL_CODESIGN_IDENTITY=none run
if [ "${rc}" -eq 0 ] && ! grep -qE '^(codesign|security)' <<<"${calls}" && grep -q 'unsigned' <<<"${out}"; then
  ok "OPS-169d INNSEGL_CODESIGN_IDENTITY=none leaves it unsigned, and says so"
else
  bad "OPS-169d =none still signed" "exit=${rc} out=${out}
${calls}"
fi

# OPS-169e
fresh "${NEW}|${NAME}|Mar  1 09:00:00 2026 GMT"
FAKE_CODESIGN_FAIL=1 run
if [ "${rc}" -eq 1 ] && grep -q 'errSecInternalComponent' <<<"${out}"; then
  ok "OPS-169e a failed signature fails the build, saying why"
else
  bad "OPS-169e a failed signature was not reported" "exit=${rc} out=${out}"
fi

# Usage.
out="$("${SCRIPT}" 2>&1)"; rc=$?
if [ "${rc}" -eq 2 ]; then
  ok "no binary named: usage, exit 2"
else
  bad "no binary named: exit ${rc}" "${out}"
fi

printf '\ncodesign-cli-selftest: %d passed, %d failed\n' "${pass}" "${fail}"
[ "${fail}" -eq 0 ]
