#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# OPS-159 (PROPOSED) — `make ca-custody-reset` removes a CA key store only
# when nothing depends on it, with a fake docker that records every call.
#
#   no CONFIRM=reset                      usage, nothing removed
#   Fulcio runs on the store              refused, nothing removed
#   the trust history holds its root      refused, nothing removed
#   the history cannot be read            refused, nothing removed
#   a store whose root never signed       the store, its material and the
#                                         root's volume removed
#   no root minted at all                 removed as well
set -uo pipefail

HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
SUT="${HERE}/ca-custody-reset.sh"
TOP="$(mktemp -d "${TMPDIR:-/tmp}/ca-custody-reset-selftest.XXXXXX")"
trap 'rm -rf "${TOP}"' EXIT
FAKE="${TOP}/fake"
mkdir -p "${FAKE}"
pass=0 fail=0
ok()  { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL  %s\n        %s\n' "$1" "$2"; }

cat > "${FAKE}/docker" <<'SH'
#!/usr/bin/env bash
F="$(dirname "$0")"
echo "$*" >> "${F}/calls"
case "$1" in
  inspect) [ -n "${FAKE_KMSCA:-}" ] && echo '["serve","--ca=kmsca"]' || echo '["serve","--ca=fileca"]' ;;
  run) if [ -n "${FAKE_CHAIN:-}" ] && [ "${*: -2:1}" = cat ]; then echo "-----BEGIN CERTIFICATE-----"; fi ;;
  exec) cat >/dev/null; exit "${FAKE_HAS:-4}" ;;
  *) exit 0 ;;
esac
SH
chmod +x "${FAKE}/docker"

fresh() { rm -f "${FAKE}/calls"; : > "${FAKE}/calls"; }
removed() { grep -q "find /v -mindepth 1 -delete" "${FAKE}/calls"; }
run() { OUT="$(env INNSEGL_RESET_DOCKER="${FAKE}/docker" "$@" "${SUT}" 2>&1)"; CODE=$?; }

echo "OPS-159 — ca-custody-reset"
fresh; run env -u CONFIRM
if [ "${CODE}" = 2 ] && ! removed; then ok "no CONFIRM=reset: usage, nothing removed"; else bad "no CONFIRM=reset: usage, nothing removed" "exit ${CODE}: ${OUT}"; fi
fresh; run env CONFIRM=reset FAKE_KMSCA=1 FAKE_CHAIN=1
if [ "${CODE}" = 3 ] && ! removed && printf '%s' "${OUT}" | grep -q 'runs on the store'; then ok "Fulcio on the store: refused, nothing removed"; else bad "Fulcio on the store: refused, nothing removed" "exit ${CODE}: ${OUT}"; fi
fresh; run env CONFIRM=reset FAKE_CHAIN=1 FAKE_HAS=0
if [ "${CODE}" = 3 ] && ! removed && printf '%s' "${OUT}" | grep -q 'trust history holds'; then ok "the history holds its root: refused, nothing removed"; else bad "the history holds its root: refused, nothing removed" "exit ${CODE}: ${OUT}"; fi
fresh; run env CONFIRM=reset FAKE_CHAIN=1 FAKE_HAS=3
if [ "${CODE}" = 3 ] && ! removed; then ok "the history unreadable: refused, nothing removed"; else bad "the history unreadable: refused, nothing removed" "exit ${CODE}: ${OUT}"; fi
fresh; run env CONFIRM=reset FAKE_CHAIN=1 FAKE_HAS=4
if [ "${CODE}" = 0 ] && grep -q "run --rm -v innsegl-trust-ca-store:/v" "${FAKE}/calls" && grep -q "run --rm -v innsegl-trust-ca-custody:/v" "${FAKE}/calls" && grep -q "run --rm -v innsegl-sigstore_sigstore-fulcio-kms:/v" "${FAKE}/calls" && ! grep -q "^volume rm" "${FAKE}/calls"; then ok "a root that never signed: the store, its material and the root's volume removed"; else bad "a root that never signed: removed" "exit ${CODE}: ${OUT} / $(cat "${FAKE}/calls")"; fi
fresh; run env CONFIRM=reset
if [ "${CODE}" = 0 ] && removed; then ok "no root minted: removed"; else bad "no root minted: removed" "exit ${CODE}: ${OUT}"; fi

echo "ca-custody-reset-selftest: ${pass} passed, ${fail} failed"
[ "${fail}" = 0 ]
