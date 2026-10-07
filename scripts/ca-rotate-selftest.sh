#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# OPS-132 — scripts/ca-rotate.sh refuses, rotates and rolls back as it says
# (#533). The orchestration only: docker, curl, the core's trust-history
# command and the proof are fakes that keep state in a directory, so every
# failure can be injected at every step. What the fakes stand in for is
# proven for real elsewhere:
#   - the volume helper's archive, stage, swap and restore, and Fulcio coming
#     back on the new root: internal/verify's TestOPS133 (a real stack);
#   - `innsegl trust-history`: cmd/innsegl's tests;
#   - the bootstrap the new CA is made like: sigstore-bootstrap-selftest.sh.
#
#   OPS-132a  no CONFIRM=rotate, no MODE, an unknown MODE or no REASON: usage,
#             and nothing is touched.
#   OPS-132b  pre-flight refuses, touching nothing, when: Fulcio or the core
#             is not running; Fulcio runs under key custody; Fulcio predates
#             the password file; the history cannot be read; the history does
#             not hold the current root; the root on disk is not the one
#             served; a fresh backup is asked for and there is none.
#   OPS-132c  a rotation: archive, new CA, Fulcio restarted on it, proof, the
#             old root ended at the switch with the mode and reason given, the
#             new root recorded. Revoke and retire.
#   OPS-132d  a failure before the switch leaves everything as it was.
#   OPS-132e  a failure after it restores the archived CA and Fulcio serves
#             the old root again; the history is untouched.
#   OPS-132f  a rollback that fails too says so, and how to finish by hand.
#   OPS-132g  the new root not recorded: rotated, with a warning.
#   OPS-132h  `rollback STAMP`: needs CONFIRM=rollback, keeps the current CA in
#             the archive, and puts STAMP's back.

set -uo pipefail

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
SCRIPT="${ROOT}/scripts/ca-rotate.sh"

pass=0; fail=0
ok()  { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; return 0; }

command -v openssl >/dev/null 2>&1 || { echo 'ca-rotate-selftest: openssl is required' >&2; exit 1; }

TOP="$(mktemp -d "${TMPDIR:-/tmp}/ca-rotate-selftest.XXXXXX")"
trap 'rm -rf "${TOP}"' EXIT

fp() { openssl x509 -in "$1" -outform DER 2>/dev/null | openssl dgst -sha256 | awk '{print $NF}'; }

mkcert() {
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$1.key" \
    -subj "/CN=$2" -days 30 -out "$1" >/dev/null 2>&1 || { echo "ca-rotate-selftest: cannot make $1" >&2; exit 1; }
}
mkcert "${TOP}/root1.pem" root1
mkcert "${TOP}/root2.pem" root2

# ---------------------------------------------------------------------------
# The fakes. FAKE is a directory of state:
#   served.pem      what Fulcio serves      disk.pem     the volume's ca.crt
#   staged.pem      the staged new CA       archive/S    an archived CA
#   history         "<id> <state>" lines    calls        every call, in order
#   running-fulcio, running-core, fulcio-cmd
# FAKE_FAIL names the steps that fail: archive stage swap restart proof end
# record restore. FAKE_STUCK=1 is a Fulcio that keeps serving what it served.
# ---------------------------------------------------------------------------
BIN="${TOP}/bin"
mkdir -p "${BIN}"

cat > "${BIN}/docker" <<'EOF'
#!/usr/bin/env bash
F="${FAKE:?}"
echo "docker $*" >> "${F}/calls"
fails() { case ",${FAKE_FAIL:-}," in *",$1,"*) return 0 ;; esac; return 1; }
fp() { openssl x509 -in "$1" -outform DER 2>/dev/null | openssl dgst -sha256 | awk '{print $NF}'; }
case "$1" in
  version|info) exit 0 ;;
  inspect)
    fmt="$3"; name="$4"
    role=core; case "${name}" in *fulcio*) role=fulcio ;; esac
    case "${fmt}" in
      *State.Running*) [ -f "${F}/running-${role}" ] || exit 1; cat "${F}/running-${role}" ;;
      *Config.Cmd*)    cat "${F}/fulcio-cmd" ;;
      *Mounts*)        [ -n "${FAKE_NO_MOUNT:-}" ] || echo fake-pki-volume ;;
      *) exit 1 ;;
    esac ;;
  restart)
    # A restart that fails fails once: the rollback's own restart works.
    if fails restart && [ ! -e "${F}/restart-failed" ]; then : > "${F}/restart-failed"; exit 1; fi
    [ -n "${FAKE_STUCK:-}" ] || cp "${F}/disk.pem" "${F}/served.pem"
    echo "$2" ;;
  run)
    cat >/dev/null
    shift
    while [ "$#" -gt 0 ] && [ "$1" != "-s" ]; do shift; done
    shift 2
    verb="$1"; stamp="${2:-}"
    echo "helper ${verb} ${stamp}" >> "${F}/calls"
    case "${verb}" in
      show)    fails show && exit 1
               cat "${F}/disk.pem" ;;
      archive) fails archive && exit 1
               [ -e "${F}/archive/${stamp}" ] && exit 1
               mkdir -p "${F}/archive"; cp "${F}/disk.pem" "${F}/archive/${stamp}" ;;
      stage)   fails stage && exit 1
               cp "${F}/next.pem" "${F}/staged.pem"; cat "${F}/staged.pem" ;;
      swap)    fails swap && exit 1
               mv "${F}/staged.pem" "${F}/disk.pem" ;;
      restore) fails restore && exit 1
               [ -e "${F}/archive/${stamp}" ] || exit 1
               cp "${F}/archive/${stamp}" "${F}/disk.pem" ;;
      discard) rm -f "${F}/staged.pem" "${F}/archive/${stamp}" ;;
      *) exit 2 ;;
    esac ;;
  exec)
    shift
    [ "$1" = "-i" ] && shift
    shift   # the container
    if [ "$1" = sh ]; then
      [ -n "${FAKE_BACKUP:-}" ] && echo /run/innsegl/trust-backups/trust-backup-x.tar.age
      exit 0
    fi
    shift 2  # innsegl trust-history
    verb="$1"; shift
    echo "history ${verb} $*" >> "${F}/calls"
    case "${verb}" in
      has)
        [ -n "${FAKE_HISTORY_BROKEN:-}" ] && exit 3
        cat > "${F}/stdin.pem"; id="$(fp "${F}/stdin.pem")"
        grep -q "^${id} " "${F}/history" 2>/dev/null || exit 4
        echo "${id}" ;;
      record)
        fails record && exit 3
        cat > "${F}/stdin.pem"; id="$(fp "${F}/stdin.pem")"
        grep -q "^${id} " "${F}/history" || echo "${id} current" >> "${F}/history" ;;
      end)
        fails end && exit 3
        id=""; mode=""; at=""; reason=""
        while [ "$#" -gt 0 ]; do
          case "$1" in
            --key-id) id="$2" ;; --mode) mode="$2" ;; --at) at="$2" ;; --reason) reason="$2" ;;
          esac
          shift 2
        done
        sed -i.bak "s/^${id} current$/${id} ${mode}|${at}|${reason}/" "${F}/history" ;;
    esac ;;
  *) exit 2 ;;
esac
EOF

cat > "${BIN}/curl" <<'EOF'
#!/usr/bin/env bash
echo "curl $*" >> "${FAKE:?}/calls"
[ -n "${FAKE_FULCIO_DOWN:-}" ] && exit 7
case "$*" in *rootCert*) cat "${FAKE}/served.pem" ;; *) exit 22 ;; esac
EOF

cat > "${BIN}/proof" <<'EOF'
#!/usr/bin/env bash
echo "proof root=${INNSEGL_SIGSTORE_VERIFY_ROOT:-} certonly=${INNSEGL_SIGSTORE_VERIFY_CERT_ONLY:-}" >> "${FAKE:?}/calls"
case ",${FAKE_FAIL:-}," in *,proof,*) exit 1 ;; esac
cmp -s "${INNSEGL_SIGSTORE_VERIFY_ROOT}" "${FAKE}/next.pem"
EOF
chmod +x "${BIN}/docker" "${BIN}/curl" "${BIN}/proof"

# ADR-0076's custody steps, as the Makefile targets the script runs.
cat > "${BIN}/custody" <<'STUB'
echo "custody $1" >> "${FAKE:?}/calls"
case ",${FAKE_FAIL:-}," in *",custody-$1,"*) exit 1 ;; esac
case "$1" in
  ready)  [ -z "${FAKE_CUSTODY_NOT_READY:-}" ] ;;
  stage)  cat "${FAKE}/next.pem" ;;
  switch) cp "${FAKE}/next.pem" "${FAKE}/served.pem" ;;
  back)   cp "${FAKE}/disk.pem" "${FAKE}/served.pem" ;;
  *) exit 2 ;;
esac
STUB
chmod +x "${BIN}/custody"

# fresh: a new state directory, a running stack on root1, root1 in the history.
fresh() {
  FAKE="$(mktemp -d "${TOP}/case.XXXXXX")"
  export FAKE
  cp "${TOP}/root1.pem" "${FAKE}/disk.pem"
  cp "${TOP}/root1.pem" "${FAKE}/served.pem"
  cp "${TOP}/root2.pem" "${FAKE}/next.pem"
  echo true > "${FAKE}/running-fulcio"
  echo true > "${FAKE}/running-core"
  echo '["serve","--ca=fileca","--fileca-key=/etc/fulcio/ca.key","--config=/etc/fulcio/serve.yaml"]' > "${FAKE}/fulcio-cmd"
  echo "$(fp "${TOP}/root1.pem") current" > "${FAKE}/history"
  : > "${FAKE}/calls"
}

# rotate [ENV=VALUE...] runs the script with the fakes and the given settings.
rotate() {
  OUT="$(env PATH="${BIN}:${PATH}" INNSEGL_ROTATE_PROOF_CMD="${BIN}/proof" \
    INNSEGL_ROTATE_WAIT_TRIES=2 INNSEGL_ROTATE_POLL_SECONDS=0 \
    CONFIRM=rotate MODE=revoke REASON='key may be exposed' FAKE_FAIL='' "$@" \
    "${SCRIPT}" rotate 2>&1)"
  CODE=$?
}

touched() { grep -qE '^helper (archive|stage|swap|restore)|^docker restart|^history (end|record)' "${FAKE}/calls"; }
served_is() { [ "$(fp "${FAKE}/served.pem")" = "$(fp "${TOP}/$1.pem")" ]; }
disk_is()   { [ "$(fp "${FAKE}/disk.pem")" = "$(fp "${TOP}/$1.pem")" ]; }
history_untouched() { [ "$(cat "${FAKE}/history")" = "$(fp "${TOP}/root1.pem") current" ]; }

echo "OPS-132a — usage"
for setting in "CONFIRM=" "MODE=" "MODE=forget" "REASON=" "REASON= "; do
  fresh; rotate "${setting}"
  if [ "${CODE}" = 2 ] && ! touched; then ok "${setting:-} refused as usage, nothing touched"; else bad "${setting} refused as usage, nothing touched" "exit ${CODE}: ${OUT}"; fi
done

echo "OPS-132b — pre-flight"
preflight() {
  local name="$1"; shift
  rotate "$@"
  if [ "${CODE}" = 3 ] && ! touched && served_is root1 && disk_is root1 && history_untouched; then
    ok "${name}: refused, nothing touched"
  else
    bad "${name}: refused, nothing touched" "exit ${CODE}: ${OUT}"
  fi
}
fresh; echo false > "${FAKE}/running-fulcio"; preflight "Fulcio not running"
fresh; rm -f "${FAKE}/running-core"; preflight "the core not running"
fresh; echo '["serve","--ca=kmsca"]' > "${FAKE}/fulcio-cmd"; preflight "Fulcio under key custody"
fresh; echo '["serve","--ca=fileca","--fileca-key-passwd","x"]' > "${FAKE}/fulcio-cmd"; preflight "Fulcio from before the password file"
fresh; preflight "the history unreadable" FAKE_HISTORY_BROKEN=1
fresh; : > "${FAKE}/history"; rotate
if [ "${CODE}" = 3 ] && ! touched && printf '%s' "${OUT}" | grep -q 'does not hold'; then ok "the history without the current root: refused, saying so"; else bad "the history without the current root: refused, saying so" "exit ${CODE}: ${OUT}"; fi
fresh; cp "${TOP}/root2.pem" "${FAKE}/disk.pem"; rotate
if [ "${CODE}" = 3 ] && ! touched; then ok "the root on disk is not the one served: refused"; else bad "the root on disk is not the one served: refused" "exit ${CODE}: ${OUT}"; fi
fresh; preflight "Fulcio not answering" FAKE_FULCIO_DOWN=1
fresh; preflight "a fresh backup asked for, none there" BACKUP_MAX_AGE_HOURS=24
fresh; rotate BACKUP_MAX_AGE_HOURS=soon
if [ "${CODE}" = 2 ] && ! touched; then ok "a backup age that is not a number: usage, nothing touched"; else bad "a backup age that is not a number: usage, nothing touched" "exit ${CODE}: ${OUT}"; fi
fresh; preflight "Fulcio mounts no CA volume" FAKE_NO_MOUNT=1
fresh; preflight "the CA on the volume cannot be read" FAKE_FAIL=show
fresh; preflight "a fresh backup asked for with no core to hold it" BACKUP_MAX_AGE_HOURS=24 INNSEGL_ROTATE_CORE_CONTAINER=
fresh; rotate BACKUP_MAX_AGE_HOURS=24 FAKE_BACKUP=1
if [ "${CODE}" = 0 ]; then ok "a fresh backup there: the rotation runs"; else bad "a fresh backup there: the rotation runs" "exit ${CODE}: ${OUT}"; fi

echo "OPS-132c — a rotation"
fresh
before="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
rotate
after="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
if [ "${CODE}" = 0 ]; then ok "exit 0"; else bad "exit 0" "exit ${CODE}: ${OUT}"; fi
if served_is root2 && disk_is root2; then ok "Fulcio serves the new root"; else bad "Fulcio serves the new root"; fi
stamp="$(sed -n 's/^helper archive \(.*\)$/\1/p' "${FAKE}/calls")"
if [ -n "${stamp}" ] && [ "$(fp "${FAKE}/archive/${stamp}")" = "$(fp "${TOP}/root1.pem")" ]; then ok "the old CA is archived as ${stamp}"; else bad "the old CA is archived"; fi
line="$(grep "^$(fp "${TOP}/root1.pem") " "${FAKE}/history")"
at="$(printf '%s' "${line}" | cut -d'|' -f2)"
if printf '%s' "${line}" | grep -q " revoke|.*|key may be exposed$"; then ok "the old root is revoked, with the reason"; else bad "the old root is revoked, with the reason" "${line}"; fi
if [[ ! "${at}" < "${before}" ]] && [[ ! "${at}" > "${after}" ]]; then ok "at the time of the switch"; else bad "at the time of the switch" "${at} not in [${before}, ${after}]"; fi
if grep -q "^$(fp "${TOP}/root2.pem") current$" "${FAKE}/history"; then ok "the new root is recorded"; else bad "the new root is recorded"; fi
order="$(grep -oE '^helper (archive|stage|swap)|^docker restart|^proof|^history (end|record)' "${FAKE}/calls" | tr '\n' ',')"
if [ "${order}" = "helper archive,helper stage,helper swap,docker restart,proof,history end,history record," ]; then ok "in order: archive, stage, swap, restart, proof, end, record"; else bad "in order" "${order}"; fi
if grep -q "^proof root=.* certonly=1$" "${FAKE}/calls"; then ok "the proof is certificate-only, against the new root"; else bad "the proof is certificate-only" "$(grep '^proof' "${FAKE}/calls")"; fi
fresh; rotate MODE=retire REASON='planned'
if [ "${CODE}" = 0 ] && grep -q " retire|.*|planned$" "${FAKE}/history"; then ok "MODE=retire retires"; else bad "MODE=retire retires" "exit ${CODE}: $(cat "${FAKE}/history")"; fi

echo "OPS-132d — a failure before the switch changes nothing"
for step in archive stage; do
  fresh; rotate FAKE_FAIL="${step}"
  if [ "${CODE}" = 4 ] && served_is root1 && disk_is root1 && history_untouched \
    && ! grep -qE 'helper swap|docker restart' "${FAKE}/calls" && [ ! -e "${FAKE}/staged.pem" ]; then
    ok "${step} fails: exit 4, as it was"
  else
    bad "${step} fails: exit 4, as it was" "exit ${CODE}: ${OUT}"
  fi
done

echo "OPS-132e — a failure after the switch is rolled back"
for f in "FAKE_FAIL=swap" "FAKE_FAIL=restart" "FAKE_STUCK=1" "FAKE_FAIL=proof" "FAKE_FAIL=end"; do
  fresh; rotate "${f}"
  # A stuck Fulcio keeps serving root1 throughout, which is the state wanted.
  if [ "${CODE}" = 5 ] && disk_is root1 && served_is root1 && history_untouched; then
    ok "${f}: exit 5, the old CA back and served"
  else
    bad "${f}: exit 5, the old CA back and served" "exit ${CODE}: ${OUT}"
  fi
done

echo "OPS-132f — a rollback that fails too"
fresh; rotate FAKE_FAIL=proof,restore
if [ "${CODE}" = 6 ] && printf '%s' "${OUT}" | grep -q 'rollback STAMP\|ca-rotate.sh rollback'; then ok "exit 6, with the command to finish by hand"; else bad "exit 6, with the command to finish by hand" "exit ${CODE}: ${OUT}"; fi

echo "OPS-132g — the new root not recorded"
fresh; rotate FAKE_FAIL=record
if [ "${CODE}" = 0 ] && served_is root2 && printf '%s' "${OUT}" | grep -q 'WARN'; then ok "rotated, with a warning"; else bad "rotated, with a warning" "exit ${CODE}: ${OUT}"; fi

echo "OPS-132h — rollback STAMP"
fresh; rotate
stamp="$(sed -n 's/^helper archive \(.*\)$/\1/p' "${FAKE}/calls")"
: > "${FAKE}/calls"
OUT="$(env PATH="${BIN}:${PATH}" INNSEGL_ROTATE_WAIT_TRIES=2 INNSEGL_ROTATE_POLL_SECONDS=0 "${SCRIPT}" rollback "${stamp}" 2>&1)"; CODE=$?
if [ "${CODE}" = 2 ] && ! touched; then ok "without CONFIRM=rollback: usage, nothing touched"; else bad "without CONFIRM=rollback: usage, nothing touched" "exit ${CODE}: ${OUT}"; fi
OUT="$(env PATH="${BIN}:${PATH}" INNSEGL_ROTATE_WAIT_TRIES=2 INNSEGL_ROTATE_POLL_SECONDS=0 CONFIRM=rollback "${SCRIPT}" rollback no-such-stamp 2>&1)"; CODE=$?
if [ "${CODE}" != 0 ] && served_is root2 && disk_is root2; then ok "an unknown stamp: refused, the CA kept"; else bad "an unknown stamp: refused, the CA kept" "exit ${CODE}: ${OUT}"; fi
OUT="$(env PATH="${BIN}:${PATH}" INNSEGL_ROTATE_WAIT_TRIES=2 INNSEGL_ROTATE_POLL_SECONDS=0 CONFIRM=rollback "${SCRIPT}" rollback "${stamp}" 2>&1)"; CODE=$?
kept="$(ls "${FAKE}/archive" | grep -v "^${stamp}$" | tail -n 1)"
if [ "${CODE}" = 0 ] && served_is root1 && disk_is root1; then ok "the archived CA is back and served"; else bad "the archived CA is back and served" "exit ${CODE}: ${OUT}"; fi
if [ -n "${kept}" ] && [ "$(fp "${FAKE}/archive/${kept}")" = "$(fp "${TOP}/root2.pem")" ]; then ok "the CA it replaced is kept in the archive"; else bad "the CA it replaced is kept in the archive"; fi
if ! grep -q '^history ' "${FAKE}/calls"; then ok "the history is not touched"; else bad "the history is not touched"; fi

rollback_with() {
  OUT="$(env PATH="${BIN}:${PATH}" INNSEGL_ROTATE_WAIT_TRIES=2 INNSEGL_ROTATE_POLL_SECONDS=0 CONFIRM=rollback "$@" 2>&1)"; CODE=$?
}
fresh; rotate; stamp="$(sed -n 's/^helper archive \(.*\)$/\1/p' "${FAKE}/calls")"
rollback_with "${SCRIPT}" rollback
if [ "${CODE}" = 2 ]; then ok "no STAMP: usage"; else bad "no STAMP: usage" "exit ${CODE}: ${OUT}"; fi
rollback_with FAKE_FAIL=restart "${SCRIPT}" rollback "${stamp}"
if [ "${CODE}" = 6 ]; then ok "Fulcio does not restart: exit 6"; else bad "Fulcio does not restart: exit 6" "exit ${CODE}: ${OUT}"; fi
fresh; rotate; stamp="$(sed -n 's/^helper archive \(.*\)$/\1/p' "${FAKE}/calls")"
rollback_with FAKE_STUCK=1 "${SCRIPT}" rollback "${stamp}"
if [ "${CODE}" = 6 ]; then ok "Fulcio does not come back on the archived root: exit 6"; else bad "Fulcio does not come back on the archived root: exit 6" "exit ${CODE}: ${OUT}"; fi
fresh; rollback_with FAKE_FAIL=archive "${SCRIPT}" rollback whatever
if [ "${CODE}" = 3 ] && disk_is root1; then ok "the current CA cannot be kept: refused, nothing changed"; else bad "the current CA cannot be kept: refused, nothing changed" "exit ${CODE}: ${OUT}"; fi


echo "OPS-152 — TO=custody: onto the CA key store (ADR-0076)"
custody() {
  OUT="$(env PATH="${BIN}:${PATH}" INNSEGL_ROTATE_PROOF_CMD="${BIN}/proof" \
    INNSEGL_ROTATE_WAIT_TRIES=2 INNSEGL_ROTATE_POLL_SECONDS=0 \
    INNSEGL_ROTATE_CUSTODY_CMD="${BIN}/custody" \
    CONFIRM=rotate TO=custody MODE=retire REASON='CA key custody' FAKE_FAIL='' "$@" \
    "${SCRIPT}" rotate 2>&1)"
  CODE=$?
}
custody_touched() { grep -qE '^custody (stage|switch|back)|^history (end|record)|^helper (archive|stage|swap)' "${FAKE}/calls"; }
fresh; custody TO=elsewhere
if [ "${CODE}" = 2 ] && ! custody_touched; then ok "TO names something else: usage, nothing touched"; else bad "TO names something else: usage, nothing touched" "exit ${CODE}: ${OUT}"; fi
fresh; custody FAKE_CUSTODY_NOT_READY=1
if [ "${CODE}" = 3 ] && ! custody_touched && served_is root1 && history_untouched; then ok "the custodian not ready: refused, nothing touched"; else bad "the custodian not ready: refused, nothing touched" "exit ${CODE}: ${OUT}"; fi
fresh; custody
if [ "${CODE}" = 0 ] && served_is root2; then ok "Fulcio serves the store's root"; else bad "Fulcio serves the store's root" "exit ${CODE}: ${OUT}"; fi
if disk_is root1 && ! grep -qE '^helper (archive|stage|swap)' "${FAKE}/calls"; then ok "the file CA is left as it was, for the way back"; else bad "the file CA is left as it was, for the way back"; fi
if grep -q "^$(fp "${TOP}/root1.pem") retire|.*|CA key custody$" "${FAKE}/history" && grep -q "^$(fp "${TOP}/root2.pem") current$" "${FAKE}/history"; then ok "the file CA's era is retired and the store's root recorded"; else bad "the file CA's era is retired and the store's root recorded" "$(cat "${FAKE}/history")"; fi
fresh; custody FAKE_FAIL=proof
if [ "${CODE}" = 5 ] && served_is root1 && history_untouched && grep -q '^custody back' "${FAKE}/calls"; then ok "the proof fails: back on the file CA, history untouched, exit 5"; else bad "the proof fails: back on the file CA, history untouched, exit 5" "exit ${CODE}: ${OUT}"; fi
fresh; custody FAKE_FAIL=custody-stage
if [ "${CODE}" = 4 ] && served_is root1 && history_untouched && ! grep -q '^custody switch' "${FAKE}/calls"; then ok "no root from the store: nothing switched, exit 4"; else bad "no root from the store: nothing switched, exit 4" "exit ${CODE}: ${OUT}"; fi
fresh; custody FAKE_FAIL=proof,custody-back
if [ "${CODE}" = 6 ]; then ok "the proof fails and the way back too: exit 6"; else bad "the proof fails and the way back too: exit 6" "exit ${CODE}: ${OUT}"; fi

echo "the command line"
OUT="$(env PATH="${BIN}:${PATH}" "${SCRIPT}" 2>&1)"; CODE=$?
if [ "${CODE}" = 2 ]; then ok "no subcommand: usage"; else bad "no subcommand: usage" "exit ${CODE}"; fi

printf '\n%d passed, %d failed\n' "${pass}" "${fail}"
[ "${fail}" -eq 0 ]
