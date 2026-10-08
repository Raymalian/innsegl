#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# ca-rotate — replace the Fulcio CA, keeping the old root trusted for what it
# signed (#533, ADR-0075, runbooks/trust-rotation.md).
#
# WHERE IT RUNS. On the host that runs the stack, from the checkout the stack
# was brought up from: `make innsegl-ca-rotate`. It talks to Docker, to
# Fulcio's published port, and to the core through `docker exec`.
#
# WHAT IT DOES, IN ORDER. Every step is checked before the next.
#   pre-flight  refuse unless: CONFIRM=rotate, MODE and REASON given; Fulcio
#               and the core are running; Fulcio is the file CA reading its
#               password from serve.yaml; the root Fulcio serves is the one on
#               the volume; the trust history is readable and holds that root;
#               with BACKUP_MAX_AGE_HOURS, a trust-key backup that new exists.
#   1 archive   copy the CA (cert, key, password, serve.yaml) to
#               archive/<STAMP> in its own volume, still locked with its own
#               password. Never deleted.
#   2 stage     make the new CA beside it, the way the bootstrap makes the
#               first, with a new generated password.
#   3 switch    note the time, move the new CA into place, restart Fulcio,
#               and wait until it serves the new root.
#   4 prove     obtain a real certificate and check it chains to the new
#               root (deploy/compose/sigstore/verify.sh, certificate only).
#   5 end       end the old root in the trust history at the switch time:
#               MODE=revoke sets revoked_at (a key that may have been exposed:
#               only what the log integrated before then is accepted),
#               MODE=retire sets retired_at.
#   6 record    record the new root in the trust history. The core's daily
#               trust pass would too; doing it here makes it immediate.
#
# WHY THE HISTORY IS WRITTEN LAST, and not first. The history is append-only:
# an end date, once written, can never be taken back. Written before the
# switch, a rotation that then failed and rolled back would leave the root in
# use marked revoked, and every commit after it refused. So the end date is
# the time of the switch, and it is written once the new root is proven.
# Anything the old root issued after that time is refused under MODE=revoke,
# whenever it was written down.
#
# ROLLBACK. A failure before the switch removes the staged CA and its archive
# copy; nothing in use changed. A failure at or after the switch, up to and
# including step 5, puts the archived CA back and restarts Fulcio on it; the
# history is untouched. `rollback STAMP` does the same by hand, and keeps the
# CA it replaces in the archive first.
#
# USAGE
#   CONFIRM=rotate MODE=retire|revoke REASON='...' scripts/ca-rotate.sh rotate
#   CONFIRM=rollback scripts/ca-rotate.sh rollback STAMP
#
# ENVIRONMENT
#   BACKUP_MAX_AGE_HOURS         refuse unless the core holds a trust-key
#                                backup (trust-backup-*.tar.age) this new
#   INNSEGL_STACK_PREFIX         innsegl (live) or innsegl-dev (dev stack)
#   INNSEGL_ROTATE_FULCIO_URL    default: where Docker says Fulcio's port is
#                                published (`docker port`)
#   INNSEGL_ROTATE_FULCIO_CONTAINER  default <prefix>-sigstore-fulcio
#   INNSEGL_ROTATE_CORE_CONTAINER    default <prefix>-mcp; empty: none
#   INNSEGL_ROTATE_HISTORY_CMD   default `docker exec -i <core> innsegl
#                                trust-history`
#   INNSEGL_ROTATE_PROOF_CMD     default deploy/compose/sigstore/verify.sh
#   INNSEGL_ROTATE_WAIT_TRIES, INNSEGL_ROTATE_POLL_SECONDS
#                                how long to wait for Fulcio (60 x 2s)
#
# EXIT
#   0  rotated (a warning, if the new root could not be recorded yet)
#   2  usage: nothing touched
#   3  pre-flight refused: nothing touched
#   4  failed before the switch: everything as it was
#   5  failed after the switch and rolled back: the old CA serves again
#   6  failed after the switch and the rollback failed: finish it by hand
#
# Portability: the bash 3.2 that ships with macOS, and GNU userland.

set -uo pipefail

readonly EXIT_USAGE=2 EXIT_REFUSED=3 EXIT_BEFORE=4 EXIT_ROLLED_BACK=5 EXIT_STUCK=6

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
SIG="${ROOT}/deploy/compose/sigstore"
PREFIX="${INNSEGL_STACK_PREFIX:-innsegl}"
FULCIO="${INNSEGL_ROTATE_FULCIO_CONTAINER-${PREFIX}-sigstore-fulcio}"
CORE="${INNSEGL_ROTATE_CORE_CONTAINER-${PREFIX}-mcp}"
FULCIO_URL="${INNSEGL_ROTATE_FULCIO_URL:-}"
HISTORY_CMD="${INNSEGL_ROTATE_HISTORY_CMD:-docker exec -i ${CORE} innsegl trust-history}"
PROOF_CMD="${INNSEGL_ROTATE_PROOF_CMD:-${SIG}/verify.sh}"
# ADR-0076: TO=custody moves Fulcio onto the CA key store instead. CUSTODY_CMD
# VERB is `make ca-custody-VERB`: ready, stage (print the store's root), switch
# (Fulcio onto the store), back (Fulcio onto the file CA again).
TO="${TO:-file}"
CUSTODY_CMD="${INNSEGL_ROTATE_CUSTODY_CMD:-custody_make}"
WAIT_TRIES="${INNSEGL_ROTATE_WAIT_TRIES:-60}"
POLL_SECONDS="${INNSEGL_ROTATE_POLL_SECONDS:-2}"

log()  { printf 'ca-rotate: %s\n' "$*"; }
warn() { printf 'ca-rotate: WARN: %s\n' "$*" >&2; }
die()  { local code="$1"; shift; printf 'ca-rotate: %s\n' "$*" >&2; exit "${code}"; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/ca-rotate.XXXXXX")"
trap 'rm -rf "${WORK}"' EXIT

# The openssl image sigstore.yml pins, so the helper runs where the bootstrap
# runs.
openssl_image() {
  sed -n 's/^  \(alpine\/openssl:[^ ]*\)$/\1/p' "${ROOT}/deploy/compose/sigstore.yml" | head -n 1
}

fingerprint() { openssl x509 -in "$1" -outform DER 2>/dev/null | openssl dgst -sha256 | awk '{print $NF}'; }

# helper VERB [STAMP] runs ca-rotate-volume.sh against Fulcio's volume.
helper() {
  cat "${SIG}/ca-lib.sh" "${SIG}/ca-rotate-volume.sh" \
    | docker run -i --rm --network none --read-only --tmpfs /tmp \
        --security-opt no-new-privileges:true \
        -v "${PKI_VOLUME}:/pki" --entrypoint /bin/sh "${IMAGE}" -s -- "$@"
}

# history VERB ARGS... runs `innsegl trust-history` inside the core.
# Word-split on purpose: HISTORY_CMD is a command line.
history() {
  # shellcheck disable=SC2086
  ${HISTORY_CMD} "$@"
}

custody_make() { make -s --no-print-directory -C "${ROOT}" "ca-custody-$1"; }

# custody VERB runs one of TO=custody's steps. Word-split on purpose.
custody() {
  # shellcheck disable=SC2086
  ${CUSTODY_CMD} "$@"
}

served_root() { curl -fsS --max-time 15 "${FULCIO_URL}/api/v1/rootCert" > "$1" 2>/dev/null; }

# wait_for_root PEM: Fulcio serves exactly this root.
wait_for_root() {
  local want got i=0
  want="$(fingerprint "$1")"
  while [ "${i}" -lt "${WAIT_TRIES}" ]; do
    i=$((i + 1))
    if served_root "${WORK}/served.pem" && got="$(fingerprint "${WORK}/served.pem")" && [ "${got}" = "${want}" ]; then
      return 0
    fi
    sleep "${POLL_SECONDS}"
  done
  return 1
}

running() { [ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = true ]; }

# locate: the volume Fulcio's CA lives in, read from the container itself, so
# the script never guesses a name.
locate() {
  IMAGE="$(openssl_image)"
  [ -n "${IMAGE}" ] || die "${EXIT_REFUSED}" "no openssl image pin in deploy/compose/sigstore.yml"
  PKI_VOLUME="$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/etc/fulcio"}}{{.Name}}{{end}}{{end}}' "${FULCIO}" 2>/dev/null)"
  [ -n "${PKI_VOLUME}" ] || die "${EXIT_REFUSED}" "${FULCIO} mounts no volume at /etc/fulcio"
}

# rollback_to STAMP: the archived CA back in place, Fulcio on it.
rollback_to() {
  helper restore "$1" >&2 || return 1
  docker restart "${FULCIO}" >/dev/null || return 1
  wait_for_root "${WORK}/old.crt"
}

# after_switch_failed MESSAGE: roll back and exit 5, or exit 6.
after_switch_failed() {
  warn "$1; rolling back to archive ${STAMP}"
  if rollback_to "${STAMP}"; then
    die "${EXIT_ROLLED_BACK}" "rolled back: Fulcio serves the old root again and the trust history was not touched. Nothing else to do; find the cause and run the rotation again."
  fi
  die "${EXIT_STUCK}" "THE ROLLBACK FAILED TOO. The old CA is in its trust volume as archive/${STAMP}, unchanged. Put it back by hand:
    CONFIRM=rollback scripts/ca-rotate.sh rollback ${STAMP}
  then check that Fulcio serves the old root:
    curl -s ${FULCIO_URL}/api/v1/rootCert | openssl x509 -noout -fingerprint -sha256
  The trust history was not touched."
}

# not_before_stamp CERT prints the certificate's NotBefore as YYYYMMDDTHHMMSSZ,
# the form bundle names use, so the two compare as strings. awk with a month
# table, not `date -d` (GNU only) or regex repeat counts (mawk 20200120).
not_before_stamp() {
  openssl x509 -in "$1" -noout -startdate 2>/dev/null | sed 's/^notBefore=//' | awk '
    BEGIN { split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", m, " ")
            for (i = 1; i <= 12; i++) mon[m[i]] = sprintf("%02d", i) }
    NF >= 4 && ($1 in mon) { split($3, t, ":")
      printf "%s%s%02dT%s%s%sZ\n", $4, mon[$1], $2, t[1], t[2], t[3] }'
}

preflight() {
  [ "${CONFIRM:-}" = rotate ] || die "${EXIT_USAGE}" "refusing: set CONFIRM=rotate to replace the Fulcio CA (runbooks/trust-rotation.md)"
  case "${MODE:-}" in
    retire|revoke) : ;;
    *) die "${EXIT_USAGE}" "MODE must be retire (a planned rotation) or revoke (the key may have been exposed), got '${MODE:-}'" ;;
  esac
  [ -n "$(printf '%s' "${REASON:-}" | tr -d '[:space:]')" ] || die "${EXIT_USAGE}" "REASON is required: it is written into the trust history"
  case "${TO}" in
    file|custody) : ;;
    *) die "${EXIT_USAGE}" "TO must be file (a new file CA) or custody (the CA key store, ADR-0076), got '${TO}'" ;;
  esac

  docker version >/dev/null 2>&1 || die "${EXIT_REFUSED}" "docker is not reachable"
  running "${FULCIO}" || die "${EXIT_REFUSED}" "${FULCIO} is not running; the stack must be up (make start)"
  if [ -n "${CORE}" ]; then
    running "${CORE}" || die "${EXIT_REFUSED}" "${CORE} is not running; the stack must be up (make start)"
  fi
  local cmd
  cmd="$(docker inspect -f '{{json .Config.Cmd}}' "${FULCIO}" 2>/dev/null)"
  case "${cmd}" in
    *--ca=fileca*) : ;;
    *) die "${EXIT_REFUSED}" "${FULCIO} is not the file CA (key custody?); this rotation replaces a file CA only" ;;
  esac
  case "${cmd}" in
    *--config=/etc/fulcio/serve.yaml*) : ;;
    *) die "${EXIT_REFUSED}" "${FULCIO} does not read its password from serve.yaml; run make update first, so the bootstrap gives this host its own CA password" ;;
  esac
  locate
  # Where Fulcio is published, asked of Docker: the port may be set in .env,
  # which this script does not read.
  if [ -z "${FULCIO_URL}" ]; then
    local published
    published="$(docker port "${FULCIO}" 5555/tcp 2>/dev/null | head -n 1)"
    FULCIO_URL="http://${published:-127.0.0.1:${INNSEGL_FULCIO_PORT:-5555}}"
  fi

  served_root "${WORK}/old.crt" && openssl x509 -in "${WORK}/old.crt" -noout 2>/dev/null \
    || die "${EXIT_REFUSED}" "Fulcio at ${FULCIO_URL} does not serve a root certificate"
  helper show > "${WORK}/disk.crt" 2>/dev/null || die "${EXIT_REFUSED}" "could not read the CA from volume ${PKI_VOLUME}"
  [ "$(fingerprint "${WORK}/old.crt")" = "$(fingerprint "${WORK}/disk.crt")" ] \
    || die "${EXIT_REFUSED}" "the root Fulcio serves is not the root in ${PKI_VOLUME}; restart Fulcio or find out why before rotating"

  local code
  OLD_ID="$(history has --kind fulcio_root < "${WORK}/old.crt" 2>"${WORK}/has.err")"; code=$?
  case "${code}" in
    0) : ;;
    4) die "${EXIT_REFUSED}" "the trust history does not hold the current root. Rotating now would leave every commit it signed unverifiable. Let the core's trust pass record it (it runs at start and daily), or record it: ${HISTORY_CMD} record --kind fulcio_root < root.pem" ;;
    *) die "${EXIT_REFUSED}" "the trust history could not be read: $(cat "${WORK}/has.err")" ;;
  esac

  if [ -n "${BACKUP_MAX_AGE_HOURS:-}" ]; then
    case "${BACKUP_MAX_AGE_HOURS}" in
      *[!0-9]*) die "${EXIT_USAGE}" "BACKUP_MAX_AGE_HOURS must be a whole number of hours" ;;
    esac
    [ -n "${CORE}" ] || die "${EXIT_REFUSED}" "BACKUP_MAX_AGE_HOURS needs the core, where the backups are"
    local found
    # The NEWEST bundle in the window, and it must postdate the CA in use: a
    # bundle from before that CA was made holds the previous one, and a
    # rotation guarded by it has no copy of the key it is about to replace.
    # Bundle names carry their UTC time, so they sort by it.
    found="$(docker exec "${CORE}" sh -c "find /run/innsegl/trust-backups -name 'trust-backup-*.tar.age' -mmin -$((BACKUP_MAX_AGE_HOURS * 60)) 2>/dev/null | sort | tail -n 1")"
    [ -n "${found}" ] || die "${EXIT_REFUSED}" "no trust-key backup newer than ${BACKUP_MAX_AGE_HOURS}h on the core (runbooks/trust-key-backup.md); take one first"
    local bundle_at root_at
    bundle_at="$(basename "${found}" | sed -n 's/^trust-backup-\([0-9]*T[0-9]*Z\)\.tar\.age$/\1/p')"
    root_at="$(not_before_stamp "${WORK}/old.crt")"
    [ -n "${bundle_at}" ] && [ -n "${root_at}" ] \
      || die "${EXIT_REFUSED}" "cannot tell whether ${found} postdates the CA in use; take a new backup (runbooks/trust-key-backup.md)"
    [ "${bundle_at}" \> "${root_at}" ] \
      || die "${EXIT_REFUSED}" "the newest trust-key backup (${found}) is older than the CA in use (made ${root_at}), so it does not hold it; take a new backup first (runbooks/trust-key-backup.md)"
    log "a trust-key backup newer than ${BACKUP_MAX_AGE_HOURS}h and than the CA in use: ${found}"
  fi
  if [ "${TO}" = custody ]; then
    custody ready >&2 || die "${EXIT_REFUSED}" "the CA key store is not ready: it must be initialised and unlocked, and the custodian must have the CA's token (runbooks/ca-custody.md)"
  fi
  log "pre-flight passed: Fulcio serves root ${OLD_ID}, and the trust history holds it"
}

# after_custody_switch_failed MESSAGE: Fulcio back on the file CA, which the
# switch left untouched, and exit 5; or exit 6.
after_custody_switch_failed() {
  warn "$1; putting Fulcio back on the file CA"
  if custody back >&2 && wait_for_root "${WORK}/old.crt"; then
    die "${EXIT_ROLLED_BACK}" "rolled back: Fulcio serves the file CA's root again and the trust history was not touched. Find the cause and run the rotation again."
  fi
  die "${EXIT_STUCK}" "THE WAY BACK FAILED TOO. The file CA is unchanged in its volume. Put Fulcio back on it by hand:
    make ca-custody-back
  then check that Fulcio serves the old root:
    curl -s ${FULCIO_URL}/api/v1/rootCert | openssl x509 -noout -fingerprint -sha256
  The trust history was not touched."
}

# to_custody: ADR-0076. The file CA is not archived or changed: it is the way
# back. The store's root is minted from the store's own key (no import).
to_custody() {
  log '1 stage: the root of the CA key store'
  if ! custody stage > "${WORK}/new.crt" || ! openssl x509 -in "${WORK}/new.crt" -noout 2>/dev/null; then
    die "${EXIT_BEFORE}" "the store gave no root; nothing in use was changed"
  fi
  log '2 switch: Fulcio onto the store'
  SWITCHED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  custody switch >&2 || after_custody_switch_failed "moving Fulcio onto the store failed"
  wait_for_root "${WORK}/new.crt" || after_custody_switch_failed "Fulcio did not come back serving the store's root"

  log '3 prove: a real certificate from the new root'
  INNSEGL_SIGSTORE_VERIFY_CERT_ONLY=1 INNSEGL_SIGSTORE_VERIFY_ROOT="${WORK}/new.crt" \
    INNSEGL_FULCIO_URL="${FULCIO_URL}" ${PROOF_CMD} >&2 || after_custody_switch_failed "the new root did not issue a certificate that chains to it"

  log "4 end: the file CA's root (${MODE}), at ${SWITCHED_AT}"
  history end --kind fulcio_root --key-id "${OLD_ID}" --mode "${MODE}" \
    --at "${SWITCHED_AT}" --reason "${REASON}" >&2 \
    || after_custody_switch_failed "the trust history refused the end date"

  log "5 record: the store's root"
  local recorded=1
  history record --kind fulcio_root < "${WORK}/new.crt" >&2 || recorded=0
  log "moved onto the CA key store. The file CA's root ${OLD_ID} is ${MODE}d at ${SWITCHED_AT}, and the file CA is left in its volume."
  log "new root sha256 fingerprint $(fingerprint "${WORK}/new.crt")"
  if [ "${recorded}" = 0 ]; then
    warn "the new root is not in the trust history yet; the core's trust pass records it on its next run, or record it now: ${HISTORY_CMD} record --kind fulcio_root < new-root.pem"
  fi
  log 'next: take a new trust-key backup, and check a commit from each era (runbooks/ca-custody.md)'
}

rotate() {
  preflight
  if [ "${TO}" = custody ]; then
    to_custody
    return
  fi
  STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

  log "1 archive: the current CA, as archive/${STAMP}"
  if ! helper archive "${STAMP}" >&2; then
    helper discard "${STAMP}" >/dev/null 2>&1
    die "${EXIT_BEFORE}" "archiving failed; nothing in use was changed"
  fi
  log '2 stage: a new CA, with a new password'
  if ! helper stage "${STAMP}" > "${WORK}/new.crt" || ! openssl x509 -in "${WORK}/new.crt" -noout 2>/dev/null; then
    helper discard "${STAMP}" >/dev/null 2>&1
    die "${EXIT_BEFORE}" "making the new CA failed; nothing in use was changed"
  fi

  log '3 switch: the new CA in place, Fulcio restarted on it'
  SWITCHED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  helper swap "${STAMP}" >&2 || after_switch_failed "moving the new CA into place failed"
  docker restart "${FULCIO}" >/dev/null || after_switch_failed "restarting Fulcio failed"
  wait_for_root "${WORK}/new.crt" || after_switch_failed "Fulcio did not come back serving the new root"

  log '4 prove: a real certificate from the new root'
  INNSEGL_SIGSTORE_VERIFY_CERT_ONLY=1 INNSEGL_SIGSTORE_VERIFY_ROOT="${WORK}/new.crt" \
    INNSEGL_FULCIO_URL="${FULCIO_URL}" ${PROOF_CMD} >&2 || after_switch_failed "the new root did not issue a certificate that chains to it"

  log "5 end: the old root (${MODE}), at ${SWITCHED_AT}"
  history end --kind fulcio_root --key-id "${OLD_ID}" --mode "${MODE}" \
    --at "${SWITCHED_AT}" --reason "${REASON}" >&2 \
    || after_switch_failed "the trust history refused the end date"

  log '6 record: the new root'
  local recorded=1
  history record --kind fulcio_root < "${WORK}/new.crt" >&2 || recorded=0

  log "rotated. Old root ${OLD_ID} is ${MODE}d at ${SWITCHED_AT}; it is kept as archive/${STAMP}."
  log "new root sha256 fingerprint $(fingerprint "${WORK}/new.crt")"
  if [ "${recorded}" = 0 ]; then
    warn "the new root is not in the trust history yet. Fulcio publishes it, so new commits verify; the core's trust pass records it on its next run, or record it now: ${HISTORY_CMD} record --kind fulcio_root < new-root.pem"
  fi
  log 'next: take a new trust-key backup, and check a commit from each era (runbooks/trust-rotation.md)'
}

rollback() {
  local stamp="${1:-}"
  [ "${CONFIRM:-}" = rollback ] || die "${EXIT_USAGE}" "refusing: set CONFIRM=rollback to put an archived CA back"
  [ -n "${stamp}" ] || die "${EXIT_USAGE}" "name the archive: scripts/ca-rotate.sh rollback STAMP"
  docker version >/dev/null 2>&1 || die "${EXIT_REFUSED}" "docker is not reachable"
  locate
  if [ -z "${FULCIO_URL}" ]; then
    local published
    published="$(docker port "${FULCIO}" 5555/tcp 2>/dev/null | head -n 1)"
    FULCIO_URL="http://${published:-127.0.0.1:${INNSEGL_FULCIO_PORT:-5555}}"
  fi
  helper show > "${WORK}/now.crt" 2>/dev/null || die "${EXIT_REFUSED}" "could not read the CA from volume ${PKI_VOLUME}"
  STAMP="$(date -u +%Y%m%dT%H%M%SZ)-before-rollback"
  helper archive "${STAMP}" >&2 || die "${EXIT_REFUSED}" "could not keep the current CA in the archive; nothing changed"
  if ! helper restore "${stamp}" >&2; then
    # The copy just made is of what is still in place; it is not kept.
    helper discard "${STAMP}" >/dev/null 2>&1
    die "${EXIT_REFUSED}" "archive ${stamp} could not be put back; the current CA is unchanged"
  fi
  # The root to wait for is the one now on the volume.
  helper show > "${WORK}/old.crt" 2>/dev/null || die "${EXIT_STUCK}" "could not read the restored CA"
  docker restart "${FULCIO}" >/dev/null || die "${EXIT_STUCK}" "restarting Fulcio failed"
  wait_for_root "${WORK}/old.crt" || die "${EXIT_STUCK}" "Fulcio did not come back serving archive ${stamp}'s root"
  log "archive ${stamp} is back and served; the CA it replaced is kept as archive/${STAMP}"
  log 'the trust history is not changed by a rollback (runbooks/trust-rotation.md, "Rollback")'
}

case "${1:-}" in
  rotate)   rotate ;;
  rollback) rollback "${2:-}" ;;
  *) die "${EXIT_USAGE}" "usage: CONFIRM=rotate MODE=retire|revoke REASON=... $0 rotate | CONFIRM=rollback $0 rollback STAMP" ;;
esac
