#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# OPS-044, OPS-046 and OPS-047 — the backup as a service in the deployment
# rather than a job on the host (RM-146, #237).
#
# WHAT IS ASSERTED, and why none of it needs Docker:
#
#   OPS-047  there is no host scheduler left, and the backup is declared as a
#            service. A grep, because "removed" is a property of the repository.
#   OPS-044  that service mounts no container-runtime socket. Also a grep, and
#            the one that matters most: a process holding that socket is root on
#            the host, and the whole point of moving the backup into the
#            deployment is that it stops holding one. The live half — attempting
#            the call inside the running container — is OPS-044's other arm and
#            needs the stack.
#   OPS-046  the healthcheck's verdicts, driven directly. It is a pure function
#            of a marker file and a clock, so it is drivable with no database,
#            no object store and no container.
#
# THE LAST CASE IS WHAT KEEPS THE REST HONEST: `unverified` must be HEALTHY. A
# healthcheck that failed on everything would pass every negative case here and
# would take a stack down for the ordinary state of a ledger whose tail has not
# sealed yet.

set -uo pipefail

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
COMPOSE="${ROOT}/deploy/compose/innsegl.yml"
HEALTH="${ROOT}/deploy/compose/innsegl/backup-health.sh"
LOOP="${ROOT}/deploy/compose/innsegl/backup-loop.sh"

pass=0
fail=0
ok()  { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; return 0; }

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

echo "OPS-047 — no host scheduler, and a service instead"

if [ -e "${ROOT}/scripts/backup-schedule.sh" ]; then
  bad "the host scheduler script is gone" "scripts/backup-schedule.sh still exists"
else
  ok "the host scheduler script is gone"
fi

if grep -nE 'launchctl|systemctl --user|crontab' "${ROOT}/Makefile" >/dev/null 2>&1; then
  bad "the Makefile installs no host timer" \
      "$(grep -nE 'launchctl|systemctl --user|crontab' "${ROOT}/Makefile" | head -1)"
else
  ok "the Makefile installs no host timer"
fi

if grep -qE '^  innsegl-backup:' "${COMPOSE}"; then
  ok "the deployment declares a backup service"
else
  bad "the deployment declares a backup service" "no innsegl-backup service in ${COMPOSE##*/}"
fi

echo "OPS-044 — that service holds no container-runtime socket"

# The service's own block, from its name to the next top-level service.
block="$(awk '/^  innsegl-backup:/{f=1} f{print} f&&/^  [a-z].*:$/&&!/^  innsegl-backup:/{if(++n>1)exit}' "${COMPOSE}")"
if [ -z "${block}" ]; then
  bad "the backup service block is readable" "could not extract it"
elif printf '%s' "${block}" | grep -qE 'docker\.sock|/var/run/docker|containerd\.sock|DOCKER_HOST'; then
  bad "the backup service mounts no runtime socket" \
      "$(printf '%s' "${block}" | grep -nE 'docker\.sock|/var/run/docker|containerd\.sock|DOCKER_HOST' | head -1)"
else
  ok "the backup service mounts no runtime socket"
fi

# And the script it runs no longer reaches for one either.
if grep -nE '^[^#]*\bdocker (run|exec|cp|inspect)\b' "${ROOT}/scripts/backup-ledger.sh" >/dev/null 2>&1; then
  bad "the backup script makes no runtime calls" \
      "$(grep -nE '^[^#]*\bdocker (run|exec|cp|inspect)\b' "${ROOT}/scripts/backup-ledger.sh" | head -1)"
else
  ok "the backup script makes no runtime calls"
fi

echo "OPS-046 — readiness names a backup that has not run inside its window"

health() {
  INNSEGL_BACKUP_MARKER="${TMP}/marker" \
  INNSEGL_BACKUP_INTERVAL=60 \
  INNSEGL_BACKUP_WINDOW=120 \
    "${HEALTH}" 2>&1
}
mark() { printf '%s %s\n' "$1" "$2" >"${TMP}/marker"; }
now()  { date -u +%s; }

rm -f "${TMP}/marker"
out="$(health)"; rc=$?
if [ "${rc}" -ne 0 ] && printf '%s' "${out}" | grep -q "NO BACKUP HAS COMPLETED"; then
  ok "no backup at all is unhealthy, and says so"
else
  bad "no backup at all is unhealthy, and says so" "exit ${rc}: ${out}"
fi

mark "$(( $(now) - 5 ))" ok
out="$(health)"; rc=$?
if [ "${rc}" -eq 0 ]; then ok "a recent good backup is healthy"
else bad "a recent good backup is healthy" "exit ${rc}: ${out}"; fi

mark "$(( $(now) - 99999 ))" ok
out="$(health)"; rc=$?
if [ "${rc}" -ne 0 ] && printf '%s' "${out}" | grep -q "WINDOW HAS BEEN MISSED"; then
  ok "a backup outside its window is unhealthy, and says so"
else
  bad "a backup outside its window is unhealthy, and says so" "exit ${rc}: ${out}"
fi

mark "$(now)" mismatch
out="$(health)"; rc=$?
if [ "${rc}" -ne 0 ] && printf '%s' "${out}" | grep -q "integrity incident"; then
  ok "a mismatch is unhealthy however recent it is"
else
  bad "a mismatch is unhealthy however recent it is" "exit ${rc}: ${out}"
fi

mark "$(now)" failed
out="$(health)"; rc=$?
if [ "${rc}" -ne 0 ]; then ok "a failed run is unhealthy"
else bad "a failed run is unhealthy" "exit ${rc}: ${out}"; fi

# THE CASE THAT KEEPS THE OTHERS HONEST.
mark "$(now)" unverified
out="$(health)"; rc=$?
if [ "${rc}" -eq 0 ]; then
  ok "an unverified but recent backup is HEALTHY"
else
  bad "an unverified but recent backup is HEALTHY" \
      "exit ${rc}: ${out} — this is the ordinary state of a ledger whose tail has not sealed"
fi

mark "not-a-number" ok
out="$(health)"; rc=$?
if [ "${rc}" -ne 0 ] && printf '%s' "${out}" | grep -q "unreadable"; then
  ok "an unreadable marker is unhealthy, and says so"
else
  bad "an unreadable marker is unhealthy, and says so" "exit ${rc}: ${out}"
fi

# The loop refuses a schedule it cannot keep, rather than spinning.
out="$(INNSEGL_BACKUP_INTERVAL=5 "${LOOP}" 2>&1)"; rc=$?
if [ "${rc}" -eq 2 ] && printf '%s' "${out}" | grep -q "floor is 60s"; then
  ok "the loop refuses an interval below its floor"
else
  bad "the loop refuses an interval below its floor" "exit ${rc}: ${out}"
fi

printf '\n%d passed, %d failed\n' "${pass}" "${fail}"
[ "${fail}" -eq 0 ]
