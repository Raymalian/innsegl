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


# ---------------------------------------------------------------------------
# BAK-009..013 — what the loop does after a run that did not produce a backup
# (RM-163, #267).
#
# THESE CARRY BAK IDS RATHER THAN OPS ONES because they are assertions about
# the BACKUP's behaviour, not about the deployment's shape: OPS-044 and OPS-047
# read the compose file, OPS-046 drives the healthcheck's verdicts, and these
# drive the loop's scheduling. They live in this file because the loop does.
#
# THE LEDGER IS NOT NEEDED AND MUST NOT BE USED. What is under test is the
# LOOP's decision — how long to wait, and whether to wait at all — which is a
# function of one number: the exit status of the script it ran. A stub that
# exits with that number drives every branch in seconds and touches no
# database, no object store and nothing that is running.
#
#   BAK-009  a run that could not reach the ledger retries on the short path
#   BAK-010  a run whose dump disagreed with a sealed segment does NOT: an
#            integrity signal is not a transient, and retrying over it quickly
#            would bury it under a new failure every few seconds
#   BAK-011  a run that produced a dump which will not restore does NOT either
#   BAK-012  a run is forceable with a signal, and the marker survives it --
#            the recovery this replaces was `rm /backups/.last-run`
#   BAK-013  the loop refuses a retry interval below its floor, as it already
#            refuses an interval below its own
# ---------------------------------------------------------------------------
echo "BAK-009..013 — a failed run retries on its class, and a run is forceable"

STUB="${TMP}/fake-backup.sh"
RUNS="${TMP}/runs"
LOOPLOG="${TMP}/loop.log"
mkdir -p "${TMP}/backups"

# A stub that records that it ran and exits with the status asked for. `--out`
# and the rest arrive as arguments and are ignored: the loop passes them
# through, and passing them through is the only thing being relied on here.
stub_exits() {
  : >"${RUNS}"
  {
    printf '#!/bin/sh\n'
    printf 'printf "run\\n" >>"%s"\n' "${RUNS}"
    printf 'exit %s\n' "$1"
  } >"${STUB}"
  chmod +x "${STUB}"
}

loop_pid=""
drive() {
  rm -f "${TMP}/marker"
  INNSEGL_BACKUP_MARKER="${TMP}/marker" \
  INNSEGL_BACKUP_SCRIPT="${STUB}" \
  INNSEGL_BACKUP_DIR="${TMP}/backups" \
  INNSEGL_BACKUP_INTERVAL=60 \
  INNSEGL_BACKUP_RETRY=5 \
  INNSEGL_BACKUP_RETRY_MAX=5 \
    "${LOOP}" >"${LOOPLOG}" 2>&1 &
  loop_pid=$!
  sleep "$1"
}
stop_loop() {
  [ -n "${loop_pid}" ] || return 0
  kill "${loop_pid}" 2>/dev/null || true
  wait "${loop_pid}" 2>/dev/null || true
  loop_pid=""
}
runs_seen() { grep -c . "${RUNS}" 2>/dev/null || printf '0'; }

# BAK-009 — unreachable ledger (exit 6). Thirteen seconds at a five-second
# retry is room for three attempts; two is enough to prove it is not waiting
# out the interval, and asserting the exact number would be asserting the
# machine's timing rather than the loop's decision.
stub_exits 6
drive 13
n="$(runs_seen)"
stop_loop
if [ "${n}" -ge 2 ]; then
  ok "BAK-009 an unreachable ledger retries within seconds (${n} attempts in 13s)"
else
  bad "BAK-009 an unreachable ledger retries within seconds" \
      "${n} attempt(s) in 13s at a 5s retry; log: $(tr '\n' '|' <"${LOOPLOG}")"
fi
if grep -q "could not reach the ledger" "${LOOPLOG}"; then
  ok "BAK-009 says the ledger was unreachable, not just that it failed"
else
  bad "BAK-009 says the ledger was unreachable, not just that it failed" \
      "$(tr '\n' '|' <"${LOOPLOG}")"
fi

# BAK-010 — a mismatch (exit 3). One attempt, and no second one, because the
# next attempt is a full interval away.
stub_exits 3
drive 13
n="$(runs_seen)"
stop_loop
if [ "${n}" -eq 1 ]; then
  ok "BAK-010 a mismatch is not retried on the short path (1 attempt in 13s)"
else
  bad "BAK-010 a mismatch is not retried on the short path" \
      "${n} attempts in 13s; log: $(tr '\n' '|' <"${LOOPLOG}")"
fi
if grep -q "integrity" "${LOOPLOG}" && grep -q "not a transient" "${LOOPLOG}"; then
  ok "BAK-010 says why it is not retrying over it"
else
  bad "BAK-010 says why it is not retrying over it" "$(tr '\n' '|' <"${LOOPLOG}")"
fi

# BAK-011 — a dump that will not restore (exit 5). Also not a transient: the
# ledger answered, and what came back does not restore.
stub_exits 5
drive 13
n="$(runs_seen)"
stop_loop
if [ "${n}" -eq 1 ]; then
  ok "BAK-011 an unusable dump is not retried on the short path (1 attempt in 13s)"
else
  bad "BAK-011 an unusable dump is not retried on the short path" \
      "${n} attempts in 13s; log: $(tr '\n' '|' <"${LOOPLOG}")"
fi

# BAK-012 — forced by signal, with the marker left where it is. The recovery
# this replaces was deleting that file by hand and restarting the container.
stub_exits 0
drive 3
before="$(runs_seen)"
kill -USR1 "${loop_pid}" 2>/dev/null || true
sleep 3
after="$(runs_seen)"
marker_survived=0
[ -f "${TMP}/marker" ] && marker_survived=1
stop_loop
if [ "${after}" -gt "${before}" ]; then
  ok "BAK-012 SIGUSR1 forces a run (${before} -> ${after})"
else
  bad "BAK-012 SIGUSR1 forces a run" \
      "${before} -> ${after} with a 60s interval; log: $(tr '\n' '|' <"${LOOPLOG}")"
fi
if [ "${marker_survived}" -eq 1 ]; then
  ok "BAK-012 the marker is still there — no file surgery was needed"
else
  bad "BAK-012 the marker is still there — no file surgery was needed" "it is gone"
fi

# BAK-013 — the retry has a floor, for the same reason the interval does.
#
# RUN IN THE BACKGROUND WITH A DEADLINE. A loop that does NOT refuse the value
# goes on to sleep its interval, and reading its output with $(...) would hang
# this self-test rather than fail it. Waiting for it, then killing it, turns
# "did not refuse" into a failing case instead of a hung one.
stub_exits 0
rm -f "${TMP}/retry-floor.log"
INNSEGL_BACKUP_RETRY=1 \
INNSEGL_BACKUP_SCRIPT="${STUB}" \
INNSEGL_BACKUP_MARKER="${TMP}/marker-floor" \
INNSEGL_BACKUP_DIR="${TMP}/backups" \
  "${LOOP}" >"${TMP}/retry-floor.log" 2>&1 &
floor_pid=$!
rc=""
i=0
while [ "${i}" -lt 8 ]; do
  if ! kill -0 "${floor_pid}" 2>/dev/null; then wait "${floor_pid}"; rc=$?; break; fi
  sleep 1
  i=$((i + 1))
done
if [ -z "${rc}" ]; then
  kill "${floor_pid}" 2>/dev/null || true
  wait "${floor_pid}" 2>/dev/null || true
  rc="still-running"
fi
out="$(cat "${TMP}/retry-floor.log" 2>/dev/null || true)"
if [ "${rc}" = "2" ] && printf '%s' "${out}" | grep -q "INNSEGL_BACKUP_RETRY"; then
  ok "BAK-013 the loop refuses a retry below its floor"
else
  bad "BAK-013 the loop refuses a retry below its floor" "exit ${rc}: ${out}"
fi

printf '\n%d passed, %d failed\n' "${pass}" "${fail}"
[ "${fail}" -eq 0 ]
