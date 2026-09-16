#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Run the ledger backup on an interval, inside the deployment (RM-146, #237).
#
# WHY THE SCHEDULE LIVES HERE AND NOT ON THE HOST
# -----------------------------------------------
# It used to be a host scheduler: launchd on one platform, systemd on the
# other, two unit layouts, and a scheduler that has to exist at all. Three CI
# failures in one day came from that split, every one of them in the harness
# rather than in the thing being tested. A container runtime is already
# required by everything else here, so the schedule can live where the
# deployment lives.
#
# THE SLEEP IS THE WHOLE SCHEDULER, deliberately. There is no cron in this
# image and none is wanted: a loop that sleeps is a thing anyone can read, and
# the orchestrator that eventually owns this schedule — a CronJob, per the
# issue's note — replaces the loop and keeps the container unchanged.
#
# IT RUNS ONCE AT START-UP, BEFORE THE FIRST SLEEP. A fresh stack otherwise has
# no backup for a whole interval while reporting a healthy backup service, and
# the first thing an operator does after bringing a stack up is not wait a day.
#
# WHAT IT RECORDS, and why readiness needs it: a service that only runs while
# the stack is up makes the backup's liveness the STACK's liveness. That has to
# be visible rather than assumed, so every run writes its verdict and its time
# to a marker the healthcheck reads. See backup-health.sh.

set -uo pipefail

INTERVAL="${INNSEGL_BACKUP_INTERVAL:-86400}"
MARKER="${INNSEGL_BACKUP_MARKER:-/backups/.last-run}"
BACKUP_SH="${INNSEGL_BACKUP_SCRIPT:-/innsegl/scripts/backup-ledger.sh}"

log() { printf 'backup-loop: %s\n' "$*"; }

case "${INTERVAL}" in
  ''|*[!0-9]*) log "FAIL: INNSEGL_BACKUP_INTERVAL is ${INTERVAL}, which is not a number of seconds"; exit 2 ;;
esac
[ "${INTERVAL}" -ge 60 ] || { log "FAIL: INNSEGL_BACKUP_INTERVAL is ${INTERVAL}s; the floor is 60s"; exit 2; }
[ -x "${BACKUP_SH}" ] || { log "FAIL: ${BACKUP_SH} is missing or not executable"; exit 2; }

# record VERDICT — one line, written whole. The healthcheck may read it at any
# moment, so it is written to a temporary file and moved into place rather than
# truncated and rewritten, which has a window in which it is empty.
record() {
  tmp="${MARKER}.$$"
  printf '%s %s\n' "$(date -u +%s)" "$1" >"${tmp}" && mv -- "${tmp}" "${MARKER}"
}

log "every ${INTERVAL}s, marker ${MARKER}"

while :; do
  started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  log "starting a backup at ${started}"
  status=0
  "${BACKUP_SH}" --out "${INNSEGL_BACKUP_DIR:-/backups}" || status=$?

  case "${status}" in
    0) log "OK — the dump restores and matches every sealed segment it covers"
       record ok ;;
    4) # Kept, and not called good. The dump is real and restores; nothing was
       # available to adjudicate it against. Recording it as `unverified` rather
       # than as a failure is the same argument backup-ledger.sh makes for
       # keeping the file: loud and unverified beats quiet and unverified.
       log "UNVERIFIED — the dump was taken and kept, but no sealed segments were available"
       record unverified ;;
    3) # An integrity incident, and the one status that must NOT refresh the
       # window: a backup that disagrees with a sealed segment is not a backup,
       # and a healthcheck that went green on it would say the opposite.
       log "MISMATCH — the dump disagrees with a sealed segment. This is an integrity incident (I4)"
       record mismatch ;;
    *) log "FAILED — no usable dump was produced (exit ${status})"
       record failed ;;
  esac

  log "sleeping ${INTERVAL}s"
  sleep "${INTERVAL}"
done
