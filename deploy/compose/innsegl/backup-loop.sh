#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Run the ledger backup on an interval, inside the deployment (RM-146, #237).
# What a failed run costs, and how soon it is tried again: RM-163, #267.
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
#
# THE SLEEP USED TO BE THE SAME FOR SUCCESS AND FOR FAILURE, and that is what
# #267 is about. A run failed because the ledger was unreachable for about two
# minutes — a database restart — and the next attempt was a full day later. The
# container sat unhealthy for eighteen hours with a day's work unprotected, and
# the recovery was deleting the marker by hand and restarting the container.
#
# SO A FAILED RUN IS CLASSIFIED BEFORE IT IS RESCHEDULED, because the two ways
# a backup fails mean opposite things:
#
#   the ledger could not be reached   Nothing was dumped, and nothing has been
#   (exit 6)                          learned about the ledger. A database that
#                                     was down for two minutes is the ordinary
#                                     case. Retry in seconds, backing off, and
#                                     stop backing off once it answers.
#
#   a dump was produced and does      The ledger answered. What came back does
#   not verify (exit 3, exit 5)       not restore, or restores and disagrees
#                                     with a sealed segment. Retrying in
#                                     seconds produces a second bad dump and
#                                     buries the first under it. This waits the
#                                     full interval and says what it means; a
#                                     mismatch in particular is an integrity
#                                     incident (I4) and wants a person, not a
#                                     shorter timer.
#
# A RUN IS FORCEABLE WITH A SIGNAL, which is the other half of #267: recovering
# from the incident meant `rm /backups/.last-run` and a container restart, which
# is file surgery on the one file the healthcheck trusts.
#
#   docker kill -s USR1 innsegl-backup
#
# wakes the sleep and runs immediately. It changes no file, it keeps the loop's
# own record of what happened, and — unlike `make innsegl-backup`, which runs a
# separate one-off container — the verdict it produces is the verdict the
# healthcheck goes on to read.
#
# WHAT THE FAILURE SAYS. "FAILED" does not say what is at risk. Every failing
# run of backup-ledger.sh measures the exposure — how long since the last dump
# that actually verified, and how many events have been appended above it — and
# leaves it in $INNSEGL_BACKUP_DIR/.exposure. This loop repeats that line beside
# its own verdict, so the container log carries the number rather than requiring
# it to be worked out afterwards by hand, which is how #267's was found.

set -uo pipefail

INTERVAL="${INNSEGL_BACKUP_INTERVAL:-86400}"
# The first wait after a transient failure, and the ceiling it doubles towards.
# Sixty seconds is longer than a database restart and shorter than anything a
# person would call an outage; fifteen minutes is the point at which a fault
# has stopped looking transient and waiting longer costs nothing.
RETRY="${INNSEGL_BACKUP_RETRY:-60}"
RETRY_MAX="${INNSEGL_BACKUP_RETRY_MAX:-900}"
MARKER="${INNSEGL_BACKUP_MARKER:-/backups/.last-run}"
BACKUP_DIR="${INNSEGL_BACKUP_DIR:-/backups}"
BACKUP_SH="${INNSEGL_BACKUP_SCRIPT:-/innsegl/scripts/backup-ledger.sh}"
EXPOSURE="${BACKUP_DIR}/.exposure"

log() { printf 'backup-loop: %s\n' "$*"; }

seconds_or_refuse() {
  case "$2" in
    ''|*[!0-9]*) log "FAIL: $1 is $2, which is not a number of seconds"; exit 2 ;;
  esac
}
seconds_or_refuse INNSEGL_BACKUP_INTERVAL "${INTERVAL}"
seconds_or_refuse INNSEGL_BACKUP_RETRY "${RETRY}"
seconds_or_refuse INNSEGL_BACKUP_RETRY_MAX "${RETRY_MAX}"

[ "${INTERVAL}" -ge 60 ] || { log "FAIL: INNSEGL_BACKUP_INTERVAL is ${INTERVAL}s; the floor is 60s"; exit 2; }
# THE RETRY HAS A FLOOR FOR THE SAME REASON THE INTERVAL DOES. Each attempt
# opens a connection and, when the ledger answers, dumps and restores a whole
# database. A retry measured in single seconds is a load generator pointed at
# the thing it is trying to protect.
[ "${RETRY}" -ge 5 ] || { log "FAIL: INNSEGL_BACKUP_RETRY is ${RETRY}s; the floor is 5s"; exit 2; }
[ "${RETRY_MAX}" -ge "${RETRY}" ] || {
  log "FAIL: INNSEGL_BACKUP_RETRY_MAX is ${RETRY_MAX}s, below INNSEGL_BACKUP_RETRY at ${RETRY}s"; exit 2; }
# Backing off past the interval would make a transient failure cost MORE than
# an ordinary wait, which is the behaviour this loop exists to remove.
[ "${RETRY_MAX}" -le "${INTERVAL}" ] || RETRY_MAX="${INTERVAL}"
[ -x "${BACKUP_SH}" ] || { log "FAIL: ${BACKUP_SH} is missing or not executable"; exit 2; }

# record VERDICT — one line, written whole. The healthcheck may read it at any
# moment, so it is written to a temporary file and moved into place rather than
# truncated and rewritten, which has a window in which it is empty.
#
# THE VERDICT VOCABULARY IS backup-health.sh's, and it is not extended here. A
# transient failure records `failed`, the same word an unusable dump records,
# because it is the same fact about the backup: the last run produced no usable
# dump. What differs is what this loop does next, and that is this loop's
# business. A verdict the healthcheck has never heard of would fall past its
# `case` and be reported HEALTHY — a fault that reads as a green light.
record() {
  tmp="${MARKER}.$$"
  printf '%s %s\n' "$(date -u +%s)" "$1" >"${tmp}" && mv -- "${tmp}" "${MARKER}"
}

# What the last failing run measured is at risk. Absent means the run did not
# get far enough to measure it; backup-ledger.sh clears the file at the start of
# every run so a stale number is never reported as a current one.
say_exposure() {
  if [ -f "${EXPOSURE}" ]; then
    while IFS= read -r line; do
      [ -n "${line}" ] && log "AT RISK — ${line}"
    done <"${EXPOSURE}"
  else
    log "AT RISK — not measured: the run did not reach the point where it could count"
  fi
}

# A FORCED RUN, without touching a file the healthcheck reads.
forced=0
trap 'forced=1' USR1

# The sleep has to be interruptible, which a foreground `sleep` is not: a signal
# arriving during one is handled after it finishes, which for this schedule is
# up to a day later. Backgrounding it and waiting makes the wait the thing the
# signal interrupts.
nap() {
  sleep "$1" &
  sleeper=$!
  wait "${sleeper}" >/dev/null 2>&1 || true
  kill "${sleeper}" 2>/dev/null || true
  wait "${sleeper}" >/dev/null 2>&1 || true
}

log "every ${INTERVAL}s, marker ${MARKER}"
log "a failed run retries in ${RETRY}s, backing off to at most ${RETRY_MAX}s"
log "force a run at any time with: docker kill -s USR1 innsegl-backup"

backoff="${RETRY}"

while :; do
  if [ "${forced}" -eq 1 ]; then
    forced=0
    log "a run was asked for by signal — starting now rather than waiting"
  fi
  started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  log "starting a backup at ${started}"
  status=0
  "${BACKUP_SH}" --out "${BACKUP_DIR}" || status=$?

  case "${status}" in
    0) log "OK — the dump restores and matches every sealed segment it covers"
       record ok
       wait_for="${INTERVAL}"
       backoff="${RETRY}" ;;
    4) # Kept, and not called good. The dump is real and restores; nothing was
       # available to adjudicate it against. Recording it as `unverified` rather
       # than as a failure is the same argument backup-ledger.sh makes for
       # keeping the file: loud and unverified beats quiet and unverified.
       log "UNVERIFIED — the dump was taken and kept, but no sealed segments were available"
       record unverified
       wait_for="${INTERVAL}"
       backoff="${RETRY}" ;;
    6) # THE TRANSIENT ONE, and the only one that gets the short path. Nothing
       # was dumped because nothing answered, so nothing has been learned about
       # the ledger or about the dump — including anything that would justify
       # waiting a day before asking again.
       log "TRANSIENT — could not reach the ledger, so no dump was attempted"
       say_exposure
       record failed
       wait_for="${backoff}"
       backoff=$((backoff * 2))
       [ "${backoff}" -le "${RETRY_MAX}" ] || backoff="${RETRY_MAX}" ;;
    3) # An integrity incident, and the one status that must NOT refresh the
       # window: a backup that disagrees with a sealed segment is not a backup,
       # and a healthcheck that went green on it would say the opposite.
       log "MISMATCH — the dump disagrees with a sealed segment. This is an integrity incident (I4)"
       log "this is not a transient and is not retried on the short path: a new dump every few"
       log "seconds would bury it. It needs a person — see runbooks/index-rebuild.md"
       say_exposure
       record mismatch
       wait_for="${INTERVAL}"
       backoff="${RETRY}" ;;
    5) log "FAILED — a dump was produced and is not usable (exit 5): empty, or it does not restore"
       log "the ledger answered, so this is not a transient and is not retried on the short path"
       say_exposure
       record failed
       wait_for="${INTERVAL}"
       backoff="${RETRY}" ;;
    2) log "REFUSED — backup-ledger.sh did not accept its configuration (exit 2)"
       log "nothing will change until the deployment does, so this is not a transient"
       say_exposure
       record failed
       wait_for="${INTERVAL}"
       backoff="${RETRY}" ;;
    *) log "FAILED — no usable dump was produced, and exit ${status} is a status this loop"
       log "does not recognise. Treated as not a transient, because an unknown fault is not"
       log "one anything here has grounds to call temporary"
       say_exposure
       record failed
       wait_for="${INTERVAL}"
       backoff="${RETRY}" ;;
  esac

  if [ "${status}" -eq 0 ] || [ "${status}" -eq 4 ]; then
    log "sleeping ${wait_for}s"
  else
    log "next attempt in ${wait_for}s — sooner with: docker kill -s USR1 innsegl-backup"
  fi
  nap "${wait_for}"
done
