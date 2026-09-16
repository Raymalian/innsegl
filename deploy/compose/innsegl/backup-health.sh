#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Is there a backup, and is it inside its window? (RM-146, #237). OPS-046.
#
# A SERVICE THAT ONLY RUNS WHILE THE STACK IS UP MAKES THE BACKUP'S LIVENESS
# THE STACK'S LIVENESS. That is the trade this design makes on purpose, and the
# whole of the cost is that a stack which was down for three days has a backup
# three days old while reporting nothing wrong. So it reports something wrong:
# this is the service's healthcheck, so `docker ps` says unhealthy and the
# operator-facing status line says it in words.
#
# WHAT IS UNHEALTHY
#   no marker at all          nothing has ever completed a run
#   older than the window     the schedule is not being kept
#   verdict `mismatch`        an integrity incident; a green light would lie
#   verdict `failed`          the last run produced no usable dump
#
# `unverified` is HEALTHY, and that is not a shrug: the dump exists and
# restores, and what was missing was the sealed segments to adjudicate it
# against — which is the normal state of a ledger whose tail has not sealed yet.
# backup-ledger.sh keeps such a dump for the same reason.
#
# THE WINDOW DEFAULTS TO TWICE THE INTERVAL, so a single slow or skipped run is
# not an alert and two in a row are. An alert that fires on ordinary jitter is
# one an operator learns to ignore.

set -uo pipefail

INTERVAL="${INNSEGL_BACKUP_INTERVAL:-86400}"
WINDOW="${INNSEGL_BACKUP_WINDOW:-$((INTERVAL * 2))}"
MARKER="${INNSEGL_BACKUP_MARKER:-/backups/.last-run}"

if [ ! -f "${MARKER}" ]; then
  printf 'backup: NO BACKUP HAS COMPLETED. Nothing has been written to %s.\n' "${MARKER}" >&2
  exit 1
fi

read -r when verdict <"${MARKER}" || true
case "${when}" in
  ''|*[!0-9]*) printf 'backup: the marker at %s is unreadable (%s)\n' "${MARKER}" "${when}" >&2; exit 1 ;;
esac

age=$(( $(date -u +%s) - when ))
human="$(date -u -d "@${when}" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
  || date -u -r "${when}" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || printf '%s' "${when}")"

case "${verdict}" in
  mismatch)
    printf 'backup: the last backup DISAGREED with a sealed segment (%s). This is an integrity incident, not a backup (I4).\n' "${human}" >&2
    exit 1 ;;
  failed)
    printf 'backup: the last run produced no usable dump (%s).\n' "${human}" >&2
    exit 1 ;;
esac

if [ "${age}" -gt "${WINDOW}" ]; then
  printf 'backup: THE WINDOW HAS BEEN MISSED. The last backup was %ss ago (%s), and the window is %ss.\n' \
    "${age}" "${human}" "${WINDOW}" >&2
  exit 1
fi

printf 'backup: %s, %ss ago, inside a %ss window\n' "${verdict}" "${age}" "${WINDOW}"
