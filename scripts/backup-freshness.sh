#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# How old is the last VERIFIED backup, and did its copy outside the container
# runtime land? (RM-190, #310). Run it on its own.
#
# WHY. The backup service's healthcheck reads a marker the loop refreshes on
# every run, including runs that verified nothing. A backup that stopped days
# ago looked like a working one from anywhere an operator actually looks, and
# the only copy lived in a container volume that a reset of the runtime
# removes along with every other volume.
#
# WHAT IT READS, all written by scripts/backup-ledger.sh:
#
#   <volume>/.last-verified   "<epoch> <dump>"  the newest dump that verified
#   <volume>/.host-copy       "<epoch> ok <dump>" | "<epoch> failed <why>" |
#                             "<epoch> off <why>"  what the copy did
#   <host>/.last-verified     "<epoch> <dump>"  the newest copy on the host
#
# The volume is read with `docker exec ... cat` -- a read, which changes
# nothing in the container. When it cannot be read (the stack is down), the
# age comes from the host folder instead: that is the point of having one.
#
# USAGE
#   scripts/backup-freshness.sh [--state-dir DIR] [--host-dir DIR]
#                               [--stale-after SECONDS] [--now EPOCH]
#
#   --state-dir    read the volume's markers from DIR instead of the container
#   --host-dir     the host folder (default $INNSEGL_BACKUP_HOST_DIR, or
#                  ~/innsegl-backups -- the same default the compose file mounts)
#   --stale-after  the bound past which a backup is STALE (default
#                  $INNSEGL_BACKUP_STALE_AFTER, else $INNSEGL_BACKUP_WINDOW,
#                  else 172800 -- the backup service's own window)
#   --now          the clock, for tests
#
# EXIT
#   0  a verified backup inside the bound, and a copy of it on the host
#   1  stale, missing, a failed or unconfigured copy, or a host folder that
#      does not hold the newest verified backup -- each named in the output
#   2  the command line was not understood
#
# Portability: bash 3.2, BSD and GNU date.

set -uo pipefail

state_dir=""
host_dir="${INNSEGL_BACKUP_HOST_DIR:-${HOME}/innsegl-backups}"
stale_after="${INNSEGL_BACKUP_STALE_AFTER:-${INNSEGL_BACKUP_WINDOW:-172800}}"
now=""
container="${INNSEGL_BACKUP_CONTAINER:-${INNSEGL_STACK_PREFIX:-innsegl}-backup}"

usage() { sed -n '/^# USAGE/,/^# Portability/p' "$0" | sed 's/^# \{0,1\}//' >&2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --state-dir)   state_dir="${2-}"; shift 2 || true ;;
    --host-dir)    host_dir="${2-}"; shift 2 || true ;;
    --stale-after) stale_after="${2-}"; shift 2 || true ;;
    --now)         now="${2-}"; shift 2 || true ;;
    -h|--help)     usage; exit 0 ;;
    *) printf 'backup-freshness: unknown argument %s\n' "$1" >&2; usage; exit 2 ;;
  esac
done
[ -n "${now}" ] || now="$(date -u +%s)"
for pair in "stale-after:${stale_after}" "now:${now}"; do
  case "${pair#*:}" in
    ''|*[!0-9]*) printf 'backup-freshness: --%s is %s, not a number of seconds\n' \
                   "${pair%%:*}" "${pair#*:}" >&2; exit 2 ;;
  esac
done

line() { printf '  %-12s %s\n' "$1" "$2"; }

human_age() {
  secs="$1"
  d=$((secs / 86400)); h=$(((secs % 86400) / 3600)); m=$(((secs % 3600) / 60))
  if   [ "${d}" -gt 0 ]; then printf '%dd %dh' "${d}" "${h}"
  elif [ "${h}" -gt 0 ]; then printf '%dh %dm' "${h}" "${m}"
  elif [ "${m}" -gt 0 ]; then printf '%dm' "${m}"
  else printf '%ds' "${secs}"; fi
}

iso() {
  date -u -r "$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
    || date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
    || printf '%s' "$1"
}

# --- the volume's markers -----------------------------------------------------
tmp=""
cleanup() { [ -z "${tmp}" ] || rm -rf "${tmp}"; }
trap cleanup EXIT

vol_readable=0
if [ -n "${state_dir}" ]; then
  [ -d "${state_dir}" ] && vol_readable=1
else
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/innsegl-freshness.XXXXXX")"
  state_dir="${tmp}"
  if docker exec "${container}" true >/dev/null 2>&1; then
    vol_readable=1
    for f in .last-verified .host-copy; do
      docker exec "${container}" cat "/backups/${f}" >"${tmp}/${f}" 2>/dev/null \
        || rm -f "${tmp}/${f}"
    done
  fi
fi

# read_marker FILE -> sets m_when, m_rest; returns 1 when absent or unreadable
read_marker() {
  m_when=""; m_rest=""
  [ -f "$1" ] || return 1
  read -r m_when m_rest <"$1" || true
  case "${m_when}" in ''|*[!0-9]*) return 1 ;; esac
  return 0
}

bad=0
vol_name=""
host_name=""
host_when=""
if read_marker "${host_dir}/.last-verified"; then
  host_when="${m_when}"; host_name="${m_rest}"
fi

# --- 1. the age of the last verified backup -----------------------------------
when=""; source_note=""
if [ "${vol_readable}" -eq 1 ] && read_marker "${state_dir}/.last-verified"; then
  when="${m_when}"; vol_name="${m_rest}"
elif [ -n "${host_when}" ]; then
  when="${host_when}"
  if [ "${vol_readable}" -eq 1 ]; then
    source_note=" (read from the host folder: the volume records none)"
  else
    source_note=" (read from the host folder: the volume could not be read)"
  fi
fi

if [ -z "${when}" ]; then
  line backup "NO VERIFIED BACKUP -- none is recorded in the volume or in ${host_dir}"
  bad=1
else
  age=$((now - when)); [ "${age}" -ge 0 ] || age=0
  desc="last verified $(iso "${when}"), $(human_age "${age}") ago${source_note}"
  if [ "${age}" -gt "${stale_after}" ]; then
    line backup "STALE -- ${desc}; the bound is $(human_age "${stale_after}")"
    bad=1
  else
    line backup "${desc}   ok"
  fi
fi

# --- 2. the copy outside the container runtime --------------------------------
copy_verdict=""
if [ "${vol_readable}" -eq 1 ] && read_marker "${state_dir}/.host-copy"; then
  copy_verdict="${m_rest%% *}"
  copy_why="${m_rest#* }"; [ "${copy_why}" != "${m_rest}" ] || copy_why=""
  copy_when="${m_when}"
fi

case "${copy_verdict}" in
  failed)
    line "host copy" "COPY FAILED at $(iso "${copy_when}") -- ${copy_why}"
    bad=1 ;;
  off)
    line "host copy" "NOT CONFIGURED -- ${copy_why}; the backup exists only inside the container runtime"
    bad=1 ;;
  *)
    if [ -z "${host_name}" ] || [ ! -f "${host_dir}/${host_name}" ]; then
      line "host copy" "NO COPY ON THE HOST -- ${host_dir} holds no verified backup"
      bad=1
    elif [ -n "${vol_name}" ] && [ "${vol_name}" != "${host_name}" ]; then
      line "host copy" "BEHIND -- ${host_dir} holds ${host_name}, the newest verified is ${vol_name}"
      bad=1
    else
      line "host copy" "${host_dir} holds ${host_name}   ok"
    fi ;;
esac

exit "${bad}"
