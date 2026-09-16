#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Put the ledger backup on a timer — OPS-035.
#
# WHY THIS EXISTS. scripts/backup-ledger.sh is written, tested, has a self-test
# of its own (scripts/backup-ledger-selftest.sh, BAK-001..004) and has never run
# on a timer. A backup that only happens when someone remembers is a backup
# that has not happened since the last time someone remembered.
#
# doc 05 §2 wants the dump off the box in production. Locally, the same script
# writing to a directory OUTSIDE the checkout is most of that value for none of
# the work: the copy no longer shares the fate of the working tree, and a
# `git clean`, a re-clone or a deleted directory does not take it. Moving the
# result somewhere else afterwards is one command regardless.
#
# THIS SCRIPT SCHEDULES; IT DOES NOT BACK ANYTHING UP. A second implementation
# of "dump the ledger and check it against the sealed segments" is a second
# thing that can disagree with the first (doc 04 §5.4), and the first one
# already refuses to call a dump good until runbooks/verify-rebuilt-index.sh
# has adjudicated it. So the schedule names that script and passes it flags.
#
# WHAT GETS INSTALLED. A launchd user agent on macOS, a systemd user timer on
# Linux. Both are per-user and need no privilege: this is a laptop's backup,
# not a fleet's.
#
# USAGE
#   scripts/backup-schedule.sh install [--no-load] [--every SECONDS]
#   scripts/backup-schedule.sh status
#   scripts/backup-schedule.sh uninstall
#
# ENVIRONMENT
#   INNSEGL_BACKUP_DIR    where the dumps go. MUST NOT be inside the checkout;
#                         defaults to a directory beside it. There is no
#                         default that names an operator path in this file —
#                         it is computed at install time from $HOME.
#   INNSEGL_SCHEDULE_DIR  where the agent/unit file is written. Defaults to the
#                         platform's user directory. A test points it at a
#                         temporary directory and passes --no-load.
#
# EXIT
#   0  done
#   1  status: nothing is scheduled
#   2  the command line was not understood
#   3  the platform has no scheduler this script knows how to use
#
# Portability: the bash 3.2 that ships with macOS.

set -uo pipefail

readonly EXIT_OK=0
readonly EXIT_NONE=1
readonly EXIT_USAGE=2
readonly EXIT_UNSUPPORTED=3

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly LABEL='dev.innsegl.backup-ledger'

# Daily. The ledger is append-only and a laptop is off for most of a day; an
# hourly dump of a chain that grew by nothing is a directory full of copies of
# one file.
EVERY="${INNSEGL_BACKUP_EVERY_SECONDS:-86400}"
LOAD=1

usage() { sed -n '/^# USAGE/,/^# EXIT/p' "$0" | sed 's/^# \{0,1\}//'; }

# --- where the dump goes -----------------------------------------------------
#
# Computed, never written down: CLAUDE.md forbids a shipped file naming a
# directory on the operator's machine, and scripts/no-operator-paths.sh is the
# gate that enforces it.
default_backup_dir() { printf '%s/.innsegl/backups' "${HOME}"; }
BACKUP_DIR="${INNSEGL_BACKUP_DIR:-$(default_backup_dir)}"

# THE PATH THE JOB RUNS WITH, and it is the whole difference between a
# schedule and a schedule that works.
#
# A launchd user agent inherits /usr/bin:/bin:/usr/sbin:/sbin and nothing else,
# and Docker Desktop is on none of them. MEASURED: the first install of this
# fired on demand and wrote one line to its log -- "backup-ledger: no container
# named innsegl-postgres -- is the stack up?" -- which is a backup that cannot
# run, arriving through the door meant to fix backups that never run.
#
# So the directories of `docker` and `git` are resolved at INSTALL time and
# written into the unit. Resolved and not hardcoded, because a shipped file may
# not name a directory on the operator's machine (CLAUDE.md,
# scripts/no-operator-paths.sh) and because Docker Desktop, Colima, Homebrew
# and a Linux package manager each put it somewhere different.
job_path() {
  p="/usr/bin:/bin:/usr/sbin:/sbin"
  for tool in docker git; do
    d="$(command -v "$tool" 2>/dev/null)" || continue
    [ -n "$d" ] || continue
    d="$(dirname "$d")"
    case ":$p:" in *":$d:"*) : ;; *) p="$d:$p" ;; esac
  done
  printf '%s' "$p"
}

platform() {
  case "$(uname -s)" in
    Darwin) printf 'launchd' ;;
    Linux)  command -v systemctl >/dev/null 2>&1 && printf 'systemd' || printf '' ;;
    *)      printf '' ;;
  esac
}

schedule_dir() {
  if [ -n "${INNSEGL_SCHEDULE_DIR:-}" ]; then printf '%s' "$INNSEGL_SCHEDULE_DIR"; return; fi
  case "$(platform)" in
    launchd) printf '%s/Library/LaunchAgents' "${HOME}" ;;
    systemd) printf '%s/.config/systemd/user' "${HOME}" ;;
  esac
}

unit_path() {
  case "$(platform)" in
    launchd) printf '%s/%s.plist' "$(schedule_dir)" "$LABEL" ;;
    systemd) printf '%s/%s.timer' "$(schedule_dir)" "$LABEL" ;;
  esac
}

service_path() { printf '%s/%s.service' "$(schedule_dir)" "$LABEL"; }

# ---------------------------------------------------------------------------

cmd_install() {
  p="$(platform)"
  if [ -z "$p" ]; then
    echo "backup-schedule: no user scheduler on this platform ($(uname -s))." >&2
    echo "  Run scripts/backup-ledger.sh --out <dir> from whatever timer you have." >&2
    return "$EXIT_UNSUPPORTED"
  fi

  case "$BACKUP_DIR" in
    "$REPO_ROOT"|"$REPO_ROOT"/*)
      {
        echo "backup-schedule: $BACKUP_DIR is inside the checkout."
        echo "  A copy in the working tree shares its fate. doc 05 §2 wants the"
        echo "  dump off the box; a second directory is the local version of that."
      } >&2
      return "$EXIT_USAGE" ;;
  esac

  mkdir -p "$(schedule_dir)" "$BACKUP_DIR" || return 1

  case "$p" in
    launchd) write_launchd ;;
    systemd) write_systemd ;;
  esac || return 1

  echo "backup-schedule: installed"
  echo "  runs   ${REPO_ROOT}/scripts/backup-ledger.sh --out ${BACKUP_DIR}"
  echo "  every  ${EVERY}s"
  echo "  unit   $(unit_path)"

  if [ -n "$LOAD" ]; then
    case "$p" in
      launchd)
        launchctl unload "$(unit_path)" >/dev/null 2>&1
        launchctl load "$(unit_path)" >/dev/null 2>&1 \
          && echo "  loaded into launchd" \
          || echo "  written, but launchctl would not load it; load it by hand" ;;
      systemd)
        systemctl --user daemon-reload >/dev/null 2>&1
        systemctl --user enable --now "${LABEL}.timer" >/dev/null 2>&1 \
          && echo "  enabled" \
          || echo "  written, but systemctl would not enable it; enable it by hand" ;;
    esac
  else
    echo "  not loaded (--no-load)"
  fi
  return "$EXIT_OK"
}

write_launchd() {
  cat > "$(unit_path)" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${REPO_ROOT}/scripts/backup-ledger.sh</string>
    <string>--out</string>
    <string>${BACKUP_DIR}</string>
    <string>--quiet</string>
  </array>
  <key>WorkingDirectory</key><string>${REPO_ROOT}</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key><string>$(job_path)</string>
  </dict>
  <key>StartInterval</key><integer>${EVERY}</integer>
  <key>RunAtLoad</key><false/>
  <key>StandardOutPath</key><string>${BACKUP_DIR}/schedule.log</string>
  <key>StandardErrorPath</key><string>${BACKUP_DIR}/schedule.log</string>
</dict>
</plist>
PLIST
}

write_systemd() {
  cat > "$(service_path)" <<UNIT
[Unit]
Description=Innsegl ledger backup, verified against the sealed segments

[Service]
Type=oneshot
Environment=PATH=$(job_path)
WorkingDirectory=${REPO_ROOT}
ExecStart=${REPO_ROOT}/scripts/backup-ledger.sh --out ${BACKUP_DIR} --quiet
UNIT
  cat > "$(unit_path)" <<UNIT
[Unit]
Description=Innsegl ledger backup on a timer

[Timer]
OnUnitActiveSec=${EVERY}
OnBootSec=600
Persistent=true

[Install]
WantedBy=timers.target
UNIT
}

cmd_status() {
  u="$(unit_path)"
  if [ -z "$u" ] || [ ! -f "$u" ]; then
    echo "backup-schedule: nothing is scheduled. The ledger is backed up only when"
    echo "  someone remembers, which is the state this exists to end."
    return "$EXIT_NONE"
  fi
  echo "backup-schedule: $u"
  # The command it will run, read back OUT OF THE INSTALLED UNIT rather than
  # recomputed. A status that printed what the script would have written says
  # nothing about what is actually on the timer.
  case "$(platform)" in
    launchd)
      sed -n '/<key>ProgramArguments<\/key>/,/<\/array>/p' "$u" \
        | sed -n 's/.*<string>\(.*\)<\/string>.*/\1/p' \
        | tr '\n' ' ' | sed 's/^/  runs  /;s/ $//'
      echo
      sed -n 's/.*<key>StartInterval<\/key><integer>\([0-9]*\)<\/integer>.*/  every \1s/p' "$u"
      sed -n '/<key>PATH<\/key>/s/.*<string>\(.*\)<\/string>.*/  path  \1/p' "$u" ;;
    systemd)
      sed -n 's/^ExecStart=/  runs  /p' "$(service_path)" 2>/dev/null
      sed -n 's/^OnUnitActiveSec=/  every /p' "$u"
      sed -n 's/^Environment=PATH=/  path  /p' "$(service_path)" 2>/dev/null ;;
  esac
  return "$EXIT_OK"
}

cmd_uninstall() {
  u="$(unit_path)"
  case "$(platform)" in
    launchd) launchctl unload "$u" >/dev/null 2>&1 ;;
    systemd) systemctl --user disable --now "${LABEL}.timer" >/dev/null 2>&1 ;;
  esac
  rm -f "$u" "$(service_path)"
  echo "backup-schedule: removed. The dumps already taken are left where they are."
  return "$EXIT_OK"
}

# ---------------------------------------------------------------------------

CMD="${1:-}"
[ $# -gt 0 ] && shift
while [ $# -gt 0 ]; do
  case "$1" in
    --no-load) LOAD=""; shift ;;
    --every)   EVERY="${2-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "backup-schedule: unknown option: $1" >&2; exit "$EXIT_USAGE" ;;
  esac
done

case "$CMD" in
  install)   cmd_install;   exit $? ;;
  status)    cmd_status;    exit $? ;;
  uninstall) cmd_uninstall; exit $? ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit "$EXIT_USAGE" ;;
esac
