#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Bring the whole stack up, from nothing, with no arguments.
#
# WHY THIS EXISTS. `make innsegl-up-here` already does the work correctly and
# this script does not repeat it — it calls it. What it adds is everything
# AROUND that call which otherwise has to be remembered:
#
#   * Docker Desktop may not be running. The make target fails with a daemon
#     error that says nothing about starting it.
#   * `up -d` returns as soon as the containers are created, not when they are
#     usable. Opening the dashboard a second later shows a load failure that
#     looks like a bug and is a race.
#   * Nothing prints where the dashboard is.
#
# NEVER CALL `docker compose -f deploy/compose/innsegl.yml` ALONE. The stack is
# two files: the second adds the /projects mount and the repository list, and a
# container recreated without it reports every repository as absent. Measured on
# 2026-09-13: recreating the dashboard with one -f also recreated innsegl-api,
# and "Verify a commit" answered 404 for every commit until it was brought back
# through the make target. That is why this script is the entry point.
#
# USAGE
#   scripts/innsegl-start.sh            boot, wait, report
#   scripts/innsegl-start.sh --status   report only, change nothing
#   scripts/innsegl-start.sh --rebuild  rebuild images first (after a UI change)
#
# EXIT
#   0  every service healthy
#   1  something did not come up; the service and its state are named
#   4  Docker could not be started

set -uo pipefail
cd "$(cd "$(dirname "$0")/.." && pwd)"

PORT="${INNSEGL_DASHBOARD_PORT:-8082}"
MODE="${1:-boot}"

say()  { printf '  %s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }

# --- the services that must be healthy, and what each one is for -------------
services() {
  cat <<'EOT'
innsegl-postgres|the ledger
innsegl-spire-server|identity
innsegl-mcp|the tool surface
innsegl-api|the dashboard's read side
innsegl-dashboard|the UI
innsegl-sigstore-fulcio|certificates
innsegl-sigstore-rekor|the transparency log
EOT
}

report() {
  local bad=0
  step "services"
  while IFS='|' read -r name what; do
    [ -n "$name" ] || continue
    state=$(docker inspect "$name" --format '{{.State.Status}}{{if .State.Health}} ({{.State.Health.Status}}){{end}}' 2>/dev/null)
    if [ -z "$state" ]; then
      printf '  %-26s %-28s %s\n' "$name" "$what" "ABSENT"; bad=1
    elif [[ "$state" == running* && "$state" != *unhealthy* && "$state" != *starting* ]]; then
      printf '  %-26s %-28s %s\n' "$name" "$what" "ok"
    else
      printf '  %-26s %-28s %s\n' "$name" "$what" "$state"; bad=1
    fi
  done < <(services)

  step "reachable"
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$PORT/" 2>/dev/null)
  if [ "$code" = "200" ]; then
    say "dashboard    http://127.0.0.1:$PORT"
  else
    say "dashboard    NOT answering on $PORT (http $code)"; bad=1
  fi

  # The tree the log is serving, and how many entries are in it. A restart that
  # lost the pin shows up here as a small number rather than as a silent
  # verification failure days later (#176, #219).
  log=$(curl -s --max-time 5 "http://127.0.0.1:${INNSEGL_REKOR_PORT:-23000}/api/v1/log" 2>/dev/null)
  if [ -n "$log" ]; then
    size=$(printf '%s' "$log" | sed -n 's/.*"treeSize":\([0-9]*\).*/\1/p')
    say "transparency log holds ${size:-?} entr$([ "${size:-0}" = 1 ] && echo y || echo ies)"
  fi
  return $bad
}

# --- --status changes nothing ------------------------------------------------
if [ "$MODE" = "--status" ]; then
  docker info >/dev/null 2>&1 || { echo "docker is not running" >&2; exit 4; }
  report; exit $?
fi

# --- 1. docker -------------------------------------------------------------
step "docker"
if docker info >/dev/null 2>&1; then
  say "already running"
else
  say "starting Docker Desktop…"
  open -a Docker 2>/dev/null || { echo "could not start Docker Desktop" >&2; exit 4; }
  for _ in $(seq 1 60); do docker info >/dev/null 2>&1 && break; sleep 5; done
  docker info >/dev/null 2>&1 || { echo "docker did not come up within 5 minutes" >&2; exit 4; }
  say "up"
fi

# --- 2. the stack ----------------------------------------------------------
# Both compose files, the SPIRE registration and the repository link, in the
# order the Makefile already establishes. Rebuild only when asked: an image
# build is the slow part and nothing about a restart requires one.
step "stack"
if [ "$MODE" = "--rebuild" ]; then
  say "rebuilding images first"
else
  say "using the images already built (pass --rebuild after a UI change)"
fi
if ! make innsegl-up-here 2>&1 | sed 's/^/  /'; then
  echo "innsegl-start: the stack did not come up" >&2
  exit 1
fi

# --- 3. wait for it to be usable -------------------------------------------
# `up -d` returns when the containers exist. Health is what decides whether the
# dashboard will answer, so that is what is waited on.
step "waiting"
for i in $(seq 1 60); do
  unhealthy=0
  while IFS='|' read -r name _; do
    [ -n "$name" ] || continue
    s=$(docker inspect "$name" --format '{{.State.Status}}{{if .State.Health}}/{{.State.Health.Status}}{{end}}' 2>/dev/null)
    case "$s" in running|running/healthy) ;; *) unhealthy=1 ;; esac
  done < <(services)
  [ "$unhealthy" = 0 ] && { say "healthy after ~$((i*3))s"; break; }
  sleep 3
done

report
rc=$?
if [ "$rc" = 0 ]; then
  step "ready"
  say "open  http://127.0.0.1:$PORT"
  say "sign  scripts/innsegl-commit.sh -m 'your message'"
fi
exit $rc
