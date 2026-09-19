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
#   scripts/innsegl-start.sh             boot, wait, report
#   scripts/innsegl-start.sh --status    report only, change nothing
#   scripts/innsegl-start.sh --services  print the reported list, need no Docker
#   scripts/innsegl-start.sh --rebuild   rebuild images first (after a UI change)
#
# EXIT
#   0  every service healthy
#   1  something did not come up; the service and its state are named — or the
#      service list could not be read from the compose files at all
#   4  Docker could not be started

set -uo pipefail
cd "$(cd "$(dirname "$0")/.." && pwd)"

PORT="${INNSEGL_DASHBOARD_PORT:-8082}"
MODE="${1:-boot}"

say()  { printf '  %s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }

# --- the services that must be healthy, and what each one is for -------------
#
# THE LIST IS DERIVED FROM THE COMPOSE FILES AND IS NOT TYPED HERE, and that is
# the whole of RM-168 (#272). It used to be seven names in a heredoc.
# `innsegl-backup` was not one of them, so when the backup sat `unhealthy` for
# eighteen hours with a day of ledger standing above the last usable dump, the
# one command an operator runs to ask "is this deployment all right" answered
# yes, twice a day, in green. Eleven other services were unreported for exactly
# the same reason and nobody had noticed either: the sealer, the reconciler,
# the three that hold sealed segments, the four behind the transparency log,
# and the SPIRE agent and OIDC provider.
#
# A hand-maintained list that drifted once drifts again, so nothing is
# maintained by hand any more. A service added to compose tomorrow appears in
# this report without anyone remembering to add it, and the row appears whether
# or not somebody also writes it a description.
#
# WHICH SERVICES. Everything the stack starts and then keeps running:
#
#   * it declares a `container_name:` — so there is a name to inspect;
#   * it sits behind no `profiles:`   — `init`, `demo`, `canary`, `verify` and
#                                       `adminrelay` are opt-in and are not
#                                       part of a boot;
#   * its `restart:` is not `"no"`    — the one-shots (the database, object and
#                                       identity initialisers, the credential
#                                       mint, the two bootstraps) exit 0 by
#                                       design, and reporting a completed
#                                       one-shot as not running would teach an
#                                       operator to ignore this report.
#
# WHICH FILES, and in which order: the three that `make innsegl-up-here`
# composes, in the order it brings them up. `innsegl.workrepo.yml` is left out
# deliberately — it overrides three services and declares no container of its
# own, so it can add no row.
#
# ONEPROCESS=1 IS NOT THIS PATH. That overlay scales the sealer and the
# reconciler to zero replicas; this script never passes it, and a deployment
# that does should expect those two rows to read ABSENT.
COMPOSE_FILES='deploy/compose/spire.yml
deploy/compose/sigstore.yml
deploy/compose/innsegl.yml'

# The parse is deliberately narrow: two-space service keys inside the top-level
# `services:` block, and the three four-space keys that decide the question.
# `FNR == 1` ends the previous file's last block, since nothing else does.
declared_services() {
  # shellcheck disable=SC2086
  awk '
    function flush() {
      if (name != "" && cname != "" && gated == 0 && restart != "no") print cname
      name = ""; cname = ""; gated = 0; restart = ""
    }
    FNR == 1 { flush(); insvc = 0 }
    /^[^[:space:]#]/ { flush(); insvc = ($0 ~ /^services:[[:space:]]*$/) ? 1 : 0; next }
    insvc && /^  [A-Za-z0-9_.-]+:[[:space:]]*(&[A-Za-z0-9_.-]+)?[[:space:]]*(#.*)?$/ {
      flush(); sub(":.*", "", $1); name = $1; next
    }
    insvc && name != "" && /^    container_name:/ { cname = $2; next }
    insvc && name != "" && /^    profiles:/       { gated = 1; next }
    insvc && name != "" && /^    restart:/        { r = $2; gsub(/"/, "", r); restart = r; next }
    END { flush() }
  ' $COMPOSE_FILES 2>/dev/null
}

# What each one is for. A name with no entry here still gets a row: undescribed
# is a prompt to describe it, and silence is the defect this file exists to end.
purpose() {
  case "$1" in
    innsegl-postgres)                      echo "the ledger" ;;
    innsegl-spire-server)                  echo "identity" ;;
    innsegl-spire-agent)                   echo "workload attestation" ;;
    innsegl-spire-oidc)                    echo "the JWKS the CA trusts" ;;
    innsegl-mcp)                           echo "the tool surface" ;;
    innsegl-api)                           echo "the dashboard's read side" ;;
    innsegl-dashboard)                     echo "the UI" ;;
    innsegl-sealer)                        echo "segment sealing" ;;
    innsegl-reconciler)                    echo "the reconcile pass" ;;
    innsegl-backup)                        echo "the ledger's backup" ;;
    innsegl-object-store)                  echo "the segment bytes" ;;
    innsegl-object-filer)                  echo "the segment metadata" ;;
    innsegl-s3)                            echo "object lock" ;;
    innsegl-sigstore-fulcio)               echo "certificates" ;;
    innsegl-sigstore-rekor)                echo "the transparency log" ;;
    innsegl-sigstore-trillian-log-server)  echo "the log's storage" ;;
    innsegl-sigstore-trillian-log-signer)  echo "the log's sequencer" ;;
    innsegl-sigstore-trillian-db)          echo "the log's database" ;;
    innsegl-sigstore-rekor-redis)          echo "the log's search index" ;;
    *)                                     echo "(undescribed)" ;;
  esac
}

services() {
  declared_services | while read -r name; do
    [ -n "$name" ] || continue
    printf '%s|%s\n' "$name" "$(purpose "$name")"
  done
}

# AN EMPTY LIST IS A FAULT, NOT AN EMPTY REPORT. A report of no services is
# indistinguishable from a healthy one at a glance, which is the failure this
# whole change is about — so it is said out loud and the script stops.
if [ -z "$(services)" ]; then
  {
    echo "innsegl-start: no services could be read from the compose files"
    echo "               looked for, beneath $(pwd):"
    printf '%s\n' "$COMPOSE_FILES" | sed 's/^/                 /'
  } >&2
  exit 1
fi

report() {
  local bad=0
  step "services"
  while IFS='|' read -r name what; do
    [ -n "$name" ] || continue
    state=$(docker inspect "$name" --format '{{.State.Status}}{{if .State.Health}} ({{.State.Health.Status}}){{end}}' 2>/dev/null)
    if [ -z "$state" ]; then
      printf '  %-36s %-26s %s\n' "$name" "$what" "ABSENT"; bad=1
    elif [[ "$state" == running* && "$state" != *unhealthy* && "$state" != *starting* ]]; then
      printf '  %-36s %-26s %s\n' "$name" "$what" "ok"
    else
      printf '  %-36s %-26s %s\n' "$name" "$what" "$state"; bad=1
    fi
  done < <(services)

  step "reachable"
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$PORT/" 2>/dev/null)
  if [ "$code" = "200" ]; then
    say "dashboard    http://127.0.0.1:$PORT"
  else
    say "dashboard    NOT answering on $PORT (http $code)"; bad=1
  fi

  # THE TREE THIS DEPLOYMENT PINNED, and whether it is still there.
  #
  # Reporting the size of whatever tree Rekor happens to be serving is what
  # this used to do, and it is the question that hid the fault on 2026-09-16:
  # a recreated Trillian database left the pin naming a tree that no longer
  # existed, Rekor answered HTTP 500 to every request, and nothing said why.
  # scripts/rekor-tlog-health.sh asks for the PINNED tree by id and reports
  # its absence in those words (#176, #219, OPS-034).
  #
  # An absent tree is a fault in the readiness report, not a warning beside a
  # green line: nothing signed after it can be anchored where anything else
  # is looking.
  INNSEGL_REKOR_PORT="${INNSEGL_REKOR_PORT:-23000}" \
    "$(dirname "$0")/rekor-tlog-health.sh" || bad=1
  return $bad
}

# --- --services reads the compose files and nothing else ---------------------
# Needs no Docker and touches no deployment. It exists so the list this report
# is built from can be read on its own, and so the self-test can assert it
# against the compose files rather than against a copy of itself.
if [ "$MODE" = "--services" ]; then
  services; exit 0
fi

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
  # -p, because since #280 a commit names the paths it is of: the index belongs
  # to the working tree rather than to the caller, and a hint that omitted it
  # would be an instruction to reproduce the defect.
  say "sign  scripts/innsegl-commit.sh -p <path> -m 'your message'"
fi
exit $rc
