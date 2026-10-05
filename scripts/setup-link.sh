#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The setup link `make start` and install.sh print once, while no account
# exists yet (#445, ADR-0062's 2026-10-01 amendment: "accounts a person can
# manage").
#
# WHY THIS EXISTS. First-user enrolment already has a one-time code
# (`innsegl admin-credential enrol-code`, cmd/innsegl/adminenrolcode.go) and
# a page that redeems it (the dashboard's own /setup?code=... route). Before
# this, an operator had to run the mint command themselves and paste the
# code into a URL by hand. This script is that same two steps -- ask
# whether an account still needs creating, mint the code if it does -- run
# once at the end of bring-up, so what prints is a link ready to open
# rather than a command still to run.
#
# It ASKS the API (GET /api/v1/auth/setup) rather than assuming: a redeploy
# onto a database that already has an account must print no link, and the
# API is the one thing that actually knows (AuthStore.EnrolmentOpen).
#
# USAGE
#   scripts/setup-link.sh [--url BASE_URL] [--container NAME]
#
#   --url        the dashboard's own origin. Default
#                $INNSEGL_SETUP_LINK_URL, else built from where the dashboard
#                is published: http://<INNSEGL_BIND>:<INNSEGL_DASHBOARD_PORT>,
#                each taken from the environment, else from
#                deploy/compose/.env, else localhost and 8082 -- doc 05's
#                reference deployment (a passkey's RP ID must be a domain,
#                never an IP literal, so an unset bind is never 127.0.0.1).
#                A wildcard bind (0.0.0.0) is dialled as localhost.
#   --container  the API container `docker exec` reaches to mint the code.
#                Default $INNSEGL_SETUP_LINK_CONTAINER, else innsegl-api.
#
# It waits for the API to answer for at most $INNSEGL_SETUP_LINK_WAIT seconds
# (default 120) and then stops with ONE message naming the URL it tried. It
# never loops forever (RM-325). Run it again whenever the stack is up.
#
# Overridable for the self-test, never for ordinary use:
#   $INNSEGL_SETUP_LINK_CURL      the curl command to run (default: curl)
#   $INNSEGL_SETUP_LINK_DOCKER    the docker command to run (default: docker)
#   $INNSEGL_SETUP_LINK_ENV       the env file to read (default deploy/compose/.env)
#   $INNSEGL_SETUP_LINK_INTERVAL  seconds between attempts (default 2)
#
# EXIT
#   0  nothing to do (an account already exists), or the link was printed
#   2  the command line was not understood
#   4  the API could not be asked at all within the wait -- inconclusive, not a refusal
#   6  the API answered "an account is needed" but minting the code failed
#
# Portability: the bash 3.2 that ships with macOS; no BSD-only flags, since
# this also runs under Linux CI (scripts/selftests-wired.sh).

set -uo pipefail

readonly EXIT_OK=0
readonly EXIT_USAGE=2
readonly EXIT_UNREACHABLE=4
readonly EXIT_MINT_FAILED=6

CURL="${INNSEGL_SETUP_LINK_CURL:-curl}"
DOCKER="${INNSEGL_SETUP_LINK_DOCKER:-docker}"
URL="${INNSEGL_SETUP_LINK_URL:-}"
CONTAINER="${INNSEGL_SETUP_LINK_CONTAINER:-${INNSEGL_STACK_PREFIX:-innsegl}-api}"
ENV_FILE="${INNSEGL_SETUP_LINK_ENV:-$(cd -- "$(dirname -- "$0")/.." && pwd -P)/deploy/compose/.env}"
WAIT="${INNSEGL_SETUP_LINK_WAIT:-120}"
INTERVAL="${INNSEGL_SETUP_LINK_INTERVAL:-2}"

# envval NAME: the environment's value, else the last NAME=value line of the
# env file (quotes and surrounding blanks stripped), else empty.
envval() {
  eval "_v=\${$1:-}"
  if [ -z "${_v}" ] && [ -r "${ENV_FILE}" ]; then
    _v="$(sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "${ENV_FILE}" | tail -n 1 \
          | sed -e 's/[[:space:]]*$//' -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'\$/\1/")"
  fi
  printf '%s' "${_v}"
}

usage() { sed -n '/^# USAGE/,/^# EXIT/p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --url) URL="${2-}"; shift 2 ;;
    --container) CONTAINER="${2-}"; shift 2 ;;
    -h|--help) usage; exit "$EXIT_OK" ;;
    *) echo "setup-link: unknown option: $1" >&2; usage >&2; exit "$EXIT_USAGE" ;;
  esac
done

if [ -z "${URL}" ]; then
  # Where the stack publishes the dashboard (deploy/compose/innsegl.yml:
  # "${INNSEGL_BIND:-127.0.0.1}:${INNSEGL_DASHBOARD_PORT:-8082}:8080").
  bind="$(envval INNSEGL_BIND)"
  port="$(envval INNSEGL_DASHBOARD_PORT)"
  case "${bind}" in ''|0.0.0.0|'::'|'[::]') bind=localhost ;; esac
  URL="http://${bind}:${port:-8082}"
fi

# Strip a trailing slash so "${URL}/api/..." never doubles one up.
URL="${URL%/}"

# Ask until the API answers, for at most WAIT seconds. innsegl-api can still
# be finishing its own start-up the instant bring-up returns; a published
# address that is simply wrong would otherwise be retried for ever (RM-325).
case "${WAIT}" in ''|*[!0-9]*) WAIT=120 ;; esac
deadline=$(( $(date +%s) + WAIT ))
while :; do
  body="$($CURL -fsS --max-time 5 "${URL}/api/v1/auth/setup" 2>/dev/null)"
  [ -n "${body}" ] && break
  if [ "$(date +%s)" -ge "${deadline}" ]; then
    echo "setup-link: could not reach ${URL}/api/v1/auth/setup (waited ${WAIT}s). Once the stack is up, run scripts/setup-link.sh to get the link (--url BASE_URL if it is published elsewhere)." >&2
    exit "$EXIT_UNREACHABLE"
  fi
  sleep "${INTERVAL}"
done

# SetupStatus{needed:bool} (internal/api/account.go), written by
# encoding/json's own compact encoder -- no pretty-printing to account for.
needed="$(printf '%s' "${body}" | sed -n 's/.*"needed":\([a-z]*\).*/\1/p')"
if [ "${needed}" != "true" ]; then
  # An account already exists -- the ordinary case on every boot after the
  # first. One line, so a quiet start-up is not mistaken for a skipped step.
  echo "setup-link: an account already exists; no setup link needed"
  exit "$EXIT_OK"
fi

code="$($DOCKER exec "${CONTAINER}" sh -c 'innsegl admin-credential enrol-code -dsn "$INNSEGL_API_AUTH_DSN"' 2>/dev/null)"
code="$(printf '%s' "${code}" | tr -d '[:space:]')"
if [ -z "${code}" ]; then
  echo "setup-link: minting the one-time code failed (docker exec ${CONTAINER} innsegl admin-credential enrol-code)" >&2
  exit "$EXIT_MINT_FAILED"
fi

cat <<EOF

No account exists yet. Open this link once to create it:
  ${URL}/setup?code=${code}

EOF
exit "$EXIT_OK"
