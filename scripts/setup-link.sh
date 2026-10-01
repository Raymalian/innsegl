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
# onto a database that already has an account must print nothing, and the
# API is the one thing that actually knows (AuthStore.EnrolmentOpen).
#
# USAGE
#   scripts/setup-link.sh [--url BASE_URL] [--container NAME]
#
#   --url        the dashboard's own origin. Default
#                $INNSEGL_SETUP_LINK_URL, else http://localhost:8082 --
#                doc 05's reference deployment (a passkey's RP ID must be a
#                domain, never an IP literal, so this is never 127.0.0.1).
#   --container  the API container `docker exec` reaches to mint the code.
#                Default $INNSEGL_SETUP_LINK_CONTAINER, else innsegl-api.
#
# Overridable for the self-test, never for ordinary use:
#   $INNSEGL_SETUP_LINK_CURL    the curl command to run (default: curl)
#   $INNSEGL_SETUP_LINK_DOCKER  the docker command to run (default: docker)
#
# EXIT
#   0  nothing to do (an account already exists), or the link was printed
#   2  the command line was not understood
#   4  the API could not be asked at all -- inconclusive, not a refusal
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
URL="${INNSEGL_SETUP_LINK_URL:-http://localhost:8082}"
CONTAINER="${INNSEGL_SETUP_LINK_CONTAINER:-innsegl-api}"

usage() { sed -n '/^# USAGE/,/^# EXIT/p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --url) URL="${2-}"; shift 2 ;;
    --container) CONTAINER="${2-}"; shift 2 ;;
    -h|--help) usage; exit "$EXIT_OK" ;;
    *) echo "setup-link: unknown option: $1" >&2; usage >&2; exit "$EXIT_USAGE" ;;
  esac
done

# Strip a trailing slash so "${URL}/api/..." never doubles one up.
URL="${URL%/}"

body="$($CURL -fsS --max-time 10 "${URL}/api/v1/auth/setup" 2>/dev/null)"
if [ -z "${body}" ]; then
  echo "setup-link: could not reach ${URL}/api/v1/auth/setup" >&2
  exit "$EXIT_UNREACHABLE"
fi

# SetupStatus{needed:bool} (internal/api/account.go), written by
# encoding/json's own compact encoder -- no pretty-printing to account for.
needed="$(printf '%s' "${body}" | sed -n 's/.*"needed":\([a-z]*\).*/\1/p')"
if [ "${needed}" != "true" ]; then
  # An account already exists -- the ordinary case on every boot after the
  # first. Nothing to print, nothing to do.
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
