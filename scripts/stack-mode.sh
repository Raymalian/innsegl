#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Is the stack this checkout brings up the live one, or a development one?
# RM-293 (#469), ADR-0072, OPS-129.
#
# A machine that develops innsegl runs a stack of its own, and it ran it under
# the live names: the same compose projects, containers and networks, and the
# same trust volumes, so its commits were signed by whatever CA key
# `innsegl-trust-fulcio-pki` held on that machine. Nothing marked it as dev,
# and an agent could start it by accident.
#
# THE SIGNAL IS AN EXPLICIT MARKER, and nothing else:
#   1. INNSEGL_STACK=dev|live in the environment, which wins;
#   2. otherwise .innsegl/stack-mode in this checkout, or in the repository's
#      main worktree (a linked worktree follows its repository, as the Rekor
#      pin does); `make dev-stack` writes it;
#   3. otherwise live — exactly what every host ran before this script.
#
# BEING AN ENROLLED CLIENT IS NOT THE SIGNAL. The core host connects to itself
# (install.sh --local-client), so ~/.innsegl/client/core.json is no evidence
# that this host is not the core. It earns one warning line and never a switch:
# a live core that flipped to dev on its next `make start` would boot an empty
# trust root beside its real one.
#
# WHAT DEV CHANGES (the Makefile reads `env`):
#   names         every compose project, container and network is
#                 innsegl-dev-* (deploy/compose/dev/*.yml overlays)
#   trust root    INNSEGL_TRUST_VOLUME_PREFIX=innsegl-dev-trust, which
#                 trust-volumes.sh creates fresh and never migrates into
#   host folders  $HOME/.innsegl/dev/{ca,log,backups}. $HOME/.innsegl/ca holds
#                 the gateway CA this machine's commit hook trusts for ITS core;
#                 a dev gateway writing there would re-point the client
#   bind          loopback only (`check`)
# The trust domain is unchanged (innsegl.dev); the names and the bring-up line
# are what say DEV.
#
# USAGE
#   scripts/stack-mode.sh mode        print dev or live
#   scripts/stack-mode.sh env         VAR=value lines for a dev stack; nothing for live
#   scripts/stack-mode.sh check       refuse what a dev stack must not run with
#   scripts/stack-mode.sh announce    check, then the one bring-up line
#   scripts/stack-mode.sh mark-dev    write the marker (`make dev-stack`)
#
# ENVIRONMENT
#   INNSEGL_STACK          dev or live; wins over the marker
#   INNSEGL_BIND           refused in dev unless loopback (also read from
#                          deploy/compose/.env, which compose reads too)
#   INNSEGL_STACK_DOCKER   the docker binary asked which containers run
#
# EXIT
#   0  answered
#   2  INNSEGL_STACK or the marker holds something other than dev or live
#   4  REFUSED: a dev stack with a non-loopback bind, or a legacy trust prefix
#   5  REFUSED: a live-named stack is running here
#
# Portability: the bash 3.2 that ships with macOS.

set -uo pipefail

readonly DEV_PREFIX='innsegl-dev'
readonly DEV_TRUST_PREFIX='innsegl-dev-trust'
readonly MARKER_REL='.innsegl/stack-mode'
# The containers whose presence means a live-named stack is up here.
readonly LIVE_NAMES='innsegl-spire-server innsegl-sigstore-rekor innsegl-mcp innsegl-api'

HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
ROOT="$(CDPATH= cd -- "${HERE}/.." && pwd -P)"
MAIN="$("${HERE}/repo-main-worktree.sh" "${ROOT}" 2>/dev/null)"
[ -n "${MAIN}" ] || MAIN="${ROOT}"
DOCKER="${INNSEGL_STACK_DOCKER:-docker}"
CORE_JSON="${HOME}/.innsegl/client/core.json"

usage() { sed -n '/^# USAGE/,/^# EXIT/p' "$0" | sed 's/^# \{0,1\}//'; }

# marker_file is the marker this checkout reads: its own, else its repository's.
marker_file() {
  if [ -f "${ROOT}/${MARKER_REL}" ]; then
    printf '%s' "${ROOT}/${MARKER_REL}"
  elif [ -f "${MAIN}/${MARKER_REL}" ]; then
    printf '%s' "${MAIN}/${MARKER_REL}"
  fi
}

# mode prints dev or live, and where that came from on fd 3 when asked.
mode() {
  case "${INNSEGL_STACK:-}" in
    dev|live) printf '%s' "${INNSEGL_STACK}"; return 0 ;;
    '') : ;;
    *)
      echo "stack-mode: INNSEGL_STACK is \"${INNSEGL_STACK}\"; it is dev or live" >&2
      return 2 ;;
  esac
  f="$(marker_file)"
  if [ -z "${f}" ]; then
    printf 'live'
    return 0
  fi
  m="$(tr -d '[:space:]' <"${f}")"
  case "${m}" in
    dev|live) printf '%s' "${m}" ;;
    *)
      echo "stack-mode: ${f} holds \"${m}\"; it holds dev or live" >&2
      return 2 ;;
  esac
}

# core_url is the enrolment's core, or nothing when this machine never
# connected. core.json is written by `innsegl connect` and is JSON; a sed is
# enough to read one string field from it, and no JSON tool is a prerequisite.
core_url() {
  [ -r "${CORE_JSON}" ] || return 0
  sed -n 's/.*"core_url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${CORE_JSON}" | head -n 1
}

# bind is INNSEGL_BIND as compose will see it: the environment, else the
# project's .env.
bind_value() {
  if [ -n "${INNSEGL_BIND+x}" ]; then
    printf '%s' "${INNSEGL_BIND}"
    return
  fi
  envf="${ROOT}/deploy/compose/.env"
  [ -r "${envf}" ] || return 0
  sed -n 's/^[[:space:]]*INNSEGL_BIND[[:space:]]*=[[:space:]]*//p' "${envf}" | tail -n 1 \
    | sed -e 's/[[:space:]]*$//' -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'\$/\1/"
}

is_loopback() {
  case "$1" in
    ''|localhost|::1|'[::1]'|127.*) return 0 ;;
    *) return 1 ;;
  esac
}

cmd_env() {
  m="$(mode)" || return $?
  [ "${m}" = dev ] || return 0
  case "${HOME}" in
    *[[:space:]]*)
      echo "stack-mode: HOME (${HOME}) has a space in it; the Makefile cannot carry a dev stack's folders" >&2
      return 4 ;;
  esac
  cat <<EOF
INNSEGL_STACK_MODE=dev
INNSEGL_STACK_PREFIX=${DEV_PREFIX}
INNSEGL_TRUST_VOLUME_PREFIX=${DEV_TRUST_PREFIX}
INNSEGL_GATEWAY_CA_HOST_DIR=${HOME}/.innsegl/dev/ca
INNSEGL_LOG_DIR=${HOME}/.innsegl/dev/log
INNSEGL_BACKUP_HOST_DIR=${HOME}/.innsegl/dev/backups
EOF
}

cmd_check() {
  m="$(mode)" || return $?
  [ "${m}" = dev ] || return 0
  b="$(bind_value)"
  if ! is_loopback "${b}"; then
    {
      echo "stack-mode: REFUSED. A DEV stack is loopback only, and INNSEGL_BIND is ${b}."
      echo "  A development stack published on another address is one other machines"
      echo "  can reach and mistake for a core. Unset INNSEGL_BIND (and remove it from"
      echo "  deploy/compose/.env), or run the live stack with INNSEGL_STACK=live."
    } >&2
    return 4
  fi
  if [ -n "${INNSEGL_TRUST_LEGACY_PREFIX:-}" ]; then
    {
      echo "stack-mode: REFUSED. INNSEGL_TRUST_LEGACY_PREFIX is set, which would copy"
      echo "  another trust root into the DEV stack's volumes. A dev stack mints its own."
    } >&2
    return 4
  fi
  return 0
}

cmd_announce() {
  m="$(mode)" || return $?
  url="$(core_url)"
  if [ "${m}" = live ]; then
    if [ -n "${url}" ]; then
      echo "innsegl: this machine is a client of ${url}; if this stack is for development, run \`make dev-stack\` once" >&2
    fi
    return 0
  fi
  cmd_check || return $?
  running="$("${DOCKER}" ps --format '{{.Names}}' 2>/dev/null)"
  found=""
  for n in ${LIVE_NAMES}; do
    if printf '%s\n' "${running}" | grep -qx "${n}"; then
      found="${found} ${n}"
    fi
  done
  if [ -n "${found}" ]; then
    {
      echo "stack-mode: REFUSED. A live-named innsegl stack is running here:${found}."
      echo "  A DEV stack beside it would collide with it on every published port."
      echo "  Stop it deliberately, or keep using it with INNSEGL_STACK=live."
    } >&2
    return 5
  fi
  what="names ${DEV_PREFIX}-*, trust volumes ${DEV_TRUST_PREFIX}-*, trust domain innsegl.dev, loopback only"
  if [ -n "${url}" ]; then
    echo "innsegl: this machine is a client of ${url}; starting a DEV stack (${what})"
  else
    echo "innsegl: starting a DEV stack (${what})"
  fi
}

cmd_mark_dev() {
  f="${MAIN}/${MARKER_REL}"
  mkdir -p "$(dirname "${f}")" || return 1
  printf 'dev\n' >"${f}" || return 1
  cat <<EOF
dev-stack: marked ${f}
  From now on \`make start\` in this repository brings up a DEVELOPMENT stack:
    names         ${DEV_PREFIX}-* (compose projects, containers, networks)
    trust root    ${DEV_TRUST_PREFIX}-* volumes, created empty: its own CA, log and ledger
    host folders  \$HOME/.innsegl/dev/{ca,log,backups}
    bind          loopback only
  It writes no harness settings and leaves this machine's client alone.
  Volumes and containers already here under live names are not touched.
  To undo: delete ${f}. INNSEGL_STACK=live|dev overrides it for one command.
EOF
}

case "${1:-}" in
  mode) m="$(mode)" || exit $?; printf '%s\n' "${m}" ;;
  env) cmd_env ;;
  check) cmd_check ;;
  announce) cmd_announce ;;
  mark-dev) cmd_mark_dev ;;
  -h|--help) usage ;;
  *) usage >&2; exit 2 ;;
esac
