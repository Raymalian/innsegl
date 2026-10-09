#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Restarts this machine's innsegl client service, but only when the service
# runs the binary named: `make client-restart` names the one `make build`
# just wrote, so a rebuild reaches the running service in one step. A service
# that runs another binary (an installed release, another checkout) is left
# alone and named. `make build` never restarts anything itself.
#
#   macOS: launchctl kickstart -k gui/<uid>/dev.innsegl.client
#   Linux: systemctl --user restart innsegl-client.service
#
# USAGE
#   scripts/client-restart.sh <binary>
#
# It returns once the restarted service answers on its loopback port (the
# --listen it was started with, else 127.0.0.1:28195), so a command run right
# after it (`innsegl status`) finds the service up. It waits at most
# $INNSEGL_CLIENT_RESTART_TIMEOUT seconds (default 30).
#
# EXIT STATUS
#   0  restarted, and the service answers
#   1  not restarted: no service, it runs another binary, or the restart
#      failed; or restarted and it did not answer in time
#   2  usage
set -uo pipefail

LABEL="dev.innsegl.client"
UNIT="innsegl-client.service"
DEFAULT_LISTEN="127.0.0.1:28195"
TIMEOUT="${INNSEGL_CLIENT_RESTART_TIMEOUT:-30}"

bin="${1:-}"
if [ -z "${bin}" ] || [ "$#" -ne 1 ]; then
  echo "usage: scripts/client-restart.sh <binary>" >&2
  exit 2
fi

# canon PATH — PATH with every directory symlink resolved.
canon() {
  local dir
  dir="$(cd -- "$(dirname -- "$1")" 2>/dev/null && pwd -P)" || { printf '%s\n' "$1"; return; }
  printf '%s/%s\n' "${dir}" "$(basename -- "$1")"
}

case "$(uname -s)" in
  Darwin)
    target="gui/$(id -u)/${LABEL}"
    if ! info="$(launchctl print "${target}" 2>/dev/null)"; then
      echo "client-restart: the client service (${target}) is not loaded; nothing restarted." \
        "\`innsegl connect\` installs it." >&2
      exit 1
    fi
    program="$(printf '%s\n' "${info}" | sed -nE 's/^[[:space:]]*program = (.*)$/\1/p' | head -n 1)"
    # The arguments block, one per line: --listen X, or --listen=X.
    listen="$(printf '%s\n' "${info}" | sed -E 's/^[[:space:]]+//' |
      awk 'want { print; exit } /^--?listen=/ { sub(/^--?listen=/, ""); print; exit } /^--?listen$/ { want = 1 }')"
    restart=(launchctl kickstart -k "${target}")
    ;;
  Linux)
    if [ "$(systemctl --user show -p LoadState --value "${UNIT}" 2>/dev/null)" != "loaded" ]; then
      echo "client-restart: the client service (${UNIT}) is not installed; nothing restarted." \
        "\`innsegl connect\` installs it." >&2
      exit 1
    fi
    execstart="$(systemctl --user show -p ExecStart --value "${UNIT}" 2>/dev/null)"
    program="$(printf '%s\n' "${execstart}" | sed -nE 's/.*path=([^ ;]+).*/\1/p' | head -n 1)"
    listen="$(printf '%s\n' "${execstart}" | sed -nE 's/.*argv\[\]=[^;]* --?listen[= ]([^ ;]+).*/\1/p' | head -n 1)"
    restart=(systemctl --user restart "${UNIT}")
    ;;
  *)
    echo "client-restart: no client service is known on $(uname -s)" >&2
    exit 1
    ;;
esac

if [ -z "${program}" ] || [ "$(canon "${program}")" != "$(canon "${bin}")" ]; then
  echo "client-restart: the client service runs ${program:-an unknown binary}, not ${bin}; left as it is." \
    "Restart it yourself if that is the one you mean: ${restart[*]}" >&2
  exit 1
fi
if ! "${restart[@]}"; then
  echo "client-restart: ${restart[*]} failed" >&2
  exit 1
fi

# Wait until the restarted service answers, so whatever runs next finds it up.
listen="${listen:-${DEFAULT_LISTEN}}"
url="http://${listen}/_client/status"
deadline=$((SECONDS + TIMEOUT))
while :; do
  code="$(curl -s -o /dev/null -m 2 -w '%{http_code}' "${url}" 2>/dev/null)"
  if [ -n "${code}" ] && [ "${code}" != "000" ]; then
    echo "client-restart: restarted the client service on ${bin}; it answers on ${listen}"
    exit 0
  fi
  if [ "${SECONDS}" -ge "${deadline}" ]; then
    echo "client-restart: restarted the client service on ${bin}, but it did not answer on ${listen}" \
      "within ${TIMEOUT}s. Check its log, then \`innsegl status\`." >&2
    exit 1
  fi
  sleep 0.5
done
