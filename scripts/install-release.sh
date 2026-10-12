#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Installs a built innsegl binary as the copy the hooks, the client service
# and scheduled jobs run (#599): /usr/local/libexec/innsegl/innsegl, owned by
# root, in a folder owned by root. `innsegl connect` names only that copy and
# refuses a binary the user can change, because hooks run on every agent
# prompt and a build in a checkout is rewritten by any agent working there.
#
# It writes one line, run as root through sudo:
#
#   1. copy the binary to a temporary file of root's,
#   2. check that copy's SHA-256 against the one printed here,
#   3. install it beside the old copy and rename it into place.
#
# So a binary changed between this script and the sudo prompt is refused, and
# a running client service is never overwritten in place (macOS kills a
# signed process whose file changes under it). On macOS the copy keeps the
# signature `make build` gave it.
#
# In a terminal it runs that line (sudo asks for the password). Without one
# it prints the line and exits 3: run it yourself, in a terminal.
#
# USAGE
#   scripts/install-release.sh <binary>
#
# $INNSEGL_RELEASE_DIR replaces the destination folder, for the self-test;
# `innsegl connect` looks only in /usr/local/libexec/innsegl.
#
# EXIT STATUS
#   0  installed
#   1  the install failed (sudo refused, or the hash check)
#   2  usage
#   3  not installed: no terminal to ask for sudo in; the line is printed
set -uo pipefail

bin="${1:-}"
if [ -z "${bin}" ] || [ "$#" -ne 1 ]; then
  echo "usage: scripts/install-release.sh <binary>" >&2
  exit 2
fi
if [ ! -f "${bin}" ] || [ ! -x "${bin}" ]; then
  echo "install-release: ${bin} is not an executable file; run \`make build\` first" >&2
  exit 2
fi
case "${bin}" in
  /*) ;;
  *) bin="$(pwd -P)/${bin}" ;;
esac

dir="${INNSEGL_RELEASE_DIR:-/usr/local/libexec/innsegl}"
dest="${dir}/innsegl"

# q STRING — STRING single-quoted for sh.
q() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }

if [ "$(uname -s)" = Darwin ]; then
  sum="$(shasum -a 256 "${bin}" | cut -d' ' -f1)"
  check="shasum -a 256 -c -"
else
  sum="$(sha256sum "${bin}" | cut -d' ' -f1)"
  check="sha256sum -c -"
fi

# set -e stops at the first failure, and the hash check ends its pipeline,
# so a mismatch installs nothing and gives nothing to root.
new="${dir}/.innsegl.new"
script="set -e; t=\$(mktemp); trap 'rm -f \"\$t\"' EXIT; cat $(q "${bin}") > \"\$t\"; echo \"${sum}  \$t\" | ${check}"
script="${script}; mkdir -p $(q "${dir}"); chown 0:0 $(q "${dir}"); chmod 0755 $(q "${dir}")"
script="${script}; install -m 0755 \"\$t\" $(q "${new}"); chown 0:0 $(q "${new}"); mv -f $(q "${new}") $(q "${dest}")"
line="sudo sh -c $(q "${script}")"

echo "install-release: installing ${bin} (sha256 ${sum}) as ${dest}, owned by root:"
echo
echo "  ${line}"
echo

if [ ! -t 0 ]; then
  echo "install-release: not installed: there is no terminal to ask for sudo in. Run the line above in one." >&2
  exit 3
fi
if ! sudo sh -c "${script}"; then
  echo "install-release: not installed: the line above failed" >&2
  exit 1
fi
echo "install-release: installed ${dest}. Hooks and the client service run it once \`innsegl connect --update\`" \
  "names it; \`make client-restart\` restarts the service on it."
exit 0
