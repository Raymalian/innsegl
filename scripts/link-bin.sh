#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Puts a freshly built innsegl binary on the PATH: makes or refreshes the
# symlink $HOME/.local/bin/innsegl -> <binary>, so `innsegl status` works from
# any directory. `make build` runs it after `go build`, on macOS and Linux.
#
#   - No link yet: makes ~/.local/bin if it must, and the link.
#   - A link already there: points it at <binary> (a link to another binary,
#     another checkout's, is moved, and the old target named).
#   - A file there that is not a link: left exactly as it is, with a warning.
#     It is somebody's own binary, and replacing it is not this script's call.
#   - ~/.local/bin not on PATH: says how to add it.
#
# It never fails the build: a link it cannot make is a warning.
#
# USAGE
#   scripts/link-bin.sh <binary>
#
# EXIT STATUS
#   0  done, or warned
#   2  usage
set -uo pipefail

bin="${1:-}"
if [ -z "${bin}" ] || [ "$#" -ne 1 ]; then
  echo "usage: scripts/link-bin.sh <binary>" >&2
  exit 2
fi
case "${bin}" in
  /*) ;;
  *) bin="$(pwd -P)/${bin}" ;;
esac

dir="${HOME}/.local/bin"
link="${dir}/innsegl"

if [ -e "${link}" ] && [ ! -L "${link}" ]; then
  echo "link-bin: ${link} is not a link; left as it is. Remove it to have \`make build\` put this" \
    "checkout's binary there, or run ${bin}." >&2
elif [ -L "${link}" ] && [ "$(readlink "${link}")" = "${bin}" ]; then
  :
else
  old=""
  [ -L "${link}" ] && old="$(readlink "${link}")"
  if ! mkdir -p "${dir}" || ! ln -sfn "${bin}" "${link}"; then
    echo "link-bin: could not link ${link} to ${bin}" >&2
  elif [ -n "${old}" ]; then
    echo "link-bin: ${link} now points at ${bin} (it pointed at ${old})"
  else
    echo "link-bin: ${link} -> ${bin}"
  fi
fi

case ":${PATH}:" in
  *":${dir}:"*) ;;
  *)
    echo "link-bin: ${dir} is not on your PATH, so \`innsegl\` is not found by name." \
      "Add it to your shell's startup file: export PATH=\"${dir}:\$PATH\"" >&2
    ;;
esac
exit 0
