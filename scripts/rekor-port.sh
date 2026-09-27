#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Print the host port Rekor listens on -- #347.
#
# `make start` publishes Rekor on a random free port, and every other tool
# assumed 23000, so after a `make start` the pin, the reindex and the readiness
# report all asked the wrong port. This is the one answer, in order:
#   1. INNSEGL_REKOR_PORT, when the operator set one;
#   2. the port Docker publishes for the running Rekor;
#   3. 23000, the compose default, when no Rekor is running.
if [ -n "${INNSEGL_REKOR_PORT:-}" ]; then
  printf '%s\n' "$INNSEGL_REKOR_PORT"
  exit 0
fi
_p="$(docker port innsegl-sigstore-rekor 3000 2>/dev/null | head -n 1 | sed 's/.*://')"
case "$_p" in
  ''|*[!0-9]*) printf '23000\n' ;;
  *) printf '%s\n' "$_p" ;;
esac
