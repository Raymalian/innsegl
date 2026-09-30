#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The directory the API mounts as the harness's managed settings (ADR-0062),
# named in one place.
#
# The default is the harness's own directory for the host OS, the same one
# install.sh writes to. $INNSEGL_MANAGED_SETTINGS_HOST_DIR overrides it.
#
# USAGE
#   scripts/managed-settings-mount.sh          print the directory
#   scripts/managed-settings-mount.sh --check  prove Docker can mount it
#
# --check exists because Docker Desktop on a Mac does not share /Library by
# default, and compose finds that out only while recreating the API, after
# the old container is already gone. Checking first leaves a running stack
# running.
#
# EXIT
#   0  printed, or Docker mounted the directory
#   3  Docker could not mount it; the message says where to share it
set -uo pipefail

dir="${INNSEGL_MANAGED_SETTINGS_HOST_DIR:-}"
if [ -z "$dir" ]; then
  case "$(uname -s)" in
    Darwin) dir="/Library/Application Support/ClaudeCode" ;;
    *)      dir="/etc/claude-code" ;;
  esac
fi

if [ "${1:-}" != "--check" ]; then
  printf '%s\n' "$dir"
  exit 0
fi

# The runtime image's own base, pinned the way the Dockerfile pins it.
image="alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce"
if ! out="$(docker run --rm -v "$dir:/run/innsegl/managed-settings:ro" "$image" true 2>&1)"; then
  {
    echo "managed-settings-mount: Docker cannot mount $dir"
    echo "  $out"
    echo "  The API reads the harness's managed settings from there before a passkey enrolment."
    echo "  Docker Desktop: Settings > Resources > File sharing, add that directory, Apply & restart."
    echo "  Or set INNSEGL_MANAGED_SETTINGS_HOST_DIR to a directory Docker can mount."
  } >&2
  exit 3
fi
