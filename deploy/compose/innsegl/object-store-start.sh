#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Starts the object store with its per-host key (#451).
#
# S3's gRPC port and the Filer's require a key, which the store reads from
# $WEED_JWT_FILER_SIGNING_KEY. innsegl-s3-identities generates it once per host
# into the volume this container mounts read-only. This reads it, refuses to
# start without it, and hands it to the image's own entrypoint in the
# environment of the process only, so it is not in the container's
# configuration.

set -eu

fail() { printf 'object-store-start: FAIL: %s\n' "$*" >&2; exit 1; }

KEY_FILE="${INNSEGL_OBJECT_FILER_JWT_KEY_FILE:-/run/innsegl/s3/filer-jwt.key}"

[ -s "${KEY_FILE}" ] \
  || fail "no key at ${KEY_FILE}. innsegl-s3-identities generates it; run it, or set \$INNSEGL_OBJECT_FILER_JWT_KEY and run it"
key="$(tr -d '\n' < "${KEY_FILE}")"
[ "${#key}" -ge 48 ] \
  || fail "the key at ${KEY_FILE} is ${#key} characters; the store will not start with a guessable key"

WEED_JWT_FILER_SIGNING_KEY="${key}"
export WEED_JWT_FILER_SIGNING_KEY
unset key

exec /entrypoint.sh "$@"
