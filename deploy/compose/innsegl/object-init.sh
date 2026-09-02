#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# The segment bucket, created WITH OBJECT LOCK (RM-076, #109, doc 05 §1).
#
#   minio | upstream | Object storage with object lock enabled | Buckets
#           created with lock on; SEG-005 canary runs against it
#
# "CREATED WITH LOCK ON" IS NOT A STYLE NOTE. S3 object lock can only be
# enabled at bucket creation; a bucket made without it can never be given it,
# and there is no repair path short of creating a second bucket and copying
# every sealed segment into it. So this runs before the sealer does, and it
# refuses to hand the stack a bucket that is not locked.
#
# doc 05 §2 sets the mode: "Object lock in compliance mode with a retention
# window >= the organization's audit horizon". COMPLIANCE means no one deletes
# a segment before its retention expires — not the root account, not the
# operator, not us. That is the property SEG-005's canary exists to measure,
# and `innsegl canary` (--profile canary) measures it against this bucket.
#
# Runs in the minio/mc image, which is the only tool needed.

set -eu

log()  { printf 'object-init: %s\n' "$*"; }
fail() { printf 'object-init: FAIL: %s\n' "$*" >&2; exit 1; }

: "${MINIO_ROOT_USER:?object-init: MINIO_ROOT_USER must be set}"
: "${MINIO_ROOT_PASSWORD:?object-init: MINIO_ROOT_PASSWORD must be set}"
BUCKET="${INNSEGL_OBJECT_STORE_BUCKET:-innsegl-segments}"
ENDPOINT="${INNSEGL_OBJECT_STORE_URL:-http://minio:9000}"
MODE="${INNSEGL_OBJECT_STORE_RETENTION_MODE:-COMPLIANCE}"
RETENTION="${INNSEGL_OBJECT_STORE_RETENTION:-1d}"

case "${MODE}" in
  COMPLIANCE|GOVERNANCE) : ;;
  *) fail "retention mode ${MODE} is neither COMPLIANCE nor GOVERNANCE (internal/segment/worm.go)" ;;
esac

# mc's own config lives in HOME, which is not writable in this image's default
# working directory for a non-root user; --config-dir keeps it somewhere it is.
MC="mc --config-dir /tmp/mc"

log "waiting for ${ENDPOINT}"
waited=0
until ${MC} alias set innsegl "${ENDPOINT}" "${MINIO_ROOT_USER}" "${MINIO_ROOT_PASSWORD}" >/dev/null 2>&1; do
  waited=$((waited + 1))
  [ "${waited}" -lt 120 ] || fail "the object store at ${ENDPOINT} never answered"
  sleep 1
done

if ${MC} ls "innsegl/${BUCKET}" >/dev/null 2>&1; then
  log "bucket ${BUCKET} already exists"
else
  log "creating bucket ${BUCKET} with object lock"
  ${MC} mb --with-lock "innsegl/${BUCKET}"
fi

# The default retention every object inherits. A sealer that forgot to set a
# retention per object would otherwise write a deletable segment into a locked
# bucket, and the bucket would still report itself as locked.
log "setting the default retention: ${MODE} for ${RETENTION}"
${MC} retention set --default "${MODE}" "${RETENTION}" "innsegl/${BUCKET}"

# ---------------------------------------------------------------------------
# And now prove it, because "mb --with-lock returned 0" is a claim about a
# command and not about a bucket. `mc retention info` reads the bucket's
# configuration back off the server.
#
# This is the same argument verify-role.sh makes about the database role, and
# it is the same argument for the same reason: a control that is asserted
# rather than measured is a control nobody has checked.
# ---------------------------------------------------------------------------
#
# NOTE ON THE TOOLING: the minio/mc image carries mc, a shell, `cut`, `tr` and
# `printf` — and no sed, no grep and no awk (measured). So the assertion below
# is a `case` pattern and not a pipeline. Adding a second image to this stack
# for the sake of grep would be a worse trade than writing shell twice.
info="$(${MC} retention info "innsegl/${BUCKET}" 2>&1)" \
  || fail "the bucket reports no object-lock configuration at all: ${info}"
printf '%s\n' "${info}"

case "${info}" in
  *"${MODE}"*) : ;;
  *) fail "the bucket's retention configuration does not name ${MODE}. doc 05 §1 requires object lock ON AT CREATION and S3 cannot enable it afterwards, so the bucket has to be recreated: docker compose -f deploy/compose/innsegl.yml down -v" ;;
esac

log "${BUCKET} is locked in ${MODE} mode for ${RETENTION} — measured, not asserted"
log "run the SEG-005 deletion canary against it with:"
log "  docker compose -f deploy/compose/innsegl.yml --profile canary run --rm innsegl-canary"
