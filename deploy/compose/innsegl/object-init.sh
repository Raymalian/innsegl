#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# The segment bucket, created WITH OBJECT LOCK (RM-076 #109, RM-143 #227,
# doc 05 §1).
#
#   object store | upstream | Object storage with object lock enabled | Buckets
#                  created with lock on; SEG-005 canary runs against it
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
# operator, not us. Measured against this store's own root identity: shortening
# the retention, downgrading it to GOVERNANCE, and deleting the version with a
# governance bypass are all refused, and the bytes read back unchanged. That is
# the property SEG-005's canary exists to measure, and `innsegl canary`
# (--profile canary) measures it against this bucket.
#
# A ZERO EXIT FROM A CREATE CALL IS NOT EVIDENCE (OPS-030). The init this
# replaced ran a create command that took a flag asking for object lock,
# reported success, and left a bucket with no lock configuration at all —
# measured, on the store RM-143 replaced, and invisible from the exit status.
# So every assertion below reads the configuration back off the server.
#
# WHY THE CLIENT IS THE REFERENCE ONE. What ran here before was the client that
# shipped with the store being replaced, which is how the init came to be tied
# to a store that was then archived. This speaks the protocol and nothing else:
# s3api create-bucket --object-lock-enabled-for-bucket,
# s3api put-object-lock-configuration, s3api get-object-lock-configuration.

set -eu

log()  { printf 'object-init: %s\n' "$*"; }
fail() { printf 'object-init: FAIL: %s\n' "$*" >&2; exit 1; }

# The directory this script was invoked from, so its verifier is found beside
# it whatever the caller's working directory. db-init.sh's line, verbatim.
readonly HERE="$(cd -- "$(dirname -- "$0")" && pwd)"

: "${INNSEGL_OBJECT_STORE_ACCESS_KEY:?object-init: INNSEGL_OBJECT_STORE_ACCESS_KEY must be set}"
: "${INNSEGL_OBJECT_STORE_SECRET_KEY:?object-init: INNSEGL_OBJECT_STORE_SECRET_KEY must be set}"
BUCKET="${INNSEGL_OBJECT_STORE_BUCKET:-innsegl-segments}"
ENDPOINT="${INNSEGL_OBJECT_STORE_URL:-http://innsegl-s3:8333}"
MODE="${INNSEGL_OBJECT_STORE_RETENTION_MODE:-COMPLIANCE}"

# THE RETENTION WINDOW, IN THE BUCKET RULE'S GRAMMAR — and the variable is
# deliberately NOT called INNSEGL_OBJECT_STORE_RETENTION.
#
# cmd/innsegl reads $INNSEGL_OBJECT_STORE_RETENTION as a GO DURATION, through
# time.ParseDuration. An S3 default retention rule has exactly two units, Days
# and Years, so this one is written `1d` / `30d` / `1y`. Go has no `d` unit:
# time.ParseDuration("1d") returns `unknown unit "d"`, and cmd/innsegl's
# envDuration helper falls back to its default — 0, meaning "inherit whatever
# the bucket says" — WITHOUT AN ERROR.
#
# So the same-looking value means two different things to the two consumers,
# and the wrong one fails silently. Two grammars, two names. This one is the
# bucket rule's; nothing in deploy/compose/innsegl.yml passes a retention to
# the sealer or the canary at all, so the bucket rule set here is the single
# source of truth and the Go services inherit it. See the sealer service for
# the full note.
RETENTION="${INNSEGL_OBJECT_LOCK_RETENTION:-1d}"

case "${MODE}" in
  COMPLIANCE|GOVERNANCE) : ;;
  *) fail "retention mode ${MODE} is neither COMPLIANCE nor GOVERNANCE (internal/segment/worm.go)" ;;
esac

# `1d` and `1y` are the only two shapes an S3 default rule can express, so the
# parse is total and anything else is refused by name rather than sent to the
# server to be rejected obscurely.
case "${RETENTION}" in
  *d) RETENTION_UNIT=Days;  RETENTION_COUNT="${RETENTION%d}" ;;
  *y) RETENTION_UNIT=Years; RETENTION_COUNT="${RETENTION%y}" ;;
  *)  fail "retention window ${RETENTION} must end in d or y — an S3 default retention rule has no other unit. \$INNSEGL_OBJECT_STORE_RETENTION is the Go-duration one and is a different variable" ;;
esac
case "${RETENTION_COUNT}" in
  ''|*[!0-9]*) fail "retention window ${RETENTION} does not begin with a whole number of ${RETENTION_UNIT}" ;;
esac
[ "${RETENTION_COUNT}" -gt 0 ] || fail "retention window ${RETENTION} is zero; a lock that expires immediately protects nothing"

export AWS_ACCESS_KEY_ID="${INNSEGL_OBJECT_STORE_ACCESS_KEY}"
export AWS_SECRET_ACCESS_KEY="${INNSEGL_OBJECT_STORE_SECRET_KEY}"
export AWS_DEFAULT_REGION="${INNSEGL_OBJECT_STORE_REGION:-us-east-1}"
# The client's own defaults would otherwise send a trailing checksum header
# this gateway answers with a signature mismatch (measured). The request is
# identical either way; only the framing differs. Set here as well as in the
# compose service so that running this script by hand behaves the same way.
export AWS_REQUEST_CHECKSUM_CALCULATION="${AWS_REQUEST_CHECKSUM_CALCULATION:-when_required}"
export AWS_RESPONSE_CHECKSUM_VALIDATION="${AWS_RESPONSE_CHECKSUM_VALIDATION:-when_required}"

s3api() { aws --endpoint-url "${ENDPOINT}" s3api "$@"; }

log "waiting for ${ENDPOINT}"
waited=0
until s3api list-buckets >/dev/null 2>&1; do
  waited=$((waited + 1))
  [ "${waited}" -lt 120 ] || fail "the object store at ${ENDPOINT} never answered an authenticated request. On this store that is ALSO what an absent identity file looks like: check that innsegl-s3-identities ran and that innsegl-s3 was started with -config"
  sleep 1
done

if s3api head-bucket --bucket "${BUCKET}" >/dev/null 2>&1; then
  log "bucket ${BUCKET} already exists"
else
  log "creating bucket ${BUCKET} with object lock"
  s3api create-bucket --bucket "${BUCKET}" --object-lock-enabled-for-bucket >/dev/null \
    || fail "could not create ${BUCKET}"
fi

# The default retention every object inherits. A sealer that forgot to set a
# retention per object would otherwise write a deletable segment into a locked
# bucket, and the bucket would still report itself as locked.
log "setting the default retention: ${MODE} for ${RETENTION_COUNT} ${RETENTION_UNIT}"
s3api put-object-lock-configuration --bucket "${BUCKET}" \
  --object-lock-configuration "ObjectLockEnabled=Enabled,Rule={DefaultRetention={Mode=${MODE},${RETENTION_UNIT}=${RETENTION_COUNT}}}" >/dev/null \
  || fail "could not set the default retention rule on ${BUCKET}. A bucket created without object lock cannot be given it — S3 allows it only at creation — so if ${BUCKET} already existed it has to be recreated: docker compose -f deploy/compose/innsegl.yml down -v"

# ---------------------------------------------------------------------------
# And now prove it, because "create-bucket returned 0" is a claim about a
# command and not about a bucket (OPS-030).
#
# This is the same argument verify-role.sh makes about the database role, and
# it is the same argument for the same reason: a control that is asserted
# rather than measured is a control nobody has checked.
# ---------------------------------------------------------------------------
info="$(s3api get-object-lock-configuration --bucket "${BUCKET}" 2>&1)" \
  || fail "the bucket reports no object-lock configuration at all: ${info}. doc 05 §1 requires object lock ON AT CREATION and S3 cannot enable it afterwards, so the bucket has to be recreated: docker compose -f deploy/compose/innsegl.yml down -v"
printf '%s\n' "${info}"

case "${info}" in
  *'"ObjectLockEnabled": "Enabled"'*) : ;;
  *) fail "${BUCKET} does not report object lock as Enabled. It cannot be enabled after creation; recreate the bucket with: docker compose -f deploy/compose/innsegl.yml down -v" ;;
esac
case "${info}" in
  *"\"Mode\": \"${MODE}\""*) : ;;
  *) fail "the bucket's default retention rule does not name ${MODE}. An object written with no retention of its own would inherit whatever it does name, and the sealer writes exactly that" ;;
esac
case "${info}" in
  *"\"${RETENTION_UNIT}\": ${RETENTION_COUNT}"*) : ;;
  *) fail "the bucket's default retention rule is not ${RETENTION_COUNT} ${RETENTION_UNIT}" ;;
esac

# Object lock is defined over VERSIONS, and a store that reported the rule while
# leaving versioning off would give every segment a single overwritable version.
# SEG-005's canary needs a version id to attempt a delete of at all.
versioning="$(s3api get-bucket-versioning --bucket "${BUCKET}" 2>&1)" || versioning=""
case "${versioning}" in
  *'"Status": "Enabled"'*) : ;;
  *) fail "${BUCKET} does not report versioning as Enabled (${versioning}). Object lock is defined over versions; without it a sealed segment has one overwritable version and nothing to refuse a delete of" ;;
esac

log "${BUCKET} is locked in ${MODE} mode for ${RETENTION_COUNT} ${RETENTION_UNIT}, versioning Enabled — measured, not asserted"
log "run the SEG-005 deletion canary against the bucket with:"
log "  docker compose -f deploy/compose/innsegl.yml --profile canary run --rm innsegl-canary"

# ---------------------------------------------------------------------------
# And now ask the server what the SCOPED credential can actually do — db-init.sh's
# last line, for db-init.sh's reason (RM-144, #228, AB-17).
#
# The identity itself is not created here: this store reads its identities from
# a file the gateway was started with, which innsegl/s3-identities.sh writes.
# That makes the scope provisioning, and provisioning is a claim. The assertion
# matters more: an identity file lives in somebody's deployment, and one line
# changed in it later — a bucket-wide `Write` in place of the prefix-scoped one
# — is invisible to any amount of review and hands the running stack a
# credential that can downgrade the rule this script just set.
#
# The resolved credential is exported rather than re-derived there, so the rule
# in s3-identities.sh is the only copy of it.
# ---------------------------------------------------------------------------
export INNSEGL_OBJECT_STORE_SEALER_ACCESS_KEY="${INNSEGL_OBJECT_STORE_SEALER_ACCESS_KEY:-innsegl-sealer}"
export INNSEGL_OBJECT_STORE_SEALER_SECRET_KEY="${INNSEGL_OBJECT_STORE_SEALER_SECRET_KEY:-${INNSEGL_OBJECT_STORE_SECRET_KEY}-sealer}"
export INNSEGL_OBJECT_STORE_URL="${ENDPOINT}"
export INNSEGL_OBJECT_STORE_BUCKET="${BUCKET}"
export INNSEGL_OBJECT_STORE_PREFIX="${INNSEGL_OBJECT_STORE_PREFIX:-segments/}"
export INNSEGL_OBJECT_STORE_RETENTION_MODE="${MODE}"
export INNSEGL_OBJECT_LOCK_RETENTION="${RETENTION}"
exec sh "${HERE}/verify-object-scope.sh"
