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

# The directory this script was invoked from, so its verifier is found beside
# it whatever the caller's working directory. db-init.sh's line, verbatim.
readonly HERE="$(cd -- "$(dirname -- "$0")" && pwd)"

: "${MINIO_ROOT_USER:?object-init: MINIO_ROOT_USER must be set}"
: "${MINIO_ROOT_PASSWORD:?object-init: MINIO_ROOT_PASSWORD must be set}"
BUCKET="${INNSEGL_OBJECT_STORE_BUCKET:-innsegl-segments}"
ENDPOINT="${INNSEGL_OBJECT_STORE_URL:-http://minio:9000}"
MODE="${INNSEGL_OBJECT_STORE_RETENTION_MODE:-COMPLIANCE}"

# THE RETENTION WINDOW, IN mc's GRAMMAR — and the variable is deliberately NOT
# called INNSEGL_OBJECT_STORE_RETENTION.
#
# cmd/innsegl reads $INNSEGL_OBJECT_STORE_RETENTION as a GO DURATION, through
# time.ParseDuration. `mc retention set` reads its window as `1d` / `30d` /
# `1y`. Go has no `d` unit: time.ParseDuration("1d") returns
# `unknown unit "d"`, and cmd/innsegl's envDuration helper falls back to its
# default — 0, meaning "inherit whatever the bucket says" — WITHOUT AN ERROR.
#
# So the same-looking value means two different things to the two consumers,
# and the wrong one fails silently. Two grammars, two names. This one is mc's;
# nothing in deploy/compose/innsegl.yml passes a retention to the sealer or the
# canary at all, so the bucket rule set here is the single source of truth and
# the Go services inherit it. See the sealer service for the full note.
RETENTION="${INNSEGL_OBJECT_LOCK_RETENTION:-1d}"

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

# ---------------------------------------------------------------------------
# THE SCOPED IDENTITY (RM-144, #228, AB-17).
#
# Everything above runs as the store's ROOT account, and that is correct: a
# bucket's object lock can only be enabled at creation and only an account that
# may set a bucket configuration can put the default rule on it. Bucket creation
# is a ONE-TIME SETUP STEP, and this script is the one-shot that performs it.
#
# What was wrong was that the same account then stayed. deploy/compose/innsegl.yml
# gave `innsegl-sealer` and `innsegl-canary` the same value it gave the server as
# MINIO_ROOT_USER, so the sealer ran as the store's root account for the whole
# life of the deployment.
#
# WHY THAT MATTERS EVEN THOUGH THE NETWORK IS SEGMENTED. The store has no
# published port and sits on a network declared `internal:`. That control is
# real and it is correctly built, and it assumes an attacker who is not on the
# host. A process ON the host with a container runtime is effectively root
# there: it reads a running container's environment and attaches a container of
# its own to any network it likes. No arrangement of container networks changes
# that, so the answer is not a better fence — it is that what such a process
# finds is a credential that cannot weaken anything.
#
# WHAT IS AND IS NOT AT RISK, because it decides how much narrowing is worth
# doing. Sealed history is safe in every case measured: COMPLIANCE retention
# refuses deletion by anyone, the account that wrote it included. The exposure
# is FUTURE protection — an identity that may set the bucket's object-lock
# configuration can downgrade the default rule to GOVERNANCE, after which
# everything written is deletable by a holder of a bypass-capable credential.
#
# So the identity below gets exactly what the sealer and the canary do, and two
# permissions are withheld by name:
#
#   s3:PutBucketObjectLockConfiguration  the downgrade itself
#   s3:BypassGovernanceRetention         deleting under a rule already downgraded
#
# THE POLICY IS A HEREDOC AND NOT A MOUNTED FILE, unlike innsegl/appendonly.sql
# and internal/api/readonly.sql, which are files precisely so they cannot drift.
# The reason is the one already written at the head of this file: the mc image
# carries no sed, no grep and no awk, and the policy has to carry THIS
# deployment's bucket name. A placeholder substituted by hand in POSIX shell
# would be a worse thing to get right than a heredoc.
# ---------------------------------------------------------------------------

SEALER_USER="${INNSEGL_OBJECT_STORE_SEALER_ACCESS_KEY:-innsegl-sealer}"

# DERIVED WHEN UNSET, NOT REQUIRED. An operator upgrading an existing
# deployment has set a root credential once and never heard of this issue; if
# the scoped credential had to be configured before the stack came up, the
# narrowing would not be deployable and would be turned off instead.
# deploy/compose/innsegl.yml derives the same value the same way, and OPS-025
# measures that the two agree by authenticating with the credential COMPOSE
# resolves against the identity THIS script provisioned.
SEALER_PASSWORD="${INNSEGL_OBJECT_STORE_SEALER_SECRET_KEY:-${MINIO_ROOT_PASSWORD}-sealer}"

# The policy name is per-deployment state and not a protected string; nothing
# outside this file and its verifier reads it.
SEALER_POLICY=innsegl-segment-writer

[ "${SEALER_USER}" != "${MINIO_ROOT_USER}" ] \
  || fail "the scoped identity \$INNSEGL_OBJECT_STORE_SEALER_ACCESS_KEY is the store's root account (${SEALER_USER}). The whole point is that they are two identities; pick another name"

# S3 access keys have a length floor and an unhelpful server-side error when
# they miss it. Refusing here names the variable instead.
case "${SEALER_PASSWORD}" in
  ????????*) : ;;
  *) fail "the scoped identity's secret is shorter than eight characters. Set \$INNSEGL_OBJECT_STORE_SEALER_SECRET_KEY, or lengthen \$INNSEGL_OBJECT_STORE_SECRET_KEY, from which it is derived" ;;
esac

# A store reached over plain S3 has no admin API and no identities to create —
# the identity has to come from whatever provisions credentials there. This
# refuses rather than degrades: a deployment that quietly kept running as root
# would be indistinguishable from one that had been narrowed.
if ${MC} admin info innsegl >/dev/null 2>&1; then
  log "creating the scoped identity ${SEALER_USER} and policy ${SEALER_POLICY}"

  cat > /tmp/${SEALER_POLICY}.json <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadTheBucketAndItsLockRule",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:ListBucketVersions",
        "s3:ListBucketMultipartUploads",
        "s3:GetBucketLocation",
        "s3:GetBucketVersioning",
        "s3:GetBucketObjectLockConfiguration"
      ],
      "Resource": ["arn:aws:s3:::${BUCKET}"]
    },
    {
      "Sid": "WriteReadAndRetainSegments",
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:PutObjectRetention",
        "s3:GetObjectRetention",
        "s3:GetObjectLegalHold",
        "s3:DeleteObject",
        "s3:DeleteObjectVersion",
        "s3:AbortMultipartUpload",
        "s3:ListMultipartUploadParts"
      ],
      "Resource": ["arn:aws:s3:::${BUCKET}/*"]
    }
  ]
}
POLICY

  # WHY s3:DeleteObject AND s3:DeleteObjectVersion ARE IN A POLICY WHOSE POINT
  # IS THAT NOTHING CAN BE DELETED. They are what SEG-005's canary needs to
  # prove its own refusal means anything: it writes a delete marker, which
  # carries no retention, and permanently removes that marker version with the
  # same credential in the same bucket. Without that control a refusal is
  # indistinguishable from a missing permission, and an inconclusive canary
  # fails. They buy an attacker nothing — a retained version refuses deletion
  # under COMPLIANCE whoever asks, which is measured by the canary on every run.
  #
  # Each of these is idempotent: re-running this one-shot over an existing
  # deployment replaces the policy, resets the secret and re-attaches, which is
  # what an operator rotating \$INNSEGL_OBJECT_STORE_SECRET_KEY needs to happen.
  ${MC} admin policy create innsegl "${SEALER_POLICY}" /tmp/${SEALER_POLICY}.json
  ${MC} admin user add innsegl "${SEALER_USER}" "${SEALER_PASSWORD}" >/dev/null
  ${MC} admin policy attach innsegl "${SEALER_POLICY}" --user "${SEALER_USER}" >/dev/null 2>&1 \
    || log "policy ${SEALER_POLICY} was already attached to ${SEALER_USER}"
  rm -f /tmp/${SEALER_POLICY}.json
elif [ -n "${INNSEGL_OBJECT_STORE_SEALER_ACCESS_KEY:-}" ]; then
  log "${ENDPOINT} exposes no admin API; taking ${SEALER_USER} as an identity provisioned outside this stack"
else
  fail "${ENDPOINT} exposes no admin API, so this script cannot create a scoped identity, and none was supplied. Provision one in that store with write access to ${BUCKET} and WITHOUT s3:PutBucketObjectLockConfiguration or s3:BypassGovernanceRetention, then set \$INNSEGL_OBJECT_STORE_SEALER_ACCESS_KEY and \$INNSEGL_OBJECT_STORE_SEALER_SECRET_KEY. Running the sealer as the store's root account is what #228 is about"
fi

log "run the SEG-005 deletion canary against the bucket with:"
log "  docker compose -f deploy/compose/innsegl.yml --profile canary run --rm innsegl-canary"

# ---------------------------------------------------------------------------
# And now ask the server what that credential can actually do — db-init.sh's
# last line, for db-init.sh's reason.
#
# Attaching a policy is provisioning, and provisioning is a claim. The
# assertion matters more: a policy is attached once and then lives in somebody's
# deployment, and a later `mc admin policy attach readwrite` by an operator who
# wanted to "just fix one thing" is invisible to any amount of review.
#
# The resolved credential is exported rather than re-derived there, so the rule
# above is the only copy of it in this script.
# ---------------------------------------------------------------------------
export INNSEGL_OBJECT_STORE_SEALER_ACCESS_KEY="${SEALER_USER}"
export INNSEGL_OBJECT_STORE_SEALER_SECRET_KEY="${SEALER_PASSWORD}"
export INNSEGL_OBJECT_STORE_URL="${ENDPOINT}"
export INNSEGL_OBJECT_STORE_BUCKET="${BUCKET}"
export INNSEGL_OBJECT_STORE_RETENTION_MODE="${MODE}"
export INNSEGL_OBJECT_LOCK_RETENTION="${RETENTION}"
exec sh "${HERE}/verify-object-scope.sh"
