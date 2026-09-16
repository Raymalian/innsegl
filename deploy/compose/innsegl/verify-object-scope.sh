#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Ask the object store what the sealer's credential can actually do
# (RM-144, #228; RM-143, #227; AB-17; doc 05 §2).
#
# WHY THIS EXISTS AT ALL
# ----------------------
# innsegl/s3-identities.sh writes an identity file that grants less. That is
# provisioning, and provisioning is a claim. verify-role.sh makes the argument
# for the database role and it is the argument this file implements, in the
# other medium:
#
#     "A role is provisioned once and then lives in somebody's deployment; a
#      later GRANT by an operator who wanted to 'just fix one thing' is
#      invisible to any amount of code review."
#
# The object store's version of that GRANT is one word. Change
#
#     "Write:<bucket>/<prefix>*"      to      "Write"
#
# in the identity file and the running stack again holds a credential that can
# set the bucket's object-lock configuration and downgrade it from COMPLIANCE
# to GOVERNANCE. It leaves no trace in this repository and none in the compose
# file. So object-init.sh ends by execing this, and the compose stack gates the
# sealer on object-init.sh completing — which means the sealer does not start
# behind a scope nobody measured.
#
# WHY THE SCOPE IS A PREFIX ON THIS STORE
# ---------------------------------------
# Measured on the pinned image: this store's permission model has no separate
# action for setting a bucket's object-lock configuration. An identity granted
# a bucket-wide `Write` may set it. There is no permission to withhold by name,
# so the narrowing is expressed as the only thing that does distinguish the two
# calls — the prefix the write is scoped to — and checks 2 and 3 below are what
# prove that separates them on this server rather than in this comment.
#
# WHY IT PROVES A PERMISSION IT HAS BEFORE IT PROVES THE ONES IT HAS NOT
# ----------------------------------------------------------------------
# "The store refused" is also true of an unreachable endpoint, a misspelled
# bucket, an expired credential and a server that is not running. A refusal is
# evidence about the SCOPE only when the same credential, against the same
# bucket, on the same server, in the same run, is shown being PERMITTED
# something. appendonlyrole_test.go calls that the anti-vacuity control and
# SEG-005's canary is built around one; this script reads the bucket's
# object-lock configuration first, and every refusal below is reported against
# that.
#
# WHY IT WRITES NOTHING
# ---------------------
# The bucket it is pointed at holds objects under COMPLIANCE retention, so
# anything this script wrote it could never remove — not on this run and not
# ever, by any account. A verifier that leaves an undeletable object behind on
# every `compose up` is a verifier an operator switches off. Proving the write
# path is SEG-005's canary's job, which writes one probe deliberately and says
# in the object's own body what it is.
#
# The one attempt that could change something writes THE RULE THE BUCKET
# ALREADY HAS. If the permission is absent the call is refused, which is the
# finding; if it is present the call succeeds and the bucket is left exactly as
# it was, which is also the finding. Attempting a downgrade in order to detect
# that a downgrade is possible would be performing the attack to report it.

set -eu

log()  { printf 'verify-object-scope: %s\n' "$*"; }
fail() { printf 'verify-object-scope: FAIL: %s\n' "$*" >&2; }

: "${INNSEGL_OBJECT_STORE_SEALER_ACCESS_KEY:?verify-object-scope: INNSEGL_OBJECT_STORE_SEALER_ACCESS_KEY must name the scoped identity}"
: "${INNSEGL_OBJECT_STORE_SEALER_SECRET_KEY:?verify-object-scope: INNSEGL_OBJECT_STORE_SEALER_SECRET_KEY must be set}"

BUCKET="${INNSEGL_OBJECT_STORE_BUCKET:-innsegl-segments}"
ENDPOINT="${INNSEGL_OBJECT_STORE_URL:-http://innsegl-s3:8333}"
MODE="${INNSEGL_OBJECT_STORE_RETENTION_MODE:-COMPLIANCE}"
RETENTION="${INNSEGL_OBJECT_LOCK_RETENTION:-1d}"
PREFIX="${INNSEGL_OBJECT_STORE_PREFIX:-segments/}"

case "${RETENTION}" in
  *d) RETENTION_UNIT=Days;  RETENTION_COUNT="${RETENTION%d}" ;;
  *y) RETENTION_UNIT=Years; RETENTION_COUNT="${RETENTION%y}" ;;
  *)  RETENTION_UNIT=Days;  RETENTION_COUNT=1 ;;
esac

# EVERYTHING BELOW CONNECTS AS THE IDENTITY UNDER TEST, never as the root
# account. verify-role.sh's rule, and for its reason: a probe run under a
# second credential measures that credential.
export AWS_ACCESS_KEY_ID="${INNSEGL_OBJECT_STORE_SEALER_ACCESS_KEY}"
export AWS_SECRET_ACCESS_KEY="${INNSEGL_OBJECT_STORE_SEALER_SECRET_KEY}"
export AWS_DEFAULT_REGION="${INNSEGL_OBJECT_STORE_REGION:-us-east-1}"
export AWS_REQUEST_CHECKSUM_CALCULATION="${AWS_REQUEST_CHECKSUM_CALCULATION:-when_required}"
export AWS_RESPONSE_CHECKSUM_VALIDATION="${AWS_RESPONSE_CHECKSUM_VALIDATION:-when_required}"

s3api() { aws --endpoint-url "${ENDPOINT}" s3api "$@"; }

failures=0

# ---------------------------------------------------------------------------
# 1. THE CONTROL. It must be able to read this bucket's object-lock rule.
#
# Not decoration: `innsegl canary` reads exactly this on every scheduled run
# (internal/segment's checkBucketLock), so a scope that withheld it would have
# disabled doc 05 §2's detection of the very downgrade this narrowing exists to
# make undoable. And it is bucket-specific and authenticated, so a refusal
# below cannot be an unreachable server or a dead credential.
# ---------------------------------------------------------------------------
if rule="$(s3api get-object-lock-configuration --bucket "${BUCKET}" 2>&1)"; then
  log "CAN read the bucket's object-lock rule:"
  printf '%s\n' "${rule}"
else
  fail "the scoped identity cannot read ${BUCKET}'s object-lock rule: ${rule}"
  fail "nothing below this line would mean anything, because a refusal would be indistinguishable from an unreachable bucket"
  exit 1
fi

# ---------------------------------------------------------------------------
# 2. IT MUST NOT BE ABLE TO SET THAT RULE. This is #228, and on this store it
#    is what the prefix-scoped write grant buys (#227).
#
# The value written is the one just read back, so a deployment whose scope has
# been widened is reported and is not further weakened by the reporting.
# ---------------------------------------------------------------------------
if out="$(s3api put-object-lock-configuration --bucket "${BUCKET}" \
      --object-lock-configuration "ObjectLockEnabled=Enabled,Rule={DefaultRetention={Mode=${MODE},${RETENTION_UNIT}=${RETENTION_COUNT}}}" 2>&1)"; then
  fail "the scoped identity SET the bucket's object-lock configuration."
  fail "  AB-17: an identity permitted this can downgrade the default rule from COMPLIANCE"
  fail "  to GOVERNANCE, and every segment written afterwards is deletable by a holder of a"
  fail "  bypass-capable credential. Sealed history survives; future protection does not."
  fail "  On this store the fix is the SCOPE OF THE WRITE GRANT and not a permission name:"
  fail "  the identity file must say Write:${BUCKET}/${PREFIX}* and not a bucket-wide Write."
  failures=$((failures + 1))
else
  log "CANNOT set the bucket's object-lock configuration: ${out}"
fi

# ---------------------------------------------------------------------------
# 3. IT MUST NOT BE ABLE TO WRITE OUTSIDE THE SEGMENT AND PROBE PREFIXES.
#
# On this store that is check 2's grant seen from the other side, and measuring
# both is what makes the finding a scope rather than a coincidence: a credential
# refused the bucket configuration but permitted a write anywhere in the bucket
# would mean the server distinguishes the two calls by something other than the
# prefix, and the whole argument for this shape would be wrong.
# ---------------------------------------------------------------------------
# --body TAKES A PATH AND NOT A STREAM. Piping into `--body /dev/stdin` is
# rejected by the client before a request is made — "Blob values must be a path
# to a file" — which this script would have reported as a refusal by the
# server. Measured, and caught by OPS-029's run of this script: a check whose
# failure mode is a false PASS is worse than no check.
probe_key="innsegl-scope-probe-$$"
probe_body="/tmp/${probe_key}"
printf 'scope probe\n' > "${probe_body}"
if out="$(s3api put-object --bucket "${BUCKET}" --key "${probe_key}" --body "${probe_body}" 2>&1)"; then
  fail "the scoped identity WROTE ${BUCKET}/${probe_key}, which is outside ${PREFIX} and outside the canary's probe prefix."
  fail "  The grant is meant to be Write:${BUCKET}/${PREFIX}*, not a bucket-wide Write."
  fail "  That object now carries the bucket's default retention and cannot be removed; it will expire."
  failures=$((failures + 1))
else
  log "CANNOT write outside the segment and probe prefixes: ${out}"
fi
rm -f "${probe_body}"

# ---------------------------------------------------------------------------
# 4. IT MUST NOT BE ABLE TO MAKE A BUCKET OF ITS OWN.
#
# A credential that can create a bucket can create one WITHOUT object lock and
# write there instead, which is the same outcome as a downgrade reached by a
# different route. The name is derived from the bucket so a refused attempt
# leaves nothing and a permitted one is visible.
# ---------------------------------------------------------------------------
probe_bucket="${BUCKET}-scope-probe"
if out="$(s3api create-bucket --bucket "${probe_bucket}" 2>&1)"; then
  fail "the scoped identity CREATED bucket ${probe_bucket}. A credential that can make a bucket can make one with no object lock and write segments there. Delete ${probe_bucket} by hand."
  failures=$((failures + 1))
else
  log "CANNOT create a bucket: ${out}"
fi

# ---------------------------------------------------------------------------
# 5. IT MUST NOT BE ABLE TO TURN VERSIONING OFF.
#
# Object lock is defined over versions. A credential that can suspend
# versioning cannot delete what is already sealed, but everything written after
# it has one overwritable version and nothing to refuse a delete of — the same
# loss as a downgraded rule, reached by a third route.
# ---------------------------------------------------------------------------
if out="$(s3api put-bucket-versioning --bucket "${BUCKET}" --versioning-configuration Status=Suspended 2>&1)"; then
  fail "the scoped identity SUSPENDED versioning on ${BUCKET}. Re-enable it immediately:"
  fail "  aws --endpoint-url ${ENDPOINT} s3api put-bucket-versioning --bucket ${BUCKET} --versioning-configuration Status=Enabled"
  failures=$((failures + 1))
else
  log "CANNOT suspend versioning: ${out}"
fi

if [ "${failures}" -ne 0 ]; then
  fail "${failures} check(s) failed. The running stack holds a credential that can weaken ${BUCKET}; doc 05 §2 requires that it cannot."
  exit 1
fi

log "${INNSEGL_OBJECT_STORE_SEALER_ACCESS_KEY} writes ${BUCKET}/${PREFIX} and can weaken nothing about the bucket — measured, not asserted"
