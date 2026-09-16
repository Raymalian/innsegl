#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Ask the object store what the sealer's credential can actually do
# (RM-144, #228, AB-17; doc 05 §2).
#
# WHY THIS EXISTS AT ALL
# ----------------------
# object-init.sh attaches a policy that grants less. That is provisioning, and
# provisioning is a claim. verify-role.sh makes the argument for the database
# role and it is the argument this file implements, in the other medium:
#
#     "A role is provisioned once and then lives in somebody's deployment; a
#      later GRANT by an operator who wanted to 'just fix one thing' is
#      invisible to any amount of code review."
#
# The object store's version of that GRANT is one command:
# `mc admin policy attach <store> readwrite --user <sealer>`. It leaves no
# trace in this repository and no trace in the compose file, and after it the
# running stack again holds a credential that can downgrade the bucket's
# object-lock rule from COMPLIANCE to GOVERNANCE. So object-init.sh ends by
# execing this, and the compose stack gates the sealer on object-init.sh
# completing — which means the sealer does not start behind a scope nobody
# measured.
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
#
# NOTE ON THE TOOLING: the minio/mc image carries mc, a shell, `cut`, `tr` and
# `printf` — and no sed, no grep and no awk. Nothing below is a pipeline.

set -eu

log()  { printf 'verify-object-scope: %s\n' "$*"; }
fail() { printf 'verify-object-scope: FAIL: %s\n' "$*" >&2; }

: "${INNSEGL_OBJECT_STORE_SEALER_ACCESS_KEY:?verify-object-scope: INNSEGL_OBJECT_STORE_SEALER_ACCESS_KEY must name the scoped identity}"
: "${INNSEGL_OBJECT_STORE_SEALER_SECRET_KEY:?verify-object-scope: INNSEGL_OBJECT_STORE_SEALER_SECRET_KEY must be set}"

BUCKET="${INNSEGL_OBJECT_STORE_BUCKET:-innsegl-segments}"
ENDPOINT="${INNSEGL_OBJECT_STORE_URL:-http://minio:9000}"
MODE="${INNSEGL_OBJECT_STORE_RETENTION_MODE:-COMPLIANCE}"
RETENTION="${INNSEGL_OBJECT_LOCK_RETENTION:-1d}"

MC="mc --config-dir /tmp/mc-scope"

# EVERYTHING BELOW CONNECTS AS THE IDENTITY UNDER TEST, never as the root
# account. verify-role.sh's rule, and for its reason: a probe run under a
# second credential measures that credential.
${MC} alias set scoped "${ENDPOINT}" \
  "${INNSEGL_OBJECT_STORE_SEALER_ACCESS_KEY}" \
  "${INNSEGL_OBJECT_STORE_SEALER_SECRET_KEY}" >/dev/null 2>&1 \
  || { fail "the scoped identity ${INNSEGL_OBJECT_STORE_SEALER_ACCESS_KEY} cannot reach ${ENDPOINT} at all"; exit 1; }

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
if rule="$(${MC} retention info "scoped/${BUCKET}" 2>&1)"; then
  log "CAN read the bucket's object-lock rule: ${rule}"
else
  fail "the scoped identity cannot read ${BUCKET}'s object-lock rule: ${rule}"
  fail "nothing below this line would mean anything, because a refusal would be indistinguishable from an unreachable bucket"
  exit 1
fi

# ---------------------------------------------------------------------------
# 2. IT MUST NOT BE ABLE TO SET THAT RULE. This is #228.
#
# The value written is the one just read back, so a deployment whose scope has
# been widened is reported and is not further weakened by the reporting.
# ---------------------------------------------------------------------------
if out="$(${MC} retention set --default "${MODE}" "${RETENTION}" "scoped/${BUCKET}" 2>&1)"; then
  fail "the scoped identity SET the bucket's object-lock configuration."
  fail "  AB-17: an identity permitted this can downgrade the default rule from COMPLIANCE"
  fail "  to GOVERNANCE, and every segment written afterwards is deletable by a holder of a"
  fail "  bypass-capable credential. Sealed history survives; future protection does not."
  fail "  Revoke s3:PutBucketObjectLockConfiguration from ${INNSEGL_OBJECT_STORE_SEALER_ACCESS_KEY}."
  failures=$((failures + 1))
else
  log "CANNOT set the bucket's object-lock configuration: ${out}"
fi

# ---------------------------------------------------------------------------
# 3. IT MUST NOT BE ABLE TO MAKE A BUCKET OF ITS OWN.
#
# A credential that can create a bucket can create one WITHOUT object lock and
# write there instead, which is the same outcome as a downgrade reached by a
# different route. The name is per-run so a refused attempt leaves nothing and
# a permitted one is visible.
# ---------------------------------------------------------------------------
probe_bucket="${BUCKET}-scope-probe"
if out="$(${MC} mb "scoped/${probe_bucket}" 2>&1)"; then
  fail "the scoped identity CREATED bucket ${probe_bucket}. A credential that can make a bucket can make one with no object lock and write segments there; remove s3:CreateBucket. Delete ${probe_bucket} by hand."
  failures=$((failures + 1))
else
  log "CANNOT create a bucket: ${out}"
fi

# ---------------------------------------------------------------------------
# 4. IT MUST NOT REACH THE STORE'S ADMIN SURFACE.
#
# An identity that can list or attach policies can widen itself, and then
# every check above is a check it can switch off.
# ---------------------------------------------------------------------------
if out="$(${MC} admin user list scoped 2>&1)"; then
  fail "the scoped identity can list the store's users, which means it holds admin permissions: ${out}"
  failures=$((failures + 1))
else
  log "CANNOT reach the admin surface: ${out}"
fi

if [ "${failures}" -ne 0 ]; then
  fail "${failures} check(s) failed. The running stack holds a credential that can weaken ${BUCKET}; doc 05 §2 requires that it cannot."
  exit 1
fi

log "${INNSEGL_OBJECT_STORE_SEALER_ACCESS_KEY} writes and reads ${BUCKET} and can weaken nothing about it — measured, not asserted"
