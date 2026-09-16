#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# The S3 gateway's identity file (RM-143, #227; RM-144, #228; AB-17).
#
# WHY THIS EXISTS AT ALL
# ----------------------
# This object store ships NO DEFAULT CREDENTIALS. Started without an identity
# file every signed request is refused with
#
#     Signed request requires setting up SeaweedFS S3 authentication
#
# which arrives at the caller as AccessDenied on a write — indistinguishable,
# from the outside, from object lock doing its job. A deployment can therefore
# look like it is enforcing SEG-005 while nothing has ever been written to it.
# So the gateway is given a file, and it is given one that this file's own
# compose service interpolates rather than one checked in with values in it.
#
# WHY A ONE-SHOT AND NOT A MOUNT
# ------------------------------
# The file carries this deployment's two S3 secrets. innsegl/identity-init.sh
# made the same call for the same reason and its comment is the one to read:
# a container that generates a file full of secrets needs to reach nothing, so
# it reaches nothing (`network_mode: none`), and it is the only container that
# mounts the volume rw.
#
# It rewrites the file on every boot rather than leaving an existing one alone,
# and that is the opposite of identity-init.sh's choice deliberately. The
# pseudonymisation secret is key material and rotating it has consequences
# (ADR-0041). This is not key material: it is deploy/compose/innsegl.yml's
# access-control decision rendered into the format the gateway reads. A file
# left alone would be a deployment whose scope is whatever it was the first
# time it ever came up.
#
# WHAT THE SCOPE IS, AND WHY IT IS A PREFIX
# -----------------------------------------
# doc 05 §2 requires the running stack to hold no identity that may weaken the
# bucket, and RM-144 (#228) is the issue that made it so. On THIS store the
# permission model has no separate action for setting a bucket's object-lock
# configuration: measured on the pinned image, an identity granted a
# bucket-wide `Write` may set it, and may therefore downgrade the default rule
# from COMPLIANCE to GOVERNANCE.
#
# What it does have is PREFIX-SCOPED actions, and they are enough. Measured,
# same image, same bucket, one identity:
#
#     Read:<bucket>                      GetObjectLockConfiguration   allowed
#     List:<bucket>                      ListObjectVersions           allowed
#     Write:<bucket>/<prefix>*           PutObject under the prefix   allowed
#                                        PutObject anywhere else      REFUSED
#                                        PutObjectLockConfiguration   REFUSED
#                                        CreateBucket                 REFUSED
#                                        DeleteBucket                 REFUSED
#                                        PutBucketVersioning          REFUSED
#                                        PutBucketPolicy              REFUSED
#                                        PutBucketLifecycle           REFUSED
#                                        PutObjectRetention           REFUSED
#                                        DeleteObjectVersion (bypass) REFUSED
#
# and SEG-005's whole canary passes on it. innsegl/verify-object-scope.sh asks
# the server the same questions after the fact, because a file is provisioning
# and provisioning is a claim.
#
# READ IS BUCKET-WIDE AND WRITE IS NOT, which looks asymmetric and is the
# measurement: a prefix-scoped Read is also refused GetObjectLockConfiguration,
# and SEG-005's canary reads exactly that on every scheduled run. Reading is
# not a way to weaken anything; writing the bucket's configuration is the only
# thing being withheld, so Read is granted where it has to be and Write is
# granted only where segments and probes go.

set -eu

log()  { printf 's3-identities: %s\n' "$*"; }
fail() { printf 's3-identities: FAIL: %s\n' "$*" >&2; exit 1; }

OUT="${INNSEGL_S3_IDENTITIES_FILE:?s3-identities: INNSEGL_S3_IDENTITIES_FILE must name the file to write}"

: "${INNSEGL_OBJECT_STORE_ACCESS_KEY:?s3-identities: INNSEGL_OBJECT_STORE_ACCESS_KEY must be set}"
: "${INNSEGL_OBJECT_STORE_SECRET_KEY:?s3-identities: INNSEGL_OBJECT_STORE_SECRET_KEY must be set}"

ROOT_USER="${INNSEGL_OBJECT_STORE_ACCESS_KEY}"
ROOT_PASSWORD="${INNSEGL_OBJECT_STORE_SECRET_KEY}"
BUCKET="${INNSEGL_OBJECT_STORE_BUCKET:-innsegl-segments}"
PREFIX="${INNSEGL_OBJECT_STORE_PREFIX:-segments/}"

# internal/segment/worm.go's canaryProbePrefix, and the reason it is named here
# rather than folded into $INNSEGL_OBJECT_STORE_PREFIX: SEG-005's probes are
# deliberately OUTSIDE the segment namespace, and scripts/backup-ledger.sh
# fetches the segment prefix recursively. Probes under it would end up in every
# ledger backup. So the scoped identity gets two write grants, not one, and
# test/deploy asserts this string still matches the Go constant.
CANARY_PREFIX="innsegl-worm-canary/"

# DERIVED WHEN UNSET, NOT REQUIRED — deploy/compose/innsegl.yml derives the
# same value from the same expression. An operator upgrading an existing
# deployment set a root credential once and never heard of #228; a narrowing
# that had to be configured before the stack came up would be switched off
# rather than adopted.
SEALER_USER="${INNSEGL_OBJECT_STORE_SEALER_ACCESS_KEY:-innsegl-sealer}"
SEALER_PASSWORD="${INNSEGL_OBJECT_STORE_SEALER_SECRET_KEY:-${ROOT_PASSWORD}-sealer}"

[ "${SEALER_USER}" != "${ROOT_USER}" ] \
  || fail "the scoped identity \$INNSEGL_OBJECT_STORE_SEALER_ACCESS_KEY is the store's root account (${SEALER_USER}). The whole point is that they are two identities; pick another name"

# S3 secrets have a length floor and an unhelpful server-side error when they
# miss it. Refusing here names the variable instead.
for secret in "${ROOT_PASSWORD}" "${SEALER_PASSWORD}"; do
  case "${secret}" in
    ????????*) : ;;
    *) fail "an S3 secret is shorter than eight characters. Set \$INNSEGL_OBJECT_STORE_SECRET_KEY, and \$INNSEGL_OBJECT_STORE_SEALER_SECRET_KEY if it is not derived from it" ;;
  esac
done

# A bucket name with a quote or a backslash in it would otherwise close the
# JSON string early and the gateway would start with whatever the fragment
# happened to parse as — which is a scope nobody chose. S3 bucket names cannot
# contain either, so this refuses rather than escaping: a name that needs
# escaping here is a name the store will reject anyway, and failing now names
# the variable.
for value in "${ROOT_USER}" "${ROOT_PASSWORD}" "${SEALER_USER}" "${SEALER_PASSWORD}" "${BUCKET}" "${PREFIX}"; do
  case "${value}" in
    *'"'*|*'\'*) fail "a value for the identity file contains a quote or a backslash, which cannot be written into it safely: ${value}" ;;
  esac
done

mkdir -p "$(dirname -- "${OUT}")"

# The file is written to a temporary name and moved into place, so a gateway
# restarting at the wrong moment never reads half a file and starts with half a
# scope.
tmp="${OUT}.partial"
cat > "${tmp}" <<IDENTITIES
{
  "identities": [
    {
      "name": "innsegl-root",
      "credentials": [{"accessKey": "${ROOT_USER}", "secretKey": "${ROOT_PASSWORD}"}],
      "actions": ["Admin", "Read", "Write", "List", "Tagging"]
    },
    {
      "name": "innsegl-sealer",
      "credentials": [{"accessKey": "${SEALER_USER}", "secretKey": "${SEALER_PASSWORD}"}],
      "actions": [
        "Read:${BUCKET}",
        "List:${BUCKET}",
        "Write:${BUCKET}/${PREFIX}*",
        "Write:${BUCKET}/${CANARY_PREFIX}*"
      ]
    }
  ]
}
IDENTITIES

# THE GATEWAY DOES NOT RUN AS ROOT AND THIS ONE-SHOT DOES. The store's image
# entrypoint drops privileges to its own `seaweed` user with su-exec; this
# script overrides the entrypoint so that it can write the volume, and
# therefore runs as root. A 0400 root-owned file is then unreadable by the
# process that has to read it — measured, and the gateway crash-loops with
#
#     fail to read /run/innsegl/s3/identities.json: permission denied
#
# which is not a message about credentials at all and is easy to read as one.
if chown seaweed:seaweed "${tmp}" 2>/dev/null; then
  chmod 0400 "${tmp}"
else
  # A different image, or no such user. The file still has to be readable by
  # whoever runs the gateway, and the control on it is the VOLUME rather than
  # the mode: exactly two containers mount it, this one rw and the gateway ro.
  chmod 0444 "${tmp}"
fi
mv -f "${tmp}" "${OUT}"

log "wrote ${OUT}"
log "  innsegl-root   ${ROOT_USER}: Admin, Read, Write, List, Tagging — the server and the one-time init, nothing that stays up"
log "  innsegl-sealer ${SEALER_USER}: Read:${BUCKET}, List:${BUCKET}, Write:${BUCKET}/${PREFIX}*, Write:${BUCKET}/${CANARY_PREFIX}*"
log "  the scoped identity may write segments and probes and may weaken nothing; innsegl/verify-object-scope.sh measures that"
