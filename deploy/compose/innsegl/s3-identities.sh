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
# bucket, and RM-144 (#228) is the issue that made it so. Up to 4.46 this
# store's permission model had no separate action for setting a bucket's
# object-lock configuration: an identity granted a bucket-wide `Write` could
# set it, and so downgrade the default rule from COMPLIANCE to GOVERNANCE.
#
# SINCE 4.48 (#451) BOTH LOCK-CONFIGURATION CALLS HAVE THEIR OWN ACTION:
# GetBucketObjectLockConfiguration and PutBucketObjectLockConfiguration. The
# scoped identity is granted the first and never the second, so the downgrade
# is now withheld by name. THE PREFIX STAYS: it also bounds WHERE the sealer
# may write, which no action replaces.
#
# Measured on the pinned image, same bucket, one identity (OPS-025..027):
#
#     Read:<bucket>                      GetObject                    allowed
#     GetBucketObjectLockConfiguration:<bucket>
#                                        GetObjectLockConfiguration   allowed
#     GetObjectRetention:<bucket>        GetObjectRetention           allowed
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
# THE TWO LOCK READS ARE GRANTED BY NAME because 4.48 stopped answering them
# under `Read` (measured: AccessDenied for the 4.46 grant set). The sealer
# reads the bucket's rule, and SEG-005's canary reads the rule and the probe's
# retention. Reading is not a way to weaken
# anything; writing the bucket's configuration is the thing being withheld.

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
        "GetBucketObjectLockConfiguration:${BUCKET}",
        "GetObjectRetention:${BUCKET}",
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

# THE OBJECT STORE'S PER-HOST KEY (#451). S3's gRPC port requires it, and so
# does the Filer's. It is generated here once, from /dev/urandom, and kept:
# this volume persists across restarts and updates, and only this one-shot and
# the object store mount it. object-store-start.sh refuses to start the store
# without it. No shipped file carries a value for it.
#
# $INNSEGL_OBJECT_FILER_JWT_KEY, when set, is used instead and replaces the
# file. Unset again later, the file keeps the last key it held.
KEY_FILE="${INNSEGL_OBJECT_FILER_JWT_KEY_FILE:-$(dirname -- "${OUT}")/filer-jwt.key}"
KEY_BYTES=32 # of randomness; 64 hex characters
key_tmp="${KEY_FILE}.partial"
if [ -n "${INNSEGL_OBJECT_FILER_JWT_KEY:-}" ]; then
  [ "${#INNSEGL_OBJECT_FILER_JWT_KEY}" -ge 48 ] \
    || fail "\$INNSEGL_OBJECT_FILER_JWT_KEY is ${#INNSEGL_OBJECT_FILER_JWT_KEY} characters; use at least 48, or unset it to have one generated"
  printf '%s\n' "${INNSEGL_OBJECT_FILER_JWT_KEY}" > "${key_tmp}"
  key_source="the operator's \$INNSEGL_OBJECT_FILER_JWT_KEY"
elif [ -s "${KEY_FILE}" ]; then
  key_source="kept from an earlier run"
else
  # 32 bytes from the kernel's CSPRNG, hex encoded: 64 characters.
  head -c "${KEY_BYTES}" /dev/urandom | od -An -v -tx1 | tr -d ' \n' > "${key_tmp}"
  printf '\n' >> "${key_tmp}"
  key_source="generated"
fi
if [ -f "${key_tmp}" ]; then
  [ "$(tr -d '\n' < "${key_tmp}" | wc -c)" -ge 48 ] || fail "the object store key came out short"
  # Root-owned and 0400: the start script reads it as root, before the store
  # drops to its own user, and nothing else needs it.
  chmod 0400 "${key_tmp}"
  mv -f "${key_tmp}" "${KEY_FILE}"
fi

log "wrote ${OUT}"
log "object store key at ${KEY_FILE}: ${key_source}"
log "  innsegl-root   ${ROOT_USER}: Admin, Read, Write, List, Tagging — the server and the one-time init, nothing that stays up"
log "  innsegl-sealer ${SEALER_USER}: Read:${BUCKET}, GetBucketObjectLockConfiguration:${BUCKET}, GetObjectRetention:${BUCKET}, List:${BUCKET}, Write:${BUCKET}/${PREFIX}*, Write:${BUCKET}/${CANARY_PREFIX}*"
log "  the scoped identity may write segments and probes and may weaken nothing; innsegl/verify-object-scope.sh measures that"
