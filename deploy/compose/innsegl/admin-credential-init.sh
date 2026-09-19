#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Mint THIS DEPLOYMENT's identity-lifecycle signing key, once (#264).
#
# Runs to completion before innsegl-mcp starts, in the shape
# innsegl/identity-init.sh established: one container, no network at all, the
# only place either volume is writable, and then it exits.
#
# WHY THIS EXISTS AT ALL
# ----------------------
# The listener split moves the six tools that CREATE and DESTROY identities
# onto their own port, and nothing authenticated a caller on it. Any process
# that could reach it could mint a run — doc 04's AB-13 and AB-15 — and the
# note above INNSEGL_MCP_ADMIN_LISTEN said not to turn the split on until
# something was arranged to do the registering, while it was on.
#
# `innsegl serve` now refuses to start with that listener enabled and no key
# set to verify credentials against, because a deployment that believes it is
# authenticated and is not is worse than one that knows it is open. This is
# what makes a clean `docker compose up` need no manual step.
#
# TWO FILES, TWO VOLUMES
# ----------------------
# The PUBLIC key set is what innsegl-mcp reads, and it is the only one of the
# two that service mounts (E8: the MCP holds no key material). The PRIVATE
# signing key stays on a volume nothing else in this stack mounts at all — a
# process that could read it could mint its own admission to the listener the
# key exists to protect.
#
# IDEMPOTENT, AND ONE-DIRECTIONALLY SO
# ------------------------------------
# An existing signing key is LEFT ALONE. Regenerating one on every boot would
# refuse every credential an operator had already minted, and would do it
# silently. `docker compose down -v` is the only way to rotate it here, exactly
# as for the pseudonymisation secret and the Fulcio CA key.
#
# Rotating deliberately is `innsegl admin-credential keygen` with a new key
# path against the same key set: the public half is ADDED, so the outgoing key
# keeps verifying until its entry is removed by hand, and no credential already
# in flight is refused.
#
# NOTHING TO DO WHEN THE SPLIT IS OFF
# -----------------------------------
# Both paths come from innsegl.yml anchors that expand to nothing unless
# INNSEGL_MCP_ADMIN_LISTEN is set. This service still runs — a conditional
# service would be a second place the split's state is decided — and says so.

set -eu

JWKS_FILE="${INNSEGL_MCP_ADMIN_JWKS_FILE:-}"
KEY_FILE="${INNSEGL_ADMIN_CREDENTIAL_KEY_FILE:-}"

# The uid innsegl-mcp runs as (innsegl.yml: `user: "1000:1000"`, one of the
# five selectors register.sh registers). Docker creates a named volume
# root-owned, so what the MCP must read is chowned here rather than by running
# the MCP as root.
RUN_UID="${INNSEGL_ADMIN_CREDENTIAL_UID:-1000}"
RUN_GID="${INNSEGL_ADMIN_CREDENTIAL_GID:-1000}"

log()  { printf 'innsegl-admin-credential-init: %s\n' "$*"; }
fail() { printf 'innsegl-admin-credential-init: FAIL: %s\n' "$*" >&2; exit 1; }

if [ -z "${JWKS_FILE}" ] && [ -z "${KEY_FILE}" ]; then
  log 'the identity lifecycle is not on its own listener, so there is nothing to authenticate'
  log 'set INNSEGL_MCP_ADMIN_LISTEN to split it out, and this will mint the keys on the next up'
  exit 0
fi

# One of the two empty is the anchors having been edited apart. Refused rather
# than half-configured: a key set with no signing key admits nothing, and a
# signing key with no key set is admitted by nobody.
[ -n "${JWKS_FILE}" ] || fail 'INNSEGL_MCP_ADMIN_JWKS_FILE is empty while the key path is not'
[ -n "${KEY_FILE}" ]  || fail 'INNSEGL_ADMIN_CREDENTIAL_KEY_FILE is empty while the key set path is not'

mkdir -p "$(dirname "${JWKS_FILE}")" "$(dirname "${KEY_FILE}")"

if [ -s "${KEY_FILE}" ]; then
  log "a signing key is already present at ${KEY_FILE}; leaving it alone"
  log 'regenerating it would refuse every credential already minted under it'
  log 'to rotate: innsegl admin-credential keygen -key <new> -jwks <this set> (both then verify)'
else
  log "minting this deployment's identity-lifecycle signing key"
  # The shipped command, not a second implementation of the format: it writes
  # the private key and ADDS the public half to the key set, which is the same
  # operation an operator performs to rotate.
  innsegl admin-credential keygen -key "${KEY_FILE}" -jwks "${JWKS_FILE}" \
    || fail 'innsegl admin-credential keygen failed'
  log "wrote ${KEY_FILE} (private) and ${JWKS_FILE} (public)"
fi

[ -s "${JWKS_FILE}" ] || fail "${JWKS_FILE} holds no key set; innsegl-mcp would refuse to start"

# 0400 on the private half, owned by nobody the MCP runs as — it does not mount
# this volume at all. The key set is public and is chowned to the reader.
chmod 0400 "${KEY_FILE}"
chmod 0444 "${JWKS_FILE}"
if [ "$(id -u)" = "0" ]; then
  chown "${RUN_UID}:${RUN_GID}" "${JWKS_FILE}"
else
  # A non-root run — a test running the shipped script directly — already owns
  # what it just created. Reported rather than silent, because in the container
  # this branch would mean the key set is unreadable by the MCP.
  log "not root, so ownership is left as $(id -u):$(id -g)"
fi

# The SIGNING KEY is never printed. The key id is: it names a public
# verification key and says nothing about who holds the private half, and it is
# what an operator matches against the key set when a rotation goes wrong.
log 'ready'
ls -l "${JWKS_FILE}"
