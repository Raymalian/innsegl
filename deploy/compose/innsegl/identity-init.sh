#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Generate THIS DEPLOYMENT's pseudonymisation secret (RM-084, #124).
#
# Runs to completion before innsegl-mcp starts, in the shape
# sigstore/bootstrap.sh established: one container, no network at all, the only
# place the secret is ever writable, and then it exits.
#
# WHY THIS EXISTS AT ALL
# ----------------------
# `innsegl serve` defaults to `-identity-mode pseudonymous`, and in that mode
# `internal/identity` refuses to start without a deployment secret of at least
# 16 bytes. #119 introduced that refusal deliberately — #116 chose it over a
# silent fall back to literal values, which would have read as "private" while
# every ticket reference went into Rekor — and the shipped compose stack was
# not updated to supply one. innsegl-mcp crashlooped on a clean `up` (#124).
#
# WHY IT IS NOT A CONSTANT IN innsegl.yml
# ---------------------------------------
# Because a pseudonym is `HMAC(deployment_secret, field ‖ ":" ‖ value)`, and
# the *deployment* half is the whole design (ADR-0041). A secret shipped in
# this repository would make `a7f3c91b` mean one particular task reference in
# EVERY installation on earth: anyone who resolved one mapping — by registering
# one run against their own copy of the stack — would hold it for everybody
# else's. That is strictly worse than not pseudonymising at all, because it
# looks private and is not.
#
# So each deployment mints its own, on its first `up`, into a volume nobody
# else can read.
#
# IDEMPOTENT, AND ONE-DIRECTIONALLY SO
# ------------------------------------
# An existing secret is LEFT ALONE. `docker compose down -v` is the only way to
# rotate it, exactly as for the Fulcio CA and the Rekor log key, and for a
# related reason: pseudonyms must be stable. ADR-0041 records that a rotation
# is survivable — resolution goes through the ledger's `run_registered` row and
# never through this key, so no history is orphaned — but it is not something
# to do by accident on every boot. A secret regenerated under a live run would
# derive a SECOND SPIFFE ID for a run id SPIRE already holds an entry for,
# which is IP §1's invariant broken by a privacy feature.
#
# THIRTY-TWO BYTES, RENDERED AS HEX
# ---------------------------------
# `internal/identity` measures the floor in bytes of the string it is given, so
# `openssl rand -hex 32` yields 64 characters carrying 256 bits — four times
# identity.MinSecretBytes. Hex rather than raw bytes because this value travels
# through a file, a volume and an operator's `cat`: base64 would need quoting
# and raw bytes would put NULs somewhere one day.

set -eu

# The path the secret lives at, named by the SAME variable `innsegl serve`
# reads it from. One name for one thing: the process that writes the file and
# the process that reads it cannot be configured to disagree.
SECRET_FILE="${INNSEGL_IDENTITY_SECRET_FILE:-}"

# The uid innsegl-mcp runs as (innsegl.yml: `user: "1000:1000"`, one of the
# five selectors register.sh registers). Docker creates a named volume
# root-owned, so what the MCP must read is chowned here rather than by running
# the MCP as root.
RUN_UID="${INNSEGL_IDENTITY_SECRET_UID:-1000}"
RUN_GID="${INNSEGL_IDENTITY_SECRET_GID:-1000}"

log()  { printf 'innsegl-identity-init: %s\n' "$*"; }
fail() { printf 'innsegl-identity-init: FAIL: %s\n' "$*" >&2; exit 1; }

[ -n "${SECRET_FILE}" ] \
  || fail 'INNSEGL_IDENTITY_SECRET_FILE is empty; innsegl.yml should have set it'

mkdir -p "$(dirname "${SECRET_FILE}")"

if [ -s "${SECRET_FILE}" ]; then
  log "a deployment secret is already present at ${SECRET_FILE}; leaving it alone"
  log 'rotating it would change every pseudonym this deployment mints from now on'
  log '(survivable — ADR-0041 resolves through the ledger row, not the key — but not by accident)'
else
  log "generating this deployment's pseudonymisation secret"
  # Written under a temporary name and renamed, so a reader sees either no
  # file or a complete one. A half-written secret would be a DIFFERENT key,
  # accepted silently by anything that only checks the length.
  tmp="${SECRET_FILE}.partial"
  openssl rand -hex 32 > "${tmp}"
  [ -s "${tmp}" ] || fail 'openssl rand produced nothing'
  mv "${tmp}" "${SECRET_FILE}"
  log "wrote ${SECRET_FILE}"
fi

# 0400 and owned by the reader. The one control on this file is the mount
# table — one writer, one reader, mounted read-only — the same control the
# Fulcio CA key and the Rekor log key have.
chmod 0400 "${SECRET_FILE}"
if [ "$(id -u)" = "0" ]; then
  chown "${RUN_UID}:${RUN_GID}" "${SECRET_FILE}"
else
  # A non-root run — a test running the shipped script directly — already owns
  # what it just created. Reported rather than silent, because in the container
  # this branch would mean the secret is unreadable by the MCP.
  log "not root, so ownership is left as $(id -u):$(id -g)"
fi

# The secret is NEVER printed. sigstore/bootstrap.sh ends by printing the Rekor
# log's PUBLIC key, which a verifier needs; there is no public half of this one,
# and a `docker compose logs` that leaked it would undo the whole exercise.
log 'ready'
ls -l "${SECRET_FILE}"
