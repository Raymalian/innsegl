#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Ask the server what the BACKUP credential can actually do (RM-146, #237,
# doc 05 §1). OPS-043.
#
# WHY THIS EXISTS AT ALL
# ----------------------
# It is verify-role.sh's shape and verify-reader-role.sh's argument, applied to
# the one role that is deliberately not like the others:
#
#     "appendonly.sql grants less. That is provisioning, and provisioning is a
#      claim."
#
# This role's provisioning is a claim with a twist in it. db-init.sh applies
# internal/api/readonly.sql to it — the same file the reader gets, so the
# ledger grants cannot drift between them — and then grants CREATEDB, which
# that file's last line has just revoked. The end state is what matters and the
# order is what produces it, so the end state is what this measures.
#
# THE POSITIVE CASE IS FIRST, ON PURPOSE
# --------------------------------------
# A scope too narrow to take a backup is worse than the exposure it closes: it
# fails at 3am, in a service nobody is watching, and the first anyone knows is
# that there are no backups. So this asks the credential to do the backup's
# WHOLE job — read the ledger, create a database, write into it, drop it —
# before it asks whether the live ledger is still closed to it.
#
# WHY IT CLASSIFIES BY SQLSTATE AND NOT BY SUCCESS
# ------------------------------------------------
# verify-reader-role.sh's table, which holds here unchanged:
#
#   role    statement                    result
#   backup  INSERT INTO innsegl.events   ERROR 42501  permission denied (ACL)
#   owner   INSERT INTO innsegl.events   ERROR IN002  the chain-link trigger
#
# BOTH are refused. Only one is refused BY PRIVILEGE. A check that asked "did
# it fail?" would pass the database owner, which is the credential the gate
# exists to catch. So only 42501 and 25006 count as refusals.
#
# THE READ-ONLY DEFAULT IS NOT THE BOUNDARY. readonly.sql leaves this role with
# default_transaction_read_only = on, and the restore turns it off for its own
# session — which it must, to write into a database it owns. So every negative
# probe below issues SET TRANSACTION READ WRITE first: if the ACL were not the
# real boundary, that one statement would be the whole of the bypass, and this
# script would find it.
#
# It leaves nothing behind: every ledger probe runs in a transaction that is
# rolled back, and the scratch database is dropped on every exit path.

set -eu

log()  { printf 'verify-backup-role: %s\n' "$*"; }
fail() { printf 'verify-backup-role: FAIL: %s\n' "$*" >&2; }

: "${PGHOST:?verify-backup-role: PGHOST must name the ledger}"
: "${PGDATABASE:?verify-backup-role: PGDATABASE must name the ledger database}"
: "${INNSEGL_BACKUP_PASSWORD:?verify-backup-role: INNSEGL_BACKUP_PASSWORD must be set}"
ROLE="${INNSEGL_BACKUP_ROLE:-innsegl_backup}"
PORT="${PGPORT:-5432}"

# Everything below connects AS THE ROLE UNDER TEST, never as the owner.
export PGPASSWORD="${INNSEGL_BACKUP_PASSWORD}"
backup() {
  psql -X -q -A -t -U "${ROLE}" -h "${PGHOST}" -p "${PORT}" -d "${PGDATABASE}" "$@"
}
backup_in() {
  db="$1"; shift
  psql -X -q -A -t -U "${ROLE}" -h "${PGHOST}" -p "${PORT}" -d "${db}" "$@"
}

# THE READ-ONLY DEFAULT IS A SESSION DEFAULT, NOT A BOUNDARY, and the positive
# probes have to turn it off exactly as the real backup does.
#
# MEASURED: readonly.sql leaves this role with default_transaction_read_only=on,
# so CREATE DATABASE is refused with 25006 (read_only_sql_transaction) even
# though pg_roles reports rolcreatedb=t. That refusal says nothing about the
# privilege, and reading it as one sent the first run of this script looking for
# a missing GRANT that was present all along.
#
# Turning it off is safe precisely because it is not the boundary: the negative
# probes below issue SET TRANSACTION READ WRITE and are STILL refused 42501, so
# what stops this credential writing the ledger is the ACL. Off, it can write
# only where it owns — a database it just created.
backup_rw() {
  PGOPTIONS='-c default_transaction_read_only=off' \
    psql -X -q -A -t -U "${ROLE}" -h "${PGHOST}" -p "${PORT}" -d "${PGDATABASE}" "$@"
}
backup_in_rw() {
  db="$1"; shift
  PGOPTIONS='-c default_transaction_read_only=off' \
    psql -X -q -A -t -U "${ROLE}" -h "${PGHOST}" -p "${PORT}" -d "${db}" "$@"
}

SCRATCH="innsegl_backup_probe_$$"
cleanup() {
  PGOPTIONS='-c default_transaction_read_only=off' \
    psql -X -q -A -t -U "${ROLE}" -h "${PGHOST}" -p "${PORT}" -d "${PGDATABASE}" \
      -c "DROP DATABASE IF EXISTS ${SCRATCH}" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

probe_state() {
  out="$(backup -v ON_ERROR_STOP=0 \
           -c '\set VERBOSITY verbose' \
           -c "BEGIN; SET TRANSACTION READ WRITE; $1; ROLLBACK;" 2>&1 || true)"
  printf '%s' "${out}" |
    sed -n 's/^ERROR:[[:space:]]*\([0-9A-Za-z][0-9A-Za-z][0-9A-Za-z][0-9A-Za-z][0-9A-Za-z]\):.*/\1/p' |
    head -n 1
}

FAILURES=0

expect_refused() {
  state="$(probe_state "$2")"
  case "${state}" in
    42501|25006) log "REFUSED  $1 (${state})" ;;
    '')          fail "ALLOWED  $1 — the statement SUCCEEDED. This credential is held by a service that is up as long as the stack is"
                 FAILURES=$((FAILURES + 1)) ;;
    *)           fail "ALLOWED  $1 — the ACL permitted it; it failed for another reason (${state}). A refusal that is not by privilege is one ALTER TABLE ... DISABLE TRIGGER away from no refusal at all, and it is the refusal the database OWNER also gets"
                 FAILURES=$((FAILURES + 1)) ;;
  esac
}

log "measuring ${ROLE} at ${PGHOST}:${PORT}/${PGDATABASE}"

# ---------------------------------------------------------------------------
# Who the session is. A SUPERUSER is bound by no ACL.
# ---------------------------------------------------------------------------
identity="$(backup -c "SELECT current_user || ' ' || current_setting('is_superuser')")" || {
  fail "the credential could not connect at all: check INNSEGL_BACKUP_PASSWORD and pg_hba"
  exit 1
}
who="$(printf '%s' "${identity}" | cut -d' ' -f1)"
super="$(printf '%s' "${identity}" | cut -d' ' -f2)"
log "connected as ${who}, is_superuser=${super}"
if [ "${super}" != "off" ]; then
  fail "${who} is a SUPERUSER. No ACL binds a superuser, so nothing below would mean anything"
  FAILURES=$((FAILURES + 1))
fi
if [ "${who}" != "${ROLE}" ]; then
  fail "connected as ${who}, expected ${ROLE}"
  FAILURES=$((FAILURES + 1))
fi

# ---------------------------------------------------------------------------
# 1. THE WHOLE JOB. Read the ledger, own a database, write into it, drop it.
# ---------------------------------------------------------------------------
if backup -c "SELECT count(*) FROM innsegl.events" >/dev/null 2>&1; then
  log "ALLOWED  read innsegl.events (the dump)"
else
  fail "REFUSED  read innsegl.events — this credential cannot take a backup at all"
  FAILURES=$((FAILURES + 1))
fi

# CREATE DATABASE cannot run inside a transaction block, so this one is not a
# rolled-back probe; it is the real thing, and it is cleaned up on every exit.
if backup_rw -v ON_ERROR_STOP=1 -c "CREATE DATABASE ${SCRATCH}" >/dev/null 2>&1; then
  log "ALLOWED  create a throwaway database (the restore)"
else
  fail "REFUSED  create a throwaway database — the restore half cannot run, so a dump could only ever be a belief. Is the CREATEDB in db-init.sh applied AFTER readonly.sql, whose last line revokes it?"
  FAILURES=$((FAILURES + 1))
fi

if backup_in_rw "${SCRATCH}" -v ON_ERROR_STOP=1 \
     -c "CREATE TABLE probe(x int)" -c "INSERT INTO probe VALUES (1)" \
     >/dev/null 2>&1; then
  log "ALLOWED  write inside the throwaway database"
else
  fail "REFUSED  write inside the throwaway database — a restore writes, so this is the same failure as not having the database"
  FAILURES=$((FAILURES + 1))
fi

if backup_rw -v ON_ERROR_STOP=1 -c "DROP DATABASE ${SCRATCH}" >/dev/null 2>&1; then
  log "ALLOWED  drop the throwaway database"
else
  fail "REFUSED  drop the throwaway database — every run would leave one behind"
  FAILURES=$((FAILURES + 1))
fi

# ---------------------------------------------------------------------------
# 2. AND THE LIVE LEDGER IS STILL CLOSED TO IT.
# ---------------------------------------------------------------------------
expect_refused "INSERT INTO innsegl.events" \
  "INSERT INTO innsegl.events (event_id) VALUES ('00000000-0000-0000-0000-000000000000')"
expect_refused "UPDATE innsegl.events" \
  "UPDATE innsegl.events SET event_hash = event_hash"
expect_refused "DELETE FROM innsegl.events" \
  "DELETE FROM innsegl.events"
expect_refused "TRUNCATE innsegl.events" \
  "TRUNCATE innsegl.events"
expect_refused "CREATE TABLE in the ledger" \
  "CREATE TABLE innsegl.probe_backup_role (x int)"

if [ "${FAILURES}" -ne 0 ]; then
  fail "${FAILURES} check(s) failed for ${ROLE}"
  exit 1
fi
log "OK — ${ROLE} can take and verify a backup, and cannot write the ledger"
