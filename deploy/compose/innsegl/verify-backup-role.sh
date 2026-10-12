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
# db-init.sh applies internal/api/readonly.sql to it — the same file the reader
# gets, so the ledger grants cannot drift between them — and ends with
# NOCREATEDB (RM-356, #604): the backup restores each dump into a private
# Postgres of its own, so it needs no database on this server.
#
# THE POSITIVE CASE IS FIRST, ON PURPOSE
# --------------------------------------
# A scope too narrow to take a backup is worse than the exposure it closes: it
# fails at 3am, in a service nobody is watching, and the first anyone knows is
# that there are no backups. So this asks the credential to read the ledger
# before it asks whether creating a database and writing the ledger are closed
# to it.
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
# default_transaction_read_only = on, and any session can turn it off. So every
# negative probe below issues SET TRANSACTION READ WRITE first: if the ACL were
# not the real boundary, that one statement would be the whole of the bypass,
# and this script would find it.
#
# It leaves nothing behind: every ledger probe runs in a transaction that is
# rolled back, and a database the CREATEDB probe made is dropped on every exit
# path.

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
# THE READ-ONLY DEFAULT IS A SESSION DEFAULT, NOT A BOUNDARY, and the CREATEDB
# probe turns it off before it asks.
#
# MEASURED: with default_transaction_read_only=on, CREATE DATABASE is refused
# with 25006 (read_only_sql_transaction) even when pg_roles reports
# rolcreatedb=t. That refusal says nothing about the privilege, so the probe
# runs with it off and accepts only 42501.
backup_rw() {
  PGOPTIONS='-c default_transaction_read_only=off' \
    psql -X -q -A -t -U "${ROLE}" -h "${PGHOST}" -p "${PORT}" -d "${PGDATABASE}" "$@"
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
# 1. THE WHOLE JOB: read the ledger. 2. No database of its own here.
# ---------------------------------------------------------------------------
if backup -c "SELECT count(*) FROM innsegl.events" >/dev/null 2>&1; then
  log "ALLOWED  read innsegl.events (the dump)"
else
  fail "REFUSED  read innsegl.events — this credential cannot take a backup at all"
  FAILURES=$((FAILURES + 1))
fi

# NO DATABASE OF ITS OWN ON THIS SERVER (RM-356, #604). The backup restores into
# a private Postgres it starts itself, so CREATE DATABASE here must be refused
# by privilege (42501), with the read-only default off as the restore once
# turned it off. CREATE DATABASE cannot run in a transaction block, so this is
# the real statement; if it ever succeeds, the cleanup drops what it made.
createdb_out="$(backup_rw -v ON_ERROR_STOP=1 -c '\set VERBOSITY verbose' \
  -c "CREATE DATABASE ${SCRATCH}" 2>&1 || true)"
createdb_state="$(printf '%s' "${createdb_out}" |
  sed -n 's/^ERROR:[[:space:]]*\([0-9A-Za-z][0-9A-Za-z][0-9A-Za-z][0-9A-Za-z][0-9A-Za-z]\):.*/\1/p' |
  head -n 1)"
if [ "${createdb_state}" = "42501" ]; then
  log "REFUSED  create a database (42501)"
else
  fail "ALLOWED  create a database (${createdb_state:-it succeeded}) — this role needs no CREATEDB: the backup restores into a private Postgres of its own. Run db-init.sh again; it ends with ALTER ROLE ... NOCREATEDB"
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
log "OK — ${ROLE} can read the ledger, and can neither create a database nor write the ledger"
