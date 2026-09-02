#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Ask the server what the append-only credential can actually do (RM-076,
# #109, doc 05 §1).
#
# WHY THIS EXISTS AT ALL
# ----------------------
# appendonly.sql grants less. That is provisioning, and provisioning is a
# claim. internal/api/readonly.go makes the argument for the other half and it
# is the argument this file implements:
#
#     "The assertion matters more than the provisioning. A role is provisioned
#      once and then lives in somebody's deployment; a later GRANT by an
#      operator who wanted to 'just fix one thing' is invisible to any amount
#      of code review. So Open asks the server, every time it starts, whether
#      the credential it was handed can write — and refuses to come up if it
#      can."
#
# db-init.sh runs this at the end of provisioning and the compose stack gates
# `innsegl-mcp` on it, so the MCP does not start behind a role nobody measured.
# `make innsegl-verify` runs it against a live stack.
#
# WHY IT CLASSIFIES BY SQLSTATE AND NOT BY SUCCESS
# ------------------------------------------------
# MEASURED on postgres:16, against the shipped migrations:
#
#   role      statement                    result
#   appender  UPDATE innsegl.events        ERROR 42501  permission denied (ACL)
#   appender  DELETE FROM innsegl.events   ERROR 42501  permission denied (ACL)
#   appender  TRUNCATE innsegl.events      ERROR 42501  permission denied (ACL)
#   owner     UPDATE innsegl.events        ERROR IN001  the append-only trigger
#   owner     DELETE FROM innsegl.events   ERROR IN001  the append-only trigger
#   owner     TRUNCATE innsegl.events      ERROR IN001  the append-only trigger
#
# BOTH roles are refused. Only one is refused BY PRIVILEGE. A check that asked
# "did the statement fail?" would pass the database owner — the exact
# credential #109 is about — because migration 0001's trigger refuses it too.
# So the only refusals that count here are 42501 (insufficient_privilege) and
# 25006 (read_only_sql_transaction). Anything else, INCLUDING SUCCESS, means
# the ACL let the statement through.
#
# It writes nothing: every probe runs inside a transaction that is rolled back,
# and the probes a writing credential would be ALLOWED to run are exactly the
# ones whose effect is discarded. Running it against a production ledger is
# safe and is the intended use — that is the point of asking the server rather
# than reading the manifest.

set -eu

log()  { printf 'verify-role: %s\n' "$*"; }
fail() { printf 'verify-role: FAIL: %s\n' "$*" >&2; }

: "${PGHOST:?verify-role: PGHOST must name the ledger}"
: "${PGDATABASE:?verify-role: PGDATABASE must name the ledger database}"
: "${INNSEGL_APPENDER_PASSWORD:?verify-role: INNSEGL_APPENDER_PASSWORD must be set}"
ROLE="${INNSEGL_APPENDER_ROLE:-innsegl_appender}"

# Everything below connects AS THE ROLE UNDER TEST, never as the owner.
export PGPASSWORD="${INNSEGL_APPENDER_PASSWORD}"
appender() {
  psql -X -q -A -t -U "${ROLE}" -h "${PGHOST}" -p "${PGPORT:-5432}" \
    -d "${PGDATABASE}" "$@"
}

# probe_state runs one statement in a transaction it always rolls back and
# prints the SQLSTATE, or the empty string if the statement succeeded.
#
# `\set VERBOSITY verbose` is what puts the SQLSTATE on the ERROR line;
# without it psql prints only the message and the code has to be guessed from
# English text that changes between releases and locales.
#
# `SET TRANSACTION READ WRITE` runs first so that a refusal below is the ACL's
# and not default_transaction_read_only's — a setting any session can turn off
# for itself, and therefore not a boundary.
probe_state() {
  out="$(appender -v ON_ERROR_STOP=0 \
           -c '\set VERBOSITY verbose' \
           -c "BEGIN; SET TRANSACTION READ WRITE; $1; ROLLBACK;" 2>&1 || true)"
  printf '%s' "${out}" |
    sed -n 's/^ERROR:[[:space:]]*\([0-9A-Za-z][0-9A-Za-z][0-9A-Za-z][0-9A-Za-z][0-9A-Za-z]\):.*/\1/p' |
    head -n 1
}

FAILURES=0

# expect_refused NAME SQL — the ACL must stop this.
expect_refused() {
  state="$(probe_state "$2")"
  case "${state}" in
    42501|25006) log "REFUSED  $1 (${state})" ;;
    '')          fail "ALLOWED  $1 — the statement SUCCEEDED"
                 FAILURES=$((FAILURES + 1)) ;;
    *)           fail "ALLOWED  $1 — the ACL permitted it; it failed for another reason (${state}). A refusal that is not by privilege is one ALTER TABLE ... DISABLE TRIGGER away from no refusal at all"
                 FAILURES=$((FAILURES + 1)) ;;
  esac
}

# expect_allowed NAME SQL — the ACL must NOT stop this. A statement the ledger's
# own triggers then refuse still counts as allowed: the trigger is the ledger's
# guarantee, not this credential's.
expect_allowed() {
  state="$(probe_state "$2")"
  case "${state}" in
    42501|25006) fail "REFUSED  $1 (${state}) — the MCP could not serve one call under this role"
                 FAILURES=$((FAILURES + 1)) ;;
    *)           log "ALLOWED  $1" ;;
  esac
}

log "measuring ${ROLE} at ${PGHOST}:${PGPORT:-5432}/${PGDATABASE}"

# ---------------------------------------------------------------------------
# Who the session is. A SUPERUSER is bound by no ACL, so every probe below
# would pass it and mean nothing.
# ---------------------------------------------------------------------------
identity="$(appender -c "SELECT current_user || ' ' || current_setting('is_superuser')")" || {
  fail "the credential could not connect at all: check INNSEGL_APPENDER_PASSWORD and pg_hba"
  exit 1
}
who="${identity% *}"
super="${identity#* }"
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
# What it must be able to do. A role that cannot append is not a failure of
# least privilege, it is an outage: every MCP tool but get_credential appends
# first (I3), so a server behind it would answer every call with
# LEDGER_UNAVAILABLE while looking healthy.
# ---------------------------------------------------------------------------
expect_allowed "INSERT innsegl.events (append to the chain)" "INSERT INTO innsegl.events
    (chain_position, event_id, event_hash, prev_event_hash, event_type,
     source, ts, canonical)
  VALUES (1, '00000000-0000-7000-8000-000000000000',
     'sha256:0000000000000000000000000000000000000000000000000000000000000000',
     'sha256:1111111111111111111111111111111111111111111111111111111111111111',
     'run_registered', 'mcp', now(), '\\x7b7d'::bytea)"
expect_allowed "SELECT innsegl.events (read its own head)" \
  "SELECT count(*) FROM innsegl.events"
expect_allowed "SELECT innsegl.chain (the genesis constant)" \
  "SELECT chain_id FROM innsegl.chain"
expect_allowed "INSERT innsegl.idempotency (take a claim)" "INSERT INTO innsegl.idempotency
    (idempotency_key, tool, request_digest, status, lease_expires_at)
  VALUES ('verify-role-probe', 'probe',
     'sha256:0000000000000000000000000000000000000000000000000000000000000000',
     'in_progress', now())"
expect_allowed "UPDATE innsegl.idempotency (settle a claim)" \
  "UPDATE innsegl.idempotency SET status = 'completed' WHERE idempotency_key = 'verify-role-probe'"

# ---------------------------------------------------------------------------
# What it must NOT be able to do. I4: no deletion, no mutation.
# ---------------------------------------------------------------------------
expect_refused "UPDATE innsegl.events" "UPDATE innsegl.events SET run_id = 'x'"
expect_refused "DELETE innsegl.events" "DELETE FROM innsegl.events WHERE false"
expect_refused "TRUNCATE innsegl.events" "TRUNCATE innsegl.events"
expect_refused "SELECT innsegl.events FOR UPDATE" \
  "SELECT chain_position FROM innsegl.events FOR UPDATE"
expect_refused "UPDATE innsegl.chain" "UPDATE innsegl.chain SET chain_id = gen_random_uuid()"
expect_refused "DELETE innsegl.chain" "DELETE FROM innsegl.chain WHERE true"
expect_refused "TRUNCATE innsegl.idempotency" "TRUNCATE innsegl.idempotency"
expect_refused "DELETE innsegl.idempotency" "DELETE FROM innsegl.idempotency WHERE false"
# A role with CREATE anywhere is a role that can write. "It has no INSERT on
# innsegl.events" would be a comforting half of the answer.
expect_refused "CREATE TABLE in schema innsegl" "CREATE TABLE innsegl.verify_role_probe (x int)"
expect_refused "CREATE TABLE in schema public" "CREATE TABLE public.verify_role_probe (x int)"
expect_refused "CREATE SCHEMA" "CREATE SCHEMA verify_role_probe"

if [ "${FAILURES}" -ne 0 ]; then
  printf 'verify-role: FAIL: %s is not the role doc 05 §1 describes (%d finding(s) above).\n' \
    "${ROLE}" "${FAILURES}" >&2
  printf 'verify-role: re-run deploy/compose/innsegl/db-init.sh to reapply appendonly.sql,\n' >&2
  printf 'verify-role: or REVOKE the privileges named above from %s by hand.\n' "${ROLE}" >&2
  exit 1
fi

log "${ROLE} can append to the chain and cannot unmake it (doc 05 §1) — measured, not asserted"
