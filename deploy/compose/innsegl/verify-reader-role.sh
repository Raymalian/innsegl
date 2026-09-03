#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Ask the server what the READ-ONLY credential can actually do (RM-076 #109,
# RM-083 #121, doc 05 §1, FD §7).
#
# WHY THIS EXISTS AT ALL
# ----------------------
# It is verify-role.sh's shape, applied to the other role, and for the reason
# verify-role.sh states:
#
#     "appendonly.sql grants less. That is provisioning, and provisioning is a
#      claim."
#
# internal/api/readonly.sql grants less too, and db-init.sh applies it — the
# file itself, mounted from internal/api, never a copy. That is still a claim.
# internal/api/readonly.go makes the argument for the other half:
#
#     "The assertion matters more than the provisioning. A role is provisioned
#      once and then lives in somebody's deployment; a later GRANT by an
#      operator who wanted to 'just fix one thing' is invisible to any amount
#      of code review. So Open asks the server, every time it starts, whether
#      the credential it was handed can write — and refuses to come up if it
#      can."
#
# `innsegl api` does exactly that at every start-up and exits 13 WRITABLE if the
# answer is "write". This script is the same question asked at PROVISIONING
# time, so that the failure lands where the role was made rather than as a
# container that will not stay up — and so that `docker compose up` cannot
# report a healthy bootstrap in front of a dashboard with no backend.
#
# WHY IT CLASSIFIES BY SQLSTATE AND NOT BY SUCCESS
# ------------------------------------------------
# MEASURED on postgres:16, against the shipped migrations:
#
#   role    statement                    result
#   reader  INSERT INTO innsegl.events   ERROR 42501  permission denied (ACL)
#   reader  UPDATE innsegl.events        ERROR 42501  permission denied (ACL)
#   reader  DELETE FROM innsegl.events   ERROR 42501  permission denied (ACL)
#   owner   INSERT INTO innsegl.events   ERROR IN002  the chain-link trigger
#   owner   UPDATE innsegl.events        ERROR IN001  the append-only trigger
#   owner   DELETE FROM innsegl.events   ERROR IN001  the append-only trigger
#
# BOTH roles are refused. Only one is refused BY PRIVILEGE. A check that asked
# "did the statement fail?" would pass the database owner — the credential the
# gate exists to catch — because migration 0001's triggers refuse it too. So
# the only refusals that count here are 42501 (insufficient_privilege) and
# 25006 (read_only_sql_transaction). Anything else, INCLUDING SUCCESS, means
# the ACL let the statement through.
#
# The role carries `default_transaction_read_only = on`, which readonly.sql
# calls "belt as well as braces": every probe below therefore issues
# `SET TRANSACTION READ WRITE` first, so that a refusal is the GRANT's and not
# a setting the same session could have turned off for itself.
#
# It writes nothing: every probe runs inside a transaction that is rolled back,
# and the probes a writing credential would be ALLOWED to run are exactly the
# ones whose effect is discarded. Running it against a production ledger is
# safe and is the intended use.

set -eu

log()  { printf 'verify-reader-role: %s\n' "$*"; }
fail() { printf 'verify-reader-role: FAIL: %s\n' "$*" >&2; }

: "${PGHOST:?verify-reader-role: PGHOST must name the ledger}"
: "${PGDATABASE:?verify-reader-role: PGDATABASE must name the ledger database}"
: "${INNSEGL_READER_PASSWORD:?verify-reader-role: INNSEGL_READER_PASSWORD must be set}"
ROLE="${INNSEGL_READER_ROLE:-innsegl_reader}"

# Everything below connects AS THE ROLE UNDER TEST, never as the owner.
export PGPASSWORD="${INNSEGL_READER_PASSWORD}"
reader() {
  psql -X -q -A -t -U "${ROLE}" -h "${PGHOST}" -p "${PGPORT:-5432}" \
    -d "${PGDATABASE}" "$@"
}

# probe_state runs one statement in a transaction it always rolls back and
# prints the SQLSTATE, or the empty string if the statement succeeded.
#
# `\set VERBOSITY verbose` is what puts the SQLSTATE on the ERROR line; without
# it psql prints only the message and the code has to be guessed from English
# text that changes between releases and locales.
probe_state() {
  out="$(reader -v ON_ERROR_STOP=0 \
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
    *)           fail "ALLOWED  $1 — the ACL permitted it; it failed for another reason (${state}). A refusal that is not by privilege is one ALTER TABLE ... DISABLE TRIGGER away from no refusal at all, and it is the refusal the database OWNER also gets"
                 FAILURES=$((FAILURES + 1)) ;;
  esac
}

# expect_allowed NAME SQL — the ACL must NOT stop this.
expect_allowed() {
  state="$(probe_state "$2")"
  case "${state}" in
    42501|25006) fail "REFUSED  $1 (${state}) — the dashboard would render its load-failure state on every view"
                 FAILURES=$((FAILURES + 1)) ;;
    *)           log "ALLOWED  $1" ;;
  esac
}

log "measuring ${ROLE} at ${PGHOST}:${PGPORT:-5432}/${PGDATABASE}"

# ---------------------------------------------------------------------------
# Who the session is. A SUPERUSER is bound by no ACL, so every probe below
# would pass it and mean nothing.
# ---------------------------------------------------------------------------
identity="$(reader -c "SELECT current_user || ' ' || current_setting('is_superuser') || ' ' || current_setting('default_transaction_read_only')")" || {
  fail "the credential could not connect at all: check INNSEGL_READER_PASSWORD and pg_hba"
  exit 1
}
who="$(printf '%s' "${identity}" | cut -d' ' -f1)"
super="$(printf '%s' "${identity}" | cut -d' ' -f2)"
defaultro="$(printf '%s' "${identity}" | cut -d' ' -f3)"
log "connected as ${who}, is_superuser=${super}, default_transaction_read_only=${defaultro}"
if [ "${super}" != "off" ]; then
  fail "${who} is a SUPERUSER. No ACL binds a superuser, so nothing below would mean anything"
  FAILURES=$((FAILURES + 1))
fi
if [ "${who}" != "${ROLE}" ]; then
  fail "connected as ${who}, expected ${ROLE}"
  FAILURES=$((FAILURES + 1))
fi
if [ "${defaultro}" != "on" ]; then
  fail "default_transaction_read_only is ${defaultro}. The GRANTs below are the enforcement and this setting is not a boundary, but its absence means the grants applied were not internal/api/readonly.sql's"
  FAILURES=$((FAILURES + 1))
fi

# ---------------------------------------------------------------------------
# What it must be able to do. internal/api/query.go reads innsegl.events and no
# other table; a reader that cannot SELECT it is not least privilege, it is an
# outage — every view in the dashboard would render its own load-failure state
# while the container reported healthy.
# ---------------------------------------------------------------------------
expect_allowed "SELECT innsegl.events (the runs index)" \
  "SELECT count(*) FROM innsegl.events"

# ---------------------------------------------------------------------------
# What it must NOT be able to do.
#
# These eight are internal/api/readonly.go's own writeProbes(), in its order,
# because they are the eight `api.Open` attempts before it will serve a single
# request: a role that fails any of them makes `innsegl api` exit 13 WRITABLE.
# Asking them here means the failure lands at provisioning rather than as a
# service that will not stay up.
# ---------------------------------------------------------------------------
expect_refused "lock innsegl.events for update" \
  "SELECT chain_position FROM innsegl.events FOR UPDATE"
expect_refused "insert into innsegl.events" "INSERT INTO innsegl.events
    (chain_position, event_id, event_hash, prev_event_hash, event_type,
     source, ts, canonical)
  VALUES (1, '00000000-0000-7000-8000-000000000000',
     'sha256:0000000000000000000000000000000000000000000000000000000000000000',
     'sha256:1111111111111111111111111111111111111111111111111111111111111111',
     'run_registered', 'mcp', now(), '\\x7b7d'::bytea)"
expect_refused "lock innsegl.chain for update" \
  "SELECT chain_id FROM innsegl.chain FOR UPDATE"
expect_refused "insert into innsegl.idempotency" "INSERT INTO innsegl.idempotency
    (idempotency_key, tool, request_digest, status, lease_expires_at)
  VALUES ('api-write-probe', 'probe',
     'sha256:0000000000000000000000000000000000000000000000000000000000000000',
     'in_progress', now())"
expect_refused "delete from innsegl.idempotency" \
  "DELETE FROM innsegl.idempotency WHERE idempotency_key = 'api-write-probe'"
# A role with CREATE anywhere is a role that can write. "It has no INSERT on
# innsegl.events" would be a comforting half of the answer.
expect_refused "create a table in schema innsegl" \
  "CREATE TABLE innsegl.api_write_probe (x int)"
expect_refused "create a table in schema public" \
  "CREATE TABLE public.api_write_probe (x int)"
expect_refused "create a schema of its own" "CREATE SCHEMA api_write_probe"

# The I4 verbs. Not in readonly.go's probe set — an UPDATE or a TRUNCATE of
# innsegl.events is refused for EVERY role by migration 0001's statement
# trigger, so it can never convict a writing credential on its own — but the
# reader must still be refused them BY PRIVILEGE, and 42501 here rather than
# IN001 is precisely the difference between this role and the owner.
expect_refused "update innsegl.events" "UPDATE innsegl.events SET run_id = 'x'"
expect_refused "delete from innsegl.events" "DELETE FROM innsegl.events WHERE false"
expect_refused "truncate innsegl.events" "TRUNCATE innsegl.events"
expect_refused "update innsegl.idempotency" \
  "UPDATE innsegl.idempotency SET status = 'completed' WHERE idempotency_key = 'api-write-probe'"

if [ "${FAILURES}" -ne 0 ]; then
  printf 'verify-reader-role: FAIL: %s is not the credential FD §7 describes (%d finding(s) above).\n' \
    "${ROLE}" "${FAILURES}" >&2
  printf 'verify-reader-role: `innsegl api` would refuse this credential too, with exit 13\n' >&2
  printf 'verify-reader-role: WRITABLE, and no restart would clear it. Re-run\n' >&2
  printf 'verify-reader-role: deploy/compose/innsegl/db-init.sh to reapply internal/api/readonly.sql,\n' >&2
  printf 'verify-reader-role: or REVOKE the privileges named above from %s by hand.\n' "${ROLE}" >&2
  exit 1
fi

log "${ROLE} can read the chain and cannot write anywhere (FD §7, doc 05 §1) — measured, not asserted"
