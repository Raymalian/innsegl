#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Ask the server what the AUTH-WRITER credential can actually do (RM-260/
# RM-261, ADR-0062). verify-reader-role.sh's own shape, with the expectations
# the opposite way round: this role MUST be able to read and write
# innsegl_auth (users, passkeys, sessions, auth events, enrolment codes,
# webauthn ceremonies) and MUST NOT be able to touch anything in innsegl —
# the schema internal/api/readonly.go's writeProbes() already protects.
#
# internal/api.AssertCannotWriteLedger asks the identical question at every
# `innsegl api` start-up by reusing AssertReadOnly's own probes against this
# role instead of the reader's. This script asks it at PROVISIONING time, so
# a widened grant is caught here rather than as a container that will not
# stay up.
#
# It writes real rows to innsegl_auth — this role is legitimately allowed to,
# so there is nothing to roll back a real write against — and deletes them
# again at the end. The innsegl-schema probes below run inside a transaction
# that is always rolled back, exactly as verify-reader-role.sh's do, because
# a SUCCESS there would be the finding.

set -eu

log()  { printf 'verify-authwriter-role: %s\n' "$*"; }
fail() { printf 'verify-authwriter-role: FAIL: %s\n' "$*" >&2; }

: "${PGHOST:?verify-authwriter-role: PGHOST must name the ledger}"
: "${PGDATABASE:?verify-authwriter-role: PGDATABASE must name the ledger database}"
: "${INNSEGL_AUTHWRITER_PASSWORD:?verify-authwriter-role: INNSEGL_AUTHWRITER_PASSWORD must be set}"
ROLE="${INNSEGL_AUTHWRITER_ROLE:-innsegl_authwriter}"

export PGPASSWORD="${INNSEGL_AUTHWRITER_PASSWORD}"
authwriter() {
  psql -X -q -A -t -U "${ROLE}" -h "${PGHOST}" -p "${PGPORT:-5432}" \
    -d "${PGDATABASE}" "$@"
}

probe_state() {
  out="$(authwriter -v ON_ERROR_STOP=0 \
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
    '')          fail "ALLOWED  $1 — the statement SUCCEEDED"
                 FAILURES=$((FAILURES + 1)) ;;
    *)           fail "ALLOWED  $1 — the ACL permitted it; it failed for another reason (${state})"
                 FAILURES=$((FAILURES + 1)) ;;
  esac
}

log "measuring ${ROLE} at ${PGHOST}:${PGPORT:-5432}/${PGDATABASE}"

identity="$(authwriter -c "SELECT current_user || ' ' || current_setting('is_superuser')")" || {
  fail "the credential could not connect at all: check INNSEGL_AUTHWRITER_PASSWORD and pg_hba"
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
# What it MUST be able to do: ordinary CRUD on innsegl_auth, exercised with a
# real row (created, then removed) so "it connects and the schema exists" is
# distinguished from "it can actually write to it".
# ---------------------------------------------------------------------------
probe_user_id="verify-authwriter-role-probe"
if ! authwriter -v ON_ERROR_STOP=1 -c \
  "INSERT INTO innsegl_auth.users (user_id, display_name) VALUES ('${probe_user_id}', 'verify-authwriter-role probe')" \
  >/dev/null 2>&1
then
  fail "REFUSED  insert into innsegl_auth.users — this role cannot do its own job"
  FAILURES=$((FAILURES + 1))
else
  log "ALLOWED  insert into innsegl_auth.users"
fi
authwriter -c "DELETE FROM innsegl_auth.users WHERE user_id = '${probe_user_id}'" >/dev/null 2>&1 ||
  log "cleanup of the probe row failed; it is harmless test data, not a live user"

# ---------------------------------------------------------------------------
# What it must NOT be able to do — internal/api/readonly.go's own
# writeProbes(), the SAME set AssertCannotWriteLedger reuses, because this
# role must fail every one of them exactly as the reader does.
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
  VALUES ('authwriter-probe', 'probe',
     'sha256:0000000000000000000000000000000000000000000000000000000000000000',
     'in_progress', now())"
expect_refused "delete from innsegl.idempotency" \
  "DELETE FROM innsegl.idempotency WHERE idempotency_key = 'authwriter-probe'"
expect_refused "create a table in schema innsegl" \
  "CREATE TABLE innsegl.authwriter_probe (x int)"
expect_refused "create a table in schema public" \
  "CREATE TABLE public.authwriter_probe (x int)"
expect_refused "create a schema of its own" "CREATE SCHEMA authwriter_probe"
# And simply reading the ledger, which this role has no business doing
# either — ADR-0062: "it may be given SELECT on the new schema ... never
# INSERT, UPDATE or DELETE on it or on anything ADR-0044 already covers", and
# this deployment chose not to grant even the SELECT (see
# internal/api/authwriter.sql's own header).
expect_refused "select innsegl.events" "SELECT count(*) FROM innsegl.events"

if [ "${FAILURES}" -ne 0 ]; then
  printf 'verify-authwriter-role: FAIL: %s is not the credential ADR-0062 describes (%d finding(s) above).\n' \
    "${ROLE}" "${FAILURES}" >&2
  printf 'verify-authwriter-role: `innsegl api` would refuse this credential too (exit 13 WRITABLE),\n' >&2
  printf 'verify-authwriter-role: and no restart would clear it. Re-run db-init.sh to reapply\n' >&2
  printf 'verify-authwriter-role: internal/api/authwriter.sql, or REVOKE the privileges named above by hand.\n' >&2
  exit 1
fi

log "${ROLE} can read and write innsegl_auth and cannot touch innsegl (ADR-0062) — measured, not asserted"
