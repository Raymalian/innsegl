#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Ask the server what the RESOLVER credential can actually do (RM-330,
# ADR-0044's 2026-10-03 amendment). The dashboard resolves alerts through
# this role, so it MUST be able to insert a row into
# innsegl.alert_resolutions and MUST NOT be able to do anything else: no
# update or delete of a resolution, no write to any other ledger table, no
# DDL, and no read of innsegl_auth.
#
# internal/api.AssertResolverScope asks the identical question at every
# `innsegl api` start-up. This script asks it at PROVISIONING time, so a
# widened grant is caught here rather than as a container that will not stay
# up.
#
# Every probe runs inside a transaction that is always rolled back, the
# insert included: the probe row names no real alert and is never kept.

set -eu

log()  { printf 'verify-resolver-role: %s\n' "$*"; }
fail() { printf 'verify-resolver-role: FAIL: %s\n' "$*" >&2; }

: "${PGHOST:?verify-resolver-role: PGHOST must name the ledger}"
: "${PGDATABASE:?verify-resolver-role: PGDATABASE must name the ledger database}"
: "${INNSEGL_RESOLVER_PASSWORD:?verify-resolver-role: INNSEGL_RESOLVER_PASSWORD must be set}"
ROLE="${INNSEGL_RESOLVER_ROLE:-innsegl_resolver}"

export PGPASSWORD="${INNSEGL_RESOLVER_PASSWORD}"
resolver() {
  psql -X -q -A -t -U "${ROLE}" -h "${PGHOST}" -p "${PGPORT:-5432}" \
    -d "${PGDATABASE}" "$@"
}

# probe_state prints the SQLSTATE a statement failed with, or nothing if it
# succeeded. The transaction is rolled back either way.
probe_state() {
  out="$(resolver -v ON_ERROR_STOP=0 \
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

expect_allowed() {
  state="$(probe_state "$2")"
  if [ -n "${state}" ]; then
    fail "REFUSED  $1 (${state}) — this role cannot do its one job"
    FAILURES=$((FAILURES + 1))
  else
    log "ALLOWED  $1"
  fi
}

log "measuring ${ROLE} at ${PGHOST}:${PGPORT:-5432}/${PGDATABASE}"

identity="$(resolver -c "SELECT current_user || ' ' || current_setting('is_superuser')")" || {
  fail "the credential could not connect at all: check INNSEGL_RESOLVER_PASSWORD and pg_hba"
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

# The one thing it must do.
expect_allowed "insert into innsegl.alert_resolutions" \
  "INSERT INTO innsegl.alert_resolutions (event_id, resolved_by, reason)
     VALUES ('00000000-0000-7000-8000-000000000000', 'resolver-probe', 'resolver-probe')"
expect_allowed "read whether an event is an alert" \
  "SELECT event_id, event_type FROM innsegl.events LIMIT 1"

# Everything else — internal/api.AssertResolverScope's own probe set.
expect_refused "update innsegl.alert_resolutions" \
  "UPDATE innsegl.alert_resolutions SET reason = reason WHERE false"
expect_refused "delete from innsegl.alert_resolutions" \
  "DELETE FROM innsegl.alert_resolutions WHERE false"
expect_refused "read innsegl_auth.users" "SELECT 1 FROM innsegl_auth.users LIMIT 1"
expect_refused "read an event's body" "SELECT canonical FROM innsegl.events LIMIT 1"
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
  VALUES ('resolver-probe', 'probe',
     'sha256:0000000000000000000000000000000000000000000000000000000000000000',
     'in_progress', now())"
expect_refused "create a table in schema innsegl" \
  "CREATE TABLE innsegl.resolver_probe (x int)"
expect_refused "create a table in schema public" \
  "CREATE TABLE public.resolver_probe (x int)"
expect_refused "create a schema of its own" "CREATE SCHEMA resolver_probe"

if [ "${FAILURES}" -ne 0 ]; then
  printf 'verify-resolver-role: FAIL: %s is not the credential ADR-0044 describes (%d finding(s) above).\n' \
    "${ROLE}" "${FAILURES}" >&2
  printf 'verify-resolver-role: `innsegl api` would refuse this credential too. Re-run db-init.sh to\n' >&2
  printf 'verify-resolver-role: reapply internal/api/resolver.sql, or REVOKE the privileges named above.\n' >&2
  exit 1
fi

log "${ROLE} can insert an alert resolution and nothing else (ADR-0044) — measured, not asserted"
