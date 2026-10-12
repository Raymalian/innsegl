#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Ask the server what the ENROLLER credential can actually do (RM-355, #603).
# The core enrols, renews and revokes client machines through this role, so it
# MUST be able to spend an enrolment token, insert and update an installation
# and append an audit row, and MUST NOT be able to read or write a user, a
# passkey or a session, mint a token, delete or rename an installation, add a
# member or an organisation, rewrite the audit trail, or write the ledger.
#
# internal/api.AssertEnrollerScope asks the identical question at every core
# start-up. This script asks it at PROVISIONING time, so a widened grant is
# caught here rather than as a core that will not stay up.
#
# Every probe touches no row (WHERE false) and runs inside a transaction that
# is always rolled back.

set -eu

log()  { printf 'verify-enroller-role: %s\n' "$*"; }
fail() { printf 'verify-enroller-role: FAIL: %s\n' "$*" >&2; }

: "${PGHOST:?verify-enroller-role: PGHOST must name the ledger}"
: "${PGDATABASE:?verify-enroller-role: PGDATABASE must name the ledger database}"
: "${INNSEGL_ENROLLER_PASSWORD:?verify-enroller-role: INNSEGL_ENROLLER_PASSWORD must be set}"
ROLE="${INNSEGL_ENROLLER_ROLE:-innsegl_enroller}"

export PGPASSWORD="${INNSEGL_ENROLLER_PASSWORD}"
enroller() {
  psql -X -q -A -t -U "${ROLE}" -h "${PGHOST}" -p "${PGPORT:-5432}" \
    -d "${PGDATABASE}" "$@"
}

# probe_state prints the SQLSTATE a statement failed with, or nothing if it
# succeeded. The transaction is rolled back either way.
probe_state() {
  out="$(enroller -v ON_ERROR_STOP=0 \
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

identity="$(enroller -c "SELECT current_user || ' ' || current_setting('is_superuser')")" || {
  fail "the credential could not connect at all: check INNSEGL_ENROLLER_PASSWORD and pg_hba"
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

# What enrolment, renewal and revocation write — internal/api.AssertEnrollerScope's
# own must-allow probes.
expect_allowed "spend an enrolment token" \
  "UPDATE innsegl_auth.enrolment_tokens SET used_at = clock_timestamp(), installation_id = installation_id WHERE false"
expect_allowed "insert an installation" \
  "INSERT INTO innsegl_auth.installations (installation_id, account_id, created_by, name, kind, repos)
     SELECT installation_id, account_id, created_by, name, kind, repos FROM innsegl_auth.installations WHERE false"
expect_allowed "renew or revoke an installation" \
  "UPDATE innsegl_auth.installations SET last_renewed_at = clock_timestamp(), status = status, revoked_at = revoked_at WHERE false"
expect_allowed "append an audit row" \
  "INSERT INTO innsegl_auth.audit (actor, account_id, action, subject, detail)
     SELECT NULL, NULL, 'probe', '', '{}'::jsonb WHERE false"
expect_allowed "claim a repository on first use" \
  "INSERT INTO innsegl_auth.repo_grants (account_id, repo) SELECT account_id, repo FROM innsegl_auth.repo_grants WHERE false"

# Everything else — the same must-refuse probes, and the ledger.
expect_refused "read innsegl_auth.users" "SELECT user_id FROM innsegl_auth.users WHERE false"
expect_refused "read innsegl_auth.passkeys" "SELECT 1 FROM innsegl_auth.passkeys WHERE false"
expect_refused "read innsegl_auth.sessions" "SELECT 1 FROM innsegl_auth.sessions WHERE false"
expect_refused "read innsegl_auth.enrolment_codes" "SELECT 1 FROM innsegl_auth.enrolment_codes WHERE false"
expect_refused "insert into innsegl_auth.enrolment_tokens" \
  "INSERT INTO innsegl_auth.enrolment_tokens SELECT * FROM innsegl_auth.enrolment_tokens WHERE false"
expect_refused "delete from innsegl_auth.installations" "DELETE FROM innsegl_auth.installations WHERE false"
expect_refused "update an installation's name or repositories" \
  "UPDATE innsegl_auth.installations SET name = name, repos = repos WHERE false"
expect_refused "insert into innsegl_auth.memberships" \
  "INSERT INTO innsegl_auth.memberships (user_id, account_id, role) SELECT NULL, NULL, NULL WHERE false"
expect_refused "insert into innsegl_auth.accounts" \
  "INSERT INTO innsegl_auth.accounts (account_id, name) SELECT NULL, NULL WHERE false"
expect_refused "update innsegl_auth.audit" "UPDATE innsegl_auth.audit SET action = action WHERE false"
expect_refused "update innsegl_auth.repo_grants" \
  "UPDATE innsegl_auth.repo_grants SET until = clock_timestamp() WHERE false"
expect_refused "read an event" "SELECT 1 FROM innsegl.events WHERE false"
expect_refused "insert into innsegl.idempotency" "INSERT INTO innsegl.idempotency
    (idempotency_key, tool, request_digest, status, lease_expires_at)
  VALUES ('enroller-probe', 'probe',
     'sha256:0000000000000000000000000000000000000000000000000000000000000000',
     'in_progress', now())"
expect_refused "create a table in schema innsegl_auth" \
  "CREATE TABLE innsegl_auth.enroller_probe (x int)"
expect_refused "create a table in schema public" \
  "CREATE TABLE public.enroller_probe (x int)"
expect_refused "create a schema of its own" "CREATE SCHEMA enroller_probe"

if [ "${FAILURES}" -ne 0 ]; then
  printf 'verify-enroller-role: FAIL: %s is not the credential RM-355 describes (%d finding(s) above).\n' \
    "${ROLE}" "${FAILURES}" >&2
  printf 'verify-enroller-role: the core would refuse this credential too. Re-run db-init.sh to\n' >&2
  printf 'verify-enroller-role: reapply internal/api/enroller.sql, or REVOKE the privileges named above.\n' >&2
  exit 1
fi

log "${ROLE} can enrol, renew and revoke a machine and nothing else (RM-355) — measured, not asserted"
