#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Ledger bootstrap for the reference compose stack (RM-076, #109).
#
# Runs once, before anything connects to the ledger, in a container built from
# the same Postgres image as the ledger itself — so the only tool it needs is
# the psql that already ships there.
#
# It does three things, in this order, and the third is not optional:
#
#   1. applies the SHIPPED migrations from migrations/*.sql, recording each one
#      in innsegl.schema_migrations exactly as internal/ledger's own runner
#      does, so that a later `innsegl serve -migrate` is a no-op rather than a
#      second attempt at migration 0001;
#   2. creates doc 05 §1's append-only role and applies appendonly.sql to it;
#   3. runs verify-role.sh, which connects AS that role and asks the server
#      what the credential can actually do.
#
# Step 3 is the point. internal/api/readonly.go is the model:
#
#     "The assertion matters more than the provisioning. A role is provisioned
#      once and then lives in somebody's deployment; a later GRANT by an
#      operator who wanted to 'just fix one thing' is invisible to any amount
#      of code review."
#
# So this script does not exit 0 on "the GRANTs ran". It exits 0 on "the server
# says this credential cannot delete".
#
# Idempotent: re-running against an initialised ledger applies nothing, and
# re-applies the grants (which is how a hand-widened role gets narrowed again).

set -eu

readonly HERE="$(cd -- "$(dirname -- "$0")" && pwd)"
readonly MIGRATIONS="${INNSEGL_MIGRATIONS_DIR:-/innsegl/migrations}"

log()  { printf 'db-init: %s\n' "$*"; }
fail() { printf 'db-init: FAIL: %s\n' "$*" >&2; exit 1; }

: "${PGHOST:?db-init: PGHOST must name the ledger}"
: "${PGUSER:?db-init: PGUSER must name the role that OWNS the schema}"
: "${PGDATABASE:?db-init: PGDATABASE must name the ledger database}"
: "${PGPASSWORD:?db-init: PGPASSWORD must be set}"

ROLE="${INNSEGL_APPENDER_ROLE:-innsegl_appender}"
: "${INNSEGL_APPENDER_PASSWORD:?db-init: INNSEGL_APPENDER_PASSWORD must be set}"

# The same grammar internal/api/readonly.go accepts. A role name reaches SQL as
# an identifier and psql quotes it, but a name this pattern rejects is a
# configuration mistake worth catching where it is made.
case "${ROLE}" in
  ''|*[!A-Za-z0-9_$]*) fail "\"${ROLE}\" is not a usable role name" ;;
esac
case "${ROLE}" in
  [0-9$]*) fail "\"${ROLE}\" is not a usable role name" ;;
esac

# psql, with errors fatal and nothing read from a user profile.
psql_owner() { psql -X -q -v ON_ERROR_STOP=1 "$@"; }

# ---------------------------------------------------------------------------
# 1. Wait for the ledger.
# ---------------------------------------------------------------------------
waited=0
until pg_isready -q -h "${PGHOST}" -p "${PGPORT:-5432}" -U "${PGUSER}" -d "${PGDATABASE}"; do
  waited=$((waited + 1))
  [ "${waited}" -lt 120 ] || fail "the ledger at ${PGHOST} never accepted a connection"
  sleep 1
done
log "ledger at ${PGHOST}:${PGPORT:-5432} is up, database ${PGDATABASE}, owner ${PGUSER}"

# ---------------------------------------------------------------------------
# 2. The migrations.
#
# internal/ledger/postgres.go's runner, reproduced in psql, statement for
# statement — the bootstrap DDL, then for each file: record it and apply it in
# ONE transaction, so the file and the row that records it commit together and
# half a migration is impossible.
#
# The `ON CONFLICT DO NOTHING` guard means an already-applied migration is
# skipped rather than re-run, which is what makes this safe on a ledger volume
# that survived a `down` without `-v`.
#
# OPS-010 holds the two runners to each other behaviourally rather than
# textually: after this script, ledger.Store.Migrate() must succeed and must
# apply nothing.
# ---------------------------------------------------------------------------
[ -d "${MIGRATIONS}" ] || fail "no migrations at ${MIGRATIONS} (\$INNSEGL_MIGRATIONS_DIR)"

psql_owner -c "
    CREATE SCHEMA IF NOT EXISTS innsegl;
    CREATE TABLE IF NOT EXISTS innsegl.schema_migrations (
        version    text PRIMARY KEY,
        name       text NOT NULL,
        applied_at timestamptz NOT NULL DEFAULT now()
    );"

applied=0
skipped=0
for file in "${MIGRATIONS}"/[0-9][0-9][0-9][0-9]_*.sql; do
  [ -f "${file}" ] || fail "no NNNN_name.sql files under ${MIGRATIONS}"
  name="$(basename "${file}")"
  version="$(printf '%s' "${name}" | cut -c1-4)"

  already="$(psql_owner -A -t -c \
    "SELECT 1 FROM innsegl.schema_migrations WHERE version = '${version}'")"
  if [ -n "${already}" ]; then
    skipped=$((skipped + 1))
    continue
  fi

  log "applying ${name}"
  # -1 wraps the -c and the -f in a single transaction, which is the whole
  # guarantee: the INSERT and the DDL commit or neither does.
  psql_owner -1 \
    -c "INSERT INTO innsegl.schema_migrations (version, name)
        VALUES ('${version}', '${name}') ON CONFLICT (version) DO NOTHING" \
    -f "${file}"
  applied=$((applied + 1))
done
log "migrations: ${applied} applied, ${skipped} already present"

# ---------------------------------------------------------------------------
# 3. The append-only role.
#
# Created here rather than in appendonly.sql because it carries a password, and
# a password does not belong in a file that ships. Everything else about the
# role — every GRANT and every REVOKE — is in appendonly.sql, where it can be
# read as one page.
# ---------------------------------------------------------------------------
exists="$(psql_owner -A -t -c "SELECT 1 FROM pg_roles WHERE rolname = '${ROLE}'")"
if [ -z "${exists}" ]; then
  verb=CREATE
  log "creating role ${ROLE}"
else
  verb=ALTER
  log "role ${ROLE} already exists; resetting its password and its grants"
fi

# Fed on stdin rather than through -c: psql substitutes :vars in a SCRIPT, and
# `-c` is handed to the server as one already-parsed command with no
# substitution at all. The password therefore reaches SQL through psql's own
# :'pass' literal quoting and never through the shell's.
psql_owner -v pass="${INNSEGL_APPENDER_PASSWORD}" -v role="${ROLE}" <<SQL
${verb} ROLE :"role" LOGIN PASSWORD :'pass';
SQL

log "applying appendonly.sql to ${ROLE}"
psql_owner -v role="${ROLE}" -v db="${PGDATABASE}" -f "${HERE}/appendonly.sql"

# ---------------------------------------------------------------------------
# 4. Ask the server. Never trust the GRANTs.
# ---------------------------------------------------------------------------
log "verifying the credential against the server"
exec sh "${HERE}/verify-role.sh"
