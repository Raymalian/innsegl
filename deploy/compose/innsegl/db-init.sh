#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Ledger bootstrap for the reference compose stack (RM-076, #109).
#
# Runs once, before anything connects to the ledger, in a container built from
# the same Postgres image as the ledger itself — so the only tool it needs is
# the psql that already ships there.
#
# It provisions BOTH of doc 05 §1's non-owner roles, and probes each one:
#
#   1. applies the SHIPPED migrations from migrations/*.sql, recording each one
#      in innsegl.schema_migrations exactly as internal/ledger's own runner
#      does, so that a later `innsegl serve -migrate` is a no-op rather than a
#      second attempt at migration 0001;
#   2. creates doc 05 §1's append-only role and applies appendonly.sql to it;
#   3. runs verify-role.sh, which connects AS that role and asks the server
#      what the credential can actually do;
#   4. creates the READ-ONLY role `innsegl api` connects as and applies
#      internal/api/readonly.sql to it — THE SAME FILE api.EnsureReadOnlyRole
#      embeds, mounted here rather than copied (see $READONLY_SQL below for how,
#      and why a second copy of those GRANTs would be the wrong answer);
#   5. runs verify-reader-role.sh, which connects AS the reader and does the
#      same thing step 3 does.
#
# Steps 3 and 5 are the point. internal/api/readonly.go is the model:
#
#     "The assertion matters more than the provisioning. A role is provisioned
#      once and then lives in somebody's deployment; a later GRANT by an
#      operator who wanted to 'just fix one thing' is invisible to any amount
#      of code review."
#
# So this script does not exit 0 on "the GRANTs ran". It exits 0 on "the server
# says the appender cannot delete and the reader cannot write".
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

# api.ReadOnlyRole. Like the appender's, a default and not a protected string:
# internal/api/readonly.go says "a deployment may name it anything, and
# EnsureReadOnlyRole takes the name as an argument", and so does this script.
READER_ROLE="${INNSEGL_READER_ROLE:-innsegl_reader}"
: "${INNSEGL_READER_PASSWORD:?db-init: INNSEGL_READER_PASSWORD must be set}"

# internal/api/readonly.sql, reached BY MOUNT and not by copy.
#
# THIS IS THE WHOLE OF HOW THE READER'S GRANTS GET HERE, and it is the same
# decision the migrations mount makes for the same reason. api.EnsureReadOnlyRole
# `//go:embed`s this exact file and applies it; `innsegl api` then probes the
# credential at every start-up against what those GRANTs produced. A second copy
# of them under deploy/ would be a read-only posture that could drift from the
# one the API measures against — and the failure mode of that drift is a
# dashboard that exits 13 in a stack whose own bootstrap said the role was fine.
#
# One translation happens on the way in, and only one: the file is written for
# Go's fmt, where %[1]s is the role identifier and %[2]s the database
# identifier, so those two verbs become psql's own :"role" and :"db" — which
# quote identifiers exactly as pgx.Identifier.Sanitize does on the Go side.
# Nothing else in the file is touched, and a file that has grown a verb this
# translation does not know about is a hard failure rather than a silent
# mistranslation. See apply_readonly_sql below.
READONLY_SQL="${INNSEGL_READONLY_SQL:-/innsegl/api/readonly.sql}"

# The same grammar internal/api/readonly.go accepts. A role name reaches SQL as
# an identifier and psql quotes it, but a name this pattern rejects is a
# configuration mistake worth catching where it is made.
check_role_name() {
  case "$1" in
    ''|*[!A-Za-z0-9_$]*) fail "\"$1\" is not a usable role name" ;;
  esac
  case "$1" in
    [0-9$]*) fail "\"$1\" is not a usable role name" ;;
  esac
}
check_role_name "${ROLE}"
check_role_name "${READER_ROLE}"
if [ "${ROLE}" = "${READER_ROLE}" ]; then
  fail "the append-only role and the read-only role are both \"${ROLE}\"; one role cannot be both"
fi
if [ "${READER_ROLE}" = "${PGUSER}" ]; then
  fail "the read-only role is the schema OWNER (\"${PGUSER}\"). readonly.sql cannot make an owner read-only: it is refused by the append-only TRIGGER (IN001) and never by the ACL, which is the exact confusion verify-reader-role.sh exists to catch"
fi

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
# 4. Ask the server about the appender. Never trust the GRANTs.
# ---------------------------------------------------------------------------
log "verifying the append-only credential against the server"
sh "${HERE}/verify-role.sh"

# ---------------------------------------------------------------------------
# 5. The read-only role.
#
# doc 05 §1: "innsegl-dashboard | Read-only UI + BFF proof checks | No write
# credentials mounted — enforced by giving it a read-only DB role". THIS is
# that role, and until it existed the reference stack had no way to run
# `innsegl api` at all: handed nothing it exits 11, and handed the appender by
# a copied line it exits 13 WRITABLE and publishes no address.
#
# Created here rather than in readonly.sql for the reason the appender is:
# the CREATE carries a password, and a password does not belong in a file that
# ships. Everything else about the role is in internal/api/readonly.sql.
# ---------------------------------------------------------------------------
[ -f "${READONLY_SQL}" ] || fail "no read-only grants at ${READONLY_SQL} (\$INNSEGL_READONLY_SQL). deploy/compose/innsegl.yml mounts internal/api/readonly.sql there; a second copy of those GRANTs under deploy/ is the wrong fix"

reader_exists="$(psql_owner -A -t -c "SELECT 1 FROM pg_roles WHERE rolname = '${READER_ROLE}'")"
if [ -z "${reader_exists}" ]; then
  reader_verb=CREATE
  log "creating role ${READER_ROLE}"
else
  reader_verb=ALTER
  log "role ${READER_ROLE} already exists; resetting its password and its grants"
fi

psql_owner -v pass="${INNSEGL_READER_PASSWORD}" -v role="${READER_ROLE}" <<SQL
${reader_verb} ROLE :"role" LOGIN PASSWORD :'pass';
SQL

# apply_readonly_sql translates Go's fmt verbs into psql's variables and applies
# the result. The `case` afterwards is not decoration: if internal/api grows a
# %[3]s, or switches to a bare %s, sed leaves it in place and psql would fail
# somewhere in the middle of a REVOKE — or, worse, succeed with a literal
# `%[3]s` swallowed by a comment. Refusing loudly here is what makes the mount
# safe to rely on.
apply_readonly_sql() {
  grants="$(sed -e 's/%\[1\]s/:"role"/g' -e 's/%\[2\]s/:"db"/g' "${READONLY_SQL}")"
  if printf '%s\n' "${grants}" | grep -Eq '%(\[|[A-Za-z])'; then
    printf 'db-init: untranslated:\n%s\n' \
      "$(printf '%s\n' "${grants}" | grep -En '%(\[|[A-Za-z])')" >&2
    fail "${READONLY_SQL} still contains an fmt verb after translation. It is internal/api's file and it has changed shape; teach the sed in apply_readonly_sql about the new verb rather than copying the GRANTs into deploy/, which is how the two would drift"
  fi
  printf '%s\n' "${grants}" |
    psql_owner -v role="${READER_ROLE}" -v db="${PGDATABASE}" -f -
}

log "applying ${READONLY_SQL} to ${READER_ROLE}"
apply_readonly_sql

# ---------------------------------------------------------------------------
# 6. Ask the server about the reader, for the same reason as step 4.
# ---------------------------------------------------------------------------
log "verifying the read-only credential against the server"
exec sh "${HERE}/verify-reader-role.sh"
