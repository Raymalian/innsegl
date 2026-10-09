#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Ledger bootstrap for the reference compose stack (RM-076, #109).
#
# Runs once, before anything connects to the ledger, in a container built from
# the same Postgres image as the ledger itself — so the only tool it needs is
# the psql that already ships there.
#
# It provisions doc 05 §1's non-owner roles, plus RM-260/RM-261's auth-writer
# (ADR-0062), and probes each one:
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
#   6. creates the BACKUP role, gives it the reader's grants plus CREATEDB,
#      and runs verify-backup-role.sh, which asks the server whether that
#      credential can do the backup's whole job and still not write the ledger.
#   5. runs verify-reader-role.sh, which connects AS the reader and does the
#      same thing step 3 does.
#   8. creates the AUTH-WRITER role (RM-260/RM-261) and applies
#      internal/api/authwriter.sql to it — full CRUD on innsegl_auth, nothing
#      on innsegl, the same mount-not-copy discipline as step 4's.
#   9. runs verify-authwriter-role.sh, which asks the server the same
#      question step 5 does, with the expectations reversed.
#  10. creates the RESOLVER role (RM-330, ADR-0044's 2026-10-03 amendment)
#      and applies internal/api/resolver.sql to it — insert an alert
#      resolution, and nothing else, the same mount-not-copy discipline.
#  11. runs verify-resolver-role.sh, which asks the server whether that is
#      all it can do.
#
# Steps 3, 5, 9 and 11 are the point. internal/api/readonly.go is the model:
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

# ---------------------------------------------------------------------------
# 0. The credentials (ADR-0078).
#
# In the stack, every password is a file in the trust credentials volume
# that innsegl-credentials generated for this host. $INNSEGL_CREDENTIALS_DIR
# names it, and the owner's and the five roles' are read from there into this
# process's own environment. No compose value and no command line carries
# them. Run by hand or by a test without that variable, the values come from
# the environment as before.
#
# THE ONE OLD VALUE. Earlier releases gave the owner a password every reader
# of this repository had. The owner is the one credential whose server needs
# the old password before it takes a new one, so the move in step 1b needs
# it, and this is the only place a shipped file names it. OPS-130 refuses
# every other old value wherever it appears.
# ---------------------------------------------------------------------------
LEDGER_OWNER_LEGACY_PUBLIC_PASSWORD='innsegl-compose-owner'
CREDENTIALS_DIR="${INNSEGL_CREDENTIALS_DIR:-}"

# check_password refuses a value that would need quoting in SQL or a pgpass
# line. Every generated value is hex; this is what lets \set take it as is.
check_password() {
  case "$2" in
    ''|*[!A-Za-z0-9._~-]*) fail "the password for $1 is empty or holds a character outside [A-Za-z0-9._~-]" ;;
  esac
}

read_credential() {
  [ -s "${CREDENTIALS_DIR}/$1" ] || fail "${CREDENTIALS_DIR}/$1 is missing; innsegl-credentials writes it before this runs"
  head -n 1 "${CREDENTIALS_DIR}/$1"
}

if [ -n "${CREDENTIALS_DIR}" ]; then
  PGPASSWORD="$(read_credential ledger-owner)" || exit 1
  INNSEGL_APPENDER_PASSWORD="$(read_credential ledger-appender)" || exit 1
  INNSEGL_READER_PASSWORD="$(read_credential ledger-reader)" || exit 1
  INNSEGL_BACKUP_PASSWORD="$(read_credential ledger-backup)" || exit 1
  INNSEGL_AUTHWRITER_PASSWORD="$(read_credential ledger-authwriter)" || exit 1
  INNSEGL_RESOLVER_PASSWORD="$(read_credential ledger-resolver)" || exit 1
  # Exported: the verify-*.sh scripts this runs read them.
  export PGPASSWORD INNSEGL_APPENDER_PASSWORD INNSEGL_READER_PASSWORD \
    INNSEGL_BACKUP_PASSWORD INNSEGL_AUTHWRITER_PASSWORD INNSEGL_RESOLVER_PASSWORD
fi

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

# The backup's role (RM-146, #237). Like the other two, a default and not a
# protected string.
#
# IT IS THE READER PLUS CREATEDB, AND NOTHING ELSE. The backup does two things:
# it dumps the ledger, which needs exactly what the reader has, and it restores
# that dump into a THROWAWAY database to prove the dump restores at all — which
# needs a database of its own to own. internal/api/readonly.sql's line 58 says
# NOCREATEDB, correctly, for the role it was written for; the CREATEDB below is
# applied AFTER it and is the one deliberate difference between these two roles.
#
# Undoing a line of somebody else's grants file is only safe because nothing
# here is trusted: verify-backup-role.sh asks the SERVER what this credential
# can do, and it asserts both halves — that the backup's whole job succeeds, and
# that writing the live ledger is still refused BY PRIVILEGE. Provisioning is a
# claim; the measurement is the gate.
BACKUP_ROLE="${INNSEGL_BACKUP_ROLE:-innsegl_backup}"
: "${INNSEGL_BACKUP_PASSWORD:?db-init: INNSEGL_BACKUP_PASSWORD must be set}"

# RM-260/RM-261 (ADR-0062) — api.AuthWriterRole. Full CRUD on innsegl_auth,
# nothing on innsegl; the opposite grant from the reader's. Like the other
# three, a default and not a protected string.
AUTHWRITER_ROLE="${INNSEGL_AUTHWRITER_ROLE:-innsegl_authwriter}"
: "${INNSEGL_AUTHWRITER_PASSWORD:?db-init: INNSEGL_AUTHWRITER_PASSWORD must be set}"

# RM-330 (ADR-0044's 2026-10-03 amendment) — api.ResolverRole. It may insert
# an alert resolution and nothing else; `innsegl api` resolves alerts from the
# dashboard through it. Like the others, a default and not a protected string.
RESOLVER_ROLE="${INNSEGL_RESOLVER_ROLE:-innsegl_resolver}"
: "${INNSEGL_RESOLVER_PASSWORD:?db-init: INNSEGL_RESOLVER_PASSWORD must be set}"

check_password owner "${PGPASSWORD}"
check_password appender "${INNSEGL_APPENDER_PASSWORD}"
check_password reader "${INNSEGL_READER_PASSWORD}"
check_password backup "${INNSEGL_BACKUP_PASSWORD}"
check_password authwriter "${INNSEGL_AUTHWRITER_PASSWORD}"
check_password resolver "${INNSEGL_RESOLVER_PASSWORD}"

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

# internal/api/authwriter.sql, reached BY MOUNT for the identical reason.
AUTHWRITER_SQL="${INNSEGL_AUTHWRITER_SQL:-/innsegl/api/authwriter.sql}"

# internal/api/resolver.sql, reached BY MOUNT for the identical reason.
RESOLVER_SQL="${INNSEGL_RESOLVER_SQL:-/innsegl/api/resolver.sql}"

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
check_role_name "${AUTHWRITER_ROLE}"
check_role_name "${RESOLVER_ROLE}"
if [ "${ROLE}" = "${READER_ROLE}" ]; then
  fail "the append-only role and the read-only role are both \"${ROLE}\"; one role cannot be both"
fi
if [ "${READER_ROLE}" = "${PGUSER}" ]; then
  fail "the read-only role is the schema OWNER (\"${PGUSER}\"). readonly.sql cannot make an owner read-only: it is refused by the append-only TRIGGER (IN001) and never by the ACL, which is the exact confusion verify-reader-role.sh exists to catch"
fi
if [ "${AUTHWRITER_ROLE}" = "${ROLE}" ] || [ "${AUTHWRITER_ROLE}" = "${READER_ROLE}" ]; then
  fail "the auth-writer role \"${AUTHWRITER_ROLE}\" collides with another role this script provisions; RM-260/RM-261 requires it hold neither the appender's nor the reader's grants"
fi
case "${RESOLVER_ROLE}" in
  "${ROLE}"|"${READER_ROLE}"|"${AUTHWRITER_ROLE}"|"${BACKUP_ROLE}"|"${PGUSER}")
    fail "the resolver role \"${RESOLVER_ROLE}\" collides with another role; RM-330 requires a role that may insert an alert resolution and nothing else" ;;
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
# 1b. Move an existing ledger onto this host's own passwords (ADR-0078).
#
# A ledger made by an earlier release has its owner and roles on the old
# public values, or on values an operator set. The files are this host's
# own. When the server refuses the owner's file password, the old one is
# tried: $INNSEGL_LEDGER_OWNER_PASSWORD if the operator set it, else the old
# public default. If one opens, ONE transaction sets the owner's password and
# every existing role's from the files. It commits whole or not at all: a
# failure leaves every old password working, and the run refuses. The lock
# timeout makes a role held by another session fail the run rather than hang
# the bring-up.
#
# A second run finds that the file's password opens, and moves nothing.
# ---------------------------------------------------------------------------

# owner_try prints "open", "refused" (the server rejected the password) or
# the error, for one candidate owner password. psql is called directly, not
# through a function, so the PGPASSWORD given here applies to it alone.
owner_try() {
  try_out="$(PGPASSWORD="$1" psql -X -q -A -t -c 'SELECT 1' 2>&1)" && { echo open; return 0; }
  case "${try_out}" in
    *"password authentication failed"*) echo refused ;;
    *) printf '%s\n' "${try_out}" ;;
  esac
}

move_ledger_passwords() {
  old="$1"
  existing="$(PGPASSWORD="${old}" psql -X -q -v ON_ERROR_STOP=1 -A -t -c \
    "SELECT rolname FROM pg_roles WHERE rolname IN ('${ROLE}', '${READER_ROLE}', '${BACKUP_ROLE}', '${AUTHWRITER_ROLE}', '${RESOLVER_ROLE}') ORDER BY rolname")" \
    || fail "could not list the ledger's roles with the old owner password; nothing was changed"
  sql="BEGIN;
SET LOCAL lock_timeout = '${INNSEGL_CREDENTIALS_LOCK_TIMEOUT:-10s}';
\\set owner '${PGUSER}'
\\set pass '${PGPASSWORD}'
ALTER ROLE :\"owner\" PASSWORD :'pass';"
  for r in ${existing}; do
    if   [ "${r}" = "${ROLE}" ];            then p="${INNSEGL_APPENDER_PASSWORD}"
    elif [ "${r}" = "${READER_ROLE}" ];     then p="${INNSEGL_READER_PASSWORD}"
    elif [ "${r}" = "${BACKUP_ROLE}" ];     then p="${INNSEGL_BACKUP_PASSWORD}"
    elif [ "${r}" = "${AUTHWRITER_ROLE}" ]; then p="${INNSEGL_AUTHWRITER_PASSWORD}"
    else                                         p="${INNSEGL_RESOLVER_PASSWORD}"
    fi
    sql="${sql}
\\set role '${r}'
\\set pass '${p}'
ALTER ROLE :\"role\" PASSWORD :'pass';"
  done
  p=''
  sql="${sql}
COMMIT;"
  # ON_ERROR_STOP ends the session at the first error, and a session that
  # ends inside BEGIN is rolled back: all of these, or none.
  if ! printf '%s\n' "${sql}" | PGPASSWORD="${old}" psql -X -q -v ON_ERROR_STOP=1 -f - >/dev/null; then
    sql=''
    fail "REFUSED: moving the ledger's passwords did not complete and was rolled back. Every old password still works; nothing was changed. Run the update again; if it fails the same way, the error above says why"
  fi
  sql=''
  log "moved the owner and $(printf '%s\n' ${existing} | grep -c .) role(s) onto this host's own passwords, in one transaction"
}

if [ -n "${CREDENTIALS_DIR}" ]; then
  state="$(owner_try "${PGPASSWORD}")"
  case "${state}" in
    open) log "the owner opens with this host's own password; nothing to move" ;;
    refused)
      old=''
      if [ -n "${INNSEGL_LEDGER_OWNER_PASSWORD:-}" ] \
        && [ "$(owner_try "${INNSEGL_LEDGER_OWNER_PASSWORD}")" = open ]; then
        old="${INNSEGL_LEDGER_OWNER_PASSWORD}"
        log "the owner opens with \$INNSEGL_LEDGER_OWNER_PASSWORD; moving the ledger onto this host's own passwords"
      elif [ "$(owner_try "${LEDGER_OWNER_LEGACY_PUBLIC_PASSWORD}")" = open ]; then
        old="${LEDGER_OWNER_LEGACY_PUBLIC_PASSWORD}"
        log "the owner opens with the public default earlier releases shipped; moving the ledger onto this host's own passwords"
      else
        fail "REFUSED: the ledger's owner opens with none of: this host's password file, \$INNSEGL_LEDGER_OWNER_PASSWORD, the old public default. Nothing was changed. Restore the trust credentials volume from the trust-key backup, or set INNSEGL_LEDGER_OWNER_PASSWORD once to the owner's current password and run the update again"
      fi
      move_ledger_passwords "${old}"
      [ "$(owner_try "${PGPASSWORD}")" = open ] \
        || fail "the move committed, but the owner does not open with the new password"
      [ "$(owner_try "${old}")" = refused ] \
        || fail "the move committed, but the old owner password still opens"
      old=''
      log 'the old owner password is refused now, and the new one opens'
      ;;
    *) fail "could not connect as the owner: ${state}" ;;
  esac
fi

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
# :'pass' literal quoting and never through the shell's. The password is set
# with \set inside that script, so it is on no command line (ADR-0078);
# check_password is why the \set needs no escaping.
psql_owner -v role="${ROLE}" <<SQL
\set pass '${INNSEGL_APPENDER_PASSWORD}'
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

psql_owner -v role="${READER_ROLE}" <<SQL
\set pass '${INNSEGL_READER_PASSWORD}'
${reader_verb} ROLE :"role" LOGIN PASSWORD :'pass';
SQL

# apply_readonly_sql translates Go's fmt verbs into psql's variables and applies
# the result. The `case` afterwards is not decoration: if internal/api grows a
# %[3]s, or switches to a bare %s, sed leaves it in place and psql would fail
# somewhere in the middle of a REVOKE — or, worse, succeed with a literal
# `%[3]s` swallowed by a comment. Refusing loudly here is what makes the mount
# safe to rely on.
apply_readonly_sql() {
  apply_role="$1"
  grants="$(sed -e 's/%\[1\]s/:"role"/g' -e 's/%\[2\]s/:"db"/g' "${READONLY_SQL}")"
  if printf '%s\n' "${grants}" | grep -Eq '%(\[|[A-Za-z])'; then
    printf 'db-init: untranslated:\n%s\n' \
      "$(printf '%s\n' "${grants}" | grep -En '%(\[|[A-Za-z])')" >&2
    fail "${READONLY_SQL} still contains an fmt verb after translation. It is internal/api's file and it has changed shape; teach the sed in apply_readonly_sql about the new verb rather than copying the GRANTs into deploy/, which is how the two would drift"
  fi
  printf '%s\n' "${grants}" |
    psql_owner -v role="${apply_role}" -v db="${PGDATABASE}" -f -
}

log "applying ${READONLY_SQL} to ${READER_ROLE}"
apply_readonly_sql "${READER_ROLE}"

# ---------------------------------------------------------------------------
# 5b. The backup's role: the reader's grants, then CREATEDB. See BACKUP_ROLE.
# ---------------------------------------------------------------------------
backup_exists="$(psql_owner -A -t -c "SELECT 1 FROM pg_roles WHERE rolname = '${BACKUP_ROLE}'")"
if [ -z "${backup_exists}" ]; then
  backup_verb=CREATE
  log "creating role ${BACKUP_ROLE}"
else
  backup_verb=ALTER
  log "role ${BACKUP_ROLE} already exists; resetting its password and its grants"
fi

psql_owner -v role="${BACKUP_ROLE}" <<SQL
\set pass '${INNSEGL_BACKUP_PASSWORD}'
${backup_verb} ROLE :"role" LOGIN PASSWORD :'pass';
SQL

log "applying ${READONLY_SQL} to ${BACKUP_ROLE}"
apply_readonly_sql "${BACKUP_ROLE}"

# AFTER the grants, never before: readonly.sql ends with NOCREATEDB and the
# order is what makes this the effective state rather than a line that was
# silently overwritten.
log "granting CREATEDB to ${BACKUP_ROLE} (throwaway restore databases only)"
psql_owner -v role="${BACKUP_ROLE}" <<'SQL'
ALTER ROLE :"role" CREATEDB;
SQL

# ---------------------------------------------------------------------------
# 6. Ask the server about the reader, for the same reason as step 4.
# ---------------------------------------------------------------------------
log "verifying the read-only credential against the server"
sh "${HERE}/verify-reader-role.sh"

# ---------------------------------------------------------------------------
# 7. And the backup's, which is the one role whose POSITIVE case matters as
#    much as its refusals: a scope too narrow to take a backup fails at 3am in
#    a service nobody is watching. OPS-043.
# ---------------------------------------------------------------------------
log "verifying the backup credential against the server"
sh "${HERE}/verify-backup-role.sh"

# ---------------------------------------------------------------------------
# 8. RM-260/RM-261 (ADR-0062) — the auth-writer role. Full CRUD on
#    innsegl_auth, nothing on innsegl: the opposite grant from the reader's,
#    applied the SAME way (mount, not copy — see AUTHWRITER_SQL above).
# ---------------------------------------------------------------------------
[ -f "${AUTHWRITER_SQL}" ] || fail "no auth-writer grants at ${AUTHWRITER_SQL} (\$INNSEGL_AUTHWRITER_SQL). deploy/compose/innsegl.yml mounts internal/api/authwriter.sql there; a second copy of those GRANTs under deploy/ is the wrong fix"

authwriter_exists="$(psql_owner -A -t -c "SELECT 1 FROM pg_roles WHERE rolname = '${AUTHWRITER_ROLE}'")"
if [ -z "${authwriter_exists}" ]; then
  authwriter_verb=CREATE
  log "creating role ${AUTHWRITER_ROLE}"
else
  authwriter_verb=ALTER
  log "role ${AUTHWRITER_ROLE} already exists; resetting its password and its grants"
fi

psql_owner -v role="${AUTHWRITER_ROLE}" <<SQL
\set pass '${INNSEGL_AUTHWRITER_PASSWORD}'
${authwriter_verb} ROLE :"role" LOGIN PASSWORD :'pass';
SQL

# apply_authwriter_sql is apply_readonly_sql's own translation, applied to
# the other file — kept separate rather than parameterised, because the two
# grant files are independent artefacts owned by the same Go package and a
# shared helper would be one more thing for a future %[3]s in either to have
# to reason about correctly.
apply_authwriter_sql() {
  apply_role="$1"
  grants="$(sed -e 's/%\[1\]s/:"role"/g' -e 's/%\[2\]s/:"db"/g' "${AUTHWRITER_SQL}")"
  if printf '%s\n' "${grants}" | grep -Eq '%(\[|[A-Za-z])'; then
    printf 'db-init: untranslated:\n%s\n' \
      "$(printf '%s\n' "${grants}" | grep -En '%(\[|[A-Za-z])')" >&2
    fail "${AUTHWRITER_SQL} still contains an fmt verb after translation. It is internal/api's file and it has changed shape; teach the sed in apply_authwriter_sql about the new verb rather than copying the GRANTs into deploy/, which is how the two would drift"
  fi
  printf '%s\n' "${grants}" |
    psql_owner -v role="${apply_role}" -v db="${PGDATABASE}" -f -
}

log "applying ${AUTHWRITER_SQL} to ${AUTHWRITER_ROLE}"
apply_authwriter_sql "${AUTHWRITER_ROLE}"

# ---------------------------------------------------------------------------
# 9. Ask the server about the auth-writer, for the same reason as steps 4
#    and 6 — and the last check this script runs.
# ---------------------------------------------------------------------------
log "verifying the auth-writer credential against the server"
sh "${HERE}/verify-authwriter-role.sh"

# ---------------------------------------------------------------------------
# 10. RM-330 (ADR-0044's 2026-10-03 amendment) — the resolver role: insert an
#     alert resolution, nothing else. Applied the SAME way (mount, not copy).
# ---------------------------------------------------------------------------
[ -f "${RESOLVER_SQL}" ] || fail "no resolver grants at ${RESOLVER_SQL} (\$INNSEGL_RESOLVER_SQL). deploy/compose/innsegl.yml mounts internal/api/resolver.sql there; a second copy of those GRANTs under deploy/ is the wrong fix"

resolver_exists="$(psql_owner -A -t -c "SELECT 1 FROM pg_roles WHERE rolname = '${RESOLVER_ROLE}'")"
if [ -z "${resolver_exists}" ]; then
  resolver_verb=CREATE
  log "creating role ${RESOLVER_ROLE}"
else
  resolver_verb=ALTER
  log "role ${RESOLVER_ROLE} already exists; resetting its password and its grants"
fi

psql_owner -v role="${RESOLVER_ROLE}" <<SQL
\set pass '${INNSEGL_RESOLVER_PASSWORD}'
${resolver_verb} ROLE :"role" LOGIN PASSWORD :'pass';
SQL

# The same translation as apply_authwriter_sql, for the same two verbs.
resolver_grants="$(sed -e 's/%\[1\]s/:"role"/g' -e 's/%\[2\]s/:"db"/g' "${RESOLVER_SQL}")"
if printf '%s\n' "${resolver_grants}" | grep -Eq '%(\[|[A-Za-z])'; then
  fail "${RESOLVER_SQL} still contains an fmt verb after translation; teach this translation the new verb rather than copying the GRANTs into deploy/"
fi
log "applying ${RESOLVER_SQL} to ${RESOLVER_ROLE}"
printf '%s\n' "${resolver_grants}" |
  psql_owner -v role="${RESOLVER_ROLE}" -v db="${PGDATABASE}" -f -

# ---------------------------------------------------------------------------
# 11. Ask the server about the resolver — the last check this script runs.
# ---------------------------------------------------------------------------
log "verifying the resolver credential against the server"
exec sh "${HERE}/verify-resolver-role.sh"
