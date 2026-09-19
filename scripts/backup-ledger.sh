#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Take a verified backup of the ledger hot tier (issue #160, RM-099).
#
# WHAT THIS IS FOR
# ----------------
# runbooks/index-rebuild.md §0: a sealed segment adjudicates a backup, it does
# not supply one -- "there is no rebuild-from-segments-alone". If every
# Postgres backup is gone, the event bodies (agent_type, task_ref, run_id,
# every tool_call and its digest) are gone with them, and nothing in this
# repository recovers them. So a backup nobody has checked against the sealed
# segments is not evidence, it is a file that looks like evidence.
#
# This script takes that check at BACKUP time rather than only at restore
# time, per the issue: "A backup nobody has verified is the same shape as a
# gate nobody has watched fail." It does four things, in order:
#
#   1. pg_dump the whole `innsegl` database OVER THE NETWORK, as a role that
#      can read it and cannot write it.
#   2. Restore that dump into a throwaway database on the SAME server -- never
#      the live one (runbooks/index-rebuild.md §2.2) -- which proves the dump
#      actually restores rather than merely that pg_dump exited 0.
#   3. Extract the restored event_hash column, in chain_position order.
#   4. Adjudicate it against the sealed segments with the gate this repository
#      already ships and already self-tests: runbooks/verify-rebuilt-index.sh.
#      This script does not re-implement that check; a second implementation
#      of "does the index match the segments" is a second thing that can
#      disagree with the first (doc 04 §5.4).
#
# WHAT IS IN THE DUMP
# --------------------
# The whole `innsegl` database, not a two-table extract of innsegl.events and
# innsegl.chain. A restore per runbooks/index-rebuild.md §4 loads the dump into
# a FRESH database and expects the schema -- the append-only triggers, the
# chain-link trigger, the CHECK constraints -- to come back with it, not to be
# re-applied from migrations by hand. It also expects innsegl.idempotency
# (migration 0002): without it a resumed MCP would be unable to tell a retried
# request from a new one and could re-append an event a client believes it
# already sent. The evidence lives in two tables; a *usable* restore needs the
# schema that enforces what the evidence means.
#
# WHERE THE DUMP GOES
# --------------------
# A local path, by default $INNSEGL_BACKUP_DIR or ./backups. doc 05 §2 already
# specifies WORM object storage with a lock for segments, and the issue names
# it as the eventual home for this dump too -- but this script does not upload
# anywhere. Shipping a cloud upload path here would mean this repository
# holding credentials for a bucket it does not operate, for a destination the
# maintainer has not chosen. A local path is the smallest correct default: it
# works with no configuration, on the laptop this is most likely to be run
# from first, and moving the file to WORM storage afterwards is one `aws s3 cp`
# regardless of which bucket is decided on.
#
# WHAT "VERIFIED" MEANS WHEN THE SEGMENTS ARE MISSING
# ----------------------------------------------------
# A backup taken with no sealed segments to check it against is not called
# good. It is not refused either -- refusing to write the dump because the
# object store is unreachable would leave an operator with nothing at all
# during exactly the outage this exists for. So the dump is always written and
# always kept; what changes is the exit status and the words printed. Loud and
# unverified beats quiet and unverified, which is the whole argument of §0.
#
# THE TWO WAYS A BACKUP FAILS MEAN OPPOSITE THINGS (RM-163, #267)
# ----------------------------------------------------------------
# Until this issue both of them exited 5, and a caller that could not tell them
# apart had one sensible response left: treat every failure as final and wait.
# That is what happened on the day #267 records -- the ledger was unreachable
# for about two minutes during a database restart, and the next attempt was a
# day later.
#
#   COULD NOT REACH THE LEDGER (exit 6). Nothing was dumped, so nothing has been
#   learned about the ledger or about any dump. This says nothing bad about the
#   backup; it says the ledger did not answer. Worth trying again shortly.
#
#   A DUMP WAS PRODUCED AND DOES NOT VERIFY (exit 5, exit 3). The ledger
#   answered. What came back is empty, or will not restore, or restores and
#   disagrees with a sealed segment. Retrying that in seconds produces a second
#   bad dump; exit 3 in particular is an integrity incident and wants a person.
#
# Which one a mid-run failure was is decided by ASKING THE LEDGER AGAIN, not by
# reading the client's error text. A message is a string that changes between
# client versions; a connection either opens or it does not.
#
# WHAT A FAILURE SAYS ABOUT WHAT IS AT RISK. "FAILED" does not say what is
# unprotected. Every failing run measures two numbers -- how long since the last
# dump that actually verified, and how many events have been appended above it
# -- prints them, and leaves them in $out_dir/.exposure for the scheduler to
# repeat. They are cleared at the start of every run, so a stale number is never
# reported as a current one, and a run that succeeds leaves none behind.
#
# EXIT STATUS (does not reuse verify-rebuilt-index.sh's numbers on purpose --
# this is a different contract with an extra failure mode of its own)
#   0  the dump was taken, restores, and matches every sealed segment it covers
#   2  the command line was not understood
#   3  the dump was taken and restores, but disagrees with a sealed segment --
#      an integrity incident, not a backup. Do not rely on it.
#   4  the dump was taken and restores, but no sealed segments were available
#      to adjudicate it against. It is kept, and it is unverified.
#   5  a dump was produced and is not usable: it is empty, it does not restore,
#      or the restore could not be read back. The ledger answered.
#   6  the ledger could not be reached, so no usable dump was produced and none
#      was judged. Transient until shown otherwise.
#
# Portability: bash 3.2 (macOS), the same discipline as verify-rebuilt-index.sh
# and the scripts/*.sh gates. No mapfile, no arrays, no ${var,,}.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
GATE="${REPO_ROOT}/runbooks/verify-rebuilt-index.sh"

readonly EXIT_OK=0
readonly EXIT_USAGE=2
readonly EXIT_MISMATCH=3
readonly EXIT_UNVERIFIED=4
readonly EXIT_DUMP_FAILED=5
readonly EXIT_UNREACHABLE=6


usage() {
  cat <<'USAGE'
backup-ledger.sh - take a pg_dump of the innsegl ledger and verify it against
                    the sealed segments before calling it good

Usage:
  scripts/backup-ledger.sh [options]

Options:
  --out DIR               directory to write the dump and its verification
                          report into (default: $INNSEGL_BACKUP_DIR or
                          ./backups)
  --postgres-host H       ledger host to connect to (default: $PGHOST or
                          postgres). A NETWORK client: this script holds no
                          container-runtime socket and launches no container.
  --postgres-port P       (default: $PGPORT or 5432)
  --database NAME         database to dump (default: innsegl)
  --role NAME             database role to connect as (default:
                          $INNSEGL_BACKUP_ROLE or innsegl_backup). Its password
                          comes from $INNSEGL_BACKUP_PASSWORD, never an
                          argument, so it cannot reach a process listing.
  --segments DIR          a directory of already-fetched sealed segment
                          objects (see runbooks/index-rebuild.md §6.1). Skips
                          fetching from object storage -- use this for a
                          restore you already staged, or in a test.
  --object-store-endpoint host:port of the object store's S3 GATEWAY. Not the
                          Filer or the volume server: those have one route in
                          and it is the gateway (doc 05 §1)
                          (default: innsegl-s3:8333)
  --object-store-bucket NAME   segment bucket (default: innsegl-segments)
  --object-store-prefix P      key prefix segments are stored under, matching
                          $INNSEGL_OBJECT_STORE_PREFIX on the sealer
                          (default: segments/, deploy/compose/innsegl.yml's
                          default -- the innsegl binary's own default is "")
  --object-store-access-key K  (default: innsegl)
  --object-store-secret-key K  (default: innsegl-compose-objects)
  --quiet                 print less on success; failures are always reported
  -h, --help              this text

Exit status: see the header comment of this script. In short: 0 verified,
3 disagrees with a sealed segment, 4 kept but unadjudicated, 5 a dump that is
not usable, 6 the ledger could not be reached.
USAGE
}

# ---------------------------------------------------------------------------
# Arguments.
# ---------------------------------------------------------------------------

out_dir="${INNSEGL_BACKUP_DIR:-${REPO_ROOT}/backups}"
pg_host="${PGHOST:-postgres}"
pg_port="${PGPORT:-5432}"
database="${PGDATABASE:-innsegl}"
role="${INNSEGL_BACKUP_ROLE:-innsegl_backup}"
segments_dir=""
object_store_endpoint="innsegl-s3:8333"
object_store_bucket="innsegl-segments"
object_store_prefix="segments/"
object_store_access_key="innsegl"
object_store_secret_key="innsegl-compose-objects"
object_store_region="${INNSEGL_OBJECT_STORE_REGION:-us-east-1}"
quiet=0

while [ $# -gt 0 ]; do
  case "$1" in
    --out)                     out_dir="${2-}"; shift 2 || true ;;
    --postgres-host)           pg_host="${2-}"; shift 2 || true ;;
    --postgres-port)           pg_port="${2-}"; shift 2 || true ;;
    --database)                database="${2-}"; shift 2 || true ;;
    --role)                    role="${2-}"; shift 2 || true ;;
    --segments)                segments_dir="${2-}"; shift 2 || true ;;
    --object-store-endpoint)   object_store_endpoint="${2-}"; shift 2 || true ;;
    --object-store-bucket)     object_store_bucket="${2-}"; shift 2 || true ;;
    --object-store-prefix)     object_store_prefix="${2-}"; shift 2 || true ;;
    --object-store-access-key) object_store_access_key="${2-}"; shift 2 || true ;;
    --object-store-secret-key) object_store_secret_key="${2-}"; shift 2 || true ;;
    --quiet)                   quiet=1; shift ;;
    -h|--help)                 usage; exit "${EXIT_OK}" ;;
    *)
      printf 'backup-ledger: unknown argument %s\n\n' "$1" >&2
      usage >&2
      exit "${EXIT_USAGE}"
      ;;
  esac
done

if [ ! -x "${GATE}" ]; then
  printf 'backup-ledger: %s is missing or not executable\n' "${GATE}" >&2
  exit "${EXIT_USAGE}"
fi
if [ -z "${INNSEGL_BACKUP_PASSWORD:-}" ]; then
  printf 'backup-ledger: INNSEGL_BACKUP_PASSWORD is unset. This connects over the network as\n' >&2
  printf '  %s and needs its password; it is never an argument, because an argument\n' "${role}" >&2
  printf '  is visible in a process listing to everything else on the machine.\n' >&2
  exit "${EXIT_USAGE}"
fi
if [ -n "${segments_dir}" ] && [ ! -d "${segments_dir}" ]; then
  printf 'backup-ledger: --segments %s is not a directory\n' "${segments_dir}" >&2
  exit "${EXIT_USAGE}"
fi
export PGPASSWORD="${INNSEGL_BACKUP_PASSWORD}"

say()  { [ "${quiet}" -eq 1 ] || printf '%s\n' "$*"; }
warn() { printf '%s\n' "$*" >&2; }

mkdir -p "${out_dir}"

# THE TWO WAYS THIS TALKS TO THE LEDGER, and the difference between them is
# the whole of what the backup role may do.
#
# pg_ro is the role as it is: internal/api/readonly.sql leaves it with
# default_transaction_read_only = on, so a session that never turns that off
# cannot write anywhere, and the dump does not need to.
#
# pg_rw turns it off, which the restore must, because a restore writes. That is
# safe because the setting is NOT the boundary: the ACL is, and
# verify-backup-role.sh proves it by issuing SET TRANSACTION READ WRITE and
# still being refused 42501 on every ledger write. With it off this credential
# can write exactly one place -- a database it created and owns.
pg_ro() {
  cmd="$1"; shift
  "${cmd}" -h "${pg_host}" -p "${pg_port}" -U "${role}" "$@"
}
pg_rw() {
  cmd="$1"; shift
  PGOPTIONS='-c default_transaction_read_only=off' \
    "${cmd}" -h "${pg_host}" -p "${pg_port}" -U "${role}" "$@"
}

# ---------------------------------------------------------------------------
# What is at risk while this keeps failing (RM-163, #267).
#
# "FAILED" names the fault and not the cost. The cost is two numbers, and both
# were worked out by hand after the fact on the day #267 records: how long ago
# the last dump that ACTUALLY VERIFIED was taken, and how many events have been
# appended above it. Neither needs anything this script does not already hold.
# ---------------------------------------------------------------------------

# Set once a dump is attempted. The exposure must never count the dump this run
# just produced -- on a mismatch that file exists, has a report beside it, and
# is precisely the one thing that has been shown not to be a backup.
dumpfile=""
exposure_file="${out_dir}/.exposure"

# CLEARED AT THE START OF EVERY RUN. A number left over from yesterday's failure
# reported as today's is worse than no number: it reads as a measurement.
#
# `|| true` because a backup directory that has gone READ-ONLY is one of the
# failures this script exists to report, and `set -e` would turn it into a
# silent exit 1 here -- before the run that would have said so.
rm -f "${exposure_file}" 2>/dev/null || true

ledger_reachable() {
  psql -X -q -A -t -h "${pg_host}" -p "${pg_port}" -U "${role}" -d "${database}" \
    -c 'SELECT 1' >/dev/null 2>&1
}

ledger_event_count() {
  n=""
  n="$(pg_ro psql -d "${database}" -X -q -A -t \
        -c 'SELECT count(*) FROM innsegl.events' 2>/dev/null | tr -d ' \r\n')" || n=""
  case "${n}" in ''|*[!0-9]*) n="" ;; esac
  printf '%s' "${n}"
}

# A DUMP IS "USABLE" IF IT HAS A VERIFICATION REPORT BESIDE IT, because that
# report is only written after the dump has been restored into a throwaway
# database and put to the gate. A `.dump` on its own may be the truncated
# remains of a run that died at step 1, which is exactly the file that must not
# be counted as protection. Nothing is deleted to establish this: the test is
# what is there, not what is removed.
#
# The glob is already in lexical order and the names are fixed-width UTC
# stamps, so the last one that qualifies is the newest.
last_usable_dump() {
  best=""
  for f in "${out_dir}"/innsegl-*.dump; do
    [ -f "${f}" ] || continue
    if [ "${f}" != "${dumpfile}" ] && [ -f "${f}.verify.txt" ]; then
      best="${f}"
    fi
  done
  printf '%s' "${best}"
}

stamp_to_iso() {
  printf '%s' "$1" | sed 's/^\(....\)\(..\)\(..\)T\(..\)\(..\)\(..\)Z$/\1-\2-\3T\4:\5:\6Z/'
}

# Both spellings, because this runs in two places: the deployment's image, whose
# date is BusyBox and takes -d, and a maintainer's machine, whose date is BSD
# and takes -j -f. Neither is asked to parse the compact form directly.
stamp_to_epoch() {
  d="$(printf '%s' "$1" | sed 's/^\(....\)\(..\)\(..\)T\(..\)\(..\)\(..\)Z$/\1-\2-\3 \4:\5:\6/')"
  [ "${d}" != "$1" ] || { printf ''; return 0; }
  date -u -d "${d}" +%s 2>/dev/null && return 0
  date -u -j -f '%Y-%m-%d %H:%M:%S' "${d}" +%s 2>/dev/null && return 0
  printf ''
}

human_age() {
  secs="$1"
  d=$((secs / 86400)); h=$(((secs % 86400) / 3600)); m=$(((secs % 3600) / 60))
  if   [ "${d}" -gt 0 ]; then printf '%dd %dh' "${d}" "${h}"
  elif [ "${h}" -gt 0 ]; then printf '%dh %dm' "${h}" "${m}"
  elif [ "${m}" -gt 0 ]; then printf '%dm' "${m}"
  else printf '%ds' "${secs}"; fi
}

# report_exposure reachable|unreachable
#
# The caller says whether the ledger is answering, because that decides whether
# the second number can be taken at all. An unreachable ledger gets the words
# "not counted" and never a guess: a backup report that invents a number is the
# same failure as a backup nobody checked.
report_exposure() {
  reach="$1"
  now_s="$(date -u +%s)"
  best="$(last_usable_dump)"
  dumped=""

  if [ -n "${best}" ]; then
    stamp="${best##*/innsegl-}"; stamp="${stamp%.dump}"
    iso="$(stamp_to_iso "${stamp}")"
    then_s="$(stamp_to_epoch "${stamp}")"
    if [ -n "${then_s}" ] && [ "${now_s}" -ge "${then_s}" ]; then
      when_line="$(printf '%-18s %s (%s ago)' 'last usable dump' "${iso}" "$(human_age $((now_s - then_s)))")"
    else
      when_line="$(printf '%-18s %s' 'last usable dump' "${iso}")"
    fi
    dumped="$(awk '$1 == "events" { print $2; exit }' "${best}.verify.txt" 2>/dev/null || true)"
    case "${dumped}" in ''|*[!0-9]*) dumped="" ;; esac
  else
    when_line="$(printf '%-18s %s' 'last usable dump' 'none -- nothing here has verified yet')"
  fi

  if [ "${reach}" != "reachable" ]; then
    events_line="$(printf '%-18s %s' 'events above it' 'not counted -- the ledger is unreachable')"
  else
    total="$(ledger_event_count)"
    if [ -z "${total}" ]; then
      events_line="$(printf '%-18s %s' 'events above it' 'not counted -- the ledger did not answer the count')"
    elif [ -n "${dumped}" ]; then
      above=$((total - dumped))
      [ "${above}" -ge 0 ] || above=0
      events_line="$(printf '%-18s %s' 'events above it' "${above}")"
    else
      events_line="$(printf '%-18s every one of the %s in the ledger' 'events above it' "${total}")"
    fi
  fi

  # Written whole and moved into place, for the reason backup-loop.sh's marker
  # is: whoever reads it may read it at any moment. Errors are swallowed: a
  # backup directory that cannot be written to is already being reported by the
  # lines below, and a redirection error on top of them says nothing new.
  { printf '%s\n%s\n' "${when_line}" "${events_line}" >"${exposure_file}.$$" &&
      mv -- "${exposure_file}.$$" "${exposure_file}"; } 2>/dev/null || true

  warn ""
  warn "backup-ledger: AT RISK -- what is unprotected while this keeps failing"
  warn "    ${when_line}"
  warn "    ${events_line}"
}

# WHICH FAILURE THIS WAS, decided by asking the ledger again rather than by
# reading the client's error text. A dump step fails both when the dump is bad
# and when the ledger went away halfway through, and those want opposite
# responses from the caller. If the ledger is gone, nothing here has grounds to
# call the dump unusable, and saying so would be an integrity claim made on no
# evidence.
end_dump_failure() {
  if ledger_reachable; then
    report_exposure reachable
    exit "${EXIT_DUMP_FAILED}"
  fi
  warn "backup-ledger: TRANSIENT -- the ledger stopped answering during the run, so nothing here"
  warn "  can say whether the dump is usable. Reported as unreachable, not as a bad dump."
  report_exposure unreachable
  exit "${EXIT_UNREACHABLE}"
}

if ! ledger_reachable; then
  warn "backup-ledger: cannot reach the ledger as ${role} at ${pg_host}:${pg_port}/${database} -- is the stack up?"
  warn "backup-ledger: TRANSIENT -- no dump was attempted, so nothing has been learned about the"
  warn "  ledger or about any dump. Worth trying again shortly rather than waiting out a whole"
  warn "  interval; a database that was down for two minutes is the ordinary case."
  report_exposure unreachable
  exit "${EXIT_UNREACHABLE}"
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/innsegl-backup.XXXXXX")"
cleanup_scratch_db=""
cleanup() {
  status=$?
  if [ -n "${cleanup_scratch_db}" ]; then
    pg_rw dropdb --if-exists "${cleanup_scratch_db}" >/dev/null 2>&1 || true
  fi
  rm -rf "${work}"
  exit "${status}"
}
trap cleanup EXIT

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
dumpfile="${out_dir}/innsegl-${timestamp}.dump"
report_file="${dumpfile}.verify.txt"

# ---------------------------------------------------------------------------
# 1. pg_dump, over the network as the backup role -- reachable only on the
#    ledger network, which is the same reason deploy/compose/innsegl.yml
#    publishes no host port for postgres: a published port is a segmentation
#    hole, not a convenience. Reaching it from inside the deployment needs no
#    such hole, and needs no runtime socket either.
# ---------------------------------------------------------------------------
say "==> pg_dump ${database} from ${pg_host}:${pg_port} as ${role}"
if ! pg_ro pg_dump -d "${database}" -Fc -f "${dumpfile}" 2>"${work}/dump.err"; then
  warn "FAIL: pg_dump did not complete:"
  sed 's/^/    /' "${work}/dump.err" >&2 || true
  end_dump_failure
fi
if [ ! -s "${dumpfile}" ]; then
  warn "FAIL: ${dumpfile} is empty"
  end_dump_failure
fi
say "    wrote ${dumpfile} ($(wc -c <"${dumpfile}" | tr -d ' ') bytes)"

# ---------------------------------------------------------------------------
# 2. Restore into a throwaway database in the SAME container, never the live
#    one (runbooks/index-rebuild.md §2.2 -- restoring over a live database is
#    the one action here whose failure mode is silent). This is the check that
#    the dump is a dump and not just a file pg_dump happened to exit 0 on.
# ---------------------------------------------------------------------------
scratch_db="innsegl_backup_verify_${timestamp}_$$"
say "==> restoring into throwaway database ${scratch_db}"
if ! pg_rw createdb "${scratch_db}" 2>"${work}/createdb.err"; then
  warn "FAIL: could not create ${scratch_db}:"
  sed 's/^/    /' "${work}/createdb.err" >&2 || true
  end_dump_failure
fi
cleanup_scratch_db="${scratch_db}"
# --no-owner --no-acl, MEASURED and not defensive. The dump's objects belong to
# the schema owner, and this role is not a superuser, so it cannot SET SESSION
# AUTHORIZATION to become them: without these two flags every ALTER ... OWNER TO
# and every GRANT in the dump fails and --exit-on-error stops the restore. With
# them the objects are owned by the backup role inside a database only it can
# see, which is all the restore has to prove.
if ! pg_rw pg_restore -d "${scratch_db}" --no-owner --no-acl --exit-on-error \
    "${dumpfile}" 2>"${work}/restore.err"; then
  warn "FAIL: the dump does not restore -- it is not a usable backup:"
  sed 's/^/    /' "${work}/restore.err" >&2 || true
  end_dump_failure
fi
say "    restore held"

# ---------------------------------------------------------------------------
# 3. Extract the restored chain, in chain_position order -- exactly the query
#    runbooks/index-rebuild.md §6.2 documents for a rebuilt index.
# ---------------------------------------------------------------------------
if ! pg_ro psql -d "${scratch_db}" -X -q -A -t -c \
    'SELECT event_hash FROM innsegl.events ORDER BY chain_position' \
    >"${work}/index.hashes" 2>"${work}/select.err"; then
  warn "FAIL: could not read innsegl.events back from the restore:"
  sed 's/^/    /' "${work}/select.err" >&2 || true
  end_dump_failure
fi
event_count="$(grep -c . "${work}/index.hashes" || true)"
say "    restored ${event_count} event(s)"

pg_rw dropdb "${scratch_db}" >/dev/null 2>&1 || true
cleanup_scratch_db=""

# ---------------------------------------------------------------------------
# 4. The sealed segments. Fetched read-only from object storage unless a
#    directory was already staged with --segments.
# ---------------------------------------------------------------------------
fetched_segments=""
if [ -n "${segments_dir}" ]; then
  say "==> using staged segments at ${segments_dir}"
else
  segments_dir="${work}/segments"
  mkdir -p "${segments_dir}"
  fetched_segments=1
  say "==> fetching sealed segments from ${object_store_bucket}/${object_store_prefix} at ${object_store_endpoint}"
  # A NETWORK CLIENT, not a launched container. This used to be a `docker run`
  # on a named network, which meant the backup held the container-runtime
  # socket — root on the host — for the sake of copying some files it is only
  # allowed to read. The image this runs in carries the S3 client instead and
  # is on the object network itself, so the same fetch is one command with no
  # privilege attached to it.
  #
  # Credentials travel as environment, not as shell string interpolation, so a
  # value containing a quote cannot break the command.
  #
  # THE CREDENTIAL THIS RUNS AS IS A READER. It needs GetObject and ListBucket
  # under the segment prefix and nothing else; the scoped identity the sealer
  # holds is enough. Neither it nor anything else can delete what it is copying
  # -- COMPLIANCE retention refuses that to everyone -- so the fetch cannot
  # damage what it is verifying against.
  AWS_ENDPOINT_URL="http://${object_store_endpoint}" \
  AWS_ACCESS_KEY_ID="${object_store_access_key}" \
  AWS_SECRET_ACCESS_KEY="${object_store_secret_key}" \
  AWS_DEFAULT_REGION="${object_store_region}" \
  AWS_REQUEST_CHECKSUM_CALCULATION=when_required \
  AWS_RESPONSE_CHECKSUM_VALIDATION=when_required \
    aws s3 cp --recursive \
      "s3://${object_store_bucket}/${object_store_prefix}" "${segments_dir}/" \
      >"${work}/s3-fetch.log" 2>&1 || true
  n_fetched="$(find "${segments_dir}" -type f 2>/dev/null | grep -c . || true)"
  if [ "${n_fetched}" -eq 0 ]; then
    warn "    could not fetch any sealed segments (see ${work}/s3-fetch.log if this is unexpected)"
  else
    say "    fetched ${n_fetched} segment object(s)"
  fi
fi

# ---------------------------------------------------------------------------
# Adjudicate. This is the step the issue exists for: the dump is not called
# good until the gate says so.
# ---------------------------------------------------------------------------
say "==> checking the restored chain against the sealed segments"
gate_status=0
"${GATE}" --segments "${segments_dir}" --index-hashes "${work}/index.hashes" \
  >"${report_file}" 2>&1 || gate_status=$?

{
  printf 'innsegl backup verification report\n'
  printf 'generated  %s\n' "${timestamp}"
  printf 'dump       %s\n' "${dumpfile}"
  printf 'database   %s (%s:%s as %s)\n' "${database}" "${pg_host}" "${pg_port}" "${role}"
  printf 'events     %s\n' "${event_count}"
  printf 'segments   %s%s\n' "${segments_dir}" "$( [ -n "${fetched_segments}" ] && printf ' (fetched)' || printf ' (staged)')"
  printf '\n'
  cat "${report_file}"
} >"${work}/report.final"
mv -- "${work}/report.final" "${report_file}"

say ""
cat "${report_file}"
say ""

case "${gate_status}" in
  0)
    say "backup-ledger: OK -- ${dumpfile} restores and matches every sealed segment it covers"
    exit "${EXIT_OK}"
    ;;
  3)
    warn "backup-ledger: MISMATCH -- ${dumpfile} restores but disagrees with a sealed segment."
    warn "This is an integrity incident, not a verified backup. Do not rely on it (I4)."
    warn "See ${report_file}."
    # The ledger answered every question this run asked, so the count below is
    # a real count. The dump just written is excluded from it on purpose: it is
    # the one file here that has been shown not to be a backup.
    report_exposure reachable
    exit "${EXIT_MISMATCH}"
    ;;
  4)
    warn "backup-ledger: UNVERIFIED -- ${dumpfile} was taken and kept, but no sealed segments"
    warn "were available to check it against. This backup has NOT been adjudicated."
    warn "See ${report_file}."
    exit "${EXIT_UNVERIFIED}"
    ;;
  *)
    warn "backup-ledger: the verification gate exited ${gate_status}, which this script does"
    warn "not recognise. Treating the backup as unverified. See ${report_file}."
    exit "${EXIT_UNVERIFIED}"
    ;;
esac
