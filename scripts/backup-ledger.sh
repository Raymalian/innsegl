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
#   1. pg_dump the whole `innsegl` database from the running container.
#   2. Restore that dump into a throwaway database in the SAME container --
#      never the live one (runbooks/index-rebuild.md §2.2) -- which proves the
#      dump actually restores rather than merely that pg_dump exited 0.
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
# from first, and moving the file to WORM storage afterwards is one `mc cp`
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
# EXIT STATUS (does not reuse verify-rebuilt-index.sh's numbers on purpose --
# this is a different contract with an extra failure mode of its own)
#   0  the dump was taken, restores, and matches every sealed segment it covers
#   2  the command line was not understood
#   3  the dump was taken and restores, but disagrees with a sealed segment --
#      an integrity incident, not a backup. Do not rely on it.
#   4  the dump was taken and restores, but no sealed segments were available
#      to adjudicate it against. It is kept, and it is unverified.
#   5  the dump could not be taken, or could not be restored, at all
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

# The pin deploy/compose/innsegl.yml uses for minio/mc, copied rather than
# read from the compose file so this script has no YAML-parsing dependency.
# Kept in one place: grep this string in deploy/compose/innsegl.yml when
# bumping it there.
readonly DEFAULT_MC_IMAGE="minio/mc:RELEASE.2025-08-13T08-35-41Z@sha256:a7fe349ef4bd8521fb8497f55c6042871b2ae640607cf99d9bede5e9bdf11727"

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
  --postgres-container N  container to pg_dump from (default: innsegl-postgres)
  --database NAME         database to dump (default: innsegl)
  --owner NAME             database role pg_dump/pg_restore/createdb run as,
                          via the container's own unix socket (default: innsegl)
  --segments DIR          a directory of already-fetched sealed segment
                          objects (see runbooks/index-rebuild.md §6.1). Skips
                          fetching from object storage -- use this for a
                          restore you already staged, or in a test.
  --minio-network NAME    docker network the object store is reachable on,
                          used only when --segments is not given
                          (default: innsegl-objects)
  --object-store-endpoint host:port inside --minio-network (default: minio:9000)
  --object-store-bucket NAME   segment bucket (default: innsegl-segments)
  --object-store-prefix P      key prefix segments are stored under, matching
                          $INNSEGL_OBJECT_STORE_PREFIX on the sealer
                          (default: segments/, deploy/compose/innsegl.yml's
                          default -- the innsegl binary's own default is "")
  --object-store-access-key K  (default: innsegl)
  --object-store-secret-key K  (default: innsegl-compose-objects)
  --mc-image REF          minio/mc image reference used to fetch segments
  --quiet                 print less on success; failures are always reported
  -h, --help              this text

Exit status: see the header comment of this script.
USAGE
}

# ---------------------------------------------------------------------------
# Arguments.
# ---------------------------------------------------------------------------

out_dir="${INNSEGL_BACKUP_DIR:-${REPO_ROOT}/backups}"
pg_container="innsegl-postgres"
database="innsegl"
owner="innsegl"
segments_dir=""
minio_network="innsegl-objects"
object_store_endpoint="minio:9000"
object_store_bucket="innsegl-segments"
object_store_prefix="segments/"
object_store_access_key="innsegl"
object_store_secret_key="innsegl-compose-objects"
mc_image="${DEFAULT_MC_IMAGE}"
quiet=0

while [ $# -gt 0 ]; do
  case "$1" in
    --out)                     out_dir="${2-}"; shift 2 || true ;;
    --postgres-container)      pg_container="${2-}"; shift 2 || true ;;
    --database)                database="${2-}"; shift 2 || true ;;
    --owner)                   owner="${2-}"; shift 2 || true ;;
    --segments)                segments_dir="${2-}"; shift 2 || true ;;
    --minio-network)           minio_network="${2-}"; shift 2 || true ;;
    --object-store-endpoint)   object_store_endpoint="${2-}"; shift 2 || true ;;
    --object-store-bucket)     object_store_bucket="${2-}"; shift 2 || true ;;
    --object-store-prefix)     object_store_prefix="${2-}"; shift 2 || true ;;
    --object-store-access-key) object_store_access_key="${2-}"; shift 2 || true ;;
    --object-store-secret-key) object_store_secret_key="${2-}"; shift 2 || true ;;
    --mc-image)                mc_image="${2-}"; shift 2 || true ;;
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
if ! docker inspect "${pg_container}" >/dev/null 2>&1; then
  printf 'backup-ledger: no container named %s -- is the stack up? (make innsegl-up)\n' \
    "${pg_container}" >&2
  exit "${EXIT_DUMP_FAILED}"
fi
if [ -n "${segments_dir}" ] && [ ! -d "${segments_dir}" ]; then
  printf 'backup-ledger: --segments %s is not a directory\n' "${segments_dir}" >&2
  exit "${EXIT_USAGE}"
fi

say()  { [ "${quiet}" -eq 1 ] || printf '%s\n' "$*"; }
warn() { printf '%s\n' "$*" >&2; }

mkdir -p "${out_dir}"

work="$(mktemp -d "${TMPDIR:-/tmp}/innsegl-backup.XXXXXX")"
cleanup_scratch_db=""
cleanup() {
  status=$?
  if [ -n "${cleanup_scratch_db}" ]; then
    docker exec "${pg_container}" dropdb -U "${owner}" --if-exists "${cleanup_scratch_db}" \
      >/dev/null 2>&1 || true
  fi
  docker exec "${pg_container}" rm -f "/tmp/${dump_basename:-innsegl-backup-none}" \
    "/tmp/${dump_basename:-innsegl-backup-none}.restore" >/dev/null 2>&1 || true
  rm -rf "${work}"
  exit "${status}"
}
trap cleanup EXIT

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
dump_basename="innsegl-${timestamp}-$$.dump"
dumpfile="${out_dir}/innsegl-${timestamp}.dump"
report_file="${dumpfile}.verify.txt"

# ---------------------------------------------------------------------------
# 1. pg_dump, inside the container, over its own unix socket -- the same
#    reason deploy/compose/innsegl.yml publishes no host port for postgres:
#    a published port is a segmentation hole, not a convenience, and an
#    operator who needs psql already uses `docker compose exec`.
# ---------------------------------------------------------------------------
say "==> pg_dump ${database} from ${pg_container}"
if ! docker exec "${pg_container}" \
    pg_dump -U "${owner}" -d "${database}" -Fc -f "/tmp/${dump_basename}" 2>"${work}/dump.err"; then
  warn "FAIL: pg_dump did not complete:"
  sed 's/^/    /' "${work}/dump.err" >&2 || true
  exit "${EXIT_DUMP_FAILED}"
fi
if ! docker cp "${pg_container}:/tmp/${dump_basename}" "${dumpfile}" 2>"${work}/cp.err"; then
  warn "FAIL: could not copy the dump out of ${pg_container}:"
  sed 's/^/    /' "${work}/cp.err" >&2 || true
  exit "${EXIT_DUMP_FAILED}"
fi
if [ ! -s "${dumpfile}" ]; then
  warn "FAIL: ${dumpfile} is empty"
  exit "${EXIT_DUMP_FAILED}"
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
if ! docker cp "${dumpfile}" "${pg_container}:/tmp/${dump_basename}.restore" 2>"${work}/cp2.err"; then
  warn "FAIL: could not stage the dump back into ${pg_container} for restore-verification:"
  sed 's/^/    /' "${work}/cp2.err" >&2 || true
  exit "${EXIT_DUMP_FAILED}"
fi
if ! docker exec "${pg_container}" createdb -U "${owner}" "${scratch_db}" 2>"${work}/createdb.err"; then
  warn "FAIL: could not create ${scratch_db}:"
  sed 's/^/    /' "${work}/createdb.err" >&2 || true
  exit "${EXIT_DUMP_FAILED}"
fi
cleanup_scratch_db="${scratch_db}"
if ! docker exec "${pg_container}" \
    pg_restore -U "${owner}" -d "${scratch_db}" --exit-on-error "/tmp/${dump_basename}.restore" \
    2>"${work}/restore.err"; then
  warn "FAIL: the dump does not restore -- it is not a usable backup:"
  sed 's/^/    /' "${work}/restore.err" >&2 || true
  exit "${EXIT_DUMP_FAILED}"
fi
say "    restore held"

# ---------------------------------------------------------------------------
# 3. Extract the restored chain, in chain_position order -- exactly the query
#    runbooks/index-rebuild.md §6.2 documents for a rebuilt index.
# ---------------------------------------------------------------------------
if ! docker exec "${pg_container}" psql -U "${owner}" -d "${scratch_db}" -Atc \
    'SELECT event_hash FROM innsegl.events ORDER BY chain_position' \
    >"${work}/index.hashes" 2>"${work}/select.err"; then
  warn "FAIL: could not read innsegl.events back from the restore:"
  sed 's/^/    /' "${work}/select.err" >&2 || true
  exit "${EXIT_DUMP_FAILED}"
fi
event_count="$(grep -c . "${work}/index.hashes" || true)"
say "    restored ${event_count} event(s)"

docker exec "${pg_container}" dropdb -U "${owner}" "${scratch_db}" >/dev/null 2>&1 || true
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
  say "==> fetching sealed segments from ${object_store_bucket}/${object_store_prefix} via ${minio_network}"
  # --entrypoint sh: the minio/mc image's own ENTRYPOINT is `mc`, so a bare
  # `docker run image sh -c ...` would run `mc sh -c ...` rather than a shell
  # (measured). Credentials travel as container environment, not as shell
  # string interpolation, so a value containing a quote cannot break the
  # command.
  docker run --rm --network "${minio_network}" \
      -v "${segments_dir}:/out" \
      -e MC_ENDPOINT="http://${object_store_endpoint}" \
      -e MC_ACCESS_KEY="${object_store_access_key}" \
      -e MC_SECRET_KEY="${object_store_secret_key}" \
      -e MC_BUCKET="${object_store_bucket}" \
      -e MC_PREFIX="${object_store_prefix}" \
      --entrypoint sh \
      "${mc_image}" \
      -c 'set -e
        mc --config-dir /tmp/mc alias set src "$MC_ENDPOINT" "$MC_ACCESS_KEY" "$MC_SECRET_KEY" >/dev/null
        mc --config-dir /tmp/mc cp --recursive "src/$MC_BUCKET/$MC_PREFIX" /out/' \
      >"${work}/mc.log" 2>&1 || true
  n_fetched="$(find "${segments_dir}" -type f 2>/dev/null | grep -c . || true)"
  if [ "${n_fetched}" -eq 0 ]; then
    warn "    could not fetch any sealed segments (see ${work}/mc.log if this is unexpected)"
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
  printf 'database   %s (container %s)\n' "${database}" "${pg_container}"
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
