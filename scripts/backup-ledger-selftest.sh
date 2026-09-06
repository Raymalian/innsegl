#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Self-test for the ledger backup gate (scripts/backup-ledger.sh).
#
# Test IDs (new; not in doc 07 -- that is the maintainer's document to amend):
#   BAK-001  a backup of a chain that matches the sealed segments is accepted
#   BAK-002  a backup that disagrees with a sealed segment is refused, loudly,
#            naming the position -- this is the acceptance criterion issue
#            #160 (RM-099) asks for: "prove the check goes red against a dump
#            that does not match the segments, and green against one that
#            does"
#   BAK-003  a backup taken with no sealed segments to check it against is
#            kept, but is reported unverified rather than passed quietly
#   BAK-004  a backup that cannot even be taken (no such container) fails
#            closed rather than reporting success on nothing
#
# WHY A REAL POSTGRES CONTAINER
# ------------------------------
# The thing under test is the glue between a real pg_dump/pg_restore round
# trip and runbooks/verify-rebuilt-index.sh -- not the gate itself, which
# already has its own self-test. A fabricated hashes file would exercise the
# gate a second time and the glue not at all. So this script boots one
# throwaway `postgres:16` container (the same pin
# deploy/compose/innsegl.yml uses for the reference stack, read from that
# file so the two cannot silently drift apart), applies the two shipped
# migrations, and loads the fourteen committed golden fixtures
# (internal/event/testdata/fixtures/v1) as real rows through the real
# append-only and chain-link triggers.
#
# The container publishes no port and joins no custom network -- only
# `docker exec` is used, the same discipline deploy/compose/innsegl.yml uses
# for postgres and doc 05 §1's segmentation note explains. It does not touch
# object storage: every case below passes scripts/backup-ledger.sh a
# `--segments` directory already staged on disk, so this test needs nothing
# from minio and creates no docker network of its own (RM-100's ~29-network
# ceiling stays untouched).
#
# THE MISMATCH FIXTURE (BAK-002)
# -------------------------------
# Rather than editing the sealed segment (which would just re-run
# verify-rebuilt-index-selftest.sh's own "flipped leaf" case), this script
# loads position 14's event_hash with one hex digit changed before inserting
# it. The append-only and chain-link triggers do not object: nothing
# downstream reads position 14's event_hash, so the row inserts cleanly and
# the "corruption" is exactly the shape a real bug would have -- a stored
# hash that does not match what was sealed. The segment used against it is
# the untouched golden object at
# sha256:86c80ddc52dda7c1b4db79204e677005893e9a5f1cd0f5ff8042de45fd518dc2.
#
# Usage: scripts/backup-ledger-selftest.sh

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
BACKUP_SH="${SCRIPT_DIR}/backup-ledger.sh"
FIX="${REPO_ROOT}/internal/event/testdata/fixtures/v1"

readonly GOLDEN_ROOT="sha256:1a3a08ee2021f778d13e8356740245621b1ea3ecc761a4e42714c42ce86dd14b"
readonly GOLDEN_ID="sha256:86c80ddc52dda7c1b4db79204e677005893e9a5f1cd0f5ff8042de45fd518dc2"

if [ ! -x "${BACKUP_SH}" ]; then
  printf 'FAIL: %s is missing or not executable\n' "${BACKUP_SH}" >&2
  exit 1
fi
if [ ! -d "${FIX}" ]; then
  printf 'FAIL: golden fixtures not found at %s\n' "${FIX}" >&2
  exit 1
fi
for tool in docker jq xxd; do
  command -v "${tool}" >/dev/null 2>&1 || { printf 'FAIL: %s is required\n' "${tool}" >&2; exit 1; }
done

PG_IMAGE="$(sed -n '/^x-postgres-image:/{
n
s/^ *//p
}' "${REPO_ROOT}/deploy/compose/innsegl.yml")"
if [ -z "${PG_IMAGE}" ]; then
  printf 'FAIL: could not read the postgres image pin from deploy/compose/innsegl.yml\n' >&2
  exit 1
fi

PG="innsegl-backup-selftest-pg-$$"
workdir="$(mktemp -d "${TMPDIR:-/tmp}/innsegl-backup-selftest.XXXXXX")"
outdir="${workdir}/backups"
mkdir -p "${outdir}"

cleanup() {
  status=$?
  docker rm -f "${PG}" >/dev/null 2>&1 || true
  rm -rf "${workdir}"
  exit "${status}"
}
trap cleanup EXIT

pass=0
fail=0

expect() {
  want="$1"; name="$2"; shift 3
  out="$("$@" 2>&1)" && got=0 || got=$?
  if [ "${got}" -eq "${want}" ]; then
    printf '  ok    %-46s exit %d\n' "${name}" "${got}"
    pass=$((pass + 1))
  else
    printf '  FAIL  %-46s exit %d, want %d\n' "${name}" "${got}" "${want}"
    printf '%s\n' "${out}" | sed 's/^/        | /'
    fail=$((fail + 1))
  fi
}

expect_says() {
  want="$1"; name="$2"; shift 3
  out="$("$@" 2>&1)" || true
  if printf '%s' "${out}" | grep -qF -- "${want}"; then
    printf '  ok    %-46s said %s\n' "${name}" "${want}"
    pass=$((pass + 1))
  else
    printf '  FAIL  %-46s did not say %s\n' "${name}" "${want}"
    printf '%s\n' "${out}" | sed 's/^/        | /'
    fail=$((fail + 1))
  fi
}

# ---------------------------------------------------------------------------
# Boot a throwaway Postgres and load the golden fixtures as real rows.
# ---------------------------------------------------------------------------
printf '==> booting a throwaway postgres (%s) for the self-test\n' "${PG_IMAGE}"
docker run -d --name "${PG}" \
  -e POSTGRES_USER=innsegl -e POSTGRES_PASSWORD=innsegl-selftest -e POSTGRES_DB=innsegl \
  "${PG_IMAGE}" >/dev/null

waited=0
until docker exec "${PG}" pg_isready -U innsegl -d innsegl >/dev/null 2>&1; do
  waited=$((waited + 1))
  [ "${waited}" -lt 60 ] || { printf 'FAIL: postgres never became ready\n' >&2; exit 1; }
  sleep 1
done

docker cp "${REPO_ROOT}/migrations/0001_ledger.sql" "${PG}:/tmp/0001.sql"
docker cp "${REPO_ROOT}/migrations/0002_idempotency.sql" "${PG}:/tmp/0002.sql"

# corrupt_position 0 means "load the fixtures exactly as committed". Applies
# the schema fresh every call -- see the note on DROP SCHEMA below.
load_fixtures() {
  corrupt_position="$1"
  sql="${workdir}/inserts.sql"
  : >"${sql}"
  n=0
  for f in "${FIX}"/0[1-9]-*.canonical.json "${FIX}"/1[0-4]-*.canonical.json; do
    [ -f "${f}" ] || continue
    n=$((n + 1))
    h="${f%.canonical.json}.hash"
    event_hash="$(cat "${h}")"
    pos="$(jq -r '.chain_position' "${f}")"
    if [ "${pos}" = "${corrupt_position}" ]; then
      # One hex digit changed. Format-valid, chain-link-valid (nothing
      # downstream checks this position's own event_hash), and different from
      # every other stored hash -- a stored value that does not match what was
      # sealed, which is exactly what UNIQUE and the CHECK constraint allow
      # through and only §5.1's own-body-hash check and the sealed segment can
      # catch.
      event_hash="$(printf '%s' "${event_hash}" | sed 's/.$/9/')"
    fi
    event_id="$(jq -r '.event_id' "${f}")"
    event_type="$(jq -r '.event_type' "${f}")"
    source_val="$(jq -r '.source' "${f}")"
    run_id="$(jq -r '.run_id // empty' "${f}")"
    idem="$(jq -r '.idempotency_key // empty' "${f}")"
    ts="$(jq -r '.ts' "${f}")"
    prev="$(jq -r '.prev_event_hash' "${f}")"
    hex="$(xxd -p "${f}" | tr -d '\n')"
    run_id_sql="NULL"; [ -n "${run_id}" ] && run_id_sql="'${run_id}'"
    idem_sql="NULL"; [ -n "${idem}" ] && idem_sql="'${idem}'"
    printf "INSERT INTO innsegl.events (chain_position, event_id, event_hash, prev_event_hash, event_type, source, run_id, idempotency_key, ts, canonical) VALUES (%s, '%s', '%s', '%s', '%s', '%s', %s, %s, '%s', decode('%s','hex'));\n" \
      "${pos}" "${event_id}" "${event_hash}" "${prev}" "${event_type}" "${source_val}" \
      "${run_id_sql}" "${idem_sql}" "${ts}" "${hex}" >>"${sql}"
  done
  if [ "${n}" -ne 14 ]; then
    printf 'FAIL: found %d fixtures, want 14\n' "${n}" >&2
    exit 1
  fi
  # innsegl.events and innsegl.chain are append-only (LED-003, I4), so this
  # test recreates the schema between loads rather than truncating it -- a
  # DROP is DDL and the append-only trigger is DML-level, the same asymmetry
  # runbooks/index-rebuild.md §2.2 measures. That is fine here: this database
  # is the self-test's own scratch fixture, never the thing under test.
  docker exec "${PG}" psql -v ON_ERROR_STOP=1 -U innsegl -d innsegl -c \
    'DROP SCHEMA innsegl CASCADE;' >/dev/null 2>&1 || true
  docker exec "${PG}" psql -v ON_ERROR_STOP=1 -U innsegl -d innsegl -f /tmp/0001.sql >/dev/null
  docker exec "${PG}" psql -v ON_ERROR_STOP=1 -U innsegl -d innsegl -f /tmp/0002.sql >/dev/null
  docker cp "${sql}" "${PG}:/tmp/inserts.sql"
  docker exec "${PG}" psql -v ON_ERROR_STOP=1 -U innsegl -d innsegl -f /tmp/inserts.sql >/dev/null
}

# The one sealed segment these fixtures were sealed into
# (runbooks/verify-rebuilt-index-selftest.sh derives the same object from the
# same fixtures and pins the same two constants).
good_segments="${workdir}/segments-good"
mkdir -p "${good_segments}"
leaves=""
for f in "${FIX}"/0[1-9]-*.hash "${FIX}"/1[0-4]-*.hash; do
  [ -f "${f}" ] || continue
  h="$(cat "${f}")"
  if [ -z "${leaves}" ]; then leaves="\"${h}\""; else leaves="${leaves},\"${h}\""; fi
done
printf '%s' '{"event_hashes":['"${leaves}"'],"first_position":1,"last_position":14,"segment_format_version":"1","segment_merkle_root":"'"${GOLDEN_ROOT}"'"}' \
  >"${good_segments}/${GOLDEN_ID}"

empty_segments="${workdir}/segments-empty"
mkdir -p "${empty_segments}"

printf '\n==> backup-ledger gate self-test\n'
printf '    script    %s\n' "${BACKUP_SH}"
printf '    postgres  %s (container %s)\n' "${PG_IMAGE}" "${PG}"

printf '\n-- BAK-001: a matching chain is accepted --\n'
load_fixtures 0
expect 0 "BAK-001 clean dump matches the sealed segment" -- \
  "${BACKUP_SH}" --postgres-container "${PG}" --database innsegl --owner innsegl \
  --out "${outdir}" --segments "${good_segments}" --quiet
expect_says "OK -- " "BAK-001 says it is OK" -- \
  "${BACKUP_SH}" --postgres-container "${PG}" --database innsegl --owner innsegl \
  --out "${outdir}" --segments "${good_segments}"

printf '\n-- BAK-002: a chain that disagrees with a sealed segment is refused (RED) --\n'
load_fixtures 14
expect 3 "BAK-002 corrupted dump vs the sealed segment" -- \
  "${BACKUP_SH}" --postgres-container "${PG}" --database innsegl --owner innsegl \
  --out "${outdir}" --segments "${good_segments}" --quiet
expect_says "position 14" "BAK-002 names the disagreeing position" -- \
  "${BACKUP_SH}" --postgres-container "${PG}" --database innsegl --owner innsegl \
  --out "${outdir}" --segments "${good_segments}"
expect_says "MISMATCH" "BAK-002 calls it a mismatch, not a pass" -- \
  "${BACKUP_SH}" --postgres-container "${PG}" --database innsegl --owner innsegl \
  --out "${outdir}" --segments "${good_segments}"

printf '\n-- BAK-001 again: back to a clean chain, back to green --\n'
load_fixtures 0
expect 0 "BAK-001 recovers once the chain matches again" -- \
  "${BACKUP_SH}" --postgres-container "${PG}" --database innsegl --owner innsegl \
  --out "${outdir}" --segments "${good_segments}" --quiet

printf '\n-- BAK-003: no sealed segments -> kept, but unverified, not silently green --\n'
expect 4 "BAK-003 no segments available" -- \
  "${BACKUP_SH}" --postgres-container "${PG}" --database innsegl --owner innsegl \
  --out "${outdir}" --segments "${empty_segments}" --quiet
expect_says "UNVERIFIED" "BAK-003 says it is unverified" -- \
  "${BACKUP_SH}" --postgres-container "${PG}" --database innsegl --owner innsegl \
  --out "${outdir}" --segments "${empty_segments}"
n_dumps_before_check="$(find "${outdir}" -maxdepth 1 -name '*.dump' | wc -l | tr -d ' ')"
if [ "${n_dumps_before_check}" -lt 1 ]; then
  printf '  FAIL  BAK-003 kept the dump despite being unverified   found %s\n' "${n_dumps_before_check}"
  fail=$((fail + 1))
else
  printf '  ok    BAK-003 kept the dump despite being unverified   %s file(s)\n' "${n_dumps_before_check}"
  pass=$((pass + 1))
fi

printf '\n-- BAK-004: the backup cannot be taken at all -> fails closed --\n'
expect 5 "BAK-004 no such container" -- \
  "${BACKUP_SH}" --postgres-container "innsegl-backup-selftest-does-not-exist" \
  --out "${outdir}" --segments "${good_segments}" --quiet
expect 2 "BAK-004 unknown flag is a usage error" -- \
  "${BACKUP_SH}" --this-flag-does-not-exist

printf '\n%d passed, %d failed\n' "${pass}" "${fail}"
if [ "${fail}" -gt 0 ]; then
  printf '\nbackup-ledger gate self-test: FAIL\n'
  exit 1
fi
printf '\nbackup-ledger gate self-test: OK\n'
