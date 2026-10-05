#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Backfill Rekor's search index from the log it already holds (#451,
# ADR-0010 amendment 2026-10-05).
#
# WHY THIS EXISTS. Rekor indexes an entry when the entry is WRITTEN and never
# afterwards. The index used to be Redis; it is now a table (EntryIndex) in
# the rekor_index database on trillian-db, which Rekor creates on first
# connect. On a host whose log predates that move, every entry written while
# the index was Redis is missing from the table: the log holds it and
# /api/v1/index/retrieve answers `[]`, which `innsegl verify` reports as a
# signature that was never logged. Measured against the pinned images: three
# entries written under Redis answered `[]` after the switch, and all three
# resolved after this ran.
#
# It also repairs an index that was lost some other way, for the same reason.
#
# WHEN. Every bring-up runs it with --if-behind (Makefile, rekor-index-ready),
# so an upgraded host is backfilled ONCE, before the core starts, and never
# again. --if-behind counts the DISTINCT entry UUIDs of this tree in the index
# (a UUID starts with the tree id in hex) and backfills only when that is
# fewer than the log's size. After the backfill Rekor indexes every new entry
# itself, so the count keeps up and later starts do nothing. It assumes every
# entry has at least one index key, which every hashedrekord does.
#
# HOW. It runs Rekor's own backfill tool (backfill-index, the same release as
# rekor-server, pinned below) on innsegl-rekor-index, the network rekor and
# trillian-db share, over log indexes 0..treeSize-1. The tool computes each
# entry's keys with the server's own code, so the keys are exactly the ones
# Rekor writes for a new entry. It is idempotent: the table has a unique key
# on (EntryKey, EntryUUID), and a second run over the same range adds nothing.
#
# USAGE
#   scripts/rekor-reindex.sh [--if-behind] [--dry-run]
#
# ENVIRONMENT
#   INNSEGL_REKOR_URL                  the log, from the host; default the
#                                      published port (scripts/rekor-port.sh)
#   INNSEGL_REKOR_REINDEX_NETWORK      default innsegl-sigstore-rekor-index
#   INNSEGL_REKOR_REINDEX_REKOR        the log, from that network;
#                                      default http://rekor:3000
#   INNSEGL_REKOR_REINDEX_DSN          the index database; default the DSN
#                                      rekor itself uses in sigstore.yml
#   INNSEGL_REKOR_REINDEX_CONCURRENCY  backfill workers, default 4
#   INNSEGL_REKOR_REINDEX_DB           the index database's container, for
#                                      --if-behind; default
#                                      innsegl-sigstore-trillian-db
#   INNSEGL_REKOR_REINDEX_DOCKER       the docker command, default docker
#                                      (self-test)
#
# EXIT
#   0  the index covers every entry the log held when this started (or,
#      with --if-behind, already did)
#   1  the backfill tool failed; what it had written is kept, and a second
#      run is safe
#   4  the log, or with --if-behind the index, could not be read; nothing
#      was changed

set -uo pipefail

# Rekor's own backfill tool, of the SAME RELEASE as rekor-server in
# deploy/compose/sigstore.yml. When one moves, both move; test/deploy checks.
BACKFILL_IMAGE="ghcr.io/sigstore/rekor/backfill-index:v1.3.10@sha256:4c09fd814a597fb8cb35dc77d9b8a42a1bd4e07d375ca2253fb51aaee2bd9066"

REKOR="${INNSEGL_REKOR_URL:-http://127.0.0.1:$("$(dirname "$0")/rekor-port.sh")}"
# INNSEGL_STACK_PREFIX names a DEV stack's network and container (ADR-0072).
NETWORK="${INNSEGL_REKOR_REINDEX_NETWORK:-${INNSEGL_STACK_PREFIX:-innsegl}-sigstore-rekor-index}"
REKOR_IN_NETWORK="${INNSEGL_REKOR_REINDEX_REKOR:-http://rekor:3000}"
DSN="${INNSEGL_REKOR_REINDEX_DSN:-rekor:rekor-index@tcp(trillian-db:3306)/rekor_index}"
CONCURRENCY="${INNSEGL_REKOR_REINDEX_CONCURRENCY:-4}"
DB="${INNSEGL_REKOR_REINDEX_DB:-${INNSEGL_STACK_PREFIX:-innsegl}-sigstore-trillian-db}"
DOCKER="${INNSEGL_REKOR_REINDEX_DOCKER:-docker}"
DRY=()
IF_BEHIND=0
for arg in "$@"; do
  case "$arg" in
    --dry-run)   DRY=(-dry-run) ;;
    --if-behind) IF_BEHIND=1 ;;
    *) echo "rekor-reindex: unknown argument $arg" >&2; exit 2 ;;
  esac
done

logjson=$(curl -sS --max-time 10 "$REKOR/api/v1/log" 2>/dev/null)
size=$(printf '%s' "$logjson" | python3 -c 'import sys,json; print(int(json.load(sys.stdin)["treeSize"]))' 2>/dev/null)
tree=$(printf '%s' "$logjson" | python3 -c 'import sys,json; print("%016x" % int(json.load(sys.stdin)["treeID"]))' 2>/dev/null)
if [ -z "${size:-}" ]; then
  echo "rekor-reindex: the log at $REKOR did not answer; nothing was changed" >&2
  exit 4
fi

plural() { [ "$1" = 1 ] && echo y || echo ies; }
echo "rekor-reindex: log at $REKOR holds $size entr$(plural "$size")"
if [ "$size" -eq 0 ]; then
  echo "rekor-reindex: the log is empty; nothing to index"
  exit 0
fi

if [ "$IF_BEHIND" = 1 ]; then
  # The DSN's own user and database: the same grant rekor has, nothing more.
  user="${DSN%%:*}"; rest="${DSN#*:}"; pass="${rest%%@*}"; dbname="${DSN##*/}"
  case "$tree" in ''|*[!0-9a-f]*) echo "rekor-reindex: the log at $REKOR named no tree; nothing was changed" >&2; exit 4 ;; esac
  indexed=$("$DOCKER" exec "$DB" mysql --protocol=TCP -h127.0.0.1 -N -B -u"$user" -p"$pass" "$dbname" \
    -e "SELECT COUNT(DISTINCT EntryUUID) FROM EntryIndex WHERE EntryUUID LIKE '${tree}%'" </dev/null 2>/dev/null | tr -d '\r' | tail -n 1)
  case "$indexed" in
    ''|*[!0-9]*) echo "rekor-reindex: the index in $DB could not be read; nothing was changed" >&2; exit 4 ;;
  esac
  if [ "$indexed" -ge "$size" ]; then
    echo "rekor-reindex: the index holds all $size entr$(plural "$size") of this tree; nothing to do"
    exit 0
  fi
  echo "rekor-reindex: the index holds $indexed of $size entr$(plural "$size"); backfilling once"
fi

# -end is INCLUSIVE, and an index past the end of the log fails the whole run
# with `getLogEntryByIndexNotFound` (measured), so it is treeSize-1 exactly.
if ! "$DOCKER" run --rm --network "$NETWORK" "$BACKFILL_IMAGE" \
    -rekor-address "$REKOR_IN_NETWORK" \
    -mysql-dsn "$DSN" \
    -start 0 -end "$((size - 1))" \
    -concurrency "$CONCURRENCY" \
    ${DRY[@]+"${DRY[@]}"} </dev/null; then
  echo "rekor-reindex: the backfill did not finish; what it wrote is kept and a second run is safe" >&2
  exit 1
fi

if [ "${#DRY[@]}" -gt 0 ]; then
  echo "rekor-reindex: --dry-run, nothing was written"
  exit 0
fi
echo "rekor-reindex: OK — entries 0..$((size - 1)) are in the search index"
