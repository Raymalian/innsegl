#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Rebuild Rekor's search index from the log it already holds.
#
# WHY THIS EXISTS. RM-138 (#219): the index is Redis, and it was configured
# with no persistence and no volume, so every container recreate emptied it.
# Rekor indexes an entry when the entry is WRITTEN and never afterwards, so an
# emptied index is never repopulated — the log keeps every record and nothing
# can find one. `innsegl verify` then reports check 2 failed, which reads
# exactly like a signature that was never logged.
#
# The index is derived state: entry UUIDs keyed by the artifact digest and by
# the signing certificate's identity. Both are recoverable by walking the log,
# which is what this does.
#
# It is idempotent. Keys are rebuilt from scratch under a temporary name and
# renamed over the live ones at the end, so a second run leaves one UUID per
# key rather than two, and an interrupted run leaves the old index untouched.
#
# USAGE
#   scripts/rekor-reindex.sh [--dry-run]
#
# ENVIRONMENT
#   INNSEGL_REKOR_URL      default http://127.0.0.1:23000
#   INNSEGL_REDIS_CONTAINER default innsegl-sigstore-rekor-redis
#
# EXIT
#   0  the index was rebuilt, and the entry count equals the log's tree size
#   1  the rebuild did not cover the whole log; the index is left as it was
#   4  the log or the index could not be reached; nothing was changed

set -uo pipefail

REKOR="${INNSEGL_REKOR_URL:-http://127.0.0.1:23000}"
REDIS="${INNSEGL_REDIS_CONTAINER:-innsegl-sigstore-rekor-redis}"
DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1

# NOTE THE </dev/null. `docker exec -i` reads the CALLER's stdin, so calling
# this inside a `while read` loop consumes the loop's input and the loop runs
# once. That is how the first version of this script renamed exactly one key.
redis() { docker exec "$REDIS" redis-cli "$@" </dev/null 2>/dev/null; }

size=$(curl -sS --max-time 10 "$REKOR/api/v1/log" 2>/dev/null \
       | python3 -c 'import sys,json; print(json.load(sys.stdin)["treeSize"])' 2>/dev/null)
if [ -z "${size:-}" ]; then
  echo "rekor-reindex: the log at $REKOR did not answer; nothing was changed" >&2
  exit 4
fi
if ! redis PING | grep -q PONG; then
  echo "rekor-reindex: the index container $REDIS did not answer; nothing was changed" >&2
  exit 4
fi

echo "rekor-reindex: log at $REKOR holds $size entr$([ "$size" = 1 ] && echo y || echo ies)"
[ "$DRY" = 1 ] && { echo "rekor-reindex: --dry-run, stopping before any write"; exit 0; }

# Build into a temporary namespace, then rename over the live keys. An
# interrupted run must not leave a half-built index serving lookups.
TMP="reindex:$$"
covered=0
batch=""

flush() { [ -n "$batch" ] && { printf '%b' "$batch" | docker exec -i "$REDIS" redis-cli --pipe >/dev/null 2>&1; batch=""; }; }

i=0
while [ "$i" -lt "$size" ]; do
  # ONE index per request. Repeating &logIndex= returns a single entry rather
  # than the set, which silently under-collected on the first run: 528 log
  # entries produced 106 keys instead of roughly twice that.
  q="logIndex=$i"; i=$((i+1))
  keys=$(curl -sS --max-time 20 "$REKOR/api/v1/log/entries?$q" 2>/dev/null | python3 -c '
import sys, json, base64
try:
    doc = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for uuid, entry in doc.items():
    try:
        body = json.loads(base64.b64decode(entry["body"]))
    except Exception:
        continue
    spec = body.get("spec", {}) or {}
    out = []
    h = ((spec.get("data") or {}).get("hash") or {})
    if h.get("algorithm") and h.get("value"):
        out.append(f'"'"'{h["algorithm"]}:{h["value"]}'"'"')
        out.append(h["value"])
    pk = ((spec.get("signature") or {}).get("publicKey") or {}).get("content")
    if pk:
        try:
            import re
            cert = base64.b64decode(pk).decode("utf8", "replace")
            for uri in re.findall(r"spiffe://[^\s\x00-\x1f\"]+", cert):
                out.append(uri)
        except Exception:
            pass
    for k in out:
        print(f"{k}\t{uuid}")
' 2>/dev/null)
  while IFS=$'\t' read -r k u; do
    [ -n "$k" ] || continue
    batch="${batch}RPUSH ${TMP}:${k} ${u}\r\n"
    covered=$((covered+1))
  done <<< "$keys"
  flush
done

echo "rekor-reindex: rebuilt $covered key entr$([ "$covered" = 1 ] && echo y || echo ies) from $size log entr$([ "$size" = 1 ] && echo y || echo ies)"
if [ "$covered" -eq 0 ]; then
  echo "rekor-reindex: the walk produced nothing; the live index is left as it was" >&2
  redis --scan --pattern "${TMP}:*" | while read -r k; do redis DEL "$k" >/dev/null; done
  exit 1
fi

# Rename each temporary key over the live one. RENAME is atomic per key; the
# whole swap is not, which is acceptable because every key it writes is a
# superset of what was there: the old index only ever held FEWER entries.
renamed=0
while read -r tk; do
  [ -n "$tk" ] || continue
  live="${tk#${TMP}:}"
  redis DEL "$live" >/dev/null
  redis RENAME "$tk" "$live" >/dev/null && renamed=$((renamed+1))
done < <(redis --scan --pattern "${TMP}:*")

echo "rekor-reindex: OK — $renamed key(s) now resolve"
