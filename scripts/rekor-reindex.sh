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
# COST (RM-324). The index is only as stale as the log is long, so the script
# first asks whether it is stale at all. A Redis key records the log's tree id
# and how many entries the index already covers; when that equals the log's
# size the run is a no-op, and when the log has grown only the new entries are
# indexed. Only a missing record, or a different tree id, walks the whole log
# -- and then in batches of entries per request, ONE python process, one redis
# pipe per batch, and a progress line at least every 10 seconds. (The first
# version fetched one entry per request with one python and one docker exec
# each: about 1,240 entries took 20 minutes with no output, on every start.)
#
# It is idempotent. A full rebuild writes keys under a temporary name and
# renames them over the live ones at the end, so a second run leaves one UUID
# per key rather than two, and an interrupted run leaves the old index
# untouched. An incremental run removes a UUID before pushing it, so an entry
# Rekor itself indexed while this ran is not listed twice.
#
# USAGE
#   scripts/rekor-reindex.sh [--dry-run]
#
# ENVIRONMENT
#   INNSEGL_REKOR_URL      default http://127.0.0.1:23000
#   INNSEGL_REDIS_CONTAINER default innsegl-sigstore-rekor-redis
#   INNSEGL_REKOR_REINDEX_TIMEOUT  overall seconds before giving up, default 600
#   INNSEGL_REKOR_REINDEX_BATCH    entries per Rekor request, default 10
#                                  (Rekor v1.3's retrieve endpoint caps it there)
#   INNSEGL_REKOR_REINDEX_DOCKER   the docker command, default docker (self-test)
#   INNSEGL_REKOR_REINDEX_PROGRESS_SECS  seconds between progress lines, default 10
#
# EXIT
#   0  the index covers the whole log (rebuilt, extended, or already did)
#   1  the run did not cover the whole log, including the timeout; a full
#      rebuild leaves the live index as it was, an incremental one keeps what
#      it had finished and the next run resumes from there
#   4  the log or the index could not be reached; nothing was changed

set -uo pipefail

REKOR="${INNSEGL_REKOR_URL:-http://127.0.0.1:$("$(dirname "$0")/rekor-port.sh")}"
REDIS="${INNSEGL_REDIS_CONTAINER:-innsegl-sigstore-rekor-redis}"
DOCKER="${INNSEGL_REKOR_REINDEX_DOCKER:-docker}"
TIMEOUT="${INNSEGL_REKOR_REINDEX_TIMEOUT:-600}"
BATCH="${INNSEGL_REKOR_REINDEX_BATCH:-10}"
STATE_KEY="innsegl:rekor-reindex:state"
DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1

# NOTE THE </dev/null. `docker exec -i` reads the CALLER's stdin, so calling
# this inside a `while read` loop consumes the loop's input and the loop runs
# once. That is how the first version of this script renamed exactly one key.
redis() { $DOCKER exec "$REDIS" redis-cli "$@" </dev/null 2>/dev/null; }
# Send a block of raw commands (read from stdin) to Redis in one round trip.
redis_pipe() { $DOCKER exec -i "$REDIS" redis-cli --pipe >/dev/null 2>&1; }

logjson=$(curl -sS --max-time 10 "$REKOR/api/v1/log" 2>/dev/null)
size=$(printf '%s' "$logjson" | python3 -c 'import sys,json; print(json.load(sys.stdin)["treeSize"])' 2>/dev/null)
tree=$(printf '%s' "$logjson" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("treeID",""))' 2>/dev/null)
if [ -z "${size:-}" ]; then
  echo "rekor-reindex: the log at $REKOR did not answer; nothing was changed" >&2
  exit 4
fi
if ! redis PING | grep -q PONG; then
  echo "rekor-reindex: the index container $REDIS did not answer; nothing was changed" >&2
  exit 4
fi

plural() { [ "$1" = 1 ] && echo y || echo ies; }
echo "rekor-reindex: log at $REKOR holds $size entr$(plural "$size")"

# What the index is recorded as covering: "<treeID> <entries>".
state=$(redis GET "$STATE_KEY" | tr -d '\r')
state_tree="${state%% *}"; state_n="${state#* }"
case "$state_n" in ''|*[!0-9]*) state=""; state_n=0 ;; esac

mode=full; start=0
if [ -n "$state" ] && [ "$state_tree" = "$tree" ] && [ "$state_n" -le "$size" ]; then
  if [ "$state_n" -eq "$size" ]; then
    echo "rekor-reindex: the index already covers all $size entr$(plural "$size") (tree $tree); nothing to do"
    exit 0
  fi
  mode=incremental; start=$state_n
  echo "rekor-reindex: index covers $state_n; adding entries $state_n..$((size-1))"
else
  echo "rekor-reindex: no usable index record; rebuilding from the whole log"
fi
[ "$DRY" = 1 ] && { echo "rekor-reindex: --dry-run, stopping before any write ($mode)"; exit 0; }

if [ "$size" -eq 0 ]; then
  echo "rekor-reindex: the log is empty; nothing to index"
  exit 0
fi

# A full rebuild goes to a temporary namespace and is renamed over the live
# keys at the end, so an interrupted run never leaves a half-built index
# serving lookups. An incremental run writes the live keys directly.
TMP="reindex:$$"
prefix=""; [ "$mode" = full ] && prefix="${TMP}:"
RESULT="$(mktemp)"; trap 'rm -f "$RESULT"' EXIT

# ONE python process does the whole walk: it fetches BATCH entries per request
# (Rekor's /api/v1/log/entries/retrieve takes several logIndexes), extracts
# the keys, and hands Redis one pipe per ~200 entries. A request that fails or
# comes back short is retried one index at a time (?logIndex=N, the old way).
python3 -u - "$REKOR" "$start" "$size" "$prefix" "$mode" "$BATCH" "$TIMEOUT" "$RESULT" \
  "$DOCKER exec -i $REDIS redis-cli --pipe" "$STATE_KEY" "$tree" <<'PY'
import os, sys, json, base64, re, time, shlex, subprocess, urllib.request

rekor, start, size, prefix, mode, batch, timeout, result, pipecmd, state_key, tree = sys.argv[1:12]
start, size, batch, timeout = int(start), int(size), int(batch), int(timeout)
pipecmd = shlex.split(pipecmd)
t0 = time.time()
last_report = t0
progress_every = float(os.environ.get("INNSEGL_REKOR_REINDEX_PROGRESS_SECS", "10"))


def http(url, data=None):
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)


def keys_of(entry):
    try:
        body = json.loads(base64.b64decode(entry["body"]))
    except Exception:
        return []
    spec = body.get("spec", {}) or {}
    out = []
    h = ((spec.get("data") or {}).get("hash") or {})
    if h.get("algorithm") and h.get("value"):
        out.append("%s:%s" % (h["algorithm"], h["value"]))
        out.append(h["value"])
    pk = ((spec.get("signature") or {}).get("publicKey") or {}).get("content")
    if pk:
        try:
            cert = base64.b64decode(pk).decode("utf8", "replace")
            out.extend(re.findall(r"spiffe://[^\s\x00-\x1f\"]+", cert))
        except Exception:
            pass
    return out


def fetch(lo, hi):
    """(uuid, entry) pairs for log indexes lo..hi-1."""
    want = hi - lo
    try:
        got = http(rekor + "/api/v1/log/entries/retrieve",
                   json.dumps({"logIndexes": list(range(lo, hi))}).encode())
        flat = [(u, e) for d in got for u, e in d.items()]
        if len(flat) == want:
            return flat
    except Exception:
        pass
    flat = []
    for i in range(lo, hi):
        # ONE index per request: repeating &logIndex= returns a single entry.
        try:
            for u, e in http("%s/api/v1/log/entries?logIndex=%d" % (rekor, i)).items():
                flat.append((u, e))
        except Exception:
            pass
    return flat


def send(lines, upto):
    if mode == "incremental":
        lines.append("SET %s %s %d" % (state_key, tree, upto))
    if not lines:
        return True
    data = ("\r\n".join(lines) + "\r\n").encode()
    return subprocess.run(pipecmd, input=data, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0


covered = 0
done = start          # next log index not yet flushed to Redis
pending = []
reason = ""
i = start
while i < size:
    if time.time() - t0 > timeout:
        reason = "timeout"
        break
    hi = min(i + batch, size)
    for u, e in fetch(i, hi):
        for k in keys_of(e):
            if mode == "incremental":
                pending.append("LREM %s%s 0 %s" % (prefix, k, u))
            pending.append("RPUSH %s%s %s" % (prefix, k, u))
            covered += 1
    i = hi
    if len(pending) >= 400 or i >= size:
        if not send(pending, i):
            reason = "redis"
            break
        pending, done = [], i
    if time.time() - last_report >= progress_every:
        print("rekor-reindex: %d/%d" % (i, size), flush=True)
        last_report = time.time()

print("rekor-reindex: %d/%d" % (done, size), flush=True)
open(result, "w").write("%d %d %s\n" % (done, covered, reason))
PY
read -r fin covered reason < "$RESULT"
fin="${fin:-0}"; covered="${covered:-0}"

cleanup_tmp() {
  redis --scan --pattern "${TMP}:*" | while read -r k; do [ -n "$k" ] && printf 'DEL %s\r\n' "$k"; done | redis_pipe
}

if [ "$reason" = timeout ]; then
  echo "rekor-reindex: timed out after ${TIMEOUT}s at $fin/$size (raise INNSEGL_REKOR_REINDEX_TIMEOUT)" >&2
  if [ "$mode" = full ]; then
    cleanup_tmp
    echo "rekor-reindex: the live index is left as it was" >&2
  else
    echo "rekor-reindex: what was finished is kept; the next run resumes at $fin" >&2
  fi
  exit 1
fi
if [ "$reason" = redis ] || [ "$fin" -lt "$size" ]; then
  echo "rekor-reindex: the index could not be written ($fin/$size); the live index is left as it was" >&2
  [ "$mode" = full ] && cleanup_tmp
  exit 4
fi

if [ "$mode" = incremental ]; then
  echo "rekor-reindex: OK — added $covered key entr$(plural "$covered") from $((size-start)) new log entr$(plural $((size-start)))"
  exit 0
fi

echo "rekor-reindex: rebuilt $covered key entr$(plural "$covered") from $size log entr$(plural "$size")"
if [ "$covered" -eq 0 ]; then
  echo "rekor-reindex: the walk produced nothing; the live index is left as it was" >&2
  cleanup_tmp
  exit 1
fi

# Rename each temporary key over the live one, a batch per round trip. RENAME
# is atomic per key; the whole swap is not, which is acceptable because every
# key it writes is a superset of what was there: the old index only ever held
# FEWER entries.
renamed=0
n=0
swap=""
while read -r tk; do
  [ -n "$tk" ] || continue
  live="${tk#"${TMP}:"}"
  swap="${swap}DEL ${live}\r\nRENAME ${tk} ${live}\r\n"
  renamed=$((renamed+1)); n=$((n+1))
  if [ "$n" -ge 200 ]; then printf '%b' "$swap" | redis_pipe; swap=""; n=0; fi
done < <(redis --scan --pattern "${TMP}:*")
[ -n "$swap" ] && printf '%b' "$swap" | redis_pipe
# Record what the index now covers only after the swap, so a run that dies
# mid-swap is rebuilt in full next time.
printf 'SET %s %s %s\r\n' "$STATE_KEY" "$tree" "$size" | redis_pipe

echo "rekor-reindex: OK — $renamed key(s) now resolve"
