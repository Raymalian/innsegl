#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# scripts/rekor-reindex.sh's own cases (RM-324) -- entirely against a FAKE
# Rekor (a small python http server this file starts on a free port, serving
# N entries) and a FAKE docker whose `redis-cli` is a python dict kept in a
# file. Nothing here reaches a real log, a real Redis or a container; it needs
# only bash, curl and python3, so it runs under Linux CI unchanged.
#
# SCRIPT may be pointed at another copy of rekor-reindex.sh, which is how the
# cases were first run red against the one-entry-per-request original.

set -uo pipefail

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
SCRIPT="${SCRIPT:-${ROOT}/scripts/rekor-reindex.sh}"

pass=0; fail=0
ok()  { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; return 0; }

TMP="$(mktemp -d)"
SERVER_PID=""
cleanup() { [ -n "${SERVER_PID}" ] && { kill "${SERVER_PID}"; wait "${SERVER_PID}"; } 2>/dev/null; rm -rf "${TMP}"; }
trap cleanup EXIT

ENTRIES="${TMP}/entries.json"     # [ "<hex digest>", ... ] one per log index
REQLOG="${TMP}/requests.log"      # one line per request the fake Rekor served
STORE="${TMP}/redis.json"         # the fake Redis
PORTFILE="${TMP}/port"
: > "${REQLOG}"; echo '{}' > "${STORE}"

# --- the fake Rekor -----------------------------------------------------------
cat > "${TMP}/fakerekor.py" <<'PY'
import base64, json, os, sys, time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

entries_path, reqlog, portfile = sys.argv[1:4]
delay = float(os.environ.get("FAKE_REKOR_DELAY", "0"))

def load():
    return json.load(open(entries_path))

def entry(i, digests):
    body = {"kind": "hashedrekord", "spec": {"data": {"hash": {"algorithm": "sha256", "value": digests[i]}}}}
    return {"u%05d" % i: {"body": base64.b64encode(json.dumps(body).encode()).decode(), "logIndex": i}}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def reply(self, obj, code=200):
        data = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        u = urlparse(self.path); digests = load()
        time.sleep(delay)
        if u.path == "/api/v1/log":
            return self.reply({"treeSize": len(digests), "treeID": "7", "rootHash": "00"})
        if u.path == "/api/v1/log/entries":
            i = int(parse_qs(u.query)["logIndex"][0])
            open(reqlog, "a").write("GET %d\n" % i)
            return self.reply(entry(i, digests) if i < len(digests) else {}, 200 if i < len(digests) else 404)
        self.reply({}, 404)
    def do_POST(self):
        digests = load()
        n = int(self.headers.get("Content-Length", "0"))
        idx = json.loads(self.rfile.read(n))["logIndexes"]
        time.sleep(delay)
        open(reqlog, "a").write("RETRIEVE %s\n" % " ".join(map(str, idx)))
        self.reply([entry(i, digests) for i in idx if i < len(digests)])

srv = HTTPServer(("127.0.0.1", 0), H)
open(portfile, "w").write(str(srv.server_address[1]))
srv.serve_forever()
PY

# --- the fake redis-cli, behind a fake docker ----------------------------------
cat > "${TMP}/fakeredis.py" <<'PY'
import fnmatch, json, os, sys
path = os.environ["FAKE_REDIS_STORE"]
db = json.load(open(path))

def run(c):
    op = c[0].upper()
    if op == "PING": print("PONG")
    elif op == "GET":
        v = db.get(c[1]);  print(v if isinstance(v, str) else "")
    elif op == "SET": db[c[1]] = " ".join(c[2:])
    elif op == "RPUSH": db.setdefault(c[1], []).append(c[2])
    elif op == "LREM": db[c[1]] = [x for x in db.get(c[1], []) if x != c[3]]
    elif op == "DEL": db.pop(c[1], None)
    elif op == "RENAME":
        if c[1] in db: db[c[2]] = db.pop(c[1])

a = sys.argv[1:]
if a[:1] == ["--scan"]:
    pat = a[a.index("--pattern") + 1]
    for k in sorted(db):
        if fnmatch.fnmatchcase(k, pat): print(k)
elif a[:1] == ["--pipe"]:
    for line in sys.stdin.read().split("\r\n"):
        if line.strip(): run(line.split())
else:
    run(a)
json.dump(db, open(path, "w"))
PY

cat > "${TMP}/fakedocker" <<SHIM
#!/bin/sh
# docker exec [-i] <container> redis-cli <args...>
[ "\$1" = "exec" ] || exit 0
shift
[ "\$1" = "-i" ] && shift
shift                       # the container name
shift                       # redis-cli
FAKE_REDIS_STORE="${STORE}" exec python3 "${TMP}/fakeredis.py" "\$@"
SHIM
chmod +x "${TMP}/fakedocker"

# --- helpers ------------------------------------------------------------------
entries() {                       # entries <n>: log indexes 0..n-1, hex digests
  python3 -c 'import json,sys; print(json.dumps(["%064x" % (i + 1) for i in range(int(sys.argv[1]))]))' "$1" > "${ENTRIES}"
}
store() {                         # store <python expr over db>
  python3 -c 'import json,sys; db=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "${STORE}" "$1"
}
run() {                           # run [env assignments...]: stdout+stderr in $out, status in $rc
  out="$(env INNSEGL_REKOR_URL="http://127.0.0.1:${PORT}" INNSEGL_REKOR_REINDEX_DOCKER="${TMP}/fakedocker" \
    INNSEGL_REKOR_REINDEX_PROGRESS_SECS=0 "$@" "${SCRIPT}" 2>&1)"; rc=$?
}
digest_key() { printf '%064x' "$1"; }   # the 1-based digest entries() gives log index i-1

entries 25
python3 "${TMP}/fakerekor.py" "${ENTRIES}" "${REQLOG}" "${PORTFILE}" &
SERVER_PID=$!
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do [ -s "${PORTFILE}" ] && break; sleep 0.25; done
PORT="$(cat "${PORTFILE}")"
[ -n "${PORT}" ] || { echo "fake rekor did not start" >&2; exit 1; }

# ---------------------------------------------------------------------------
echo "a full run indexes every entry, in batches, and says how far it is"

run env
if [ "${rc}" = 0 ]; then ok "exits 0"; else bad "exits 0" "exit ${rc}: ${out}"; fi
n_keys="$(store 'len([k for k in db if k.startswith("sha256:")])')"
if [ "${n_keys}" = 25 ]; then ok "all 25 sha256:<digest> keys exist"; else bad "all 25 sha256:<digest> keys exist" "got ${n_keys}: ${out}"; fi
bare="$(store 'len([k for k in db if len(k) == 64])')"
if [ "${bare}" = 25 ]; then ok "all 25 bare <digest> keys exist"; else bad "all 25 bare <digest> keys exist" "got ${bare}"; fi
dup="$(store 'max(len(v) for k, v in db.items() if isinstance(v, list))')"
if [ "${dup}" = 1 ]; then ok "one UUID per key"; else bad "one UUID per key" "longest list: ${dup}"; fi
if [ "$(store 'db.get("sha256:" + "%064x" % 3)')" = "['u00002']" ]; then ok "a key resolves to the right entry UUID"; else bad "a key resolves to the right entry UUID" "$(store 'db.get("sha256:" + "%064x" % 3)')"; fi
if [ "$(store '[k for k in db if k.startswith("reindex:")]')" = "[]" ]; then ok "no temporary keys are left behind"; else bad "no temporary keys are left behind"; fi
if [ "$(store 'db.get("innsegl:rekor-reindex:state")')" = "7 25" ]; then ok "the tree id and covered size are recorded"; else bad "the tree id and covered size are recorded" "$(store 'db.get("innsegl:rekor-reindex:state")')"; fi
if printf '%s\n' "${out}" | grep -q 'rekor-reindex: 10/25'; then ok "a progress line reports 10/25"; else bad "a progress line reports 10/25" "${out}"; fi
calls="$(wc -l < "${REQLOG}" | tr -d ' ')"
if [ "${calls}" -le 3 ]; then ok "25 entries took ${calls} requests, not 25"; else bad "25 entries took at most 3 requests" "took ${calls}"; fi

# ---------------------------------------------------------------------------
echo
echo "a second run finds the index current and does nothing"

: > "${REQLOG}"
before="$(cat "${STORE}")"
run env
if [ "${rc}" = 0 ]; then ok "exits 0"; else bad "exits 0" "exit ${rc}: ${out}"; fi
if printf '%s' "${out}" | grep -q 'nothing to do'; then ok "says there is nothing to do"; else bad "says there is nothing to do" "${out}"; fi
if [ ! -s "${REQLOG}" ]; then ok "fetches no entry"; else bad "fetches no entry" "$(cat "${REQLOG}")"; fi
if [ "$(cat "${STORE}")" = "${before}" ]; then ok "writes nothing"; else bad "writes nothing"; fi

# ---------------------------------------------------------------------------
echo
echo "an appended entry is indexed on its own"

entries 26
: > "${REQLOG}"
run env
if [ "${rc}" = 0 ]; then ok "exits 0"; else bad "exits 0" "exit ${rc}: ${out}"; fi
if [ "$(store 'db.get("sha256:" + "%064x" % 26)')" = "['u00025']" ]; then ok "the new entry resolves"; else bad "the new entry resolves" "$(store 'db.get("sha256:" + "%064x" % 26)') / ${out}"; fi
if [ "$(store 'db.get("innsegl:rekor-reindex:state")')" = "7 26" ]; then ok "the covered size moves to 26"; else bad "the covered size moves to 26" "$(store 'db.get("innsegl:rekor-reindex:state")')"; fi
if [ "$(cat "${REQLOG}")" = "RETRIEVE 25" ]; then ok "only log index 25 was fetched"; else bad "only log index 25 was fetched" "$(cat "${REQLOG}")"; fi
dup="$(store 'max(len(v) for k, v in db.items() if isinstance(v, list))')"
if [ "${dup}" = 1 ]; then ok "still one UUID per key"; else bad "still one UUID per key" "longest list: ${dup}"; fi

# An entry Rekor itself indexed while the walk ran must not be listed twice.
python3 - "${STORE}" <<'PY'
import json, sys
db = json.load(open(sys.argv[1])); d = "%064x" % 27
db["sha256:" + d] = ["u00026"]; db[d] = ["u00026"]
json.dump(db, open(sys.argv[1], "w"))
PY
entries 27
run env
if [ "$(store 'db.get("sha256:" + "%064x" % 27)')" = "['u00026']" ]; then ok "an entry already indexed is not listed twice"; else bad "an entry already indexed is not listed twice" "$(store 'db.get("sha256:" + "%064x" % 27)')"; fi

# ---------------------------------------------------------------------------
echo
echo "a different tree id is rebuilt in full"

python3 - "${STORE}" <<'PY'
import json, sys
db = json.load(open(sys.argv[1])); db["innsegl:rekor-reindex:state"] = "999 27"
json.dump(db, open(sys.argv[1], "w"))
PY
: > "${REQLOG}"
run env
if printf '%s' "${out}" | grep -q 'rebuilding from the whole log'; then ok "says it is rebuilding"; else bad "says it is rebuilding" "${out}"; fi
if [ "$(store 'db.get("innsegl:rekor-reindex:state")')" = "7 27" ]; then ok "the new tree id is recorded"; else bad "the new tree id is recorded"; fi

# ---------------------------------------------------------------------------
echo
echo "a run that cannot finish in time stops with a clear message and keeps the live index"

entries 60
python3 - "${STORE}" <<'PY'
import json, sys
db = json.load(open(sys.argv[1])); db.pop("innsegl:rekor-reindex:state")
json.dump(db, open(sys.argv[1], "w"))
PY
kill "${SERVER_PID}" 2>/dev/null; wait "${SERVER_PID}" 2>/dev/null
: > "${PORTFILE}"
FAKE_REKOR_DELAY=0.4 python3 "${TMP}/fakerekor.py" "${ENTRIES}" "${REQLOG}" "${PORTFILE}" &
SERVER_PID=$!
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do [ -s "${PORTFILE}" ] && break; sleep 0.25; done
PORT="$(cat "${PORTFILE}")"
before="$(cat "${STORE}")"
run env INNSEGL_REKOR_REINDEX_TIMEOUT=2 INNSEGL_REKOR_REINDEX_BATCH=1
if [ "${rc}" = 1 ]; then ok "exits 1"; else bad "exits 1" "exit ${rc}: ${out}"; fi
if printf '%s' "${out}" | grep -q 'timed out after 2s'; then ok "names the timeout"; else bad "names the timeout" "${out}"; fi
if [ "$(cat "${STORE}")" = "${before}" ]; then ok "the live index is left as it was"; else bad "the live index is left as it was" "$(store '[k for k in db if k.startswith("reindex:")][:3]')"; fi

# ---------------------------------------------------------------------------
echo
printf 'rekor-reindex-selftest: %s passed, %s failed\n' "${pass}" "${fail}"
[ "${fail}" = 0 ] || exit 1
