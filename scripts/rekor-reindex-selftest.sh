#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# scripts/rekor-reindex.sh's own cases (#451) -- entirely against a FAKE Rekor
# (a small python http server this file starts on a free port, answering
# /api/v1/log with a tree size) and a FAKE docker that records the command it
# was given and exits with FAKE_DOCKER_RC. Nothing here reaches a real log, a
# real database or a container; it needs only bash, curl and python3, so it
# runs under Linux CI unchanged.
#
# What the real backfill does against the pinned images was measured and is
# recorded in ADR-0010's 2026-10-05 amendment. These cases pin what the
# script asks of it: the right network, the server's own release of the tool,
# the DSN rekor uses, and an inclusive end that is exactly treeSize-1.
#
# SCRIPT may be pointed at another copy of rekor-reindex.sh, which is how the
# cases were first run red against the Redis version.

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

SIZE="${TMP}/size"           # the tree size the fake Rekor reports
CALLS="${TMP}/docker.calls"  # one line per docker invocation, args NUL-free
PORTFILE="${TMP}/port"

# --- the fake Rekor -----------------------------------------------------------
cat > "${TMP}/fakerekor.py" <<'PY'
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
size_path, portfile = sys.argv[1:3]

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path == "/api/v1/log":
            data = json.dumps({"treeSize": int(open(size_path).read()), "treeID": "4381500033330817613"}).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
            return
        self.send_response(404); self.end_headers()

srv = HTTPServer(("127.0.0.1", 0), H)
open(portfile, "w").write(str(srv.server_address[1]))
srv.serve_forever()
PY

# `docker exec ... mysql` answers the index count (FAKE_INDEX_COUNT, or fails
# with FAKE_EXEC_RC); `docker run` is the backfill (FAKE_DOCKER_RC).
cat > "${TMP}/fakedocker" <<SHIM
#!/bin/sh
printf '%s\n' "\$*" >> "${CALLS}"
if [ "\$1" = exec ]; then
  [ "\${FAKE_EXEC_RC:-0}" = 0 ] || exit "\$FAKE_EXEC_RC"
  printf '%s\n' "\${FAKE_INDEX_COUNT:-0}"
  exit 0
fi
exit "\${FAKE_DOCKER_RC:-0}"
SHIM
chmod +x "${TMP}/fakedocker"

run() {                       # run [env assignments...] [-- script args]: output in $out, status in $rc
  : > "${CALLS}"
  out="$(env INNSEGL_REKOR_URL="http://127.0.0.1:${PORT}" INNSEGL_REKOR_REINDEX_DOCKER="${TMP}/fakedocker" \
    "$@" 2>&1)"; rc=$?
}
call() { cat "${CALLS}"; }
has() { printf '%s\n' "$(call)" | grep -qF -- "$1"; }

echo 25 > "${SIZE}"
python3 "${TMP}/fakerekor.py" "${SIZE}" "${PORTFILE}" &
SERVER_PID=$!
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do [ -s "${PORTFILE}" ] && break; sleep 0.25; done
PORT="$(cat "${PORTFILE}")"
[ -n "${PORT}" ] || { echo "fake rekor did not start" >&2; exit 1; }

# The DSN rekor itself is given, read from the compose file, so the backfill
# cannot write to a database the server does not read.
COMPOSE_DSN="$(sed -n 's/.*"--search_index\.mysql\.dsn=\([^"]*\)".*/\1/p' "${ROOT}/deploy/compose/sigstore.yml")"

# ---------------------------------------------------------------------------
echo "a log of 25 entries is backfilled over 0..24 by Rekor's own tool"

run "${SCRIPT}"
if [ "${rc}" = 0 ]; then ok "exits 0"; else bad "exits 0" "exit ${rc}: ${out}"; fi
if [ "$(wc -l < "${CALLS}" | tr -d ' ')" = 1 ]; then ok "runs docker once"; else bad "runs docker once" "$(call)"; fi
if has "run --rm --network innsegl-sigstore-rekor-index "; then ok "on the network rekor and trillian-db share"; else bad "on the network rekor and trillian-db share" "$(call)"; fi
if printf '%s' "$(call)" | grep -Eq 'ghcr\.io/sigstore/rekor/backfill-index:v[0-9.]+@sha256:[0-9a-f]{64} '; then ok "runs backfill-index pinned by tag and digest"; else bad "runs backfill-index pinned by tag and digest" "$(call)"; fi
if has "-rekor-address http://rekor:3000 "; then ok "reads the log from inside the network"; else bad "reads the log from inside the network" "$(call)"; fi
if [ -n "${COMPOSE_DSN}" ] && has "-mysql-dsn ${COMPOSE_DSN} "; then ok "writes with the DSN rekor uses (${COMPOSE_DSN})"; else bad "writes with the DSN rekor uses" "compose: '${COMPOSE_DSN}'; call: $(call)"; fi
if has "-start 0 -end 24 "; then ok "covers 0..24 -- -end is inclusive, and 25 would fail the run"; else bad "covers 0..24" "$(call)"; fi
if printf '%s' "${out}" | grep -q 'OK'; then ok "says OK"; else bad "says OK" "${out}"; fi

# ---------------------------------------------------------------------------
echo
echo "an empty log runs nothing"

echo 0 > "${SIZE}"
run "${SCRIPT}"
if [ "${rc}" = 0 ]; then ok "exits 0"; else bad "exits 0" "exit ${rc}: ${out}"; fi
if [ ! -s "${CALLS}" ]; then ok "runs no container"; else bad "runs no container" "$(call)"; fi
echo 25 > "${SIZE}"

# ---------------------------------------------------------------------------
echo
echo "--dry-run is passed through and writes nothing"

run "${SCRIPT}" --dry-run
if [ "${rc}" = 0 ]; then ok "exits 0"; else bad "exits 0" "exit ${rc}: ${out}"; fi
if has " -dry-run"; then ok "the tool is asked for a dry run"; else bad "the tool is asked for a dry run" "$(call)"; fi

# ---------------------------------------------------------------------------
echo
echo "a backfill that fails is reported, not swallowed"

run FAKE_DOCKER_RC=1 "${SCRIPT}"
if [ "${rc}" = 1 ]; then ok "exits 1"; else bad "exits 1" "exit ${rc}: ${out}"; fi
if printf '%s' "${out}" | grep -q 'second run is safe'; then ok "says a second run is safe"; else bad "says a second run is safe" "${out}"; fi

# ---------------------------------------------------------------------------
echo
echo "a log that does not answer changes nothing"

run INNSEGL_REKOR_URL="http://127.0.0.1:1" "${SCRIPT}"
if [ "${rc}" = 4 ]; then ok "exits 4"; else bad "exits 4" "exit ${rc}: ${out}"; fi
if [ ! -s "${CALLS}" ]; then ok "runs no container"; else bad "runs no container" "$(call)"; fi

# ---------------------------------------------------------------------------
# --if-behind is what every bring-up runs (#451). It backfills ONCE: when the
# index holds fewer of this tree's entries than the log, and never otherwise.
echo
echo "--if-behind: an index that covers the log is left alone"

run FAKE_INDEX_COUNT=25 "${SCRIPT}" --if-behind
if [ "${rc}" = 0 ]; then ok "exits 0"; else bad "exits 0" "exit ${rc}: ${out}"; fi
if ! grep -q '^run ' "${CALLS}"; then ok "runs no backfill"; else bad "runs no backfill" "$(call)"; fi
if has "exec innsegl-sigstore-trillian-db mysql"; then ok "asks trillian-db how much the index holds"; else bad "asks trillian-db how much the index holds" "$(call)"; fi
if has "LIKE '3cce3710ee0baa4d%'"; then ok "counts only this tree's entries (UUID prefix = tree id in hex)"; else bad "counts only this tree's entries" "$(call)"; fi

echo
echo "--if-behind: an index behind the log is backfilled over the whole log"

run FAKE_INDEX_COUNT=3 "${SCRIPT}" --if-behind
if [ "${rc}" = 0 ]; then ok "exits 0"; else bad "exits 0" "exit ${rc}: ${out}"; fi
if has "-start 0 -end 24 "; then ok "backfills 0..24"; else bad "backfills 0..24" "$(call)"; fi
if printf '%s' "${out}" | grep -q '3 of 25'; then ok "says how far behind it was"; else bad "says how far behind it was" "${out}"; fi

echo
echo "--if-behind: an empty index (an upgraded host) is backfilled"

run FAKE_INDEX_COUNT=0 "${SCRIPT}" --if-behind
if [ "${rc}" = 0 ] && has "-start 0 -end 24 "; then ok "backfills 0..24"; else bad "backfills 0..24" "exit ${rc}: $(call)"; fi

echo
echo "--if-behind: an index that cannot be read is a failure, not a skip"

run FAKE_EXEC_RC=1 "${SCRIPT}" --if-behind
if [ "${rc}" = 4 ]; then ok "exits 4"; else bad "exits 4" "exit ${rc}: ${out}"; fi
if ! grep -q '^run ' "${CALLS}"; then ok "runs no backfill"; else bad "runs no backfill" "$(call)"; fi

echo
echo "--if-behind: an empty log asks nothing"

echo 0 > "${SIZE}"
run FAKE_INDEX_COUNT=0 "${SCRIPT}" --if-behind
if [ "${rc}" = 0 ] && [ ! -s "${CALLS}" ]; then ok "exits 0 and runs nothing"; else bad "exits 0 and runs nothing" "exit ${rc}: $(call)"; fi
echo 25 > "${SIZE}"

echo
printf 'rekor-reindex-selftest: %s passed, %s failed\n' "${pass}" "${fail}"
[ "${fail}" -eq 0 ]
