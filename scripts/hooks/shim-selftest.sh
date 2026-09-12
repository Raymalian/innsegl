#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# OPS-019, OPS-020 and OPS-021 — the reference shim, driven directly.
#
# RM-129 (#208) rewrites scripts/hooks/subagent-identity.sh onto the three
# ingestion tools of E11. The rewrite's failure mode is SILENT: the shim is the
# only thing capturing identity and activity today, and a shim that registers
# runs and records nothing looks, from every report an operator can read,
# exactly like a shim that works. Nothing crashes. The dashboard simply shows a
# run with a blank activity log, which is also what a quiet agent looks like.
#
# So the shim is driven here with a synthetic payload for each of the SIX
# harness events, against a stub that speaks the streamable-HTTP transport and
# records every tools/call it is given. What is asserted is not "the script ran"
# but WHICH TOOL IT CALLED AND WITH WHAT — and, just as load-bearing, which
# tools it no longer calls at all.
#
# THE NEGATIVE CASES ARE THE POINT. A shim that still digests bodies locally,
# still writes $LOG/<run>/<digest>.json, or still calls register_agent directly
# would pass every positive assertion below while leaving the work E11 exists to
# move exactly where it was. Cases 7, 12 and 13 are what fail then.
#
# USAGE
#   scripts/hooks/shim-selftest.sh
#
# It needs python3 (the stub, and the shim's own JSON handling) and curl. It
# needs no Docker, no MCP, no SPIRE and no network beyond loopback.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SHIM="$ROOT/scripts/hooks/subagent-identity.sh"

pass=0
fail=0
ok()  { pass=$((pass + 1)); echo "  ok    $1"; }
bad() { fail=$((fail + 1)); echo "  FAIL  $1" >&2; }

if [ ! -x "$SHIM" ]; then
  echo "shim-selftest: $SHIM is missing or not executable" >&2
  exit 4
fi
for need in python3 curl; do
  command -v "$need" >/dev/null 2>&1 || { echo "shim-selftest: $need is required" >&2; exit 4; }
done

WORK="$(mktemp -d)"
trap 'if [ -n "${STUB_PID:-}" ]; then kill "$STUB_PID" 2>/dev/null; wait "$STUB_PID" 2>/dev/null; fi; rm -rf "$WORK"' EXIT

CALLS="$WORK/calls"          # one line per tools/call: <tool> <arguments json>
SCRIPTED="$WORK/scripted"    # <tool> <ok|err> <json>, the stub's answer
: > "$CALLS"
: > "$SCRIPTED"

# ---------------------------------------------------------------------------
# The stub MCP.
#
# It answers the three requests the transport makes of it — initialize, the
# initialized notification, and tools/call — and replies to the last with an
# SSE frame, because that is what the shipped server does and the shim has to
# read it. Everything it is asked is written down; nothing it is asked is
# interpreted.
# ---------------------------------------------------------------------------
cat > "$WORK/stub.py" <<'PY'
import json, os, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

CALLS = os.environ["STUB_CALLS"]
SCRIPTED = os.environ["STUB_SCRIPTED"]


def scripted(tool):
    """The answer this run has scripted for tool, as (kind, payload)."""
    with open(SCRIPTED, encoding="utf-8") as fh:
        for line in fh:
            name, _, rest = line.rstrip("\n").partition(" ")
            kind, _, payload = rest.partition(" ")
            if name == tool:
                return kind, json.loads(payload)
    return "ok", {}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        try:
            req = json.loads(raw)
        except ValueError:
            self.send_response(400)
            self.end_headers()
            return

        method = req.get("method")
        if method == "initialize":
            body = json.dumps({"jsonrpc": "2.0", "id": req.get("id"), "result": {
                "protocolVersion": "2025-11-25", "capabilities": {},
                "serverInfo": {"name": "stub", "version": "v0"}}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Mcp-Session-Id", "stub-session")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if method == "notifications/initialized":
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if method != "tools/call":
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        params = req.get("params", {})
        tool = params.get("name", "")
        with open(CALLS, "a", encoding="utf-8") as fh:
            fh.write(tool + " " + json.dumps(params.get("arguments", {}), sort_keys=True) + "\n")

        kind, payload = scripted(tool)
        result = {"structuredContent": payload,
                  "content": [{"type": "text", "text": json.dumps(payload)}]}
        if kind == "err":
            result["isError"] = True
        frame = ("event: message\ndata: " + json.dumps(
            {"jsonrpc": "2.0", "id": req.get("id"), "result": result}) + "\n\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(frame)))
        self.end_headers()
        self.wfile.write(frame)


srv = HTTPServer(("127.0.0.1", 0), Handler)
print(srv.server_port, flush=True)
srv.serve_forever()
PY

STUB_CALLS="$CALLS" STUB_SCRIPTED="$SCRIPTED" python3 "$WORK/stub.py" > "$WORK/port" 2>"$WORK/stub.err" &
STUB_PID=$!
for _ in $(seq 1 100); do
  PORT="$(head -n 1 "$WORK/port" 2>/dev/null)"
  [ -n "$PORT" ] && break
  sleep 0.1
done
[ -n "${PORT:-}" ] || { echo "shim-selftest: the stub never reported a port" >&2; cat "$WORK/stub.err" >&2; exit 4; }
ADMIN="http://127.0.0.1:$PORT/"

# ---------------------------------------------------------------------------
# Driving one event.
# ---------------------------------------------------------------------------

RUNS="$WORK/runs"
LOG="$WORK/log"

# script_tool fixes what the stub answers for one tool.
script_tool() {
  grep -v "^$1 " "$SCRIPTED" > "$SCRIPTED.new" 2>/dev/null || :
  mv "$SCRIPTED.new" "$SCRIPTED"
  printf '%s %s %s\n' "$1" "$2" "$3" >> "$SCRIPTED"
}

# drive runs the shim on one payload and leaves its exit status in $STATUS, its
# stderr in $WORK/err and the calls it made in $CALLS (reset per drive).
drive() {
  : > "$CALLS"
  printf '%s' "$1" | env \
    INNSEGL_MCP_ADMIN_URL="$ADMIN" \
    INNSEGL_RUNS_DIR="$RUNS" \
    INNSEGL_LOG_DIR="$LOG" \
    INNSEGL_SIGNER="$WORK/signer" \
    "$SHIM" > "$WORK/out" 2> "$WORK/err"
  STATUS=$?
}

# called reports whether tool was invoked with every one of the given
# substrings present in its arguments.
called() {
  local tool="$1"; shift
  local line
  line="$(grep "^$tool " "$CALLS" | head -n 1)"
  [ -n "$line" ] || return 1
  local want
  for want in "$@"; do
    case "$line" in *"$want"*) : ;; *) return 1 ;; esac
  done
  return 0
}

# A signer that records its arguments and succeeds, so the capture path can be
# observed without a deployment.
cat > "$WORK/signer" <<'SH'
#!/bin/sh
printf '%s\n' "$*" >> "$(dirname "$0")/signer.calls"
SH
chmod +x "$WORK/signer"

CWD="$ROOT"

echo "shim-selftest: the reference shim, driven event by event"

# --- OPS-019 -----------------------------------------------------------------

script_tool observe_session ok '{"session_id":"sess-1","phase":"start","known":true,"registered":true,"run_id":"run-aaaa1111","task":"e11","worktree":"","repo":"example.test/org/name","branch":"dev/e11","agent_type":"session","spiffe_id":"spiffe://innsegl.dev/agent/a/b/run-aaaa1111"}'

# 1. SessionStart forwards the session and asks for a run.
drive "{\"hook_event_name\":\"SessionStart\",\"session_id\":\"sess-1\",\"cwd\":\"$CWD\"}"
if [ "$STATUS" -eq 0 ] && called observe_session '"phase": "start"' '"session_id": "sess-1"' "\"cwd\": \"$CWD\""; then
  ok "SessionStart calls observe_session(phase=start) with the harness's own cwd"
else
  bad "SessionStart: status $STATUS, calls: $(cat "$CALLS")"
fi

# 2. and it registers nothing itself.
if ! grep -q '^register_agent ' "$CALLS"; then
  ok "SessionStart no longer calls register_agent — the registration moved (#207)"
else
  bad "SessionStart still calls register_agent directly"
fi

# 3. SubagentStart is the same call, keyed on the agent.
script_tool observe_session ok '{"session_id":"agent-7","phase":"start","known":true,"registered":true,"run_id":"run-bbbb2222","task":"e11","worktree":"","repo":"example.test/org/name","branch":"dev/e11","agent_type":"prober","spiffe_id":"spiffe://innsegl.dev/agent/a/b/run-bbbb2222"}'
drive "{\"hook_event_name\":\"SubagentStart\",\"session_id\":\"sess-1\",\"agent_id\":\"agent-7\",\"agent_type\":\"prober\",\"cwd\":\"$CWD\"}"
if [ "$STATUS" -eq 0 ] && called observe_session '"phase": "start"' '"session_id": "agent-7"' '"agent_type": "prober"'; then
  ok "SubagentStart calls observe_session(phase=start) keyed on the agent id"
else
  bad "SubagentStart: status $STATUS, calls: $(cat "$CALLS")"
fi

# 4. A subagent that cannot be given an identity does no work (IP §6.1).
script_tool observe_session err '{"error_class":"LEDGER_UNAVAILABLE","message":"no","retryable":true}'
drive "{\"hook_event_name\":\"SubagentStart\",\"session_id\":\"sess-1\",\"agent_id\":\"agent-9\",\"agent_type\":\"prober\",\"cwd\":\"$CWD\"}"
if [ "$STATUS" -eq 2 ]; then
  ok "SubagentStart refuses when no identity can be issued (IP §6.1)"
else
  bad "SubagentStart returned $STATUS for a refused registration; IP §6.1 wants 2"
fi

# 5. PostToolUse forwards the observed call, body and all.
script_tool observe_tool_call ok '{"digest":"sha256:'"$(printf 'a%.0s' $(seq 1 64))"'","stored":true}'
drive '{"hook_event_name":"PostToolUse","session_id":"sess-1","agent_id":"agent-7","tool_name":"Edit","tool_input":{"file_path":"x"}}'
if [ "$STATUS" -eq 0 ] && called observe_tool_call '"run_id": "run-bbbb2222"' '"tool": "Edit"' '"body":'; then
  ok "PostToolUse calls observe_tool_call with the run, the tool and the body"
else
  bad "PostToolUse: status $STATUS, calls: $(cat "$CALLS")"
fi

# 6. and it does not record the event itself any more.
if ! grep -q '^record_event ' "$CALLS"; then
  ok "PostToolUse no longer calls record_event — the digesting moved (#206)"
else
  bad "PostToolUse still calls record_event directly"
fi

# 7. NEGATIVE, and the one that catches a half-done rewrite: the shim must not
#    write the body to the local log layout. That file is observe_tool_call's
#    to write now, into the volume the MCP holds.
if [ -z "$(find "$LOG" -type f 2>/dev/null)" ]; then
  ok "PostToolUse writes no body locally — the layout moved into the MCP (#206)"
else
  bad "the shim still writes bodies under \$INNSEGL_LOG_DIR: $(find "$LOG" -type f)"
fi

# 8. SubagentStop ends the session by its id, and retires nothing itself.
script_tool observe_session ok '{"session_id":"agent-7","phase":"stop","known":true,"retired":true,"run_id":"run-bbbb2222","retired_at":"2026-09-12T00:00:00.000Z"}'
drive '{"hook_event_name":"SubagentStop","session_id":"sess-1","agent_id":"agent-7","agent_type":"prober"}'
if [ "$STATUS" -eq 0 ] && called observe_session '"phase": "stop"' '"session_id": "agent-7"' && ! grep -q '^retire_agent ' "$CALLS"; then
  ok "SubagentStop calls observe_session(phase=stop) and no longer retires directly"
else
  bad "SubagentStop: status $STATUS, calls: $(cat "$CALLS")"
fi

# 9. SessionEnd likewise.
script_tool observe_session ok '{"session_id":"sess-1","phase":"stop","known":true,"retired":true,"run_id":"run-aaaa1111","retired_at":"2026-09-12T00:00:00.000Z"}'
drive '{"hook_event_name":"SessionEnd","session_id":"sess-1"}'
if [ "$STATUS" -eq 0 ] && called observe_session '"phase": "stop"' '"session_id": "sess-1"'; then
  ok "SessionEnd calls observe_session(phase=stop)"
else
  bad "SessionEnd: status $STATUS, calls: $(cat "$CALLS")"
fi

# 10. ONE OUTCOME PER STOP. `cmd && { ...; warn-if-detail } || warn-failed`
#     returns the last conditional's status, so the failure arm fires after a
#     SUCCESSFUL stop. Measured in RM-129's live run, which printed
#     "retired <run>" and "could not retire <run>" one after the other — a stop
#     that worked, reported as a stop that did not.
if grep -q 'retired run-aaaa1111' "$WORK/err" && ! grep -q 'could not' "$WORK/err"; then
  ok "a successful stop reports exactly one outcome"
else
  bad "a successful stop reported both outcomes: $(cat "$WORK/err")"
fi

# --- OPS-020: a stop never blocks ---------------------------------------------
#
# Measured before this rule existed: a refused stop was answered with NINE
# repeated invocations. Both halves are checked — a tool that reports failure,
# and a deployment that is not there at all.

script_tool observe_session err '{"error_class":"LEDGER_UNAVAILABLE","message":"down","retryable":true}'
drive '{"hook_event_name":"SubagentStop","session_id":"sess-1","agent_id":"agent-7","agent_type":"prober"}'
if [ "$STATUS" -eq 0 ]; then
  ok "SubagentStop exits 0 when the stop is refused (no retry storm)"
else
  bad "SubagentStop exited $STATUS on a refused stop; a stop must never block"
fi

STATUS=99
printf '%s' '{"hook_event_name":"SessionEnd","session_id":"sess-1"}' | env \
  INNSEGL_MCP_ADMIN_URL="http://127.0.0.1:1/" \
  INNSEGL_RUNS_DIR="$RUNS" INNSEGL_LOG_DIR="$LOG" \
  "$SHIM" > "$WORK/out" 2> "$WORK/err"
STATUS=$?
if [ "$STATUS" -eq 0 ]; then
  ok "SessionEnd exits 0 when the deployment is unreachable"
else
  bad "SessionEnd exited $STATUS with no deployment; a stop must never block"
fi

# --- OPS-021: the one gate that cannot move into the MCP ----------------------

# Re-establish a live run for the agent the gate is asked about.
script_tool observe_session ok '{"session_id":"agent-7","phase":"start","known":true,"registered":true,"run_id":"run-bbbb2222","task":"e11","worktree":"","repo":"example.test/org/name","branch":"dev/e11","agent_type":"prober"}'
drive "{\"hook_event_name\":\"SubagentStart\",\"session_id\":\"sess-1\",\"agent_id\":\"agent-7\",\"agent_type\":\"prober\",\"cwd\":\"$CWD\"}"

drive '{"hook_event_name":"PreToolUse","session_id":"sess-1","agent_id":"agent-7","tool_name":"Bash","tool_input":{"command":"git commit -m \"x\""}}'
if [ "$STATUS" -eq 2 ]; then
  ok "OPS-021: a plain git commit is refused, and only the harness can do that"
else
  bad "OPS-021: a plain git commit exited $STATUS, want 2"
fi
if grep -q 'run-bbbb2222' "$WORK/err"; then
  ok "OPS-021: the refusal names THIS run, so the work is signed under it"
else
  bad "OPS-021: the refusal does not name the run: $(cat "$WORK/err")"
fi
if [ -z "$(grep -c . "$CALLS" | grep -v '^0$')" ]; then
  ok "OPS-021: the refusal reaches the MCP for nothing — it is local by necessity"
else
  bad "OPS-021: the gate called $(cat "$CALLS")"
fi

drive '{"hook_event_name":"PreToolUse","session_id":"sess-1","agent_id":"agent-7","tool_name":"Bash","tool_input":{"command":"innsegl-commit.sh -r run-bbbb2222 -m x"}}'
if [ "$STATUS" -eq 0 ]; then
  ok "OPS-021: the signing path itself is not refused"
else
  bad "OPS-021: the signer was refused with $STATUS"
fi

drive '{"hook_event_name":"PreToolUse","session_id":"sess-1","agent_id":"agent-7","tool_name":"Read","tool_input":{"file_path":"x"}}'
if [ "$STATUS" -eq 0 ] && [ ! -s "$CALLS" ]; then
  ok "OPS-021: a tool that is not a commit is allowed, and costs no call"
else
  bad "OPS-021: a Read exited $STATUS and called $(cat "$CALLS")"
fi

# --- The rewrite's own bound --------------------------------------------------
#
# 12 and 13 are what a half-finished rewrite fails. They read the shim as TEXT,
# because a derivation left behind is invisible from the outside until the day a
# second harness has to copy it.

if ! grep -qE '^[^#]*sha256:' "$SHIM"; then
  ok "the shim builds no payload digest — doc 02 §1's hash form moved (#206)"
else
  bad "the shim still builds a digest: $(grep -nE '^[^#]*sha256:' "$SHIM" | head -n 3)"
fi

if ! grep -qE '^[^#]*(remote get-url|worktree list|symbolic-ref)' "$SHIM"; then
  ok "the shim derives no workspace — repo, branch and task moved (#205)"
else
  bad "the shim still derives a workspace: $(grep -nE '^[^#]*(remote get-url|worktree list|symbolic-ref)' "$SHIM" | head -n 3)"
fi

# The frozen oracle is MCP-043's, and a dispatch path that reached it would be
# the derivation quietly back in the shim under another name.
if [ -f "$ROOT/scripts/hooks/reference-derivation.sh" ] \
   && [ "$(grep -c 'reference-derivation.sh' "$SHIM")" = "1" ] \
   && grep -q 'INNSEGL_HOOK_LIB' "$SHIM"; then
  ok "the frozen derivation is reachable only by sourcing, never by an event"
else
  bad "the frozen derivation is referenced from more than the library seam"
fi

echo
echo "shim-selftest: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
