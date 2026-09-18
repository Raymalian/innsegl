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
# The stub MCP — scripts/hooks/stub-mcp.py, shared with the second shim's own
# self-test (OPS-022). It answers the three requests the transport makes of it
# and writes down every tools/call it is given; nothing it is asked is
# interpreted. It lived inline here until RM-130 needed the same seventy lines,
# and copying them into a second self-test would have been, in the test suite
# that proves E11, the exact duplication E11 exists to answer.
# ---------------------------------------------------------------------------
STUB="$ROOT/scripts/hooks/stub-mcp.py"
[ -f "$STUB" ] || { echo "shim-selftest: $STUB is missing" >&2; exit 4; }

STUB_CALLS="$CALLS" STUB_SCRIPTED="$SCRIPTED" python3 "$STUB" > "$WORK/port" 2>"$WORK/stub.err" &
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

# 3b. AND IT NAMES THE SESSION THAT SPAWNED IT — ADR-0045's third member
# (#214), resolved in the MCP since RM-156 (#259).
#
# THE SESSION ID, NOT A RUN ID. The shim used to read a sibling marker file and
# send the run id it found there, which is a lookup only this harness could
# perform: the first-sight registration a tool call makes holds no run id, so
# that path could never carry an edge at all. What is sent now is the identifier
# this harness already has, and the MCP resolves it against the durable
# session → run mapping it alone holds.
if called observe_session '"parent_session_id": "sess-1"'; then
  ok "SubagentStart names the session that spawned it, in its own vocabulary"
else
  bad "SubagentStart sent no parent_session_id: $(grep observe_session "$CALLS" | tail -1)"
fi

# 3c. AND IT RESOLVES NOTHING ITSELF. This is the negative that catches the
# lookup quietly coming back: a shim that sends a run id is a shim that had to
# know what a run is, which is the work every other harness would then copy.
if ! grep observe_session "$CALLS" | tail -1 | grep -q 'parent_run_id'; then
  ok "SubagentStart resolves no run id of its own — the lookup moved (#259)"
else
  bad "SubagentStart still sends a resolved parent_run_id: $(grep observe_session "$CALLS" | tail -1)"
fi

# 3d. A SUBAGENT WHOSE HARNESS REPORTS NO SESSION STAYS A ROOT RUN. absent is
# not an error, and an EMPTY parent is not the same as none (doc 02 §1) — a root
# run naming an empty parent would be claiming one it does not have. A parent
# session the DEPLOYMENT has never seen is the MCP's case, not this file's: it
# answers with a root run and a detail rather than with a refusal.
script_tool observe_session ok '{"session_id":"agent-orphan","phase":"start","known":true,"registered":true,"run_id":"run-cccc3333","task":"e11","worktree":"","repo":"example.test/org/name","branch":"dev/e11","agent_type":"prober","spiffe_id":"spiffe://innsegl.dev/agent/a/b/run-cccc3333"}'
drive "{\"hook_event_name\":\"SubagentStart\",\"agent_id\":\"agent-orphan\",\"agent_type\":\"prober\",\"cwd\":\"$CWD\"}"
if [ "$STATUS" -eq 0 ] && ! grep observe_session "$CALLS" | tail -1 | grep -q 'parent_'; then
  ok "a subagent whose harness reports no session sends no parent at all"
else
  bad "orphan subagent: status $STATUS, call: $(grep observe_session "$CALLS" | tail -1)"
fi

# 3e. AND A HARNESS THAT REPORTS ONE ID FOR BOTH REPORTS NO PARENT. A session
# naming itself is a cycle of length one; the MCP refuses it, and a refused
# SubagentStart is a subagent that does no work.
script_tool observe_session ok '{"session_id":"same-id","phase":"start","known":true,"registered":true,"run_id":"run-dddd4444","task":"e11","worktree":"","repo":"example.test/org/name","branch":"dev/e11","agent_type":"prober"}'
drive "{\"hook_event_name\":\"SubagentStart\",\"session_id\":\"same-id\",\"agent_id\":\"same-id\",\"agent_type\":\"prober\",\"cwd\":\"$CWD\"}"
if [ "$STATUS" -eq 0 ] && ! grep observe_session "$CALLS" | tail -1 | grep -q 'parent_'; then
  ok "an agent id equal to the session id is no parent, not a self-reference"
else
  bad "self-referencing ids: status $STATUS, call: $(grep observe_session "$CALLS" | tail -1)"
fi

# 4. A subagent that cannot be given an identity does no work (IP §6.1).
script_tool observe_session err '{"error_class":"LEDGER_UNAVAILABLE","message":"no","retryable":true}'
drive "{\"hook_event_name\":\"SubagentStart\",\"session_id\":\"sess-1\",\"agent_id\":\"agent-9\",\"agent_type\":\"prober\",\"cwd\":\"$CWD\"}"
if [ "$STATUS" -eq 2 ]; then
  ok "SubagentStart refuses when no identity can be issued (IP §6.1)"
else
  bad "SubagentStart returned $STATUS for a refused registration; IP §6.1 wants 2"
fi

# 5. PostToolUse forwards the observed call, body and all — NAMED BY SESSION.
#    RM-142 (#226): it named the run, which it could only do when registration
#    had succeeded. A marker is absent exactly when the deployment was down at
#    start, so the session lost its identity AND every call it went on to make.
script_tool observe_tool_call ok '{"digest":"sha256:'"$(printf 'a%.0s' $(seq 1 64))"'","stored":true}'
drive '{"hook_event_name":"PostToolUse","session_id":"sess-1","agent_id":"agent-7","tool_name":"Edit","tool_input":{"file_path":"x"}}'
if [ "$STATUS" -eq 0 ] && called observe_tool_call '"session_id": "agent-7"' '"tool": "Edit"' '"body":'; then
  ok "PostToolUse calls observe_tool_call with the session, the tool and the body"
else
  bad "PostToolUse: status $STATUS, calls: $(cat "$CALLS")"
fi

# 5b. AND IT NAMES THE RIGHT ONE. There are two kinds of run: a subagent's,
#     keyed on the agent id, and the operator's own session, keyed on the
#     session id. A payload carrying BOTH must name the agent — passing the
#     session id unconditionally attributes a subagent's tool calls to the run
#     of the session that spawned it, which is a misattribution written into an
#     append-only record. Caught exactly this way while RM-142 was written.
if called observe_tool_call '"session_id": "agent-7"' && ! called observe_tool_call '"session_id": "sess-1"'; then
  ok "a subagent's call names the AGENT, never the session that spawned it"
else
  bad "PostToolUse named the wrong identity: $(cat "$CALLS")"
fi

# 5b-ii. AND IT CARRIES THE PARENT — RM-156 (#259). This call REGISTERS when the
# session is one the deployment has never seen, which is exactly what a refused
# start leaves behind, and every run registered that way used to be a root run.
# The path that recovers a lost identity lost the edge instead.
if called observe_tool_call '"parent_session_id": "sess-1"'; then
  ok "a subagent's tool call names the session that spawned it, for first sight"
else
  bad "PostToolUse sent no parent_session_id: $(cat "$CALLS")"
fi

# 5c. and the operator's own session, which carries no agent id, names itself.
: > "$CALLS"
script_tool observe_tool_call ok '{"digest":"sha256:'"$(printf 'b%.0s' $(seq 1 64))"'","stored":true}'
drive '{"hook_event_name":"PostToolUse","session_id":"sess-1","tool_name":"Edit","tool_input":{"file_path":"x"}}'
if called observe_tool_call '"session_id": "sess-1"' '"agent_type": "session"'; then
  ok "the operator's own session names itself, with no marker required"
else
  bad "main-session PostToolUse: $(cat "$CALLS")"
fi

# 5c-ii. and it names NO parent. The operator's own session is a root run, and
# a session that named itself as its own parent would be a cycle of length one.
if ! grep observe_tool_call "$CALLS" | tail -1 | grep -q 'parent_'; then
  ok "the operator's own session is a root run, and names no parent"
else
  bad "the main session named a parent: $(cat "$CALLS")"
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

# 8b. THE TWO TREE POINTERS, AND THE COLLISION THAT WOULD HAVE BEEN SILENT.
#
# RM-156 (#259). The signer has no agent or session id in its environment — a
# shell command cannot discover which agent it is inside — so SessionStart
# publishes the session's run under a key derived from the working tree, and
# the signer reads it as the parent of whatever it registers. Measured before
# this: 87 orchestrator runs, all of them the signer's, none with a parent.
#
# SubagentStart publishes ITS run under the same tree key and SubagentStop
# removes it. If the two shared a name, the stop just driven would have taken
# the session's pointer with it and every later commit in this tree would go
# back to naming no parent — which is indistinguishable, from the outside, from
# this change never having been made. So both files are asserted by name, after
# a subagent in the same tree has started and stopped.
TREE_HASH="$(printf '%s' "$(cd "$CWD" && pwd -P)" | shasum -a 256 | cut -c1-32)"
if [ -f "$RUNS/by-tree/$TREE_HASH.session" ]; then
  ok "SessionStart publishes this tree's session pointer, for the signer"
else
  bad "no session pointer at $RUNS/by-tree/$TREE_HASH.session; the signer has no parent to name"
fi
if [ "$(sed -n 1p "$RUNS/by-tree/$TREE_HASH.session" 2>/dev/null)" = "run-aaaa1111" ]; then
  ok "the session pointer names the SESSION's run, on line 1 where the signer reads it"
else
  bad "session pointer line 1 = $(sed -n 1p "$RUNS/by-tree/$TREE_HASH.session" 2>/dev/null), want run-aaaa1111"
fi
if [ ! -f "$RUNS/by-tree/$TREE_HASH" ]; then
  ok "SubagentStop removed the subagent's pointer and left the session's"
else
  bad "the subagent's tree pointer survived its stop: $(cat "$RUNS/by-tree/$TREE_HASH")"
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

# 9b. AND THE SESSION POINTER GOES WITH THE SESSION. The run it names has just
# been retired, and register_agent refuses a retired parent — a pointer left
# behind would make every later commit in this tree take the signer's fallback
# path and register with no parent anyway, after a warning about a stale file.
if [ ! -f "$RUNS/by-tree/$TREE_HASH.session" ]; then
  ok "SessionEnd removes this tree's session pointer with the session"
else
  bad "the session pointer outlived its session: $(cat "$RUNS/by-tree/$TREE_HASH.session")"
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

# --- #261: capture is bounded to what the run actually wrote -------------------
#
# `git add -A` staged the whole tree, so a stopping run became the signed author
# of whatever else was uncommitted. Measured three times on 2026-09-18, once by a
# review subagent that had written nothing at all. The bound is the run's own
# tool-call bodies; these drive the extraction the shim performs.

bound() {   # $1 = body dir, $2 = worktree
  python3 - "$1" "$2" <<'PYEOF' 2>/dev/null
import json, os, pathlib, sys
bodies, root = sys.argv[1], os.path.realpath(sys.argv[2])
out = []
for f in pathlib.Path(bodies).glob("*.json"):
    try:
        d = json.loads(f.read_text())
    except Exception:
        continue
    if d.get("tool_name") not in ("Edit", "Write", "NotebookEdit"):
        continue
    fp = (d.get("tool_input") or {}).get("file_path")
    if not isinstance(fp, str) or not fp:
        continue
    real = os.path.realpath(fp)
    if real == root or real.startswith(root + os.sep):
        out.append(os.path.relpath(real, root))
print("\n".join(sorted(set(out))))
PYEOF
}

CAPT="$WORK/capture"; mkdir -p "$CAPT/tree/sub" "$CAPT/bodies-readonly" "$CAPT/bodies-writer"
: >"$CAPT/tree/mine.txt"; : >"$CAPT/tree/sub/theirs.txt"; : >"$CAPT/tree/elsewhere.txt"

# A run that only read: no Edit/Write body at all.
printf '{"tool_name":"Read","tool_input":{"file_path":"%s/tree/mine.txt"}}' "$CAPT" >"$CAPT/bodies-readonly/a.json"
if [ -z "$(bound "$CAPT/bodies-readonly" "$CAPT/tree")" ]; then
  ok "#261: a run that wrote nothing captures nothing"
else
  bad "#261: a read-only run would still have staged files"
fi

# A run that wrote one file, in a tree where other files are also dirty.
printf '{"tool_name":"Edit","tool_input":{"file_path":"%s/tree/mine.txt"}}' "$CAPT" >"$CAPT/bodies-writer/a.json"
printf '{"tool_name":"Write","tool_input":{"file_path":"%s/outside.txt"}}' "$CAPT" >"$CAPT/bodies-writer/b.json"
got="$(bound "$CAPT/bodies-writer" "$CAPT/tree")"
if [ "$got" = "mine.txt" ]; then
  ok "#261: only the run's own writes are staged, and only inside its worktree"
else
  bad "#261: expected just mine.txt, got: $(echo "$got" | tr '\n' ' ')"
fi

# A body store that is not there: the run cannot say what it touched.
if [ -z "$(bound "$CAPT/nonexistent" "$CAPT/tree")" ]; then
  ok "#261: an unreadable body store yields nothing, so the shim refuses"
else
  bad "#261: a missing body store produced paths"
fi


echo
echo "shim-selftest: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
