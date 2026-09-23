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
# The shipped shim by default. The override exists because this file IS THE
# HARNESS'S OWN HOOK on any machine that wired it up: it takes effect the
# instant it is saved, for every session on that machine, and an unclosed `if`
# in it has already locked an operator out of their shell. Driving a candidate
# from a scratch copy BEFORE installing it is the only way to find that out
# safely, and a test that can only be run after the dangerous step is not a
# test of it.
SHIM="${INNSEGL_SELFTEST_SHIM:-$ROOT/scripts/hooks/subagent-identity.sh}"

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

# CREDFILE IS EMPTY UNTIL CASE 15 FILLS IT, so every case above it runs against
# a listener that demands nothing — which is single-listener mode, and is the
# thing OPS-073 asserts has not changed. AUTHLOG records what each request
# carried, including the ones that carried nothing.
CREDFILE="$WORK/required"
AUTHLOG="$WORK/authlog"
: > "$CREDFILE"
: > "$AUTHLOG"

STUB_CALLS="$CALLS" STUB_SCRIPTED="$SCRIPTED" \
STUB_CREDENTIAL="$CREDFILE" STUB_AUTH_LOG="$AUTHLOG" \
python3 "$STUB" > "$WORK/port" 2>"$WORK/stub.err" &
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
#
# $INNSEGL_API_URL IS PINNED AT A DEAD PORT and not left to its default, which is
# the deployment this machine may well be running. A selftest that asked the live
# ledger how many commits a fixture run had made would answer differently
# depending on what was up, and the capture path branches on that answer.
#
# $SIGNER defaults to the inert recorder below. The capture cases override it
# with one that really commits, because "no commit" has to be asserted as a HEAD
# that did not move.
#
# $INNSEGL_GIT_GUARD_SCRIPT IS PINNED AT THE SHIPPED GUARD and not left to the
# shim's own sibling lookup — #278. $SHIM is a scratch copy whenever a candidate
# is being driven before it is installed, which is the whole point of the
# override, and a scratch copy has no sibling. Pinning it also means the guard
# under test is the repository's, never whatever happens to sit next to the copy.
drive() {
  : > "$CALLS"
  printf '%s' "$1" | env \
    INNSEGL_MCP_ADMIN_URL="$ADMIN" \
    INNSEGL_RUNS_DIR="$RUNS" \
    INNSEGL_LOG_DIR="$LOG" \
    INNSEGL_SIGNER="${SIGNER:-$WORK/signer}" \
    INNSEGL_API_URL="${API:-http://127.0.0.1:1/}" \
    INNSEGL_ADMIN_CREDENTIAL_MINT="${MINT:-}" \
    INNSEGL_GIT_GUARD="${GIT_GUARD:-1}" \
    INNSEGL_GIT_GUARD_SCRIPT="${TREE_GUARD:-$ROOT/scripts/hooks/git-tree-guard.sh}" \
    INNSEGL_ORPHAN_SWEEP_SCRIPT="${ORPHAN_SWEEP_SCRIPT:-$WORK/sweep-stub}" \
    "$SHIM" > "$WORK/out" 2> "$WORK/err"
  STATUS=$?
  # EVERY call this run has ever made, because $CALLS is reset per drive and
  # case 14 is about what the shim never sends, in any event, ever.
  cat "$CALLS" >> "$WORK/allcalls"
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

# --- OPS-056: a harness that ends a session ends what it started --------------
#
# RM-157 (#260). MEASURED: five subagent runs sat Active for between three and
# nine hours after the processes behind them were gone, and an operator closed
# them by hand. A killed subagent fires no SubagentStop, so its own stop never
# happens; the reaper's grace is twelve hours by policy and shortening it kills
# working agents. The one party that KNEW is the session that started them.
#
# BOTH HALVES ARE DRIVEN HERE, and the second is the one that matters. Ending a
# run because its parent ended would be the inference IP \u00a73 E7 forbids; what
# makes this an ASSERTION is that it is made once, by the session, at the moment
# the session ends \u2014 and at no other moment. So a whole session is played out
# with a subagent left open, and every event before the end is checked for
# having asserted nothing.

SESS=sess-56
AGENT=agent-56

script_tool observe_session ok '{"session_id":"sess-56","phase":"start","known":true,"registered":true,"run_id":"run-5656aaaa","task":"e9","worktree":"","repo":"example.test/org/name","branch":"dev/e9","agent_type":"session"}'
drive "{\"hook_event_name\":\"SessionStart\",\"session_id\":\"$SESS\",\"cwd\":\"$CWD\"}"
if [ "$STATUS" -eq 0 ] && ! grep -q 'ends_descendants' "$CALLS"; then
  ok "OPS-056: a session that is STARTING asserts nothing about what it started"
else
  bad "OPS-056: SessionStart sent ends_descendants: $(cat "$CALLS")"
fi

# The subagent starts, and is then KILLED: no SubagentStop is ever driven for
# it, which is exactly the shape the five stranded runs had.
script_tool observe_session ok '{"session_id":"agent-56","phase":"start","known":true,"registered":true,"run_id":"run-5656bbbb","task":"e9","worktree":"","repo":"example.test/org/name","branch":"dev/e9","agent_type":"prober"}'
drive "{\"hook_event_name\":\"SubagentStart\",\"session_id\":\"$SESS\",\"agent_id\":\"$AGENT\",\"agent_type\":\"prober\",\"cwd\":\"$CWD\"}"
if [ "$STATUS" -eq 0 ] && ! grep -q 'ends_descendants' "$CALLS"; then
  ok "OPS-056: starting a subagent asserts nothing about ending one"
else
  bad "OPS-056: SubagentStart sent ends_descendants: $(cat "$CALLS")"
fi

# THE SESSION IS STILL RUNNING. Every event it fires while it works must leave
# the killed subagent's run exactly where it is: no stop at all, and nothing
# asserting anything about descendants.
script_tool observe_tool_call ok '{"digest":"sha256:'"$(printf 'c%.0s' $(seq 1 64))"'","stored":true}'
drive "{\"hook_event_name\":\"PostToolUse\",\"session_id\":\"$SESS\",\"tool_name\":\"Edit\",\"tool_input\":{\"file_path\":\"x\"}}"
still_running_calls="$(cat "$CALLS")"
drive "{\"hook_event_name\":\"PreToolUse\",\"session_id\":\"$SESS\",\"tool_name\":\"Read\",\"tool_input\":{\"file_path\":\"x\"}}"
still_running_calls="$still_running_calls
$(cat "$CALLS")"
if ! printf '%s' "$still_running_calls" | grep -q 'ends_descendants' \
   && ! printf '%s' "$still_running_calls" | grep -q '"phase": "stop"'; then
  ok "OPS-056: nothing is ended while the session is still running"
else
  bad "OPS-056: a working session asserted an ending: $still_running_calls"
fi

# AND AT THE NEXT SESSION END, IT SAYS SO \u2014 once, for itself, naming no child.
script_tool observe_session ok '{"session_id":"sess-56","phase":"stop","known":true,"retired":true,"run_id":"run-5656aaaa","retired_at":"2026-09-18T00:00:00.000Z","detail":"this stop ends what it started: 1 run(s) below this one are recorded as ended"}'
drive "{\"hook_event_name\":\"SessionEnd\",\"session_id\":\"$SESS\"}"
if [ "$STATUS" -eq 0 ] && called observe_session '"phase": "stop"' "\"session_id\": \"$SESS\"" '"ends_descendants": true'; then
  ok "OPS-056: SessionEnd asserts that it ends the runs it started"
else
  bad "OPS-056: SessionEnd: status $STATUS, calls: $(cat "$CALLS")"
fi

# A JSON BOOLEAN, NOT THE STRING "true". The tool declares a boolean, so a
# string is refused \u2014 and the refusal would arrive as a stop that silently did
# not happen, because a stop never blocks and never reports one as a failure the
# harness can act on.
if ! grep -q '"ends_descendants": "true"' "$CALLS"; then
  ok "OPS-056: the assertion is sent as a JSON boolean, not as a string"
else
  bad "OPS-056: ends_descendants was sent as a string: $(cat "$CALLS")"
fi

# ONE CALL, AND NO RUN IDS. The shim does not enumerate the session's subagents,
# does not hold their run ids and does not retire anything itself: resolving
# which runs a run started is the MCP's, which is the whole of E11. A shim that
# walked its own marker directory would pass the assertion above and be the
# lookup back in the harness.
if [ "$(grep -c '^observe_session ' "$CALLS")" = "1" ] && ! grep -q '^retire_agent ' "$CALLS"; then
  ok "OPS-056: one stop, and the shim resolves no descendants of its own"
else
  bad "OPS-056: SessionEnd made $(grep -c '^observe_session ' "$CALLS") session calls: $(cat "$CALLS")"
fi

# AND THE SUBAGENT'S OWN STOP ASSERTS IT TOO, because a subagent can itself have
# started others and they die with it the same way.
script_tool observe_session ok '{"session_id":"agent-56","phase":"stop","known":true,"retired":true,"run_id":"run-5656bbbb","retired_at":"2026-09-18T00:00:00.000Z"}'
drive "{\"hook_event_name\":\"SubagentStop\",\"session_id\":\"$SESS\",\"agent_id\":\"$AGENT\",\"agent_type\":\"prober\"}"
if [ "$STATUS" -eq 0 ] && called observe_session '"phase": "stop"' '"ends_descendants": true'; then
  ok "OPS-056: a subagent's stop ends what that subagent started"
else
  bad "OPS-056: SubagentStop: status $STATUS, calls: $(cat "$CALLS")"
fi

# AND A REFUSED START RETIRES WITHOUT ASSERTING ANYTHING. The worktree gate
# stops a subagent on its way in and retires the run it just registered; that
# run started nothing, and a stop that claimed otherwise would be a claim made
# about nothing at all.
script_tool observe_session ok '{"session_id":"agent-57","phase":"start","known":true,"registered":true,"run_id":"run-5757cccc","task":"e9","worktree":"","repo":"example.test/org/name","branch":"dev/e9","agent_type":"prober"}'
: > "$CALLS"
printf '%s' "{\"hook_event_name\":\"SubagentStart\",\"session_id\":\"$SESS\",\"agent_id\":\"agent-57\",\"agent_type\":\"prober\",\"cwd\":\"$CWD\"}" | env \
  INNSEGL_MCP_ADMIN_URL="$ADMIN" INNSEGL_RUNS_DIR="$RUNS" INNSEGL_LOG_DIR="$LOG" \
  INNSEGL_SIGNER="$WORK/signer" INNSEGL_REQUIRE_WORKTREE=1 \
  "$SHIM" > "$WORK/out" 2> "$WORK/err"
if [ "$?" -eq 2 ] && grep -q '"phase": "stop"' "$CALLS" && ! grep -q 'ends_descendants' "$CALLS"; then
  ok "OPS-056: the worktree gate's own stop asserts nothing about descendants"
else
  bad "OPS-056: the worktree gate's stop: $(cat "$CALLS")"
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

# THE WORKTREE AND THE BRANCH, which are describe_workspace's and stay its.
#
# `remote get-url` LEFT THIS BAN in #266 and the reason is narrow: a
# repository-scoped credential has to name a repository BEFORE the call it
# authorises, and the only tool that could answer is behind the credential. So
# the shim reads origin for that one purpose, and case 14 holds the boundary —
# no repo, branch, task or worktree ever reaches a tool argument from here.
# Nothing else about E11 moved: a second harness still calls one tool and gets
# one answer, and the two derivations that produced four field incidents are
# still not in this file.
if ! grep -qE '^[^#]*(worktree list|symbolic-ref)' "$SHIM"; then
  ok "the shim derives no worktree and no branch — both moved (#205)"
else
  bad "the shim still derives a workspace: $(grep -nE '^[^#]*(worktree list|symbolic-ref)' "$SHIM" | head -n 3)"
fi

# 14. AND THE REPOSITORY IT DOES READ GOES NOWHERE NEAR A TOOL CALL. This is
#     the behavioural half of case 13, and it is the one that would catch the
#     derivation creeping back: a shim that started sending its own `repo`,
#     `branch`, `task` or `worktree` would be claiming workspace facts the
#     ledger records, which is exactly what #205 took away.
if ! grep -qE '"(repo|branch|task|worktree)":' "$WORK/allcalls"; then
  ok "no tool call from the shim carries repo, branch, task or worktree (#205)"
else
  bad "the shim sent a workspace fact: $(grep -hE '"(repo|branch|task|worktree)":' "$WORK/allcalls")"
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

# --- OPS-074..077: the capture is bounded, and the bound is on the COMMIT ------
#
# `git add -A` staged the whole tree, so a stopping run became the signed author
# of whatever else was uncommitted. Measured three times on 2026-09-18, once by a
# review subagent that had written nothing at all.
#
# THE FIRST FIX WAS TESTED THE WRONG WAY ROUND, and that is the lesson these
# cases exist to hold. It added a bound on what the stop ADDS, and proved it by
# calling the extraction directly against a fixture of bodies: 27 assertions, all
# green, and a nine-file capture through the same code afterwards. Two holes, and
# neither was visible from there, because neither is a property of the
# extraction:
#
#   A BASH WRITE IS INVISIBLE. The run that slipped through made 62 `Bash`
#   calls, 27 of them writing to a file, against 1 `Write` and 1 `Edit`. A
#   filter that looks for Edit/Write/NotebookEdit describes how a PERSON writes
#   files, not how these agents do.
#
#   `git add` REMOVES NOTHING. The stop commits the INDEX, so whatever another
#   party had already staged went in regardless of what the bound picked.
#
# So these cases drive the SHIM, against a real repository, and assert what ended
# up in a commit — not what a function returned. A case here fails if the capture
# is unbounded even while every extraction assertion passes.

CREPO="$WORK/capture/repo"
mkdir -p "$CREPO" "$WORK/nohooks"
git -C "$CREPO" init -q 2>/dev/null
git -C "$CREPO" config user.email "selftest@example.test"
git -C "$CREPO" config user.name "shim-selftest"
git -C "$CREPO" config commit.gpgsign false
# core.hooksPath, because this repository sets one and a fixture living inside
# it would otherwise inherit the gates written for the real tree.
git -C "$CREPO" config core.hooksPath "$WORK/nohooks"
printf 'base\n' > "$CREPO/base.txt"
git -C "$CREPO" add base.txt
git -C "$CREPO" commit -q -m "base"
CREPO_REAL="$(cd "$CREPO" && pwd -P)"

# A SIGNER THAT ACTUALLY COMMITS, so "no commit" is asserted as a HEAD that did
# not move rather than as a script that was not called. It refuses anywhere but
# the fixture: earlier cases drive a stop against the REAL repository, and a
# signer that committed would commit there.
cat > "$WORK/capture-signer" <<SH
#!/bin/sh
printf '%s\n' "\$*" >> "$WORK/signer.calls"
[ "\$(pwd -P)" = "$CREPO_REAL" ] || { echo "capture-signer: refusing outside the fixture" >&2; exit 1; }
git commit -q -m "captured by the harness" >/dev/null 2>&1
SH
chmod +x "$WORK/capture-signer"

# capture_run <agent-id> <run-id> — a registered run whose marker names the
# fixture, with an empty body store ready for the case to plant into.
capture_run() {
  script_tool observe_session ok "{\"session_id\":\"$1\",\"phase\":\"start\",\"known\":true,\"registered\":true,\"run_id\":\"$2\",\"task\":\"rm158\",\"worktree\":\"\",\"repo\":\"example.test/org/name\",\"branch\":\"dev/rm158\",\"agent_type\":\"prober\"}"
  SIGNER="$WORK/capture-signer" drive "{\"hook_event_name\":\"SubagentStart\",\"session_id\":\"sess-1\",\"agent_id\":\"$1\",\"agent_type\":\"prober\",\"cwd\":\"$CREPO\"}"
  rm -rf "${LOG:?}/$2"; mkdir -p "$LOG/$2"
}

# wrote_body <run-id> <name> <tool> <tool_input json>
wrote_body() { printf '{"tool_name":"%s","tool_input":%s}' "$3" "$4" > "$LOG/$1/$2.json"; }

# capture_stop <agent-id> — the stop, with the committing signer in place.
capture_stop() {
  script_tool observe_session ok "{\"session_id\":\"$1\",\"phase\":\"stop\",\"known\":true,\"retired\":true,\"run_id\":\"retired\"}"
  : > "$WORK/signer.calls"
  SIGNER="$WORK/capture-signer" drive "{\"hook_event_name\":\"SubagentStop\",\"session_id\":\"sess-1\",\"agent_id\":\"$1\",\"agent_type\":\"prober\"}"
}

staged_now() { git -C "$CREPO" diff --cached --name-only | sort | tr '\n' ' '; }

# --- OPS-074: the index holds work the run cannot account for ------------------
#
# The run wrote one file through `Edit`. Another party has already STAGED a file
# of its own, and the run also ran a `Bash` command that wrote a third. A stop
# that commits the index signs all three under this run.
capture_run agent-cap1 run-cap1
wrote_body run-cap1 a Edit "{\"file_path\":\"$CREPO/mine.txt\"}"
# The Bash write, recorded exactly as the harness records it: a command, and no
# file path anywhere in the event. Guessing a filename out of the redirection is
# `git add -A` with more steps, so this must not be credited to the run.
wrote_body run-cap1 b Bash "{\"command\":\"printf x > $CREPO/bashwrote.txt\"}"
printf 'mine\n'   > "$CREPO/mine.txt"
printf 'bash\n'   > "$CREPO/bashwrote.txt"
printf 'theirs\n' > "$CREPO/theirs.txt"
git -C "$CREPO" add theirs.txt        # staged by someone who is not this run
HEAD_BEFORE="$(git -C "$CREPO" rev-parse HEAD)"
capture_stop agent-cap1
cp "$WORK/err" "$WORK/err.cap1"

if [ "$(git -C "$CREPO" rev-parse HEAD)" = "$HEAD_BEFORE" ] && [ ! -s "$WORK/signer.calls" ]; then
  ok "OPS-074: an index holding work the run cannot account for produces no commit"
else
  bad "OPS-074: the stop committed $(git -C "$CREPO" show --stat --oneline HEAD | head -n 5 | tr '\n' ' ')"
fi
if [ "$(staged_now)" = "theirs.txt " ]; then
  ok "OPS-074: the refusal leaves the index exactly as it found it"
else
  bad "OPS-074: the index after the refusal is '$(staged_now)', want 'theirs.txt '"
fi
if grep -q 'theirs.txt' "$WORK/err.cap1"; then
  ok "OPS-074: and it names the path it could not account for"
else
  bad "OPS-074: the refusal does not name theirs.txt: $(cat "$WORK/err.cap1")"
fi
if [ ! -s "$WORK/signer.calls" ] && ! grep -q 'bashwrote.txt' "$WORK/signer.calls"; then
  ok "OPS-074: a file written by a Bash redirection is not guessed into the capture"
else
  bad "OPS-074: a Bash write reached the capture: $(cat "$WORK/signer.calls")"
fi

# --- OPS-075: a run that recorded no write captures nothing, in any tree -------
#
# THE FIRST MEASURED INCIDENT, in a fixture. A review subagent read files for
# eight minutes, wrote none, and its stop signed 12 files and ~890 lines the
# session had authored. Reading alone must reach no commit however dirty the
# tree is and whoever else has staged what.
git -C "$CREPO" reset -q
git -C "$CREPO" checkout -q -- .
git -C "$CREPO" clean -qfd
capture_run agent-cap2 run-cap2
wrote_body run-cap2 a Read "{\"file_path\":\"$CREPO/base.txt\"}"
printf 'dirty\n' >> "$CREPO/base.txt"
printf 'other\n'   > "$CREPO/other.txt"
printf 'theirs2\n' > "$CREPO/theirs2.txt"
git -C "$CREPO" add theirs2.txt       # the session's own work, already staged
HEAD_BEFORE="$(git -C "$CREPO" rev-parse HEAD)"
capture_stop agent-cap2
if [ "$(git -C "$CREPO" rev-parse HEAD)" = "$HEAD_BEFORE" ] && [ ! -s "$WORK/signer.calls" ]; then
  ok "OPS-075: a run that recorded no write produces no commit in a dirty tree"
else
  bad "OPS-075: a read-only run committed $(git -C "$CREPO" show --stat --oneline HEAD | head -n 5 | tr '\n' ' ')"
fi
if [ "$(staged_now)" = "theirs2.txt " ]; then
  ok "OPS-075: and it neither stages nor unstages anything on its way past"
else
  bad "OPS-075: a read-only run left the index as '$(staged_now)', want 'theirs2.txt '"
fi
if grep -q 'run-cap2' "$WORK/err"; then
  ok "OPS-075: and it says which run declined, so the work is not stranded silently"
else
  bad "OPS-075: nothing named run-cap2: $(cat "$WORK/err")"
fi

# --- OPS-076: a refusal is nameable -------------------------------------------
#
# Stranding the work silently is worse than the misattribution this fixes: the
# run is gone, and the only party left who can sign its work is the operator. So
# a refusal carries the run id AND the argument that signs under it.
if grep -q 'run-cap1' "$WORK/err.cap1" && grep -q -- '-r run-cap1' "$WORK/err.cap1"; then
  ok "OPS-076: a refusal names the run and the argument that signs under it later"
else
  bad "OPS-076: the refusal does not say what to sign the work under: $(cat "$WORK/err.cap1")"
fi

# --- OPS-077: the capture that IS allowed is bounded to the run's own writes ---
git -C "$CREPO" reset -q
git -C "$CREPO" checkout -q -- .
git -C "$CREPO" clean -qfd
capture_run agent-cap3 run-cap3
wrote_body run-cap3 a Write "{\"file_path\":\"$CREPO/mine3.txt\"}"
printf 'mine3\n'   > "$CREPO/mine3.txt"
printf 'theirs3\n' > "$CREPO/theirs3.txt"     # dirty, and nobody staged it
HEAD_BEFORE="$(git -C "$CREPO" rev-parse HEAD)"
capture_stop agent-cap3
if [ "$(git -C "$CREPO" rev-parse HEAD)" != "$HEAD_BEFORE" ]; then
  ok "OPS-077: a run whose index is entirely its own is captured"
else
  bad "OPS-077: nothing was captured: $(cat "$WORK/err")"
fi
if grep -q -- '-r run-cap3' "$WORK/signer.calls"; then
  ok "OPS-077: and it is signed under that run, not under a fresh identity"
else
  bad "OPS-077: the signer was given '$(cat "$WORK/signer.calls")'"
fi
if [ "$(git -C "$CREPO" show --name-only --format= HEAD | sort | tr -d '\n' | sed 's/^ *//')" = "mine3.txt" ]; then
  ok "OPS-077: the commit holds the run's own write and nothing else in the tree"
else
  bad "OPS-077: the capture committed $(git -C "$CREPO" show --name-only --format= HEAD | tr '\n' ' ')"
fi

# --- OPS-085..088: a capture that fails leaves a durable record ---------------
#
# #277 (RM-172). Every refusal and every failure in the capture path above
# reported itself through `warn`, and `warn` writes to the stderr of a
# SubagentStop, which the harness discards. The hook is also forbidden to exit 2
# on a stop — nine invocations, measured — so it could not report by refusing
# either. A refused capture, a failed signature and a clean tree were therefore
# one thing seen from outside: nothing. Measured, two subagents stopped within
# the same minute; one was captured and committed, the other was not, and the
# only evidence of the second was that its files were missing hours later.
#
# So these cases assert a FILE and not a message — what the stop wrote down,
# read back after the process that wrote it has exited. Every one of them is red
# against the shim as it stood, and red on merit: not because an assertion is
# spelled differently, but because there was no record of any kind to read.

UNCAP="$RUNS/uncaptured.jsonl"

# The record is APPEND-ONLY by design, so a case that wants to assert what ONE
# stop wrote clears it first. Cases above this line have already written to it:
# they drive stops against the real repository, whose tree is dirty on a working
# machine, and a refusal there is exactly the thing being recorded.
uncap_reset() { rm -f "$UNCAP"; }
uncap_lines() { if [ -f "$UNCAP" ]; then grep -c . "$UNCAP"; else echo 0; fi; }

# uncap_field <field> — that field of the LAST line written.
uncap_field() {
  python3 -c '
import json, sys
last = ""
try:
    for last in open(sys.argv[1]):
        pass
except Exception:
    last = ""
try:
    v = json.loads(last).get(sys.argv[2], "")
except Exception:
    v = ""
print(v if isinstance(v, str) else json.dumps(v))
' "$UNCAP" "$1" 2>/dev/null
}

# capture_run_wt <agent-id> <run-id> <worktree> — capture_run, with the ledger
# naming a worktree. The issue asks the record to name one, and a fixture whose
# worktree is empty cannot tell a field that is carried from a field that is
# dropped.
capture_run_wt() {
  script_tool observe_session ok "{\"session_id\":\"$1\",\"phase\":\"start\",\"known\":true,\"registered\":true,\"run_id\":\"$2\",\"task\":\"rm172\",\"worktree\":\"$3\",\"repo\":\"example.test/org/name\",\"branch\":\"dev/rm172\",\"agent_type\":\"prober\"}"
  SIGNER="$WORK/capture-signer" drive "{\"hook_event_name\":\"SubagentStart\",\"session_id\":\"sess-1\",\"agent_id\":\"$1\",\"agent_type\":\"prober\",\"cwd\":\"$CREPO\"}"
  rm -rf "${LOG:?}/$2"; mkdir -p "$LOG/$2"
}

# capture_stop_by <agent-id> <signer> — the stop, with a chosen signer.
capture_stop_by() {
  script_tool observe_session ok "{\"session_id\":\"$1\",\"phase\":\"stop\",\"known\":true,\"retired\":true,\"run_id\":\"retired\"}"
  : > "$WORK/signer.calls"
  SIGNER="$2" drive "{\"hook_event_name\":\"SubagentStop\",\"session_id\":\"sess-1\",\"agent_id\":\"$1\",\"agent_type\":\"prober\"}"
}

# drive_deaf — drive, with the hook's stderr sent where the harness sends a
# SubagentStop's: nowhere. This is the whole claim of #277 made into a fixture.
drive_deaf() {
  : > "$CALLS"
  printf '%s' "$1" | env \
    INNSEGL_MCP_ADMIN_URL="$ADMIN" \
    INNSEGL_RUNS_DIR="$RUNS" \
    INNSEGL_LOG_DIR="$LOG" \
    INNSEGL_SIGNER="${SIGNER:-$WORK/signer}" \
    INNSEGL_API_URL="${API:-http://127.0.0.1:1/}" \
    INNSEGL_ADMIN_CREDENTIAL_MINT="${MINT:-}" \
    "$SHIM" > /dev/null 2>/dev/null
  STATUS=$?
  cat "$CALLS" >> "$WORK/allcalls"
}

# A signer that cannot sign because the deployment is not there, and one that
# cannot because the run has already been retired. Both are real refusals of
# scripts/innsegl-commit.sh and both used to reach the operator as nothing at
# all: the signer printed to a stderr the harness throws away.
cat > "$WORK/signer-down" <<SH
#!/bin/sh
printf '%s\n' "\$*" >> "$WORK/signer.calls"
echo "innsegl-commit: the identity lifecycle did not answer; nothing was signed" >&2
exit 1
SH
cat > "$WORK/signer-retired" <<SH
#!/bin/sh
printf '%s\n' "\$*" >> "$WORK/signer.calls"
echo "innsegl-commit: refused, that run is already retired and cannot sign" >&2
exit 1
SH
chmod +x "$WORK/signer-down" "$WORK/signer-retired"

creset() {
  git -C "$CREPO" reset -q
  git -C "$CREPO" checkout -q -- .
  git -C "$CREPO" clean -qfd
}

# --- OPS-085: the index holds files the run cannot account for ----------------
#
# The refusal OPS-074 proves is correct is also the refusal that vanished. Same
# fixture shape, and what is asserted here is what survived it.
creset
uncap_reset
capture_run_wt agent-cap5 run-cap5 wt-cap5
wrote_body run-cap5 a Edit "{\"file_path\":\"$CREPO/mine5.txt\"}"
printf 'mine5\n'   > "$CREPO/mine5.txt"
printf 'theirs5\n' > "$CREPO/theirs5.txt"
git -C "$CREPO" add theirs5.txt        # staged by someone who is not this run
HEAD_BEFORE="$(git -C "$CREPO" rev-parse HEAD)"
capture_stop agent-cap5

if [ "$STATUS" -eq 0 ] && [ "$(uncap_lines)" = "1" ]; then
  ok "OPS-085 a refused capture writes exactly one durable record, and still exits 0"
else
  bad "OPS-085 status $STATUS, $(uncap_lines) record(s) at $UNCAP"
fi
if [ "$(uncap_field reason)" = "index_unaccounted" ] && [ "$(uncap_field run_id)" = "run-cap5" ]; then
  ok "OPS-085 and it names the run and why the capture was refused"
else
  bad "OPS-085 reason '$(uncap_field reason)' run '$(uncap_field run_id)', want index_unaccounted / run-cap5"
fi
# THE FOUR THE ISSUE ASKS FOR: the run, the reason, the worktree and the file
# count. The tree is carried twice on purpose — `dir` is where the work is on
# this machine, which is what a recovery needs, and `worktree` is what the
# ledger calls it, which is what a reader correlating with a run needs.
if [ "$(uncap_field dir)" = "$CREPO" ] && [ "$(uncap_field worktree)" = "wt-cap5" ] \
   && [ "$(uncap_field wrote)" = "1" ] && [ "$(uncap_field unaccounted)" = "1" ] \
   && [ "$(uncap_field dirty)" != "0" ]; then
  ok "OPS-085 and the worktree and the file counts, which is what a recovery needs"
else
  bad "OPS-085 dir '$(uncap_field dir)' worktree '$(uncap_field worktree)' wrote '$(uncap_field wrote)' unaccounted '$(uncap_field unaccounted)' dirty '$(uncap_field dirty)'"
fi
# AND IT NAMES THE PATH THE RUN COULD HAVE COMMITTED. Without it a recovery
# knows a capture failed and not what to stage.
if [ "$(uncap_field wrote_paths)" = '["mine5.txt"]' ] \
   && [ "$(uncap_field unaccounted_paths)" = '["theirs5.txt"]' ]; then
  ok "OPS-085 and which paths were the run's and which were not"
else
  bad "OPS-085 wrote_paths $(uncap_field wrote_paths) unaccounted_paths $(uncap_field unaccounted_paths)"
fi
# THE RECORD IS READ HERE TOO, and not only the tree. "Nothing moved" is true
# of a shim that does nothing at all, so a case asserting only that is green
# against the very defect it exists to catch.
if [ "$(uncap_field run_id)" = "run-cap5" ] \
   && [ "$(git -C "$CREPO" rev-parse HEAD)" = "$HEAD_BEFORE" ] && [ "$(staged_now)" = "theirs5.txt " ]; then
  ok "OPS-085 and writing it changes nothing: HEAD is where it was, and so is the index"
else
  bad "OPS-085 run '$(uncap_field run_id)', HEAD moved or the index is '$(staged_now)'"
fi

# --- OPS-086: a run that cannot be asked, and a run with nothing of its own ----
#
# Two refusals that are not the same refusal, and the record has to tell them
# apart — a reader who cannot is back to reading a missing file hours later.
creset
uncap_reset
capture_run_wt agent-cap6 run-cap6 wt-cap6
rm -rf "${LOG:?}/run-cap6"              # its tool-call bodies are gone
printf 'dirty6\n' >> "$CREPO/base.txt"
capture_stop agent-cap6
R_UNREADABLE="$(uncap_field reason)"
if [ "$STATUS" -eq 0 ] && [ "$(uncap_field reason)" = "bodies_unreadable" ] \
   && [ "$(uncap_field run_id)" = "run-cap6" ]; then
  ok "OPS-086 a run that cannot be asked what it wrote is recorded as that, not as silence"
else
  bad "OPS-086 status $STATUS, reason '$(uncap_field reason)', run '$(uncap_field run_id)'"
fi

creset
uncap_reset
capture_run_wt agent-cap7 run-cap7 wt-cap7
wrote_body run-cap7 a Read "{\"file_path\":\"$CREPO/base.txt\"}"
printf 'dirty7\n' >> "$CREPO/base.txt"
printf 'theirs7\n' > "$CREPO/theirs7.txt"
git -C "$CREPO" add theirs7.txt
capture_stop agent-cap7
R_READONLY="$(uncap_field reason)"
if [ "$STATUS" -eq 0 ] && [ "$(uncap_field reason)" = "no_recorded_writes" ] \
   && [ "$(uncap_field wrote)" = "0" ] && [ "$(uncap_field dirty)" != "0" ]; then
  ok "OPS-086 and a read-only run is recorded as having written nothing, with the tree still dirty"
else
  bad "OPS-086 read-only: status $STATUS, reason '$(uncap_field reason)', wrote '$(uncap_field wrote)', dirty '$(uncap_field dirty)'"
fi
# BOTH NAMED, not merely unequal. Two runs that record nothing also record
# two reasons that differ from any constant, which is how a case like this
# passes over the very silence it is about.
if [ "$R_UNREADABLE" = "bodies_unreadable" ] && [ "$R_READONLY" = "no_recorded_writes" ] \
   && [ "$R_UNREADABLE" != "$R_READONLY" ]; then
  ok "OPS-086 and the two refusals are told apart, which is the whole use of the record"
else
  bad "OPS-086 the two refusals recorded '$R_UNREADABLE' and '$R_READONLY'"
fi

# --- OPS-087: signing unavailable, and a run already retired ------------------
#
# The path that loses the most. The capture got as far as staging the run's own
# work and then the signature failed, so the work IS recoverable — staged, in a
# named tree, under a named run — and every word of that used to go to a stderr
# the harness discards. The signer said WHY, once, and that sentence was the
# first thing lost.
creset
uncap_reset
capture_run_wt agent-cap8 run-cap8 wt-cap8
wrote_body run-cap8 a Write "{\"file_path\":\"$CREPO/mine8.txt\"}"
printf 'mine8\n' > "$CREPO/mine8.txt"
HEAD_BEFORE="$(git -C "$CREPO" rev-parse HEAD)"
capture_stop_by agent-cap8 "$WORK/signer-down"
if [ "$STATUS" -eq 0 ] && [ "$(uncap_field reason)" = "signing_failed" ] \
   && [ "$(uncap_field run_id)" = "run-cap8" ]; then
  ok "OPS-087 a signature that could not be made is recorded, and the stop still exits 0"
else
  bad "OPS-087 status $STATUS, reason '$(uncap_field reason)', run '$(uncap_field run_id)'"
fi
case "$(uncap_field detail)" in
  *"did not answer"*) ok "OPS-087 and it carries what the signer said, which is the one sentence that was lost" ;;
  *) bad "OPS-087 the record does not carry the signer's reason: '$(uncap_field detail)'" ;;
esac
# ENOUGH TO REDO THE WORK: the tree, the run, and the paths that are staged in
# it waiting to be signed under that run.
if [ "$(git -C "$CREPO" rev-parse HEAD)" = "$HEAD_BEFORE" ] && [ "$(staged_now)" = "mine8.txt " ] \
   && [ "$(uncap_field dir)" = "$CREPO" ] && [ "$(uncap_field staged)" = "1" ]; then
  ok "OPS-087 and it names the tree and the count still staged there, so the work can be signed later"
else
  bad "OPS-087 staged '$(staged_now)' dir '$(uncap_field dir)' staged count '$(uncap_field staged)'"
fi

creset
uncap_reset
capture_run_wt agent-cap9 run-cap9 wt-cap9
wrote_body run-cap9 a Write "{\"file_path\":\"$CREPO/mine9.txt\"}"
printf 'mine9\n' > "$CREPO/mine9.txt"
capture_stop_by agent-cap9 "$WORK/signer-retired"
case "$(uncap_field reason)/$(uncap_field detail)" in
  signing_failed/*"already retired"*)
    ok "OPS-087 a run already retired is recorded with the refusal that names it" ;;
  *) bad "OPS-087 retired: reason '$(uncap_field reason)' detail '$(uncap_field detail)'" ;;
esac
if [ "$STATUS" -eq 0 ] && [ "$(uncap_lines)" = "1" ]; then
  ok "OPS-087 one attempt, one record, and a stop that never blocks"
else
  bad "OPS-087 retired: status $STATUS, $(uncap_lines) record(s)"
fi

# --- OPS-088: success writes nothing, and the record outlives the process ------
#
# The negative half, and it is asserted against a refusal in the SAME log rather
# than on its own: "nothing was written" is worth nothing unless something else
# would have been. A capture that commits is already recorded as
# `commit_recorded` by the ledger, so a second line here would be a second
# source of truth for one fact.
creset
uncap_reset
capture_run_wt agent-cap10 run-cap10 wt-cap10
wrote_body run-cap10 a Read "{\"file_path\":\"$CREPO/base.txt\"}"
printf 'dirty10\n' >> "$CREPO/base.txt"
capture_stop agent-cap10
AFTER_REFUSAL="$(uncap_lines)"

creset
capture_run_wt agent-cap11 run-cap11 wt-cap11
wrote_body run-cap11 a Write "{\"file_path\":\"$CREPO/mine11.txt\"}"
printf 'mine11\n' > "$CREPO/mine11.txt"
HEAD_BEFORE="$(git -C "$CREPO" rev-parse HEAD)"
capture_stop agent-cap11
AFTER_SUCCESS="$(uncap_lines)"

if [ "$(git -C "$CREPO" rev-parse HEAD)" != "$HEAD_BEFORE" ] \
   && [ "$AFTER_REFUSAL" = "1" ] && [ "$AFTER_SUCCESS" = "1" ]; then
  ok "OPS-088 a capture that commits writes no record, where a refused one wrote exactly one"
else
  bad "OPS-088 $AFTER_REFUSAL record(s) after the refusal, $AFTER_SUCCESS after the capture"
fi
# THE REFUSED RUN IS NAMED AND THE CAPTURED ONE IS NOT, asserted together. An
# empty file satisfies the second half on its own, which is the shim this
# replaces.
if grep -q 'run-cap10' "$UNCAP" 2>/dev/null && ! grep -q 'run-cap11' "$UNCAP" 2>/dev/null; then
  ok "OPS-088 and the ledger fact is not duplicated: the refused run is named, the captured one is not"
else
  bad "OPS-088 the log names $(grep -o 'run-cap1[01]' "$UNCAP" 2>/dev/null | sort -u | tr '\n' ' ')"
fi

# A clean tree is not an attempt, so it is not an outcome either. This is what
# stops the record from becoming a line per stop, which is a line nobody reads.
creset
BEFORE_CLEAN="$(uncap_lines)"
capture_run_wt agent-cap12 run-cap12 wt-cap12
wrote_body run-cap12 a Write "{\"file_path\":\"$CREPO/mine12.txt\"}"
capture_stop agent-cap12
# THE LOG IS NOT CLEARED FIRST, deliberately. "It wrote nothing" is worth
# nothing measured against an empty file; it is worth something measured
# against a log that already holds the one line a refusal put there.
if [ "$BEFORE_CLEAN" = "1" ] && [ "$(uncap_lines)" = "1" ] \
   && ! grep -q 'run-cap12' "$UNCAP" 2>/dev/null; then
  ok "OPS-088 a stop over a clean tree attempts no capture and records none"
else
  bad "OPS-088 $BEFORE_CLEAN record(s) before the clean stop and $(uncap_lines) after"
fi

# AND THE RECORD SURVIVES THE PROCESS THAT WROTE IT. The same refusal, driven
# with the hook's stderr sent exactly where the harness sends a SubagentStop's,
# and read back afterwards from the filesystem. If this passes while the
# warnings are thrown away, the record is durable in the only sense the issue
# asks for.
creset
uncap_reset
capture_run_wt agent-cap13 run-cap13 wt-cap13
wrote_body run-cap13 a Edit "{\"file_path\":\"$CREPO/mine13.txt\"}"
printf 'mine13\n'   > "$CREPO/mine13.txt"
printf 'theirs13\n' > "$CREPO/theirs13.txt"
git -C "$CREPO" add theirs13.txt
script_tool observe_session ok '{"session_id":"agent-cap13","phase":"stop","known":true,"retired":true,"run_id":"retired"}'
SIGNER="$WORK/capture-signer" drive_deaf '{"hook_event_name":"SubagentStop","session_id":"sess-1","agent_id":"agent-cap13","agent_type":"prober"}'
if [ "$STATUS" -eq 0 ] && [ "$(uncap_field run_id)" = "run-cap13" ] \
   && [ "$(uncap_field reason)" = "index_unaccounted" ]; then
  ok "OPS-088 a stop whose stderr goes nowhere still leaves the record on disk"
else
  bad "OPS-088 deaf stop: status $STATUS, $(uncap_lines) record(s), run '$(uncap_field run_id)'"
fi

creset
uncap_reset

# --- OPS-089: a tree that cannot be read is not a tree with nothing in it -----
#
# #284 (RM-178). The stop asked `git status` how much was uncommitted through a
# pipe into `wc -l`, and a pipeline reports the LAST command's status — so a
# `git status` that failed printed nothing, counted 0, and was indistinguishable
# from a clean tree. The hook then concluded there was nothing to capture, no
# capture was attempted, no capture failed, and #277's record was never written.
#
# EVERY CASE HERE IS RED ON MERIT against the shim as it stood, and red for the
# one reason that matters: the record file is EMPTY. Not a different reason, not
# a differently spelled field — nothing at all was written, which is the defect.

# capture_run_in <agent-id> <run-id> <dir> — capture_run, against a chosen tree
# rather than the fixture repository. The marker records whatever cwd the start
# event carried, existing or not, which is how a tree that is GONE by the time
# the run stops is driven at all.
capture_run_in() {
  script_tool observe_session ok "{\"session_id\":\"$1\",\"phase\":\"start\",\"known\":true,\"registered\":true,\"run_id\":\"$2\",\"task\":\"rm178\",\"worktree\":\"wt-$2\",\"repo\":\"example.test/org/name\",\"branch\":\"dev/rm178\",\"agent_type\":\"prober\"}"
  SIGNER="$WORK/capture-signer" drive "{\"hook_event_name\":\"SubagentStart\",\"session_id\":\"sess-1\",\"agent_id\":\"$1\",\"agent_type\":\"prober\",\"cwd\":\"$3\"}"
  rm -rf "${LOG:?}/$2"; mkdir -p "$LOG/$2"
}

# A DIRECTORY GIT REFUSES TO ANSWER ABOUT. `.git` as a file naming a gitdir that
# is not there is `fatal: not a git repository`, exit 128 — a real failure of the
# real command, rather than a stub standing in for one. An unreadable index and
# a deleted tree reach the same line by the same route.
UNREADABLE="$WORK/capture/unreadable"
mkdir -p "$UNREADABLE"
printf 'gitdir: %s/capture/nowhere-%s\n' "$WORK" "$$" > "$UNREADABLE/.git"

uncap_reset
capture_run_in agent-cap20 run-cap20 "$UNREADABLE"
capture_stop agent-cap20
if [ "$STATUS" -eq 0 ] && [ "$(uncap_lines)" = "1" ] \
   && [ "$(uncap_field reason)" = "tree_unreadable" ] \
   && [ "$(uncap_field run_id)" = "run-cap20" ]; then
  ok "OPS-089 a stop whose tree cannot be read records that, and still exits 0"
else
  bad "OPS-089 status $STATUS, $(uncap_lines) record(s), reason '$(uncap_field reason)', run '$(uncap_field run_id)'"
fi
# AND IT CARRIES WHAT GIT SAID. "Could not read the tree" is not actionable;
# "not a git repository" and "index.lock exists" are different problems with
# different remedies, and that sentence went to a stderr the harness discards.
case "$(uncap_field detail)" in
  *"not a git repository"*)
    ok "OPS-089 and the reason git gave, which is the sentence that was being lost" ;;
  *) bad "OPS-089 the record carries no reason from git: '$(uncap_field detail)'" ;;
esac
if [ "$(uncap_field dir)" = "$UNREADABLE" ] && [ "$(uncap_field worktree)" = "wt-run-cap20" ]; then
  ok "OPS-089 and it names the tree on this machine and the one the ledger knows"
else
  bad "OPS-089 dir '$(uncap_field dir)' worktree '$(uncap_field worktree)'"
fi

# A TREE THAT IS GONE IS THE SAME DEFECT ONE LINE EARLIER. It never reached the
# `git status` at all: the stop tested for a directory, found none, and left.
uncap_reset
capture_run_in agent-cap21 run-cap21 "$WORK/capture/vanished-$$"
capture_stop agent-cap21
if [ "$STATUS" -eq 0 ] && [ "$(uncap_lines)" = "1" ] \
   && [ "$(uncap_field reason)" = "tree_absent" ] \
   && [ "$(uncap_field run_id)" = "run-cap21" ]; then
  ok "OPS-089 a run whose tree is gone is recorded too, and told apart from an unreadable one"
else
  bad "OPS-089 vanished tree: status $STATUS, $(uncap_lines) record(s), reason '$(uncap_field reason)'"
fi

# AND A GENUINELY CLEAN TREE STILL WRITES NOTHING, which is the half that keeps
# the record worth reading. Measured against a log that already holds the line
# an unreadable tree put there, not against an empty file — "it wrote nothing"
# is true of a shim that writes nothing ever.
uncap_reset
capture_run_in agent-cap22 run-cap22 "$UNREADABLE"
capture_stop agent-cap22
UNREADABLE_LINES="$(uncap_lines)"
creset
capture_run agent-cap23 run-cap23
wrote_body run-cap23 a Write "{\"file_path\":\"$CREPO/mine23.txt\"}"
capture_stop agent-cap23
if [ "$UNREADABLE_LINES" = "1" ] && [ "$(uncap_lines)" = "1" ] \
   && ! grep -q 'run-cap23' "$UNCAP" 2>/dev/null; then
  ok "OPS-089 and a clean tree, read successfully, still writes nothing at all"
else
  bad "OPS-089 clean tree: $UNREADABLE_LINES record(s) before, $(uncap_lines) after"
fi

# THE RECORD OUTLIVES THE PROCESS, driven with the hook's stderr sent exactly
# where the harness sends a SubagentStop's: nowhere. Everything the old code
# had to say about an unreadable tree went there, which is why it said nothing.
uncap_reset
capture_run_in agent-cap24 run-cap24 "$UNREADABLE"
script_tool observe_session ok '{"session_id":"agent-cap24","phase":"stop","known":true,"retired":true,"run_id":"retired"}'
SIGNER="$WORK/capture-signer" drive_deaf '{"hook_event_name":"SubagentStop","session_id":"sess-1","agent_id":"agent-cap24","agent_type":"prober"}'
if [ "$STATUS" -eq 0 ] && [ "$(uncap_field run_id)" = "run-cap24" ] \
   && [ "$(uncap_field reason)" = "tree_unreadable" ]; then
  ok "OPS-089 a deaf stop over an unreadable tree still leaves the record on disk"
else
  bad "OPS-089 deaf stop: status $STATUS, $(uncap_lines) record(s), run '$(uncap_field run_id)'"
fi

# AND IT TOUCHED NOTHING. A stop that cannot read a tree must not stage, commit
# or unstage in the one it CAN read.
creset
printf 'untouched\n' > "$CREPO/untouched23.txt"
git -C "$CREPO" add untouched23.txt
HEAD_BEFORE="$(git -C "$CREPO" rev-parse HEAD)"
uncap_reset
capture_run_in agent-cap25 run-cap25 "$UNREADABLE"
capture_stop agent-cap25
if [ "$(git -C "$CREPO" rev-parse HEAD)" = "$HEAD_BEFORE" ] \
   && [ "$(staged_now)" = "untouched23.txt " ] && [ "$(uncap_lines)" = "1" ]; then
  ok "OPS-089 and recording an unread tree changes nothing in any other one"
else
  bad "OPS-089 HEAD moved or the index is '$(staged_now)'"
fi

creset
uncap_reset

# --- OPS-095: the shim consults the destructive-git guard ---------------------
#
# #278 (RM-173). The guard itself is driven by
# scripts/hooks/git-tree-guard-selftest.sh, against a real tree, with the real
# command actually attempted. What is asserted HERE is the only thing that file
# cannot assert: that this shim reaches the guard at all, on the one event that
# can BLOCK a tool call, and that reaching it costs every other command nothing.
#
# A LIVE RUN, A TRACKED EDIT IT WROTE, AND THE STOP THAT WOULD HAVE CAPTURED IT
# HAS NOT FIRED. That is the window the measured incident happened in.
rm -f "$RUNS"/agent-* 2>/dev/null
creset
capture_run agent-guard1 run-guard1
wrote_body run-guard1 a Edit "{\"file_path\":\"$CREPO/base.txt\"}"
printf 'AGENT WORK\n' >> "$CREPO/base.txt"

guard_drive() {
  drive "{\"hook_event_name\":\"PreToolUse\",\"session_id\":\"sess-1\",\"agent_id\":\"agent-guard1\",\"tool_name\":\"${2:-Bash}\",\"cwd\":\"$CREPO\",\"tool_input\":{\"command\":$(printf '%s' "$1" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')}}"
}

# EVERY CASE CARRIES THE BLOCK, and none of them asserts "it was allowed" on its
# own. A shim that consults nothing allows every command there is, so a case
# asserting only that a `git status` got through is GREEN against the very
# defect it exists to catch — the same trap OPS-088 documents for "success
# writes nothing". Each assertion below therefore reads the one refusal that
# must happen alongside the thing that must not.
guard_drive 'git reset --hard HEAD'
BLOCKED=$STATUS
cp "$WORK/err" "$WORK/err.blocked"
DIRTY_AFTER="$(git -C "$CREPO" status --porcelain | wc -l | tr -d ' ')"

guard_drive 'git status --porcelain'
ALLOWED=$STATUS
guard_drive 'git reset --hard HEAD' Read
NOT_BASH=$STATUS
guard_drive 'echo "git reset --hard is what took the work"'
QUOTED=$STATUS
guard_drive 'git commit -m "x"'
COMMITTING=$STATUS
cp "$WORK/err" "$WORK/err.commit"
GIT_GUARD=0
guard_drive 'git reset --hard HEAD'
SWITCHED_OFF=$STATUS
GIT_GUARD=1
TREE_GUARD="$WORK/no-such-guard"
guard_drive 'git reset --hard HEAD'
NO_GUARD=$STATUS
TREE_GUARD=""

if [ "$BLOCKED" -eq 2 ] && grep -q 'run-guard1' "$WORK/err.blocked"; then
  ok "OPS-095 a Bash call that would discard a live run's work is blocked, naming the run"
else
  bad "OPS-095 status $BLOCKED, stderr: $(head -n 2 "$WORK/err.blocked")"
fi
# AND NOTHING RAN. A blocked call and an allowed one the harness happened not to
# run are the same exit status from here; the tree is what tells them apart.
if [ "$BLOCKED" -eq 2 ] && [ "$DIRTY_AFTER" != "0" ]; then
  ok "OPS-095 and nothing ran: the edit is still in the tree"
else
  bad "OPS-095 blocked $BLOCKED, $DIRTY_AFTER uncommitted path(s) left"
fi
# THE REFUSAL IS ACTIONABLE, not a wall. An agent that is merely refused reaches
# for the next spelling of the same command.
if [ "$BLOCKED" -eq 2 ] && grep -q 'INNSEGL_ALLOW_DESTRUCTIVE=1' "$WORK/err.blocked" \
   && grep -q 'innsegl-commit -r run-guard1' "$WORK/err.blocked"; then
  ok "OPS-095 and it offers both ways out: sign the work, or discard it deliberately"
else
  bad "OPS-095 the refusal offers no way through: $(cat "$WORK/err.blocked")"
fi

# EVERY OTHER COMMAND IS UNTOUCHED, and this is the half that decides whether
# the gate survives contact with an agent that runs git all day.
if [ "$BLOCKED" -eq 2 ] && [ "$ALLOWED" -eq 0 ]; then
  ok "OPS-095 and in the same tree a git that destroys nothing is allowed"
else
  bad "OPS-095 blocked $BLOCKED, git status $ALLOWED"
fi
if [ "$BLOCKED" -eq 2 ] && [ "$NOT_BASH" -eq 0 ]; then
  ok "OPS-095 and the same command under a tool that is not Bash is not a command"
else
  bad "OPS-095 blocked $BLOCKED, Read event $NOT_BASH"
fi
if [ "$BLOCKED" -eq 2 ] && [ "$QUOTED" -eq 0 ]; then
  ok "OPS-095 and a quoted mention of it is not the command either"
else
  bad "OPS-095 blocked $BLOCKED, quoted mention $QUOTED"
fi

# THE COMMIT GATE IS UNCHANGED BY THE GATE IN FRONT OF IT. OPS-021 asserts it on
# a clean fixture; this asserts it in the one state where both could fire, and
# asserts that the two refusals are DIFFERENT — a new gate that swallowed the
# old one would pass every assertion either makes on its own.
if [ "$BLOCKED" -eq 2 ] && [ "$COMMITTING" -eq 2 ] \
   && grep -q 'Sign it under THIS' "$WORK/err.commit" \
   && ! grep -q 'Sign it under THIS' "$WORK/err.blocked"; then
  ok "OPS-095 and a plain commit still meets the gate that was always there, not this one"
else
  bad "OPS-095 blocked $BLOCKED, commit $COMMITTING, $(head -n 1 "$WORK/err.commit")"
fi

# AND IT CAN BE TURNED OFF, in one variable, without touching the file. A gate
# in front of git on somebody's machine that cannot be switched off is a gate
# that gets deleted instead.
if [ "$BLOCKED" -eq 2 ] && [ "$SWITCHED_OFF" -eq 0 ]; then
  ok "OPS-095 and INNSEGL_GIT_GUARD=0 stops the shim consulting it at all"
else
  bad "OPS-095 blocked $BLOCKED, switched off $SWITCHED_OFF"
fi

# AND A MISSING GUARD ALLOWS. This file is wired into a harness; a shim that
# blocked every git command because a sibling script was not installed would be
# worse than the loss it exists to prevent.
if [ "$BLOCKED" -eq 2 ] && [ "$NO_GUARD" -eq 0 ]; then
  ok "OPS-095 and a guard that is not installed fails open"
else
  bad "OPS-095 blocked $BLOCKED, missing guard $NO_GUARD"
fi

creset
rm -f "$RUNS"/agent-* 2>/dev/null

# --- OPS-073: single-listener mode, unchanged --------------------------------
#
# ASSERTED FIRST, over everything above it, because "nothing changed" is only
# worth anything as a statement about the whole suite. Fourteen cases have just
# run against a listener demanding nothing: not one request may have carried a
# credential, and nothing may have been minted, or the claim that a deployment
# without #264 behaves exactly as before is untested.
if [ -s "$AUTHLOG" ] && ! grep -qv '^-$' "$AUTHLOG"; then
  ok "OPS-073: with nothing to authenticate, no request carries a credential"
else
  bad "OPS-073: a credential was presented to a listener that asked for none: $(grep -v '^-$' "$AUTHLOG" | head -n 2)"
fi
if [ ! -f "$WORK/mint.count" ]; then
  ok "OPS-073: and nothing was minted — the mint is driven by a refusal, not a mode"
else
  bad "OPS-073: the shim minted $(cat "$WORK/mint.count") credential(s) unprompted"
fi

# --- OPS-069..072: the listener's credential (#266) ---------------------------
#
# #264 put a repository-scoped credential in front of all six identity-lifecycle
# tools, which is every tool this shim calls. Measured before #266: this file
# contained no Authorization header at all, so deploying #264 answered every
# registration on the machine with 401 — no identity, and therefore no signed
# commit either.
#
# THE MINT IS A COMMAND, and here it is a script rather than a container: what
# is under test is when the shim mints, what it does with what it gets and
# where the value ends up, none of which is a property of Docker. The shipped
# default reaches the deployment's own signing key; this stands in for it, and
# the stub demands exactly what it issued.
cat > "$WORK/mint" <<'SH'
#!/bin/sh
# Issues cred-1, cred-2, ... and tells the stub to demand the newest one. $2 is
# how many requests it stays good for, which is how an expiry is reproduced
# without waiting fifteen minutes for a real credential to age out.
n=$(( $(cat "$MINT_STATE/mint.count" 2>/dev/null || echo 0) + 1 ))
printf '%s' "$n" > "$MINT_STATE/mint.count"
printf '%s\n' "$1" >> "$MINT_STATE/mint.scopes"
printf 'cred-%s %s\n' "$n" "${MINT_USES:-100}" > "$MINT_STATE/required"
printf 'cred-%s\n' "$n"
SH
chmod +x "$WORK/mint"
export MINT_STATE="$WORK"
MINT="$WORK/mint"

# A listener that now demands something nobody holds. `spent 0` is a token no
# caller was ever given AND a budget already exhausted, so the first request of
# the next event is refused however it is answered.
printf 'spent 0\n' > "$CREDFILE"
: > "$AUTHLOG"

# 15. OPS-069 — the shim presents one, and the call goes through.
script_tool observe_session ok '{"session_id":"agent-cred","phase":"start","known":true,"registered":true,"run_id":"run-dddd4444","task":"e10","worktree":"","repo":"example.test/org/name","branch":"dev/e10","agent_type":"prober"}'
drive "{\"hook_event_name\":\"SubagentStart\",\"session_id\":\"sess-1\",\"agent_id\":\"agent-cred\",\"agent_type\":\"prober\",\"cwd\":\"$CWD\"}"
if [ "$STATUS" -eq 0 ] && called observe_session '"session_id": "agent-cred"'; then
  ok "OPS-069: a refused registration is minted for and repeated, not failed"
else
  bad "OPS-069: SubagentStart exited $STATUS behind a credential: $(cat "$WORK/err")"
fi
if grep -q '^Bearer cred-1$' "$AUTHLOG"; then
  ok "OPS-069: the credential is presented as a Bearer token on the listener"
else
  bad "OPS-069: nothing was presented: $(sort -u "$AUTHLOG" | head -n 3)"
fi
if [ "$(head -n 1 "$AUTHLOG")" = "-" ] && [ "$(cat "$WORK/mint.count")" = "1" ]; then
  ok "OPS-069: minted once, and only after the listener asked — never speculatively"
else
  bad "OPS-069: minted $(cat "$WORK/mint.count" 2>/dev/null) times, first request was $(head -n 1 "$AUTHLOG")"
fi
# AND IT IS SCOPED TO THE REPOSITORY THIS EVENT IS ABOUT. A credential for
# another repository is refused by the listener with the same silent 401, so a
# wrong scope here looks exactly like no credential at all.
WANT_REPO="$(cd "$ROOT" && git remote get-url origin 2>/dev/null \
  | sed -e 's|^[a-z][a-z0-9+.-]*://||' -e 's|^git@||' -e 's|:|/|' -e 's|\.git$||' -e 's|/*$||' \
  | awk -F/ 'NF>=3 { h = tolower($1); p = $2; for (i = 3; i <= NF; i++) p = p "/" $i; print h "/" p }')"
if [ -n "$WANT_REPO" ] && [ "$(tail -n 1 "$WORK/mint.scopes")" = "$WANT_REPO" ]; then
  ok "OPS-069: the credential names the repository the event happened in"
else
  bad "OPS-069: minted for '$(tail -n 1 "$WORK/mint.scopes")', want '$WANT_REPO'"
fi

# 16. OPS-071 — the value reaches no marker, no log line and no argument vector.
#
# The credential lives fifteen minutes and cannot be withdrawn, because a
# revocation list would be a dependency on the issuer being reachable. So a copy
# left in a file is a copy anyone on this machine can replay until it ages out.
LEAKED="$(grep -rl 'cred-1' "$RUNS" "$LOG" "$WORK/err" "$WORK/out" 2>/dev/null | grep -v '^'"$WORK/required"'$')"
if [ -z "$LEAKED" ]; then
  ok "OPS-071: the credential is in no marker, no body log and no line the shim printed"
else
  bad "OPS-071: the credential was written to: $LEAKED"
fi
if ! grep -qE '^[^#]*export[[:space:]]+ADMIN_CRED' "$SHIM"; then
  ok "OPS-071: it is never exported, so no child of this hook inherits it"
else
  bad "OPS-071: the shim exports the credential to every child it runs"
fi
# ON STDIN, NOT IN argv. `ps` publishes the argument vector of every process on
# this machine; a bearer token there is replayable by anything logged in.
if grep -Fq '"$ADMIN_CRED" | python3 -c "$MCP_CLIENT"' "$SHIM" \
   && ! grep -qE '^[^#]*(-H|--header).*Authorization' "$SHIM"; then
  ok "OPS-071: it reaches the client on stdin, never on a command line"
else
  bad "OPS-071: the credential is passed on a command line: $(grep -nE '^[^#]*Authorization' "$SHIM" | head -n 2)"
fi

# 17. OPS-072 — a stop that cannot authenticate warns and exits 0.
#
# Measured before the no-blocking rule existed: a refused stop produced NINE
# repeated invocations. A credential that cannot be minted must not become the
# tenth reason for one — the run expires on its TTL, which is what the reaper
# is for (IP §6.7).
printf 'spent 0\n' > "$CREDFILE"
MINT="$WORK/no-mint"        # a mint command that is not there at all
drive '{"hook_event_name":"SubagentStop","session_id":"sess-1","agent_id":"agent-cred","agent_type":"prober"}'
if [ "$STATUS" -eq 0 ]; then
  ok "OPS-072: a stop that cannot authenticate exits 0 (no retry storm)"
else
  bad "OPS-072: SubagentStop exited $STATUS with no credential; a stop must never block"
fi
STATUS=99
printf 'spent 0\n' > "$CREDFILE"
drive '{"hook_event_name":"SessionEnd","session_id":"sess-1"}'
if [ "$STATUS" -eq 0 ]; then
  ok "OPS-072: and so does SessionEnd"
else
  bad "OPS-072: SessionEnd exited $STATUS with no credential"
fi
# AND THE REFUSAL SAYS WHAT TO DO. The listener answers every credential
# failure with one byte-identical sentence by design, so this is the only place
# an operator is ever told which command mints and against which key.
MINT="$WORK/no-mint"
printf 'spent 0\n' > "$CREDFILE"
drive "{\"hook_event_name\":\"SubagentStart\",\"session_id\":\"sess-1\",\"agent_id\":\"agent-told\",\"agent_type\":\"prober\",\"cwd\":\"$CWD\"}"
if grep -q 'admin-credential mint' "$WORK/err" && grep -q 'signing.key' "$WORK/err"; then
  ok "OPS-072: a refusal names the command that mints and the key it mints against"
else
  bad "OPS-072: the refusal offers no remedy: $(cat "$WORK/err")"
fi

# --- OPS-096..100: a kill is a certain event, and silence is not --------------
#
# RM-182 (#290). A killed subagent fires NO `SubagentStop`. Its marker survives,
# its work survives, and the ledger goes on reporting the run active for the
# whole of the reaper's grace — measured, five runs active for between three and
# nine hours after the processes were gone.
#
# THE TWO CASES ARE NOT THE SAME EVENT, and the system treated them as one:
#
#   A KILL IS CERTAIN. Something asked for the agent to stop and was told it
#   had. The run must leave the active list at that moment.
#
#   SILENCE IS AMBIGUOUS. A quiet agent may still be working. The reaper's grace
#   answers that one and is not touched here; nothing below reads a clock, and
#   no case introduces a threshold.
#
# THE KILL IS ALREADY OBSERVABLE AND NOTHING LOOKED. `PostToolUse` fires in the
# parent session for every tool call including the one that does the killing,
# and it carries the tool's INPUT and its RESULT. The `task_id` a kill is
# addressed to is the same id the subagent's marker is named with.
#
# EVERY NEGATIVE CASE CARRIES ITS OWN POSITIVE CONTROL, in the same case, driven
# through the same path with exactly one field changed. A case that asserted
# only "nothing happened" would pass against a shim that does nothing at all,
# which is the shim these cases were written against — it would prove the
# discriminator works by proving the feature is absent.

# THE LISTENER DEMANDS NOTHING AGAIN. The credential cases above leave the stub
# refusing every request with no mint configured, and a fixture built against
# that registers no run and writes no marker — so every case below would fail
# for a reason that has nothing to do with a kill.
: > "$CREDFILE"
MINT=""

KSESS="sess-kill"
KOTHER="sess-other"
KTREE="$(printf '%s' "$CREPO_REAL" | shasum -a 256 | cut -c1-32)"

# honoured <task-id> — the harness's own answer to a kill it carried out, in the
# shape measured from a real drill: it echoes the task, names what KIND of task
# it was, and says it stopped it.
honoured() {
  printf '{"message":"Successfully stopped task: %s (a prober)","task_id":"%s","task_type":"local_agent","command":"a prober"}' "$1" "$1"
}

# kill_run <agent-id> <run-id> [owning session] — a registered subagent left
# exactly as SubagentStart leaves it: a marker, a by-tree pointer, a body store.
kill_run() {
  script_tool observe_session ok "{\"session_id\":\"$1\",\"phase\":\"start\",\"known\":true,\"registered\":true,\"run_id\":\"$2\",\"task\":\"rm182\",\"worktree\":\"\",\"repo\":\"example.test/org/name\",\"branch\":\"dev/rm182\",\"agent_type\":\"prober\"}"
  drive "{\"hook_event_name\":\"SubagentStart\",\"session_id\":\"${3:-$KSESS}\",\"agent_id\":\"$1\",\"agent_type\":\"prober\",\"cwd\":\"$CREPO\"}"
  rm -rf "${LOG:?}/$2"; mkdir -p "$LOG/$2"
}

# kill_event <calling session> <task-id> <tool_response json> — the parent
# session's PostToolUse for a TaskStop, which is the only event that sees a kill.
kill_event() {
  script_tool observe_session ok "{\"session_id\":\"$2\",\"phase\":\"stop\",\"known\":true,\"retired\":true,\"run_id\":\"retired-$2\"}"
  drive "{\"hook_event_name\":\"PostToolUse\",\"session_id\":\"$1\",\"cwd\":\"$CREPO\",\"tool_name\":\"TaskStop\",\"tool_input\":{\"task_id\":\"$2\"},\"tool_response\":$3}"
}

# retired_by_kill <task-id> — did that drive retire exactly that run?
retired_by_kill() { called observe_session '"phase": "stop"' "\"session_id\": \"$1\""; }
# stopped_anything — did it retire ANYTHING at all?
stopped_anything() { grep -q '^observe_session ' "$CALLS"; }

# --- OPS-096: the kill retires the run there and then -------------------------
creset
uncap_reset
kill_run agent-kill1 run-kill1
kill_event "$KSESS" agent-kill1 "$(honoured agent-kill1)"
# ONE ASSERTION, THREE CLAIMS. The kill is still recorded as the tool call it is
# — a retirement that swallowed the call would lose the parent's own activity —
# it retires the killed run under the id the marker is named with, and it ends
# what that run had below it, which a kill does as surely as a stop does.
if [ "$STATUS" -eq 0 ] \
  && called observe_tool_call '"tool": "TaskStop"' \
  && retired_by_kill agent-kill1 \
  && called observe_session '"ends_descendants": true'; then
  ok "OPS-096 a kill is recorded as a tool call AND retires the killed run at that moment"
else
  bad "OPS-096 the kill retired nothing (exit $STATUS): $(grep '^observe_session ' "$CALLS" | head -n 1)"
fi

# AND IT LEAVES NOTHING BEHIND THAT WOULD RETIRE IT A SECOND TIME. The marker is
# the local half of the double-retire guard (#179): SubagentStop already exits
# on an absent one, so removing it here reuses that guard rather than adding a
# second spelling of it. The by-tree pointer goes with it for the reason
# SessionEnd removes the session's — the run it names is retired, and a signer
# that resolved it would register against a retired parent.
if [ ! -f "$RUNS/agent-kill1" ] && [ ! -f "$RUNS/by-tree/$KTREE" ]; then
  ok "OPS-096 and the killed run's marker and by-tree pointer are gone with it"
else
  bad "OPS-096 the kill left its marker or pointer behind: $(ls "$RUNS/agent-kill1" "$RUNS/by-tree/$KTREE" 2>&1 | tr '\n' ' ')"
fi

# --- OPS-097: the RESULT is read, not just the input ---------------------------
#
# A `TaskStop` against a task that was already finished, or that does not exist,
# must retire nothing. Measured on the live harness: both of those fire no
# PostToolUse at all today — but that is the harness's behaviour and not this
# shim's rule, and a shim that retired on the INPUT would be one harness change
# away from retiring a run that is still working.
creset
kill_run agent-kill2 run-kill2
kill_event "$KSESS" agent-kill2 '{"error":"No task found with ID: agent-kill2"}'
retired_by_kill agent-kill2 && K_ERR=1 || K_ERR=0
kill_event "$KSESS" agent-kill2 "$(honoured agent-kill2)"
retired_by_kill agent-kill2 && K_OK=1 || K_OK=0
if [ "$STATUS" -eq 0 ] && [ "$K_ERR" = 0 ] && [ "$K_OK" = 1 ]; then
  ok "OPS-097 a TaskStop the harness refused retires nothing; the same call honoured retires the run"
else
  bad "OPS-097 the result decided nothing: refused=$K_ERR honoured=$K_OK"
fi

# AND A RESULT THAT NAMES A DIFFERENT TASK IS NOT THIS TASK'S KILL. The harness
# echoes the task it actually stopped; a reply that names another one is either
# a different kill or not a kill at all, and either way this marker's run is
# still working.
creset
kill_run agent-kill3 run-kill3
kill_event "$KSESS" agent-kill3 '{"message":"Successfully stopped task: agent-elsewhere (x)","task_id":"agent-elsewhere","task_type":"local_agent","command":"x"}'
stopped_anything && K_OTHER=1 || K_OTHER=0
kill_event "$KSESS" agent-kill3 "$(honoured agent-kill3)"
retired_by_kill agent-kill3 && K_OK=1 || K_OK=0
if [ "$STATUS" -eq 0 ] && [ "$K_OTHER" = 0 ] && [ "$K_OK" = 1 ]; then
  ok "OPS-097 and a result naming a different task retires nothing, here or anywhere"
else
  bad "OPS-097 a result naming another task retired something: elsewhere=$K_OTHER honoured=$K_OK"
fi

# --- OPS-098: a task that is not an agent run ---------------------------------
#
# Monitors and background shells are stopped through the same tool. The harness
# says which kind it stopped, and a shell is not a run.
creset
kill_run agent-kill4 run-kill4
kill_event "$KSESS" agent-kill4 '{"message":"Successfully stopped task: agent-kill4 (echo hi)","task_id":"agent-kill4","task_type":"local_bash","command":"echo hi"}'
retired_by_kill agent-kill4 && K_SHELL=1 || K_SHELL=0
kill_event "$KSESS" agent-kill4 "$(honoured agent-kill4)"
retired_by_kill agent-kill4 && K_OK=1 || K_OK=0
if [ "$STATUS" -eq 0 ] && [ "$K_SHELL" = 0 ] && [ "$K_OK" = 1 ]; then
  ok "OPS-098 a stopped background shell retires nothing; the same id as an agent retires the run"
else
  bad "OPS-098 a shell was treated as a run: shell=$K_SHELL agent=$K_OK"
fi

# AND A TASK WITH NO MARKER RETIRES NOTHING, SILENTLY. Most stopped tasks are
# not agents at all, so this is the common path and it must not talk: a warning
# per background shell would be noise the operator learns to ignore, on the one
# surface that also carries a refusal worth reading.
creset
kill_event "$KSESS" bnosuchtask0 "$(honoured bnosuchtask0)"
stopped_anything && K_NOMARK=1 || K_NOMARK=0
[ -s "$WORK/err" ] && K_LOUD=1 || K_LOUD=0
kill_run agent-kill5 run-kill5
kill_event "$KSESS" agent-kill5 "$(honoured agent-kill5)"
retired_by_kill agent-kill5 && K_OK=1 || K_OK=0
if [ "$STATUS" -eq 0 ] && [ "$K_NOMARK" = 0 ] && [ "$K_LOUD" = 0 ] && [ "$K_OK" = 1 ]; then
  ok "OPS-098 and a task_id with no marker retires nothing and says nothing"
else
  bad "OPS-098 an unmarked task was not silent: retired=$K_NOMARK noisy=$K_LOUD control=$K_OK"
fi

# --- OPS-099: never a run this session does not own ----------------------------
#
# The markers directory is one directory for every session on the machine, and
# other repositories' sessions have live runs in it with real processes behind
# them. The marker records the harness session that started the run; anything
# else is somebody else's agent.
creset
kill_run agent-kill6 run-kill6 "$KOTHER"
kill_event "$KSESS" agent-kill6 "$(honoured agent-kill6)"
retired_by_kill agent-kill6 && K_THEIRS=1 || K_THEIRS=0
kill_event "$KOTHER" agent-kill6 "$(honoured agent-kill6)"
retired_by_kill agent-kill6 && K_OWN=1 || K_OWN=0
if [ "$STATUS" -eq 0 ] && [ "$K_THEIRS" = 0 ] && [ "$K_OWN" = 1 ]; then
  ok "OPS-099 another session's run is never retired; its own session retires it"
else
  bad "OPS-099 ownership decided nothing: other=$K_THEIRS owner=$K_OWN"
fi

# AND A MARKER THAT RECORDS NO OWNER IS NOT THIS SESSION'S. Every marker written
# before this change has none, and "not recorded" is not "mine": the safe
# direction is the silent one, because the run may still be working.
creset
kill_run agent-kill7 run-kill7
python3 -c '
import json, sys
p = sys.argv[1]
d = json.load(open(p))
d.pop("owner_session", None)
open(p, "w").write(json.dumps(d))
' "$RUNS/agent-kill7"
kill_event "$KSESS" agent-kill7 "$(honoured agent-kill7)"
retired_by_kill agent-kill7 && K_ANON=1 || K_ANON=0
kill_run agent-kill8 run-kill8
kill_event "$KSESS" agent-kill8 "$(honoured agent-kill8)"
retired_by_kill agent-kill8 && K_OK=1 || K_OK=0
if [ "$STATUS" -eq 0 ] && [ "$K_ANON" = 0 ] && [ "$K_OK" = 1 ]; then
  ok "OPS-099 and a marker that records no owner is left alone"
else
  bad "OPS-099 an unowned marker was retired: anonymous=$K_ANON control=$K_OK"
fi

# AND A task_id IS A MARKER NAME, NEVER A PATH. It is model-supplied text that
# this shim would otherwise paste into a filename, so `../` reaches outside the
# markers directory and a `session-` prefix names the OPERATOR'S OWN session
# marker — the one run on this machine that must never be retired by anything
# but its own SessionEnd. The escape target is planted with a well-formed,
# correctly-owned marker so that only the shape rule can refuse it.
creset
mkdir -p "$RUNS"
# PLANTED AS VALID AS IT CAN BE MADE: the right owner, and a session_id that
# agrees with the name the kill would reach it by. Every other guard admits it,
# so only the shape rule can refuse it and this case tests that rule alone.
python3 -c '
import json, sys
json.dump({"run_id": "run-escaped", "owner_session": sys.argv[2], "dir": sys.argv[3],
           "session_id": "../agent-escaped", "task": "rm182", "worktree": "",
           "agent_type": "prober"}, open(sys.argv[1], "w"))
' "$WORK/agent-escaped" "$KSESS" "$CREPO"
kill_event "$KSESS" "../agent-escaped" "$(honoured ../agent-escaped)"
stopped_anything && K_ESC=1 || K_ESC=0
# The session's own marker, planted rather than driven: a SessionStart here
# would link this throwaway fixture into whatever deployment is up.
# A REAL SESSION MARKER, in the shape SessionStart writes: its session_id is
# the session, while the file it lives in carries the `session-` prefix. Both
# the shape rule and the name rule refuse it, which is the point — the
# operator's own run is the one thing on this machine a kill must never reach.
python3 -c '
import json, sys
json.dump({"run_id": "run-the-operators-own-session", "owner_session": sys.argv[2],
           "dir": sys.argv[3], "session_id": sys.argv[2], "task": "rm182",
           "worktree": "", "agent_type": "session"}, open(sys.argv[1], "w"))
' "$RUNS/session-$KSESS" "$KSESS" "$CREPO"
kill_event "$KSESS" "session-$KSESS" "$(honoured "session-$KSESS")"
stopped_anything && K_SESS=1 || K_SESS=0
kill_run agent-kill9 run-kill9
kill_event "$KSESS" agent-kill9 "$(honoured agent-kill9)"
retired_by_kill agent-kill9 && K_OK=1 || K_OK=0
if [ "$STATUS" -eq 0 ] && [ "$K_ESC" = 0 ] && [ "$K_SESS" = 0 ] && [ "$K_OK" = 1 ]; then
  ok "OPS-099 and a task_id that names a path or a session marker reaches neither"
else
  bad "OPS-099 a task_id escaped the markers directory: traversal=$K_ESC session=$K_SESS control=$K_OK"
fi

# --- OPS-100: a second retirement, and the work the killed run left ------------
#
# `SubagentStop` may still arrive on some paths, and a double retire is #179.
# The guard is not new: the marker is gone, so the stop takes the absent-marker
# exit it has always had, and the lifecycle tool answers a repeated stop from
# the instant of the first.
creset
uncap_reset
kill_run agent-kill10 run-kill10
kill_event "$KSESS" agent-kill10 "$(honoured agent-kill10)"
retired_by_kill agent-kill10 && K_FIRST=1 || K_FIRST=0
kill_event "$KSESS" agent-kill10 "$(honoured agent-kill10)"
stopped_anything && K_SECOND=1 || K_SECOND=0
K_SECOND_RC="$STATUS"
drive "{\"hook_event_name\":\"SubagentStop\",\"session_id\":\"$KSESS\",\"agent_id\":\"agent-kill10\",\"agent_type\":\"prober\"}"
stopped_anything && K_STOP=1 || K_STOP=0
if [ "$K_FIRST" = 1 ] && [ "$K_SECOND" = 0 ] && [ "$K_SECOND_RC" -eq 0 ] \
  && [ "$K_STOP" = 0 ] && [ "$STATUS" -eq 0 ]; then
  ok "OPS-100 a retired kill is retired once: a repeat and a late SubagentStop both retire nothing and exit 0"
else
  bad "OPS-100 the run was retired twice: first=$K_FIRST repeat=$K_SECOND($K_SECOND_RC) stop=$K_STOP($STATUS)"
fi

# AND THE WORK IT LEFT IS WRITTEN DOWN WHERE IT OUTLIVES THE PROCESS — #277.
# The kill path does NOT capture and does not sign: it is the PARENT's tool call,
# mid-flight, and committing another run's tree from there is the #261 incident
# with a new trigger. What it does is leave the record, so the orphaned work is
# findable without anyone tripping over it (#288).
creset
uncap_reset
kill_run agent-kill11 run-kill11
wrote_body run-kill11 a Write "{\"file_path\":\"$CREPO/killed.txt\"}"
printf 'killed\n' > "$CREPO/killed.txt"
kill_event "$KSESS" agent-kill11 "$(honoured agent-kill11)"
if [ "$(uncap_lines)" = "1" ] \
  && [ "$(uncap_field reason)" = "run_killed" ] \
  && [ "$(uncap_field run_id)" = "run-kill11" ] \
  && [ "$(uncap_field dirty)" = "1" ] \
  && [ "$(uncap_field wrote)" = "1" ] \
  && [ "$(uncap_field task)" = "rm182" ]; then
  ok "OPS-100 and a killed run that left work records it as run_killed, naming the run and what it wrote"
else
  bad "OPS-100 the killed run's work was not recorded: $(uncap_lines) line(s), reason=$(uncap_field reason) run=$(uncap_field run_id) dirty=$(uncap_field dirty) wrote=$(uncap_field wrote)"
fi

# AND A KILLED RUN THAT LEFT NOTHING WRITES NOTHING. `run_retired` is already on
# the chain for it; a second source of truth for one fact is what the capture
# record deliberately does not become. What had no record was the WORK.
creset
uncap_reset
kill_run agent-kill12 run-kill12
kill_event "$KSESS" agent-kill12 "$(honoured agent-kill12)"
retired_by_kill agent-kill12 && K_OK=1 || K_OK=0
if [ "$K_OK" = 1 ] && [ "$(uncap_lines)" = "0" ]; then
  ok "OPS-100 and a killed run with a clean tree is retired and writes no record"
else
  bad "OPS-100 a clean kill wrote $(uncap_lines) record(s), retired=$K_OK"
fi

# --- OPS-101: the record carries a CLAIM, and a claim is on work -------------
#
# RM-183 (#291). The guard in scripts/hooks/git-tree-guard.sh decides whose work
# to protect by asking the ledger who is LIVE, and #290 made a killed run stop
# being live at the moment of the kill. Measured on one tree, one piece of work
# and one run: `git clean -fd` refused before the retirement and was allowed
# after it. The protection that vanished was a side effect of the run being
# WRONGLY reported active, and the work most at risk is exactly this work --
# a live run's uncommitted work has somebody coming back for it and a killed
# run's does not.
#
# So the record is what carries the claim past the retirement, and to do that it
# has to name two things it did not name before:
#
#   WHICH PATHS the kill actually left uncommitted -- `wrote_paths` is every
#   path the run ever wrote in that tree, including the ones it committed
#   itself, and a claim over those is a claim over work that is already safe.
#
#   WHAT WAS IN THEM. A claim keyed on a FILENAME cannot be released. This file
#   is append-only and never rotated, so a claim that came back every time
#   somebody re-edited a path some long-dead run once wrote would wedge the tree
#   by accumulation -- which is the failure liveness was chosen to avoid (#260),
#   arrived at from the other direction.
#
# `claim_top` is the repository the paths are relative to, because the guard
# must not weigh a claim against a tree that merely resembles it.
creset
uncap_reset
kill_run agent-kill13 run-kill13
wrote_body run-kill13 a Write "{\"file_path\":\"$CREPO/left.txt\"}"
wrote_body run-kill13 b Write "{\"file_path\":\"$CREPO/kept.txt\"}"
printf 'left behind\n' > "$CREPO/left.txt"
printf 'already safe\n' > "$CREPO/kept.txt"
git -C "$CREPO" add kept.txt
git -C "$CREPO" commit -q -m "the run signed this one itself"
K_SHA="$(python3 -c '
import hashlib, sys
print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$CREPO/left.txt")"
kill_event "$KSESS" agent-kill13 "$(honoured agent-kill13)"
K_CLAIM="$(uncap_field claim)"
git -C "$CREPO" reset -q --hard HEAD~1
rm -f "$CREPO/left.txt"
K_REC=0
[ "$(uncap_field reason)" = "run_killed" ] || K_REC=1
[ "$(uncap_field wrote)" = "2" ] || K_REC=1
[ "$(uncap_field claim_n)" = "1" ] || K_REC=1
[ "$(uncap_field claim_top)" = "$CREPO_REAL" ] || K_REC=1
printf '%s' "$K_CLAIM" | grep -q '"path": "left.txt"' || K_REC=1
printf '%s' "$K_CLAIM" | grep -q "\"sha\": \"$K_SHA\"" || K_REC=1
printf '%s' "$K_CLAIM" | grep -q '"size": 12' || K_REC=1
printf '%s' "$K_CLAIM" | grep -q 'kept.txt' && K_REC=1
if [ "$K_REC" = 0 ]; then
  ok "OPS-101 a kill records what it left uncommitted, with the content, and not what the run had already committed"
else
  bad "OPS-101 the claim is wrong: wrote=$(uncap_field wrote) claim_n=$(uncap_field claim_n) top=$(uncap_field claim_top) claim=$K_CLAIM"
fi

# AND A KILL THAT LEFT NOTHING UNCOMMITTED CLAIMS NOTHING, which is the same
# rule one level in: the record is written because the run wrote files in that
# tree, and the claim is empty because none of them are still at risk. Driven
# against the same fixture as the case above with one thing changed -- the file
# is committed rather than left.
creset
uncap_reset
kill_run agent-kill14 run-kill14
wrote_body run-kill14 a Write "{\"file_path\":\"$CREPO/safe.txt\"}"
printf 'safe\n' > "$CREPO/safe.txt"
git -C "$CREPO" add safe.txt
git -C "$CREPO" commit -q -m "committed before the kill"
printf 'somebody else\n' > "$CREPO/theirs.txt"
kill_event "$KSESS" agent-kill14 "$(honoured agent-kill14)"
K_EMPTY="$(uncap_field claim)"
K_EMPTY_N="$(uncap_field claim_n)"
git -C "$CREPO" reset -q --hard HEAD~1
rm -f "$CREPO/safe.txt" "$CREPO/theirs.txt"
if [ "$(uncap_lines)" = "1" ] && [ "$K_EMPTY_N" = "0" ] && [ "$K_EMPTY" = "[]" ]; then
  ok "OPS-101 and a kill whose written paths are all committed records the kill and claims none of them"
else
  bad "OPS-101 an empty claim was not empty: lines=$(uncap_lines) claim_n=$K_EMPTY_N claim=$K_EMPTY"
fi

# --- OPS-109: SessionStart hands its event to the orphan sweep (#288) ---------
#
# scripts/hooks/orphan-sweep.sh is the half of #288 that needs no observer, and
# its own header names SessionStart as the caller. A sweep nobody calls is the
# passivity #288 is about, so the call is asserted here, where the event is.
#
# $INNSEGL_ORPHAN_SWEEP_SCRIPT is pinned at a recorder for every drive in this
# file, so no case above ever swept anything. The recorder keeps its argv and
# its stdin; the sweep's own behaviour is OPS-106..108's job, not this one's.
#
# The deployment is DOWN for the positive case. A crash that took the session
# with it is exactly when the next session may find nothing answering, and a
# sweep placed after observe_session's early exit would never run then.
cat > "$WORK/sweep-stub" <<STUB
#!/bin/sh
{ printf 'argv=%s\n' "\$*"; cat; printf '\n'; } >> "$WORK/sweeps"
exit 0
STUB
chmod +x "$WORK/sweep-stub"
rm -f "$WORK/sweeps"
ADMIN_SAVED="$ADMIN"
ADMIN="http://127.0.0.1:1/"
drive "{\"hook_event_name\":\"SessionStart\",\"session_id\":\"sess-sweep\",\"cwd\":\"$CWD\"}"
ADMIN="$ADMIN_SAVED"
if [ "$STATUS" = "0" ] && grep -q '^argv=hook$' "$WORK/sweeps" 2>/dev/null \
   && grep -q "\"cwd\":\"$CWD\"" "$WORK/sweeps" 2>/dev/null; then
  ok "OPS-109 SessionStart runs the orphan sweep with its own event, even with the deployment down"
else
  bad "OPS-109 SessionStart did not hand its event to the sweep: status $STATUS, sweeps: $(cat "$WORK/sweeps" 2>/dev/null)"
fi

# The control: the sweep belongs to the session coming back to the tree, not to
# a subagent starting inside it, and a stop is the dying party's own event.
rm -f "$WORK/sweeps"
drive "{\"hook_event_name\":\"SubagentStart\",\"session_id\":\"sess-sweep\",\"agent_id\":\"agent-sweep\",\"agent_type\":\"general-purpose\",\"cwd\":\"$CWD\"}"
drive "{\"hook_event_name\":\"SubagentStop\",\"session_id\":\"sess-sweep\",\"agent_id\":\"agent-sweep\",\"cwd\":\"$CWD\"}"
if [ ! -s "$WORK/sweeps" ]; then
  ok "OPS-109 and neither SubagentStart nor SubagentStop runs it"
else
  bad "OPS-109 a subagent event ran the sweep: $(cat "$WORK/sweeps")"
fi

# And a sweep that fails or cannot be found never fails the session.
ORPHAN_SWEEP_SCRIPT="$WORK/no-such-sweep"
drive "{\"hook_event_name\":\"SessionStart\",\"session_id\":\"sess-sweep2\",\"cwd\":\"$CWD\"}"
unset ORPHAN_SWEEP_SCRIPT
if [ "$STATUS" = "0" ]; then
  ok "OPS-109 and a missing sweep leaves SessionStart exiting 0"
else
  bad "OPS-109 a missing sweep failed SessionStart: status $STATUS"
fi

echo
echo "shim-selftest: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
