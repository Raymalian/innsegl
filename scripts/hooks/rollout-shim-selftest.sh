#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# OPS-022 — the SECOND harness's shim, driven directly.
#
# RM-130 (#209) is the issue that proves E11. Three tools were added and the
# reference shim was rewritten onto them, and none of that demonstrates
# anything on its own: a surface only one harness can drive has solved nothing.
# What settles it is a shim for a harness that shares no mechanism with the
# first — no hook system, no way to be called mid-session at all — reaching the
# same three tools and producing a run that reads in the ledger exactly like a
# reference-harness run.
#
# THE SECOND HARNESS IS DRIVEN FROM ITS TRANSCRIPT, NOT FROM HOOKS. Codex CLI
# writes one JSONL rollout per session and offers no callback this shim can
# use, so the shim reads that file after the fact. That is the more valuable
# proof rather than a weaker one: post-hoc ingestion is what a harness with no
# cooperation whatever must do, and it exercises the three tools without the
# harness knowing innsegl exists. ADR-0048.
#
# WHAT IS ASSERTED is not "the script ran" but WHICH TOOL IT CALLED AND WITH
# WHAT, and — the half that carries the weight — which tools it never calls.
# A shim that reached register_agent, derived a branch, or digested a body
# locally would pass every positive assertion here while leaving the work E11
# exists to move exactly where it was. Cases 5, 6 and 7 are what fail then.
#
# THE TRANSCRIPT FIXTURE IS SYNTHETIC AND THE SCHEMA IS NOT. The record shapes
# below were read off real rollout files — record types, payload types and the
# member names of each — and the values are invented. No transcript belonging to
# anyone is read by this test, and none is checked in.
#
# USAGE
#   scripts/hooks/rollout-shim-selftest.sh
#
# It needs python3. It needs no Docker, no MCP, no SPIRE, no second harness and
# no network beyond loopback.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SHIM="$ROOT/scripts/hooks/rollout-ingest.py"
STUB="$ROOT/scripts/hooks/stub-mcp.py"

pass=0
fail=0
ok()  { pass=$((pass + 1)); echo "  ok    $1"; }
bad() { fail=$((fail + 1)); echo "  FAIL  $1" >&2; }

command -v python3 >/dev/null 2>&1 || { echo "rollout-shim-selftest: python3 is required" >&2; exit 4; }
[ -f "$STUB" ] || { echo "rollout-shim-selftest: $STUB is missing" >&2; exit 4; }
if [ ! -f "$SHIM" ]; then
  echo "rollout-shim-selftest: $SHIM does not exist — the second shim is unwritten" >&2
  exit 1
fi

WORK="$(mktemp -d)"
trap 'if [ -n "${STUB_PID:-}" ]; then kill "$STUB_PID" 2>/dev/null; wait "$STUB_PID" 2>/dev/null; fi; rm -rf "$WORK"' EXIT

CALLS="$WORK/calls"          # one line per tools/call: <tool> <arguments json>
SCRIPTED="$WORK/scripted"    # <tool> <ok|err> <json>, the stub's answer
: > "$CALLS"
: > "$SCRIPTED"

STUB_CALLS="$CALLS" STUB_SCRIPTED="$SCRIPTED" python3 "$STUB" > "$WORK/port" 2>"$WORK/stub.err" &
STUB_PID=$!
for _ in $(seq 1 100); do
  PORT="$(head -n 1 "$WORK/port" 2>/dev/null)"
  [ -n "$PORT" ] && break
  sleep 0.1
done
[ -n "${PORT:-}" ] || { echo "rollout-shim-selftest: the stub never reported a port" >&2; cat "$WORK/stub.err" >&2; exit 4; }
ADMIN="http://127.0.0.1:$PORT/"

# script_tool fixes what the stub answers for one tool.
script_tool() {
  grep -v "^$1 " "$SCRIPTED" > "$SCRIPTED.new" 2>/dev/null || :
  mv "$SCRIPTED.new" "$SCRIPTED"
  printf '%s %s %s\n' "$1" "$2" "$3" >> "$SCRIPTED"
}

# drive runs the shim over one transcript and leaves its exit status in
# $STATUS, its stderr in $WORK/err and the calls it made in $CALLS.
drive() {
  : > "$CALLS"
  env INNSEGL_MCP_ADMIN_URL="$ADMIN" INNSEGL_SIGNER="$WORK/signer" \
    python3 "$SHIM" "$1" > "$WORK/out" 2> "$WORK/err"
  STATUS=$?
}

# called reports whether tool was invoked with every one of the given
# substrings present in its arguments, on any one call.
called() {
  local tool="$1"; shift
  local line want hit
  while IFS= read -r line; do
    case "$line" in "$tool "*) : ;; *) continue ;; esac
    hit=yes
    for want in "$@"; do
      case "$line" in *"$want"*) : ;; *) hit=no; break ;; esac
    done
    [ "$hit" = yes ] && return 0
  done < "$CALLS"
  return 1
}

# count_calls: grep -c always prints a count and exits 1 when it is zero, so
# the status is discarded rather than defaulted — `|| echo 0` printed twice.
count_calls() {
  local n
  n="$(grep -c "^$1 " "$CALLS" 2>/dev/null)"
  printf '%s' "${n:-0}"
}

# A signer that records its arguments and succeeds, so the capture path can be
# observed without a deployment.
cat > "$WORK/signer" <<'SH'
#!/bin/sh
printf '%s\n' "$*" >> "$(dirname "$0")/signer.calls"
SH
chmod +x "$WORK/signer"

# ---------------------------------------------------------------------------
# The transcript. One session, two tool calls of the two shapes a rollout
# carries, and the conversational records that are not tool calls at all.
#
# `custom_tool_call` and `function_call` are both tool invocations and both
# must be forwarded; `custom_tool_call_output`, `message`, `reasoning`,
# `token_count` and `turn_context` are not, and a shim that forwarded them
# would fill a run's activity log with the model's prose.
# ---------------------------------------------------------------------------
SID="01a0c0de-0000-7000-8000-0123456789ab"
CWD="/tmp/rollout-selftest-tree"
TRANSCRIPT="$WORK/rollout.jsonl"
cat > "$TRANSCRIPT" <<EOF
{"timestamp":"2026-09-13T10:00:00.000Z","type":"session_meta","payload":{"id":"$SID","session_id":"$SID","timestamp":"2026-09-13T10:00:00.000Z","cwd":"$CWD","originator":"harness_cli","cli_version":"0.0.0","source":"cli","history_mode":"default","model_provider":"provider","context_window":1,"base_instructions":"none"}}
{"timestamp":"2026-09-13T10:00:01.000Z","type":"turn_context","payload":{"cwd":"$CWD","approval_policy":"never","model":"model","summary":"auto","turn_id":"turn-1"}}
{"timestamp":"2026-09-13T10:00:02.000Z","type":"event_msg","payload":{"type":"user_message","message":"add a line to notes.txt"}}
{"timestamp":"2026-09-13T10:00:03.000Z","type":"response_item","payload":{"type":"reasoning","id":"rs_1","summary":[]}}
{"timestamp":"2026-09-13T10:00:04.000Z","type":"response_item","payload":{"type":"custom_tool_call","call_id":"call_1","id":"ctc_1","name":"shell","input":"{\"command\":[\"bash\",\"-lc\",\"echo one >> notes.txt\"]}","status":"completed"}}
{"timestamp":"2026-09-13T10:00:05.000Z","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"call_1","id":"cto_1","output":"{\"exit_code\":0}"}}
{"timestamp":"2026-09-13T10:00:06.000Z","type":"response_item","payload":{"type":"function_call","call_id":"call_2","id":"fc_1","name":"apply_patch","arguments":"{\"patch\":\"*** Begin Patch\"}"}}
{"timestamp":"2026-09-13T10:00:07.000Z","type":"response_item","payload":{"type":"function_call_output","call_id":"call_2","id":"fco_1","output":"ok"}}
{"timestamp":"2026-09-13T10:00:08.000Z","type":"event_msg","payload":{"type":"token_count","info":{},"rate_limits":{}}}
{"timestamp":"2026-09-13T10:00:09.000Z","type":"response_item","payload":{"type":"message","id":"m_1","role":"assistant","content":[{"type":"output_text","text":"done"}]}}
{"timestamp":"2026-09-13T10:00:10.000Z","type":"event_msg","payload":{"type":"task_complete","turn_id":"turn-1","last_agent_message":"done"}}
EOF

echo "rollout-shim-selftest: the second harness's shim, driven over a transcript"

START_REPLY="{\"session_id\":\"$SID\",\"phase\":\"start\",\"known\":true,\"registered\":true,\"run_id\":\"run-cccc3333\",\"task\":\"rm130\",\"worktree\":\"\",\"repo\":\"example.test/org/name\",\"branch\":\"dev/rm130\",\"agent_type\":\"codex\",\"spiffe_id\":\"spiffe://innsegl.dev/agent/codex/rm130/run-cccc3333\",\"run_token\":\"tok-1\"}"
script_tool observe_session ok "$START_REPLY"
script_tool observe_tool_call ok '{"digest":"sha256:00","stored":true}'

drive "$TRANSCRIPT"

# 1. The session's own record opens the run.
if [ "$STATUS" -eq 0 ] && called observe_session '"phase": "start"' "\"session_id\": \"$SID\"" "\"cwd\": \"$CWD\""; then
  ok "session_meta calls observe_session(phase=start) with the transcript's own session id and cwd"
else
  bad "session_meta: status $STATUS, calls: $(cat "$CALLS")"
fi

# 2. Every tool call in the transcript is forwarded, under the run the start
#    returned — and BOTH shapes, because a rollout carries two.
if called observe_tool_call '"run_id": "run-cccc3333"' '"tool": "shell"' 'echo one' \
  && called observe_tool_call '"run_id": "run-cccc3333"' '"tool": "apply_patch"'; then
  ok "each tool call is forwarded to observe_tool_call under the run the start returned"
else
  bad "the tool calls were not forwarded: $(cat "$CALLS")"
fi

# 3. …and only the tool calls. Two in the transcript, two on the wire.
n="$(count_calls observe_tool_call)"
if [ "$n" -eq 2 ]; then
  ok "exactly the transcript's 2 tool calls are forwarded; prose and outputs are not"
else
  bad "observe_tool_call was called $n times, want 2: $(cat "$CALLS")"
fi

# 4. The end of the transcript ends the session.
if called observe_session '"phase": "stop"' "\"session_id\": \"$SID\""; then
  ok "the end of the transcript calls observe_session(phase=stop)"
else
  bad "no stop was sent: $(cat "$CALLS")"
fi

# --- the negative cases: what the shim must NOT do ---------------------------

# 5. It does not register. observe_session does that, inside the MCP (#207).
if ! grep -q '^register_agent ' "$CALLS" && ! grep -q '^retire_agent ' "$CALLS"; then
  ok "the shim never calls register_agent or retire_agent — the lifecycle moved (#207)"
else
  bad "the shim still drives the run lifecycle itself: $(cat "$CALLS")"
fi

# 6. It does not resolve a workspace. observe_session calls describe_workspace
#    in process, so a second shim derives no repo, no branch and no task.
if ! grep -q '^describe_workspace ' "$CALLS"; then
  ok "the shim never calls describe_workspace directly — observe_session composes it (#205)"
else
  bad "the shim resolves the workspace itself: $(cat "$CALLS")"
fi

# 7. It does not digest, and it does not append. A shim that computed a
#    payload_digest and called record_event would be the 807-line shell again.
if ! grep -q '^record_event ' "$CALLS" && ! grep -q 'payload_digest' "$CALLS"; then
  ok "the shim digests nothing and appends nothing itself — observe_tool_call does both (#206)"
else
  bad "the shim still digests or appends locally: $(cat "$CALLS")"
fi

# 8. The body forwarded is the harness's own record, verbatim. The MCP writes
#    it to the operator's volume; the shim decides nothing about where.
if called observe_tool_call '"call_id\": \"call_1' ; then
  ok "the observed record is forwarded whole, so the activity log has the evidence"
else
  bad "the body was not the transcript record: $(cat "$CALLS")"
fi

# --- a transcript with nothing in it -----------------------------------------

# 9. A file with no session_meta forwards nothing and does not fail. Reading a
#    transcript is best-effort by construction: it is read after the session,
#    so there is nothing left to block.
printf '%s\n' '{"timestamp":"2026-09-13T10:00:00.000Z","type":"event_msg","payload":{"type":"token_count","info":{}}}' > "$WORK/empty.jsonl"
drive "$WORK/empty.jsonl"
if [ "$STATUS" -eq 0 ] && [ ! -s "$CALLS" ]; then
  ok "a transcript with no session record forwards nothing and exits 0"
else
  bad "the empty transcript: status $STATUS, calls: $(cat "$CALLS")"
fi

# 10. A start that is refused stops the ingestion rather than recording tool
#     calls against a run that was never issued (I3's converse: no record
#     without an identity).
script_tool observe_session err '{"error_class":"LEDGER_UNAVAILABLE","message":"no","retryable":true}'
drive "$TRANSCRIPT"
if [ "$STATUS" -ne 0 ] && [ "$(count_calls observe_tool_call)" -eq 0 ]; then
  ok "a refused start forwards no tool calls: no record without an identity"
else
  bad "a refused start still forwarded: status $STATUS, calls: $(cat "$CALLS")"
fi

echo
echo "rollout-shim-selftest: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
