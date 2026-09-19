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
drive() {
  : > "$CALLS"
  printf '%s' "$1" | env \
    INNSEGL_MCP_ADMIN_URL="$ADMIN" \
    INNSEGL_RUNS_DIR="$RUNS" \
    INNSEGL_LOG_DIR="$LOG" \
    INNSEGL_SIGNER="$WORK/signer" \
    INNSEGL_ADMIN_CREDENTIAL_MINT="${MINT:-}" \
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

# 3b. AND IT NAMES THE RUN THAT SPAWNED IT — ADR-0045's third member (#214).
# Case 1 registered sess-1 as run-aaaa1111 and wrote its marker; this subagent
# is keyed on agent-7, so the parent is the sibling marker named by the session.
# Without this the ledger holds two runs and no relation between them.
if called observe_session '"parent_run_id": "run-aaaa1111"'; then
  ok "SubagentStart names the session's run as its parent"
else
  bad "SubagentStart sent no parent_run_id: $(grep observe_session "$CALLS" | tail -1)"
fi

# 3c. AND A SUBAGENT WITH NO PARENT STAYS A ROOT RUN. absent is not an error,
# and an EMPTY parent is not the same as none (doc 02 §1) — a root run naming an
# empty parent would be claiming one it does not have.
script_tool observe_session ok '{"session_id":"agent-orphan","phase":"start","known":true,"registered":true,"run_id":"run-cccc3333","task":"e11","worktree":"","repo":"example.test/org/name","branch":"dev/e11","agent_type":"prober","spiffe_id":"spiffe://innsegl.dev/agent/a/b/run-cccc3333"}'
drive "{\"hook_event_name\":\"SubagentStart\",\"session_id\":\"sess-never-registered\",\"agent_id\":\"agent-orphan\",\"agent_type\":\"prober\",\"cwd\":\"$CWD\"}"
if [ "$STATUS" -eq 0 ] && ! grep observe_session "$CALLS" | tail -1 | grep -q 'parent_run_id'; then
  ok "a subagent whose parent never registered sends no parent at all"
else
  bad "orphan subagent: status $STATUS, call: $(grep observe_session "$CALLS" | tail -1)"
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

# 5c. and the operator's own session, which carries no agent id, names itself.
: > "$CALLS"
script_tool observe_tool_call ok '{"digest":"sha256:'"$(printf 'b%.0s' $(seq 1 64))"'","stored":true}'
drive '{"hook_event_name":"PostToolUse","session_id":"sess-1","tool_name":"Edit","tool_input":{"file_path":"x"}}'
if called observe_tool_call '"session_id": "sess-1"' '"agent_type": "session"'; then
  ok "the operator's own session names itself, with no marker required"
else
  bad "main-session PostToolUse: $(cat "$CALLS")"
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

echo
echo "shim-selftest: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
