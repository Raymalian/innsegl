#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# The harness issues the identity, not the model — #171 (RM-106).
#
# The model can no longer call `register_agent`: #170 moved it to a listener
# the model's MCP client is never pointed at. This is what calls it instead.
# The harness runs this script when it starts a subagent, and the subagent
# receives a run it did not ask for and cannot change.
#
# IP §6.1 is the standard this has to meet:
#
#   "the MCP must make it impossible to do attributed work anonymously, not
#    merely inconvenient."
#
# It meets it by refusing. If the identity cannot be issued, this script exits
# 2, and the harness stops the subagent from doing its task. Measured on
# 2026-09-07: a blocked subagent answered the refusal instead of its prompt,
# and never produced the word it was told to produce.
#
# # Wiring
#
# In ~/.claude/settings.json — NOT the project's .claude/settings.json, which
# an agent working in the repository can edit and therefore switch off:
#
#   "hooks": {
#     "SubagentStart": [{"hooks":[{"type":"command","command":"<abs path>"}]}],
#     "SubagentStop":  [{"hooks":[{"type":"command","command":"<abs path>"}]}]
#   }
#
# Needs the admin listener on: INNSEGL_MCP_ADMIN_LISTEN=0.0.0.0:8090 in the
# deployment, published as 28090.
#
#   INNSEGL_MCP_ADMIN_URL   default http://127.0.0.1:28090/
#   INNSEGL_RUNS_DIR        default ~/.innsegl/runs
#
# # Two things it deliberately does not do
#
# NEVER BLOCKS ON STOP. Exit 2 on SubagentStop produced nine repeated
# invocations before the harness gave up — a retry storm, not a refusal. A stop
# that cannot retire logs and moves on; the run expires on its own TTL, which
# is what the TTL is for.
#
# NO EVENT RECORDING. It registers and retires, and that is all. Recording each
# tool call was the other half of #171 and it is not built, because a file
# written through `Bash` fires no file-write hook — so a hook-based record is
# structurally incomplete, while the tree the run signs is not. The work is
# read from the diff, not from the narrative.

set -u

EVENT_JSON="$(cat)"

ADMIN_URL="${INNSEGL_MCP_ADMIN_URL:-http://127.0.0.1:28090/}"
RUNS_DIR="${INNSEGL_RUNS_DIR:-$HOME/.innsegl/runs}"

field() {
  printf '%s' "$EVENT_JSON" | sed -n 's/.*"'"$1"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1
}

EVENT="$(field hook_event_name)"
AGENT_ID="$(field agent_id)"
AGENT_TYPE="$(field agent_type)"
CWD="$(field cwd)"

# No agent_id means this fired for the parent session, not a subagent. Nothing
# to do, and refusing here would block the operator's own session.
[ -n "$AGENT_ID" ] || exit 0

mkdir -p "$RUNS_DIR" 2>/dev/null || true
RUNFILE="$RUNS_DIR/$AGENT_ID"

# ---------------------------------------------------------------------------
# One MCP call over the streamable-HTTP transport.
#
# The session is opened per call rather than kept: a hook is a short-lived
# process with nowhere to keep one, and the cost is a handshake against a
# server on loopback.
# ---------------------------------------------------------------------------
mcp_call() {
  _tool="$1"
  _args="$2"
  _hdr="$(mktemp)"

  curl -sS --max-time 30 --dump-header "$_hdr" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    --data-binary '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"innsegl-harness-hook","version":"v0"}}}' \
    "$ADMIN_URL" >/dev/null 2>&1 || { rm -f "$_hdr"; return 1; }

  _sid="$(sed -n 's/^[Mm]cp-[Ss]ession-[Ii]d:[[:space:]]*//p' "$_hdr" | tr -d '\r' | head -n 1)"
  rm -f "$_hdr"
  [ -n "$_sid" ] || return 1

  curl -sS --max-time 10 \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    -H "Mcp-Session-Id: $_sid" \
    --data-binary '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
    "$ADMIN_URL" >/dev/null 2>&1

  _raw="$(curl -sS --max-time 60 \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    -H "Mcp-Session-Id: $_sid" \
    --data-binary "$(printf '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"%s","arguments":%s}}' "$_tool" "$_args")" \
    "$ADMIN_URL" 2>&1)" || return 1

  # The transport answers with an SSE frame; the payload is the `data:` line.
  _payload="$(printf '%s' "$_raw" | sed -n 's/^data: //p' | head -n 1)"
  [ -n "$_payload" ] || _payload="$_raw"
  printf '%s' "$_payload"
}

case "$EVENT" in

  SubagentStart)
    # The task comes from the BRANCH, not from the hook input. The hook is
    # never told what the subagent was asked to do — it gets a type and a
    # generated id and nothing else. A branch name is git state that outlives
    # the session and that the model does not choose at spawn time.
    #
    # A branch name is not a task_id, though, and the first run of this hook
    # proved it: doc 02 §5's grammar is [a-z0-9][a-z0-9-]{0,62}, and
    # `dev/rm105-caller-split` was refused for the slash. So it is derived,
    # not used raw:
    #
    #   1. an RM number if the branch carries one — dev/rm105-x -> rm105 —
    #      because that is this project's own task identifier, and two branches
    #      for one issue should name one task.
    #   2. otherwise the branch, lowercased, with everything outside the
    #      grammar folded to a hyphen and the result trimmed to 63.
    BRANCH="$(git -C "${CWD:-.}" rev-parse --abbrev-ref HEAD 2>/dev/null)"
    [ -n "$BRANCH" ] && [ "$BRANCH" != "HEAD" ] || BRANCH="detached"

    TASK="$(printf '%s' "$BRANCH" | tr 'A-Z' 'a-z' | sed -n 's/.*\(rm[0-9][0-9]*\).*/\1/p')"
    if [ -z "$TASK" ]; then
      TASK="$(printf '%s' "$BRANCH" | tr 'A-Z' 'a-z' \
        | sed -e 's/[^a-z0-9-]/-/g' -e 's/^[^a-z0-9]*//' -e 's/--*/-/g' -e 's/-*$//' \
        | cut -c1-63)"
    fi
    [ -n "$TASK" ] || TASK="unnamed"

    KEY="harness-$AGENT_ID"
    ARGS="$(printf '{"agent_type":"%s","task_id":"%s","idempotency_key":"%s"}' \
      "${AGENT_TYPE:-subagent}" "$TASK" "$KEY")"

    OUT="$(mcp_call register_agent "$ARGS")" || {
      echo "innsegl: refused — the identity service could not be reached at $ADMIN_URL." >&2
      echo "innsegl:   No identity, no attributed work (IP §6.1). Bring the deployment up:" >&2
      echo "innsegl:   make innsegl-up" >&2
      exit 2
    }

    RUN_ID="$(printf '%s' "$OUT" | sed -n 's/.*\\"run_id\\":\\"\([^\\]*\)\\".*/\1/p' | head -n 1)"
    [ -n "$RUN_ID" ] || RUN_ID="$(printf '%s' "$OUT" | sed -n 's/.*"run_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"

    if [ -z "$RUN_ID" ]; then
      echo "innsegl: refused — register_agent returned no run_id." >&2
      echo "innsegl:   $(printf '%s' "$OUT" | head -c 300)" >&2
      exit 2
    fi

    printf '%s\n' "$RUN_ID" > "$RUNFILE"
    echo "innsegl: $AGENT_TYPE is $RUN_ID (task $TASK)" >&2
    exit 0
    ;;

  SubagentStop)
    [ -f "$RUNFILE" ] || exit 0
    RUN_ID="$(head -n 1 "$RUNFILE")"
    rm -f "$RUNFILE"
    [ -n "$RUN_ID" ] || exit 0

    # Never exit 2 here. See the header.
    if mcp_call retire_agent "$(printf '{"run_id":"%s"}' "$RUN_ID")" >/dev/null 2>&1; then
      echo "innsegl: retired $RUN_ID" >&2
    else
      echo "innsegl: could not retire $RUN_ID; it will expire on its TTL" >&2
    fi
    exit 0
    ;;

  *)
    exit 0
    ;;
esac
