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
#     "SessionStart":  [{"hooks":[{"type":"command","command":"<abs path>"}]}],
#     "SessionEnd":    [{"hooks":[{"type":"command","command":"<abs path>"}]}],
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
# EVENT RECORDING IS BEST-EFFORT AND SAYS SO. PostToolUse records each tool
# call against the run, but a hook-based record is structurally incomplete and
# that is not a bug to be fixed: a file written through `Bash` — `echo ... >
# file` — fires the Bash hook and no file-write hook, so the record shows a
# shell command and not the write inside it.
#
# The tree the run signs has no such gap. So the record is a convenience for
# reading a run back, and the DIFF is the evidence. A reader who needs to know
# what a run produced reads the commit; a reader who wants to know what order
# it worked in reads this. Only the first is proof.
#
# It never blocks. A tool call refused because the ledger was briefly
# unreachable would make every agent's work hostage to a bookkeeping write —
# and the identity, which IS load-bearing, was already checked at start.

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

SESSION_ID="$(field session_id)"

mkdir -p "$RUNS_DIR" 2>/dev/null || true

# TWO MARKERS, because there are two kinds of run.
#
#   $RUNS_DIR/<agent_id>            a subagent's run
#   $RUNS_DIR/session-<session_id>  the operator's own session
#
# Until now only the first existed, and the hook exited early whenever
# agent_id was absent — which is every event the main session fires. The
# consequence was measured 2026-09-08: work in one repository produced no run
# at all, and the operator's words were "jeg kjørte ting i raymalian. ingen
# agent fikk identitet der. ingenting ble registrert."
SESSIONFILE="$RUNS_DIR/session-${SESSION_ID:-unknown}"
if [ -n "$AGENT_ID" ]; then
  RUNFILE="$RUNS_DIR/$AGENT_ID"
else
  RUNFILE="$SESSIONFILE"
fi

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

# derive_task sets BRANCH, TASK and REPONAME from the MAIN worktree.
#
# A function because two events need it now: a subagent's registration and the
# operator's own session. It was inline in SubagentStart when only subagents
# had identities.
derive_task() {
  # `git worktree list` reports the main worktree first, from inside any
  # linked one, so this resolves the same branch wherever it runs.
  MAIN="$(git -C "${CWD:-.}" worktree list --porcelain 2>/dev/null | awk '/^worktree /{print $2; exit}')"
  [ -n "$MAIN" ] || MAIN="${CWD:-.}"
  BRANCH="$(git -C "$MAIN" rev-parse --abbrev-ref HEAD 2>/dev/null)"
  [ -n "$BRANCH" ] && [ "$BRANCH" != "HEAD" ] || BRANCH="detached"

  # A branch name is not a task_id: doc 02 §5 is [a-z0-9][a-z0-9-]{0,62} and
  # `dev/rm105-caller-split` is refused for the slash. An RM number is this
  # project's own task identifier and is preferred where the branch carries
  # one; otherwise the branch is folded into the grammar.
  TASK="$(printf '%s' "$BRANCH" | tr 'A-Z' 'a-z' | sed -n 's/.*\(rm[0-9][0-9]*\).*/\1/p')"
  if [ -z "$TASK" ]; then
    TASK="$(printf '%s' "$BRANCH" | tr 'A-Z' 'a-z' \
      | sed -e 's/[^a-z0-9-]/-/g' -e 's/^[^a-z0-9]*//' -e 's/--*/-/g' -e 's/-*$//' \
      | cut -c1-63)"
  fi
  [ -n "$TASK" ] || TASK="unnamed"

  # Prefix the repository, because without it the ledger cannot answer "what
  # did agents do in that other project today".
  #
  # A run_registered event carries agent_type and task_ref and NOTHING about
  # the repository -- the repo is only recorded when a run signs a commit,
  # and a run that signs nothing never gets one. Measured 2026-09-08: five
  # runs from other projects all read `main` with no repository, and were
  # indistinguishable from each other.
  #
  # doc 02 §3's fields are a protected surface, so adding a repo field to
  # run_registered would be a major version. The repository name goes into
  # the task_id instead, which is a field that already exists --
  # `<repo>-<branch>` rather than a bare `main`.
  REPONAME="$(git -C "$MAIN" remote get-url origin 2>/dev/null \
    | sed -e 's|.*[/:]||' -e 's|\.git$||' | tr 'A-Z' 'a-z' \
    | sed -e 's/[^a-z0-9-]/-/g' -e 's/^[^a-z0-9]*//' -e 's/-*$//')"
  [ -n "$REPONAME" ] && TASK="$(printf '%s-%s' "$REPONAME" "$TASK" | cut -c1-63)"
}

case "$EVENT" in

  PreToolUse)
    # PLAIN `git commit` IS REFUSED, AND THE REFUSAL IS THE INSTRUCTION.
    #
    # ADR-0046. Measured 2026-09-08: subagents had made 1979 recorded tool calls
    # and signed nothing, ever. `sign_commit` was available the whole time and
    # went unused, which is the same failure the project exists to answer, one
    # level out -- IP §6.1 says attributed work must be impossible without an
    # identity, NOT merely inconvenient, and an instruction in a prompt is the
    # definition of merely inconvenient.
    #
    # Exit 2 on PreToolUse blocks the call and hands this stderr back to the
    # model as the reason, so the instruction arrives at the only moment it
    # matters. Nothing has to be pre-loaded into a subagent's prompt and nothing
    # can be forgotten, because nothing is remembered.
    #
    # ASYMMETRIC, as identity is: blocking for a subagent, a warning for the
    # operator's own session. Refusing a subagent costs nothing. Refusing the
    # human stops them working on their own machine.
    #
    # AND IT FAILS OPEN. If the deployment is unreachable or the repository is
    # not linked, this warns and allows: an agent that can neither commit nor
    # sign is worse than an unsigned commit, and scripts/verify-branch.sh still
    # refuses to merge what was not signed.
    CMD="$(printf '%s' "$EVENT_JSON" | python3 -c '
import json,sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
if d.get("tool_name") != "Bash":
    sys.exit(0)
print(d.get("tool_input", {}).get("command", ""))' 2>/dev/null)"

    case "$CMD" in
      *"git commit"*|*"git "*" commit"*) : ;;
      *) exit 0 ;;
    esac

    # innsegl-commit.sh does not shell out to `git commit` -- sign_commit builds
    # the object inside the MCP -- so this cannot block the signing path itself.
    case "$CMD" in *innsegl-commit*) exit 0 ;; esac

    if [ -z "$AGENT_ID" ]; then
      echo "innsegl: this is a plain git commit. It will not carry an agent identity." >&2
      echo "innsegl:   scripts/innsegl-commit.sh -m \"...\" signs it instead." >&2
      exit 0
    fi

    [ -f "$RUNFILE" ] || {
      echo "innsegl: no run for this agent, so signing is not available; allowing." >&2
      exit 0
    }

    echo "innsegl: refused. Use scripts/innsegl-commit.sh, not git commit." >&2
    echo "innsegl:" >&2
    echo "innsegl:   git add -A" >&2
    echo "innsegl:   scripts/innsegl-commit.sh -m \"<type>(<scope>): <what changed>\"" >&2
    echo "innsegl:" >&2
    echo "innsegl: It stages exactly what you staged, signs the commit under this" >&2
    echo "innsegl: run's identity, and logs it in Rekor. A plain git commit produces" >&2
    echo "innsegl: work nobody can attribute, which is the one thing this" >&2
    echo "innsegl: deployment exists to prevent (IP §6.1)." >&2
    exit 2
    ;;

  SessionStart)
    # THE OPERATOR'S OWN SESSION, which had no identity at all until now.
    #
    # WHY THIS NEVER BLOCKS, when SubagentStart does. IP §6.1 is that
    # attributed work must be impossible without an identity, and a subagent
    # exists only to do work this system is meant to attribute — refusing it
    # costs nothing that matters. This session is the human's. Refusing it
    # because a container is down would stop them working on their own machine,
    # over a ledger. So it warns and gets out of the way, and the enforcement
    # stays where the attribution actually happens: scripts/innsegl-commit.sh
    # refuses to commit without a run, and the branch gate refuses to merge
    # what was not signed.
    [ -n "$SESSION_ID" ] || exit 0
    [ -f "$SESSIONFILE" ] && exit 0

    derive_task

    OUT="$(mcp_call register_agent "$(printf '{"agent_type":"%s","task_id":"%s","idempotency_key":"session-%s"}' \
      "${INNSEGL_SESSION_AGENT_TYPE:-session}" "$TASK" "$SESSION_ID")" 2>/dev/null)" || {
      echo "innsegl: no identity for this session — the deployment at $ADMIN_URL is not answering." >&2
      echo "innsegl:   Work is not blocked, but nothing you do here is in the ledger" >&2
      echo "innsegl:   until it is. Bring it up with: make innsegl-up-here" >&2
      exit 0
    }

    RUN_ID="$(printf '%s' "$OUT" | sed -n 's/.*\\"run_id\\":\\"\([^\\]*\)\\".*/\1/p' | head -n 1)"
    [ -n "$RUN_ID" ] || RUN_ID="$(printf '%s' "$OUT" | sed -n 's/.*"run_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
    [ -n "$RUN_ID" ] || exit 0

    printf '%s\n' "$RUN_ID" > "$SESSIONFILE"
    echo "innsegl: this session is $RUN_ID (task $TASK)" >&2

    # AND LINK THE REPOSITORY, so signing is possible here at all.
    #
    # ADR-0046 mechanism 1. sign_commit resolves a repository beneath the MCP's
    # workspace volume, and a repository that was never linked is simply not
    # there -- so an agent that WANTED to sign could not, which is half the
    # reason 1979 tool calls produced no signatures. The link is a symlink and
    # needs no restart, so doing it here costs a fraction of a second and
    # removes the setup step entirely.
    #
    # Best-effort: a failure here is not a reason to fail the session. The
    # PreToolUse gate fails open for exactly this case.
    if [ -n "$MAIN" ] && [ -d "$MAIN" ]; then
      ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)"
      if [ -f "$ROOT/Makefile" ]; then
        make -C "$ROOT" --no-print-directory innsegl-link DIR="$MAIN" >/dev/null 2>&1 \
          && echo "innsegl: $MAIN is signable" >&2 \
          || echo "innsegl: could not link $MAIN; signing here will not work yet" >&2
      fi
    fi
    exit 0
    ;;

  SessionEnd)
    [ -n "$SESSION_ID" ] || exit 0
    [ -f "$SESSIONFILE" ] || exit 0
    RUN_ID="$(head -n 1 "$SESSIONFILE")"
    rm -f "$SESSIONFILE"
    [ -n "$RUN_ID" ] || exit 0
    mcp_call retire_agent "$(printf '{"run_id":"%s"}' "$RUN_ID")" >/dev/null 2>&1 \
      && echo "innsegl: retired $RUN_ID" >&2 \
      || echo "innsegl: could not retire $RUN_ID; it will expire on its TTL" >&2
    exit 0
    ;;

  SubagentStart)
    # The task comes from the BRANCH, and from the MAIN worktree's branch
    # rather than this agent's own.
    #
    # Measured 2026-09-07: a subagent spawned with worktree isolation runs in
    # .claude/worktrees/agent-<id> on a branch called worktree-agent-<id>.
    # Reading the branch at $CWD therefore gave every subagent its own
    # throwaway task — `worktree-agent-af9a60aaad38d71b2` in the ledger, where
    # `rm105` belonged. Every agent working on one task must name that one
    # task, or the ledger records a task per agent and answers no question
    # anyone would ask of it.
    #
    derive_task


    # #172: refuse a subagent that is not in its own worktree, when asked to.
    #
    # The harness decides where a subagent runs and a hook cannot change it —
    # but it CAN refuse. With INNSEGL_REQUIRE_WORKTREE=1 a subagent sharing the
    # operator's tree gets no identity and does no work, so what each run
    # produced stays readable as the diff of its own worktree rather than
    # having to be untangled from everyone else's.
    #
    # Off by default: turning it on means every subagent must be spawned with
    # worktree isolation, and a caller that does not know that sees only
    # refusals.
    if [ "${INNSEGL_REQUIRE_WORKTREE:-0}" = "1" ] && [ "$MAIN" = "$(cd "${CWD:-.}" 2>/dev/null && pwd -P)" ]; then
      echo "innsegl: refused — this subagent shares the operator's working tree." >&2
      echo "innsegl:   With INNSEGL_REQUIRE_WORKTREE=1 a run must have a tree of its own," >&2
      echo "innsegl:   so that what it produced is its own diff (#172). Spawn it with" >&2
      echo "innsegl:   worktree isolation." >&2
      exit 2
    fi

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

  PostToolUse)
    # Records what the harness OBSERVED, not what the model reported. The model
    # never calls this: it is invoked by the harness after the tool has already
    # run, and it reads the run id from the marker SubagentStart wrote.
    [ -f "$RUNFILE" ] || exit 0
    RUN_ID="$(head -n 1 "$RUNFILE")"
    [ -n "$RUN_ID" ] || exit 0

    TOOL="$(field tool_name)"
    [ -n "$TOOL" ] || exit 0

    # doc 02 §1's digest form, over the tool's own input. The BODY is never
    # sent — record_event takes a digest and nothing else, which is why the
    # MCP knows that a file was written and never what was in it.
    DIGEST="sha256:$(printf '%s' "$EVENT_JSON" | shasum -a 256 2>/dev/null | awk '{print $1}')"
    case "$DIGEST" in
      sha256:????????????????????????????????????????????????????????????????) : ;;
      *) exit 0 ;;   # no usable digest, and a bad one is worse than none
    esac

    # event_type is the AGENT TOOL that was invoked, not a ledger event type.
    # record_event writes exactly one kind of event and the caller does not
    # choose it; passing "tool_call" here is refused, with that explanation.
    SAFE_TOOL="$(printf '%s' "$TOOL" | sed -e 's/[^A-Za-z0-9_-]//g' | cut -c1-63)"
    [ -n "$SAFE_TOOL" ] || exit 0

    KEY="harness-$AGENT_ID-$(printf '%s' "$DIGEST" | cut -c8-27)"
    mcp_call record_event "$(printf '{"run_id":"%s","event_type":"%s","payload_digest":"%s","idempotency_key":"%s"}' \
      "$RUN_ID" "$SAFE_TOOL" "$DIGEST" "$KEY")" >/dev/null 2>&1 || true

    # ALWAYS 0. See the header: the identity is load-bearing and was checked at
    # start; a bookkeeping write is not, and must never hold up an agent's work.
    exit 0
    ;;

  *)
    exit 0
    ;;
esac
