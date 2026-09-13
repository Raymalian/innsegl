#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# THE REFERENCE SHIM. Read the harness's own event, forward it, exit 0.
#
# The harness issues the identity, not the model — #171 (RM-106). The model
# cannot call `register_agent`: #170 moved it to a listener the model's MCP
# client is never pointed at. This is what calls it instead, and the subagent
# receives a run it did not ask for and cannot change.
#
# IP §6.1 is the standard it has to meet: "the MCP must make it impossible to do
# attributed work anonymously, not merely inconvenient." It meets it by
# refusing. A SubagentStart that cannot get an identity exits 2, and the harness
# stops the subagent from doing its task.
#
# # What this file is NOT any more — RM-129 (#208), E11
#
# It was 807 lines with 29 local computations: git plumbing, `shasum`
# digesting, a `$LOG/<run>/<digest>.json` layout, and a directory of marker
# files whose LINE ORDER two other scripts had to agree about. Every one of
# those was work a second harness would have to reimplement identically, which
# is why one harness got identity AND an activity record while every other
# harness got identity and a blank log.
#
# Three tools took it:
#
#   describe_workspace   repo, worktree, branch and task from a cwd  (#205)
#   observe_tool_call    digest the body, store it, append tool_call (#206)
#   observe_session      start/stop, and all of the bookkeeping      (#207)
#
# `observe_session` calls `describe_workspace` in process, so this file reaches
# two tools directly and the third through them. It derives no branch, folds no
# task, parses no remote, digests nothing, and knows nothing about where a body
# is written.
#
# # What deliberately stays, and why each one cannot leave
#
#   THE `git commit` REFUSAL. It must BLOCK the tool call, and only the harness
#   can do that. Every future shim implements it. (ADR-0046, OPS-021.)
#
#   READING THIS HARNESS'S EVENT SHAPE. That is the shim's whole job.
#
#   ONE REMEMBERED RUN ID. A harness event carries a session id and never a run
#   id; the only tool that maps one to the other also REGISTERS, and
#   register_agent is metered per caller (ADR-0025), so asking it on every tool
#   call would exhaust the meter. So the answer is written down once and read
#   back. It is a cache of the MCP's answer, not a derivation.
#
#   THE BY-TREE POINTER, which is scripts/innsegl-commit.sh's index and not the
#   harness protocol. Without it the signer mints a throwaway identity per
#   commit: measured, 53 signed commits under ephemeral runs while all 16 agent
#   runs that did the work showed "Signed nothing". Nothing in the MCP publishes
#   it yet.
#
#   THE STOP-TIME CAPTURE (ADR-0046) and the BODY RETENTION SWEEP. Neither
#   moved. Both are named in #208's closing comment as the next things that
#   should.
#
# # Wiring
#
# In the HARNESS's own settings, not the project's — a project file is one an
# agent working in the repository can edit and therefore switch off:
#
#   SessionStart  SessionEnd  SubagentStart  SubagentStop  PreToolUse
#   PostToolUse   → this script
#
# Needs the admin listener on: INNSEGL_MCP_ADMIN_LISTEN=0.0.0.0:8090 in the
# deployment, published as 28090.
#
#   INNSEGL_MCP_ADMIN_URL   default http://127.0.0.1:28090/
#   INNSEGL_RUNS_DIR        default ~/.innsegl/runs
#
# Needs `python3` and `curl`. python3 does the JSON in both directions, which
# is what removed the `sed`-and-`printf` parsing the old file used: a branch
# name carrying a quote used to build a malformed request, and the transport's
# two reply shapes needed two regexps that had to be kept in step.
#
# # Two rules that are not negotiable
#
# NEVER `exit 2` ON A STOP PATH. Measured: a blocked stop produced NINE repeated
# invocations before the harness gave up — a retry storm, not a refusal. Every
# failure on a stop path warns and exits 0. The run expires on its TTL, which is
# what the TTL is for.
#
# RECORDING IS BEST-EFFORT AND SAYS SO. A hook-based record is structurally
# incomplete and that is not a bug to be fixed: a file written through `Bash` —
# `echo ... > file` — fires the Bash hook and no file-write hook, so the record
# shows a shell command and not the write inside it. The tree the run SIGNS has
# no such gap. The record is a convenience for reading a run back; the diff is
# the evidence. So PostToolUse never blocks: a tool call refused because the
# ledger was briefly unreachable would make an agent's work hostage to a
# bookkeeping write, and the identity — which IS load-bearing — was checked at
# start.

set -u

EVENT_JSON="$(cat)"

ADMIN_URL="${INNSEGL_MCP_ADMIN_URL:-http://127.0.0.1:28090/}"
RUNS_DIR="${INNSEGL_RUNS_DIR:-$HOME/.innsegl/runs}"

# ---------------------------------------------------------------------------
# The harness's own event, read once.
#
# shlex.quote on the way out, so a command containing a quote or a newline
# arrives here as one value rather than as shell. Every field is optional: a
# harness that does not send one is not an error, and each branch below decides
# what a missing one means.
# ---------------------------------------------------------------------------
eval "$(printf '%s' "$EVENT_JSON" | python3 -c '
import json, shlex, sys
try:
    event = json.load(sys.stdin)
except Exception:
    event = {}
tool_input = event.get("tool_input")
if not isinstance(tool_input, dict):
    tool_input = {}
for name, value in (
    ("EVENT", event.get("hook_event_name")),
    ("SESSION_ID", event.get("session_id")),
    ("AGENT_ID", event.get("agent_id")),
    ("AGENT_TYPE", event.get("agent_type")),
    ("CWD", event.get("cwd")),
    ("TOOL", event.get("tool_name")),
    ("CMD", tool_input.get("command")),
):
    print(name + "=" + shlex.quote(value if isinstance(value, str) else ""))
' 2>/dev/null)"
# A missing python3 leaves every one of them unset, and `set -u` would then kill
# the hook rather than let it get out of the way.
: "${EVENT:=}" "${SESSION_ID:=}" "${AGENT_ID:=}" "${AGENT_TYPE:=}" "${CWD:=}" "${TOOL:=}" "${CMD:=}"

# THE KEY THIS EVENT IS ABOUT, because there are two kinds of run: a subagent's,
# and the operator's own session. Until #182 only the first existed and the hook
# exited whenever agent_id was absent — which is every event the main session
# fires, so work in one repository produced no run at all.
if [ -n "$AGENT_ID" ]; then
  KEY="$AGENT_ID"
else
  KEY="session-${SESSION_ID:-unknown}"
fi

warn() { echo "innsegl: $*" >&2; }

# say_detail passes on a reply's `detail`, which is how observe_session reports
# what a call could not finish WITHOUT refusing — a stop that blocks is answered
# by a harness with a retry storm, not with a fix. Always returns 0, so it can
# end a branch without deciding it.
say_detail() { _d="$(reply_field "$1" detail)"; [ -n "$_d" ] && warn "  $_d"; return 0; }

# One MCP call: mcp_call <tool> <name> <value> ... → the tool's result object.
mcp_call() {
  _tool="$1"
  shift
  python3 -c "$MCP_CLIENT" "$ADMIN_URL" "$_tool" "$@" 2>/dev/null
}

# THE CLIENT ITSELF, in one place, because a shim's transport should be the
# least interesting thing in it.
#
# python3 rather than curl and sed. The old file opened the session with curl,
# read the id back out of a dumped header file with sed, built the request with
# printf — where a branch name carrying a quote produced a malformed call — and
# then needed TWO regexps for the reply, because the SSE frame escapes the JSON
# inside a JSON string and a direct reply does not. All of that is one library
# call here, and nothing about it is this harness's business.
#
# Arguments arrive as name/value pairs and an EMPTY VALUE IS OMITTED, which is
# what keeps the optional ones optional without a branch per call site. The body
# of an observed tool call travels in argv, so a harness event larger than
# ARG_MAX fails the call rather than being silently truncated — the tool bounds
# one body at a mebibyte in any case.
MCP_CLIENT='
import json, sys, urllib.request

url, tool = sys.argv[1], sys.argv[2]
args = {k: v for k, v in zip(sys.argv[3::2], sys.argv[4::2]) if v != ""}

def post(payload, session=None, timeout=60):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers={
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream"})
    if session:
        req.add_header("Mcp-Session-Id", session)
    with urllib.request.urlopen(req, timeout=timeout) as reply:
        return reply.headers.get("Mcp-Session-Id"), reply.read().decode("utf-8", "replace")

try:
    # The session is opened per call rather than kept: a hook is a short-lived
    # process with nowhere to keep one, and the cost is a handshake against a
    # server on loopback.
    session, _ = post({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-11-25", "capabilities": {},
        "clientInfo": {"name": "innsegl-harness-hook", "version": "v0"}}}, timeout=30)
    if not session:
        raise RuntimeError("the transport returned no session id")
    post({"jsonrpc": "2.0", "method": "notifications/initialized"}, session, timeout=10)
    _, raw = post({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                   "params": {"name": tool, "arguments": args}}, session)
except Exception:
    sys.exit(1)

# The transport answers with an SSE frame; the payload is the `data:` line. A
# direct JSON reply has none and is read as it stands.
for line in raw.splitlines():
    if line.startswith("data: "):
        raw = line[6:]
        break
try:
    result = json.loads(raw)["result"]
    body = result.get("structuredContent")
    if not isinstance(body, dict):
        body = json.loads((result.get("content") or [{}])[0].get("text", "{}"))
except Exception:
    sys.exit(1)
print(json.dumps(body))
# An IP §4 error result and a transport failure are one outcome here: a caller
# with no answer does not care which, and the ones that want the message read it
# off the body this printed.
sys.exit(1 if result.get("isError") else 0)
'

# reply_field prints one string member of a result object, or nothing.
reply_field() {
  printf '%s' "$1" | python3 -c '
import json, sys
try: value = json.load(sys.stdin).get(sys.argv[1])
except Exception: value = None
print(value if isinstance(value, str) else "")
' "$2" 2>/dev/null
}

# ---------------------------------------------------------------------------
# The remembered run. See the header for why this one thing could not move.
#
# It holds what the MCP ANSWERED — the run, its task, its worktree relative to
# the repository, its agent type — plus the directory the harness said the event
# happened in, because a stop payload cannot be relied on to say where it was.
# Nothing in it is derived here, and nothing outside this file reads it, so it
# has no line order for anything to disagree about.
# ---------------------------------------------------------------------------
MARKER="$RUNS_DIR/$KEY"

remember() {
  mkdir -p "$RUNS_DIR" 2>/dev/null || return 1
  # 0600: this file names a run a reader could then sign under.
  ( umask 077; printf '%s' "$1" | python3 -c '
import json, sys
body = json.load(sys.stdin); body["dir"] = sys.argv[1]; print(json.dumps(body))
' "$2" > "$MARKER" ) 2>/dev/null
}

recall() { cat "$MARKER" 2>/dev/null; }

# ---------------------------------------------------------------------------
# The signer, resolved most portable first.
#
#   1  $INNSEGL_SIGNER          an operator who put it somewhere else
#   2  innsegl-commit on PATH   `make innsegl-install-signer` puts it there
#   3  this hook's own sibling  the fallback, and the only one that assumes a
#                               layout the agent may not have
#
# 2 is why this exists. The refusal used to name `scripts/innsegl-commit.sh`,
# which resolves only inside this repository; an agent working in a project with
# no `scripts/` directory was pointed at a file that does not exist while
# holding nineteen finished files. A gate that blocks and offers nothing is
# worse than no gate, because the work is stranded rather than merely unsigned.
# ---------------------------------------------------------------------------
signer() {
  if [ -n "${INNSEGL_SIGNER:-}" ] && [ -x "${INNSEGL_SIGNER}" ]; then
    printf '%s' "$INNSEGL_SIGNER"
  elif command -v innsegl-commit >/dev/null 2>&1; then
    printf '%s' innsegl-commit
  else
    printf '%s' "$(CDPATH= cd -- "$(dirname -- "$0")/.." 2>/dev/null && pwd -P)/innsegl-commit.sh"
  fi
}

# Sourcing this file defines its functions, dispatches nothing, and pulls in the
# frozen reference derivation, so MCP-043 can compare describe_workspace's port
# against the shell it was ported from with no harness, no MCP and no network.
# Set only by tests; the harness never sets it.
#
# Locating the sibling when this file is SOURCED: $0 is the shell rather than
# this script and says nothing, while POSIX `.` keeps the caller's positional
# parameters — and a caller that sourced this file necessarily holds its path,
# which both callers pass as $1. INNSEGL_HOOK_DIR overrides for anything that
# does not.
if [ -n "${INNSEGL_HOOK_LIB:-}" ]; then
  _lib="${INNSEGL_HOOK_DIR:-$(dirname -- "${1:-$0}")}"
  . "$_lib/reference-derivation.sh"
  return 0
fi

case "$EVENT" in

  SessionStart)
    # THE OPERATOR'S OWN SESSION, which had no identity at all until #182.
    #
    # WHY THIS NEVER BLOCKS, when SubagentStart does. IP §6.1 is that attributed
    # work must be impossible without an identity, and a subagent exists only to
    # do work this system is meant to attribute — refusing it costs nothing that
    # matters. This session is the human's. Refusing it because a container is
    # down would stop them working on their own machine, over a ledger. So it
    # warns and gets out of the way, and the enforcement stays where the
    # attribution happens: the signer refuses to commit without a run, and the
    # branch gate refuses to merge what was not signed.
    [ -n "$SESSION_ID" ] || exit 0

    # RETENTION, BY AGE ALONE: 90 days and no other rule. A log whose depth
    # depends on how full the disk happens to be cannot be reasoned about, and
    # this one is evidence.
    #
    # THIS NO LONGER BELONGS HERE and is kept only because nothing else does it.
    # Since #211 the MCP writes these bodies, and doc 05's own rule is that
    # retention belongs to whoever writes them; a second harness that never runs
    # this line leaves the same directory growing. It is the first of the two
    # jobs #208's closing comment hands on.
    #
    # Only the BODIES expire. Identity does not and cannot: `run_registered`,
    # the SPIFFE ID, the trailers and every digest live in the hash chain, which
    # is append-only by construction. "Who was this agent and what did it sign"
    # is answerable forever; "what exactly did it type three months ago" is not.
    _log="${INNSEGL_LOG_DIR:-$HOME/.innsegl/log}"
    [ -d "$_log" ] && find "$_log" -type f -name '*.json' -mtime +"${INNSEGL_LOG_DAYS:-90}" -delete 2>/dev/null
    [ -d "$_log" ] && find "$_log" -type d -empty -delete 2>/dev/null

    REPLY="$(mcp_call observe_session \
      session_id "$SESSION_ID" phase start cwd "$CWD" \
      agent_type "${INNSEGL_SESSION_AGENT_TYPE:-session}")" || {
      warn "no identity for this session — the deployment at $ADMIN_URL is not answering."
      warn "  Work is not blocked, but nothing you do here is in the ledger"
      warn "  until it is. Bring it up with: make innsegl-up-here"
      [ -n "${REPLY:-}" ] && warn "  $(reply_field "$REPLY" message | cut -c1-200)"
      exit 0
    }

    RUN_ID="$(reply_field "$REPLY" run_id)"
    [ -n "$RUN_ID" ] || exit 0
    remember "$REPLY" "$CWD" || warn "could not write this session's marker under $RUNS_DIR"
    warn "this session is $RUN_ID (task $(reply_field "$REPLY" task))"
    say_detail "$REPLY"

    # AND LINK THE REPOSITORY, so signing is possible here at all (ADR-0046
    # mechanism 1). sign_commit resolves a repository beneath the MCP's
    # workspace volume, and one that was never linked is simply not there — so
    # an agent that WANTED to sign could not, which is half the reason 1979 tool
    # calls produced no signatures. The link is a symlink and needs no restart.
    #
    # The repository's own tree, on this machine: describe_workspace answered
    # with this tree RELATIVE to it (MCP-029), and `make innsegl-link` wants the
    # absolute one. Best-effort — a failure here is not a reason to fail the
    # session, and the PreToolUse gate fails open for exactly this case.
    WT="$(reply_field "$REPLY" worktree)"
    MAIN="$CWD"
    [ -n "$WT" ] && MAIN="${CWD%"/$WT"}"
    if [ -d "$MAIN" ]; then
      ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." 2>/dev/null && pwd -P)"
      if [ -n "$ROOT" ] && [ -f "$ROOT/Makefile" ]; then
        make -C "$ROOT" --no-print-directory innsegl-link DIR="$MAIN" >/dev/null 2>&1 \
          && warn "$MAIN is signable" \
          || warn "could not link $MAIN; signing here will not work yet"
      fi
    fi
    exit 0
    ;;

  SessionEnd)
    # Never exit 2. See the header.
    [ -n "$SESSION_ID" ] || exit 0
    [ -f "$MARKER" ] || exit 0
    # if/else rather than `&& { ... } || ...`: a block whose LAST command is a
    # conditional warn returns that condition's status, so the `||` arm fires
    # after a successful stop and the hook reports the retirement and its own
    # failure in the same breath. Measured in RM-129's live run, which printed
    # "retired <run>" and "could not retire <run>" one after the other.
    if REPLY="$(mcp_call observe_session session_id "$SESSION_ID" phase stop)"; then
      warn "retired $(reply_field "$REPLY" run_id)"
      say_detail "$REPLY"
    else
      warn "could not end this session; the run expires on its TTL (IP §6.7)"
    fi
    # The marker is only this shim's cache of an answer. observe_session keeps
    # the mapping a later stop retries from, so removing this loses nothing —
    # which is precisely what moving the bookkeeping bought.
    rm -f "$MARKER"
    exit 0
    ;;

  SubagentStart)
    # A subagent with no identity does no work (IP §6.1). This is the one start
    # that refuses, and the refusal is the enforcement.
    [ -n "$AGENT_ID" ] || exit 0

    # The parent run: a session marker is what the run belongs under, and
    # observe_session takes no parent_run_id, so a subagent registered through
    # it is a root run. ADR-0045's third member is not carried by this path and
    # #208's closing comment says so rather than leaving it to be discovered.
    REPLY="$(mcp_call observe_session \
      session_id "$AGENT_ID" phase start cwd "$CWD" \
      agent_type "${AGENT_TYPE:-subagent}")" || {
      warn "refused — no identity could be issued for this subagent."
      [ -n "${REPLY:-}" ] && warn "  $(reply_field "$REPLY" message | cut -c1-300)"
      warn "  No identity, no attributed work (IP §6.1). Bring the deployment up:"
      warn "  make innsegl-up"
      exit 2
    }

    RUN_ID="$(reply_field "$REPLY" run_id)"
    [ -n "$RUN_ID" ] || { warn "refused — observe_session returned no run."; exit 2; }
    WT="$(reply_field "$REPLY" worktree)"

    # #172: refuse a subagent that is not in its own worktree, when asked to.
    #
    # The harness decides where a subagent runs and a hook cannot change it —
    # but it CAN refuse. With INNSEGL_REQUIRE_WORKTREE=1 a subagent sharing the
    # operator's tree gets no identity and does no work, so what each run
    # produced stays readable as the diff of its own worktree. Off by default:
    # turning it on means every subagent must be spawned with worktree
    # isolation, and a caller who does not know that sees only refusals.
    #
    # describe_workspace answers this: an EMPTY worktree is the repository's own
    # tree. The run just registered is retired on the way out rather than left
    # Active for the reaper to find.
    if [ "${INNSEGL_REQUIRE_WORKTREE:-0}" = "1" ] && [ -z "$WT" ]; then
      mcp_call observe_session session_id "$AGENT_ID" phase stop >/dev/null 2>&1
      warn "refused — this subagent shares the operator's working tree."
      warn "  With INNSEGL_REQUIRE_WORKTREE=1 a run must have a tree of its own,"
      warn "  so that what it produced is its own diff (#172). Spawn it with"
      warn "  worktree isolation."
      exit 2
    fi

    remember "$REPLY" "$CWD" || warn "could not write this run's marker under $RUNS_DIR"

    # AND A POINTER KEYED BY THE WORKING TREE — scripts/innsegl-commit.sh's
    # index, in its own three-line format, and the one piece of local file
    # layout E11 has not taken.
    #
    # It is what makes attribution automatic instead of remembered. A shell
    # command cannot discover which agent it is inside — no environment variable
    # carries an agent or session id — so without this the signer mints a
    # throwaway identity per commit: 53 signed commits under ephemeral runs
    # while all 16 agent runs that did the work showed "Signed nothing". The
    # tree is the one thing both sides can see.
    _tree="$(CDPATH= cd -- "${CWD:-.}" 2>/dev/null && pwd -P)"
    if [ -n "$_tree" ] && mkdir -p "$RUNS_DIR/by-tree" 2>/dev/null; then
      _key="$(printf '%s' "$_tree" | shasum -a 256 2>/dev/null | cut -c1-32)"
      [ -n "$_key" ] && printf '%s\n%s\n%s\n' \
        "$RUN_ID" "$(reply_field "$REPLY" task)" "$WT" \
        > "$RUNS_DIR/by-tree/$_key" 2>/dev/null
    fi

    warn "${AGENT_TYPE:-subagent} is $RUN_ID (task $(reply_field "$REPLY" task))"
    exit 0
    ;;

  SubagentStop)
    # NOTHING HERE EVER EXITS 2. See the header: blocking on stop produced a
    # nine-deep retry storm once already.
    [ -n "$AGENT_ID" ] || exit 0
    MARK="$(recall)"
    [ -n "$MARK" ] || exit 0
    RUN_ID="$(reply_field "$MARK" run_id)"
    [ -n "$RUN_ID" ] || { rm -f "$MARKER"; exit 0; }

    # CAPTURE WHAT THIS AGENT LEFT (ADR-0046). Measured: subagents had 314 Edit
    # and 33 Write calls and zero commits. The work was never lost — it sat in
    # the worktree — but it was never attributed to the agent that did it
    # either, and an orchestrator committing it later signs it as its own.
    #
    # This did not move into the MCP and should: it is git plumbing every shim
    # would otherwise copy. #208's closing comment hands it on.
    DIR="$(reply_field "$MARK" dir)"
    if [ -n "$DIR" ] && [ -d "$DIR" ]; then
      # Did it already commit under its own identity? Ask the ledger, not the
      # worktree: a commit that was signed and then had its branch moved is
      # still this run's commit.
      committed="$(curl -sS --max-time 5 \
        "${INNSEGL_API_URL:-http://127.0.0.1:8082}/api/v1/runs/$RUN_ID" 2>/dev/null \
        | sed -n 's/.*"commits"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -n 1)"
      dirty="$(git -C "$DIR" status --porcelain 2>/dev/null | wc -l | tr -d ' ')"

      if [ "${committed:-0}" = "0" ] && [ "${dirty:-0}" != "0" ]; then
        TASK="$(reply_field "$MARK" task)"
        WT="$(reply_field "$MARK" worktree)"
        TYPE="${AGENT_TYPE:-$(reply_field "$MARK" agent_type)}"
        warn "$RUN_ID left $dirty uncommitted path(s) and signed nothing; capturing"
        git -C "$DIR" add -A 2>/dev/null || true
        MSG="chore(agent): work left by $TYPE run $RUN_ID

Captured by the harness at SubagentStop because the run ended with $dirty
uncommitted path(s) and no commit of its own. Signed under that run's identity
so the work is attributed to the agent that did it rather than to whoever
commits next (ADR-0046).

The build was not run. A subagent's work is recorded as it was left; the branch
gate is what decides whether it may merge."
        # Signed under THIS RUN, not a new one — and not retired here, the stop
        # below is the one that belongs to this event.
        # The work stays STAGED whether or not this succeeds, so a failure loses
        # nothing but the attribution, and the run it should carry is named here
        # rather than written to a file nothing has ever read.
        ( cd "$DIR" && "$(signer)" -r "$RUN_ID" ${TASK:+-t "$TASK"} ${WT:+-w "$WT"} -m "$MSG" ) >&2 \
          || warn "could not sign $RUN_ID's work; it is staged in $DIR and signing it later needs -r $RUN_ID"
      fi
    fi

    # See SessionEnd for why this is an if and not a `&& { } ||`.
    if REPLY="$(mcp_call observe_session session_id "$AGENT_ID" phase stop)"; then
      warn "retired $(reply_field "$REPLY" run_id)"
      say_detail "$REPLY"
    else
      warn "could not retire $RUN_ID; the reaper expires it as run_expired (IP §6.7)"
    fi

    # Removed unconditionally, and that is a change the move paid for. This file
    # used to be the ONLY record of the run, so a stop that deleted it before a
    # failed retirement lost the run for good — three runs registered one
    # afternoon were still Active seventeen hours later with no marker left to
    # retry from. observe_session holds that mapping now.
    rm -f "$MARKER"
    if [ -n "${DIR:-}" ]; then
      _key="$(printf '%s' "$(CDPATH= cd -- "$DIR" 2>/dev/null && pwd -P)" | shasum -a 256 2>/dev/null | cut -c1-32)"
      [ -n "$_key" ] && rm -f "$RUNS_DIR/by-tree/$_key" 2>/dev/null
    fi
    exit 0
    ;;

  PostToolUse)
    # Records what the harness OBSERVED, not what the model reported. The model
    # never calls this: it is invoked after the tool has already run.
    #
    # The WHOLE event is the body. observe_tool_call digests it, writes it to
    # the MCP's own local volume and appends the `tool_call` carrying the digest
    # and the tool name — so this file no longer knows doc 02 §1's hash form,
    # the `$LOG/<run>/<digest>.json` layout, or that a body is kept at all. The
    # body still never leaves this machine; it is now the MCP that holds it.
    #
    # ALWAYS 0. See the header.
    MARK="$(recall)"
    [ -n "$MARK" ] || exit 0
    RUN_ID="$(reply_field "$MARK" run_id)"
    [ -n "$RUN_ID" ] && [ -n "$TOOL" ] || exit 0
    mcp_call observe_tool_call \
      run_id "$RUN_ID" tool "$TOOL" body "$EVENT_JSON" \
      run_token "$(reply_field "$MARK" run_token)" >/dev/null 2>&1 || true
    exit 0
    ;;

  PreToolUse)
    # PLAIN `git commit` IS REFUSED, AND THE REFUSAL IS THE INSTRUCTION.
    #
    # ADR-0046. Measured: subagents had made 1979 recorded tool calls and signed
    # nothing, ever. `sign_commit` was available the whole time and went unused,
    # which is the same failure this project exists to answer, one level out —
    # IP §6.1 says attributed work must be impossible without an identity, NOT
    # merely inconvenient, and an instruction in a prompt is the definition of
    # merely inconvenient.
    #
    # THIS IS WHY THE SHIM STILL EXISTS. Exit 2 on PreToolUse blocks the call
    # and hands this stderr back to the model as the reason, so the instruction
    # arrives at the only moment it matters. No MCP tool can do that: blocking
    # a tool call is the harness's own power, and every future shim implements
    # these few lines for itself.
    #
    # ASYMMETRIC, as identity is: blocking for a subagent, a warning for the
    # operator's own session. Refusing a subagent costs nothing. Refusing the
    # human stops them working on their own machine.
    #
    # AND IT FAILS OPEN. If the deployment is unreachable or the repository is
    # not linked, this warns and allows: an agent that can neither commit nor
    # sign is worse than an unsigned commit, and scripts/verify-branch.sh still
    # refuses to merge what was not signed.
    case "$CMD" in
      *"git commit"*|*"git "*" commit"*) : ;;
      *) exit 0 ;;
    esac
    # The signer does not shell out to `git commit` — sign_commit builds the
    # object inside the MCP — so this cannot block the signing path itself.
    case "$CMD" in *innsegl-commit*) exit 0 ;; esac

    SIGNER="$(signer)"
    if [ -z "$AGENT_ID" ]; then
      warn "this is a plain git commit. It will not carry an agent identity."
      warn "  $SIGNER -m \"...\" signs it instead."
      exit 0
    fi

    MARK="$(recall)"
    [ -n "$MARK" ] || { warn "no run for this agent, so signing is not available; allowing."; exit 0; }

    # NEVER BLOCK WITHOUT A WAY THROUGH. If the signer is not there, this agent
    # cannot sign no matter what it is told, and refusing would only lose the
    # work. The branch gate still refuses to merge what was not signed.
    if [ "$SIGNER" != "innsegl-commit" ] && [ ! -x "$SIGNER" ]; then
      warn "this commit will not carry an agent identity: the signer is not"
      warn "reachable at $SIGNER, so refusing would strand your work rather"
      warn "than sign it. Allowing, and scripts/verify-branch.sh will refuse"
      warn "to merge it."
      exit 0
    fi

    # THE RUN GOES IN THE INSTRUCTION, and this is what makes the commit the
    # AGENT's rather than a stranger's. Without -r the signer mints a fresh
    # throwaway identity per commit, so the work is attributed to something with
    # no link back to whoever produced it.
    GATE_RUN="$(reply_field "$MARK" run_id)"
    GATE_TASK="$(reply_field "$MARK" task)"
    # ONE MESSAGE, because the message IS the product. Each paragraph was added
    # after an agent did the wrong thing with a shorter one:
    #
    #   NOT `git add -A`. It said that once, and it was wrong twice over — it
    #   contradicts staging deliberately, and it arrives at the moment an agent
    #   is most suggestible, mid-refusal and looking for the shortest way out.
    #   An agent that stages everything sweeps up whatever else is in the tree.
    #
    #   THE WHOLE CALL WAS REFUSED, not the git part of it. A hook can allow or
    #   refuse a tool call; it cannot run half of one. A command that wrote a
    #   message file and then committed loses BOTH, and the agent's next move is
    #   to reach for the file it believes it just wrote. Measured in the field:
    #   the file did not exist, and the agent counted that as a second refusal
    #   rather than as a consequence of the first.
    #
    #   THE -r IS THIS RUN. Without it the signer mints a throwaway identity per
    #   commit and the work is credited to nobody in particular.
    cat >&2 <<EOF
innsegl: refused. Sign it under THIS agent's identity:
innsegl:
innsegl:   git add <the files you changed>
innsegl:   $SIGNER -r $GATE_RUN${GATE_TASK:+ -t $GATE_TASK} -m "<type>(<scope>): <what changed>"
innsegl:
innsegl: NOTHING in that command ran, not just the git part. If you were writing
innsegl: a message file in the same call, write it in its own call first -- then
innsegl: sign. Long messages: -F <file> rather than -m.
innsegl:
innsegl: The -r is this run. Without it the signer mints a throwaway identity
innsegl: and the work is credited to nobody in particular.
innsegl:
innsegl: The signer belongs to the innsegl deployment, not to the repository you
innsegl: are working in, so it is reachable from anywhere. It stages what you
innsegl: staged, signs under this run's identity, and logs it in Rekor. A plain
innsegl: commit produces work nobody can attribute, which is the one thing this
innsegl: deployment exists to prevent (IP §6.1).
EOF
    exit 2
    ;;

  *)
    exit 0
    ;;
esac
