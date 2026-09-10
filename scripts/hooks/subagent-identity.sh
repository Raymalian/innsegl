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
# tree_key turns a working tree into a stable file name. The RESOLVED path, so
# a symlinked route to the same tree does not look like a different one.
tree_key() {
  _t="$(CDPATH= cd -- "${1:-.}" 2>/dev/null && pwd -P)" || return 1
  [ -n "$_t" ] || return 1
  printf '%s' "$_t" | shasum -a 256 2>/dev/null | cut -c1-32
}

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

# run_id_of reads the run id out of a register_agent reply, in either of the
# two shapes the transport delivers: the SSE frame escapes the JSON inside a
# JSON string, and a direct reply does not. An empty answer is not an error
# here -- the caller decides what a missing run id means, and for a
# not-yet-restarted deployment it means "try again without ADR-0045's members".
run_id_of() {
  _out="$1"
  _id="$(printf '%s' "$_out" | sed -n 's/.*\\"run_id\\":\\"\([^\\]*\)\\".*/\1/p' | head -n 1)"
  [ -n "$_id" ] || _id="$(printf '%s' "$_out" | sed -n 's/.*"run_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
  printf '%s' "$_id"
}

# derive_task sets BRANCH, TASK and REPO from the MAIN worktree.
#
# A function because two events need it now: a subagent's registration and the
# operator's own session. It was inline in SubagentStart when only subagents
# had identities.
derive_task() {
  # `git worktree list` reports the main worktree first, from inside any
  # linked one, so this resolves the same branch wherever it runs.
  MAIN="$(git -C "${CWD:-.}" worktree list --porcelain 2>/dev/null | awk '/^worktree /{print $2; exit}')"
  [ -n "$MAIN" ] || MAIN="${CWD:-.}"
  # symbolic-ref before rev-parse: on an UNBORN branch -- a repository whose
  # first commit has not been made -- rev-parse fails and the branch would be
  # recorded as "detached", which under ADR-0045 is not a shrug in a log line
  # any more but a wrong value in an append-only record. symbolic-ref reads the
  # name HEAD points at whether or not anything is committed there yet.
  BRANCH="$(git -C "$MAIN" symbolic-ref --short --quiet HEAD 2>/dev/null)"
  [ -n "$BRANCH" ] || BRANCH="$(git -C "$MAIN" rev-parse --abbrev-ref HEAD 2>/dev/null)"
  # A genuinely detached HEAD has no branch, and "detached" is the honest
  # answer rather than a name: doc 02 stores `branch` verbatim, so inventing
  # one would put a branch in the ledger that does not exist.
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

  # THE REPOSITORY, as its own member (ADR-0045, schema 2).
  #
  # This used to be squeezed into task_id as a `<repo>-<branch>` prefix, and
  # the comment here said why: run_registered carried agent_type and task_ref
  # and NOTHING about the repository, doc 02 §3's fields are a protected
  # surface, and adding one would be a major version. Measured 2026-09-08,
  # five runs from other projects all read `main` with no repository and were
  # indistinguishable from each other.
  #
  # Schema 2 IS that major version, so the squeeze is gone and task_ref goes
  # back to naming the task -- which is ADR-0045's own consequence, written
  # down there before it was written here.
  #
  # doc 02 §5's grammar for `repo` is `host/org/name` with the HOST lowercased
  # and the other two left alone: `github.com/KodyMike/Repo` is correct and
  # lowercasing the org would be a repository that does not exist on a
  # case-sensitive forge.
  REPO="$(git -C "$MAIN" remote get-url origin 2>/dev/null \
    | sed -e 's|^[a-z][a-z0-9+.-]*://||' -e 's|^git@||' -e 's|:|/|' \
          -e 's|\.git$||' -e 's|/*$||')"
  case "$REPO" in
    */*/*)
      REPO="$(printf '%s' "$REPO" | awk -F/ '{
        h = tolower($1); p = $2
        for (i = 3; i <= NF; i++) p = p "/" $i
        print h "/" p
      }')"
      ;;
    # Not host/org/name: a local clone with no origin, or a remote in a shape
    # doc 02 §5 has no grammar for. Empty rather than guessed -- the tool
    # refuses a missing repo by name, which is a better failure than a
    # plausible wrong one in an append-only record.
    *) REPO="" ;;
  esac
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

    # THE ABSOLUTE PATH, resolved from this hook's own location.
    #
    # This said `scripts/innsegl-commit.sh`, which resolves only inside the
    # innsegl repository. Reported 2026-09-09 by an agent working in another
    # project: that project has no `scripts/` directory at all, so the refusal
    # pointed at a file that does not exist. The agent had nineteen finished
    # files and no way forward -- a gate that blocks and offers nothing is worse
    # than no gate, because the work is stranded rather than merely unsigned.
    # RESOLUTION ORDER, most portable first.
    #
    #   1  $INNSEGL_SIGNER            an operator who put it somewhere else
    #   2  innsegl-commit on PATH     `make innsegl-install-signer` puts it there
    #   3  this hook's own repository the fallback, and the only one that
    #                                 assumed a layout the agent may not have
    #
    # 2 is why this exists. The message named a path relative to the innsegl
    # repository, which an agent working anywhere else cannot resolve, and it
    # was pointed at a file that does not exist while holding finished work.
    if [ -n "${INNSEGL_SIGNER:-}" ] && [ -x "${INNSEGL_SIGNER}" ]; then
      SIGNER="$INNSEGL_SIGNER"
    elif command -v innsegl-commit >/dev/null 2>&1; then
      SIGNER="innsegl-commit"
    else
      SIGNER="$(CDPATH= cd -- "$(dirname -- "$0")/.." 2>/dev/null && pwd -P)/innsegl-commit.sh"
    fi

    if [ -z "$AGENT_ID" ]; then
      echo "innsegl: this is a plain git commit. It will not carry an agent identity." >&2
      echo "innsegl:   $SIGNER -m \"...\" signs it instead." >&2
      exit 0
    fi

    [ -f "$RUNFILE" ] || {
      echo "innsegl: no run for this agent, so signing is not available; allowing." >&2
      exit 0
    }

    # NEVER BLOCK WITHOUT A WAY THROUGH. If the signer is not there, this agent
    # cannot sign no matter what it is told, and refusing would only lose the
    # work. The branch gate still refuses to merge what was not signed, so the
    # guarantee is kept where it can be kept.
    if [ "$SIGNER" = "innsegl-commit" ] || [ -x "$SIGNER" ]; then :; else
      echo "innsegl: this commit will not carry an agent identity: the signer is not" >&2
      echo "innsegl: reachable at $SIGNER, so refusing would strand your work rather" >&2
      echo "innsegl: than sign it. Allowing, and scripts/verify-branch.sh will refuse" >&2
      echo "innsegl: to merge it." >&2
      exit 0
    fi

    # THE RUN GOES IN THE INSTRUCTION, and this is what makes the commit the
    # AGENT's rather than a stranger's.
    #
    # Without -r the signer mints a fresh throwaway identity per commit, so the
    # work is attributed to something with no link back to whoever produced it.
    # Measured 2026-09-09 in another project: 53 signed commits in the ledger,
    # every one of them under an ephemeral `orchestrator` or `signer` run, while
    # all 16 agent runs that did the work showed "Signed nothing". Attribution
    # existed and answered nothing.
    #
    # A shell command cannot discover which agent it is inside -- no environment
    # variable carries it. But this hook knows, because it wrote the marker at
    # SubagentStart, and this message is read by the model. So the identity
    # travels in the instruction.
    GATE_RUN="$(sed -n 1p "$RUNFILE" 2>/dev/null)"
    GATE_TASK="$(sed -n 4p "$RUNFILE" 2>/dev/null)"
    echo "innsegl: refused. Sign it under THIS agent's identity:" >&2
    echo "innsegl:" >&2
    # NOT `git add -A`. It said that, and it was wrong twice over: it
    # contradicts staging deliberately, and it arrives at the moment an agent
    # is most suggestible -- mid-refusal, looking for the shortest way out.
    # An agent that stages everything sweeps up whatever else is in the tree,
    # which is how a commit ends up carrying work nobody meant to sign.
    echo "innsegl:   git add <the files you changed>" >&2
    echo "innsegl:   $SIGNER -r $GATE_RUN${GATE_TASK:+ -t $GATE_TASK} -m \"<type>(<scope>): <what changed>\"" >&2
    echo "innsegl:" >&2
    echo "innsegl: The -r is this run. Without it the signer mints a throwaway" >&2
    echo "innsegl: identity and the work is credited to nobody in particular." >&2
    echo "innsegl:" >&2
    echo "innsegl: The signer belongs to the innsegl deployment, not to the repository" >&2
    echo "innsegl: you are working in, so it is reachable from anywhere. It stages what" >&2
    echo "innsegl: you staged, signs under this run's identity, and logs it in Rekor." >&2
    echo "innsegl: A plain git commit produces work nobody can attribute, which is the" >&2
    echo "innsegl: one thing this deployment exists to prevent (IP §6.1)." >&2
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

    # RETENTION, by age alone: 90 days and no other rule. A log whose depth
    # depends on how full the disk happens to be cannot be reasoned about, and
    # this one is evidence.
    #
    # WHAT EXPIRES AND WHAT NEVER DOES. Only the BODIES expire -- the commands,
    # the file contents, the chat-shaped detail of what an agent was doing.
    # Identity does not, and cannot: `run_registered`, the SPIFFE ID, the
    # Agent-Identity trailer and every digest live in the hash chain, which is
    # append-only by construction. So "who was this agent and what did it sign"
    # is answerable forever, and "what exactly did it type three months ago" is
    # not. That is the intended shape, not a limitation of it.
    #
    # Once per session rather than on every tool call. The policy is the same
    # -- nothing survives 90 days either way -- but a `find` across a quarter of
    # a year of files, run before every Edit, would be a tax on every keystroke.
    # Deleting a body is safe at any time: the chain keeps its digest.
    _log="${INNSEGL_LOG_DIR:-$HOME/.innsegl/log}"
    [ -d "$_log" ] && find "$_log" -type f -name '*.json' -mtime +"${INNSEGL_LOG_DAYS:-90}" -delete 2>/dev/null
    [ -d "$_log" ] && find "$_log" -type d -empty -delete 2>/dev/null

    derive_task

    OUT="$(mcp_call register_agent "$(printf \
      '{"agent_type":"%s","task_id":"%s","idempotency_key":"session-%s","repo":"%s","branch":"%s"}' \
      "${INNSEGL_SESSION_AGENT_TYPE:-session}" "$TASK" "$SESSION_ID" "$REPO" "$BRANCH")" 2>/dev/null)" || {
      echo "innsegl: no identity for this session — the deployment at $ADMIN_URL is not answering." >&2
      echo "innsegl:   Work is not blocked, but nothing you do here is in the ledger" >&2
      echo "innsegl:   until it is. Bring it up with: make innsegl-up-here" >&2
      exit 0
    }

    RUN_ID="$(run_id_of "$OUT")"
    # The session branch never blocks: refusing the operator's own session
    # stops them working on their own machine, and a session that could not
    # register simply has no identity to write down.
    if [ -z "$RUN_ID" ]; then
      OUT="$(mcp_call register_agent "$(printf \
        '{"agent_type":"%s","task_id":"%s","idempotency_key":"session-%s"}' \
        "${INNSEGL_SESSION_AGENT_TYPE:-session}" "$TASK" "$SESSION_ID")" 2>/dev/null)" || exit 0
      RUN_ID="$(run_id_of "$OUT")"
    fi
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

    # THE PARENT RUN, when this session has one.
    #
    # ADR-0045's third member, and the reason a `git log` can be read as a
    # tree rather than a list: without it a subagent's work and its
    # orchestrator's are two unrelated runs that happen to share a repository.
    # The session marker SessionStart wrote is where the parent's run id is,
    # and its absence is not an error -- a session with no parent is a root
    # run, which is why parent_run_id is the one optional member of the three.
    PARENT=""
    [ -f "$SESSIONFILE" ] && PARENT="$(head -n 1 "$SESSIONFILE" 2>/dev/null)"

    ARGS="$(printf '{"agent_type":"%s","task_id":"%s","idempotency_key":"%s","repo":"%s","branch":"%s"}' \
      "${AGENT_TYPE:-subagent}" "$TASK" "$KEY" "$REPO" "$BRANCH")"
    if [ -n "$PARENT" ]; then
      ARGS="$(printf '{"agent_type":"%s","task_id":"%s","idempotency_key":"%s","repo":"%s","branch":"%s","parent_run_id":"%s"}' \
        "${AGENT_TYPE:-subagent}" "$TASK" "$KEY" "$REPO" "$BRANCH" "$PARENT")"
    fi

    OUT="$(mcp_call register_agent "$ARGS")" || {
      echo "innsegl: refused — the identity service could not be reached at $ADMIN_URL." >&2
      echo "innsegl:   No identity, no attributed work (IP §6.1). Bring the deployment up:" >&2
      echo "innsegl:   make innsegl-up" >&2
      exit 2
    }

    RUN_ID="$(run_id_of "$OUT")"

    # A DEPLOYMENT THAT HAS NOT BEEN RESTARTED YET.
    #
    # The MCP SDK validates a call against the tool's advertised inputSchema
    # and refuses additional properties outright:
    #
    #   validating "arguments": validating root: unexpected additional
    #   properties ["repo" "branch"]
    #
    # So a hook carrying ADR-0045's members against a server that predates them
    # does not get a lesser identity, it gets NONE -- and a subagent with no
    # identity cannot commit at all, which is the one outcome this hook exists
    # to prevent. Registering without them writes the schema 1 event that
    # server still accepts: nothing is lost that was not already absent before
    # ADR-0045, and a restart restores the full record.
    if [ -z "$RUN_ID" ]; then
      OUT="$(mcp_call register_agent "$(printf \
        '{"agent_type":"%s","task_id":"%s","idempotency_key":"%s"}' \
        "${AGENT_TYPE:-subagent}" "$TASK" "$KEY")")" || true
      RUN_ID="$(run_id_of "$OUT")"
      [ -n "$RUN_ID" ] && echo "innsegl: this deployment records no repository for a run yet; restart it (make innsegl-up-here)." >&2
    fi

    if [ -z "$RUN_ID" ]; then
      echo "innsegl: refused — register_agent returned no run_id." >&2
      echo "innsegl:   $(printf '%s' "$OUT" | head -c 300)" >&2
      exit 2
    fi

    # THREE LINES, because SubagentStop has to find this agent's work and the
    # stop payload cannot be relied on to say where it was. The marker is
    # already being written here; it costs nothing to write down what was
    # resolved while it is still known.
    #
    #   1  run_id
    #   2  the main worktree, which is the repository sign_commit resolves
    #   3  this agent's worktree RELATIVE to it, empty when it shares the tree
    #   4  the task it was REGISTERED with -- sign_commit checks Agent-Task
    #      against the identity, and re-deriving it at stop reads the
    #      worktree's own branch instead of the one the run was minted from
    #   5  its agent_type -- the stop payload does not carry it, and a commit
    #      message that says "work left by  run ..." has a hole in it
    REL=""
    case "$CWD" in
      "$MAIN") : ;;
      "$MAIN"/*) REL="${CWD#"$MAIN"/}" ;;
    esac
    printf '%s\n%s\n%s\n%s\n%s\n' "$RUN_ID" "$MAIN" "$REL" "$TASK" "$AGENT_TYPE" > "$RUNFILE"

    # AND A POINTER KEYED BY THE WORKING TREE.
    #
    # This is what makes attribution automatic instead of remembered. A shell
    # command cannot discover which agent it is inside -- no environment
    # variable carries an agent or session id, checked -- so innsegl-commit
    # used to mint a throwaway identity per commit. Measured 2026-09-09 in
    # another project: 53 signed commits, every one under an ephemeral run,
    # while all 16 agent runs that did the work showed "Signed nothing".
    # Attribution existed and answered nothing.
    #
    # The tree is the one thing both sides can see. The hook knows which run
    # works in which directory; the signer knows which directory it is in.
    tree_key "$CWD" > /dev/null 2>&1 && {
      mkdir -p "$RUNS_DIR/by-tree" 2>/dev/null
      # THREE lines: the run, its task, and the worktree RELATIVE to the
      # repository. The third is not optional -- sign_commit runs `git commit`
      # in the tree it resolves from the repo id, so an agent working in a
      # linked worktree must say which one, or the index it staged and the
      # index that gets committed are different trees (MCP-029).
      printf '%s\n%s\n%s\n' "$RUN_ID" "$TASK" "$REL" > "$RUNS_DIR/by-tree/$(tree_key "$CWD")" 2>/dev/null || true
    }
    echo "innsegl: $AGENT_TYPE is $RUN_ID (task $TASK)" >&2
    exit 0
    ;;

  SubagentStop)
    [ -f "$RUNFILE" ] || exit 0
    RUN_ID="$(sed -n 1p "$RUNFILE")"
    MAIN="$(sed -n 2p "$RUNFILE")"
    REL="$(sed -n 3p "$RUNFILE")"
    TASK="$(sed -n 4p "$RUNFILE")"
    [ -n "$AGENT_TYPE" ] || AGENT_TYPE="$(sed -n 5p "$RUNFILE")"
    rm -f "$RUNFILE"
    # The pointer goes with the run. A stale one would credit this agent for
    # work done after it stopped.
    if [ -n "$MAIN" ]; then
      _k="$(tree_key "${REL:+$MAIN/$REL}${REL:-$MAIN}")" 2>/dev/null
      [ -n "$_k" ] && rm -f "$RUNS_DIR/by-tree/$_k" 2>/dev/null
    fi
    [ -n "$RUN_ID" ] || exit 0

    # CAPTURE WHAT THIS AGENT LEFT, in the order the operator asked for.
    #
    # ADR-0046. Measured 2026-09-08: subagents had 314 Edit and 33 Write calls
    # and zero commits. The work was never lost -- it sat in the worktree -- but
    # it was never attributed to the agent that did it either, and an
    # orchestrator committing it later signs it as its own.
    #
    # NOTHING HERE EVER EXITS 2. Blocking on stop produced a nine-deep retry
    # storm once already. Every failure below warns and gets out of the way.
    capture_dir="${MAIN:-}"
    [ -n "$REL" ] && capture_dir="$MAIN/$REL"
    if [ -n "$capture_dir" ] && [ -d "$capture_dir" ]; then
      # 1. did it already commit under its own identity? Ask the ledger, not
      #    the worktree: a commit that was signed and then had its branch moved
      #    is still this run's commit.
      committed="$(curl -sS --max-time 5 \
        "${INNSEGL_API_URL:-http://127.0.0.1:8082}/api/v1/runs/$RUN_ID" 2>/dev/null \
        | sed -n 's/.*"commits"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -n 1)"
      # 2. is there anything to capture at all?
      dirty="$(git -C "$capture_dir" status --porcelain 2>/dev/null | wc -l | tr -d ' ')"

      if [ "${committed:-0}" = "0" ] && [ "${dirty:-0}" != "0" ]; then
        echo "innsegl: $RUN_ID left $dirty uncommitted path(s) and signed nothing; capturing" >&2
        git -C "$capture_dir" add -A 2>/dev/null || true
        if command -v innsegl-commit >/dev/null 2>&1; then
          CAPTURE_SIGNER="innsegl-commit"
        else
          CAPTURE_SIGNER="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)/../innsegl-commit.sh"
        fi
        MSG="chore(agent): work left by $AGENT_TYPE run $RUN_ID

Captured by the harness at SubagentStop because the run ended with $dirty
uncommitted path(s) and no commit of its own. Signed under that run's identity
so the work is attributed to the agent that did it rather than to whoever
commits next (ADR-0046).

The build was not run. A subagent's work is recorded as it was left; the branch
gate is what decides whether it may merge."
        # 3. sign it under THIS RUN, not a new one -- and do not retire it here,
        #    the retirement below is the one that belongs to this stop.
        if ( cd "$capture_dir" && "$CAPTURE_SIGNER" \
               -r "$RUN_ID" ${TASK:+-t "$TASK"} ${REL:+-w "$REL"} -m "$MSG" ) >&2 2>&1; then
          :
        else
          # 4. the orchestrator's fallback. The work stays staged and a marker
          #    names it, so the next session signs it with this run named
          #    rather than losing the attribution entirely.
          mkdir -p "$RUNS_DIR/pending" 2>/dev/null || true
          printf '%s\n%s\n%s\n%s\n' "$RUN_ID" "$capture_dir" "$dirty" "$AGENT_TYPE" \
            > "$RUNS_DIR/pending/$RUN_ID" 2>/dev/null || true
          echo "innsegl: could not sign $RUN_ID's work; left staged and recorded in" >&2
          echo "innsegl:   $RUNS_DIR/pending/$RUN_ID" >&2
        fi
      fi
    fi

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

    # AND THE BODY, LOCALLY, because the ledger may never hold it.
    #
    # A tool_call event says `"tool_name": "Edit"` and a digest. It does not say
    # which file or what changed, and it never will: doc 02 §3 gives the body no
    # member and IP E4 makes that mechanical. That is not an oversight to route
    # around -- the chain is append-only, so anything written there can never be
    # deleted, and this is data with a 90-day life.
    #
    # So the two halves live apart, and the split pays for itself: the digest in
    # the chain PROVES this file has not been altered, and deleting the file
    # later breaks nothing, because verification reads the digest and not the
    # body.
    #
    # The name IS the digest, so a reader needs no index to check one.
    #
    # ON DISK IN THE CLEAR. These bodies carry tool inputs -- file contents,
    # commands, paths. That is the point of keeping them and the reason they
    # stay on the operator's own machine and are never sent anywhere.
    if [ -n "${INNSEGL_LOG_DIR:-$HOME/.innsegl/log}" ]; then
      _d="${INNSEGL_LOG_DIR:-$HOME/.innsegl/log}/$RUN_ID"
      if mkdir -p "$_d" 2>/dev/null; then
        printf '%s' "$EVENT_JSON" > "$_d/$(printf '%s' "$DIGEST" | cut -c8-).json" 2>/dev/null || true
      fi
    fi

    # ALWAYS 0. See the header: the identity is load-bearing and was checked at
    # start; a bookkeeping write is not, and must never hold up an agent's work.
    exit 0
    ;;

  *)
    exit 0
    ;;
esac
