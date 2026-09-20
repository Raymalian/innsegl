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
#   INNSEGL_UNCAPTURED_LOG  default $INNSEGL_RUNS_DIR/uncaptured.jsonl — where a
#                           stop-time capture that did NOT happen is written
#                           down, because a stop's stderr is discarded (#277)
#   INNSEGL_GIT_GUARD       1. Set to 0 to stop consulting the destructive-git
#                           guard on PreToolUse (#278)
#   INNSEGL_GIT_GUARD_SCRIPT  default this file's sibling git-tree-guard.sh
#
# Needs `python3` and `curl`. python3 does the JSON in both directions, which
# is what removed the `sed`-and-`printf` parsing the old file used: a branch
# name carrying a quote used to build a malformed request, and the transport's
# two reply shapes needed two regexps that had to be kept in step.
#
# # Presenting a credential — #266
#
# #264's listener answers an unauthenticated caller with one byte-identical
# 401, before the MCP session layer, so `initialize` is refused on the same
# terms as a tool call. Four decisions, and each is the cheap half of a pair:
#
#   WHO MINTS. This file, for itself, by running the shipped
#   `innsegl admin-credential mint` inside a throwaway container that mounts the
#   deployment's private signing key READ-ONLY and has no network at all. The
#   key is never copied onto this machine's filesystem and this file never sees
#   it; the only value that crosses the boundary is the credential, on a pipe.
#   A long-lived minting service would be a standing mint oracle; a container
#   that lives for a fifth of a second and is reachable only through the Docker
#   API adds no privilege that API did not already carry.
#
#   HOW OFTEN. Never, unless the listener refuses. The first attempt of a hook
#   carries no credential; a 401 — and nothing else — mints one and repeats the
#   same call exactly once. A deployment that does not enforce makes no 401,
#   mints nothing and costs nothing, so single-listener mode is unchanged by
#   construction rather than by a flag someone has to set correctly.
#
#   WHAT EXPIRY DOES. Nothing special, which is the point. A hook is a
#   short-lived process, so within one the question rarely arises; when it does
#   — the SubagentStop path can spend minutes signing an agent's leftover work
#   before it retires the run — the next call is refused, a fresh credential is
#   minted, and the call is repeated. No clock is read here and no `exp` is
#   parsed: the server's own refusal is the only trigger, so there is never a
#   second opinion about when a credential died.
#
#   WHERE IT IS KEPT. In one shell variable, for the life of one process. Not
#   exported, so it reaches no child but the one handed it; not written, so no
#   marker and no file on this machine holds it; not logged; and never in an
#   argument vector — it travels to the client on STDIN, because `ps` shows the
#   arguments of every process on this machine and a bearer token there is
#   replayable for the rest of its fifteen minutes.
#
# AND A STOP STILL NEVER BLOCKS. A stop that cannot authenticate warns and exits
# 0 like every other stop failure: the run expires on its TTL, which is what the
# reaper is for, and a blocked stop was measured producing nine invocations.
#
# # Two rules that are not negotiable
#
# NEVER `exit 2` ON A STOP PATH. Measured: a blocked stop produced NINE repeated
# invocations before the harness gave up — a retry storm, not a refusal. Every
# failure on a stop path warns and exits 0. The run expires on its TTL, which is
# what the TTL is for.
#
# THE CREDENTIAL IS MINTED, NEVER KEPT — #266. #264 put a repository-scoped
# credential in front of all six identity-lifecycle tools, and every call this
# file makes is to one of them. Measured before #266: `grep -c Authorization`
# here returned 0, so the check could not be deployed without silencing every
# registration on the machine. See "Presenting a credential" below.
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
# WHAT THE TOOL DID, AND NOT ONLY WHAT IT WAS ASKED TO DO -- RM-182 (#290). A
# kill is the one thing this shim acts on that it did not itself cause, so what
# it acts on is the report that the kill HAPPENED. A result that is not an
# object leaves all three of these empty, and empty retires nothing.
tool_result = event.get("tool_response")
if not isinstance(tool_result, dict):
    tool_result = {}
for name, value in (
    ("EVENT", event.get("hook_event_name")),
    ("SESSION_ID", event.get("session_id")),
    ("AGENT_ID", event.get("agent_id")),
    ("AGENT_TYPE", event.get("agent_type")),
    ("CWD", event.get("cwd")),
    ("TOOL", event.get("tool_name")),
    ("CMD", tool_input.get("command")),
    ("TASK_ID", tool_input.get("task_id")),
    ("STOPPED_ID", tool_result.get("task_id")),
    ("STOPPED_TYPE", tool_result.get("task_type")),
    ("STOPPED_ERR", "1" if tool_result.get("error") else ""),
):
    print(name + "=" + shlex.quote(value if isinstance(value, str) else ""))
' 2>/dev/null)"
# A missing python3 leaves every one of them unset, and `set -u` would then kill
# the hook rather than let it get out of the way.
: "${EVENT:=}" "${SESSION_ID:=}" "${AGENT_ID:=}" "${AGENT_TYPE:=}" "${CWD:=}" "${TOOL:=}" "${CMD:=}"
: "${TASK_ID:=}" "${STOPPED_ID:=}" "${STOPPED_TYPE:=}" "${STOPPED_ERR:=}"

# THE KEY THIS EVENT IS ABOUT, because there are two kinds of run: a subagent's,
# and the operator's own session. Until #182 only the first existed and the hook
# exited whenever agent_id was absent — which is every event the main session
# fires, so work in one repository produced no run at all.
if [ -n "$AGENT_ID" ]; then
  KEY="$AGENT_ID"
else
  KEY="session-${SESSION_ID:-unknown}"
fi

# THE ID THE MCP KNOWS THIS RUN BY, which is not the marker's filename above.
# SubagentStart calls observe_session with the AGENT id and SessionStart with
# the SESSION id, so anything naming a run by session has to make the same
# choice or it names the wrong one. Passing $SESSION_ID unconditionally would
# attribute a subagent's tool calls to the run of the session that spawned it —
# caught by the selftest, and the reason this is one variable and not a
# decision repeated at each call site.
if [ -n "$AGENT_ID" ]; then
  IDENT="$AGENT_ID"
  IDENT_TYPE="${AGENT_TYPE:-subagent}"
else
  IDENT="$SESSION_ID"
  IDENT_TYPE="${INNSEGL_SESSION_AGENT_TYPE:-session}"
fi

# THE SESSION THAT STARTED THIS ONE, in this harness's own vocabulary — and
# nothing more than that. RM-156 (#259).
#
# This used to be a LOOKUP. The shim read a sibling marker file out of its own
# cache and sent the run id it found there, which worked on the one path it was
# written for: measured, 21 registrations out of 185 carried a parent and every
# one came through SubagentStart. The first-sight registration a tool call
# makes had none, because this file has no run id to give it at that point, and
# neither has any other harness.
#
# So the lookup moved into the MCP, which is the only component holding the
# durable session → run mapping. What is left here is the identifier this
# harness already has. A subagent's parent is the session that spawned it; the
# operator's own session has no parent, and absent is not an error — mcp_call
# omits an empty value rather than sending one, and doc 02 §1 distinguishes
# absent from empty.
if [ -n "$AGENT_ID" ]; then
  PARENT_IDENT="$SESSION_ID"
else
  PARENT_IDENT=""
fi
# A harness that reports one id for both is reporting no parent. Sending it
# would be a session naming itself, which the MCP refuses — and a refused
# SubagentStart is a subagent that does no work.
[ "$PARENT_IDENT" != "$IDENT" ] || PARENT_IDENT=""

# tree_key names the pointer a working tree is indexed by, in one place.
#
# Three callers now write or remove one — SessionStart, SubagentStart and
# SubagentStop — and scripts/innsegl-commit.sh reads them. A derivation
# repeated at each site is a derivation that can disagree at one of them, and a
# pointer written under a key nobody reads is silent: attribution simply goes
# back to being a throwaway identity per commit.
tree_key() {
  _t="$(CDPATH= cd -- "${1:-.}" 2>/dev/null && pwd -P)"
  [ -n "$_t" ] || return 1
  printf '%s' "$_t" | shasum -a 256 2>/dev/null | cut -c1-32
}

warn() { echo "innsegl: $*" >&2; }

# say_detail passes on a reply's `detail`, which is how observe_session reports
# what a call could not finish WITHOUT refusing — a stop that blocks is answered
# by a harness with a retry storm, not with a fix. Always returns 0, so it can
# end a branch without deciding it.
say_detail() { _d="$(reply_field "$1" detail)"; [ -n "$_d" ] && warn "  $_d"; return 0; }

# ---------------------------------------------------------------------------
# #266 — THE CREDENTIAL. One variable, one mint, written nowhere.
# ---------------------------------------------------------------------------

# Not exported. `export` here would hand the credential to every child this
# hook runs — git, curl, shasum, the signer — and to anything they run, which
# is precisely "an environment variable that outlives the call".
ADMIN_CRED=""
CRED_REPO=""
CRED_REMEDY_SAID=""

# Where this deployment's private signing key lives, as deploy/compose's own
# volume and image names. Both overridable for a deployment that renamed either.
ADMIN_KEY_VOLUME="${INNSEGL_ADMIN_KEY_VOLUME:-${COMPOSE_PROJECT_NAME:-innsegl-core}_innsegl-admin-key}"
ADMIN_KEY_PATH="${INNSEGL_ADMIN_KEY_PATH:-/k/signing.key}"
ADMIN_IMAGE="${INNSEGL_IMAGE:-innsegl:local}"

# repo_id_of prints doc 02 §5's host/org/name for a working tree, or nothing.
#
# THIS IS THE ONE DERIVATION E11 COULD NOT TAKE, and it is here for a reason
# that does not apply to branch, task or worktree: those are things the ledger
# records and `describe_workspace` answers, while this names the repository a
# CREDENTIAL AUTHORISES — and the credential has to exist before the call that
# would ask. There is no order of operations in which the server answers it.
#
# `git remote get-url` and not `git config --get remote.origin.url`, because
# the MCP's own repoIDFromWorktree uses the former: only it applies an
# operator's `insteadOf` rewrites, and a caller that skipped them would derive
# a repository the server does not agree with — refused, with a listener that
# by design will not say why. scripts/innsegl-commit.sh carries the same
# pipeline and shim-selftest.sh pins the two against each other.
#
# doc 02 §5 lowercases the HOST and leaves the org and the name alone, so
# `github.com/Example-Org/Example-Repo` is correct and lowercasing all three
# names a repository that does not exist on a case-sensitive forge.
repo_id_of() {
  [ -n "${1:-}" ] && [ -d "$1" ] || return 1
  git -C "$1" remote get-url origin 2>/dev/null \
    | sed -e 's|^[a-z][a-z0-9+.-]*://||' -e 's|^git@||' -e 's|:|/|' -e 's|\.git$||' -e 's|/*$||' \
    | awk -F/ 'NF>=3 { h = tolower($1); p = $2; for (i = 3; i <= NF; i++) p = p "/" $i; print h "/" p }'
}

# cred_repo prints the repository a credential for this event must authorise.
#
# FOUR SOURCES, MOST AUTHORITATIVE FIRST, because a stop carries no cwd:
#
#   1  INNSEGL_REPO_ID     an operator who has said it outright
#   2  the marker's `repo` THE MCP'S OWN ANSWER, recorded at registration. This
#                          is the one that cannot disagree with the server, so
#                          it is preferred over anything derived here.
#   3  the harness's cwd   what every start and every PostToolUse carries
#   4  the marker's `dir`  where the harness said the run was working, which is
#                          what a SubagentStop has instead of a cwd
#
# Answered once and remembered for the process; a hook handles one event about
# one repository.
cred_repo() {
  [ -n "$CRED_REPO" ] && { printf '%s' "$CRED_REPO"; return 0; }
  if [ -n "${INNSEGL_REPO_ID:-}" ]; then
    CRED_REPO="$INNSEGL_REPO_ID"
  else
    _mark="$(recall)"
    CRED_REPO="$(reply_field "${_mark:-}" repo)"
    if [ -z "$CRED_REPO" ]; then
      for _d in "$CWD" "$(reply_field "${_mark:-}" dir)" "$PWD"; do
        [ -n "$_d" ] || continue
        CRED_REPO="$(repo_id_of "$_d")"
        [ -n "$CRED_REPO" ] && break
      done
    fi
  fi
  [ -n "$CRED_REPO" ] || return 1
  printf '%s' "$CRED_REPO"
}

# mint_admin_credential fills $ADMIN_CRED, or says what to run and fails.
#
# THE KEY IS READ WHERE IT LIVES. The deployment's one-shot writes it 0400 and
# root-owned onto a volume nothing else in the stack mounts; this runs the
# shipped mint command against that volume READ-ONLY, in a container with no
# network, no writable root filesystem and no privilege escalation, which
# prints one credential and exits. `--user 0:0` because 0400 root-owned is the
# point — the image's own 1000:1000 cannot read it, so neither could a
# compromised innsegl-mcp, which does not mount this volume at all.
#
# A TIMEOUT WHEN THE SYSTEM HAS ONE. A wedged container runtime must not wedge
# a harness hook; where `timeout` is absent the mint is still bounded by docker
# failing fast against a daemon that is not there.
mint_admin_credential() {
  _scope="$(cred_repo)" || {
    warn "no repository could be named for this event, so no credential can be minted for it"
    return 1
  }
  _limit=""
  command -v timeout >/dev/null 2>&1 && _limit="timeout ${INNSEGL_ADMIN_CREDENTIAL_TIMEOUT:-20}"
  ADMIN_CRED=""
  if [ -n "${INNSEGL_ADMIN_CREDENTIAL_MINT:-}" ]; then
    # An operator whose signing key is not on this machine's container volume:
    # any command that prints one credential for the repository it is given.
    # Deliberately word-split — a command with its own arguments is the normal
    # case.
    ADMIN_CRED="$($INNSEGL_ADMIN_CREDENTIAL_MINT "$_scope" 2>/dev/null)" || ADMIN_CRED=""
  elif command -v docker >/dev/null 2>&1; then
    # shellcheck disable=SC2086
    ADMIN_CRED="$($_limit docker run --rm --network none --read-only --user 0:0 \
      --security-opt no-new-privileges \
      -v "$ADMIN_KEY_VOLUME:$(dirname "$ADMIN_KEY_PATH"):ro" \
      "$ADMIN_IMAGE" \
      admin-credential mint -key "$ADMIN_KEY_PATH" -repo "$_scope" 2>/dev/null)" || ADMIN_CRED=""
  fi
  ADMIN_CRED="$(printf '%s' "$ADMIN_CRED" | tr -d '\r\n')"
  [ -n "$ADMIN_CRED" ] || { credential_remedy "$_scope"; return 1; }
  return 0
}

# credential_remedy — a refusal that says what to run, once per process.
#
# The listener answers every credential failure with one byte-identical
# sentence, because a distinguishable reason is an oracle over which audiences
# and repositories exist. That makes THIS the only place an operator can be
# told what to do, and a 401 with no remedy strands an agent holding finished
# work.
credential_remedy() {
  [ -z "$CRED_REMEDY_SAID" ] || return 0
  CRED_REMEDY_SAID=1
  warn "the identity lifecycle at $ADMIN_URL requires a repository-scoped"
  warn "  credential and none could be minted for ${1:-this repository}."
  warn ""
  warn "  Mint one against this deployment's signing key:"
  warn "    docker run --rm --network none --user 0:0 \\"
  warn "      -v $ADMIN_KEY_VOLUME:$(dirname "$ADMIN_KEY_PATH"):ro $ADMIN_IMAGE \\"
  warn "      admin-credential mint -key $ADMIN_KEY_PATH -repo ${1:-<host/org/name>}"
  warn ""
  warn "  The key is written by the deployment's own one-shot, so an empty"
  warn "  volume means the stack has never been up with the lifecycle split:"
  warn "    make innsegl-up"
  warn ""
  warn "  Minting elsewhere: set INNSEGL_ADMIN_CREDENTIAL_MINT to a command"
  warn "  that prints one credential for the repository it is given."
  warn ""
  warn "  The listener will never say why one is inadmissible. Ask on this"
  warn "  machine instead: innsegl admin-credential verify -jwks <set>"
}

# One MCP call: mcp_call <tool> <name> <value> ... → the tool's result object.
#
# THE REFUSAL IS THE ONLY TRIGGER (#266). The first attempt carries whatever
# credential is held, which on a fresh hook is none; status 3 means the
# listener refused one, and the answer is to mint and repeat the SAME call
# once. That one branch covers every case there is: a listener that enforces,
# a credential that aged out between two calls of a long stop, and a
# deployment that enforces nothing — which never returns 3, so never mints.
#
# EXACTLY ONCE, because a loop here is a loop against a server that has already
# said no.
mcp_call() {
  _tool="$1"
  shift
  _out="$(printf '%s\n' "$ADMIN_CRED" | python3 -c "$MCP_CLIENT" "$ADMIN_URL" "$_tool" "$@" 2>/dev/null)"
  _rc=$?
  if [ "$_rc" -eq 3 ] && mint_admin_credential; then
    _out="$(printf '%s\n' "$ADMIN_CRED" | python3 -c "$MCP_CLIENT" "$ADMIN_URL" "$_tool" "$@" 2>/dev/null)"
    _rc=$?
    [ "$_rc" -eq 3 ] && credential_remedy "$CRED_REPO"
  fi
  printf '%s' "$_out"
  return "$_rc"
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
#
# EVERY VALUE IS A STRING EXCEPT `bool:true` AND `bool:false`, which are sent as
# JSON booleans. A tool schema that declares a boolean refuses the string
# "true", and the refusal would arrive as a stop that did not happen — silent,
# because a stop never blocks. The prefix is explicit rather than inferred:
# coercing every value that happens to read `true` would rewrite a harness
# event body, a task or a branch name that spelled it.
MCP_CLIENT='
import json, sys, urllib.error, urllib.request

url, tool = sys.argv[1], sys.argv[2]
args = {}
for name, value in zip(sys.argv[3::2], sys.argv[4::2]):
    if value == "":
        continue
    args[name] = value == "bool:true" if value in ("bool:true", "bool:false") else value

# THE CREDENTIAL ARRIVES ON STDIN and reaches no other surface (#266). Not in
# argv, which `ps` publishes to every process on this machine; not in the
# environment, which /proc publishes to every process of this user; not in a
# file, which outlives both. One line, read once, held in one local.
credential = sys.stdin.readline().strip()

def post(payload, session=None, timeout=60):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers={
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream"})
    if session:
        req.add_header("Mcp-Session-Id", session)
    if credential:
        req.add_header("Authorization", "Bearer " + credential)
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
except urllib.error.HTTPError as refused:
    # 3, AND NOTHING ELSE IS READ FROM IT. #264 wraps the whole admin handler,
    # so the refusal may land on `initialize` or on the call itself; either way
    # the body is one byte-identical sentence that says nothing about what was
    # wrong, and the caller mints a credential and repeats the call. Every
    # other status is a transport failure like any other.
    sys.exit(3 if refused.code == 401 else 1)
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

#
# AND WHICH HARNESS SESSION OWNS THE RUN -- RM-182 (#290). This is ONE directory
# for every session on the machine, and other repositories have sessions with
# live runs in it right now, with real processes behind them. The kill path
# below reaches a marker by a name a MODEL supplied, so "whose run is this" has
# to be answerable from the marker itself rather than from where it happens to
# sit. The answer is the session this hook is running in: a subagent is owned by
# the session that spawned it, and a session is owned by itself.
#
# A MARKER THAT RECORDS NO OWNER IS NOT THIS SESSION'S. Every marker written
# before this change has none, and the kill path reads absent as "not mine" --
# which retires nothing, silently, and leaves the reaper answering for it
# exactly as it did before. Safe is the silent direction: the run may still be
# working.
remember() {
  mkdir -p "$RUNS_DIR" 2>/dev/null || return 1
  # 0600: this file names a run a reader could then sign under.
  ( umask 077; printf '%s' "$1" | python3 -c '
import json, sys
body = json.load(sys.stdin)
body["dir"] = sys.argv[1]
body["owner_session"] = sys.argv[2]
print(json.dumps(body))
' "$2" "$SESSION_ID" > "$MARKER" ) 2>/dev/null
}

recall() { cat "$MARKER" 2>/dev/null; }

# THE PARENT LOOKUP THAT USED TO BE HERE IS GONE — RM-156 (#259).
#
# It read a sibling marker file, pulled `run_id` out of it, and sent that run id
# to observe_session. Everything about it was right except where it lived: it
# resolved a run, which is the one thing E11 says no harness should have to
# know about, and so the two registration paths that hold no run id — the
# first-sight registration a tool call makes, and the signer — could not have
# an edge at all. See PARENT_IDENT above: this file now forwards the session
# identifier it already has, and the MCP resolves it.

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

# ---------------------------------------------------------------------------
# WHAT A STOPPING RUN CAN ACCOUNT FOR — #261 (RM-158).
#
# THE BOUND IS ON THE COMMIT, NOT ON THE `git add`. That distinction is the
# whole of this change and the first fix missed it: a bound was added that read
# the run's own tool-call bodies and staged only the files they named, it passed
# 27 assertions, and a nine-file capture went through it days later. `git add`
# REMOVES NOTHING, and the capture commits the INDEX — so anything another party
# had already staged was committed under the stopping run regardless of what the
# bound picked. The test proved the bound chose the right files. It never asked
# what was committed.
#
# So the question this answers is not "which files may I add" but "is everything
# that would be COMMITTED something this run can show it wrote". If the answer
# is no, the whole capture is refused (issue #261, option 3) and the work stays
# exactly where it was, staged, with the run named so it can be signed later.
#
# NOTHING IS GUESSED FROM A SHELL COMMAND, and that is deliberate rather than
# unfinished. The measured run made 62 `Bash` calls, 27 of which write to a file
# through `>`, `>>` or a heredoc, against 1 `Write` and 1 `Edit` — so the record
# of what an agent wrote is structurally incomplete, exactly as the header says.
# The available answer would be to parse redirections out of the commands and
# stage what they seem to name. That is `git add -A` with more steps: it takes a
# shell grammar this file cannot evaluate — variables, pipelines, `cd`, a
# command substitution that prints a path — and turns a guess into a signature
# that verifies forever under a named identity. A run whose writes went through
# `Bash` therefore accounts for nothing, its capture is refused, and the refusal
# says which run to sign the work under. Under-capturing leaves work unsigned;
# over-capturing signs a lie.
#
# It answers with eight variables rather than a status, because every caller
# below needs the counts to say anything useful to the operator:
#
#   ACC_TOP            the repository's own tree, which is what the index is of
#   ACC_READ           1 if the run has a body store to be asked at all
#   ACC_INDEX          1 if the index could be read
#   ACC_WROTE          its writes, one per line, relative to ACC_TOP
#   ACC_WROTE_N        how many
#   ACC_STAGED_N       how many paths the index holds
#   ACC_UNACCOUNTED_N  how many of those the run cannot show it wrote
#   ACC_UNACCOUNTED    the first of them, for a message a human can act on
#
# THE REPOSITORY'S TREE AND NOT THE EVENT'S cwd. `git diff --cached` names paths
# from the top of the worktree while `git add` reads them from wherever it is
# run, so a harness working in a subdirectory would compare two different
# spellings of the same file and find every one of them unaccounted for.
CAPTURE_ACCOUNT='
import json, os, pathlib, shlex, subprocess, sys

bodies, cwd = sys.argv[1], sys.argv[2]

def git(where, *args):
    return subprocess.run(("git", "-C", where) + args, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, timeout=60
                          ).stdout.decode("utf-8", "replace")

top, read, index, wrote, staged = "", "0", "0", set(), []
try:
    top = git(cwd, "rev-parse", "--show-toplevel").strip()
except Exception:
    top = ""
if top:
    top = os.path.realpath(top)
    if os.path.isdir(bodies):
        read = "1"
        for f in sorted(pathlib.Path(bodies).glob("*.json")):
            try:
                d = json.loads(f.read_text())
            except Exception:
                continue
            # THE THREE TOOLS THAT NAME A FILE. A Bash command names none, and
            # is not read: see the comment above for why guessing is worse than
            # refusing.
            if d.get("tool_name") not in ("Edit", "Write", "NotebookEdit"):
                continue
            fp = (d.get("tool_input") or {}).get("file_path")
            if not isinstance(fp, str) or not fp:
                continue
            real = os.path.realpath(fp if os.path.isabs(fp) else os.path.join(cwd, fp))
            if real.startswith(top + os.sep):
                wrote.add(os.path.relpath(real, top))
    try:
        # -z, so a path carrying a quote or a space arrives as one value. Without
        # it git quotes such a name and the comparison below never matches it,
        # which would read as unaccounted and refuse every capture in that tree.
        staged = [p for p in git(top, "diff", "--cached", "--name-only", "-z").split("\0") if p]
        index = "1"
    except Exception:
        index = "0"

unaccounted = sorted(set(staged) - wrote)
for name, value in (
    ("ACC_TOP", top),
    ("ACC_READ", read),
    ("ACC_INDEX", index),
    ("ACC_WROTE", "\n".join(sorted(wrote))),
    ("ACC_WROTE_N", str(len(wrote))),
    ("ACC_STAGED_N", str(len(staged))),
    ("ACC_UNACCOUNTED_N", str(len(unaccounted))),
    ("ACC_UNACCOUNTED", "\n".join(unaccounted[:10])),
):
    print(name + "=" + shlex.quote(value))
'

# capture_account <body dir> <the tree the run worked in> → the variables above.
#
# Defaulted BEFORE the eval, so a machine with no python3, a body store that
# cannot be read or a tree that is not a repository leaves the caller looking at
# "nothing is accounted for" — which refuses — rather than at `set -u` killing
# the stop. A stop never blocks, and a stop that died here would leave the run
# Active for the reaper.
capture_account() {
  ACC_TOP=""; ACC_READ=0; ACC_INDEX=0; ACC_WROTE=""; ACC_WROTE_N=0
  ACC_STAGED_N=0; ACC_UNACCOUNTED_N=0; ACC_UNACCOUNTED=""
  eval "$(python3 -c "$CAPTURE_ACCOUNT" "$1" "$2" 2>/dev/null)"
}

# capture_remedy — what a refused capture leaves the operator holding.
#
# A REFUSAL THAT STRANDS THE WORK IS WORSE THAN THE MISATTRIBUTION IT PREVENTS.
# The run is gone by the time this prints; the only party left who can sign its
# work is whoever reads this line, and they need the run id, because without
# `-r` the signer mints a throwaway identity and the work is credited to nobody.
# So this names the run, the tree, and the command — and it changes nothing on
# disk, so what was staged is still staged.
capture_remedy() {
  warn ""
  warn "  Nothing was staged or unstaged; the work is where you left it."
  warn "  $RUN_ID wrote ${ACC_WROTE_N:-0} path(s) in that tree. To sign its own work under it:"
  warn "    cd $DIR"
  warn "    git add <the paths that run wrote>"
  warn "    $(signer) -r $RUN_ID${TASK:+ -t $TASK} -m \"<type>(<scope>): <what changed>\""
  warn "  Whatever else is in the index belongs to whoever staged it, and signing"
  warn "  it under this run would attribute their work to this agent (#261)."
}

# ---------------------------------------------------------------------------
# WHETHER THERE IS ANYTHING TO CAPTURE, AND WHETHER THAT WAS ANSWERED — #284
# (RM-178).
#
# This was one line:
#
#   dirty="$(git -C "$DIR" status --porcelain 2>/dev/null | wc -l | tr -d ' ')"
#
# and the pipe threw away the only thing that could tell the two cases apart. A
# `git status` that FAILS prints nothing, `wc -l` counts nothing, and the count
# reads 0 — so a tree with nothing in it and a tree that could not be read
# became the same answer, and the branch below concluded there was nothing to
# capture. No capture was attempted, so none failed, so #277's record was never
# written. The run stopped, its work stayed in the tree, and nothing anywhere
# said so.
#
# IT IS #277's DEFECT ONE LEVEL OUT, and harder to see: the hook did exactly
# what its code said. The measurement that catches it is the one that
# distinguishes "nothing to do" from "could not tell" — which this repository
# already treats as load-bearing. verify-branch.sh was changed in #281 for
# reporting "could not check" as "failed", and no-personal-identity.sh refuses
# rather than passes when its configuration is absent.
#
# THE EXIT STATUS IS TAKEN WITHOUT A PIPE, which is the whole fix. `cmd | wc -l`
# reports `wc`'s status, and `wc` always succeeds. A command substitution's
# status is the command's own, so the count is made from a value already in
# hand rather than from a stream whose producer's fate was not recorded.
#
# AND WHAT GIT SAID IS KEPT. "Could not read the tree" is not actionable; "fatal:
# not a git repository" and "index.lock exists" are different problems with
# different remedies, and the sentence naming which one is on a stderr that the
# harness discards for a stop. It is replayed AND carried into the record, the
# same answer #277 gave for the signer's output.
#
# ALWAYS RETURNS 0. A stop never blocks, and reading a tree must not decide a
# stop: the caller branches on TREE_RC.
# ---------------------------------------------------------------------------
read_tree() {
  dirty=0
  TREE_RC=0
  TREE_SAID=""
  _tsaid="$RUNS_DIR/.git-status-said.$$"
  mkdir -p "$RUNS_DIR" 2>/dev/null || :
  rm -f "$_tsaid" 2>/dev/null || :
  # Two commands, so the umask is in force BEFORE the redirection creates the
  # file — the same reason the signer's transcript is opened this way.
  ( umask 077; : > "$_tsaid" ) 2>/dev/null || :
  if [ -w "$_tsaid" ]; then
    _tout="$(git -C "$1" status --porcelain 2>>"$_tsaid")"
    TREE_RC=$?
    TREE_SAID="$(cat "$_tsaid" 2>/dev/null)"
  else
    # A runs directory that cannot hold a transcript is not a reason to stop
    # asking the question; it only costs the sentence git would have said.
    _tout="$(git -C "$1" status --porcelain 2>/dev/null)"
    TREE_RC=$?
  fi
  rm -f "$_tsaid" 2>/dev/null || :
  # `$( )` strips trailing newlines and `printf '%s\n'` adds exactly one back,
  # so this counts lines rather than counting one for an empty answer.
  if [ -n "$_tout" ]; then
    dirty="$(printf '%s\n' "$_tout" | wc -l | tr -d ' ')"
  fi
  return 0
}

# ---------------------------------------------------------------------------
# WHAT A CAPTURE THAT DID NOT HAPPEN LEAVES BEHIND — #277 (RM-172).
#
# Every refusal above and every failure below reported itself through `warn`,
# and `warn` writes to the stderr of a SubagentStop, which the harness
# discards. The hook is also forbidden to `exit 2` on a stop — nine
# invocations, measured — so it cannot report by refusing either. A refused
# capture, a failed signature and a clean tree were therefore the same thing
# seen from outside: nothing at all. Measured: two subagents stopped within the
# same minute, one was captured and committed, the other was not, and the only
# evidence of the second was that its files were missing hours later. That is
# the I3 breach — an action was attempted and abandoned, and nothing recorded
# it.
#
# So a capture attempt that does not end in a commit writes a line HERE. Not a
# message: a FILE, because the requirement is that the record outlive the
# process that wrote it, and stderr does not.
#
# ONE LINE PER ATTEMPT, APPENDED. Never rewritten and never rotated from here:
# a record a second stop can truncate is a record that two subagents stopping
# in the same minute would lose, which is the incident itself.
#
# NOT THROUGH THE DEPLOYMENT, and that is the whole reason it is a local file
# rather than a ledger event. A ledger event would be the better home on every
# path except the ones that need it most — a failed signature and a refused
# credential ARE the deployment being unreachable, and a record that needs the
# component that just failed is absent exactly when it is read for. This needs
# python3 and a filesystem, and the hook has already used both by this line.
#
# SUCCESS WRITES NOTHING. A capture that commits is recorded by the ledger as
# `commit_recorded`; a second line about it here would be a second source of
# truth for one fact.
#
# NEITHER IS A FAILED RETIREMENT, and that boundary is deliberate rather than
# forgotten: a run that is not retired is expired by the reaper as
# `run_expired` (IP §6.7), so it already has a durable record. What had none
# was the WORK.
# ---------------------------------------------------------------------------
UNCAPTURED_LOG="${INNSEGL_UNCAPTURED_LOG:-$RUNS_DIR/uncaptured.jsonl}"

# The record, in one place. Fields are positional so the shell never builds
# JSON: a worktree path carrying a quote or a newline used to be how this
# file made malformed payloads, and json.dumps is the same answer MCP_CLIENT
# gave for the same problem.
UNCAPTURED_RECORD='
import json, os, sys, time

log = sys.argv[1]
names = ("reason", "detail", "run_id", "agent_type", "task", "worktree", "dir",
         "dirty", "wrote", "staged", "unaccounted", "unaccounted_paths",
         "wrote_paths")
rec = dict(zip(names, sys.argv[2:]))
for n in names:
    rec.setdefault(n, "")
for n in ("dirty", "wrote", "staged", "unaccounted"):
    try:
        rec[n] = int(rec[n] or 0)
    except ValueError:
        rec[n] = 0
# BOUNDED ON PURPOSE. A single write() to a descriptor opened O_APPEND is
# atomic, and two stops in the same minute is the case this exists for, so the
# line is kept well inside one buffer rather than allowed to grow with the size
# of a run. The counts are the record; the paths are a convenience.
rec["unaccounted_paths"] = [p for p in rec["unaccounted_paths"].splitlines() if p][:10]
rec["wrote_paths"] = [p for p in rec["wrote_paths"].splitlines() if p][:20]
rec["detail"] = rec["detail"][-400:]
rec["time"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
rec["record"] = "capture_not_made"
# 0600, for the same reason the marker is: this names a run and a tree.
fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
try:
    os.write(fd, (json.dumps(rec, sort_keys=True) + "\n").encode("utf-8"))
finally:
    os.close(fd)
'

# uncaptured <reason> [what the failure said] — one durable line, always 0.
#
# IT READS THE VARIABLES OF ITS CALLER rather than taking eleven arguments. A
# call site that restates the counts is a call site that can restate one of
# them wrongly, and the record would then describe a capture that did not
# happen the way it says. Every one is defaulted, so a branch reached before
# capture_account ran records zeroes instead of killing the stop under `set -u`.
#
# ALWAYS RETURNS 0, like say_detail. Recording an outcome must never decide one,
# and a stop never blocks.
uncaptured() {
  mkdir -p "$RUNS_DIR" 2>/dev/null || :
  python3 -c "$UNCAPTURED_RECORD" "$UNCAPTURED_LOG" \
    "$1" "${2:-}" "${RUN_ID:-}" "${TYPE:-}" "${TASK:-}" "${WT:-}" "${DIR:-}" \
    "${dirty:-0}" "${ACC_WROTE_N:-0}" "${ACC_STAGED_N:-0}" "${ACC_UNACCOUNTED_N:-0}" \
    "${ACC_UNACCOUNTED:-}" "${ACC_WROTE:-}" 2>/dev/null \
    || warn "and that refusal could not be written to $UNCAPTURED_LOG either"
  return 0
}

# ---------------------------------------------------------------------------
# A KILL IS NOT A SILENCE — RM-182 (#290).
#
# A killed subagent fires NO `SubagentStop`. Its marker survives, its work
# survives, and the ledger goes on reporting the run active for the whole of the
# reaper's grace: measured, five runs Active for between three and nine hours
# after the processes were gone, closed by hand.
#
# THE TWO CASES ARE DIFFERENT EVENTS AND THE SYSTEM TREATED THEM AS ONE:
#
#   A KILL IS CERTAIN. Something asked for this agent to stop and was told it
#   had. Waiting twelve hours on a fact already in hand is not caution.
#
#   SILENCE IS AMBIGUOUS. A quiet agent may still be working. The reaper's grace
#   answers that one and NOTHING HERE TOUCHES IT. A shorter silence threshold
#   was proposed and refused: it ends agents that are working but slow, which is
#   the whole of E9. This file reads no clock and adds no threshold.
#
# THE KILL WAS ALWAYS OBSERVABLE AND NOTHING LOOKED. `PostToolUse` fires in the
# PARENT session for every tool call including the one that does the killing,
# and it carries the tool name, its input and its result. The `task_id` a kill
# is addressed to is the same id the subagent's marker is named with — measured
# on one drill, marker and task_id identical. A PID check cannot do this job:
# subagents are not separate processes, and the MCP container cannot see the
# host's anyway.
#
# `run_retired` IS THE HONEST EVENT. The run did stop. `run_expired` is what the
# reaper says when it gave up waiting, which is not what happened.
#
# WHY THE STOP-TIME CAPTURE IS NOT ALSO RUN HERE, deliberately. A SubagentStop
# is the stopping run's own event and may sign that run's tree. This is the
# PARENT's tool call, mid-flight, in whatever tree the parent is working in, and
# staging and then committing an index from there is the #261 incident with a
# new trigger. What this leaves instead is the RECORD #277 writes, so the
# orphaned work is findable without anyone tripping over it (#288).
#
# ALWAYS RETURNS 0, AND NEVER exit 2. This is a PostToolUse, and a stop path
# that blocks was measured retrying nine deep.
# ---------------------------------------------------------------------------
retire_killed_task() {
  [ "$TOOL" = "TaskStop" ] || return 0
  [ -n "$TASK_ID" ] || return 0

  # THE RESULT, NOT THE INPUT. A `TaskStop` against a task that had already
  # finished, or that never existed, must retire nothing — and asking what was
  # REQUESTED cannot tell either of those from a kill. Measured on this harness:
  # both refuse the tool call outright and fire no PostToolUse at all, so today
  # nothing reaches this line. That is the harness's behaviour and not this
  # file's rule, and a shim that acted on the input would be one harness change
  # away from retiring a run that is still working.
  #
  # Three things the harness has to have said, and each is one half of a pair:
  #
  #   IT ECHOED THIS TASK. A reply naming a different task is either a different
  #   kill or not a kill; either way this marker's run is still working.
  #   IT STOPPED AN AGENT. Monitors and background shells are stopped through
  #   the same tool and are not runs. `local_bash` is the measured value for one.
  #   IT REPORTED NO ERROR.
  #
  # An unrecognised task kind retires nothing, which is the safe direction: a
  # harness that renames the kind loses this feature rather than misusing it.
  [ "$STOPPED_ID" = "$TASK_ID" ] || return 0
  [ "$STOPPED_TYPE" = "local_agent" ] || return 0
  [ -z "$STOPPED_ERR" ] || return 0

  # A task_id IS A MARKER NAME, NEVER A PATH. It is model-supplied text about to
  # be pasted into a filename: `../` reaches outside the markers directory, and
  # a `session-` prefix names the OPERATOR'S OWN session marker — the one run on
  # this machine that must never be retired by anything but its own SessionEnd.
  case "$TASK_ID" in
    *[!A-Za-z0-9_-]*) return 0 ;;
    session-*) return 0 ;;
  esac

  _kmark="$(cat "$RUNS_DIR/$TASK_ID" 2>/dev/null)"
  # A TASK WITH NO MARKER RETIRES NOTHING, SILENTLY, and the silence is the
  # requirement rather than an omission: most stopped tasks are not agents, so
  # this is the common path, and a warning per background shell is noise on the
  # one surface that also carries a refusal worth reading.
  [ -n "$_kmark" ] || return 0

  # AND THE MARKER HAS TO BE THIS TASK'S. It records the id the run was
  # registered under, which for a subagent is the agent id — the same value the
  # file is named with. A marker reached by any other route does not agree with
  # its own name, and nothing writes one that would.
  [ "$(reply_field "$_kmark" session_id)" = "$TASK_ID" ] || return 0

  # NEVER A RUN THIS SESSION DOES NOT OWN. See `remember`: the markers directory
  # is shared by every session on the machine, and the runs in it belonging to
  # another repository's session have real processes behind them.
  _kowner="$(reply_field "$_kmark" owner_session)"
  if [ -z "$SESSION_ID" ] || [ -z "$_kowner" ] || [ "$_kowner" != "$SESSION_ID" ]; then
    return 0
  fi

  RUN_ID="$(reply_field "$_kmark" run_id)"
  [ -n "$RUN_ID" ] || return 0
  DIR="$(reply_field "$_kmark" dir)"
  TASK="$(reply_field "$_kmark" task)"
  WT="$(reply_field "$_kmark" worktree)"
  TYPE="$(reply_field "$_kmark" agent_type)"

  # THE SAME CALL THE STOP PATH MAKES, which is what makes a second retirement a
  # non-event: `observe_session` answers a repeated stop from the instant of the
  # first and emits no second `run_retired` (#179). `ends_descendants` for the
  # reason SubagentStop sends it — a killed agent takes whatever it started with
  # it, exactly as a stopping one does.
  if REPLY="$(mcp_call observe_session session_id "$TASK_ID" phase stop \
    ends_descendants bool:true)"; then
    warn "$TASK_ID was killed; retired $(reply_field "$REPLY" run_id)"
    say_detail "$REPLY"
  else
    warn "$TASK_ID was killed and $RUN_ID could not be retired; the reaper"
    warn "  expires it as run_expired (IP §6.7)"
  fi

  # AND THE MARKER GOES, which is the LOCAL half of the double-retirement guard
  # and not a new one: SubagentStop already exits on an absent marker, so a stop
  # arriving late for this agent takes the exit it has always had. The by-tree
  # pointer goes with it for the reason SessionEnd removes the session's — the
  # run it names is retired, and a signer resolving it would register against a
  # retired parent and warn about a stale pointer every time it signs there.
  rm -f "$RUNS_DIR/$TASK_ID" 2>/dev/null || :
  if [ -n "$DIR" ]; then
    _kkey="$(tree_key "$DIR" || true)"
    [ -n "$_kkey" ] && rm -f "$RUNS_DIR/by-tree/$_kkey" 2>/dev/null
  fi

  # WHAT IT LEFT IN THE TREE, written where it outlives this process — #277.
  # One reason, `run_killed`, so a reader finds the record by the thing that
  # happened; the detail says which of the three cases it was and the counts say
  # how much. The detail does NOT claim the uncommitted paths ARE this run's:
  # `wrote_paths` is in the record for a reader who wants that intersection.
  #
  # A CLEAN TREE WRITES NOTHING, and neither does a run that recorded no write
  # in that tree. `run_retired` is already on the chain for the run itself; what
  # had no record was the WORK, and a run with none there has none to lose.
  if [ -n "$DIR" ] && [ ! -d "$DIR" ]; then
    uncaptured run_killed "the run was killed and its tree $DIR is not a directory, so whether it left work there cannot be answered"
  elif [ -n "$DIR" ]; then
    read_tree "$DIR"
    if [ "$TREE_RC" != "0" ]; then
      uncaptured run_killed "the run was killed and reading the tree $DIR exited $TREE_RC: $TREE_SAID"
    elif [ "${dirty:-0}" != "0" ]; then
      capture_account "${INNSEGL_LOG_DIR:-$HOME/.innsegl/log}/$RUN_ID" "$DIR"
      if [ "${ACC_WROTE_N:-0}" != "0" ]; then
        uncaptured run_killed "the run was killed with $dirty uncommitted path(s) in $DIR, and it recorded writing ${ACC_WROTE_N} path(s) there"
      fi
    fi
  fi
  return 0
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

    # AND A POINTER KEYED BY THE WORKING TREE, so that the SIGNER has a parent
    # to name — RM-156 (#259).
    #
    # Measured 2026-09-18: 87 `orchestrator` runs in the ledger, every one of
    # them registered by scripts/innsegl-commit.sh, and not one carrying a
    # parent. That is not because they had none. A shell command cannot
    # discover which agent it is inside — no environment variable carries an
    # agent or a session id — and the signer has neither, so it had nothing to
    # send and nothing the MCP could resolve for it.
    #
    # The working tree is the one thing both sides can see, which is the same
    # observation the subagent pointer below rests on. This is its sibling, and
    # it answers a different question: not "which run signs here" but "which
    # session is this tree's".
    #
    # IT CANNOT COLLIDE WITH THE SUBAGENT POINTER. That one's name is exactly
    # the 32 hex characters of the tree key, and SubagentStop removes that exact
    # name; this one carries a `.session` suffix, which no tree key can spell.
    # Getting that wrong would be silent in the worst way — a SubagentStop would
    # delete the session's pointer and every later commit in the tree would go
    # back to being parentless, which is indistinguishable from this change
    # never having been made.
    #
    # Line 2 is not read by anything. It is there so a human opening the file
    # can see which session the run at the top of it belongs to.
    _key="$(tree_key "$CWD" || true)"
    if [ -n "$_key" ] && mkdir -p "$RUNS_DIR/by-tree" 2>/dev/null; then
      printf '%s\n%s\n' "$RUN_ID" "$SESSION_ID" \
        > "$RUNS_DIR/by-tree/$_key.session" 2>/dev/null \
        || warn "could not write this tree's session pointer; commits here will name no parent"
    fi

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
    # READ BEFORE THE MARKER IS REMOVED. It is the only record of which tree
    # this session's pointer was keyed on, and it is deleted a few lines below.
    END_DIR="$(reply_field "$(recall)" dir)"
    # if/else rather than `&& { ... } || ...`: a block whose LAST command is a
    # conditional warn returns that condition's status, so the `||` arm fires
    # after a successful stop and the hook reports the retirement and its own
    # failure in the same breath. Measured in RM-129's live run, which printed
    # "retired <run>" and "could not retire <run>" one after the other.
    # AND IT ENDS WHAT IT STARTED — RM-157 (#260).
    #
    # THIS HOOK IS THE ONLY PARTY THAT KNOWS. A subagent killed with its session
    # fires no SubagentStop, so nothing ever ends its run: measured, five
    # subagent runs sat Active for between three and nine hours after the
    # processes were gone, and an operator closed them by hand. The reaper is
    # not the answer — its grace is twelve hours by policy, and shortening it
    # kills working agents, which is the whole of E9.
    #
    # WHAT THIS HOOK IS CLAIMING by sending it: the processes behind the runs
    # this session started are gone, because this session is what started them
    # and it is ending now. That is true at SessionEnd and it is not true
    # anywhere else, which is why no other branch of this file sends it — not
    # PostToolUse, not PreToolUse, and not a start. A harness that sent it while
    # its subagents were still working would end live agents under its own
    # identity, permanently.
    #
    # It defaults to off in the MCP, so a harness that never learns about it
    # keeps exactly today's behaviour.
    if REPLY="$(mcp_call observe_session session_id "$SESSION_ID" phase stop \
      ends_descendants bool:true)"; then
      warn "retired $(reply_field "$REPLY" run_id)"
      say_detail "$REPLY"
    else
      warn "could not end this session; the run expires on its TTL (IP §6.7)"
    fi
    # The marker is only this shim's cache of an answer. observe_session keeps
    # the mapping a later stop retries from, so removing this loses nothing —
    # which is precisely what moving the bookkeeping bought.
    rm -f "$MARKER"
    # AND THE TREE'S SESSION POINTER GOES WITH IT. The run it names has just
    # been retired, and register_agent refuses a retired parent: a pointer left
    # behind would make every commit in this tree take the fallback path, warn
    # about a stale pointer, and register with no parent anyway. The reply's own
    # cwd is not available on this event, so the marker's is what names the tree
    # — the same value SessionStart keyed it on, read above before the marker
    # went.
    if [ -n "$END_DIR" ]; then
      _key="$(tree_key "$END_DIR" || true)"
      [ -n "$_key" ] && rm -f "$RUNS_DIR/by-tree/$_key.session" 2>/dev/null
    fi
    exit 0
    ;;

  SubagentStart)
    # A subagent with no identity does no work (IP §6.1). This is the one start
    # that refuses, and the refusal is the enforcement.
    [ -n "$AGENT_ID" ] || exit 0

    # THE PARENT SESSION (RM-135, #214; RM-156, #259). The subagent's work was
    # always attributed; what was missing is the EDGE — a reader could see both
    # runs and not see that one produced the other, which is what "who did this
    # work" resolves to the moment an orchestrator delegates.
    #
    # THE SESSION ID, NOT A RUN ID. This file used to resolve the run itself and
    # send that; the resolution is the MCP's now, because it is the part every
    # other harness would otherwise have to reimplement. An empty value is
    # omitted by mcp_call, so a subagent whose harness reports no session stays
    # a root run rather than naming a parent that is not there — and so does one
    # whose parent session this deployment has never seen, which the MCP answers
    # with a root run and a `detail` rather than with a refusal.
    REPLY="$(mcp_call observe_session \
      session_id "$AGENT_ID" phase start cwd "$CWD" \
      agent_type "${AGENT_TYPE:-subagent}" \
      parent_session_id "$PARENT_IDENT")" || {
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
    # THREE LINES ARE WHAT IS WRITTEN; A FOURTH MAY BE READ. When the run named
    # here is retired, the signer registers a successor and rewrites this file
    # with a fourth line saying which run it superseded (RM-134, #213). Nothing
    # reads line 4 — it is there for a human opening the file — and a
    # SubagentStart for this tree truncates it back to three, which loses
    # nothing: the succession is recorded on the chain, in the successor's
    # `run_registered` idempotency key.
    #
    # It is what makes attribution automatic instead of remembered. A shell
    # command cannot discover which agent it is inside — no environment variable
    # carries an agent or session id — so without this the signer mints a
    # throwaway identity per commit: 53 signed commits under ephemeral runs
    # while all 16 agent runs that did the work showed "Signed nothing". The
    # tree is the one thing both sides can see.
    _key="$(tree_key "$CWD" || true)"
    if [ -n "$_key" ] && mkdir -p "$RUNS_DIR/by-tree" 2>/dev/null; then
      printf '%s\n%s\n%s\n' \
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
    # READ BEFORE ANY BRANCH DECIDES ANYTHING — #284. These three used to be
    # read inside the capture branch, which is the one branch that is not taken
    # when the tree cannot be read; the record written on the new paths would
    # then have named no worktree and no task, and a record missing the field a
    # reader correlates on is a record that has to be correlated by hand.
    TASK="$(reply_field "$MARK" task)"
    WT="$(reply_field "$MARK" worktree)"
    TYPE="${AGENT_TYPE:-$(reply_field "$MARK" agent_type)}"
    if [ -n "$DIR" ] && [ ! -d "$DIR" ]; then
      # THE TREE THE RUN WORKED IN IS NOT THERE — #284. This branch used to be
      # the `else` of a test with no `else`: the marker named a directory, the
      # directory was gone, and the stop walked past in silence. "The tree is
      # gone" is the first cause the issue names, and it never reached the
      # `git status` the issue is about, because it was excluded one line
      # earlier. Whether that run left work behind is now unanswerable, which is
      # exactly why it is written down rather than assumed to be nothing.
      warn "$RUN_ID's working tree is gone: $DIR is not a directory."
      warn "  Whether it left uncommitted work there cannot be answered now, so this"
      warn "  is not a clean tree; it is an unread one (#284)."
      uncaptured tree_absent "the run's tree $DIR is not a directory, so its uncommitted work could not be counted"
    elif [ -n "$DIR" ]; then
      # Did it already commit under its own identity? Ask the ledger, not the
      # worktree: a commit that was signed and then had its branch moved is
      # still this run's commit.
      committed="$(curl -sS --max-time 5 \
        "${INNSEGL_API_URL:-http://127.0.0.1:8082}/api/v1/runs/$RUN_ID" 2>/dev/null \
        | sed -n 's/.*"commits"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -n 1)"
      read_tree "$DIR"

      if [ "$TREE_RC" != "0" ]; then
        # ASKED BEFORE THE COMMIT COUNT, and that order is the decision. A run
        # that has committed once may still have left work uncommitted, so the
        # commit count answers a different question and cannot stand in for
        # this one. What is recorded here is not "there was work"; it is that
        # nobody knows, which is the whole of #284.
        warn "$RUN_ID's tree at $DIR could not be read: git status exited $TREE_RC."
        [ -n "$TREE_SAID" ] && printf '%s\n' "$TREE_SAID" >&2
        warn "  That is not a clean tree. Whatever it left there is still there, and"
        warn "  no capture was attempted, so no capture failed (#284)."
        uncaptured tree_unreadable "git status in $DIR exited $TREE_RC: $TREE_SAID"
      elif [ "${committed:-0}" = "0" ] && [ "${dirty:-0}" != "0" ]; then
        # ONLY WHAT THIS RUN WROTE, AND ONLY IF THAT IS ALL THERE IS (#261).
        #
        # `git add -A` staged the whole tree, so a run became the signed author of
        # whatever else happened to be uncommitted. Measured three times on
        # 2026-09-18: a read-only review subagent signed 12 files and ~890 lines it
        # had only read; a second capture took another agent's in-flight work, which
        # that agent had to soft-reset and re-commit; a third took a one-line edit
        # the session made. Each verified against Fulcio and Rekor under the wrong
        # identity — worse than unsigned, because it is confidently wrong and
        # permanent.
        #
        # The first answer bounded what was ADDED and left the commit unbounded,
        # which fixed nothing an already-staged file could not walk straight past.
        # This is the bound on the COMMIT: if the index holds anything this run
        # cannot show it wrote, the WHOLE capture is refused. See capture_account.
        _bodies="${INNSEGL_LOG_DIR:-$HOME/.innsegl/log}/$RUN_ID"
        capture_account "$_bodies" "$DIR"

        if [ "$ACC_READ" != "1" ] || [ "$ACC_INDEX" != "1" ]; then
          # NO RECORD, NO CAPTURE. A run that cannot be asked what it touched must
          # not have a tree signed on its behalf; that is the bug itself.
          warn "$RUN_ID left $dirty uncommitted path(s) in $DIR and cannot be asked what it wrote."
          if [ "$ACC_READ" != "1" ]; then
            warn "  Its tool-call bodies are unreadable at $_bodies."
          else
            warn "  The index of that tree could not be read."
          fi
          warn "  Refusing the capture rather than signing work it may not have done (#261)."
          capture_remedy
          if [ "$ACC_READ" != "1" ]; then
            uncaptured bodies_unreadable "the tool-call bodies of this run are unreadable at $_bodies"
          else
            uncaptured index_unreadable "the index of $DIR could not be read"
          fi
        elif [ "$ACC_WROTE_N" = "0" ]; then
          # A READ-ONLY RUN CAPTURES NOTHING, IN ANY TREE. This is the first
          # measured incident, and the one an unbounded capture gets most wrong:
          # there is no diff anywhere that belongs to this run.
          warn "$RUN_ID recorded no file write, so it captures nothing of the $dirty uncommitted path(s) in $DIR."
          if [ "$ACC_STAGED_N" != "0" ]; then
            warn "  The $ACC_STAGED_N path(s) staged there are not this run's to sign and were left alone."
          fi
          uncaptured no_recorded_writes "the run recorded no file write, so nothing in that tree is its own to capture"
        elif [ "$ACC_UNACCOUNTED_N" != "0" ]; then
          warn "$RUN_ID left $dirty uncommitted path(s) in $DIR, and the index already holds"
          warn "  $ACC_UNACCOUNTED_N path(s) it cannot show it wrote:"
          printf '%s\n' "$ACC_UNACCOUNTED" | while IFS= read -r _p; do
            [ -n "$_p" ] && warn "    $_p"
          done
          [ "$ACC_UNACCOUNTED_N" -gt 10 ] 2>/dev/null && warn "    ... and $((ACC_UNACCOUNTED_N - 10)) more"
          warn "  A capture commits the index, so signing now would put all of them"
          warn "  under this run. Refusing the whole capture (#261)."
          capture_remedy
          uncaptured index_unaccounted "the index already held $ACC_UNACCOUNTED_N path(s) the run cannot show it wrote"
        else
          printf '%s\n' "$ACC_WROTE" | while IFS= read -r _f; do
            [ -n "$_f" ] && git -C "$ACC_TOP" add -- "$_f" 2>/dev/null || true
          done
          # AND THE SAME QUESTION AGAIN, of the index as it now stands. The check
          # above is what keeps a refusal from touching the tree; THIS one is the
          # invariant the commit rests on, asked of the thing actually about to be
          # committed. They are the same call because two spellings of one rule
          # drift, and the one that drifts is always the one nothing runs.
          capture_account "$_bodies" "$DIR"
          if [ "$ACC_UNACCOUNTED_N" != "0" ]; then
            warn "$RUN_ID's own writes did not stage cleanly in $DIR: the index now holds"
            warn "  $ACC_UNACCOUNTED_N path(s) it cannot account for. Refusing the capture (#261)."
            capture_remedy
            uncaptured staging_unaccounted "staging the run's own writes left $ACC_UNACCOUNTED_N path(s) it cannot account for"
          elif [ "$ACC_STAGED_N" = "0" ]; then
            warn "$RUN_ID wrote nothing in $DIR that is uncommitted; capturing nothing of the $dirty path(s) there"
            uncaptured nothing_uncommitted "every path the run wrote is already committed; the $dirty uncommitted path(s) there are not its own"
          else
            warn "$RUN_ID left $dirty uncommitted path(s); capturing the $ACC_STAGED_N it wrote"
            MSG="chore(agent): work left by $TYPE run $RUN_ID

Captured by the harness at SubagentStop because the run ended with $dirty
uncommitted path(s) and no commit of its own. Signed under that run's identity
so the work is attributed to the agent that did it rather than to whoever
commits next (ADR-0046).

Every path in this commit is one the run's own tool-call bodies record it
writing; a capture whose index held anything else is refused rather than
narrowed (#261).

The build was not run. A subagent's work is recorded as it was left; the branch
gate is what decides whether it may merge."
            # Signed under THIS RUN, not a new one — and not retired here, the stop
            # below is the one that belongs to this event.
            # The work stays STAGED whether or not this succeeds, so a failure loses
            # nothing but the attribution, and the run it should carry is named here
            # rather than written to a file nothing has ever read.
            #
            # AND WHAT THE SIGNER SAID IS KEPT, not just shouted — #277. Its
            # output went straight to a stderr the harness discards, so the one
            # sentence that says WHY a signature failed — a run already retired,
            # a deployment that is not up, a credential the listener refused —
            # was the first thing lost, and a stop that signed nothing looked
            # exactly like a stop with nothing to sign. It is replayed to stderr
            # exactly as before AND carried into the record, which outlives this
            # process.
            _said="$RUNS_DIR/.signer-said.$$"
            rm -f "$_said" 2>/dev/null || :
            # Two commands, so the umask is in force BEFORE the redirection
            # creates the file: a redirection on the subshell itself is
            # performed at fork, which is before anything inside it runs.
            ( umask 077; : > "$_said" ) 2>/dev/null || :
            if ( cd "$DIR" && "$(signer)" -r "$RUN_ID" ${TASK:+-t "$TASK"} ${WT:+-w "$WT"} -m "$MSG" ) >> "$_said" 2>&1; then
              cat "$_said" >&2
            else
              cat "$_said" >&2
              warn "could not sign $RUN_ID's work; it is staged in $DIR and signing it later needs -r $RUN_ID"
              uncaptured signing_failed "$(cat "$_said" 2>/dev/null)"
            fi
            rm -f "$_said" 2>/dev/null || :
          fi
        fi
      fi
    fi

    # See SessionEnd for why this is an if and not a `&& { } ||`, and for the
    # contract `ends_descendants` carries. A SUBAGENT SENDS IT TOO, because a
    # subagent can itself start others and they die with it exactly the same
    # way. A leaf subagent — which is most of them — has nothing below it, so
    # the MCP resolves no descendants and the flag costs one field.
    if REPLY="$(mcp_call observe_session session_id "$AGENT_ID" phase stop \
      ends_descendants bool:true)"; then
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
      # THE SUBAGENT'S POINTER AND NOT THE SESSION'S. This removes exactly the
      # 32 hex characters of the tree key; the session pointer SessionStart
      # writes carries a `.session` suffix and outlives every subagent that
      # worked in the same tree (RM-156, #259).
      _key="$(tree_key "$DIR" || true)"
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
    # NAMED BY SESSION, NOT BY RUN — RM-142 (#226).
    #
    # This block used to read the marker first and `exit 0` when there was
    # none. A marker is absent exactly when registration was refused, which is
    # exactly when the deployment was down at SessionStart — so the session lost
    # its identity AND every tool call it went on to make, silently, after one
    # warning at the beginning. Measured: the ledger held 101 orchestrator runs,
    # 69 general-purpose, and 3 session.
    #
    # The session id is something this harness always has, whether or not a
    # registration ever succeeded. Handing it over lets the MCP resolve the run
    # it already holds, or register the session on first sight — so a refused
    # start recovers on the next tool call instead of being terminal, and this
    # file needs no retry, no backoff and no "did it work" check. That is the
    # point: a retry written here is a retry every future shim reimplements.
    #
    # The marker is still read when it exists, for the run token alone. Where
    # the caller names a session rather than a run, the token is not required —
    # a session id is not the public value a run id is.
    #
    # ALWAYS 0. See the header.
    # AND IT CARRIES THE PARENT TOO — RM-156 (#259). This call REGISTERS when
    # the session is one the deployment has never seen, which is precisely the
    # case a refused start leaves behind, and until now every run registered
    # that way was a root run: the path that recovers a lost identity lost the
    # edge instead. It costs one more argument, and the MCP ignores it for a
    # session it already holds.
    [ -n "$TOOL" ] && [ -n "$IDENT" ] || exit 0
    MARK="$(recall)"
    mcp_call observe_tool_call \
      session_id "$IDENT" cwd "$CWD" tool "$TOOL" body "$EVENT_JSON" \
      agent_type "$IDENT_TYPE" \
      parent_session_id "$PARENT_IDENT" \
      run_token "$(reply_field "${MARK:-}" run_token)" >/dev/null 2>&1 || true

    # AND IF THIS TOOL CALL WAS A KILL, THE KILLED RUN LEAVES THE ACTIVE LIST
    # NOW — RM-182 (#290). Recorded FIRST and retired second: the kill is the
    # parent's own activity, and a retirement that swallowed it would lose the
    # one tool call that explains why the run ended. See retire_killed_task for
    # everything it refuses to act on, and for why a silence is still the
    # reaper's question rather than this one.
    retire_killed_task
    exit 0
    ;;

  PreToolUse)
    # A DESTRUCTIVE git IS REFUSED WHILE AN AGENT RUN HOLDS UNCOMMITTED WORK IN
    # THIS TREE — #278 (RM-173).
    #
    # Measured: a `git reset --hard HEAD~1` in a shared checkout discarded a
    # subagent's finished but uncommitted work — eight minutes of it — and
    # nothing refused, warned or recorded the loss. Agent work lives in the
    # working tree until the SubagentStop capture commits it, and the operator
    # shares that tree.
    #
    # ASKED FIRST, BEFORE THE COMMIT GATE BELOW. A command that both commits and
    # discards reaches whichever gate is written first, and an unsigned commit
    # can be signed again tomorrow while discarded work cannot be rewritten.
    #
    # THE DECISION IS NOT HERE. scripts/hooks/git-tree-guard.sh holds it, because
    # the same decision has to be reachable from a `git` on PATH — which is the
    # only thing that sees a HUMAN's terminal, and the human is who the measured
    # incident was. This branch is the half that needs no operator action: it
    # covers every git command an agent runs through the Bash tool, and it is
    # the one place that can BLOCK one.
    #
    # AND IT REFUSES THE OPERATOR'S OWN SESSION TOO, which is the opposite of
    # the asymmetry the commit gate below is built on — and for the reason that
    # asymmetry rests on. Refusing the human there would stop them working on
    # their own machine over a ledger; refusing them HERE stops them destroying
    # somebody else's unfinished work, and only ever when a live agent run
    # actually wrote the files at stake. The guard never counts the session's
    # own writes, and it names the override in the refusal.
    #
    # THE PREFILTER IS A SUPERSET OF THE GUARD'S ANSWER, deliberately: it names
    # the five SUBCOMMANDS the guard can refuse and none of the flags that
    # decide it. It can only send more to the guard than the guard will refuse,
    # never fewer, so it cannot become a second, drifting spelling of the rule —
    # which is the whole hazard of a fast path in front of a decision.
    #
    # AND IT FAILS OPEN, like everything else in front of git here. Anything but
    # an exit of 2 — a missing guard, a missing python3, an unreadable runs
    # directory — allows.
    if [ "$TOOL" = "Bash" ] && [ "${INNSEGL_GIT_GUARD:-1}" != "0" ]; then
      case "$CMD" in
        *git*)
          case "$CMD" in
            *reset*|*checkout*|*restore*|*clean*|*switch*)
              TREE_GUARD="${INNSEGL_GIT_GUARD_SCRIPT:-$(dirname -- "$0")/git-tree-guard.sh}"
              if [ -x "$TREE_GUARD" ]; then
                printf '%s' "$EVENT_JSON" | "$TREE_GUARD" hook
                _grc=$?
                [ "$_grc" = "2" ] && exit 2
              fi
              ;;
          esac
          ;;
      esac
    fi

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
