#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# `git commit`, but the commit carries an agent identity.
#
# WHY THIS EXISTS. On 2026-09-07 this repository's own branch held twelve
# commits and three were signed. The other nine were made with plain
# `git commit`, by an orchestrator that had every tool it needed and simply did
# not reach for them. A system that depends on somebody remembering is the
# thing this project exists to replace.
#
# Signing was four MCP calls in a fixed order, made by hand each time. This is
# those four calls, in that order, once.
#
# USE IT
#
#   git add -A
#   scripts/innsegl-commit.sh -m "fix(thing): what changed"
#   scripts/innsegl-commit.sh -F /path/to/message
#
# The staged tree is what gets signed, exactly as `git commit` would take it.
#
# WHAT IT NEEDS
#
#   - the deployment up, with the admin listener on (INNSEGL_MCP_ADMIN_LISTEN)
#   - this working tree visible to the MCP: `make innsegl-up-here`
#
#   INNSEGL_MCP_ADMIN_URL   default http://127.0.0.1:28090/   register, retire
#   INNSEGL_MCP_URL         default http://127.0.0.1:28080/   sign
#
# The two URLs are not a mistake. #170 put the identity lifecycle on a listener
# the model's MCP client is never pointed at, so registering and signing happen
# against different ports on purpose.
#
# IT REFUSES RATHER THAN FALLING BACK. If the deployment is down this exits
# non-zero and makes no commit. It will not quietly `git commit` for you: an
# unsigned commit that the operator believes is signed is worse than no commit,
# and IP §6.1 is that attributed work must be impossible without an identity
# rather than merely inconvenient.

set -eu

ADMIN_URL="${INNSEGL_MCP_ADMIN_URL:-http://127.0.0.1:28090/}"
AGENT_URL="${INNSEGL_MCP_URL:-http://127.0.0.1:28080/}"
# `signer`, not `orchestrator`, and the distinction is the point.
#
# This script mints a THROWAWAY identity per commit: register, sign, retire, in
# about half a second. Measured across the ledger on 2026-09-09 -- 95 such runs
# with a median life of 0.58s, against 44 real agent runs with a median of
# 11m38s. They are 87% of everything registered in a working day.
#
# Typed `orchestrator` they were indistinguishable from a real agent, so a
# dashboard listing runs newest-first buried the four live agents under a
# hundred half-second signers, and the operator read that as "everything dies
# immediately". Nothing was dying. Filtering them out happened to work only
# because no real subagent had used that type yet, which is luck rather than
# design.
#
# doc 02 §5 gives agent_type a grammar, not an enum -- its own example is
# `fix-ci` -- so this is a new value and not a protected-string change.
AGENT_TYPE="${INNSEGL_AGENT_TYPE:-signer}"

usage() {
  echo "usage: innsegl-commit.sh -m <message> | -F <file>" >&2
  echo "                        [-r <run_id>]   sign under an existing run, do not retire it" >&2
  echo "                        [-w <path>]     a linked worktree of this repository" >&2
  echo "                        [-t <task>]     the task the run was registered with" >&2
  echo "       stage first, exactly as for git commit" >&2
  exit 2
}

[ $# -gt 0 ] || usage

MESSAGE=""
RUN_GIVEN=""
WORKTREE=""
TASK_GIVEN=""
while [ $# -gt 0 ]; do
  case "$1" in
    -m) [ $# -ge 2 ] || usage; MESSAGE="$2"; shift 2 ;;
    -F) [ $# -ge 2 ] || usage; MESSAGE="$(cat "$2")"; shift 2 ;;
    # -r: sign under a run that ALREADY EXISTS, and do not retire it.
    #
    # The harness hook uses this to sign a subagent's leftover work under the
    # subagent's own identity rather than the orchestrator's (ADR-0046). It
    # must not register: the run is the one SubagentStart created. It must not
    # retire either -- SubagentStop does that immediately afterwards, and a
    # double retirement is #179.
    -r) [ $# -ge 2 ] || usage; RUN_GIVEN="$2"; shift 2 ;;
    # -w: a linked worktree of this repository, relative to it. MCP-029.
    -w) [ $# -ge 2 ] || usage; WORKTREE="$2"; shift 2 ;;
    # -t: the task this run was REGISTERED with, which must be used verbatim
    # rather than re-derived.
    #
    # sign_commit checks that Agent-Task lowercases to the task inside
    # Agent-Identity, and the identity was minted at registration. Deriving the
    # task again here reads whatever branch this process happens to stand on --
    # which, for a subagent in its own worktree, is `wt-...` and not the main
    # branch the run was registered from. Measured 2026-09-08:
    #
    #   invalid claim: Agent-Task is "3abfd36b", which does not lowercase to
    #   the task "3213771b" in Agent-Identity
    -t) [ $# -ge 2 ] || usage; TASK_GIVEN="$2"; shift 2 ;;
    *)  usage ;;
  esac
done
[ -n "$MESSAGE" ] || { echo "innsegl-commit: empty message" >&2; exit 2; }

ROOT="$(git rev-parse --show-toplevel)"

# The repository identifier the MCP resolves against its workspace: host/org/name.
REPO="${INNSEGL_REPO_ID:-$(git remote get-url origin 2>/dev/null \
  | sed -e 's|^git@||' -e 's|^https://||' -e 's|^http://||' -e 's|:|/|' -e 's|\.git$||')}"
[ -n "$REPO" ] || { echo "innsegl-commit: no origin remote; set INNSEGL_REPO_ID" >&2; exit 2; }

# The task, from the branch. Same derivation the harness hook uses, and for the
# same reason: doc 02 §5's grammar is [a-z0-9][a-z0-9-]{0,62}, so a branch name
# with a slash is refused. An RM number is this project's own task identifier.
BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo detached)"
TASK="$(printf '%s' "$BRANCH" | tr 'A-Z' 'a-z' | sed -n 's/.*\(rm[0-9][0-9]*\).*/\1/p')"
if [ -z "$TASK" ]; then
  TASK="$(printf '%s' "$BRANCH" | tr 'A-Z' 'a-z' \
    | sed -e 's/[^a-z0-9-]/-/g' -e 's/^[^a-z0-9]*//' -e 's/--*/-/g' -e 's/-*$//' | cut -c1-63)"
fi
[ -n "$TASK" ] || TASK="unnamed"
[ -n "$TASK_GIVEN" ] && TASK="$TASK_GIVEN"

# The staged tree, and a refusal when there is nothing staged. `git commit`
# refuses an empty commit by default and so does this.
TREE="$(git write-tree)"
if [ "$TREE" = "$(git rev-parse HEAD^{tree} 2>/dev/null || echo none)" ]; then
  echo "innsegl-commit: nothing staged — the tree is identical to HEAD" >&2
  exit 1
fi

# TWO KEYS, because the two calls want opposite things and one key cannot do
# both. This is the bug that made retrying impossible: a single key derived
# from the content is the SAME on every attempt, so a retry after a failure
# asked for the run the failed attempt had already retired on its way out --
# and got RUN_ALREADY_RETIRED, forever, with no way forward but a new message.
#
#   RUN_KEY  is per ATTEMPT. A retry is a new attempt and deserves a live run.
#   SIGN_KEY is per CONTENT. Signing the same staged tree twice must not
#            produce two commits.
CONTENT="$(printf '%s' "$TREE$MESSAGE" | shasum -a 256 | cut -c1-32)"
RUN_KEY="run-$CONTENT-$$-$(date -u +%s)"
# SIGN_KEY is derived AFTER the run is known, further down, because the run is
# part of the request the key names. See its comment there.

# ---------------------------------------------------------------------------
# One MCP call. Session per call: this is a short-lived process with nowhere to
# keep one, against a server on loopback.
# ---------------------------------------------------------------------------
mcp() {
  _url="$1"; _tool="$2"; _args="$3"
  _hdr="$(mktemp)"
  curl -sS --max-time 30 --dump-header "$_hdr" \
    -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    --data-binary '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"innsegl-commit","version":"v0"}}}' \
    "$_url" >/dev/null 2>&1 || { rm -f "$_hdr"; return 1; }
  _sid="$(sed -n 's/^[Mm]cp-[Ss]ession-[Ii]d:[[:space:]]*//p' "$_hdr" | tr -d '\r' | head -n 1)"
  rm -f "$_hdr"
  [ -n "$_sid" ] || return 1
  curl -sS --max-time 10 -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' -H "Mcp-Session-Id: $_sid" \
    --data-binary '{"jsonrpc":"2.0","method":"notifications/initialized"}' "$_url" >/dev/null 2>&1
  curl -sS --max-time 300 -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' -H "Mcp-Session-Id: $_sid" \
    --data-binary "$(printf '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"%s","arguments":%s}}' "$_tool" "$_args")" \
    "$_url" 2>/dev/null | sed -n 's/^data: //p' | head -n 1
}

# field NAME < payload — pulls one value out of a tool result. The result's
# text is JSON inside a JSON string, so python does it rather than sed.
field() {
  python3 -c '
import json,sys
name=sys.argv[1]
raw=sys.stdin.read().strip()
if not raw: sys.exit(1)
d=json.loads(raw)
if "error" in d:
    print(d["error"].get("message","")[:400], file=sys.stderr); sys.exit(1)
r=d.get("result",{})
text=r.get("content",[{}])[0].get("text","")
# isError FIRST. A refusal carries a plain-sentence reason, not JSON, so
# parsing before checking crashes on the very case the reason explains -- and
# the operator sees a Python traceback instead of what the tool said. Cost an
# hour twice: sign_commit refused, and the refusal was invisible.
if r.get("isError"):
    print(text[:600], file=sys.stderr); sys.exit(1)
body=json.loads(text)
v=body
for part in name.split("."):
    v=v[part]
print(v)' "$1"
}

fail() { echo "innsegl-commit: $*" >&2; exit 1; }

# ---- 1. an identity ---------------------------------------------------------
if [ -n "$RUN_GIVEN" ]; then
  # Somebody else's run, and somebody else's to retire. See -r.
  RUN="$RUN_GIVEN"
  echo "innsegl-commit: signing under the existing run $RUN (task $TASK)"
else
  OUT="$(mcp "$ADMIN_URL" register_agent \
    "$(printf '{"agent_type":"%s","task_id":"%s","idempotency_key":"%s"}' "$AGENT_TYPE" "$TASK" "$RUN_KEY")")" \
    || fail "the identity service at $ADMIN_URL could not be reached. No identity, no attributed work (IP §6.1). Try: make innsegl-up-here"
  RUN="$(printf '%s' "$OUT" | field run_id)" || fail "register_agent refused"
  echo "innsegl-commit: run $RUN  (agent $AGENT_TYPE, task $TASK)"

  # retire whatever happens next, including a failure. An identity left live
  # after a failed signature is exactly the orphan retirement exists to prevent.
  retire() {
    mcp "$ADMIN_URL" retire_agent "$(printf '{"run_id":"%s"}' "$RUN")" >/dev/null 2>&1 || true
  }
  trap retire EXIT
fi

# ---- 2. the signature -------------------------------------------------------

# THE RUN IS PART OF THE KEY, and leaving it out made every retry impossible.
#
# The key must name a request, and the request carries run_id. Keyed on content
# alone, a first attempt that failed for any reason burned the key: the retry
# sends the same tree and message under a NEW run, the digests differ, and the
# ledger answers -- correctly -- that the key already names a different call:
#
#   DUPLICATE_REQUEST: idempotency_key "commit-3e6e2b46..." already names the
#   "sign_commit" call with request digest sha256:68911802..., not this one
#
# Measured 2026-09-08 while proving MCP-029. The tree and message were
# identical; only the run had changed, because the first attempt had failed.
#
# What content-keying was protecting is not lost: the same run replaying the
# same tree still dedupes, and the MCP refuses to create a second commit for a
# tree that is already at HEAD whatever key is used.
SIGN_KEY="commit-$CONTENT-$RUN"
ARGS="$(python3 -c '
import json,sys
run,repo,tree,task,key,wt=sys.argv[1:7]
args={"run_id":run,"repo":repo,"staged_ref":tree,
      "message":sys.stdin.read(),"task_ref":task,
      "idempotency_key":key}
# Absent, not empty: an empty string is a value the tool would have to give a
# meaning, and MCP-029 gives it one only by omission.
if wt: args["worktree"]=wt
print(json.dumps(args))' \
  "$RUN" "$REPO" "$TREE" "$TASK" "$SIGN_KEY" "$WORKTREE" <<EOF
$MESSAGE
EOF
)"

SIGNED="$(mcp "$AGENT_URL" sign_commit "$ARGS")" || fail "the MCP at $AGENT_URL could not be reached"
SHA="$(printf '%s' "$SIGNED" | field commit_sha)" || fail "sign_commit refused — nothing was committed"
IDX="$(printf '%s' "$SIGNED" | field rekor_entry.log_index 2>/dev/null || echo '?')"

echo "innsegl-commit: signed $(git rev-parse --short "$SHA")  rekor index $IDX"
git --no-pager log -1 --format='  %s' "$SHA"
