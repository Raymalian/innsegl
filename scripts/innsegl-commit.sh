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
AGENT_TYPE="${INNSEGL_AGENT_TYPE:-orchestrator}"

usage() {
  echo "usage: innsegl-commit.sh -m <message> | -F <file>" >&2
  echo "       stage first, exactly as for git commit" >&2
  exit 2
}

MESSAGE=""
case "${1:-}" in
  -m) [ $# -ge 2 ] || usage; MESSAGE="$2" ;;
  -F) [ $# -ge 2 ] || usage; MESSAGE="$(cat "$2")" ;;
  *)  usage ;;
esac
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

# The staged tree, and a refusal when there is nothing staged. `git commit`
# refuses an empty commit by default and so does this.
TREE="$(git write-tree)"
if [ "$TREE" = "$(git rev-parse HEAD^{tree} 2>/dev/null || echo none)" ]; then
  echo "innsegl-commit: nothing staged — the tree is identical to HEAD" >&2
  exit 1
fi

# A key that is stable for one attempt and different across attempts. Same
# staged tree twice is the same commit and must not become two runs; a retry
# after a failure is a new attempt and must not be answered from the first.
KEY="commit-$(printf '%s' "$TREE$MESSAGE" | shasum -a 256 | cut -c1-32)"

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
body=json.loads(r["content"][0]["text"])
if r.get("isError"):
    print(str(body)[:400], file=sys.stderr); sys.exit(1)
v=body
for part in name.split("."):
    v=v[part]
print(v)' "$1"
}

fail() { echo "innsegl-commit: $*" >&2; exit 1; }

# ---- 1. an identity ---------------------------------------------------------
OUT="$(mcp "$ADMIN_URL" register_agent \
  "$(printf '{"agent_type":"%s","task_id":"%s","idempotency_key":"%s"}' "$AGENT_TYPE" "$TASK" "$KEY-reg")")" \
  || fail "the identity service at $ADMIN_URL could not be reached. No identity, no attributed work (IP §6.1). Try: make innsegl-up-here"
RUN="$(printf '%s' "$OUT" | field run_id)" || fail "register_agent refused"
echo "innsegl-commit: run $RUN  (agent $AGENT_TYPE, task $TASK)"

# retire whatever happens next, including a failure. An identity left live
# after a failed signature is exactly the orphan retirement exists to prevent.
retire() {
  mcp "$ADMIN_URL" retire_agent "$(printf '{"run_id":"%s"}' "$RUN")" >/dev/null 2>&1 || true
}
trap retire EXIT

# ---- 2. the signature -------------------------------------------------------
ARGS="$(python3 -c '
import json,sys
run,repo,tree,task,key=sys.argv[1:6]
print(json.dumps({"run_id":run,"repo":repo,"staged_ref":tree,
                  "message":sys.stdin.read(),"task_ref":task,
                  "idempotency_key":key+"-sign"}))' \
  "$RUN" "$REPO" "$TREE" "$TASK" "$KEY" <<EOF
$MESSAGE
EOF
)"

SIGNED="$(mcp "$AGENT_URL" sign_commit "$ARGS")" || fail "the MCP at $AGENT_URL could not be reached"
SHA="$(printf '%s' "$SIGNED" | field commit_sha)" || fail "sign_commit refused — nothing was committed"
IDX="$(printf '%s' "$SIGNED" | field rekor_entry.log_index 2>/dev/null || echo '?')"

echo "innsegl-commit: signed $(git rev-parse --short "$SHA")  rekor index $IDX"
git --no-pager log -1 --format='  %s' "$SHA"
