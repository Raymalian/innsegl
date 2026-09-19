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
#   INNSEGL_API_URL         default http://127.0.0.1:8082     is a run still live
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
#
# # THE LISTENER'S CREDENTIAL — #266
#
# #264 put a repository-scoped credential in front of the six identity-lifecycle
# tools, and this script reaches two of them. Measured before that landed:
# `grep -c Authorization` in this file returned 0, so deploying the check as it
# stood answered `register_agent` with 401 and no commit could be signed at all.
#
# FOUR DECISIONS, and each of them is the cheap half of a pair:
#
#   WHO MINTS. This script, for itself, by running the shipped
#   `innsegl admin-credential mint` inside a throwaway container that mounts the
#   deployment's private signing key READ-ONLY and has no network. The key is
#   never copied onto this machine's filesystem, never read by this script, and
#   never printed. A long-lived minting service would be a standing mint oracle
#   for anything that could reach it; a container that exists for 200ms and is
#   reachable only through the Docker API adds no privilege that API did not
#   already carry.
#
#   HOW OFTEN. Never, until the listener says otherwise. The first attempt
#   carries no credential; a 401 — and nothing else — mints one and retries the
#   same call exactly once. So a deployment that does not enforce (the default,
#   and every deployment before #264) makes no 401, mints nothing, and behaves
#   byte-for-byte as this script did before. Nothing is probed, nothing is
#   configured, and there is no mode to get wrong.
#
#   WHAT EXPIRY DOES. Nothing special, which is the point. The credential lives
#   fifteen minutes and a single `sign_commit` may take five; a credential that
#   ages out between `register_agent` and `retire_agent` produces a 401 on the
#   next call, which mints a fresh one and retries. No clock is read here, no
#   `exp` is parsed, and no timer decides anything — the server's own refusal is
#   the only trigger, so there is no second opinion about when a token died.
#
#   WHERE IT IS KEPT. In one shell variable, for the life of one process. Never
#   exported, never written to a file, never echoed, and never placed in an
#   argument vector: the header travels to curl through a `-K -` configuration
#   on a pipe, because `ps` shows every argument of every process on this
#   machine and a bearer token there is replayable for the rest of its life.

set -eu

ADMIN_URL="${INNSEGL_MCP_ADMIN_URL:-http://127.0.0.1:28090/}"
AGENT_URL="${INNSEGL_MCP_URL:-http://127.0.0.1:28080/}"
AGENT_TYPE="${INNSEGL_AGENT_TYPE:-orchestrator}"
# The READ side, and the only question this script asks it: is the run on this
# tree's pointer still one that may sign? It is a third address because it is a
# third service — the two MCP listeners write, `innsegl api` reads — and the
# harness hook already reaches it at this default.
API_URL="${INNSEGL_API_URL:-http://127.0.0.1:8082}"

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



# THE RUN THIS TREE BELONGS TO, discovered rather than remembered.
#
# Without this the script mints a throwaway identity per commit, and the work is
# credited to something with no link back to the agent that produced it.
# Measured 2026-09-09 in another project: 53 signed commits in the ledger, every
# one under an ephemeral run, while all 16 agent runs that did the work showed
# "Signed nothing". Attribution existed and answered nothing.
#
# A shell command cannot discover which agent it is inside -- no environment
# variable carries an agent or session id. The WORKING TREE is the one thing
# both sides can see: the harness hook knows which run works in which directory
# and publishes a pointer at registration; this reads it back.
#
# An explicit -r still wins, and an absent pointer still falls back to minting a
# run, so nothing that worked before stops working.
#
# THE POINTER IS KEPT, not just read. RM-134 (#213): a pointer whose run has
# been retired strands the tree, and the answer is a successor written back
# here — so the file it was read from and the key that names it stay in scope.
PTR_FILE=""
RUN_FROM_POINTER=""
if [ -z "$RUN_GIVEN" ] && [ -n "$ROOT" ]; then
  _key="$(printf '%s' "$(CDPATH= cd -- "$ROOT" && pwd -P)" | shasum -a 256 2>/dev/null | cut -c1-32)"
  _ptr="${INNSEGL_RUNS_DIR:-$HOME/.innsegl/runs}/by-tree/$_key"
  if [ -f "$_ptr" ]; then
    RUN_GIVEN="$(sed -n 1p "$_ptr")"
    [ -n "$TASK_GIVEN" ] || TASK_GIVEN="$(sed -n 2p "$_ptr")"
    [ -n "$WORKTREE" ] || WORKTREE="$(sed -n 3p "$_ptr")"
    PTR_FILE="$_ptr"
    TREE_KEY="$_key"
    RUN_FROM_POINTER=1
    # It says what it FOUND and not what it is about to do. Whether this run
    # may still sign is decided below, and the line used to promise "signing
    # under it" several hundred lines before anything had asked.
    echo "innsegl-commit: this tree's pointer names $RUN_GIVEN" >&2
  fi
fi

# The repository identifier the MCP resolves against its workspace: host/org/name.
# doc 02 §5 lowercases the HOST and leaves the org and the name alone, so
# `github.com/KodyMike/Repo` is correct and lowercasing all three would name a
# repository that does not exist on a case-sensitive forge. The hook applies
# the same rule; a difference between the two would show up as a refusal from
# the tool with no obvious cause.
REPO="${INNSEGL_REPO_ID:-$(git remote get-url origin 2>/dev/null \
  | sed -e 's|^[a-z][a-z0-9+.-]*://||' -e 's|^git@||' -e 's|:|/|' -e 's|\.git$||' -e 's|/*$||' \
  | awk -F/ 'NF>=3 { h = tolower($1); p = $2; for (i = 3; i <= NF; i++) p = p "/" $i; print h "/" p }')}"
[ -n "$REPO" ] || { echo "innsegl-commit: no origin remote; set INNSEGL_REPO_ID" >&2; exit 2; }

# THE TREE EVERY GIT READ BELOW IS ABOUT.
#
# `-w` names the working tree this run works in, and until now the script took
# it, passed it to sign_commit, and then read the INDEX from wherever it
# happened to be invoked. A field agent hit exactly that: run from the
# repository root with `-w` pointing at a worktree whose index was full, and
# the script answered "nothing staged" about a tree that was staged somewhere
# else. The message pointed the wrong way, twice, and CLAUDE.md says to pass
# `-w` -- it does not say the shell also has to be standing in that directory.
#
# So `-w` decides where git reads, not only what sign_commit is told. Absolute
# is taken as given; relative is MCP-029's meaning, a linked worktree of this
# repository.
# RELATIVE TO THE MAIN WORKTREE, NEVER TO WHERE YOU HAPPEN TO STAND.
#
# `git rev-parse --show-toplevel` answers with the LINKED worktree when you are
# standing in one, and MCP-029's `worktree` is relative to the REPOSITORY. Join
# the two and you get the path twice:
#
#   .worktrees/583/.worktrees/583
#
# reported from the field on 2026-09-10, along with the other half: run from a
# linked worktree with no -w at all, the script read that worktree's index while
# sign_commit committed in the main checkout, and the staged_ref check refused
# the mismatch. Between them there was no way to sign from a worktree, which is
# where a subagent works.
#
# `git worktree list` reports the main worktree first from inside any linked
# one, so it is the one stable base both cases can be resolved against.
MAIN_WT="$(git worktree list --porcelain 2>/dev/null | awk '/^worktree /{print $2; exit}')"
[ -n "$MAIN_WT" ] || MAIN_WT="$ROOT"
HERE_WT="$(cd "$ROOT" 2>/dev/null && pwd -P)"
MAIN_WT="$(cd "$MAIN_WT" 2>/dev/null && pwd -P)"

# AND IT DERIVES ITSELF WHEN YOU DID NOT PASS IT. Standing in a linked worktree
# is the whole signal; asking the caller to say so as well is asking them to
# repeat what the shell already knows, and the field report is what that costs.
if [ -z "$WORKTREE" ] && [ -n "$HERE_WT" ] && [ "$HERE_WT" != "$MAIN_WT" ]; then
  case "$HERE_WT" in
    "$MAIN_WT"/*) WORKTREE="${HERE_WT#"$MAIN_WT"/}" ;;
    # A worktree that is NOT under the main one -- a SIBLING, which is what
    # `git worktree add ../name` makes and what an operator gets by default.
    # The case above only matched a nested worktree, so standing in a sibling
    # fell through with WORKTREE empty, WT became the MAIN worktree, and the
    # commit was made from the wrong tree's index entirely; the branch recorded
    # was the trunk's. MEASURED 2026-09-10 on a sibling worktree: branch came
    # out `main` where `feat/apts-se-005` was checked out under the cursor.
    #
    # Absolute, because it cannot be expressed relative to the main worktree.
    # The re-expression below leaves an absolute path alone, and sign_commit
    # refuses one it cannot see rather than signing the wrong tree quietly.
    *) WORKTREE="$HERE_WT" ;;
  esac
fi

case "$WORKTREE" in
  "")  WT="$MAIN_WT" ;;
  /*)  WT="$WORKTREE" ;;
  *)
    # Against the main worktree first, because that is what -w means. Then
    # against where you are standing, because a caller who typed the path they
    # can see is not wrong in any way worth refusing over.
    if [ -d "$MAIN_WT/$WORKTREE" ]; then WT="$MAIN_WT/$WORKTREE"
    elif [ "$HERE_WT" != "${HERE_WT%/"$WORKTREE"}" ]; then WT="$HERE_WT"
    elif [ -d "$PWD/$WORKTREE" ]; then WT="$PWD/$WORKTREE"
    else WT="$MAIN_WT/$WORKTREE"
    fi
    ;;
esac
if [ ! -d "$WT" ]; then
  echo "innsegl-commit: -w $WORKTREE names no directory." >&2
  echo "innsegl-commit:   tried $MAIN_WT/$WORKTREE" >&2
  [ "$HERE_WT" != "$MAIN_WT" ] && echo "innsegl-commit:   and    $HERE_WT" >&2
  exit 2
fi
# Re-expressed relative to the repository, which is what sign_commit's argument
# means; an absolute path here would name a directory the server cannot see.
case "$WT" in
  "$MAIN_WT")   WORKTREE="" ;;
  "$MAIN_WT"/*) WORKTREE="${WT#"$MAIN_WT"/}" ;;
  *)
    # A worktree of this repository that is not INSIDE it. sign_commit resolves
    # a worktree beneath the repository the MCP has linked, so there is no
    # argument that names this one and the server cannot reach it.
    #
    # Refused loudly rather than passed on. Before sibling worktrees were
    # recognised at all this fell through to the MAIN worktree and signed THAT
    # tree's index under this tree's name: the wrong content, attributed
    # confidently. A refusal an operator can act on is the better failure.
    echo "innsegl-commit: $WT is a worktree of this repository but is not inside it." >&2
    echo "innsegl-commit:   sign_commit reaches a worktree beneath the linked repository," >&2
    echo "innsegl-commit:   so this one has no name it can resolve." >&2
    echo "innsegl-commit:" >&2
    echo "innsegl-commit:   Either link it as a repository of its own:" >&2
    echo "innsegl-commit:     make -C <innsegl> innsegl-link DIR=$WT" >&2
    echo "innsegl-commit:   or keep worktrees inside the repository:" >&2
    echo "innsegl-commit:     git worktree add .worktrees/<name> -b <branch>" >&2
    exit 2
    ;;
esac

# The task, from the branch. Same derivation the harness hook uses, and for the
# same reason: doc 02 §5's grammar is [a-z0-9][a-z0-9-]{0,62}, so a branch name
# with a slash is refused. An RM number is this project's own task identifier.
# symbolic-ref first: on an unborn branch rev-parse fails and the branch would
# be recorded as "detached", and under ADR-0045 `branch` is a member of
# run_registered rather than a log line.
BRANCH="$(git -C "$WT" symbolic-ref --short --quiet HEAD 2>/dev/null)"
[ -n "$BRANCH" ] || BRANCH="$(git -C "$WT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo detached)"
[ -n "$BRANCH" ] && [ "$BRANCH" != "HEAD" ] || BRANCH="detached"
TASK="$(printf '%s' "$BRANCH" | tr 'A-Z' 'a-z' | sed -n 's/.*\(rm[0-9][0-9]*\).*/\1/p')"
if [ -z "$TASK" ]; then
  TASK="$(printf '%s' "$BRANCH" | tr 'A-Z' 'a-z' \
    | sed -e 's/[^a-z0-9-]/-/g' -e 's/^[^a-z0-9]*//' -e 's/--*/-/g' -e 's/-*$//' | cut -c1-63)"
fi
[ -n "$TASK" ] || TASK="unnamed"
[ -n "$TASK_GIVEN" ] && TASK="$TASK_GIVEN"

# The staged tree, and a refusal when there is nothing staged. `git commit`
# refuses an empty commit by default and so does this.
TREE="$(git -C "$WT" write-tree)"
if [ "$TREE" = "$(git -C "$WT" rev-parse HEAD^{tree} 2>/dev/null || echo none)" ]; then
  # NAMING THE TREE IS THE POINT. "nothing staged" without it sent an agent
  # looking for a staging mistake it had not made; the mistake was that this
  # script was reading a different index from the one it had been told about.
  echo "innsegl-commit: nothing staged in $WT — its index is identical to HEAD." >&2
  if [ "$WT" != "$ROOT" ]; then
    echo "innsegl-commit:   That is the tree -w named. If you staged your work" >&2
    echo "innsegl-commit:   somewhere else, pass -w for THAT tree instead." >&2
  fi
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
# #266 — THE CREDENTIAL, HELD FOR ONE PROCESS AND WRITTEN NOWHERE.
#
# One variable. Not exported, so it does not reach a single child but the ones
# handed it deliberately; not written, so no file on this machine holds it; not
# logged, so no line of this script's output carries it. It starts empty and
# stays empty unless the listener refuses a call, which is what makes a
# deployment with no credential check indistinguishable from this script's
# behaviour before #266 existed.
# ---------------------------------------------------------------------------
ADMIN_CRED=""

# The deployment this machine's key lives in. Both are the shipped defaults
# from deploy/compose/innsegl.yml, and both are overridable for a deployment
# that renamed its project or its image.
ADMIN_KEY_VOLUME="${INNSEGL_ADMIN_KEY_VOLUME:-${COMPOSE_PROJECT_NAME:-innsegl-core}_innsegl-admin-key}"
ADMIN_KEY_PATH="${INNSEGL_ADMIN_KEY_PATH:-/k/signing.key}"
INNSEGL_IMAGE_REF="${INNSEGL_IMAGE:-innsegl:local}"

# admin_cred_config prints a `curl -K` configuration, and prints nothing at all
# when there is no credential or the call is not bound for the admin listener.
#
# A CONFIGURATION ON A PIPE, never `-H` on a command line, and never a here
# document. `ps` shows the argument vector of every process on this machine, so
# a bearer token passed as an argument is a token any local process can replay
# for the rest of its fifteen minutes. A here document is a temporary FILE in
# most shells, which is the same disclosure with a shorter life. `printf` is a
# builtin writing into a pipe: no argument vector, no file, no descriptor that
# outlives the call.
#
# The token is base64url and dots throughout, so nothing in it needs escaping
# inside curl'"'"'s quoted configuration value.
admin_cred_config() {
  [ -n "$ADMIN_CRED" ] || return 0
  [ "${1:-}" = "$ADMIN_URL" ] || return 0
  printf 'header = "Authorization: Bearer %s"\n' "$ADMIN_CRED"
}

# mint_admin_credential fills $ADMIN_CRED with one credential for this
# repository, or explains what to run and returns non-zero.
#
# THE KEY IS READ WHERE IT LIVES AND NOWHERE ELSE: on the volume the
# deployment'"'"'s one-shot wrote it to, mounted read-only into a container with no
# network, no writable root filesystem and no privilege escalation, which
# prints one credential on stdout and exits. Nothing copies the key to this
# machine, and this script never sees it — the only value that crosses the
# boundary is the credential itself, on a pipe.
#
# `--user 0:0` because the one-shot leaves the key 0400 and root-owned, which
# is the point: the image'"'"'s own 1000:1000 cannot read it, so a compromised
# innsegl-mcp — which does not mount this volume at all — could not either.
mint_admin_credential() {
  _scope="${INNSEGL_REPO_ID:-$REPO}"
  ADMIN_CRED=""
  if [ -n "${INNSEGL_ADMIN_CREDENTIAL_MINT:-}" ]; then
    # An operator whose signing key is not on this machine'"'"'s container volume:
    # any command that prints one credential for the repository it is given.
    # Deliberately word-split, because a command with its own arguments is the
    # normal case.
    # shellcheck disable=SC2086
    if ADMIN_CRED="$($INNSEGL_ADMIN_CREDENTIAL_MINT "$_scope" 2>/dev/null)"; then :; else ADMIN_CRED=""; fi
  elif command -v docker >/dev/null 2>&1; then
    if ADMIN_CRED="$(docker run --rm --network none --read-only --user 0:0 \
        --security-opt no-new-privileges \
        -v "$ADMIN_KEY_VOLUME:$(dirname "$ADMIN_KEY_PATH"):ro" \
        "$INNSEGL_IMAGE_REF" \
        admin-credential mint -key "$ADMIN_KEY_PATH" -repo "$_scope" 2>/dev/null)"; then :; else ADMIN_CRED=""; fi
  fi
  ADMIN_CRED="$(printf '%s' "$ADMIN_CRED" | tr -d '\r\n')"
  [ -n "$ADMIN_CRED" ] || { credential_remedy "$_scope"; return 1; }
  return 0
}

# credential_remedy — a refusal that says what to run.
#
# A 401 with no remedy strands an agent holding finished work, which is the
# whole failure #266 exists to prevent: the listener'"'"'s own answer is one
# byte-identical sentence by design, because a distinguishable reason is an
# oracle, so the only place an operator can be told what to do is here.
CRED_REMEDY_SAID=""
credential_remedy() {
  # ONCE PER PROCESS. The retirement trap runs on the way out of a failure, so
  # a repeated remedy would print the same eighteen lines under the message
  # that already explained them.
  [ -z "$CRED_REMEDY_SAID" ] || return 0
  CRED_REMEDY_SAID=1
  echo "innsegl-commit: the identity-lifecycle listener at $ADMIN_URL requires a" >&2
  echo "innsegl-commit:   repository-scoped credential, and none could be minted for" >&2
  echo "innsegl-commit:   $1." >&2
  echo "innsegl-commit:" >&2
  echo "innsegl-commit:   Mint one against this deployment's signing key:" >&2
  echo "innsegl-commit:     docker run --rm --network none --user 0:0 \\" >&2
  echo "innsegl-commit:       -v $ADMIN_KEY_VOLUME:$(dirname "$ADMIN_KEY_PATH"):ro $INNSEGL_IMAGE_REF \\" >&2
  echo "innsegl-commit:       admin-credential mint -key $ADMIN_KEY_PATH -repo $1" >&2
  echo "innsegl-commit:" >&2
  echo "innsegl-commit:   That key is written by the deployment's own one-shot, so if the" >&2
  echo "innsegl-commit:   volume is empty the stack has never been up with the identity" >&2
  echo "innsegl-commit:   lifecycle split out:" >&2
  echo "innsegl-commit:     make innsegl-up-here" >&2
  echo "innsegl-commit:" >&2
  echo "innsegl-commit:   Minting elsewhere: set INNSEGL_ADMIN_CREDENTIAL_MINT to a command" >&2
  echo "innsegl-commit:   that prints one credential for the repository it is given." >&2
  echo "innsegl-commit:" >&2
  echo "innsegl-commit:   The listener will never say why a credential is inadmissible —" >&2
  echo "innsegl-commit:   one byte-identical refusal is deliberate. Ask on your own" >&2
  echo "innsegl-commit:   machine instead:  innsegl admin-credential verify -jwks <set>" >&2
}

# ---------------------------------------------------------------------------
# One MCP call. Session per call: this is a short-lived process with nowhere to
# keep one, against a server on loopback.
#
# THE REFUSAL IS THE ONLY TRIGGER (#266). mcp_once carries whatever credential
# is held — none, at first — and reports a 401 as status 3. mcp answers that by
# minting one and repeating the SAME call once, which covers both the first
# call of a process and a credential that aged out mid-run: this script'"'"'s
# `sign_commit` may take minutes and the credential lives fifteen.
#
# EXACTLY ONCE, because a loop here is a loop against a server that has already
# said no. A second 401 is reported to the caller with the remedy above.
# ---------------------------------------------------------------------------
mcp() {
  if _mcp_out="$(mcp_once "$1" "$2" "$3")"; then _mcp_rc=0; else _mcp_rc=$?; fi
  if [ "$_mcp_rc" -eq 3 ]; then
    mint_admin_credential || return 3
    if _mcp_out="$(mcp_once "$1" "$2" "$3")"; then _mcp_rc=0; else _mcp_rc=$?; fi
    if [ "$_mcp_rc" -eq 3 ]; then
      echo "innsegl-commit: the credential this process minted was refused as well." >&2
      credential_remedy "${INNSEGL_REPO_ID:-$REPO}"
      return 3
    fi
  fi
  printf '%s' "$_mcp_out"
  return "$_mcp_rc"
}

# mcp_once URL TOOL ARGS — one attempt, with whatever credential is held.
#
#   0  the server answered; the answer may still be an IP §4 error result
#   1  the transport failed
#   3  the listener refused the credential
#
# THE STATUS IS READ ON EVERY REQUEST, not only the first. #264 wraps the whole
# admin handler, so `initialize` is refused on the same terms as a tool call —
# and a credential that expires between the handshake and the call is refused
# there instead. Reading only the first would turn that into an empty answer
# and a generic "could not be reached".
mcp_once() {
  _url="$1"; _tool="$2"; _args="$3"
  _hdr="$(mktemp)"
  admin_cred_config "$_url" | curl -sS -K - --max-time 30 --dump-header "$_hdr" \
    -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    --data-binary '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"innsegl-commit","version":"v0"}}}' \
    "$_url" >/dev/null 2>&1 || { rm -f "$_hdr"; return 1; }
  if refused_401 "$_hdr"; then rm -f "$_hdr"; return 3; fi
  _sid="$(sed -n 's/^[Mm]cp-[Ss]ession-[Ii]d:[[:space:]]*//p' "$_hdr" | tr -d '\r' | head -n 1)"
  rm -f "$_hdr"
  [ -n "$_sid" ] || return 1
  admin_cred_config "$_url" | curl -sS -K - --max-time 10 -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' -H "Mcp-Session-Id: $_sid" \
    --data-binary '{"jsonrpc":"2.0","method":"notifications/initialized"}' "$_url" >/dev/null 2>&1
  _hdr="$(mktemp)"
  if _body="$(admin_cred_config "$_url" | curl -sS -K - --max-time 300 --dump-header "$_hdr" \
      -H 'Content-Type: application/json' \
      -H 'Accept: application/json, text/event-stream' -H "Mcp-Session-Id: $_sid" \
      --data-binary "$(printf '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"%s","arguments":%s}}' "$_tool" "$_args")" \
      "$_url" 2>/dev/null)"; then :; else rm -f "$_hdr"; return 1; fi
  if refused_401 "$_hdr"; then rm -f "$_hdr"; return 3; fi
  rm -f "$_hdr"
  printf '%s' "$_body" | sed -n 's/^data: //p' | head -n 1
}

# refused_401 reads one dumped status line. A redirect would leave several in
# the file, so the LAST status line is the one that answered.
refused_401() {
  case "$(grep -a '^HTTP/' "$1" 2>/dev/null | tail -n 1 | tr -d '\r')" in
    *' 401 '*|*' 401') return 0 ;;
    *) return 1 ;;
  esac
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

# register_run KEY -- one registration, setting REGISTERED_RUN.
#
# It is a function because there are now two callers: the run this script mints
# for a tree with no pointer, and the SUCCESSOR a retired pointer needs. Two
# copies would be two things that can disagree about repo, branch or the
# schema-1 fallback below -- and the fallback is the half nobody exercises
# until a deployment is mid-upgrade, which is exactly when a divergence bites.
#
# repo and branch are required members of run_registered under schema 2
# (ADR-0045), and this script already resolves both -- it just used to keep
# them to itself, so a run it registered recorded nowhere it worked unless the
# signature that followed happened to succeed.
#
# AND IT FALLS BACK, because a client and a server upgrade at different
# moments. The MCP SDK validates arguments against the tool's advertised
# inputSchema and refuses additional properties outright:
#
#   validating "arguments": validating root: unexpected additional
#   properties ["repo" "branch"]
#
# So a new script against a not-yet-restarted server does not degrade, it
# STOPS -- and stopping means no identity, which means the human cannot commit
# at all. The second attempt drops the two members and registers the schema 1
# event that server still writes. Nothing is lost that was not already absent
# before ADR-0045, and the moment the deployment is restarted the first attempt
# succeeds again.
#
# The retry is driven by the PAYLOAD, not by the exit status: `mcp` returns 0
# for a JSON-RPC error, because the transport worked and the server answered.
# `field` is what reads the answer, so `field` is what decides.
REGISTERED_RUN=""
register_run() {
  _rk="$1"
  # A CREDENTIAL REFUSAL IS NOT AN UNREACHABLE SERVER, and saying so would send
  # an operator to `make innsegl-up-here` about a deployment that is up and
  # answering. `mcp` returns 3 for that case and has already printed the one
  # remedy there is; anything else is the transport.
  if _out="$(mcp "$ADMIN_URL" register_agent \
    "$(printf '{"agent_type":"%s","task_id":"%s","idempotency_key":"%s","repo":"%s","branch":"%s"}' \
      "$AGENT_TYPE" "$TASK" "$_rk" "$REPO" "$BRANCH")")"; then :; else
    [ "$?" -eq 3 ] && exit 1
    fail "the identity service at $ADMIN_URL could not be reached. No identity, no attributed work (IP §6.1). Try: make innsegl-up-here"
  fi
  if REGISTERED_RUN="$(printf '%s' "$_out" | field run_id 2>/dev/null)"; then
    return 0
  fi
  if _out="$(mcp "$ADMIN_URL" register_agent \
    "$(printf '{"agent_type":"%s","task_id":"%s","idempotency_key":"%s"}' \
      "$AGENT_TYPE" "$TASK" "$_rk")")"; then :; else
    [ "$?" -eq 3 ] && exit 1
    fail "the identity service at $ADMIN_URL could not be reached. No identity, no attributed work (IP §6.1). Try: make innsegl-up-here"
  fi
  REGISTERED_RUN="$(printf '%s' "$_out" | field run_id)" || fail "register_agent refused"
  echo "innsegl-commit: this deployment does not accept repo/branch yet, so the run" >&2
  echo "innsegl-commit:   records no repository (schema 1). Restart it to fix that:" >&2
  echo "innsegl-commit:   make innsegl-up-here" >&2
}

# run_state RUN -- what the ledger says about a run, in one word:
#
#   active   registered, not retired, not expired -- it may sign
#   retired  `run_retired` is on the chain (IP §6.2)
#   expired  `run_expired` is -- the reaper took it (IP §6.7)
#   absent   this ledger holds no such run
#   unknown  the question could not be asked
#
# It asks the READ api and nothing else. The alternatives were worse: every
# write tool that refuses a retired run also does something to a live one, so
# probing with `get_credential` would append a `credential_issued` on the happy
# path, and probing by calling `sign_commit` and reading the refusal is exactly
# the "after the fact" this exists to get in front of.
#
# `unknown` is deliberately not `retired`. A probe that did not run is not
# evidence that a run is dead, and treating it as one would strand every tree
# in the deployment whenever the read API was down -- the same bug as #213 with
# a wider blast radius.
run_state() {
  _rs="$(curl -s --connect-timeout 2 --max-time 5 -w '\n%{http_code}' \
    "$API_URL/api/v1/runs/$1" 2>/dev/null)" || { echo unknown; return 0; }
  case "$(printf '%s' "$_rs" | tail -n 1)" in
    200)
      printf '%s' "$_rs" | sed '$d' | python3 -c '
import json,sys
try:
    s = json.load(sys.stdin).get("status", "")
except Exception:
    s = ""
print(s if s in ("active", "retired", "expired") else "unknown")' 2>/dev/null \
        || echo unknown
      ;;
    404) echo absent ;;
    *)   echo unknown ;;
  esac
}

# ---- 0. the run this tree points at has to be one that may still sign -------
#
# RM-134 (#213). Until now whatever the pointer said went straight to
# `sign_commit`, and when the run had been retired the tool refused -- rightly,
# IP §6.2 makes retirement effective immediately -- leaving the tree
# uncommittable by anyone until somebody deleted the pointer by hand. Three
# separate callers hit that in one day and all three invented the same
# workaround. A workaround three people invent on the spot is a missing feature.
#
# WHY A SUCCESSOR AND NOT A RE-REGISTRATION. A run id is a pure function of
# (agent_type, task, idempotency_key) -- registerAgentRunID -- so asking again
# with the same three values DERIVES THE SAME RETIRED ID, `register_agent`
# replays its recorded reply, and the caller is handed the dead run a second
# time. Deleting the pointer does not help for the same reason: the next
# derivation names the same run. The successor therefore has to differ in
# something the derivation SEES, and the one thing free to vary is the key.
#
# SO THE KEY NAMES THE RUN IT SUCCEEDS. That makes it distinct -- no key that
# produced the predecessor can contain the predecessor's own id -- and it makes
# the succession a RECORD rather than a log line: register_agent writes the
# idempotency key into `run_registered`, so the chain itself says which run
# this one continues. observe_session made the same move for its markers, and
# for the same reason.
#
# It is also DETERMINISTIC, keyed on the retired run and the tree. A crash
# between the registration and the pointer rewrite, or a pointer that cannot be
# written at all, leaves the next attempt deriving the same successor instead
# of minting a second identity for one tree (IP §6.6).
#
# Only a run resolved FROM THE POINTER is succeeded. An explicit -r means that
# run and nothing else -- the harness signs a subagent's leftover work under it
# so the work is attributed to the agent that did it (ADR-0046) -- and quietly
# turning that into a different agent's commit is precisely the swap this
# project exists not to make. A retired -r still goes to `sign_commit` and is
# still refused there, by the tool, naming the run the caller named.
if [ -n "$RUN_GIVEN" ] && [ -n "$RUN_FROM_POINTER" ]; then
  case "$(run_state "$RUN_GIVEN")" in
    retired|expired)
      SUPERSEDED="$RUN_GIVEN"
      echo "innsegl-commit: $SUPERSEDED is no longer a run that may sign." >&2
      echo "innsegl-commit:   Registering a SUCCESSOR for this tree rather than" >&2
      echo "innsegl-commit:   re-deriving, which would name the same dead run." >&2
      register_run "succeeds-$SUPERSEDED-$TREE_KEY"
      RUN_GIVEN="$REGISTERED_RUN"
      echo "innsegl-commit: $SUPERSEDED  ->  $RUN_GIVEN" >&2
      echo "innsegl-commit:   this tree's work now spans two runs, and the successor's" >&2
      echo "innsegl-commit:   run_registered carries the key that names the first." >&2
      # THE POINTER CARRIES THE SUCCESSION TOO. Line 4 is new and inert: the
      # hook writes three lines and this script reads three, so a reader that
      # predates it is unaffected, and a human opening the file can see the
      # tree did not always belong to the run at the top of it.
      if printf '%s\n%s\n%s\nsuperseded %s\n' \
           "$RUN_GIVEN" "$TASK" "$WORKTREE" "$SUPERSEDED" > "$PTR_FILE" 2>/dev/null; then
        :
      else
        echo "innsegl-commit: the pointer could not be rewritten; it still names $SUPERSEDED." >&2
        echo "innsegl-commit:   Harmless: the successor is derived from that run and this" >&2
        echo "innsegl-commit:   tree, so the next commit finds $RUN_GIVEN again rather than" >&2
        echo "innsegl-commit:   registering a second identity for one tree (IP §6.6)." >&2
      fi
      ;;
    absent)
      # NOT a retirement, and not something to register over. A pointer naming
      # a run the ledger never held means the pointer is wrong or it belongs to
      # another deployment; inventing an identity here would attribute this
      # tree's work to a run whose own history cannot be found, which is the
      # opposite of what the pointer is for.
      echo "innsegl-commit: this tree's pointer names $RUN_GIVEN, which the ledger" >&2
      echo "innsegl-commit:   at $API_URL has never held." >&2
      echo "innsegl-commit:" >&2
      echo "innsegl-commit:   A run that never existed is a broken pointer, not a" >&2
      echo "innsegl-commit:   retirement, so nothing is registered in its place." >&2
      echo "innsegl-commit:" >&2
      echo "innsegl-commit:   Either this is the wrong deployment -- check INNSEGL_API_URL" >&2
      echo "innsegl-commit:   and INNSEGL_RUNS_DIR name the same one -- or the pointer is" >&2
      echo "innsegl-commit:   stale and removing it lets this script mint a run:" >&2
      echo "innsegl-commit:     rm $PTR_FILE" >&2
      exit 1
      ;;
    unknown)
      echo "innsegl-commit: whether $RUN_GIVEN may still sign could not be asked of" >&2
      echo "innsegl-commit:   $API_URL, so this goes ahead as it always did. If the run" >&2
      echo "innsegl-commit:   has been retired, sign_commit is what will say so." >&2
      ;;
  esac
fi

# ---- 1. an identity ---------------------------------------------------------
if [ -n "$RUN_GIVEN" ]; then
  # Somebody else's run, and somebody else's to retire. See -r.
  RUN="$RUN_GIVEN"
  echo "innsegl-commit: signing under the existing run $RUN (task $TASK)"
else
  register_run "$RUN_KEY"
  RUN="$REGISTERED_RUN"
  echo "innsegl-commit: run $RUN  (agent $AGENT_TYPE, task $TASK)"

  # retire whatever happens next, including a failure. An identity left live
  # after a failed signature is exactly the orphan retirement exists to prevent.
  #
  # A SUCCESSOR IS NOT RETIRED HERE, and that is why it is registered above
  # this branch rather than inside it. The pointer now names it, so the tree's
  # next commit has to find it alive; retiring it on the way out would leave
  # the pointer naming a retired run again, which is the bug. It ends the way
  # the harness's own run ends -- retired by whoever owns the session, or
  # expired by the reaper as run_expired (IP §6.7).
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
# The refusal must not claim a rollback that did not happen (RM-145, #229). sign_commit
# creates the commit and then verifies it, so a Phase C failure leaves the commit
# AT HEAD, carrying its identity trailers, and absent from the ledger. Telling an
# operator "nothing was committed" is exactly what makes them commit again or
# reset, on the strength of a claim this tool never honoured. So ask git what is
# actually there rather than asserting it.
if ! SHA="$(printf '%s' "$SIGNED" | field commit_sha)"; then
  HEAD_NOW="$(git -C "$WT" rev-parse --short HEAD 2>/dev/null || echo '?')"
  HEAD_SUBJ="$(git -C "$WT" log -1 --format='%s' 2>/dev/null || echo '')"
  # AN EMPTY INDEX IS THE TELL. This script refuses at the top unless the index
  # differs from HEAD, so if it matches HEAD now, the commit happened between
  # then and this line -- which is Phase B, and Phase B is where the Rekor entry
  # is made too. There is no other way to reach this state.
  if git -C "$WT" diff --cached --quiet 2>/dev/null; then
    echo "innsegl-commit: sign_commit refused AFTER the commit was made." >&2
    echo "innsegl-commit:" >&2
    echo "innsegl-commit:   ${HEAD_NOW}${HEAD_SUBJ:+  $HEAD_SUBJ}" >&2
    echo "innsegl-commit:" >&2
    echo "innsegl-commit:   is at HEAD, carrying its identity trailers, and Rekor holds" >&2
    echo "innsegl-commit:   its entry. What is missing is the ledger's commit_recorded." >&2
    echo "innsegl-commit:   Nothing rolls back: the two phases are narrow by ordering and" >&2
    echo "innsegl-commit:   not by cleanup, so no failure here undoes a commit." >&2
    echo "innsegl-commit:" >&2
    echo "innsegl-commit:   DO NOT commit again and DO NOT reset. A second commit is a" >&2
    echo "innsegl-commit:   second signature for one change; a reset destroys a commit" >&2
    echo "innsegl-commit:   whose Rekor entry is already public and permanent." >&2
    echo "innsegl-commit:" >&2
    echo "innsegl-commit:   The repair is the reconciler's. It matches the Rekor entry to" >&2
    echo "innsegl-commit:   the intent and appends the record that is missing:" >&2
    echo "innsegl-commit:" >&2
    echo "innsegl-commit:     innsegl reconcile -once" >&2
    exit 1
  fi
  fail "sign_commit refused and the index is still staged; HEAD is $HEAD_NOW. Nothing was committed."
fi
IDX="$(printf '%s' "$SIGNED" | field rekor_entry.log_index 2>/dev/null || echo '?')"

echo "innsegl-commit: signed $(git -C "$WT" rev-parse --short "$SHA")  rekor index $IDX"
git --no-pager log -1 --format='  %s' "$SHA"
