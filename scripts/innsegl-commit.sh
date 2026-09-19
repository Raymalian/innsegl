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
#   scripts/innsegl-commit.sh -p src/a.go -p src/b.go -m "fix(thing): what changed"
#   scripts/innsegl-commit.sh -p src/a.go -F /path/to/message
#
# `-p` names a path this commit is of. It stages that path and it BOUNDS the
# commit: if the index holds anything else, the whole commit is refused, naming
# the path that is not yours.
#
# # WHY YOU HAVE TO NAME THEM — #280
#
# `git commit` commits THE INDEX, and the index belongs to the working tree
# rather than to you. Measured on 2026-09-19: two writers shared one tree, one
# staged a single file and asked for a signature, and this script refused —
# correctly, the index had moved under it. Seconds later the other writer
# committed and its commit carried three files: its own two, and the one the
# first writer had staged. Nothing was lost. What landed was worse than a loss:
# a signed, permanent, verifiable record of work its message and its identity
# did not name, and the writer who had done nothing wrong was the one refused.
#
# `git add -A` is how that happens and it is why the line above this one used to
# say it. Nothing here can tell one writer's `git add` from another's, and no
# amount of locking inside this script can reach backwards over a `git add` made
# minutes earlier in a process it never saw. The only party who knows which
# paths are yours is you, so you say, and this holds the commit to it.
#
# It is the bound #261 put on the harness's capture path, asked here: what would
# be COMMITTED must be a subset of what the caller can account for. Only the
# source of the accounting differs — a stopped run cannot be asked anything, so
# a capture reads its own tool-call bodies; a caller that is still running says.
#
# THE ONE CALLER THAT NEED NOT. `-r` is the harness signing a stopped
# subagent's leftover work, and scripts/hooks/ has already asked this question
# of that index before it gets here (#261). It is also the one caller that
# cannot be asked to change its mind, because the run whose work it is has
# already gone.
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
  echo "usage: innsegl-commit.sh -p <path> [-p <path>…] -m <message> | -F <file>" >&2
  echo "                        [-p <path>]     a path this commit is of; repeatable" >&2
  echo "                        [-r <run_id>]   sign under an existing run, do not retire it" >&2
  echo "                        [-w <path>]     a linked worktree of this repository" >&2
  echo "                        [-t <task>]     the task the run was registered with" >&2
  echo "       -p stages the path AND bounds the commit: an index holding anything" >&2
  echo "       you did not name is refused rather than signed under your identity." >&2
  exit 2
}

[ $# -gt 0 ] || usage

# A newline, spelled once. `-p` accumulates into one newline-separated variable
# because POSIX sh has no arrays, and a path holding a newline is refused where
# it is given rather than silently split into two here.
NL="$(printf '\nx')"; NL="${NL%x}"

MESSAGE=""
RUN_GIVEN=""
WORKTREE=""
TASK_GIVEN=""
PATHS=""
# Set only by a `-r` ON THE COMMAND LINE, and read only by the bound below. A
# run resolved from this tree's pointer sets RUN_GIVEN too, and it is an
# ordinary agent committing its own work -- the case the bound is for.
R_EXPLICIT=""
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
    -r) [ $# -ge 2 ] || usage; RUN_GIVEN="$2"; R_EXPLICIT=1; shift 2 ;;
    # -p: a path this commit is of, relative to the tree being committed or to
    # where you are standing. Repeatable. #280.
    #
    # A NEWLINE IS REFUSED RATHER THAN CARRIED. Git can hold such a path and
    # this list cannot: it is newline-separated all the way to the JSON that
    # names it, and a path that split in two would name a file nobody meant.
    # Refusing it costs a caller nothing — git quotes such a name in its own
    # output, so it is already unusable by hand.
    -p) [ $# -ge 2 ] || usage
        case "$2" in
          *"$NL"*)
            echo "innsegl-commit: -p names a path containing a newline, which this" >&2
            echo "innsegl-commit:   cannot carry without splitting it into two names." >&2
            exit 2 ;;
          "")
            echo "innsegl-commit: -p needs a path." >&2
            exit 2 ;;
        esac
        PATHS="$PATHS$2$NL"
        shift 2 ;;
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
RUNS_DIR="${INNSEGL_RUNS_DIR:-$HOME/.innsegl/runs}"
TREE_KEY=""
if [ -n "$ROOT" ]; then
  TREE_KEY="$(printf '%s' "$(CDPATH= cd -- "$ROOT" && pwd -P)" | shasum -a 256 2>/dev/null | cut -c1-32)"
fi

PTR_FILE=""
RUN_FROM_POINTER=""
if [ -z "$RUN_GIVEN" ] && [ -n "$TREE_KEY" ]; then
  _ptr="$RUNS_DIR/by-tree/$TREE_KEY"
  if [ -f "$_ptr" ]; then
    RUN_GIVEN="$(sed -n 1p "$_ptr")"
    [ -n "$TASK_GIVEN" ] || TASK_GIVEN="$(sed -n 2p "$_ptr")"
    [ -n "$WORKTREE" ] || WORKTREE="$(sed -n 3p "$_ptr")"
    PTR_FILE="$_ptr"
    RUN_FROM_POINTER=1
    # It says what it FOUND and not what it is about to do. Whether this run
    # may still sign is decided below, and the line used to promise "signing
    # under it" several hundred lines before anything had asked.
    echo "innsegl-commit: this tree's pointer names $RUN_GIVEN" >&2
  fi
fi

# THE SESSION THIS TREE BELONGS TO, and so the parent of any run registered
# here -- RM-156 (#259).
#
# Measured 2026-09-18: 87 `orchestrator` runs in the ledger, every one of them
# registered by this script, and not one carrying a parent. The reason was not
# that they had none. It is that a shell command cannot discover which agent it
# is inside: no environment variable carries an agent or a session id, which is
# the same gap the by-tree pointer above was written to close for identity.
#
# So the harness hook writes a SECOND pointer at SessionStart, keyed on the
# same working tree and answering a different question: not "which run signs
# here" but "which session is this tree's". Line 1 is that session's run, and
# it is what this script names as the parent of whatever it registers.
#
# WHY IT CANNOT COLLIDE WITH THE POINTER ABOVE. The subagent pointer's name is
# exactly the 32 hex characters of the tree key, and SubagentStop removes that
# exact name; this one carries a `.session` suffix, which no tree key can
# spell. Two pointers, two lifetimes: the subagent's lasts as long as the
# subagent, this one as long as the session.
#
# Absent is not an error, and it is the ordinary state of a tree whose session
# started before the hook wrote one, or on a machine with no harness at all.
# The run is then registered as a root run, exactly as it always was.
PARENT_RUN=""
if [ -n "$TREE_KEY" ] && [ -f "$RUNS_DIR/by-tree/$TREE_KEY.session" ]; then
  PARENT_RUN="$(sed -n 1p "$RUNS_DIR/by-tree/$TREE_KEY.session")"
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

# ---------------------------------------------------------------------------
# WHAT THIS COMMIT IS OF — #280 (RM-175).
#
# #261 bound the harness's CAPTURE path: a stop refuses to sign when the index
# holds anything the stopping run cannot show it wrote, and it refuses the WHOLE
# capture rather than narrowing it, because narrowing means unstaging work that
# belongs to somebody else. A caller committing its own work goes down this path
# instead, and this path had no such bound at all.
#
# ONE RULE, BOTH PATHS. Everything that would be COMMITTED must be a subset of
# what the caller can account for. Only the source of the accounting differs,
# because only it can: a stopped run cannot be asked anything, so #261 reads its
# tool-call bodies; a caller that is still running says, with `-p`.
#
# AND SAYING IS THE BETTER SOURCE. The body store is structurally incomplete —
# a write through a shell redirection names no file — which #261 can afford
# because a capture is a fallback, and this path could not: it would refuse
# every ordinary commit. What a running caller knows, it can simply state.
#
# WHY NOT SERIALISE INSTEAD, which is the other obvious answer. The interleaving
# that caused the incident happened entirely OUTSIDE this script: the second
# writer's `git add` had already landed before its commit ever started, so there
# is no lock this script can take that reaches back over it. A lock would also
# only bind the parties that take it, and the other party is a bare `git add` in
# a shell. Separate indexes fail for the same reason twice over — every writer
# would have to opt in, and the commit is made by a server process that reads
# `.git/index` whatever this script sets. Naming is the only account of "mine"
# that survives contact with a second writer.
#
# THE ORDER IS: account, then stage, then account again. The first pass is what
# keeps a refusal from touching the tree — an index that already holds somebody
# else's path is refused before this script has staged anything, so the work of
# both writers is exactly where they left it. The third is the invariant the
# commit rests on, asked of the index as it now stands. They are the same call
# because two spellings of one rule drift, and the one that drifts is always the
# one nothing runs. #261 makes the same move for the same reason.
# ---------------------------------------------------------------------------

# The top of the tree being committed, which is how `git diff --cached` spells
# every path it reports. A caller types what is in front of it instead, so the
# two have to be reconciled before anything can be compared -- see COMMIT_PATHS.
TOP="$(git -C "$WT" rev-parse --show-toplevel 2>/dev/null || true)"
[ -n "$TOP" ] || TOP="$WT"

if [ -z "$PATHS" ] && [ -z "$R_EXPLICIT" ]; then
  echo "innsegl-commit: name the paths this commit is of, with -p." >&2
  echo "innsegl-commit:" >&2
  echo "innsegl-commit:   \`git commit\` commits the INDEX, and the index belongs to this" >&2
  echo "innsegl-commit:   working tree rather than to you. A commit that named no paths" >&2
  echo "innsegl-commit:   carries whatever anyone else happened to stage, under YOUR" >&2
  echo "innsegl-commit:   identity, permanently and verifiably (#280)." >&2
  echo "innsegl-commit:" >&2
  _staged="$(git -C "$TOP" diff --cached --name-only 2>/dev/null || true)"
  if [ -n "$_staged" ]; then
    echo "innsegl-commit:   The index holds these. Name the ones that are yours:" >&2
    echo "innsegl-commit:" >&2
    printf '%s\n' "$_staged" | while IFS= read -r _p; do
      [ -n "$_p" ] && echo "innsegl-commit:     -p $_p" >&2
    done
  else
    echo "innsegl-commit:   Nothing is staged in $TOP." >&2
    echo "innsegl-commit:   -p stages what it names, so name your paths and run again." >&2
  fi
  exit 2
fi

# COMMIT_PATHS -- the names, reconciled, and the index measured against them.
#
# It prints shell assignments rather than a status because every refusal below
# needs the counts to say anything an operator can act on:
#
#   CP_NAMED          the -p paths, spelled as git spells a staged path
#   CP_BAD            the ones that are not in this tree at all
#   CP_INDEX          1 if the index could be listed
#   CP_STAGED_N       how many paths it holds
#   CP_UNACCOUNTED_N  how many of those were not named
#   CP_UNACCOUNTED    the first of them, for a message a human can act on
#
# -z on the diff, and it is not a detail: without it git QUOTES any path with a
# space or a non-ASCII byte, so the comparison would miss exactly those and
# report them foreign -- a bound that refuses every commit touching a file with
# a space in its name is a bound nobody keeps.
#
# NOTHING IS NORMALISED INTO THE TREE, only resolved within it. A path that
# lands outside is reported in CP_BAD and refused: guessing which tree a caller
# meant is how a path silently becomes foreign, and the caller is then refused
# for staging its own file with nothing to act on.
COMMIT_PATHS='
import os, shlex, subprocess, sys

top, cwd, raw = sys.argv[1], sys.argv[2], sys.argv[3]
top = os.path.realpath(top)
named, bad = [], []
for p in [q for q in raw.split(chr(10)) if q]:
    # Where the caller is STANDING first, because that is what it typed; the top
    # of the tree second, for a caller standing somewhere else entirely -- a
    # linked worktree named by -w, which is the subagent case.
    here = os.path.realpath(p if os.path.isabs(p) else os.path.join(cwd, p))
    if not here.startswith(top + os.sep):
        here = os.path.realpath(os.path.join(top, p))
    if here == top or not here.startswith(top + os.sep):
        bad.append(p)
        continue
    named.append(os.path.relpath(here, top).replace(os.sep, "/"))

staged, index = [], "0"
try:
    done = subprocess.run(("git", "-C", top, "diff", "--cached", "--name-only", "-z"),
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60)
    if done.returncode == 0:
        staged = [q for q in done.stdout.decode("utf-8", "replace").split(chr(0)) if q]
        index = "1"
except Exception:
    index = "0"

unaccounted = sorted(set(staged) - set(named))
for name, value in (
    ("CP_NAMED", chr(10).join(named)),
    ("CP_BAD", chr(10).join(bad)),
    ("CP_INDEX", index),
    ("CP_STAGED_N", str(len(staged))),
    ("CP_UNACCOUNTED_N", str(len(unaccounted))),
    ("CP_UNACCOUNTED", chr(10).join(unaccounted[:10])),
):
    print(name + "=" + shlex.quote(value))
'

# commit_paths -- the variables above, for the -p list as it stands.
#
# Defaulted BEFORE the eval, so a machine with no python3 or a tree that cannot
# be read leaves the caller looking at "the index could not be listed" -- which
# refuses -- rather than at `set -u` killing the script with no explanation.
commit_paths() {
  CP_NAMED=""; CP_BAD=""; CP_INDEX=0; CP_STAGED_N=0; CP_UNACCOUNTED_N=0; CP_UNACCOUNTED=""
  eval "$(python3 -c "$COMMIT_PATHS" "$TOP" "$PWD" "$PATHS" 2>/dev/null)"
}

# paths_refusal -- what a refused commit leaves the caller holding.
#
# A REFUSAL THAT STRANDS THE WORK IS WORSE THAN THE MISATTRIBUTION IT PREVENTS,
# so this names every path that is not accounted for and changes nothing on
# disk. Whoever staged the rest is still the only party who may commit it.
paths_refusal() {
  echo "innsegl-commit: the index of $TOP holds $CP_UNACCOUNTED_N path(s) this commit did" >&2
  echo "innsegl-commit:   not name:" >&2
  printf '%s\n' "$CP_UNACCOUNTED" | while IFS= read -r _p; do
    [ -n "$_p" ] && echo "innsegl-commit:     $_p" >&2
  done
  [ "$CP_UNACCOUNTED_N" -gt 10 ] 2>/dev/null \
    && echo "innsegl-commit:     ... and $((CP_UNACCOUNTED_N - 10)) more" >&2
  echo "innsegl-commit:" >&2
  echo "innsegl-commit:   \`git commit\` commits the index, so signing now would put all of" >&2
  echo "innsegl-commit:   them under this run's identity -- permanently, verifiably, and" >&2
  echo "innsegl-commit:   under a message that does not describe them (#280)." >&2
  echo "innsegl-commit:" >&2
  echo "innsegl-commit:   Nothing was staged or unstaged; every writer's work is where it" >&2
  echo "innsegl-commit:   was. Either name the path with -p because it is yours, or leave" >&2
  echo "innsegl-commit:   it to whoever staged it -- it is theirs to commit." >&2
}

if [ -n "$PATHS" ]; then
  commit_paths
  if [ -n "$CP_BAD" ]; then
    echo "innsegl-commit: -p names a path that is not in $TOP:" >&2
    printf '%s\n' "$CP_BAD" | while IFS= read -r _p; do
      [ -n "$_p" ] && echo "innsegl-commit:     $_p" >&2
    done
    echo "innsegl-commit:" >&2
    echo "innsegl-commit:   A commit is written inside the tree it is of, so a path outside" >&2
    echo "innsegl-commit:   it can never be one of its own. Name it relative to that tree," >&2
    echo "innsegl-commit:   or pass -w for the tree you meant." >&2
    exit 2
  fi
  if [ "$CP_INDEX" != "1" ] || [ -z "$CP_NAMED" ]; then
    # NO ACCOUNT, NO COMMIT. An index that cannot be listed, read as an empty
    # one, would make this bound vacuous exactly where the tree is in the state
    # least worth guessing about. #261 takes the same view of a run whose record
    # cannot be read.
    echo "innsegl-commit: what the index of $TOP would commit could not be listed, so the" >&2
    echo "innsegl-commit:   paths this commit named cannot be held to it." >&2
    echo "innsegl-commit:   Refusing rather than signing a tree nothing accounted for (#280)." >&2
    exit 1
  fi

  # FIRST PASS, before anything is staged. A refusal here has touched nothing.
  if [ "$CP_UNACCOUNTED_N" != "0" ]; then
    paths_refusal
    exit 1
  fi

  # A file rather than a pipeline: `while … | read` runs its body in a subshell
  # in most shells, so a failure inside one could not stop this one; and a `for`
  # over a split variable would glob a path holding a `*`.
  _names="$(mktemp)"
  printf '%s\n' "$CP_NAMED" > "$_names"
  while IFS= read -r _p; do
    [ -n "$_p" ] || continue
    if ! git -C "$TOP" add -- "$_p" 2>/dev/null; then
      rm -f "$_names"
      echo "innsegl-commit: git could not stage $_p." >&2
      echo "innsegl-commit:   -p names the paths this commit is of and stages them, so a" >&2
      echo "innsegl-commit:   path git will not take is one this commit cannot be of." >&2
      exit 1
    fi
  done < "$_names"
  rm -f "$_names"

  # AND THE SAME QUESTION AGAIN, of the index as it now stands. The pass above
  # is what keeps a refusal from touching the tree; THIS one is the invariant
  # the commit rests on, asked of the thing actually about to be committed --
  # and it is what catches another writer staging between the two.
  commit_paths
  if [ "$CP_INDEX" != "1" ] || [ "$CP_UNACCOUNTED_N" != "0" ]; then
    paths_refusal
    exit 1
  fi
fi

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

# try_register KEY REPO BRANCH PARENT -- one attempt, 0 iff a run came back.
#
# The arguments are assembled by python3 and an EMPTY ONE IS OMITTED, because
# doc 02 §1 distinguishes absent from empty: a run that recorded an empty
# parent would be claiming one it does not have, and the closed schema refuses
# an empty `repo` outright. A transport failure is fatal here and not a fallback
# case -- a deployment that cannot be reached is not a deployment that might
# accept fewer members.
try_register() {
  if _out="$(mcp "$ADMIN_URL" register_agent "$(python3 -c '
import json, sys
key, repo, branch, parent, agent_type, task = sys.argv[1:7]
args = {"agent_type": agent_type, "task_id": task, "idempotency_key": key}
if repo: args["repo"] = repo
if branch: args["branch"] = branch
if parent: args["parent_run_id"] = parent
print(json.dumps(args))' "$1" "$2" "$3" "$4" "$AGENT_TYPE" "$TASK")")"; then :; else
    _st=$?
    # A CREDENTIAL REFUSAL IS NOT AN UNREACHABLE SERVER, and saying so would
    # send an operator to `make innsegl-up-here` about a deployment that is up
    # and answering. `mcp` returns 3 for that case and has already printed the
    # one remedy there is; anything else is the transport.
    #
    # IT ENDS THE LADDER, it does not fall to the next rung. Every rung below
    # presents the SAME credential to the SAME listener, so a refusal is not
    # something dropping the parent or dropping repo/branch can satisfy -- it
    # would only be re-answered, identically, twice more, and the operator
    # would read the schema-1 advice for a problem that is not the schema.
    [ "$_st" -eq 3 ] && exit 1
    fail "the identity service at $ADMIN_URL could not be reached. No identity, no attributed work (IP §6.1). Try: make innsegl-up-here"
  fi
  REGISTERED_RUN="$(printf '%s' "$_out" | field run_id 2>/dev/null)" || return 1
  return 0
}

# register_run KEY -- one registration, setting REGISTERED_RUN.
#
# THREE ATTEMPTS, EACH DROPPING WHAT THE PREVIOUS ONE WAS REFUSED FOR, and none
# of them optional:
#
#   1  repo, branch and the parent    what this script actually knows
#   2  without the parent             the pointer names a run that may no
#                                     longer be one (see below)
#   3  without repo and branch        a server that predates ADR-0045
#
# WHY THE PARENT IS DROPPED RATHER THAN FATAL. Since RM-156 register_agent
# REFUSES a parent that is retired or that the ledger has never held, which is
# right -- an edge in an append-only record is permanent, and one that names a
# run that is not there is permanently wrong. But the parent here comes from a
# pointer on a disk, and a pointer is exactly the thing that goes stale: a
# session that ended without its hook running leaves one behind. Refusing the
# COMMIT over that would strand the work for a bookkeeping edge, so the edge is
# what gives way. The run is registered as a root run and the operator is told
# which pointer to look at.
#
# The retry is driven by the PAYLOAD, not by the exit status: `mcp` returns 0
# for a JSON-RPC error, because the transport worked and the server answered.
# `field` is what reads the answer, so `field` is what decides.
register_run() {
  _rk="$1"
  # `if`, never `cmd && return`: under `set -e` an AND-list whose left side
  # fails takes the whole script down, and the left side failing is the case
  # every line below exists for.
  if try_register "$_rk" "$REPO" "$BRANCH" "$PARENT_RUN"; then
    return 0
  fi

  if [ -n "$PARENT_RUN" ] && try_register "$_rk" "$REPO" "$BRANCH" ""; then
    echo "innsegl-commit: this tree's session pointer names $PARENT_RUN, which is not a" >&2
    echo "innsegl-commit:   run that may be a parent -- retired, or one this ledger has" >&2
    echo "innsegl-commit:   never held. The run was registered with no parent rather than" >&2
    echo "innsegl-commit:   with a wrong edge, which nothing could amend." >&2
    echo "innsegl-commit:   The stale pointer is $RUNS_DIR/by-tree/$TREE_KEY.session" >&2
    return 0
  fi

  try_register "$_rk" "" "" "" || fail "register_agent refused"
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

# sign_args PATHS -- the sign_commit arguments, with or without the bound.
#
# A function because it is built TWICE: once with `paths` and, against a
# deployment that predates the argument, once without. See the ladder below.
sign_args() {
  python3 -c '
import json,sys
run,repo,tree,task,key,wt,paths=sys.argv[1:8]
args={"run_id":run,"repo":repo,"staged_ref":tree,
      "message":sys.stdin.read(),"task_ref":task,
      "idempotency_key":key}
# Absent, not empty: an empty string is a value the tool would have to give a
# meaning, and MCP-029 gives it one only by omission.
if wt: args["worktree"]=wt
# THE BOUND TRAVELS WITH THE REQUEST -- #280. The check above is what an
# operator reads; this is what cannot be walked past, because sign_commit is the
# thing that actually commits the index and it asks the same question of the
# index it is about to commit. A check that lived only here would be a check the
# caller learns about after a round trip; one that lived only there could be
# skipped by any other client of the tool.
if paths: args["paths"]=[p for p in paths.split(chr(10)) if p]
print(json.dumps(args))' \
    "$RUN" "$REPO" "$TREE" "$TASK" "$SIGN_KEY" "$WORKTREE" "$1" <<EOF
$MESSAGE
EOF
}

# signing_refused -- everything that happens when no commit_sha came back.
#
# THE REFUSAL MUST NOT CLAIM A ROLLBACK THAT DID NOT HAPPEN (RM-145, #229).
# sign_commit creates the commit and then verifies it, so a Phase C failure
# leaves the commit AT HEAD, carrying its identity trailers, and absent from the
# ledger. Telling an operator "nothing was committed" is exactly what makes them
# commit again or reset, on the strength of a claim this tool never honoured. So
# ask git what is actually there rather than asserting it.
#
# It is a function because the ladder below reaches it from two places, and the
# one thing this block must never do is disagree with itself about whether a
# commit exists.
signing_refused() {
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
}

# ---------------------------------------------------------------------------
# THE CALL, AND THE ONE RUNG BELOW IT — #280.
#
# A CLIENT AND A SERVER UPGRADE AT DIFFERENT MOMENTS, and this script has been
# here before: register_run's ladder exists because the MCP SDK validates
# arguments against the tool's advertised inputSchema and refuses additional
# properties outright.
#
#   validating "arguments": validating root: unexpected additional
#   properties ["paths"]
#
# Measured on 2026-09-19 while this change was still in the working tree: the
# deployed image predated the argument, a writer's commit was refused with that
# sentence, and it fell back to a checked-out copy of the previous script to get
# signed at all. A new script against a not-yet-restarted server must not STOP,
# because stopping means the human cannot commit.
#
# SO THE SECOND ATTEMPT DROPS `paths` AND SAYS SO, LOUDLY. What is lost is the
# half of the bound that cannot be walked past; what remains is the half this
# script already applied before it called anything — it accounted for the index
# and refused a foreign path before a run was even registered. A commit that
# gets here has already passed that. The operator is told which half is missing
# and what to run to get it back.
#
# THE KEY IS NOT BURNED. Schema validation happens in the SDK, ahead of the tool
# handler, so the refused attempt claimed no idempotency key and appended
# nothing; the second attempt carries the same key by design.
#
# The retry is driven by the PAYLOAD and not by the exit status, for the reason
# register_run states: `mcp` returns 0 for a JSON-RPC error, because the
# transport worked and the server answered. `field` is what reads the answer,
# so `field` is what decides.
# ---------------------------------------------------------------------------
SIGN_ERR="$(mktemp)"
SIGNED="$(mcp "$AGENT_URL" sign_commit "$(sign_args "${CP_NAMED:-}")")" \
  || fail "the MCP at $AGENT_URL could not be reached"
if SHA="$(printf '%s' "$SIGNED" | field commit_sha 2>"$SIGN_ERR")"; then
  :
elif [ -n "${CP_NAMED:-}" ] && grep -q 'additional propert' "$SIGN_ERR" 2>/dev/null; then
  echo "innsegl-commit: this deployment's sign_commit does not accept \`paths\` yet, so" >&2
  echo "innsegl-commit:   the commit is bounded by this script alone: it accounted for" >&2
  echo "innsegl-commit:   the index and refused nothing foreign before it called anything." >&2
  echo "innsegl-commit:   What is missing is the server-side half, which no other client" >&2
  echo "innsegl-commit:   of the tool can walk past. Restart the deployment to get it:" >&2
  echo "innsegl-commit:     make innsegl-up-here" >&2
  SIGNED="$(mcp "$AGENT_URL" sign_commit "$(sign_args '')")" \
    || fail "the MCP at $AGENT_URL could not be reached"
  if SHA="$(printf '%s' "$SIGNED" | field commit_sha 2>"$SIGN_ERR")"; then
    :
  else
    cat "$SIGN_ERR" >&2
    rm -f "$SIGN_ERR"
    signing_refused
  fi
else
  cat "$SIGN_ERR" >&2
  rm -f "$SIGN_ERR"
  signing_refused
fi
rm -f "$SIGN_ERR"
IDX="$(printf '%s' "$SIGNED" | field rekor_entry.log_index 2>/dev/null || echo '?')"

echo "innsegl-commit: signed $(git -C "$WT" rev-parse --short "$SHA")  rekor index $IDX"
git --no-pager log -1 --format='  %s' "$SHA"
