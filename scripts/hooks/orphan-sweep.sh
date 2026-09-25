#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# THE DEATH NOBODY OBSERVED — #288 (RM-180).
#
# A subagent was registered, wrote two files through the `Write` tool, and was
# killed with no stop event. MEASURED, everything that survived:
#
#   the work        both files still in the tree
#   the marker      run id, task, repo, branch, directory, SPIFFE id
#   the bodies      both writes, attributable to the run
#   the ledger      the run still reading `active`
#   the guard       refusing a command that would destroy the work (#278)
#
# So nothing was lost and the identity was recoverable. What did NOT happen is
# that anything SAID the work was there. `SubagentStop` does not fire on a kill,
# so no capture was attempted; no capture failed, so #277's record was never
# written. The drill produced zero new lines in the capture log. `SessionStart`
# registered the session and expired old bodies and scanned no markers; the
# reaper measured silence and read no tree — `git status` appears nowhere in it.
# Recovery was real and entirely passive: the only thing that would ever mention
# the work was the guard, and only if somebody happened to run a command that
# would have destroyed it.
#
# #290 CLOSED THE HALF WITH AN OBSERVER. A kill the parent session sees fires its
# `PostToolUse`, the run is retired at that instant, and the record naming the
# run, the tree and the paths is written then and there. #291 made that record
# carry a claim the guard keeps weighing afterwards.
#
# WHAT IS LEFT IS THE KILL NOBODY SAW, and it is what this file is for:
#
#   - a crash or an OOM, where no tool call is made and no hook fires;
#   - the whole session dying, taking its children with it;
#   - another harness, which fires no hook here at all.
#
# For those there is no observer by construction, so the thing that asks the
# question cannot be one. This asks it when nobody is trying to delete anything
# and no session is there to notice.
#
# # WHERE IT RUNS, WHICH IS THE DECISION WORTH ARGUING
#
# IT MUST NOT DEPEND ON THE DEAD SESSION BEING ALIVE. That rules out every event
# the dead session would have fired — its `SubagentStop`, its `SessionEnd`, its
# `PostToolUse`. A crash fires none of them, which is the whole case.
#
# SO THE CALLER IS SOMEBODY ELSE'S `SessionStart`, and this file is a script that
# any caller can run:
#
#   `sweep`  the sweep itself, over the repository containing a directory.
#            `scripts/hooks/orphan-sweep.sh sweep [<dir>]` from a terminal, a
#            login shell, a cron entry or another harness. Nothing here installs
#            any of those: wiring a periodic job on somebody's machine is not a
#            change a script may make on its own, which is the same argument
#            git-tree-guard.sh makes about putting a `git` on PATH.
#
#   `hook`   a `SessionStart` event on stdin, whose `cwd` names the tree.
#            scripts/hooks/subagent-identity.sh calls this, and it is the half
#            that needs no operator action.
#
# WHY `SessionStart` IS THE RIGHT HOOK, and not merely an available one:
#
#   IT IS A DIFFERENT SESSION BY CONSTRUCTION. The session that starts is not the
#   session that died, which is exactly the independence the case requires.
#
#   IT IS THE MOMENT SOMEBODY COMES BACK TO THE TREE. A record written where
#   nobody is looking is the passivity #288 is about. This one is written as the
#   session that will work in that tree begins, so the party who can act on it is
#   the party it is handed to.
#
#   IT ALREADY DOES PER-SESSION HOUSEKEEPING. The body-retention sweep runs
#   there, so the cost model is settled: one more bounded, best-effort job that
#   can never fail the session.
#
# AND THE ONES THAT WERE CONSIDERED AND ARE WORSE:
#
#   `SessionEnd` fires in the session that is ENDING, which is the session the
#   case says does not get to run its hooks.
#
#   `PostToolUse` is #290's path and needs a live observer.
#
#   THE REAPER is the right cadence and the wrong place twice over: it runs in a
#   container that cannot see this machine's working trees at all, and its job is
#   to measure silence rather than to read a tree. If the MCP ever publishes the
#   marker directory the way #208 hands on the stop-time capture, this belongs
#   with it.
#
# # WHAT DECIDES, AND WHAT DELIBERATELY DOES NOT
#
# A MARKER THAT IS STILL THERE IS THE FIRST HALF. `SubagentStop` removes it and
# so does #290's kill path, so a marker still on disk names a run whose stop
# nobody ran. On its own that means nothing — a killed subagent leaves its marker
# behind forever (#260) — which is why it is only the first half.
#
# THE LEDGER IS THE SECOND, AND IT IS THE ONE THAT DECIDES. It holds the four
# states, and the words are its own (internal/ledger/runstate.go):
#
#   active     not ended, and heard from since the newest withdrawal
#   lapsed     the newest fact is a withdrawal — the reaper's grace has passed
#   abandoned  a withdrawal, past the restore horizon
#   retired    ended by its harness or by a human
#
# `active` IS SKIPPED AND NOTHING ELSE ANSWERS FOR IT. A quiet agent may still be
# working, and the reaper's grace is what answers that — NO CLOCK IS READ HERE,
# no threshold is added, and the grace is not touched. A previous attempt at a
# short silence threshold was rejected for ending agents that are working but
# slow, and nothing in this file could implement one: it never reads a time.
#
# A WORD THIS FILE DOES NOT KNOW IS SKIPPED TOO. A state it cannot name is not a
# state it may call death.
#
# AND `lapsed` IS ACTED ON, WHICH IS THE ONE JUDGEMENT CALL HERE. A lapsed run
# can be restored, so a record about one can turn out to have been written about
# a run that came back. Waiting for `abandoned` instead would mean waiting out
# the restore horizon — thirty days by default — which is a record nobody will
# ever read, and the crash case is precisely the one that needs it. The trade is
# affordable only because this file RECORDS: nothing is retired, nothing is
# signed, no claim is created and no tree changes behaviour, so being early costs
# one line in a log. The record carries the state the ledger reported, so a
# reader is never left guessing which of the four it was.
#
# A LEDGER THAT DOES NOT ANSWER ENDS THE SWEEP IN SILENCE, and this is the
# opposite of what the guard does one level out — on purpose. The guard is
# deciding about a command already in flight and has to answer now, so it refuses
# when it cannot tell, because a wrong allow costs the work. This has no command
# in front of it and nothing to lose by waiting: a sweep that cannot ask has not
# found nothing, it has not LOOKED, and there will be another session start.
#
# # WHAT IT MAY NOT TOUCH
#
# NEVER A RUN THIS MACHINE DOES NOT OWN, and the boundary is the TREE. One
# markers directory serves every session on this machine, and the runs in it
# belonging to another repository have live processes behind them right now. So a
# sweep considers only markers whose directory is the repository the caller named
# and never runs git anywhere else. A crashed session in another repository is
# swept when somebody opens THAT repository, which is also where its record is
# worth reading.
#
# THE OPERATOR'S OWN SESSION IS NOT AN AGENT. `session-*` is skipped for the
# reason the guard skips it: uncommitted work in your own tree is normal, and a
# line at every session start telling you your own files exist is noise on the
# surface that also carries things worth reading.
#
# IT RETIRES NOTHING. It makes no MCP call at all — the only thing it asks the
# deployment is one read of a run's public status — so there is no tool it could
# reach that would end a run. Retiring on silence is the reaper's, and #290 is
# the only thing that retires early, on a kill somebody observed.
#
# IT SIGNS NOTHING AND COMMITS NOTHING. Committing another run's work under an
# identity that did not do it is #269's open question and must not be answered by
# accident, least of all by an unattended job. Nor can the run that wrote it: it
# is no longer active, and the signer refuses it (IP §6.2). The record names the
# run so that a person can have a live run adopt the work (ADR-0051).
#
# IT CHANGES NOTHING ON DISK BUT ONE APPENDED LINE. No marker is removed, no path
# is staged, nothing in the tree is written, and `git status` runs with
# `--no-optional-locks` so the sweep cannot take the index lock even to refresh
# it. A sweep that wedged a tree would be worse than the passivity it replaces.
#
# ONE RECORD PER RUN, EVER. The log is append-only and never rotated, so a sweep
# that re-announced the same orphan at every session start would turn the record
# into noise and the file into a transcript of how often somebody opened a
# terminal. A run this log already carries a record for is skipped, and so is one
# whose death WAS observed and recorded as `run_killed`.
#
# # WHAT THIS RECORD IS NOT
#
# IT IS NOT A CLAIM THE GUARD WEIGHS. git-tree-guard.sh refuses over the claim in
# a `run_killed` record and reads no other reason, so nothing in any tree starts
# refusing because of this file. That is deliberate and it is a boundary rather
# than an omission: a kill is an observed certainty and a `lapsed` run is a
# ledger state, and making a tree refuse on the strength of the second is a
# separate decision with its own cases to write. The `claim` field is written
# because it means exactly what it means in a `run_killed` record — the paths the
# run left uncommitted, each with a digest of the bytes it left — so one reader
# reads the whole log.
#
# # WHAT IT DOES NOT COVER, plainly
#
#   - A run whose writes went through `Bash` redirections. `echo x > file` fires
#     the Bash hook and no file-write hook, so the body records a shell command
#     and not the write inside it. It recorded no path, so it claims none. The
#     capture and the guard have the same hole for the same reason.
#   - A run whose tool-call bodies are gone — pruned by the 90-day retention, or
#     never written. NO PATHS, NO RECORD: the record's whole value is the paths,
#     and one naming none would point at a dirty tree that belongs to whoever
#     wrote it.
#   - A repository nobody opens again. Nothing sweeps a tree on spec.
#   - A tree that cannot be read, or a ledger that does not answer. Silence, for
#     the reason above.
#   - The operator's own session, and any marker outside the named repository.
#   - More than 50 paths from one run, which is the bound the record is written
#     under; `claim_n` says how many there were.
#
# # ENVIRONMENT
#
#   INNSEGL_ORPHAN_SWEEP=0   off entirely.
#   INNSEGL_RUNS_DIR         default ~/.innsegl/runs
#   INNSEGL_LOG_DIR          default ~/.innsegl/log
#   INNSEGL_UNCAPTURED_LOG   default $INNSEGL_RUNS_DIR/uncaptured.jsonl — the
#                            same default and the same variable #277 writes it
#                            under, so a machine that moves one moves both
#   INNSEGL_API_URL          default http://127.0.0.1:8082
#
# EXIT: always 0. This is called from a session's own start and from whatever an
# operator wires it to; a sweep that could fail either would be a sweep somebody
# turns off. Needs python3 and git, and does nothing at all without them.

set -u

RUNS_DIR="${INNSEGL_RUNS_DIR:-$HOME/.innsegl/runs}"
LOG_DIR="${INNSEGL_LOG_DIR:-$HOME/.innsegl/log}"
UNCAP_LOG="${INNSEGL_UNCAPTURED_LOG:-$RUNS_DIR/uncaptured.jsonl}"
API_URL="${INNSEGL_API_URL:-http://127.0.0.1:8082}"

# ---------------------------------------------------------------------------
# The sweep, in python3 — the same choice the shim and the guard made and for
# the same reason: this reads JSON markers, JSON bodies, a NUL-separated status
# and a JSON log, and every one of those in `sed` is a quoting bug waiting for a
# path with a space in it.
#
# argv: <dir> <runs dir> <log dir> <api url> <uncaptured log>
#
# It prints what it recorded on stderr, or prints nothing. Any exception exits
# 0: nothing here may fail a session.
# ---------------------------------------------------------------------------
ORPHAN_SWEEP='
import hashlib, json, os, pathlib, subprocess, sys, time
import urllib.error, urllib.request

where, runs_dir, log_dir, api_url, uncap_log = sys.argv[1:6]

# The four states the ledger holds, in its own words -- see
# internal/ledger/runstate.go. `active` is the only one that means a run may
# still be working, and a word in neither tuple is a state this file does not
# know, which is not a state it may call death.
ACTIVE = "active"
GONE = ("lapsed", "abandoned", "retired")

# THE REASON IS ITS OWN, and that is what keeps this out of the guard: #291
# weighs a claim only on `run_killed`, so no tree begins refusing because of a
# line written here. See the header.
REASON = "run_unobserved"
# A death that WAS observed is already recorded, by the path that observed it.
OBSERVED = ("run_killed",)

CLAIM_LIMIT = 50            # the bound the record is written under
MARKER_LIMIT = 500          # one sweep never walks an unbounded directory
UNCAP_TAIL = 4 * 1024 * 1024
PATHS_SHOWN = 10

def out(line=""):
    # Every line carries the prefix, blank ones included: this lands on the same
    # stderr the shim writes its warnings to, interleaved with the harness.
    sys.stderr.write(("innsegl: " + line if line else "innsegl:") + "\n")

# --- the tree ---------------------------------------------------------------

def git(top, *args):
    p = subprocess.run(("git", "-C", top) + args, stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL, timeout=60)
    if p.returncode != 0:
        raise RuntimeError("git " + " ".join(args))
    return p.stdout.decode("utf-8", "replace")

def status_z(top):
    # `--no-optional-locks` SO A SWEEP CANNOT WEDGE A TREE. A plain `git status`
    # refreshes the index opportunistically, which takes index.lock; this one
    # runs unattended while another session is starting, and taking a lock there
    # is a way to break a git command a person is running in the same second.
    # Falling back matters only on a git too old to know the flag (2.15, 2017),
    # where the alternative is a sweep that silently never runs.
    try:
        return git(top, "--no-optional-locks", "status", "--porcelain", "-z")
    except Exception:
        return git(top, "status", "--porcelain", "-z")

def dirty_set(top):
    # EVERY uncommitted path, tracked and untracked together. The guard weighs
    # the two halves separately because a command can only destroy one of them;
    # this asks a different question — is the work still sitting there — and a
    # path is uncommitted or it is not.
    fields = status_z(top).split("\0")
    found, i = set(), 0
    while i < len(fields):
        f = fields[i]
        i += 1
        if len(f) < 4:
            continue
        code, path = f[:2], f[3:]
        # A rename carries its source in the NEXT field.
        if "R" in code or "C" in code:
            i += 1
        if code != "!!":
            found.add(path)
    return found

def hits(wrote, dirty):
    # An untracked DIRECTORY is reported by git as `dir/` and stands for
    # everything under it, so a written path beneath one is uncommitted too.
    found = set()
    for d in dirty:
        if d.endswith("/"):
            for w in wrote:
                if w.startswith(d):
                    found.add(w)
        elif d in wrote:
            found.add(d)
    return found

# --- the markers ------------------------------------------------------------

class Run(object):
    def __init__(self, marker, run_id, agent_type, task, worktree, directory):
        self.marker = marker
        self.run_id = run_id
        self.agent_type = agent_type
        self.task = task
        self.worktree = worktree
        self.dir = directory

def s(value):
    # A marker is a file on disk and a member of it may be anything JSON can
    # hold; every one of these reaches a string concatenation below.
    return value if isinstance(value, str) else ""

def safe_id(value):
    # A run id out of a marker reaches a URL path, so its SHAPE is checked here
    # rather than escaped there — the same rule #290 applies to a task id before
    # it becomes a filename. Anything else is skipped, silently.
    if not value or len(value) > 200:
        return False
    for ch in value:
        if not (ch.isalnum() or ch in "-_"):
            return False
    return True

def markers_for(top):
    # Every run marker whose directory is this tree or inside it, and nothing
    # else on the machine. THE SESSION IS NOT ONE OF THEM: `session-*` names the
    # operator, and uncommitted work in your own tree is your own business.
    found = []
    try:
        names = sorted(os.listdir(runs_dir))
    except OSError:
        return found
    for name in names:
        if len(found) >= MARKER_LIMIT:
            break
        if name.startswith(".") or name.startswith("session-") or name == "by-tree":
            continue
        path = os.path.join(runs_dir, name)
        try:
            if not os.path.isfile(path):
                continue
            body = json.loads(open(path).read())
        except Exception:
            continue
        if not isinstance(body, dict):
            continue
        run_id = body.get("run_id") or ""
        directory = body.get("dir") or ""
        if not isinstance(run_id, str) or not isinstance(directory, str):
            continue
        if not safe_id(run_id) or not directory:
            continue
        try:
            real = os.path.realpath(directory)
        except Exception:
            continue
        if real != top and not real.startswith(top + os.sep):
            continue
        found.append(Run(name, run_id, s(body.get("agent_type")), s(body.get("task")),
                         s(body.get("worktree")), real))
    return found

# --- who the ledger says is gone --------------------------------------------

def ledger_state(run_id):
    # The state of the run, "" when the ledger has never heard of it, or None when
    # the ledger did not answer at all. The caller treats None as "this sweep
    # has not looked" and stops: see the header.
    url = api_url.rstrip("/") + "/api/v1/runs/" + run_id
    try:
        with urllib.request.urlopen(url, timeout=5) as reply:
            body = json.loads(reply.read().decode("utf-8"))
        state = (body or {}).get("status")
        return state if isinstance(state, str) and state else None
    except urllib.error.HTTPError as refused:
        # A ledger that answers "I have never heard of this run" is a ledger
        # that is UP. It is not an answer that anything died, so nothing is
        # recorded for it — but the next run is still asked.
        if refused.code == 404:
            return ""
        return None
    except Exception:
        return None

# --- what this run wrote, and what of it is still sitting there --------------

def wrote_by(run, top):
    # Only what the tool-call bodies of that run record it writing -- the same
    # source and the same three tools that bound the stop-time capture in #261
    # and the guard`s claim in #278. A Bash redirection recorded no path.
    store = os.path.join(log_dir, run.run_id)
    if not os.path.isdir(store):
        return set()
    wrote = set()
    try:
        bodies = sorted(pathlib.Path(store).glob("*.json"))
    except OSError:
        return set()
    for f in bodies:
        try:
            d = json.loads(f.read_text())
        except Exception:
            continue
        if not isinstance(d, dict):
            continue
        if d.get("tool_name") not in ("Edit", "Write", "NotebookEdit"):
            continue
        ti = d.get("tool_input")
        if not isinstance(ti, dict):
            continue
        fp = ti.get("file_path")
        if not isinstance(fp, str) or not fp:
            continue
        base = d.get("cwd") if isinstance(d.get("cwd"), str) and d.get("cwd") else run.dir
        try:
            real = os.path.realpath(fp if os.path.isabs(fp) else os.path.join(base, fp))
        except Exception:
            continue
        if real.startswith(top + os.sep):
            wrote.add(os.path.relpath(real, top))
    return wrote

def claim_for(top, at_risk):
    # The paths, each with a digest of the bytes that are in it now. It is the
    # bytes IN THE WORKING TREE and not a git blob id, so that no gitattribute, clean
    # filter or autocrlf setting can make the writer and a later reader disagree
    # about whether a file is the same file. `size` is recorded with it because
    # it rejects the common case without reading a byte.
    claim, total = [], 0
    for p in sorted(at_risk):
        total += 1
        if len(claim) >= CLAIM_LIMIT:
            continue
        try:
            h, size = hashlib.sha256(), 0
            with open(os.path.join(top, p), "rb") as fh:
                while True:
                    chunk = fh.read(65536)
                    if not chunk:
                        break
                    size += len(chunk)
                    h.update(chunk)
        except OSError:
            continue        # gone between the status and here: nothing to name
        claim.append({"path": p, "sha": h.hexdigest(), "size": size})
    return claim, total

# --- what this log already carries -------------------------------------------

def already_recorded():
    # ONE RECORD PER RUN, EVER. The log is append-only and never rotated, so
    # only the end of it is read; a file that has grown past the tail has its
    # oldest records dropped, and those name work that is likeliest long since
    # committed.
    seen = set()
    try:
        size = os.path.getsize(uncap_log)
        with open(uncap_log, "rb") as fh:
            if size > UNCAP_TAIL:
                fh.seek(size - UNCAP_TAIL)
                fh.readline()       # drop the partial line the seek landed in
            raw = fh.read().decode("utf-8", "replace")
    except OSError:
        return seen
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue                # one unreadable line is not the whole log
        if not isinstance(rec, dict):
            continue
        run_id = rec.get("run_id")
        if not isinstance(run_id, str) or not run_id:
            continue
        if rec.get("reason") in (REASON,) + OBSERVED:
            seen.add(run_id)
    return seen

# --- the record --------------------------------------------------------------

def write_record(run, state, top, dirty_n, wrote, claim, claim_n):
    # THE SHAPE IS #277 FIELD FOR FIELD -- see UNCAPTURED_RECORD in
    # scripts/hooks/subagent-identity.sh. One log, one reader, one meaning per
    # field: `claim` here is what it is in a `run_killed` record, the paths the
    # run left uncommitted with a digest of the bytes it left in each.
    rec = {
        "record": "capture_not_made",
        "reason": REASON,
        "detail": ("the ledger reports this run " + state +
                   " and its marker is still here, so nothing ran its stop: it "
                   "left " + str(claim_n) + " path(s) it wrote uncommitted in " +
                   top + ". Nothing was retired, signed or committed"),
        "run_id": run.run_id,
        "agent_type": run.agent_type,
        "task": run.task,
        "worktree": run.worktree,
        "dir": run.dir,
        "dirty": dirty_n,
        "wrote": len(wrote),
        "staged": 0,
        "unaccounted": 0,
        "unaccounted_paths": [],
        "wrote_paths": sorted(wrote)[:20],
        "claim_top": top,
        "claim": claim,
        "claim_n": claim_n,
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    # One write() to a descriptor opened O_APPEND is atomic, and 0600 for the
    # reason the marker is: this names a run and a tree.
    fd = os.open(uncap_log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, (json.dumps(rec, sort_keys=True) + "\n").encode("utf-8"))
    finally:
        os.close(fd)

def report(run, state, top, claim, claim_n):
    who = run.run_id
    if run.agent_type:
        who += " (" + run.agent_type + (", task " + run.task if run.task else "") + ")"
    out("a run that is gone left uncommitted work here, and nothing had said so (#288):")
    out()
    out("  " + who)
    out("  is " + state + " in the ledger with its marker still in place, so nothing")
    out("  ran its stop and nothing captured what it left in " + top + ":")
    for entry in claim[:PATHS_SHOWN]:
        out("    " + entry["path"])
    if claim_n > PATHS_SHOWN:
        out("    ... and " + str(claim_n - PATHS_SHOWN) + " more")
    out()
    out("  Recorded in " + uncap_log + ". Nothing was retired, signed or")
    out("  committed, and the tree was not touched.")
    out()
    # NOT `-r`. Every run recorded here is one the ledger no longer calls
    # active, and the signer refuses those (RUN_ALREADY_RETIRED, IP §6.2): the
    # first real use of this report printed `innsegl-commit -r <run>` and it
    # was refused. A live run ADOPTS the work instead (ADR-0051): the commit
    # names both runs, and sign_commit proves each path against the bodies of
    # this run, refusing any it cannot.
    out("  A " + state + " run may not sign (IP §6.2). A live run can adopt it,")
    out("  and the commit names both runs:")
    out("    innsegl-commit -a " + run.run_id + " -p <path> -m \"<type>(<scope>): <what changed>\"")

# --- the sweep ---------------------------------------------------------------

def main():
    try:
        top = os.path.realpath(git(where, "rev-parse", "--show-toplevel").strip())
    except Exception:
        return 0            # not a repository, or a git that will not answer
    runs = markers_for(top)
    if not runs:
        return 0            # no agent has ever been registered here
    try:
        dirty = dirty_set(top)
    except Exception:
        return 0            # the tree could not be read: not looked, not found
    if not dirty:
        return 0            # nothing uncommitted here at all
    seen = already_recorded()
    for run in runs:
        if run.run_id in seen:
            continue        # this run already has its line
        state = ledger_state(run.run_id)
        if state is None:
            # THE LEDGER DID NOT ANSWER. Silence is not an answer about a run,
            # and there will be another session start.
            return 0
        if state not in GONE:
            continue        # active, never heard of, or a word this file does
                            # not know — none of which is a death
        wrote = wrote_by(run, top)
        if not wrote:
            continue        # no recorded write here, so no path to name
        at_risk = hits(wrote, dirty)
        if not at_risk:
            continue        # everything it wrote here is committed or gone
        claim, claim_n = claim_for(top, at_risk)
        if not claim:
            continue        # nothing left to read: nothing to record
        write_record(run, state, top, len(dirty), wrote, claim, claim_n)
        seen.add(run.run_id)
        report(run, state, top, claim, claim_n)
    return 0

try:
    sys.exit(main())
except SystemExit:
    raise
except Exception:
    sys.exit(0)
'

# sweep <dir> — always 0, in every circumstance.
sweep() {
  [ "${INNSEGL_ORPHAN_SWEEP:-1}" = "0" ] && return 0
  command -v python3 >/dev/null 2>&1 || return 0
  command -v git >/dev/null 2>&1 || return 0
  [ -d "$1" ] || return 0
  python3 -c "$ORPHAN_SWEEP" "$1" "$RUNS_DIR" "$LOG_DIR" "$API_URL" "$UNCAP_LOG"
  return 0
}

usage() {
  cat >&2 <<'EOF'
innsegl: orphan-sweep.sh — say that a run which died unobserved left work in a
                           tree, when nobody is trying to delete anything (#288)

  orphan-sweep.sh sweep [<dir>]   sweep the repository containing <dir>
  orphan-sweep.sh hook            take the tree from a SessionStart on stdin

  It records and nothing else: no run is retired, nothing is signed or
  committed, no marker is removed and the tree is never written to. A run the
  ledger still reports `active` is left alone — silence is the reaper's
  question, and no clock is read here. Always exits 0.
EOF
}

MODE="${1:-}"
[ $# -gt 0 ] && shift

case "$MODE" in
  sweep)
    sweep "${1:-$(pwd -P)}"
    exit 0
    ;;

  hook)
    # The harness's own SessionStart event, on stdin. Only its `cwd` is read;
    # an event that cannot be parsed falls back to this process's directory,
    # and a directory that is not a repository sweeps nothing.
    _ev="$(cat)"
    _read="$(printf '%s' "$_ev" | python3 -c '
import json, shlex, sys
try:
    e = json.load(sys.stdin)
except Exception:
    e = {}
print("SWEEP_CWD=" + shlex.quote(e.get("cwd") or ""))
' 2>/dev/null)"
    SWEEP_CWD=""
    eval "$_read" 2>/dev/null || exit 0
    [ -n "$SWEEP_CWD" ] && [ -d "$SWEEP_CWD" ] || SWEEP_CWD="$(pwd -P)"
    sweep "$SWEEP_CWD"
    exit 0
    ;;

  ""|-h|--help|help)
    usage
    exit 0
    ;;

  *)
    usage
    exit 0
    ;;
esac
