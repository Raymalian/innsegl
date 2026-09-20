#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# THE GUARD IN FRONT OF A DESTRUCTIVE git — #278 (RM-173).
#
# Measured: two subagents were working in one shared checkout. A routine
# `git reset --hard HEAD~1` in that same checkout, dropping a throwaway probe
# commit, discarded every tracked modification in the tree — including one
# subagent's finished but uncommitted work. Untracked files survived; tracked
# edits did not, which is exactly what a hard reset does. Eight minutes of an
# agent's work went, and nothing refused, warned or recorded it.
#
# Agent work lives in the working tree until a SubagentStop capture commits it
# (ADR-0046). Between the last edit and that capture it has no protection at
# all, and the operator shares the tree. This is that protection: a pre-command
# check that refuses while a registered, unretired run holds uncommitted work
# here.
#
# # WHERE THIS CAN SIT, AND WHY NOT THE OBVIOUS PLACE
#
# THE OBVIOUS PLACE IS A git HOOK, AND GIT HAS NONE THAT WOULD WORK. There is no
# pre-reset, no pre-checkout and no pre-clean hook; `post-checkout` runs after
# the tree has already been rewritten. The one hook that can ABORT and that a
# `reset --hard` fires is `reference-transaction`, and it is too late.
# MEASURED in a scratch repository, a hook that exits non-zero on `prepared`:
#
#   $ git reset --hard HEAD~1
#   reference-transaction fired: phase=prepared
#   reference-transaction fired: phase=aborted
#   fatal: ref updates aborted by hook
#   reset exit=128
#   --- tree after ---        <- the uncommitted line is already gone
#
# The ref did not move and the work was destroyed anyway: git resets the index
# and the working tree BEFORE it opens the ref transaction. A guard there would
# report a refusal over a tree that had already lost the thing it was guarding.
# That is worse than no guard, because it reads as protection.
#
# SO THE GUARD IS A DECIDER, AND THE CALLER IS WHOEVER CAN STILL REFUSE:
#
#   `hook`   the harness's PreToolUse, which sees an agent's Bash calls and can
#            block one by exiting 2. scripts/hooks/subagent-identity.sh calls
#            this. It is the half that needs no operator action, and it covers
#            every git command an agent runs through the Bash tool.
#
#   `wrap`   a `git` earlier on PATH than the real one, which is the ONLY place
#            that sees a human's own terminal. Symlink this file as `git` in a
#            directory ahead of git's own:
#
#              mkdir -p ~/.innsegl/bin
#              ln -s <checkout>/scripts/hooks/git-tree-guard.sh ~/.innsegl/bin/git
#              PATH="$HOME/.innsegl/bin:$PATH"
#
#            NOT INSTALLED BY ANYTHING HERE. A file that inserts itself in front
#            of git on an operator's machine is not a change a script may make
#            on its own, and the wiring belongs wherever this harness's other
#            wiring lives.
#
#   `check`  the decision alone, on an argv, for anything else that wants it.
#
# WHAT IT DOES NOT COVER, said plainly, because a guard believed to cover more
# than it does is the failure it exists to prevent:
#
#   - a human's terminal, until the wrapper above is on PATH;
#   - `/usr/bin/git`, `command git`, a shell alias or a git alias, an editor's
#     own git integration, and any tool that calls libgit2 — the wrapper is a
#     PATH entry, not a capability;
#   - `eval`, `sh -c '...'`, a Makefile recipe or a script the agent runs: the
#     hook sees the command it was given, and a `git` inside a file it executes
#     is not in that string. NOTHING IS GUESSED from a command it cannot
#     tokenise — see the note on shlex below;
#   - another harness, which fires no PreToolUse here at all.
#
# # WHAT IT REFUSES, AND WHAT IT DELIBERATELY DOES NOT
#
#   reset --hard / --merge / --keep     discard tracked worktree state
#   checkout -- <paths>, checkout .     the same, per path
#   checkout -f / switch -f             the discarding branch switch
#   restore <paths>                     unless it is --staged only, which is
#                                       an index edit and touches no file
#   clean -f                            removes UNTRACKED files
#
# `reset --soft` and `reset --mixed` move a ref and an index and no file, so
# they are allowed. `git stash` is allowed on purpose: it is where work GOES,
# not where it is lost.
#
# TRACKED AND UNTRACKED ARE COUNTED SEPARATELY, because the incident turned on
# exactly that distinction. `clean -f` cannot touch a tracked edit and a
# `reset --hard` cannot touch an untracked file, so each form is weighed only
# against the paths it can actually destroy. A guard that refused `clean -fd`
# over a modified tracked file would be refusing over work that command cannot
# reach, and a guard that cries wolf is a guard that gets an override in a
# shell profile.
#
# # WHO COUNTS AS LIVE, WHICH IS THE PART THAT CAN GET THIS WRONG
#
# The registration already exists: SubagentStart writes a marker under
# $INNSEGL_RUNS_DIR naming the run and the tree, and SubagentStop removes it.
# THE MARKER ALONE IS NOT ENOUGH. A subagent killed with its session fires no
# SubagentStop, so its marker is never removed (#260 measured five such runs
# sitting Active for between three and nine hours). A guard trusting the marker
# would refuse in that tree forever.
#
# So liveness is asked of the LEDGER, which is the component that actually knows
# — `status: active` and nothing else is live — and when the ledger does not
# answer, of the marker's age against the reaper's own grace (IP §6.7). A marker
# older than that names a run the reaper has expired or will, so it holds
# nothing. Neither half can wedge a tree on its own.
#
# # AND A CLAIM THAT OUTLIVES ITS RUN — RM-183 (#291)
#
# Liveness above answers a live run. It used to answer a KILLED one too, by
# accident: a killed subagent fires no SubagentStop, so the ledger went on
# reporting it active for the whole of the reaper's grace and this guard went on
# protecting its work for twelve hours. #290 fixed the lie — a kill is certain,
# so the run leaves the active list at the moment of the kill — and the
# protection went with it. MEASURED on one tree, one piece of work, one run:
#
#   before the retirement:  git clean -fd  ->  exit 2, refused
#   after  the retirement:  git clean -fd  ->  exit 0, allowed
#
# AND THE WORK MOST AT RISK IS EXACTLY THIS WORK. A live run's uncommitted work
# has somebody coming back for it. A killed run's does not: it sits in the tree
# with nobody to commit it, and it is the one kind of uncommitted agent work a
# destructive git will silently take.
#
# So a killed run's claim is carried by the record the kill writes (#277, #290):
# reason `run_killed`, naming the run, the tree it worked in, and each path it
# left uncommitted there TOGETHER WITH A DIGEST OF WHAT WAS IN IT.
#
# WHY THE DIGEST IS THE WHOLE DESIGN. Liveness was chosen in #278 because a
# killed subagent's marker is never removed (#260) and a claim keyed on one
# would refuse in that tree forever. A claim keyed on a FILENAME has the same
# defect one step further on: the record is append-only and never rotated, so a
# claim that came back every time somebody re-edited a path some long-dead run
# once wrote would end up claiming every file in the repository. THE CLAIM IS ON
# THE WORK, NOT ON THE NAME. It is released by any of three facts about the
# tree, and by no clock at all:
#
#   the path is COMMITTED    — it is not uncommitted any more, so it is not hit
#   the path is GONE         — there is nothing left to protect
#   the path is WRITTEN OVER — the bytes differ, so this is somebody else's work
#                              in a file that happens to share a name
#
# and by the operator discarding it once, deliberately, through the override
# that was already there — after which the paths are gone and the second rule
# applies. NOTHING HERE ADDS A THRESHOLD and nothing here reads a clock.
#
# IT IS NEVER A BLANKET CLAIM, which is the one place it differs from a live
# run. A live run whose body store cannot be read is refused over every dirty
# path in the tree, because a run nobody can ask is not a run that wrote
# nothing. A retired run cannot be given that: the record outlives every one of
# its paths, and a blanket claim that outlives its run is a tree nobody can use.
# A killed claim is a finite list of paths and contents or it is nothing.
#
# WHAT IT DOES NOT COVER, again plainly:
#
#   - a record written before this existed, which names no content and therefore
#     claims nothing. The protection starts at the next kill;
#   - any other reason in that log. `index_unaccounted`, `no_recorded_writes`
#     and the rest are records of a run that DID stop, which is #277;
#   - a run whose writes went through `Bash` redirections, which recorded no
#     path to claim — the same hole as above, for the same reason;
#   - more than 50 paths from one kill, which is the bound the record is written
#     under. `claim_n` in the record says how many there were.
#
# # WHAT A RUN CLAIMS
#
# Only what its own tool-call bodies record it writing — the same source, and
# the same three tools, that bound the stop-time capture in #261. A dirty path
# no live run wrote belongs to whoever wrote it, and the issue is explicit that
# those are not refused over.
#
# AND A RUN WHOSE RECORD CANNOT BE READ IS REFUSED OVER, not allowed past. That
# is the same rule as #284 one level out: an unreadable body store is not a run
# that wrote nothing, it is a run nobody asked. The cost of being wrong is
# asymmetric — a wrong refusal costs one environment variable, a wrong allow
# costs the work.
#
# A RUN'S WRITES THROUGH `Bash` ARE NOT COUNTED, and that is a real hole rather
# than a decision: `echo x > file` fires the Bash hook and no file-write hook, so
# the body records a shell command and not the write inside it. The shim's own
# header says so, and the capture refuses for the same reason. A run whose work
# went entirely through redirections claims nothing here and is not protected.
#
# # FAIL OPEN, ALWAYS
#
# Every internal failure — no python3, an unreadable runs directory, a git that
# will not answer, a command that will not tokenise — ALLOWS. This file sits in
# front of git on a machine somebody works on. A guard that refuses when it is
# confused takes the repository away from its owner, and the only thing worse
# than an unguarded reset is a shell that cannot run git at all.
#
# # ENVIRONMENT
#
#   INNSEGL_ALLOW_DESTRUCTIVE=1   the deliberate override. One command, one
#                                 variable, and the refusal prints it.
#   INNSEGL_GIT_GUARD=0           off entirely.
#   INNSEGL_RUNS_DIR              default ~/.innsegl/runs
#   INNSEGL_UNCAPTURED_LOG        default $INNSEGL_RUNS_DIR/uncaptured.jsonl
#   INNSEGL_LOG_DIR               default ~/.innsegl/log
#   INNSEGL_API_URL               default http://127.0.0.1:8082
#   INNSEGL_RUN_TTL_HOURS         default 12, the reaper's grace (IP §6.7)
#   INNSEGL_REAL_GIT              wrap mode, when PATH cannot be trusted
#
# EXIT: 0 allows, 2 refuses, and nothing else ever refuses. Anything other than
# 2 out of `check`/`hook` is an internal failure and its caller must allow.

set -u

RUNS_DIR="${INNSEGL_RUNS_DIR:-$HOME/.innsegl/runs}"
LOG_DIR="${INNSEGL_LOG_DIR:-$HOME/.innsegl/log}"
# The same default and the same variable the shim writes it under, so a machine
# that moves one moves both.
UNCAP_LOG="${INNSEGL_UNCAPTURED_LOG:-$RUNS_DIR/uncaptured.jsonl}"
API_URL="${INNSEGL_API_URL:-http://127.0.0.1:8082}"
TTL_HOURS="${INNSEGL_RUN_TTL_HOURS:-12}"

# ---------------------------------------------------------------------------
# The decision, in one place, in python3 — the same choice the shim made and for
# the same reason: this reads JSON markers, JSON bodies, a NUL-separated status
# and a shell command line, and every one of those in `sed` is a quoting bug
# waiting for a path with a space in it.
#
# argv: <mode> <cwd> <runs dir> <log dir> <api url> <ttl hours> <uncaptured log>
#       [args...]
#   mode "argv"    args are a git command line, without the leading `git`
#   mode "command" args[0] is a whole shell command string to be tokenised
#
# It prints the refusal on stderr and exits 2, or prints nothing and exits 0.
# Any exception exits 0: see FAIL OPEN above.
# ---------------------------------------------------------------------------
GUARD_DECIDE='
import hashlib, json, os, pathlib, shlex, subprocess, sys, time

ALLOW, REFUSE = 0, 2

mode, cwd, runs_dir, log_dir, api_url, ttl_hours, uncap_log = sys.argv[1:8]
rest = sys.argv[8:]

def out(line=""):
    # Every line carries the prefix, blank ones included — the shim'"'"'s own
    # refusals do, and an operator reading a blocked tool call is reading two
    # files'"'"' output interleaved with the harness'"'"'s.
    sys.stderr.write(("innsegl: " + line if line else "innsegl:") + "\n")

# --- what is a destructive form -------------------------------------------
#
# Answers (english, scope) where scope is "tracked" or "untracked", or None.
# The scope is which half of a dirty tree the command can actually destroy.

GLOBAL_VALUED = ("-C", "-c", "--git-dir", "--work-tree", "--namespace",
                 "--exec-path", "--super-prefix", "--config-env")
# checkout/switch options that consume the argument after them, so that
# `git checkout -b main` does not read `main` as a pathspec.
VALUED = ("-b", "-B", "--orphan", "--conflict", "--pathspec-from-file",
          "--recurse-submodules", "-t", "--track", "--start-point")

def shorts(tok):
    """The letters of a short-option cluster: -fd -> fd. Long options: ""."""
    if tok.startswith("--") or not tok.startswith("-") or tok == "-":
        return ""
    return tok[1:]

def subcommand(args):
    """(subcommand, its args, the -C directory if one was given)."""
    i, chdir = 0, None
    while i < len(args):
        a = args[i]
        if a in GLOBAL_VALUED:
            if a == "-C" and i + 1 < len(args):
                chdir = args[i + 1]
            i += 2
            continue
        if a.startswith("--") and "=" in a and a.split("=", 1)[0] in GLOBAL_VALUED:
            if a.startswith("-C="):
                chdir = a.split("=", 1)[1]
            i += 1
            continue
        if a.startswith("-"):
            i += 1
            continue
        break
    if i >= len(args):
        return None, [], chdir
    return args[i], args[i + 1:], chdir

def classify(sub, args, where):
    if sub == "reset":
        for a in args:
            if a in ("--hard", "--merge", "--keep"):
                return "git reset " + a, "tracked"
        return None, None

    if sub == "clean":
        if any(a in ("-n", "--dry-run") for a in args):
            return None, None
        for a in args:
            if a in ("--force",) or "f" in shorts(a):
                return "git clean -f", "untracked"
        return None, None

    if sub == "restore":
        staged = any(a == "--staged" or a == "-S" for a in args)
        worktree = any(a == "--worktree" or a == "-W" for a in args)
        if staged and not worktree:
            # An index edit. It rewrites no file in the tree.
            return None, None
        return "git restore", "tracked"

    if sub in ("checkout", "switch"):
        for a in args:
            if a in ("--force", "--discard-changes") or "f" in shorts(a):
                return "git " + sub + " --force", "tracked"
        if sub == "switch":
            return None, None
        # `git checkout -- <paths>` and `git checkout <path>`: the pathspec
        # forms. A bare `git checkout <branch>` is not one of them, and git
        # itself refuses a switch that would lose a conflicting change.
        if "--" in args:
            return "git checkout -- <paths>", "tracked"
        i = 0
        while i < len(args):
            a = args[i]
            if a in VALUED:
                i += 2
                continue
            if a.startswith("-"):
                i += 1
                continue
            if os.path.exists(os.path.join(where, a)):
                return "git checkout <paths>", "tracked"
            i += 1
        return None, None

    return None, None

# --- turning a shell command into git command lines ------------------------
#
# shlex AND NOTHING ELSE. `echo "git reset --hard"` must not be read as a reset,
# and a tokeniser written in shell could not tell the difference; shlex applies
# the quoting rules, so a quoted occurrence arrives as one token and matches
# nothing. A command shlex CANNOT parse — an unbalanced quote, a heredoc — is
# not guessed at: it is allowed, because the alternative is refusing a command
# on the strength of a substring.

OVERRIDE_VAR = "INNSEGL_ALLOW_DESTRUCTIVE"
SEPARATORS = (";", "&&", "||", "|", "|&", "&", "(", ")", "{", "}", "!")
PREFIXES = ("command", "builtin", "exec", "nohup", "time", "sudo", "env",
            "nice", "stdbuf", "xargs")

def logical_lines(command):
    """The command split on newlines, honouring quotes that span them."""
    lines, buf = [], ""
    for raw in command.splitlines():
        buf = raw if not buf else buf + "\n" + raw
        if buf.rstrip().endswith("\\"):
            continue
        try:
            shlex.split(buf)
        except ValueError:
            continue          # an open quote: this line is not finished
        lines.append(buf)
        buf = ""
    if buf:
        lines.append(buf)
    return lines

def git_command_lines(command, start):
    """(git args, the directory it would run in) for each git in the command.

    `cd` IS FOLLOWED, and it has to be. MEASURED against the installed gate: the
    harness reports the SESSION'"'"'s cwd on every event, and an agent writes
    `cd <tree> && git reset --hard` far more often than it writes the bare form
    — so a guard reading only the event'"'"'s cwd weighed the command against a
    tree the command was never going to touch, allowed it, and the scratch
    repository it WAS about lost its uncommitted line.

    It is followed approximately, and the approximation is stated: `cd` inside a
    subshell does not survive it in a real shell and does survive it here,
    because `(` and `)` are read as separators rather than as nesting. That
    errs towards weighing a LATER command against an EARLIER `cd`, which asks
    about the wrong tree and can therefore only be wrong in the direction of a
    decision this guard already has to make correctly for the common case.

    AND THE OVERRIDE IS READ OUT OF THE COMMAND, not only out of the
    environment. MEASURED against the installed gate: a PreToolUse hook is a
    child of the HARNESS, not of the shell the command would have run in, so
    `INNSEGL_ALLOW_DESTRUCTIVE=1 git reset --hard` — the exact line the refusal
    prints — reached the guard with the variable unset and was refused again. A
    gate that blocks and offers a remedy that does not work is the failure the
    shim'"'"'s own header warns about: the work is stranded rather than merely
    at risk, and the next thing tried is the spelling with no remedy at all.
    """
    found, where, previous = [], start, start
    sticky = [False]
    for line in logical_lines(command):
        try:
            toks = shlex.split(line)
        except ValueError:
            continue
        runs, cur = [], []
        for t in toks:
            if t in SEPARATORS:
                if cur:
                    runs.append(cur)
                cur = []
            else:
                cur.append(t)
        if cur:
            runs.append(cur)
        for r in runs:
            i, waived = 0, False
            # leading VAR=value assignments, and the usual wrappers
            while i < len(r):
                t = r[i]
                if t == "export" and i == 0:
                    i += 1
                elif "=" in t and not t.startswith("-") and "/" not in t.split("=", 1)[0]:
                    if t.split("=", 1)[0] == OVERRIDE_VAR and t.split("=", 1)[1] not in ("", "0"):
                        waived = True
                    i += 1
                elif t in PREFIXES:
                    i += 1
                else:
                    break
            if i >= len(r):
                # AN ASSIGNMENT THAT IS THE WHOLE COMMAND sets it for what
                # follows in the same shell, which is how `export X=1 && git …`
                # is written. One that PREFIXES a command sets it for that
                # command alone, which is how the refusal prints it.
                if waived:
                    sticky[0] = True
                continue
            if r[i] in ("cd", "pushd"):
                target = r[i + 1] if i + 1 < len(r) else os.path.expanduser("~")
                if target == "-":
                    target = previous
                elif not os.path.isabs(target):
                    target = os.path.join(where, target)
                if os.path.isdir(target):
                    previous, where = where, target
                continue
            if r[i] == "git" or r[i].endswith("/git"):
                if waived or sticky[0]:
                    continue
                found.append((r[i + 1:], where))
    return found

# --- the tree ---------------------------------------------------------------

def git(where, *args):
    p = subprocess.run(("git", "-C", where) + args, stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL, timeout=30)
    if p.returncode != 0:
        raise RuntimeError("git " + " ".join(args))
    return p.stdout.decode("utf-8", "replace")

def dirty_sets(top):
    """(tracked, untracked) as sets of paths relative to top."""
    fields = git(top, "status", "--porcelain", "-z").split("\0")
    tracked, untracked, i = set(), set(), 0
    while i < len(fields):
        f = fields[i]
        i += 1
        if len(f) < 4:
            continue
        code, path = f[:2], f[3:]
        # A rename carries its source in the NEXT field.
        if "R" in code or "C" in code:
            i += 1
        if code == "??":
            untracked.add(path)
        elif code != "!!":
            tracked.add(path)
    return tracked, untracked

# --- who is live, and what do they claim ------------------------------------

class Run(object):
    def __init__(self, run_id, agent_type, task, directory, mtime):
        self.run_id = run_id
        self.agent_type = agent_type
        self.task = task
        self.dir = directory
        self.mtime = mtime

def markers_for(top):
    """Every run marker whose directory is this tree or inside it.

    THE SESSION IS NOT ONE OF THEM. `session-*` is the operator'"'"'s own run, and
    refusing the operator over their own uncommitted work is refusing them the
    use of their own repository. This guards AGENT work.
    """
    found = []
    try:
        names = sorted(os.listdir(runs_dir))
    except OSError:
        return found
    for name in names:
        if name.startswith(".") or name.startswith("session-") or name == "by-tree":
            continue
        path = os.path.join(runs_dir, name)
        try:
            if not os.path.isfile(path):
                continue
            body = json.loads(open(path).read())
            st = os.stat(path)
        except Exception:
            continue
        run_id = body.get("run_id") or ""
        directory = body.get("dir") or ""
        if not run_id or not directory:
            continue
        try:
            real = os.path.realpath(directory)
        except Exception:
            continue
        if real != top and not real.startswith(top + os.sep):
            continue
        found.append(Run(run_id, body.get("agent_type") or "",
                         body.get("task") or "", real, st.st_mtime))
    return found

LEDGER_SILENT = [False]

def is_live(run):
    """The ledger if it answers, the marker'"'"'s age if it does not."""
    if not LEDGER_SILENT[0]:
        try:
            import urllib.error, urllib.request
            url = api_url.rstrip("/") + "/api/v1/runs/" + run.run_id
            try:
                with urllib.request.urlopen(url, timeout=3) as r:
                    status = (json.loads(r.read().decode("utf-8")) or {}).get("status")
                if isinstance(status, str) and status:
                    return status == "active"
            except urllib.error.HTTPError:
                # A ledger that answers "I have never heard of this run" is a
                # ledger that is UP. Only this run falls back to its marker; the
                # next one is still asked.
                pass
        except Exception:
            LEDGER_SILENT[0] = True
    try:
        hours = float(ttl_hours)
    except ValueError:
        hours = 12.0
    return (time.time() - run.mtime) <= hours * 3600.0

def claimed_by(run, top):
    """(paths the run recorded writing, whether its record could be read)."""
    store = os.path.join(log_dir, run.run_id)
    if not os.path.isdir(store):
        return set(), False
    wrote = set()
    for f in sorted(pathlib.Path(store).glob("*.json")):
        try:
            d = json.loads(f.read_text())
        except Exception:
            continue
        if d.get("tool_name") not in ("Edit", "Write", "NotebookEdit"):
            continue
        fp = (d.get("tool_input") or {}).get("file_path")
        if not isinstance(fp, str) or not fp:
            continue
        base = d.get("cwd") if isinstance(d.get("cwd"), str) and d.get("cwd") else run.dir
        real = os.path.realpath(fp if os.path.isabs(fp) else os.path.join(base, fp))
        if real.startswith(top + os.sep):
            wrote.add(os.path.relpath(real, top))
    return wrote, True

# --- and what a run killed here still claims --------------------------------

# The record is append-only and never rotated, so only the end of it is read.
# A file that has grown past this has its oldest records dropped, and the oldest
# records are the ones whose work is likeliest to be long since committed.
UNCAP_TAIL = 4 * 1024 * 1024
KILLED_CACHE = {}

def killed_claims(top):
    # Every run KILLED in this tree with a claim the record still identifies.
    # See the header: the record carries the claim because the run no longer
    # can, and it carries the CONTENT because a claim on a name cannot be
    # released. Answers a list of (run, {path: (sha, size)}).
    if top in KILLED_CACHE:
        return KILLED_CACHE[top]
    found = []
    KILLED_CACHE[top] = found
    try:
        size = os.path.getsize(uncap_log)
        with open(uncap_log, "rb") as fh:
            if size > UNCAP_TAIL:
                fh.seek(size - UNCAP_TAIL)
                fh.readline()       # drop the partial line the seek landed in
            raw = fh.read().decode("utf-8", "replace")
    except OSError:
        return found
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue                # one unreadable line is not the whole log
        if not isinstance(rec, dict) or rec.get("reason") != "run_killed":
            continue
        # THE TREE IS THE OWNERSHIP BOUNDARY. One log serves every session on
        # this machine, and the sessions belonging to another repository have
        # live runs with real processes behind them. A record is weighed here
        # only if it names THIS repository as the tree its paths are relative
        # to; nothing else in it is trusted to say so.
        ctop = rec.get("claim_top")
        if not isinstance(ctop, str) or not ctop:
            continue
        try:
            if os.path.realpath(ctop) != top:
                continue
        except Exception:
            continue
        claim = rec.get("claim")
        if not isinstance(claim, list) or not claim:
            continue                # the shape written before #291: no content,
                                    # so no claim, and the header says so
        held = {}
        for e in claim:
            if not isinstance(e, dict):
                continue
            path, sha, count = e.get("path"), e.get("sha"), e.get("size")
            if (isinstance(path, str) and path and isinstance(sha, str)
                    and sha and isinstance(count, int) and count >= 0):
                held[path] = (sha, count)
        if held:
            found.append((Run(rec.get("run_id") or "",
                              rec.get("agent_type") or "",
                              rec.get("task") or "",
                              rec.get("dir") or ctop, 0.0), held))
    return found

def still_held(top, held, candidates):
    # Of the claimed paths this command can destroy, the ones that still hold
    # the work the record identified. THIS IS THE RELEASE: a path whose bytes
    # have changed is somebody else in a file with the same name, and a claim
    # that survived that would wedge the tree by accumulation.
    #
    # Size first, because it rejects the common case without reading a byte.
    kept = []
    for path in sorted(candidates):
        sha, count = held[path]
        full = os.path.join(top, path)
        try:
            if os.path.getsize(full) != count:
                continue
            h = hashlib.sha256()
            with open(full, "rb") as fh:
                while True:
                    chunk = fh.read(65536)
                    if not chunk:
                        break
                    h.update(chunk)
        except OSError:
            continue                # gone, or unreadable: nothing to protect
        if h.hexdigest() == sha:
            kept.append(path)
    return kept

def hits(wrote, dirty):
    """The claimed paths this command can actually destroy.

    An untracked DIRECTORY is reported by git as `dir/` and stands for
    everything under it, so a claimed path beneath one counts.
    """
    found = set()
    for d in dirty:
        if d.endswith("/"):
            for w in wrote:
                if w.startswith(d):
                    found.add(w)
        elif d in wrote:
            found.add(d)
    return found

# --- the decision -----------------------------------------------------------

def decide(args, spelling, start):
    sub, subargs, chdir = subcommand(args)
    if not sub:
        return ALLOW
    where = start
    if chdir:
        where = chdir if os.path.isabs(chdir) else os.path.join(start, chdir)
    if not os.path.isdir(where):
        return ALLOW

    english, scope = classify(sub, subargs, where)
    if not english:
        return ALLOW

    try:
        top = os.path.realpath(git(where, "rev-parse", "--show-toplevel").strip())
    except Exception:
        return ALLOW        # not a repository, or a git that will not answer
    try:
        tracked, untracked = dirty_sets(top)
    except Exception:
        return ALLOW
    dirty = untracked if scope == "untracked" else tracked
    if not dirty:
        return ALLOW        # nothing this command could destroy

    for run in markers_for(top):
        if not is_live(run):
            continue
        wrote, readable = claimed_by(run, top)
        if not readable:
            refuse(english, run, sorted(dirty), spelling, unreadable=True)
            return REFUSE
        theirs = hits(wrote, dirty)
        if theirs:
            refuse(english, run, sorted(theirs), spelling)
            return REFUSE

    # AND THEN THE RUNS THAT WERE KILLED HERE — RM-183 (#291). Second, so that a
    # tree with no killed-run claim in it behaves exactly as it did before this
    # existed, and so that a live run is still the first thing a refusal names.
    for run, held in killed_claims(top):
        theirs = hits(set(held), dirty)
        if not theirs:
            continue                # committed, gone, or not in this scope
        kept = still_held(top, held, theirs)
        if kept:
            refuse(english, run, kept, spelling, killed=True)
            return REFUSE
    return ALLOW

def refuse(english, run, paths, spelling, unreadable=False, killed=False):
    who = run.run_id
    if run.agent_type:
        who += " (" + run.agent_type + (", task " + run.task if run.task else "") + ")"
    out("refused: " + english + " would discard work an agent run has not committed.")
    out()
    if killed:
        out("  " + who)
        out("  was KILLED with " + str(len(paths)) +
            " uncommitted path(s) in " + run.dir + ",")
        out("  and the tree still holds them exactly as it left them:")
        for p in paths[:10]:
            out("    " + p)
        if len(paths) > 10:
            out("    ... and " + str(len(paths) - 10) + " more")
    elif unreadable:
        out("  " + who)
        out("  is live in " + run.dir + " and what it wrote cannot be read:")
        out("  there is no tool-call body store for it under " + log_dir + ".")
        out("  " + str(len(paths)) + " uncommitted path(s) here may be its work, and a run")
        out("  nobody can ask is not a run that wrote nothing (#284).")
    else:
        out("  " + who)
        out("  wrote " + str(len(paths)) + " of the uncommitted path(s) in " + run.dir + ":")
        for p in paths[:10]:
            out("    " + p)
        if len(paths) > 10:
            out("    ... and " + str(len(paths) - 10) + " more")
    out()
    if killed:
        out("  Nothing is coming back for that work. A killed agent fires no stop,")
        out("  so nothing captured it and nothing is going to (#290, #291); the")
        out("  claim is the record in " + uncap_log + ".")
        out("  It is spent the moment these paths are committed, removed or written")
        out("  over, so this is not a lock on the tree.")
    else:
        out("  That run has not stopped, so nothing has captured its work yet. A hard")
        out("  reset took eight minutes of a subagent'"'"'s finished work once already, and")
        out("  nothing refused, warned or recorded it (#278).")
    out()
    out("  To KEEP the work, sign it under the run that did it:")
    out("    innsegl-commit -r " + run.run_id +
        ((" -t " + run.task) if run.task else "") + " -m \"<type>(<scope>): <what changed>\"")
    out()
    out("  To discard it anyway, deliberately:")
    out("    INNSEGL_ALLOW_DESTRUCTIVE=1 " + spelling)

def main():
    if mode == "argv":
        return decide(rest, "git " + " ".join(shlex.quote(a) for a in rest), cwd)
    command = rest[0] if rest else ""
    for args, where in git_command_lines(command, cwd):
        spelling = "git " + " ".join(shlex.quote(a) for a in args)
        if decide(args, spelling, where) == REFUSE:
            return REFUSE
    return ALLOW

try:
    sys.exit(main())
except SystemExit:
    raise
except Exception:
    sys.exit(ALLOW)
'

# decide <mode> <cwd> <args...> — 0 to allow, 2 to refuse, 0 on any failure.
#
# THE OVERRIDE AND THE OFF SWITCH ARE READ HERE, before anything is computed, so
# that a machine that has turned this off pays nothing at all for it.
decide() {
  [ "${INNSEGL_GIT_GUARD:-1}" = "0" ] && return 0
  if [ "${INNSEGL_ALLOW_DESTRUCTIVE:-0}" != "0" ]; then
    echo "innsegl: INNSEGL_ALLOW_DESTRUCTIVE is set; not guarding this command (#278)." >&2
    return 0
  fi
  command -v python3 >/dev/null 2>&1 || return 0
  _mode="$1"; _cwd="$2"; shift 2
  python3 -c "$GUARD_DECIDE" "$_mode" "$_cwd" \
    "$RUNS_DIR" "$LOG_DIR" "$API_URL" "$TTL_HOURS" "$UNCAP_LOG" "$@"
  _rc=$?
  [ "$_rc" = "2" ] && return 2
  return 0
}

# real_git — the git this wrapper stands in front of.
#
# EVERY PATH ENTRY IS COMPARED AGAINST THIS FILE, not just the first: a wrapper
# that found itself would recurse until the shell ran out of processes, and a
# wrapper installed by symlink has a different name in every one of them.
real_git() {
  if [ -n "${INNSEGL_REAL_GIT:-}" ] && [ -x "${INNSEGL_REAL_GIT}" ]; then
    printf '%s' "$INNSEGL_REAL_GIT"
    return 0
  fi
  _self="$(cd -- "$(dirname -- "$0")" 2>/dev/null && pwd -P)/$(basename -- "$0")"
  _self_real="$(python3 -c 'import os,sys;print(os.path.realpath(sys.argv[1]))' "$_self" 2>/dev/null || printf '%s' "$_self")"
  _found=""
  _ifs="$IFS"
  IFS=:
  for _d in $PATH; do
    [ -n "$_d" ] || _d=.
    _c="$_d/git"
    [ -x "$_c" ] || continue
    _c_real="$(python3 -c 'import os,sys;print(os.path.realpath(sys.argv[1]))' "$_c" 2>/dev/null || printf '%s' "$_c")"
    [ "$_c_real" = "$_self_real" ] && continue
    _found="$_c"
    break
  done
  IFS="$_ifs"
  printf '%s' "$_found"
}

usage() {
  cat >&2 <<'EOF'
innsegl: git-tree-guard.sh — refuse a destructive git while an agent run holds
                             uncommitted work in this tree (#278)

  git-tree-guard.sh check [--] <git args...>   decide on one command line
  git-tree-guard.sh command '<shell command>'  decide on a shell command string
  git-tree-guard.sh hook                       decide on a PreToolUse event (stdin)
  git-tree-guard.sh wrap <git args...>         decide, then run the real git

  Symlinked as `git` on PATH it is `wrap`. Exit 2 refuses; anything else allows.
EOF
}

# ---------------------------------------------------------------------------
# Dispatch. Invoked AS `git` — which is how the PATH wrapper is installed — the
# whole argv is a git command line and there is no mode word to read.
# ---------------------------------------------------------------------------
case "$(basename -- "$0")" in
  git|git.sh) set -- wrap "$@" ;;
esac

MODE="${1:-}"
[ $# -gt 0 ] && shift

case "$MODE" in
  check)
    [ "${1:-}" = "--" ] && shift
    decide argv "$(pwd -P)" "$@"
    exit $?
    ;;

  command)
    decide command "$(pwd -P)" "${1:-}"
    exit $?
    ;;

  hook)
    # The harness's own PreToolUse event, on stdin. Only a Bash command is read;
    # every other tool is allowed without a thought, and an event that cannot be
    # parsed is allowed too.
    _ev="$(cat)"
    _read="$(printf '%s' "$_ev" | python3 -c '
import json, shlex, sys
try:
    e = json.load(sys.stdin)
except Exception:
    e = {}
ti = e.get("tool_input")
if not isinstance(ti, dict):
    ti = {}
cmd = ti.get("command")
print("GUARD_TOOL=" + shlex.quote(e.get("tool_name") or ""))
print("GUARD_CMD=" + shlex.quote(cmd if isinstance(cmd, str) else ""))
print("GUARD_CWD=" + shlex.quote(e.get("cwd") or ""))
' 2>/dev/null)"
    GUARD_TOOL=""; GUARD_CMD=""; GUARD_CWD=""
    eval "$_read" 2>/dev/null || exit 0
    [ "$GUARD_TOOL" = "Bash" ] || exit 0
    [ -n "$GUARD_CMD" ] || exit 0
    case "$GUARD_CMD" in *git*) : ;; *) exit 0 ;; esac
    [ -n "$GUARD_CWD" ] && [ -d "$GUARD_CWD" ] || GUARD_CWD="$(pwd -P)"
    decide command "$GUARD_CWD" "$GUARD_CMD"
    exit $?
    ;;

  wrap)
    decide argv "$(pwd -P)" "$@"
    _rc=$?
    [ "$_rc" = "2" ] && exit 2
    GIT="$(real_git)"
    if [ -z "$GIT" ]; then
      echo "innsegl: git-tree-guard.sh is installed as git and cannot find the real one;" >&2
      echo "innsegl: set INNSEGL_REAL_GIT to it." >&2
      exit 2
    fi
    exec "$GIT" "$@"
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
