#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# OPS-090..093 — the destructive-git guard, driven against a real repository.
#
# #278 (RM-173). Measured: a `git reset --hard HEAD~1` in a shared checkout
# discarded a subagent's finished but uncommitted work — eight minutes of it —
# and nothing refused, warned or recorded the loss. The guard this drives is
# scripts/hooks/git-tree-guard.sh.
#
# WHAT IS ASSERTED IS THE TREE, NOT A RETURN CODE. Every refusal case runs the
# real command through the guard's `wrap` mode, against a real git, and then
# reads the files back. A guard that returns 2 while the command still ran is a
# guard that passes every assertion about its own exit status and loses the work
# anyway — which is the shape of the first fix to #261, and the reason that one
# needed a second.
#
# AND IT RUNS NOWHERE NEAR THE CHECKOUT IT PROTECTS. Every fixture is a fresh
# repository under mktemp; a self-test for a guard on `reset --hard` that used
# the developer's own tree would be one bug away from being the incident.
#
# USAGE
#   scripts/hooks/git-tree-guard-selftest.sh
#
#   INNSEGL_TREE_GUARD   the guard to drive. Point it at a script that always
#                        exits 0 to see what the repository looked like before
#                        this one existed: every OPS-090..093 refusal goes red,
#                        and every "it does not refuse" case stays green.
#
# It needs python3 and git. No Docker, no MCP, no network beyond loopback.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GUARD="${INNSEGL_TREE_GUARD:-$ROOT/scripts/hooks/git-tree-guard.sh}"

pass=0
fail=0
ok()  { pass=$((pass + 1)); echo "  ok    $1"; }
bad() { fail=$((fail + 1)); echo "  FAIL  $1" >&2; }

[ -x "$GUARD" ] || { echo "guard-selftest: $GUARD is missing or not executable" >&2; exit 4; }
for need in python3 git; do
  command -v "$need" >/dev/null 2>&1 || { echo "guard-selftest: $need is required" >&2; exit 4; }
done

WORK="$(mktemp -d)"
trap 'if [ -n "${LEDGER_PID:-}" ]; then kill "$LEDGER_PID" 2>/dev/null; wait "$LEDGER_PID" 2>/dev/null; fi; rm -rf "$WORK"' EXIT

RUNS="$WORK/runs"
LOG="$WORK/log"
mkdir -p "$RUNS" "$LOG"

# ---------------------------------------------------------------------------
# A stub ledger, because "the run is retired" is the case the guard must get
# right and the marker cannot express it: a subagent killed with its session
# fires no SubagentStop and leaves its marker behind forever (#260).
# ---------------------------------------------------------------------------
cat > "$WORK/ledger.py" <<'PY'
import http.server, json, os, socketserver, sys

STATE = os.environ["LEDGER_STATE"]

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        run = self.path.rsplit("/", 1)[-1]
        try:
            states = json.loads(open(STATE).read())
        except Exception:
            states = {}
        if run not in states:
            self.send_response(404); self.end_headers(); return
        body = json.dumps({"run_id": run, "status": states[run]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass

class S(socketserver.TCPServer):
    allow_reuse_address = True

s = S(("127.0.0.1", 0), H)
print(s.server_address[1], flush=True)
s.serve_forever()
PY
LEDGER_STATE="$WORK/ledger.json"
echo '{}' > "$LEDGER_STATE"
LEDGER_STATE="$LEDGER_STATE" python3 "$WORK/ledger.py" > "$WORK/ledger.port" 2>"$WORK/ledger.err" &
LEDGER_PID=$!
for _ in $(seq 1 100); do
  LPORT="$(head -n 1 "$WORK/ledger.port" 2>/dev/null)"
  [ -n "$LPORT" ] && break
  sleep 0.1
done
[ -n "${LPORT:-}" ] || { echo "guard-selftest: the stub ledger never reported a port" >&2; exit 4; }
LEDGER="http://127.0.0.1:$LPORT"

# ledger_says <run-id> <status|-> — `-` means the ledger has never heard of it.
ledger_says() {
  python3 -c '
import json, sys
p, run, status = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    d = json.loads(open(p).read())
except Exception:
    d = {}
if status == "-":
    d.pop(run, None)
else:
    d[run] = status
open(p, "w").write(json.dumps(d))
' "$WORK/ledger.json" "$1" "$2"
}

# ---------------------------------------------------------------------------
# The fixture repository, and a run registered against it.
# ---------------------------------------------------------------------------
REPO="$WORK/repo"
mkdir -p "$REPO" "$WORK/nohooks"
git -C "$REPO" init -q
git -C "$REPO" config user.email "guard-selftest@example.test"
git -C "$REPO" config user.name "guard-selftest"
git -C "$REPO" config commit.gpgsign false
git -C "$REPO" config core.hooksPath "$WORK/nohooks"
printf 'base\n' > "$REPO/tracked.txt"
printf 'other\n' > "$REPO/other.txt"
git -C "$REPO" add tracked.txt other.txt
git -C "$REPO" commit -q -m base
git -C "$REPO" branch -q side
REPO_REAL="$(cd "$REPO" && pwd -P)"

# register <marker> <run-id> <agent-type> <task> — the marker SubagentStart
# writes, in the shape it writes it.
register() {
  printf '{"run_id":"%s","task":"%s","worktree":"","agent_type":"%s","dir":"%s"}\n' \
    "$2" "$4" "$3" "$REPO_REAL" > "$RUNS/$1"
  mkdir -p "$LOG/$2"
  ledger_says "$2" active
}

# wrote <run-id> <name> <path> — one tool-call body recording a file write, in
# the shape the MCP stores it.
wrote() {
  printf '{"tool_name":"Edit","cwd":"%s","tool_input":{"file_path":"%s"}}' \
    "$REPO_REAL" "$3" > "$LOG/$1/$2.json"
}

# run_guard <mode> <args...> — the guard, with every path pinned at the fixture.
run_guard() {
  ( cd "$REPO" && env \
      INNSEGL_RUNS_DIR="$RUNS" \
      INNSEGL_LOG_DIR="$LOG" \
      INNSEGL_API_URL="${API_OVERRIDE:-$LEDGER}" \
      INNSEGL_ALLOW_DESTRUCTIVE="${OVERRIDE:-0}" \
      "$GUARD" "$@" ) > "$WORK/out" 2> "$WORK/err"
  STATUS=$?
}

# attempt <git args...> — the real command, through the guard's wrap mode. This
# is the assertion that matters: either the guard refused AND git never ran, or
# git ran and the tree changed.
attempt() { run_guard wrap "$@"; }

# state — the whole working tree, as one comparable string.
state() {
  ( cd "$REPO" && for f in $(git ls-files) $(git ls-files --others --exclude-standard); do
      printf '%s=%s;' "$f" "$(cat "$f" 2>/dev/null | tr -d '\n')"
    done )
}

dirty_now() { git -C "$REPO" status --porcelain | wc -l | tr -d ' '; }

# reset_fixture — back to a clean tree, with no run registered anywhere.
reset_fixture() {
  git -C "$REPO" checkout -q --force main 2>/dev/null || git -C "$REPO" checkout -q --force master
  git -C "$REPO" reset -q --hard HEAD
  git -C "$REPO" clean -qfd
  rm -f "$RUNS"/* 2>/dev/null
  rm -rf "${LOG:?}"/* 2>/dev/null
  echo '{}' > "$WORK/ledger.json"
}

echo "guard-selftest: the destructive-git guard, driven against a real tree"

# --- OPS-090: every destructive form is refused, and the tree is unchanged ----
#
# ONE LIVE RUN, ONE FILE IT WROTE, AND THE FILE IS STILL DIRTY. That is the
# whole precondition the issue names, and each form below is measured against
# the same one so that a difference between them is a difference in the guard
# and not in the fixture.

# reset --hard, which is the measured incident itself.
reset_fixture
register agent-1 run-aaaa1111 general-purpose rm173
wrote run-aaaa1111 a "$REPO_REAL/tracked.txt"
printf 'AGENT WORK\n' >> "$REPO/tracked.txt"
BEFORE="$(state)"
attempt reset --hard HEAD
if [ "$STATUS" -eq 2 ] && [ "$(state)" = "$BEFORE" ]; then
  ok "OPS-090 reset --hard is refused and the tracked edit is still there"
else
  bad "OPS-090 reset --hard: status $STATUS, tree $(state)"
fi

# checkout -- <path>, the per-path spelling of the same loss.
attempt checkout -- tracked.txt
if [ "$STATUS" -eq 2 ] && [ "$(state)" = "$BEFORE" ]; then
  ok "OPS-090 checkout -- <path> is refused and the file is unchanged"
else
  bad "OPS-090 checkout --: status $STATUS, tree $(state)"
fi

# git restore, which is the same operation under its modern name.
attempt restore tracked.txt
if [ "$STATUS" -eq 2 ] && [ "$(state)" = "$BEFORE" ]; then
  ok "OPS-090 restore <path> is refused and the file is unchanged"
else
  bad "OPS-090 restore: status $STATUS, tree $(state)"
fi

# The discarding branch switch, in both spellings.
attempt checkout -f side
if [ "$STATUS" -eq 2 ] && [ "$(state)" = "$BEFORE" ]; then
  ok "OPS-090 a discarding checkout -f is refused"
else
  bad "OPS-090 checkout -f: status $STATUS, tree $(state)"
fi
attempt switch --discard-changes side
if [ "$STATUS" -eq 2 ] && [ "$(state)" = "$BEFORE" ]; then
  ok "OPS-090 and so is switch --discard-changes"
else
  bad "OPS-090 switch --discard-changes: status $STATUS, tree $(state)"
fi

# clean -f, which reaches the half of the tree a reset cannot: the UNTRACKED
# files that survived the incident.
reset_fixture
register agent-2 run-bbbb2222 general-purpose rm173
wrote run-bbbb2222 a "$REPO_REAL/new.txt"
printf 'AGENT WORK\n' > "$REPO/new.txt"
BEFORE="$(state)"
attempt clean -fd
if [ "$STATUS" -eq 2 ] && [ -f "$REPO/new.txt" ] && [ "$(state)" = "$BEFORE" ]; then
  ok "OPS-090 clean -f is refused over an untracked file the run wrote"
else
  bad "OPS-090 clean -fd: status $STATUS, tree $(state)"
fi

# AND A COMBINED SHORT FLAG IS NOT A WAY ROUND IT.
attempt clean -xfd
if [ "$STATUS" -eq 2 ] && [ -f "$REPO/new.txt" ]; then
  ok "OPS-090 and -xfd is read as the same command, not as an unknown one"
else
  bad "OPS-090 clean -xfd: status $STATUS"
fi

# --- OPS-091: the refusal says what the issue asks it to say ------------------
reset_fixture
register agent-3 run-cccc3333 prober rm173
wrote run-cccc3333 a "$REPO_REAL/tracked.txt"
wrote run-cccc3333 b "$REPO_REAL/other.txt"
printf 'AGENT WORK\n' >> "$REPO/tracked.txt"
printf 'AGENT WORK\n' >> "$REPO/other.txt"
attempt reset --hard HEAD
if grep -q 'run-cccc3333' "$WORK/err"; then
  ok "OPS-091 the refusal names the run that holds the work"
else
  bad "OPS-091 the refusal names no run: $(cat "$WORK/err")"
fi
if grep -q 'wrote 2 of the uncommitted' "$WORK/err"; then
  ok "OPS-091 and the file count, which is what says how much is at stake"
else
  bad "OPS-091 no file count: $(cat "$WORK/err")"
fi
if grep -q 'INNSEGL_ALLOW_DESTRUCTIVE=1' "$WORK/err"; then
  ok "OPS-091 and how to override it deliberately"
else
  bad "OPS-091 no override in the refusal: $(cat "$WORK/err")"
fi
# A REFUSAL THAT STRANDS THE WORK IS WORSE THAN THE LOSS IT PREVENTS. The run is
# named with the command that would sign its work rather than left as a wall.
if grep -q 'innsegl-commit -r run-cccc3333' "$WORK/err"; then
  ok "OPS-091 and how to keep the work instead, under the run that did it"
else
  bad "OPS-091 no remedy: $(cat "$WORK/err")"
fi

# --- OPS-092: what it must NOT refuse ----------------------------------------
#
# THE HALF THAT DECIDES WHETHER THIS IS USABLE. A guard that refuses a clean
# tree, or a tree whose only dirty files are the operator's own, is a guard that
# gets switched off in a shell profile within the week, and then protects
# nothing at all.

# A clean tree.
reset_fixture
register agent-4 run-dddd4444 general-purpose rm173
wrote run-dddd4444 a "$REPO_REAL/tracked.txt"
attempt reset --hard HEAD
if [ "$STATUS" -eq 0 ]; then
  ok "OPS-092 a clean tree is not refused over, live run or not"
else
  bad "OPS-092 clean tree refused: $(cat "$WORK/err")"
fi

# A dirty tree with no run registered at all.
reset_fixture
printf 'operator work\n' >> "$REPO/tracked.txt"
BEFORE_N="$(dirty_now)"
attempt reset --hard HEAD
if [ "$STATUS" -eq 0 ] && [ "$(dirty_now)" = "0" ]; then
  ok "OPS-092 with no run live, the operator's own reset runs as it always did"
else
  bad "OPS-092 no-run reset: status $STATUS, dirty was $BEFORE_N now $(dirty_now)"
fi

# A run whose stop HAS fired: the marker is gone.
reset_fixture
register agent-5 run-eeee5555 general-purpose rm173
wrote run-eeee5555 a "$REPO_REAL/tracked.txt"
printf 'AGENT WORK\n' >> "$REPO/tracked.txt"
rm -f "$RUNS/agent-5"
attempt reset --hard HEAD
if [ "$STATUS" -eq 0 ] && [ "$(dirty_now)" = "0" ]; then
  ok "OPS-092 a run whose stop removed its marker holds nothing"
else
  bad "OPS-092 stopped run: status $STATUS, dirty $(dirty_now)"
fi

# A run the LEDGER says is retired, with its marker still lying there — the
# killed subagent of #260, and the case the marker alone cannot answer.
reset_fixture
register agent-6 run-ffff6666 general-purpose rm173
wrote run-ffff6666 a "$REPO_REAL/tracked.txt"
ledger_says run-ffff6666 retired
printf 'LEFTOVER\n' >> "$REPO/tracked.txt"
attempt reset --hard HEAD
if [ "$STATUS" -eq 0 ] && [ "$(dirty_now)" = "0" ]; then
  ok "OPS-092 a marker left behind by a killed run does not wedge the tree"
else
  bad "OPS-092 retired run: status $STATUS, dirty $(dirty_now), $(cat "$WORK/err")"
fi

# THE SAME RUN, SAID TO BE ACTIVE, IS REFUSED OVER. Asserted immediately after
# the case above and against the same fixture, because "it allowed" is worth
# nothing unless the only thing changed was the ledger's answer.
reset_fixture
register agent-6 run-ffff6666 general-purpose rm173
wrote run-ffff6666 a "$REPO_REAL/tracked.txt"
printf 'LEFTOVER\n' >> "$REPO/tracked.txt"
attempt reset --hard HEAD
if [ "$STATUS" -eq 2 ] && [ "$(dirty_now)" != "0" ]; then
  ok "OPS-092 and the same marker with the ledger saying active IS refused"
else
  bad "OPS-092 active run: status $STATUS, dirty $(dirty_now)"
fi

# Dirty files that belong to nobody: a live run that wrote a DIFFERENT file.
reset_fixture
register agent-7 run-7777aaaa general-purpose rm173
wrote run-7777aaaa a "$REPO_REAL/tracked.txt"
printf 'not the agents\n' >> "$REPO/other.txt"
attempt reset --hard HEAD
if [ "$STATUS" -eq 0 ] && [ "$(dirty_now)" = "0" ]; then
  ok "OPS-092 a dirty file no live run wrote is not refused over"
else
  bad "OPS-092 unowned dirty file: status $STATUS, dirty $(dirty_now), $(cat "$WORK/err")"
fi

# THE OPERATOR'S OWN SESSION IS NOT AN AGENT. Its marker names the same tree and
# its writes are the operator's; refusing them is refusing a person the use of
# their own repository.
reset_fixture
printf '{"run_id":"run-session1","task":"t","worktree":"","agent_type":"session","dir":"%s"}\n' \
  "$REPO_REAL" > "$RUNS/session-abc"
mkdir -p "$LOG/run-session1"
ledger_says run-session1 active
printf '{"tool_name":"Edit","cwd":"%s","tool_input":{"file_path":"%s"}}' \
  "$REPO_REAL" "$REPO_REAL/tracked.txt" > "$LOG/run-session1/a.json"
printf 'my own work\n' >> "$REPO/tracked.txt"
attempt reset --hard HEAD
if [ "$STATUS" -eq 0 ] && [ "$(dirty_now)" = "0" ]; then
  ok "OPS-092 the operator's own session is not guarded against its own tree"
else
  bad "OPS-092 session marker: status $STATUS, dirty $(dirty_now), $(cat "$WORK/err")"
fi

# THE SCOPES DO NOT LEAK INTO EACH OTHER. `clean -f` cannot destroy a tracked
# edit and `reset --hard` cannot destroy an untracked file, so neither may be
# refused over work it could not reach.
reset_fixture
register agent-8 run-8888bbbb general-purpose rm173
wrote run-8888bbbb a "$REPO_REAL/tracked.txt"
printf 'AGENT WORK\n' >> "$REPO/tracked.txt"
attempt clean -fd
if [ "$STATUS" -eq 0 ]; then
  ok "OPS-092 clean -f is not refused over a tracked edit it cannot touch"
else
  bad "OPS-092 clean over a tracked edit was refused: $(cat "$WORK/err")"
fi
reset_fixture
register agent-9 run-9999cccc general-purpose rm173
wrote run-9999cccc a "$REPO_REAL/new.txt"
printf 'AGENT WORK\n' > "$REPO/new.txt"
attempt reset --hard HEAD
if [ "$STATUS" -eq 0 ] && [ -f "$REPO/new.txt" ]; then
  ok "OPS-092 and reset --hard is not refused over an untracked file it cannot touch"
else
  bad "OPS-092 reset over an untracked file: status $STATUS"
fi

# The non-destructive spellings, each of which moves a ref or an index and no
# file in the tree.
reset_fixture
register agent-10 run-aaaa0000 general-purpose rm173
wrote run-aaaa0000 a "$REPO_REAL/tracked.txt"
printf 'AGENT WORK\n' >> "$REPO/tracked.txt"
git -C "$REPO" add tracked.txt
SOFT=0
run_guard check reset --soft HEAD; [ "$STATUS" -eq 0 ] || SOFT=1
run_guard check reset HEAD;        [ "$STATUS" -eq 0 ] || SOFT=1
run_guard check restore --staged tracked.txt; [ "$STATUS" -eq 0 ] || SOFT=1
run_guard check clean -n;          [ "$STATUS" -eq 0 ] || SOFT=1
run_guard check status;            [ "$STATUS" -eq 0 ] || SOFT=1
run_guard check switch side;       [ "$STATUS" -eq 0 ] || SOFT=1
run_guard check checkout -b newbranch; [ "$STATUS" -eq 0 ] || SOFT=1
if [ "$SOFT" -eq 0 ]; then
  ok "OPS-092 reset --soft, reset, restore --staged, clean -n and a plain switch all run"
else
  bad "OPS-092 a command that destroys nothing was refused: $(cat "$WORK/err")"
fi

# THE OVERRIDE, which is the only thing standing between this guard and an
# operator who cannot get their work done.
reset_fixture
register agent-11 run-bbbb0000 general-purpose rm173
wrote run-bbbb0000 a "$REPO_REAL/tracked.txt"
printf 'AGENT WORK\n' >> "$REPO/tracked.txt"
OVERRIDE=1
attempt reset --hard HEAD
OVERRIDE_STATUS=$STATUS
OVERRIDE=0
if [ "$OVERRIDE_STATUS" -eq 0 ] && [ "$(dirty_now)" = "0" ]; then
  ok "OPS-092 the override lets the command through"
else
  bad "OPS-092 override: status $OVERRIDE_STATUS, dirty $(dirty_now)"
fi
if grep -q 'INNSEGL_ALLOW_DESTRUCTIVE is set' "$WORK/err"; then
  ok "OPS-092 and says so, so an override is never silent"
else
  bad "OPS-092 the override was silent: $(cat "$WORK/err")"
fi

# --- OPS-093: the record that cannot be read, and the command that cannot be --
#              read either
#
# A LIVE RUN WHOSE BODY STORE IS GONE IS REFUSED OVER. Same rule as #284 one
# level out: a run nobody can ask is not a run that wrote nothing. Refusing
# costs one environment variable; allowing costs the work.
reset_fixture
register agent-12 run-cccc0000 general-purpose rm173
rm -rf "${LOG:?}/run-cccc0000"
printf 'SOMEBODYS WORK\n' >> "$REPO/tracked.txt"
attempt reset --hard HEAD
if [ "$STATUS" -eq 2 ] && [ "$(dirty_now)" != "0" ]; then
  ok "OPS-093 a live run whose record cannot be read is refused over, not past"
else
  bad "OPS-093 unreadable record: status $STATUS, dirty $(dirty_now)"
fi
if grep -q 'cannot be read' "$WORK/err"; then
  ok "OPS-093 and the refusal says that is why, not that the files are its work"
else
  bad "OPS-093 the refusal does not say what it could not read: $(cat "$WORK/err")"
fi

# --- OPS-093: the hook path --------------------------------------------------
#
# The harness's own PreToolUse event, which is the half that needs no operator
# action. Exit 2 is what blocks a Bash call.
reset_fixture
register agent-13 run-dddd0000 general-purpose rm173
wrote run-dddd0000 a "$REPO_REAL/tracked.txt"
printf 'AGENT WORK\n' >> "$REPO/tracked.txt"

hook_event() {
  python3 -c '
import json, sys
print(json.dumps({"hook_event_name": "PreToolUse", "tool_name": sys.argv[1],
                  "cwd": sys.argv[2], "tool_input": {"command": sys.argv[3]}}))
' "$1" "${EVENT_CWD:-$REPO_REAL}" "$2"
}
drive_hook() {
  printf '%s' "$(hook_event "${2:-Bash}" "$1")" | ( cd "${EVENT_CWD:-$REPO}" && env \
      INNSEGL_RUNS_DIR="$RUNS" INNSEGL_LOG_DIR="$LOG" \
      INNSEGL_API_URL="$LEDGER" INNSEGL_ALLOW_DESTRUCTIVE=0 \
      "$GUARD" hook ) > "$WORK/out" 2> "$WORK/err"
  STATUS=$?
}

drive_hook 'git reset --hard HEAD'
if [ "$STATUS" -eq 2 ]; then
  ok "OPS-093 a PreToolUse Bash call carrying a destructive git is blocked"
else
  bad "OPS-093 hook: status $STATUS for a bare reset --hard"
fi

# AND IT IS FOUND WHEREVER IT IS IN THE LINE. An agent writes a compound
# command far more often than a bare one.
drive_hook 'cd '"$REPO_REAL"' && git reset --hard HEAD && echo done'
if [ "$STATUS" -eq 2 ]; then
  ok "OPS-093 and found in a compound command, not only as the first word"
else
  bad "OPS-093 hook compound: status $STATUS"
fi
drive_hook 'echo one
git restore tracked.txt'
if [ "$STATUS" -eq 2 ]; then
  ok "OPS-093 and on the second line of a multi-line command"
else
  bad "OPS-093 hook multi-line: status $STATUS"
fi

# AND THE `cd` IS FOLLOWED. MEASURED against the installed gate: the harness
# reports the SESSION's cwd on every event, not the command's, and an agent
# writes `cd <tree> && git reset --hard` far more often than the bare form. A
# guard reading only the event's cwd weighed that command against a tree it was
# never going to touch, allowed it, and the repository it WAS about lost its
# uncommitted line. Both halves are asserted together: the event's own cwd is a
# DIFFERENT repository, clean and with no run live in it, so a guard ignoring
# the `cd` allows and a guard following it refuses.
ELSEWHERE="$WORK/elsewhere"
mkdir -p "$ELSEWHERE"
git -C "$ELSEWHERE" init -q
git -C "$ELSEWHERE" config user.email "guard-selftest@example.test"
git -C "$ELSEWHERE" config user.name "guard-selftest"
git -C "$ELSEWHERE" config commit.gpgsign false
git -C "$ELSEWHERE" config core.hooksPath "$WORK/nohooks"
printf 'x\n' > "$ELSEWHERE/x.txt"
git -C "$ELSEWHERE" add x.txt
git -C "$ELSEWHERE" commit -q -m base
EVENT_CWD="$ELSEWHERE"
drive_hook 'cd '"$REPO_REAL"' && git reset --hard HEAD'
CD_FOLLOWED=$STATUS
drive_hook 'git reset --hard HEAD'
CD_ABSENT=$STATUS
EVENT_CWD=""
if [ "$CD_FOLLOWED" -eq 2 ] && [ "$CD_ABSENT" -eq 0 ]; then
  ok "OPS-093 and a cd into the guarded tree is followed, while the event's own cwd is not"
else
  bad "OPS-093 cd: with cd $CD_FOLLOWED, without $CD_ABSENT"
fi

# THE OVERRIDE THE REFUSAL PRINTS HAS TO WORK WHERE IT IS PRINTED. MEASURED
# against the installed gate: a PreToolUse hook is a child of the HARNESS, not
# of the shell the command would have run in, so the exact line the refusal
# offered — `INNSEGL_ALLOW_DESTRUCTIVE=1 git reset --hard` — arrived with the
# variable unset and was refused a second time. A gate that blocks and offers a
# remedy that does not work strands the work rather than protecting it.
drive_hook 'git reset --hard HEAD'
NO_WAIVER=$STATUS
drive_hook 'INNSEGL_ALLOW_DESTRUCTIVE=1 git reset --hard HEAD'
PREFIXED=$STATUS
drive_hook 'export INNSEGL_ALLOW_DESTRUCTIVE=1 && git reset --hard HEAD'
EXPORTED=$STATUS
drive_hook 'INNSEGL_ALLOW_DESTRUCTIVE=0 git reset --hard HEAD'
EXPLICIT_ZERO=$STATUS
if [ "$NO_WAIVER" -eq 2 ] && [ "$PREFIXED" -eq 0 ] && [ "$EXPORTED" -eq 0 ] \
   && [ "$EXPLICIT_ZERO" -eq 2 ]; then
  ok "OPS-093 and the override is read out of the command itself, where the hook can see it"
else
  bad "OPS-093 override in command: bare $NO_WAIVER, prefixed $PREFIXED, exported $EXPORTED, zero $EXPLICIT_ZERO"
fi

# NOTHING IS GUESSED FROM A SUBSTRING, which is the whole reason the command is
# tokenised rather than grepped. A guard that refused this would refuse every
# message, comment and heredoc that mentions the command it guards — including
# the refusal it prints itself.
drive_hook 'echo "git reset --hard is what took the work"'
if [ "$STATUS" -eq 0 ]; then
  ok "OPS-093 a quoted mention of the command is not the command"
else
  bad "OPS-093 a quoted mention was refused: $(cat "$WORK/err")"
fi
drive_hook 'git status --porcelain'
if [ "$STATUS" -eq 0 ]; then
  ok "OPS-093 and a git that destroys nothing costs a Bash call nothing"
else
  bad "OPS-093 git status was refused: $(cat "$WORK/err")"
fi
drive_hook 'git reset --hard HEAD' Read
if [ "$STATUS" -eq 0 ]; then
  ok "OPS-093 and a tool that is not Bash is not read as a command at all"
else
  bad "OPS-093 a Read event was refused: $(cat "$WORK/err")"
fi

# --- OPS-093: it fails open ---------------------------------------------------
#
# This file sits in front of git on a machine somebody works on. Every way it
# can be confused must end in the command running: the only thing worse than an
# unguarded reset is a shell that cannot run git at all.
reset_fixture
register agent-14 run-eeee0000 general-purpose rm173
wrote run-eeee0000 a "$REPO_REAL/tracked.txt"
printf 'AGENT WORK\n' >> "$REPO/tracked.txt"
BEFORE="$(state)"
OPEN=0
# A runs directory that is not there at all.
( cd "$REPO" && env INNSEGL_RUNS_DIR="$WORK/nonexistent" INNSEGL_LOG_DIR="$LOG" \
    INNSEGL_API_URL="$LEDGER" "$GUARD" check reset --hard HEAD ) >/dev/null 2>&1
[ $? -eq 0 ] || OPEN=1
# A command with an unbalanced quote, which cannot be tokenised.
drive_hook 'git reset --hard "unclosed'
[ "$STATUS" -eq 0 ] || OPEN=1
# Outside a repository altogether.
( cd "$WORK" && env INNSEGL_RUNS_DIR="$RUNS" INNSEGL_LOG_DIR="$LOG" \
    INNSEGL_API_URL="$LEDGER" "$GUARD" check reset --hard HEAD ) >/dev/null 2>&1
[ $? -eq 0 ] || OPEN=1
# A ledger that is not answering: the marker's own age decides, and this one is
# seconds old, so it is still refused.
API_OVERRIDE="http://127.0.0.1:1"
attempt reset --hard HEAD
API_OVERRIDE=""
[ "$STATUS" -eq 2 ] || OPEN=1
if [ "$OPEN" -eq 0 ] && [ "$(state)" = "$BEFORE" ]; then
  ok "OPS-093 every confusion allows, and a silent ledger falls back to the marker's age"
else
  bad "OPS-093 fail-open: something refused that should not have, or the tree moved"
fi

# AND AN OLD MARKER HOLDS NOTHING. The reaper's grace is the boundary: past it
# the ledger has expired the run whether or not anything can ask it.
API_OVERRIDE="http://127.0.0.1:1"
run_guard check reset --hard HEAD
WAS=$STATUS
API_OVERRIDE=""
( cd "$REPO" && env INNSEGL_RUNS_DIR="$RUNS" INNSEGL_LOG_DIR="$LOG" \
    INNSEGL_API_URL="http://127.0.0.1:1" INNSEGL_RUN_TTL_HOURS=0 \
    "$GUARD" check reset --hard HEAD ) >/dev/null 2>&1
NOW=$?
if [ "$WAS" -eq 2 ] && [ "$NOW" -eq 0 ]; then
  ok "OPS-093 with no ledger, a marker past the reaper's grace stops holding the tree"
else
  bad "OPS-093 ttl: fresh marker $WAS, expired marker $NOW"
fi

# --- OPS-102..104: the claim outlives the run that made it -------------------
#
# #291 (RM-183). #290 made a killed run leave the active list at the moment of
# the kill, which is right and was asked for. The guard above decides whose work
# to protect by asking the ledger who is LIVE, and a retired run is not live —
# so measured on one tree, one piece of work and one run:
#
#   before the retirement:  git clean -fd  ->  exit 2, refused
#   after  the retirement:  git clean -fd  ->  exit 0, allowed
#
# Before #290 that work was protected for twelve hours, but only as a side
# effect of the run being WRONGLY reported active. The side effect went and the
# protection went with it — and the work most at risk is exactly this work, the
# one kind of uncommitted agent work with nobody coming back for it.
#
# WHAT CARRIES THE CLAIM INSTEAD is the record #290 already writes when it
# retires: reason `run_killed`, naming the run, the tree, and each path it left
# uncommitted there together with the CONTENT it left in it.
#
# EVERY CASE BELOW CARRIES ITS OWN POSITIVE CONTROL, in the same case, against
# the same fixture, with one thing changed. A case that asserted only "it
# refused" would pass against a guard that refuses everything, which is the
# failure OPS-092 exists to catch; a case that asserted only "it allowed" would
# pass against the guard as it stands.

# killed <run-id> <agent-type> <task> <path...> — the record the kill path
# writes, in the shape it writes it: the run, the tree, and a claim naming each
# uncommitted path AND the content the kill left in it.
killed() {
  _krun="$1"; _ktype="$2"; _ktask="$3"; shift 3
  python3 -c '
import hashlib, json, os, sys
log, run, atype, task, top, reason, ctop = sys.argv[1:8]
claim = []
for p in sys.argv[8:]:
    data = open(os.path.join(top, p), "rb").read()
    claim.append({"path": p, "size": len(data),
                  "sha": hashlib.sha256(data).hexdigest()})
rec = {"record": "capture_not_made", "reason": reason, "run_id": run,
       "agent_type": atype, "task": task, "dir": top, "worktree": "",
       "claim_top": ctop or top, "claim": claim, "claim_n": len(claim),
       "dirty": len(claim), "wrote": len(claim), "staged": 0,
       "wrote_paths": [c["path"] for c in claim],
       "unaccounted": 0, "unaccounted_paths": [],
       "detail": "the run was killed", "time": "2026-09-20T00:00:00Z"}
with open(log, "a") as fh:
    fh.write(json.dumps(rec, sort_keys=True) + "\n")
' "$RUNS/uncaptured.jsonl" "$_krun" "$_ktype" "$_ktask" "$REPO_REAL" \
    "${KREASON:-run_killed}" "${KTOP:-}" "$@"
}

# retire <marker> <run-id> — the kill itself, as #290 performs it: the run
# leaves the active list and its marker goes with it.
retire() {
  ledger_says "$2" retired
  rm -f "$RUNS/$1"
}

# --- OPS-102: the claim survives the retirement -------------------------------
#
# THE UNTRACKED HALF, which is the half `clean -fd` reaches. The control runs
# FIRST and against the identical tree: retired, with no record, the file goes,
# which is the defect exactly as it was measured. Then the same tree, the same
# work and the same run, with the record — and it does not.
reset_fixture
register agent-k1 run-k1111111 general-purpose rm183
wrote run-k1111111 a "$REPO_REAL/new.txt"
printf 'AGENT WORK\n' > "$REPO/new.txt"
retire agent-k1 run-k1111111
attempt clean -fd
K_NORECORD=$STATUS
K_NORECORD_GONE=0; [ -f "$REPO/new.txt" ] || K_NORECORD_GONE=1
printf 'AGENT WORK\n' > "$REPO/new.txt"
killed run-k1111111 general-purpose rm183 new.txt
attempt clean -fd
if [ "$K_NORECORD" -eq 0 ] && [ "$K_NORECORD_GONE" -eq 1 ] \
   && [ "$STATUS" -eq 2 ] && [ -f "$REPO/new.txt" ]; then
  ok "OPS-102 a killed run's untracked work is refused over after it is retired, and without the record it is not"
else
  bad "OPS-102 killed untracked: without the record $K_NORECORD (gone=$K_NORECORD_GONE), with it $STATUS"
fi

# THE TRACKED HALF, which is the half `reset --hard` reaches, and the shape of
# the measured incident in #278.
reset_fixture
register agent-k2 run-k2222222 general-purpose rm183
wrote run-k2222222 a "$REPO_REAL/tracked.txt"
printf 'AGENT WORK\n' >> "$REPO/tracked.txt"
retire agent-k2 run-k2222222
BEFORE="$(state)"
killed run-k2222222 general-purpose rm183 tracked.txt
attempt reset --hard HEAD
K_TRACKED=$STATUS
K_TRACKED_KEPT=0; [ "$(state)" = "$BEFORE" ] && K_TRACKED_KEPT=1
rm -f "$RUNS/uncaptured.jsonl"
attempt reset --hard HEAD
if [ "$K_TRACKED" -eq 2 ] && [ "$K_TRACKED_KEPT" -eq 1 ] \
   && [ "$STATUS" -eq 0 ] && [ "$(dirty_now)" = "0" ]; then
  ok "OPS-102 and the killed run's tracked edit survives reset --hard, while the same tree without the record does not"
else
  bad "OPS-102 killed tracked: with the record $K_TRACKED (kept=$K_TRACKED_KEPT), without it $STATUS dirty $(dirty_now)"
fi

# AND IT DOES NOT NEED THE RUN'S BODY STORE. The claim is in the record because
# a killed run's tool-call bodies are not what outlives it: the log directory is
# the harness's to prune, and a claim that needed it would evaporate silently.
reset_fixture
register agent-k3 run-k3333333 prober rm183
printf 'AGENT WORK\n' > "$REPO/new.txt"
retire agent-k3 run-k3333333
killed run-k3333333 prober rm183 new.txt
rm -rf "${LOG:?}/run-k3333333"
attempt clean -fd
K_NOBODIES=$STATUS
rm -f "$RUNS/uncaptured.jsonl"
attempt clean -fd
if [ "$K_NOBODIES" -eq 2 ] && [ "$STATUS" -eq 0 ] && [ ! -f "$REPO/new.txt" ]; then
  ok "OPS-102 and the claim holds with the run's body store deleted, which is what makes it durable"
else
  bad "OPS-102 no body store: with the record $K_NOBODIES, without it $STATUS"
fi

# THE REFUSAL SAYS WHOSE WORK IT IS, THAT THE RUN WAS KILLED, AND BOTH WAYS OUT.
# A refusal that strands the work is worse than the loss it prevents, and a
# claim with no release is the wedge the issue forbids.
reset_fixture
register agent-k4 run-k4444444 prober rm183
printf 'AGENT WORK\n' > "$REPO/new.txt"
retire agent-k4 run-k4444444
killed run-k4444444 prober rm183 new.txt
attempt clean -fd
K_SAYS=0
grep -q 'run-k4444444' "$WORK/err" || K_SAYS=1
grep -q 'new.txt' "$WORK/err" || K_SAYS=1
grep -qi 'killed' "$WORK/err" || K_SAYS=1
grep -q 'innsegl-commit -r run-k4444444' "$WORK/err" || K_SAYS=1
grep -q 'INNSEGL_ALLOW_DESTRUCTIVE=1' "$WORK/err" || K_SAYS=1
if [ "$STATUS" -eq 2 ] && [ "$K_SAYS" -eq 0 ]; then
  ok "OPS-102 and the refusal names the run, the path, the kill, and both ways to release it"
else
  bad "OPS-102 refusal text (status $STATUS): $(cat "$WORK/err")"
fi

# --- OPS-103: the claim is spent when its own work is -------------------------
#
# THE PART THAT DECIDES WHETHER THIS IS SAFE TO SHIP. Liveness was chosen in
# #278 precisely because a killed subagent's marker is never removed (#260), so
# a claim keyed on the marker would refuse in that tree forever. A claim that
# outlives its run needs a release of its own, and every one below is asserted
# against a fixture that refused a line earlier.

# COMMITTED. The work is safe, so the claim is spent.
reset_fixture
register agent-k5 run-k5555555 prober rm183
printf 'AGENT WORK\n' > "$REPO/new.txt"
retire agent-k5 run-k5555555
killed run-k5555555 prober rm183 new.txt
attempt clean -fd
K_BEFORE=$STATUS
git -C "$REPO" add new.txt
git -C "$REPO" commit -q -m "the killed run work, kept"
attempt clean -fd
K_AFTER=$STATUS
# and the fixture goes back to the one commit it started with, so every case
# below begins where every case above it did.
git -C "$REPO" reset -q --hard HEAD~1
rm -f "$REPO/new.txt"
if [ "$K_BEFORE" -eq 2 ] && [ "$K_AFTER" -eq 0 ]; then
  ok "OPS-103 committing the claimed path spends the claim"
else
  bad "OPS-103 commit: before $K_BEFORE, after $K_AFTER: $(cat "$WORK/err")"
fi

# WRITTEN OVER. This is the case a claim keyed on a FILENAME cannot answer, and
# the reason the record carries the content: uncaptured.jsonl is append-only and
# never rotated, so a claim that resurrected every time somebody re-edited a
# path a long-dead run once wrote would wedge the tree by accumulation.
reset_fixture
register agent-k6 run-k6666666 prober rm183
printf 'AGENT WORK\n' > "$REPO/new.txt"
retire agent-k6 run-k6666666
killed run-k6666666 prober rm183 new.txt
attempt clean -fd
K_BEFORE=$STATUS
printf 'SOMEBODY ELSES WORK, LATER\n' > "$REPO/new.txt"
attempt clean -fd
if [ "$K_BEFORE" -eq 2 ] && [ "$STATUS" -eq 0 ]; then
  ok "OPS-103 and a path written over since the kill is no longer the killed run's work"
else
  bad "OPS-103 rewritten: before $K_BEFORE, after $STATUS: $(cat "$WORK/err")"
fi

# GONE. Nothing left to protect, so nothing is refused over.
reset_fixture
register agent-k7 run-k7777777 prober rm183
printf 'AGENT WORK\n' > "$REPO/new.txt"
retire agent-k7 run-k7777777
killed run-k7777777 prober rm183 new.txt
attempt clean -fd
K_BEFORE=$STATUS
rm -f "$REPO/new.txt"
attempt clean -fd
if [ "$K_BEFORE" -eq 2 ] && [ "$STATUS" -eq 0 ]; then
  ok "OPS-103 and a claim whose path is gone claims nothing"
else
  bad "OPS-103 removed: before $K_BEFORE, after $STATUS: $(cat "$WORK/err")"
fi

# DISCARDED DELIBERATELY, ONCE, THROUGH THE OVERRIDE THAT ALREADY EXISTS — and
# the tree is clear afterwards, because the release is the work going rather
# than the operator being remembered as having asked.
reset_fixture
register agent-k8 run-k8888888 prober rm183
printf 'AGENT WORK\n' > "$REPO/new.txt"
retire agent-k8 run-k8888888
killed run-k8888888 prober rm183 new.txt
attempt clean -fd
K_BEFORE=$STATUS
OVERRIDE=1
attempt clean -fd
K_OVER=$STATUS
K_SAID=0; grep -q 'INNSEGL_ALLOW_DESTRUCTIVE is set' "$WORK/err" && K_SAID=1
OVERRIDE=0
printf 'operator work\n' >> "$REPO/tracked.txt"
attempt reset --hard HEAD
if [ "$K_BEFORE" -eq 2 ] && [ "$K_OVER" -eq 0 ] && [ ! -f "$REPO/new.txt" ] \
   && [ "$K_SAID" -eq 1 ] && [ "$STATUS" -eq 0 ]; then
  ok "OPS-103 and the override discards it once, says so, and leaves no claim behind"
else
  bad "OPS-103 override: before $K_BEFORE, override $K_OVER (said=$K_SAID), after $STATUS, file $([ -f "$REPO/new.txt" ] && echo present || echo gone)"
fi

# AND A CLAIM CANNOT BLOCK A TREE WITH NOTHING IN IT TO PROTECT. The record
# stays on disk forever; what it claims has to be what is actually there.
reset_fixture
register agent-k9 run-k9999999 prober rm183
printf 'AGENT WORK\n' > "$REPO/new.txt"
retire agent-k9 run-k9999999
killed run-k9999999 prober rm183 new.txt
attempt clean -fd
K_BEFORE=$STATUS
rm -f "$REPO/new.txt"
attempt clean -fd
K_CLEAN=$STATUS
printf 'the operator, weeks later\n' >> "$REPO/tracked.txt"
attempt reset --hard HEAD
if [ "$K_BEFORE" -eq 2 ] && [ "$K_CLEAN" -eq 0 ] && [ "$STATUS" -eq 0 ] \
   && [ "$(dirty_now)" = "0" ]; then
  ok "OPS-103 and a spent claim does not come back for the next person's work in that tree"
else
  bad "OPS-103 spent claim: before $K_BEFORE, clean $K_CLEAN, later $STATUS dirty $(dirty_now)"
fi

# --- OPS-104: what a killed claim must NOT reach ------------------------------
#
# THE SCOPES STILL DO NOT LEAK. `clean -f` cannot destroy a tracked edit and
# `reset --hard` cannot destroy an untracked file. That distinction is what the
# measured incident turned on, and a claim that outlives its run is not a reason
# to flatten it.
reset_fixture
register agent-ka run-ka000000 prober rm183
printf 'AGENT WORK\n' >> "$REPO/tracked.txt"
retire agent-ka run-ka000000
killed run-ka000000 prober rm183 tracked.txt
attempt clean -fd
K_WRONG=$STATUS
attempt reset --hard HEAD
if [ "$K_WRONG" -eq 0 ] && [ "$STATUS" -eq 2 ]; then
  ok "OPS-104 a killed claim on a tracked edit does not refuse clean -f, and does refuse reset --hard"
else
  bad "OPS-104 tracked scope: clean $K_WRONG, reset $STATUS"
fi
reset_fixture
register agent-kb run-kb000000 prober rm183
printf 'AGENT WORK\n' > "$REPO/new.txt"
retire agent-kb run-kb000000
killed run-kb000000 prober rm183 new.txt
attempt reset --hard HEAD
K_WRONG=$STATUS
attempt clean -fd
if [ "$K_WRONG" -eq 0 ] && [ "$STATUS" -eq 2 ] && [ -f "$REPO/new.txt" ]; then
  ok "OPS-104 and a killed claim on an untracked file does not refuse reset --hard, and does refuse clean -f"
else
  bad "OPS-104 untracked scope: reset $K_WRONG, clean $STATUS"
fi

# A RECORD ABOUT ANOTHER TREE REACHES NOTHING HERE. One markers directory serves
# every session on the machine, and the runs in it belonging to another
# repository have real processes behind them.
reset_fixture
register agent-kc run-kc000000 prober rm183
printf 'AGENT WORK\n' > "$REPO/new.txt"
retire agent-kc run-kc000000
KTOP="$ELSEWHERE"
killed run-kc000000 prober rm183 new.txt
KTOP=""
attempt clean -fd
K_ELSE=$STATUS
printf 'AGENT WORK\n' > "$REPO/new.txt"
rm -f "$RUNS/uncaptured.jsonl"
killed run-kc000000 prober rm183 new.txt
attempt clean -fd
if [ "$K_ELSE" -eq 0 ] && [ "$STATUS" -eq 2 ]; then
  ok "OPS-104 and a record naming another tree claims nothing here, while the same record naming this one does"
else
  bad "OPS-104 other tree: elsewhere $K_ELSE, here $STATUS"
fi

# AND ONLY A KILL. A capture refused for any other reason is #277's record of a
# run that DID stop, and #291 is about the one kind of work with nobody coming
# back for it.
reset_fixture
register agent-kd run-kd000000 prober rm183
printf 'AGENT WORK\n' > "$REPO/new.txt"
retire agent-kd run-kd000000
KREASON=nothing_uncommitted
killed run-kd000000 prober rm183 new.txt
KREASON=""
attempt clean -fd
K_OTHER=$STATUS
printf 'AGENT WORK\n' > "$REPO/new.txt"
rm -f "$RUNS/uncaptured.jsonl"
killed run-kd000000 prober rm183 new.txt
attempt clean -fd
if [ "$K_OTHER" -eq 0 ] && [ "$STATUS" -eq 2 ]; then
  ok "OPS-104 and only a run_killed record claims anything; another reason is left to #277"
else
  bad "OPS-104 reason: other $K_OTHER, run_killed $STATUS"
fi

# A RECORD IN THE OLD SHAPE CLAIMS NOTHING, said plainly because it is a real
# gap rather than an oversight: a record written before the claim existed names
# no content, and a claim with no content has no release. The protection starts
# at the next kill.
reset_fixture
register agent-ke run-ke000000 prober rm183
printf 'AGENT WORK\n' > "$REPO/new.txt"
retire agent-ke run-ke000000
python3 -c '
import json, sys
rec = {"record": "capture_not_made", "reason": "run_killed",
       "run_id": "run-ke000000", "agent_type": "prober", "task": "rm183",
       "dir": sys.argv[2], "worktree": "", "dirty": 1, "wrote": 1,
       "wrote_paths": ["new.txt"], "staged": 0, "unaccounted": 0,
       "unaccounted_paths": [], "detail": "old shape",
       "time": "2026-09-20T00:00:00Z"}
with open(sys.argv[1], "a") as fh:
    fh.write(json.dumps(rec, sort_keys=True) + "\n")
' "$RUNS/uncaptured.jsonl" "$REPO_REAL"
attempt clean -fd
K_OLD=$STATUS
printf 'AGENT WORK\n' > "$REPO/new.txt"
rm -f "$RUNS/uncaptured.jsonl"
killed run-ke000000 prober rm183 new.txt
attempt clean -fd
if [ "$K_OLD" -eq 0 ] && [ "$STATUS" -eq 2 ]; then
  ok "OPS-104 and a record written before the claim existed claims nothing, while one written after does"
else
  bad "OPS-104 old shape: old $K_OLD, new $STATUS"
fi

# AND IT FAILS OPEN. A record file that is not JSON, not readable, or not there
# allows — this guard sits in front of git on a machine somebody works on.
reset_fixture
register agent-kf run-kf000000 prober rm183
printf 'AGENT WORK\n' > "$REPO/new.txt"
retire agent-kf run-kf000000
printf 'not json at all\n{"reason":\n' > "$RUNS/uncaptured.jsonl"
attempt clean -fd
K_JUNK=$STATUS
printf 'AGENT WORK\n' > "$REPO/new.txt"
printf 'not json at all\n' > "$RUNS/uncaptured.jsonl"
killed run-kf000000 prober rm183 new.txt
attempt clean -fd
if [ "$K_JUNK" -eq 0 ] && [ "$STATUS" -eq 2 ]; then
  ok "OPS-104 and an unparseable record allows, while a good line after a bad one is still read"
else
  bad "OPS-104 junk record: junk $K_JUNK, junk+good $STATUS"
fi

# --- OPS-094: the half that sees a human's terminal --------------------------
#
# The incident was an OPERATOR's command in their own shell, and no PreToolUse
# hook will ever see one. The only place that does is a `git` earlier on PATH,
# so this drives the guard EXACTLY as it would be installed — symlinked as
# `git`, with the real one behind it — and then reads the file back.
reset_fixture
register agent-15 run-ffff0000 general-purpose rm173
wrote run-ffff0000 a "$REPO_REAL/tracked.txt"
printf 'AGENT WORK\n' >> "$REPO/tracked.txt"
BEFORE="$(state)"

mkdir -p "$WORK/bin"
ln -sf "$GUARD" "$WORK/bin/git"
as_git() {
  ( cd "$REPO" && PATH="$WORK/bin:$PATH" env \
      INNSEGL_RUNS_DIR="$RUNS" INNSEGL_LOG_DIR="$LOG" \
      INNSEGL_API_URL="$LEDGER" INNSEGL_ALLOW_DESTRUCTIVE="${OVERRIDE:-0}" \
      git "$@" ) > "$WORK/out" 2> "$WORK/err"
  STATUS=$?
}

as_git reset --hard HEAD
if [ "$STATUS" -eq 2 ] && [ "$(state)" = "$BEFORE" ]; then
  ok "OPS-094 installed as git on PATH, a plain reset --hard is refused"
else
  bad "OPS-094 as git: status $STATUS, tree $(state)"
fi

# AND IT DOES NOT FIND ITSELF. A wrapper that resolved `git` to its own symlink
# would fork until the machine ran out of processes, and a symlink has a
# different name in every PATH entry it is installed in — so the comparison is
# on the resolved file, not the name.
as_git status --porcelain
if [ "$STATUS" -eq 0 ] && grep -q 'tracked.txt' "$WORK/out"; then
  ok "OPS-094 and a harmless git reaches the real one behind it"
else
  bad "OPS-094 wrap passthrough: status $STATUS, out '$(cat "$WORK/out")'"
fi

OVERRIDE=1
as_git reset --hard HEAD
OVERRIDE=0
if [ "$STATUS" -eq 0 ] && [ "$(dirty_now)" = "0" ]; then
  ok "OPS-094 and the override reaches the real git through the wrapper"
else
  bad "OPS-094 wrap override: status $STATUS, dirty $(dirty_now)"
fi

# THE SAME ANSWER IN EVERY SHELL. This file runs wherever git runs, which is
# every shell on the machine, and a guard that refuses under one and allows
# under another is worse than one that never refuses: the operator learns to
# trust it in the shell where it works.
reset_fixture
register agent-16 run-1111ffff general-purpose rm173
wrote run-1111ffff a "$REPO_REAL/tracked.txt"
printf 'AGENT WORK\n' >> "$REPO/tracked.txt"
SHELLS=""
SAME=1
FIRST=""
for _sh in sh bash zsh dash; do
  command -v "$_sh" >/dev/null 2>&1 || continue
  ( cd "$REPO" && env INNSEGL_RUNS_DIR="$RUNS" INNSEGL_LOG_DIR="$LOG" \
      INNSEGL_API_URL="$LEDGER" "$_sh" "$GUARD" check reset --hard HEAD \
  ) > "$WORK/out.$_sh" 2> "$WORK/err.$_sh"
  eval "RC_$_sh=\$?"
  eval "_rc=\$RC_$_sh"
  SHELLS="$SHELLS $_sh:$_rc"
  [ "$_rc" -eq 2 ] || SAME=0
  if [ -z "$FIRST" ]; then
    FIRST="$_sh"
  elif ! cmp -s "$WORK/err.$FIRST" "$WORK/err.$_sh"; then
    SAME=0
  fi
done
if [ "$SAME" -eq 1 ] && [ -n "$FIRST" ]; then
  ok "OPS-094 sh, bash, zsh and dash refuse it identically, byte for byte"
else
  bad "OPS-094 shells disagreed:$SHELLS"
fi

reset_fixture

echo
echo "guard-selftest: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
