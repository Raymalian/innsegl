#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# OPS-106..108 — the sweep for a death nobody observed, driven against a real
# repository and a real ledger reply.
#
# #288 (RM-180). MEASURED on the drill the issue is filed from: a subagent was
# registered, wrote two files through `Write`, and was killed with no stop
# event. The work, the marker, the tool-call bodies and the run in the ledger
# all survived — and NOTHING SAID THE WORK WAS THERE. `SubagentStop` does not
# fire on a kill, so no capture was attempted; no capture failed, so #277's
# record was never written. The drill produced zero new lines in the capture
# log. #290 closed the half a session OBSERVES. This drives the half nobody
# does.
#
# WHAT IS ASSERTED IS THE RECORD AND THE TREE, NOT A RETURN CODE. The sweep
# always exits 0 — it is called from a session's own start — so an assertion on
# its status would pass against a file that did nothing at all. Every case reads
# scripts/hooks/orphan-sweep.sh's output where it lands: a line in the capture
# log, and the tree read back afterwards.
#
# AND IT RUNS NOWHERE NEAR THE CHECKOUT IT SWEEPS. Every fixture is a fresh
# repository under mktemp with its own markers directory, body store, capture
# log and stub ledger. A self-test for something that reads other sessions'
# markers must never be able to reach the real ones.
#
# USAGE
#   scripts/hooks/orphan-sweep-selftest.sh
#
#   INNSEGL_SWEEP_SCRIPT   the sweep to drive. Point it at a script that does
#                          NOTHING to see the repository before this existed:
#                          every OPS-106 case goes red and every "it records
#                          nothing" control stays green. Point it at one that
#                          records EVERY marker and the halves swap over. No
#                          case may pass against either.
#
# It needs python3 and git. No Docker, no MCP, no network beyond loopback.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SWEEP="${INNSEGL_SWEEP_SCRIPT:-$ROOT/scripts/hooks/orphan-sweep.sh}"
GUARD="${INNSEGL_TREE_GUARD:-$ROOT/scripts/hooks/git-tree-guard.sh}"

pass=0
fail=0
ok()  { pass=$((pass + 1)); echo "  ok    $1"; }
bad() { fail=$((fail + 1)); echo "  FAIL  $1" >&2; }

[ -x "$SWEEP" ] || { echo "sweep-selftest: $SWEEP is missing or not executable" >&2; exit 4; }
for need in python3 git; do
  command -v "$need" >/dev/null 2>&1 || { echo "sweep-selftest: $need is required" >&2; exit 4; }
done

WORK="$(mktemp -d)"
trap 'if [ -n "${LEDGER_PID:-}" ]; then kill "$LEDGER_PID" 2>/dev/null; wait "$LEDGER_PID" 2>/dev/null; fi; rm -rf "$WORK"' EXIT

RUNS="$WORK/runs"
LOG="$WORK/log"
UNCAP="$RUNS/uncaptured.jsonl"
mkdir -p "$RUNS" "$LOG"

# ---------------------------------------------------------------------------
# A stub ledger. It answers the four states the real one holds, 404 for a run
# it has never heard of, and NOTHING AT ALL when it is asked to be down.
#
# IT ALSO RECORDS EVERY METHOD IT IS ASKED FOR, which is how OPS-108 asserts
# that the sweep retires nothing: a file that ended a run would have to say so
# to some server, and the only server here writes down what it was asked.
# ---------------------------------------------------------------------------
cat > "$WORK/ledger.py" <<'PY'
import http.server, json, os, socketserver

STATE = os.environ["LEDGER_STATE"]
SEEN = os.environ["LEDGER_SEEN"]

class H(http.server.BaseHTTPRequestHandler):
    def note(self):
        with open(SEEN, "a") as fh:
            fh.write(self.command + " " + self.path + "\n")

    def do_GET(self):
        self.note()
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

    def do_POST(self):
        self.note()
        self.send_response(200); self.end_headers()

    do_PUT = do_POST
    do_DELETE = do_POST
    do_PATCH = do_POST

    def log_message(self, *a):
        pass

class S(socketserver.TCPServer):
    allow_reuse_address = True

s = S(("127.0.0.1", 0), H)
print(s.server_address[1], flush=True)
s.serve_forever()
PY
LEDGER_STATE="$WORK/ledger.json"
LEDGER_SEEN="$WORK/ledger.seen"
echo '{}' > "$LEDGER_STATE"
: > "$LEDGER_SEEN"
LEDGER_STATE="$LEDGER_STATE" LEDGER_SEEN="$LEDGER_SEEN" \
  python3 "$WORK/ledger.py" > "$WORK/ledger.port" 2>"$WORK/ledger.err" &
LEDGER_PID=$!
for _ in $(seq 1 100); do
  LPORT="$(head -n 1 "$WORK/ledger.port" 2>/dev/null)"
  [ -n "$LPORT" ] && break
  sleep 0.1
done
[ -n "${LPORT:-}" ] || { echo "sweep-selftest: the stub ledger never reported a port" >&2; exit 4; }
LEDGER="http://127.0.0.1:$LPORT"

# ledger_says <run-id> <state|-> — `-` means it has never heard of the run.
ledger_says() {
  python3 -c '
import json, sys
p, run, state = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    d = json.loads(open(p).read())
except Exception:
    d = {}
if state == "-":
    d.pop(run, None)
else:
    d[run] = state
open(p, "w").write(json.dumps(d))
' "$LEDGER_STATE" "$1" "$2"
}

# ---------------------------------------------------------------------------
# The fixture repository.
# ---------------------------------------------------------------------------
REPO="$WORK/repo"
mkdir -p "$REPO" "$WORK/nohooks"
git -C "$REPO" init -q
git -C "$REPO" config user.email "sweep-selftest@example.test"
git -C "$REPO" config user.name "sweep-selftest"
git -C "$REPO" config commit.gpgsign false
git -C "$REPO" config core.hooksPath "$WORK/nohooks"
printf 'base\n' > "$REPO/tracked.txt"
printf 'other\n' > "$REPO/other.txt"
git -C "$REPO" add tracked.txt other.txt
git -C "$REPO" commit -q -m base
REPO_REAL="$(cd "$REPO" && pwd -P)"

ELSEWHERE="$WORK/elsewhere"
mkdir -p "$ELSEWHERE"
git -C "$ELSEWHERE" init -q
git -C "$ELSEWHERE" config user.email "sweep-selftest@example.test"
git -C "$ELSEWHERE" config user.name "sweep-selftest"
git -C "$ELSEWHERE" config commit.gpgsign false
git -C "$ELSEWHERE" config core.hooksPath "$WORK/nohooks"
printf 'x\n' > "$ELSEWHERE/x.txt"
git -C "$ELSEWHERE" add x.txt
git -C "$ELSEWHERE" commit -q -m base
ELSEWHERE_REAL="$(cd "$ELSEWHERE" && pwd -P)"

# register <marker> <run-id> <agent-type> <task> — the marker SubagentStart
# writes, in the shape it writes it, INCLUDING the owner the kill path reads.
# $MARK_DIR overrides the tree it names, for the case about another repository.
register() {
  printf '{"run_id":"%s","session_id":"%s","task":"%s","worktree":"","agent_type":"%s","dir":"%s","owner_session":"sess-dead"}\n' \
    "$2" "$1" "$4" "$3" "${MARK_DIR:-$REPO_REAL}" > "$RUNS/$1"
  mkdir -p "$LOG/$2"
  ledger_says "$2" active
}

# wrote <run-id> <name> <path> — one tool-call body recording a file write, in
# the shape the MCP stores it.
wrote() {
  printf '{"tool_name":"Write","cwd":"%s","tool_input":{"file_path":"%s"}}' \
    "$REPO_REAL" "$3" > "$LOG/$1/$2.json"
}

# sweep_now — the sweep, with every path pinned at the fixture. It is run from
# OUTSIDE the repository and handed the directory, which is how a SessionStart
# in a subdirectory would reach it.
sweep_now() {
  ( cd "$WORK" && env \
      INNSEGL_RUNS_DIR="$RUNS" \
      INNSEGL_LOG_DIR="$LOG" \
      INNSEGL_API_URL="${API_OVERRIDE:-$LEDGER}" \
      INNSEGL_UNCAPTURED_LOG="$UNCAP" \
      INNSEGL_ORPHAN_SWEEP="${SWEEP_OFF:-1}" \
      "$SWEEP" sweep "${SWEEP_DIR:-$REPO_REAL}" ) > "$WORK/out" 2> "$WORK/err"
  STATUS=$?
}

# records — how many lines the capture log holds.
records() { if [ -f "$UNCAP" ]; then grep -c . "$UNCAP" 2>/dev/null; else echo 0; fi; }

# rec_field <field> [<index>] — one field of the nth record, default the last.
rec_field() {
  python3 -c '
import json, sys
try:
    lines = [l for l in open(sys.argv[1]) if l.strip()]
except OSError:
    lines = []
want, idx = sys.argv[2], int(sys.argv[3])
if not lines:
    print(""); raise SystemExit(0)
try:
    rec = json.loads(lines[idx])
except Exception:
    print(""); raise SystemExit(0)
v = rec.get(want)
if isinstance(v, list):
    print(" ".join(json.dumps(x, sort_keys=True) if isinstance(x, dict) else str(x) for x in v))
else:
    print("" if v is None else str(v))
' "$UNCAP" "$1" "${2:--1}"
}

# tree_state — the whole working tree, as one comparable string.
tree_state() {
  ( cd "$REPO" && for f in $(git ls-files) $(git ls-files --others --exclude-standard); do
      printf '%s=%s;' "$f" "$(cat "$f" 2>/dev/null | tr -d '\n')"
    done )
}
head_now()   { git -C "$REPO" rev-parse HEAD; }
staged_now() { git -C "$REPO" diff --cached --name-only | tr '\n' ' '; }

# reset_fixture — a clean tree, no markers, no bodies, no records, no ledger.
reset_fixture() {
  git -C "$REPO" checkout -q --force main 2>/dev/null || git -C "$REPO" checkout -q --force master
  git -C "$REPO" reset -q --hard HEAD
  git -C "$REPO" clean -qfd
  rm -f "$RUNS"/* 2>/dev/null
  rm -rf "${LOG:?}"/* 2>/dev/null
  rm -f "$UNCAP" 2>/dev/null
  echo '{}' > "$LEDGER_STATE"
  : > "$LEDGER_SEEN"
}

# orphan <marker> <run-id> <state> — the whole of the case, in one line: a run
# registered here, one untracked file it wrote still sitting in the tree, and
# the ledger reporting it in the given state with its marker never removed.
orphan() {
  register "$1" "$2" general-purpose rm180
  wrote "$2" a "$REPO_REAL/left.txt"
  printf 'AGENT WORK\n' > "$REPO/left.txt"
  ledger_says "$2" "$3"
}

echo "sweep-selftest: the unobserved-death sweep, driven against a real tree"

# --- OPS-106: the drill ------------------------------------------------------
#
# A run whose stop nobody ran, whose marker is therefore still on disk, which
# the ledger no longer reports active, and whose work is still in the tree.
# Nothing is trying to delete anything and no session is alive to notice.
#
# THE CONTROL RUNS FIRST AND AGAINST THE IDENTICAL FIXTURE: the same marker, the
# same bodies, the same two files, and the ledger saying `active`. That is a run
# that may still be working, and it must produce nothing — which is also what a
# sweep keyed on the MARKER rather than on the ledger would get wrong, and the
# marker is never removed for a killed subagent (#260).
reset_fixture
register agent-o1 run-o1111111 general-purpose rm180
wrote run-o1111111 a "$REPO_REAL/tracked.txt"
wrote run-o1111111 b "$REPO_REAL/new.txt"
printf 'AGENT WORK\n' >> "$REPO/tracked.txt"
printf 'AGENT WORK\n' > "$REPO/new.txt"
BEFORE="$(tree_state)"
BEFORE_HEAD="$(head_now)"
sweep_now
O_LIVE="$(records)"
ledger_says run-o1111111 retired
sweep_now
O_GONE="$(records)"
O_SAYS=0
[ "$(rec_field reason)" = "run_unobserved" ] || O_SAYS=1
[ "$(rec_field run_id)" = "run-o1111111" ] || O_SAYS=1
[ "$(rec_field claim_top)" = "$REPO_REAL" ] || O_SAYS=1
[ "$(rec_field claim_n)" = "2" ] || O_SAYS=1
[ "$(rec_field dir)" = "$REPO_REAL" ] || O_SAYS=1
[ "$(rec_field agent_type)" = "general-purpose" ] || O_SAYS=1
[ "$(rec_field task)" = "rm180" ] || O_SAYS=1
case "$(rec_field claim)" in *tracked.txt*) : ;; *) O_SAYS=1 ;; esac
case "$(rec_field claim)" in *new.txt*) : ;; *) O_SAYS=1 ;; esac
if [ "$O_LIVE" = "0" ] && [ "$O_GONE" = "1" ] && [ "$O_SAYS" -eq 0 ]; then
  ok "OPS-106 a run the ledger no longer calls active, with its marker still here and its work in the tree, is recorded — and the same fixture called active is not"
else
  bad "OPS-106 drill: active $O_LIVE, gone $O_GONE, fields $O_SAYS ($(cat "$UNCAP" 2>/dev/null))"
fi

# AND THE RECORD NAMES THE PATHS WITH WHAT IS IN THEM, which is what makes it
# actionable rather than a note that something happened. Same meaning as a
# `run_killed` claim (#291), so one reader reads the whole log.
O_CLAIM=0
python3 -c '
import hashlib, json, os, sys
rec = json.loads([l for l in open(sys.argv[1]) if l.strip()][-1])
top = rec["claim_top"]
for e in rec["claim"]:
    data = open(os.path.join(top, e["path"]), "rb").read()
    assert e["sha"] == hashlib.sha256(data).hexdigest(), e["path"]
    assert e["size"] == len(data), e["path"]
' "$UNCAP" 2>/dev/null || O_CLAIM=1
if [ "$O_CLAIM" -eq 0 ]; then
  ok "OPS-106 and every claimed path carries the digest and size of the bytes actually in it"
else
  bad "OPS-106 claim digests do not match the tree"
fi

# AND THE STDERR SAYS IT WHERE A PERSON IS LOOKING, with the run named. It
# must NOT offer to sign the work under that run. Every run this records is one
# the ledger no longer calls active, and the signer refuses a retired run
# (RUN_ALREADY_RETIRED, IP §6.2) -- measured on the first real use: the command
# this report used to print was refused. Who signs work a dead run left is #269,
# and a hint is not where that gets decided.
O_SAID=0
grep -q 'run-o1111111' "$WORK/err" || O_SAID=1
grep -q 'tracked.txt' "$WORK/err" || O_SAID=1
grep -q 'innsegl-commit -r' "$WORK/err" && O_SAID=1
grep -q 'may not sign' "$WORK/err" || O_SAID=1
grep -q '#269' "$WORK/err" || O_SAID=1
grep -q '#288' "$WORK/err" || O_SAID=1
if [ "$O_SAID" -eq 0 ]; then
  ok "OPS-106 and it says so on stderr, naming the run and a path, and that the run may not sign it"
else
  bad "OPS-106 stderr: $(cat "$WORK/err")"
fi

# THE THREE WORDS THAT MEAN GONE, AND THE ONE THAT DOES NOT. The vocabulary is
# the ledger's own closed set (internal/ledger/runstate.go) and this file reads
# it rather than "anything but active": a word it does not know is not a word it
# may call death.
O_STATES=""
O_WORDS=0
for _state in retired lapsed abandoned active nonsense; do
  reset_fixture
  orphan agent-o2 run-o2222222 "$_state"
  sweep_now
  _n="$(records)"
  O_STATES="$O_STATES $_state:$_n"
  case "$_state" in
    retired|lapsed|abandoned) [ "$_n" = "1" ] || O_WORDS=1 ;;
    *)                        [ "$_n" = "0" ] || O_WORDS=1 ;;
  esac
done
if [ "$O_WORDS" -eq 0 ]; then
  ok "OPS-106 and retired, lapsed and abandoned each record while active and an unknown word record nothing"
else
  bad "OPS-106 states:$O_STATES"
fi

# --- OPS-107: what must produce nothing --------------------------------------
#
# THE HALF THAT DECIDES WHETHER THIS IS USABLE. A sweep that announced something
# at every session start is a sweep an operator stops reading, and then the work
# is as unfindable as it was before. Every case below carries its own positive
# control against the same fixture with ONE thing changed, so "it recorded
# nothing" cannot pass against a file that does nothing at all.

# A CLEAN TREE. Nothing is sitting there, so nothing is orphaned.
reset_fixture
register agent-o3 run-o3333333 general-purpose rm180
wrote run-o3333333 a "$REPO_REAL/left.txt"
ledger_says run-o3333333 retired
sweep_now
O_CLEAN="$(records)"
printf 'AGENT WORK\n' > "$REPO/left.txt"
sweep_now
if [ "$O_CLEAN" = "0" ] && [ "$(records)" = "1" ]; then
  ok "OPS-107 a clean tree records nothing, and the same tree with the work in it records"
else
  bad "OPS-107 clean tree: clean $O_CLEAN, dirty $(records)"
fi

# WORK THE RUN ALREADY COMMITTED ITSELF. It is not uncommitted, so it is not at
# risk and there is nothing to say.
reset_fixture
register agent-o4 run-o4444444 general-purpose rm180
wrote run-o4444444 a "$REPO_REAL/left.txt"
printf 'AGENT WORK\n' > "$REPO/left.txt"
ledger_says run-o4444444 retired
git -C "$REPO" add left.txt
git -C "$REPO" commit -q -m "the run committed its own work"
sweep_now
O_COMMITTED="$(records)"
git -C "$REPO" reset -q --hard HEAD~1
printf 'AGENT WORK\n' > "$REPO/left.txt"
sweep_now
if [ "$O_COMMITTED" = "0" ] && [ "$(records)" = "1" ]; then
  ok "OPS-107 work the run committed itself records nothing, and the same work uncommitted records"
else
  bad "OPS-107 committed: committed $O_COMMITTED, uncommitted $(records)"
fi

# A DIRTY PATH THE RUN NEVER WROTE. It belongs to whoever wrote it, and a sweep
# claiming it would be attributing somebody else's work to a dead agent.
reset_fixture
register agent-o5 run-o5555555 general-purpose rm180
wrote run-o5555555 a "$REPO_REAL/left.txt"
printf 'not the agents\n' >> "$REPO/other.txt"
ledger_says run-o5555555 retired
sweep_now
O_NOTMINE="$(records)"
printf 'AGENT WORK\n' > "$REPO/left.txt"
sweep_now
if [ "$O_NOTMINE" = "0" ] && [ "$(records)" = "1" ]; then
  ok "OPS-107 a dirty path the run never wrote records nothing, while one it did records"
else
  bad "OPS-107 unowned path: unowned $O_NOTMINE, owned $(records)"
fi

# NO MARKER AT ALL. A run whose stop DID run removed its own marker, so there is
# nothing unobserved about it.
reset_fixture
printf 'AGENT WORK\n' > "$REPO/left.txt"
mkdir -p "$LOG/run-o6666666"
printf '{"tool_name":"Write","cwd":"%s","tool_input":{"file_path":"%s"}}' \
  "$REPO_REAL" "$REPO_REAL/left.txt" > "$LOG/run-o6666666/a.json"
ledger_says run-o6666666 retired
sweep_now
O_NOMARK="$(records)"
printf '{"run_id":"run-o6666666","session_id":"agent-o6","task":"rm180","worktree":"","agent_type":"general-purpose","dir":"%s","owner_session":"sess-dead"}\n' \
  "$REPO_REAL" > "$RUNS/agent-o6"
sweep_now
if [ "$O_NOMARK" = "0" ] && [ "$(records)" = "1" ]; then
  ok "OPS-107 a run whose stop removed its marker records nothing, and the same run with the marker left behind records"
else
  bad "OPS-107 marker: absent $O_NOMARK, present $(records)"
fi

# THE OPERATOR'S OWN SESSION IS NOT AN AGENT. Its uncommitted work is the
# operator's own, and a line about it at every session start is noise on the one
# surface that also carries things worth reading.
reset_fixture
register session-dead run-o7777777 session rm180
wrote run-o7777777 a "$REPO_REAL/left.txt"
printf 'MY OWN WORK\n' > "$REPO/left.txt"
ledger_says run-o7777777 retired
sweep_now
O_SESSION="$(records)"
mv "$RUNS/session-dead" "$RUNS/agent-o7"
sweep_now
if [ "$O_SESSION" = "0" ] && [ "$(records)" = "1" ]; then
  ok "OPS-107 the operator's own session marker records nothing, while the same marker under an agent name records"
else
  bad "OPS-107 session marker: session $O_SESSION, agent $(records)"
fi

# A MARKER NAMING ANOTHER TREE REACHES NOTHING HERE. One markers directory
# serves every session on the machine, and the runs in it belonging to another
# repository have live processes behind them right now.
reset_fixture
MARK_DIR="$ELSEWHERE_REAL"
register agent-o8 run-o8888888 general-purpose rm180
MARK_DIR=""
wrote run-o8888888 a "$REPO_REAL/left.txt"
printf 'AGENT WORK\n' > "$REPO/left.txt"
ledger_says run-o8888888 retired
sweep_now
O_ELSE="$(records)"
O_ELSE_SEEN=0
grep -q 'run-o8888888' "$LEDGER_SEEN" && O_ELSE_SEEN=1
register agent-o8 run-o8888888 general-purpose rm180
wrote run-o8888888 a "$REPO_REAL/left.txt"
ledger_says run-o8888888 retired
sweep_now
if [ "$O_ELSE" = "0" ] && [ "$O_ELSE_SEEN" -eq 0 ] && [ "$(records)" = "1" ]; then
  ok "OPS-107 a marker naming another repository is never even asked about, while the same marker naming this one records"
else
  bad "OPS-107 other tree: elsewhere $O_ELSE (asked=$O_ELSE_SEEN), here $(records)"
fi

# A LEDGER THAT DOES NOT ANSWER SAYS NOTHING AT ALL. This is the opposite of
# what the guard does, deliberately: the guard has a command in flight and must
# answer, this has nothing to lose by waiting, and a sweep that cannot ask has
# not found nothing — it has not looked.
reset_fixture
orphan agent-o9 run-o9999999 retired
API_OVERRIDE="http://127.0.0.1:1"
sweep_now
O_DEAF="$(records)"
O_DEAF_SILENT=0; [ -s "$WORK/err" ] || O_DEAF_SILENT=1
API_OVERRIDE=""
sweep_now
if [ "$O_DEAF" = "0" ] && [ "$O_DEAF_SILENT" -eq 1 ] && [ "$(records)" = "1" ]; then
  ok "OPS-107 a ledger that does not answer records nothing and says nothing, while the same fixture with it up records"
else
  bad "OPS-107 deaf ledger: down $O_DEAF (silent=$O_DEAF_SILENT), up $(records)"
fi

# A RUN THE LEDGER HAS NEVER HEARD OF is not a run the ledger says is gone. The
# ledger is UP and answering, so the sweep goes on asking about the rest.
reset_fixture
orphan agent-oa run-oa000000 -
sweep_now
O_UNKNOWN="$(records)"
ledger_says run-oa000000 retired
sweep_now
if [ "$O_UNKNOWN" = "0" ] && [ "$(records)" = "1" ]; then
  ok "OPS-107 a run the ledger has never heard of records nothing, while the same run it calls retired records"
else
  bad "OPS-107 unknown run: unknown $O_UNKNOWN, retired $(records)"
fi

# NO BODY STORE, NO RECORD. The record's whole value is the paths; one naming
# none would point at a dirty tree that belongs to whoever wrote it. Said as a
# gap rather than hidden: a body store pruned by the 90-day retention takes the
# protection with it.
reset_fixture
orphan agent-ob run-ob000000 retired
rm -rf "${LOG:?}/run-ob000000"
sweep_now
O_NOBODIES="$(records)"
mkdir -p "$LOG/run-ob000000"
wrote run-ob000000 a "$REPO_REAL/left.txt"
sweep_now
if [ "$O_NOBODIES" = "0" ] && [ "$(records)" = "1" ]; then
  ok "OPS-107 a run whose tool-call bodies are gone records nothing, and the same run with them records"
else
  bad "OPS-107 no bodies: gone $O_NOBODIES, present $(records)"
fi

# ONE RECORD PER RUN, EVER. This log is append-only and never rotated, and the
# sweep runs at every session start: a line each time would turn the record into
# a transcript of how often somebody opened a terminal.
reset_fixture
orphan agent-oc run-oc000000 retired
sweep_now
sweep_now
sweep_now
O_ONCE="$(records)"
register agent-od run-od000000 general-purpose rm180
wrote run-od000000 a "$REPO_REAL/second.txt"
printf 'MORE WORK\n' > "$REPO/second.txt"
ledger_says run-od000000 retired
sweep_now
if [ "$O_ONCE" = "1" ] && [ "$(records)" = "2" ]; then
  ok "OPS-107 three sweeps record one run once, and a second orphan still gets its own line"
else
  bad "OPS-107 idempotence: three sweeps $O_ONCE, second orphan $(records)"
fi

# A DEATH THAT WAS OBSERVED IS ALREADY RECORDED. #290 writes `run_killed` at the
# moment of the kill; a second line about it here would be a second source of
# truth for one fact.
reset_fixture
orphan agent-oe run-oe000000 retired
python3 -c '
import json, sys
rec = {"record": "capture_not_made", "reason": "run_killed",
       "run_id": "run-oe000000", "dir": sys.argv[2], "claim_top": sys.argv[2],
       "claim": [], "claim_n": 0, "time": "2026-09-20T00:00:00Z"}
with open(sys.argv[1], "a") as fh:
    fh.write(json.dumps(rec, sort_keys=True) + "\n")
' "$UNCAP" "$REPO_REAL"
sweep_now
O_KILLED="$(records)"
rm -f "$UNCAP"
sweep_now
if [ "$O_KILLED" = "1" ] && [ "$(records)" = "1" ] \
   && [ "$(rec_field reason)" = "run_unobserved" ]; then
  ok "OPS-107 a run whose kill was already recorded gets no second record, while the same run with no record does"
else
  bad "OPS-107 observed death: with $O_KILLED, without $(records) reason $(rec_field reason)"
fi

# --- OPS-108: what the sweep must never do -----------------------------------
#
# THE ISSUE IS EXPLICIT: it records, and it does not retire and does not sign.
# Committing another run's work under an identity that did not do it is #269's
# open question and must not be answered by accident.

reset_fixture
orphan agent-p1 run-p1000000 retired
P_BEFORE="$(tree_state)"
P_HEAD="$(head_now)"
sweep_now
P_RECORDED="$(records)"
P_METHODS="$(awk '$1 != "GET"' "$LEDGER_SEEN" 2>/dev/null | wc -l | tr -d ' ')"
P_STATE="$(python3 -c 'import json,sys; print(json.loads(open(sys.argv[1]).read()).get("run-p1000000",""))' "$LEDGER_STATE")"
P_MARKER=0; [ -f "$RUNS/agent-p1" ] && P_MARKER=1
if [ "$P_RECORDED" = "1" ] && [ "$P_METHODS" = "0" ] && [ "$P_STATE" = "retired" ] \
   && [ "$P_MARKER" -eq 1 ] && [ "$(tree_state)" = "$P_BEFORE" ] \
   && [ "$(head_now)" = "$P_HEAD" ] && [ -z "$(staged_now)" ] && [ "$STATUS" -eq 0 ]; then
  ok "OPS-108 it records, and nothing else: no write ever reaches the ledger, no marker goes, nothing is staged, HEAD does not move and the tree is byte-identical"
else
  bad "OPS-108 side effects: recorded $P_RECORDED, non-GET $P_METHODS, state $P_STATE, marker $P_MARKER, staged '$(staged_now)', head $([ "$(head_now)" = "$P_HEAD" ] && echo same || echo MOVED), status $STATUS"
fi

# AND ITS RECORD IS NOT A CLAIM THE GUARD WEIGHS. #291 refuses over the claim in
# a `run_killed` record and reads no other reason, so nothing in any tree starts
# refusing because a sweep ran. The control is the SAME record under the reason
# the guard does weigh, against the same tree in the same second.
guard_says() {
  ( cd "$REPO" && env \
      INNSEGL_RUNS_DIR="$RUNS" INNSEGL_LOG_DIR="$LOG" \
      INNSEGL_API_URL="$LEDGER" INNSEGL_UNCAPTURED_LOG="$UNCAP" \
      INNSEGL_ALLOW_DESTRUCTIVE=0 \
      "$GUARD" check -- clean -fd ) >/dev/null 2>&1
  GUARD_STATUS=$?
}
guard_says
P_GUARD=$GUARD_STATUS
python3 -c '
import json, sys
lines = [l for l in open(sys.argv[1]) if l.strip()]
rec = json.loads(lines[-1]); rec["reason"] = "run_killed"
lines[-1] = json.dumps(rec, sort_keys=True) + "\n"
open(sys.argv[1], "w").writelines(lines)
' "$UNCAP"
guard_says
if [ "$P_GUARD" -eq 0 ] && [ "$GUARD_STATUS" -eq 2 ]; then
  ok "OPS-108 and a run_unobserved record makes no tree refuse, while the identical record read as run_killed does"
else
  bad "OPS-108 guard: unobserved $P_GUARD, killed $GUARD_STATUS"
fi

# IT EXITS 0 WITH EVERYTHING BROKEN. It is called from a session's own start,
# and a sweep that could fail one is a sweep somebody turns off.
reset_fixture
P_OPEN=0
P_QUIET=0
try_broken() {
  sweep_now
  [ "$STATUS" -eq 0 ] || P_OPEN=1
  [ -s "$WORK/err" ] && P_QUIET=1
}
# A runs directory that is not there at all.
_realruns="$RUNS"
RUNS="$WORK/nonexistent"
try_broken
RUNS="$_realruns"
# A markers directory of junk.
printf 'not json at all\n' > "$RUNS/agent-junk"
printf '{"run_id":' > "$RUNS/agent-half"
mkdir -p "$RUNS/agent-adirectory"
try_broken
rm -rf "$RUNS/agent-adirectory"
# A capture log that is not JSON, with a real orphan behind it.
orphan agent-p2 run-p2000000 retired
printf 'not json at all\n{"reason":\n' > "$UNCAP"
sweep_now
P_JUNKLOG=$STATUS
P_JUNKREC="$(records)"
# A directory that is not a repository, and one that is not there.
SWEEP_DIR="$WORK"
try_broken
SWEEP_DIR="$WORK/no-such-directory"
try_broken
SWEEP_DIR=""
if [ "$P_OPEN" -eq 0 ] && [ "$P_QUIET" -eq 0 ] && [ "$P_JUNKLOG" -eq 0 ] \
   && [ "$P_JUNKREC" = "3" ]; then
  ok "OPS-108 every broken input exits 0 in silence, and one unreadable line in the log does not stop a good record being written after it"
else
  bad "OPS-108 fail-quiet: status $P_OPEN, noise $P_QUIET, junk log $P_JUNKLOG, records $P_JUNKREC"
fi

# THE OFF SWITCH, because a control an operator cannot turn off is a control
# they route around instead.
reset_fixture
orphan agent-p3 run-p3000000 retired
SWEEP_OFF=0
sweep_now
SWEEP_OFF=""
P_OFF="$(records)"
sweep_now
if [ "$P_OFF" = "0" ] && [ "$(records)" = "1" ]; then
  ok "OPS-108 and INNSEGL_ORPHAN_SWEEP=0 records nothing, while the same fixture with it on records"
else
  bad "OPS-108 off switch: off $P_OFF, on $(records)"
fi

# THE SAME ANSWER IN EVERY SHELL. This file is reachable from a hook, a cron
# entry and a terminal, and a sweep that recorded under one shell and not under
# another would be a record whose absence means nothing.
reset_fixture
orphan agent-p4 run-p4000000 retired
P_SHELLS=""
P_SAME=1
P_FIRST=""
for _sh in sh bash zsh dash; do
  command -v "$_sh" >/dev/null 2>&1 || continue
  rm -f "$UNCAP"
  ( cd "$WORK" && env INNSEGL_RUNS_DIR="$RUNS" INNSEGL_LOG_DIR="$LOG" \
      INNSEGL_API_URL="$LEDGER" INNSEGL_UNCAPTURED_LOG="$UNCAP" \
      "$_sh" "$SWEEP" sweep "$REPO_REAL" ) > "$WORK/out.$_sh" 2> "$WORK/err.$_sh"
  P_SHELLS="$P_SHELLS $_sh:$(records)"
  [ "$(records)" = "1" ] || P_SAME=0
  python3 -c '
import json, sys
rec = json.loads([l for l in open(sys.argv[1]) if l.strip()][-1])
rec.pop("time", None)
open(sys.argv[2], "w").write(json.dumps(rec, sort_keys=True))
' "$UNCAP" "$WORK/rec.$_sh"
  if [ -z "$P_FIRST" ]; then
    P_FIRST="$_sh"
  else
    cmp -s "$WORK/err.$P_FIRST" "$WORK/err.$_sh" || P_SAME=0
    cmp -s "$WORK/rec.$P_FIRST" "$WORK/rec.$_sh" || P_SAME=0
  fi
done
if [ "$P_SAME" -eq 1 ] && [ -n "$P_FIRST" ]; then
  ok "OPS-108 sh, bash, zsh and dash write the same record and the same report, byte for byte"
else
  bad "OPS-108 shells disagreed:$P_SHELLS"
fi

reset_fixture

echo
echo "sweep-selftest: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
