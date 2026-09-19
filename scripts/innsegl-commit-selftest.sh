#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# OPS-037 and OPS-038 — the by-tree pointer, driven through every state its run
# can be in.
#
# RM-134 (#213). `scripts/innsegl-commit.sh` resolves the run for a tree from a
# pointer the harness wrote, and until now it handed whatever it found to
# `sign_commit`. When the run named there had been retired the tool refused —
# correctly, IP §6.2 makes retirement immediate — and the script had no answer
# to the refusal. The tree could not be committed to again, by anyone, until
# somebody deleted the pointer by hand. Measured: three separate callers hit it
# in one day and all three invented the same workaround.
#
# THE HARD PART IS NOT THE DETECTION, IT IS THE SUCCESSOR. A run id is a pure
# function of (agent_type, task, idempotency_key) — see registerAgentRunID — so
# a caller that re-derives from the same three values gets the SAME retired id
# back, `register_agent` replays its recorded reply, and nothing has moved.
# Deleting the pointer does not help either: the next derivation names the same
# dead run. So the successor has to differ in something the derivation sees,
# and case 1 is what holds that: the key it registers under NAMES the run it
# succeeds, which no key that produced the predecessor could have done.
#
# WHAT IS ASSERTED is which tool was called with which run_id — not that the
# script exited 0. A script that registered a successor and then signed under
# the retired run would pass every exit-status check and fix nothing.
#
# USAGE
#   scripts/innsegl-commit-selftest.sh
#
# It needs python3, curl, git and shasum. It needs no Docker, no MCP, no SPIRE
# and no network beyond loopback. OPS-039 is the other half of this and cannot
# be: only a genuinely retired run against a live deployment proves the fix.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SIGNER="$ROOT/scripts/innsegl-commit.sh"

pass=0
fail=0
ok()  { pass=$((pass + 1)); echo "  ok    $1"; }
bad() { fail=$((fail + 1)); echo "  FAIL  $1" >&2; }

[ -x "$SIGNER" ] || { echo "commit-selftest: $SIGNER is missing or not executable" >&2; exit 4; }
for need in python3 curl git shasum; do
  command -v "$need" >/dev/null 2>&1 || { echo "commit-selftest: $need is required" >&2; exit 4; }
done

WORK="$(mktemp -d)"
cleanup() {
  for pid in ${STUB_PID:-} ${API_PID:-}; do
    kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
  done
  rm -rf "$WORK"
}
trap cleanup EXIT

CALLS="$WORK/calls"          # one line per tools/call: <tool> <arguments json>
SCRIPTED="$WORK/scripted"    # <tool> <ok|err> <json>, the stub's answer
RUNSTATES="$WORK/runstates"  # <run_id> <status>, what the read API answers
: > "$CALLS"
: > "$SCRIPTED"
: > "$RUNSTATES"

# ---------------------------------------------------------------------------
# The stub MCP is scripts/hooks/stub-mcp.py, the one the two shim self-tests
# already drive. A third copy of that transport would be a third thing that can
# disagree about what an SSE frame looks like.
# ---------------------------------------------------------------------------
STUB="$ROOT/scripts/hooks/stub-mcp.py"
[ -f "$STUB" ] || { echo "commit-selftest: $STUB is missing" >&2; exit 4; }

# EMPTY UNTIL THE CREDENTIAL SECTION FILLS IT, so every case above that one
# runs against a listener demanding nothing. That is single-listener mode, and
# OPS-073 is the assertion that it did not change (#266).
CREDFILE="$WORK/required"
AUTHLOG="$WORK/authlog"
: > "$CREDFILE"
: > "$AUTHLOG"

STUB_CALLS="$CALLS" STUB_SCRIPTED="$SCRIPTED" \
STUB_CREDENTIAL="$CREDFILE" STUB_AUTH_LOG="$AUTHLOG" \
python3 "$STUB" > "$WORK/port" 2>"$WORK/stub.err" &
STUB_PID=$!
for _ in $(seq 1 100); do
  PORT="$(head -n 1 "$WORK/port" 2>/dev/null)"
  [ -n "$PORT" ] && break
  sleep 0.1
done
[ -n "${PORT:-}" ] || { echo "commit-selftest: the stub never reported a port" >&2; cat "$WORK/stub.err" >&2; exit 4; }
MCP_URL="http://127.0.0.1:$PORT/"

# ---------------------------------------------------------------------------
# The stub READ API — `GET /api/v1/runs/{run_id}`, which is where the signer
# learns whether the pointer's run is still alive.
#
# It is a stub of the shipped surface and not a second definition of it: the
# three answers below are internal/api's own — a 200 carrying `status`, a 404
# for a run this ledger never held, and nothing else. A run absent from
# $RUNSTATES is a 404, because that is exactly what the shipped API does with
# a run id it has no row for.
# ---------------------------------------------------------------------------
cat > "$WORK/stub-api.py" <<'PY'
import json, os, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

STATES = os.environ["STUB_RUNSTATES"]


def status_of(run_id):
    with open(STATES, encoding="utf-8") as fh:
        for line in fh:
            name, _, state = line.rstrip("\n").partition(" ")
            if name == run_id:
                return state
    return None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        prefix = "/api/v1/runs/"
        if not self.path.startswith(prefix):
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        run_id = self.path[len(prefix):]
        state = status_of(run_id)
        if state is None:
            body = json.dumps({"error": {"code": "not_found",
                                         "message": "no run %r in this ledger" % run_id}}).encode()
            code = 404
        else:
            body = json.dumps({"run_id": run_id, "status": state,
                               "agent_type": "orchestrator", "task_ref": "rm134",
                               "commits": 0, "timeline": []}).encode()
            code = 200
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


srv = HTTPServer(("127.0.0.1", 0), Handler)
print(srv.server_port, flush=True)
sys.stdout.flush()
srv.serve_forever()
PY

STUB_RUNSTATES="$RUNSTATES" python3 "$WORK/stub-api.py" > "$WORK/apiport" 2>"$WORK/api.err" &
API_PID=$!
for _ in $(seq 1 100); do
  APIPORT="$(head -n 1 "$WORK/apiport" 2>/dev/null)"
  [ -n "$APIPORT" ] && break
  sleep 0.1
done
[ -n "${APIPORT:-}" ] || { echo "commit-selftest: the stub API never reported a port" >&2; cat "$WORK/api.err" >&2; exit 4; }
API_URL="http://127.0.0.1:$APIPORT"

# ---------------------------------------------------------------------------
# A repository with something staged in it, and the pointer that names its run.
# ---------------------------------------------------------------------------
REPO_DIR="$(cd "$WORK" && pwd -P)/repo"
mkdir -p "$REPO_DIR"
git -C "$REPO_DIR" init -q -b main
git -C "$REPO_DIR" config user.email tester@example.test
git -C "$REPO_DIR" config user.name Tester
git -C "$REPO_DIR" config commit.gpgsign false
git -C "$REPO_DIR" remote add origin https://example.test/org/name.git
echo one > "$REPO_DIR/a.txt"
git -C "$REPO_DIR" add a.txt
git -C "$REPO_DIR" commit -qm "first"
HEAD_SHA="$(git -C "$REPO_DIR" rev-parse HEAD)"
echo two > "$REPO_DIR/a.txt"
git -C "$REPO_DIR" add a.txt

RUNS="$WORK/runs"
TREE_KEY="$(printf '%s' "$REPO_DIR" | shasum -a 256 | cut -c1-32)"
PTR="$RUNS/by-tree/$TREE_KEY"
mkdir -p "$RUNS/by-tree"

# point_at RUN — write the three-line pointer the harness writes.
point_at() { printf '%s\n%s\n%s\n' "$1" "rm134" "" > "$PTR"; }

# state RUN STATUS — what the read API says about a run. No line, and it 404s.
state() {
  grep -v "^$1 " "$RUNSTATES" > "$RUNSTATES.new" 2>/dev/null || :
  mv "$RUNSTATES.new" "$RUNSTATES"
  [ -n "${2:-}" ] && printf '%s %s\n' "$1" "$2" >> "$RUNSTATES"
  return 0
}

script_tool() {
  grep -v "^$1 " "$SCRIPTED" > "$SCRIPTED.new" 2>/dev/null || :
  mv "$SCRIPTED.new" "$SCRIPTED"
  printf '%s %s %s\n' "$1" "$2" "$3" >> "$SCRIPTED"
}

# The stub's sign_commit answers with the repository's own HEAD, because the
# signer reports the commit it was given and `git log` has to be able to find
# it. Nothing here is a real signature; what is under test is which run_id the
# call carried.
script_tool sign_commit ok "{\"commit_sha\":\"$HEAD_SHA\",\"rekor_entry\":{\"log_index\":7},\"trailers\":{}}"
script_tool register_agent ok '{"run_id":"run-successor00000000000000000000","spiffe_id":"spiffe://innsegl.dev/agent/orchestrator/rm134/run-successor00000000000000000000","expires_at":"2026-09-16T00:00:00.000Z"}'

# drive [extra args…] — run the signer against the stubs and leave its exit
# status in $STATUS and everything it said in $WORK/out.
drive() {
  : > "$CALLS"
  ( cd "$REPO_DIR" && env \
      INNSEGL_MCP_ADMIN_URL="$MCP_URL" \
      INNSEGL_MCP_URL="$MCP_URL" \
      INNSEGL_API_URL="${API_OVERRIDE:-$API_URL}" \
      INNSEGL_RUNS_DIR="$RUNS" \
      INNSEGL_ADMIN_CREDENTIAL_MINT="${MINT:-}" \
      "$SIGNER" "$@" -m "test(rm134): a staged change" ) > "$WORK/out" 2>&1
  STATUS=$?
}

# called TOOL [substring…] — the tool was invoked and its arguments carry each
# of the given substrings.
called() {
  local tool="$1"; shift
  local line
  line="$(grep "^$tool " "$CALLS" | head -n 1)"
  [ -n "$line" ] || return 1
  local want
  for want in "$@"; do
    case "$line" in *"$want"*) : ;; *) return 1 ;; esac
  done
  return 0
}

said() { grep -q -- "$1" "$WORK/out"; }

RETIRED=run-retired0000000000000000000000
GHOST=run-ghost000000000000000000000000
LIVE=run-live00000000000000000000000000
SUCCESSOR=run-successor00000000000000000000

echo "commit-selftest: the by-tree pointer, in every state its run can be in"

# --- OPS-037 -----------------------------------------------------------------

# 1. A pointer naming a retired run is SUCCEEDED, not handed on.
point_at "$RETIRED"
state "$RETIRED" retired
drive
if [ "$STATUS" -eq 0 ] && called sign_commit "\"run_id\": \"$SUCCESSOR\""; then
  ok "a retired pointer signs under the successor, never under the retired run"
else
  bad "retired pointer: status $STATUS, calls: $(cat "$CALLS"), said: $(cat "$WORK/out")"
fi

# 2. AND THE SUCCESSOR IS DERIVABLY DISTINCT. A run id is a pure function of
#    (agent_type, task, idempotency_key), so a successor registered under a key
#    that could have produced the predecessor IS the predecessor. The key names
#    the run it succeeds, which is both what makes it distinct and the record
#    of the succession — `register_agent` writes the key into `run_registered`.
if called register_agent "succeeds-$RETIRED"; then
  ok "the successor registers under a key naming the run it succeeds"
else
  bad "the successor's idempotency key does not name $RETIRED: $(grep '^register_agent ' "$CALLS")"
fi

# 3. Both ids are said out loud. The pointer is an attribution record and the
#    tree's work now spans two runs; a swap nobody is told about loses that.
if said "$RETIRED" && said "$SUCCESSOR"; then
  ok "both run ids are named to the operator"
else
  bad "the succession named only one run: $(cat "$WORK/out")"
fi

# 4. The pointer afterwards names the successor, so the next commit on this
#    tree does not repeat the whole dance.
if [ "$(sed -n 1p "$PTR")" = "$SUCCESSOR" ]; then
  ok "the pointer afterwards names the successor"
else
  bad "the pointer still reads $(sed -n 1p "$PTR")"
fi

# 5. and it keeps the run it superseded, so a later reader can follow the tree
#    back across the break.
if [ "$(sed -n 4p "$PTR")" != "superseded $RETIRED" ]; then
  bad "the pointer does not record what it superseded: $(cat "$PTR")"
else
  ok "the pointer records the run it superseded"
fi

# 6. THE SUCCESSION IS DETERMINISTIC. If the pointer could not be rewritten —
#    a read-only directory, a crash between the registration and the write —
#    the next commit must re-derive the SAME successor rather than mint a
#    second identity for one tree (IP §6.6).
FIRST_KEY="$(grep '^register_agent ' "$CALLS" | head -n 1)"
point_at "$RETIRED"
drive
if [ -n "$FIRST_KEY" ] && [ "$(grep '^register_agent ' "$CALLS" | head -n 1)" = "$FIRST_KEY" ]; then
  ok "a second attempt from the same pointer derives the same successor"
else
  bad "the successor is not deterministic: $(grep '^register_agent ' "$CALLS" | head -n 1)"
fi

# --- OPS-038 -----------------------------------------------------------------

# 7. A pointer naming a run this ledger never held is a REFUSAL. Registering
#    something new over it would invent an identity for work whose own run
#    cannot be found, which is the opposite of what a pointer is for.
point_at "$GHOST"
state "$GHOST"
drive
if [ "$STATUS" -ne 0 ] && ! grep -q '^register_agent ' "$CALLS" && ! grep -q '^sign_commit ' "$CALLS"; then
  ok "a pointer naming a run that never existed is refused, not re-registered"
else
  bad "ghost pointer: status $STATUS, calls: $(cat "$CALLS")"
fi

# 8. and the refusal names the run, and leaves the pointer alone — an operator
#    cannot repair a pointer the tool has already overwritten.
if [ "$STATUS" -ne 0 ] && said "$GHOST" && [ "$(sed -n 1p "$PTR")" = "$GHOST" ]; then
  ok "the refusal names the run and leaves the pointer as it found it"
else
  bad "ghost refusal: said $(cat "$WORK/out"), pointer $(sed -n 1p "$PTR")"
fi

# --- the states that must NOT change ----------------------------------------

# 9. A live pointer is untouched. The whole feature is invisible until a run
#    is dead.
point_at "$LIVE"
state "$LIVE" active
drive
if [ "$STATUS" -eq 0 ] && called sign_commit "\"run_id\": \"$LIVE\"" && ! grep -q '^register_agent ' "$CALLS"; then
  ok "a live pointer signs under its own run and registers nothing"
else
  bad "live pointer: status $STATUS, calls: $(cat "$CALLS")"
fi
if [ "$(sed -n 1p "$PTR")" = "$LIVE" ] && [ "$(wc -l < "$PTR")" -eq 3 ]; then
  ok "a live pointer is left exactly as it was"
else
  bad "a live pointer was rewritten: $(cat "$PTR")"
fi

# 10. A read API that cannot be reached must not block a commit. The probe is
#     how the signer learns the run is dead; not being able to run it is not
#     evidence that it is, and refusing here would strand every tree whenever
#     the dashboard is down.
point_at "$LIVE"
API_OVERRIDE="http://127.0.0.1:1" drive
if [ "$STATUS" -eq 0 ] && called sign_commit "\"run_id\": \"$LIVE\""; then
  ok "an unreachable read API does not block the commit"
else
  bad "unreachable API: status $STATUS, calls: $(cat "$CALLS")"
fi
if said "could not be asked"; then
  ok "and the signer says the probe did not run"
else
  bad "an unreachable probe was silent: $(cat "$WORK/out")"
fi

# 11. AN EXPLICIT -r IS NEVER SUBSTITUTED. -r means that run and nothing else
#     — the harness signs a subagent's leftover work under it so the work is
#     attributed to the agent that did it (ADR-0046) — so a retired one goes to
#     `sign_commit` and is refused there, by the tool, exactly as before. What
#     must never happen is this script quietly making it a different agent's
#     commit, which is the swap the whole feature exists not to be.
point_at "$LIVE"
drive -r "$RETIRED"
if called sign_commit "\"run_id\": \"$RETIRED\"" && ! grep -q '^register_agent ' "$CALLS"; then
  ok "-r is carried through untouched; nothing is succeeded behind the caller"
else
  bad "-r retired: status $STATUS, calls: $(cat "$CALLS")"
fi

# --- RM-156 (#259): the run this script mints has a parent ------------------
#
# Measured 2026-09-18: 87 `orchestrator` runs in the ledger, every one of them
# registered by this script, and not one carrying a parent. The reason was not
# that they had none — it is that a shell command cannot discover which agent
# it is inside, so this script had nothing to name and nothing the MCP could
# resolve for it.
#
# SessionStart now publishes the session's run under a SIBLING of the pointer
# above, keyed on the same working tree and suffixed `.session`. The suffix is
# the whole safety of it: SubagentStop removes the 32 hex characters exactly,
# so a subagent starting and stopping in this tree cannot take the session's
# pointer with it.

SESSION_PTR="$PTR.session"
SESSION_RUN=run-session0000000000000000000000

# point_session RUN — the two-line pointer SessionStart writes. Line 2 is not
# read by anything; it is there so a human can see whose run line 1 is.
point_session() { printf '%s\n%s\n' "$1" "sess-1" > "$SESSION_PTR"; }

# 12. A tree with no subagent pointer mints a run, and that run names the
#     session's.
rm -f "$PTR"
point_session "$SESSION_RUN"
state "$SESSION_RUN" active
script_tool register_agent ok "{\"run_id\":\"$SUCCESSOR\",\"spiffe_id\":\"spiffe://innsegl.dev/agent/orchestrator/rm134/$SUCCESSOR\",\"expires_at\":\"2026-09-16T00:00:00.000Z\"}"
drive
if [ "$STATUS" -eq 0 ] && called register_agent "\"parent_run_id\": \"$SESSION_RUN\""; then
  ok "a run the signer mints names this tree's session as its parent"
else
  bad "signer parent: status $STATUS, calls: $(cat "$CALLS"), said: $(cat "$WORK/out")"
fi

# 13. and the pointer is READ, never written. It belongs to the session, and a
#     signer that rewrote it would end the session's claim on its own tree.
if [ "$(sed -n 1p "$SESSION_PTR")" = "$SESSION_RUN" ] && [ "$(wc -l < "$SESSION_PTR")" -eq 2 ]; then
  ok "the session pointer is left exactly as the harness wrote it"
else
  bad "the signer rewrote the session pointer: $(cat "$SESSION_PTR")"
fi

# 14. NO POINTER, NO PARENT. A tree whose session never registered — or a
#     machine with no harness at all — mints a root run, exactly as before.
#     doc 02 §1 distinguishes absent from empty, so the member must not appear.
rm -f "$SESSION_PTR"
drive
if [ "$STATUS" -eq 0 ] && ! grep '^register_agent ' "$CALLS" | grep -q 'parent_run_id'; then
  ok "a tree with no session pointer mints a root run, and claims no parent"
else
  bad "no-pointer parent: status $STATUS, calls: $(grep '^register_agent ' "$CALLS")"
fi

# 15. A STALE POINTER COSTS THE EDGE AND NOT THE COMMIT.
#
#     register_agent refuses a parent that is retired or that the ledger has
#     never held (RM-156), which is right: an edge is permanent, and one
#     naming a run that is not there is permanently wrong. But this parent came
#     off a disk, and a session that ended without its hook running leaves a
#     pointer behind. Refusing the COMMIT over that would strand the work for a
#     bookkeeping edge, so the edge is what gives way.
#
#     The stub answers every register_agent the same way, so what is asserted
#     is the LADDER: three attempts, each dropping what the one before it was
#     refused for. A signer that gave up after the first would show one call.
point_session "$SESSION_RUN"
script_tool register_agent err '{"error_class":"RUN_ALREADY_RETIRED","message":"parent_run_id was retired","retryable":false}'
drive
ATTEMPTS="$(grep -c '^register_agent ' "$CALLS")"
if [ "${ATTEMPTS:-0}" -eq 3 ]; then
  ok "a refused registration drops the parent, then repo and branch, in that order"
else
  bad "the fallback ladder made $ATTEMPTS attempts, want 3: $(grep '^register_agent ' "$CALLS")"
fi
if grep '^register_agent ' "$CALLS" | sed -n 1p | grep -q 'parent_run_id' \
   && ! grep '^register_agent ' "$CALLS" | sed -n 2p | grep -q 'parent_run_id' \
   && grep '^register_agent ' "$CALLS" | sed -n 2p | grep -q '"repo"'; then
  ok "the second attempt drops the parent and keeps the repository"
else
  bad "the ladder dropped the wrong member: $(grep '^register_agent ' "$CALLS")"
fi

# --- putting the ladder's fixtures back before the credential cases ----------
#
# Case 15 above leaves two things behind that belong to IT and not to anything
# after it: a session pointer on disk, and a register_agent scripted to refuse.
# The cases below are about the CREDENTIAL — a run that cannot register for an
# unrelated reason would fail them for the wrong one, and the failure would
# read as a credential fault.
rm -f "$SESSION_PTR"
script_tool register_agent ok '{"run_id":"run-successor00000000000000000000","spiffe_id":"spiffe://innsegl.dev/agent/orchestrator/rm134/run-successor00000000000000000000","expires_at":"2026-09-16T00:00:00.000Z"}'

# --- OPS-073: single-listener mode, unchanged --------------------------------
#
# ASSERTED FIRST, over all fifteen cases above it, because "nothing changed" is
# only worth anything as a statement about the whole suite. Every one of them
# has just run against a listener demanding nothing; not one request may have
# carried a credential, and nothing may have been minted.
if [ -s "$AUTHLOG" ] && ! grep -qv '^-$' "$AUTHLOG"; then
  ok "OPS-073: with nothing to authenticate, no request carries a credential"
else
  bad "OPS-073: a credential was presented to a listener that asked for none: $(grep -v '^-$' "$AUTHLOG" | head -n 2)"
fi
if [ ! -f "$WORK/mint.count" ]; then
  ok "OPS-073: and nothing was minted — the mint is driven by a refusal, not a mode"
else
  bad "OPS-073: $(cat "$WORK/mint.count") credential(s) were minted unprompted"
fi

# --- OPS-069..071: the listener's credential (#266) ---------------------------
#
# #264 put a repository-scoped credential in front of register_agent and
# retire_agent, both of which this script calls. Measured before #266: this file
# carried no Authorization header, so deploying the check answered the FIRST of
# those with 401 and no commit could be signed at all.
#
# THE HARD CASE IS EXPIRY, and it is what the budget below reproduces. A
# credential lives fifteen minutes and cannot be withdrawn; one `sign_commit`
# can take five, so a run that registers, signs and retires may outlive the
# credential it started with. A signing path that died there would lose work
# that was already done.
cat > "$WORK/mint" <<'SH'
#!/bin/sh
# Issues cred-1, cred-2, ... and tells the stub to demand the newest one, good
# for MINT_USES requests. Three requests is exactly one MCP call — initialize,
# the initialized notification, and the call itself — so a budget of three ages
# every credential out the moment the call that used it finishes. Fifteen
# minutes of waiting, in one line.
n=$(( $(cat "$MINT_STATE/mint.count" 2>/dev/null || echo 0) + 1 ))
printf '%s' "$n" > "$MINT_STATE/mint.count"
printf '%s\n' "$1" >> "$MINT_STATE/mint.scopes"
printf 'cred-%s %s\n' "$n" "${MINT_USES:-100}" > "$MINT_STATE/required"
printf 'cred-%s\n' "$n"
SH
chmod +x "$WORK/mint"
export MINT_STATE="$WORK" MINT_USES=3
MINT="$WORK/mint"

# A listener demanding something nobody holds, and a tree with no pointer — so
# this run registers, signs and retires: three calls, one process.
rm -f "$PTR"
printf 'spent 0\n' > "$CREDFILE"
: > "$AUTHLOG"
drive

# 16. OPS-069 — the whole cycle completes behind the credential.
if [ "$STATUS" -eq 0 ] && called register_agent && called sign_commit && grep -q 'signed' "$WORK/out"; then
  ok "OPS-069: register, sign and retire all complete against a listener that demands one"
else
  bad "OPS-069: status $STATUS, calls: $(cat "$CALLS"), said: $(cat "$WORK/out")"
fi
if [ "$(head -n 1 "$AUTHLOG")" = "-" ] && grep -q '^Bearer cred-1$' "$AUTHLOG"; then
  ok "OPS-069: nothing is minted until the listener asks, and then it is presented"
else
  bad "OPS-069: first request carried '$(head -n 1 "$AUTHLOG")'; log: $(sort -u "$AUTHLOG" | tr '\n' ' ')"
fi
if [ "$(tail -n 1 "$WORK/mint.scopes")" = "example.test/org/name" ]; then
  ok "OPS-069: the credential is scoped to the repository being committed to"
else
  bad "OPS-069: minted for '$(tail -n 1 "$WORK/mint.scopes")', want example.test/org/name"
fi

# 17. OPS-070 — a credential spent mid-run is re-minted, not failed.
#
# Three calls, each of which exhausts its credential, so the second and third
# are refused on their own handshake and recover. The count is the assertion: a
# script that minted once and gave up would have stopped at the second call,
# holding a registered run and an unsigned tree.
if [ "$(cat "$WORK/mint.count")" -ge 3 ]; then
  ok "OPS-070: a credential that runs out mid-run is re-minted per refused call"
else
  bad "OPS-070: only $(cat "$WORK/mint.count") credential(s) minted across three calls"
fi
if grep -q '^Bearer cred-2$' "$AUTHLOG" && grep -q '^Bearer cred-3$' "$AUTHLOG"; then
  ok "OPS-070: each later call carries the credential minted for it, not the dead one"
else
  bad "OPS-070: the re-minted credentials were never presented: $(sort -u "$AUTHLOG" | tr '\n' ' ')"
fi

# 18. OPS-071 — the value reaches no file and no line this script printed.
#
# It cannot be withdrawn before it expires, because a revocation list would be
# a dependency on the issuer being reachable. A copy left behind is therefore a
# copy anyone on this machine can replay for the rest of its life.
LEAKED="$(grep -rl 'cred-' "$RUNS" "$WORK/out" "$REPO_DIR/.git" 2>/dev/null)"
if [ -z "$LEAKED" ]; then
  ok "OPS-071: the credential is in no pointer, no git metadata and nothing printed"
else
  bad "OPS-071: the credential was written to: $LEAKED"
fi
if grep -Fq 'curl -sS -K -' "$SIGNER" \
   && ! grep -qE '^[^#]*(-H|--header)[^#]*Authorization' "$SIGNER" \
   && ! grep -qE '^[^#]*export[[:space:]]+ADMIN_CRED' "$SIGNER"; then
  ok "OPS-071: it travels in a curl configuration on a pipe — no argv, no file, no export"
else
  bad "OPS-071: the credential reaches a command line or the environment"
fi

# 19. AND A REFUSAL SAYS WHAT TO DO. The listener answers every credential
#     failure with one byte-identical sentence by design, so this is the only
#     place an operator learns which command mints and against which key. It
#     must also not blame the deployment: the server is up and answering.
MINT="$WORK/no-mint"
printf 'spent 0\n' > "$CREDFILE"
drive
if [ "$STATUS" -ne 0 ] \
   && grep -q 'admin-credential mint' "$WORK/out" \
   && grep -q 'signing.key' "$WORK/out" \
   && ! grep -q 'could not be reached' "$WORK/out"; then
  ok "OPS-069: a refusal names the mint command and the key, and blames no outage"
else
  bad "OPS-069: status $STATUS, said: $(cat "$WORK/out")"
fi

echo
echo "commit-selftest: $pass ok, $fail failed"
[ "$fail" -eq 0 ] || exit 1
