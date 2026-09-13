#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""THE SECOND HARNESS'S SHIM. Read the transcript, forward it, exit 0.

RM-130 (#209). E11 moved the derivation into the MCP so that a shim reads its
own event and stops. The reference shim proved the tools work; it did not prove
they are harness-neutral, because it is the harness they were extracted from.
This is the test of that: a shim for a harness that shares no mechanism with the
first, written against the same three tools.

    describe_workspace   repo, worktree, branch and task from a cwd  (#205)
    observe_tool_call    digest the body, store it, append tool_call (#206)
    observe_session      start/stop, and all of the bookkeeping      (#207)

observe_session calls describe_workspace in process, so this file reaches two
tools directly and the third through them -- exactly as the reference shim does.

# THE ROUTE IS POST-HOC TRANSCRIPT INGESTION, AND THAT IS THE POINT

The second harness is Codex CLI, which has no hook system: no callback, no
gate, no mid-session extension point this file can use. What it does offer is a
rollout transcript, one JSONL file per session written as the session runs,
whose records are

    {"timestamp": ..., "type": "session_meta"|"response_item"|"event_msg"|...,
     "payload": {...}}

and whose payloads carry `session_meta` (the session's id and its cwd) and
`custom_tool_call` / `function_call` (each tool the model invoked, with its
name and its input). So this reads the file after the session and forwards it.

That is a STRONGER demonstration than a second hook-driven shim would have
been, not a weaker one. It is the route available to a harness that cooperates
in no way whatever beyond writing its own log, and it exercises all three tools
without the harness knowing innsegl exists. Whatever the MCP still asked a
caller to work out for itself would have shown up here immediately, because
nothing about the first harness could be leaned on.

# WHAT THIS ROUTE CANNOT DO, AND WHAT THAT COSTS

THERE IS NO COMMIT REFUSAL, AND THERE CANNOT BE ONE. The reference shim's
PreToolUse gate exits 2 and the harness blocks the tool call; that is the one
thing E11 says can never move into the MCP, because blocking a call is the
harness's own power. A transcript is read after the fact. By the time this file
sees `git commit` the commit exists, and nothing here can unmake it. No
mechanism is invented above: the refusal is simply absent.

The cost is exact, and it is the difference between prevention and detection.
On the reference harness an agent CANNOT make an unattributed commit. Here it
can, and what this shim does instead is notice -- the commit is in the
transcript as a tool call, so the ledger records that the run made it, while the
commit object itself carries no trailer and no signature. Attribution survives;
enforcement does not. scripts/verify-branch.sh is what refuses to merge the
result, which makes the gate a merge-time one rather than a commit-time one.

THE STOP-TIME CAPTURE IS WHAT PARTLY ANSWERS THIS (ADR-0046). A session that
ends with uncommitted work in its tree has that work signed under the run it was
done by. It is the one signing a post-hoc reader can honestly do, because the
tree is still there to be signed, and it is why a run ingested from a transcript
can carry a signed commit at all.

# WIRING

    scripts/hooks/rollout-ingest.py <path to a rollout .jsonl>

The path is REQUIRED and is never guessed. A shim that reached for "the most
recent transcript" would ingest whichever session happened to be newest,
including one the operator never meant to record, and a ledger is not a place
to put something by accident.

    INNSEGL_MCP_ADMIN_URL           default http://127.0.0.1:28090/
    INNSEGL_SESSION_AGENT_TYPE      default rollout
    INNSEGL_SIGNER                  default innsegl-commit, on PATH

Needs python3 and nothing else. It prints the run id on stdout.

# FAILURE IS LOUD HERE, AND THAT IS A DIFFERENCE WORTH STATING

The reference shim must never block and never fail: it runs inside a live
session, and a refusal there costs the operator their work. This runs after the
session is over, so there is nothing left to hold up. A call that is refused
stops the ingestion and says why, and the file can simply be re-read -- every
tool involved is idempotent on a derived key, so a second pass over the same
transcript appends nothing twice (ADR-0017, LED-008).
"""

import json
import os
import subprocess
import sys
import urllib.request

URL = os.environ.get("INNSEGL_MCP_ADMIN_URL", "http://127.0.0.1:28090/")
AGENT_TYPE = os.environ.get("INNSEGL_SESSION_AGENT_TYPE", "rollout")
SIGNER = os.environ.get("INNSEGL_SIGNER", "innsegl-commit")

# --- the transport, which is the least interesting thing in this file --------


def post(body, session=None, timeout=60):
    request = urllib.request.Request(URL, json.dumps(body).encode(), {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream"})
    if session:
        request.add_header("Mcp-Session-Id", session)
    with urllib.request.urlopen(request, timeout=timeout) as reply:
        return reply.headers.get("Mcp-Session-Id"), reply.read().decode("utf-8", "replace")


def call(tool, /, **arguments):
    """One MCP call. An empty argument is omitted, so optional stays optional.

    The tool name is positional-only: `observe_tool_call` takes an argument
    called `tool` of its own, and a keyword parameter here would collide.
    """
    NEXT[0] += 1
    _, raw = post({"jsonrpc": "2.0", "id": NEXT[0], "method": "tools/call", "params": {
        "name": tool, "arguments": {k: v for k, v in arguments.items() if v}}}, SESSION)
    for line in raw.splitlines():          # the reply is an SSE frame; a direct
        if line.startswith("data: "):      # JSON reply has no data: line and is
            raw = line[6:]                 # read as it stands.
            break
    result = json.loads(raw)["result"]
    body = result.get("structuredContent") or {}
    if result.get("isError"):
        sys.exit("innsegl: %s refused: %s" % (tool, body.get("message") or body))
    return body


SESSION, _ = post({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-11-25", "capabilities": {},
    "clientInfo": {"name": "innsegl-rollout-shim", "version": "v0"}}}, timeout=30)
post({"jsonrpc": "2.0", "method": "notifications/initialized"}, SESSION, timeout=10)
NEXT = [1]

# --- the shim itself ---------------------------------------------------------
#
# The whole of it. No branch is derived, no task folded, no remote parsed,
# nothing digested, no marker file written and no idea where a body is kept --
# and the run id is a local variable rather than a file on disk, because one
# process reads the whole transcript. That last one is the reference shim's
# single remaining local computation, and this route does not even need it.

if len(sys.argv) != 2:
    sys.exit("usage: rollout-ingest.py <path to a rollout .jsonl>")

run = {}
cwd = ""
for record in (json.loads(line) for line in open(sys.argv[1], encoding="utf-8") if line.strip()):
    payload = record.get("payload") or {}
    if record.get("type") == "session_meta":
        cwd = payload.get("cwd") or ""
        run = call("observe_session", phase="start", agent_type=AGENT_TYPE, cwd=cwd,
                   session_id=payload.get("session_id") or payload.get("id"))
    elif run and payload.get("type") in ("custom_tool_call", "function_call"):
        call("observe_tool_call", run_id=run["run_id"], tool=payload.get("name"),
             body=json.dumps(record), run_token=run.get("run_token"))

if not run:
    sys.exit(0)

# CAPTURE WHAT THE SESSION LEFT, under the identity of the run that did it
# (ADR-0046). Without this a transcript-driven run has tool calls and no
# signature, because the refusal that makes a reference-harness agent sign
# cannot exist on this route.
#
# THIS IS GIT PLUMBING IN A SHIM AND IT SHOULD NOT BE. The reference shim has
# the same three commands for the same reason; #208's closing comment already
# hands the capture on as work belonging in the MCP, and a second shim needing
# it independently is the measurement that says so. It is the largest thing
# this file computes locally.
if cwd and subprocess.run(["git", "-C", cwd, "status", "--porcelain"],
                          capture_output=True, text=True).stdout.strip():
    subprocess.run(["git", "-C", cwd, "add", "-A"], check=False)
    subprocess.run([SIGNER, "-r", run["run_id"]]
                   + (["-t", run["task"]] if run.get("task") else [])
                   + (["-w", run["worktree"]] if run.get("worktree") else [])
                   + ["-m", "chore(agent): work left by session run %s\n\n"
                      "Captured after the session because it ended with uncommitted work "
                      "and no commit of its own. Signed under that run's identity so the "
                      "work is attributed to the agent that did it rather than to whoever "
                      "commits next (ADR-0046)." % run["run_id"]], cwd=cwd, check=False)

call("observe_session", phase="stop", session_id=run["session_id"])
print(run["run_id"])
