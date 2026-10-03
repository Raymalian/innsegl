#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Harness compatibility check (RM-329, ADR-0069 decision 6).

Connecting innsegl must leave Claude Code's features as they were. This runs
the same checks in two setups and compares them:

  scripts/harness-compat.py run <label> <outdir>     record one setup
  scripts/harness-compat.py compare <dirA> <dirB>    exit 1 on any difference

A run records, from a fresh Claude Code in the current directory:
  - the slash commands, tools and MCP servers it reports at start (headless)
  - whether each interactive-only command appears when its prefix is typed
  - the result of a set of functions: a model turn, a subagent, web search,
    web fetch, network from the agent's shell, and an MCP call when one is
    connected

Run it on a machine without innsegl (pause it: `sudo innsegl connect --pause`)
and with it, on each new Claude Code version. It needs a signed-in Claude
Code and a terminal; it is not a CI test. Extra environment for a run is
passed through, so a setup can be described entirely by its environment.
"""

import json
import os
import pty
import re
import select
import subprocess
import sys
import time

# Interactive-only commands and the prefix that brings each up. Headless
# start lists do not include these, so they are checked in a terminal.
MENU = [
    ("/remote", "remote-control"),
    ("/ultra", "ultrareview"),
    ("/usage", "usage"),
    ("/status", "status"),
    ("/mod", "model"),
    ("/login", "login"),
    ("/chrome", "chrome"),
    ("/schedule", "schedule"),
    ("/plugin", "plugin"),
    ("/fast", "fast"),
    ("/teleport", "teleport"),
    ("/install-github", "install-github-app"),
]

FUNCTIONS = [
    ("model", "Reply with exactly: OK", None),
    ("subagent", "Use the Task tool to start one general-purpose subagent whose only job is to reply PONG. "
                 "Then print exactly what it returned.", "Task Agent"),
    ("websearch", "Use the WebSearch tool to search for: claude code. Print the first result URL only.", "WebSearch"),
    ("webfetch", "Use the WebFetch tool on https://example.com and print the page title only.", "WebFetch"),
    ("shellnet", "Run exactly this Bash command and print its output verbatim: "
                 "env | grep -ciE '^(https?_proxy|node_extra_ca_certs)=' ; "
                 "git ls-remote https://github.com/git/git HEAD >/dev/null && echo git-ok ; "
                 "curl -s -o /dev/null -w 'npm-%{http_code}\\n' https://registry.npmjs.org/", "Bash"),
]

ANSI = re.compile(rb"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[()][0-9A-Za-z]|\x1b[=>78]")


def headless(prompt, tools, timeout=240):
    args = ["claude", "-p", prompt, "--output-format", "stream-json", "--verbose"]
    if tools:
        args += ["--allowedTools", tools]
    try:
        out = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout, text=True).stdout
    except subprocess.TimeoutExpired:
        return []
    events = []
    for line in out.splitlines():
        try:
            events.append(json.loads(line))
        except ValueError:
            pass
    return events


def menu_has(prefix, want, wait=12, args=()):
    pid, fd = pty.fork()
    if pid == 0:
        os.environ["TERM"] = "xterm-256color"
        os.execvp("claude", ["claude", *args])
    out = b""

    def pump(seconds):
        nonlocal out
        end = time.time() + seconds
        while time.time() < end:
            ready, _, _ = select.select([fd], [], [], 0.2)
            if ready:
                try:
                    out += os.read(fd, 65536)
                except OSError:
                    return

    pump(wait)
    os.write(fd, prefix.encode())
    pump(4)
    os.write(fd, b"\x03")
    pump(0.5)
    os.write(fd, b"\x03")
    pump(1)
    try:
        os.kill(pid, 9)
        os.waitpid(pid, 0)
    except OSError:
        pass
    return ("/" + want) in ANSI.sub(b"", out).decode("utf-8", "replace")


def summarise(events):
    result = [e for e in events if e.get("type") == "result"]
    tools = [c.get("name") for e in events if e.get("type") == "assistant"
             for c in e.get("message", {}).get("content", []) if isinstance(c, dict) and c.get("type") == "tool_use"]
    ok = bool(result) and not result[-1].get("is_error")
    return {"ok": ok, "tools": sorted(set(t for t in tools if t)), "text": str(result[-1].get("result", ""))[:200] if result else ""}


def run(label, outdir):
    os.makedirs(outdir, exist_ok=True)
    report = {"label": label, "functions": {}, "menu": {}}
    start = headless("Reply with exactly: OK", None)
    init = next((e for e in start if e.get("type") == "system" and e.get("subtype") == "init"), {})
    report["version"] = init.get("claude_code_version")
    # MCP-supplied commands and tools depend on whether a server finished
    # connecting in time, not on the setup; MCP servers are compared by name.
    report["slash_commands"] = sorted(c for c in init.get("slash_commands", []) if not c.startswith("mcp__"))
    report["tools"] = sorted(t for t in init.get("tools", []) if not t.startswith("mcp__"))
    report["mcp_servers"] = sorted(m.get("name", "") for m in init.get("mcp_servers", []))
    for name, prompt, tools in FUNCTIONS:
        report["functions"][name] = summarise(headless(prompt, tools))
        print(f"{name:10} {'ok' if report['functions'][name]['ok'] else 'FAILED'}", flush=True)
    for prefix, want in MENU:
        report["menu"][want] = menu_has(prefix, want)
        print(f"/{want:20} {'present' if report['menu'][want] else 'MISSING'}", flush=True)
    # A resumed session must offer what a new one does.
    resumed = "remote-control (resumed)"
    report["menu"][resumed] = menu_has("/remote", "remote-control", args=["--continue"])
    print(f"/{resumed:20} {'present' if report['menu'][resumed] else 'MISSING'}", flush=True)
    path = os.path.join(outdir, "report.json")
    with open(path, "w") as f:
        json.dump(report, f, indent=1)
    print("wrote", path)


def compare(a_dir, b_dir):
    a = json.load(open(os.path.join(a_dir, "report.json")))
    b = json.load(open(os.path.join(b_dir, "report.json")))
    diffs = []
    for key in ("slash_commands", "tools", "mcp_servers"):
        keep = lambda xs: {x for x in xs if not x.startswith("mcp__")}
        only_a, only_b = sorted(keep(a[key]) - keep(b[key])), sorted(keep(b[key]) - keep(a[key]))
        if only_a or only_b:
            diffs.append(f"{key}: only in {a['label']}: {only_a}; only in {b['label']}: {only_b}")
    for want in sorted(set(a["menu"]) | set(b["menu"])):
        if a["menu"].get(want) != b["menu"].get(want):
            diffs.append(f"/{want}: {a['label']}={a['menu'].get(want)} {b['label']}={b['menu'].get(want)}")
    for name in sorted(set(a["functions"]) | set(b["functions"])):
        fa, fb = a["functions"].get(name, {}), b["functions"].get(name, {})
        if fa.get("ok") != fb.get("ok"):
            diffs.append(f"{name}: {a['label']} ok={fa.get('ok')} {b['label']} ok={fb.get('ok')}")
    print(f"{a['label']} (Claude Code {a.get('version')}) vs {b['label']} (Claude Code {b.get('version')})")
    for d in diffs:
        print("  DIFFERENT", d)
    print("  no difference" if not diffs else f"  {len(diffs)} difference(s)")
    return 1 if diffs else 0


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "run":
        run(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 4 and sys.argv[1] == "compare":
        sys.exit(compare(sys.argv[2], sys.argv[3]))
    else:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
