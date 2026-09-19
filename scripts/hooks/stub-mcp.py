# SPDX-License-Identifier: Apache-2.0
"""A stub MCP that records every tools/call it is given.

It answers the three requests the streamable-HTTP transport makes of it --
initialize, the initialized notification, and tools/call -- and replies to the
last with an SSE frame, because that is what the shipped server does and a shim
has to read it. Everything it is asked is written down; nothing it is asked is
interpreted.

Two environment variables, both required:

    STUB_CALLS      appended to, one line per tools/call:
                    "<tool> <arguments as sorted json>"
    STUB_SCRIPTED   read per call, one line per tool:
                    "<tool> <ok|err> <result json>"

Two more, both optional and both off by default, so every caller that predates
them is answered exactly as before (#266):

    STUB_CREDENTIAL a file holding "<token> <requests it is still good for>".
                    Absent, empty, or a file that is not there: no credential is
                    required and this stub behaves as it always did. Present: a
                    request that does not carry "Authorization: Bearer <token>"
                    is answered 401 before anything is recorded, and so is one
                    that carries it after the budget is spent -- which is how a
                    credential EXPIRING mid-call is reproduced without waiting
                    fifteen minutes for a real one to.
    STUB_AUTH_LOG   appended to, one line per request: the Authorization header
                    as it arrived, or "-" for a request that carried none. It is
                    what lets a self-test assert that a credential was presented
                    at all, and that nothing else ever carries one.

The chosen port is printed on stdout so the caller can bind to :0 and not race
anything.

WHY IT IS ITS OWN FILE. It was written inside scripts/hooks/shim-selftest.sh
for OPS-019..021 and the second shim's self-test needed the same seventy lines.
Copying them would have been the exact failure E11 exists to answer -- a second
caller reimplementing what the first already had -- in the test suite that
proves E11. There is one stub, and both self-tests drive it.
"""

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

CALLS = os.environ["STUB_CALLS"]
SCRIPTED = os.environ["STUB_SCRIPTED"]
CREDENTIAL = os.environ.get("STUB_CREDENTIAL", "")
AUTH_LOG = os.environ.get("STUB_AUTH_LOG", "")

# The shipped listener's own answer, byte for byte (internal/mcp/admincred.go).
# A stub that refused with a different sentence would let a caller key on the
# wrong string and pass here while failing against the deployment.
REFUSAL = ("unauthorized: the identity-lifecycle listener requires a "
           "repository-scoped credential")


def required():
    """(token, uses) this stub currently demands, or (None, 0) for no check."""
    if not CREDENTIAL:
        return None, 0
    try:
        with open(CREDENTIAL, encoding="utf-8") as fh:
            token, _, uses = fh.readline().strip().partition(" ")
    except OSError:
        return None, 0
    if not token:
        return None, 0
    return token, int(uses or "0")


def spend(token, uses):
    """Charge one request against the budget, so a credential can run out."""
    with open(CREDENTIAL, "w", encoding="utf-8") as fh:
        fh.write("%s %d\n" % (token, uses - 1))


def scripted(tool):
    """The answer this run has scripted for tool, as (kind, payload)."""
    with open(SCRIPTED, encoding="utf-8") as fh:
        for line in fh:
            name, _, rest = line.rstrip("\n").partition(" ")
            kind, _, payload = rest.partition(" ")
            if name == tool:
                return kind, json.loads(payload)
    return "ok", {}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def refuse(self):
        body = REFUSAL.encode()
        self.send_response(401)
        self.send_header("WWW-Authenticate", "Bearer")
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def admitted(self):
        """The credential check, BEFORE the body is read or anything recorded.

        That order is the shipped server's: #264 wraps the whole admin handler,
        so a refused caller cannot even learn the surface -- and a stub that
        recorded the call first would let a caller pass a self-test while
        appending nothing against the real listener.
        """
        presented = self.headers.get("Authorization", "")
        if AUTH_LOG:
            with open(AUTH_LOG, "a", encoding="utf-8") as fh:
                fh.write((presented or "-") + "\n")
        token, uses = required()
        if token is None:
            return True
        if presented != "Bearer " + token or uses <= 0:
            return False
        spend(token, uses)
        return True

    def do_POST(self):
        if not self.admitted():
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self.refuse()
            return
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        try:
            req = json.loads(raw)
        except ValueError:
            self.send_response(400)
            self.end_headers()
            return

        method = req.get("method")
        if method == "initialize":
            body = json.dumps({"jsonrpc": "2.0", "id": req.get("id"), "result": {
                "protocolVersion": "2025-11-25", "capabilities": {},
                "serverInfo": {"name": "stub", "version": "v0"}}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Mcp-Session-Id", "stub-session")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if method == "notifications/initialized":
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if method != "tools/call":
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        params = req.get("params", {})
        tool = params.get("name", "")
        with open(CALLS, "a", encoding="utf-8") as fh:
            fh.write(tool + " " + json.dumps(params.get("arguments", {}), sort_keys=True) + "\n")

        kind, payload = scripted(tool)
        result = {"structuredContent": payload,
                  "content": [{"type": "text", "text": json.dumps(payload)}]}
        if kind == "err":
            result["isError"] = True
        frame = ("event: message\ndata: " + json.dumps(
            {"jsonrpc": "2.0", "id": req.get("id"), "result": result}) + "\n\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(frame)))
        self.end_headers()
        self.wfile.write(frame)


srv = HTTPServer(("127.0.0.1", 0), Handler)
print(srv.server_port, flush=True)
sys.stdout.flush()
srv.serve_forever()
