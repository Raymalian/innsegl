# Runbook — putting one agent's work through Innsegl

**What this is for.** An orchestrator has work to dispatch and wants the commit
that results to carry an identity a stranger can check. This is the sequence,
with the exact calls and the real output of a run made on 2026-09-05.

**What it is not for.** A human signing their own commits. That is not what
this system does, and `innsegl init` deliberately does not configure it —
see #158. Every identity here belongs to a run, is issued by the MCP server,
and cannot be altered by the agent that receives it.

---

## 0. Who does what

| | |
|---|---|
| **MCP server** | issues identities. Holds the SPIRE admin credential — the only service that does. |
| **Orchestrator** | asks for one, records what the work did, signs through `sign_commit`. |
| **Sub-agents** | hold no credentials and never reach the MCP server. |
| **Operator** | owns the deployment. Never signs as themselves. |

The four MCP calls below are the orchestrator's, in order. Nothing else in the
system needs to know they happened.

---

## 1. Bring the stack up

```sh
export INNSEGL_SPIRE_JWT_ISSUER=http://spire-oidc:8080
make innsegl-up
```

`INNSEGL_REKOR_PORT` moves Rekor off host port 3000 if something already holds
it. The default collides with a great many development servers, and the failure
is a bind error during bring-up, not later:

```sh
export INNSEGL_REKOR_PORT=3010     # only if 3000 is taken
```

**Take it down with `make innsegl-down`, not `make innsegl-purge`.** The first
stops the stack; the second deletes the ledger, which holds the only copy of
what the agents did.

---

## 2. The whole sequence, already scripted

```sh
make innsegl-demo
```

That runs a demo agent through all four calls. Its output on 2026-09-05:

```
demo-agent: signed commit fafd1c410133265dd38df67d9a26015d50b4708d
demo-agent:   rekor entry 08ac2bed26125cc2…07c2 at log index 0
demo-agent:   trailer Agent-Identity: spiffe://innsegl.dev/agent/fbbcd8eb/d0834c31/run-dd41951f222496a135241a77d1430237
demo-agent:   trailer Agent-Run: run-dd41951f222496a135241a77d1430237
demo-agent:   trailer Agent-Task: d0834c31
demo-agent: retired run-dd41951f222496a135241a77d1430237 at 2026-09-05T17:51:55.888Z
demo-agent: get_credential after retirement is refused: RUN_ALREADY_RETIRED
```

**Read that as the specification for your own orchestrator.** The rest of this
runbook is the same four calls made by hand, because an orchestrator that is
not `demo-agent` has to make them itself.

---

## 3. The four calls

The MCP server speaks streamable HTTP on `127.0.0.1:8080`, at `/` — not
`/mcp`. Open a session first; every later call carries its id.

```sh
curl -sD /tmp/h -X POST http://127.0.0.1:8080/ \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{
       "protocolVersion":"2024-11-05","capabilities":{},
       "clientInfo":{"name":"orchestrator","version":"1"}}}' >/dev/null
SID=$(grep -i mcp-session-id /tmp/h | tr -d '\r' | awk '{print $2}')
```

Then `notifications/initialized`, and the tools are callable.

### 3.1 `register_agent` — get an identity for this unit of work

```json
{"agent_type": "docs-writer", "task_id": "RM-077", "idempotency_key": "…"}
```

```json
{
  "run_id":    "run-61835d52daf594e228cb17cb522f3a2d",
  "spiffe_id": "spiffe://innsegl.dev/agent/4799d6f0/01a32f1e/run-61835d52daf594e228cb17cb522f3a2d",
  "expires_at": "2026-09-05T17:56:02.106Z"
}
```

`4799d6f0` is `docs-writer` and `01a32f1e` is `RM-077`, pseudonymised under
ADR-0041. **Neither is recoverable from the identity.** Resolving them needs the
ledger row, which is what §5 does.

### 3.2 `record_event` — one call per thing the agent did

```json
{"run_id": "run-…", "event_type": "Write",
 "payload_digest": "sha256:992f34…", "idempotency_key": "…"}
```

```json
{"chain_position": 2, "event_id": "01a072b2-6546-7996-8873-2171094d6df7"}
```

**`event_type` is the agent's tool name**, not a ledger event type. `record_event`
writes exactly one kind of event, `tool_call`, and the caller does not choose
it. Passing `"tool_call"` is refused, with that explanation:

```
INVARIANT_VIOLATION (not retryable): event_type "tool_call" spells one of
doc 02 §3's event types. record_event writes exactly one event type, tool_call,
and the caller does not choose it; the argument names the agent tool that was
invoked …
```

### 3.3 `sign_commit` — instead of `git commit`

```json
{"run_id": "run-…", "repo": "github.com/org/name", "staged_ref": "<tree>",
 "message": "…", "task_ref": "RM-077", "idempotency_key": "…"}
```

The repository must be in the MCP's workspace — the `innsegl-workspace` volume,
mounted at `/work`, laid out as `/work/<host>/<org>/<name>`. A repository the
server cannot see is the most common first failure.

**Note the inconsistency**: `register_agent` takes `task_id`, `sign_commit`
takes `task_ref`. Same value, two names, and the schemas are a protected
surface — so this is recorded here rather than fixed.

### 3.4 `retire_agent` — end the run

```json
{"run_id": "run-…"}
```

Effective immediately. The next `get_credential` for that run is refused:

```
RUN_ALREADY_RETIRED: run "run-dd41…" was retired at 2026-09-05T17:51:55.888Z;
retirement is effective immediately (IP §6.2)
```

Retiring is not cleanup you can skip. Until it happens the identity is live.

---

## 4. Check it from outside

```sh
make innsegl-verify-commit COMMIT=fafd1c410133265dd38df67d9a26015d50b4708d
```

This runs with **no route to the ledger**, which is the point (I5). Three
checks, all of them on the run above:

```
1. Fulcio certificate chain valid — verified
     certificate identity   spiffe://innsegl.dev/agent/fbbcd8eb/d0834c31/run-dd41951f…
     certificate validity   2026-09-05T17:51:55Z .. 2026-09-05T18:01:55Z
     validity evaluated at  2026-09-05T17:51:55Z (the log's signed integration time)

2. Rekor inclusion proven — verified
     log index 0, tree size 1, integration time signed by the log

3. Trailer matches certificate identity — verified
```

Ten minutes of certificate validity, and it is checked against the log's own
signed integration time rather than the verifier's clock.

---

## 5. Trace a run back

Attribution says *who*. The ledger says *what they did*.

```sh
curl -s http://127.0.0.1:8081/api/v1/runs/run-dd41951f222496a135241a77d1430237
```

The `run_registered` row carries `agent_type` and `task_ref` in clear, which is
how a pseudonym is resolved: **through the row, never through a key**. Every
`tool_call` for that run follows, in chain order, with its digest.

With the ledger you see everything. With only the commit you see nothing beyond
the identity — which is the intended split.

---

## 6. Do not lose the ledger

`runbooks/index-rebuild.md` §0 is the long version. The short version:

- A sealed segment proves **which events existed and in what order**. It cannot
  give back an event's `agent_type`, `task_ref`, `run_id` or anything else
  readable. Those live in Postgres and nowhere else.
- **There is no rebuild-from-segments-alone.** If every Postgres backup is gone,
  the chain of work is gone. What survives is attribution, still verifiable from
  git, Fulcio and Rekor.
- `make innsegl-purge` deletes it. `make innsegl-down` does not.

Backing the ledger up is tracked as #160 and is not shipped.

---

## Gaps this runbook had to work around

| gap | what to do instead |
|---|---|
| No `.mcp.json` ships, so an MCP client has nothing to point at. | Write one against `http://127.0.0.1:8080/`. It is a dotfile and `.gitignore` covers it. |
| `register_agent` takes `task_id`; `sign_commit` takes `task_ref`. | Pass the same value under both names. |
| The MCP workspace is empty on a fresh stack. | Place the repository under `/work/<host>/<org>/<name>` in the `innsegl-workspace` volume before calling `sign_commit`. |
| `innsegl init` cannot reach the SPIRE admin API in the shipped deployment (#156). | Not needed for this runbook. Only `innsegl init` needs it. |
| Nothing backs up the ledger (#160). | `pg_dump` by hand until it ships. |
