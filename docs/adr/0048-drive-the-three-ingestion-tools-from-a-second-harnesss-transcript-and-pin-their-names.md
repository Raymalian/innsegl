# ADR-0048: Drive the three ingestion tools from a second harness's transcript, and pin their names

- Status: accepted
- Date: 2026-09-13
- Deciders: the operator, on a live run measured end to end
- Context: E11, closing RM-130

## Context

E11 moved the derivation out of the reference shim and into the MCP: three new
tools — `describe_workspace`, `observe_tool_call`, `observe_session` — replaced
807 lines of shell with 29 local computations. The stated goal was that a shim
for any harness should be roughly thirty lines of "read the event, forward it,
exit 0".

None of that demonstrated anything on its own. The tools were extracted **from**
the reference harness, so the reference harness was always going to fit them.
A surface that only one caller can drive has solved nothing, and until something
else had driven it, "harness-neutral" was a claim.

Their names were deliberately left out of `scripts/protected-surfaces.sh` for
the same reason. That gate fails on a partial set and does not forbid an
additional name, so adding a tool costs no major release — which means a name
can wait until it has been used. A name pinned before a second caller has
touched it is a name pinned on a guess.

## Decision

Write a shim for a second harness, drive a real session through it end to end,
and only then pin the three names.

### The harness, and the route

The second harness is **Codex CLI 0.153.0**, and it has **no hook system at
all**: no callback, no gate, no mid-session extension point this shim can use.
What it does offer is a rollout transcript — one JSONL file per session, written
as the session runs:

```
{"timestamp": ..., "type": "session_meta"|"response_item"|"event_msg"|..., "payload": {...}}
```

whose payloads carry `session_meta` (the session's id and its working
directory) and `custom_tool_call` / `function_call` (each tool the model
invoked, with its name and its input).

So the route is **post-hoc transcript ingestion**, not hooks:

| transcript record | tool call |
|---|---|
| `session_meta` | `observe_session(phase=start, session_id, cwd, agent_type)` |
| each `custom_tool_call` / `function_call` | `observe_tool_call(run_id, tool, body)` |
| end of file | `observe_session(phase=stop, session_id)` |

This was chosen over any cleverer integration because it is the **weakest**
assumption available. It is what a harness that cooperates in no way whatever
must do, and it exercises all three tools without the harness knowing innsegl
exists. Anything the MCP still left a caller to work out for itself would have
surfaced immediately, because nothing about the first harness could be leaned
on. A second hook-driven shim would have proved much less.

### What the route cannot do, and what that costs

**There is no commit refusal, and there cannot be one.** The reference shim's
`PreToolUse` gate exits 2 and the harness blocks the tool call; E11 already
holds that this one thing can never move into the MCP, because blocking a call
is the harness's own power. A transcript is read after the session is over. By
the time the shim sees `git commit`, the commit exists. No mechanism was
invented to paper over this; the refusal is simply absent.

The cost is exact and it is the difference between prevention and detection:

| | reference harness | transcript ingestion |
|---|---|---|
| an unattributed commit is | impossible | possible |
| the ledger records that the run made it | yes | yes — it is a tool call in the transcript |
| the commit object carries a trailer and a signature | yes | no |
| what stops it reaching the trunk | the shim, at commit time | `scripts/verify-branch.sh`, at merge time |

Attribution survives; enforcement moves from commit time to merge time.

**The stop-time capture is what partly answers this.** A session that ends with
uncommitted work has that work signed under the run that did it (ADR-0046). It
is the only signing a post-hoc reader can honestly perform — the tree is still
there to be signed — and it is why a transcript-driven run carries a signed
commit at all.

## What was measured

A throwaway repository, a real session driven through the second harness, and
the shim run once over the transcript it produced.

**The run, read back out of the ledger** — event sequence, chain positions
18195–18202:

```
run         run-3bd7304b…      agent_type rollout   task main   status retired
spiffe      spiffe://innsegl.dev/agent/5babb2eb/1dbdbb97/run-3bd7304b…
repos       example.test/scratch/rm130-probe          commits 1

18195  run_registered
18196  tool_call          tool exec   sha256:ad5436b8c9294ed5…
18197  tool_call          tool exec   sha256:ca06adc0c646174e…
18198  tool_call          tool exec   sha256:b68dada8c27aea8d…
18199  credential_issued
18200  commit_intent
18201  commit_recorded    047850f759e7ff0c69f7349a…
18202  run_retired
```

**Against a reference-harness run** taken from the same ledger, which is the
acceptance criterion — indistinguishable:

| | second harness | reference harness |
|---|---|---|
| sequence | `run_registered` → `tool_call`×3 → `credential_issued` → `commit_intent` → `commit_recorded` → `run_retired` | `run_registered` → `tool_call`×4 → `credential_issued` → `commit_intent` → `commit_recorded` → `run_retired` |
| `source` on every event | `mcp` | `mcp` |
| `schema_version` | 2 | 2 |
| tool-call bodies | on the operator's volume, digest-named, `0600` | the same |

The only differences are the `agent_type` string and the tool names, both of
which are the harness's own vocabulary and neither of which is a schema member.
The event schema did not change; E11 was additive throughout.

**The commit, verified with no route to the ledger** — a container on the
Sigstore network only, holding a read-only copy of the tree and no database
credential:

```
VERDICT: VERIFIED

1. Fulcio certificate chain valid
     certificate identity  spiffe://innsegl.dev/agent/5babb2eb/1dbdbb97/run-3bd7304b…
     validity evaluated at 2026-09-13T17:02:33Z (the log's signed integration time)
2. Rekor inclusion proven
     log index   532        tree size 535
     tree root   0245ee13eff979757a36c8680689c0bd3a1c5b0aa51bb1464d66fbe6a17ccefe
3. Trailer matches certificate identity
     Agent-Identity trailer == certificate URI SAN
```

**The dashboard**, for the property the epic's exit criteria name: the run
renders with a populated activity log — three tool calls, the credential, the
intent, the recorded commit with its Rekor index, and the retirement, each
reporting "chain link holds".

## What the surface cost

The shim is one file. Counted as executable lines — no comments, no docstrings,
no blanks:

| | lines |
|---|---|
| imports and environment | 8 |
| MCP transport: handshake, SSE frame, one `call` helper | 26 |
| **the shim itself: read the record, forward it** | **15** |
| stop-time capture (`git status`, `git add`, invoke the signer) | 11 |
| stop, and print the run | 2 |
| total | 62 |

**The ingestion is 15 lines against a ~30-line target.** It derives no branch,
folds no task, parses no remote, digests nothing, writes no marker file and
knows nothing about where a body is kept. It does not even need the reference
shim's one remaining local computation — the remembered run id — because a
single process reads the whole transcript and the run is a local variable.

Two things are larger than they should be, and both are reported rather than
hidden.

**The transport is 26 lines and the MCP does not reduce it.** Every shim
reimplements `initialize`, the `notifications/initialized` notification, the
`Mcp-Session-Id` header and the `data:` line of an SSE frame. It is boilerplate,
not derivation, and it is the same 26 lines in any language — but it is still
larger than the work it carries, and it is a fixed cost per harness.

**The stop-time capture is 11 lines of git plumbing in a shim, and it should not
be.** The reference shim has the same three commands for the same reason;
RM-129's closing note already hands the capture on as work belonging in the MCP.
A second shim needing it independently, written against a completely different
harness, is the measurement that settles it: **this is the next thing that
belongs in the MCP.** A tool that took a run id and a working directory and did
the capture itself would take both shims to the target and would remove the
only git command either of them runs.

## The names are now pinned

`describe_workspace`, `observe_tool_call` and `observe_session` joined
`PROTECTED_VOCAB` in `scripts/protected-surfaces.sh` and surface 4 of
`VERSIONING.md`. From here they change only in a major release with a migration
attestation (doc 08 §3). Adding a ninth tool is still not a change to the
surface; renaming or removing one of the eight is.

A pin that has never been observed failing is not known to be live, so the gate
was watched both ways. Before the pin, renaming `observe_tool_call` in the
shipped source passed in silence — `mcp-tool 5 5 OK`. After it, the same rename
is caught twice over:

```
FAIL: mcp-tool: 7/8 present. A protected string set is never partial;
      the missing member was renamed or dropped: observe_tool_call
      mcp-tool  7  8  BREACHED (partial set)

VERDICT  SURFACE    KEY
CHANGED  mcp-tool   observe_tool_call
```

That is phase 11 of `scripts/protected-surfaces-selftest.sh` (OPS-023).

## Consequences

- E11's claim is now a measurement. A harness with no hook system reaches the
  same three tools through a 15-line shim and produces a run the ledger cannot
  tell apart from a reference-harness run.
- The three tool names are frozen.
- Post-hoc ingestion is a supported route with a stated limitation. A deployment
  that adopts it gets attribution and an activity log, and gets its enforcement
  at merge time rather than at commit time. That is a real reduction and it is
  written down rather than glossed.
- The capture is next. It is the last git command in either shim and the only
  local computation the second shim could not avoid.

## Alternatives considered

**A second hook-driven harness.** Rejected: it would have re-tested the
mechanism the tools were extracted from and shown nothing about a harness that
cannot call out at all. The hardest case is the informative one.

**Inventing a refusal for the post-hoc route** — a wrapper around the harness
binary, or a git hook installed into the repository. Rejected on the issue's own
terms: a git hook is not the harness blocking a tool call, it is a different
gate with different failure modes, and describing it as the refusal would have
misreported what this route can do. The limitation is stated instead.

**Reading whichever transcript is newest.** Rejected. The shim takes an explicit
path and never guesses, because a shim that reached for "the most recent
session" would ingest whichever one happened to be newest — and a ledger is not
a place to put something by accident.
