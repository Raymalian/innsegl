# ADR-0058: An agent's identity lifecycle is driven by its traffic

- Status: accepted; amended 2026-10-01 (see the Amendment)
- Date: 2026-09-28
- Deciders: the operator

## Context

IP §4 defines `observe_session(session_id, phase, cwd, agent_type?, task?)`:
`phase=start` resolves the workspace, registers the run and returns its
credential handle; `phase=stop` retires the run found by session id. Today
those two calls are made by harness shims — `SessionStart`, `SubagentStart`,
`PostToolUse`, `Stop` — each firing at a lifecycle point the harness chooses
to expose. IP §4 already names the failure this creates: "a session whose
start was refused lost its identity **and** every tool call it went on to
make," which is why a retry belongs inside `observe_session` itself rather
than in a shim — "a retry written in one shim is a retry every future shim
reimplements."

A spiked alternative sits the record at a different point: a gateway on the
harness's own model-request path (Claude Code's documented LLM-gateway
integration) rather than on its hook events. Measured 2026-09-28, across
seven spikes against a working gateway prototype:

| Question | Finding |
|---|---|
| Identity at the first model request, main and subagent | Issued every time |
| Main vs subagent | The harness's own per-request header is present only on subagent traffic |
| Parent → child link by containment (child's text found inside the spawning prompt) | Mislinked twice: once by a streaming-order timing bug, once because a parent's own brief legitimately quoted a child's job text as a substring |
| Parent → child link by exact equality (child's brief equals the spawning prompt) | Linked correctly once the rule was fixed, including a nested three-level tree |
| Resume, same session id, after a process kill | Same run continued; no new registration |
| Resume, same conversation fingerprint, new session id (fork) | A new run, linked to the one it forked from |
| Gateway restart mid-session | Same run on the far side; no new registration, given a persistent mapping |
| Silence past policy, then traffic again | Restored before the request was forwarded |
| No identity | The harness stopped after one refused request; no retries, no work done |
| End-of-session signal on the wire | None; nothing distinguishes a session ending from one merely quiet |

This does not touch identity issuance itself: **ADR-0053** already settled
that the only path to a run's credential is the MCP, attested through SPIRE,
never a workload's own claim — I1. What changes is which signal drives
`observe_session`'s two phases, and this ADR has to say, precisely, what
counts as a start, a resume, a fork, a lapse, a retirement and an adoption
when the signal is traffic rather than a hook firing.

Three prior ADRs bound the answer. **ADR-0052** already redefined
`run_expired` as a credential withdrawal, not a death, with restoration
whenever the run speaks again inside its horizon — this ADR must use that
state machine, not invent a second one. **ADR-0051** already made a
retired run's later resumption an adoption of its old work by a new run,
never a revival of the old one — same requirement. **ADR-0045** already put
`parent_run_id` on `run_registered`, required alongside `repo` and `branch`,
on the argument that where a run came from is a property of the run at the
moment it exists, not metadata bolted on after — checkable evidence, not an
index. **ADR-0041**'s pseudonymisation of `agent_type` and `task_id` in the
SPIFFE ID is untouched by any of this: this ADR changes when identity is
established, never what goes into it. **ADR-0025** already recorded that
nothing calling `register_agent` is an authenticated caller — every argument
it reads is a claim, rate-limited per asserted caller and alerted out of
band, not trusted outright; the harness's per-request agent-id header is the
same shape of claim, and it needs the same posture: named as asserted,
cross-checked by an independent witness, never taken as proof by itself.
That second witness is decided in **ADR-0057**, alongside this one.

## Decision

**1. Start is unchanged.** A run's identity begins at its first model
request, issued through the MCP over SPIRE exactly as ADR-0053 fixed it. The
gateway is a new *trigger* for `observe_session`'s start phase, not a new
issuance path; I1 is untouched.

**2. Main vs subagent is the harness's own per-request header.** No header
means the root agent; a header present names a subagent. This is
**harness-asserted**, not attested by SPIRE — the same caveat ADR-0025
already states for every `register_agent` argument — and it is not trusted
alone: a second, independent witness cross-checks the gateway's own record
of it, per ADR-0057. A disagreement between the two is recorded as an alert,
never silently resolved (I3).

**3. A parent link is exact equality, never containment.** A child's brief
equals the spawning `Agent` tool call's prompt, byte for byte; an agent is
never linked to its own spawn; the agent with no agent-id header is always
the root. Containment was measured to mislink twice in the same afternoon —
once as a timing bug (a spawn parsed only at the end of a stream, fixed by
parsing while it streams) and once for a reason no timing fix removes: a
parent's own brief can legitimately quote a child's job text as a
substring, and containment cannot tell a quote from a match. Equality has
no such failure mode; it was re-run against a nested three-level tree and
linked every level correctly. This decides the value ADR-0045 already made
required on `run_registered`; ADR-0045 decided the field, this decides how
its value is computed when the trigger is traffic.

**4. Resume is the same session, or the same conversation fingerprint: no
new run.** A process killed mid-task and resumed under the same session id
continued as the same run, across a gateway restart in between. This closes
the gap the hook-driven design had: previously, a resumed session was
indistinguishable from a new one and registered again.

**5. Fork is a known fingerprint under a new session: a new, linked run —
and recording what it forked from in the chain is a protected-schema
need, not a decision made here.** `register_agent` runs as it would for
any new run: a fork is a genuinely new identity, a new credential, a new
SPIFFE ID. What a run forked from is true at the moment the run is
created — ADR-0045's own argument for `parent_run_id`, applied to a
different lineage — so making that fact checkable by a third party needs a
protected addition to `run_registered` (or an equivalent doc 02 does not
yet name). This ADR does not name that member or claim a schema version
for it: the operator has bundled every protected-schema addition this
epic needs into **one** doc 02 change — one `schema_version`, one
migration attestation — decided together before E15 starts, not ADR by
ADR. Until that bundled change lands, a fork's origin lives only in the
gateway's mapping table (decision 9): insert-only, but operational state,
not tamper-evident, and outside I5's third-party verification. A fork is
also not a subagent — no spawning tool call names it, and the run it
forked from may still be active, lapsed, or already retired — so whatever
member the bundled change eventually adds must not be `parent_run_id`,
which already means something else.

**6. Lapse and restore follow ADR-0052, with one new gate: restore happens
before the request is forwarded, and a failed restore refuses the
request.** Traffic from a lapsed run must clear identity restoration first.
If the ledger or SPIRE cannot be reached, the gateway does not queue the
request and does not forward it provisionally — it refuses,
`IDENTITY_UNAVAILABLE`, retryable, the same class and the same fail-closed
reasoning IP §6.1 already requires when a run has no identity at all.
ADR-0052's four states, and the rule that a withdrawal stands only until an
event the run itself causes contradicts it, are unchanged; this only fixes
the moment in the request path the gateway has to check them.

**7. Retirement has three sources, expected to fire in this order:**

   a. the harness's own end-of-session signal, for the main agent — a
      `SessionEnd` hook, the second small harness hook this design needs,
      beside the one this epic already needs on the commit path for exact
      attribution;
   b. hand-back — the spawning tool call's result reaching the parent — for
      a subagent, which has no session of its own to end;
   c. a silence horizon, default seven days from the run's last recorded
      activity, configurable (mirroring ADR-0052's own withdrawal-horizon
      setting), as the backstop for when neither signal arrives — a crash,
      a killed process, a shim that never ran.

   The backstop is the one place this ADR writes `run_retired` from an
   inference rather than an observed signal, and ADR-0052 is right that
   silence is not death. What makes this safe rather than a contradiction of
   it: the backstop answers the same question ADR-0052's "abandoned" already
   answers — what this deployment will do, not what happened to the agent —
   and being wrong about it costs nothing worse than an adoption where a
   resume would otherwise have happened (decision 8; ADR-0051 unchanged).
   Under the stated defaults the backstop fires before ADR-0052's own
   abandon horizon would be reached, so in the common case a lapsed run
   either resumes or is retired by this backstop, and "abandoned" is read
   only where an operator has raised this horizon past the other or lowered
   it. The two clocks are independent settings; neither ADR supersedes the
   other.

**8. Resumption after retirement is adoption, never revival.** Traffic that
names a retired run's session or fingerprint starts a new run. Its own work
is its own; picking up the retired run's uncommitted work, if any, still
goes through `sign_commit`'s `adopt_run` and the `run_adopted` event exactly
as ADR-0051 describes. The retired run stays retired.

**9. Mapping state is persisted in the existing ledger database, not a new
store.** Session id → run id, conversation fingerprint → run lineage, and
the lapse and retirement clocks live in the same database the hash chain
already uses, not a store of their own. This is operational routing state,
the same relationship idempotency claims already have to the chain: what
has to be independently checkable is the ledger event a lookup resolves to,
never the lookup table itself. A gateway restart must find the same
mapping it left and continue the same runs, exactly as a restart today
finds the same registered entries.

**10. Run tokens are held only by the gateway.** No agent-readable token
file exists on the developer's machine. There is nothing local left to
read, which is what closes the same-user token gap this design set out to
close.

**11. No identity, no request.** A request the gateway cannot resolve to a
live, restorable identity is refused before it reaches the model provider —
a clear reason, never queued, never forwarded provisionally. This is IP
§6.1's own rule — an agent without identity does no attributed work, and
that must be impossible, not merely inconvenient — applied at the point
traffic now passes through.

## Alternatives considered

- **Keep the hook-driven lifecycle** (`SessionStart`, `SubagentStart`,
  `PostToolUse`, `Stop` deciding start and stop). Rejected on the two gaps
  measured against it directly: a shim that fails or is skipped leaves an
  agent working with no identity and no record of any of it, which is why
  IP §4 already pulls retry logic into `observe_session` itself rather than
  trust four independent shims to agree; and a resumed session registered
  as a new run every time, which the gateway's per-request view of session
  id and conversation fingerprint fixes without any shim change.
- **Transcript-driven**: read the harness's own session log after the fact,
  rather than sit on the request path. Rejected: by the time a transcript
  exists to read, the request has already happened, so there is nothing
  left to refuse — it cannot enforce decision 11 at all, only describe what
  already got through. It also depends on an undocumented, harness-internal
  file shape with no support contract, where a gateway sits on the harness's
  own documented model-request path.
- **A new run for every resume**, the hook-era default. Rejected: measured
  to fragment one continuing task into a separate identity each time its
  session was resumed, against the product's own goal of one page per
  agent and against reading a run as one continuing purpose rather than one
  process lifetime.
- **Containment for the parent link.** Rejected on the measurement in
  decision 3: it mislinked a nested subagent to the wrong parent because a
  parent's own brief happened to contain the child's job text as a
  substring, and no amount of fixing the streaming-order bug removes that
  second failure. Exact equality does not have it.

## Consequences

- Recording a fork's origin in the chain is a protected-schema **need**,
  not a decision this ADR makes: the operator has bundled it with every
  other protected-schema addition this epic needs into one doc 02 change —
  one `schema_version`, one migration attestation, one set of updated
  golden fixtures, decided together before E15 starts. This ADR names
  neither the member nor the version. Until the bundled change lands, a
  fork's origin is operational state only — the gateway's mapping table,
  decision 9 — and carries none of I5's third-party verification.
- ADR-0052's four-state machine is unchanged. This ADR adds one more caller
  of `run_retired` — the silence backstop — beside the ones that already
  exist (the harness, a human, an observed kill). Its safety rests on
  decision 8, not on the inference behind it being reliable; that is stated
  here rather than left implicit.
- Enforcement now sits in front of every model request, not only at
  `register_agent` and `get_credential`'s own boundaries. A gateway outage
  now blocks model access outright rather than letting a stale local
  credential carry an agent past it — the same fail-closed trade IP §6.1
  already made for every other tool, extended to a point that did not exist
  before.
- The session/fingerprint mapping is new, unprotected operational state in
  the ledger database. Its retention is not decided here — at minimum it
  must outlive the longest silence horizon in use — and is left to the
  implementation ADR that builds it.
- The hook shims are not removed by this decision. Until they are, both
  lifecycles can run at once and can disagree; a disagreement between them
  is an alert under decision 2's principle, not a silent choice of one over
  the other. Reconciling or retiring the shims is separate, later work.
- **Exit cost.** Decisions 1, 2, 4, 6, 8, 10 and 11 change only what
  *triggers* existing behaviour; reverting them returns the trigger to the
  hooks with no change to `run_registered`, `run_expired`, `run_retired` or
  `run_adopted`. Decision 5 costs nothing to reverse today: while a fork's
  origin lives only in the mapping table, dropping it is an operational-state
  change like any other. Once the bundled protected-schema change lands and
  starts recording it in the chain, that addition inherits the same
  append-only irreversibility as every other doc 02 member (I4) — but that
  cost belongs to the ADR that makes the bundled change, not to this one.
  Decision 7's backstop is cheap to turn off — raise its horizon past any
  realistic silence, or stop calling it — but not free: runs it already
  retired stay retired, and their owners, if they return, adopt rather than
  resume, permanently.
- **Tests to write, first.** Exact-equality parent linking against both
  measured mislink cases; resume as the same run for both a repeated
  session id and a repeated fingerprint, and as a new linked run for a
  fingerprint under a new session id; restore-before-forward, with a
  refusal when restore fails and no partial forwarding; each of the three
  retirement sources firing independently, including the horizon ordering
  in decision 7; adoption of a backstop-retired run; the mapping surviving
  a gateway restart; a request refused end to end with no model call made
  when no identity resolves.

## Amendment (2026-10-01): where the working directory comes from, and how a refusal reads

**What changed.**

- **The working directory comes from a hook, not the conversation.** A new
  run is registered from the directory the harness states in its own hook
  input: `session_id`, `cwd` and, for a subagent, `agent_id`, structured
  fields on every hook event. `innsegl hook session` runs on
  `SessionStart`, `UserPromptSubmit`, `SubagentStart` and `CwdChanged` and
  posts them to a local gateway endpoint; the gateway keeps them in memory,
  per session and agent. The request body is no longer read for a
  directory at all.
- **Restoring a run reads the chain.** A restore replays the run's own
  registration from what `run_registered` recorded (agent type, task,
  repository). It needs no directory.
- **A refusal says whether to try again.** Decision 11 is unchanged:
  nothing is forwarded. What changed is the status. A refusal for a missing
  input the harness will supply (no directory stated yet) or for a
  dependency outage (a retryable IP §4 class, or a connection that could
  not be made) is 503 with `Retry-After` and a reason naming the cause. A
  refusal of the request itself stays 403.
- **A stopped stack is named, not just refused.** When the gateway cannot
  be reached at all, the session hook stops the user's prompt before it is
  sent and says what is down and the two ways out: start the stack, or
  `install.sh --pause`, which sets the managed settings aside unchanged
  until `--resume`.

**Why.** Reading the directory out of the conversation's prose broke when
the harness moved the statement: a session resumed after a summary states
its directory only in later messages, and every request was refused as not
retryable. That refusal could not clear on its own, and the only way out was
editing the managed settings by hand. The hook input is the harness's
structured channel for the same fact.

**What still holds.** Fail-closed is unchanged: no request is forwarded
without an identity, and the pause is an operator action behind the
administrator boundary that already guards the managed settings. A stated
directory is a harness claim of the same class as the agent-id header
(decision 2): it still goes through `describe_workspace`, which admits only
a git worktree under the projects mount and inside the admin scope.
