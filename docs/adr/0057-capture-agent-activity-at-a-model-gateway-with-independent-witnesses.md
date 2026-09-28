# ADR-0057: Capture agent activity at a model gateway, with independent witnesses

- Status: proposed
- Date: 2026-09-28
- Deciders: the operator

## Context

The mission (doc 01 §1) is to attribute every action and commit, not only
commits. The harness hooks this project has used until now cannot do that.
A hook fires on the events a harness chooses to emit, and three kinds of
activity never reach one: a command that fails, an action the harness itself
refuses, and the brief the agent was given in the first place. A hook also
sees only its own harness's shape, so every new harness is a new hook
contract to keep matching.

A local spike (`docs/decisions/model-gateway-spike.md`) measured what a
reverse proxy in front of the model API sees instead, by running one harness
with its model endpoint pointed at a local recorder and comparing the two.

- All model traffic passed through, subagents included: 7 of 7 requests in
  one session, distinguishable from the main agent by a per-request header.
- The brief was visible twice over: as the first user message, and as the
  spawn prompt inside a subagent's `Agent` tool call.
- A failed command surfaced as a tool result carrying `is_error` with the
  exit code; a refused action surfaced the same way, carrying the harness's
  own refusal text. Both are ordinary content in the traffic a gateway
  already sees, not something it has to ask for separately.
- Every new agent got a stable identity at its first request, tied to the
  (session, agent) pair the traffic itself carries — 3 of 3 in one run,
  including the correct parent link once the gateway parsed spawns while
  streaming rather than only at the end.
- A workspace snapshot taken before each request, against a private git
  index, captured a create, an edit and a delete back to the original state
  — including a change that was never committed.
- Attributing a commit to the exact agent that made it, even when two agents
  ran the identical command at the same moment, held 3 of 3 once a
  `PreToolUse` hook carried the tool_use id into the signer and the gateway
  cross-checked it against the model response it had relayed.
- Reasoning is not available: the provider returns a signature over it, not
  its content. And anything a harness does without telling the model is
  outside this path by construction — a hook action, or a side effect the
  harness never reports back.

The threat model written alongside this design (doc 04, reviewed per §6
because the gateway is a new trust boundary) covers the gateway on its own
terms — what it can be tricked into, what it must refuse, what stays
residual regardless of design. This ADR is about the capture *approach*, not
that review; it cites doc 04 rather than repeating it.

## Decision

Capture agent activity from the model traffic itself, through a gateway
component the harness is pointed at instead of the model provider directly.
The gateway forwards every request unchanged and records what passed: the
brief, every tool call and its result (success, failure, or refusal), and
the tree of who spawned whom.

Two more witnesses corroborate the gateway rather than being trusted in its
place:

- **Workspace snapshots.** Before each request is forwarded, the working
  tree is snapshotted against a private index, so what changed on disk is
  recorded independently of what the conversation claims happened —
  including a change that is later reverted or never committed.
- **The harness's own telemetry** (OpenTelemetry, where a harness emits it)
  sees tool decisions and results from inside the harness process, not from
  the wire.

A disagreement between witnesses — an edit on disk the conversation never
asked for, a tool result one witness saw that another did not, a commit with
no matching tool call — is recorded as an alert. It is never silently
resolved in favor of whichever witness spoke. This is the same "verify, do
not trust" stance the ledger already takes toward its own history, applied
to the act of capture.

Capture is an adapter, not a dependency the core is built on. Identity
issuance, signing and the ledger do not know which witness produced a given
record. If a harness ever stops allowing its model endpoint to be
redirected, the telemetry witness becomes primary and the harness's own
hooks carry enforcement; the ledger's shape does not change. How an agent's
identity moves through that traffic (registration, resume, lapse, fork) is
the lifecycle ADR (0058); how a specific commit is tied to the tool call
that made it is the commit ADR (0059); where the gateway runs is the
placement ADR (0060).

### Against the exemptions and invariants

- **E2 (no runtime behavior control).** The gateway observes and forwards;
  it does not decide what an agent may do. Its one refusal is orthogonal to
  behavior: no identity, no forwarding. That is E2's boundary, not a
  crossing of it — the gateway still proves nothing about how an agent
  behaves, only records what it did.
- **E4 (no payload storage in the ledger).** The ledger keeps digests and
  references, as it already does for commits. What the gateway captures —
  request and response bodies, snapshots — stays in local stores on the
  operator's machine, never in the ledger itself. Nothing here widens what
  the ledger holds.
- **I3 (no action without a record).** This is the decision's point: hooks
  left failures, refusals and the brief unrecorded, and the gateway closes
  that gap for the paths it sees. What it cannot see (below) stays outside
  I3's reach, honestly, rather than papered over.
- **I5 (verification trusts nobody, including this system).** A second and
  third witness recorded independently of the gateway are what make a
  gateway compromise or bug detectable rather than merely embarrassing — a
  fabricated record has to fool the traffic, the disk, and the harness's own
  telemetry at once, and any one holdout is an alert.

### What stays unrecorded

- **Model reasoning.** The provider returns a signature over it, not its
  content, to any recorder on the wire. No design choice here changes that.
- **Activity outside the model loop.** Anything a harness does without
  telling the model — its own internal bookkeeping, a side effect never
  reported back in a tool result — is invisible to a witness built on model
  traffic, disk state and harness telemetry alike. This is a stated limit,
  not a gap being closed later; doc 04 records it as residual rather than as
  a defect to fix.

## Alternatives considered

- **Hooks only (the status quo).** This is the problem statement, not an
  alternative: hooks fire on what a harness chooses to emit, which measurably
  excludes failures, refusals and the brief, and ties capture to one
  harness's event shape at a time.
- **Transcript files.** Some harnesses write a local transcript of the
  conversation. Its format is not a stable interface — it is documented
  nowhere as one, changes without notice between harness releases, and nothing
  obliges a harness to keep writing it in a shape any two versions agree on.
  Building capture on it means re-discovering the format on every upgrade,
  with no failure signal when it silently changes.
- **Telemetry only, no gateway.** OpenTelemetry is real evidence and stays as
  a witness, but proving it captures failures and refusals, or the brief, the
  same way the gateway does was not attempted in the spike — and telemetry is
  opt-in per harness, off by default, where the gateway sees traffic as soon
  as the harness's model endpoint is pointed at it. It becomes primary only if
  the gateway path is ever closed off; it does not replace starting there.
- **OS-level process or network audit.** Watching what a harness's process
  does at the OS level (syscalls, arbitrary network capture) was not spiked
  and answers a different question: it would show that traffic moved, not
  what a brief said, which request produced which result, or which agent a
  tool call belonged to. Recovering that meaning from raw traffic is what the
  measured approach already gets for free by sitting at the one layer — the
  model API — where a harness already structures it that way.

## Consequences

- Capture no longer depends on keeping pace with each harness's hook surface;
  it depends on a harness allowing its model endpoint to be redirected, which
  is documented, supported behavior for the harnesses measured so far.
- The gateway becomes a new trust boundary and a new single point of denial:
  no identity through it means no forwarding, so a gateway outage stops
  attributed work rather than degrading it quietly. That trade is deliberate
  and is doc 04's to carry, not this ADR's to relitigate.
- A fabricated or missing record is now something two more witnesses can
  catch, at the cost of running and reconciling three sources of truth
  instead of one. Disagreement handling (what counts as an alert, how it is
  resolved) is real, ongoing work, not a detail left to implementation.
- **Exit cost.** Reversing this means going back to harness hooks as the
  primary source, which is a straightforward regression in capability (loss
  of failures, refusals, and the brief) but not a data-shape change: nothing
  the gateway records asks the event schema (doc 02) for anything the ledger
  does not already have a place for. No protected string changes with this
  decision.
