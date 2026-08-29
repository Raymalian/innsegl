# ADR-0025: Rate-limit `register_agent` per asserted caller, meter it on the ledger appender, and raise the trip out of band

- Status: accepted
- Date: 2026-08-29
- Deciders: Mike

## Context

IP §6.10 states the requirement in one sentence:

> Rate-limit `register_agent` per caller; a runaway loop must not exhaust SPIRE
> or flood the ledger silently — test the limit and the alert.

Doc 04 §3 gives the same thing as an abuse case, AB-07 — "flood
`register_agent` to exhaust SPIRE / bloat ledger" — with the control "rate
limit + alert" and the test MCP-013. Doc 04 §2's MCP row repeats it under
**D**oS: "register floods → rate limit + alert (MCP-013)". Doc 05 §2 lists
"rate-limit trips" among the monitoring minimums, and adds the sentence that
turns out to settle the hardest question below: "Every alert in this list
corresponds to an event type **or test** in the catalog."

Four forces shape the answer, and three of them are constraints this project
has already hit and recorded.

**1. There is no authenticated caller.** E1 exempts authorization from v0.1.
ADR-0019 recorded the same gap from the other side: `get_credential` binds a
credential to the run named *in the request*, and nothing proves the requester
is that run. So whatever a bucket is keyed on is a value the caller asserts.
Doc 04 §4 already says the equivalent of `task_ref`: it is "a claim, not a
fact".

**2. A global limit is the attack, not the defence.** A5 makes availability a
first-class asset and doc 04's opening note says the fail-closed design
"converts many attacks into DoS". A single global counter on `register_agent`
means one runaway agent refuses every other agent in the deployment — resource
exhaustion achieved by the control.

**3. The event schema is closed and has no type for this.** Doc 02 §3's eleven
types are protected; doc 02 §7 makes a twelfth a major schema version with a
migration attestation. This project has hit the same wall three times —
ADR-0013 (no type for an unattributed SPIRE entry), ADR-0019, ADR-0021 — and
each time refused to force a wrong type.

**4. IP §4's error vocabulary is closed and has no class for "slow down".**
ADR-0016 wrote the eleven classes and their `retryable` flags out one row at a
time, explicitly so that a twelfth "has to be decided rather than parsed".
ADR-0017 and ADR-0018 both hit a situation with no fitting class and both
flagged it rather than inventing one.

One further constraint is structural rather than documentary: the issue that
owns this work owns `internal/mcp/ratelimit.go` and does not own
`register_agent.go`, so the meter has to install itself through
`RegisterAgentConfig` rather than by editing the tool. That turned out to
matter for a reason that has nothing to do with file ownership; see the
Decision's point 2.

Invariants in play: I3 (no action without a record) is why a refusal must not
be silent; I4 (nothing is ever deleted) is why a flooded ledger is permanent
damage rather than a cleanup task; I1 is what a SPIRE entry per flooded call
consumes.

## Decision

**1. The bucket is keyed on the pair (`agent_type`, `task_ref`), and that is
stated as a claim.** These are the two `register_agent` arguments that name who
is registering and what for. `idempotency_key` is excluded: it is the value the
flood varies, and keying on it produces a limiter that never limits anything.

What this protects against, stated exactly: a **runaway loop** — a bug, which
is the realistic form of AB-07 — keeps asserting one `agent_type` and one
`task_id` while cycling keys, so it is bounded, and bounded inside its own
bucket with no effect on any other caller.

What it does **not** protect against, stated equally exactly: an **adversary**
who varies `agent_type` or `task_id` gets a fresh bucket per variation and
defeats the limit entirely. Until callers are authenticated (E1 work), this is
a runaway-loop guard, not an anti-DoS control, and it is not to be recorded as
closing AB-07 against an adversary. AB-07's *stated* control is "rate limit +
alert" and that is what ships; the residual is named here rather than in a
report nobody re-reads.

**2. The meter sits on `RegisterAgentConfig.Ledger`, inside the idempotency
claim.** `RateLimitRegisterAgent` returns a copy of the configuration whose
appender is metered, and refuses rather than returning an unmetered one.

Two consequences, both load-bearing:

- ADR-0018 fixed the order `run_registered`-then-SPIRE-entry, so a refusal at
  the appender reaches **neither** system. One meter protects both. MCP-013
  asserts this positively — SPIRE is never even *asked* — so a future
  reordering fails the test rather than silently halving the protection.
- A **replay is never metered.** ADR-0017's store answers a completed key from
  the record without re-executing the tool, so the meter never sees it. This is
  not a side effect, it is the decisive argument for the placement: a limiter
  ahead of the claim would refuse a crash-replay, and IP §6.6 requires that
  replay to return the original result. The control would break the invariant
  it exists to protect.

The cost, stated rather than hidden: a refused call still claims and releases
an idempotency row, so a flood reaches Postgres as two cheap statements per
call. It does not reach the append-only chain at all, which is what MCP-013 is
about and what I4 makes permanent.

**3. The algorithm is a generic cell rate algorithm — one timestamp per
caller** — because a fixed window lets a caller spend a full allowance in the
last instant of one window and again in the first instant of the next, which is
twice the configured rate at exactly the moment a flood begins; and because it
is exact in integer time, so the boundary MCP-013 asserts (call N admitted,
call N+1 refused) is the same on every platform.

The shipped default is **60 calls per minute per caller**, chosen against doc 05
§4's sizing rather than taste: 10⁶ runs a year is ≈0.03 registrations a second
across the whole deployment, so one a second for a single caller is some thirty
times the entire projected fleet rate, while still admitting a sixty-way CI
fan-out on the first try.

**4. The caller table is bounded, and the bound may never become a refusal.**
The key is caller-supplied, so an unbounded map is a memory-exhaustion vector —
AB-07 one layer down. `DefaultRateLimitMaxCallers` is 4096. Eviction drops
refilled buckets first (a full bucket and an absent one admit identically, so
that costs nothing), and if that frees nothing it evicts the bucket **closest
to refilling** — never the one furthest from it, which is by construction the
flooding caller's. Eviction therefore only ever *grants* credit and never
refuses a caller: refusing on a full table would let anyone minting distinct
keys deny service to every caller not already in it, which is force 2 again.
`Stats().Evicted` is how an operator sees the table is under pressure and the
limit is weaker than configured.

**5. The trip goes to an alert sink, not to the ledger.** No doc 02 §3 type
fits, and the reasoning is written out in `ratelimit.go`: `tool_call` would
record work that did not happen *and* would be the ledger flood the limit
exists to prevent, written by the limit itself; `ledger_drift_detected`
requires a `subject_event_id` and a refusal's entire content is that no event
was written. So the trip is delivered through `RateLimit.Alert` — defaulting to
an error-level `slog` line that says explicitly that the ledger does not hold
it — which is the pattern RM-019 established for the drift kind ADR-0013 could
not record. Doc 05 §2 anticipates exactly this: rate-limit trips are in the
monitoring minimums, and every alert there corresponds to "an event type **or
test**". This one corresponds to MCP-013.

One alert per trip **episode**, not per refused call: a line per refusal is a
log flood, the same failure in a different sink. The episode re-arms when the
caller is served again, so a second incident pages again. `RateLimitStats`
(`Admitted`, `Refused`, `Trips`, `Evicted`, `Callers`) is the monitored surface
for everything else, and `Trips` is doc 05 §2's metric by name.

**6. A refusal is `IDENTITY_UNAVAILABLE`, retryable, scoped to the run.** IP §4
has no class for "slow down". Of the eleven, only four are retryable under
ADR-0016, and `retryable: true` is the instruction this situation warrants —
waiting is precisely what makes the call succeed, and a `false` would spin an
agent against an answer that *will* change. Of those four, `SIGNING_UNAVAILABLE`
and `TRANSPARENCY_UNAVAILABLE` name Sigstore, which is untouched.
`LEDGER_UNAVAILABLE` is the tempting one, because the meter sits on the ledger
appender — and it is rejected precisely because of that: it would send an
operator to Postgres during a flood, which is the wrong page at the worst
moment. `IDENTITY_UNAVAILABLE` is the one whose *fact* is true — no identity is
being issued to this caller right now — it is the class IP §6.1 already pairs
with `register_agent`, and the message carries the true reason and the wait.
The refusal names the derived `run_id`, matching what `register_agent` already
does when a ledger outage stops a registration that likewise created no run.

## Alternatives considered

- **Key the bucket on the transport connection or source IP.** Rejected: doc 05
  §2 puts the MCP behind a reverse proxy and runs replicas, so the address seen
  is the proxy's for every caller — a per-caller limit that is a global limit in
  production, which is force 2 in disguise. It is also not more authenticated
  than the arguments: an attacker who can vary `agent_type` can generally vary
  source address too.
- **Key on `idempotency_key`.** Rejected: it is the field the flood varies by
  construction (see `registerAgentRunID` — a new key is a new run, a new entry
  and a new event), so every flooded call would land in its own empty bucket.
- **Key on the SPIFFE ID or the derived `run_id`.** Rejected for the same
  reason: both are functions of the idempotency key, so both are per-call, and
  a per-call bucket is not a limit.
- **Stop and ask the human, because "per caller" is undefined while E1 exempts
  authorization.** Seriously considered — the project rule is that a spec
  ambiguity is a question, not permission. Rejected on the ADR-0016 precedent:
  IP §6.10 names the control and doc 07 numbers its test, so declining to
  choose ships AB-07 uncontrolled while the question is open. The choice is
  made here, its exact limits are written in the Decision rather than implied,
  and the follow-up is recorded below the way ADR-0004 and ADR-0016 record
  theirs. No spec document is edited.
- **A global limit as well as the per-caller one, as a backstop against the
  key-varying adversary.** Rejected for v0.1: it is the denial of service in
  force 2, deliberately installed. A global *ceiling* far above the per-caller
  limit is a defensible thing to want, but it only becomes meaningful once
  callers are authenticated — before that its only effect is to convert a
  key-varying attack into an outage for everybody, which is a strictly worse
  outcome than the flood it stops. Recorded as follow-up 3.
- **Meter ahead of the idempotency claim, where a refusal costs no Postgres
  round trip.** Rejected: it refuses crash-replays, breaking IP §6.6's
  requirement that a replay return the original result. The saving is two cheap
  statements against a table that is not the ledger; the cost is the invariant.
- **Meter on the SPIRE client instead of the ledger appender.** Rejected:
  ADR-0018 writes the ledger first, so a meter there admits the whole flood into
  the chain and stops it only at SPIRE — the half of AB-07 that I4 makes
  permanent would be the half left unprotected.
- **Record the trip as a `tool_call` event.** Rejected twice over: the call did
  not happen, so the chain would claim work that was never done; and one ledger
  row per refused call is exactly the flood the limit exists to prevent, written
  by the limit. A rate limit that floods the ledger to report that it stopped a
  flood is self-defeating.
- **Record the trip as `ledger_drift_detected`.** Rejected: it requires
  `subject_event_id`, and the entire content of a refusal is that no event was
  written, so there is no subject and doc 02 §1 forbids an empty-string
  placeholder. Its documented meaning — "ledger claim with no external proof" —
  is also not this. Same shape as the refusal ADR-0013 made.
- **Invent a twelfth event type, `rate_limit_exceeded`.** Rejected: doc 02 §3 is
  closed and §7 makes a new type a major schema version with a migration
  attestation. That is a human decision; follow-up 2.
- **Return `INVARIANT_VIOLATION` for a refusal.** Rejected on both fields it
  sets: it is alert-level per ADR-0016 and would page an operator for a caller's
  retry loop, and it is not retryable, which tells a caller its call can never
  succeed when in fact it succeeds a second later.
- **Return `DUPLICATE_REQUEST`.** Rejected: RM-020 defines it as a key reused
  for a *different* request, and it is not retryable. A flood is neither.
- **Invent a twelfth error class, `RATE_LIMITED`.** Rejected here for the reason
  ADR-0017 and ADR-0018 gave for theirs: the vocabulary is a protected surface
  (VERSIONING.md surface 4) and adding to it is not an implementing agent's
  decision. Follow-up 1.
- **A fixed-window counter, which is simpler.** Rejected: the window edge admits
  two full allowances back to back, and it does so at the start of a flood,
  which is the one moment the limit exists for.
- **A token bucket held as a floating-point count.** Rejected: accumulated
  rounding makes the boundary platform-dependent, and the boundary is the
  property MCP-013 asserts.
- **Refuse new callers when the table is full, rather than evicting.**
  Rejected: it converts a memory bound into a global denial of service that
  anyone minting distinct keys can trigger. Eviction that only ever grants
  credit trades accuracy for availability, which is the correct direction when
  the alternative is force 2.
- **Evict the least-recently-used bucket.** Rejected: under a flood the
  attacker's own bucket is the most recently used, so LRU would preserve it —
  but LRU needs a second timestamp per bucket to do what `tat` already encodes.
  Evicting by `tat` (closest to refilling) is the same intent with one field,
  and it is provably the ordering that evicts the flooder last.

## Consequences

- **AB-07's control now exists and is tested**, with the residual named: doc 04
  §3's AB-07 row can be read as closed against a runaway loop and **not** closed
  against an adversary who varies the caller key. Doc 04 §5's residual-risk list
  does not yet carry that entry; adding it is follow-up 4.
- **`register_agent` gains a failure mode that is not a dependency outage.** An
  agent's retry loop must honour `retryable` *and* back off, because a tight
  retry against a rate limit is the flood continuing. The message carries the
  wait; IP §4's error object has no field for it, which is follow-up 1's second
  half.
- **The limit is opt-in at wiring time.** `RateLimitRegisterAgent` must be
  called before `ConfigureRegisterAgent` or the tool is unmetered. It refuses a
  nil limiter, a limiter built for another tool, and a nil ledger — the last
  because `ConfigureRegisterAgent`'s own nil-ledger check would otherwise see
  the wrapper and pass. Wiring it into the server entry point is a supervisor
  merge action, the same shape ADR-0016 §5 and ADR-0018 record for the tools.
- **The alert has exactly one channel.** A deployment that routes alerts
  anywhere but stderr must set `RateLimit.Alert`; the default is an error-level
  `slog` line that says in its own text that the ledger does not hold this. If
  follow-up 2 is ever taken, the sink stays — an operator alert and a ledger
  record are different jobs.
- **Required follow-ups, for the human only** (`docs/` outside `docs/adr/` is
  not edited by implementing agents):
  1. IP §4 has no class for "slow down" and its error object has no
     `retry_after`. This ships `IDENTITY_UNAVAILABLE` with the wait in the
     message. Whether the vocabulary should gain a twelfth class — the third
     time this has been asked, after ADR-0017's "the original call has not
     finished yet" and ADR-0018's "the argument cannot name a run" — is a
     protected-surface decision. Three unrelated situations now share one
     workaround; that is the argument for taking the question seriously.
  2. Doc 02 §3 has no event type for a rate-limit trip, so it is not in the
     ledger. Doc 05 §2's "an event type **or** test" makes that conformant, and
     MCP-013 is the test. If a trip should be a ledger record, doc 02 §3 needs
     `rate_limit_exceeded` and doc 02 §7's migration attestation.
  3. IP §6.10 says "per caller" and E1 exempts the authorization that would make
     a caller identifiable. The gap should be stated in IP or doc 04 rather than
     only here, and a global ceiling reconsidered once callers are
     authenticated.
  4. Doc 04 §5's residual risks should carry the key-varying adversary named in
     the Decision, so that AB-07 is not read as fully closed.
- **Exit cost.** Low while the limit is opt-in and off by default in the shipped
  entry point: removing it is deleting a wrapper. It rises the moment the limit
  is on in a real deployment, because agents in the field will have been written
  against a `register_agent` that can refuse with `IDENTITY_UNAVAILABLE` for a
  reason no dependency outage explains, and against the specific default of 60
  per minute. Changing the default downward after that is a behavioural break
  for every caller sitting under the old one; changing the *class* is a
  protected-surface change under doc 08 §3.
