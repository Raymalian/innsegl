# ADR-0017: Record the tool call's reply in Postgres, above the ledger's event-level dedupe

- Status: accepted
- Date: 2026-08-29
- Deciders: Mike

## Context

IP §6.6 is one sentence with two halves: "Every tool call is idempotent via
required `idempotency_key`; replaying any request after a crash returns the
original result, never a second identity, second event, or second commit."

The second half is already built. RM-009 (#17) gave `innsegl.events` a UNIQUE
`idempotency_key`, so one key appends at most one event and a replayed `Append`
returns the original event and writes nothing (LED-008). That is what I3 and I4
rest on, and it is not in question here.

The first half is not built, and the ledger cannot build it. A tool *call* is a
larger thing than an append:

- Its effect can precede any event. IP §6.5's two-phase protocol signs between
  two appends; the register-shaped tool of IP §4 creates a SPIRE entry and mints
  an identity before `run_registered` exists. A crash in that window leaves an
  effect with no record of the call at all.
- Its reply can carry values no event holds. IP §4's register-shaped tool
  returns an expiry; doc 02 §2 and §3 give no event an expiry member, and adding
  one would be a major `schema_version`. So even a completed call cannot have
  its reply reconstructed from the chain.
- Its reply can be lost after the record is written. Crash between the append
  and the response reaching the agent and the ledger is perfectly consistent
  while the agent knows nothing.

In each case the ledger answers "did this happen?" and cannot answer "what did
it return?", which is the question IP §6.6 makes a replay ask.

Doc 05 §2 fixes where the answer lives: "MCP replicas are stateless
(idempotency store lives in Postgres) — MCP-011's crash/replay property is what
makes horizontal scaling safe." A process-local map satisfies every
single-process test and then breaks, silently, in the direction that mints a
second identity, the first time there are two replicas or one restart.

ADR-0004 fixes which calls are in scope: a key is required if and only if the
originating tool accepts one, and forbidden elsewhere. ADR-0005 fixes the
storage scope: one chain per database, no scope column.

## Decision

**A Postgres table records the reply of every keyed tool call, and a replay
returns those stored bytes.** It sits above the ledger's dedupe and never
duplicates it: the same key names the same action at both layers.

Seven parts, each of which could reasonably have gone another way:

1. **A table in the same database as the chain** (`innsegl.idempotency`,
   migration 0002, applied by the ledger's own runner). `idempotency_key` is
   the primary key, database-wide, with no scope column to get wrong — exactly
   how ADR-0005 scoped the ledger's. One migration set means a deployment
   cannot have one schema without the other.

2. **Claim, run, record — as three single statements, with no window between
   deciding and acting.** The claim is one `INSERT … ON CONFLICT DO UPDATE …
   RETURNING` with a `UNION ALL` arm that reports the row when the insert
   declines. A read-then-write pair would leave a window two replicas both walk
   through.

3. **A key presented with a different request is refused as
   `DUPLICATE_REQUEST`, not retryable.** RM-009 refuses the same reuse one layer
   down for the same reason: doc 02 §2 gives the key one job, dedupe, and
   returning the earlier reply would answer a question the caller did not ask.
   The request is fingerprinted as the SHA-256 of the RFC 8785 canonical form of
   `{tool, params}` — the project's one definition of sameness (doc 02 §4.2), so
   two spellings of one integer are one request. Parameters are fingerprinted,
   never stored: the store does not become a second copy of a request that may
   carry a payload.

4. **The reply is returned byte for byte from the column**, canonicalized once
   on the way in, never recomputed on the way out. Stored as `bytea`, not
   `jsonb`, for the reason `innsegl.events.canonical` is `bytea`: `jsonb`
   re-serializes, and a re-serialized reply is not the reply that was sent.

5. **A claim carries a lease, and an expired claim is taken over.** A replica
   SIGKILLed mid-call leaves its claim behind, and IP §6.6 requires the replay
   to *return* something — so a claim that can never be taken over wedges the
   key forever, which fails the requirement more completely than a second
   execution does. The takeover runs the tool a second time. That is where the
   layering pays: the inner effect is itself idempotent — the ledger's UNIQUE
   key for an event, the run's own SPIRE entry for an identity — so the second
   execution produces no second record. What never happens is two *answers*:
   whichever call completes first is the one every caller is given, including
   the overtaken one, whose own reply is discarded.

6. **A failed call frees its key; a call whose reply cannot be serialized does
   not.** A tool that reported failure may be retried at once. A tool that
   succeeded and produced an unrepresentable reply has already had its effect,
   so an immediate retry would repeat it; the lease paces that one instead.

7. **The table is prunable, and the schema says exactly how.** Unlike
   `innsegl.events` this is a bounded record of recent calls, not the ledger, so
   an operator must be able to delete from it. A row-level trigger (SQLSTATE
   IN003, alongside the ledger's IN001 and IN002) refuses to rewrite or reopen a
   completed row, refuses to repoint a claim at a different call, and refuses to
   delete or `TRUNCATE` a claim that is still in flight. Deleting a *completed*
   row is allowed.

Error classes come from `internal/mcp/errors.go` (RM-020, ADR-0016) rather than
from a second scheme in this file: one package, one error type, one rendering of
IP §4's protected vocabulary. Where this layer knows more than the class default
it narrows `retryable` and never widens it, which is ADR-0016's rule.

## Alternatives considered

- **Rely on the ledger's UNIQUE `idempotency_key` alone (LED-008) and call
  IP §6.6 done.** Rejected because it answers the wrong question. A replay would
  have to reconstruct the reply from the event, and no event carries the
  register-shaped tool's expiry (doc 02 §2, §3); adding one is a major
  `schema_version` with a migration attestation (doc 02 §7). It also cannot
  cover a crash between the effect and the append at all — the window IP §6.5
  calls "the single most dangerous".

- **Keep the store in memory, keyed per replica.** Rejected outright by doc 05
  §2. It passes every single-process test, so the failure is invisible until
  there are two replicas, and its failure mode is the exact one IP §6.6 names:
  a second identity. It also cannot survive `kill -9`, which is the scenario the
  requirement is written about.

- **A distributed lock (Redis, etcd, an advisory lock held across the call)
  instead of a leased row.** Rejected because it stores the exclusion and not
  the answer. The lock tells a replay that it may not run; it cannot tell it
  what the first run returned, so the reply would still have to be recorded
  somewhere — and that somewhere is this table, at which point the lock is a
  second system with a second failure mode. Holding a Postgres transaction open
  across a SPIRE or Rekor call, the version with no new dependency, pins a
  connection for the duration of the slowest external call in the system.

- **Never take over an expired claim: a claimed key stays claimed forever.**
  Rejected because it converts a crashed replica into a permanently unanswerable
  key. IP §6.6 requires the replay to return the original result; returning
  "still running", forever, to every future caller is not that, and it makes the
  crash case strictly worse than the double-execution it avoids. The takeover is
  safe precisely because the inner effects are idempotent, which is a property
  the rest of the system already has to have.

- **Make the takeover safe by having the overtaken caller win.** Rejected: the
  first reply recorded is the one already handed to whichever caller read it, so
  letting a later completion overwrite it would mean two callers were given
  different answers to one call. First-completion-wins is enforced by the
  `WHERE status = 'in_progress'` on the recording statement, not by convention.

- **A `wait` budget as a third bound on how long a replay waits.** Rejected as a
  knob that is not visible to an operator. Two bounds already exist and both
  are: the caller's own context, and the lease. A third would silently decide
  between them.

- **Store the request parameters, not just their digest, so a refusal can show
  what differed.** Rejected because tool parameters can carry a payload, and a
  store that keeps them becomes a second place a payload lives with a different
  retention rule. The digest answers the only question the store asks — is this
  the same request? — and doc 02 §2 already keeps payloads out of events by
  recording only a `payload_digest`.

- **Refuse `DELETE` on this table as `innsegl.events` does.** Rejected because
  this table is not the ledger. Its rows are bounded operational state, and a
  table that can only grow is one an operator eventually truncates in a hurry —
  the outcome the guard was meant to prevent. Refusing to delete an *in-flight*
  claim gets the safety without the growth.

## Consequences

- `internal/mcp` reports three of IP §4's classes from this path:
  `DUPLICATE_REQUEST` for a key naming a different request, `INVARIANT_VIOLATION`
  for a call or reply the store cannot record, and `LEDGER_UNAVAILABLE`
  otherwise. The mapping is `internal/ledger`'s policy, because it is the same
  database and a caller must not have to know which layer answered.

- Pruning a completed row re-opens its key to execution. The retention window an
  operator chooses is therefore the replay window they are willing to serve, and
  it must exceed the longest crash-to-retry gap they expect. The ledger's own
  UNIQUE key remains the backstop against a second *event* whatever is pruned
  here, which is why this is a retention decision and not a correctness one.

- A replay that arrives while the original is running blocks — up to the
  caller's context or the lease, whichever ends first. With the default
  sixty-second lease, a replay after a crashed replica waits for the remainder
  of that lease before taking over. Shortening the lease trades that wait
  against more double executions.

- **Flagged for the human, not resolved here.** IP §4's error-class vocabulary
  is closed and has no class for "the original call has not finished yet". The
  three candidates are all wrong in different ways: `DUPLICATE_REQUEST` is what
  ADR-0016 fixes as not retryable and what RM-020 defines as a key reused for a
  *different* request; `INVARIANT_VIOLATION` is alert-level and would page an
  operator over a slow tool; `LEDGER_UNAVAILABLE` names a dependency that is in
  fact up. This code returns `LEDGER_UNAVAILABLE`, because it is the only one
  whose `retryable` flag gives the caller the instruction the situation
  warrants, because `internal/ledger` already reports a context failure during a
  ledger operation the same way, and because the message names the true state.
  Whether IP §4 should gain a twelfth class is a protected-surface question and
  not an implementing agent's to answer.

- **Flagged for the human, not resolved here.** Doc 07 has no test ID for this
  layer. LED-008 is the ledger's dedupe; MCP-007 and MCP-011 exercise this store
  through tools that do not exist yet (RM-022..025, RM-029). The tests written
  for RM-021 are named for the behaviour and cite IP §6.6; if doc 07 should gain
  an ID for the store itself, that is an edit to a document implementing agents
  do not make.

- A snapshot subtlety is now load-bearing and is tested rather than commented.
  When a competing claim commits *while* another caller's claim statement is
  running, that statement's `INSERT` blocks on the uncommitted row and then
  declines, while its `SELECT` arm reads a snapshot taken before the commit —
  so neither arm returns a row. The store reads that as "someone else holds this
  key" and waits, which is what it means.
  `TestAClaimThatCommitsDuringAnotherCallersStatementIsWaitedForNotLost` forces
  it deterministically by holding the conflicting `INSERT` open in a
  transaction; the concurrency test hits it perhaps two runs in three.

- **Exit cost.** Low, and deliberately so. This table is not a protected
  surface: no part of it enters an event, a preimage, a segment or a Rekor
  entry, and nothing outside `internal/mcp` reads it. Replacing the mechanism
  costs a migration and a package; the only thing that could not be undone is a
  reply already handed to an agent, which is why the reply's bytes — not the
  mechanism — are what the schema protects.
