# ADR-0020: Retire a run by its `run_id` alone, recording before deleting, and answer every later call from the ledger

- Status: accepted
- Date: 2026-08-29
- Deciders: Mike

## Context

IP §4 gives `retire_agent` in two sentences:

> `retire_agent(run_id)` → `{retired_at}`. Deletes SPIRE entry, appends
> `run_retired`. Idempotent: retiring a retired run returns success with the
> original timestamp.

Three things follow that the signature does not say out loud.

**There is no `idempotency_key`, and there must not be one.** ADR-0004 already
settled this and gave the substantive reason rather than a document-precedence
one: "`retire_agent`'s idempotency is intrinsic to `run_id`. A run retires
once. A separate key would invent a way for two retirements of one run to
disagree, which is a contradiction the ledger would then have to record." The
same ADR forbids the field on the `run_retired` event, whatever the source, and
`internal/event` enforces the absence rather than merely not requiring it —
`idempotency_key` is part of the canonical preimage (doc 02 §4), so a field a
later implementation starts populating changes that event type's bytes forever.

That decision has a consequence this issue is the first to pay. The mechanism
every other idempotent path in this system uses is a key: the ledger's UNIQUE
`idempotency_key` (LED-008), the MCP's own claim table (ADR-0017), the reaper's
derived `reaper:run_expired:<run-id>` (ADR-0014). Retirement may use none of
them. Its idempotency has to be a **read of the ledger** instead.

**"The original timestamp" has to come from somewhere durable.** After a
retirement the SPIRE entry is gone — that is the point — so the entry cannot
say when it went. The `run_retired` event's `ts` is the only record of the
instant, and I4 guarantees it is still there: "Retirement deletes the SPIRE
entry, never ledger content."

**Two systems, one order.** ADR-0018 faced the same two-systems problem for
registration and stated the rule for both directions: *the ledger may describe
an identity that does not exist; SPIRE must never hold an identity the ledger
does not describe.* It named this tool in the decision. ADR-0014's reaper is
the third instance: it appends `run_expired` **before** deleting the entry.

Invariants in play: **I3** (no action without a record — deleting an identity
is an action), **I4** (the record is permanent, so the instant is recoverable
and an over-claim is not correctable), and IP §6.2 (retirement is effective
immediately, with no cached-credential grace path through the MCP).

## Decision

**1. Ledger first, SPIRE second — the third instance of ADR-0018's rule.**
`retire_agent` appends `run_retired` and then calls `RetireRun`.

The named failure mode, in full: a crash, or a ledger success followed by a
SPIRE refusal, leaves a run the ledger describes as retired whose registration
entry still exists. The call reports the SPIRE failure with SPIRE's own class
(IP §6.1: unreachable is `IDENTITY_UNAVAILABLE`, retryable), so the caller
knows the retirement is incomplete. A retry converges: the record is found, no
second event is appended, the entry is deleted, and the reply is the original
instant. A caller that never retries leaves the entry to RM-017's reaper.

Nothing can happen under the run inside that window, because every MCP path
resolves a run through the ledger-backed run directory before it does anything
— which is what doc 07 MCP-009 asserts, and what `TestMCP009AnyToolAgainstA
RetiredRunIsRefused` measures against the shipped `get_credential`.

Retirement is the direction where this order is not merely the safer window but
the **effective** one. Writing the record is precisely what makes retirement
take effect through the MCP, so doing it first *shortens* the interval in which
a retired run is still credentialable. The other order would lengthen it and
then misreport it: with the entry deleted and no `run_retired` yet,
`get_credential` refuses at its SPIRE gate with `RUN_NOT_FOUND` — "this run
never existed" rather than "this run was retired" — and a crash there destroys
an identity with nothing anywhere recording that it existed or when it went,
which is I3 broken permanently.

**2. `retired_at` is the ledger's `ts`, read back off the append and, on every
later call, out of the run directory.** The tool reads no clock. Two records of
one retirement — the reply and the event — cannot then disagree, and cannot
disagree *permanently*, which is what I4 would make of a discrepancy.

A record the ledger returns without a readable `ts` is `INVARIANT_VIOLATION`,
not an empty `retired_at`. The reply's entire content is one instant, and a
blank one is exactly the shape a vacuously-passing idempotency test takes.

**3. The run directory is `get_credential`'s, not a second one.** IP §4 gives
this tool a `run_id` and nothing else, so something must map it to a run and to
its retirement. That something is `mcp.CredentialRuns`, already defined and
already used by the tool that has to agree with this one. MCP-009 is precisely
the claim that every tool agrees a run is retired; two definitions of "what is
a run" are two things that can disagree about exactly that.

Its `RetiredAt` must be the **earliest** `run_retired` for the run. See 5.

**4. The directory's answer is checked before SPIRE is asked to delete.**
`credentialRunIdentity` — the same function `get_credential` calls before
asking SPIRE to *mint* — requires the directory to have answered about the run
that was asked for, with an identity that is well formed and is that run's own
inside the `/agent/` subtree. A directory that answered with another run's
identity would otherwise be a way to delete an entry that is not this run's.

**5. Retirement's idempotency is a check-then-append, and the window that
leaves is accepted and named.** The one mechanism that would make it atomic is
the key ADR-0004 forbids. Two genuinely concurrent *first* retirements of one
run can therefore both find no record and both append, leaving two
`run_retired` events in the chain.

What that costs is noise, permanently (I4). What it does not cost: both callers
are told the same instant, because the directory answers with the earliest; at
most one deletion finds an entry and the other is the "success with nothing
deleted" IP §4 already requires; and every later call is answered from the
earliest record. The window cannot produce a retirement that is not recorded,
or an entry deleted without a record.

**6. The MCP idempotency store (ADR-0017) is not used by this tool.** It is
keyed by a caller-supplied `idempotency_key` this tool does not have.

## Alternatives considered

- **Synthesise a key — `"retire_agent:" + run_id` — for the idempotency store,
  the reaper's move in ADR-0014.** Rejected on three counts. It re-introduces
  precisely what ADR-0004 rejected: a second way to name one retirement, which
  can disagree with the first. The store's namespace is shared with
  caller-supplied keys (ADR-0014 records the same residual risk from the other
  side), so a client that had used the string `retire_agent:run-x` for another
  call would make that run *unretirable* with `DUPLICATE_REQUEST` — a refusal
  about something other than retirement, blocking the one operation that must
  always be available. And ADR-0017's store is prunable, so its answer is not
  durable enough to be the source of an instant the ledger keeps forever.
  The reaper's case is not this case: its key goes on the *event*, where
  ADR-0004 leaves it unconstrained for `run_expired` and forbids it for
  `run_retired`.

- **Give `run_retired` an `idempotency_key` after all, so the ledger's UNIQUE
  index makes retirement atomic.** Rejected: ADR-0004 forbids it, and the
  forbidding is enforced in `internal/event`, in the golden fixtures and in the
  fixture verifier. Reversing it is a new major `schema_version` with a
  migration attestation (doc 02 §7) — an unreasonable price for closing a race
  whose worst outcome is a duplicate record of a fact both records agree on.

- **Delete the SPIRE entry first, then append.** Rejected: see decision 1. Its
  window is an action with no record (I3), and unlike the chosen window it is
  not recoverable — the instant is gone with the entry.

- **Refuse a second retirement with `RUN_ALREADY_RETIRED`.** Rejected because
  IP §4 says the opposite in as many words: "Idempotent: retiring a retired run
  returns success with the original timestamp." It would also make the
  crash-and-retry path fail, which is the path that converges a half-finished
  retirement — a caller told `RUN_ALREADY_RETIRED` has no way to get the entry
  deleted, and the orphan then waits for the reaper.

- **Return early on the already-retired path without asking SPIRE to delete.**
  Rejected: it is exactly the state a crashed retirement leaves, so returning
  early is refusing to converge the one case idempotency exists for. `RetireRun`
  is itself idempotent, so the cost on the ordinary path is one lookup.

- **Define a second, retirement-specific run directory.** Rejected: MCP-009 is
  the claim that all five tools agree about retirement, and a second mapping is
  a second thing that can disagree. It would also have to be given a way to
  read the ledger, which is a third copy of a question already answered.

- **Take `retired_at` from the MCP's clock, and record the same value in the
  event.** Rejected: doc 02 §2 makes `ts` server-assigned by the *ledger* and
  ignores client-supplied values (LED-010, IP §6.8), so the event would carry
  the ledger's instant whatever the reply said. Two instants for one
  retirement, differing by a network round trip, one of them permanent.

- **Answer a later call from the SPIRE entry's absence rather than the ledger.**
  Rejected: SPIRE cannot tell a retired run from one that never existed, which
  is why `RequireActiveRun` reports `RUN_NOT_FOUND` and says so in its own
  comment. And it holds no instant to answer with.

## Consequences

- **Two `run_retired` events for one run are possible** under concurrent first
  retirements, and permanent (I4). Readers must take the earliest as the
  retirement. `internal/ledger` exposes no run-scoped query today, so the
  directory implementation that will answer `CredentialRuns.CredentialRun` is
  where that rule lives; **this ADR is the statement of the contract that
  implementation must satisfy**, and RM-025's double implements it exactly that
  way so the contract is executed rather than described. ADR-0018 flagged the
  same missing read for the mirror case.

- **A retired run whose entry survived a failed deletion will be deleted by the
  reaper at its deadline, which appends `run_expired` as well.** The chain then
  carries both terminal events for one run. That is noise, not a contradiction:
  `run_retired` is the retirement, `run_expired` is the reaper's record of
  removing an entry it found past its deadline, and both are true. Making the
  reaper skip an already-retired run needs the same run-scoped ledger read as
  above and is `internal/spire`'s surface, not this issue's.

- **`retire_agent` reads no clock, and has no `Now` in its configuration.**
  That is deliberate and should stay: adding one would create a second source
  for an instant that must have exactly one.

- **`credentialLedgerError` and `credentialRunIdentity` are now used by two
  tools.** They live in `get_credential.go` because that tool was written
  first. ADR-0018 recorded the same observation about the ledger-error mapping
  and called moving it a supervisor merge action; with a third caller
  (`record_event`, RM-024) landing in the same wave, the case for moving both
  into `errors.go` is stronger, and it remains a merge action rather than
  something an issue-scoped agent should do to a file it does not own.

- **Flagged for the human, not resolved here.** Doc 07 has no test-catalog ID
  for retirement's *ordering*, the same gap ADR-0018 flagged for registration
  and proposed **MCP-017** for. `TestRetireAgentRecordsBeforeItDeletes` and
  `TestRetireAgentFailsClosedWhenTheLedgerIsDown` are the two halves of it —
  with SPIRE down the event exists and the entry survives; with the ledger down
  SPIRE is never asked — and they are unnumbered. They would be MCP-017's other
  direction.

- **Flagged for the human, not resolved here.** Doc 07's MCP-009 row carries
  retirement's own idempotency in a parenthesis — "(retire itself: idempotent
  success with original timestamp)" — while doc 01 §4 states it as part of the
  signature and the RM-025 issue states it as its own acceptance criterion. The
  tests are written to satisfy every reading: `TestMCP005RetireAgentSchema
  Conformance` is doc 07's MCP-001..005 row for this tool, `TestMCP005Retire
  AgentIsIdempotentWithTheOriginalTimestamp` is the idempotency as the issue
  states it, and `TestMCP009AnyToolAgainstARetiredRunIsRefused` asserts both
  halves of doc 07's MCP-009 row. Whether the idempotency clause should be its
  own ID is a doc 07 edit.

- **Exit cost.** Low for the ordering, which is observable only as a window;
  reversing it after a deployment means the chain was written under two
  conventions, as ADR-0018 notes for registration. Effectively zero for the
  timestamp source, which is an implementation choice inside one tool. The one
  thing that is *not* cheap is the absence of `idempotency_key` on
  `run_retired`, and that cost was already incurred by ADR-0004: it is a
  protected surface, and adding the field is a major `schema_version` with new
  fixtures, dual-version verifiers and a signed migration attestation.
