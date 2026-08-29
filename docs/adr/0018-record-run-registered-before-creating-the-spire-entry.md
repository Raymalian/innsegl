# ADR-0018: Record `run_registered` before creating the SPIRE entry, and derive the run id from the call

- Status: accepted
- Date: 2026-08-29
- Deciders: Mike

## Context

IP §4 says `register_agent` "Creates SPIRE entry + `run_registered` event
atomically (see 6.5)". The two live in different systems — a SPIRE datastore
and a Postgres chain — so no transaction spans them and *atomically* cannot
mean what it means inside one database. What it can mean is that one order is
chosen, its failure window is named, and the window is put on the side that
cannot break an invariant.

The two windows are not symmetric.

- **SPIRE first.** A crash between the entry and the append leaves an
  **identity with no record**. That is I3 ("no action without a record") broken
  in the direction that matters: during the window the entry is real, so
  `get_credential` would issue a credential and a commit could be signed and
  attributed to a run the ledger never registered. IP §6.7's reaper eventually
  deletes the orphan and appends `run_expired`, which leaves the chain
  describing an ending with no beginning — up to a TTL plus grace later.
- **Ledger first.** A crash between the append and the entry leaves a **record
  with no identity**. Nothing can be signed under it: SPIRE holds no entry, so
  `get_credential` refuses (`spire.Client.RequireActiveRun`). The record is an
  over-claim — `run_registered` names an identity that was not created — and
  the run is inert.

RM-017's reaper faced the mirror of this and chose to append `run_expired`
*before* deleting the entry, for the same reason and with the same shape of
residual (an expiry recorded for an entry that then failed to delete).

Two further forces:

- **ADR-0017 runs the tool twice on purpose.** A claim whose lease has run out
  is taken over and the tool executes a second time; the ADR justifies that by
  saying "the inner effect is itself idempotent — the ledger's UNIQUE key for
  an event, **the run's own SPIRE entry for an identity**". That sentence is
  only true if both executions ask for the *same* run. A run id minted per
  execution would make it false, and MCP-007 would hold in the ordinary replay
  and fail in the one interleaving nobody watches.
- **Doc 02 §3's schema is closed.** IP §6.5's two-phase intent/record protocol
  is not available here: there is no `run_intent` event type, and adding one is
  a major `schema_version` with a migration attestation (doc 02 §7).

Invariants in play: I1 (no identity without attestation), I3 (no action without
a record), I4 (nothing is deleted or mutated, so an over-claim is permanent).

## Decision

**1. The ledger is written before the identity changes state, in both
directions.** `register_agent` appends `run_registered` and *then* creates the
SPIRE entry; `retire_agent` and the reaper record and *then* delete. Stated as
one rule: **the ledger may describe an identity that does not exist; SPIRE must
never hold an identity the ledger does not describe.** The record may run ahead
of SPIRE and can never fall behind it.

The named failure mode, in full: a crash — or a ledger success followed by a
SPIRE refusal — leaves a `run_registered` event for a run that has no
registration entry. The run is inert (no credential, no signature, no commit),
the ledger's UNIQUE `idempotency_key` means a retry produces no second event
(LED-008), and a retry that reaches SPIRE completes the registration. A caller
that never retries leaves a permanent dangling `run_registered`. That is noise
in the chain, not a broken invariant, and it is the price of the window being
on this side.

**2. The run id is derived, not minted.** It is
`"run-" + first 128 bits of SHA-256(quote(agent_type) ‖ quote(task_id) ‖
quote(idempotency_key))`, so the same call names the same run on any replica,
after any crash, with nothing shared between them. This is what makes ADR-0017
§5's second execution harmless: it asks SPIRE for the entry that already
exists.

**3. SPIRE reporting the run's entry as a duplicate is adoption, not failure.**
Because the run id is derived, the only thing that can have created an entry
for it is this same call executed again, so `DUPLICATE_REQUEST` from
`RegisterRun` is followed by `LookupRun` and the existing entry is used.

**4. An entry SPIRE reports and then does not hold is `RUN_ALREADY_RETIRED`,
not retryable.** The only things that remove a run's entry are retirement and
the reaper, and both mean the run is over. Failing closed here is what stops
`register_agent` from re-creating an entry for a run that was retired — IP §6.2
makes retirement effective immediately, and a resurrection through this path
would be the cached-credential grace path it forbids, wearing a different hat.

**5. `expires_at` is read off the entry SPIRE created**, as the clock at
creation plus that entry's own TTL, in doc 02 §1's timestamp form. Not off the
request: a reply must not promise a lifetime SPIRE did not grant, and IP §6.2
forbids extending a TTL to help.

**6. `task_id` is the caller's reference; the SPIFFE ID carries its lowercased
form.** Golden fixture 01 is the definition: `task_ref` "JIRA-118" against
`spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42`. IP §4 gives the tool one
argument, so it is recorded verbatim as the event's `task_ref` and lowercased
into the SPIFFE ID's `{task-id}`. `agent_type` is *not* normalized: it is held
to doc 02 §5's grammar as given, because a silently rewritten `agent_type`
would make the recorded value differ from the one the caller believes it
registered.

## Alternatives considered

- **Create the SPIRE entry first, then record it.** Rejected: its window is an
  identity with no record, which is I3 broken in the direction that lets
  attributed work happen off the books. The reaper does converge it, but only
  after a TTL plus grace, and only into a chain that records an expiry for a
  run it never recorded a registration for. The over-claim in the chosen order
  is permanent too, but it never lets anything be signed.

- **Two-phase, as IP §6.5 does for commits: a `run_intent` before and a
  `run_registered` after.** Rejected because doc 02 §3's `event_type` enum is
  closed and protected; adding a twelfth value is a major `schema_version` with
  a migration attestation. It would also buy less than it does for signing:
  IP §6.5's phases straddle an *external* signature that the reconciler can
  find in Rekor afterwards, whereas a SPIRE entry has no third-party record to
  reconcile against — the entry itself is the only evidence, and `LookupRun`
  already answers that question directly.

- **Mint a UUID run id and lean on the idempotency store to hide the second
  execution.** Rejected because it does not hide it. ADR-0017 §5 takes over an
  expired claim and *runs the tool again*; only the reply is deduplicated, not
  the effect. With a minted id the second execution would create a second SPIRE
  entry under a second SPIFFE ID, and the reply that wins would name only one
  of them — leaving a real identity that no ledger event and no reply mentions.
  That is exactly the "second identity" MCP-007 exists to catch, reachable
  without any concurrency at all: one crashed replica is enough.

- **Look SPIRE up before creating, and skip the create when an entry exists.**
  Rejected as a read-then-write with a window two replicas both walk through;
  the duplicate answer has to be handled regardless, so the lookup buys nothing
  and costs a round trip on every registration. Decision 3 handles the answer
  instead of racing to avoid it.

- **Treat `DUPLICATE_REQUEST` from SPIRE as a tool failure and report it.**
  Rejected: it makes the ordinary crash-and-retry path fail. The caller did
  supply a repeatable key, IP §6.6 says the replay returns the original result,
  and the entry that exists *is* that result.

- **A distributed transaction or an outbox that creates the SPIRE entry
  asynchronously.** Rejected outright by IP §6.1: "No queuing of identity
  issuance, no provisional identities, no 'register later'." An outbox is a
  queue whatever it is called, and RM-018's SPI-006 asserts the absence of that
  property globally.

- **Reject `agent_type` and `task_id` in the input JSON Schema instead of in
  the handler.** Rejected because a schema rejection is a protocol error, not
  IP §4's `{error_class, message, retryable}` object, and IP §4 says *all*
  tools return structured errors. The schema still documents the shape; the
  handler is what refuses a value.

## Consequences

- **A dangling `run_registered` is possible and permanent** (I4). It is
  detectable — a `run_registered` with no entry, no `run_retired` and no
  `run_expired` — and RM-027's reconciler already walks SPIRE against the
  ledger for the mirror case (ADR-0013). Whether an un-minted registration
  should raise `ledger_drift_detected` is a reconciler question and is left to
  it; nothing here depends on the answer.

- **Residual risk: pruning plus retirement.** ADR-0017 makes completed
  idempotency rows prunable, and pruning re-opens a key to execution. A replay
  of a pruned key whose run has since been retired re-derives the same run id
  and would re-create the entry — except that decision 4 catches the case SPIRE
  can see. The case it cannot see is a key pruned *and* the entry deleted, where
  `RegisterRun` succeeds outright and resurrects the identity. Closing it needs
  a run-scoped ledger read (`run_retired`/`run_expired` for this run), which no
  ledger method offers today and which is RM-024/RM-026 surface. **Flagged for
  the human, not resolved here:** the operator-visible rule is that the
  idempotency retention window must exceed the longest crash-to-retry gap, which
  ADR-0017 already states for a different reason.

- **`internal/ledger.StoreError` does not implement `mcp.Classified`**, so
  `register_agent` maps it across by string identity in its own file, the way
  `Classify` does for `*spire.Error`. That mapping will be written a second time
  by every other tool that appends. It should move: either `*ledger.StoreError`
  grows `ErrorClass()` or `Classify` grows a case. Both files are outside this
  issue's ownership; it is a supervisor merge action, and ADR-0016 already
  records the same follow-up for RM-021's error.

- **Flagged for the human, not resolved here:** IP §4's closed vocabulary has no
  class for "the caller sent an argument that cannot name a run". This tool
  reports `INVARIANT_VIOLATION`, following the precedent already in the shipped
  source — `spire.Client.resolve` and `RunRef.SPIFFEID` classify a malformed
  registration the same way, and `mcp.Bind` classifies an off-surface tool name
  the same way. It is alert-level for what may be a caller's typo, which is the
  wrong volume; `ATTESTATION_FAILED` would be the wrong *fact* (SPIRE was never
  asked). Whether IP §4 should gain a twelfth class is a protected-surface
  question, and the same one ADR-0017 raised for "the original call has not
  finished yet".

- **Flagged for the human, not resolved here:** doc 07 has no test-catalog ID
  for the ordering itself. MCP-001 and MCP-007 cover the shape and the
  idempotency; the tests that pin *ledger-before-SPIRE* — with SPIRE down, the
  event exists and no entry does; with the ledger down, SPIRE is never asked —
  are the ones that would catch a future reordering, and they are unnumbered.
  Proposed: **MCP-017** (C) the identity is never created before its record.

- **Exit cost.** The ordering is observable in the chain, so reversing it after
  a deployment means the chain contains both conventions and a reader cannot
  tell which window a given `run_registered` was written under. The derived run
  id is worse: run ids are in SPIFFE IDs, in Fulcio certificates and in Rekor
  entries, so changing the derivation changes nothing already written but makes
  the id of a *replayed* call unpredictable across the cutover — a replay of a
  pre-cutover key would mint a new run rather than adopting the old one. Both
  are cheap before the first tag and a major release after it.
