# ADR-0004: Scope `idempotency_key` to the MCP tools that accept one

- Status: accepted
- Date: 2026-08-28
- Deciders: Mike

## Context

Two normative documents disagree about when an event carries `idempotency_key`.

Doc 02 §2 describes the field as conditional: *"Required on events created by
MCP tool calls; used for dedupe (TC LED-008)."* Read plainly, that makes the
field required on every event with `source: mcp`.

IP §4 gives the tool signatures, and two of the five take no such argument:

```
register_agent(agent_type, task_id, idempotency_key)                       has one
get_credential(run_id, audience)                                           NO key
record_event(run_id, event_type, payload_digest, idempotency_key)          has one
sign_commit(run_id, repo, staged_ref, message, task_ref, idempotency_key)  has one
retire_agent(run_id)                                                       NO key
```

Under doc 02's broader reading, `credential_issued` and `run_retired` would be
required to carry a field their originating tool cannot supply. The first
implementation of RM-006 took that reading and froze it into golden fixtures 02
and 07, which is how the conflict surfaced: fixtures are the byte-level
definition of a protected surface (VERSIONING.md), so a wrong reading there
becomes permanent at the next tag.

Invariants in play. I3 ("no action without a record") is what the dedupe key
protects: a retried tool call must not produce a second record of one action.
I4 (append-only history) is what makes the choice urgent — the field's presence
is part of the canonical preimage, so it cannot be corrected later without a
major schema version and a migration attestation.

## Decision

**IP §4 wins.** `idempotency_key` is required if and only if the event
originates from an MCP tool that accepts one:

- **Required** when `source` is `mcp` and `event_type` is one of
  `run_registered`, `tool_call`, `commit_intent`, `commit_recorded`.
- **Forbidden** on `credential_issued` and `run_retired`, whatever the source.
- **Unconstrained** otherwise — notably a `commit_recorded` repaired by the
  reconciler (doc 02 §3, TC REC-002), which is not an MCP tool call.

Absence is *enforced*, not merely un-required. Doc 02 §1 makes absent and empty
distinct states, and a field left optional-by-omission is one a later
implementation starts populating — at which point the canonical bytes for that
event type change, silently, forever.

Two supporting reasons, which are the substance rather than a deference to
document precedence:

- **`get_credential` must not be deduplicated.** IP §6.2 requires transparent
  re-fetch when an SVID expires, so a repeat call is a legitimate second
  issuance rather than a retry of the first. Each issuance is a distinct
  auditable fact. Collapsing them behind a dedupe key would hide credential
  churn, which is precisely the signal an auditor is looking for.
- **`retire_agent`'s idempotency is intrinsic to `run_id`.** IP §4: "Idempotent:
  retiring a retired run returns success with the original timestamp." A run
  retires once. A separate key would invent a way for two retirements of one run
  to disagree, which is a contradiction the ledger would then have to record.

Relatedly, doc 02 §2's `idempotency_key` limit of "≤128" is counted in **bytes**.
"Characters" does not survive crossing a language boundary: for U+1D11E,
JavaScript reports 2 (UTF-16 code units), Python 1 (code point), and Go 1 rune
or 4 bytes. That is doc 04 residual risk #4 exactly. Bytes is the only reading
every implementation computes identically, and it is the stricter of the two.

## Alternatives considered

- **Follow doc 02 §2 literally — require the key on every `source: mcp` event.**
  Rejected because it demands a value the emitting tool has no way to obtain.
  The MCP server would have to synthesise a key, and a synthesised dedupe key
  either collides (suppressing a real second credential issuance, breaking I3)
  or is unique per call (making the field decorative). Both outcomes are worse
  than absence.
- **Make the field optional everywhere and enforce nothing.** Rejected because
  "optional" is not a state doc 02 §1 admits for a value that is either present
  or absent. An unenforced field drifts: one implementation starts writing it,
  the canonical bytes for that event type change, and every previously written
  event of that type becomes unreproducible by the newer code.
- **Amend doc 02 §2 to match the implementation.** Rejected on process grounds.
  The project rule is that a conflict in a spec is a question for the human, not
  permission to amend the doc; and doc 02 §§2–5 are protected, so an edit there
  is a schema decision, not an editorial one. The narrowing wording is recorded
  as a follow-up below instead.
- **Defer the decision and ship the broader fixtures.** Rejected outright.
  Golden fixtures are immutable once merged, so deferring means the wrong
  reading becomes a protected surface and the correction becomes a major
  release with a migration attestation.

## Consequences

- Golden fixtures 02 (`credential_issued`) and 07 (`run_retired`) lose the
  field. Because the corpus is a hash chain, every fixture from `chain_position`
  2 through 14 was regenerated; `00-doc02-example`, `01-run_registered`,
  `genesis.hash` and `format-probe.*` are byte-identical to before. The
  regeneration was done with the Python oracle first and the Go implementation
  made to match it, never the reverse.
- `internal/event` enforces the rule in `Envelope.Fields`, driven by
  `TestSER003IdempotencyKeyScope`. `TestSER001FixturesObeyIdempotencyKeyScope`
  and `testdata/fixtures/v1/verify.py` additionally hold the golden corpus to
  it, so a fixture cannot drift away from the rule the envelope enforces.
- The event-type literals now appear in `internal/event/envelope.go` as
  unexported sets. The canonical `event_type` enum belongs with the event types
  (RM-007, #15); these sets are a local reference to it and must be kept in step
  when that lands.
- **Required follow-up, for the human only:** doc 02 §2's `idempotency_key`
  description should be narrowed from "Required on events created by MCP tool
  calls" to "Required on events created by MCP tool calls that accept an
  `idempotency_key`", and the byte-counted reading of "≤128" made explicit.
  `docs/` outside `docs/adr/` is not edited by implementing agents, so this ADR
  records the change rather than making it. Until that edit lands, this ADR is
  the operative reading.
- Exit cost. This is now a protected surface. Reversing it after the first tag
  means a new `schema_version`, a fixture set for that version with this one
  retained and still asserted, verifiers that accept both, and a signed
  migration attestation marking the cutover chain position (doc 02 §7). Before
  the first tag the cost is another regeneration of the chain.
