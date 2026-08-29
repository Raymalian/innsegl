# ADR-0021: Let `record_event` write exactly one event type, `tool_call`, and read its `event_type` argument as the agent tool's name

- Status: accepted
- Date: 2026-08-29
- Deciders: Mike

## Context

IP §4 gives `record_event` in one line:

> `record_event(run_id, event_type, payload_digest, idempotency_key)` →
> `{event_id, chain_position}`.

Read literally, `event_type` selects one of doc 02 §3's eleven `event_type`
values. That reading does not survive contact with doc 02 §3, and the way it
fails is worth stating precisely, because it is what decides this ADR.

**Six of the eleven are unreachable by construction.**

- ADR-0004 forbids `idempotency_key` on `credential_issued` and `run_retired`,
  "whatever the source", and enforces the absence in `internal/event`.
  `record_event` always carries a key (IP §4), so an event of either type built
  by this tool is refused by the schema before it reaches the chain.
- doc 02 §3's "Emitted by" column attributes `commit_intent_expired`,
  `run_expired`, `unattributed_signature_detected`, `ledger_drift_detected` to
  the reconciler and the reaper, and `segment_sealed` to the system. This tool's
  `source` is `mcp`. Recording one of those from a tool call would put an MCP
  attribution on a fact that doc 02 assigns to a component the caller is not.

**Four more are another tool's output, and each requires members IP §4 gives
this tool no argument for.** `run_registered` needs `agent_type` and
`task_ref`; `commit_intent` needs `repo` and `tree_hash`; `commit_recorded`
needs six members including `rekor_log_index`. A caller able to write them
could claim an identity SPIRE never issued (I1) or a Rekor entry that does not
exist (I2, I5) — which is exactly the state the reconciler exists to raise
`ledger_drift_detected` about (IP §6.5). Letting a caller forge one would put
the forgery *inside* the ledger the reconciler compares against.

That leaves `tool_call` — "One agent tool invocation; body only as
`payload_digest`", the row issue #32 describes in its own summary. And
`tool_call` requires a member IP §4 also gives this tool no argument for:
**`tool_name`**.

So the literal reading makes the accepted set **empty**: under it,
`record_event` cannot write any event at all. That is not an interpretation a
shipped tool can hold.

Invariants in play. I3 ("no action without a record") is what makes an
unusable `record_event` unacceptable rather than merely awkward — it is the
only surface an agent has for recording its own actions. I4 (append-only) is
what makes the choice urgent: whatever goes into `tool_name` is part of the
canonical preimage and cannot be corrected later without a new major
`schema_version` and a migration attestation (doc 02 §7). E4 is what the tool
is for: references and hashes, never bodies.

## Decision

**1. `record_event` writes exactly one of doc 02 §3's eleven event types,
`tool_call`, and the caller does not select it.** The forgery question is
closed by construction rather than by an allowlist: there is no argument, no
value and no ordering of arguments that causes this tool to append any other
type.

**2. IP §4's `event_type` argument names the AGENT TOOL that was invoked, and
is recorded as the event's `tool_name`.** IP §4's four arguments then map one
for one onto the four caller-supplied members of a `tool_call` event —
`run_id`, `tool_name`, `payload_digest`, `idempotency_key` — and every other
member of the envelope is server-decided or ledger-assigned. The argument is
faithfully rendered into the member that exists for it.

**3. A value that spells one of the eleven `event_type` values is refused,
including `tool_call` itself**, as `INVARIANT_VIOLATION` with a message saying
what the argument is for. That value is what a caller reading IP §4 literally
would send, and it must fail loudly: silently recording a tool named
`segment_sealed` would put a string confusable with an event type into an
append-only chain forever, and a dashboard timeline (doc 06) would render it
beside real event types.

**4. `tool_name` is held to a name grammar, `^[A-Za-z0-9][A-Za-z0-9._:/@+_-]*$`
within doc 02's reference bound.** doc 02 gives the member no grammar, only the
bound that `internal/event/validate.go`'s own E4 note relies on: "A body cannot
be smuggled into `reason` or `tool_name`, because a reference is at most
MaxReferenceBytes." This narrows that bound to a *name*: it covers `bash`,
`Read`, `str_replace_editor`, `mcp__codemap__search_symbol`,
`github.com/acme/api` and `slack:post`, and admits no whitespace, no line
break, no quote and no brace — so a JSON body, a diff hunk, a shell transcript
and a sentence of prose are refused on their punctuation whatever their length.
Narrowing what the schema accepts is always safe; widening it would not be.

**5. `payload_digest` is `sha256:` plus exactly 64 lowercase hex digits, or
absent.** doc 02 §2 makes it conditional — "Present iff a payload exists" — and
doc 02 §1 admits no empty-string placeholder, so an empty argument omits the
member rather than writing it blank. A non-empty value that is not a digest is
refused, and **the refusal does not quote it back**: an error message is a
second place a payload could come to rest.

**6. The run checks live inside the idempotency claim; the argument checks live
outside it.** Argument validation is a property of the request alone, so a
malformed call costs nothing and reserves no key. Whether the run exists and is
live is authoritative state that changes, and IP §6.6 requires a replay to
return the original result — so a run retired *after* a successful call must
not turn that call's replay into a refusal. Putting the checks inside the claim
means a replay is answered from the recorded reply and never re-gated.

## Alternatives considered

- **Accept only the literal `event_type == "tool_call"` and refuse the other
  ten, then set `tool_name` to a constant — `"record_event"`, the MCP tool
  through which the invocation was recorded.** This is the reading that keeps
  IP §4's argument name meaning what it says, and it was the strongest
  competitor. Rejected because it destroys the member's information content
  permanently. Every `tool_call` in history would carry the same `tool_name`,
  the run-detail timeline of doc 06 would render N identical rows, and an
  auditor could never learn which tool an agent invoked — the one question
  doc 02 §3 created the member to answer. ADR-0004 rejected exactly this shape
  of outcome for `idempotency_key`: a synthesised value "either collides … or is
  unique per call (making the field decorative). Both outcomes are worse than
  absence." Here absence is not available, so the decorative outcome is the
  whole cost. And because the chain is append-only, it is not correctable
  later: it would take a new `schema_version` with a migration attestation. The
  cost of *this* ADR's reading, by contrast, is that one argument's NAME reads
  oddly against IP §4 — reversible by a documentation edit, with no effect on
  any recorded byte.

- **Add a fifth argument, `tool_name`, and leave `event_type` as the enum.**
  Rejected: IP §4's five signatures are the interface contract the contract
  tests are written from, and doc 08 §3 protects the tool surface. Adding an
  argument is a change to that surface, which is a human's decision and a
  release-level one — not something an implementing agent does to make its own
  issue easier. It is recorded as the follow-up below instead.

- **Read `tool_name` out of MCP request metadata (`_meta`, the transport's
  headers, the session).** Rejected outright, and it is worth writing down why:
  it would be an undocumented side channel into an append-only ledger — an
  unbounded, unvalidated string reaching a protected member through a path no
  schema covers. That is the precise shape of the hole this issue exists to
  prevent (E4), and it would be invisible in IP §4's signature.

- **Accept any tool name, including the eleven `event_type` spellings, on the
  grounds that refusing them is cosmetic — a caller can always send
  `run_registered ` with a trailing space.** Rejected. The refusal is not
  claimed as a security boundary; the security property is decision 1, which no
  spelling can defeat. It is a confusability guard, and it is also what turns
  the most likely wrong call in the whole tool — the literal reading of IP §4 —
  from a silent wrong result into a message that tells the caller what to send.
  A refusal that costs nothing and removes a permanent ambiguity is worth its
  four lines.

- **Make `payload_digest` mandatory, since the issue summary says the event
  "carries only a digest".** Rejected: doc 02 §2 says the member is present iff
  a payload exists, and an invocation with no out-of-band body has no digest to
  send. Requiring one would force callers to invent a digest of nothing — a
  fabricated reference in a system whose entire claim is that its references
  are real.

- **Stop and ask the human before writing any code, since the project rule is
  that a spec conflict is a question and not permission to amend.** Seriously
  considered — doc 01 §4 and doc 02 §3 genuinely disagree here, and the
  disagreement is not small. Rejected on the ADR-0004 and ADR-0016 precedent:
  both resolved a doc 01 / doc 02 conflict inside an ADR and recorded the
  document edit as a human-only follow-up, because the alternative was freezing
  a protected surface by not deciding. This tool cannot exist without the
  decision, and `tool_name`'s content becomes immutable at the first append.
  The decision is made here and nowhere else; no document outside `docs/adr/`
  is edited.

## Consequences

- **`record_event` is a tool that cannot forge.** MCP-006's row for this tool
  reaches five of IP §4's eleven classes — `RUN_NOT_FOUND`,
  `RUN_ALREADY_RETIRED`, `LEDGER_UNAVAILABLE`, `DUPLICATE_REQUEST`,
  `INVARIANT_VIOLATION` — and none of the identity or signing classes, because
  it touches neither SPIRE nor Sigstore.

- **The run directory is get_credential's, not a second one.** RM-023 wrote
  that "the run directory is shared with the other four tools, and a second
  definition of what is a run is a second thing that can disagree about
  retirement". `record_event` takes `CredentialRuns` and reuses
  `credentialRunIdentity`, so the check that the directory answered about the
  run that was asked for, with that run's own identity inside the `/agent/`
  subtree, has one implementation across the tools rather than three.

- **`tool_name`'s grammar is now part of what a caller can rely on.** It is not
  a protected surface — doc 02 gives the member no grammar and this narrowing
  lives in `internal/mcp` — but tightening it further after the first tag would
  refuse calls that used to work, so it should be treated as behavioural
  contract. Loosening it back toward doc 02's bare reference bound is always
  safe.

- **Required follow-up, for the human only** (`docs/` outside `docs/adr/` is not
  edited by implementing agents):
  1. IP §4's `record_event` signature should be corrected. Either rename
     `event_type` to `tool_name`, which is what this ADR reads it as, or add a
     fifth `tool_name` argument and constrain `event_type` to `tool_call`. The
     first costs nothing; the second changes the tool surface.
  2. doc 02 §3 should say which of the eleven types an MCP *tool call* may
     originate. The "Emitted by" column says `mcp` for six of them without
     distinguishing which tool, and this ADR had to derive the answer from
     ADR-0004 plus the type-specific member lists.
  3. doc 07 has no test ID for "a caller cannot record an event type it does not
     own". MCP-003 covers schema conformance and MCP-006 the error matrix;
     `TestRecordEventWritesToolCallAndTheCallerCannotForgeAnotherType` is named
     for the behaviour and cites this ADR.

- **Exit cost.** Low on the wire, permanent in the chain. Reversing decision 2
  — reading `event_type` as the enum after all — costs an argument rename and a
  test run *before* the first `tool_call` is appended in anger. Afterwards, the
  `tool_name` values already recorded stay what they are: they are agent tool
  names, in an append-only chain, and nothing rewrites them. That asymmetry is
  the reason this ADR prefers recording a true value under an oddly named
  argument to recording a decorative one under a correctly named argument.
