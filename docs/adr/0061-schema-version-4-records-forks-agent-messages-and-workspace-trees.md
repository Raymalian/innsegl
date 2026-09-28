# ADR-0061: Schema version 4 records a fork's origin, an agent's own messages, and a per-step workspace tree hash

- Status: proposed
- Date: 2026-09-28
- Deciders: the operator

## Context

Three ADRs decided, on 2026-09-28, that the flight-recorder work needs facts
the chain has no member for, and each one deliberately stopped short of
naming that member itself:

- **ADR-0058** decision 5: a fork is a new identity linked to a known
  fingerprint under a new session, and what it forked from is true the
  moment the run is created — the same argument that put `parent_run_id` on
  `run_registered` in schema 2, applied to a different lineage. But
  `parent_run_id` already answers a different question (who spawned this run
  as a subagent), and a fork is neither: no spawning tool call names it, and
  the run it forked from may still be active, lapsed, or already retired.
  ADR-0058's own words: "whatever member the bundled change eventually adds
  must not be `parent_run_id`, which already means something else." Until a
  member exists, a fork's origin lives only in the gateway's insert-only
  mapping table — operational state, not tamper-evident, outside I5's
  third-party verification.
- **ADR-0057**: the brief is visible twice over in the traffic a gateway
  captures — as the first user message and as the spawn prompt inside a
  subagent's own tool call — and every one of an agent's own messages passes
  through the same traffic. Its Consequences name this outright as
  undecided: "Whether capture needs event types the ledger does not already
  have (for an agent message, or a snapshot) is not decided here: any new
  event type goes through doc 02's protected-schema process on its own
  merits."
- **ADR-0060** decision 5: a workspace snapshot is taken before each request
  is forwarded, against a private git index, and its tree object is what
  should be checkable against the chain: "The resulting tree object's hash is
  what the ledger records, the same way every other content this project
  hashes into the chain is recorded by its digest, not by where it happens to
  be stored."

All three point at one bundled decision rather than three separate ones.
ADR-0058's Consequences state the reason plainly: "the operator has bundled
every protected-schema addition this epic needs into **one** doc 02
change — one `schema_version`, one migration attestation, one set of
updated golden fixtures, decided together before E15 (#358) starts." This
ADR is that decision, tracked as #407 (RM-258).

Doc 08 §3 (the versioning policy) allows a protected surface — the event
schema is surface 1 — to change only in a release that also ships, together:
a new `schema_version` accepted alongside every earlier one, forever;
updated golden fixtures for the new version; a signed migration attestation
marking the exact chain position of the cutover; and a superseding ADR. Per
ADR-0007, an addition to the closed member and type lists is not a
modification or a removal, so it does not fail a MINOR/PATCH release's
diff on its own — but moving a protected surface at all still requires the
MAJOR-release procedure taken early, which `VERSIONING.md`'s pre-1.0 section
already requires for exactly this case.

Before deciding which additions earn that cost, every candidate the
epic's own issues had raised was evaluated against what the chain, the body
store, and the existing alert mechanism already do — nine in total, not
three. Six needed no protected addition at all: a commit's landing outcome
is already derived, never assumed, from the tool result of the `git commit`
invocation and from asking the repository whether the recorded SHA is
reachable (ADR-0059 §6); a tool call's outcome — success, error, or refusal
— is already carried in full under `tool_call`'s existing `payload_digest`
and body store, the same mechanism ADR-0051 already relies on; a captured
body's truncation is a body-store retention decision, not a chain fact,
and doc 02 §1 already treats an absent value as the honest way to record an
incomplete one; the gateway does not need its own `source` value, because
`source` names a writer's *role* and ADR-0058 decision 1 is explicit that
the gateway is a new trigger for that role, not a new one; and neither a
"commit requested, never signed" alert nor a rate-limit alert needs a new
event type, because both are structurally the existing `ledger_drift_detected`
alert — a chained fact with no corroborating record inside a window — and
ADR-0025 decision 5 already rejected inventing a rate-limit event type for
the identical reason. The operator reviewed that evaluation and approved
exactly the remaining three additions below on 2026-09-28.

## Decision

**`schema_version` becomes `"4"`.** Three additions, each on an existing or
minimally-new type, following the exact shape ADR-0045 (schema 1→2) and
ADR-0051 (schema 2→3) already used: additive, closed-list membership, no
existing member touched.

1. **`forked_from_run_id` on `run_registered`.** Optional. String, the
   `run_id` grammar (the same grammar `parent_run_id` already uses). Names
   the run a fork's traffic-observed fingerprint was linked from. Needed by
   ADR-0058 decision 5. Reuse of `parent_run_id` was not enough because that
   member already answers "who spawned this run as a subagent" — a
   containment-free, exact-equality fact about a spawning tool call — and a
   fork has none: it is a known conversation fingerprint continuing under a
   new session, never a spawn, and the run it forked from can be active,
   lapsed, or retired at the moment the fork is linked. One member cannot
   honestly answer both questions at once.

2. **A new event type, `agent_message`.** Members: `role`, required, string
   enum (`brief` | `assistant`); `payload_digest`, required — an override of
   the general "present iff a payload exists" rule, with direct precedent in
   ADR-0051's `run_adopted`, whose `payload_digest` is likewise required and
   names the claim rather than an optional attachment. As proposed here it
   is the ordinary envelope grammar, `sha256:` plus 64 lowercase hex, the
   same as every other `payload_digest` in doc 02 §2 — no new digest
   grammar is introduced by this ADR (see the confirmation-risk open
   question in Consequences, which this ADR does not resolve). Needed by
   ADR-0057: the brief and an agent's own messages are traffic the gateway
   captures and the flight-recorder's stated purpose is to show, provably,
   and neither has a home in any existing type. Reuse of `tool_call` was
   not enough because ADR-0021 pins `tool_call.tool_name` to literally name
   the agent tool that was invoked and refuses any value spelling something
   else with a message saying what the argument is for; a brief or a model
   message names no tool, and forcing it through `tool_call` would
   misrepresent the record to any reader who takes `tool_name` at its word.

3. **`workspace_tree_hash` on `tool_call`.** Optional. String, a git object
   id — the same convention `commit_intent.tree_hash` already uses, not
   `sha256:`-prefixed. Records the hash of the workspace snapshot taken
   before the request that produced this tool call was forwarded. Needed by
   ADR-0060 decision 5. Not a duplicate of `commit_intent.tree_hash`: that
   member is the staged tree of a specific commit (phase A of two-phase
   signing), while this is a per-step snapshot of the whole working tree,
   taken on every request regardless of whether it ever becomes a commit.
   Carried on `tool_call` rather than a new type because a snapshot is 1:1
   with the tool result that triggered it — one event per action stays
   true, with no event-volume doubling from a parallel snapshot type.
   **Scope.** The hash is of the working tree *after* the step, whatever
   produced its state — the run's own edit, a human editing the same
   checkout, or another agent sharing it. It is evidence of what the tree
   held at that moment, never a claim that this run authored everything the
   hash covers; authorship of a specific change is what `commit_intent` and
   `commit_recorded` already establish, separately and per commit. A
   deployment that wants this member to mean what a reader will assume it
   means should give each parallel agent its own worktree, so one run's
   `workspace_tree_hash` is never state another run also wrote into.

**Canonical serialization is unchanged.** Doc 02 §4 — JCS, the hash
construction, the genesis constant — is untouched by any of the three.
Only the closed allowed-member list per type grows, exactly as schema 2 and
schema 3 already did.

**The migration attestation.** A `schema_migrated` event states
`from_schema_version: "3"`, `to_schema_version: "4"`, and
`cutover_position` fixed at the exact chain position of the cutover — set
when the release actually ships, per doc 08 §3(c), and not fixed by this
ADR. New golden fixtures cover schema 4: a `run_registered` carrying
`forked_from_run_id`; an `agent_message` with `role: brief` and one with
`role: assistant`; a `tool_call` carrying `workspace_tree_hash`. Every
existing schema 1–3 fixture is kept exactly as committed (TC-SER's own
rule, and I4); a schema-4-aware verifier must accept schema `"1"`, `"2"`,
`"3"`, and `"4"` side by side, forever.

**Doc 02 gains one errata line** pointing at this ADR, mirroring the
convention ADR-0051 already set: this ADR carries the three members'
definitions, and doc 02's §3 table is not rewritten.

**Prospective only, per E7.** All three additions apply from the schema-4
cutover forward and never before it. No `agent_message` is ever written for
a brief or a model message that predates the cutover; no `run_registered`
already on the chain gains a `forked_from_run_id` after the fact; no
`tool_call` already on the chain gains a `workspace_tree_hash` it was
appended without. E7 reads this as the general case of the same rule doc 08
already states for the schema itself — "records are never migrated in
place" — extended to the facts this ADR adds: a fork, a brief, or a
workspace state that happened before the cutover is unattributed by these
members, exactly as pre-adoption commits are unattributed under E7, and
neither is inferred or backfilled after the fact.

## Alternatives considered

- **Reuse `parent_run_id` for fork lineage.** Rejected: ADR-0058 decision 5
  already forbids it by name. A fork is not a subagent — nothing spawns it
  through a tool call — and the run it forked from is not necessarily
  active, where a `parent_run_id` names a spawning run whose relationship
  is fixed at the child's creation. Overloading one member to answer both
  would leave a reader no way to tell which question it was answering for a
  given event.
- **Carry the brief and an agent's own messages inside `tool_call`.**
  Rejected: ADR-0021 pins `tool_call.tool_name` to name the exact agent
  tool invoked, and refuses any other use of the argument outright. Neither
  a brief nor a model message invokes a tool; the type's own definition
  would become false the moment it carried one.
- **Bundle all nine evaluated candidates into this version, since the
  version is moving anyway.** Rejected on the six the evaluation found
  already answered without a schema change: a landing-outcome field and a
  tool-call outcome field are both derivable or already covered by the
  existing body-store mechanism, and this project has twice already refused
  a free addition of exactly that shape when the version was moving for
  another reason (ADR-0059 §6; ADR-0025 decision 5); a `body_truncated`
  field would let a schema member paper over a body-store policy question
  doc 02 §1 already answers by omission; a fifth `source` value and a new
  alert type would each add a protected string with no I5 verification
  benefit over the mechanism already in place. Adding only what has no
  working substitute keeps the version bump's cost — a new fixture set, a
  new verifier branch, a migration attestation — proportionate to what it
  actually buys.
- **Leave fork lineage in the gateway's mapping table indefinitely.**
  Rejected as a permanent answer, though it is the correct interim one:
  that table is insert-only but still operational state, outside I5's
  third-party verification. Acceptable while nothing else needs it
  (ADR-0058 already relies on it for a fork's issue-level acceptance
  criteria); not acceptable for a fact whose whole point is to be checkable
  by a stranger, which is why it is in this bundle at all.
- **Land each of the three members in its own schema version, as the code
  that needs it ships.** Rejected: doc 08 §3 attaches the same fixed cost —
  a new `schema_version`, updated golden fixtures, a migration attestation
  — to every protected-schema change regardless of size. Three versions for
  three facts all named on the same day, by ADRs decided on the same day,
  would triple that cost for no benefit; it is exactly the bundling
  ADR-0058 asked the operator to decide once, before the epic that needs it
  starts.

## Consequences

- **Protected surfaces change.** One new event type (`agent_message`, with
  its own two members `role` and `payload_digest`) and two new members on
  existing types (`forked_from_run_id` on `run_registered`;
  `workspace_tree_hash` on `tool_call`). Purely additive: no type is
  renamed, no existing member changes meaning, no MCP tool name or error
  class changes. ADR-0007's gate reads this as an addition rather than a
  modification — the class that does not fail a MINOR/PATCH release's
  fixture diff — but moving a protected surface at all still needs the
  MAJOR-release procedure taken early, per `VERSIONING.md`'s pre-1.0
  section. Doc 08 allows the change only with a new `schema_version`
  (`"4"`), golden fixtures for it, a `schema_migrated` attestation at the
  cutover, and this ADR. The operator accepted that cost for a pre-1.0
  release on 2026-09-28, with every other requirement of doc 08 kept.
- **Doc 02 gains one errata line** pointing at this ADR. Doc 02's own §3
  table is not rewritten.
- **Events already on the chain are untouched (I4).** A schema 1, 2, or 3
  event carrying none of these three members stays valid forever, unchanged;
  a schema-4-aware verifier keeps validating every earlier version by its
  own rules, with no exception carved out for it.
- **What stays exactly where it was.** The six evaluated-and-not-added
  candidates — a landing-outcome field, a tool-call outcome field, a
  body-truncation field, a fifth `source` value, and the two alert types —
  keep the mechanism that already answers them: the body store, a read-time
  derivation, or the existing `ledger_drift_detected` alert. None of them
  becomes harder to check for having been left out of this version; each
  already had a working answer before this ADR and keeps it after.
- **Fork lineage becomes I5-checkable once this lands, and only then.**
  Until the migration cutover, a fork's origin is still only the gateway's
  mapping table — insert-only, operational, and outside third-party
  verification, exactly as ADR-0058 left it. After the cutover, a fork
  linked before it stays exactly that way, permanently: per E7, this ADR is
  never read backwards to add `forked_from_run_id` to a `run_registered`
  that already exists.
- **`workspace_tree_hash` is evidence of tree state, not a claim of
  authorship.** It hashes the working tree after a step regardless of who
  or what changed it since the previous snapshot — the run itself, a human
  at the same checkout, or another agent sharing it. A reader who treats it
  as "this run wrote everything this hash covers" is reading past what it
  proves. Recorded here as a scope note for whoever implements E16, since
  the member's name invites exactly that misreading.
- **Open question for the operator, not decided by this ADR.** A plain
  digest of short, guessable content — a brief such as "fix the login bug"
  — can be *confirmed* by anyone who can read the ledger or the read-only
  API: hash their guess, compare. This is not new; `tool_call.payload_digest`
  already has the identical weakness today, unremarked until this ADR
  named it for `agent_message`. Recorded but not fixed here because fixing
  it changes what `payload_digest` means on this new type, which is a
  further protected-surface decision the operator has not been asked to
  approve — the 2026-09-28 approval covered the three additions in
  Decision, plain-digest grammar included, not a new digest kind.
  **Recommendation for a follow-up ADR:** make `agent_message.payload_digest`
  a keyed digest — HMAC-SHA256 under a per-deployment secret the core holds
  and never exports — with a grammar distinguishable from a plain digest
  (for example an `hmac-sha256:` prefix in place of `sha256:`), so a
  verifier can tell which kind it is holding and a guesser without the
  secret cannot confirm a brief's content by hashing candidates. Moving
  `tool_call.payload_digest` to the same keyed form is a separable, later
  decision and is explicitly not part of this recommendation or this
  bundle: `tool_call` bodies are already reachable through the body store
  by a caller with ledger access, so the trade the keyed form makes —
  weakening unassisted third-party confirmation in exchange for keeping a
  short digest un-guessable — needs its own evaluation against that
  existing access path, not an inherited answer from `agent_message`.
- **Exit cost.** Events are append-only: once schema 4 events carrying any
  of these three members exist, they stay valid under schema 4 forever,
  independent of whether a later release keeps writing new ones in the same
  shape — I4 protects bytes already written, not the decision to keep
  producing more of them. Removing any of the three later means refusing
  new instances, not rewriting the ones already on the chain, exactly as
  ADR-0051 already stated for `run_adopted`. An `agent_message` event, once
  appended, permanently records that a brief or a model message existed
  with a given digest; there is no path that un-records one.
- **Tests to write, first:** a schema-4 `run_registered` with and without
  `forked_from_run_id`, both validating and hashing correctly; an
  `agent_message` with `role: brief` and one with `role: assistant`, each
  refusing an absent `payload_digest`; a schema-4 `tool_call` with and
  without `workspace_tree_hash`; every schema 1–3 golden fixture
  re-verified byte-for-byte unchanged under a schema-4-aware verifier; a
  schema-3-only reader's behaviour against a member it does not recognise,
  per doc 02 §1's tolerance rule; the protected-surfaces gate recording
  these three as an addition, never a modification, against the
  pre-schema-4 manifest.
