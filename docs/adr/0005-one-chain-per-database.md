# ADR-0005: Scope a ledger chain to a database

- Status: accepted
- Date: 2026-08-28
- Deciders: Mike

## Context

Doc 02 §2 defines `chain_position` as "1-based, strictly consecutive **per
chain**, assigned by the ledger under serialized append". It never says what a
chain is, and the envelope it defines has no `chain_id` member.

RM-008 (#16) built the hash chain against the sequence it was handed, which is
the right answer for the chain algebra and says nothing about storage. RM-009
cannot avoid the question: a table either holds one chain or several, and the
uniqueness constraints, the append lock and every read path differ between the
two. Its handoff comment raised the gap explicitly.

The constraint that shapes the answer is that doc 02 §§2–5 are a protected
surface. Adding `chain_id` to the envelope is a new major `schema_version` with
new golden fixtures, verifiers accepting both versions, and a signed migration
attestation marking the cutover position (doc 02 §7). It is not an option for a
storage decision, and the project rule is that a conflict in a spec is a
question for the human, not permission to amend the document.

The invariant in play is I4. The chain is what makes tampering visible; a
verifier walks 1→n and fails at the first mismatch. That walk presupposes it
knows which events form the sequence. If storage held several chains, every
artifact the system exports — a sealed segment, its Rekor anchor, an auditor's
dump — would carry no chain identity, because no hashed member names one. The
partition would live in unsigned out-of-band metadata, which is exactly the
kind of claim this project exists not to make.

## Decision

**One chain per database.** The store scopes a chain to the database it is
connected to: everything in `innsegl.events` belongs to one chain,
`chain_position` is its primary key, and a second chain is a second database.
There is no `chain_id` column on events and no scope argument on `Append`.

The database additionally carries a storage-level chain identity —
`innsegl.chain`, holding a generated `chain_id` and the genesis constant this
chain was rooted at. It exists so an operator, a backup or a client pointed at
the wrong database can tell, and so `Migrate` can refuse a database rooted at a
genesis this build does not compute. It is never part of an event and never
enters a preimage.

## Alternatives considered

- **Add `chain_id` to the envelope.** Rejected on the protected-surface rule.
  It would make the first storage decision of the project a major schema
  version with a migration attestation, before v0.1 has shipped a single event,
  and it would put a member in the preimage that a single-chain deployment —
  the only shape doc 05 describes — never varies.
- **A `chain_id` column on `events`, outside the hash.** Rejected because the
  scope would exist in storage and not in the artifact. A segment's Merkle root
  is computed over `event_hash` values (doc 02 §4.6), none of which commits to a
  chain identity, so an auditor handed a sealed segment could not say which
  chain it came from and the operator's answer would be unsigned. It also turns
  every uniqueness rule into a composite one — `(chain_id, chain_position)`,
  `(chain_id, idempotency_key)` — so a single query that forgets the scope
  merges two histories, which is the one corruption a hash chain cannot repair.
  And the append lock would need a per-chain key: either all chains serialize
  on one lock, buying nothing, or the key is derived per chain, which is a new
  way to get a lock wrong.
- **A chain per Postgres schema inside one database.** Rejected because it
  costs everything the previous option costs — a scope threaded through every
  statement — while buying less than a separate database: one blast radius, one
  role grant, one backup, one advisory-lock namespace, one `max_connections`.
  The isolation reads real and is not.
- **Derive the chain from `run_id`, or from the trust domain.** Rejected
  because the ledger is one history, not many: I3 says no action happens
  without a record, and an auditor asks what happened in this deployment, not
  what happened in run 42. `segment_sealed` and the system-scope alerts
  reference no run at all (doc 02 §2), so under a run-derived scope they would
  belong to no chain.
- **Defer, and let the first multi-chain deployment decide.** Rejected because
  the decision is not symmetric (see the exit cost below). Deferring means the
  default is chosen by whichever code path is written first, and the expensive
  direction is the one that gets chosen by accident.

## Consequences

- `chain_position` is the primary key of `innsegl.events`. `event_hash` and
  `prev_event_hash` are each `UNIQUE`, the second of which is the anti-fork
  constraint: an event can be the predecessor of at most one other event, so a
  second branch off any position is refused by an index rather than found later
  by a verifier. `idempotency_key` is `UNIQUE`. All three are database-wide,
  and no composite key exists to be got wrong.
- `pg_advisory_xact_lock` is scoped to a database, which now coincides exactly
  with the scope of a chain: one lock, no key derivation, single-writer append
  with readers untouched.
- Append throughput is bounded by one serialized writer per chain. Doc 05's
  estimate is ~2×10⁷ events/year, four orders of magnitude inside a single
  serialized writer, so the bound is not a limit worth engineering around. If
  it ever becomes one, the answer is another deployment, not a scope column.
- `Migrate` refuses a database whose recorded genesis differs from the constant
  this build computes (doc 02 §4.4). Pointing a binary at a foreign chain fails
  at migration rather than at the first append.
- Tests get a database each, which is now the same statement as a chain each.
- **Exit cost, and it is asymmetric.** Splitting is cheap: a new chain is a new
  database, the old one keeps its history untouched, and I4 is not disturbed.
  Merging is impossible — it would mean rewriting `chain_position` and
  `prev_event_hash` on existing events, which is precisely the mutation the
  ledger exists to refuse. Introducing a real multi-chain scope later costs
  either a new major `schema_version` carrying `chain_id` in the envelope, with
  new fixtures, dual-version verifiers and a signed migration attestation
  (doc 02 §7), or a storage-level column whose scope the exported artifacts
  still do not carry. That asymmetry is why the choice is made now and written
  down rather than left to the first caller.
- **Flagged for the human, not resolved here.** Doc 02 §2 says "per chain" and
  defines no chain. This ADR defines it for storage only, and only for the
  single-chain deployment doc 05 describes. If a deployment ever needs several
  chains in one ledger, doc 02 has to say what names a chain and how a verifier
  reading a sealed segment learns which one it is looking at. That is a schema
  question, and it is not an implementing agent's to answer.
