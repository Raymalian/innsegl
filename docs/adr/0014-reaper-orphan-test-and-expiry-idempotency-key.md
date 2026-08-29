# ADR-0014: Bound a run identity by its entry's TTL plus a configured grace, and key `run_expired` by run id

- Status: accepted
- Date: 2026-08-29
- Deciders: Mike

## Context

IP §6.7 is one sentence: *"Agent crashes without `retire_agent` → SPIRE entry TTL
expires it; a reaper deletes expired entries and appends `run_expired` (distinct
from `run_retired`)."* Doc 07 turns it into SPI-003. Building it forces two
questions neither document answers.

**What makes an entry "expired"?** SPIRE holds no liveness signal. A registration
entry created by `Client.RegisterRun` (RM-015) carries two durable facts and
nothing else — when the server created it, and the TTL of the SVIDs it issues.
There is no field saying "the workload behind this entry is still running" and
no callback when one stops. The reaper cannot detect a crash; it can only bound
a lifetime.

Worse, the two normative statements about that lifetime pull apart:

- IP §1: *"One SPIRE registration entry per run, short TTL, created at
  registration, deleted at retirement. Identity ≡ single run ≡ single purpose."*
- IP §6.2: *"SVID expires mid-run → `get_credential` re-fetches transparently."*

The second says a run may outlive the SVID TTL. The SVID TTL is therefore a
*rotation period*, not a run deadline, and "entry TTL expiry" in SPI-003 cannot
mean "the run ends when its first SVID does".

**How does a second pass avoid recording a second expiry?** Doc 05 §2 runs the
single-active components under leader election and #25 puts the reaper among
them, but election is a deployment property and failover double-runs are
expected — doc 05 §2 says as much of the sealer and reconciler ("both are
idempotent so failover double-runs are harmless").

Facts measured against the shipped stack, SPIRE 1.15.3 from
`deploy/compose/spire.yml`, not recalled:

- `types.Entry` carries `created_at` and `expires_at`, both seconds since the
  epoch. `created_at` is populated on entries created through the entry API.
  `expires_at` is **zero** on every entry `RegisterRun` creates, because
  `RegisterRun` sets only `x509_svid_ttl` and `jwt_svid_ttl`.
- The entry API has no path-prefix filter. `ListEntries` filters by exact SPIFFE
  ID, parent ID, selectors, hint or downstream — so subtree selection is the
  client's to make.
- A deleted entry leaves the server's datastore immediately, which is what
  RM-015's `RequireActiveRun` depends on, but the agent keeps serving an SVID it
  has already minted for a few seconds. RM-014 measured 3–7s; SPI-003 re-measured
  2.6–7.3s on this stack.

Invariants in play. **I3** ("no action without a record") is what forces the
ordering below: deleting an identity is an action. **I4** ("no record is ever
deleted or mutated … retirement deletes the SPIRE entry, never ledger content")
is what makes the key shape below irreversible, because `idempotency_key` is part
of the canonical preimage (doc 02 §4).

## Decision

**1. An entry is orphaned when the wall clock has passed a deadline derived from
the entry itself:** `expires_at + grace` when SPIRE holds an entry expiry,
otherwise `created_at + x509_svid_ttl + grace`. Grace is a caller-supplied policy
value, not a derived constant: `spire.ReaperConfig` treats a zero Grace as zero
so no caller is surprised into a policy it did not ask for, and `innsegl reap`
defaults its `-grace` flag to `DefaultReapGrace`, which is `DefaultRunTTL`
(5 minutes) — one further identity lifetime of slack.

An entry inside the agent subtree that the reaper cannot judge — a SPIFFE ID that
is not a run identity, an entry with no TTL of its own, an entry SPIRE reports no
timestamps for — is **reported and left alone**, never deleted. Deleting an
identity because its metadata was unreadable is worse than leaving it.

**2. `run_expired` carries `idempotency_key = "reaper:run_expired:" + run_id`,**
and the reaper records the expiry **before** deleting the entry. ADR-0004 leaves
the key unconstrained on this event type (it is neither required — the source is
`reaper`, not `mcp` — nor forbidden, since no MCP tool emits it). The key is
derived from the run id and nothing else, so it is stable across sweeps,
processes and restarts.

Idempotency therefore does **not** depend on the entry being gone. A pass that
still sees an entry SPIRE has already deleted finds the recorded expiry, appends
nothing, and re-issues a delete that returns `NotFound` — which is a success with
nothing deleted, on the same reasoning IP §4 gives for retirement.

## Alternatives considered

- **Reap at `created_at + TTL`, no grace.** Rejected: it bounds every run at its
  SVID TTL and makes IP §6.2's transparent mid-run re-fetch pointless, because
  the entry the re-fetch depends on would be deleted at the moment the first SVID
  expired. Reaping late costs detection latency; reaping early destroys a working
  run's identity mid-flight. The safe direction is late.
- **A flat maximum run age, ignoring the entry's TTL.** Rejected: it throws away
  the only per-run signal SPIRE holds. A run registered with a 20-second TTL and
  one registered with the 30-minute maximum are not the same risk, and a single
  constant would either reap the second too early or the first far too late.
- **Set `expires_at` at registration and let SPIRE prune expired entries.**
  Rejected on two counts. SPIRE's own pruning would delete the entry with nothing
  appended anywhere — I3 inverted, and the ledger could then no longer tell a
  retired run from a crashed one, which is the entire content of §6.7. It also
  requires changing `RegisterRun`, which is RM-015's merged surface.
- **No idempotency key; scan the ledger for an existing `run_expired`.**
  Rejected: `internal/ledger` exposes no run-scoped query, so this is O(chain) per
  orphan, and check-then-append is racy in exactly the concurrent case the key
  exists to survive. `EventByIdempotencyKey` is the read path the ledger already
  provides for this question (LED-008).
- **Delete the entry first, append second.** Rejected: a crash between the two
  erases an identity with nothing anywhere recording that it existed or why it
  went (I3). Appending first and crashing leaves the entry for one more sweep,
  visible in the ledger the whole time — the recoverable failure.
- **Filter the subtree server-side.** Not available: the entry API has no
  path-prefix filter. Client-side is also the safer direction — an entry the
  reaper cannot classify is one it leaves alone, whereas a server-side filter
  that quietly matched more than intended would quietly delete more than
  intended.

## Consequences

- **`internal/spire/reaper.go`** owns the policy; `innsegl reap` owns the default.
  SPI-003 drives both, against the containerised SPIRE and a real Postgres
  ledger, with a second run registered at the ordinary TTL that must survive the
  same sweep.
- **Irreversible.** `idempotency_key` is part of the canonical preimage, so the
  prefix above is fixed for every `run_expired` ever written. Exit cost after the
  first tag: a new `schema_version`, fixtures for it with this version's retained
  and still asserted, verifiers accepting both, and a signed migration
  attestation (doc 02 §7). Before the first tag the cost is a fixture
  regeneration — and there is no `run_expired` golden fixture today, so it is
  currently zero.
- **Residual risk: the idempotency namespace is shared.** MCP keys are
  caller-supplied (IP §4), so a client can occupy `reaper:run_expired:<run-id>`
  with an event of its own. The reaper then refuses to read that event as the
  run's expiry: `INVARIANT_VIOLATION`, alert-level, and the entry is left in
  place for a human rather than deleted on the strength of a record that is not
  about it. Fail-loud, not silent. Closing it properly needs a source-scoped key
  namespace in the ledger, which is `internal/ledger`'s surface and a schema
  decision, not this issue's.
- **Open question for the human.** Whether a bounded lifetime is the intended
  reading of IP §6.7 at all, given IP §6.2. Under this ADR a deployment whose
  runs legitimately outlive their entry TTL must set `-grace` to cover the
  longest legitimate run, and IP §1's "short TTL" then bounds SVID *rotation*
  rather than run *life*. If instead a run is meant to end when its entry TTL
  elapses, IP §6.2's transparent re-fetch needs rewording. This ADR does not
  amend either document: a conflict in a spec is a question for the human.
- **Leader election is not implemented and nothing depends on it.** Doc 05 §2's
  HA sketch names the sealer and the reconciler as single-active and does not
  name the reaper; #25 does. `innsegl reap` sweeps once and exits, so the
  deployment supplies the schedule and the single-activeness. Two overlapping
  sweeps produce one `run_expired` per orphan and one deletion between them.
