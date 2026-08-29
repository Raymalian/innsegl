# ADR-0013: Record SPIRE entry drift as `ledger_drift_detected` where a subject event exists, and refuse to record the unattributed case at all

- Status: accepted
- Date: 2026-08-29
- Deciders: RM-019 (#27)

## Context

Threat model AB-11 — "Tamper with SPIRE entries directly to widen a run's
identity" — is carried in doc 04 with the mitigation "Entry reconciliation +
alert" and the status **open — add TC**. Doc 04's SPIRE deployment section gives
the mechanism: "entries mutated out-of-band → periodic reconciliation of
expected-vs-actual entries; alert on unexplained entries (extends REC drift
model to SPIRE)".

ADR-0012 leaves a second, related hole open on purpose and names this issue as
its only control: `BatchDeleteEntry` carries opaque entry IDs, rego cannot
resolve one to a SPIFFE ID, and so the authorization policy that scopes entry
*creation* to the agent subtree cannot scope entry *deletion* at all. A stolen
admin credential can delete any entry in the trust domain. ADR-0011 adds a third
route: the SPIRE server's local admin socket is unauthenticated by construction
and is contained by a private tmpfs, not by authorization, so anything that
reaches the server host has full admin.

Reconciliation therefore has to detect four states, and the question this ADR
settles is which of them the **closed** event schema of doc 02 §3 can carry.
Doc 02 §7 makes that schema unamendable outside a major version with a migration
attestation, and doc 01's protected-strings rule makes inventing an
`event_type` a change no implementing agent may make.

The two candidate rows in doc 02 §3 are:

| `event_type` | Extra required fields | Meaning |
|---|---|---|
| `unattributed_signature_detected` | `rekor_log_index` (integer), `rekor_entry_uuid`, `certificate_identity` | Alert: trust-domain signature with no intent |
| `ledger_drift_detected` | `subject_event_id`, `reason` | Alert: ledger claim with no external proof |

## Decision

Three of the four drift kinds are appended as `ledger_drift_detected`, carrying
the ledger event whose claim the SPIRE state contradicts as `subject_event_id`:

| kind | `subject_event_id` | the claim it contradicts |
|---|---|---|
| `spire_entry_missing` | the run's `run_registered` event | doc 02 §3 gives that event's meaning as "Identity created; SPIRE entry exists". SPIRE holds none. |
| `spire_entry_not_deleted` | the run's `run_retired` or `run_expired` event | IP §1: retirement deletes the SPIRE entry. It is there. |
| `spire_entry_duplicated` | the run's `run_registered` event | IP §1 allows exactly one entry per run. There are more. |

Each is literally doc 02's own gloss on the type — "ledger claim with no
external proof" — with SPIRE's entry list as the external proof, in the same
way the Rekor cross-check of IP §6.5 is the external proof for a
`commit_recorded`.

The fourth kind, `spire_entry_unattributed` — SPIRE holds an entry in the agent
subtree that no ledger run explains at all — **is not written to the ledger**.
It is raised through the reconciler's alert sink (error-level `slog` by default)
and reported in `Result.Unrecordable`, and the reconciler says so rather than
going quiet.

The `reason` values are constants per kind and carry no entry id, SPIFFE ID or
timestamp; what varies goes in the event's `run_id` and `spiffe_id` members.
`reason` is half the idempotency key, so a value that varied with anything but
the kind would make the same standing finding appendable twice.

## Alternatives considered

**Force `ledger_drift_detected` with a synthetic `subject_event_id`.** Rejected:
there is no subject. The whole content of the finding is that the ledger says
nothing about this identity, and `subject_event_id` is validated as a UUIDv7
that names a real event. A zero UUID, or the id of some unrelated event, is a
false statement written into an append-only chain that I4 forbids anyone to
correct by deletion. A detection control that lies in its own record is worse
than one that reports out of band.

**Reuse `unattributed_signature_detected`.** Right shape, wrong domain, and it
does not typecheck. Its three required members describe a Rekor entry:
`rekor_log_index` is an integer, `rekor_entry_uuid` and `certificate_identity`
are references. A SPIRE registration entry has an honest value for at most
`certificate_identity` (the SPIFFE ID), and doc 02 §1 forbids empty-string
placeholders for the other two — "Absent and empty are distinct states and only
'absent' is allowed for a missing value" — while the schema requires them
present. There is no way to write this event that the ledger would accept.

**Add `unattributed_identity_detected` to doc 02 §3.** This is the correct
long-term fix and it is not an implementing agent's to make. Doc 02 §7: any
change to §2–§5 is a new major `schema_version`, released only with updated
golden fixtures, verifiers that accept both versions, and a signed migration
attestation event marking the cutover position. It is recorded as an open item
below rather than performed.

**Have the reconciler delete the unexplained entry.** Rejected: reconciliation
is detection, and deletion is a race it cannot win. An entry created by an MCP
whose `run_registered` append has not yet committed is indistinguishable, in
one cycle, from a planted one; a reconciler that deletes on sight would break
IP §6.5's ordering and take out live runs. Detection is what doc 04 claims and
it is what this delivers.

**Reconcile the whole trust domain rather than the agent subtree.** Rejected:
the infrastructure entries the stack needs — spire-oidc's, created by
`deploy/compose/spire/register.sh` under `/innsegl/` — are not run identities
and have no ledger events by design. Flagging them would put a permanent false
positive in the alert stream on every deployment, and an alert that is always
firing is an alert nobody reads. An identity minted outside the agent subtree
is AB-10, whose control is the authorization policy of ADR-0012 and whose test
is SPI-005.

## Consequences

**Easier.** AB-11 has a test (SPI-008) and a control for the first time. The
ADR-0012 residual — an admin credential that can delete any entry — becomes
detectable within one reconciler cycle, with a ledger event naming the run.
Idempotency needs no new state: the dedupe key is `(subject_event_id, reason)`
read back out of the chain, so a restarted or newly leader-elected reconciler
(doc 05 §2 runs it single-active with failover) is as quiet as the one it
replaced.

**Harder, and honestly so.** The one kind that is AB-11 in its purest form — an
entry for an identity the ledger has never heard of — is the one kind with no
ledger record. Its alert lives only in the operator's log stream and in the
reconciler's returned `Result`, which means:

- it is not in the append-only chain, so it is not covered by I4's immutability,
  not sealed into a segment, and not anchored in Rekor;
- its dedupe is in-process, because there is no ledger record to read back, so
  a restarted reconciler re-alerts once for each standing finding. That is a
  direct consequence of the missing event type, not an independent choice;
- the dashboard's drift feed (FD §3.1) will not show it until the event type
  exists.

**Open item for a human — doc 02 §3 needs a new event type.** An
`unattributed_identity_detected` alongside `unattributed_signature_detected`,
system-scope (`run_id`/`spiffe_id` omitted, as fixture 09 already demonstrates
for a system-scope alert), with the SPIRE entry's SPIFFE ID and entry id as its
required members. That is a major `schema_version` with a migration attestation
per doc 02 §7. Until it exists, this ADR is the operative reading, and the
reconciler reports the gap on every cycle rather than hiding it.

**Open item for a human — doc 07 needs an SPI-008 row.** Issue #27's acceptance
criterion is "new TC needed" and `docs/` outside this directory is not an
implementing agent's to edit. The row is written out in the header comment of
`internal/spire/reconcile_test.go` ready to be transcribed, and doc 04's AB-11
row can move from "**open — add TC**" to "SPI-008" at the same time.

**Reversal cost.** Low for the recording decision — the three recordable kinds
are ordinary `ledger_drift_detected` events and a future schema version can
supersede them by the ordinary `supersedes` route (I4). The unattributed case
costs whatever the schema migration costs, which is doc 02 §7's price and is
not reduced by anything done here.
