# ADR-0036: Cross-check the chain against Rekor in both directions, and sweep a bounded trailing window of the log

- Status: accepted
- Date: 2026-08-30
- Deciders: RM-036 (#44)

## Context

IP §6.10 makes a claim about the worst case of a total MCP compromise:

> The MCP cannot forge attribution even if fully compromised: it never holds
> signing keys (E8), so the worst case is fake *events*, which the reconciler's
> Rekor cross-check surfaces as drift. Write the test that demonstrates this:
> inject a fabricated `commit_recorded` with no Rekor entry, assert drift
> detection fires.

Threat model AB-03 is the same sentence from the attacker's side — "compromised
MCP fabricates `commit_recorded` to frame an agent" — with `REC-004` as its only
test, and the MCP's **E**levation row in doc 04 §2 rests the whole containment
argument on it: "MCP compromise cannot forge signatures, only fake events, which
drift detection surfaces (REC-004)". Until this issue there was no such
detection, so the containment claim was an assertion.

IP §6.5's last paragraph asks for the other direction in the same breath: "any
Rekor entry for our trust domain with *no* corresponding intent is an
alert-level `unattributed_signature_detected` event — that is either a bug or a
compromise, and it must be loud" (REC-003).

Three things constrain how this can be built.

**RM-035's reconciler runs its join from the intent, on purpose.** ADR-0035
records why: for each open `commit_intent`, ask the repository for signed
commits holding its tree, then ask Rekor for the entry whose artifact is that
commit. That query is bounded by the number of open intents rather than by the
size of the log, and it is the same artifact-hash join `internal/signing` uses.
It cannot express either question here. REC-003's whole subject is entries no
intent names, so no tree hash reaches them; REC-004's subject is records whose
intent is already resolved, so they are not in the open set at all.

**The event schema is closed.** Doc 02 §1 rejects unknown members at append and
§7 makes any new member or type a major `schema_version` with a migration
attestation. ADR-0013 had to refuse `unattributed_signature_detected` for SPIRE
drift because a registration entry has no honest value for `rekor_log_index` or
`rekor_entry_uuid`, and doc 02 §1 forbids an empty-string placeholder.

**There is no index from a trust domain to the entries signed under it.** Rekor
indexes by artifact hash, by public key and by email. "Which entries bear a
certificate naming `spiffe://innsegl.dev/agent/…`?" is answerable only by
reading entries. Reading all of them, every minute, is linear in the log's
lifetime — bearable on the self-hosted Rekor that ADR-0010 ships as the default,
not bearable on the public one that ADR-0002 still supports.

## Decision

**Four decisions, taken together.**

**1. The cross-check runs in both directions, and the two are different
findings.** Drift detection is `internal/reconciler/drift.go`, called from the
existing cycle after the repairs:

| direction | finding | event | what it means |
|---|---|---|---|
| log → chain | `unattributed_signature` | `unattributed_signature_detected` | a Rekor entry under a certificate bearing one of this trust domain's identities that no `commit_recorded` claims and no open intent could still claim (REC-003) |
| chain → log | `fabricated_commit_record` | `ledger_drift_detected` | a `commit_recorded` whose named entry the log does not hold, or holds attesting another artifact, another identity or another index (REC-004, AB-03) |

They are not merged. A signature nobody claimed is a possible compromise **of an
agent** — or of anything that can reach SPIRE's unauthenticated admin socket
(ADR-0011) — and a claim nobody signed is a possible compromise **of the MCP**.
Which half of the system to stop trusting is the first thing an operator needs,
and a single "drift" counter does not carry it.

**2. Both event types are used as-is, because both typecheck.** This was
checked against doc 02 §3 rather than assumed, and unlike ADR-0013 neither
forces a placeholder:

- `unattributed_signature_detected` requires `rekor_log_index` (integer),
  `rekor_entry_uuid` and `certificate_identity`. All three are read off the log
  entry. It is appended **system-scope** — `run_id` and `spiffe_id` omitted,
  which doc 02 §2 permits for "system-scope alerts that reference no run", as
  golden fixture 09 already demonstrates. That is not a workaround: the
  certificate names a run the chain has never heard of, and writing that run id
  into `run_id` would assert, in a record I4 makes permanent, that a run exists,
  on the strength of a certificate this deployment did not issue. The identity
  is not lost; it is in `certificate_identity`, which is where doc 02 §3 puts it.
- `ledger_drift_detected` requires `subject_event_id` and `reason`. The subject
  is the `commit_recorded` whose claim the log contradicts, which is literally
  doc 02 §3's gloss on the type — "a ledger claim with no external proof" — with
  the transparency log as the external proof. It carries the **subject's** run
  scope, as ADR-0013's three recordable SPIRE kinds do, so the drift feed names
  the agent that was framed.

`reason` is one of five constants, spelled in `drift.go` and treated as
protected-adjacent for ADR-0013's reason: it is part of the canonical preimage
of an event in an append-only chain. The commonest of them — the record whose
entry the log simply does not hold — is doc 02 §6 golden fixture 10's own
`reason` verbatim, "commit_recorded claims a Rekor entry that the log does not
contain"; the fixture's values are illustrative rather than normative, but a
shipped alert that reads differently from the schema document's own example of
it is a needless divergence. What varies goes in the event's run scope
and in the finding's `Detail`, which is never written to the chain.

**3. Four assertions are checked, in one order, and the first failure is the
reason.** A `commit_recorded` asserts that an entry exists, that it attests
`sha256(commit_sha)`, that it was accepted under `spiffe_id`'s certificate, and
that it sits at `rekor_log_index`. Each is put back to the log. Checking only
existence would leave the obvious second move — point a fabricated record at a
real entry belonging to some other commit — undetected. One reason per subject
keeps the dedupe key stable.

A `rekor_entry_uuid` that is not 64 or 80 hex characters is answered **without
asking the log**, as `reasonUnusableUUID`. Measured against the shipped
rekor-server v1.3.10: such a value comes back as `HTTP 422`, which every reader
in this package is required to treat as an outage, and an outage suppresses the
finding — so an attacker would buy permanent silence with a malformed uuid.

**4. The log-side sweep is a bounded TRAILING window with no cursor.** Each
cycle reads `[max(0, treeSize − Window), treeSize)`, default 1024 entries, using
`POST /api/v1/log/entries/retrieve` in batches of ten (rekor-server's own
`maxItems`, measured: eleven is an HTTP 422).

No cursor, deliberately. A cursor would make a long-running process sweep a
different range from a freshly started one, and "a fresh reconciler behaves
identically to the one it replaced" is the property REC-005 and ADR-0013 both
rest on. It is also what makes the idempotency proof meaningful: both dedupe
keys are read back out of the chain in the same walk that finds the open intents
— an entry is already reported iff some `unattributed_signature_detected` names
its uuid, a record iff some `ledger_drift_detected` names its `event_id` — so a
restarted process or a newly elected leader is exactly as quiet.

The cost is stated rather than hidden: an entry more than one window old by the
time a reconciler first looks at it is never swept. A deployment whose log is
its own should set `Window` to cover the log; one returning from a long outage
should raise it once.

**Two consequences of this being detection and not policy, recorded because
they are decisions:**

- **An entry outside this trust domain is not swept into a finding.**
  ADR-0013's reasoning applies unchanged: an alert that fires on every
  stranger's signature is an alert nobody reads. On the public Sigstore that
  ADR-0002 permits, that is every entry but ours.
- **An entry under one of our identities while that run still holds an OPEN
  `commit_intent` is not flagged.** That state is REC-002's repair window — the
  signature exists and the record does not *yet* — and the same cycle has just
  either repaired it or left it open on purpose. Alerting would make the
  reconciler's two jobs contradict each other. The grace is scoped to the
  identity with the open intent and lasts exactly as long as that intent does,
  which `commit_intent_expired` bounds at `ExpireAfter`.

## Alternatives considered

**A. One event type for both directions.** `ledger_drift_detected` alone could
carry the unattributed case if a subject were invented for it, and
`unattributed_signature_detected` alone could carry the fabricated case since a
fabricated record does name a uuid and an index. Both lose the same way, and it
is ADR-0013's way: the first needs a `subject_event_id` that names no event,
which doc 02 §1 forbids and I4 makes permanent; the second would report a
compromised MCP as a compromised agent, which is the one distinction an
operator acts on first.

**B. Sweep the whole log every cycle.** Simplest, and correct. Rejected on
cost: linear in the log's lifetime, so the reconciler gets slower forever, and
on public Sigstore it is not merely slow but impossible. A window that is a
documented gap is better than a design that quietly stops running.

**C. Persist a high-water mark and sweep forward from it.** The obvious fix for
B's gap, and it was rejected for the property it costs. There is no event type
to persist a mark in (the schema is closed), so it would live in memory or in a
side table; either way a fresh reconciler would sweep a different range from a
running one, and REC-005's whole method — "prove it with a FRESH reconciler" —
would stop meaning anything. It is also the state RM-019 and ADR-0013 were
careful not to introduce.

**D. Derive the sweep floor from the chain — the highest `rekor_log_index` any
`commit_recorded` names.** Attractive: chain-derived, so a fresh process agrees
with a running one, and no configuration. It fails on the attack it is meant to
catch. A compromised MCP can append a `commit_recorded` naming
`rekor_log_index: 9_999_999`, and every entry below that floor stops being
swept — the detector is switched off by the component it is watching.

**E. Match a swept entry to an intent by tree hash rather than by "some record
claims this uuid".** It would catch an entry a run made *outside* a
`sign_commit` call even while another intent of that run is open, which the
grace in decision 4 lets through. Rejected because the artifact of a gitsign
entry is `sha256(commit_sha)` and nothing in it reaches the tree: matching would
mean fetching the commit object for every swept entry from a repository the
reconciler may not have, and failing to find one — a shallow clone, a repository
not yet fetched — would produce an alert about an innocent signature. The
narrower rule alerts one cycle later and never alerts wrongly.

**F. Have the reconciler act on drift — revoke, quarantine, refuse.**
Rejected for ADR-0013's reason, unchanged: reconciliation is detection, and a
detector that acts cannot distinguish, within one cycle, an attack from an MCP
whose append has not committed yet. IP §6.5 asks for "loud", and loud is what
this delivers.

**G. Verify each swept entry's inclusion proof from first principles, as
ADR-0009's anchor verifier does.** Rejected as the wrong question here. The
anchor verifier exists because the ledger's operator is not trusted about their
own anchor. Drift detection asks whether the log holds an entry the ledger did
not know about — a claim that gets *stronger*, not weaker, if the log is lying
in our favour by hiding entries, and one where a log inventing extra entries
produces a false alert an operator investigates rather than a false green.
Verifying inclusion is `internal/verify`'s job (ADR-0034) and it is done there.

## Consequences

**Easier.** IP §6.10's central claim and threat model AB-03 have a test, and doc
04 §2's MCP **E**levation row is no longer an assertion. Both directions are
alert-level events in the append-only chain, so they are sealed into a segment
and anchored in Rekor like everything else, and FD §3.1's drift feed has
something to render. Idempotency needed no new state: the dedupe keys are the
chain, so a restarted reconciler or a newly elected leader (doc 05 §2 runs it
single-active with failover) is as quiet as the one it replaced, and LED-008's
unique `idempotency_key` makes two concurrent reconcilers produce one event.

**Harder, and honestly so.**

- **Drift detection is OPTIONAL in `Config`, and is therefore OFF in the shipped
  `innsegl reconcile` command.** `Config.Drift` is a nil-able pointer, and
  `cmd/innsegl/reconcile.go` — which RM-036 does not own — does not set it.
  `Result.Drift.Enabled` reports the state on every cycle rather than letting a
  deployment believe a reconciler without it is watching, but until the command
  wires it, REC-003 and REC-004 are proved by tests and not running in a
  deployment. This is the single most important follow-up in this ADR.
- **The window is a real gap.** An entry older than `Window` when the reconciler
  first sees it is never swept, and nothing on the chain records that it was
  skipped. `Result.SweptFrom`/`SweptTo` report the range each cycle, which is
  the honest minimum; a deployment that wants the guarantee must size the window
  to its log.
- **The grace period is a real window.** While a run holds an open
  `commit_intent`, a *second* signature under that run's identity is not
  flagged. It is flagged on the first cycle after the intent resolves, and
  `ExpireAfter` bounds how long that is.
- **A second entry-body decoder now exists in this package.** `rekor.go`'s
  `attributionOf` is given an artifact hash and answers "is this the entry for
  it?"; `sweep.go`'s `attributionAndArtifact` is given nothing and answers "what
  is this entry, and whose?". Neither is expressible as the other and both are
  tested, but they read the same five members of the same body and a change to
  Rekor's entry shape must be made in two places.
- **Segment anchors are in the same log and are correctly ignored** — ADR-0009
  signs them with a raw P-256 key and no certificate, so they carry no URI SAN
  and attribute nothing. That is load-bearing: were anchors certificate-signed,
  every sealed segment would raise an unattributed-signature alert.

**What the project should do next.**

- **Wire `Config.Drift` into `innsegl reconcile`** (a `-rekor-url`-derived
  `LogSweeper` is already there — the command's `reconciler.NewRekorLog` result
  satisfies both interfaces) with a `-sweep-window` flag and an
  `INNSEGL_RECONCILE_SWEEP_WINDOW` environment variable. Until then the control
  ships dark.
- **Doc 07 has no ID for the negative control**, which is the case that makes
  REC-003 and REC-004 mean anything: a legitimate signed commit — real intent,
  real signature, real record — must raise nothing. Proposed **REC-007**. It is
  written and green in `internal/reconciler/drift_test.go` and
  `driftintegration_test.go`.
- **Doc 07 has no ID for the second-order fabrication**, a `commit_recorded`
  pointed at a real Rekor entry belonging to another commit or another
  identity. Proposed **REC-008**; also written and green.
- **Doc 04's AB-04 row is not this issue's**, contrary to #44's acceptance
  criteria. Doc 04 §3 gives AB-04 ("compromised agent signs something outside
  its purpose") the controls "audience allowlist; one-run identity; retirement
  immediacy" and the tests MCP-008, SPI-004 and MCP-014. REC-003 is a *partial*
  detection for it — a signature outside any recorded intent surfaces — and doc
  04 §4 already says so ("rogue-agent detection … unattributed signatures
  surface in drift detection"). AB-03 is closed by this work; AB-04 is not, and
  is not claimed.
- **`deploy/compose/sigstore-testscope.yml` is now referenced by a third
  suite** from inside `internal/signing/testdata/`, and
  `deploy/compose/spire/register.sh` has been reimplemented a fifth time. Both
  are the unowned `deploy/` work ADR-0031, ADR-0032 and ADR-0035 have each
  already asked for.
