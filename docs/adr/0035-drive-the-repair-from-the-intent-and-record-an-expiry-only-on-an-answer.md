# ADR-0035: Drive the reconciler's repair from the intent rather than from the log, and record an expiry only on an answer

- Status: accepted
- Date: 2026-08-30
- Deciders: Mike
- Implements: **IP §6.5**, IP §6.4, RM-035 (#43); test IDs REC-001, REC-002, REC-005; invariants I3, I4
- Builds on: [ADR-0004](0004-idempotency-key-scope.md),
  [ADR-0009](0009-anchor-a-segment-as-a-signed-hashedrekord-entry.md),
  [ADR-0013](0013-record-spire-entry-drift-as-ledger-drift-detected.md),
  [ADR-0014](0014-reaper-orphan-test-and-expiry-idempotency-key.md),
  [ADR-0031](0031-orchestrate-released-gitsign-through-git-commit-and-configure-around-the-absent-ct-log.md),
  [ADR-0032](0032-inject-a-sigstore-outage-by-stopping-the-shipped-container-and-assert-the-absence-of-a-commit-against-the-object-database.md),
  [ADR-0033](0033-append-the-intent-before-the-credential-is-spent-and-derive-a-ledger-key-per-phase.md)

## Context

IP §6.5 calls the gap between a signature and its record "the single most
dangerous window", states the three-phase protocol that bounds it, and assigns
the repair to a reconciler. ADR-0033 built the protocol and named the two
residues precisely:

- **A → B** — a `commit_intent` and no signature. Reached by a crash after the
  append, by Fulcio or Rekor dying between gate 7 and `git commit`, or by
  gitsign refusing.
- **B → C** — a commit object and a Rekor entry and no `commit_recorded`.
  ADR-0033 records that `sign_commit` deliberately does **not** repair this one:
  a lease takeover there is refused, because recovering a Rekor entry for an
  existing commit is `internal/signing`'s unexported `findRekorEntry`
  (ADR-0031 decision 6), and duplicating the reconciler inside the tool the
  reconciler exists to repair would be two implementations of one job.

Five forces meet.

**1. IP §6.5 describes the repair as a search of the log.** "The reconciler
scans Rekor for certificates bearing our trust domain's identities, matches them
to intents." Read as a query plan that is a walk of the whole log, which is
feasible against a self-hosted Rekor with a handful of entries and not feasible
against public Sigstore, which ADR-0002 and ADR-0010 both keep as a supported
configuration.

**2. A Rekor entry does not carry the commit SHA.** gitsign's online mode writes
a `hashedrekord` whose artifact is **sha256 of the commit SHA**. SHA-256 does
not invert, so an entry found by scanning the log cannot yield the `commit_sha`
that doc 02 §3 makes a required member of `commit_recorded`. Something outside
the log has to supply the candidate commit either way.

**3. The two failure directions are not symmetric, and I4 makes one of them
permanent.** A missing repair is a gap that the next cycle can still close. A
wrong `commit_intent_expired` is a record, in an append-only chain, stating that
no signature exists — about a signature that does. It can be superseded and
never deleted (I4), and doc 06 §3.3 would have rendered it in the meantime.

**4. A `commit_recorded` this component invents is fabricated attribution.** It
is precisely what RM-036's drift detection (REC-003, REC-004, IP §6.10) exists
to catch, arriving from the component meant to be the cure. A test asserting
only that "a `commit_recorded` was appended" passes against a reconciler that
invents one.

**5. doc 05 §2 runs this single-active with failover, and REC-005 is what makes
that safe.** Leader election belongs to the deployment. What belongs here is the
property that two overlapping cycles produce one event.

## Decision

**Six decisions, in `internal/reconciler/` and `cmd/innsegl/reconcile.go`.**

### 1. The join runs from the intent, not from the log

For each intent the chain has not yet resolved:

```
  the repository named by `repo` is asked for every commit OBJECT whose tree is
  the intent's `tree_hash` and which carries a `gpgsig` header
    for each such commit:
      Rekor is asked for the entry whose artifact is sha256(commit_sha)
      the entry is this intent's IFF the certificate it was accepted under
      carries the intent's own `spiffe_id` as its URI SAN
```

Three reasons. The cost is bounded by the number of open intents rather than by
the size of the log, so a public-Sigstore deployment is not asked to walk a
billion entries. The artifact-hash lookup is the same join `internal/signing`
uses to prove an entry belongs to a commit, so the tool and the reconciler
cannot disagree about what "this commit's entry" means. And force 2 says the
commit has to come from the repository in either plan, so driving from the log
buys nothing and costs the scan.

IP §6.5's sentence names the RELATION — a certificate bearing our trust domain's
identity, matched to an intent — and this establishes exactly that relation. The
log-side sweep the sentence literally describes is REC-003's, whose entire
subject is entries with **no** intent; it belongs to the component that has a
use for it, and that component is RM-036.

The trust-domain scope is enforced once, at the intent: an intent claiming an
identity outside `spiffe://{td}/agent/` is unresolvable and is never acted on,
and the equality above carries the scope to the certificate. A second
trust-domain test inside the match was written, and a mutation deleting it
changed no test — so it was removed rather than left standing as untested
reassurance. That is ADR-0033 decision 3's rule ("a check that can never fire is
a check nobody can test") applied to this file.

### 2. Commit objects, not refs; a `gpgsig` header, not a verification

Candidates come from `git cat-file --batch-all-objects`, the same question
ADR-0032 asks from the other side when it asserts a failed signature created no
commit. `git log --all` would miss a commit that a `reset --hard` or a failed
replay left unreachable — and a B → C crash followed by a reset leaves exactly
that. Calling such a signature nonexistent would produce the permanent falsehood
of force 3.

The `gpgsig` header is a filter and is not sold as a verification: verifying is
`innsegl verify`'s (RM-037) and Rekor's. It drops the commits nobody ever tried
to sign, so an ordinary unsigned commit that happens to hold the same tree can
never be a candidate. The load-bearing check remains the log's.

### 3. An expiry is recorded only on a positive answer

`commit_intent_expired` is appended only when the repository WAS read and holds
no signed commit for that tree, or when every candidate WAS put to the log and
the log said it holds no entry. A repository that cannot be reached, a log that
cannot be asked, or more than one signed commit claiming one intent leaves the
intent **open**, appends nothing, and raises an operator alert; `innsegl
reconcile` exits **UNRESOLVED (7)** for it.

"We could not tell" is therefore never recorded as "it never happened". The
distinction is carried in the code by one sentinel: `ErrNoEntry` is the log
answering, everything else is the log being unreachable, and an entry that
exists but is not this commit's signature — wrong kind, wrong artifact, a public
key that is not a certificate, a certificate with no URI SAN — is `ErrNoEntry`
too, because those are the log answering as well.

### 4. The bounded window defaults to 15 minutes, and is configurable

IP §6.5 says "a bounded window" and names no number. The bound is derived, not
picked:

```
  lower bound   signing.DefaultTimeout        2m00s   one `git commit`
              + the Rekor index poll             2.5s  5 × 500ms
              + signing.DefaultSkew          1m00s   IP §6.8's NTP-scale bound
              ≈ 3m03s of legitimately in-flight signature
  upper bound   doc 05 §4 lists reconciler drift among the monitoring minimums:
                an intent nobody has ruled on is an outage nobody has been told
                about, and the window is how long that silence lasts.
```

Fifteen minutes is a shade under **five times** the worst legitimate Phase B, so
a slow Sigstore, a retried gitsign and a skewed clock together cannot reach it,
and it is short enough that an operator learns of a stuck signing path inside
one coffee break. It moves with `Config.ExpireAfter` and `innsegl reconcile
-expire-after`, and a deployment whose Sigstore is slower **should** move it. A
non-positive value is refused at the flag with the reason, because zero would
expire an intent the instant it was appended.

### 5. The repair carries Phase C's own idempotency key, and `source: reconciler`

```
  commit_recorded       idempotency_key = "sign_commit/recorded/" + <the digest
                        the intent's own "sign_commit/intent/" key carries>
                        …or "reconciler:commit_recorded:" + intent_event_id when
                        the intent carries no key sign_commit derived
  commit_intent_expired idempotency_key = "reconciler:commit_intent_expired:"
                        + intent_event_id
```

The first is what makes REC-002's requirement literally true. IP §6.5 asks that
"the ledger converges to the same state as the no-crash run", and a repaired
`commit_recorded` carrying a different `idempotency_key` from the one Phase C
would have written is a different state. With the prefix swap the two runs
differ in exactly one member — `source` — and that difference is required rather
than incidental: doc 02 §3 marks `commit_recorded` "mcp **or** reconciler" and
doc 06 §3.3 labels repaired history as repaired. A repair that looked identical
to an original would be a lie by omission.

The four prefixes are **PROTECTED-ADJACENT**, on ADR-0014's reasoning: they
become `idempotency_key` values in an append-only chain, and `idempotency_key`
is part of the canonical preimage (doc 02 §4), so changing one makes every
replay append a second event instead of deduplicating. The first two are
`internal/mcp`'s, spelled here rather than imported because the component that
repairs the MCP's crashes must not depend on the MCP; the integration case pins
them against keys a real `sign_commit` produced, so a divergence fails a test.

Both keys also make failover safe (force 5). `idempotency_key` is UNIQUE across
the chain (LED-008) and the ledger serialises appends, so two reconcilers that
both read before either wrote produce ONE event between them. An append that
comes back as an event this cycle did not write is reported as "nothing
appended", and an append that comes back as the WRONG event type or naming
another intent is an error, not a shrug.

### 6. `innsegl reconcile` loops, elects no leader, and has three verdicts

The default is a loop, because IP §6.5 says the reconciler "runs continuously";
`-once` is the opt-out for a scheduled job. Leader election is the deployment's
(doc 05 §2), exactly as `innsegl reap` decided in ADR-0014. Exit statuses
continue the CLI contract — the canary owns 3 and 4, the reaper 5 and 6:

```
  0  every open intent was ruled on (repaired, expired, or still in-window)
  2  the command line was not understood
  7  UNRESOLVED   an open intent could not be ruled on; its window is still open
  8  INCONCLUSIVE the cycle could not run; nothing was examined
```

A cycle that could not reach Rekor for an hour must not exit 0 when the operator
finally stops it, so the loop's exit status is the worst verdict it saw.

## Alternatives considered

**Walk the log and match entries to intents, as IP §6.5's sentence reads.**
The literal implementation, and it is the one REC-003 will need. Rejected as the
repair's query plan on force 2: the entry does not carry the commit SHA, so the
repository must be consulted anyway to produce the `commit_sha` that doc 02 §3
requires — which means the log walk is a strictly larger amount of work for the
same join, and unbounded against public Sigstore. Driving from the intent is
bounded by the thing that actually needs repairing.

**Export `findRekorEntry` from `internal/signing` and call it.** ADR-0033's own
suggestion, and it would have avoided a second Rekor reader. Rejected on two
grounds: `findRekorEntry` matches against a `*x509.Certificate` the SIGNER
already holds, and the reconciler has no such certificate — it has an intent and
must read the identity back out of whatever certificate the log holds, which is
a different function with a different signature; and it would make the component
that repairs the MCP's crashes depend on the package the MCP signs with, so a
deployment could not run the reconciler where it does not run gitsign. A third
reader now exists (`internal/segment`, `internal/signing`, here) and that cost
is real; it is recorded in Consequences rather than hidden.

**Expire an intent whenever no signature is found, without distinguishing "the
log said no" from "the log did not answer".** Much simpler, and the window makes
it look safe: a Rekor outage shorter than the window costs nothing. Rejected on
force 3. A Rekor outage LONGER than the window — which is exactly the outage
worth having a reconciler for — would then write a `commit_intent_expired` for
every signature made during it, permanently, and doc 06 §3.3 would render each
one as a signature that never happened. Detection controls must fail silent, not
fail wrong.

**Repair the first matching commit when several claim one intent.** Two signed
commits holding one tree, each with an entry under this run's certificate, is
either an amend or a genuine double-signature. Rejected because choosing between
them is a guess about which commit an intent named, recorded permanently as
attribution. The cycle reports it and alerts instead — the same shape ADR-0013
chose for the SPIRE drift the schema cannot record.

**Give the repaired `commit_recorded` the reconciler's own key namespace.**
Cleaner layering: no `internal/mcp` string spelled in `internal/reconciler`.
Rejected because it makes REC-002's convergence claim false in a member an
auditor reads — the two runs would then differ in `source` AND
`idempotency_key`, and the second difference has no meaning to defend. It also
loses a real property: a later `sign_commit` replay of the crashed call
deduplicates against the repair rather than colliding with it.

**Verify the commit's own gpgsig signature before repairing.** Strictly more
evidence. Rejected as this component's job: `innsegl verify` (RM-037) is the one
verifier by doc 05 §3.1's "one verifier rule", and a second CMS/PKCS7 reader
inside the reconciler would be exactly threat model §5.4's divergent-verifier
concern. The join here is the artifact hash and the certificate identity, both
read out of the log's own bytes, and the repair records what the log holds
rather than asserting that it is valid.

**Let the reconciler take a filesystem path per intent.** Rejected for
ADR-0033 decision 3's reason, unchanged: `repo` is an identifier in an
append-only record, and a component that took a path would read any directory
its process can reach. `<root>/host/org/name`, with `repo` already held to
exactly three segments of `[A-Za-z0-9][A-Za-z0-9._-]*`.

## Consequences

**The B → C window is now closed end to end, and it was measured.** The
integration case drives the shipped `sign_commit` over the shipped MCP transport
against a real SPIRE, a real Fulcio, a real Rekor, a real Postgres and the
released gitsign; refuses exactly the Phase C append; asserts the residue in
four places; and then compares the repaired run against a run through the same
tool that did not crash:

```
B → C residue: intent 01a052b7-d9a1-795e-b86c-6ed0fa7b03e4 at position 7,
               commit b93edefda75beb0be284d40655f4231619266917, no commit_recorded
REC-002 repair: commit b93edefda75beb0be284d40655f4231619266917,
                rekor uuid 4c32c7bd…f730c4f9ae09fc8ad8e49e index 1
REC-002 state diff: the two runs are identical except
                    [commit_recorded.source: mcp -> reconciler]
```

**A → B is produced by a real outage, not by a stub.** Fulcio is stopped and the
tool is handed a Sigstore probe that still answers healthy — which is precisely
the case ADR-0033 gate 7 says it cannot cover, in as many words. gitsign's
failure is real, the repository gains no commit object (asserted against
`cat-file --batch-all-objects`, IP §6.3), and the intent is really dangling.

**A third Rekor reader now exists in this repository**, after
`internal/segment`'s (ADR-0009) and `internal/signing`'s (ADR-0031). They read
different things — an anchor's inclusion proof, a commit's entry under a known
certificate, and a commit's entry with the identity read back out — but they
share a base URL, a hashedrekord shape and two endpoint paths. A reader should
know all three are there.

**`register.sh` has now been reimplemented a FIFTH time.** ADR-0031 asked for
`deploy/compose/spire/register.sh` to be parameterised by project and container
name; ADR-0033 called this the second issue to pay for its absence and ADR-0034
the fourth. `internal/reconciler`'s harness is the fifth copy, and it also
reaches into `internal/signing/testdata/sigstore-testscope.yml` — the second
suite to do so from outside that package. Both are the same unowned `deploy/`
work.

**`scripts/coverage-floors.sh` has no line floor for `internal/reconciler`.**
The package sits at 90.2% statement coverage with nothing holding it there; the
entry to add is `"internal/reconciler 85"`, and `scripts/` is not RM-035's to
change. `scripts/branch-coverage.sh` does not list this package either, and
should not until IP §2 names it — the four surfaces it floors are the ledger's
append, sealing, verification and the MCP tools' error paths, and the reconciler
is none of them.

**`cmd/innsegl/cli_test.go`'s `implementedSubcommands` tripwire fired**, as its
author intended: `reconcile` stopped being a stub and the "not implemented"
assertion failed loudly rather than going stale. One word changed.

**Not answered here, and flagged rather than resolved.**

- **`internal/rundir` uses `task_ref` VERBATIM as the SPIFFE ID's `{task_id}`,
  and doc 02 §5 makes `{task_id}` lowercase.** doc 02's own golden fixture 01
  carries `task_ref` `"JIRA-118"` and a SPIFFE ID holding `jira-118`, and the
  run directory would refuse that run with `identity … does not name run … of
  task …`. `internal/mcp`'s own SIG-001 harness lowercases it; the shipped
  directory does not. The integration case here uses an already-lowercase
  `task_ref` and says so in a comment rather than papering over it. It is
  RM-068's (#89) to answer.
- **Doc 07 has no ID for the property decision 3 exists to hold** — that an
  expiry is never recorded on an unanswered question. REC-001 covers the expiry
  and REC-005 the idempotency; "a Rekor outage produces no `commit_intent_expired`"
  is unnumbered. Proposed **REC-006**.
- **IP §6.5 does not say what a reconciler should do when two signed commits
  claim one intent.** Decision 3 refuses and alerts; the alternative — supersede
  one with the other — is a schema question (doc 02 §2's `supersedes`) and a
  human's.

**Exit cost.** Moderate, concentrated in decision 5. The four key prefixes are
values in an append-only chain: changing a derivation makes every replay append
a second event rather than deduplicate, so a change needs the old spelling kept
as a fallback lookup — the same exit cost ADR-0033 recorded for the two it owns,
now with a second dependent. Everything else is reversible: the query direction
is code, the window is a flag, and the two readers are interfaces.
