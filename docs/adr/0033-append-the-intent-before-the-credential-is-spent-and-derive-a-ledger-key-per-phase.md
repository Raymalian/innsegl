# ADR-0033: Order `sign_commit` so nothing that can fail cheaply happens after Phase A, and give each phase its own derived ledger key

- Status: accepted
- Date: 2026-08-30
- Deciders: Mike
- Implements: IP §4, IP §6.1, IP §6.3, **IP §6.5**, RM-033 (#41); test IDs MCP-004, SIG-001 (ledger half)
- Builds on: [ADR-0004](0004-idempotency-key-scope.md),
  [ADR-0016](0016-error-class-carries-retryability-and-one-place-renders-it.md),
  [ADR-0017](0017-record-the-tool-call-reply-not-only-the-event.md),
  [ADR-0018](0018-record-run-registered-before-creating-the-spire-entry.md),
  [ADR-0024](0024-readiness-probes-sigstore-by-fetching-its-trust-material.md),
  [ADR-0028](0028-place-commit-trailers-in-process-and-refuse-the-messages-git-places-ambiguously.md),
  [ADR-0031](0031-orchestrate-released-gitsign-through-git-commit-and-configure-around-the-absent-ct-log.md),
  [ADR-0032](0032-inject-a-sigstore-outage-by-stopping-the-shipped-container-and-assert-the-absence-of-a-commit-against-the-object-database.md)

## Context

IP §6.5 calls this "the single most dangerous window" and states the protocol
in three lines: append `commit_intent` before any signing, sign, append
`commit_recorded` referencing the intent. It also states what a crash at each
boundary leaves and who repairs it. What it does not state is everything else
`sign_commit` has to do — resolve a run, find a working tree, obtain a
credential, decide what a tree hash is — and **where in the three phases each
of those belongs is the whole of this decision**. A protocol whose Phase A is
correct and whose Phase A is preceded by nothing is a protocol that leaves a
dangling intent for every malformed request.

Five forces meet.

**1. The two windows are asymmetric, and IP says so.** An intent with no
signature is recoverable: RM-035's reconciler expires it (REC-001). A signature
with no intent is *drift*: RM-036 raises `unattributed_signature_detected`
(REC-003), which "is either a bug or a compromise, and it must be loud". So the
ledger is written first — the same rule ADR-0018 chose for `register_agent` and
RM-017's reaper chose for `run_expired`.

**2. IP §6.1 already puts one thing before Phase A, in terms.** "spire-agent
socket lost mid-run at `get_credential` → `IDENTITY_UNAVAILABLE`; any in-flight
`sign_commit` aborts **before Phase A** (6.5)." The credential is therefore not
a Phase B concern, even though `internal/signing` fetches it inside `Sign`.

**3. IP §4 gives this tool a `repo` and doc 02 §5 says what a `repo` is.**
`host/org/name`, lowercase host — an identifier in an append-only record, not a
path. `signing.Request.Repo` is a working tree. Something has to map one to the
other, and it cannot be the caller, or the tool's `repo` argument becomes a way
to name any directory the server process can read.

**4. IP §4 gives one `idempotency_key` and this tool appends two events.**
`internal/ledger`'s `idempotency_key` is UNIQUE across the chain (LED-008), so
the caller's key cannot be written twice. Worse than a conflict: a *reused* key
does not fail. `Append` hands back the ORIGINAL event, of whatever type it was,
and a tool that read `event_id` off it would link a `commit_recorded` to a
`tool_call`.

**5. `gitsign`'s refusal does not say which half of Sigstore refused it.**
ADR-0032 (RM-034, this wave) measured it from the failure-injection side and
recorded the consequence for this issue in as many words: "A warm `Signer` maps
a Rekor outage to `ErrSigning` rather than `ErrTransparencyUnavailable`, which
RM-033's `sign_commit` has to render as `TRANSPARENCY_UNAVAILABLE` or the class
is right only on a run's first commit."

Invariants in play: I2 throughout (no signing without a valid credential for
this run), I3 in Phase A and Phase C, I5 in the Rekor members of
`commit_recorded`, I6 through the author gate.

## Decision

**Six decisions, all in `internal/mcp/sign_commit.go`.**

### 1. Nine gates run before Phase A, and only one append runs after Phase B

The order, in full:

```
  1  the request grammar           run_id, repo, staged_ref, message, task_ref
  2  the idempotency claim         ADR-0017; everything below is inside it
  3  the run                       exists, not retired, identity is its own
  4  the claim                     the three trailers this run can assert
  5  the working tree              resolved from `repo` by the workspace
  6  the staged tree               staged_ref == index, and index != HEAD
  7  Sigstore reachability         ADR-0024's probe, per half
  8  the credential                through get_credential  (IP §6.1)
  9  the signer                    opened, so a missing gitsign fails here
 --- PHASE A ---  append commit_intent {repo, tree_hash}
 --- PHASE B ---  signer.Sign  — Fulcio and Rekor, as one gitsign operation
     read-back    the commit's tree == the intent's tree_hash; the Rekor
                  members exist; the trailers are the ones claimed
 --- PHASE C ---  append commit_recorded {…, intent_event_id}
```

Gate 7 is the one that is not obviously ours to make. `internal/signing`
already fetches Fulcio's root and Rekor's log key inside `Sign`, and that fetch
is ADR-0031 decision 2's own reachability probe. Doing it again here, through
`mcp.HealthSigstore`, costs two HTTP round trips per call and buys the thing
that matters: **the commonest cause of a failed signature stops leaving a
dangling intent.** It also means "Sigstore is reachable" is one definition —
the readiness endpoint and the tool ask the same question of the same thing.

It is not a guarantee and is not sold as one. Fulcio can die between gate 7 and
`git commit`; that residue is the A → B window, and it is exactly what the
reconciler is for.

### 2. `staged_ref` names a tree, and the index must agree with it

`staged_ref` is resolved with `git rev-parse --verify --quiet <ref>^{tree}` and
required to equal `git write-tree`. Three refusals come out of that, all before
Phase A:

- the reference names no tree — the caller's own reference is wrong;
- it names a tree the index does not hold — `git commit` commits the index, so
  signing would cover something other than what the caller named and what the
  intent would record;
- the index is already the tree at HEAD — `git commit` refuses an empty commit,
  so no commit object can be created.

The third is also **exactly the state a crash between Phase B and Phase C
leaves behind**, so its message names the reconciler. That is the honest
outcome and it is stated in Consequences rather than hidden: a lease takeover
after a B-crash is refused, loudly, and does not sign a second time.

`git write-tree` writes tree objects and no commit object, so IP §6.3's "the
repo has no new commit object at all" survives a failed call — asserted against
`git cat-file --batch-all-objects` rather than against HEAD.

### 3. The working tree is resolved from `repo`, never supplied

`mcp.Workspace` maps `host/org/name` onto `<root>/host/org/name`. `repo` is
already held to doc 02 §5's grammar — exactly three segments, each
`[A-Za-z0-9][A-Za-z0-9._-]*` — so no segment can be `..` and none can contain a
separator. That is what makes the mapping total rather than merely usually
safe, and it is why there is no second "does this escape the root?" check: a
check that can never fire is a check nobody can test.

### 4. The credential comes through `get_credential`, not through a second path to SPIRE

`SignCommitThroughGetCredential` calls the shipped tool in process. One
audience allowlist, one retirement check, one SPIRE entry check, one
`credential_issued` append (I3). A run retired a moment ago cannot sign,
because the gate that refuses is the gate an agent would have hit.

The credential is fetched **before** Phase A (IP §6.1) and handed to the
wrapper on its first request, so the pre-fetch is not a second issuance. A
*second* request from the wrapper means it judged the credential unusable,
which is IP §6.2's transparent re-fetch, and it is deliberately not
suppressed — ADR-0004's argument is that collapsing issuances hides credential
churn, which is the signal an auditor wants.

The identity in the credential handed to `gitsign` is the run directory's, not
the token's. Reading it out of the token would make `Signer.checkCredential`
compare a value with itself.

### 5. Both phases carry a DERIVED ledger key, namespaced by tool and phase

```
commit_intent     idempotency_key = "sign_commit/intent/"   + sha256(quote(key))[:32]
commit_recorded   idempotency_key = "sign_commit/recorded/" + sha256(quote(key))[:32]
```

Both, not one. Spending the caller's key verbatim on the intent would collide
with the same string used by `record_event` or `register_agent` — and a
colliding append does not fail, it returns the earlier event of the wrong type
(force 4 above). A digest rather than a suffix because a key at doc 02 §2's
128-byte limit plus `#recorded` is 137 bytes, and a length branch is a branch
that is wrong on the day it fires.

Three independent refusals now stand between a reused key and a mislinked
event, and no one of them is load bearing: ADR-0017's store refuses a key
naming a different request (`DUPLICATE_REQUEST`); the namespacing makes the
collision unreachable from a caller's key space; and every append checks the
returned record's `event_type` and `run_id` against what it wrote.

The caller's key is not lost. It is the primary key of the idempotency store's
own row, which is where an operator looks up what a call returned.

### 6. `ErrSigning` is re-probed, and the dependency's answer decides the class

`ErrSigning` is a subprocess exiting non-zero. When it arrives, Sigstore is
asked once more, on a context detached from the caller's cancellation, and if a
half is down that half's class is returned — `SIGNING_UNAVAILABLE` or
`TRANSPARENCY_UNAVAILABLE`, retryable, per IP §6.3. Only a refusal with both
halves healthy is `INVARIANT_VIOLATION`.

This is ADR-0032's finding answered. It answers it without pattern-matching
gitsign's prose, which is the property ADR-0031 decision 2 was after when it
made the trust-material fetch the discriminator rather than the subprocess's
text. It also means the finding's premise — a warm `Signer` skipping the
fetch — cannot arise here anyway: `NewGitsignSigners` opens **one Signer per
call**, so the fetch always runs. One per call rather than one per run, and
ADR-0031 named the cost (a `get_credential` per commit); the reason is that a
map of Signers keyed by run is state that has to be expired on retirement, and
a cached credential surviving retirement is precisely the grace path IP §6.2
forbids.

MEASURED, on the shipped compose stack, for the case ADR-0032 raises — a run's
**second** commit with `rekor` stopped:

```
a run's SECOND commit with Rekor stopped: TRANSPARENCY_UNAVAILABLE (retryable=true)
```

with the repository holding the same number of commit objects afterwards as
before (`git cat-file --batch-all-objects`) and HEAD unmoved. So three
independent things would each have to fail before the class degraded: the
per-call Signer would have to become per-run, the pre-Phase-A probe would have
to stop running, and the `ErrSigning` re-probe would have to stop answering.

## Alternatives considered

**Put Phase A first, before the run is even resolved.** The most literal
reading of "before any signing", and it is worse in every case: a malformed
`repo`, an unknown run, a retired run and a missing working tree would each
append an intent that the reconciler then has to expire. IP §6.5's ordering
constraint is between the intent and the SIGNATURE, and moving cheap failures
in front of the intent violates nothing while making the A → B window empty for
every one of them.

**Skip the pre-Phase-A Sigstore probe and rely on the wrapper's own.** One
fewer round trip, one less dependency in the config, and `internal/signing`
already distinguishes the two halves correctly. Rejected because it makes every
Fulcio or Rekor outage — the two failures IP §6.3 says will actually happen —
leave a `commit_intent` behind. The reconciler would work; the ledger would
fill with expired intents for an outage nothing in the system caused.

**Let `sign_commit` repair the B → C window itself on replay:** detect that the
tree is already at HEAD, adopt the existing commit, find its Rekor entry, and
append the missing `commit_recorded`. This is what a reader wants it to do, and
it cannot be done from here: recovering a Rekor entry for an existing commit is
`findRekorEntry`, which `internal/signing` keeps unexported (ADR-0031 decision
6). Exporting it is RM-035's to do — and RM-035 is the component IP §6.5
assigns the repair to, so doing it here would be a second implementation of the
reconciler's job living in the tool the reconciler exists to repair.

**Take a filesystem path as `repo` and derive `host/org/name` from the git
remote.** Fewer moving parts and no workspace to configure. Rejected on two
grounds: the recorded `repo` would then be whatever `origin` happened to be at
signing time, which is a fact about a mutable git config and not about the
artifact; and the tool's argument would name a directory, which is an
arbitrary-path read for anything that can call the MCP.

**Spend the caller's `idempotency_key` on `commit_intent` and derive only the
recorded one.** Keeps the caller's key greppable in the chain, which is a real
operator benefit. Rejected because of force 4: the ONE case where it matters —
a key already used by another tool — is the case where `Append` succeeds and
returns the wrong event. The store's `DUPLICATE_REQUEST` refuses that reuse one
layer up, so the risk is small; it is not small enough to accept in the tool
that writes the record a court would be shown.

**Render `ErrSigning` as `INVARIANT_VIOLATION` and leave it.** Simple and
defensible on its face: a subprocess we drove refused. Rejected because
ADR-0032 measured that a Rekor outage arrives wearing it, and IP §6.3 requires
Rekor's outage to be `TRANSPARENCY_UNAVAILABLE` and retryable. A non-retryable
alert-level class for a dependency outage is the failure mode IP §6.11 objects
to in the dashboard, one layer down.

**Configure `sign_commit` unconditionally in `cmd/innsegl`.** Rejected because
`signing.NewSigner` resolves `gitsign` with `exec.LookPath` at construction, so
a deployment that does not intend to sign would fail to start; and because
there is no defensible default working-tree root. The tool is BOUND
unconditionally — it is one of IP §4's five — and configured only when
`-workspace` names a root, with a start-up warning naming the flag when it does
not. That is ADR-0025's shape: turning a capability off is an operator decision
that appears in the log every time the process starts.

## Consequences

**The two windows are now named, bounded and documented in one place.** A
crash or outage between A and B leaves a `commit_intent` and no signature —
REC-001. Between B and C, a commit object and a Rekor entry and no
`commit_recorded` — REC-002. RM-035 must handle both, and the second is the one
this tool deliberately does not repair.

**A lease takeover that lands in the B → C window is refused, not repaired.**
ADR-0017 re-runs a tool whose claim expired; if the first execution had already
committed, gate 6 refuses ("nothing is staged") and names the reconciler. No
second commit is created — which is IP §6.6's actual requirement — but the
caller gets `INVARIANT_VIOLATION` rather than the original result until the
reconciler has run. **This is the one place `sign_commit` is not
self-healing**, and it is deliberate: see the third alternative above.

**`internal/mcp` now runs `git`.** `GitRepos` shells out for `rev-parse` and
`write-tree` with an environment built from nothing, on ADR-0031 decision 3's
argument generalised to a read: no `~/.gitconfig`, alias or credential helper
can change what a plumbing command answers. It is a read-only path and creates
no commit object, but it is a second place in this repository that invokes git,
and a reader should know it is there.

**`SignCommitRekorEntry` and `SignCommitTrailer` are new wire shapes and are
now protected.** IP §4 names `rekor_entry` and `trailers` and does not say what
is inside them. `rekor_entry` carries `uuid` and `log_index` — doc 02 §3's own
two members, so the reply and the record name the entry identically — plus
`log_id` and `integrated_at`. `trailers` is an ordered array of `{key, value}`
rather than rendered `Key: value` lines, because the three keys are protected
strings a consumer switches on, and splitting on a separator would make that
separator part of the contract. MCP-004 pins both.

**`cmd/innsegl serve` grows seven settings**, all opt-in behind `-workspace`:
`-oidc-issuer`, `-sign-author-name`, `-sign-author-email`,
`-sign-author-operators`, `-sign-author-allow-unlinked`, `-gitsign`. The author
policy is built once and handed to the signer factory, and
`ConfigureSignCommit` asks that factory whether the configured author is
admitted — so a deployment whose I6 policy does not admit its own author
**refuses to start** rather than discovering it on its first signature, after
the intent is already on the chain.

**`MissingTools()` is now empty and RM-068's test says so.** RM-068 left
`TestTheShippedSurfaceIsFourToolsAndSignCommitIsTheMissingOne` asserting the
opposite, deliberately, so that binding the fifth tool would fail loudly rather
than let the start-up report and both health endpoints go stale. It did, and it
is now `TestTheShippedSurfaceIsTheFiveToolsOfIP4`.

**SIG-001's ledger half needs a SPIRE and a Sigstore inside `internal/mcp`,
and reimplements the OIDC registration a third time.** `internal/signing`'s
harness lives in that package's test files and cannot be imported; `rundir`,
the shipped run directory, imports `internal/mcp` and so cannot be imported by
an in-package test either. So the case seeds `run_registered` on a real chain
and reads the run back out of the returned record, and it repeats
ADR-0031's five-selector registration of `spire-oidc`. That is now **three**
copies of a script `deploy/compose/spire/register.sh` could provide if it were
parameterised by project and container name — ADR-0031 asked for it, and this
is the second issue to pay for its absence.

**`internal/signing/testdata/sigstore-testscope.yml` now has a second caller
outside its package, and a third copy exists in `test/failure`.** The harness
looks for `deploy/compose/sigstore-testscope.yml` first and falls back, so the
move ADR-0031 asked for can happen without touching this file. It should happen.

**Not answered here, and flagged rather than resolved:** IP §4 gives
`staged_ref` no definition anywhere in the eight documents — decision 2 is an
inference, and a caller that reads `staged_ref` as "the branch I am committing
to" gets a refusal. And doc 07 has no test ID for the ordering property this
whole file exists to hold; SIG-001's "intent+recorded events in order" is the
closest, and the transcript assertion that proves the *signature* falls between
them is unnumbered.

**Exit cost.** Moderate, and concentrated in decision 5. The two derived keys
are values in an append-only chain: changing the derivation makes every replay
of a historical call append a second pair of events rather than dedupe, so a
change would need the old derivation kept as a fallback lookup. Everything else
is reversible — the gate order is code, the workspace is one interface, and the
wire shapes are pinned by MCP-004 but not yet by a released tag.
