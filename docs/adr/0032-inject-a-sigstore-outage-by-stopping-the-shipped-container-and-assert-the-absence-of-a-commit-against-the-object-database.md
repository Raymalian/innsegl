# ADR-0032: Inject a Sigstore outage by stopping the shipped container, inject slowness by delaying a real one, and assert the absence of a commit against the object database

- Status: accepted
- Date: 2026-08-30
- Deciders: Mike
- Implements: IP §6.3, RM-034 (#42); test IDs SIG-002, SIG-003, SIG-004
- Builds on: [ADR-0015](0015-failure-injection-stack-per-test-process.md),
  [ADR-0022](0022-a-compose-project-per-test-process-for-the-shipped-spire-stack.md),
  [ADR-0024](0024-readiness-probes-sigstore-by-fetching-its-trust-material.md),
  [ADR-0029](0029-compose-self-hosted-sigstore-as-its-own-project-joined-to-spires-oidc-network.md),
  [ADR-0031](0031-orchestrate-released-gitsign-through-git-commit-and-configure-around-the-absent-ct-log.md)

## Context

IP §6.3 is three sentences and each one is a test:

> Fulcio down → `SIGNING_UNAVAILABLE`, retryable. The commit is not created.
> There is no unsigned fallback, no local-key fallback, no "sign later" queue.
> Test: with Fulcio blocked, assert the repo has no new commit object at all.
>
> Rekor down → signing fails (`TRANSPARENCY_UNAVAILABLE`). A signature without
> a transparency entry is not non-repudiable and must not exist. Test: block
> only Rekor, assert no commit.
>
> Slow Sigstore → explicit timeouts, bounded retries with backoff and jitter,
> then the error. No indefinite hangs holding repo locks.

Five forces shape how those can be written, and four of them are facts rather
than choices.

**The assertion is an absence, and an absence is the easiest thing in this
repository to prove vacuously.** "The repository has no new commit object" is
satisfied by a signer that never ran, by a fixture that staged nothing, by a
repository that was never initialised, and by a harness that skipped. Eleven
vacuous passes had been caught on this project when ADR-0031 was written and
the count is now twelve. Every decision below that looks like extra work is
there because of this sentence.

**Blocking a dependency means removing it, not describing it.** IP §2:
"a mocked Fulcio proves nothing about I5". A `CredentialSource` or an
`http.RoundTripper` that returned `ErrSigningUnavailable` would establish that
`errors.Is` works. What SIG-002 has to establish is what a *repository* holds
after a certificate authority goes away, and that is only observable if one
does.

**ADR-0031 already decided the ordering these cases are about, and said so.**
Its decision 2: the trust-material fetch "is also the reachability probe, and
it runs before `git` does. It is the one place that can distinguish
`SIGNING_UNAVAILABLE` (Fulcio) from `TRANSPARENCY_UNAVAILABLE` (Rekor) without
pattern-matching a subprocess's prose, and because it precedes the commit,
neither failure can leave a commit object behind — IP §6.3's 'the repo has no
new commit object at all', obtained by ordering rather than by cleanup." A
failure-injection suite that only exercised that probe would be testing the
cheap half. The expensive half — what happens when the probe has *already
passed* and the log dies afterwards — is the half IP §6.3's Rekor sentence is
actually about, because that is where a signature can exist without an entry.

**Neither of the two existing harnesses can be used.**
`internal/signing/sigstoreharness_test.go` builds exactly the right pair of
stacks and is a `_test.go` file in package `signing`: not importable, by
construction. `test/failure/harness_test.go` builds a SPIRE stack in this very
package and cannot be used either, for a reason that is about configuration
rather than Go: it brings `spire.yml` up on its default issuer,
`https://oidc.innsegl.dev`, which ADR-0010 decided is never stood up. Fulcio
performs OIDC discovery against the issuer named in the token, the `iss` claim
is baked into the server's configuration at container start, and ADR-0029
decision 3 exists because getting this wrong produces a refusal that names
neither the issuer nor the mismatch.

**`TestMain` belongs to another issue's file.** `test/failure/harness_test.go`
owns the package's single `TestMain`, and it is where `stopPostgres()` — the
package's existing lazily-started dependency — is torn down. RM-034 does not
own that file, so there is no process-exit hook for a `compose down`.

## Decision

**Seven decisions, all in `test/failure/sigstore_test.go`,
`test/failure/sigstoreharness_test.go` and
`test/failure/sigstore-isolated.yml`. Nothing under `internal/` changed.**

### 1. An outage is a stopped shipped container, and the port is asked before the outage is relied on

SIG-002 runs `docker compose stop fulcio` on the shipped
`deploy/compose/sigstore.yml` service; SIG-003 stops `rekor`. `stopSigService`
then polls the published loopback port until it genuinely **refuses**
connections, and only then returns.

The poll is the substance, not politeness. `docker stop` returns when the
container is gone, which is not the same instant the host stops accepting on
the published port; a case that asserted an error before the port had closed
would be asserting against a race, and a case that asserted one after it closed
for an unrelated reason would be asserting against nothing. This is
`internal/ledger`'s LED-009 discipline — poll `pg_locks` until the parked
writers are provably waiting, rather than sleep and hope — applied to a socket.

Each case additionally asserts that **the other** dependency is still serving,
by ADR-0024's definition (bytes that parse, not a status code). A window in
which both were down would satisfy `SIGNING_UNAVAILABLE` and
`TRANSPARENCY_UNAVAILABLE` equally well and would prove neither.

### 2. Slowness is a real HTTP proxy in front of a real, healthy service, and the retries are counted per request

`sigFailProxy` is an `httputil.ReverseProxy` in front of the real Fulcio or the
real Rekor. It forwards every byte and adds nothing but delay, so what the
wrapper meets on the far side of its timeout is the genuine article. It records
every request — method, path, timestamp, and the status the backend answered —
including the ones the client abandoned mid-flight, because a request the
client gave up on is still an attempt it made.

**Per request, not per connection**, and that is the one place this diverges
from `test/failure/harness_test.go`'s `countingProxy`. That one counts TCP
connections, which is the right granularity for a gRPC channel that opens one
per attempt. It is the wrong granularity here: Go's HTTP client keeps the
connection alive, so five sequential POSTs to Rekor's search index are one TCP
connection and five requests. Counting requests is what makes "bounded retries"
a measurement. Recording the **path** is what makes it possible to slow the
wrapper's own lookup without also slowing gitsign's upload — which is how
SIG-004 reaches the retry loop with a real entry really in the log.

### 3. "No new commit object" is a set difference over the object database, filtered to commits

`sigCommitObjects` runs
`git cat-file --batch-all-objects --batch-check='%(objectname) %(objecttype)'`
and keeps the `commit` rows. `assertNoNewCommit` compares the **set** before
and after, and names any member that appeared.

Three choices are packed into that and none is incidental. `cat-file
--batch-all-objects` rather than `git log` or `rev-list`, because those walk
refs: a commit object that exists but was never pointed at is invisible to
them, and "no new commit object at all" would then be satisfied by a signer
that created a commit and merely failed to move `HEAD`. The **filter on
`commit`**, because `git add` writes blobs and `git commit` writes trees, and
both may legitimately exist after a refused signature; what may not exist is a
commit. The **set** rather than the count, because a count is preserved by any
change that adds one object and removes another.

### 4. Every case carries a positive control, and one gates the suite

A control runs first: same fixture, same wrapper, same repository shape, same
claim, every dependency healthy. It asserts a real signed commit appears, that
the object count goes from zero to exactly one, that `HEAD` is that commit,
that the certificate's SAN is the claim's identity, and that a Rekor entry
exists. If it does not produce a commit the parent calls `t.Fatal` before any
failure-injection case runs, because those cases assert the absence of
something this fixture would not have been shown capable of producing.

Then **each blocked case restores its dependency and signs again**, in the same
repository, through the same `Signer`, with the same credential, and asserts
the object database gains exactly one commit. A refusal that becomes a commit
the moment the dependency returns is a refusal caused by the dependency. A
refusal on its own is indistinguishable from a broken fixture.

### 5. SIG-003 is two arms, and the second one defeats the pre-flight probe on purpose

The first arm is a cold `Signer`: the ADR-0031 probe fetches Rekor's log key,
fails, and the case asserts `ErrTransparencyUnavailable`, *not*
`ErrSigningUnavailable`, and no commit.

The second arm signs once with everything healthy — which warms the wrapper's
trust-material cache — and only then stops Rekor. The next `Sign` therefore
skips the probe entirely and goes straight to `git commit`, which is the
ordering the sentence is actually about: the natural implementation signs first
and logs after, and would leave a signed commit behind with nothing to make it
non-repudiable.

MEASURED, and this is the evidence the arm exists for. During the outage the
wire log in front of Fulcio shows:

```
12:45:46.656 GET  /api/v1/rootCert    -> 200      (the warm-up)
12:45:46.733 POST /api/v1/signingCert -> 201      (the warm-up)
12:45:47.304 POST /api/v1/signingCert -> 201      (with Rekor stopped)
```

A certificate was **issued** while the log was down — watched on the wire, not
inferred from the absence of a Fulcio error in a subprocess's prose — and the
object database still gained no commit. gitsign's own account of what then
happened is worth recording, because it contains a bounded retry nobody in this
project wrote:

```
failed to sign message: error uploading tlog (commit): uploading commit-SHA
rekor entry: Post "http://127.0.0.1:51559/api/v1/log/entries": giving up after
4 attempt(s): ... connect: connection refused
...
fatal: failed to write commit object
```

The arm asserts attribution against the **URLs** rather than that prose: the
error names Rekor's endpoint and does not name Fulcio's.

### 6. SIG-004 is three arms, and each one measures a different clause

- **Fulcio slow before the commit.** Latency past the client timeout on
  `/api/v1/rootCert`. MEASURED: refused after **2.001 s** against **30 s**
  injected, `ErrSigningUnavailable`, and **exactly one** request on the wire.
  The bound is asserted as `== 1` rather than `>= 1`, because a probe that
  started retrying would be a change worth failing over.
- **Rekor slow after the commit**, which is the only place in the shipped
  signing path that retries at all. Only `/api/v1/index/retrieve` is delayed,
  so gitsign's upload to `/api/v1/log/entries` succeeds and the entry really
  exists. MEASURED: **exactly 5** searches on the wire in **7.315 s**, gaps
  `[1.502s 1.502s 1.502s 1.502s]`, then `ErrTransparencyUnavailable`.
- **The repo lock.** `Config.Timeout` cut to 8 s against 120 s of injected
  Fulcio latency, with the trust material already cached so the delay lands
  inside `git commit`. MEASURED: refused after **8.002 s** with
  `signal: killed`, no lock file anywhere under `.git`, and an ordinary
  `git commit` accepted immediately afterwards.

A commit **does** exist at the end of the second arm, and that is not a §6.3
violation: the signature and its Rekor entry both exist and only the wrapper's
read-back failed, which is IP §6.5's crash-between-Phase-B-and-Phase-C window
that RM-035's reconciler repairs. The assertion that belongs there is that the
wrapper reported a failure rather than a `Result` it could not substantiate.

### 7. A third stack, a third overlay, and one parent test — all forced, all recorded

`test/failure/sigstore-isolated.yml` is a near-duplicate of
`internal/signing/testdata/sigstore-testscope.yml`. ADR-0031 predicted this in
terms — "moving it to `deploy/compose/sigstore-testscope.yml` is a rename and
should happen the moment a second suite needs it — RM-034's failure injection
is the likely first" — and RM-034 does not own `deploy/`. Pointing at another
package's `testdata` instead would make this suite break on a file it neither
owns nor is told about. Both copies should be deleted in the change that
creates the `deploy/compose/` one.

The three cases are subtests of one parent because the pair of compose projects
is torn down on the parent's `t.Cleanup`, and `TestMain` is not this issue's to
extend. It is also the right shape: they share one positive control.

## Alternatives considered

**A stub `CredentialSource`, a fake `http.RoundTripper`, or an unroutable
address.** Each is one line and none of them removes a dependency. A stub
proves the wrapper has the `case` arm we wrote; it cannot answer what a
repository holds after a real CA goes away, which is the entire content of
SIG-002. IP §2 settles it: "a mocked Fulcio proves nothing about I5."

**Partition the network instead of stopping the container** — `iptables` in the
container's namespace, or disconnecting it from the published network. Closer
to a real outage in one respect (the process is still alive and could still
complete work server-side) and rejected on two: it needs `NET_ADMIN` in a stack
that drops every capability by design (ADR-0029), and doc 07 says "Fulcio
blocked", not "Fulcio partitioned". ADR-0015 rejected the mirror image of this
for SPI-006 and the reasoning inverts cleanly: there, the *server-side*
completion was the interesting failure, so the server had to die; here, a
stopped container is both stronger and simpler.

**Count TCP connections, as `countingProxy` does.** Rejected on measurement:
Go's HTTP client reuses the connection, so the five searches SIG-004 has to
count would have appeared as one.

**Assert only the number of commit objects.** Rejected for the set difference:
a count is preserved by an implementation that adds a commit and prunes
another, and the failure message "3, want 3" would name nothing.

**Use `git log`, `git rev-list --all` or `HEAD`.** All ref-based, so all blind
to an unreferenced commit object — which is exactly the artefact a
"sign-later"-shaped bug would leave. `HEAD` is still asserted, but as a second
check rather than the first.

**Reuse `test/failure/harness_test.go`'s SPIRE stack and add Sigstore to it.**
The obvious economy, and it cannot work: that stack is up on
`INNSEGL_SPIRE_JWT_ISSUER=https://oidc.innsegl.dev`, the `iss` claim is fixed
at container start, and Fulcio has to *fetch* the discovery document from the
issuer it is told about. A JWT-SVID from that server buys no certificate from
any Fulcio. Standing up a stack of its own also means SPI-006's SIGKILL of
`spire-server` and SIG-002's stop of `fulcio` can never land on each other.

**Reference `internal/signing/testdata/sigstore-testscope.yml` from here.** No
duplication, and it couples this suite to a path in another package's testdata
that RM-032 is free to move. The duplication is visible, commented in both
files, and deletable in one change; the coupling would be invisible until it
broke.

**Assert that the retry gaps show backoff and jitter, as IP §6.3 words it.**
Rejected because it would be red against shipped code this issue may not
change — `internal/**` is out of RM-034's scope — and a test that fails for a
reason the author is forbidden to fix is a test that gets skipped. The gaps are
measured, logged, and recorded below as a finding instead. The inverse — an
assertion that the gaps are *equal* — was rejected for the opposite reason: it
would make the defect a requirement.

**Assert only that `.git/index.lock` is absent, and stop there.** That is what
doc 07's parenthesis literally asks for, and on shipped code it passes because
nothing ever took the lock (see Consequences). The case watches for locks
*while the signature is in flight* as well, so the assertion becomes real the
moment the invocation changes.

## Consequences

**A third Sigstore stack exists, and a `go test ./...` may now run three.**
`internal/signing` brings up SPIRE+Sigstore, `test/failure`'s `TestMain` brings
up a SPIRE trio, and this suite brings up a second SPIRE trio plus Sigstore:
roughly eleven more containers and a couple of minutes of bring-up per
concurrent test process. That is ADR-0015's bargain — "harder, and paid every
run" — taken a second time, and for the same reason: a case that destroys a
dependency may not destroy anybody else's.

**IP §6.3's "bounded retries with backoff and jitter" is only partly true of
the shipped signing path, and this suite now measures exactly how.** Two
findings, both MEASURED:

- The trust-material probe (`internal/signing.trustMaterial`) makes **exactly
  one** attempt. One attempt is bounded, and it is not a retry policy.
- The Rekor entry lookup (`findRekorEntry`) makes **exactly five**, and the
  four gaps came out `1.502101292s 1.502027042s 1.502630708s 1.502466333s` —
  identical to within a millisecond, because `rekorLookupDelay` is a constant.
  There is no growth and there is no jitter.

Neither is a bug this issue may fix: `internal/**` is out of scope for RM-034,
and both numbers are deliberate constants with comments explaining them. Both
are a question for the human, below.

**A warm `Signer` maps a Rekor outage to `ErrSigning`, not
`ErrTransparencyUnavailable`.** ADR-0031's probe distinguishes the two classes
only while the trust material is uncached; once cached, Rekor's death arrives
as gitsign's non-zero exit with the log's URL in the output. SIG-003's second
arm records this. **RM-033's `sign_commit` has to map it**, or IP §4's error
class for a Rekor outage will be right on the first commit of a run and wrong
on every one after it. See "what the project should do next".

**`git commit` in the form the wrapper uses holds no repository lock across the
signature, and that is why the lock clause passes.** MEASURED on git 2.51.0
with a signing program that sleeps six seconds:

```
git commit --file <msg>    -> no lock present at any point
git commit --only b.txt    -> .git/index.lock and .git/next-index-<pid>.lock
                              present for the whole signature
```

The whole-index path writes and releases the index lock *before* invoking the
signer; the `COMMIT_PARTIAL` path a pathspec selects holds both across it and
leaves them behind when the signer dies. So IP §6.3's lock clause is satisfied
structurally by ADR-0031 decision 1's exact command line, and it is one
argument away from not being. RM-033 must not add a pathspec or `-a` to that
invocation; the case watches for in-flight locks so that a change which did
would turn "the lock was released" from a true-but-empty statement into a
failing assertion.

**gitsign retries the Rekor upload four times on its own.** Bounded, upstream's,
and outside this project's control. Worth knowing when reading a SIG-003
timing: the refusal in that arm includes gitsign's own four attempts.

**`test/failure` now holds two harnesses and two overlays for two stacks.** The
duplication is commented at both ends. It is the same cost ADR-0015 recorded
for `internal/spire`'s harness versus this package's, arrived at the same way,
and it will drift unless a change to the SPIRE selectors or the Sigstore
overlay is made in every copy.

**Exit cost.** Low. Nothing outside `test/failure/` depends on any of it, and
deleting the three files removes SIG-002, SIG-003 and SIG-004 and nothing else.

## What the project should do next

1. **RM-033 must map a Rekor failure that arrives through `ErrSigning` to
   `TRANSPARENCY_UNAVAILABLE`**, or accept that the class is only correct on a
   cold `Signer` and say so. This suite's SIG-003 second arm is the case to
   extend once it does.
2. **Decide what IP §6.3's "bounded retries with backoff and jitter" requires
   of the signing path**, and if it requires more than one attempt at the trust
   probe and more than a constant delay at the lookup, file it against
   `internal/signing`. `internal/segment.RetryPolicy` already has the shape
   (`Backoff(attempt)`), and it too has no jitter — so the answer probably
   belongs in one place used by both.
3. **Move the Sigstore test overlay to `deploy/compose/sigstore-testscope.yml`**
   and delete both copies. ADR-0031 asked for this and named RM-034 as the
   trigger; RM-034 could not do it because it does not own `deploy/`.
4. **Give `test/failure`'s `TestMain` a teardown hook that lazily-started
   dependencies can register with.** `stopPostgres()` is hard-coded there and
   this suite could not add a second one, which is the whole reason its cases
   are subtests of one parent rather than three top-level tests named for their
   catalog IDs.

## For the human — two spec questions this ADR does not answer

**Doc 07's SIG-004 row and IP §6.3 do not quite agree.** IP §6.3 asks for
"bounded retries with backoff and jitter"; doc 07's Expected column asks for
"bounded retries then error; no repo lock held indefinitely (assert lock
released)". The suite discharges doc 07's row in full and IP §6.3's sentence in
part, and the part it does not discharge is a property of shipped code rather
than of the test. Which of the two is the requirement is a question for the
human, and the answer decides whether item 2 above is a bug or a nicety.

**Doc 07's SIG-004 parenthesis assumes a lock that the shipped invocation never
takes.** "Assert lock released" is written as though `git commit` holds one
across the signature; measured, it does not, on the whole-index path the
wrapper uses. The case still asserts it, and additionally watches for locks
held in flight so the assertion has something to be about if the invocation
ever changes. Whether the row should instead read "assert the repository is
usable afterwards" is the human's call.
