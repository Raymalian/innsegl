# ADR-0037: Gate I6 over every commit the repository already has, refuse a shallow clone, and make GH-001's run date a tracked artefact that expires

- Status: accepted
- Date: 2026-08-30
- Deciders: Mike

## Context

I6 is the invariant this project cannot prove:

> No GitHub contributor is ever added. Commit author is the human operator or a
> deliberately unlinked address; agent identity lives only in trailers +
> signature. Never emit `Co-authored-by:` with a resolvable account.

Every other invariant is settled by an artefact. I1 and I2 by a hash chain and
a Merkle root; I4 by an object-lock refusal; I5 by a Fulcio certificate and a
Rekor inclusion proof. Each of those can be re-checked from the artefact alone,
years later, by someone who does not trust us.

I6 is settled by GitHub's behaviour. There is no artefact. A commit authored by
an address GitHub can resolve produces a contributor, and once the account is
in the graph the commit cannot be un-authored without rewriting history that
other people have already fetched. ADR-0028 §7 already drew the operational
conclusion — the author guard blocks rather than warns, and its zero value
admits nothing — and left the repo-level half explicitly open:

> **IP §6.9's repo-level CI gate is not built here.** `CheckAuthor` is exported
> so that gate asks this package's question rather than a second question
> shaped like it, but the gate itself — walking a repository's commit authors —
> belongs to RM-038 and to `.github/`, neither of which this issue owns.

RM-038 is that gate, plus the half of I6 that faces outward. IP §6.9:

> Author-email safety (I6): a repo-level CI gate test asserts commit author
> emails match the configured human/unlinked pattern. Include an integration
> test against a scratch GitHub repo verifying no new contributor appears after
> agent commits; document that this check is empirical and must be re-run if
> GitHub changes attribution behavior.

doc 07 numbers the two halves **GH-002** (C, the gate) and **GH-001** (E, the
empirical check), and threat model §5, residual risk 3, names the property that
makes the second one awkward:

> GitHub contributor-logic change. I6's empirical guarantee (GH-001) is a
> snapshot of external behavior; the test is dated and re-run on a schedule.

Four decisions follow, and the last two are about honesty rather than
mechanism.

## Decision

**1. The gate walks every non-merge commit reachable from HEAD, not a
pull-request range.**

The obvious implementation is `git log base..head` over the commits a pull
request adds. It is rejected because resolving that range is where this class
of gate fails silently. `github.event.pull_request.base.sha` is the base branch
at event time and not necessarily an ancestor of the head; `actions/checkout`
leaves HEAD at `refs/pull/N/merge` on a `pull_request` event, which is neither
of them; a shallow clone has neither ref present at all. Every one of those
mistakes produces an empty or wrong range, and an empty range contains no
violation, so **the gate passes on every pull request forever** while looking
exactly like a working gate. Fifteen vacuous passes have already been caught on
this project; this one would have been the sixteenth.

Walking the whole reachable history removes the resolution step entirely. HEAD
always exists, its ancestry always contains the pull request's own commits, and
the answer is stronger than the range answer: it is issue #46's second
acceptance criterion, "this project's own commit history satisfies I6", asserted
continuously instead of once.

**Merge commits are excluded**, and not as a convenience. GitHub's own
contributor calculation excludes them, so a merge commit cannot produce the
outcome I6 forbids; a merge commit's author is whoever performed the merge
rather than the author of any content; and GitHub synthesises one per
pull-request run at `refs/pull/N/merge`, authored by `GitHub
<noreply@github.com>`, which exists in no repository and is fetched only to be
built. Including them would fail every pull request over a commit nobody wrote.

**2. A shallow clone is a hard failure, and an empty range is a hard failure.**

These are the two ways decision 1 could still be hollowed out. `fetch-depth: 0`
is set in `author-gate.yml` and in ci.yml's two suite-running jobs, and the test
asserts `git rev-parse --is-shallow-repository` is false rather than quietly
inspecting the three commits it can see. `collect` returns an error rather than
an empty slice, so no caller can read "nothing selected" as "nothing wrong".

Neither is a skip. A skip is what `scripts/test-no-skips.sh` exists to refuse,
and both of these conditions mean the gate did not run — which is a failure,
not a pass.

**3. The gate asks `internal/signing`'s question, for both halves of I6, and
holds no copy of either rule.**

The author half calls `signing.AuthorPolicy.CheckAuthor` — the same call
`CommitMessage` makes before it will render a message for gitsign — so an
address the gate admits is exactly an address `sign_commit` would sign under.

The co-authorship half is the awkward one, because ADR-0028 §5's matcher
(`hasTrailerToken`: start of line, case-insensitive, optional whitespace before
the separator) is deliberately unexported. The gate therefore asks
`signing.CommitMessage` itself, **one line at a time**, in a synthetic
two-paragraph message, and treats `errors.Is(err, signing.ErrCoAuthorship)` as
the answer. Per line rather than per message, because `CommitMessage` returns on
the first problem it meets: a message with a `---` divider above a
`Co-authored-by:` trailer comes back as `ErrMessage`, and the trailer would go
unseen. Asked line by line, nothing can mask anything else.

The alternative — reimplementing a five-line matcher in `test/e2e` — is the
shape of thing that is right on the day it is written and wrong the first time
ADR-0028's matcher is widened. This is the same argument ADR-0028 decision 1
made about `git interpret-trailers`, pointed the other way.

**4. The empirical half refuses to run rather than degrading into something
that passes.**

GH-001 needs a throwaway GitHub repository, a push credential and a wall-clock
wait, and it is not adaptable: the thing under test is GitHub's attribution
logic, so any version of it that does not contact GitHub is testing this
repository instead, which is what GH-002 already does. It therefore skips, with
a message naming the two environment variables, the shape of repository
required, the token scope, the default fifteen-minute propagation wait and the
exact command — and the skip is allowlisted in `scripts/test-no-skips.sh` with
that reasoning written out, alongside the two entries already there.

What it asserts when it does run is two things, not one. The **immediate** one
is that `GET /repos/{repo}/commits/{sha}` returns `author: null` — a contributor
is precisely an account GitHub resolved an author email to, so a non-null
`author` is I6 broken before any propagation delay and needs no waiting. The
**deferred** one is that the account-bearing contributor list is unchanged after
the wait. The anonymous list (`anon=1`) is recorded as an observation and not
asserted on: an anonymous entry is git's author identity, not an account, and
expecting it to be absent would be expecting GitHub to forget the commit.

**5. The run date is a tracked file, and it expires.**

`test/e2e/testdata/gh-001-run.json` carries the status, the UTC instant of the
last real run, the scratch repository, the author address, the pushed SHAs, the
contributor lists observed before and after, the propagation wait actually used,
and `rerun_after_days`. A successful run rewrites it; committing it is the last
step.

`TestGH001TheRecordedRunDateIsHonest` reads that file on every CI run, on every
machine, with no credential and no network, and **never skips**. It fails when
the recorded run has aged past `rerun_after_days`, which turns threat model §5's
"re-run on a schedule" from an intention into an assertion. It also refuses a
record that claims a pass it did not observe: status `ran` must carry the
repository, the author, the SHAs, and contributor lists that are genuinely
equal, so a hand-edited status cannot stand in for the measurement.

Today the file reads status `never-run`, which is the true state: **I6's
empirical half is unproven.** The test says so in the log on every run, in those
words. The monthly job in `author-gate.yml` fails while the credential is
unprovisioned, so the debt reaches the repository owner by email rather than
sitting in a file.

**6. E3 is documented in the package a reader arrives at, not only in an ADR.**

IP §3, E3 — "GitHub's UI does not render gitsign signatures as Verified. Do not
chase this; document the limitation." The place someone meets that question is
the same place they meet the contributor question, so `test/e2e/doc.go` carries
a section on it: what GitHub's badge actually checks (keys an *account* has
uploaded), why gitsign can never satisfy it (the key is ephemeral by design, and
the binding is a short-lived certificate plus a Rekor entry, neither of which
the badge consults), what an "Unverified" badge therefore means (GitHub holds no
uploaded key that made this signature — true, and silent about whether the
signature is good), and why chasing it is the wrong trade: it would mean
uploading a long-lived key to an account, reintroducing the standing key E8
removes and the account attribution I6 removes, to win a badge. The GH-001
record carries the same statement in a `github_verified_badge` field, so a
reader of the empirical record meets it too.

**7. GH-002 is a workflow of its own, `author-gate.yml`, not a job in
`ci.yml`.**

Four reasons, in order of weight. It is the only gate that reads git history, so
it is the only one that needs `fetch-depth: 0`, and a checkout option needs to
sit next to the reason for it. The check's NAME has to carry the finding: a red
"I6 author gate" tells a reviewer what is wrong, a red "test (race)" does not.
It needs no Docker, no gitsign, no Postgres and no MinIO, so it answers in under
a minute instead of after the integration suite. And it is where the monthly
GH-001 schedule belongs — a re-run that is not a merge gate at all and must not
fire on every push.

The gate's test cases also run inside `go test ./...`, so `ci.yml` enforces I6
too; the separate workflow is about latency and legibility, not about being the
only enforcement.

## Alternatives considered

- **Gate the pull request's own commit range (`base..head`).** The literal
  reading of doc 07 GH-002 and rejected on the failure mode: every way of
  resolving that range in GitHub Actions has a case that yields nothing, and
  nothing passes. Walking the reachable history is a superset of the range on
  every event, costs a `fetch-depth: 0` on a 25-commit repository, and cannot
  resolve to the wrong thing.

- **Implement the gate as a shell script over `git log` with a regular
  expression for the address.** Rejected for the reason ADR-0028 already
  rejected a configurable regex: one unescaped dot or missing anchor silently
  opens a gate that has no cryptographic backstop. Worse here, because a second
  copy of the rule can drift from `CheckAuthor` without either copy changing —
  the drift happens when `internal/signing` is edited and the script is not.

- **Add a `cmd/i6gate` binary so the workflow runs a program rather than a
  test.** Cleaner to invoke and rejected on cost: it would put a production
  command in the shipped binary whose only caller is CI, and `go test` already
  supplies the fixture repository, the assertions and the failure formatting.
  doc 07 classes GH-002 as (C) — a CI gate — not as a shipped feature.

- **Let the author policy live in the workflow file as an environment
  variable.** Rejected because the policy would then exist only in a file the
  test cannot read, so `go test ./...` on a developer's machine would enforce
  either nothing or a second hardcoded copy. One committed file,
  `test/e2e/testdata/author-policy.json`, decoded strictly so a mistyped key is
  a failure rather than a silently ignored one.

- **Put the operator allowlist in `CONTRIBUTING.md` or `VERSIONING.md`, where a
  human would look first.** Genuinely better for discoverability and not
  available: RM-038 owns `.github/workflows/`, `test/e2e/`, `docs/adr/` and one
  line of `scripts/test-no-skips.sh`. The gate names the exact path in every
  refusal instead, and this ADR records that the file's home is a scope
  artefact — moving it somewhere a contributor would find unaided is a
  reasonable follow-up.

- **Skip the history check on a shallow clone.** Rejected twice over: a skip is
  what `scripts/test-no-skips.sh` exists to refuse, and a gate that silently
  inspects three commits out of twenty-five is the exact false green this
  project keeps finding. `fetch-depth: 0` is one line in two jobs.

- **Have the gate accept `@users.noreply.github.com` as the unlinked form.**
  Not re-litigated; ADR-0028 §6 settled it, and the gate inherits the decision
  by calling `CheckAuthor` rather than by restating it. The bite test pins the
  consequence: `9999+agent-bot@users.noreply.github.com` is refused while the
  operator's own noreply address, enumerated in `Operators`, is admitted.

- **Let GH-001 fall back to a local git server or a recorded HTTP fixture.**
  Rejected: it would assert that our recording of GitHub's 2026 behaviour
  matches our recording of GitHub's 2026 behaviour. The entire value of GH-001
  is that it is the one case in the catalogue whose answer we do not control.

- **Emit a warning annotation when the GH-001 credential is unprovisioned,
  rather than failing the scheduled job.** Rejected: a warning on a job nobody
  opens is the false-green shape this repository has hit repeatedly. The job
  runs only on a schedule or by hand, so failing it blocks no merge and sends
  the owner one email a month saying an invariant is still unmeasured.

- **Fail CI immediately while the record reads `never-run`.** The strictest
  option, and rejected as the wrong instrument: it would block every unrelated
  merge on a credential only one person can provision, and the pressure would
  be released by editing the file rather than by running the test. The loud
  `UNPROVEN` log line on every run, the failing monthly job, and the hard
  staleness failure once a run IS recorded put the pressure where it can be
  acted on.

- **Assert that no anonymous contributor appears either.** Rejected as false:
  an anonymous contributor entry is git's author identity as recorded in the
  commit, not a GitHub account, and expecting its absence would be expecting
  GitHub to forget the commit exists. It is recorded as an observation, which is
  what makes the record readable later if GitHub's behaviour changes.

## Consequences

- **A commit that violates I6 and reaches `main` fails every subsequent pull
  request until the history is rewritten or the address is added to the
  policy.** This is the fail-closed direction and it is deliberate — a
  contributor in the graph is not undoable, so the gate should not be
  satisfiable by waiting — but it is operationally sharp, and the remediation
  path is exactly one file. `test/e2e/testdata/author-policy.json` is the right
  fix when a NEW HUMAN operator starts committing. It is never the right fix for
  an agent address (ADR-0028 §6), and the failure message says so.

- **The co-authorship half of the gate has a residual: a line whose carriage
  return survives into the commit object.** `signing.CommitMessage` refuses a C0
  control before it looks for the trailer, so such a line comes back as
  `ErrMessage` and is not reported as co-authorship. The gate strips one
  trailing CR — the CRLF artefact — and no more. Widening it would mean
  normalising a message before asking about it, which is the mutation ADR-0028's
  alternatives section rejects. **Flagged, not resolved.**

- **`ci.yml`'s `test` and `coverage` jobs now check out the full history.** The
  cost is a few seconds on a 25-commit repository today and grows with the
  history. If it ever matters, the fix is to move the history test out of
  `go test ./...` and into `author-gate.yml` alone — at the price of I6 no
  longer being enforced by a developer's local run, which is why it was not
  done now.

- **doc 07 has no ID for two properties this work pins.** The first is the
  anti-vacuity guard: the same scan, run over this repository's real history
  under the zero-value policy, must refuse every commit — the check that
  proves the gate is reading this history rather than reporting an absence it
  never looked for. Proposed **GH-003** (U). The second is the honesty of the
  dated record itself, `TestGH001TheRecordedRunDateIsHonest`, which is the only
  thing enforcing threat model §5's re-run schedule. Proposed **GH-004** (U).

- **`test/e2e/testdata/author-policy.json` is a policy file living under
  `testdata/`, which reads like a fixture and is not one.** It is where the
  gate's ownership boundary put it. A contributor looking for "who may author a
  commit here" will not find it by browsing; they will find it by failing the
  gate, which names the path. Moving it to the repository root and referencing
  it from `CONTRIBUTING.md` is a follow-up for whoever owns those files.

- **I6's empirical half is unproven as of this ADR's date, and nothing in this
  repository claims otherwise.** GH-002 proves this project follows its own
  author policy. Only GH-001 proves the policy achieves what I6 claims, and it
  has never been run: the record says `never-run`, the test says `UNPROVEN` in
  the log on every CI run, and the monthly job fails. Per IP §8 — "any invariant
  I1–I6 that cannot be demonstrated by a running test is treated as
  unimplemented regardless of what the code appears to do" — **I6 is
  half-demonstrated**, and the half that faces GitHub is waiting on a human with
  a throwaway repository.

- **The snapshot expires by design, and the expiry is a merge gate.** Once a run
  is recorded, `rerun_after_days` (90) later every pull request fails until the
  test is re-run. That is the intended cost of an invariant whose truth is
  somebody else's implementation detail, and it is the mechanism threat model §5
  asks for. An operator who wants a different interval edits one number in the
  record, in the open.

- **Exit cost.** Low. `test/e2e` has no production code and never will; deleting
  it deletes the gate and nothing else. The one thing that is expensive to
  reverse is the author policy's content: an address admitted once is in signed
  commits and in Rekor, and narrowing the allowlist later cannot un-author them.
