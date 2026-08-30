# Architecture decision records

This directory is the project's decision record. It is the one part of `docs/`
that ships in the public repository — everything else under `docs/` is local
only.

An ADR is written for every significant decision. The test is: would a new
maintainer ask "why is it like this?"

## Rules

- ADRs live at `docs/adr/NNNN-title.md`, numbered sequentially.
- **ADRs are immutable once accepted.** A reversal is a *new* ADR that
  supersedes the old one; the superseded ADR keeps its text and gains a
  `Status: superseded by ADR-MMMM` line. Never rewrite history here.
- Start from [`0000-template.md`](0000-template.md). Every ADR carries all five
  sections: Status, Context, Decision, Alternatives considered, Consequences.
- "We preferred X" is not a reason. Each rejected alternative states the
  concrete reason it lost.

## Index

| ADR | Title | Status | Date |
|---|---|---|---|
| [0000](0000-template.md) | Template | — | — |
| [0001](0001-language-and-module-path.md) | Implement the backend in Go; the dashboard in TypeScript | accepted | 2026-08-28 |
| [0002](0002-public-sigstore-default.md) | Default to public Sigstore; self-hosted as first-class configuration | accepted; superseded in part by [0010](0010-self-hosted-sigstore-is-the-shipped-default.md) | 2026-08-28 |
| [0003](0003-apache-2-0-license.md) | License Innsegl under Apache-2.0 | accepted | 2026-08-28 |
| [0004](0004-idempotency-key-scope.md) | Scope `idempotency_key` to the MCP tools that accept one | accepted | 2026-08-28 |
| [0005](0005-one-chain-per-database.md) | Scope a ledger chain to a database | accepted | 2026-08-28 |
| [0006](0006-segment-object-format-and-content-addressed-segment-id.md) | Address a sealed segment by the digest of its object, and make that digest its `segment_id` | accepted | 2026-08-28 |
| [0007](0007-protected-surfaces-gate-semantics.md) | Enforce the protected surfaces with a self-verifying gate, and define what it does before the first tag exists | accepted | 2026-08-28 |
| [0008](0008-worm-canary-proves-refusal-by-attempting-deletion.md) | Prove the WORM configuration by attempting a real deletion, and fail closed on anything short of a refusal | accepted | 2026-08-28 |
| [0009](0009-anchor-a-segment-as-a-signed-hashedrekord-entry.md) | Anchor a sealed segment as a signed `hashedrekord` entry, verify it from first principles, and accept at-least-once anchoring | accepted | 2026-08-28 |
| [0010](0010-self-hosted-sigstore-is-the-shipped-default.md) | Ship self-hosted Fulcio/Rekor as the default, and demote public Sigstore to "where an accepted issuer already exists" | accepted | 2026-08-28 |
| [0011](0011-compose-spire-admin-api-segmentation.md) | Segment the SPIRE admin API by mount and by network, and state the part SPIRE will not segment | accepted | 2026-08-28 |
| [0012](0012-scope-the-mcp-admin-credential-with-an-opa-authorization-policy.md) | Scope the MCP admin credential with an OPA authorization policy | accepted | 2026-08-28 |
| [0013](0013-record-spire-entry-drift-as-ledger-drift-detected.md) | Record SPIRE entry drift as `ledger_drift_detected` where a subject event exists, and refuse to record the unattributed case at all | accepted | 2026-08-29 |
| [0014](0014-reaper-orphan-test-and-expiry-idempotency-key.md) | Bound a run identity by its entry's TTL plus a configured grace, and key `run_expired` by run id | accepted | 2026-08-29 |
| [0015](0015-failure-injection-stack-per-test-process.md) | Give SPIRE failure injection a stack per test process, and record the half of SPI-007 that `sign_commit` must finish | accepted | 2026-08-29 |
| [0016](0016-error-class-carries-retryability-and-one-place-renders-it.md) | Make `retryable` a property of the error class, narrowable but never widenable, and render IP §4's error in exactly one place | accepted | 2026-08-29 |
| [0017](0017-record-the-tool-call-reply-not-only-the-event.md) | Record the tool call's reply in Postgres, above the ledger's event-level dedupe | accepted | 2026-08-29 |
| [0018](0018-record-run-registered-before-creating-the-spire-entry.md) | Record `run_registered` before creating the SPIRE entry, and derive the run id from the call | accepted | 2026-08-29 |
| [0019](0019-scope-mintjwtsvid-to-the-agent-subtree-and-issue-one-audience-per-credential.md) | Allow `MintJWTSVID` to the admin credential only inside the agent subtree, and issue exactly one audience per credential | accepted | 2026-08-29 |
| [0020](0020-retire-a-run-by-its-run-id-alone-recording-before-deleting.md) | Retire a run by its `run_id` alone, recording before deleting, and answer every later call from the ledger | accepted | 2026-08-29 |
| [0021](0021-record-event-writes-only-tool-call-and-its-event-type-argument-names-the-tool.md) | Let `record_event` write exactly one event type, `tool_call`, and read its `event_type` argument as the agent tool's name | accepted | 2026-08-29 |
| [0022](0022-a-compose-project-per-test-process-for-the-shipped-spire-stack.md) | Give every test process that drives the shipped SPIRE stack a compose project of its own, and require the project name rather than defaulting it | accepted | 2026-08-29 |
| [0023](0023-read-the-recorded-reply-through-a-locking-read.md) | Read the recorded reply through a locking read, so a completion that loses the race is handed the winner's bytes | accepted | 2026-08-29 |
| [0024](0024-readiness-probes-sigstore-by-fetching-its-trust-material.md) | Define Sigstore reachability as serving parseable trust material, and keep every readiness probe read-only | accepted | 2026-08-29 |
| [0025](0025-rate-limit-register-agent-per-asserted-caller-and-alert-out-of-band.md) | Rate-limit `register_agent` per asserted caller, meter it on the ledger appender, and raise the trip out of band | accepted | 2026-08-29 |
| [0026](0026-mcp-006-is-reachability-through-the-shipped-tool-and-an-unreachable-cell-is-a-finding.md) | Read MCP-006 as reachability through the shipped tool, and record an unreachable cell as a finding rather than manufacturing a path to it | accepted | 2026-08-29 |
| [0027](0027-crash-mcp-011-by-sigkilling-a-purpose-built-server-and-hold-the-narrow-windows-open.md) | Crash MCP-011 by SIGKILLing a purpose-built MCP process, fuzz the kill timing against a measured call, and hold the two narrowest windows open rather than chase them | accepted | 2026-08-29 |
| [0028](0028-place-commit-trailers-in-process-and-refuse-the-messages-git-places-ambiguously.md) | Place commit trailers in process, refuse the messages git places ambiguously, and read I6 as "never emit `Co-authored-by:` at all" | accepted | 2026-08-30 |
| [0029](0029-compose-self-hosted-sigstore-as-its-own-project-joined-to-spires-oidc-network.md) | Compose self-hosted Sigstore as its own project joined to SPIRE's OIDC network, give the log a key that survives a restart, and issue no SCT | accepted | 2026-08-30 |
| [0030](0030-ship-the-mcp-entry-point-and-read-a-run-out-of-the-chain.md) | Ship the MCP entry point, read a run out of the chain in its own package, and make the earliest `run_retired` the answer | accepted | 2026-08-30 |
| [0031](0031-orchestrate-released-gitsign-through-git-commit-and-configure-around-the-absent-ct-log.md) | Orchestrate released gitsign through `git commit`, build its environment from nothing, and configure around the absent CT log | accepted | 2026-08-30 |
| [0032](0032-inject-a-sigstore-outage-by-stopping-the-shipped-container-and-assert-the-absence-of-a-commit-against-the-object-database.md) | Inject a Sigstore outage by stopping the shipped container, inject slowness by delaying a real one, and assert the absence of a commit against the object database | accepted | 2026-08-30 |
| [0033](0033-append-the-intent-before-the-credential-is-spent-and-derive-a-ledger-key-per-phase.md) | Order `sign_commit` so nothing that can fail cheaply happens after Phase A, and give each phase its own derived ledger key | accepted | 2026-08-30 |
| [0034](0034-verify-against-the-logs-record-of-the-commit-sha-and-evaluate-the-certificate-at-its-signed-integration-time.md) | Verify against the log's record of the commit SHA, and evaluate the certificate at the log's signed integration time | accepted | 2026-08-30 |
| [0035](0035-drive-the-repair-from-the-intent-and-record-an-expiry-only-on-an-answer.md) | Drive the reconciler's repair from the intent rather than from the log, and record an expiry only on an answer | accepted | 2026-08-30 |
| [0036](0036-cross-check-the-chain-against-rekor-in-both-directions-and-sweep-a-trailing-window.md) | Cross-check the chain against Rekor in both directions, and sweep a bounded trailing window of the log | accepted | 2026-08-30 |

## Open items

- **ADR-0007** flags a gap it does not close: `VERSIONING.md` protects "the
  `error_class` values they return" without enumerating them, and the only
  enumeration is IP §4, which is local-only. `scripts/protected-surfaces.sh`
  therefore carries the sole shipped copy of that vocabulary. Publishing the
  list belongs with the MCP tool work (RM-022..025).
- **ADR-0009** leaves one question for the human: doc 02 §3 gives
  `ledger_drift_detected` as emitted by `reconciler`, but the component that
  discovers an anchoring failure is the sealer, whose other output
  (`segment_sealed`) doc 02 marks `system`. The alert defaults to `system` and
  the caller may override; which value doc 02 intends needs deciding.
- **ADR-0004** requires one edit outside `docs/adr/`: doc 02 §2's
  `idempotency_key` description must be narrowed to "MCP tool calls that accept
  an `idempotency_key`", and its "≤128" made explicit as bytes. Implementing
  agents do not edit `docs/` outside this directory, so the ADR is the operative
  reading until a human makes that edit.
- **ADR-0005** leaves one question for the human: doc 02 §2 says
  `chain_position` is consecutive "per chain" and never defines a chain, and
  the envelope has no `chain_id`. The ADR defines a chain as a database, which
  is sufficient for the single-chain deployment doc 05 describes. A deployment
  needing several chains in one ledger requires doc 02 to say what names a
  chain and how a verifier reading a sealed segment learns which one it holds.
- ~~**ADR-0002** carries a blocking open verification item: whether public-good
  Fulcio will accept a project-operated OIDC issuer (`oidc.innsegl.dev`).~~
  **Closed 2026-08-28 by [ADR-0010](0010-self-hosted-sigstore-is-the-shipped-default.md).**
  Measured against the live instance: public-good Fulcio accepts no issuer of
  type `spiffe`, and the SPIFFE federation enrollment process ADR-0002's first
  fallback assumed was closed `not_planned` upstream. The second fallback
  triggered — self-hosted Fulcio/Rekor is now the shipped default and
  `oidc.innsegl.dev` is not stood up.
- **ADR-0010** leaves one question that cannot be settled from public sources:
  whether Sigstore's maintainers would entertain a SPIFFE issuer request from a
  project of this size if asked directly. Nobody has asked. Settling it costs
  one issue on `sigstore/fulcio` per that project's own new-IDP process; it is
  not on the critical path and the decision does not change if the answer is
  friendly. ADR-0010 also names a standing re-measurement: one unauthenticated
  `GET https://fulcio.sigstore.dev/api/v2/configuration` tells you whether a
  `spiffe` issuer has reappeared, and belongs with the threat model §6 review
  triggers — a human edit, outside this directory.
- **ADR-0017** leaves two questions for the human. IP §4's error-class
  vocabulary is closed and has no class for "the original call has not finished
  yet"; the MCP idempotency store returns `LEDGER_UNAVAILABLE` because it is the
  only candidate whose `retryable` flag gives the caller the right instruction,
  and whether IP §4 should gain a twelfth class is a protected-surface decision.
  And doc 07 has no test ID for the tool-call idempotency store itself: LED-008
  is the ledger's event-level dedupe, and MCP-007 and MCP-011 reach this layer
  only through tools that do not exist yet.
- **ADR-0018** leaves two questions for the human. IP §4's closed vocabulary
  has no class for "the caller sent an argument that cannot name a run";
  `register_agent` reports `INVARIANT_VIOLATION`, following the precedent
  already in the shipped source, which is alert-level for what may be a typo.
  And doc 07 has no ID for the ordering the ADR fixes — that the identity is
  never created before its record — which is the property a future reordering
  would silently break; **MCP-017** is proposed for it.
- **ADR-0020** leaves two questions for the human. Doc 07 has no ID for
  retirement's ordering either — the same gap ADR-0018 proposed **MCP-017** for,
  seen from the other direction: with SPIRE down the `run_retired` event exists
  and the entry survives, and with the ledger down SPIRE is never asked. And
  doc 07's MCP-009 row carries retirement's own idempotency in a parenthesis
  while doc 01 §4 states it as part of the signature and RM-025 states it as an
  acceptance criterion of its own; whether it should be a separate ID is a
  doc 07 edit. The ADR also records a consequence a later issue must honour: a
  run directory answering `CredentialRuns.CredentialRun` must report the
  **earliest** `run_retired` for a run, because concurrent first retirements can
  append two and IP §4 requires every later call to be answered with the
  original.
- **ADR-0024** leaves two items for the human. Readiness proves reachability,
  never writability — a read-only Postgres, a full disk or a Fulcio that serves
  its root and refuses to issue are all reported healthy — and that limit must
  appear wherever the endpoint is documented for operators. And doc 07 has no ID
  for the Sigstore half against a *real* Fulcio and Rekor, which cannot be
  written until RM-030 (#38) lands them in `deploy/compose/`; **MCP-018** is
  proposed for it.
- **ADR-0025** leaves four items for the human. IP §6.10 says "per caller" and
  E1 exempts the authorization that would make a caller identifiable, so the
  bucket is keyed on the asserted (`agent_type`, `task_ref`) pair: a runaway
  loop is bounded, an adversary who varies either value is not, and doc 04 §5's
  residual risks should say so rather than letting AB-07 read as fully closed.
  Doc 02 §3 has no event type for a rate-limit trip, so the trip is an operator
  alert and not a ledger record — conformant with doc 05 §2's "an event type
  **or** test", and `rate_limit_exceeded` is what doc 02 §3 would need if a
  record is wanted. And IP §4 has no class for "slow down" and no `retry_after`
  field; the refusal ships as `IDENTITY_UNAVAILABLE` with the wait in the
  message, which is the **third** situation to share that workaround after
  ADR-0017's and ADR-0018's — the case for a twelfth class is now cumulative.
- **ADR-0027** leaves three items for the human. IP §6.6 opens with "Every tool
  call is idempotent via required `idempotency_key`", and doc 07's MCP-011 row
  expects "Original result returned" from every tool — but ADR-0004 already
  decided that `get_credential` and `retire_agent` take no key, and that
  `get_credential` must *not* be deduplicated because "each issuance is a
  distinct auditable fact". Read literally, IP §6.6 and MCP-011 therefore ask
  for behaviour ADR-0004 forbids; read with ADR-0004, they ask for three
  different things of four tools. The harness asserts the ADR-0004 reading and
  names it per tool, and IP §6.6 should say "every tool call that accepts an
  `idempotency_key`" with MCP-011 stating what the two unkeyed tools owe a
  replay instead — which is IP §4's own words for `retire_agent` (the original
  timestamp) and "no second identity, one record per issuance" for
  `get_credential`. Second: IP §6.6 is written about a process and there is no
  process — nothing wires the five tools onto a listener, which RM-026 and
  RM-027 both flagged; `test/failure/crashd` is a test-only stand-in and the
  real `cmd/innsegl mcp serve` should replace it. Third: `internal/mcp`
  declares `CredentialRuns` and ships no implementation of it, so `crashd`
  carries the second private copy after RM-028's; the reader belongs with that
  entry point.
- **ADR-0026** leaves two items for the human. IP §4 presents the eleven error
  classes as one vocabulary shared by all five tools; RM-028's reachability
  matrix found that for four of the five whole columns are empty — no MCP tool
  can raise `ATTESTATION_FAILED` at all, because attestation happens at the
  Workload API and the tools only ever touch SPIRE's admin APIs — so IP §4
  should say per tool which classes a caller must handle, or state that the
  vocabulary is deliberately shared and over-broad. And doc 07's MCP-006 says
  "reachable per tool" without saying reachable *through what*: RM-020's matrix
  proves each class renderable over the transport and RM-028's proves each one
  reachable through a shipped tool, and the two readings currently collide on
  one line.
- **ADR-0029** leaves one spec edit for the human, and it is the second half of
  an edit ADR-0010 already named. Doc 05 §1's `fulcio` row still reads "Compose
  default is the **local** stack so CI needs no network; the *installed product*
  default is public Sigstore per ADR-0002 — the compose README states this
  asymmetry explicitly." ADR-0010 removed that asymmetry, so the row instructs
  the compose README to state something untrue;
  `deploy/compose/sigstore/README.md` states the current position and names the
  row as stale instead. Doc 05 §3's `oidc.innsegl.dev` row is the same edit's
  other half — ADR-0010 decision 1 already decided it is not built. Separately,
  and inside the repository rather than the specs,
  `deploy/compose/spire.yml` still defaults `INNSEGL_SPIRE_JWT_ISSUER` to
  `https://oidc.innsegl.dev`: every path the project actually uses needs
  `http://spire-oidc:8080`, which is why `make sigstore-up` sets it for both
  compose files and `sigstore.yml` refuses to start without it. Changing that
  default is RM-014's file.
- **ADR-0030** leaves three things for the human and resolves none of them.
  `run_expired` does not set `CredentialRun.RetiredAt`, so a run the reaper
  expired reads as live to the run directory and is refused one layer down as
  `RUN_NOT_FOUND` rather than `RUN_ALREADY_RETIRED`; whether an expired run
  should be reported as retired is a question about IP §4's vocabulary and
  doc 02 §3's two terminal events. Doc 07 has no test-catalog ID for the entry
  point, so "the server starts and answers a real call end to end" and "the
  served `register_agent` is metered" are unnumbered — the fourth and fifth
  such cases since ADR-0018 proposed MCP-017. And the register_agent rate limit
  is now ON in the shipped entry point, which makes ADR-0025's follow-up 1 — a
  twelfth error class, or a `retry_after` on IP §4's error object — a live cost
  rather than a hypothetical one.
- **ADR-0031** leaves four. `gitsign` is a runtime dependency with no `go.mod`
  entry, pinned only by the test harness's `harnessGitsignVersion` — deliberate,
  and it means a version bump is invisible to `go mod` tooling.
  `internal/signing/testdata/sigstore-testscope.yml` is a compose overlay under
  `internal/` because RM-032 does not own `deploy/`; ADR-0029 asked for it in
  `deploy/compose/` and moving it there is a rename that should happen the
  moment a second suite needs it. `deploy/compose/spire/register.sh` cannot be
  driven against a per-process stack — it hardcodes `innsegl-spire-oidc` and
  `-f spire.yml` with no project — so the Go harness reimplements its five
  selectors; parameterising the script is `deploy/`'s to do, and until it
  happens every suite that needs Fulcio will rediscover that a missing OIDC
  registration presents as Fulcio's "There was an error processing the identity
  token". And doc 07 has no ID for the wrapper's own certificate check, the
  INVARIANT_VIOLATION that arrives from our own side; proposed **SIG-010**.
- **ADR-0032** leaves four, and two of them are questions about the spec rather
  than about the code. IP §6.3 asks the signing path for "bounded retries with
  backoff and jitter"; MEASURED, `internal/signing`'s trust-material probe makes
  exactly one attempt and its Rekor lookup makes exactly five at a constant
  500 ms — bounded, waiting, and with neither growth nor jitter — so whether
  that sentence is a requirement is a question for the human, and RM-034 could
  not answer it because `internal/**` is outside its scope. Doc 07's SIG-004
  parenthesis, "assert lock released", assumes a lock that the shipped
  `git commit --file` invocation never takes: measured, the whole-index path
  releases `.git/index.lock` before calling the signing program, while a
  pathspec would hold it across the signature — so the clause is satisfied
  structurally and is one argument away from not being. A warm `Signer` maps a
  Rekor outage to `ErrSigning` rather than `ErrTransparencyUnavailable`, which
  RM-033's `sign_commit` has to render as `TRANSPARENCY_UNAVAILABLE` or the
  class is right only on a run's first commit. And `test/failure` now carries a
  second Sigstore compose overlay for the same reason ADR-0031 carried the
  first — no ownership of `deploy/` — so the move ADR-0031 asked for now has two
  copies to delete instead of one.
- **ADR-0033** leaves three, and one of them is a question about the spec. IP §4
  names `sign_commit`'s `staged_ref` argument once and no document in `docs/`
  defines it, so reading it as "a git revision naming the tree the caller
  staged, which must equal the index" is an INFERENCE — a caller who reads it as
  the branch being committed to gets a refusal, and that is a question for the
  human rather than permission to widen the reading. Doc 07 has no ID for the
  property IP §6.5 exists to state: SIG-001's "intent+recorded events in order"
  covers the two events, and the assertion that the SIGNATURE fell between them
  is unnumbered — proposed **SIG-011**. And the five-selector registration of
  `spire-oidc` that ADR-0031 had to reimplement now exists in three places
  (`internal/signing`, `internal/mcp`, `test/failure`), because
  `deploy/compose/spire/register.sh` still hardcodes one container name and one
  project; parameterising it is `deploy/`'s to do and every suite that needs
  Fulcio pays for its absence again.
- **ADR-0034** leaves five, and the first is the one to act on. The verifier
  FETCHES Fulcio's root and Rekor's log key from the URLs it is given, because
  that is what a stranger has, which means `innsegl verify` pointed at an
  endpoint an attacker controls proves nothing; pinning them (`--rekor-key`,
  `--fulcio-root`, with the fetch as a named fallback) is the next serious step
  for that package and it was not invented quietly here. A second CMS
  certificate reader now exists, in a package that may not import the first —
  threat model §5.4's concern, doubled. Doc 07 has no ID for the signed entry
  timestamp, which is what makes VER-004's and VER-005's "moment" trustworthy;
  proposed **VER-007**. `scripts/coverage-floors.sh` has no line floor for
  `internal/verify` (the branch floor does apply); the entry to add is
  `"internal/verify 95"`, and `scripts/` is not RM-037's to change. And
  `register.sh` has now been reimplemented a FOURTH time, and
  `sigstore-testscope.yml` is now referenced by a second suite from inside
  `internal/signing/testdata/` — both are the same unowned `deploy/` work
  ADR-0031 and ADR-0032 already asked for.
- **ADR-0035** leaves three, and the first is a defect in shipped code. The run
  directory (`internal/rundir`) uses `task_ref` VERBATIM as the SPIFFE ID's
  `{task_id}`, and doc 02 §5 makes `{task_id}` lowercase — so doc 02's own
  golden fixture 01, whose `task_ref` is `"JIRA-118"` and whose SPIFFE ID holds
  `jira-118`, would be refused by the shipped directory as an identity that
  "does not name run … of task …". `internal/mcp`'s SIG-001 harness lowercases
  it and the shipped directory does not; RM-035's integration case uses an
  already-lowercase `task_ref` and says so rather than papering over it. It is
  RM-068's (#89) to answer. Doc 07 has no ID for the property that keeps an
  expiry honest — that a Rekor outage produces no `commit_intent_expired` —
  proposed **REC-006**. And IP §6.5 does not say what to do when two signed
  commits claim one intent; the reconciler refuses and alerts, and superseding
  one with the other is a schema question and a human's.
- **ADR-0036** leaves four, and the first is that the control ships dark.
  `Config.Drift` is optional and `cmd/innsegl/reconcile.go` — not RM-036's —
  does not set it, so REC-003 and REC-004 are proved by tests and are not
  running in a deployment; wiring it, with a `-sweep-window` flag, is the
  follow-up. Doc 07 has no ID for the negative control that makes both cases
  mean anything (a legitimate signed commit raising nothing), proposed
  **REC-007**, nor for the second-order fabrication — a `commit_recorded`
  pointed at a real entry belonging to another commit or another identity —
  proposed **REC-008**; both are written and green. And issue #44's acceptance
  criteria claim AB-04, which doc 04 §3 assigns to MCP-008, SPI-004 and
  MCP-014; this work closes AB-03 and is only a partial detection for AB-04,
  and says so rather than claiming it.
