# ADR-0026: Read MCP-006 as reachability through the shipped tool, and record an unreachable cell as a finding rather than manufacturing a path to it

- Status: accepted
- Date: 2026-08-29
- Deciders: Mike

## Context

Doc 07 gives MCP-006 one line:

> Every documented error class reachable per tool (parameterized matrix) —
> Each `error_class` produced by at least one test; retryable flag correct —
> IP §4

IP §4 lists eleven classes and five tools and does not say which tool can
produce which class. Read literally, the cell count is 5 × 11 = 55, and the
acceptance criterion in #36 — "the matrix is exhaustive over tools multiplied
by error classes" — is that number.

**RM-020 (#28) already built a 110-assertion matrix**,
`TestMCP006EveryErrorClassIsReachableOverTheTransport` in
`internal/mcp/server_test.go`: five tool names × eleven classes × {run_id, no
run_id}, over a real `httptest` server and a real SDK client. It was written
before any tool existed, so what it binds under each of the five names is a
*probe* — a handler that takes a class as an argument and returns
`Errorf(class, runID, …)`. What it proves is real and load-bearing: every class
is **renderable** over the transport, in IP §4's four-field shape, with the
right flag, with `run_id` absent rather than empty when there is no run.

It cannot prove the other thing, because a probe is not a tool. Since RM-020,
four of the five tools have landed (RM-022..025). The question a matrix can now
ask, and could not before, is whether a **caller** can drive
`register_agent`, `get_credential`, `record_event` or `retire_agent` to each
class — through the arguments IP §4 gives it and the dependencies its
`Configure*` seam actually holds.

Three forces make that question the one worth answering:

- **A probe agrees with itself.** RM-020's matrix would stay green if every
  tool were deleted tomorrow, because the thing under test is the rendering,
  not the tool. Nine vacuous passes have already been caught on this project;
  a second 55-cell matrix that also asked a double what it thinks would be the
  tenth, and the most expensive to discover.
- **The tools' dependency sets are narrow and asymmetric.** `RecordEventConfig`
  has three members and none is a SPIRE client. `RetireAgentConfig` has no
  idempotency store, because ADR-0004 forbids the tool a key. `CredentialConfig`
  is the only one that holds a minter or an audience allowlist. Whole columns of
  IP §4's vocabulary have nothing to fail behind them.
- **A class a tool cannot produce is a fact about the document.** IP §4 writes
  the eleven as one vocabulary shared by all five tools. Where that is not true
  of a tool, saying so is worth more than a green row: it tells the next reader
  which classes a caller of that tool actually has to switch on, and it is the
  kind of thing that only becomes visible once the implementations exist.

## Decision

**1. MCP-006 is discharged by two matrices, not one, and this issue owns the
second.** RM-020's is the *wire-shape* matrix: is each class renderable by a
tool bound to return it. RM-028's is the *reachability* matrix: can a caller
drive the shipped tool to it. Both are needed and neither subsumes the other,
so RM-020's is not rewritten and not duplicated.

**2. Every one of the 55 cells carries a verdict, and the verdict is data.**
`reachable` carries the input that reaches the class; `unreachable` carries the
reason no input can; `deferred` is `sign_commit` (RM-033, #41) and nothing
else. A cell with a verdict and no substance fails
`TestMCP006TheMatrixIsExactlyToolsTimesClasses` before anything is run: a
reachable cell with no input, an unreachable cell with no explanation, or a
missing pair is a failure, so the table cannot decay into 55 rows of silence.

**3. Where a class cannot be reached, it is recorded and NOT manufactured.**
No test injects a class a tool's real dependencies cannot raise merely to turn
a row green. `ATTESTATION_FAILED` is the case this rule was written for: it is
unreachable through all four shipped tools, because they touch SPIRE only
through the admin entry API (`classifyAdmin`, which maps `PermissionDenied` to
`INVARIANT_VIOLATION`) and the admin SVID API (`credentialMintCodes`, same
mapping). The class is raised by `classifyWorkload` on the *Workload* API —
attestation happens when the workload fetches its own SVID from `spire-agent`,
which is SPI-002's territory, not an MCP tool call. IP §6.1's selector-mismatch
requirement is real and is met; it is simply not met *here*.

**4. Unreachability is asserted, not merely asserted-in-prose.** Four
mechanisms, so that a cell marked unreachable fails if it ever stops being:

- a **closure test** — a battery of malformed, hostile and boundary inputs
  against every tool, asserting that any class that comes back is one the
  matrix already grants that tool;
- a **gRPC status sweep** through the *shipped* minter (`mcp.NewSPIREMinter`
  over a faked `grpc.ClientConnInterface`), asserting that no code produces
  `ATTESTATION_FAILED`;
- **input-schema assertions** read off `tools/list` — a tool with no
  `idempotency_key` cannot reach `DUPLICATE_REQUEST`, a tool with no `audience`
  cannot reach `AUDIENCE_MISMATCH` — which bind the matrix to the advertised
  contract rather than to today's code shape;
- a **deferral assertion** — `sign_commit` is reported by `MissingTools()`, so
  the day RM-033 binds it the eleven blank cells fail rather than staying
  blank.

**5. The retryable flag is asserted from a hand-written table.** `ip4Retryable`
is transcribed from IP §4 and ADR-0016, marked *stated* or *derived* exactly as
ADR-0016 marks each row, and is never read from `internal/mcp`. For a cell
whose failure is chosen deliberately the assertion is equality. For an
exploratory outcome — the input battery, the status sweep — the assertion is
ADR-0016 §2's rule instead: a layer may **narrow** `retryable`, never widen it.
Equality would be wrong there, because narrowing is designed behaviour
(`credentialMintCodes` deliberately reports an unrecognised gRPC code as
`IDENTITY_UNAVAILABLE` *not* retryable — "unrecognised is not the same as
transient: do not spin").

**6. The tests live in `test/contract/`, outside `internal/mcp`.** Not for
isolation from the other agents on this branch — though it gives that too —
but because a package outside `internal/mcp` can only reach the tools the way a
caller does: over the HTTP transport, through `mcp.New` and the exported
`Configure*` seams. It cannot call an unexported helper to shortcut a class
into existence, which is exactly the property a reachability claim needs. #36
names `test/contract/` as the issue's exclusive scope, and
`scripts/coverage-floors.sh` instruments with `-coverpkg=./...`, so what this
package exercises still counts towards `internal/mcp`'s line floor.

**7. `RUN_NOT_FOUND` and `RUN_ALREADY_RETIRED` are asserted as a distinction,
in both directions.** RM-025 found that a *deleted SPIRE entry* produces
`RUN_NOT_FOUND` (get_credential's gate 4, `spire.RequireActiveRun`) while
`RUN_ALREADY_RETIRED` must come from the *ledger's* `run_retired` record (gate
3). MCP-010 is therefore not satisfied by "either of the two arrived": a run
retired through the tool and a run whose entry was deleted behind the MCP's
back are put in those two states for real and asserted to reach the caller as
two different classes. A deleted entry is not a retirement and must not be
reported as one — it says the run never existed, which is the wrong fact.

## Alternatives considered

- **Re-run RM-020's 5 × 11 × 2 shape against the real tools and call MCP-006
  done.** Rejected: it is the duplicate the issue warned against. It would also
  be impossible without inventing a way to make each tool return each class,
  which is the manufacture rule 3 forbids.
- **Force a path to every class in every tool — a test-only hook, an injected
  class, a fake that returns whatever the row wants.** Rejected as the
  vacuous-pass failure mode in its purest form: 55 green rows that assert the
  double, not the tool. It also destroys the finding: `ATTESTATION_FAILED`
  would look reachable everywhere and no reader would learn that the MCP tool
  surface cannot raise it.
- **Mark the unreachable cells "skipped" and say nothing.** Rejected: a skip is
  indistinguishable from an untested cell, and doc 07's whole posture is that a
  gate reports what went unproven rather than passing quietly
  (`scripts/branch-coverage.sh` PENDING, `requirePG`'s skip message). The
  reason a class is unreachable is the deliverable.
- **Assert `retryable` by equality everywhere, including the battery and the
  sweep.** Rejected on contact with the code: it fails for every unrecognised
  gRPC code, where narrowing to non-retryable is deliberate and correct. The
  narrowing invariant is the assertion ADR-0016 §2 actually makes, and it is
  strictly stronger where it matters — no layer may tell a caller to retry a
  refusal.
- **Put the tests in `internal/mcp/contract_test.go`.** Rejected for rule 6's
  reason: an in-package test can reach `Errorf`, `classifyAs` and every tool's
  unexported state, and a reachability claim made with those tools is not a
  claim about what a caller can do. `internal/mcp/` is also being written by
  two other agents on this branch right now.
- **Use fakes for Postgres, and prove `LEDGER_UNAVAILABLE` by having one
  return it.** Rejected: IP §6.4's class is "Postgres down", and the only
  honest test of it is a real Postgres that goes down. It is proven here by
  SIGKILLing a dedicated container out from under a stack that has already
  registered a run successfully — and doing it that way is what surfaced the
  57P01 divergence in the Consequences below, which no fake would have shown.
- **Stand up the containerised SPIRE stack here too, so the entry-API classes
  come from a real server.** Rejected as duplication with a real cost: RM-023's
  `credStack` already drives the shipped minter against
  `deploy/compose/spire.yml`, and `test/failure` already kills a real
  spire-server for SPI-006/007. What this package adds instead is the SVID API
  through the *shipped* classifier over a faked connection, which is the one
  SPIRE path a test can exercise for real without a container, and which is
  where the `ATTESTATION_FAILED` question actually lives.

## Consequences

- **`test/contract/` exists and is a Docker-dependent package.** Without a
  daemon it skips with a message naming what went unproven. It starts one
  shared Postgres for the package and one extra, disposable container for the
  outage case.
- **FINDING — two layers over one database disagree about a Postgres death.**
  Under a real SIGKILL, the first call that meets a stale pooled connection can
  receive `SQLSTATE 57P01: terminating connection due to unexpected postmaster
  exit`. `internal/ledger`'s `classify` reports that as `LEDGER_UNAVAILABLE`
  **retryable**; `internal/mcp/idempotency.go`'s `classifyStorage` sends every
  SQLSTATE that is not a constraint violation to `LEDGER_UNAVAILABLE`
  **not retryable** ("the database answered, but not usefully"). One outage,
  two layers, opposite advice — precisely ADR-0016's "a `false` on a dependency
  outage turns a thirty-second Postgres restart into a failed run". The window
  is one call wide, which is why only a real outage finds it. Not fixed here:
  `internal/mcp` is not RM-028's to edit. The tests drain the pools first and
  log the transitional classification, so the divergence is visible in the run
  output rather than a flake.
- **FINDING — `internal/mcp` declares `CredentialRuns` and ships no
  implementation of it.** Nothing yet reads `run_registered` and `run_retired`
  back out of the ledger, so `get_credential`, `record_event` and
  `retire_agent` cannot be wired in a deployment today. `test/contract` carries
  a deliberately dumb chain-scanning reader for its own use; the real one is
  somebody's issue and does not appear to have one.
- **FINDING — the mint path classifies with an empty `run_id`.**
  `spireMinter.MintJWTSVID` calls `credentialMintError("", err)`, so
  `get_credential`'s `IDENTITY_UNAVAILABLE` — the class a caller is most likely
  to retry — reaches the wire without the run it belongs to, even though the
  call named one. IP §4 makes `run_id` optional, so this is legal; it is
  asserted as observed behaviour, not endorsed.
- **FINDING — an input the advertised schema refuses never reaches a tool, and
  that refusal carries no `error_class`.** IP §4 says "All tools return
  structured errors", but argument validation happens in the transport, and its
  error has text content and no structured content. Correct SDK behaviour, and
  not one of the eleven; a caller switching on `error_class` must handle a tool
  error that has none.
- **The matrix has to grow when `sign_commit` lands.** Eleven cells are
  `deferred`, and `TestMCP006SignCommitIsDeferredNotForgotten` fails the moment
  RM-033 (#41) binds the tool. That is the intended trigger, not a nuisance.
- **Required follow-up, for the human only** (`docs/` outside `docs/adr/` is
  not edited by implementing agents):
  1. IP §4 presents the eleven classes as one vocabulary for all five tools.
     For four of the five that is not true, and this matrix records which
     columns are empty and why. IP §4 should say per tool which classes a
     caller has to handle, or state that the vocabulary is deliberately shared
     and over-broad.
  2. Doc 07's MCP-006 says "reachable per tool" without saying reachable
     *through what*. It is worth one clause distinguishing the wire-shape
     matrix (RM-020) from the reachability matrix (RM-028), because the two IDs
     currently collide on one line.
