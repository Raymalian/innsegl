# ADR-0043: Enforce IP §2's 100% branch floor with gobco, in a job that reruns the tests

- Status: accepted
- Date: 2026-09-05
- Deciders: Mike

## Context

IP §2 states two coverage floors, not one: "90% line coverage on the MCP
server and ledger packages, and 100% branch coverage on: hash-chain append,
segment sealing, signature verification, and every error-return path of every
MCP tool." RM-002 (#10) built `scripts/coverage-floors.sh` for the first floor
and left the second as a `NOT ENFORCED` block naming two candidates: a
branch-coverage tool such as `gobco`, or a per-branch test-ID manifest checked
against doc 07's test catalogue. RM-064 (#72) is the issue that closes that
gap, and this ADR is the record RM-064's own acceptance criteria require of
it.

### Why a statement floor cannot stand in for a branch floor

`go test -cover` and `go tool cover` measure **statements**: a line of code is
"covered" if any test executed it at least once. Go's toolchain has no branch
mode — there is no flag that reports whether an `if` was ever taken both
ways. That gap is not cosmetic. Take `internal/ledger`'s own shape:

```go
func Append(pos int, payload string) (int, error) {
	if payload == "" {
		return 0, ErrEmptyPayload
	}
	...
}
```

A single test that calls `Append` with a non-empty payload drives the
`payload == ""` condition, the return statement inside the `if`, and every
statement after it — reaching 100% *statement* coverage while the error path
is never exercised at all. That is exactly the shape doc 04's failure modes
worry about: an error-return path that compiles, is never wrong in review, and
is never run. `scripts/coverage-floors.sh`'s own self-test
(`coverage-floors-selftest.sh`) demonstrates this concretely — its fixture's
`TestAppendSuccess` alone reaches high statement coverage while leaving three
error branches untested in both directions.

`gobco` (github.com/rillig/gobco) closes that gap by instrumenting **conditions**
rather than statements: every `if`, `&&`, `||`, `for` and `case` condition in
the target package is wrapped so that a test run records whether it was ever
evaluated `true` and ever evaluated `false`. `gobco -branch` reports every
condition that was observed in only one direction. That is condition/decision
coverage, not full path coverage — a function with two independent two-way
conditions has 4 paths through it but only 4 direction-observations to
satisfy, so gobco can be green on a path combination nothing ever exercised.
IP §2 asks for "branch coverage", and condition coverage is what a tool can
mechanically check for that name in Go today; it is a materially stronger
floor than statements, not a complete one, and this ADR does not claim
otherwise.

## Decision

**Use gobco, run as a separate CI job, gating the five surfaces below.**

`scripts/branch-coverage.sh` runs `gobco -branch ./<package>` once per
package that carries a floored surface, and fails (`exit 1`) if any
instrumented condition in a named surface file was observed in only one
direction. A surface whose file does not exist yet reports `PENDING` — named
and counted, never silently skipped or silently passed.

### Why these five surfaces, mapped from IP §2's four

IP §2 names four things: hash-chain append, segment sealing, signature
verification, and every error-return path of every MCP tool. The script
floors five, because segment sealing spans two files with independent branch
logic and folding them into one grep pattern would hide a regression in
either:

| # | surface (IP §2) | package | file(s) |
|---|---|---|---|
| 1 | hash-chain append | `internal/ledger` | `chain.go` |
| 2 | segment sealing | `internal/segment` | `seal.go` |
| 3 | (segment sealing, cont'd) | `internal/segment` | `merkle.go` |
| 4 | signature verification | `internal/verify` | every file (RM-037) |
| 5 | every MCP tool error-return path | `internal/mcp` | every file (RM-022…025) |

Surfaces 4 and 5 floor the whole package rather than one file: "signature
verification" and "every error-return path of every MCP tool" are properties
of the package's public surface, not of one file inside it, and floor-by-file
would let a new file in either package ship unfloored by omission.

### Why a separate job, and why that costs something

`gobco` does not read an existing `cover.out`. It **recompiles and reruns the
tests** of every package it is pointed at, under its own instrumentation. Two
consequences follow directly:

- **It cannot be a step appended to the `coverage` job.** That job already
  produces one profile with `-coverpkg=./...`; gobco needs its own
  instrumented build of exactly the packages under floor, and running it
  there would mean running the full suite for `internal/verify` and
  `internal/mcp` — both real, container-backed integration suites (SPIRE,
  Fulcio, Rekor) — a second time in the same job, which doubles that job's
  runtime and its Docker load for no coverage benefit the first run didn't
  already produce a profile for.
- **It is genuinely slower.** Measured locally: `./scripts/branch-coverage.sh`
  over the five surfaces, including `internal/verify`'s and `internal/mcp`'s
  real compose-backed integration suites, took several minutes — long enough
  that it must not block on the `coverage` job's own run, and short enough
  (relative to the rest of CI) that a dedicated job in parallel costs nothing
  the pipeline wasn't already going to spend.

Running it as its own job (`branch-coverage` in `.github/workflows/ci.yml`)
buys parallelism with the statement-floor job and keeps a gobco failure
attributable at a glance, at the cost of a second full test invocation of
`internal/ledger`, `internal/segment`, `internal/verify` and `internal/mcp`
on every CI run.

### The self-test is the same shape as the statement floor's, deliberately

`scripts/coverage-floors-selftest.sh` proves `coverage-floors.sh` red-then-green
by building a throwaway module, leaving a floored package's error branches
uncovered, asserting a non-zero exit, covering them, and asserting zero.
`scripts/branch-coverage-selftest.sh` does the same thing against
`branch-coverage.sh`, reusing a fixture shaped like `internal/ledger/chain.go`
(the same three-condition `Append` function used above) plus a second,
always-fully-covered fixture package standing in for `internal/mcp`, so the
assertions can check that the gate blames the *right* surface and leaves the
control surface passing — not merely that something, somewhere, went red. A
gate this project has repeatedly found could not fail (a stripped `data-*`
attribute, a census blaming the harness for a shot never fired, a test
asserting the defect it was meant to catch) is the failure mode this
self-test exists to rule out for the branch floor specifically.

## Alternatives considered

**A per-branch test-ID manifest checked against doc 07.** RM-002 named this
as the other candidate: enumerate every branch in the four surfaces by hand,
assign each a doc 07 test ID, and gate on the manifest being fully claimed by
passing tests. Rejected because it does not scale with the code — every new
`if` in a floored surface requires a human to remember to add a manifest
entry, and a forgotten one is silent (the manifest is complete by
construction, since nobody added the missing line), which is exactly the
false-green shape this project keeps finding elsewhere (#101, RM-035). A
tool that reads the actual conditions in the compiled package cannot be
forgotten in that way: an unlisted new `if` is instrumented and checked
automatically the next time the surface's package is floored.

**Full path coverage.** Rejected as unavailable in Go tooling at any
reasonable cost — no maintained tool computes it, and hand-rolling one is out
of proportion to what IP §2 asks for ("branch coverage", not "path
coverage").

**Running gobco inside the existing `coverage` job.** Rejected for the reason
in Decision above: it would rerun `internal/verify` and `internal/mcp`'s
container-backed suites a second time inside a job whose own run already paid
that cost once, for a tool that cannot consume the first run's profile.

## Consequences

**What becomes possible.** A deliberately untaken branch in any of the five
surfaces fails CI, observed directly:
`scripts/branch-coverage-selftest.sh` red phase reports
`FAIL     hash-chain append    3 one-directional condition(s)` and exits 1;
covering those conditions makes the same run report
`ok       hash-chain append    100% branch` and exit 0.

**What it costs.** A second, slower CI job that recompiles and reruns
`internal/ledger`, `internal/segment`, `internal/verify` and `internal/mcp`'s
tests under gobco's instrumentation — Docker-backed integration suites
included — on every push and pull request. `scripts/coverage-floors.sh`
keeps the statement floor un-duplicated rather than trying to derive branch
information from the same run; the two gates cost two test runs of the
overlapping packages, accepted because neither can produce the other's
number.

**What is still not claimed.** Condition/decision coverage is not path
coverage: a function with several independent conditions can be
condition-complete while specific *combinations* of them are never exercised.
`gobco` cannot see that, and neither can this gate.

**What is now retired.** `scripts/coverage-floors.sh`'s `NOT ENFORCED` block
and its `TODO(#10)` markers are gone; the branch floor section that remains
there points at this gate rather than apologising for its absence.
`COVERAGE_REQUIRE_PACKAGES=1` is set on the statement-floor step so a floored
package that disappears fails rather than silently skipping — `gobco`'s own
`PENDING` reporting in `branch-coverage.sh` already gives the branch floor the
equivalent property for surfaces 4 and 5, which do not exist until RM-037 and
RM-022…025 land.

**Reversal cost.** Dropping gobco means re-opening RM-064: the four IP §2
surfaces would again have a floor stated in the spec and unchecked in CI,
which is the exact gap this ADR closes.

## References

- IP §2 (coverage floors); doc 04 (failure modes: an untested error-return
  path).
- RM-002 (#10) — named `gobco` and the manifest alternative; left the branch
  floor as `NOT ENFORCED`.
- RM-064 (#72) — this issue; its acceptance criteria are what this ADR and
  `scripts/branch-coverage-selftest.sh` satisfy.
- RM-008 (#16), RM-010 (#18), RM-037, RM-022…025 — the four surfaces IP §2
  names.
- `scripts/branch-coverage.sh`, `scripts/branch-coverage-selftest.sh`,
  `scripts/coverage-floors.sh`, `scripts/coverage-floors-selftest.sh`.
- github.com/rillig/gobco, pinned at v1.3.4 in `.github/workflows/ci.yml`.
