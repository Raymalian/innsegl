# ADR-0015: Give SPIRE failure injection a stack per test process, and record the half of SPI-007 that `sign_commit` must finish

- Status: accepted
- Date: 2026-08-29
- Deciders: Mike

## Context

Doc 07 puts SPI-006 and SPI-007 in layer F — failure injection — and IP §6.1
states what they have to establish:

> spire-server down at `register_agent` → `IDENTITY_UNAVAILABLE`, retryable. No
> queuing of identity issuance, no provisional identities, no "register later."
> An agent without identity does no attributed work — and the MCP must make it
> **impossible** to do attributed work anonymously, not merely inconvenient.
>
> spire-agent socket lost mid-run at `get_credential` → `IDENTITY_UNAVAILABLE`;
> any in-flight `sign_commit` aborts before Phase A (6.5).

Three forces shape how those can be written, and none of them is about the
assertions themselves.

**Proving "impossible" means destroying a real dependency.** An error return is
what a *convenient* refusal looks like too, so the substance of SPI-006 is not
the error, it is what SPIRE holds afterwards and what a workload can fetch
afterwards. That means SIGKILLing a real `spire-server` and a real
`spire-agent`, and IP §7 rules out the cheap alternative: SPIRE is used as
released upstream, and doc 01 §2's "a mocked Fulcio proves nothing about I5"
applies to attestation identically.

**The stack these tests destroy is the stack other tests depend on.**
internal/spire's TC-SPI cases run against `deploy/compose/spire.yml`, and
`go test ./...` runs packages concurrently. A kill landing on
`innsegl-spire-server` fails those cases for a reason unrelated to them,
destroys a developer's running stack, and makes a green SPI-006 an artefact of
scheduling.

**SPI-007 names a component that does not exist.** `sign_commit` and the
two-phase protocol are RM-033 (#41), in E5. Its second clause — "in-flight
`sign_commit` aborts before Phase A" — has nothing to be asserted about yet,
while its first clause — `get_credential` fails — is fully provable today and
is the clause that carries I1 and I2.

## Decision

Failure injection runs against the **shipped** compose stack brought up under a
compose project, container names and network names unique to the *test
process*, via the `test/failure/spire-isolated.yml` overlay; nothing in
`test/failure/` ever touches the shared stack, and the overlay changes only the
names and the restart policy.

SPI-007 asserts its `get_credential` half against shipped code and a really
killed agent, and models its Phase A half with a stand-in that is named as a
stand-in in the test; the case is recorded here as **partially discharged**
until RM-033 lands.

## Alternatives considered

**Kill the shared `innsegl-spire-server`.** Loses on three counts, any one
sufficient: internal/spire's cases fail concurrently for an unrelated reason; a
developer's stack is destroyed by running the test suite; and whether SPI-006
passes depends on which package the Go test runner scheduled first, which is
the definition of a test that does not prove its claim.

**One shared failure stack for the whole suite** — the first implementation.
Rejected on measurement, not on principle. Two concurrent `go test ./...`
invocations start two copies of the same test binary, which is routine while
`scripts/coverage-floors.sh` runs beside an ordinary test run. Observed
2026-08-29: a control entry belonging to pid 38913 appeared in pid 35815's
datastore mid-case and failed SPI-006 with

    an entry appeared 18.99s after recovery without anybody asking for one
    ... That is a queued identity.

SPI-006's central assertion is that the *entire* entry set is unchanged across
the outage — which is how a provisional identity under any path or any name is
caught. That assertion is only sound if the datastore has exactly one writer,
so the writer is scoped to the process.

**A stub Workload API, or a fake gRPC error injected at the client.** Proves the
classifier has a `case` arm and nothing about whether SPIRE issues an identity
to a run whose registration failed. It also cannot answer the question SPI-006
is actually asking, which is about a datastore.

**Partition the network instead — kill the socat admin proxy.** Cheaper and
leaves the stack alive, but doc 07 says "spire-server down". With the server
still running, "no queued or provisional identity anywhere" would be a claim
about a *reachable* server, and the interesting failure — something completing
the registration later, server-side — is exactly what would be excluded.

**Serialize the shared stack behind a lock file.** Fixes the concurrency
collision but not the state: a run killed mid-case leaves its entries behind for
the next process to find, and a stale lock hangs CI rather than failing it. A
stack per process has neither problem and needs no lock.

**Defer SPI-007 entirely until RM-033.** Leaves the fail-closed credential path
— I1 and I2 at the workload boundary — untested through the whole of E5, to buy
a completeness that RM-033 will deliver anyway.

**Write `sign_commit` in the test file so the ordering can be asserted.** That
is RM-033's production code, and putting it in a `_test.go` file gives it no
issue, no review and no home. The stand-in is deliberately four lines and
deliberately named as a model of the ordering, not an implementation of it.

## Consequences

**Easier.** Any layer-F case may now destroy its dependency without
coordinating with any other package or with the developer's environment.
`test/failure/` always tears its stack down, so a killed SPIRE is never left
behind as a trap.

**Harder, and paid every run.** A SPIRE stack per test process: roughly 30–40
seconds of bring-up and three extra containers per concurrent `go test ./...`.
The harness is also duplicated — internal/spire's is a `_test.go` file in
package `spire` and cannot be imported — so the two will drift unless changes
to selectors, admin minting or the socat hop are made in both.

**What doc 07 must be read with.** SPI-007 is green on its credential clause
only. What is proved: a workload being served SVIDs stops being served them the
moment the agent dies, every refusal is `IDENTITY_UNAVAILABLE`/retryable, the
fetch fails by returning an error rather than a degraded credential, and no
event — in particular no `commit_intent` — reaches the ledger across the
failure. What is not proved: that `sign_commit` calls `get_credential` before
Phase A. When RM-033 lands, `TestSPI007SpireAgentSocketLostMidRun` must be
extended to drive the real `sign_commit` and assert the same two things of it.
Until then, a green SPI-007 must not be read as the whole row.

**Exit cost.** Deleting the overlay and pointing the harness at the shared
project is a few lines, and re-introduces the scheduling dependence and the
cross-process collision above. Nothing here is irreversible and nothing outside
`test/failure/` depends on it.
