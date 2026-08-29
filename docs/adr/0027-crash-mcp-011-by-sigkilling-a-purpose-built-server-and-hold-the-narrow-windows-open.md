# ADR-0027: Crash MCP-011 by SIGKILLing a purpose-built MCP process, fuzz the kill timing against a measured call, and hold the two narrowest windows open rather than chase them

- Status: accepted
- Date: 2026-08-29
- Deciders: Mike

## Context

IP §6.6 states MCP-011 in two sentences that pull in different directions:

> Every tool call is idempotent via required `idempotency_key`; replaying any
> request after a crash returns the original result, never a second identity,
> second event, or second commit. Test each tool with crash-and-replay.
>
> No in-memory-only state that matters: kill -9 at arbitrary points (**fuzz the
> kill timing** in tests) must never violate I1–I6 after restart +
> reconciliation.

Three constraints follow, and each one has an obvious wrong answer.

**There is nothing to kill.** IP §6.6 is written about a process, and this
repository has no process that serves the five tools of IP §4. `cmd/innsegl` is
the CLI — reaper and WORM canary. Nothing wires `mcp.Server.Handler` onto a
listener; RM-026 and RM-027 both flagged the gap, and RM-028 reached the tools
through `httptest` inside the test binary. `httptest` cannot be `kill -9`ed:
killing the test binary kills the test.

**A hand-picked list of kill points is not fuzzing.** "Fuzz the kill timing" is
the spec's own instruction, and three named points is the version of this test
that finds only the bugs somebody already thought of.

**A crash harness that kills too early passes while proving nothing.** This is
the specific failure mode, and it is invisible: a call that never reached the
server cannot leave a second identity behind, so every assertion holds and the
suite is green. Ten vacuous passes have already been caught on this project;
this test is the easiest one yet to write vacuously.

Two further facts about the code under test shape what the harness can even
observe. ADR-0018 puts the ledger append strictly before the SPIRE entry, so
"the event is on the chain and the identity is not" is a real, reachable state.
ADR-0017 §5 makes a lease takeover run the tool a *second time*, which is where
a second identity would appear if the run id were minted rather than derived —
so that path has to be exercised, not avoided.

## Decision

**MCP-011 SIGKILLs a real OS process that is the shipped MCP server, chooses
its kill timing by seeded stratified sampling over a *measured* call duration,
classifies every landing from durable state read back out of Postgres and
SPIRE, and fails unless the campaign demonstrably reached each named window.**

Six parts.

1. **A throwaway server binary, `test/failure/crashd`.** Everything below its
   flag parsing is the shipped package's own configuration API:
   `mcp.ConfigureRegisterAgent`, `ConfigureGetCredential`, `ConfigureRecordEvent`,
   `ConfigureRetireAgent`, `mcp.New`, `Server.Handler` over `net/http`. It runs
   against a real containerised Postgres and a real containerised SPIRE reached
   over mTLS with an admin SVID. There is no shutdown path in it, deliberately:
   a graceful stop is a code path the scenario never takes. It is `kill -9`ed
   with `syscall.SIGKILL` and the harness reads the wait status back and
   *requires* `Signaled() && Signal() == SIGKILL` — "the test called kill" and
   "the process was killed" are different claims and only the second is
   MCP-011's.

2. **Blind kill timing is stratified over a calibrated window.** Each tool's
   uninterrupted call is timed for real, and kill delays are drawn across
   `[0, 1.25 × that duration)` at nanosecond resolution: the window is cut into
   strata, one delay is drawn uniformly *inside* each, and the strata are
   visited in a seeded random order. Stratifying is what makes a short campaign
   cover the whole call instead of clumping; drawing inside each stratum is
   what keeps the individual points unchosen. Calibrating is what keeps the
   window honest across machines — a hard-coded window is too wide on a fast
   host and too narrow on a slow one, and in both cases the campaign silently
   degenerates to one bucket.

3. **A landing is classified from durable state, never from the delay.** After
   every kill the harness reads the idempotency row (through the shipped
   `Lookup`), the chain (through `ledger.Store`), and SPIRE (through the
   shipped `LookupRun`, which raises `INVARIANT_VIOLATION` rather than picking
   a favourite when a run has more than one entry). The iteration is credited
   with the window those three reads describe — including when an aimed shot
   overshot, which is then simply retried.

4. **The two narrowest windows are held open rather than chased.** Measured,
   not assumed: polling for the SPIRE entry and then signalling overshot 8
   times out of 8. Both narrow windows are one round trip wide, so each gets a
   device.

   * *"the entry exists and the reply is not recorded"* and its `record_event`
     twin: a transaction of the test's own takes `SELECT … FOR UPDATE` on the
     claim's row, which parks the server inside the statement ADR-0023 gave
     that same locking read. That the server is genuinely parked — rather than
     presumed slow — is read out of `pg_stat_activity`, which is the standard
     RM-066 set with `waitForLockWaiters`.
   * *"the reply is recorded and the caller never saw it"*, ADR-0017's
     motivating window: a proxy between caller and server stops forwarding the
     server's bytes from the moment the call is dispatched, and the kill fires
     when a poll shows the row `completed`.

5. **The campaign fails unless it demonstrably did something.** Three gates,
   all of which have been observed firing:
   * every named window must have been reached at least once;
   * the blind half must have landed on *both* sides of "something durable
     happened" — a campaign whose kills all arrived before the tool started
     asserted nothing, and says so in those words;
   * the headline comparison — a replay's bytes against the bytes recorded
     before the crash — must have been made at least once, counted rather than
     assumed.

6. **"Post-reconcile" is asked of the reconciler.** IP §6.6 says invariants
   hold "after restart + reconciliation", and doc 07's MCP-011 repeats it. The
   campaign ends by running RM-019's `spire.Reconciler` over the real SPIRE
   subtree and the real chain and requiring zero drift and zero alerts
   appended, with a positive control on both sides of the comparison — a cycle
   that found nothing because there was nothing to compare agrees for free. The
   two drift kinds a crash could plausibly produce are exactly the ones this
   catches: `spire_entry_unattributed` (an identity the chain has never heard
   of) and `spire_entry_missing` (a run recorded registered with no identity).

7. **`get_credential` is asserted under ADR-0004's rule, not IP §6.6's opening
   clause.** ADR-0004 already decided that this tool takes no key and must not
   be deduplicated: "a repeat call is a legitimate second issuance rather than
   a retry of the first. Each issuance is a distinct auditable fact." So a
   replay here returns a *fresh* credential by design, and what MCP-011 holds
   it to is the rest of the sentence: no second identity, and exactly one
   `credential_issued` per call that reached the append — never one per crash.
   `retire_agent` likewise carries no key and is asserted against IP §4's own
   words: the original timestamp, read back off the chain.

The seed is printed at the head of every run and again with every failure;
`INNSEGL_CRASH_SEED` replays a campaign exactly, `INNSEGL_CRASH_BLIND` sets the
strata count.

## Alternatives considered

- **Drive the tools in-process and "simulate" the crash — cancel a context,
  close a pool, drop the store.** Rejected because it tests the simulation. The
  property IP §6.6 names is that no in-memory state matters, and the only way
  to establish that a Go process holds nothing that matters is to remove the
  process without letting any of its code run. A cancelled context runs
  `defer`s, flushes, and returns errors the tools can classify; `kill -9` does
  none of that. RM-018 set this precedent for SPI-006/007 by killing real
  containers rather than mocking a socket, and RM-023 for MCP-014.

- **Kill a dependency instead — SIGKILL Postgres, or SPIRE, under each tool.**
  Rejected because it is a different test that already exists. SPI-006 and
  SPI-007 kill SPIRE, LED-009 kills Postgres, and RM-028's `LEDGER_UNAVAILABLE`
  row kills the database mid-call. None of them removes the *MCP*, which is the
  process holding the idempotency claim, the one that has already appended and
  not yet minted, and the one IP §6.6 names.

- **Wait for `cmd/innsegl mcp serve` and test that.** Rejected on sequencing,
  not on merit: the entry point is unwritten, MCP-011 is in this wave, and a
  test that waits for another issue is a test that does not exist. `crashd`
  imports only exported seams, so when the real entry point lands the harness
  points at it by changing which binary it builds. That is stated here so the
  swap is a known follow-up rather than a discovery.

- **Pick three kill points by hand: before the append, between append and
  SPIRE, after the reply.** Rejected by the spec's own wording — "fuzz the kill
  timing" — and by what the campaign actually found. The blind half landed in
  *"run_retired on the chain, entry deleted, reply not delivered"* and in
  *"claimed, nothing durable yet"*, neither of which is on the obvious list of
  three, and the second of which only exists because ADR-0017 writes the claim
  before the tool body.

- **Use a fixed kill-delay range in milliseconds.** Rejected: `register_agent`
  measured 67 ms on the development machine and `record_event` 13 ms, a factor
  of five apart, and both move with SPIRE's and Postgres's latency. One
  hard-coded range would make one tool's campaign all-early and another's
  all-late, and neither would announce that it had.

- **Retry the narrow windows harder instead of holding them open.** Rejected on
  measurement: the poll-and-signal loop overshot 8 out of 8 for
  *"entry created, reply not recorded"*. The window is one Postgres round trip
  and the observation is one Postgres round trip, so more attempts buy a
  coin-flip at best. A hard gate on a coin-flip is a flaky test; a soft gate on
  one is a vacuous test.

- **Assert only per-iteration and skip the census.** Rejected because it is
  exactly the vacuous pass this issue was warned about. Every per-iteration
  assertion in this file holds trivially when the kill lands before the tool
  starts, and nothing in the per-iteration path can tell that it did. The
  census is the only place the campaign's own adequacy is checked, and it was
  confirmed to fire: forcing every blind delay to zero produces
  *"every blind kill landed before the tool did anything durable (12 of them).
  A call that never started cannot leave a second identity, so this campaign
  asserted nothing."*

- **Trust that the byte-identity check is measuring the idempotency store.**
  Rejected; it is demonstrated instead.
  `TestMCP011PruningTheRecordedReplyReopensTheKeyAndStillMintsOneIdentity`
  deletes the completed row — which ADR-0017 §7 explicitly permits, and whose
  effect its Consequences state — and shows the reply changing while the run
  id, the identity, the single `run_registered` and the single SPIRE entry all
  stay put. A check that could not change its answer is not a check.

- **Let the campaign run with the shipped sixty-second idempotency lease.**
  Rejected as unaffordable and, more importantly, as the weaker test. A replay
  of a claim whose owner was SIGKILLed waits out the remainder of the lease
  before taking it over, so the default would cost a minute per crash-mid-claim
  iteration. `crashd` runs with 750 ms, which makes ADR-0017 §5's *takeover* —
  the second execution, the path where a minted run id would produce a second
  identity — the ordinary case in this harness rather than the rare one.

## Consequences

- **What a SIGKILL of `crashd` does and does not prove, stated rather than
  implied.** It proves that the shipped tool code, the shipped transport, the
  shipped idempotency store and a real SPIRE together survive the operating
  system removing the server process at points spread across the whole call:
  nothing the process held in memory was needed, and a replay converges. It
  does **not** prove anything about a host or container dying (Postgres and
  SPIRE keep running, so page-cache and fsync behaviour under machine loss is
  untested), about more than one replica (the campaign runs one at a time),
  about an orchestrator's restart policy, or about the MCP holding its admin
  credential as an attested workload rather than as PEM files. The first of
  those is doc 05's territory and the last is blocked on there being an
  `innsegl-mcp` workload at all.

- **One place substitutes, and it is named.** In the *"reply recorded, caller
  never saw it"* window the caller's non-delivery is produced by the harness
  cutting the response, not by the crash destroying it; the process is then
  really killed. The durable state at the instant of the kill — completed row,
  event on the chain, entry in SPIRE — is identical to the real thing, and that
  state is the whole of what MCP-011 asserts on. Nothing about the network path
  is demonstrated by that device.

- **"Never a second commit" is unproven and stays unproven.** `sign_commit` is
  RM-033 (#41). The test measures its absence — `mcp.New().MissingTools()` —
  and *fails* rather than skips the day it is bound, so the deferral cannot
  outlive the reason for it.

- **The reconciler is now exercised against state a crash produced**, not only
  against state a test planted. RM-019's own cases plant drift; this one
  produces none and proves it, over a datastore and a chain that took nineteen
  SIGKILLs to build.

- **`crashd` carries a second copy of the run directory.** `internal/mcp`
  declares `CredentialRuns` and ships no implementation; RM-028 wrote one for
  the contract suite and it is a `_test.go` file in another package. This is
  the second copy, and it will be the third the next time somebody needs one.
  A shipped reader belongs with the MCP entry point.

- **A campaign leaves live SPIRE entries behind.** The register, `record_event`
  and `get_credential` runs are never retired, because retiring them would
  destroy the state the datastore-wide census asserts on. They live in the
  per-process stack ADR-0022 gives this package and die with it.

- **Cost.** The default campaign is ten blind strata per tool plus the targeted
  shots: 35 s without `-race`, and the whole `test/failure` package runs in
  about two minutes with it. `INNSEGL_CRASH_BLIND` scales it in either
  direction without changing what is asserted.

- **Exit cost.** Low. `test/failure/crashd` and two `_test.go` files, importing
  only exported API; `git diff internal/` is empty for this change. Deleting
  them loses MCP-011 and nothing else. Repointing the harness at a real
  `cmd/innsegl mcp serve` when one exists is a change to which binary is built
  and to nothing that is asserted.
