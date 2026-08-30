# ADR-0030: Ship the MCP entry point, read a run out of the chain in its own package, and make the earliest `run_retired` the answer

- Status: accepted
- Date: 2026-08-30
- Deciders: Mike

## Context

Four of IP §4's five tools existed, each tested against a real Postgres and a
real SPIRE, and nothing in the repository could run them.

```
$ innsegl serve
innsegl serve: not implemented
```

`internal/mcp` publishes four installation seams — `ConfigureRegisterAgent`,
`ConfigureGetCredential`, `ConfigureRecordEvent`, `ConfigureRetireAgent` — and
the only caller of any of them was `test/failure/crashd`, a binary RM-029 wrote
so that MCP-011 had a process to SIGKILL. Its own header said so: "this file is
the missing entry point, built for one purpose and shipped nowhere". RM-026,
RM-027 and RM-029 each flagged the gap independently.

Two things were missing, not one.

**There was no server.** No configuration, no dependency construction, no
listener, no lifecycle, and none of RM-026's `/healthz` and `/readyz`.

**There was no shipped run directory.** Three of the four tools begin by
resolving `run_id` through `mcp.CredentialRuns`. RM-023 declared the interface
and deliberately shipped no implementation of it, writing that "the run
directory is shared with the other four tools, and a second definition of what
is a run is a second thing that can disagree about retirement". There was no
*first* definition either: every implementation was a test double or `crashd`'s
private copy, so `get_credential`, `record_event` and `retire_agent` could not
be wired in a deployment at all. RM-028 recorded exactly that.

Two contracts were also stated and enforced nowhere:

- **ADR-0020 §5.** `retire_agent`'s idempotency is a check-then-append, because
  ADR-0004 forbids `run_retired` an `idempotency_key`. Two genuinely concurrent
  *first* retirements of one run can therefore both find no record and both
  append, and I4 makes both permanent. What keeps that survivable is that the
  directory answers with the **earliest**: "both callers are told the same
  instant". RM-025 implemented that rule in a test double, which is a statement
  about the double.
- **ADR-0025.** "`RateLimitRegisterAgent` must be called before
  `ConfigureRegisterAgent` or the tool is unmetered." Both orders compile and
  both produce a working `register_agent`; the wrong one ships AB-07 recorded as
  mitigated and not mitigated, silently.

## Decision

### 1. The run directory is its own package, `internal/rundir`

It is the only component that must know both halves, and neither half may know
it.

- **Not `internal/ledger`.** That package's own documentation draws the line:
  "The chain is type-agnostic. It does not know what an event means: no
  event_type enum, no per-type required members." This reader is nothing but
  event types and per-type members. It would also have to import
  `internal/mcp`, which already imports `internal/ledger` — an import cycle, not
  a matter of taste.
- **Not `internal/mcp`.** IP §1 makes that package the transport, the tool
  surface and the admin credential. A Postgres query per run inside it would put
  a storage layout in the component whose entire contract is the wire, and the
  package is a closed, protected surface.

So a third package, above both, imported by the entry point that joins them.

### 2. The directory believes nothing it did not read on the chain

`agent_type` and `task_ref` are **read from the `run_registered` event**, not
parsed back out of `spiffe_id`. `crashd`'s copy split the SPIFFE ID, and that
made `mcp.credentialRunIdentity` — which requires `spiffe_id` to end in
`/agent/{agent_type}/{task_id}/{run_id}` — a check that could not fail, because
the three components it compares had been derived from the string it compares
them to. Reading them independently makes the check a real one: two recorded
members must agree with a third.

Every member the reader cannot read is `INVARIANT_VIOLATION` scoped to the run,
never a zero value. Three tools mint, append and delete against this answer.

### 3. `internal/ledger` gains exactly one method: `EventsForRun`

Run-scoped, in chain order, over the index migration 0001 already carries for
this question (`events_run_id_idx (run_id, chain_position) WHERE run_id IS NOT
NULL`). Without it a directory answers every tool call by reading the whole
chain and filtering in Go — O(chain) per call on a table doc 05 §4 sizes at
20 GB a year. An empty run id is refused rather than matched, because `run_id`
is nullable and the events that carry none must never be selected by an empty
string.

ADR-0018 and ADR-0020 both flagged this missing read. It also unblocks the two
things ADR-0020 listed as needing it — the reaper skipping an already-retired
run, and the pruned-key resurrection case — neither of which is done here.

### 4. The earliest `run_retired` is the retirement, by **instant**

Not "the first one in chain order". The two agree on every chain a single
ledger writes, because `ts` is assigned inside the serialized append — which is
precisely why relying on the agreement would be untested code the day it stopped
holding: two writers, a restored backup, a clock stepped backwards inside
IP §6.8's bound.

The rule is proved twice. `TestTheEarliestRunRetiredWinsWhenSeveralArePresent`
supplies four `run_retired` records with the earliest instant **last** in chain
order, which is the only shape that separates "earliest" from "first" and which
a reader that took the first would fail.
`TestTheEarliestRunRetiredWinsOnARealChain` puts four real `run_retired` events
on a real Postgres chain, spaced so the ledger's millisecond `ts` separates
them, with a second run retired in between so that a reader whose scoping is
wrong reports the wrong instant. And
`TestServeAnswersARealMCPCallEndToEnd` retires one run twice through the
**served** tool and requires the same instant back.

### 5. `innsegl serve` is configured by flags that all fall back to environment
variables

RM-011's canary set the precedent and the reaper follows it: a scheduled
container is configured entirely by environment, and the ledger DSN — which
carries a password — never goes on a command line the process table can read.
The four names the reaper already defines (`INNSEGL_LEDGER_DSN`,
`INNSEGL_SPIRE_ADDRESS`, `INNSEGL_TRUST_DOMAIN`, `INNSEGL_SPIRE_SERVER_ID`,
`INNSEGL_WORKLOAD_API_ADDRESS`, `INNSEGL_SPIRE_TIMEOUT`) are **reused**, not
spelled a second way: two names for one setting is a deployment that can set the
wrong one.

Nothing has a default that could be mistaken for a decision:

- **`-fulcio-url` and `-rekor-url` are required.** ADR-0010 makes the
  self-hosted pair the shipped default, so there is no address to fall back to,
  and a readiness probe pointed at somebody else's log reports green about the
  wrong system.
- **`-parent-id` is required.** An entry with no reachable parent is an entry no
  workload can ever match.
- **`-listen` and `-health-listen` default to loopback**, not `0.0.0.0`. This
  process holds SPIRE admin (IP §1); a default that published it on every
  interface would make an operator's omission the exposure.

### 6. Health is on a second listener

`/healthz` and `/readyz` bind separately from the MCP transport. The readiness
report names which dependency is failing and why, which is operational
information; the port that carries it is the orchestrator's, not the fleet's.
Separating them means a deployment can expose one without exposing the other,
which is the same segmentation doc 05 §1 asks for one layer down.

### 7. The rate limit is ON by default in the shipped entry point

`-register-rate-calls` defaults to `DefaultRegisterAgentRateLimitCalls` (60) over
`DefaultRegisterAgentRateLimitWindow` (a minute), and `0` serves `register_agent`
unmetered. `RateLimitRegisterAgent` wraps the configuration **before**
`ConfigureRegisterAgent`, which is the only place that order can be got wrong.

Turning the control off is never silent: `-register-rate-calls=0` writes a
warning naming AB-07 every time the process starts.

**This raises an exit cost ADR-0025 named.** That ADR's consequences say the
cost is "low while the limit is opt-in and off by default in the shipped entry
point", and it is now on by default, so agents in the field will be written
against a `register_agent` that can refuse with `IDENTITY_UNAVAILABLE` for a
reason no dependency outage explains. It is on anyway, because the alternative
is shipping the entry point with the control it was built for switched off, and
because #89 states the acceptance criterion as "the served `register_agent` is
rate-limited". **Flagged for the human**: ADR-0025's follow-up 1 — whether
IP §4's vocabulary should gain a twelfth class, or its error object a
`retry_after` — is now a live cost rather than a hypothetical one, because
callers meet the refusal in the shipped default.

### 8. Least privilege on the database role is MEASURED, and warns by default

doc 05 §1 requires the MCP to run under a database role that can append and not
delete. At start-up `serve` asks Postgres what its own role may actually do to
`innsegl.events` (`has_table_privilege`), rather than trusting a deployment
manifest, which is not what enforces it: migration 0001 revokes `UPDATE`,
`DELETE` and `TRUNCATE` from `PUBLIC` and the append-only trigger refuses them,
but a trigger is disableable by a superuser and a revoke does not bind the table
owner.

- No `INSERT` is always fatal. Every tool that acts appends first (I3); a
  replica that could not write would fail every call while looking healthy.
- `UPDATE`, `DELETE` or `TRUNCATE` is a doc 05 §1 **finding**, not an outage. It
  is reported loudly at every start, and refused when
  `-require-append-only-role` is set.

The default warns rather than refuses because the compose stack does not yet
create the role — it ships with RM-030 — and a start-up refusal on a
configuration defect would take a deployment down for something no outage
caused. A deployment that has the role sets the flag and gets the refusal.

### 9. The admin credential has two sources and the second is never implicit

The Workload API is the default and what a deployment uses: doc 05 §1 runs
`innsegl-mcp` as an attested container, so holding the admin credential means
*being* the workload SPIRE attests. Three PEM files (`-svid`, `-key`,
`-bundle`, all or none) are the other, for the case where the MCP is not yet an
attested workload — bootstrapping a trust domain, and MCP-011's campaign, which
runs this binary on the host beside a containerised SPIRE whose Workload API
socket is inside the container. `internal/mcp`'s own `get_credential` tests and
`test/failure`'s harness mint the admin SVID the same way for the same reason.

### 10. `crashd` is deleted and MCP-011 kills the shipped binary

RM-029 predicted the swap would be "a change to which binary is built and
nothing that is asserted", and it was: `crashd` called the same exported seams
over the same real dependencies. `test/failure/crashharness_test.go` now builds
`./cmd/innsegl` and starts `innsegl serve`. The campaign's windows are now the
deployment's windows.

### 11. Nothing depends on orderly shutdown for correctness

IP §6.6 removes this process with SIGKILL at arbitrary points and requires
I1–I6 to hold with none of the shutdown having run; that is the ledger's append
rule, the run id's derivation and the idempotency store, and MCP-011 proves it.
The `SIGINT`/`SIGTERM` handler and the bounded `http.Server.Shutdown` exist for
the ordinary stop — an orchestrator rolling a replica — and for nothing else.

## Alternatives considered

- **Put the run directory in `internal/ledger`.** Rejected: import cycle
  (`internal/mcp` → `internal/ledger`), and it breaks that package's stated
  type-agnosticism.
- **Put it in `internal/mcp` beside the interface it satisfies.** Rejected: the
  package is off limits to this issue by construction, and on the merits it
  would put a SQL layout inside the component whose contract is the wire.
- **Have the directory scan the whole chain, as `crashd` did.** Rejected: it is
  the read every tool call makes, on a table that only grows. The index for the
  scoped read already existed.
- **Derive `agent_type` and `task_ref` by splitting `spiffe_id`.** Rejected: it
  makes `credentialRunIdentity` unfalsifiable. See 2.
- **Take "the first `run_retired` in chain order" as the retirement.** Rejected:
  ADR-0020 §5 says earliest, and chain order is only incidentally the same thing.
- **Refuse to start on an over-privileged database role.** Rejected as the
  default, offered as a flag. See 8.
- **Serve health on the MCP port.** Rejected: it publishes per-dependency
  operational detail to whoever can reach the tool surface.
- **Default `-fulcio-url`/`-rekor-url` to public Sigstore.** Rejected: ADR-0010
  makes the self-hosted pair the shipped default and `mcp.NewSigstoreEndpoints`
  already refuses an unset address for the same reason. A default here would
  silently become the project's answer to "which log attests your agents".
- **Keep `crashd` beside the real binary.** Rejected: a second entry point is a
  second thing that can drift from the one that ships, and the campaign's whole
  value is that the process it kills is the process a deployment runs.
- **Ship the limit off by default, as ADR-0025's consequences assumed.**
  Rejected. See 7, including the exit cost that decision incurs.

## Consequences

- **`internal/rundir` is a new shipped package** and the only implementation of
  `mcp.CredentialRuns` outside tests. A second one would reintroduce exactly
  what RM-023 warned about.
- **`internal/ledger` has one new exported name**, `EventsForRun`. It reads as a
  query, so `TestNoMutatingSurface` is unaffected.
- **`serve` opens a second pgx pool** to the chain's database, for the
  idempotency store, because `*ledger.Store` keeps its pool unexported and a
  component that closed a pool it did not create would take the ledger down with
  it. Two pools to one database is the cost; it is the same shape `crashd` had.
- **`get_credential`'s minter dials a second gRPC connection** to SPIRE, with
  the *same* credential and the same server authorization — not a second
  credential. `*spire.Client` offers no accessor for its own connection.
  ADR-0011's segmentation and ADR-0012's policy apply to both identically.
- **Two `run_retired` events for one run stay possible and stay permanent**
  (ADR-0020 §5). What is new is that a shipped reader now makes them agree.
- **Flagged for the human, not resolved here.** `run_expired` does **not** set
  `RetiredAt`. `mcp.CredentialRun.RetiredAt` is documented as "the instant
  `run_retired` was appended", and this reader honours that spelling exactly. A
  run the reaper expired therefore reads as *live* to the directory, and is
  refused one layer down by `get_credential`'s SPIRE gate with `RUN_NOT_FOUND`
  rather than `RUN_ALREADY_RETIRED`. Whether an expired run should be reported
  as retired is a question about IP §4's vocabulary and doc 02 §3's two terminal
  events; it is not an inference an implementing agent should make, and no spec
  document was edited to settle it.
- **Flagged for the human, not resolved here.** Doc 07 has no test-catalog ID
  for the entry point. MCP-011, MCP-012 and MCP-013 all now run against the
  shipped binary, but "the server starts, advertises the surface and answers a
  real call end to end" is unnumbered, and so is "the served `register_agent` is
  metered". `TestServeAnswersARealMCPCallEndToEnd` and
  `TestTheServedRegisterAgentIsMetered` are the two, and they are the fourth and
  fifth unnumbered cases flagged since ADR-0018 proposed MCP-017.
- **Flagged for the human, not resolved here.** `-require-append-only-role`
  should become the default once RM-030's compose stack creates the role, and
  doc 05 §1's "least-privilege shape is first proven, not first ignored" then
  has something enforcing it. Until then the shipped default reports rather than
  refuses, and this ADR is the record of that gap.
- **Exit cost.** Low for the run directory: it is an implementation of an
  interface that already existed, and replacing it replaces one file. Low for
  the entry point's structure. Moderate for the configuration surface, which is
  operator-visible the moment anything is deployed against it — flag names and
  environment variable names are what a manifest is written to. Highest for
  decision 7, which is a behaviour every caller of `register_agent` will be
  written against; see the flag there.
