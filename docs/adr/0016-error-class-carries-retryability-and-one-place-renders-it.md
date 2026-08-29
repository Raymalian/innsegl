# ADR-0016: Make `retryable` a property of the error class, narrowable but never widenable, and render IP §4's error in exactly one place

- Status: accepted
- Date: 2026-08-29
- Deciders: Mike

## Context

IP §4 gives the MCP's error contract in two sentences:

> All tools return structured errors: `{error_class, message, retryable: bool,
> run_id?}`. Error classes: `ATTESTATION_FAILED`, `IDENTITY_UNAVAILABLE`,
> `CREDENTIAL_EXPIRED`, `AUDIENCE_MISMATCH`, `LEDGER_UNAVAILABLE`,
> `SIGNING_UNAVAILABLE`, `TRANSPARENCY_UNAVAILABLE`, `RUN_NOT_FOUND`,
> `RUN_ALREADY_RETIRED`, `DUPLICATE_REQUEST`, `INVARIANT_VIOLATION`.

It does not say what `retryable` is for each class. IP §6 says it for three:

- §6.1 "spire-server down at `register_agent` → `IDENTITY_UNAVAILABLE`, retryable"
- §6.1 "Attestation selector mismatch → `ATTESTATION_FAILED`, not retryable"
- §6.3 "Fulcio down → `SIGNING_UNAVAILABLE`, retryable"

The other **eight are unstated**. They are not a detail: `retryable` is the
field an agent's retry loop reads, and getting it wrong in either direction is
a defect that only shows up in production — a `true` on a refusal spins an
agent forever against an answer that will not change, and a `false` on a
dependency outage turns a thirty-second Postgres restart into a failed run.

Three further forces:

- **A scheme already exists one layer down.** RM-015 built
  `internal/spire.Error`, which carries `Class`, `Retryable`, `RunID` and a
  cause, and it deliberately keeps `Retryable` as a field rather than deriving
  it, because IP §6.1 makes `IDENTITY_UNAVAILABLE` retryable when SPIRE is
  unreachable and not retryable when SPIRE answered something the client cannot
  act on. A second, independent scheme in `internal/mcp` would make the wire
  depend on which layer happened to fail.
- **The vocabulary is protected.** VERSIONING.md surface 4 is "the MCP tool
  names and their error-class vocabulary"; `scripts/protected-surfaces.sh`
  enforces the eleven spellings. Before this change the shipped source spelled
  four of the eleven (the subset `internal/spire` can raise) and the gate
  reported the surface as legitimately partial.
- **The transport has to exist before the tools do.** E4 wave 2 puts four tools
  in four files written by four agents at once. Whatever registers a tool must
  not be a file all four of them edit.

Invariants in play: I3 (no action without a record) is why a ledger outage must
fail closed rather than be papered over; E8 and IP §1 are why the transport
must publish no surface beyond the five tools — the MCP is the only holder of
the SPIRE admin credential, and a resource or prompt endpoint would be a second
door to read state through.

## Decision

**1. `retryable` is a property of the class, not of the call.** A class is
retryable exactly when it names a **dependency outage** — a condition outside
the request that may clear on its own without the caller changing anything.
Every other class describes the request itself or durable state, and repeating
the request cannot change either.

| class | `retryable` | source |
|---|---|---|
| `ATTESTATION_FAILED` | false | **stated** — IP §6.1 |
| `IDENTITY_UNAVAILABLE` | true | **stated** — IP §6.1 |
| `CREDENTIAL_EXPIRED` | false | derived — the credential is part of the request; IP §6.2 forbids extending a TTL "to help", so the caller needs a *new* credential, which is a different request |
| `AUDIENCE_MISMATCH` | false | derived — the allowlist does not change between two identical calls |
| `LEDGER_UNAVAILABLE` | true | derived — IP §6.4, Postgres down is a dependency outage |
| `SIGNING_UNAVAILABLE` | true | **stated** — IP §6.3 |
| `TRANSPARENCY_UNAVAILABLE` | true | derived — IP §6.3, Rekor down is the same shape as Fulcio down |
| `RUN_NOT_FOUND` | false | derived — an absent run does not appear by being asked for twice |
| `RUN_ALREADY_RETIRED` | false | derived — IP §6.2, retirement is immediate and terminal, and I4 forbids un-retiring |
| `DUPLICATE_REQUEST` | false | derived — the second answer to a duplicate is the same duplicate (ADR-0004) |
| `INVARIANT_VIOLATION` | false | derived — IP §6.2 makes it alert-level; a retry repeats the violation |

**2. A layer closer to the failure may NARROW `retryable`, never widen it.**
`internal/spire`'s per-error flag is honoured by ANDing it with the class
default. So a SPIRE failure the client cannot act on stays non-retryable even
under `IDENTITY_UNAVAILABLE`, and no layer can mark a refusal retryable.

**3. One rendering point.** `mcp.Classify` turns any error into `*mcp.Error`,
and `(*mcp.Error).MarshalJSON` is the only code that writes IP §4's object. The
vocabulary is closed at that boundary: a class outside the eleven is reported
as `INVARIANT_VIOLATION` naming the rejected value, and an error nothing
classified is `INVARIANT_VIOLATION` too — IP §4 has no "internal error" class,
and an unclassified failure inside the MCP is a defect, which is alert-level.
`run_id` is omitted when there is no run rather than emitted empty, because
doc 02 §1 makes absent and empty distinct states and that rule does not stop at
the ledger.

Carriers other than `*mcp.Error` and `*spire.Error` join the taxonomy by
implementing `mcp.Classified` — one method returning class, run and the
retryable flag that layer measured — rather than by rendering IP §4's object
themselves.

**4. Transport.** A remote MCP server over the Streamable HTTP transport of the
official `github.com/modelcontextprotocol/go-sdk`, registering as `innsegl`,
publishing a tools capability and nothing else, with `net/http`'s
`CrossOriginProtection` applied so a cross-site browser POST is refused by the
transport rather than executed.

**5. Registration seam.** Each tool owns one file and registers itself from
that file's `init` with `RegisterTool(name, binder)`; `New` runs the binders in
IP §4 order. Registering a name outside the five, a nil binder, or a second
binder for one name panics at init. No file is shared between tool authors.

## Alternatives considered

- **Treat `retryable` as a free per-call boolean, since IP §4 writes it as a
  value rather than a rule.** Rejected: two calls that fail the same way would
  be free to disagree, and a caller cannot build a retry policy on a flag whose
  meaning varies by call site. The three values IP §6 does state are stated per
  *class*, not per call, which is the reading this ADR generalises.
- **Derive retryability from the spelling — the four classes whose names end in
  `_UNAVAILABLE`.** It happens to produce this exact table, and it was rejected
  precisely because it does: the agreement is a coincidence of naming, and a
  twelfth class would silently inherit a retry policy from how it was spelled
  rather than from what it means. The table is written out instead, one row per
  class, so a future class has to be decided rather than parsed.
- **`CREDENTIAL_EXPIRED` retryable, on the reading that IP §6.2's "re-fetches
  transparently" means a retry of `sign_commit` succeeds.** Rejected: it makes
  the flag true for a caller that retries the tool and false for a caller that
  re-presents the same dead credential, i.e. it depends on something the wire
  does not carry. The fail-closed reading is the one that cannot produce a hot
  loop against an expired credential, and IP §6.2's "never extend TTLs to
  'help'" is the same posture.
- **Let each layer render IP §4's object itself.** Rejected: the wire shape
  would then have as many implementations as there are failure sources, and
  doc 08 §3 protects that shape. It is also how a fifth field — a token, a
  cause chain, a stack — reaches a caller.
- **A second error type in `internal/mcp` unrelated to `internal/spire`'s.**
  Rejected for the reason the Context gives: one vocabulary, mapped by string
  identity, so a rename in either package fails the mapping loudly instead of
  inventing a name.
- **Hand-roll the JSON-RPC-over-HTTP MCP transport.** Rejected: it is
  reimplementing a protocol this project does not own, and IP §7's posture for
  SPIRE and Sigstore — "used as released upstream components … configuration
  and orchestration only" — is the right one for MCP as well. The cost is two
  new module dependencies, which is the smaller risk.
- **Stdio transport.** Rejected: IP §1 says "remote MCP server (HTTP
  transport)", and stdio cannot serve the deployment topology of doc 05.
- **One `tools.go` listing the five binders, merged by the supervisor.**
  Rejected: E4 wave 2 runs four agents against `internal/mcp/` at once, and a
  shared list is exactly the file they would all edit. Self-registration keyed
  by the five protected names gives the same determinism — `New` iterates
  IP §4's order, not Go's initialisation order — with no shared file.
- **Stop and ask the human about the eight unstated flags before writing any
  code.** Seriously considered, because the project rule is that a spec
  ambiguity is a question and not permission. Rejected on the ADR-0004
  precedent: that ADR resolved a doc 02 / IP §4 conflict in the ADR and
  recorded the doc edit as a human-only follow-up, because the alternative was
  freezing a protected surface by not deciding. The same applies here, and the
  follow-up below is written the same way. The flags are decided in this ADR
  and nowhere else; doc 01 is not edited.

## Consequences

- **`internal/mcp` now exists, so its gates now apply.** It carries a 90% line
  floor in `scripts/coverage-floors.sh` that was SKIPped while the package was
  absent, and it is listed as a branch-coverage surface in
  `scripts/branch-coverage.sh` that was PENDING. Both start being measured with
  this change.
- **The protected-surfaces gate now finds all eleven error classes** where it
  found four. `error-class` is not in that script's `STRICT_KINDS`, so the
  partial state was allowed; from here the set is complete and a rename fails
  the build with no tag needed.
- **Two new module dependencies**: `github.com/modelcontextprotocol/go-sdk` and
  `github.com/google/jsonschema-go` (the latter is how a tool's result schema
  is derived from its Go type, so MCP-001..005's "documented result shape" is
  generated rather than written twice).
- **RM-021's `*IdempotencyError` has to join the taxonomy.** It is being
  written in parallel and carries its own `Class`/`Retryable` fields; it must
  implement `mcp.Classified` so `Classify` renders it, or `Classify` must grow
  a case for it. Until then a store failure surfaces as `INVARIANT_VIOLATION` —
  loud and wrong rather than quiet and wrong, which is the intended failure
  mode, but it is a supervisor merge action, not a state to ship.
- **Required follow-up, for the human only** (`docs/` outside `docs/adr/` is
  not edited by implementing agents):
  1. Doc 07 has no test-catalog ID for the transport itself. MCP-006 covers the
     error-class matrix and is what this change's `TestMCP006…` asserts, but
     "the server registers under the name `innsegl` over HTTP transport and
     advertises the five tools and nothing else" has no ID. Proposed:
     **MCP-015** (C) server identity and tool surface over the HTTP transport,
     and **MCP-016** (C) no capability beyond tools — proving IP §1/E8 have no
     second door.
  2. IP §4 should state `retryable` per class, so this ADR stops being the
     operative reading for eight of the eleven.
- **Exit cost.** The eleven spellings are a protected surface already. This ADR
  additionally makes the *flags* part of the contract a caller's retry policy is
  built on: flipping one after the first tag is a behavioural break for every
  agent in the field, and should be treated as major-release work with the
  migration note doc 08 §3 requires, even though VERSIONING.md's surface 4
  names the vocabulary rather than the flags. Before the first tag the cost is
  a table edit and a test run.
