# ADR-0085: Capture additional wire formats through adapters in the one gateway

- Status: proposed
- Date: 2026-10-21
- Deciders: the operator

## Context

ADR-0057 records activity from model traffic, corroborated by workspace
snapshots and harness telemetry. The current implementation recognises
Claude Code and interprets Anthropic Messages requests and replies. A
Responses-speaking harness cannot use that recording path merely by pointing
its model endpoint at the gateway: request identification, tool calls,
results, session lifecycle and streaming events have different shapes.

The existing identity engine, ledger and signing service should not acquire
a second implementation for a second wire format. I1 and I2 require the
existing attested identity and signing boundaries. I3 requires explicit
recording gaps rather than silent omissions; I4 and I5 prohibit rewriting
evidence or presenting a guessed association as verified attribution. I6
continues to govern commit author identity and trailers.

Code-mode traffic can expose an outer script rather than each command it
executes. Structured nested tool hooks are documented, but their identifiers
cannot be assumed to match wire call identifiers. The current commit drift
reconciler examines structured Bash commands; it does not establish that an
unattributed commit inside an outer script will be detected. A hook's claim
alone cannot replace ADR-0059's independent check against relayed traffic.

Incremental requests and WebSocket continuation also mean a request need
not repeat its full conversation. Supporting a frame relay is not the same
as interpreting complete application messages or recovering their context.
The journal's signed-chain mechanism is reusable, but session identification,
retained-header policy and format-aware replay require integration work.

## Decision

Propose interpreting each supported wire format through an adapter in the
existing gateway, sharing its guards, identity lifecycle, journal and ledger,
and delivering Responses capture before independently verified command
attribution and signing. This proposal supersedes no accepted ADR and does
not select the unresolved routing, transport or degraded-capture policies.

The proposed adapter contract and acceptance boundaries are:

1. **Select one adapter from a recognised route and harness shape.** It
   supplies request facts, tool calls and results, assistant text and
   lifecycle signals. A body that resembles another format must not select
   that format. Bind each permitted route to an operator-configured upstream;
   no client-supplied destination is accepted. Method, path boundaries,
   redirects and replay must preserve that restriction.
2. **Forward original bytes and interpret a bounded copy.** Compression,
   malformed input, truncation and missing context have explicit limits and
   recording states. Unknown facts remain unknown; a parse failure cannot
   yield an empty record labelled complete or create signing authority.
3. **Keep evidence sources distinguishable.** Outer wire calls, nested
   executions, hooks, telemetry and snapshots are separate observations.
   Correlate only associations established by version-specific fixtures and
   independent evidence. A missing or failed witness is visible, not inferred
   from the presence of another witness.
4. **Keep signing independently gated.** Preserve ADR-0059's verified
   pending-call, run, scope and time-window checks. Do not authorise a commit
   from a hook-only claim, a script substring or a guessed call-id mapping.
   A capture-only milestone must not claim complete command attribution or
   signed-commit support. Any alternative authorisation model requires a
   separate superseding decision before implementation.
5. **Preserve availability and journal contracts.** ADR-0068's outage
   fallback, bounded signed journal, idempotent import and fail-closed signing
   remain. Its explicit treatment of core 4xx refusals remains too; this ADR
   does not turn identity, scope or revocation refusals into pass-through.
   Credential-free gap evidence and replay need an explicit contract before
   enabling an unreadable or unsupported-format path.
6. **Separate forwarding credentials from retained evidence.** Send each
   provider credential only to its intended upstream. Do not retain provider
   credentials, account identifiers or gateway credentials in journal headers,
   imported exchange bodies, diagnostics or downstream replies. Consume and
   remove gateway-only credentials before forwarding upstream. Preserve old
   signed journal bytes rather than rewriting entries to add a format.
7. **Declare supported versions and transports.** Repeated events, retries,
   interruption and restarts must not duplicate or reassign records. An
   HTTP-only first release is conditional on measured feature parity and
   reliable transport selection. Otherwise WebSocket interpretation,
   reassembly and response-chain recovery are prerequisites to claiming
   support, not an unobserved forwarding path.

Before acceptance, the operator must settle these choices using measurements
of the supported harness versions:

- Base-URL or HTTPS-proxy routing for Codex, including model discovery,
  credential renewal and required feature parity. ADR-0069 remains unchanged
  for Claude Code; a Codex-specific base URL does not reverse that decision.
- Whether setup enables telemetry by default and which partial-evidence
  configurations are supported and visibly labelled.
- Whether the initial scope is Responses/Codex only, with Chat Completions
  deferred until its session identity policy is established.
- The independently supported association between nested execution and wire
  calls, and the exact limitations if that association cannot be established.
- Whether both ChatGPT-login and API-key modes pass separate acceptance
  checks initially, and whether HTTP-only operation meets required parity.
- Which unsupported-shape or decoding failures may continue with durable gap
  evidence. Changing ADR-0068's core-refusal policy requires explicitly
  superseding its affected decision, not an implicit availability exception.

## Alternatives considered

- **A separate gateway implementation per format.** Duplicates guard ordering,
  lifecycle, journal import and future fixes. Adapters let both formats share
  those contracts while isolating interpretation.
- **Change only a base URL or proxy setting.** Routes bytes but does not make
  the current recogniser or interpreter understand them; successful inference
  is not evidence of successful recording.
- **Use hooks alone for attribution or parse scripts heuristically.** A
  harness claim is not independent corroboration, and script text does not
  establish which nested command ran. Neither satisfies the existing signing
  authorisation contract.
- **Treat all unknown outcomes as success, or all gaps as complete capture.**
  Fabricates evidence. Forwarding availability and recording completeness must
  be reported separately.
- **Assume HTTP fallback or reuse the WebSocket relay without interpretation.**
  Neither establishes feature parity or capture of incremental application
  messages. Transport support must be measured and tested.

These are reasons for the proposed choice, not a record of operator acceptance.

## Consequences

The existing Claude path retains its behavior while new adapters share the
identity and evidence machinery. Implementing a second format still requires
changes across client routing, session statements, journal redaction/replay,
snapshots, witnesses, reconciliation and the commit path; the adapter is not
the entire integration.

Before implementation is enabled, version-specific sanitized fixtures must
establish request decoding, root/subagent identity, prewarm behavior, nested
call correlation, actual snapshot production and supported transport. The
proposed OAI tests must be reviewed into doc 07, including redaction during
outage/import, interruption, deduplication, restart recovery, mixed client/core
versions and real signed-commit verification. Doc 04 must cover the additional
credential handling, format confusion and recording-gap boundaries. Signing
acceptance requires verification and inclusion-proof evidence, not merely a
successful model response or commit command.

ADR-0057's capture approach, ADR-0058's issuance/restore rules, ADR-0059's
independent signing gate, ADR-0068's journal/refusal rules and ADR-0069's Claude
proxy choice remain in force. If measurements require changing a specific
decision, identify the superseded portion explicitly before acceptance.

No protected event field, enum, serialization, trailer, SPIFFE grammar,
error-class vocabulary or namespace changes are proposed. Adding new
protected content requires doc 08's release and migration procedure; using
free-form body data does not waive it.

**Exit cost.** Before enablement, removing an adapter is an implementation
reversal with no recorded state to migrate. After enablement, new routing can
be disabled, but old journal entries, recorded bodies and ledger events must
remain verifiable and readable under their original interpretation. Removing
support must expose unsupported capture rather than silently discard evidence;
the shared signing and identity guarantees remain.
