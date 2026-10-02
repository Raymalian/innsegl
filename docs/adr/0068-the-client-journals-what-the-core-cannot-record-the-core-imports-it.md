# ADR-0068: The client journals what the core cannot record; the core imports it

- Status: accepted
- Date: 2026-10-02
- Deciders: the operator

## Context

Attribution is the purpose: agent work in a repository must never go
unrecorded. The harness must never be blocked either. Before this decision
only the core recorded, and it was the one place a model request could go.
A core outage, a core restart, or any request the core could not record
inside a repository was either a refusal or a gap.

## Decision

1. **The client service is the availability layer.** A model request goes to
   the core. When the core does not answer (connect, TLS, timeout, or a 5xx of
   its own), the client sends the request to the provider directly, with its
   headers and body unchanged, and streams the reply back as it arrives.
2. **The core says whether it recorded.** On every reply it relays from the
   provider, the core sets `X-Innsegl-Recorded`: `true` (recorded under a
   run), `false` (inside a repository, not recorded), or `none` (no
   repository). A 5xx without the header did not come from the provider, so
   it is an outage, never a provider error to resend.
3. **The client journals what the core did not record in a repository.** In
   case 1 for a session whose statement names a repository, and whenever the
   core answers `false`, the client writes one journal entry per exchange:
   sequence, previous entry hash, installation, session, agent, the statement
   in force, the request headers without credentials, the request body, the
   reply as streamed, and the client's start and end times. The entry is
   signed with the installation's own key (the key its client certificate
   names) over the exact bytes stored. A session outside any repository is
   forwarded and not journaled; the bypass is logged.
4. **The journal is bounded.** A request that must be journaled when the
   journal cannot be written (full, or unwritable) is refused with a clear
   message. It is the one refusal.
5. **The core imports the journal behind the client-certificate guard.** For
   each entry it verifies the signature under the presented certificate's
   key, that the entry names the caller's installation, and that the entry
   continues that installation's chain. A failure is a rejection, and nothing
   after it is processed. A verified entry is replayed through the same guards
   and recorders a live request passes, so the run is registered by the same
   identity lifecycle, scope and first-use rules. The signed entry is then
   stored on the core and acknowledged. Import is idempotent by entry hash.
   The client deletes only acknowledged entries.
6. **Time.** Imported events carry the core's own `ts` (doc 02 §2). The
   client's times are in the signed entry, which is the recorded body: it is
   stored on the core, and a tool call recorded from it names the entry's
   hash in its body, so the chain commits to it (E4). The event schema is
   unchanged. A later major release may add a client source and an
   occurrence time.
7. **Signing stays fail-closed.** Nothing here signs a commit or issues an
   identity without the core.

## Alternatives considered

- **Refuse while the core is down.** Blocks the harness, which is the failure
  this decision exists to remove.
- **Forward without recording.** Leaves a gap in attribution inside a
  repository.
- **Add a client source and occurrence time to the schema now.** A major
  release with a migration attestation (doc 08); the journal does not need it
  to close the gap.

## Consequences

- The client host holds conversation content between an outage and the next
  import, in a 0700 directory, never with a provider credential.
- An entry that is authentic but cannot be recorded (a repository the
  installation may not record, a refused replay) is stored on the core with
  its reason and acknowledged, so the evidence is kept and the chain moves on.
- A rejected entry stops the import of everything after it until it is
  inspected: a broken chain is evidence, not noise.
- A tool call journaled during an outage is paired with its result only when
  the import runs before the next live request; the client uploads first,
  bounded, so this is the normal case.
- Narrows, for model traffic, ADR-0057's single point of denial and
  ADR-0058 decision 11: an outage no longer refuses or leaves a gap. A
  request the core refuses outright (a 4xx of its own, such as a lifecycle
  refusal) is still a refusal; turning those into a forward plus a finding
  is separate work.
