# ADR-0053: Issue a run's identity only through the attested MCP, never to a workload that declares a label

- Status: accepted; amended 2026-10-01 (see the Amendment)
- Date: 2026-09-26
- Deciders: the operator

## Context

`DefaultRegisterAgentSelectors` (internal/mcp/register_agent.go) creates each
run's SPIRE entry with three selectors:

```
docker:label:dev.innsegl.run-id:<run_id>
docker:label:dev.innsegl.agent-type:<agent_type>
docker:label:dev.innsegl.task-id:<task_id>
```

A label is chosen by whoever starts the container. The run id is public: it is
printed in every `Agent-Run` trailer and on the dashboard. So anything that can
start a container with those three labels, and mount the Workload API socket,
matches the entry. deploy/compose/spire/agent.conf already names this bypass.

### What was measured, 2026-09-26

Read-only, against the running stack (`spire-server entry show`, `docker ps`,
config files). Nothing was created, changed or restarted.

| question | answer |
|---|---|
| SPIRE release | 1.15.3, server and agent (deploy/compose/spire.yml) |
| workload attestors the agent runs | `docker` and `unix` (with `discover_workload_path`), nothing else |
| entries registered | 12: 10 agent runs, the MCP, the OIDC provider |
| selectors on the 10 run entries | the three labels above, and nothing else. No image, no uid, no binary |
| selectors on the MCP and OIDC entries | `unix:sha256`, `unix:uid:1000`, `docker:image_config_digest`, `docker:image_id`, a component label |
| containers carrying a `dev.innsegl.run-id` label | 0 |
| services mounting the Workload API socket | the MCP, the init job, the OIDC provider, and the `verify` profile's test workload |

Three facts follow.

1. **No run ever attests.** Ten live run entries, and no workload that could
   match any of them. Agent runs are processes outside the container runtime.
   On the measured deployment that runtime runs in a virtual machine, so the
   SPIRE agent cannot see an agent's process at all, only its own PID namespace.
2. **The credential path does not use the entry's selectors.** `get_credential`
   mints a JWT-SVID through the admin API's `MintJWTSVID`
   (internal/mcp/get_credential.go). ADR-0019 records that minting is not
   entry-gated. The entry is read as a record that the run is live (IP §4:
   fail closed if the entry is missing), not as an attestation.
3. **The label path is still open.** It is unused, not closed. A container
   with the three labels and the socket volume would be issued the run's
   X509-SVID and JWT-SVIDs by the SPIRE agent. That path skips the MCP, so it
   writes no ledger event (I3). This was read from config and from
   deploy/compose/spire/verify.sh, which attests a labelled container the same
   way. It was not exercised against a live run entry.

What SPIRE *can* verify here is the MCP itself: its entry binds a binary hash,
a non-root uid and an image digest, and only that SVID is accepted by the admin
API (server.conf `admin_ids`).

## Decision

**The identity service verifies the issuer, not the claimant.** A run's entry
carries one selector, `innsegl:run:<run_id>`, of a type no workload attestor
emits. No workload can match it, so no workload is ever issued a run's identity
by attestation. The only path to a run's credential is `MintJWTSVID`, reachable
only with the MCP's SVID, which SPIRE issues against `unix:sha256`, a non-root
`unix:uid` and `docker:image_config_digest`.

Proving that a caller of the MCP *is* the run it names is the MCP's job, not
SPIRE's. That is the open gap the MCP caller-authentication work closes. This
ADR does not close it and does not decide how.

`RegisterAgentConfig.Selectors` stays. A deployment that does run agents as
containers on a Linux node may supply its own selectors. It then owns the
review of them, as doc 04 already requires.

## Alternatives considered

- **`docker:image_config_digest` with the labels.** No agent run is a
  container, so there is no image to bind. Where runs are containers, every run
  from one image has the same digest, so it does not tell runs apart. And the
  Docker socket access that forges a label also starts that image.
- **`unix:uid` with `unix:path` or `unix:sha256`.** The SPIRE agent cannot see
  processes outside its PID namespace, and on the measured deployment that is
  every agent. Where it can see them, every run of one harness shares the same
  uid and the same binary hash, so the selector binds the harness, not the run.
  The harness binary also changes on every upgrade, which leaves a stale entry
  (the case register.sh already handles for the MCP image).
- **Both combined.** Inherits both limits. The only selector that differs per
  run is still a label, which is the thing being replaced.
- **Keep the labels and document that they are not the control.** Leaves a
  second issuance path open that skips the MCP and the ledger. Writing down a
  hole is not closing it.
- **Create no run entry at all.** IP §4 has `get_credential` fail closed when
  the entry is missing, and retirement deletes it. Without the entry, that gate
  and the retirement signal both go.
- **Parent run entries to a SPIFFE ID no node holds.** Also unmatchable today.
  But an ID that names no node can be made to name one by a later
  registration. A selector type no attestor emits can only be produced by
  installing a plugin, which is a reviewed config change.

## Consequences

- One issuance path for a run: through the MCP, with a ledger event. The
  label bypass in agent.conf's comment stops applying to run entries.
- SPIRE's workload attestation stops being part of a run's identity story.
  Everything rests on the MCP's own attestation and on MCP caller
  authentication, which is not built yet. Until it is, any local process that
  can reach the MCP can still ask for any run's credential. This ADR does not
  change that.
- A compromised MCP can mint any run's credential. That was already true
  (ADR-0019); this makes it the only way, not a new one.
- No protected string changes. SPIFFE IDs, trailers and event schema are
  untouched. `innsegl` is this project's own namespace.
- **Migration.** Run entries registered before the change keep their labels.
  At start-up the MCP rewrites the selectors of every live run entry to the new
  one with `BatchUpdateEntry`, which authz-policy.rego already allows. The
  SPIFFE ID, entry and run do not change, so no ledger record changes meaning.
  Retired runs have no entry and need nothing. Letting old entries age out was
  rejected: a lapsed run can be restored (ADR-0052), so an old entry could keep
  the label path open for the whole restore horizon.
- **Tests, written first.** A container carrying a live run's three labels and
  the socket volume is refused an SVID; observed issued before the change. SPIRE
  accepts `innsegl:run:<run_id>` on create and on update. `get_credential` still
  mints for a live run and still fails closed for a missing entry.
- agent.conf's comments describing labels as the run binding must be updated
  in the same change. So must verify.sh, which tests a path runs no longer use.
- **Exit cost.** Low. Going back is a selector function and one more rewrite
  of live entries. Nothing on the chain records selectors.

## Amendment (2026-10-01): caller authentication for client traffic

**What changed.** The caller-authentication gap this ADR names is closed for
client traffic by ADR-0063: every client-facing route checks an installation
API key scoped to repositories.

**Why.** The core now serves callers on other machines, so a caller must
prove which installation it is.

**What still holds.** A run's identity is issued only through the attested
MCP, never to a workload that declares a label (I1). A key lets a client ask;
it does not let a client name its own identity.
