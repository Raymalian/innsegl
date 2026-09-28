# ADR-0060: The gateway runs inside the one innsegl process

- Status: proposed
- Date: 2026-09-28
- Deciders: the operator

## Context

Epic #356 (E13) is writing the decision records for the flight recorder before
any code lands. Its three sibling issues in the same wave — #365 (capture at a
model gateway, with independent witnesses), #366 (an agent's identity lifecycle
driven by its traffic) and #367 (a commit attributed through the tool call that
made it) — decide *what* the gateway records and enforces. This issue, #368
(RM-223), decides only *where it runs*.

That question has a direct answer only because of two decisions already on the
books.

**ADR-0056** folded the sealer and the reconciler into `innsegl-mcp` by giving
`innsegl serve` an `-also` flag (`INNSEGL_MCP_ALSO`, comma-separated), taking
the deployment from 19 containers to 17: "A plain `docker compose up` is one
process." `cmd/innsegl/serve.go` implements this as a fixed map,
`alsoCommands`, from a companion's SUBCOMMAND name to the same function that
subcommand's own binary invocation runs — `api`, `seal`, `reconcile`, `reap`
today. `-also` is parsed once, validated against exactly those names, and each
named companion is started as a goroutine in the running process, reading the
same environment the process itself was given, with no separate configuration
path. The comment on that map states the intent plainly: "Four of doc 05 §1's
services are this same binary run four ways... They are separate containers
because the compose file starts them separately, not because they need
separate processes." Critically, a companion's exit — including a clean,
zero-status return — stops the whole replica; the code's own words are "ANY
RETURN IS A FAILURE, INCLUDING A SUCCESSFUL ONE," because a companion that has
quietly stopped doing its job is otherwise indistinguishable, from every other
component's side, from one that has simply not run yet.

`deploy/compose/innsegl.yml` ships this default: `innsegl-mcp`'s
`INNSEGL_MCP_ALSO` defaults to `seal,reconcile,reap`, its tool-surface listener
is bound inside the container so the container network can reach it (other
services, the dashboard among them, address it by container name), and the
host reaches it only because compose publishes that port to loopback
specifically — the admin listener and the health listener are published the
same way. Nothing outside the container needs to open a socket to the
tool-surface port from the host at all today; the harness has never been a
caller of it.

**ADR-0011** already reasoned, for the SPIRE admin API, about what a container
and a compose network can and cannot promise. Its residual-risk finding is
stated flatly and has not needed revision since: "anything that can reach the
Docker socket can start a container with any label and any image," and can
therefore join any network a running service is on, whatever that service's
own bind address says. A read-only mount of that socket is not a mitigation —
ADR-0011 measured a container creation succeed through one. That finding is
this ADR's starting point, not a separate concern: it is the exact mechanism
that would defeat a loopback-only bind if the machinery weren't held elsewhere
too.

**ADR-0030** made loopback the default for the MCP's own `-listen` and
`-health-listen`, and gave the reason once, for a surface with comparable
stakes: "This process holds SPIRE admin... a default that published it on
every interface would make an operator's omission the exposure." **ADR-0044**
is the precedent for the shape of an answer here: when a new capability's
placement conflicts with a stated guarantee (there, the dashboard's read-only
role; here, the container count and the state surface), the ADR settles the
binding constraint before anything is built around it, rather than discovering
it by breaking a measured guarantee later.

The gateway is a new kind of component for this codebase, not a new instance
of an old one. Every existing companion (`api`, `seal`, `reconcile`, `reap`)
reads the ledger or writes to it; none of them sits in the path of a model
provider login credential or the full text of every agent's conversation, in
transit, on every request. That is a new asset class through a boundary this
project has not had before, and it is why the flight-recorder design names a
threat-model review as a precondition for building it at all (doc 04 §6
requires review whenever a new trust boundary is added). Placement has to be
decided with that review's terms already in view: identity for every run is
still issued only through the one attested MCP (I1, ADR-0053), and nothing
this ADR proposes may create a second definition of that. State for the
gateway would also be new ledger-database writes and reads, which is exactly
the surface I4's append-only protection and doc 02's protected schema already
govern; ADR-0044's method — extend the one writer this project already has,
rather than open a second store or a second package — is the one this ADR
reuses rather than reinvents.

Finally, the fewer-parts direction this project already committed to (ADR-0056
is its phase 1: 19 containers to 17) is a standing constraint on any new
capability, not a one-time cleanup. A design for the gateway that added a
container, or a host process outside the one artifact this project builds and
ships, would be moving against a decision already made, not merely declining
to advance it further.

## Decision

**The gateway is a fifth companion of the one `innsegl` process, published on
loopback only, with no new store.**

1. **No new container.** `serve -also gateway` joins `api`, `seal`,
   `reconcile` and `reap` as a fifth entry in `alsoCommands`: the same map, the
   same goroutine-per-companion lifecycle, the same rule that any return —
   success or failure — stops the replica. The gateway is not exempt from that
   rule; a gateway that has silently stopped forwarding traffic is exactly the
   failure mode the existing companions are already built to surface loudly
   rather than let happen quietly. The deployment's container count is
   unchanged by this decision, and a plain `docker compose up` stays the
   one-process shape ADR-0056 established.

2. **Published on loopback only, and the gateway refuses any other bind.**
   The MCP's own tool-surface port is reachable inside the compose network
   because other containers are its callers and is restricted to loopback at
   the host only by how compose publishes it — a pattern that exists because
   ADR-0011 already established that "put it on its own network" is not
   always something a component can enforce by itself. The gateway has no
   in-network caller: nothing but the harness running on the same machine as
   the operator ever calls it. Its listen configuration therefore does what
   ADR-0030 made the *default* for the MCP's own admin and health listeners,
   and goes one step further: it is not only defaulted to loopback, it
   refuses to start bound to anything else. A gateway that mediates every
   model call and every commit is at least as sensitive as the surfaces
   ADR-0030 was written to protect that way.

3. **State lives in the existing ledger database.** The agent-to-run mapping,
   conversation fingerprints and lifecycle policy state the gateway needs are
   new tables and new reads on the one Postgres this project already owns and
   writes through `internal/ledger`'s existing writer role — not a new store,
   local or otherwise, and not a new package parallel to it. This is
   ADR-0044's method applied a second time: extend the writer that already
   exists, and let the append-only guarantee that already covers
   `innsegl.events` be the same guarantee (unmodified, per ADR-0044's own
   "Measured, not assumed" finding about what a careless schema addition can
   do to it) that a reviewer checks once, not once per store.

4. **Bodies reuse the existing body store.** Conversation and action content
   the gateway captures is written to the store this project already has,
   under the retention setting that already governs it. No second content
   store is introduced by this placement.

5. **Workspace snapshots are refs inside the project repositories, under a
   reserved namespace, taken through the projects mount the MCP already has.**
   No new mount and no new storage subsystem: the gateway reaches a project's
   working tree exactly the way `describe_workspace` already does, and a
   snapshot is read-only toward that working tree — it observes the tree
   through a private index of its own, the same discipline the commit path
   already applies so that one writer's snapshot can never pick up another
   writer's staged changes.

6. **The host carries only the `innsegl` binary, one managed-settings file and
   one harness hook, once E20 completes.** The binary is the signer, the git
   hook target and the status surface; nothing else is installed on the
   developer's machine as a result of this placement. The hook shims
   (session-start, subagent-start, post-tool-use, stop), the commit wrapper
   script, and the run-token files it currently reads are retired once parity
   with the new path is proven — that retirement is E20's exit condition, not
   a consequence of accepting this ADR on its own.

7. **In this placement, the process boundary is the container boundary.**
   The gateway does not get a separate operating-system user or a separate
   container wall the way a standalone service would; it inherits whatever
   isolation the `innsegl-mcp` container already has. That equivalence holds
   only on one condition: agents must not be able to reach the container
   runtime's socket. ADR-0011 already measured what happens when that
   condition fails for a different surface — a caller with that socket can
   start a container with any label and any image and join it to any network
   a running service is reachable on, which would let it reach this gateway
   directly regardless of what its own listen configuration refuses. Denying
   agents that socket, through the harness sandbox configured in managed
   settings, is therefore a requirement of choosing this placement, not an
   optional hardening step layered on afterward. This is recorded as a build
   rule in the threat model (doc 04), which doc 04 §6 already requires be
   reviewed for any new trust boundary, and this ADR does not restate that
   review's findings — it states the one placement fact the review depends on.

8. **The gateway stays on whatever machine runs the harness, always.** It is
   the component that sees the model provider's login credential and the full
   text of every agent's conversation, in transit, on every request. Nothing
   in this decision sends either across a network the harness-to-gateway hop
   does not already need to cross.

## Alternatives considered

- **A separate gateway container.** Rejected: it adds a part in the exact
  architecture ADR-0056's phase 1 just spent reducing (19 to 17, with further
  phases aimed lower still), for a component the `-also` mechanism already
  gives a working process-lifecycle model to, for free. Nothing about
  mediating model traffic needs a process boundary the existing four
  companions don't already have; adding a fifth container here would be
  moving backward against a decision this project already made, not declining
  to extend it.

- **A host daemon started outside the containers** (independent of compose,
  managed by whatever service mechanism the host provides). Rejected: it is a
  new install surface with its own service-management lifecycle to package,
  start, restart and keep current — a second thing this project would have to
  build, test and ship, beside the one container image it already does all
  three for. It also does not answer any of the state questions this ADR
  settles for free inside the one process: a daemon outside the container
  needs its own path to the ledger database, its own path to the body store
  and its own path to the projects mount, each a second definition of
  something this project already has exactly one definition of.

- **Running the gateway only on a remote core, with the harness elsewhere.**
  Rejected on the asset this ADR's own context names first: the gateway is
  what sees the model provider's login credential and the full content of
  every agent's conversation, in transit, on every request that passes
  through it. Placing it anywhere but the machine the harness runs on sends
  both across a network this design has no reason to cross. The mission this
  project states — attribute every action and every commit — does not require
  that crossing, and nothing about the gateway's job changes if the harness
  and the gateway are never more than a loopback hop apart.

## Consequences

**Easier.** E14 (gateway core) is a fifth entry in a map that already exists,
not a new deployment artifact: no new compose service, no new row in doc 05's
topology table, no new image to build or scan. E15 and E16 (identity from
traffic, action records) inherit answered state questions — extend
`internal/ledger` and the existing schema, the way ADR-0044 already showed how
to do for this project, rather than design a new persistence layer from
nothing.

**Harder.** The gateway's failure now stops the whole `innsegl-mcp` replica,
exactly as a sealer's or a reconciler's failure already does — `serve.go`'s
companion-failure channel does not distinguish between them. A gateway bug now
takes tool serving down with it, extending a trade-off the threat model already
accepts for the recording loops ("no record means no work") to the entire
agent traffic path, not only to the parts of it that were already
ledger-writes.

**Harder.** Everything resting on the gateway's loopback boundary and on
denying agents the container runtime's socket is now load-bearing for asset
classes — provider credentials, full conversation content — that the existing
four companions never touched. ADR-0011 reasoned about a container and a
compose network the same way for the SPIRE admin credential; this placement
leans on the identical assumption for a second, more exposed surface, and
inherits ADR-0011's residual-risk finding rather than needing a new one.

**Now settled, not yet built.** This ADR fixes where the gateway runs and
where its state lives; it does not build the loopback refusal, the sandbox
denial or the state schema themselves. Each is a build rule with a test that
must be observed failing first, per the epic's acceptance criteria, and each
test ID is added to the catalogue when E14's wave starts.

**Interacts with fewer parts.** This decision holds the container count the
fewer-parts plan's phase 1 already reached rather than reversing it, and it
does not block that plan's further phases (the object store, the signing
log, serving the dashboard from the API), which reduce different parts of the
stack and do not depend on this one.

**Exit cost if reversed: moderate.** Splitting the gateway back into its own
container is small on the code side — the companion function is an ordinary
subcommand the same way `api`, `seal`, `reconcile` and `reap` already are, so
extracting it changes which binary invocation starts it and not what it does.
What is not small is what the split would owe back: "the process boundary is
the container boundary" is this ADR's whole security argument for its
placement, and a gateway in its own container needs its own version of that
argument, reviewed on its own terms, not inherited from this one. Every
developer machine's managed-settings file and sandbox policy would also need
re-verification against the new placement, because they were written against
this one. The state decisions are cheaper to reverse on their own: dropping a
table or a ref namespace and pointing the gateway at a new store touches
nothing else this project owns, the same shape ADR-0044 already recorded for
its own table.
