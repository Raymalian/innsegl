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
caller of it. The gateway's own listener follows this same pattern rather
than a stricter one; see decision 2.

**ADR-0011** already reasoned, for the SPIRE admin API, about what a container
and a compose network can and cannot promise. Its residual-risk finding is
stated flatly and has not needed revision since: "anything that can reach the
Docker socket can start a container with any label and any image," and can
therefore join any network a running service is on, whatever that service's
own bind address says. A read-only mount of that socket is not a mitigation —
ADR-0011 measured a container creation succeed through one. That finding is
this ADR's starting point, not a separate concern: it is the exact mechanism
that would defeat the loopback-only guarantee decision 2 describes, if network
segmentation weren't holding it too.

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
reuses rather than reinvents. For status specifically, ADR-0052 already
settled the question this ADR would otherwise re-litigate: a run's state is
read from its newest recorded fact rather than stored, "because a stored
state would be a fact nobody appended" (I4) — the read
`internal/ledger/runstate.go` already performs. ADR-0051's `run_adopted` is
part of that same vocabulary.

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

2. **Published to the host on loopback only; inside the container, the
   gateway listens the way the tool surface already does.** A socket bound to
   loopback inside a container's own network namespace cannot receive traffic
   docker forwards in from a published host port — binding it there would
   make the gateway unreachable, not merely host-only. So the gateway's
   listener binds an address reachable within the container, exactly as
   `INNSEGL_MCP_LISTEN`'s own default already does for the tool surface; what
   makes it loopback-only as experienced from outside the container is the
   compose publish line — `127.0.0.1:<port>:<container-port>`, the same
   pattern the tool-surface, admin and health ports already use — guarded by
   a compose-config test in the same family ADR-0056 already runs to hold the
   folded process to its settings, so that line cannot drift to every
   interface, or lose its publish, unnoticed.

   That published-port guarantee is a host-reachability guarantee, not a
   same-container guarantee, and this ADR states plainly what the gateway can
   and cannot itself tell about an inbound connection. It can check, and
   must, that it is unreachable from any compose network `innsegl-mcp` does
   not itself join — the same segmentation ADR-0011 already used for the
   SPIRE admin endpoint, where an unjoined service "cannot even resolve" the
   target, let alone connect. It cannot reliably tell, and does not claim to,
   whether a connection arriving on a network it does share with another
   container in the stack came in through the host's published path or
   directly from that sibling container: docker's forwarding does not
   preserve that distinction for the process to inspect, the same gap
   ADR-0011 already recorded as residual for the SPIRE admin TCP endpoint
   ("recorded, not solved"). The requirement this draws is on the compose
   topology, not on runtime inspection: no other container in the stack may
   be joined to whatever network carries the gateway's listening address, so
   there is no sibling connection left for the gateway to have to tell apart.
   ADR-0030's reasoning is the precedent for making loopback the default
   here, the way it already is for the MCP's own admin and health listeners
   ("a default that published it on every interface would make an operator's
   omission the exposure") — expressed as a compose default and a guarding
   test, not as a process-level bind refusal, which is not a control a
   containerized listener can meaningfully offer.

3. **The agent-to-run mapping is insert-only; lifecycle status is never
   stored.** A new table records each (session, agent id, conversation
   fingerprint) tuple's run id and its parent, forked and adopted links,
   written once, by the same writer role `internal/ledger.Store` already
   holds — a new table beside `innsegl.events`, the shape ADR-0044 already
   used, not a new package or a new database. Unlike ADR-0044's own
   `alert_resolutions`, which is deliberately correctable index-like metadata
   about a permanent record, this mapping *is* the record: a row here that
   could later be updated or deleted is exactly what an actor trying to
   disown attributed work would want, so it is insert-only the way
   `innsegl.events` itself is — the writer role's `UPDATE`/`DELETE`/`TRUNCATE`
   grant on it is revoked and a trigger refuses them, not merely a documented
   expectation. Lifecycle status — active, lapsed, abandoned, retired — is
   never a column here or anywhere: it is derived at read time from the
   lifecycle events already on the chain (`run_registered`, `run_expired`,
   which ADR-0052 already settled records a lapse rather than a death,
   `run_adopted` from ADR-0051, and `run_retired`), the same read
   `internal/ledger/runstate.go` already performs, extended to cover a
   fingerprint's own history rather than reinvented beside it. If the
   identity-lifecycle design (#366) finds a fact these events cannot express,
   a new event type is doc 02's process to add, not a status column this ADR
   invents to avoid it.

4. **Bodies reuse the existing body store.** Conversation and action content
   the gateway captures is written to the store this project already has,
   under the retention setting that already governs it. No second content
   store is introduced by this placement.

5. **Snapshot objects live in a per-repository git object store inside the
   existing body-store volume — never in the project's own repository.** For
   each project the projects mount already gives the MCP access to, the
   gateway keeps a separate `GIT_DIR` (objects and refs, nothing else) inside
   the body-store volume this project already provisions — no new volume and
   no new store, the same volume the action-record bodies already live in,
   and one only `innsegl-mcp` mounts, so nothing an agent's own tool access
   can reach. A snapshot's working tree is read through the projects mount
   exactly as `describe_workspace` already reads it, through a private index
   of its own, and is never written: the project's own working tree and its
   own `.git` are touched by nothing this decision adds. The resulting tree
   object's hash is what the ledger records, the same way every other
   content this project hashes into the chain is recorded by its digest, not
   by where it happens to be stored. Keeping the objects outside the
   repository an agent is working in, rather than as refs inside it under a
   reserved namespace, is deliberate: an agent's ordinary access already
   includes writing to its own repository's `.git`, so evidence kept there is
   not independent of the party it is evidence about — an agent that wanted
   its own record gone could reach for the same namespace meant to hold it.

6. **The host carries only the `innsegl` binary, one managed-settings file and
   two harness hooks, once E20 completes.** The binary is the signer, the
   git hook target and the status surface. The two harness hooks are: the
   commit hook, which injects the tool call's id into git's environment for
   `prepare-commit-msg` to read; and the session-end hook, which retires the
   main agent's run when its harness session ends (ADR-0058 decision 7a) —
   a subagent is retired by hand-back instead, with the long-silence horizon
   as backstop, so no third hook is needed for it. Nothing else is installed
   on the developer's machine as a result of this placement. The other hook
   shims (session-start, subagent-start, post-tool-use, stop), the commit
   wrapper script, and the run-token files they currently read are retired
   once parity with the new path is proven — that retirement is E20's exit
   condition, not a consequence of accepting this ADR on its own.

7. **In this placement, the process boundary is the container boundary.**
   The gateway does not get a separate operating-system user or a separate
   container wall the way a standalone service would; it inherits whatever
   isolation the `innsegl-mcp` container already has. That equivalence holds
   only on one condition: agents must not be able to reach the container
   runtime's socket. ADR-0011 already measured what happens when that
   condition fails for a different surface — a caller with that socket can
   start a container with any label and any image and join it to any network
   a running service is reachable on, which would let it reach this gateway
   directly over the same network the published path also relies on,
   defeating the segmentation decision 2 describes even though the compose
   publish line itself stayed correct. Denying agents that socket, through
   the harness sandbox configured in managed
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

**Harder.** Everything resting on the gateway's compose-network segmentation,
on the published-port guarantee holding, and on denying agents the container
runtime's socket is now load-bearing for asset classes — provider
credentials, full conversation content — that the existing four companions
never touched. ADR-0011 reasoned about a container and a compose network the
same way for the SPIRE admin credential; this placement leans on the
identical assumption for a second, more exposed surface, and inherits
ADR-0011's residual-risk finding rather than needing a new one.

**Now settled, not yet built.** This ADR fixes where the gateway runs and
where its state lives; it does not build the compose publish line, the
compose-config test that guards it, the network segmentation, the sandbox
denial, the insert-only mapping table or the per-repository object store
themselves. Each is a build rule with a test that must be observed failing
first, per the epic's acceptance criteria, and each test ID is added to the
catalogue when E14's wave starts.

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
this one. The state decisions are cheaper to reverse on their own: dropping
the mapping table or the per-repository object store and pointing the
gateway at a new one touches nothing else this project owns, the same shape
ADR-0044 already recorded for its own table. One state decision is not
symmetric: because the mapping table is insert-only by revoked grant,
correcting a wrong row is not a delete or an update but a new event type
through doc 02's process — deliberately, since what that table records is
itself evidence, not index-like metadata.
