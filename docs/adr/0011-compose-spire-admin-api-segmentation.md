# ADR-0011: Segment the SPIRE admin API by mount and by network, and state the part SPIRE will not segment

- Status: accepted
- Date: 2026-08-28
- Deciders: Mike

## Context

Doc 05 §1 gives the reference compose stack one architectural rule and one
sentence about how seriously to take it:

> `spire-server` … admin API reachable solely from `innsegl-mcp` … Network
> segmentation even in compose: `spire-server` admin API and `postgres` write
> role reachable only from the services that need them … **Compose is where the
> least-privilege shape is first proven, not first ignored.**

Doc 01 §1 says why: the MCP is "the only component holding SPIRE server admin
credentials. Agents talk only to the MCP; they never see SPIRE admin APIs."
Threat model A2 is that credential; AB-10 is its theft. Everything downstream of
the trust domain root (A1) inherits whatever this boundary is worth.

RM-014 (#22) builds the SPIRE trio before `innsegl-mcp` exists (E4), so the
boundary has to be built now, empty, in a shape that admits exactly one more
member later.

The complication is that **SPIRE does not expose the admin API on a separate
listener.** Its surface is:

1. **A local Unix socket** (`server.socket_path`). Unauthenticated: whatever can
   `connect()` to it has full admin, including minting entries anywhere in the
   trust domain. This is what `spire-server entry create` uses.
2. **The TCP endpoint** (`bind_address:bind_port`, one port, default 8081). The
   Agent API — which every agent must reach in order to attest — and the admin
   APIs are multiplexed onto that one port. They are separated by *authorization*
   (`server.admin_ids`, matched against the caller's X509-SVID), never by port
   or interface.

So "put the admin API on its own network" is not directly expressible. A design
that claims otherwise would be describing a control it does not have.

## Decision

Segment the admin API by the two mechanisms that are real, and record the one
that is not.

1. **The unauthenticated local socket is unshareable.** It lives on a **tmpfs
   private to the `spire-server` container** (`/run/spire/admin`, `uid=1000,
   mode=0700`) rather than on a named volume. A tmpfs cannot be mounted by a
   second container, so "only spire-server holds it" is enforced by the
   container runtime, not by everyone remembering not to add a line to a
   `volumes:` list. `innsegl-mcp` will not be given it.

2. **The TCP endpoint is reachable from exactly two containers.** `spire-server`
   joins two `internal: true` networks and no others:
   `innsegl-spire-node` (member: `spire-agent`) and `innsegl-spire-admin`
   (member: `innsegl-mcp`, when E4 lands — declared now with a single member so
   that joining it is the whole of what grants admin reachability). Port 8081 is
   not published to the host. Every other service in doc 05 §1 — postgres,
   minio, rekor, fulcio, sealer, reconciler, dashboard, demo-agent — is on
   neither network and cannot open a socket to the server at all.

3. **`admin_ids` is a single ID**: `spiffe://innsegl.dev/innsegl/mcp`. Neither
   the agent's node SVID nor any agent-run SVID is admin.

4. **Bootstrap registration runs inside the server container** via
   `docker compose exec`, not from a registrar container. A registrar would have
   to mount the admin socket, which would make (1) false on the first boot.

**Recorded, not solved:** `spire-agent` sits on `innsegl-spire-node` and can
therefore open TCP 8081, on which the admin methods are also served. It is
refused by `admin_ids`, which is authorization, not segmentation. This ADR does
not claim otherwise.

**Also recorded:** `admin_ids` grants *full* admin. It does not scope entry
creation to the `/agent/` subtree, which is what SPI-005 and AB-10 require.
SPIRE's mechanism for that is the experimental OPA authorization policy engine
(`server.experimental.auth_opa_policy_engine`). Wiring it belongs with the admin
client and its test (RM-015, #23); a half-configured experimental authorization
policy shipped without the test that proves it would replace SPIRE's default
policy with something weaker, which is the failure mode the upstream
documentation warns about in its first paragraph.

## Alternatives considered

- **Share the admin socket with `innsegl-mcp` and call that the boundary.**
  Rejected on two counts. It is unauthenticated, so it grants strictly more than
  `admin_ids` does and forecloses ever scoping the MCP's admin to the `/agent/`
  subtree — SPI-005 and AB-10 would become unimplementable rather than deferred.
  And a socket on a shared volume is one `volumes:` line away from being shared
  with a third container, with nothing failing when that happens.

- **Bind the server's TCP endpoint to the admin network's interface only.**
  Rejected because it does not do what it appears to: `bind_address` takes one
  address, and the Agent API is on the same listener, so binding to the admin
  network would leave `spire-agent` unable to attest — no agent, no identities,
  no stack. Binding to the node network instead changes nothing about admin.

- **A one-shot registrar container holding the admin socket.** Rejected: it
  makes the claim in doc 05 §1 false from the first boot, and it buys only the
  convenience of not typing `docker compose exec`.

- **Configure the OPA policy engine now, to scope admin to `/agent/`.**
  Rejected for this issue, not on the merits. A custom rego policy *replaces*
  SPIRE's default authorization policy wholesale; shipping one without the test
  that demonstrates each denial is how an authorization policy silently becomes
  permissive. It belongs with RM-015, which has the test IDs (SPI-005) and the
  client that exercises them.

- **`join_token` node attestation (the usual compose shortcut), or
  `insecure_bootstrap`.** Rejected in `deploy/compose/spire/bootstrap.sh`, whose
  header records the reasoning: a join token has to be minted after the server is
  up and handed over out of band, so `docker compose up` would not by itself
  produce a working stack, and it is a single-use bearer secret an agent cannot
  re-attest with after losing its data directory. `insecure_bootstrap` is
  trust-on-first-use against a spoofed server — precisely the spoofing case doc
  04 names node attestation as the control for. The stack uses `x509pop` with a
  node CA generated at bootstrap, and an `UpstreamAuthority "disk"` root so the
  agent's bootstrap trust bundle is a file rather than a promise.

## Consequences

- **Easier:** `innsegl-mcp` (E4) gains admin reachability by joining one
  network and being named in one `admin_ids` entry. Nothing else has to change,
  and nothing else *can* gain it by accident: a new service that needs SPIRE
  gets the Workload API socket volume, which grants an identity and no
  authority.
- **Harder:** bootstrap registration is an operator action
  (`deploy/compose/spire/register.sh`, which `docker compose exec`s into the
  server) rather than a compose service. That is the intended cost.
- **Verified, not assumed** (2026-08-28, SPIRE 1.15.3, Docker 29.6.2):
  `docker network inspect innsegl-spire-admin` lists exactly
  `innsegl-spire-server`; `innsegl-spire-node` lists the server and the agent;
  a container attached to `innsegl-oidc-frontend` cannot even resolve
  `spire-server` (`nc: bad address 'spire-server'`), let alone connect. A
  workload carrying per-run selectors received
  `spiffe://innsegl.dev/agent/demo/rm-014/<run-id>`.
- **Residual risk, restated so it is not lost:** anything that can reach the
  Docker socket can start a container with any label and any image and will
  attest successfully, because the docker workload attestor's selectors are
  container metadata. `spire-agent` is the only container in the stack that
  mounts that socket. Its `:ro` is *not* a mitigation and is not claimed as
  one: a read-only bind mount of a Unix socket restricts nothing, verified on
  2026-08-28 by issuing `POST /v1.45/containers/create` through such a mount
  and getting HTTP 201. Narrowing it requires an allowlisting socket proxy in
  front of the daemon, which doc 05 §1 does not name as a service; until then
  this is a node-trust assumption — doc 05 §2, "SPIRE hosts are the most
  restricted machines in the deployment."
- **Exit cost if reversed:** low. Moving the admin socket back onto a volume is
  a two-line change; the expensive part would be re-establishing what the
  boundary is supposed to mean, which is why it is written down here.
