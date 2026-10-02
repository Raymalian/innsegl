# ADR-0063: The core runs on its own host, and every client machine holds its own enrolled certificate

- Status: accepted
- Date: 2026-10-01
- Deciders: the operator

## Context

ADR-0060 put the gateway in the one innsegl process and kept it on the
machine that runs the harness, bound to loopback. That fits one machine. It
cannot serve a second one, and it leaves the developer's own machine holding
the signing path, the ledger and the container socket.

The hosted shape splits them. The gateway, the MCP and the API run on a core
host. A client machine (an installation: a developer machine or a CI runner)
runs only the `innsegl` binary, the harness hooks and the git hooks. Once the
gateway answers on a network, loopback no longer says who is calling, and
ADR-0053 already names the missing piece: nothing proves who a caller of the
core is.

## Decision

1. **The core runs on its own host.** Client machines carry no ledger,
   signer or container socket.
2. **Enrolment.** An installation is enrolled once with a single-use
   enrolment token. A member of an organisation mints it on the dashboard
   behind a fresh passkey ceremony (ADR-0062), or with a core CLI. It lives
   15 minutes and only its hash is stored. The client generates its own key
   pair and sends a certificate request. The core consumes the token,
   records the installation, and issues the certificate. The token is the
   only bearer secret in the design.
3. **The certificate.** A short-lived X.509 SPIFFE certificate with the path
   `spiffe://<td>/client/<32 lowercase hex id>`, valid 24 hours, renewed at
   half-life over the current certificate. It is issued by the deployment's
   identity authority through the attested MCP, restricted by policy to the
   client path, and can never yield a signing credential: signing tokens stay
   limited to agent runs. If the authority's policy engine cannot check the
   request's names, the gateway's own CA issues a certificate of the same
   shape. This ADR records that fallback.
4. **The client service.** The key is held by a user-level service,
   `innsegl client serve`. The harness, the hooks and git talk to it locally.
   It is the only holder of the key and opens one mutually authenticated
   connection to the core.
5. **Every client-facing route requires a valid client certificate for a live
   installation.** That is model requests, session endpoints, the commit
   path, telemetry and git push. The stated repository must be within the
   installation's scope and its organisation's. A session is pinned to one
   installation. Any failure is one identical refusal, with nothing recorded
   and no idempotency claim.
6. **Revocation and suspension are on the installation.** Renewal is refused
   for a revoked or suspended one. The short lifetime bounds an outage of
   the status cache.
7. **Ownership.** Organisations own installations. A run records the
   installation that made it in the gateway's mapping table, outside the event
   chain, so ownership is a read-time join and no event changes.
8. **I1, E5 and E8 are unchanged.** A run's identity is still issued only
   through the MCP (ADR-0053). A certificate lets a client ask for a
   signature; signing stays in the core. Client identities are never
   published: only agent-run identities are ever signed into public
   artifacts, and there is no new trust domain.

## Alternatives considered

- **Long-lived API keys.** Readable by the agent's shell, and usable from any
  machine until revoked.
- **Reuse the admin bearer.** It carries admin powers and is the wrong
  audience for a client.
- **Loopback only.** Cannot serve a second machine.

## Consequences

- A stolen certificate or key is useful for at most the remaining lifetime,
  and the key sits in a service the agent's shell does not read from a file.
- Clients can be added and removed without touching the core's trust roots.
- A client must renew before expiry; a machine offline longer than a day
  re-enrols.
- ADR-0060, ADR-0030, ADR-0053, ADR-0025 and ADR-0062 are amended to match.

## Amendment (2026-10-02): what is recorded, and who holds a repository

**What changed.**

- **A session outside any git repository passes through, unrecorded.** A
  session whose statement names no repository (a home folder, system
  troubleshooting, a discussion) is still a client of the core: it needs a
  valid client certificate for a live installation, and a revoked or
  suspended installation is refused as before. Its model requests are
  forwarded to the provider with no run registered, no mapping row and
  nothing in the chain. A session that has stated nothing yet is not such a
  session: it waits for the hook, as before. The event schema is unchanged.
- **A session in a repository is recorded under the repository's real
  name, on first use.** No one grants a repository by hand. The first time
  an installation acts on a repository no organisation holds, its
  organisation becomes the holder: a live grant, written by the core's
  accounts writer and audited with the installation as the actor. A
  repository another organisation holds live is refused with decision 5's
  one refusal; one live holder per repository stays enforced by the
  database.
- **An installation's repository list defaults to `*`.** `*` means every
  repository its organisation holds or will hold. An explicit list set at
  enrolment still narrows: a repository it leaves out is out of scope, and
  is never claimed.
- **Recording is sticky.** A session that has been recorded stays recorded
  when it later states a directory outside any repository: its runs
  continue, and a new subagent is registered under the session's last
  repository. After a core restart, the session's run mapping and the run's
  own registration carry the same fact.
- **One rule everywhere.** The session statement, run registration, the
  commit path and the mirror push (ADR-0065) all use it: a repository is in
  scope once the organisation holds it.

**Why.** Requiring a grant before any session could start refused every
session outside a repository and every repository not yet granted, though
neither is a reason to withhold model access. The record exists for work on
repositories; work elsewhere has nothing to record against.

**What still holds.** Every request needs an enrolled, live installation.
Nothing in a stated repository goes unrecorded, and leaving it does not
stop the recording. Signing stays in the core and fails closed.
