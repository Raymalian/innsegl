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
