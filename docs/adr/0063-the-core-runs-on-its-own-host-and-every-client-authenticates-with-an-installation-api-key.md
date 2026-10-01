# ADR-0063: The core runs on its own host, and every client authenticates with an installation API key

- Status: accepted
- Date: 2026-10-01
- Deciders: the operator

## Context

ADR-0060 put the gateway in the one innsegl process and kept it on the
machine that runs the harness, bound to loopback. That fits one machine. It
cannot serve a second one, and it leaves the developer's own machine holding
the signing path, the ledger and the container socket.

The hosted shape splits them. The gateway, the MCP and the API run on a core
host. A client machine runs only the `innsegl` binary, the harness hooks and
the git hooks. Once the gateway answers on a network, loopback no longer says
who is calling, and ADR-0053 already names the missing piece: nothing proves
who a caller of the core is.

## Decision

1. **The core runs on its own host.** Client machines carry no ledger,
   signer or container socket.
2. **Every client-facing route checks an installation API key.** That is
   model requests, session endpoints, the commit path, telemetry and git
   push. One key belongs to one client installation, is owned by an account,
   is scoped to repositories, and has the capability `harness`.
3. **Format and storage.** `ik_<keyid>_<secret>`. Only a hash of the secret
   is stored.
4. **One middleware, one failure.** Any failure (missing, malformed, unknown,
   revoked, out of scope) is one identical 401. Nothing is recorded and no
   idempotency claim is made.
5. **Revocation takes effect within a short cache window.**
6. **Issuance.** On the account page, behind a fresh passkey ceremony
   (ADR-0062), or by an admin CLI on the core for bootstrap.
7. **Nothing about the key reaches the event chain.**
8. **I1 and E8 are unchanged.** A run's identity is still issued only
   through the MCP (ADR-0053). A key lets a client ask for a signature;
   signing stays in the core.

A leaked key lets its holder relay through the gateway with their own
provider login, register runs, and get commits signed, in the scoped
repositories only. It grants no read, no admin and no deletion, and it is
bounded by its scope and by revocation.

## Alternatives considered

- **Loopback only.** Cannot serve a second machine.
- **Mutual TLS client certificates.** Harder to issue and rotate from a
  dashboard, and no per-repository scope without a separate mapping.
- **Reuse the admin bearer.** It carries admin powers and is the wrong
  audience for a client.

## Consequences

- Clients can be added and removed without touching the core's trust roots.
- A stolen key is a bounded, revocable loss, not a loss of the core.
- ADR-0060 decisions 2 and 8, ADR-0030, ADR-0053, ADR-0025 and ADR-0062 are
  amended to match.
- The cache window is a stated delay between revocation and effect.
