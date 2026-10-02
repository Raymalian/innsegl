# ADR-0066: One name, one certificate

- Status: accepted; amended 2026-10-02
- Date: 2026-10-01
- Deciders: the operator

## Context

Clients reach the core over TLS, and passkeys (ADR-0062) bind to the name the
browser sees. Both need a name that does not change.

## Decision

1. The core answers at one DNS name, `<core-name>`.
2. Its gateway certificate names `<core-name>` and optionally an address. The
   core's own CA issues it.
3. `innsegl connect` installs that CA on the client. The gateway also
   verifies client certificates (ADR-0063) against the deployment's trust
   bundle.
4. Automatic publicly-trusted certificates are a later option.
5. Passkeys bind to `<core-name>`, so it must be stable.

## Alternatives considered

- **Several names for gateway, API and dashboard.** More certificates to
  issue and more origins for a passkey to bind to.
- **Bare address, no name.** A passkey cannot bind to it, and a change of
  address would orphan every credential.
- **Public certificates now.** Adds an external dependency before the shape
  is settled.

## Consequences

- Renaming the core invalidates every passkey; recovery codes are the path.
- Each client trusts the core's CA, and only for this purpose.

## Amendment (2026-10-02): the dashboard is served over HTTPS at the same name

**What changed.** The dashboard is served over HTTPS at `<core-name>`
(RM-311, #493). The core's CA issues its certificate for the same names as
the gateway's, so a client that trusts the core trusts both. The dashboard's
certificate has its own key, written by the core to a volume the dashboard
mounts read-only and renewed before it expires. The relying-party ID is
`<core-name>` and the origin is the dashboard's HTTPS address.

**Why.** A browser offers passkeys only on a secure origin, and a plain-HTTP
address is secure only on `localhost`. A separate key means a dashboard that
leaks its key cannot present the gateway's certificate.

**What still holds.** One name, one CA. Plain HTTP stays for `localhost`.
