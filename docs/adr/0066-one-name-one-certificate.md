# ADR-0066: One name, one certificate

- Status: accepted
- Date: 2026-10-01
- Deciders: the operator

## Context

Clients reach the core over TLS, and passkeys (ADR-0062) bind to the name the
browser sees. Both need a name that does not change.

## Decision

1. The core answers at one DNS name, `<core-name>`.
2. Its gateway certificate names `<core-name>` and optionally an address. The
   core's own CA issues it.
3. `innsegl connect` installs that CA on the client.
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
