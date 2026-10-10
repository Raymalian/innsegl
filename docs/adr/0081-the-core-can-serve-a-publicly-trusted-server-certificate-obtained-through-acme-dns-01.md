# ADR-0081: The core can serve a publicly trusted server certificate, obtained through ACME DNS-01

- Status: accepted
- Date: 2026-10-10
- Deciders: the operator
- Builds on: ADR-0066 decision 4 ("automatic publicly trusted certificates are a later option"), ADR-0078

## Context

The core answers at one name (ADR-0066) with a server certificate from its
own CA. Every client installs that CA, and a browser opening the dashboard
must trust it too. A deployment that wants a certificate every browser and
client already trusts needs one from a public certificate authority, renewed
without anyone remembering to.

The core may sit on a private address that no certificate authority can
reach, so the proof of control cannot be an HTTP or TLS answer from the core
itself. It has to be a DNS record in the name's own zone.

## Decision

1. The core can obtain its server certificate through ACME with the DNS-01
   challenge, from an ACME directory set by configuration (production by
   default; a staging directory is a setting). Off by default: the own CA
   stays the default.
2. The core terminates TLS itself, as before. The gateway reads its current
   certificate on every handshake and the dashboard's server reads its file
   on every handshake, so a renewal needs no restart. The gateway and the
   dashboard each get a certificate with a key of its own (ADR-0066's
   2026-10-02 amendment).
3. The DNS record is written through a DNS provider chosen by configuration,
   through a maintained ACME library that supports many providers, pinned to
   a version. No provider is the default. The build compiles in a set of
   them, the ones that take a plain API token plus three generic ones (RFC
   2136 dynamic updates, an HTTP endpoint, a command) that reach any DNS a
   deployment runs. Not all of them: the library's all-providers set more
   than doubles the binary, past the size the identity agent hashes a
   workload's binary up to, and the core would get no identity (measured in
   an update rehearsal). A test holds the binary under that size.
4. The DNS credential is a per-host credential (ADR-0078): a file in its own
   volume, read-only to the core and to nothing else, handed to the provider
   as the `_FILE` form of the provider's own setting. The operator scopes it
   to one zone; the core refuses a name outside that zone. Changing it
   recreates the core on the next update.
5. Client certificates do not change. The public certificate covers the
   server only. Hosted mode keeps requiring a client certificate from the
   deployment's own authority (ADR-0063).
6. A client trusts the system's roots for its core only once the core is
   recorded as having a public server certificate. `innsegl connect` records
   it when it enrols, and `innsegl connect --update` re-checks it. A core on
   its own CA is still trusted through that CA alone.
7. The account and both certificates are kept in a volume, so a restart
   orders nothing. A certificate is renewed with a third of its lifetime
   left; a failed renewal is retried hourly while the certificate in use is
   still valid.
8. `innsegl status` names the server certificate's source, names and expiry.
9. Tests never reach a real certificate authority. They run against a local
   ACME test server with a fake DNS.

## Alternatives considered

- **HTTP-01 or TLS-ALPN-01.** Needs the core reachable from the certificate
  authority, which a core on a private address is not.
- **A provider built into the code.** Ties every deployment to one provider.
- **A separate tool that writes the certificate, the core only reloading it.**
  One more part to run, update and watch.
- **Trusting the system's roots for every core.** Widens trust for the
  deployments that never asked for a public certificate.

## Consequences

- The DNS credential can edit the zone the core's name is in. It is kept
  like every other service credential, and scoped by the operator.
- A client of a core with a public certificate trusts every public root for
  that one name, as a browser does.
- The ACME library brings a large dependency set, for its many providers.
- The dashboard's certificate and the gateway's are ordered separately, so
  one renewal is two orders.
