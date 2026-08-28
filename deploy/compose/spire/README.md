# Reference SPIRE compose stack

The three SPIRE services of doc 05 §1, wired the way that document requires:
`spire-server` (trust domain `innsegl.dev`), `spire-agent` (node and workload
attestation) and `spire-oidc` (the JWT-SVID → OIDC bridge Fulcio validates
against). Built by RM-014 (#22).

Everything here is configuration and its reasoning; the reasoning lives next to
the setting it explains, so read `../spire.yml`, `server.conf`, `agent.conf`,
`oidc-discovery-provider.conf` and `bootstrap.sh` rather than a summary of them.
[ADR-0011](../../../docs/adr/0011-compose-spire-admin-api-segmentation.md)
records the admin-API segmentation decision and the part of it SPIRE will not
give us.

## Run it

```sh
make spire-up          # or, without make:
docker compose -f deploy/compose/spire.yml up -d
deploy/compose/spire/register.sh
```

`up` is enough to get a healthy server and agent. `register.sh` creates the one
bootstrap registration entry the stack needs — `spire-oidc`'s own identity —
without which the discovery provider has no JWKS to publish. It is idempotent.

Then:

```sh
curl -s http://127.0.0.1:8443/.well-known/openid-configuration
curl -s http://127.0.0.1:8443/keys
```

Both must answer, and `/keys` must contain a key. That is the readiness probe
for `spire-oidc`: it has no container healthcheck because the image is
distroless (no shell, no HTTP client) and the provider's own `/ready` listener
binds localhost by design, so no sibling container can reach it either. Probing
over HTTP from outside is how Fulcio will probe it, which makes it the only
probe whose answer means anything.

## Prove it issues an SVID

```sh
make spire-verify      # or: deploy/compose/spire/verify.sh
```

Registers a run, starts a workload carrying that run's selectors, fetches the
SVID, asserts the SPIFFE ID is
`spiffe://innsegl.dev/agent/{agent-type}/{task-id}/{run-id}`, then deletes the
entry and waits for the agent to converge on refusing it. Exit status is the
verdict.

Note what that last step measures: SPIRE's refusal after `entry delete` is
*eventual* — the deleted entry has to fall out of the server's cache and then
the agent's, and for a few seconds the agent still serves the SVID it already
minted. IP §6.2's "retirement is effective immediately" is therefore an
obligation on the MCP ("no cached-credential grace path *through the MCP*"),
not something SPIRE provides. RM-015 (#23) owns it; this script measures the
floor it has to sit on.

## Tear it down

```sh
make spire-down        # or:
docker compose -f deploy/compose/spire.yml --profile verify down -v
```

`-v` removes the volumes, including the bootstrap PKI. The next `up` generates a
fresh trust domain root and a fresh agent identity, so every registration entry
from the old stack is gone with it — which is correct, and is why `down` without
`-v` is the right command when you want to keep a stack across a reboot.

## What is not here

- **Fulcio, Rekor, Postgres, MinIO, and the built `innsegl-*` services.** They
  are the rest of doc 05 §1 and other issues' files. This file declares the
  networks and volumes they attach to; see the membership rules written at each
  declaration in `../spire.yml`.
- **Per-run registration entries.** Doc 01 §1: one entry per run, short TTL,
  created at registration and deleted at retirement — by the MCP, over the admin
  API. That lifecycle is `internal/spire` (RM-015, #23); `register.sh` creates
  infrastructure entries only and must not grow a path that creates a run entry.
- ~~**Admin scoping to the `/agent/` subtree.**~~ Landed with RM-015 (#23):
  `authz-policy.rego` plus `authz-policy-data.json`, wired at
  `server.experimental.auth_opa_policy_engine`. It narrows what an admin SPIFFE
  ID may call and requires every entry it creates or updates to be a
  `spiffe://innsegl.dev/agent/{type}/{task}/{run}`. The local socket keeps full
  admin (ADR-0011's tmpfs is what contains it), and `BatchDeleteEntry` cannot be
  scoped at all — both stated in
  [ADR-0012](../../../docs/adr/0012-scope-the-mcp-admin-credential-with-an-opa-authorization-policy.md).
  **On a SPIRE version bump, re-copy `authz-policy-data.json` from the matching
  upstream tag and re-run TC-SPI:** an RPC missing from that table is denied to
  every caller.
- **TLS in front of `spire-oidc`.** All of `.dev` is HSTS-preloaded (doc 05 §3),
  so the production deployment must terminate TLS ahead of it. Compose serves
  plain HTTP on loopback and says so in two places
  (`allow_insecure_scheme` + `insecure_addr`) so neither can be enabled quietly.

## Compose defaults vs shipped defaults

Doc 05 §1 asks the compose README to state one asymmetry explicitly: the compose
stack uses **local** Fulcio/Rekor so CI needs no network. As of
[ADR-0010](../../../docs/adr/0010-self-hosted-sigstore-is-the-shipped-default.md)
the *installed product* default is self-hosted too, so the asymmetry doc 05 §1
was written against — local in compose, public Sigstore when installed — no
longer exists. Public Sigstore is now the configured-in option, "where an
accepted issuer already exists". Doc 05 §1's table still describes the old
default; that is a spec edit for a human, not something an implementing agent
may make.
