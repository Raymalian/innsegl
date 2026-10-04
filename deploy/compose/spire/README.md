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
curl -s http://127.0.0.1:28443/.well-known/openid-configuration
curl -s http://127.0.0.1:28443/keys
```

Both must answer, and `/keys` must contain a key. That is the readiness probe
for `spire-oidc`: it has no container healthcheck because the image is
distroless (no shell, no HTTP client) and the provider's own `/ready` listener
binds localhost by design, so no sibling container can reach it either. Probing
over HTTP from outside is how Fulcio will probe it, which makes it the only
probe whose answer means anything.

## Prove a run's identity is not issued to a workload

```sh
make spire-verify      # or: deploy/compose/spire/verify.sh
```

Registers a run the way `register_agent` does, with one selector,
`innsegl:run:<run_id>`, of a type no workload attestor emits (ADR-0053). Then
starts a workload carrying that run's three `dev.innsegl.*` labels and the
Workload API socket, and asserts it is NOT issued
`spiffe://innsegl.dev/agent/{agent-type}/{task-id}/{run-id}`. A control
identity on the same workload's labels, outside the agent subtree, must be
issued first, so the refusal cannot pass because the stack issues nothing.
Exit status is the verdict.

A run's credential has one path: the MCP's `get_credential`, which mints
through the admin API and writes a ledger event.

## Tear it down

```sh
make spire-down        # or:
docker compose -f deploy/compose/spire.yml --profile verify down -v
```

`-v` removes the volumes, including the bootstrap PKI. The next `up` generates a
fresh trust domain root and a fresh agent identity, so every registration entry
from the old stack is gone with it — which is correct, and is why `down` without
`-v` is the right command when you want to keep a stack across a reboot.

## The test overlay beside this file

`../spire-testscope.yml` is a compose overlay used only by the Go test suite. It
renames the project, every container and every network to
`innsegl-<suite>test-<pid>` so that two test processes never drive the same
SPIRE (RM-065, #81;
[ADR-0022](../../../docs/adr/0022-a-compose-project-per-test-process-for-the-shipped-spire-stack.md)).

It changes nothing else, it is never applied by anything above, and `spire.yml`
is unchanged by its existence — the commands in this README behave exactly as
they always have. Applying the overlay without setting
`INNSEGL_SPIRE_TEST_STACK` is a deliberate compose error rather than a stack
under a shared name.

## What is not here

- **Fulcio, Rekor, Postgres, the object store, and the built `innsegl-*` services.** They
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
  Since #476 the admin may also call `MintX509SVID`, but only for a client
  certificate: one URI SAN `spiffe://innsegl.dev/client/<32 hex>`, nothing
  else in the request, at most 24 hours (ADR-0012's amendment, ADR-0063).
  `MintJWTSVID` stays limited to agent runs, so a client can never sign.
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
