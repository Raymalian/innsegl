# Gateway capture

## Purpose

The gateway is a reverse proxy in front of the model provider's API. It
records every agent's activity from the traffic itself, with independent
witnesses, instead of trusting a harness's own hooks (ADR-0057). It also
registers and ends runs from that traffic (ADR-0058) and serves the commit
path. It runs inside the one innsegl process (ADR-0060).

The gateway and the commit hook are how agents are recorded and how their
commits are signed. The MCP wire surface is deprecated (ADR-0077): it is
still served, and removed at the next major release.

## Commands

There is no `gateway` entry in the command table. It runs as a companion:

```
innsegl serve -also gateway            (compose default: -also seal,reconcile,reap,gateway)
```

Set `INNSEGL_MCP_ALSO` to change the companions. Empty in the Makefile leaves
the compose default alone.

## Settings

Read from the environment when the gateway starts (`cmd/innsegl/gateway.go`):

| Variable | Default | Meaning |
|---|---|---|
| `INNSEGL_GATEWAY_LISTEN` | `:8095` | listen address inside the container |
| `INNSEGL_GATEWAY_UPSTREAM` | the provider's API (`defaultGatewayUpstream`) | must be `https`; refused otherwise, no bypass |
| `INNSEGL_GATEWAY_SHUTDOWN_TIMEOUT` | `15s` | orderly shutdown bound |
| `INNSEGL_GATEWAY_RATE`, `INNSEGL_GATEWAY_BURST` | `20`, `100` | per-session rate limit (GW-013) |
| `INNSEGL_LEDGER_DSN` | unset | turns on the identity stack; unset means no identity guard |
| `INNSEGL_GATEWAY_BACKSTOP_INTERVAL` | `15m` | how often the silence backstop sweeps |
| `INNSEGL_GATEWAY_SILENCE_AFTER` | `168h` | silence after which the backstop ends a run |
| `INNSEGL_GATEWAY_SESSION_END_GRACE` | `3m` | grace after a session-end signal |
| `INNSEGL_IDENTITY_SECRET`, `INNSEGL_IDENTITY_SECRET_FILE` | unset | same secret as `serve`; keys `agent_message` digests |
| `INNSEGL_AGENT_MESSAGE_KEY_ID` | `gateway-v1` | names the derived message key |
| `INNSEGL_GATEWAY_CA_KEY_DIR` | required | the gateway CA's private key |
| `INNSEGL_GATEWAY_CA_CERT_DIR` | required | where the CA certificate is published |
| `INNSEGL_GATEWAY_CERT_NAMES` | empty | extra names (IP or DNS) on the server certificate |
| `INNSEGL_MCP_MESSAGE_KEY_DIR` | unset | where the derived message key is written for `innsegl api` |
| `INNSEGL_GATEWAY_CLIENT_AUTH` | empty | `spiffe` is hosted mode: every route needs an enrolled client certificate |
| `INNSEGL_GATEWAY_ACCOUNTS_DSN` | unset | accounts writer; required in hosted mode |
| `INNSEGL_GATEWAY_PORT` | `28095` | compose host port |
| `INNSEGL_GATEWAY_CA_HOST_DIR` | `~/.innsegl/ca` | host folder the CA certificate is published to |
| `INNSEGL_ACME` | `off` | `on`: the server certificate is publicly trusted, obtained through ACME DNS-01 (ADR-0081); the own CA otherwise |
| `INNSEGL_ACME_EMAIL` | required when on | the ACME account's contact |
| `INNSEGL_ACME_DIRECTORY` | the public CA's production directory | an ACME directory URL, `https` only; set the staging directory here to try it |
| `INNSEGL_ACME_ZONE` | required when on | the one DNS zone the DNS credential is for; every DNS name in `INNSEGL_GATEWAY_CERT_NAMES` must be in it |
| `INNSEGL_ACME_DNS_PROVIDER` | required when on | the DNS provider, by the name `internal/acme/providers.go` gives it (a set compiled in, plus `rfc2136`, `httpreq` and `exec`, which reach any DNS); each reads its own settings |
| `INNSEGL_ACME_DNS_CREDENTIAL_VAR` | required when on | the provider's own credential variable; the core sets its `_FILE` form to the stored credential |
| `INNSEGL_ACME_CREDENTIAL_DIR` | `/run/innsegl/credentials/acme-dns` | where the credential file `dns-token` is |
| `INNSEGL_ACME_STATE_DIR` | `/run/innsegl/acme` | the ACME account and both certificates |
| `INNSEGL_ACME_ROOTS_FILE` | unset | an extra root for reaching the ACME directory, for a local ACME test server |
| `INNSEGL_ACME_DNS_RESOLVERS` | the system's | `host:port` list the DNS-01 check asks, and only those, whether the record is out (a split-horizon or test DNS) |

With `INNSEGL_ACME=on` the core obtains two certificates for the DNS names
in `INNSEGL_GATEWAY_CERT_NAMES` (addresses are left out: a public
certificate names none), one for the gateway and one for the dashboard, each
with its own key. It renews each with a third of its lifetime left, checking
hourly, and swaps it in with no restart. A first order that fails never keeps
the core down: it serves its own CA's certificate, the status line says why,
and it tries again every 10 minutes. Hosted mode still requires a client
certificate from the deployment's own authority. `innsegl status` shows a
`server certificate` line: its source, names and expiry. Clients trust the
system's roots for a core with a public certificate once `innsegl connect`
(or `innsegl connect --update`) has recorded it ([client-and-connect.md](client-and-connect.md)).

## Files, volumes, containers

| Item | Holds |
|---|---|
| `innsegl-mcp` | runs the gateway; host port `${INNSEGL_BIND}:28095` |
| volume `innsegl-gateway-ca-key` | the gateway CA private key, mounted into the core only |
| host folder `~/.innsegl/ca` | the gateway CA certificate (public) |
| volume `innsegl-message-key` | derived agent-message key, read-only into `innsegl-api` |
| `gateway-snapshots` under the log dir | workspace snapshots, single-host shape only; the dashboard reads snapshots from the mirror, not from here |
| volume `innsegl-credential-acme-dns` | the ACME DNS credential, read-only; written by `make innsegl-acme-credential` |
| volume `innsegl-acme-state` | the ACME account and both certificates, read-write, this service only |
| `INNSEGL_MIRROR_DIR` (hosted) | the per-repository mirror: the `/_core/git/` push endpoint writes it, and a tool call's `workspace_tree_hash` is read from the snapshot ref its client pushed there ([commit-path.md](commit-path.md)) |

Routes on its listener: model traffic, `/_gateway/session-end`,
`/_gateway/session-workspace`, `/_gateway/commit-trailers`,
`/_gateway/commit-sign`, and in hosted mode the `/_core/...` routes
(enrol, renew, status, disconnect, journal, git, trust-backup, ca-custody,
operator-author, unrouted-session).

`/_core/status` lists the core's `/readyz` dependencies and reports as
components, the signing probe's `signing` among them
([signing-probe.md](signing-probe.md)); the client service reads it every
minute.

`/_core/unrouted-session` (RM-319) takes a machine's report of a session
whose model traffic bypassed innsegl: `POST {"session_id", "last_activity_at"}`,
behind the client guard, so the machine is the verified installation. It is
kept in `innsegl.unrouted_sessions` (migration 0022), one row per machine and
session, with the newest activity; no repository is stored. 204 kept, 400 not
a report, 401 no verified machine, 503 not kept (the client sends it again).

Guards run in order before anything is forwarded (`internal/gateway/guard.go`).
Refusal statuses: 400 unrecognised harness shape, 403 identity, 429 rate
limit. A hosted-mode client-certificate refusal is one identical 401.

## Exit codes and error classes

| Code | Meaning |
|---|---|
| 22 | UNAVAILABLE: the gateway could not start |
| 23 | FAILED: it was relaying and stopped on an error |

As a companion of `serve`, a failure here ends the process with `serve`'s codes.

## Tests

- `internal/gateway/*_test.go` (GW-001 to GW-019, GID-001 to GID-017,
  GREC-001 to GREC-007, SNAP-001 to SNAP-005, JRN-003 to JRN-007, OTW-001, TLS-001)
- `cmd/innsegl/gateway*_test.go` (GW-004, GW-007, GW-010, GW-011, GW-013,
  GID-009, GID-012, GREC-001 to GREC-007)
- `internal/acme/*_test.go` (TLS-004 to TLS-006, against a local ACME test
  server and a fake DNS, never a real CA), `cmd/innsegl/acmecert_test.go`
  (TLS-007 to TLS-009), `internal/client/coretrust_test.go` (TLS-010)
- `cmd/innsegl/exposure_test.go` (GW-015), `enrol_test.go` (GW-016 to GW-019)
- `internal/gateway/unrouted_test.go`, `cmd/innsegl/coreunrouted_test.go` (GW-020)
- `internal/mcp/gateway_test.go`, `gatewayrecord_test.go` (GID-001 to GID-004, GREC)
- `test/deploy/gatewaypublish_test.go`, `bindaddress_test.go` (GW-005),
  `gatewaydrain_test.go`

## Decisions

- [ADR-0057](../docs/adr/0057-capture-agent-activity-at-a-model-gateway-with-independent-witnesses.md) capture at a gateway
- [ADR-0058](../docs/adr/0058-an-agents-identity-lifecycle-is-driven-by-its-traffic.md) lifecycle driven by traffic
- [ADR-0060](../docs/adr/0060-the-gateway-runs-inside-the-one-innsegl-process.md) one process
- [ADR-0061](../docs/adr/0061-schema-version-4-records-forks-agent-messages-and-workspace-trees.md) schema 4 events
- [ADR-0063](../docs/adr/0063-the-core-runs-on-its-own-host-and-every-client-machine-holds-its-own-enrolled-certificate.md) hosted mode
- [ADR-0066](../docs/adr/0066-one-name-one-certificate.md) one name, one certificate
- [ADR-0081](../docs/adr/0081-the-core-can-serve-a-publicly-trusted-server-certificate-obtained-through-acme-dns-01.md) a public server certificate through ACME DNS-01
- [ADR-0069](../docs/adr/0069-claude-code-reaches-the-client-as-its-https-proxy.md) the client as proxy
- [ADR-0077](../docs/adr/0077-the-mcp-wire-surface-is-deprecated.md) the MCP wire surface is deprecated

## Runbooks

- [orchestrated-run.md](../runbooks/orchestrated-run.md)
