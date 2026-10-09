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

## Files, volumes, containers

| Item | Holds |
|---|---|
| `innsegl-mcp` | runs the gateway; host port `${INNSEGL_BIND}:28095` |
| volume `innsegl-gateway-ca-key` | the gateway CA private key, mounted into the core only |
| host folder `~/.innsegl/ca` | the gateway CA certificate (public) |
| volume `innsegl-message-key` | derived agent-message key, read-only into `innsegl-api` |
| `gateway-snapshots` under the log dir | workspace snapshots |

Routes on its listener: model traffic, `/_gateway/session-end`,
`/_gateway/session-workspace`, `/_gateway/commit-trailers`,
`/_gateway/commit-sign`, and in hosted mode the `/_core/...` routes
(enrol, renew, status, disconnect, journal, git, trust-backup, ca-custody).

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
- `cmd/innsegl/exposure_test.go` (GW-015), `enrol_test.go` (GW-016 to GW-019)
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
- [ADR-0069](../docs/adr/0069-claude-code-reaches-the-client-as-its-https-proxy.md) the client as proxy
- [ADR-0077](../docs/adr/0077-the-mcp-wire-surface-is-deprecated.md) the MCP wire surface is deprecated

## Runbooks

- [orchestrated-run.md](../runbooks/orchestrated-run.md)
