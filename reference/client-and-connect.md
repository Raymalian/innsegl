# Client service and connect

## Purpose

A client machine enrols with a core once (`innsegl connect`). After that a
user service, `innsegl client serve`, holds the machine's certificate and
forwards the harness's, the hooks' and git's requests to the core over it
(ADR-0063). `innsegl status` says what is up and down.

## Commands

```
innsegl connect <core-url> --token <ie_…> (--ca <file> | --ca-fingerprint sha256:<hex>)
                [--hardened] [--name <n>] [--listen 127.0.0.1:28195] [--managed-settings <path>] [--no-service] [DIR…]
innsegl connect --update [--hardened] [--managed-settings <path>]
innsegl connect --pause | --resume | --disconnect [--managed-settings <path>]
innsegl client serve [--listen 127.0.0.1:28195]
innsegl status
```

`innsegl connect` flags:

| Flag | Meaning |
|---|---|
| `-token` | the single-use enrolment token (`ie_…`), from `innsegl accounts enrol-token` |
| `-ca` | a file holding the core's CA certificate |
| `-ca-fingerprint` | the core CA's `sha256:<hex>`; the CA is fetched once and checked against it |
| `-name` | this installation's display name (default: the host name) |
| `-listen` | loopback address of the client service (default `127.0.0.1:28195`) |
| `-managed-settings` | write the harness's managed settings here instead of the system path |
| `-hardened` | also lock the harness down: managed hooks only, bypass mode off, the sandbox |
| `-egress-control` | with `--hardened`, limit the sandbox's network to the hosts in this file |
| `-no-service` | do not install or remove the user service |
| `-update` | rewrite this machine's managed settings to the chosen mode; no token |
| `-service` | with `--update`, also rewrite and reload the client service |
| `-pause` / `-resume` | set the managed settings aside, or put them back |
| `-disconnect` | remove what connect wrote: settings keys, the service, `~/.innsegl/client` |

`innsegl client serve` takes only `-listen` (default: the address connect
wrote). `innsegl status` takes no flags.

## Settings

The managed settings connect writes point the harness at the client service
(`internal/client/settings.go`):

| Key | Value |
|---|---|
| `INNSEGL_CORE_URL` | the client service's local URL |
| `HTTPS_PROXY`, `HTTP_PROXY` (both spellings) | the same URL; the client is the harness's HTTPS proxy (ADR-0069) |
| `NO_PROXY` | `127.0.0.1,localhost,::1` |
| `NODE_EXTRA_CA_CERTS` | the client's proxy CA |
| `OTEL_*`, `CLAUDE_CODE_ENABLE_TELEMETRY` | telemetry sent to the client service |
| provider switches | pinned to `0` so traffic goes through the recorded API |

Default managed-settings path: `/Library/Application Support/ClaudeCode/managed-settings.json`
on macOS, `/etc/claude-code/managed-settings.json` elsewhere
(`cmd/innsegl/connect.go:130`).

## Files, volumes, containers

Under `~/.innsegl/client/` (`internal/client/files.go:50`):

| File | Holds |
|---|---|
| `key.pem`, `cert.pem`, `bundle.pem` | the machine's key, certificate and trust bundle |
| `gateway-ca.pem` | the core's gateway CA |
| `core.json` | core URL, installation id, listen address, provider URL |
| `revoked` | present when the core revoked this installation |
| `outbox/` | the signed client journal, for what the core could not record (ADR-0068) |
| `proxy-ca.pem`, `proxy-ca-key.pem` | the local proxy CA |

Also `~/.innsegl/trust-backups/` and `~/.innsegl/trust-backup/identity.txt`
(see [trust-key-backup.md](trust-key-backup.md)).

The user service: LaunchAgent `dev.innsegl.client` on macOS, systemd user
unit `innsegl-client.service` on Linux (`internal/client/service.go`).

Local routes: `GET /_client/status`. Core routes it calls: `/_core/enrol`,
`/_core/renew`, `/_core/status`, `/_core/disconnect`, `/_core/journal`,
`/_core/git/`, `/_core/trust-backup`, `/_core/ca-custody`.

The certificate is renewed at half-life.

## Exit codes and error classes

| Command | Code | Meaning |
|---|---|---|
| `connect` | 24 | enrolment or a settings change failed |
| `client serve` | 25 | the service could not run |
| `status` | 1 | something is down; the output names it |

## Tests

- `cmd/innsegl/connect_test.go` (EGR-001, ENF-006), `connectmode_test.go`
  (BAK-025), `connectsudo_test.go`
- `cmd/innsegl/enrol_test.go` (GW-016 to GW-019, KEY-001 to KEY-005, SPI-020)
- `cmd/innsegl/clientserve_test.go`, `status_test.go`, `disconnect_core_test.go`,
  `clientjournal_test.go`
- `internal/client/*_test.go` (JRN-002, JRN-008, JRN-009, BAK-025 to BAK-028)
- `internal/clientjournal/entry_test.go` (JRN-001)
- `internal/accounts/enrol_test.go` (KEY-001 to KEY-005)

## Decisions

- [ADR-0063](../docs/adr/0063-the-core-runs-on-its-own-host-and-every-client-machine-holds-its-own-enrolled-certificate.md) enrolled client certificates
- [ADR-0064](../docs/adr/0064-the-client-derives-the-workspace-and-the-core-binds-it-to-the-installations-scope.md) workspace and scope
- [ADR-0065](../docs/adr/0065-a-per-repository-mirror-on-the-core-is-the-evidence-store.md) the mirror clients push to
- [ADR-0066](../docs/adr/0066-one-name-one-certificate.md) one name, one certificate
- [ADR-0068](../docs/adr/0068-the-client-journals-what-the-core-cannot-record-the-core-imports-it.md) the client journal
- [ADR-0069](../docs/adr/0069-claude-code-reaches-the-client-as-its-https-proxy.md) the client as HTTPS proxy

## Runbooks

- [cutover.md](../runbooks/cutover.md)
