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

`innsegl` by name is `~/.local/bin/innsegl`, the link `make build` makes to
the checkout's `./innsegl`; with `~/.local/bin` not on PATH, run `./innsegl`
in the checkout.

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

`innsegl status` prints one line per part of the core: its readiness checks
(`spire`, `ledger`, `sigstore`) and its scheduled controls. The scheduled
WORM canary is `worm canary`: `up` with when it last passed, or `DOWN` with
the check that failed, `stale` (no run in twice the interval), or `no run
recorded` ([ledger-and-segments.md](ledger-and-segments.md)).

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

Local routes: `GET /_client/status`, and `/_client/core/<core path>` for the
CLI (below). Core routes it calls: `/_core/enrol`, `/_core/renew`,
`/_core/status`, `/_core/disconnect`, `/_core/journal`, `/_core/git/`,
`/_core/trust-backup`, `/_core/ca-custody`, `/_core/operator-author`.

The certificate is renewed at half-life.

### The CLI reaches the core through the service

`innsegl status`, `ca-custody`, `trust-backup fetch`, `author` and
`connect --disconnect` never dial the core. They send their calls to the
client service on its loopback address, under `/_client/core`, and the
service sends them on over its own certificate (`internal/client/corepass.go`).
On macOS a binary started from a terminal without the Local Network
permission cannot reach a core on the LAN ("no route to host"); the launchd
service can, and loopback is never "local network".

The service passes exactly these, and refuses anything else itself, without
asking the core (CLI-018):

| Method | Core path | Used by |
|---|---|---|
| GET | `/_core/status` | `status` |
| GET | `/_core/ca-custody`, `/_core/ca-custody/material` | `ca-custody status`, `ca-custody unlock` |
| POST | `/_core/ca-custody/unlock` | `ca-custody unlock` |
| GET | `/_core/trust-backup`, `/_core/trust-backup/latest` | `trust-backup fetch` |
| GET, POST | `/_core/operator-author` | `author` |
| POST | `/_core/disconnect` | `connect --disconnect` |

A call names its installation (`X-Innsegl-Installation`, from `core.json`);
the service refuses one for another installation (409), and a revoked
installation's service refuses every call (403). Every answer it gives
carries `X-Innsegl-Client-Pass`.

What the CLI says when the way is not there:

| Situation | The CLI says |
|---|---|
| the service does not answer | the client service is not answering at `<addr>`; start it: `launchctl kickstart -k gui/$(id -u)/dev.innsegl.client` (macOS) or `systemctl --user restart innsegl-client.service` |
| the service predates this route (the binary was rebuilt, the service not restarted) | the client service is older than this command; restart it so it runs this build (the same command), or `make client-restart` |
| the service could not reach the core | the core did not answer the client service |
| the core does not know a route or method (405, or a path its gateway refuses as an unrecognised harness shape) | the core is older than this client; update the core |

`connect --disconnect` alone dials the core itself when the service is down
or older: a disconnect is the last thing the machine does with its key and
must not depend on the service it removes. Where that dial is refused too, it
says to revoke the machine from the Account page.

## Exit codes and error classes

| Command | Code | Meaning |
|---|---|---|
| `connect` | 24 | enrolment or a settings change failed |
| `client serve` | 25 | the service could not run |
| `status` | 1 | something is down; the output names it. With the client service down, both it and the core are down: the core is asked through it |

## Tests

- `cmd/innsegl/connect_test.go` (EGR-001, ENF-006), `connectmode_test.go`
  (BAK-025), `connectsudo_test.go`
- `cmd/innsegl/enrol_test.go` (GW-016 to GW-019, KEY-001 to KEY-005, SPI-020)
- `cmd/innsegl/sealcanary_test.go` (OPS-172, PROPOSED: the canary's line in status)
- `cmd/innsegl/clientserve_test.go`, `status_test.go` (CLI-019, PROPOSED),
  `disconnect_core_test.go`, `clientjournal_test.go`, `connect_test.go`
  (CLI-020, PROPOSED), `authorcli_test.go` (ENF-016, PROPOSED)
- `internal/client/*_test.go` (JRN-002, JRN-008, JRN-009, BAK-025 to BAK-028);
  `corepass_test.go` (CLI-017 to CLI-019, PROPOSED: the pass-through over a
  real loopback listener, its refusals, and what the CLI says);
  `operatorauthor_test.go` (ENF-016, PROPOSED)
- `scripts/codesign-cli-selftest.sh` (OPS-169, PROPOSED),
  `scripts/client-restart-selftest.sh` (OPS-170, PROPOSED),
  `scripts/link-bin-selftest.sh` (OPS-171, PROPOSED)
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

- [client-update.md](../runbooks/client-update.md): update the client on a
  machine — `git pull && make build && make client-restart`, in the checkout
  (or `make -C <checkout> …`). `make build` links the binary as
  `~/.local/bin/innsegl`, so `innsegl status` runs by name once
  `~/.local/bin` is on PATH.
- [cutover.md](../runbooks/cutover.md)
