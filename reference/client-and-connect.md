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
in the checkout. That link is for the CLI only: the hooks, the client service
and scheduled jobs run the installed copy (below).

### The installed copy

Hooks run on every agent prompt and tool call, and the client service runs
with nobody watching. So they never run a build in a checkout, which any agent
working there can rebuild. They run `/usr/local/libexec/innsegl/innsegl`, owned
by root in a folder owned by root, on macOS and Linux (#599).

```sh
make build && make install-release && make client-restart
```

`make install-release` prints one line and, in a terminal, runs it (sudo asks
for the password):

```sh
sudo sh -c 'set -e; t=$(mktemp); …; cat <checkout>/innsegl > "$t"; echo "<sha256>  $t" | shasum -a 256 -c -; mkdir -p /usr/local/libexec/innsegl; chown 0:0 …; install -m 0755 "$t" …/.innsegl.new; …; mv -f …/.innsegl.new /usr/local/libexec/innsegl/innsegl'
```

It copies the build to a file of root's, checks the copy against the SHA-256
printed, and renames it into place, so a running service is never overwritten
under it. A build changed after the line was printed fails the check and
nothing is installed. On Linux the check is `sha256sum -c -`. Without a
terminal it prints the line, installs nothing and exits 3. The copy keeps the
signature `make build` gave it.

`innsegl connect` (enrolment and `--update`) names only a binary the user
cannot change: this binary, when it is owned by root and so is every folder
above it, or else the installed copy, when it holds this binary's bytes.
Otherwise it refuses before writing anything, says which file or folder the
user can change, and names `make install-release`. That holds whenever it
writes the system managed settings, which every session loads, or a client
service. Settings of your own (`--managed-settings <path>`) with
`--no-service` run nothing on their own and name this binary when no
installed copy of it is there. `--disconnect` is never refused for it.
`innsegl link` writes the same binary into a repository's git hooks, under
the same rule. A repository linked earlier, whose hooks name another binary,
is rewritten onto the installed copy the next time the session hook runs in
it; with no installed copy of this build there, its hooks stay as they are. `--update` also moves a client service that starts another
binary (an earlier connect's checkout build) onto the installed copy and
restarts it. `make build` says when the installed copy is another build; until
it is installed again, the hooks and the service run the old one.
`make client-restart` restarts a service that runs the installed copy of this
build, and leaves alone one that runs the installed copy of another.

Until #237 an older innsegl scheduled the ledger backup on the host
(LaunchAgent `dev.innsegl.backup-ledger`, or the systemd user timer of that
name), running `scripts/backup-ledger.sh` from the checkout. The backup now
runs in the deployment. `innsegl connect` names that job when it is still
installed, with the one command that removes it, and removes nothing itself.

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
| `-service` | with `--update`, also rewrite and reload the client service (rewritten without it when it starts another binary than the hooks run) |
| `-pause` / `-resume` | set the managed settings aside, or put them back |
| `-disconnect` | remove what connect wrote: settings keys, the service, `~/.innsegl/client`; asks you to confirm on the terminal (below) |

`innsegl client serve` takes only `-listen` (default: the address connect
wrote). `innsegl status` takes no flags.

A core whose server certificate is publicly trusted (ACME, ADR-0081) is
recorded in `core.json` as `"server_certificate": "public"`; the client then
trusts the system's roots for it as well as the core's own CA. `innsegl
connect` records it when it enrols, and `innsegl connect --update` checks it
again (restart the client service after a change). A core on its own CA is
trusted through that CA alone. `innsegl status` shows the core's `server
certificate` line.

`innsegl status` also prints a `mirror WARN` line for each branch the core's
mirror refused as a rewrite ([commit-path.md](commit-path.md)); a warning,
not an outage, so the exit status is unchanged.

`innsegl status` prints one line per part of the core: its readiness checks
(`spire`, `ledger`, `sigstore`) and its scheduled controls. The scheduled
WORM canary is `worm canary`: `up` with when it last passed, or `DOWN` with
the check that failed, `stale` (no run in twice the interval), or `no run
recorded` ([ledger-and-segments.md](ledger-and-segments.md)). The signing
probe is `signing`: when it fails, one line, `signing: FAILING since <time>
— <reason>`, counted as down ([signing-probe.md](signing-probe.md)). The
`sigstore` line means only that Fulcio and Rekor answer.

The client service reads the signing probe from the core every minute and
shows a desktop notification on the first failure of an outage, and a log
line; nothing more until signing has worked again. On macOS the notification
comes from Notification Centre; on Linux from `notify-send`, with the text as
arguments. Without `notify-send` nothing is shown, and the log says so once.
Elsewhere only the log line is written. `GET /_client/status` carries
the last reading as `signing` (`up`, `detail`, and while it fails `since` and
`reason`); it is absent before the first reading and while the core does not
answer. The commit hook reads it to say in a refusal since when signing is
down ([commit-path.md](commit-path.md)). It also carries `version`, the
build the service runs: `innsegl doctor` restarts a service whose build is
not its own ([doctor.md](doctor.md)).

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
| `hooks` | `innsegl hook pre-tool-use` (Bash), `innsegl hook post-tool-use` (every tool), `innsegl hook session` (session events); see [commit-path.md](commit-path.md). A machine connected before a hook was added gains it with `innsegl connect --update` |

Default managed-settings path: `/Library/Application Support/ClaudeCode/managed-settings.json`
on macOS, `/etc/claude-code/managed-settings.json` elsewhere
(`cmd/innsegl/connect.go:130`).

An innsegl hook entry is any command hook whose program is named `innsegl`,
at any path and whether or not the file is still there, followed by `hook
pre-tool-use`, `hook post-tool-use` or `hook session`. `connect` keeps one
entry per event, the one it writes for this binary, and removes every other
innsegl entry, saying each one it removes (an older binary's path, a
duplicate, an event it no longer uses). `--disconnect` removes every innsegl
entry. Hooks that are not innsegl's stay in place.

When this user cannot write the managed settings, connect stages the new file
in the temporary directory and prints one command to run as an administrator:

```sh
sudo sh -c 'set -e; t=$(mktemp); …; cat <staged> > "$t"; echo "<sha256>  $t" | shasum -a 256 -c -; mkdir -p <dir>; install -m 0644 "$t" <managed-settings>'
```

It copies the staged file to a temporary file owned by root, checks that copy
against the SHA-256 the file had when staged, and installs only that copy. A
staged file changed after staging fails the check and nothing is installed.
On Linux the check is `sha256sum -c -`.

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
| `session-processes.json` | the harness process of each watched session |
| `client.sock` | the CLI socket (0600; the folder is 0700): the CLI's calls to the core, and the service's status (below) |
| `unrouted-sessions.json` | sessions whose model traffic bypassed innsegl (below) |
| `age-plugins.json` | each pinned age plugin: name, absolute path, SHA-256 (below) |

Also `~/.innsegl/trust-backups/` and `~/.innsegl/trust-backup/identity.txt`
(see [trust-key-backup.md](trust-key-backup.md)).

The user service: LaunchAgent `dev.innsegl.client` on macOS, systemd user
unit `innsegl-client.service` on Linux (`internal/client/service.go`). Its
log: `~/Library/Logs/innsegl-client.log` on macOS; `journalctl --user -u
innsegl-client.service` on Linux.

The service unlocks the CA key store itself (ADR-0076), with the age plugin
the identity file names (`age-plugin-<name>`).

**The plugin is pinned.** `innsegl connect` (enrolment and `--update`)
resolves each plugin once, on its own PATH, to an absolute path with symlinks
resolved, and records that path and the file's SHA-256 in
`~/.innsegl/client/age-plugins.json`. Every use runs the plugin only while all
of these hold, and checks them again just before the plugin starts: the CLI's
`ca-custody unlock`, `trust-backup drill`, `doctor`, and the service's own
unlock.

- PATH still finds the pinned file, not another copy.
- Neither the file nor its directory is writable by group or others.
- Both are owned by root or this user.
- The hash is unchanged.

Otherwise the plugin is refused with the reason and the repair: check that
it is the plugin you installed, then run `innsegl connect --update`. Connect
also refuses to pin a plugin that fails these checks, and names it. A plain
X25519 identity needs no pin.

age finds a plugin by name on PATH only. So the service's PATH stays: a
service manager gives a short default (launchd: `/usr/bin:/bin:/usr/sbin:/sbin`),
and connect adds the pinned file's own directory after it, not the shared bin
directory that links to it (`EnvironmentVariables` in the plist,
`Environment="PATH=…"` in the unit). It writes no PATH when the default already
finds every plugin. When `--update` finds a plugin in a new directory (an
upgrade), it rewrites and restarts the installed service itself.

### Host dependencies

`innsegl connect` (enrolment and `--update`) checks the host first and names
everything missing in one run, each with one install command for this OS. It
installs nothing. A missing required tool stops it before anything is
written. `innsegl doctor`'s first line is the same check: `host: ok`, or one
`host: MISSING` line per tool. The core host's tools are checked by
`install.sh` ([stack-and-make.md](stack-and-make.md)).

| Tool | Needed for | macOS | Debian/Ubuntu | Fedora |
|---|---|---|---|---|
| git 2.31 or later | hooks, linking, signing (required) | `xcode-select --install` | `sudo apt-get install -y git` | `sudo dnf install -y git` |
| `age-plugin-<name>` named in the identity file | the CA unlock and backup restore | `brew install age-plugin-se` | `cargo install age-plugin-yubikey` | `cargo install age-plugin-yubikey` |
| `notify-send` | the signing-down notification (optional) | — | `sudo apt-get install -y libnotify-bin` | `sudo dnf install -y libnotify` |

A Secure Enclave identity (`age-plugin-se`) works on macOS only. A missing
or refused plugin does not stop connect: it is named, and the CA unlock fails
until it is installed and pinned.

Local routes: on the loopback TCP address, `GET /_client/status` and the
harness's traffic; on the CLI socket, `GET /_client/status` and
`/_client/core/<core path>` (below). Core routes it calls: `/_core/enrol`, `/_core/renew`,
`/_core/status`, `/_core/disconnect`, `/_core/journal`, `/_core/git/`,
`/_core/trust-backup`, `/_core/ca-custody`, `/_core/operator-author`,
`/_core/unrouted-session`.

The certificate is renewed at half-life.

### Sessions that bypass innsegl

The service never locks the machine down, so a session can reach the
provider without passing through it (its own base URL, a proxy setting left
out). Once a minute it reads the harness's transcripts
(`$CLAUDE_CONFIG_DIR/projects`, else `~/.claude/projects`) changed since it
started. A session with model replies there since the service started, in a
repository innsegl records (one with an origin), whose model traffic never
reached the service, is a finding (RM-319). It is kept in
`unrouted-sessions.json`, shown in `GET /_client/status` as
`unrouted_sessions`, and reported to the core at `/_core/unrouted-session`,
again whenever its activity moves on; a report the core does not take is
sent again later. `innsegl status` prints one `unrouted WARN` line for each,
naming the session, its repository and its last activity. It does not change
the exit status, and nothing is refused: the remedy is to start the session
again after `innsegl connect`. A session outside any repository is not a
finding. The dashboard overview lists the findings
([dashboard-api.md](dashboard-api.md)).

### The CLI reaches the core through the service

`innsegl status`, `ca-custody`, `trust-backup fetch`, `author` and
`connect --disconnect` never dial the core. They send their calls to the
client service on its CLI socket, `~/.innsegl/client/client.sock`, under
`/_client/core`, and the service sends them on over its own certificate
(`internal/client/corepass.go`, `socket.go`). On macOS a binary started from
a terminal without the Local Network permission cannot reach a core on the
LAN ("no route to host"); the launchd service can.

Only the service's own user may use the socket (#600). The folder is 0700
and the socket 0600, and the service asks the kernel for each caller's uid
(`LOCAL_PEERCRED` on macOS, `SO_PEERCRED` on Linux). A connection from any
other uid is closed before a byte is read, and the service's log says so
(CLI-043). The loopback TCP address no longer passes these calls: a
`/_client/core` request there gets 410 naming the socket, and the core is
not asked (CLI-044). The harness's traffic, the hooks and git stay on the
TCP address, and so does `GET /_client/status`, which the hooks read.
`innsegl doctor` and `innsegl status` read the service's status on the
socket. A socket the service cannot open is said in its log; the TCP
address serves on.

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
| the service does not answer | the client service is not answering at `<socket>`; start it: `launchctl kickstart -k gui/$(id -u)/dev.innsegl.client` (macOS) or `systemctl --user restart innsegl-client.service` |
| the service predates this route (the binary was rebuilt, the service not restarted) | the client service is older than this command; restart it so it runs this build (the same command), or `make client-restart` |
| the service could not reach the core | the core did not answer the client service |
| the core does not know a route or method (405, or a path its gateway refuses as an unrecognised harness shape) | the core is older than this client; update the core |

`connect --disconnect` alone dials the core itself when the service is down
or older: a disconnect is the last thing the machine does with its key and
must not depend on the service it removes. Where that dial is refused too, it
says to revoke the machine from the Account page.

### Disconnect asks the person at the machine

On an enrolled machine, `connect --disconnect` revokes the installation on
the core, so it first asks for the person at the machine (CLI-045). innsegl
has no Touch ID prompt of its own, so this is a typed confirmation: it opens
the terminal (`/dev/tty`) directly, says which installation on which core it
revokes, and goes on only when `disconnect` is typed. A process without a
terminal (an agent's shell, a pipe) cannot answer it. Anything else, or no
terminal, changes nothing: the command says so and exits 24.

## Exit codes and error classes

| Command | Code | Meaning |
|---|---|---|
| `connect` | 24 | enrolment or a settings change failed, or this binary is one the user can change and no installed copy of it is there |
| `make install-release` | 3 | not installed: no terminal to ask for sudo in; the line is printed |
| `client serve` | 25 | the service could not run |
| `status` | 1 | something is down; the output names it. With the client service down, both it and the core are down: the core is asked through it |

## Tests

- `cmd/innsegl/connect_test.go` (EGR-001, ENF-006), `connectmode_test.go`
  (BAK-025), `connectsudo_test.go`
- `cmd/innsegl/enrol_test.go` (GW-016 to GW-019, KEY-001 to KEY-005, SPI-020)
- `cmd/innsegl/twomachine_test.go` (OPS-174): a second machine, the shipped
  binary under a home of its own, enrols, works through `innsegl client
  serve` and `innsegl status`, and is refused with 401 on requests and
  renewal once revoked
- `cmd/innsegl/clientcore_test.go` (OPS-176): the same client and core in one process
- `cmd/innsegl/sealcanary_test.go` (OPS-172, PROPOSED: the canary's line in status)
- `cmd/innsegl/clientserve_test.go`, `status_test.go` (CLI-019, PROPOSED),
  `disconnect_core_test.go`, `clientjournal_test.go`, `connect_test.go`
  (CLI-020, PROPOSED), `authorcli_test.go` (ENF-016, PROPOSED)
- `internal/client/*_test.go` (JRN-002, JRN-008, JRN-009, BAK-025 to BAK-028);
  `corepass_test.go` (CLI-017 to CLI-019, PROPOSED: the pass-through over a
  real socket, its refusals, and what the CLI says);
  `socket_test.go` (CLI-043, CLI-044, PROPOSED: another uid refused by the
  kernel's peer credentials; the TCP pass-through gone; the socket serves
  only the CLI)
- `cmd/innsegl/disconnectpresence_test.go` (CLI-045, PROPOSED: disconnect
  asks the person on the terminal, and changes nothing without them)
  `operatorauthor_test.go` (ENF-016, PROPOSED)
- `scripts/codesign-cli-selftest.sh` (OPS-169, PROPOSED),
  `scripts/client-restart-selftest.sh` (OPS-170, PROPOSED),
  `scripts/link-bin-selftest.sh` (OPS-171, PROPOSED)
- `internal/clientjournal/entry_test.go` (JRN-001)
- `internal/client/unrouted_test.go`, `cmd/innsegl/status_test.go` (HAR-022)
- `internal/client/signingwatch_test.go`, `cmd/innsegl/status_test.go` (SIG-015, PROPOSED)
- `internal/accounts/enrol_test.go` (KEY-001 to KEY-005)
- `internal/client/hostos_test.go` (CLI-024, CLI-026, PROPOSED: the log hint
  per OS; `notify-send` on Linux, and said once when it is absent)
- `internal/client/servicepath_test.go`, `cmd/innsegl/connectpath_test.go`
  (CLI-025, PROPOSED: the plugin's directory in the service's PATH)
- `internal/trustbackup/pin_test.go`, `internal/client/servicepath_test.go`,
  `cmd/innsegl/connectpath_test.go` (CLI-046, CLI-047, PROPOSED: a plugin
  writable by others, changed, or not the one PATH finds is refused with the
  repair; `--update` pins it again)
- `internal/hostdeps/hostdeps_test.go`, `cmd/innsegl/preflight_test.go`
  (CLI-027, PROPOSED: every missing tool named in one run, with this OS's
  command; connect refuses before writing anything)
- `cmd/innsegl/connectrelease_test.go`, `linkrelease_test.go` (CLI-041, CLI-042, PROPOSED: connect and link
  refuses a binary the user can change unless the installed copy holds it;
  hooks, plist and unit name the installed copy; `--update` moves the service
  onto it; the leftover host backup job is named with its removal)
- `scripts/install-release-selftest.sh` (OPS-211, PROPOSED: one hash-checked
  sudo line, a changed build refused, nothing run without a terminal);
  `scripts/client-restart-selftest.sh` (OPS-170h, PROPOSED: the installed
  copy of this build counts as it)
- `internal/client/settingshooks_test.go` (CLI-034, CLI-035, CLI-036,
  PROPOSED: connect replaces stale innsegl hook entries and keeps foreign
  ones; disconnect removes every innsegl entry; the administrator command
  refuses a staged file changed after staging)

## Decisions

- [ADR-0063](../docs/adr/0063-the-core-runs-on-its-own-host-and-every-client-machine-holds-its-own-enrolled-certificate.md) enrolled client certificates
- [ADR-0064](../docs/adr/0064-the-client-derives-the-workspace-and-the-core-binds-it-to-the-installations-scope.md) workspace and scope
- [ADR-0065](../docs/adr/0065-a-per-repository-mirror-on-the-core-is-the-evidence-store.md) the mirror clients push to
- [ADR-0066](../docs/adr/0066-one-name-one-certificate.md) one name, one certificate
- [ADR-0068](../docs/adr/0068-the-client-journals-what-the-core-cannot-record-the-core-imports-it.md) the client journal
- [ADR-0069](../docs/adr/0069-claude-code-reaches-the-client-as-its-https-proxy.md) the client as HTTPS proxy

## Runbooks

- [client-update.md](../runbooks/client-update.md): update the client on a
  machine — `git pull && make build && make install-release && make client-restart`,
  in the checkout (or `make -C <checkout> …`). `make build` links the binary as
  `~/.local/bin/innsegl`, so `innsegl status` runs by name once
  `~/.local/bin` is on PATH.
- [cutover.md](../runbooks/cutover.md)
