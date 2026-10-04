# innsegl

Innsegl records what AI agents do from their own model traffic, gives each
agent run a short-lived identity, and signs the commits an agent makes under
that identity: an attested SPIFFE workload, a short-lived Fulcio
certificate, and a Rekor transparency-log entry, so anyone can verify who —
or what — made a commit with no access to innsegl's own database. It ships
its own self-hosted Fulcio and Rekor by default
([ADR-0010](docs/adr/0010-self-hosted-sigstore-is-the-shipped-default.md)),
so no account and no third-party service is required. A dashboard shows the
resulting ledger.

## Quickstart

On the host that runs the core:

```sh
git clone https://github.com/Raymalian/innsegl.git
cd innsegl
./install.sh ~/path/to/project
```

That checks the prerequisites, brings the stack up, builds the binary, and
installs the commit hook in `~/path/to/project`.
The core mounts no project folder: it reads each repository from its own
mirror, which a connected machine pushes to.
It prints the dashboard's address and, while no account exists, a one-time
setup link.

Then connect each machine that runs agents — this one too. Sign in to the
dashboard, open **Account**, choose **Connect a machine**, and run the
command it shows on that machine:

```sh
innsegl connect https://<core-name>:28095 --token <ie_…> --ca-fingerprint sha256:<hex> ~/path/to/project
```

The token is single use and lives 15 minutes. `--ca-fingerprint` fetches
the core's CA once and checks it; `--ca <file>` gives the CA file instead.
Without one of the two, `connect` refuses: the core is never trusted on
first use. `--hardened` also locks the harness down, and `--egress-control
<file>` with it limits the sandbox's network to the hosts in a file. A token
can also be minted on the core with `innsegl accounts enrol-token …`.

## What gets installed where

On the core host, by `install.sh`:

| | |
|---|---|
| the stack | Docker containers, via `make start` — SPIRE, self-hosted Sigstore, and innsegl itself |
| each `DIR` argument | its `prepare-commit-msg` hook, the same as `innsegl link <dir>` (or `make link DIR=<dir>`) |

`install.sh` writes no Claude Code settings. Those are `innsegl connect`'s,
on every machine. Nothing is put on PATH for signing: an agent's commits are
signed through the gateway, and a human commits with plain git.

On a machine, by `innsegl connect`:

| | |
|---|---|
| `~/.innsegl/client/` | the machine's key (`key.pem`, mode 0600), its certificate, the trust bundle, the core's CA, the client's proxy CA and `core.json`. The sandbox denies `~/.innsegl` to an agent's shell, so an agent cannot read the key |
| the client service | `innsegl client serve`, a LaunchAgent (macOS, `~/Library/LaunchAgents/dev.innsegl.client.plist`) or a systemd user unit (Linux, `innsegl-client.service`). It listens on `127.0.0.1:28195` as Claude Code's HTTPS proxy, sends model requests to the core over the machine's certificate, and renews it at half-life. `GET /_client/status` shows the installation, the certificate's expiry and whether the core answers. `--no-service` skips it |
| Claude Code managed settings | the system managed-settings file: the proxy and its CA, telemetry, and two hooks — `innsegl hook pre-tool-use` on `PreToolUse` (Bash), and `innsegl hook session` on the session's start, each prompt, subagents, directory changes and the end. With `--hardened`, also the lockdown and the sandbox. After writing, `connect` checks that Claude Code loaded the file |
| each `DIR` argument | its `prepare-commit-msg` hook, the same as `innsegl link <dir>` |

Every one of these is additive. Settings you already have are left exactly
as they were, and each file gets a timestamped backup the moment before it
is changed for the first time. Running it again changes nothing that is
already in place. Writing the system path needs an administrator; when it
is not writable, `connect` prints the one command to run, before it spends
the token.

## When the core is down

Claude Code keeps working. When the core does not answer, the client sends
model requests straight to the provider and keeps a signed, hash-chained
journal of them, which the core checks and records when it is back. A
session's end and the harness's telemetry are kept the same way. Only a
client service that is not running stops a prompt, with a message saying so.

`innsegl status` says what is up and what is down between the machine and
its core, the versions, and what the machine may record. It exits non-zero
and names whatever is down.

To use Claude Code without innsegl for a while:

```sh
innsegl connect --pause     # sets the managed settings aside, unchanged
innsegl connect --resume    # puts them back
```

Restart Claude Code after either.

## Uninstall

On a machine, `innsegl connect --disconnect` removes exactly the managed
settings keys `connect` wrote — and what an older `install.sh` wrote —
stops and removes the client service, and deletes `~/.innsegl/client`.
Before deleting the key it revokes the machine's installation on the core.
If the core cannot be reached, it says so, and the machine is revoked from
the dashboard's Account page instead.

On the core host, `./install.sh --uninstall` removes the `innsegl-commit`
symlink an older install put on PATH, if one is still there. It does not stop
or delete anything running. To do that:

```sh
make innsegl-down     # stop innsegl, keep the ledger and the signed history
make innsegl-purge    # stop innsegl AND delete its data volumes
```

An install from before the gateway wired six hooks into
`~/.claude/settings.json` and an `innsegl` MCP entry into `~/.claude.json`.
`./install.sh --uninstall-legacy` removes exactly those.

## More

[`deploy/compose/README.md`](deploy/compose/README.md) is the full
reference: what the stack is made of, how to boot it by hand, the
`make smoke` first-run contract, and what it deliberately does not expose.
