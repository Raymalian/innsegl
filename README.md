# innsegl

Innsegl signs a git commit under a real agent identity: an attested SPIFFE
workload, a short-lived Fulcio certificate, and a Rekor transparency-log
entry, so anyone can verify who — or what — made a commit with no access to
innsegl's own database. It ships its own self-hosted Fulcio and Rekor by
default ([ADR-0010](docs/adr/0010-self-hosted-sigstore-is-the-shipped-default.md)),
so no account and no third-party service is required. An MCP server exposes
the calls an agent needs to register, get a credential, sign, and retire,
and a dashboard shows the resulting ledger.

## Quickstart

```sh
git clone https://github.com/Raymalian/innsegl.git
cd innsegl
./install.sh --local-client ~/path/to/project
```

That checks the prerequisites, brings the stack up, puts `innsegl-commit` on
PATH, connects this machine's Claude Code to it (`--local-client`), and
links `~/path/to/project` so it can be signed. Then, from that project:

```sh
innsegl-commit -p <path> -m "your message"
```

or, from this checkout:

```sh
make sign -- -m "your message"
```

### The core on its own host

`install.sh` is the server installer. Without `--local-client` it brings the
stack up and writes no Claude Code settings on that host. Each developer
machine or CI runner then enrols once, with a single-use token minted on the
core (`innsegl accounts enrol-token …`) and the core's CA
(`~/.innsegl/ca/gateway-ca.pem` on the core host):

```sh
innsegl connect https://<core-name>:28095 --token <ie_…> --ca gateway-ca.pem ~/path/to/project
```

Instead of the CA file, `--ca-fingerprint sha256:<hex>` fetches it once and
checks it against that fingerprint. Without one of the two, `connect`
refuses: the core is never trusted on first use.

## What gets installed where

On the core host, by `install.sh`:

| | |
|---|---|
| the stack | Docker containers, via `make start` — SPIRE, self-hosted Sigstore, and innsegl itself |
| `innsegl-commit` | symlinked onto PATH at `~/.local/bin/innsegl-commit` |
| each `DIR` argument | linked into the stack so it becomes signable, the same as `make link DIR=<dir>` |
| Claude Code managed settings | only with `--local-client`: the system managed-settings file, routing every model request straight to the gateway on this host, with the sandbox and the hooks below |

On a client machine, by `innsegl connect`:

| | |
|---|---|
| `~/.innsegl/client/` | the machine's key (`key.pem`, mode 0600), its certificate, the trust bundle, the core's CA and `core.json`. The sandbox denies `~/.innsegl` to an agent's shell, so an agent cannot read the key |
| the client service | `innsegl client serve`, a LaunchAgent (macOS, `~/Library/LaunchAgents/dev.innsegl.client.plist`) or a systemd user unit (Linux, `innsegl-client.service`). It listens on `127.0.0.1:28195`, forwards to the core over the machine's certificate, and renews it at half-life. `GET /_client/status` shows the installation, the certificate's expiry and whether the core answers. `--no-service` skips it |
| Claude Code managed settings | the system managed-settings file: every model request, the hooks and telemetry sent to the local service, the sandbox, and two hooks — `innsegl hook pre-tool-use` on `PreToolUse` (Bash), and `innsegl hook session` on `SessionStart`, `UserPromptSubmit`, `SubagentStart` and `CwdChanged`, which tells the core each session's working directory |
| each `DIR` argument | its `prepare-commit-msg` hook, the same as `innsegl link <dir>` |

Every one of these is additive. Settings you already have are left exactly
as they were, and each file gets a timestamped backup the moment before it
is changed for the first time. Running either again changes nothing that is
already in place. Writing the system path needs an administrator; when it
is not writable, both print the one command to run, and `connect` does so
before it spends the token.

## When the stack is down

Every model request goes through the gateway, and the gateway refuses
rather than forward a request it cannot attribute. So when Docker or the
stack is not running, Claude Code cannot reach the model. Before each
prompt, the session hook checks, and stops the prompt with a message naming
the cause instead of a bare "connection refused".

| What you see | What it means | What to do |
|---|---|---|
| "the gateway … is not answering" | Docker or the stack is not running | `make start` |
| "answered with a certificate this machine does not trust" | the gateway's CA changed since install | re-run `install.sh` |
| 503, "a dependency is down; retrying" | SPIRE or the ledger is unreachable | Claude Code retries; if it persists, `make start` |
| 503, "has not stated this session's working directory yet" | the session hook is not installed | re-run `install.sh` |
| 403 | the request itself was refused, for the reason given | read the reason |

To use Claude Code without innsegl while the stack is down:

```sh
./install.sh --pause     # sets the managed settings aside, unchanged
./install.sh --resume    # puts them back
```

On a client machine, `innsegl connect --pause` and `innsegl connect --resume`
do the same. Restart Claude Code after either.

On a client machine, `innsegl status` says what is up and what is down
between the machine and its core, the versions, and what the machine may
record. It exits non-zero and names whatever is down.

## Uninstall

```sh
./install.sh --uninstall
```

Removes exactly what `install.sh` added to the managed settings, and the
`innsegl-commit` symlink — nothing you added yourself. It leaves the
backups in place and does not stop or delete anything running. To do that:

```sh
make innsegl-down     # stop innsegl, keep the ledger and the signed history
make innsegl-purge    # stop innsegl AND delete its data volumes
```

On a client machine, `innsegl connect --disconnect` removes exactly the
managed settings keys `connect` wrote, stops and removes the client service,
and deletes `~/.innsegl/client`. Before deleting the key it revokes the
machine's installation on the core. If the core cannot be reached, it says
so, and the machine is revoked from the dashboard's Account page instead.

An install from before the gateway wired six hooks into
`~/.claude/settings.json` and an `innsegl` MCP entry into `~/.claude.json`.
`./install.sh --uninstall-legacy` removes exactly those.

## More

[`deploy/compose/README.md`](deploy/compose/README.md) is the full
reference: what the stack is made of, how to boot it by hand, the
`make smoke` first-run contract, and what it deliberately does not expose.
