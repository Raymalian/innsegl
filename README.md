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
./install.sh ~/path/to/project
```

That checks the prerequisites, brings the stack up, puts `innsegl-commit` on
PATH, connects this checkout to Claude Code, and links `~/path/to/project`
so it can be signed. Then, from that project:

```sh
innsegl-commit -p <path> -m "your message"
```

or, from this checkout:

```sh
make sign -- -m "your message"
```

## What gets installed where

| | |
|---|---|
| the stack | Docker containers, via `make start` — SPIRE, self-hosted Sigstore, and innsegl itself |
| `innsegl-commit` | symlinked onto PATH at `~/.local/bin/innsegl-commit` |
| Claude Code managed settings | the system managed-settings file: every model request routed through the innsegl gateway, the sandbox, and two hooks — `innsegl hook pre-tool-use` on `PreToolUse` (Bash), and `innsegl hook session` on `SessionStart`, `UserPromptSubmit`, `SubagentStart` and `CwdChanged`, which tells the gateway each session's working directory |
| each `DIR` argument | linked into the stack so it becomes signable, the same as `make link DIR=<dir>` |

Every one of these is additive. Settings you already have are left exactly
as they were, and each file gets a timestamped backup the moment before
install.sh changes it for the first time. Running `install.sh` again
changes nothing that is already in place. Writing the system path needs an
administrator; when it is not writable, install.sh prints the one command
to run.

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

Restart Claude Code after either.

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

An install from before the gateway wired six hooks into
`~/.claude/settings.json` and an `innsegl` MCP entry into `~/.claude.json`.
`./install.sh --uninstall-legacy` removes exactly those.

## More

[`deploy/compose/README.md`](deploy/compose/README.md) is the full
reference: what the stack is made of, how to boot it by hand, the
`make smoke` first-run contract, and what it deliberately does not expose.
