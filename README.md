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
| Claude Code hooks | added to `~/.claude/settings.json` — `SessionStart`, `SessionEnd`, `SubagentStart`, `SubagentStop`, `PreToolUse`, `PostToolUse` |
| the `innsegl` MCP server | added to `~/.claude.json`, type `http`, at `http://127.0.0.1:28080/` |
| each `DIR` argument | linked into the stack so it becomes signable, the same as `make link DIR=<dir>` |

Every one of these is additive. Existing hooks, other MCP servers, and
anything else already in those two files are left exactly as they were, and
each file gets a timestamped backup the moment before install.sh changes it
for the first time. Running `install.sh` again changes nothing that is
already in place.

## Uninstall

```sh
./install.sh --uninstall
```

Removes exactly the hook entries and the MCP entry `install.sh` added, and
the `innsegl-commit` symlink — nothing you added yourself. It leaves the
backups in place and does not stop or delete anything running. To do that:

```sh
make innsegl-down     # stop innsegl, keep the ledger and the signed history
make innsegl-purge    # stop innsegl AND delete its data volumes
```

## More

[`deploy/compose/README.md`](deploy/compose/README.md) is the full
reference: what the stack is made of, how to boot it by hand, the
`make smoke` first-run contract, and what it deliberately does not expose.
