# CLI overview

## Purpose

`innsegl` is one binary. Each subcommand is one part of the system. The
dispatch table is `commands` in `cmd/innsegl/cli.go`; a test asserts the set.

## Commands

`innsegl help` prints the table. `innsegl version` prints the build version.

| Subcommand | What it does | Page |
|---|---|---|
| `innsegl accounts` | manage organisations, enrolment tokens, installations and repository grants | [dashboard-api.md](dashboard-api.md) |
| `innsegl admin-credential` | issue the repository-scoped credential the identity lifecycle requires | [identity.md](identity.md) |
| `innsegl api` | serve the dashboard's read-only query API and proof BFF | [dashboard-api.md](dashboard-api.md) |
| `innsegl ca-custodian` | keep the CA key store's custody on the core: init, renew, unlock | [ca-custody.md](ca-custody.md) |
| `innsegl ca-custody` | say whether the core's CA is sealed, and unlock it | [ca-custody.md](ca-custody.md) |
| `innsegl canary` | prove the object store refuses to delete a sealed segment (SEG-005) | [ledger-and-segments.md](ledger-and-segments.md) |
| `innsegl client` | the enrolled machine's local endpoint | [client-and-connect.md](client-and-connect.md) |
| `innsegl connect` | enrol this machine with a core and point the harness at it | [client-and-connect.md](client-and-connect.md) |
| `innsegl git-hook` | git's prepare-commit-msg hook: add the run's trailers | [commit-path.md](commit-path.md) |
| `innsegl hook` | the harness hook that passes a git commit its tool call id | [commit-path.md](commit-path.md) |
| `innsegl init` | set up signed commits in one repository end to end | [commit-path.md](commit-path.md) |
| `innsegl link` | install the prepare-commit-msg hook in a repository | [commit-path.md](commit-path.md) |
| `innsegl migrate-schema` | attest a major schema cutover in this chain | [ledger-and-segments.md](ledger-and-segments.md) |
| `innsegl reap` | delete identity entries orphaned past their TTL | [reconciler-and-reaper.md](reconciler-and-reaper.md) |
| `innsegl reconcile` | reconcile signing intents against the transparency log | [reconciler-and-reaper.md](reconciler-and-reaper.md) |
| `innsegl retire` | end a run an operator knows is over | [identity.md](identity.md) |
| `innsegl seal` | seal ledger segments and anchor them in the log | [ledger-and-segments.md](ledger-and-segments.md) |
| `innsegl serve` | run the MCP server; with `-also`, the companions too | [identity.md](identity.md), [gateway.md](gateway.md) |
| `innsegl sign` | git's signing program: ask the core to sign a commit | [commit-path.md](commit-path.md) |
| `innsegl status` | what is up and down between this machine and its core | [client-and-connect.md](client-and-connect.md) |
| `innsegl trust-backup` | write, fetch or test-open the encrypted trust-key backup | [trust-key-backup.md](trust-key-backup.md) |
| `innsegl trust-history` | read, record and end trust-history entries (for ca-rotate) | [trust-history.md](trust-history.md) |
| `innsegl verify` | verify a commit's attribution without the ledger | [verify.md](verify.md) |

The gateway has no table entry of its own. It runs inside `innsegl serve`
through `-also gateway` (ADR-0060). See [gateway.md](gateway.md).

git can also call the binary directly as its signing program:
`innsegl --status-fd=<N> -bsau <key>` and `innsegl --verify ...` dispatch to
`sign` (`cmd/innsegl/cli.go:190`).

## Settings

Every flag that reads the environment names its variable in `-h`, as
`($INNSEGL_...)`. A flag on the command line wins over the variable.

## Files, volumes, containers

The image built from `Dockerfile` runs this binary in every innsegl
container. See [stack-and-make.md](stack-and-make.md).

## Exit codes and error classes

Shared by every subcommand (`cmd/innsegl/cli.go:17`):

| Code | Meaning |
|---|---|
| 0 | the command completed |
| 1 | reserved; no subcommand returns it as "not implemented" any more |
| 2 | the command line was not understood, or an unknown subcommand |

Each subcommand adds its own codes from 3 upward. They are listed on its page.
Codes are reused across subcommands (for example 7 is `serve` UNAVAILABLE and
`verify` pre-history), so read a code together with the command that
returned it.

## Tests

- `cmd/innsegl/cli_test.go`: the command table and usage block.
- `test/deploy/referencedocs_test.go`: DOC-001 (PROPOSED), every subcommand
  is named on a reference page.

## Decisions

- [ADR-0001](../docs/adr/0001-language-and-module-path.md) language and module path
- [ADR-0016](../docs/adr/0016-error-class-carries-retryability-and-one-place-renders-it.md) error class and rendering

## Runbooks

- [runbooks/README.md](../runbooks/README.md)
