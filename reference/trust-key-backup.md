# Trust-key backup and drill

## Purpose

Once a day the core writes one encrypted bundle of every trust key: the
Fulcio CA and its password, the Rekor key, the log's database, the identity
secret, the SPIRE upstream CA, the gateway CA key and the trust history. It
is encrypted to the operator's public recipients, so the core cannot open
it. The operator's client fetches it, and a drill proves it opens (ADR-0074).

## Commands

```
innsegl trust-backup create --dir DIR [--keep N] [--every D] [--retry D] [--owner UID:GID]
                            [--path NAME=PATH]... [--mysql NAME=HOST:PORT/DB]... [--value NAME=ENVVAR]...
innsegl trust-backup fetch
innsegl trust-backup drill [--dir DIR] [--identity FILE] [--extract DIR]
```

| Verb | Runs on | Does |
|---|---|---|
| `create` | the core (`innsegl-trust-backup` service) | writes a bundle; with `--every`, on a schedule |
| `fetch` | the operator's machine | keeps the core's newest bundle now (the client service also fetches on start and hourly) |
| `drill` | the operator's machine | opens the newest kept bundle, checks every checksum, lists what it holds, names what is missing |

`create` flags: `-dir` (required), `-keep` [`14`], `-every` (0 writes once),
`-retry` [`15m`], `-owner`, `-path`, `-mysql`, `-value` (repeatable).
`fetch` has no flags.
`drill` flags: `-dir` [`~/.innsegl/trust-backups`], `-identity`
[`~/.innsegl/trust-backup/identity.txt`], `-extract` (write files 0600 for a
restore; empty writes nothing).

`make innsegl-ca-rotate BACKUP_MAX_AGE_HOURS=N` refuses unless a bundle is
newer than N hours.

## Settings

| Variable | Where | Meaning |
|---|---|---|
| `INNSEGL_TRUST_BACKUP_RECIPIENTS` | core host | space-separated age recipients; none means no bundle is written |
| `INNSEGL_TRUST_BACKUP_KEEP` | compose | bundles kept [`14`] |
| `INNSEGL_TRUST_BACKUP_INTERVAL` | compose | schedule [`24h`] |
| `INNSEGL_TRUST_BACKUP_MYSQL_USER`, `INNSEGL_TRUST_BACKUP_MYSQL_PASSWORD` | `create` | the log database's credentials for `--mysql` |
| `INNSEGL_TRUST_BACKUP_DIR` | core | where `innsegl-mcp` reads bundles to serve them |

Recipients may be X25519, post-quantum, tagged P-256 (`age1tag1…`) or
plugin recipients with a tagged P-256 payload (`age1se1…`). The core runs no
age plugin.

## Files, volumes, containers

| Item | Holds |
|---|---|
| `innsegl-trust-backup` | runs `create` (compose profile `trust-backup`); read-only root, only `DAC_READ_SEARCH` and `CHOWN` |
| volume `innsegl-trust-backups` | the bundles, read-only into `innsegl-mcp` |
| `trust-backup-*.tar.age` and a checksum file | one bundle: a tar of every item plus `manifest.json` (size, mode, sha256 per file) |
| `~/.innsegl/trust-backups/` | the operator's copies, newest 30 (dir 0700, files 0600) |
| `~/.innsegl/trust-backup/identity.txt` | the operator's age identity |

Items the drill expects (`cmd/innsegl/trustbackupcli.go:48`): `fulcio-pki`,
`rekor-key`, `trillian-db`, `identity-secret`, `spire-upstream-ca`,
`gateway-ca-key`, `trust-history`; the CA password as `ca.pass` in
`fulcio-pki` (or the older `fulcio-ca-password` item); and for a custody
bundle, `ca-store` and `ca-custody` (see [ca-custody.md](ca-custody.md)).

Core routes, behind an active workstation of the operator organisation:
`GET /_core/trust-backup` (list and producer status) and
`GET /_core/trust-backup/latest` (newest bundle; name and sha256 in headers).
`innsegl status` warns when the newest copy is missing or older than two days.

## Exit codes and error classes

| Code | Meaning |
|---|---|
| 26 | a bundle was not written, fetched or opened |

## Tests

- `internal/trustbackup/*_test.go` (bundle, identity, mysql, plugin, recipients, store)
- `cmd/innsegl/trustbackupcli_test.go`, `trustbackupdrill_test.go` (BAK-030),
  `coretrustbackup_test.go`
- `internal/client/trustbackup_test.go`
- `scripts/innsegl-migrate-selftest.sh` (BAK-024)

## Decisions

- [ADR-0073](../docs/adr/0073-trust-roots-are-kept-as-an-append-only-history.md) the trust history
- [ADR-0074](../docs/adr/0074-trust-keys-are-backed-up-encrypted-and-off-the-host.md) the trust-key backup
- [ADR-0076](../docs/adr/0076-the-ca-key-store-is-unlocked-by-the-operators-machine.md) custody bundles

## Runbooks

- [trust-key-backup.md](../runbooks/trust-key-backup.md)
- [ca-custody.md](../runbooks/ca-custody.md)
