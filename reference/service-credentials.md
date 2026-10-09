# Service credentials

## Purpose

Every password a service uses to reach the ledger, the object store or the
log database is generated per host, kept in a trust volume, and read from a
file. No shipped file gives one a value, and none is on a command line or in
`docker inspect` (ADR-0078). An existing host that ran on the old public
defaults moves at the next `make update`, with no manual step.

## Commands

None of its own. `make update` and `make start` run the two generators:

- `innsegl-credentials` (core project): `deploy/compose/innsegl/credentials-init.sh`
- `sigstore-bootstrap` (Sigstore project): `deploy/compose/sigstore/bootstrap.sh`

Both source `deploy/compose/credentials-lib.sh`. A credential that exists is
kept; a missing one is 32 bytes from `openssl rand -hex 32`.

## The credentials

| store | credential | file in the trust volume | read by |
|---|---|---|---|
| ledger | owner | `ledger-owner` | `postgres` (first start), `innsegl-db-init` |
| ledger | appender | `ledger-appender` | `innsegl-mcp`, reconciler, sealer |
| ledger | reader | `ledger-reader` | `innsegl-api` |
| ledger | auth writer | `ledger-authwriter` | `innsegl-api`, `innsegl-mcp` |
| ledger | resolver | `ledger-resolver` | `innsegl-api` |
| ledger | backup | `ledger-backup` | `innsegl-backup` |
| object store | root identity | `objects-root` | `innsegl-s3-identities`, `innsegl-object-init` |
| object store | sealer identity | `objects-sealer` | `innsegl-mcp`, sealer, backup, canary |
| log database | MySQL root | `logdb-root` | `trillian-db` |
| log database | Trillian's user | `logdb-trillian` | Trillian pair, `innsegl-trust-backup` |
| log database | Rekor's index user | `logdb-rekor` | `rekor`, `scripts/rekor-reindex.sh` |

## Settings

| setting | default | meaning |
|---|---|---|
| `INNSEGL_LEDGER_OWNER_PASSWORD` | unset | read once, by the move, on a host whose owner password the operator set; remove it after the update |
| `INNSEGL_CREDENTIALS_LOCK_TIMEOUT` | `10s` | how long the ledger's move waits for a role another session holds |
| `INNSEGL_OBJECT_STORE_SECRET_KEY_FILE` | set by the stack | the file `innsegl seal` and `innsegl canary` read the secret from |
| `INNSEGL_TRUST_BACKUP_MYSQL_PASSWORD_FILE` | set by the stack | the file `innsegl trust-backup` reads the log database password from |
| `INNSEGL_BACKUP_PASSWORD_FILE` | set by the stack | the file `scripts/backup-ledger.sh` reads the backup role's password from |
| `INNSEGL_TRUST_CREDENTIALS_VOLUME`, `INNSEGL_TRUST_SIGSTORE_CREDENTIALS_VOLUME` | from `trust-volumes.sh env` | the two trust volumes' names |

Setting a value and its `_FILE` both is refused. A connection string carries
no password: it names the rendered `pgpass` with `passfile=`. `-h` shows a
credential default as `xxxxx`.

No longer read: `INNSEGL_LEDGER_APPENDER_PASSWORD`,
`INNSEGL_LEDGER_READER_PASSWORD`, `INNSEGL_LEDGER_AUTHWRITER_PASSWORD`,
`INNSEGL_LEDGER_RESOLVER_PASSWORD`, `INNSEGL_LEDGER_BACKUP_PASSWORD`,
`INNSEGL_OBJECT_STORE_SECRET_KEY`, `INNSEGL_OBJECT_STORE_SEALER_SECRET_KEY`.

## Files, volumes, containers

| volume | holds | mounted by |
|---|---|---|
| `innsegl-trust-credentials` | the core's eight credentials, 0400 | `innsegl-credentials` (rw); `innsegl-db-init`, `innsegl-s3-identities`, `innsegl-trust-backup` (ro) |
| `innsegl-trust-sigstore-credentials` | the log database's three | `sigstore-bootstrap` (rw); `innsegl-trust-backup` (ro) |
| `innsegl-credential-<name>` (core) | one credential in its reader's form: `password`, `pgpass`, or `secret` | the services that use it, read-only |
| `sigstore-credential-logdb` | `root`, `trillian`, `init.sql`, `healthcheck.cnf`, `rekor.cnf` | `trillian-db` |
| `sigstore-credential-trillian` | `flags` (Trillian's `--config`) | the Trillian pair |
| `sigstore-credential-rekor-index` | `rekor-server.yaml` (Rekor's `--config`) | `rekor` |

The per-credential volumes are rewritten from the trust volumes on every
start. Which service mounts which is the grant;
`test/deploy/credentials_test.go` holds the table. Dev stacks use
`innsegl-dev-trust-credentials` and `innsegl-dev-trust-sigstore-credentials`.

## The move, on an existing host

- Ledger (`innsegl/db-init.sh` step 1b): the owner's file password is tried;
  if refused, `INNSEGL_LEDGER_OWNER_PASSWORD`, then the old public default.
  One that opens moves the owner and every service role in ONE transaction,
  then checks the new one opens and the old one is refused. A failure rolls
  back: every old password still works, and the run exits non-zero. None
  opens: refused, nothing changed.
- Object store: the identity file is rewritten from the files at every start;
  `innsegl-s3-identities` waits for `innsegl-db-init`.
- Log database: the init file sets every user's password at every MySQL
  start, as the superuser, and removes `root@'%'`.

To rotate one credential other than the ledger owner's: remove its file from
the trust volume and run `make update`.

## Exit codes and error classes

`innsegl-db-init` exits 1 with `REFUSED:` when the move cannot run or rolled
back. `innsegl-credentials` exits 1 when a stored credential is malformed.

## Tests

- OPS-130 (`test/deploy/credentials_test.go`, `cmd/innsegl/credentialenv_test.go`):
  no shipped default, no password in a DSN or compose value, the mount table,
  `-h` never prints a credential.
- OPS-163 (`test/deploy/credentialsmove_test.go`, `logdbcredentials_test.go`):
  the move against a real Postgres and the pinned MySQL.
- OPS-164 (`scripts/credentials-selftest.sh`): the generators.

## Decisions

ADR-0078. ADR-0075 is the same rule for the CA key's password.

## Runbooks

[trust-key-backup.md](../runbooks/trust-key-backup.md) restores both volumes.
