# Ledger, segments and sealing

## Purpose

The ledger is one append-only hash chain of events in Postgres (ADR-0005).
The sealer cuts it into segments, writes each to a write-once object store
and anchors it in the transparency log (ADR-0006, ADR-0009). The canary
proves the store refuses deletion. A backup is checked against the sealed
segments before it counts.

## Commands

```
innsegl seal [flags]
innsegl canary [flags]
innsegl migrate-schema [-dsn DSN] [-from VERSION]
make innsegl-canary
make innsegl-backup
make backup-freshness
make innsegl-verify
```

- `innsegl seal` runs continuously; `-once` runs one cycle. Run it single-active.
- `innsegl canary` tries to delete a probe object and must be refused (SEG-005).
- `innsegl migrate-schema` appends one `schema_migrated` event naming where
  the chain starts writing schema_version `4`. Run it before the upgraded
  writers start. Running it twice appends nothing the second time.
- `make innsegl-canary` runs the canary in its container (profile `canary`).
- `make innsegl-backup` runs `pg_dump`, restores it into a throwaway
  database and checks it against the sealed segments before keeping it.
- `make backup-freshness` reports the age of the last verified backup and
  whether its host copy landed.
- `make innsegl-verify` asks Postgres and the object store what this
  deployment's credentials can actually do (append-only role, object-lock scope).

## Settings

`innsegl seal` (defaults in brackets):

| Flag | Variable | Meaning |
|---|---|---|
| `-dsn` | `INNSEGL_LEDGER_DSN` | ledger connection |
| `-segment-events` | `INNSEGL_SEAL_SEGMENT_EVENTS` | events per segment [`1000`] |
| `-max-segment-age` | `INNSEGL_SEAL_MAX_SEGMENT_AGE` | seal a partial segment after this wait [`10m`] |
| `-interval` | `INNSEGL_SEAL_INTERVAL` | between cycles [`1m`] |
| `-scan-window` | `INNSEGL_SEAL_SCAN_WINDOW` | survey page and unanchored retry depth [`5000`] |
| `-anchor-attempts` | `INNSEGL_ANCHOR_ATTEMPTS` | submissions before the alert [`5`] |
| `-anchor-bound` | `INNSEGL_ANCHOR_BOUND` | anchoring lag before amber [`15m`] |
| `-anchor-key` | `INNSEGL_ANCHOR_KEY` | EC key that signs submissions; empty is ephemeral |
| `-rekor-url` | `INNSEGL_REKOR_URL` | transparency log |
| `-endpoint`, `-bucket`, `-prefix`, `-region` | `INNSEGL_OBJECT_STORE_*` | object store |
| `-access-key`, `-secret-key` | `INNSEGL_OBJECT_STORE_ACCESS_KEY`, `INNSEGL_OBJECT_STORE_SECRET_KEY` | store credential |
| `-mode`, `-retention` | `INNSEGL_OBJECT_STORE_RETENTION_MODE`, `INNSEGL_OBJECT_STORE_RETENTION` | object lock [`COMPLIANCE`, `0` = bucket default] |
| `-tls`, `-timeout` | `INNSEGL_OBJECT_STORE_TLS`, `INNSEGL_OBJECT_STORE_TIMEOUT` | [`true`, `1m`] |
| `-once`, `-json`, `-quiet` | | one cycle; JSON; quiet when idle |

`innsegl canary` takes the same object-store flags plus
`-min-bucket-retention` (`INNSEGL_CANARY_MIN_BUCKET_RETENTION`) and
`-probe-retention` (`INNSEGL_CANARY_PROBE_RETENTION`).

Compose defaults: bucket `innsegl-segments`, prefix `segments/`. Backup
service: `INNSEGL_BACKUP_INTERVAL` [`86400` s], `INNSEGL_BACKUP_WINDOW`
[`172800` s], `INNSEGL_BACKUP_RETRY` [`60`], `INNSEGL_BACKUP_RETRY_MAX`
[`900`], `INNSEGL_BACKUP_HOST_DIR` [`~/innsegl-backups`], `INNSEGL_BACKUP_DIR`
for `make innsegl-backup` [`backups`].

## Files, volumes, containers

| Item | Holds |
|---|---|
| `innsegl-postgres` | the ledger database |
| trust volume `<prefix>-ledger-data` | the chain and every event body |
| `innsegl-db-init` | migrations and database roles (`deploy/compose/innsegl/db-init.sh`) |
| `innsegl-s3`, `innsegl-object-init`, `innsegl-s3-identities` | the object store, its bucket and identities |
| volumes `innsegl-object-data`, `innsegl-object-filer-data`, `innsegl-s3-identities` | object store data |
| `innsegl-sealer` | the sealer as its own container (profile `separate`); default runs it in `innsegl-mcp` |
| `innsegl-canary` | the canary (profile `canary`) |
| `innsegl-backup`, volume `innsegl-backups` | scheduled ledger backup |
| `migrations/` | SQL migrations, embedded by `migrations/migrations.go` |

## Exit codes and error classes

| Command | Code | Meaning |
|---|---|---|
| `seal` | 9 | UNANCHORED: sealed and stored, no log entry |
| `seal` | 10 | INCONCLUSIVE: the cycle could not run |
| `canary` | 3 | the store permits deletion; fail the deploy |
| `canary` | 4 | the canary could not run; fails closed |
| `migrate-schema` | 5 | the chain mixes versions, or the attestation landed wrong; stop the old writers |
| `migrate-schema` | 6 | the ledger could not be opened, read or appended to |
| `backup-freshness.sh` | 1 | stale, missing or no host copy |

## Tests

- `internal/ledger/*_test.go` (LED-001 to LED-045, HAR-001, ALR-001, ALR-005)
- `internal/segment/*_test.go` (SEG-001 to SEG-006, HAR-010, OPS-029)
- `cmd/innsegl/seal_test.go`, `sealengine_test.go` (SEG-001, SEG-007 to SEG-013)
- `cmd/innsegl/canary_test.go` (SEG-005, OPS-029, HAR-009)
- `cmd/innsegl/migrateschema_test.go` (LED-035, LED-036)
- `internal/event/*_test.go` (SER-001 to SER-026)
- `test/deploy/appendonlyrole_test.go` (OPS-009, OPS-010), `objectscope_test.go`
  (OPS-025 to OPS-030), `filerisolation_test.go`, `objectoneprocess_test.go`
- `scripts/backup-ledger-selftest.sh` (BAK-001 to BAK-008, BAK-014, BAK-015),
  `scripts/backup-service-selftest.sh` (BAK-009 to BAK-013)
- `runbooks/verify-rebuilt-index-selftest.sh` (SEG-006)

## Decisions

- [ADR-0005](../docs/adr/0005-one-chain-per-database.md) one chain per database
- [ADR-0006](../docs/adr/0006-segment-object-format-and-content-addressed-segment-id.md) segment format
- [ADR-0008](../docs/adr/0008-worm-canary-proves-refusal-by-attempting-deletion.md) WORM canary
- [ADR-0009](../docs/adr/0009-anchor-a-segment-as-a-signed-hashedrekord-entry.md) anchoring
- [ADR-0033](../docs/adr/0033-append-the-intent-before-the-credential-is-spent-and-derive-a-ledger-key-per-phase.md) intent before credential
- [ADR-0050](../docs/adr/0050-prune-the-hot-tier-without-deleting-a-row.md) hot tier pruning
- [ADR-0061](../docs/adr/0061-schema-version-4-records-forks-agent-messages-and-workspace-trees.md) schema version 4

## Runbooks

- [backup-ledger.md](../runbooks/backup-ledger.md)
- [index-rebuild.md](../runbooks/index-rebuild.md)
- [object-store-worm.md](../runbooks/object-store-worm.md)
