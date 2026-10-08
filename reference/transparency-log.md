# Transparency log (Rekor and Trillian)

## Purpose

The self-hosted transparency log records every signature and every segment
anchor. Rekor serves it; Trillian stores it in its database. The log's tree
id is pinned so a restart never starts an empty tree, and its search index
must be complete before anything verifies against it (ADR-0010).

## Commands

```
make sigstore-up
make sigstore-verify
make sigstore-down
make rekor-tlog-id
make rekor-reindex
scripts/rekor-tlog-pin.sh path|rel|read|guard [repo]
scripts/rekor-reindex.sh [--if-behind] [--dry-run]
scripts/rekor-tlog-health.sh [--url URL] [--pin-file FILE] [--quiet]
scripts/rekor-port.sh
```

| Command | Does |
|---|---|
| `make sigstore-up` | ensure the trust volumes, guard the pin, start SPIRE, Fulcio, Trillian and Rekor, then make the index ready |
| `make sigstore-verify` | get a real Fulcio certificate for a real JWT-SVID |
| `make sigstore-down` | tear the Sigstore project down (trust volumes are external and guarded) |
| `make rekor-tlog-id` | read the tree Rekor serves and pin it |
| `make rekor-reindex` | backfill the search index from the whole log; the repair |
| `rekor-tlog-pin.sh guard` | refuse to boot with pin 0 next to an existing log |
| `rekor-reindex.sh --if-behind` | backfill only when the index holds fewer entries than the log (run by every bring-up) |
| `rekor-tlog-health.sh` | is the pinned tree still served (run at the end of `make start`) |
| `rekor-port.sh` | the host port: `INNSEGL_REKOR_PORT`, else Docker's published port, else `23000` |

`make update` brings the log's services up again and recreates only what
changed (see [stack-and-make.md](stack-and-make.md)).

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `INNSEGL_REKOR_TLOG_ID` | the pin, else `0` | tree id passed to Rekor; `0` mints a new tree |
| `INNSEGL_REKOR_ALLOW_NEW_TREE` | unset | set to let the guard allow a new tree |
| `INNSEGL_REKOR_PORT` | `23000` | host port (`make start` picks a free one) |
| `INNSEGL_REKOR_URL` | `http://127.0.0.1:$INNSEGL_REKOR_PORT` | log URL from the host |
| `INNSEGL_REKOR_REINDEX_NETWORK` | `innsegl-sigstore-rekor-index` | network the backfill runs on |
| `INNSEGL_REKOR_REINDEX_REKOR` | `http://rekor:3000` | log URL on that network |
| `INNSEGL_REKOR_REINDEX_DSN` | the DSN Rekor uses | the index database |
| `INNSEGL_REKOR_REINDEX_CONCURRENCY` | `4` | backfill workers |
| `INNSEGL_REKOR_REINDEX_DB` | `innsegl-sigstore-trillian-db` | index database container, for `--if-behind` |
| `INNSEGL_STACK_PREFIX` | `innsegl` | a dev stack has its own pin file |

## Files, volumes, containers

| Item | Holds |
|---|---|
| `innsegl-sigstore-rekor` | Rekor; container port 3000, host `127.0.0.1:23000` |
| `innsegl-sigstore-trillian-log-server`, `innsegl-sigstore-trillian-log-signer` | Trillian |
| `innsegl-sigstore-trillian-db` | the log database and the search index table |
| trust volume `<prefix>-trillian-db` | the log itself |
| trust volume `<prefix>-rekor-key` | Rekor's signing key |
| `deploy/compose/.rekor-tlog-id` | the pin; resolved against the main worktree; gitignored |
| `deploy/compose/sigstore/rekor-index.sql` | the index table |

The old `innsegl-sigstore-rekor-redis` container is removed by name at bring-up.

## Exit codes and error classes

| Script | Code | Meaning |
|---|---|---|
| `rekor-tlog-pin.sh guard` | 3 | unsafe: would mint a new tree beside a log |
| `rekor-reindex.sh` | 1 | the backfill failed; a second run is safe |
| `rekor-reindex.sh` | 4 | the log or the index could not be read; nothing changed |
| `rekor-tlog-health.sh` | 2 | usage |
| `rekor-tlog-health.sh` | 4 | Rekor unreachable; inconclusive |
| `rekor-tlog-health.sh` | 6 | THE PINNED TREE IS ABSENT |

MCP error class `TRANSPARENCY_UNAVAILABLE` and verify exit 4 mean the log
could not be reached.

## Tests

- `scripts/rekor-tlog-pin-selftest.sh` (OPS-055), `rekor-reindex-selftest.sh`,
  `rekor-port-selftest.sh`
- `test/deploy/rekorindex_test.go` (OPS-036), `trustroot_test.go` (OPS-034)
- `test/smoke/rekorport_test.go` (OPS-006, OPS-014, OPS-015)
- `internal/segment/anchor_rekor_test.go` (SEG-003, SEG-004),
  `internal/reconciler/rekor_test.go` (REC-002)
- `test/failure/sigstore_test.go` (SIG-002 to SIG-004); destructive, never
  with the stack up

## Decisions

- [ADR-0009](../docs/adr/0009-anchor-a-segment-as-a-signed-hashedrekord-entry.md) segment anchors
- [ADR-0010](../docs/adr/0010-self-hosted-sigstore-is-the-shipped-default.md) self-hosted Sigstore, index in the log database
- [ADR-0024](../docs/adr/0024-readiness-probes-sigstore-by-fetching-its-trust-material.md) readiness probes
- [ADR-0029](../docs/adr/0029-compose-self-hosted-sigstore-as-its-own-project-joined-to-spires-oidc-network.md) Sigstore project
- [ADR-0032](../docs/adr/0032-inject-a-sigstore-outage-by-stopping-the-shipped-container-and-assert-the-absence-of-a-commit-against-the-object-database.md) outage injection
- [ADR-0036](../docs/adr/0036-cross-check-the-chain-against-rekor-in-both-directions-and-sweep-a-trailing-window.md) chain against the log

## Runbooks

- [index-rebuild.md](../runbooks/index-rebuild.md)
- [trust-key-backup.md](../runbooks/trust-key-backup.md)
