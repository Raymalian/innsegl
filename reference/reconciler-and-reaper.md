# Reconciler and reaper

## Purpose

The reconciler expires dangling signing intents, repairs records a crash
lost, and cross-checks the chain against the transparency log (ADR-0035,
ADR-0036). Optional passes watch SPIRE entries, rebased commits, unsigned
agent commits, reported writes and the trust history. The reaper ends runs
that are past their TTL and have gone quiet (ADR-0014). Both run single-active.

## Commands

```
innsegl reconcile [flags]
innsegl reap [flags]
```

By default both run inside `innsegl-mcp` (`-also seal,reconcile,reap,gateway`,
ADR-0056). The compose profile `separate` runs `innsegl-reconciler` and
`innsegl-sealer` as their own containers instead.

Inside `innsegl-mcp` each companion runs on `serve`'s own context, so SIGTERM
(`docker stop`, `make update`) stops all of them together. A reap sweep in
flight finishes first; then the process exits within seconds. Run on its own,
`innsegl reap -interval` stops on SIGINT or SIGTERM the same way.

## Settings

`innsegl reconcile` (defaults in brackets):

| Flag | Variable | Meaning |
|---|---|---|
| `-dsn` | `INNSEGL_LEDGER_DSN` | ledger connection |
| `-rekor-url` | `INNSEGL_REKOR_URL` | transparency log |
| `-interval`, `-once` | `INNSEGL_RECONCILE_INTERVAL` | between cycles [`1m`]; one cycle |
| `-expire-after` | `INNSEGL_RECONCILE_EXPIRE_AFTER` | when a dangling `commit_intent` is expired [`15m`] |
| `-drift-window` | `INNSEGL_DRIFT_WINDOW` | recent log entries cross-checked; 0 is off [`1024`] |
| `-spire-address`, `-spire-server-id`, `-trust-domain`, `-workload-api`, `-timeout` | `INNSEGL_SPIRE_*`, `INNSEGL_TRUST_DOMAIN`, `INNSEGL_WORKLOAD_API_ADDRESS` | SPIRE entry pass; off when the address is empty |
| `-mirror-dir` | `INNSEGL_MIRROR_DIR` | the core's mirror, `<root>/host/org/name.git` (wins over `-workspace`) |
| `-workspace` | `INNSEGL_WORKSPACE` | single-host working trees |
| `-rebase-branch`, `-rebase-repos` | `INNSEGL_REBASE_BRANCH`, `INNSEGL_REBASE_REPOS` | ADR-0047 pass; set both or neither |
| `-tool-body-dir` | `INNSEGL_MCP_LOG_DIR` | turns on the unsigned-commit check |
| `-writes-log-dir`, `-writes-repos` | `INNSEGL_WRITES_LOG_DIR`, `INNSEGL_WRITES_REPOS` | reported-writes check (counts only) |
| `-trust-history`, `-trust-sentinels` | `INNSEGL_TRUST_HISTORY`, `INNSEGL_TRUST_SENTINELS` | daily trust pass (see [trust-history.md](trust-history.md)) |
| `-fulcio-url` | `INNSEGL_FULCIO_URL` | read by the trust watch |
| `-gateway-ca-dir` | `INNSEGL_GATEWAY_CA_CERT_DIR` | gateway CA for the expiry watch |
| `-json`, `-quiet` | | report shape |

`innsegl reap` (defaults in brackets):

| Flag | Variable | Meaning |
|---|---|---|
| `-dsn` | `INNSEGL_LEDGER_DSN` | ledger connection |
| `-grace` | `INNSEGL_REAP_GRACE` | silence past the TTL before a run is orphaned [`12h`] |
| `-interval` | `INNSEGL_REAP_INTERVAL` | 0 sweeps once and exits |
| `-spire-address`, `-spire-server-id`, `-trust-domain`, `-workload-api`, `-timeout` | as above | SPIRE admin API [`15s`] |
| `-json`, `-quiet` | | report shape |

A run past its TTL that is still appending is not reaped. The reaper records
a withdrawal that a later call can undo (ADR-0052); `innsegl retire` is the
permanent end (see [identity.md](identity.md)).

## Files, volumes, containers

| Item | Holds |
|---|---|
| `innsegl-mcp` | runs both by default |
| `innsegl-reconciler` | the reconciler alone (profile `separate`) |
| volume `innsegl-mirror` | the per-repository mirror the passes read (ADR-0065) |
| `/harness-log` inside the container | retained tool-call bodies, read-only |

## Exit codes and error classes

| Command | Code | Meaning |
|---|---|---|
| `reconcile` | 7 | UNRESOLVED: an open intent could not be ruled on |
| `reconcile` | 8 | INCONCLUSIVE: the cycle could not run |
| `reap` | 5 | INCOMPLETE: an orphan could not be reaped |
| `reap` | 6 | INCONCLUSIVE: the sweep could not run |

## Tests

- `internal/reconciler/*_test.go` (REC-001 to REC-011, CMT-015 to CMT-017,
  OTW-001 to OTW-003, ADP-015, HAR-004)
- `cmd/innsegl/reconcile_test.go` (REC-001), `reconcilewiring_test.go`
  (OPS-016, SPI-008), `rebasewiring_test.go` (OPS-006), `reconciletrust_test.go`
- `cmd/innsegl/reap_test.go` (OPS-066 to OPS-068, SPI-003)
- `cmd/innsegl/servestop_test.go` (OPS-177: reap and every companion stop on
  SIGTERM, after the sweep in flight)
- `internal/spire/reaper*_test.go`, `silence*_test.go`, `population_test.go`
  (SPI-003, SPI-011 to SPI-019)
- `internal/rundir/*_test.go` (MCP-022, MCP-023, MCP-078, REC-017, REC-018)
- `test/deploy/rebasedefaults_test.go`
- `test/chaos/*_test.go` (OPS-001, OPS-003, REC-002, REC-005)

## Decisions

- [ADR-0013](../docs/adr/0013-record-spire-entry-drift-as-ledger-drift-detected.md) SPIRE drift
- [ADR-0014](../docs/adr/0014-reaper-orphan-test-and-expiry-idempotency-key.md) reaper orphan test
- [ADR-0035](../docs/adr/0035-drive-the-repair-from-the-intent-and-record-an-expiry-only-on-an-answer.md) repair from the intent
- [ADR-0036](../docs/adr/0036-cross-check-the-chain-against-rekor-in-both-directions-and-sweep-a-trailing-window.md) chain against Rekor
- [ADR-0047](../docs/adr/0047-anchor-attribution-to-the-change-not-the-commit-object.md) rebased commits
- [ADR-0051](../docs/adr/0051-let-a-live-run-adopt-a-dead-runs-work-and-record-the-handover.md) adoption
- [ADR-0052](../docs/adr/0052-a-withdrawn-credential-is-a-lapse-not-a-death.md) withdrawal is a lapse
- [ADR-0055](../docs/adr/0055-an-anchor-resolves-the-drift-alert-about-its-segment.md) anchor resolves drift
- [ADR-0056](../docs/adr/0056-a-single-machine-deployment-runs-the-loops-in-the-mcp.md) loops in the MCP

## Runbooks

- [index-rebuild.md](../runbooks/index-rebuild.md)
- [spire-admin-access.md](../runbooks/spire-admin-access.md)
