# Trust history

## Purpose

`trust-history.json` lists every Fulcio root and transparency-log key a
deployment has used, plus the SPIRE upstream CA and the gateway CA. It holds
public material only and is append-only. The verifier accepts any root and
log key in it, within each entry's end dates, so a rotation does not break
older commits (ADR-0073).

## Commands

```
innsegl trust-history has    --kind K            < PEM
innsegl trust-history record --kind K            < PEM
innsegl trust-history end    --kind K --key-id ID --mode retire|revoke --at RFC3339 --reason TEXT
```

All three take `--file` (default `$INNSEGL_TRUST_HISTORY`). They exist for
`scripts/ca-rotate.sh`, which runs them inside the core with `docker exec`
(see [ca-password-and-rotation.md](ca-password-and-rotation.md)).

The reconciler's trust pass writes the history with no operator step: on its
first cycle and daily after, it records the material in use, imports lost
roots, verifies sentinel commits, and warns before expiry. See
[reconciler-and-reaper.md](reconciler-and-reaper.md).

## Settings

| Variable or flag | Default | Meaning |
|---|---|---|
| `INNSEGL_TRUST_HISTORY` | compose: `/run/innsegl/trust/trust-history.json` | the history file |
| `INNSEGL_TRUST_SENTINELS` (`reconcile -trust-sentinels`) | `trust-sentinels.json` beside the history | operator-pinned sentinels |
| `verify -trust-history`, `api -trust-history` | | readers of the history |

Entry kinds (`internal/trusthistory/history.go:58`): `fulcio_root`,
`transparency_log`, `spire_upstream_ca`, `gateway_ca`, `lost_root`.

An entry is `{kind, key_id, public_pem, first_used, retired_at,
retired_reason, revoked_at, tree_id}`; `key_id` is the hex sha256 of the
DER public key. A `lost_root` entry carries no public material. The only allowed change to an existing entry is setting an
end date or reason where it was unset.

## Files, volumes, containers

On the trust volume `<prefix>-history` (mounted in `innsegl-mcp` at
`/run/innsegl/trust/`):

| File | Written by | Holds |
|---|---|---|
| `trust-history.json` | reconciler, `trust-history record/end` | the history (format version 1) |
| `trust-lost-roots.json` | the operator | lost roots to import; never in this repository |
| `trust-sentinels.json` | the operator | optional pinned sentinels |
| `trust-sentinels-auto.json` | reconciler | one sentinel per root era, append-only |
| `trust-status.json` | reconciler | current problems, each with first-seen time |

Problems are served by `GET /_core/status` and `GET /api/v1/health`, shown
by `innsegl status` as `trust WARN` lines and on the dashboard overview.

## Exit codes and error classes

| Command | Code | Meaning |
|---|---|---|
| `trust-history` | 3 | the history could not be read or written, or refused the change |
| `trust-history has` | 4 | the history does not hold this material |

Verdict `pre-history` and `innsegl verify` exit 7: see [verify.md](verify.md).

## Tests

- `internal/trusthistory/history_test.go`, `end_test.go`, `expiry_test.go`, `lost_test.go`
- `internal/trustwatch/watch_test.go`
- `cmd/innsegl/trusthistorycli_test.go`, `reconciletrust_test.go`
- `internal/verify/carotation_test.go` (OPS-133)
- `test/deploy/trustroot_test.go` (OPS-031 to OPS-036, OPS-044, OPS-045, OPS-047)

## Decisions

- [ADR-0013](../docs/adr/0013-record-spire-entry-drift-as-ledger-drift-detected.md) no honest subject, no append
- [ADR-0034](../docs/adr/0034-verify-against-the-logs-record-of-the-commit-sha-and-evaluate-the-certificate-at-its-signed-integration-time.md) signed integration time
- [ADR-0073](../docs/adr/0073-trust-roots-are-kept-as-an-append-only-history.md) the trust history
- [ADR-0075](../docs/adr/0075-each-host-has-its-own-ca-password-and-the-ca-rotates-by-script.md) end dates written at the switch

## Runbooks

- [trust-rotation.md](../runbooks/trust-rotation.md)
- [trust-domain-re-rooting.md](../runbooks/trust-domain-re-rooting.md)
