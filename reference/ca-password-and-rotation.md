# CA password and rotation

## Purpose

Each host's Fulcio CA key is locked with its own password, generated at
install into `ca.pass` beside the key. Fulcio reads it from its own config
file, so it is on no command line. The CA is replaced by one script, which
keeps the old root trusted for what it signed (ADR-0075).

## Commands

```
make innsegl-ca-rotate CONFIRM=rotate MODE=retire|revoke REASON='...' [BACKUP_MAX_AGE_HOURS=N] [TO=custody]
make innsegl-ca-rollback CONFIRM=rollback STAMP=<archive name>
```

Both run `scripts/ca-rotate.sh` (`rotate` or `rollback STAMP`).

`rotate`, in order:

1. Pre-flight: needs `CONFIRM=rotate`, a `MODE` and a `REASON`; the stack is
   up; Fulcio is the file CA on `serve.yaml`; the root it serves is the root
   on its volume; the trust history holds that root; optionally a trust-key
   backup newer than `BACKUP_MAX_AGE_HOURS`.
2. Archive the CA in its own volume, still locked, never deleted.
3. Make the new CA the way the bootstrap makes the first one.
4. Switch and restart Fulcio; prove a real certificate chains to the new root.
5. End the old root in the trust history (`retire` or `revoke`) at the
   switch time, then record the new root.

`TO=custody` mints the new root from the CA key store instead (see
[ca-custody.md](ca-custody.md)). `rollback` puts an archived CA back and
keeps the current one in the archive.

`MODE=retire`: the old root stays trusted for entries the log integrated
before the end date, within the skew bound. `MODE=revoke`: only before it,
with no skew.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `CONFIRM`, `MODE`, `REASON`, `STAMP`, `TO`, `BACKUP_MAX_AGE_HOURS` | | make arguments, above |
| `INNSEGL_STACK_PREFIX` | `innsegl` (`innsegl-dev` on a dev stack) | container names |
| `INNSEGL_ROTATE_FULCIO_URL` | Fulcio's published port (`docker port`) | |
| `INNSEGL_ROTATE_FULCIO_CONTAINER` | `<prefix>-sigstore-fulcio` | |
| `INNSEGL_ROTATE_CORE_CONTAINER` | `<prefix>-mcp` | empty: none |
| `INNSEGL_ROTATE_HISTORY_CMD` | `docker exec -i <core> innsegl trust-history` | |
| `INNSEGL_ROTATE_PROOF_CMD` | `deploy/compose/sigstore/verify.sh` | |
| `INNSEGL_ROTATE_WAIT_TRIES`, `INNSEGL_ROTATE_POLL_SECONDS` | `60`, `2` | wait for Fulcio |
| `INNSEGL_FULCIO_CA_PASSWORD` | unset | legacy only; read once to write `ca.pass`, then ignored |

How an existing host moves to `ca.pass` on its next bootstrap (every
`make update` runs it): `ca.pass` exists and wins; else the variable must
open the key and is written once; else a key on the old public default is
re-locked under a generated password; else the bootstrap refuses and names
the variable. The old public default is never adopted.

## Files, volumes, containers

| Item | Holds |
|---|---|
| trust volume `<prefix>-fulcio-pki` | `ca.crt`, the encrypted `ca.key`, `ca.pass`, and archived CAs |
| `serve.yaml` | Fulcio's config with `fileca-key-passwd`, written by the bootstrap |
| `innsegl-sigstore-bootstrap` | generates the password and the first CA (`deploy/compose/sigstore/bootstrap.sh`, `ca-lib.sh`) |
| `innsegl-sigstore-fulcio` | Fulcio, started with `--config=/etc/fulcio/serve.yaml` |
| `deploy/compose/sigstore/ca-rotate-volume.sh` | the in-volume archive and swap |

## Exit codes and error classes

`scripts/ca-rotate.sh`:

| Code | Meaning |
|---|---|
| 0 | rotated (a warning if the new root could not be recorded yet) |
| 2 | usage; nothing touched |
| 3 | pre-flight refused; nothing touched |
| 4 | failed before the switch; everything as it was |
| 5 | failed after the switch and rolled back; the old CA serves again |
| 6 | failed after the switch and the rollback failed; finish by hand |

## Tests

- `scripts/ca-rotate-selftest.sh` (OPS-132, OPS-152)
- `scripts/sigstore-bootstrap-selftest.sh` (OPS-131)
- `test/deploy/capassword_test.go`, `capasswordfile_test.go` (OPS-011, OPS-130)
- `internal/verify/carotation_test.go` (OPS-133)
- `cmd/innsegl/trusthistorycli_test.go`

## Decisions

- [ADR-0010](../docs/adr/0010-self-hosted-sigstore-is-the-shipped-default.md) self-hosted Sigstore
- [ADR-0073](../docs/adr/0073-trust-roots-are-kept-as-an-append-only-history.md) the trust history
- [ADR-0075](../docs/adr/0075-each-host-has-its-own-ca-password-and-the-ca-rotates-by-script.md) password per host, rotation by script

## Runbooks

- [trust-rotation.md](../runbooks/trust-rotation.md)
