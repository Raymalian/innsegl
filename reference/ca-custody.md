# CA key custody

## Purpose

Optional. The Fulcio CA key lives as a non-exportable key in a sealed key
store beside Fulcio. Nothing on the core can unseal it. After a restart the
operator's machine unlocks it with a hardware-held key (ADR-0076). Off by
default: the shipped stack is the file CA (OPS-051).

## Commands

```
innsegl ca-custodian init                  initialise a new CA key store, once
innsegl ca-custodian serve                 initialise if new; renew the CA's token; serve the core
innsegl ca-custodian ready                 exit 0 when the store is unlocked and the CA has a token
innsegl ca-custodian restore SNAPSHOT      put a backup's store into a new store
innsegl ca-custody status                  say whether the core's CA can sign
innsegl ca-custody unlock [--identity F]   unlock it if it is sealed (asks for Touch ID)
```

`ca-custodian` runs on the core. `ca-custody` runs on the operator's
machine; the client service does the same check once a minute and asks for
the unlock only when the store is sealed.

| Make target | Does |
|---|---|
| `make innsegl-ca-custody-init` | once: start the store and mint its keys (live stack only) |
| `make ca-custody-up` | start the store and the custodian; Fulcio on the store once rotated there |
| `make ca-custody-volumes` | create the two custody trust volumes |
| `make ca-custody-ready` | `innsegl ca-custodian ready` in the custodian container |
| `make ca-custody-stage` | mint the store's root if there is none, and print it |
| `make ca-custody-switch` | Fulcio onto the store |
| `make ca-custody-back` | Fulcio onto the file CA again (custody leaves it untouched) |
| `make ca-custody-reset CONFIRM=reset` | remove a store nothing depends on (Fulcio not on it, its root not in the trust history), so `make update` provisions a fresh one |
| `make ca-custody-restore FROM=DIR CONFIRM=restore` | restore the store and sealed material from an extracted trust-key backup |

Turning custody on is a rotation: `make innsegl-ca-rotate CONFIRM=rotate
TO=custody MODE=retire REASON='...'` (see
[ca-password-and-rotation.md](ca-password-and-rotation.md)). Until then
bring-up starts the store and leaves Fulcio on the file CA.

`scripts/ca-custody.sh` (`init`, `unseal`, `status`, `token`, `revoke`) is
the manual path from before the custodian.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `INNSEGL_CA_CUSTODY` | off | `on` in the compose `.env` adds `innsegl.custody.yml` and `sigstore.keycustody.yml` |
| `INNSEGL_CA_STORE_ADDR` | required | the store's address |
| `INNSEGL_CA_CUSTODY_RECIPIENTS` | required for init | age recipients the unlock material is sealed to |
| `INNSEGL_CA_CUSTODY_DIR` | | where the sealed material is kept |
| `INNSEGL_CA_TOKEN_PATH` | | the CA's token file (memory-backed volume) |
| `INNSEGL_CA_STORE_KEY` | `innsegl-ca` | the CA key's name in the store |
| `INNSEGL_CA_CUSTODIAN_LISTEN` | `:8210` | `serve` |
| `INNSEGL_CA_CUSTODIAN_URL` | | where the core reaches the custodian |
| `ca-custody --identity` | `~/.innsegl/trust-backup/identity.txt` | the age identity that opens the material |

The custodian renews the CA token every 8 hours and snapshots the store
hourly and at every init and unlock. A declined Touch ID prompt is not asked
again for 15 minutes.

## Files, volumes, containers

| Item | Holds |
|---|---|
| `innsegl-ca-store` | the key store |
| `innsegl-ca-custodian` | `innsegl ca-custodian serve` |
| `innsegl-ca-bootstrap` | mints the store's root and Fulcio's issuer config |
| `innsegl-ca-export`, `innsegl-ca-import` | one-shot import (profile `ca-import`) |
| trust volume `innsegl-trust-ca-store` | the store's data |
| trust volume `innsegl-trust-ca-custody` | the sealed unlock material (`material/unlock.age`) |
| volume `innsegl-ca-token` | the CA's token, in memory |
| volume `<prefix>-sigstore_sigstore-fulcio-kms` | the store's root chain and issuer config |
| backup items `ca-store/store.snap`, `ca-custody/unlock.age` | custody in a trust-key bundle |

Core routes (operator organisation workstations only): `/_core/ca-custody`,
`/_core/ca-custody/material`, `/_core/ca-custody/unlock`. The core reaches
the custodian on an internal unlock network and logs none of what it carries.

## Exit codes and error classes

| Command | Code | Meaning |
|---|---|---|
| `ca-custodian`, `ca-custody` | 27 | the command failed |
| `ca-custody status` | 28 | SEALED: the CA cannot sign |
| `ca-custody-restore`, `innsegl-ca-custody-init` | 2 | refused: missing `CONFIRM`/`FROM`, or a dev stack |
| `ca-custody-reset` | 2 | missing `CONFIRM=reset` |
| `ca-custody-reset` | 3 | refused: Fulcio runs on the store, its root is in the trust history, or the history could not be asked |

## Tests

- `internal/cacustody/*_test.go` (OPS-136 to OPS-145, OPS-153 to OPS-155)
- `cmd/innsegl/cacustodiancli_test.go` (OPS-146, OPS-155), `cacustodycli_test.go`
  (BAK-029), `corecacustody_test.go` (OPS-147)
- `cmd/ca-bootstrap/*_test.go` (OPS-049, OPS-050, OPS-052, OPS-148)
- `internal/client/cacustody_test.go` (BAK-026 to BAK-028)
- `test/deploy/cacustody_test.go` (OPS-051, OPS-149 to OPS-151, OPS-155, BAK-030)
- `scripts/ca-custody-selftest.sh` (OPS-049 to OPS-051)
- `scripts/ca-custody-reset-selftest.sh` (OPS-159)
- `internal/cacustody/store_test.go` OPS-136 also signs the way Fulcio asks, `transit/sign/<key>/sha2-256`

## Decisions

- [ADR-0074](../docs/adr/0074-trust-keys-are-backed-up-encrypted-and-off-the-host.md) the backup carries custody
- [ADR-0075](../docs/adr/0075-each-host-has-its-own-ca-password-and-the-ca-rotates-by-script.md) rotation
- [ADR-0076](../docs/adr/0076-the-ca-key-store-is-unlocked-by-the-operators-machine.md) custody

## Runbooks

- [ca-custody.md](../runbooks/ca-custody.md)
- [trust-key-backup.md](../runbooks/trust-key-backup.md)
