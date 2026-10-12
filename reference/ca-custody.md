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
innsegl ca-custodian ready                 exit 0 when the CA can sign: store unlocked, token alive, key readable and matching the chain
innsegl ca-custodian restore SNAPSHOT      put a backup's store into a new store
innsegl ca-custody status                  say whether the core's CA can sign
innsegl ca-custody unlock [--identity F]   unlock it, or repair a dead token, when the CA cannot sign (asks for Touch ID)
innsegl ca-custody recipients             list the recipients the unlock material is sealed to
innsegl ca-custody reseal --add R | --remove R | --set FILE [--identity F] [--opener R]
                                          re-seal the same material to a new set (asks, then Touch ID twice)
```

`ca-custody reseal` flags, from `innsegl ca-custody reseal -h`:

```
  -add value
    	a recipient to add (age1…); repeatable
  -identity string
    	the age identity file that opens the unlock material (a Secure Enclave identity asks for Touch ID) (default "~/.innsegl/trust-backup/identity.txt")
  -opener string
    	this machine's own recipient, when the identity file does not name it
  -remove value
    	a recipient to remove; repeatable
  -set string
    	a file holding the whole new set, one recipient per line, # comments allowed
```

`ca-custodian` runs on the core. `ca-custody` runs on the operator's
machine; the client service does the same check once a minute and asks for
the unlock whenever the core reports `can_sign: false`: sealed, or unsealed with a dead token. One Touch ID repairs either; no container restart. The command prints the reason it is repairing. A core too old to report `can_sign` is unlocked only when sealed.

| Make target | Does |
|---|---|
| `make innsegl-ca-custody-init` | once: start the store and mint its keys |
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

On a dev stack (`make dev-stack`, ADR-0072) every target runs custody under
innsegl-dev-* names: the dev overlays `deploy/compose/dev/sigstore.keycustody.yml`
and `deploy/compose/dev/innsegl.custody.yml`, and the trust volumes
`innsegl-dev-trust-ca-store` and `innsegl-dev-trust-ca-custody`. Seal a dev
store to a development age identity made for it
(`INNSEGL_CA_CUSTODY_RECIPIENTS` in the compose `.env`), never the
operator's own.

## The CA holds no token

Fulcio does not hold the store's token (#585). Its KMS client reads a token
once, at start, and an unlock revokes the token it replaces, so a Fulcio that
held the token kept running on a revoked one. Instead the custodian is
Fulcio's signing gateway:

- Fulcio's `VAULT_ADDR` is `http://innsegl-ca-signer:8211`, the custodian's
  alias on the network `innsegl-ca-sign`, whose only members are Fulcio and
  the custodian. Fulcio is not on the store's network and mounts no token.
- Its `VAULT_TOKEN` is the fixed string `innsegl-ca-custodian-supplies-the-token`.
  It is not a credential: the pinned KMS client refuses to start with no
  token, and the gateway drops it.
- The gateway forwards `PUT`/`POST /v1/transit/sign/<key>`,
  `PUT`/`POST /v1/transit/sign/<key>/sha2-256` and `GET /v1/transit/keys/<key>`,
  with the token the custodian holds at that moment. Anything else is 403.
  No answer carries the token.
- So an unlock, or a store restart and unlock, restores signing with no
  Fulcio restart.
- `innsegl-ca-token-keeper` keeps the token volume mounted while the
  custodian is recreated. The volume is memory only, and with no container
  using it the token would be lost. The keeper runs as nobody and cannot
  read it.

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
| `INNSEGL_CA_SIGN_LISTEN` | unset (no gateway); the overlay sets `innsegl-ca-signer:8211` | `serve`: the CA's signing gateway |
| `INNSEGL_CA_SIGN_NETWORK` | `innsegl-ca-sign` | the network Fulcio and the custodian share |
| `INNSEGL_CA_CHAIN_PATH` | unset; the overlay sets `/etc/fulcio/chain.pem` | the chain the CA presents; the custodian requires the store's key to match its first certificate. Unset, or not yet written, skips that check |
| `INNSEGL_CA_CUSTODIAN_URL` | | where the core reaches the custodian; on `innsegl-api` (its `-ca-custodian-url`), where the dashboard does. Unset there: the dashboard's unlock routes answer 503 "custody is off" |
| `ca-custody --identity` | `~/.innsegl/trust-backup/identity.txt` | the age identity that opens the material |

A plugin identity runs its plugin only as `innsegl connect` pinned it, by
absolute path and SHA-256, in `~/.innsegl/client/age-plugins.json` (#598). The
pin is checked before every unlock, by the CLI and by the client service. A
plugin that has changed, that PATH finds somewhere else, or that is writable
by someone other than its owner is refused. Repair: check that it is the
plugin you installed, then run `innsegl connect --update`. See
[client-and-connect.md](client-and-connect.md).

The custodian renews the CA token when it starts and every 15 minutes after.
The token period is 24 hours, so the token dies only when no custodian has
run for a day, however often the custodian is recreated. A refused renewal is
logged at once. The custodian snapshots the store hourly and at every init
and unlock. A declined Touch ID prompt is not asked again for 15 minutes.

## Can the CA sign

The custodian's status (`/status`, the core's `/_core/ca-custody`) carries
`can_sign` and, when false, `reason`. It is tested on every call, in this
order, and makes no signature:

| Check | Reason when it fails |
|---|---|
| the store answers | `the store is not answering` |
| initialised | `the store is not initialised` |
| unsealed | `the store is sealed; the operator's machine unlocks it` |
| a token file | `the CA has no token yet` |
| the token's lookup succeeds with time left | `the CA's token was refused by the store`, or `has expired` |
| the token reads the CA key | `the CA's token cannot read the CA key "<key>"` |
| the key is the one in `INNSEGL_CA_CHAIN_PATH`'s first certificate | `... they have drifted, and Fulcio refuses to start on them` |

`ca-custodian ready` and `ca-custody status` both read `can_sign` and print
the reason.

## Reseal

The material is sealed at init to `INNSEGL_CA_CUSTODY_RECIPIENTS`. A reseal
seals the **same** material to a new set of recipients (ADR-0082 decision 7).
The CA key, the store, the unseal key and the secret ids do not change. It
is two steps on the custodian:

1. `POST /reseal` with the material the opener opened, the opener's own
   recipient, the set, and the set's digest. The custodian proves the
   material (below), seals it to the set with a fresh check inside, and
   keeps that copy staged. `unlock.age` is not touched. The answer is the
   staged copy, the set and its digest.
2. `POST /reseal/confirm` with the material and the check, both read from
   the staged copy, and the digest again. Only then is the staged copy
   swapped in and the set written to `recipients.txt`. Opening the staged
   copy takes the opener's touch again.

A staged copy not confirmed within 10 minutes is dropped, and a custodian
restart drops it too; `unlock.age` stays as it was. A new reseal replaces a
staged one.

Refused, with the material unchanged:

| Refusal | Answer |
|---|---|
| an empty set | 400 |
| a set without the opener's recipient | 400 |
| a member that is not a recipient the core seals to | 400 |
| a digest other than the set's, at either step | 409 |
| a confirm with nothing staged, or after the window | 409 |
| an unsealed store with no material commitment yet | 409 |
| material the store does not accept | 403 |
| a confirm without the staged copy's check | 403 |

Proving the material: a sealed store is unsealed with it. An unsealed store
cannot test an unseal key, so the material must match `unlock.sha256`, the
commitment written at init and at every unlock of a sealed store. In both
cases both roles log in, as an unlock does. Every step is one audit line in
the custodian's log, with set digests and recipients, never material.

`GET /recipients` lists the set: `recipients`, `digest`, and `recorded`
(false for a store initialised before the reseal existed: the configured
set). The digest is `sha256:` over the members, trimmed, each once, sorted,
one per line, each line ending in a newline.

### `innsegl ca-custody reseal`

On the operator's machine, through the client service and the core:

1. `GET /_core/ca-custody/recipients`: the current set.
2. The new set: the current one with `--add` and `--remove` applied, or the
   whole of `--set FILE`. Refused here, before anything is opened: an empty
   set, a member that is no recipient, and a set without this machine. This
   machine is the recipient its identity file names: an X25519 key's own, or
   a `# public key: age1…` or `# recipient: age1…` comment line. `--opener`
   names it when the file does not. An unchanged set does nothing.
3. It prints the current set, the new set, each member added (`+`) or
   removed (`-`), both digests, and asks `[y/N]`. Anything but `y` or `yes`
   opens nothing and exits 27.
4. It opens the material (Touch ID), posts the reseal, checks that the
   staged copy is for the digest it showed, opens that copy (Touch ID again),
   and posts the confirm. A staged copy for any other set is never
   confirmed and expires.
5. It prints the new set's size and digest, and that trust-key backups now
   also encrypt to it.

A reseal is four custody calls; it fits in the core's per-machine limit.
The client service must be at least as new as the command: an older one
refuses the reseal routes with 403 (`restart the client service`).

## Files, volumes, containers

| Item | Holds |
|---|---|
| `innsegl-ca-store` | the key store |
| `innsegl-ca-custodian` | `innsegl ca-custodian serve` |
| `innsegl-ca-bootstrap` | mints the store's root and Fulcio's issuer config |
| `innsegl-ca-export`, `innsegl-ca-import` | one-shot import (profile `ca-import`) |
| `innsegl-ca-token-keeper` | keeps the token volume mounted; reads nothing |
| network `innsegl-ca-sign` | Fulcio and the custodian's signing gateway, nothing else |
| trust volume `innsegl-trust-ca-store` | the store's data |
| trust volume `innsegl-trust-ca-custody` | the sealed unlock material (`material/unlock.age`); beside it `recipients.txt` (the set it is sealed to, which the trust backup also encrypts to), `recipients.sha256` (that set's digest) and `unlock.sha256` (the material's commitment). None of the three opens anything |
| volume `innsegl-ca-token` | the CA's token, in memory; the custodian, the bootstrap and the keeper mount it, Fulcio does not |
| volume `<prefix>-sigstore_sigstore-fulcio-kms` | the store's root chain and issuer config; Fulcio and the custodian mount it read-only (the custodian is recreated when it changes, OPS-165). The bootstrap writes it as 65532; a new volume takes that owner from the bootstrap image, so no chown is needed (OPS-192) |
| backup items `ca-store/store.snap`, `ca-custody/unlock.age` | custody in a trust-key bundle |

Core routes (operator organisation workstations only, each with its one
method, under one per-machine rate limit): `GET /_core/ca-custody`,
`GET /_core/ca-custody/material`, `POST /_core/ca-custody/unlock`,
`GET /_core/ca-custody/recipients`, `POST /_core/ca-custody/reseal`,
`POST /_core/ca-custody/reseal/confirm`. Each goes to the custodian route of
the same name. The core reaches the custodian on an internal unlock network
and logs none of what it carries: one line per forwarded POST, with the
route and the installation.
The unlock network has three members: the custodian, `innsegl-core` and
`innsegl-api` (ADR-0082). The API is on no other new network. It requests
only the six custodian routes above, from an allowlist in its code, and
only after it has verified a fresh assertion from an active unlock key
([dashboard-api.md](dashboard-api.md#unlock-keys)). It logs none of what
they carry; each unlock and reseal step is an auth event with key ids and
recipient fingerprints.

## Unlock keys (dashboard)

An owner or admin of the operator's organisation enrols a hardware security
key from the account page. The browser derives two age X25519 recipients
from the key's PRF output (`internal/unlockkey`, format `innsegl unlock
v1`); the API stores them with the salts and never sees the PRF output. A
synced passkey (backup-eligible) and a key without a PIN are refused.

A key is **pending** until its custody recipient is in the sealed set,
**active** while it is, **revoked** for good once revoked. The state is read
from `GET /recipients` on every list, so a reseal from this command and one
from the dashboard both make a key active. A first key is applied from the
operator's machine (`innsegl ca-custody reseal --add <recipient>`); after
that an owner with an active key can apply new ones from the dashboard,
which proposes the current set plus every key not revoked, less every
revoked one. Revoking is forward-only (ADR-0082 decision 8): a revoked key
still opens older sealed copies and older bundles. The backup recipient is
recorded; bundles go to `recipients.txt`, which holds the custody
recipients.

## Exit codes and error classes

| Command | Code | Meaning |
|---|---|---|
| `ca-custodian`, `ca-custody` | 27 | the command failed |
| `ca-custody status` | 28 | the CA cannot sign: SEALED, or unsealed with the reason printed |
| `ca-custody reseal` | 27 | refused, declined, or failed; the material is unchanged unless the confirm was accepted |
| `ca-custody reseal` | 2 | no change named, or `--set` with `--add`/`--remove` |
| `ca-custodian ready` | 27 | not ready: the reason is printed |
| `ca-custody-restore` | 2 | refused: missing `CONFIRM`/`FROM` |
| `ca-custody-reset` | 2 | missing `CONFIRM=reset` |
| `ca-custody-reset` | 3 | refused: Fulcio runs on the store, its root is in the trust history, or the history could not be asked |

## Tests

- `internal/cacustody/*_test.go` (OPS-136 to OPS-145, OPS-153 to OPS-155,
  OPS-183 to OPS-186 in `continuity_test.go`, OPS-188 and OPS-189 in
  `gateway_test.go`: the gateway forwards only the two calls, and a store
  restart and unlock need no CA restart; OPS-201 to OPS-206 in
  `reseal_test.go`: the reseal and its refusals)
- `cmd/innsegl/cacustodiancli_test.go` (OPS-146, OPS-155, OPS-185, OPS-186,
  OPS-188: the gateway has its own listener),
  `cacustodycli_test.go` (BAK-029, CLI-021), `corecacustody_test.go` (OPS-147),
  `corecacustodyreseal_test.go` (CLI-052: the core carries the reseal routes,
  operator machines only), `cacustodyreseal_test.go` (CLI-053: `reseal`
  shows both sets, stops on no, refuses before any Touch ID, never confirms
  another set), `cacustodyresealstore_test.go` (CLI-054: a real store,
  reseal to two, restart sealed, unlock with the second; Docker, `-p 1`)
- `cmd/ca-bootstrap/*_test.go` (OPS-049, OPS-050, OPS-052, OPS-148)
- `internal/client/cacustody_test.go` (BAK-026 to BAK-028)
- `test/deploy/custody/cacustody_test.go` (OPS-051, OPS-149 to OPS-151, OPS-155, OPS-186: the custodian mounts the chain the CA presents, OPS-187: Fulcio holds no token, BAK-030)
- `test/deploy/custody/custodyvolumeowner_test.go` (OPS-192: a fresh KMS volume is the bootstrap's to write)
- `test/deploy/custody/devcustody_test.go` (OPS-129: live custody names unchanged, dev custody innsegl-dev-* throughout)
- `internal/api/unlockkeys_test.go`, `unlockkeys_store_test.go` (AUTH-013 to
  AUTH-018: the dashboard's unlock keys; AUTH-018 applies one by a reseal and
  unlocks a real store after a restart; Docker, `-p 1`)
- `scripts/ca-custody-selftest.sh` (OPS-049 to OPS-051)
- `scripts/ca-custody-reset-selftest.sh` (OPS-159)
- `internal/cacustody/store_test.go` OPS-136 also signs the way Fulcio asks, `transit/sign/<key>/sha2-256`

## Decisions

- [ADR-0074](../docs/adr/0074-trust-keys-are-backed-up-encrypted-and-off-the-host.md) the backup carries custody
- [ADR-0075](../docs/adr/0075-each-host-has-its-own-ca-password-and-the-ca-rotates-by-script.md) rotation
- [ADR-0076](../docs/adr/0076-the-ca-key-store-is-unlocked-by-the-operators-machine.md) custody
- [ADR-0082](../docs/adr/0082-a-second-unlock-device-a-hardware-security-key-through-the-dashboard.md) the reseal

## Runbooks

- [ca-custody.md](../runbooks/ca-custody.md)
- [trust-key-backup.md](../runbooks/trust-key-backup.md)
