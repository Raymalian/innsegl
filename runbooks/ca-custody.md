# CA key custody: the operator's machine unlocks the CA

Move the Fulcio CA key into a sealed store, with the operator's machine
unlocking it after every restart. Nobody types an unseal key. ADR-0076, #533.

`<repo>` is the innsegl checkout on the core: the host that runs the stack.
Every step says where it runs.

## Before you start

- The trust-key backup is on and drills cleanly (`runbooks/trust-key-backup.md`).
  Custody uses the same recipients: whoever can open the backup can unlock
  the CA.
- The operator's machine is enrolled (`innsegl connect`). Its identity file
  is at `~/.innsegl/trust-backup/identity.txt`.
- The client service on that machine is current. Run `innsegl connect
  --update --service` once on that machine. It rewrites the service as an
  interactive agent, which is what lets it ask for Touch ID.

## 1. Turn it on — the core

Add one line to `<repo>/deploy/compose/.env`:

```sh
INNSEGL_CA_CUSTODY=on
```

Then `make update`.

This starts the store and the custodian. On a new store, the custodian:

- initialises the store and creates the CA key inside it;
- seals the unlock material to the backup's recipients;
- revokes the root token.

Fulcio stays on the file CA for now.

**Check:**

```sh
docker logs innsegl-ca-custodian 2>&1 | tail -3
```

It prints `initialised: the CA key "innsegl-ca" is in the store`. `make update`
also prints `Fulcio still runs the file CA` with the next command.

## 2. Move Fulcio onto the store — the core

This is a rotation: a new root, minted from the store's key. Take a fresh
backup and drill it first (`runbooks/trust-rotation.md`, pre-flight 1). Then:

```sh
make innsegl-ca-rotate CONFIRM=rotate TO=custody MODE=retire REASON='CA key custody' BACKUP_MAX_AGE_HOURS=24
```

It mints the store's root and switches Fulcio. It then proves a real
certificate, ends the file CA's era in the trust history, and records the new
root. The file CA is left untouched in its volume, as the way back.

**Check:** it ends with `moved onto the CA key store` and the new root's
fingerprint. Then take a new backup and drill it: it now holds `ca-store` and
`ca-custody` too.

## 3. After a restart — the operator's machine

After any restart the store is sealed and the CA cannot sign. Within a minute
the client service shows a Touch ID prompt. Approve it.

From a terminal instead:

```sh
innsegl ca-custody status
innsegl ca-custody unlock
```

**Check:** `innsegl ca-custody status` prints `unlocked; the CA can sign`.

Fulcio may take up to a minute to come back after the unlock: it restarts on
its own once its token is there. While the store is sealed, Fulcio's log
reads `ecdsa public keys are not equal`.

If you decline the prompt, the service waits 15 minutes before asking again.
`innsegl ca-custody unlock` asks at once.

## Rollback

**During step 2:** the rotation puts Fulcio back on the file CA on its own
(exit 5).

**Afterwards, by hand — the core:**

```sh
make ca-custody-back
```

Fulcio is then on the file CA again, and that root's era has ended. Rotate to
a new file CA (`runbooks/trust-rotation.md`), then remove the `.env` line and
`make update`.

## Restore

The trust-key backup holds the store's own snapshot (`ca-store`) and the
sealed material (`ca-custody`). A bundle that says custody is on and lacks
either fails the drill.

On the operator's machine, extract the newest bundle:

```sh
innsegl trust-backup drill --extract <dir>
```

Copy `<dir>` to the core. Then, on the core:

```sh
make ca-custody-restore CONFIRM=restore FROM=<dir>
```

It replaces the store with a new one and restores the snapshot into it. It
puts the sealed material back. The store is left sealed under its original
keys. Unlock it from the operator's machine (step 3), then remove `<dir>` from
both machines.

**Check:** `innsegl ca-custody status` prints `unlocked`, and Fulcio serves the
root it served before.

Losing the operator's Secure Enclave key loses the unlock. The store's data
stays unreadable. Recovery is a new store and a new root:

1. `make ca-custody-back` puts Fulcio on the file CA.
2. Remove the two custody volumes.
3. Repeat steps 1 and 2.
