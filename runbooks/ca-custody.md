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

The same unlock repairs an unsealed store whose CA token is dead: `status`
then prints `unlocked, but the CA CANNOT sign` with the reason, and `make
update` prints `repair: on the operator machine, run: innsegl doctor`,
which runs the same unlock. Signing resumes at once; no container restarts, because Fulcio
holds no token (it signs through the custodian).

If you decline the prompt, the service waits 15 minutes before asking again.
`innsegl ca-custody unlock` asks at once.

## Signing stopped — the operator's machine

Signs: `innsegl status` prints `signing: FAILING since <time>`, the client
service shows a notification, or a commit is refused with `signing is down`.

1. Mac: run `innsegl doctor`. Approve Touch ID if it asks.
2. If it prints a line starting `VM:`, run that command on the VM. Then run
   `innsegl doctor` on the Mac again.
3. Done when doctor prints `signing: OK (probe passed <time>)` and exits 0.
4. Then: `innsegl resign` for any commit made unsigned during the outage, and
   check that the dashboard's unsigned-commit alerts are cleared.

Doctor checks, in order: the client service, the hooks in the repository,
the core and its clock, the CA key store, the core's readiness, and the
signing probe. It restarts the client service and unlocks the store itself.
It never runs anything on the VM, and never removes a volume, resets or
restores the store, or rotates the CA.

If doctor says `ca custody: DRIFTED`, the store's key is not the key in
Fulcio's `chain.pem`. Nothing on the Mac repairs that, and an unlock does
not change it. It comes from a rotation or a restore that did not finish:
see [trust-rotation.md](trust-rotation.md) and the Restore section below.
Do not start the store over: Fulcio and the trust history depend on it.

## Add a second unlock device — the operator's machine

With one recipient, losing that machine's key loses the unlock. A reseal
seals the **same** material to a new set (ADR-0082 decision 7). The CA key,
the store and its unseal key do not change, and nothing restarts.

You need the new device's public recipient, `age1…`. It is public: copying
it opens nothing.

1. Mac: list the set the material is sealed to now:

   ```sh
   innsegl ca-custody recipients
   ```

2. Mac: add the new recipient:

   ```sh
   innsegl ca-custody reseal --add age1...
   ```

   It prints the current set, the new set, the added member (`+`) and both
   digests, then asks `[y/N]`. Check the added recipient character by
   character against the new device, then answer `y`. Approve Touch ID
   twice: once to open the material, once to open the staged copy.

3. **Check:** it prints `resealed: the unlock material is sealed to 2
   recipient(s)`, and `innsegl ca-custody recipients` lists both.

4. Prove the new device: on it, after the next sealed restart (or a
   planned one), run `innsegl ca-custody unlock --identity <its identity
   file>`. It prints `unlocked; the CA can sign`.

5. Take a new trust-key backup and drill it. New bundles also encrypt to the
   new set; older bundles keep the recipients they were written to.

To remove a device, use `--remove age1...` from a device that stays in the
set. A removed device no longer opens new copies, but older copies and older
bundles still open with it. To replace the whole set, write it to a file, one
recipient per line, and use `--set <file>`.

Refused, with nothing opened and nothing changed: an empty set, a set
without the machine you run it on, and a member that is not a recipient.
If the confirm does not arrive within 10 minutes, the custodian drops the
staged copy and the old material stands. Run the command again.

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

## Start the store over — the core

Only for a store nothing depends on yet: Fulcio is not on it, and its root
is not in the trust history. A store's policies cannot be changed after
provisioning (its root token is revoked), so a store provisioned with a wrong
one is replaced, never repaired.

```sh
cd <repo> && make ca-custody-reset CONFIRM=reset && make update
```

**Check:** `docker logs innsegl-ca-custodian` prints `initialised`. Then take
a new trust-key backup and drill it before step 2. It refuses (exit 3) while
Fulcio runs on the store or the trust history holds its root.

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
