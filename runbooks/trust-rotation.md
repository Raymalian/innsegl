# Trust rotation: replace the Fulcio CA

Replace the Fulcio CA without losing what the old one signed. The old root
stays in the trust history (ADR-0073), so commits it signed still verify.
ADR-0075, #533.

`<repo>` is the innsegl checkout on the core: the host that runs the stack.
Every step says where it runs.

## When to rotate

| Why | MODE | What the old root still vouches for |
|---|---|---|
| Expiry is near: `innsegl status` prints a `trust WARN` a year and 90 days before | `retire` | everything the log took in before the switch, plus the skew bound (60s) |
| A planned change, nothing wrong | `retire` | the same |
| The CA key, or its password, may have been exposed | `revoke` | only what the log took in **strictly before** the switch. No skew. |

`revoke` also cuts off good commits the old CA signed during the switch.
Pause agents first (pre-flight step 3).

This rotates a **file CA** only. A host running Fulcio under key custody
(`sigstore.keycustody.yml`) is refused; see the gaps at the end.
`TO=custody` moves a file CA onto the CA key store instead
(`runbooks/ca-custody.md`, ADR-0076).

## Pre-flight

### 1. A fresh encrypted backup, and a drill — the operator's machine

Do this before anything else. It is what makes a bad rotation recoverable.

With the trust-key backup service on (`runbooks/trust-key-backup.md`):

On the core, write a bundle now:

```sh
docker restart innsegl-trust-backup
docker logs --since 2m innsegl-trust-backup
```

**Check:** it prints `wrote trust-backup-<time>.tar.age`.

On the operator's machine, fetch it and open it:

```sh
innsegl trust-backup fetch
innsegl trust-backup drill
```

**Check:** `check  ok  every checksum matches`, no `MISSING` line, exit 0.

Without the backup service, take a copy of the four trust volumes another
way, and prove it opens on another machine, before going on. Do not rotate
without one.

### 2. This host runs this release — the core

```sh
cd <repo>
docker inspect -f '{{json .Config.Cmd}}' innsegl-sigstore-fulcio
```

**Check:** it contains `--config=/etc/fulcio/serve.yaml`. If it contains
`--fileca-key-passwd`, run `make update` first. That moves the host onto its
own CA password (ADR-0075) and recreates Fulcio.

Once `ca.pass` exists, `INNSEGL_FULCIO_CA_PASSWORD` is no longer read.
Remove its line from `deploy/compose/.env`; the password lives on in the
CA volume and in its backups.

### 3. Pause agents

Stop new agent sessions for a few minutes. Two reasons:
- under `revoke`, a commit the old CA signs during the switch is refused,
  because nothing can tell it from one the exposed key signed;
- if the rotation fails after the switch and rolls back, a commit signed in
  those seconds chains to a new root that is then discarded.

The script checks the rest itself, and refuses before touching anything:
the stack is up, Fulcio is the file CA, the root Fulcio serves is the root on
its volume, and the trust history holds that root.

## Rotate — the core

```sh
cd <repo>
make innsegl-ca-rotate CONFIRM=rotate MODE=revoke REASON='<why, in one line>' BACKUP_MAX_AGE_HOURS=2
```

`MODE=retire` for a planned rotation. `BACKUP_MAX_AGE_HOURS` refuses unless
the core holds a trust-key bundle that new; leave it out on a host without
the backup service.

What it does, each step checked before the next:

1. **archive**: copies the CA (`ca.crt`, `ca.key`, `ca.pass`, `serve.yaml`)
   to `archive/<STAMP>` in the CA's own volume. The key stays locked with its
   own password. Never deleted.
2. **stage**: makes the new CA the way the first one was made, with a new
   generated password.
3. **switch**: notes the time, moves the new CA into place, restarts Fulcio,
   waits until it serves the new root.
4. **prove**: gets a real certificate from Fulcio and checks it chains to the
   new root. Nothing is written to the transparency log.
5. **end**: writes the old root's end date into the trust history: the time
   of the switch, with your `REASON`.
6. **record**: adds the new root to the trust history.

**Check:** the last lines read

```
ca-rotate: rotated. Old root <key id> is revoked at <time>; it is kept as archive/<STAMP>.
ca-rotate: new root sha256 fingerprint <fingerprint>
```

Write down `<STAMP>`.

| Exit | Meaning | What to do |
|---|---|---|
| 0 | rotated | the checks below |
| 2 | usage | nothing touched; fix the command |
| 3 | pre-flight refused | nothing touched; the message says why |
| 4 | failed before the switch | nothing in use changed; fix the cause, run again |
| 5 | failed after the switch, rolled back | Fulcio serves the old root again; the history is unchanged |
| 6 | the rollback failed too | the message prints the command to finish it; run it now |

A `WARN` that the new root is not recorded is safe: Fulcio publishes it, so
new commits verify, and the core's trust pass records it within a day.

## Check afterwards

### 1. Fulcio serves the new root — the core

```sh
curl -s http://127.0.0.1:5555/api/v1/rootCert | openssl x509 -noout -fingerprint -sha256
```

**Check:** the fingerprint the rotation printed.

### 2. Old and new commits verify — the dashboard, or the core

On the dashboard's **Verify a commit** page:
- a commit signed **before** the rotation: `verified`, and the chain check
  names a trust history entry;
- a commit signed **after** it: `verified` under the published root.

From the core instead, with the history copied out of the core:

```sh
docker exec innsegl-mcp cat /run/innsegl/trust/trust-history.json > /tmp/trust-history.json
INNSEGL_FULCIO_URL=http://127.0.0.1:5555 INNSEGL_REKOR_URL=http://127.0.0.1:$(scripts/rekor-port.sh) INNSEGL_OIDC_ISSUER=http://spire-oidc:8080 innsegl verify <sha> --repo <clone> --trust-history /tmp/trust-history.json
```

**Check:** `VERDICT: VERIFIED` for both.

### 3. The sentinels — the core, the next day

`innsegl status` shows no `trust WARN`. The daily trust pass picks a
sentinel commit for the new root once one reaches the mirror.

### 4. A new backup — the core and the operator's machine

The bundle from pre-flight holds the **old** key. Take a new one and drill
it, as pre-flight step 1. Keep the old bundle too: it is the only copy of
the old CA outside this host.

Then resume agents.

## Rollback

**During a rotation** the script rolls back on its own (exit 5).

**By hand**, to put an archived CA back — the core:

```sh
cd <repo>
make innsegl-ca-rollback CONFIRM=rollback STAMP=<STAMP>
```

It first keeps the CA in use as `archive/<time>-before-rollback`, then puts
`<STAMP>` back and restarts Fulcio. **Check:** step 1 above prints the old
root's fingerprint.

A rollback does not change the trust history, which is append-only. After a
**completed** rotation the old root already has its end date, so commits it
signs after a rollback do not verify. Do not roll back a completed rotation;
rotate forward again instead.

## What stays where

| Item | Where | Kept |
|---|---|---|
| The new CA and its password | the CA volume, `ca.key`, `ca.pass`, `serve.yaml` | in use |
| Every old CA, each with its own password | the CA volume, `archive/<STAMP>/` | forever |
| Every root's public certificate and end date | the trust history | forever, append-only |

## Gaps

| Gap | What to do instead |
|---|---|
| A lost CA key cannot be archived, so the script refuses (exit 4) | Restore the CA volume from the trust-key backup, then rotate. |
| Key custody hosts are refused | Rotate the key in the store and re-mint the root; record the new root with `docker exec -i innsegl-mcp innsegl trust-history record --kind fulcio_root < root.pem`, and end the old one with `innsegl trust-history end`. |
| The transparency log's key is not rotated by this | The trust history already accepts more than one log key; there is no script for it yet. |
| A rotation is not an event in the ledger | The trust history and its backups are the record. A ledger event is a protected schema change (ADR-0073). |
