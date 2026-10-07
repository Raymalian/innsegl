# Trust-key backup: set up, check, restore

The core writes one encrypted bundle of its trust keys and its transparency
log every day. The operator's enrolled machine keeps copies. This runbook
turns it on, proves a bundle opens, and restores one. ADR-0074, #533.

`<repo>` is the innsegl checkout on the core. `<recipient>` is the public key
the bundle is encrypted to; the identity that opens it never goes on the
core. Every step names where it runs.

## What a bundle holds

| item | from | restore into |
|---|---|---|
| `fulcio-pki` | the Fulcio CA certificate, encrypted key and config | volume `innsegl-trust-fulcio-pki` |
| `fulcio-ca-password` | `INNSEGL_FULCIO_CA_PASSWORD` | `deploy/compose/.env`, if it is not the default |
| `rekor-key` | the log's signing key | volume `innsegl-trust-rekor-key` |
| `trillian-db` | the log's database, as SQL from one consistent snapshot | the log database, `test` |
| `identity-secret` | the pseudonymisation secret | volume `innsegl-trust-identity-secret` |
| `spire-upstream-ca` | SPIRE's upstream CA | volume `innsegl-spire_spire-pki-server` |
| `gateway-ca-key` | the gateway's CA key | volume `innsegl-core_innsegl-gateway-ca-key` |
| `trust-history` | ADR-0073's history and sentinels | volume `innsegl-trust-history` |

The ledger is not in it: `runbooks/backup-ledger.md` covers the ledger.

## 1. Turn it on — the core

Add two lines to `<repo>/deploy/compose/.env` (bring-up keeps lines it did
not write):

```sh
COMPOSE_PROFILES=trust-backup
INNSEGL_TRUST_BACKUP_RECIPIENTS=<recipient>
```

More than one recipient is a space-separated list. Then `make update`.

**Check:** `docker logs innsegl-trust-backup` prints
`wrote trust-backup-<time>.tar.age: 8 items`. With no recipient it prints
`NO BUNDLE WRITTEN: … no recipient is configured`, and writes nothing.

**Rollback:** remove the two lines and `make update`. The bundles stay on the
`innsegl-trust-backups` volume until you remove it.

## 2. Keep copies — the operator's machine

The client service fetches on start and every hour. To fetch now:

```sh
innsegl trust-backup fetch
```

**Check:** `innsegl status` prints `trust backup  newest trust-backup-…, 2h old`.
`WARN` there means no copy, or none newer than two days. A 403 means this
machine may not fetch: only an active workstation of the operator
organisation, enrolled by its owner or an admin, may.

## 3. Drill — the operator's machine, every quarter

```sh
innsegl trust-backup drill
```

It opens the newest copy with `~/.innsegl/trust-backup/identity.txt`
(`--identity` names another), checks the outer sha256 before it asks for the
identity, then every file against the manifest, and lists every item. A
hardware-held identity asks to be unlocked. Nothing is written.

**Check:** `check  ok  every checksum matches`, and no `MISSING` line. Exit 0.

## 4. Restore — a throwaway stack first

Rehearse on a throwaway stack before a real one, the way `cutover.md` was
rehearsed: another host, or a dev-marked checkout (ADR-0072), whose names and
trust volumes share nothing with the live stack. Below, the names are the
live ones; a dev stack's are `innsegl-dev-*`.

**On the machine that holds the identity:**

```sh
innsegl trust-backup drill --extract <dir>
```

`<dir>` must not exist. It now holds each item's files in the clear, 0600.
Copy it to the target host over a channel you trust, and delete it from both
machines when step 4 is done.

**On the target host, stack down** (`make innsegl-down`, and `stop` on the
Sigstore and SPIRE projects, as `cutover.md` step 1), load each volume:

```sh
deploy/compose/trust-volumes.sh ensure
restore() { docker run --rm -v "<dir>/$1":/from:ro -v "$2":/to alpine:3.22 sh -c 'cp -a /from/. /to/'; }
restore fulcio-pki      innsegl-trust-fulcio-pki
restore rekor-key       innsegl-trust-rekor-key
restore trust-history   innsegl-trust-history
restore identity-secret innsegl-trust-identity-secret
```

Restore `spire-upstream-ca` and `gateway-ca-key` into their volumes the same
way. Then fix the owners: the files arrive owned by the copying user.
- The Fulcio, Rekor and SPIRE files: compare with a fresh `make start`'s
  volumes.
- The identity secret, the gateway CA key and the trust history: uid 1000.

Then the log. Start only its database, and load the export into it. The
export drops and recreates every table. `<trillian-db-password>` is the one in
`deploy/compose/sigstore.yml`.

```sh
docker compose -f deploy/compose/sigstore.yml up -d trillian-db
docker exec -i innsegl-sigstore-trillian-db mysql -utest -p<trillian-db-password> test < <dir>/trillian-db/trillian.sql
```

Then `make start`.

**Check, in this order:**
1. `docker logs innsegl-sigstore-trillian-log-server` names the tree id the
   Rekor pin names (`scripts/rekor-tlog-pin.sh`).
2. A commit signed **before** the bundle was written verifies, as
   `cutover.md` step 6: `VERDICT: VERIFIED`, all three checks `verified`.
3. The trust watch's sentinels pass: `innsegl status` shows no `trust WARN`.

**Rollback:** a throwaway stack is removed with its prefix's volumes. On a
real host, keep the old volumes until step 3 of the check passes.

## Gaps

| gap | what to do instead |
|---|---|
| No command restores a bundle into volumes; step 4 is manual | Rehearse it on a throwaway stack each quarter, as above. |
| The restore needs every volume's owner put back by hand | Compare with a freshly started stack's volumes. |
| The search index is not in the bundle | `scripts/rekor-reindex.sh` rebuilds it from the restored log. |
| A bundle is one day old at most; what changed since is not in it | The trust history and the ledger backups cover what changed. |
