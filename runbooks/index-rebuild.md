# Runbook — rebuilding the ledger index

**Doc 05 §2 deliverable.** Read the first two sections before typing anything.
They are short, and they are the ones that stop an operator making the outage
permanent.

---

## 0. The asymmetry, in the order it matters at 3am

**Losing the database loses convenience, not proof.**

| | Postgres (the hot tier) | Sealed segments + Rekor anchors |
|---|---|---|
| What it is | an index over events | the evidence that the index is honest |
| How it is protected | **backups** — ordinary, boring, restorable | **verification** — it is already immutable |
| Losing it costs | query speed, the dashboard, the reconciler's inputs | the ability to prove the index was not rewritten |
| The correct verb | *restore* | *re-verify* — **never restore** |

Three consequences follow, and each one changes what you type:

1. **Attribution does not depend on this database at all.** `innsegl verify`
   has no ledger flag and no way to be given one (I5). While Postgres is down,
   every commit anyone ever signed is still fully verifiable by anybody:

   ```bash
   innsegl verify <commit-sha> \
     -repo /path/to/repo \
     -fulcio-url "$INNSEGL_FULCIO_URL" \
     -rekor-url  "$INNSEGL_REKOR_URL"
   ```

   Exit 0 verified · 3 failed · 4 unavailable · 5 unattributed · 6 unusable.
   Run this **first**. If it is green, the outage is an availability incident,
   not an integrity incident, and you have time.

2. **Restoring Postgres is ordinary.** It is a database. Use your backups.
   Nothing in this document asks you to be clever about it.

3. **Segments are never restored.** A sealed segment object in the bucket is
   under object lock. There is no state it can be in that a write would repair.
   If a segment looks wrong, the object is not the problem — see §2.

---

## 1. What a sealed segment actually contains

Operators reach for segments expecting a backup. They are not one, and knowing
that in advance saves an hour.

A segment object is exactly five members (`internal/segment/object.go`,
ADR-0006):

```json
{"event_hashes":["sha256:…","sha256:…"],"first_position":1,"last_position":14,"segment_format_version":"1","segment_merkle_root":"sha256:…"}
```

**Event hashes. Not event bodies.**

So:

- A segment can tell you **which events existed, in which order** over a range
  of chain positions, and prove that range's Merkle root is in a transparency
  log somebody else runs.
- A segment **cannot** give you back an event's `event_type`, `run_id`, `ts`,
  `spiffe_id`, `repo`, `commit_sha` or anything else. Those live only in the
  `canonical` column of `innsegl.events`, i.e. only in a Postgres backup.

> **There is no rebuild-from-segments-alone.** If every Postgres backup is gone,
> the event bodies are gone and no procedure in this repository recovers them.
> What survives is (a) every attribution claim, still independently verifiable
> from git + Fulcio + Rekor, and (b) proof of the shape and ordering of the
> ledger that recorded them. That is the honest meaning of "loses convenience,
> not proof", and it is a smaller claim than "we can rebuild everything".

The segments' job in a rebuild is therefore **adjudication, not supply**: they
are how you find out whether the backup you just restored is the ledger you
sealed.

---

## 2. The refusal list

Every action here is tempting during an outage and every one of them is wrong.
Two of them succeed silently, which is why they are listed with what to type
instead rather than a warning.

### 2.1 Never restore, overwrite or re-upload a sealed segment

A segment object's name is the SHA-256 of its bytes. There is no such thing as
a corrected segment: different bytes are a different segment.

**Measured** against MinIO with object lock in COMPLIANCE mode:

```
$ mc rm --force --version-id <v> rb/innsegl-segments/sha256:86c80ddc…
mc: <ERROR> Failed to remove …
    Object … is WORM protected and cannot be overwritten
```

But the ordinary delete is **not** refused:

```
$ mc rm rb/innsegl-segments/sha256:86c80ddc…
Created delete marker … (versionId=c9686339-…)

$ mc ls rb/innsegl-segments/          # the segment is gone
$ mc ls --versions rb/innsegl-segments/sha256:86c80ddc…
… c9686339-… v2 DEL sha256:86c80ddc…
… 2eeb88ee-… v1 PUT sha256:86c80ddc…   ← still there
```

Object lock protects **versions**, not **keys**. A missing segment during an
incident is very often a delete marker, not a destroyed object. The repair is
to remove the *marker*:

```bash
mc ls --versions "$ALIAS/$BUCKET/$SEGMENT_ID"          # find the DEL version
mc rm --force --version-id "<the DEL version>" "$ALIAS/$BUCKET/$SEGMENT_ID"
```

Never `mc cp` the object back. You would be writing a new version of an
immutable record, and the version history would show you doing it.

### 2.2 Never restore over a live ledger database

`pg_restore --clean`, `dropdb && createdb`, "just re-run the migrations on top"
— all of these are DDL, and **the append-only trigger is DML-level**. It does
not fire on `DROP`.

**Measured** on a database holding a real chain:

```
$ psql -c 'DELETE FROM innsegl.events WHERE chain_position = 5'
ERROR:  innsegl: DELETE on innsegl.events is refused: the ledger is append-only …
$ psql -c 'UPDATE innsegl.events SET event_type = ...'      → refused (IN001)
$ psql -c 'TRUNCATE innsegl.events'                         → refused (IN001)
$ psql -c 'DELETE FROM innsegl.events WHERE chain_position = 9999'
ERROR:  … refused …                       ← even a DELETE matching no row
$ psql -c 'BEGIN; DROP TABLE innsegl.events CASCADE; ROLLBACK'
BEGIN
DROP TABLE                                ← no refusal. DDL walks past the guard.
ROLLBACK
```

So: **restore into a new, empty database. Always.** Then cut over. A restore
into the live database is the one action whose failure mode is silent.

```bash
createdb -h "$PGHOST" -U "$PGUSER" innsegl_rebuild
pg_restore -h "$PGHOST" -U "$PGUSER" -d innsegl_rebuild --exit-on-error innsegl.dump
```

### 2.3 Never trust a restore because it loaded cleanly

`pg_dump` emits the data **before** it emits the triggers. The chain-link
trigger therefore does not run during a restore, and a doctored dump loads
green.

**Measured.** A plain dump with one `prev_event_hash` altered by a single
character:

```
$ psql -v ON_ERROR_STOP=1 -d innsegl_tampered -f plain-tampered.sql
(no error)
$ psql -d innsegl_tampered -Atc 'SELECT count(*) FROM innsegl.events'
14
$ psql -d innsegl_tampered -Atc 'DELETE FROM innsegl.events WHERE chain_position=5'
ERROR:  … append-only … refused …         ← the guard is back on, too late
```

The ledger's own guards protect a *running* ledger. They say nothing about the
bytes you just loaded into it. §5 is the check that does.

### 2.4 Never re-run the sealer to "fix" a range

Sealing is idempotent by content address, so re-sealing an identical range is
harmless — and useless. Re-sealing a range you have *changed* produces a
different `segment_id`, which is a second object claiming positions an existing
object already claims. That is drift, and it is what `ledger_drift_detected`
exists to report. If the range changed, the ledger changed, and you have an
integrity incident rather than a rebuild.

### 2.5 Never let a rebuilt index into service before §5 and §6 pass

An index that has not been checked against the segments is a database, not a
ledger.

---

## 3. Decide what you lost

| Symptom | This is | Go to |
|---|---|---|
| Postgres unreachable, data intact | availability | restart it; §0 note 1 tells the auditor what is still true |
| Postgres data lost, backup exists | ordinary restore | §4 |
| Postgres data lost, no usable backup | permanent loss of event bodies | §1's warning, then §7 — record what is gone |
| Segment missing from the bucket | usually a delete marker | §2.1 |
| Segment present but fails verification | integrity incident, **not** a rebuild | stop; do not overwrite anything; §5 gives you the evidence |
| Index restored but disagrees with a segment | integrity incident | §5, then §7 |

---

## 4. Restore Postgres, into a new database

```bash
export PGHOST=... PGUSER=... PGPASSWORD=...

createdb innsegl_rebuild
pg_restore -d innsegl_rebuild --exit-on-error /backups/innsegl-<date>.dump
```

**Verified:** a `pg_restore` into a fresh database preserves `innsegl.chain`,
so the rebuilt database keeps the **original `chain_id`**:

```
$ psql -d innsegl        -Atc 'SELECT chain_id FROM innsegl.chain'
11fe7294-1af0-44f1-b1c0-3cc1bcf7ed09
$ psql -d innsegl_restore -Atc 'SELECT chain_id FROM innsegl.chain'
11fe7294-1af0-44f1-b1c0-3cc1bcf7ed09
```

### 4.1 If you are replaying events rather than restoring a dump

Only possible if you hold the event bodies from somewhere other than a dump.
Apply the schema and insert **in ascending `chain_position` order**:

```bash
psql -v ON_ERROR_STOP=1 -d innsegl_rebuild -f migrations/0001_ledger.sql
psql -v ON_ERROR_STOP=1 -d innsegl_rebuild -f migrations/0002_idempotency.sql
```

> **There is no `innsegl migrate` subcommand.** `innsegl serve -migrate`
> (`$INNSEGL_MIGRATE`) applies migrations, but it starts a server, which needs
> SPIRE and Sigstore. For a rebuild, apply the SQL files directly, as above.
> They are the same files the binary embeds.

Ordering is not advice. **Measured:**

```
$ tac load.sql | psql -v ON_ERROR_STOP=1 -d innsegl_rebuild
ERROR:  innsegl: chain_position 14 has no predecessor at 13: positions are
        strictly consecutive (doc 02 §2)
$ psql -v ON_ERROR_STOP=1 -d innsegl_rebuild -f load.sql
INSERT 0 1   (×14)
```

On this path the chain-link trigger *does* run, on every row, and a gap or a
bad link is refused as it is inserted (SQLSTATE `IN002`).

> **A fresh migrate mints a new `chain_id`, and it cannot be corrected.**
> Migration 0001 inserts the chain row with `DEFAULT gen_random_uuid()`, and
> `innsegl.chain` is append-only:
>
> ```
> $ psql -d innsegl_rebuild -Atc 'SELECT chain_id FROM innsegl.chain'
> a5b79565-6f03-4027-b1cb-6cc9e6f3a017      ← not the original
> $ psql -d innsegl_rebuild -Atc "UPDATE innsegl.chain SET chain_id = '11fe7294-…'"
> ERROR:  innsegl: UPDATE on innsegl.chain is refused …
> ```
>
> The genesis constant is unchanged, so the chain still verifies; only the
> storage-level name differs. Record the original `chain_id` alongside the
> rebuild (§7) and update anything that pinned it. There is no shipped way to
> carry it across a fresh migrate.

---

## 5. Check the restore against itself

Three SQL checks, in this order. All three are **measured** — each one was run
against a deliberately damaged restore and found the damage.

### 5.1 Do the bodies hash to their hashes?

This is the check that turns a segment full of hashes into a statement about
event *bodies*.

```sql
SELECT chain_position,
       'sha256:' || encode(sha256(canonical), 'hex') AS recomputed,
       event_hash
FROM   innsegl.events
WHERE  'sha256:' || encode(sha256(canonical), 'hex') <> event_hash
ORDER  BY chain_position;
```

Zero rows is the only acceptable result. On a restore with one byte of one
event body altered:

```
5|sha256:36d71f5498f2de…|sha256:70abcd6d1dde6f…
```

### 5.2 Does every event link to its predecessor?

```sql
-- genesis
SELECT e.chain_position
FROM   innsegl.events e, innsegl.chain c
WHERE  e.chain_position = 1 AND e.prev_event_hash <> c.genesis_prev_event_hash;

-- every later link
SELECT a.chain_position, a.prev_event_hash, b.event_hash
FROM   innsegl.events a
JOIN   innsegl.events b ON b.chain_position = a.chain_position - 1
WHERE  a.prev_event_hash <> b.event_hash
ORDER  BY a.chain_position;
```

On the doctored restore from §2.3 this returns `5`. Zero rows is the only
acceptable result.

### 5.3 Are the positions contiguous?

```sql
SELECT count(*)            AS events,
       min(chain_position) AS first,
       max(chain_position) AS last,
       max(chain_position) - min(chain_position) + 1 - count(*) AS missing
FROM   innsegl.events;
```

`missing` must be `0` and `first` must be `1`.

**What these three cannot catch.** A forgery that is internally consistent.
**Measured:** a restore in which position 7's `event_hash` was replaced and
position 8's `prev_event_hash` re-linked to it — two edits — satisfies every
constraint and trigger the database has:

```
$ psql -v ON_ERROR_STOP=1 -d innsegl_forged -f forged.sql
INSERT 0 1   (×14)
$ psql -d innsegl_forged -Atc 'SELECT count(*) FROM innsegl.events'
14
```

That is what §6 is for. The database cannot adjudicate its own contents; only
something outside it can.

---

## 6. Check the restore against the sealed segments

### 6.1 Fetch the segments — read-only

```bash
mkdir -p ./segments
mc alias set seg "https://$INNSEGL_OBJECT_STORE_ENDPOINT" \
  "$INNSEGL_OBJECT_STORE_ACCESS_KEY" "$INNSEGL_OBJECT_STORE_SECRET_KEY"
mc cp --recursive "seg/$INNSEGL_OBJECT_STORE_BUCKET/" ./segments/
```

Each file is named by its `segment_id`, which is its object key, which is the
SHA-256 of its own bytes. Do not rename them; the name is a check.

Confirm the store is still refusing deletions while you are here — this is the
shipped SEG-005 canary, and doc 05 §2 makes it a scheduled job, not a
deploy-time ritual:

```bash
innsegl canary -min-bucket-retention 720h
```

**Measured** against MinIO with COMPLIANCE lock: exit 0, eight named checks,
including `version_delete_refused` and `privileged_bypass_delete_refused`.
Exit 3 means the store permits deletion — that is a bigger incident than your
outage. Exit 4 means nothing was proved.

### 6.2 Dump the rebuilt index's hashes and compare

```bash
psql -d innsegl_rebuild -Atc \
  'SELECT event_hash FROM innsegl.events ORDER BY chain_position' > index.hashes

runbooks/verify-rebuilt-index.sh --segments ./segments --index-hashes index.hashes
```

Exit 0 verified · 2 usage · 3 a check failed · 4 could not run.

The gate re-derives doc 02 §4.6 from the document, in shell, and its self-test
pins the answer against the constants the Go sealer commits — so a disagreement
between the two implementations is loud rather than silent (doc 04 §5.4).

**Measured, on the good rebuild:**

```
==> sealed segments in ./segments
    ok  positions 1..14 (14 events)  sha256:86c80ddc52dda7c1b4db79204e677005893e9a5f1cd0f5ff8042de45fd518dc2
        root sha256:1a3a08ee2021f778d13e8356740245621b1ea3ecc761a4e42714c42ce86dd14b

    1 object(s), positions 1..14 covered by a sealed segment

==> rebuilt index: 14 event(s), positions 1..14

rebuilt index vs sealed segments: OK
```

**Measured, on the internally consistent forgery from §5 that the database
accepted:**

```
FAIL: the index disagrees with a sealed segment at chain position 7
      sealed  sha256:d555eca4b95f2b5a31775be9f5a65fa7fa0183b1375c3174df35a52006b1ac4b
      index   sha256:deadbeefd555eca4b95f2b5a31775be9f5a65fa7fa0183b1375c3174df35a52b
      segment sha256:86c80ddc52dda7c1b4db79204e677005893e9a5f1cd0f5ff8042de45fd518dc2
      This index is not a rebuild of that ledger. Do not put it into service (I4)

rebuilt index vs sealed segments: FAIL (1 finding(s))
```

That is the whole architecture in one screen: the database said yes, the sealed
segment said no, and the sealed segment is the one that has been in a
transparency log since the day it was written.

**What this step does not cover.** Positions past the last sealed one. The gate
reports them explicitly:

```
    positions 15..N are not covered by any segment here.
    They are restored, not proved: nothing in this directory can confirm them.
```

The unsealed tail of a live ledger is normal. It is also unproved, and it must
be described that way in the incident record — never rounded up to "verified".

### 6.3 Check the segment roots are in the transparency log

The segments prove the index; Rekor proves the segments. The anchoring members
live on the *superseding* `segment_sealed` event (doc 02 §3), so the rebuilt
index names its own anchors:

```sql
SELECT convert_from(canonical, 'UTF8')
FROM   innsegl.events
WHERE  event_type = 'segment_sealed'
ORDER  BY chain_position;
```

For each event carrying `anchor_rekor_entry_uuid`, fetch the entry and check
that the entry's subject is that segment's root. An anchor is a `hashedrekord`
whose `spec.data.hash.value` is the Merkle root **as bare hex**, without the
`sha256:` prefix (`internal/segment/rekor.go`):

```bash
curl -sS -H 'Accept: application/json' \
  "$INNSEGL_REKOR_URL/api/v1/log/entries/$UUID" \
| python3 -c '
import base64, json, sys
for uuid, e in json.load(sys.stdin).items():
    body = json.loads(base64.b64decode(e["body"]))
    print(uuid, body["spec"]["data"]["hash"]["value"], e.get("integratedTime"))'
```

The printed hash must equal the segment's `segment_merkle_root` with
`sha256:` stripped.

> **WRITTEN, NOT RUN.** Everything else marked *Measured* in this runbook was
> executed. This step was not: it needs a Rekor instance, and the machine this
> was written on had none free. The endpoint, the entry kind and the bare-hex
> form are read from `internal/segment/rekor.go`, not from memory.

> **NOT SHIPPED.** There is no `innsegl verify-segment` or
> `innsegl seal -verify`. `innsegl verify` is about *commits* and deliberately
> takes no ledger and no segment. Checking a segment's anchor is the manual
> query above until a subcommand exists for it.

---

## 7. Cut over, and write down what is true

1. Point the MCP at the rebuilt database and **require the append-only role**:

   ```bash
   innsegl serve -dsn "$INNSEGL_LEDGER_DSN" -require-append-only-role
   ```

   `$INNSEGL_REQUIRE_APPEND_ONLY_ROLE` sets the same thing. Without it the
   server logs `DATABASE ROLE IS OVER-PRIVILEGED` and starts anyway. A rebuild
   is exactly when a role gets recreated with too much, so set it here even if
   you do not set it elsewhere.

2. Run the reconciler once and read the report before scheduling it:

   ```bash
   innsegl reconcile -once -json \
     -dsn "$INNSEGL_LEDGER_DSN" -rekor-url "$INNSEGL_REKOR_URL" \
     -workspace "$INNSEGL_WORKSPACE" -trust-domain "$INNSEGL_TRUST_DOMAIN"
   ```

3. Record, in the incident write-up:

   - the original `chain_id` and the rebuilt one, if they differ (§4.1);
   - the backup used, and its timestamp;
   - the highest chain position **covered by a sealed segment**, and the
     highest position in the index — the difference is the restored-but-unproved
     tail;
   - the `verify-rebuilt-index.sh` output, verbatim;
   - the canary's output, verbatim;
   - any event bodies that could not be recovered, by position range.

**Do not append a ledger event describing the rebuild.** There is no event type
for it. Event type names are a protected string set (doc 02 §3), so inventing
`index_rebuilt` is a major release with a migration attestation (doc 08), not
an incident action. The record of a rebuild lives outside the ledger, which is
correct: the ledger records what agents did, not what operators did to the
database.

---

## 8. Gaps this runbook had to work around

Recorded here rather than papered over. Each is a command an operator would
reasonably expect to exist and does not.

| Wanted | Status |
|---|---|
| `innsegl seal` | **wired but not implemented.** `innsegl seal` prints `innsegl seal: not implemented` and exits 1. `internal/segment` has the sealer, the anchorer and the WORM writer; nothing in `cmd/innsegl` calls them. A production deployment therefore has no segments yet, and this runbook's §6 is written against the format, not against a live sealer. |
| `innsegl migrate` | absent. Apply `migrations/*.sql` with `psql`, or start `innsegl serve -migrate`. |
| `innsegl verify-segment` / an anchor check | absent. §6.3 is a manual `curl`. |
| a rebuild/import subcommand | absent. §4.1 is `psql`. |
| carrying `chain_id` across a fresh migrate | impossible today — see §4.1. |
| object storage in the reference stack | absent. `deploy/compose/` ships SPIRE (`spire.yml`) and self-hosted Sigstore (`sigstore.yml`) only. Doc 05 §1 lists twelve services; `postgres`, `minio`, `innsegl-mcp`, `innsegl-reconciler`, `innsegl-sealer`, `innsegl-dashboard` and `demo-agent` are not among the shipped compose services — the smoke test creates Postgres and the MCP itself. Tracked as issue #109. Commands here that name a bucket or a DSN assume your deployment, not the shipped stack. |
| CI wiring for `verify-rebuilt-index-selftest.sh` | not wired. Run it by hand after changing the gate. `.github/` is owned elsewhere. |
