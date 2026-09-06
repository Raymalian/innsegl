# Runbook — backing up the ledger

**Issue #160 (RM-099) deliverable.** Read `index-rebuild.md` §0 and §1 first —
this document is the other half of the same asymmetry: that runbook restores
a backup and adjudicates it; `scripts/backup-ledger.sh` takes one and
adjudicates it at the same time, so a bad backup is discovered on the day it
was made rather than on the day it is needed.

---

## Why this exists, in one line

> "History is just as important. We need the full chain of what was done —
> that's why we need to save history too, so that we have proof of what was
> done." — the maintainer, issue #160

`index-rebuild.md` §0 says a segment adjudicates a backup, it does not supply
one, and "there is no rebuild-from-segments-alone". If every Postgres backup
is gone, the event bodies — `agent_type`, `task_ref`, `run_id`, every
`tool_call` and its digest — are gone with them. Nothing shipped here backed
Postgres up before this issue, and until #159's sibling Makefile change,
`innsegl-down` deleted it on every teardown.

**§0's own words are "losing the database loses convenience, not proof".**
That framing is correct about attribution (I5) and is the maintainer's to
amend; this runbook does not rewrite it. It is noted here because a backup
procedure written underneath a header that says "convenience" is easy to
under-invest in, and the point of §2 below is that this one still checks
itself before it is trusted.

## Run it

```bash
make innsegl-backup                    # dumps to ./backups by default
INNSEGL_BACKUP_DIR=/mnt/ledger-backups make innsegl-backup
```

or directly:

```bash
scripts/backup-ledger.sh --out ./backups
```

It needs the `innsegl-postgres` container from `make innsegl-up` running, and
reaches it and the object store only through `docker exec` / `docker run
--network innsegl-objects` — the same no-published-port discipline
`deploy/compose/innsegl.yml` uses, so nothing here opens a new hole in the
stack's network segmentation.

Read `scripts/backup-ledger.sh`'s header comment for the full contract; the
short version:

1. `pg_dump` the whole `innsegl` database from the running container.
2. Restore that dump into a throwaway database in the **same** container,
   never the live one (`index-rebuild.md` §2.2) — this is what proves the
   dump restores, not merely that `pg_dump` exited `0`.
3. Extract the restored `event_hash` column, in `chain_position` order.
4. Fetch the sealed segments from object storage (or use `--segments DIR` for
   a directory already staged) and adjudicate the restored chain against them
   with `runbooks/verify-rebuilt-index.sh` — reused, not reimplemented, for
   the reason `verify-rebuilt-index.sh`'s own header gives: a second
   implementation of "does the index match the segments" is a second thing
   that can disagree with the first (doc 04 §5.4).

| Exit | Meaning |
|---|---|
| `0` | the dump was taken, restores, and matches every sealed segment it covers |
| `2` | the command line was not understood |
| `3` | the dump restores but **disagrees** with a sealed segment — an integrity incident, not a backup |
| `4` | the dump restores but **no sealed segments were available** to check it against — kept, unverified |
| `5` | the dump could not be taken or could not be restored at all |

## Three decisions, and why

**Where the dump goes.** A local path — `./backups` by default,
`$INNSEGL_BACKUP_DIR` to override — never a cloud upload this script performs
itself. Doc 05 §2 already specifies WORM object storage with a lock for
segments, and the issue names it as this dump's eventual home too, but
shipping upload credentials for a bucket this repository does not operate,
to a destination the maintainer has not chosen, is a bigger decision than a
backup script should make silently. Moving the file to WORM storage
afterwards is one `mc cp`, regardless of which bucket is decided on.

**What is in the dump.** The whole `innsegl` database, not a
`innsegl.events`/`innsegl.chain` extract. `index-rebuild.md` §4's restore path
loads a dump into a fresh database and expects the schema — the append-only
triggers, the chain-link trigger, the CHECK constraints — to come back with
it rather than be reapplied from migrations by hand, and it expects
`innsegl.idempotency` (migration 0002) too: without it a resumed MCP cannot
tell a retried request from a new one. The evidence lives in two tables; a
*usable* restore needs the whole schema that gives that evidence its meaning.

**Whether the segments must be present.** Neither a silent pass nor a refusal
to take the backup. The dump is always written and kept — refusing to write
it because the object store happens to be unreachable would leave an operator
with nothing during exactly the outage this exists for — but it is not called
good either: exit `4`, and the words "UNVERIFIED", not "OK". §0's own
discipline is "the correct verb is *verify*, never assume"; a backup nobody
could check against the segments is exactly the case that discipline says to
say out loud rather than pass through quietly.

## Self-test

```bash
scripts/backup-ledger-selftest.sh
```

Boots one throwaway `postgres:16` container (the pin
`deploy/compose/innsegl.yml` uses), loads the fourteen committed golden
fixtures (`internal/event/testdata/fixtures/v1`) as real rows through the
real append-only and chain-link triggers, then runs `backup-ledger.sh`
against it four ways:

- **BAK-001** — a chain that matches the sealed segment is accepted (green).
- **BAK-002** — one event's stored hash does not match what was sealed; the
  backup is refused, and the message names the position (red — the
  acceptance criterion issue #160 asks for).
- **BAK-003** — no sealed segments are available; the dump is kept but
  reported unverified, not silently passed.
- **BAK-004** — the container does not exist; the script fails closed rather
  than reporting success on nothing.

These four IDs are proposed, not in doc 07: the test catalogue is normative
and is not edited from here, the same position `verify-rebuilt-index.md`
takes for SEG-007.

Not wired into CI — `.github/` is owned elsewhere. Run it by hand after
changing either script.

## What this does not do

- Does not schedule itself. `make innsegl-backup` is a manual or
  cron-invoked command; nothing here adds a scheduled job.
- Does not upload anywhere. See "where the dump goes" above.
- Does not touch the sealed segments. Fetching them is read-only, the same
  `mc cp` `index-rebuild.md` §6.1 documents by hand.
- Does not replace `index-rebuild.md`. That runbook is still what an operator
  reads to restore this dump during an incident; this one is what produces a
  dump worth restoring.
