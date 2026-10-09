# ADR-0078: Every service credential is generated per host and read from a file

- Status: accepted
- Date: 2026-10-09
- Deciders: the operator
- Extends: ADR-0075 (the same rule, for every credential rather than the CA's)

## Context

ADR-0075 stopped the Fulcio CA key's password from being a value in a public
file. The same class remained everywhere else. The compose files gave every
database and object-store credential a default, so a deployment that set
nothing ran on passwords every reader of this repository has:

| store | credential | default came from | used by |
|---|---|---|---|
| ledger (Postgres) | owner | `INNSEGL_LEDGER_OWNER_PASSWORD:-…` | `postgres` (first start), `innsegl-db-init` |
| ledger | appender | `INNSEGL_LEDGER_APPENDER_PASSWORD:-…` | `innsegl-mcp`, reconciler, sealer |
| ledger | reader | `INNSEGL_LEDGER_READER_PASSWORD:-…` | `innsegl-api` |
| ledger | auth writer | `INNSEGL_LEDGER_AUTHWRITER_PASSWORD:-…` | `innsegl-api`, `innsegl-mcp` (enrolment) |
| ledger | resolver | `INNSEGL_LEDGER_RESOLVER_PASSWORD:-…` | `innsegl-api` |
| ledger | backup | `INNSEGL_LEDGER_BACKUP_PASSWORD:-…` | `innsegl-backup` |
| object store | root identity | `INNSEGL_OBJECT_STORE_SECRET_KEY:-…` | `innsegl-s3-identities`, `innsegl-object-init` |
| object store | sealer identity | derived from the root's default | `innsegl-mcp`, sealer, backup, canary |
| log database (MySQL) | root | a literal in `sigstore.yml` | `trillian-db` |
| log database | Trillian's user | the same literal | the Trillian pair, `innsegl-trust-backup` |
| log database | Rekor's index user | a literal in `rekor-index.sql` | `rekor`, `scripts/rekor-reindex.sh` |

Eleven credentials. None of the three stores publishes a port, so none was
reachable from outside the Docker networks. Each was reachable from every
container on its network, and from anything on the host that can use Docker
(AB-17). The values also showed in `docker inspect`, on Trillian's and
Rekor's command lines, and in `innsegl accounts -h`, whose flag default is
the DSN with the password in it.

doc 04 says the ledger's append-only property holds because "nothing which
runs holds the owner credential". A default every reader has is held by
everyone.

The other generated secrets (the pseudonymisation secret, the object store's
gRPC key, the admin signing key, the gateway CA, the CA password) already
follow ADR-0075's shape and are not changed.

## Decision

1. **Generated per host, at first bring-up.** Each credential is 32 bytes
   from openssl's CSPRNG, as 64 hex characters, written once and then kept.
   The generator is `deploy/compose/credentials-lib.sh`, run by a one-shot
   with no network: `innsegl-credentials` in the core project, and
   `sigstore-bootstrap` (which already runs first) in the Sigstore project.
   No shipped file gives any of them a value. OPS-130 fails the build if one
   does.

2. **Kept in a trust volume per project.** `innsegl-trust-credentials` holds
   the core's eight; `innsegl-trust-sigstore-credentials` holds the log
   database's three. Both are created, stamped and protected by
   `trust-volumes.sh` like the other trust volumes, so `down -v` cannot remove
   them. One volume per project, because the two projects come up separately
   and each must find its own before it starts.

   They are not irreplaceable in the sense the other trust volumes are: a
   lost one can be recovered by setting every password again over the
   servers' own sockets. But until someone does, the ledger refuses every
   bring-up. So membership of the trust volumes widens from "irreplaceable"
   to "irreplaceable, or its loss stops the stack".

3. **Each service mounts only the credentials it uses.** The trust volume is
   mounted by the generator (read-write) and read-only by the three things
   that set passwords on a server (`innsegl-db-init`, `innsegl-s3-identities`,
   `trillian-db` through its rendered init file) and by the trust backup.
   Every other service gets one small volume per credential, which the
   generator rewrites from the trust volume on every start. The mount table
   is the grant: `innsegl-api` mounts the reader, auth-writer and resolver
   credentials and nothing else. A single volume mounted everywhere would
   hand the owner credential to every service, which is what doc 04 says
   must not happen.

4. **Read from files, never from a command line or a compose value.**
   - Postgres: `POSTGRES_PASSWORD_FILE`.
   - `innsegl` itself: a DSN with no password and `passfile=` naming the
     rendered file; pgx reads the password from it. The object store's
     secret comes from `INNSEGL_OBJECT_STORE_SECRET_KEY_FILE`, the log
     database's from `INNSEGL_TRUST_BACKUP_MYSQL_PASSWORD_FILE`.
   - The shell one-shots read the file into their own process environment.
   - MySQL: `MYSQL_ROOT_PASSWORD_FILE` and `MYSQL_PASSWORD_FILE`, and the
     `--init-file` is rendered with the passwords in it.
   - Trillian: its own `--config` flag file. Rekor: its own `--config` file.
   Measured on the pinned images: both read the file and refuse one with an
   unknown setting.
   - A flag whose default comes from a credential variable shows it redacted
     in `-h`.

   One exception: Rekor's `backfill-index` tool takes its DSN only as a
   flag. `scripts/rekor-reindex.sh` runs it in a `--rm` container, once,
   when the search index is behind the log; the password is on that
   container's command line for the length of that run.

5. **An existing host moves at the next `make update`, with no manual step.**
   - Ledger: `innsegl-db-init` connects as the owner with the file's
     password. If the server refuses it, it tries the old owner password:
     `INNSEGL_LEDGER_OWNER_PASSWORD` when set, else the old public default.
     If that opens, ONE transaction sets the owner's and every service role's
     password from the files, with a lock timeout so it cannot hang the
     bring-up. Then it reconnects with the new password and checks the old
     one is refused. A failure rolls the transaction back: every old password
     still works and the run exits non-zero. If no password opens, it refuses
     and names the two ways back (restore the volume, or set the variable
     once).
   - Object store: the identity file is rewritten from the files on every
     start, as it always was. `innsegl-s3-identities` waits for
     `innsegl-db-init`, so a refused ledger move changes nothing else.
   - Log database: the rendered init file runs as the superuser at every
     MySQL start and sets every user's password from the files. No old
     password is needed. It also removes `root@'%'`, which nothing uses; root
     remains on the container's local socket only.
   - Rerunning changes nothing: the files exist, the passwords already match.

   The move is atomic per store, not across stores. Each store and its
   clients always agree, because the clients are recreated from the same
   files in the same `make update`. A run stopped after the ledger
   committed is finished by the next one.

6. **The old values appear once.** `LEDGER_OWNER_LEGACY_PUBLIC_PASSWORD` in
   `db-init.sh` is the only old value the move needs, because the owner is
   the only credential whose server asks for its old password. OPS-130
   refuses every other old value anywhere in a shipped file.

7. **They are in the trust-key backup (ADR-0074).** The bundle carries both
   volumes as `credentials` and `sigstore-credentials`, and the drill names
   either one if it is missing. A restore puts them back before the first
   bring-up, so a restored ledger or log database opens with the passwords
   it was left with.

## Alternatives considered

**The variables, with no default.** Every install would need a manual step,
and the values would still be in `docker inspect` and on two command lines.

**One credentials volume mounted by every service.** Simpler, and every
service would hold the ledger owner's password. doc 04's append-only
argument rests on which credential is held.

**Compose `secrets:`.** Outside swarm they are bind mounts of host files,
which something must create first, outside compose, with the right owner.
The one-shot that writes a volume is already this project's shape (#124,
#451, ADR-0075).

**Set the ledger passwords over the server's local socket.** It needs no old
password, but needs a one-shot that shares the server's socket directory or a
`docker exec` from the Makefile. The owner connection `innsegl-db-init`
already holds does the same with neither.

**Keep the passwords beside the data, as ADR-0075 keeps the CA's password
beside its key.** Both database servers own their data directories and treat
what is in them as theirs.

## Consequences

- A fresh host's credentials exist only on that host and in its trust-key
  backups.
- `INNSEGL_LEDGER_*_PASSWORD`, `INNSEGL_OBJECT_STORE_SECRET_KEY` and
  `INNSEGL_OBJECT_STORE_SEALER_SECRET_KEY` are no longer read by the stack.
  `INNSEGL_LEDGER_OWNER_PASSWORD` is read once, by the move, on a host that
  set it. All can be removed from `.env` after the update.
- Two more trust volumes, and eleven small per-credential volumes.
- Found on the way: `backup-loop.sh` dropped the backup service's own
  arguments, so the ledger backup read sealed segments as the object store's
  root account, on its old default. It passes them through now, and the
  backup reads as the sealer identity, as its compose file always said.
- A bundle written before this release fails the drill for the two missing
  items, as it should: it cannot restore a host made after it.
- Rotation of one credential is: delete its file in the trust volume and run
  `make update`. Not covered here: rotating the ledger owner's password
  that way needs the old one, which the move reads from the file it is
  replacing. That is a follow-up.
- Spec edits this needs (not made here): doc 05 §2's list of trust volumes;
  doc 04's owner-credential paragraph can say the owner password is per host;
  doc 07 gains OPS-163 (the move) and OPS-164 (the generator).
- Exit cost: put the defaults back. The files stay where they are, harmless.
