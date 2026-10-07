# ADR-0074: Trust keys are backed up encrypted, and off the host

- Status: accepted
- Date: 2026-10-07
- Deciders: the operator

## Context

ADR-0073 records which roots and log keys a deployment has used. It does not
keep the keys. On 2026-09-16 a deployment lost its Fulcio CA key and its
transparency log with no copy anywhere: the backups held the ledger only. So
every commit signed in that era can never be proven again.

The keys that a lost host takes with it are:

| item | where it lives | if it is lost |
|---|---|---|
| Fulcio CA certificate, key and the key's password | `sigstore-fulcio-pki`, `INNSEGL_FULCIO_CA_PASSWORD` | old certificates chain only through the history; new ones need a new root |
| Rekor signing key | `sigstore-rekor-key` | the log can no longer sign |
| the transparency log (Trillian's database) | `sigstore-trillian-db-data` | old inclusion proofs are gone |
| pseudonymisation secret | `innsegl-identity-secret` | agent and task pseudonyms change |
| SPIRE upstream CA | `spire-pki-server` | every client re-enrols |
| gateway CA key | `innsegl-gateway-ca-key` | clients re-trust the gateway |
| trust history | `innsegl-trust-history` | rotated-away roots stop verifying |

A backup of these is worth stealing. It must be useless to whoever takes it
from the core.

## Decision

1. **One encrypted bundle a day.** A service, `innsegl-trust-backup`, runs
   `innsegl trust-backup create` on the core's own image. Each bundle is one
   [age](https://age-encryption.org) file. Inside is a tar stream: every item
   above, then `manifest.json`, which names each file with its size, mode and
   sha256. The newest 14 are kept on their own volume,
   `innsegl-trust-backups`. A checksum file beside each bundle holds the
   ciphertext's sha256.

2. **The core holds public keys only.** The bundle is encrypted to the
   recipients in `INNSEGL_TRUST_BACKUP_RECIPIENTS`, a space-separated list set
   on the host and never in this repository. The core can write a bundle and
   can never open one. With no recipient, no bundle is written: the run says
   so in its log and in `status.json`, and there is no unencrypted fallback.

   The core encrypts with the age library and runs no plugin. It takes X25519
   and post-quantum recipients, tagged P-256 recipients (`age1tag1…`), and
   plugin recipients whose payload is a tagged P-256 key (`age1se1…`). A
   hardware-held key's identity opens those on the operator's machine.

3. **No plaintext on disk.** Key files are read into memory one at a time and
   written straight into the encryptor. The log's database is exported in Go
   from one `REPEATABLE READ` transaction started `WITH CONSISTENT SNAPSHOT`:
   the MySQL analogue of the ledger backup's `pg_dump`. The log keeps running.
   The export streams into the bundle in 8 MiB parts and is never held whole.
   It is plain SQL that the stock `mysql` client restores, and the core's
   image gains no database client.

4. **Least privilege for the one reader of every key.** The service runs as
   uid 0 because the key volumes belong to four different users. Every
   capability is dropped except `DAC_READ_SEARCH`, to read them, and `CHOWN`,
   to hand what it writes to uid 1000. Every key volume is mounted read-only.
   The root filesystem is read-only. Its only network is the log database's.
   It sits behind the compose profile `trust-backup`, because it mounts other
   projects' volumes by name, and a stack without them must still start.

5. **Off the host, over the enrolled connection.** `innsegl-mcp` mounts the
   bundles read-only and serves them behind the client certificate:
   `GET /_core/trust-backup` lists them with the producer's last status, and
   `GET /_core/trust-backup/latest` is the newest bundle, with its name and
   sha256 in headers.
   - Only an active workstation may fetch. Its installation must belong to the
     operator organisation, and the user who enrolled it must still be that
     organisation's owner or an admin. Every other machine gets 403.
   - Each machine may make six requests at once and one more every ten
     minutes.

   The operator's client service fetches on start and hourly, and checks the
   outer sha256 before keeping a copy. It keeps the newest 30 under
   `~/.innsegl/trust-backups/` (directory 0700, files 0600). No ssh or copy
   step exists to forget. `innsegl status` shows the newest copy's age, and
   warns when it is missing or more than two days old.

6. **A drill that proves the backup opens.** `innsegl trust-backup drill`
   opens the newest kept bundle with the operator's identity. It checks the
   outer checksum first, then every file against the manifest, and lists what
   the bundle holds. It names any expected item that is missing. By default it
   writes nothing; `--extract` writes the files, 0600, for a restore. A full
   restore into a throwaway stack, verifying a commit signed before the
   backup, is `runbooks/trust-key-backup.md`. It is meant to run every
   quarter.

## Alternatives considered

**Encrypt with a key the core holds.** Then whoever takes the core takes the
backup and its key together. That protects against nothing this backup is for.

**Run the age plugin on the core.** A plugin binary in the core's image, for a
key the core never uses to decrypt, would be one more thing to ship and
patch. The tag form makes it unnecessary.

**`mysqldump` in the image.** It adds a database client of about 43 MB to
every service on the image. A MariaDB client also refuses the log database's
self-signed TLS by default. Its dumps open with a line that the server's own
5.7 client does not parse. The Go export avoids all three, and a test checks
that its restore is byte-identical (`CHECKSUM TABLE`) on the log's own
database image.

**Copy the database's data directory.** Copying files from under a running
server gives a database nobody can restore. Stopping the log every day to copy
it is an outage.

**Push the bundle to the operator over ssh.** That needs a credential on the
core that can reach the operator's machine. The enrolled client already holds
a certificate the core trusts. Pulling over that connection adds no new
credential.

**Let any enrolled machine fetch.** The bundle is encrypted, so a copy on the
wrong machine leaks nothing today. But who holds copies of the keys is still
the operator's decision, and a recipient compromised later would make every
such copy matter.

## Consequences

- Losing the host no longer loses the keys or the log. Restore them from the
  newest bundle, then the ledger, and old commits verify as before.
- The backup is only as safe as the identity that opens it. Losing every
  identity makes every bundle unreadable. Losing the identity and the host
  together is unrecoverable. Where the identity is kept, and whether a second
  recipient is held on paper, is a deployment decision, not this ADR's.
- `innsegl-trust-backup` can read every key on the host. Its mounts are
  read-only and its network is one database's. What it writes is ciphertext.
- A bundle is a snapshot of one day. A root rotated or a log entry written
  since the newest bundle is not in it. The trust history and the ledger
  backups cover what changed.
- The search index (`rekor_index`) is not in the bundle. It is rebuilt from
  the log (`scripts/rekor-reindex.sh`).
- Exit cost: disable the profile and remove the volume. Nothing else reads it.
