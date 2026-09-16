<!-- SPDX-License-Identifier: Apache-2.0 -->

# `innsegl.yml` — the components this project *is*

`spire.yml` and `sigstore.yml` are Innsegl's **dependencies**. This is Innsegl:
doc 05 §1's other seven rows, none of which existed as a compose service before
[#109](https://github.com/Raymalian/innsegl/issues/109).

| doc 05 §1 row | here | notes |
|---|---|---|
| `postgres` | service | ledger hot tier, volume-backed, **publishes no host port** |
| object storage | **three services** | `innsegl-object-store` holds the bytes, `innsegl-object-filer` the metadata, and `innsegl-s3` is the S3 gateway — the only one of the three that enforces object lock, and the only one anything else can reach. Buckets get object lock **on at creation**, COMPLIANCE mode |
| `innsegl-mcp` | service | attested through the Workload API; append-only DB role |
| `innsegl-reconciler` | service | same binary, `reconcile` |
| `innsegl-sealer` | service | same binary, `seal` |
| `innsegl-dashboard` | **two services** | `innsegl-dashboard` is the UI — nginx and the built React bundle, holding no database credential at all — and `innsegl-api` is the BFF, the only holder of the read-only role. The row's "No write credentials mounted" is satisfied by both at once: nothing is mounted on the UI, and what is mounted next door cannot write |
| `demo-agent` | service, `--profile demo` | a curl MCP client; runs to completion |

Five services here are not doc 05 §1 rows. `innsegl-db-init`,
`innsegl-object-init`, `innsegl-identity-init` and `innsegl-s3-identities` are
one-shots that exist for the same reason `spire-bootstrap` does — something has
to run once, before anything else. `innsegl-canary` (`--profile canary`) is doc 05 §2's requirement
that SEG-005's deletion check "runs as a scheduled job in production, not only
at deploy".

---

## This deployment's pseudonymisation secret

**This is the part of #124 that is a privacy control rather than plumbing.**

`innsegl serve` defaults to `-identity-mode pseudonymous`, and in that mode
`internal/identity` refuses to start without a deployment secret of at least
16 bytes. #119 introduced that refusal deliberately — #116 chose it over a
silent fall back to literal values, which would have read as "private" while
every ticket reference went into Rekor — and this file was not updated to
supply one, so `innsegl-mcp` crashlooped on a clean `up`.

The fix is not a constant in `innsegl.yml`, and that is the whole of the
reasoning. A pseudonym is `HMAC(deployment_secret, field ‖ ":" ‖ value)`, so a
secret shipped in this repository would give **every deployment the same
pseudonyms**: `a7f3c91b` would mean one particular ticket reference in every
installation, and anyone who resolved one mapping — by registering one run
against their own copy of this stack — would hold it for everybody else's. That
is worse than not pseudonymising at all, because it looks private and is not.

| | |
|---|---|
| [`identity-init.sh`](identity-init.sh) | `openssl rand -hex 32` into the `innsegl-identity-secret` volume, **only if absent**; `network_mode: none`, `read_only: true`, the only rw mount of that volume anywhere |
| `innsegl-mcp` | gates on its completion and reads the file through `INNSEGL_IDENTITY_SECRET_FILE`, mounted read-only |

An existing secret is left alone, because pseudonyms must be stable: `down -v`
is the only rotation, exactly as for the Fulcio CA and the Rekor log key.
ADR-0041 records that a rotation is survivable — resolution goes through the
ledger's `run_registered` row and never through this key, so no history is
orphaned — but a secret regenerated under a live run would derive a *second*
SPIFFE ID for a run id SPIRE already holds an entry for.

The path is read from a file rather than a value because compose can mount a
volume and cannot read one into an environment variable; that is
`INNSEGL_MCP_SVID_FILE`'s convention, joined rather than re-invented. Supplying
both `INNSEGL_IDENTITY_SECRET` and `INNSEGL_IDENTITY_SECRET_FILE` is refused
rather than resolved in favour of one.

---

## The append-only database role

**This is the part of #109 that is a security control rather than plumbing.**

doc 05 §1 requires the MCP to run under a database role that can append and
cannot delete. Nothing created one, so the reference stack ran the MCP as the
database owner and `innsegl serve` printed `DATABASE ROLE IS OVER-PRIVILEGED`
on an adopter's first contact with the system.

Three files, and the split matters:

| | |
|---|---|
| [`appendonly.sql`](appendonly.sql) | the GRANTs and REVOKEs, on one page |
| [`db-init.sh`](db-init.sh) | migrates as the owner, creates the role, applies the grants, then runs the check below |
| [`verify-role.sh`](verify-role.sh) | **connects as the role and asks the server what it can actually do** |

`internal/api/readonly.go` is the model and states the reason plainly:

> The assertion matters more than the provisioning. A role is provisioned once
> and then lives in somebody's deployment; a later `GRANT` by an operator who
> wanted to "just fix one thing" is invisible to any amount of code review.

So `db-init.sh` does not exit 0 on "the GRANTs ran". It exits 0 on "the server
says this credential cannot delete", and `innsegl-mcp` gates on its completion.
`innsegl serve` then runs with `-require-append-only-role`, so the server
*refuses to start* rather than warning — the flag existed already and was
defaulted off precisely because nothing created the role.

### Why the check reads SQLSTATEs and not exit codes

MEASURED on `postgres:16`, against the shipped migrations:

| role | statement | result |
|---|---|---|
| `innsegl_appender` | `UPDATE innsegl.events` | `42501` permission denied — **the ACL** |
| `innsegl_appender` | `DELETE FROM innsegl.events` | `42501` permission denied — **the ACL** |
| `innsegl_appender` | `TRUNCATE innsegl.events` | `42501` permission denied — **the ACL** |
| owner (`innsegl`) | `UPDATE innsegl.events` | `IN001` — the append-only **trigger** |
| owner (`innsegl`) | `DELETE FROM innsegl.events` | `IN001` — the append-only **trigger** |
| owner (`innsegl`) | `TRUNCATE innsegl.events` | `IN001` — the append-only **trigger** |

Both roles are refused. Only one is refused **by privilege**. A check that
asked "did the statement fail?" would pass the database owner — the exact
credential #109 is about — because migration 0001's trigger refuses it too. So
only `42501` (insufficient_privilege) and `25006` (read_only_sql_transaction)
count as refusals here; anything else, **including success**, means the ACL let
the statement through.

`OPS-010` proves the check bites: it grants `DELETE ON innsegl.events` to the
role — the exact "just fix one thing" — and requires `verify-role.sh` to fail
and to name `DELETE`.

Run it against a live stack at any time. It writes nothing; every probe is
rolled back:

```sh
make innsegl-verify
```

### What the role may do

| table | privileges | why |
|---|---|---|
| `innsegl.events` | `SELECT, INSERT` | I4 admits no other verb on the chain |
| `innsegl.chain` | `SELECT` | written once, by migration 0001 |
| `innsegl.idempotency` | `SELECT, INSERT, UPDATE` | IP §6.6's claim is taken, leased, then completed — not append-only, and never `TRUNCATE` |
| `innsegl.schema_migrations` | `SELECT` | readable for debugging; the stack migrates as the owner |

Plus `ALTER DEFAULT PRIVILEGES`, so a table added by a **later** migration
arrives append-only too, rather than inheriting whatever the owner's defaults
happened to be.

---

## The other database role: `innsegl_reader`

doc 05 §1's dashboard row ends "No write credentials mounted — enforced by
giving it a read-only DB role". That role is `innsegl_reader`, and
`innsegl-api` is the only thing that connects as it.

Its grants are **`internal/api/readonly.sql`** — not a copy of them.
`innsegl.yml` mounts that file into `innsegl-db-init` exactly as it mounts
`migrations/`, and for the same reason: `api.EnsureReadOnlyRole` `go:embed`s
it, and `innsegl api` probes the credential against what it produced before it
will serve a request. A second set of GRANTs under `deploy/` would be a
read-only posture that could drift from the one the API measures against, and
the failure mode of that drift is an `innsegl-api` that exits **13 WRITABLE**
in a stack whose own bootstrap reported the role fine. `db-init.sh` translates
Go's two `fmt` verbs into psql's `:"role"` and `:"db"` on the way in, and
refuses loudly if the file ever grows a third.

Then it asks the server, exactly as it does for the appender:
`verify-reader-role.sh` connects **as** `innsegl_reader` and attempts every
write `api.Open` attempts, plus the I4 verbs. MEASURED on postgres:16:

| role | statement | result |
|---|---|---|
| `innsegl_reader` | `INSERT INTO innsegl.events` | ERROR **42501** permission denied (the ACL) |
| `innsegl_reader` | `UPDATE innsegl.events` | ERROR **42501** permission denied (the ACL) |
| `innsegl_reader` | `DELETE FROM innsegl.events` | ERROR **42501** permission denied (the ACL) |
| owner | `INSERT INTO innsegl.events` | ERROR **IN002** the chain-link trigger |
| owner | `UPDATE innsegl.events` | ERROR **IN001** the append-only trigger |
| owner | `DELETE FROM innsegl.events` | ERROR **IN001** the append-only trigger |

Both are refused; only one is refused **by privilege**. A check that asked "did
the write fail?" would pass the database owner — the credential the gate exists
to catch. So `42501` and `25006` are the only refusals that count, and anything
else, success included, means the ACL let the statement through. `innsegl api`
uses the same rule, and it has no flag to switch the check off.

Ask a running stack yourself:

```bash
docker compose -f deploy/compose/innsegl.yml exec innsegl-api \
  wget -q -O- http://127.0.0.1:8082/api/v1/health
```

The body is the report `api.Open` measured — role, `superuser`,
`default_transaction_read_only`, and every probe with its SQLSTATE. "No write
credentials mounted" is a fact you read back rather than a claim in a README.

---

## What is not here

**Authentication.** Neither `innsegl-dashboard` nor `innsegl-api` authenticates
anybody. `innsegl api` says so in its own `--help`, and doc 05 §3 puts
`dashboard.innsegl.dev` behind Cloudflare Access — RM-062 (#70) is the issue
that does it. Nothing here invents a scheme in the meantime, and both services
publish on loopback only.

What *is* enforced, and it is the half that survives a misconfigured proxy: the
credential the query API holds **cannot write**, whoever reaches it. See
"The other database role" above.

---

## The object store's scoped identity

**#228, and #227 changed how it is expressed.** Everything above about the
database roles is an argument about the object store too, and until #228 the
object store did not have it: the compose file gave `innsegl-sealer` and
`innsegl-canary` the same value it gave the server as its root credential, so
the sealer ran as the store's root account for the whole life of the
deployment.

Three files, and the split is the same one the database roles use:

| | |
|---|---|
| [`s3-identities.sh`](s3-identities.sh) | writes the gateway's identity file — the root identity, and the scoped one the sealer and the canary run as |
| [`object-init.sh`](object-init.sh) | creates the locked bucket **as root**, sets the default rule, and reads the whole configuration back off the server |
| [`verify-object-scope.sh`](verify-object-scope.sh) | **connects as the scoped identity and asks the server what it can actually do** |

### The narrowing is a key prefix, not a withheld permission

The deployed store's permission model has **no separate action for setting a
bucket's object-lock configuration**. Measured: an identity granted a
bucket-wide `Write` may set it, and may therefore downgrade the default rule
from `COMPLIANCE` to `GOVERNANCE`. There is nothing to withhold by name.

What it does have is prefix-scoped grants, and they draw the line in exactly the
right place. The scoped identity holds:

```
Read:<bucket>                        List:<bucket>
Write:<bucket>/segments/*            Write:<bucket>/innsegl-worm-canary/*
```

and measured against the running server, it may and may not:

| attempt | |
|---|---|
| `GetObjectLockConfiguration` | **allowed** — SEG-005's canary reads it every run |
| `PutObject` under either prefix | **allowed** — the sealer's whole job, and the canary's probe |
| `PutObject` anywhere else | refused |
| `PutObjectLockConfiguration` | refused |
| `CreateBucket`, `DeleteBucket` | refused |
| `PutBucketVersioning` | refused |
| `PutBucketPolicy`, `PutBucketLifecycle` | refused |
| `PutObjectRetention` | refused |
| `DeleteObjectVersion` with a governance bypass | refused |

All with `AccessDenied`, and the whole eight-check canary passes on it. The
grant this replaced could write anywhere in the bucket; this one cannot, so the
migration did not cost the narrowing — it tightened it.

**Two write grants and not one.** The sealer writes under
`$INNSEGL_OBJECT_STORE_PREFIX`; SEG-005's canary writes its probe under
`internal/segment`'s own `innsegl-worm-canary/`, deliberately outside the
segment namespace so that `scripts/backup-ledger.sh`'s recursive fetch of the
segment prefix does not pull probes into every ledger backup.

**Read is bucket-wide and write is not**, which looks asymmetric and is the
measurement: a prefix-scoped `Read` is also refused
`GetObjectLockConfiguration`, and the canary needs it. Reading is not a way to
weaken anything.

### The identity file, and the failure that reads like something else

This store **ships no default credentials**. Started without `-s3.config`, every
signed request is refused with

```
Signed request requires setting up SeaweedFS S3 authentication
```

which arrives at the caller as `AccessDenied` on a write — indistinguishable,
from the outside, from object lock doing its job. A deployment can look like it
is enforcing SEG-005 while nothing has ever been written to it. That is why
`innsegl-s3-identities` is a gated one-shot and why `object-init.sh`'s timeout
message names it.

The file is rewritten on every boot from `innsegl.yml`'s own interpolation,
which is the opposite of what `identity-init.sh` does with the pseudonymisation
secret, and deliberately: that is key material, and this is the compose file's
access-control decision rendered into the format the gateway reads. A file left
alone would be a deployment whose scope is whatever it was the first time it
ever came up.

---

## The Filer is a second door, and it has no lock on it

**#227, and it is the reason the object store is three containers.**

Object lock is enforced at the **S3 layer**. The Filer is a different process
speaking a different protocol to the same metadata. Measured, on the pinned
image, against an object under `COMPLIANCE` retention that the gateway refuses
to delete for *every* identity including the store's own root account:

```
curl -X DELETE 'http://<filer>:8888/buckets/<bucket>/<key>.versions?recursive=true'
→ 204 No Content
```

No credential. No signature. The S3 layer then reports `NoSuchKey`. The layer
below has the same shape: the master and volume servers accept unauthenticated
writes and deletes of raw needles from anything that can reach them.

Three things close it, and OPS-029 measures all three by attempting the delete
rather than by reading the configuration:

1. **The Filer and the gateway are separate containers.** `weed server -s3`
   runs both in one process on one bind address, and there is then no
   arrangement of networks that admits the gateway and excludes the Filer.
2. **The Filer runs with `-disableHttp`.** The gateway reaches it over gRPC,
   which that flag leaves alone — the whole stack, canary included, works with
   the HTTP listener gone.
3. **`innsegl-object-backend` has three members**, and the gateway is the only
   one also on `innsegl-objects`. A compromised sealer, canary or init cannot
   resolve the Filer's name, let alone reach it.

The gateway's own extra listeners are turned off for the reason the old browser
console was: `-iam=false` (an IAM API on the S3 port itself), `-port.iceberg=0`,
`-port.lance=0`. None is part of storing a sealed segment and each is an
authenticated write surface on the service whose job is refusing writes.

---

## One trap worth knowing about: two retention grammars

An S3 default retention rule has exactly two units, so `object-init.sh` takes
`1d`, `30d`, `1y`. `cmd/innsegl` takes a **Go duration** —
`time.ParseDuration`, which has no `d` unit at all.
`time.ParseDuration("1d")` returns `unknown unit "d"`, and `cmd/innsegl`'s
`envDuration` helper falls back to its default **without an error**.

So a value that looks right in both places means two different things, and the
wrong one fails silently. `innsegl.yml` resolves it by never passing a
retention to a Go service:

| variable | grammar | read by |
|---|---|---|
| `INNSEGL_OBJECT_LOCK_RETENTION` | `mc` (`1d`) | `object-init.sh`, once, at bucket creation |
| `INNSEGL_OBJECT_STORE_RETENTION` | Go (`24h`) | `cmd/innsegl` — **set by nothing here** |

The bucket rule is the single source; the sealer and the canary inherit it,
which is what their `0` default means. A deployment that wants a per-object
window longer than the bucket's sets the second one itself, in Go's grammar.

Found by #112's review of this file rather than by anything failing, which is
the point: it was right by accident.

---

## Running it

See [`../README.md`](../README.md) for the boot block. The short version, once
SPIRE and Sigstore are up:

```sh
make innsegl-up             # build, register the MCP, boot the seven rows
make innsegl-verify         # ask about the MCP's DB credential and the sealer's store credential
make innsegl-canary         # SEG-005: prove a sealed segment cannot be deleted
make innsegl-demo           # register -> sign -> retire, over the real transport
make innsegl-verify-commit COMMIT=<sha>   # verify with NO route to the ledger
make innsegl-down
```

`make innsegl-verify` asks about the **appender** and about the sealer's
object-store credential. The reader has the same question and no Makefile
target of its own yet; ask it directly:

```sh
docker compose -f deploy/compose/innsegl.yml \
  run --rm --entrypoint sh innsegl-db-init /innsegl/init/verify-reader-role.sh
```

Or ask the running service, which reports what `api.Open` measured when it
started rather than re-measuring:

```sh
docker compose -f deploy/compose/innsegl.yml exec innsegl-api \
  wget -q -O- http://127.0.0.1:8082/api/v1/health
```

### Two ordering requirements, and why they exist

**`register.sh` must run after the image is built.** The MCP is an attested
workload: `register.sh` creates
`spiffe://innsegl.dev/innsegl/mcp` — `server.conf`'s single `admin_ids` value —
with five selectors, all derived from the **image**, so the entry can be
created before anything from that image has ever run. `innsegl:local` is built
here rather than pulled, so **every rebuild changes its config digest** and the
previous entry matches nothing; `register.sh` detects that and replaces the
entry rather than reporting it as already present.

**`register.sh` writes `deploy/compose/.env`.** `innsegl serve` requires the
attested node's SPIFFE ID and refuses to start without one. It is not knowable
in advance — it is `.../spire/agent/x509pop/<sha1 of the agent certificate>`,
and `spire/bootstrap.sh` mints a fresh certificate on every `up` after a
`down -v` — so `register.sh` writes it where compose reads it automatically.
The file is gitignored and describes exactly one booted stack.

---

## Segmentation

Network membership is the access-control list, and the rule is written at each
`networks:` declaration in `innsegl.yml`. Five networks, and the two that look
mergeable are deliberately not:

| network | members |
|---|---|
| `innsegl-ledger` (internal) | postgres, db-init, mcp, reconciler, sealer |
| `innsegl-ledger-readonly` (internal) | postgres, api, dashboard |
| `innsegl-objects` (internal) | innsegl-s3, object-init, sealer, canary |
| `innsegl-object-backend` (internal) | object-store, object-filer, innsegl-s3 |
| `innsegl-mcp-clients` | mcp, demo-agent |
| `innsegl-dashboard-frontend` | dashboard |

`innsegl-s3` is the only service on both object networks, and that is the whole
of what makes it the only route to the Filer and the volume server. The MCP is
on no network with either. The dashboard is on no network with the
MCP — one shared frontend network would give it a route to the write surface,
which is the one thing doc 05 §1's dashboard note forbids.

`innsegl-api` **adds no network**. It joins `innsegl-ledger-readonly`, which
#109 declared in advance for exactly this arrival, and `innsegl-sigstore`,
which the proof BFF needs. The UI→BFF hop rides `innsegl-ledger-readonly`
because both containers are already members of it for reasons doc 05 §1 gives,
and a sixth network would buy no isolation the membership list does not already
describe — unlike the dashboard/MCP frontend split, which buys the one thing
that note forbids.

`innsegl-identity-init` and `innsegl-s3-identities` are on no network at all —
`network_mode: none`, which costs zero of #100's twenty-nine. It generates key material and writes a file;
nothing it does requires reaching anything, so nothing can reach it either.
MEASURED: this file added exactly five networks (17 -> 22 on a machine already
running the two dependency stacks and one test harness) and #227 made it six.
The full reference deployment is fourteen: three for SPIRE, five for Sigstore,
six here. Docker's
default address pools run out at roughly twenty-nine and this repository's
per-process test harnesses take up to eight each, so #100 is a real constraint
and every network above had to earn its place — one that would have been merged
(a shared MCP/dashboard frontend) is deliberately two.

**Nothing in this file publishes a host port except the MCP and the dashboard,
and that is a control rather than an omission.** MEASURED by RM-054 (#62): publishing a container's
port inserts an ACCEPT rule for that container's address into Docker's own
filter chain, matched *before* the isolation rules that keep one bridge network
out of another. A published Postgres is reachable **by address** from a
container on an unrelated network. Use `docker compose exec`, which crosses no
network at all.
