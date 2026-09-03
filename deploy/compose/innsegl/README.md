<!-- SPDX-License-Identifier: Apache-2.0 -->

# `innsegl.yml` — the components this project *is*

`spire.yml` and `sigstore.yml` are Innsegl's **dependencies**. This is Innsegl:
doc 05 §1's other seven rows, none of which existed as a compose service before
[#109](https://github.com/Raymalian/innsegl/issues/109).

| doc 05 §1 row | here | notes |
|---|---|---|
| `postgres` | service | ledger hot tier, volume-backed, **publishes no host port** |
| `minio` | service | object lock **on at creation**, COMPLIANCE mode |
| `innsegl-mcp` | service | attested through the Workload API; append-only DB role |
| `innsegl-reconciler` | service | same binary, `reconcile` |
| `innsegl-sealer` | service | same binary, `seal` |
| `innsegl-dashboard` | **two services** | `innsegl-dashboard` is the UI — nginx and the built React bundle, holding no database credential at all — and `innsegl-api` is the BFF, the only holder of the read-only role. The row's "No write credentials mounted" is satisfied by both at once: nothing is mounted on the UI, and what is mounted next door cannot write |
| `demo-agent` | service, `--profile demo` | a curl MCP client; runs to completion |

Three services here are not doc 05 §1 rows. `innsegl-db-init` and
`innsegl-object-init` are one-shots that exist for the same reason
`spire-bootstrap` does — something has to run once, before anything else.
`innsegl-canary` (`--profile canary`) is doc 05 §2's requirement that SEG-005's
deletion check "runs as a scheduled job in production, not only at deploy".

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

## One trap worth knowing about: two retention grammars

`mc retention set` takes `1d`, `30d`, `1y`. `cmd/innsegl` takes a **Go
duration** — `time.ParseDuration`, which has no `d` unit at all.
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
make innsegl-verify         # ask the server about the MCP's DB credential
make innsegl-canary         # SEG-005: prove a sealed segment cannot be deleted
make innsegl-demo           # register -> sign -> retire, over the real transport
make innsegl-verify-commit COMMIT=<sha>   # verify with NO route to the ledger
make innsegl-down
```

`make innsegl-verify` asks about the **appender**. The reader has the same
question and no Makefile target of its own yet; ask it directly:

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
| `innsegl-objects` (internal) | minio, object-init, sealer, canary |
| `innsegl-mcp-clients` | mcp, demo-agent |
| `innsegl-dashboard-frontend` | dashboard |

The MCP is on no network with MinIO. The dashboard is on no network with the
MCP — one shared frontend network would give it a route to the write surface,
which is the one thing doc 05 §1's dashboard note forbids.

`innsegl-api` **adds no network**. It joins `innsegl-ledger-readonly`, which
#109 declared in advance for exactly this arrival, and `innsegl-sigstore`,
which the proof BFF needs. The UI→BFF hop rides `innsegl-ledger-readonly`
because both containers are already members of it for reasons doc 05 §1 gives,
and a sixth network would buy no isolation the membership list does not already
describe — unlike the dashboard/MCP frontend split, which buys the one thing
that note forbids.

MEASURED: this file adds exactly five networks (17 -> 22 on a machine already
running the two dependency stacks and one test harness). The full reference
deployment is thirteen: three for SPIRE, five for Sigstore, five here. Docker's
default address pools run out at roughly twenty-nine and this repository's
per-process test harnesses take up to eight each, so #100 is a real constraint
and every network above had to earn its place — one that would have been merged
(a shared MCP/dashboard frontend) is deliberately two.

**Neither `postgres` nor `minio` publishes a host port, and that is a control
rather than an omission.** MEASURED by RM-054 (#62): publishing a container's
port inserts an ACCEPT rule for that container's address into Docker's own
filter chain, matched *before* the isolation rules that keep one bridge network
out of another. A published Postgres is reachable **by address** from a
container on an unrelated network. Use `docker compose exec`, which crosses no
network at all.
