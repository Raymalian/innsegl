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
| `innsegl-dashboard` | service, **UI half only** | the BFF has no `cmd/` entry point — see below |
| `demo-agent` | service, `--profile demo` | a curl MCP client; runs to completion |

Four services here are not doc 05 §1 rows. `innsegl-db-init`,
`innsegl-object-init` and `innsegl-identity-init` are one-shots that exist for
the same reason `spire-bootstrap` does — something has to run once, before
anything else. `innsegl-canary` (`--profile canary`) is doc 05 §2's requirement
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

## What is not here

**The dashboard's BFF.** `internal/api` serves `GET /api/v1/runs` and
`GET /api/v1/proof/{sha}`, and `readonly.go` both provisions the read-only role
doc 05 §1's dashboard note is about *and* refuses to serve a request if the
server says that credential can write. It has **no `cmd/` entry point** — no
`main` in this module constructs an `api.Server` — so there is nothing to put
in a container.

Until there is, `innsegl-dashboard` serves the built React application and
holds **no database credential at all**, which satisfies "no write credentials
mounted" in the only way currently available: by having none. Every view that
reads the query API renders its own load-failure state. That is visible and
honest; a service that claimed to be this row and quietly was not would be
worse.

The `innsegl-ledger-readonly` network is declared with `postgres` and the
dashboard on it, so that when the BFF lands, joining it and holding
`api.EnsureReadOnlyRole`'s credential is the whole of what changes.

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
| `innsegl-ledger-readonly` (internal) | postgres, dashboard |
| `innsegl-objects` (internal) | minio, object-init, sealer, canary |
| `innsegl-mcp-clients` | mcp, demo-agent |
| `innsegl-dashboard-frontend` | dashboard |

The MCP is on no network with MinIO. The dashboard is on no network with the
MCP — one shared frontend network would give it a route to the write surface,
which is the one thing doc 05 §1's dashboard note forbids.

`innsegl-identity-init` is on no network at all — `network_mode: none`, which
costs zero of #100's twenty-nine. It generates key material and writes a file;
nothing it does requires reaching anything, so nothing can reach it either.

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
