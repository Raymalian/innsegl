# Reference self-hosted Sigstore compose stack

The two Sigstore rows of doc 05 §1 — `fulcio` (the local CA) and `rekor` with
its backing log and database services as sidecars — wired the way that document
requires and pinned by tag *and* digest. Built by RM-030 (#38).

Everything here is configuration and its reasoning, and the reasoning lives next
to the setting it explains. Read `../sigstore.yml`, `fulcio-config.yaml`,
`bootstrap.sh` and `verify.sh` rather than a summary of them.
[ADR-0029](../../../docs/adr/0029-compose-self-hosted-sigstore-as-its-own-project-joined-to-spires-oidc-network.md)
records the six decisions this stack embodies and what each one costs.

## This is the shipped default, not a CI convenience

Doc 05 §1 asked the compose README to state one asymmetry explicitly: local
Sigstore in compose, public Sigstore in the installed product. **That asymmetry
no longer exists, and the sentence in doc 05 §1's `fulcio` row is stale.**

[ADR-0010](../../../docs/adr/0010-self-hosted-sigstore-is-the-shipped-default.md)
measured the question and answered it: public-good Fulcio's allowlist contains
no issuer of type `spiffe` at all, the SPIFFE federation process was closed
`not_planned` in March and the machinery that implemented it was deleted in
2024. A project-operated SPIRE trust domain cannot be onboarded there. So
**self-hosted Fulcio and Rekor are the shipped default and the reference
deployment**, in compose and installed alike; public Sigstore is demoted to a
supported configuration, available "where the deployment already holds a token
from an issuer on Fulcio's published allowlist".

Doc 05 §1's table still describes the old default. That is a spec edit for a
human, not something an implementing agent may make; it is flagged in ADR-0029's
last section.

**Say which log you mean.** ADR-0010's consequence applies to everything this
stack produces: whoever deploys Innsegl now runs the log that attests their own
agents. The mechanism is unchanged — a Merkle-backed append-only log with
verifiable inclusion proofs, checkable by anyone holding the log's public key —
and `verify.sh` demonstrates one end to end. What does not survive is the "even
we can't" claim. Every place the project renders non-repudiation must render
the log endpoint in use beside it.

## Run it

```sh
make sigstore-up       # brings up BOTH stacks, wired to each other
make sigstore-verify   # a real Fulcio certificate for a real JWT-SVID
make sigstore-down     # tears the Sigstore half down, volumes included
```

`make sigstore-up` is the supported path and it is not a convenience wrapper.
It brings up `spire.yml` **and** `sigstore.yml` with the same
`INNSEGL_SPIRE_JWT_ISSUER`, then runs `spire/register.sh`. Without that, the
two stacks boot disagreeing about who the issuer is and Fulcio refuses every
token. By hand:

```sh
export INNSEGL_SPIRE_JWT_ISSUER=http://spire-oidc:8080
docker compose -f deploy/compose/spire.yml up -d
deploy/compose/spire/register.sh
docker compose -f deploy/compose/sigstore.yml up -d
```

Then, the readiness probe — which is the same question the MCP's health check
asks, per
[ADR-0024](../../../docs/adr/0024-readiness-probes-sigstore-by-fetching-its-trust-material.md):

```sh
curl -s http://127.0.0.1:5555/api/v1/rootCert      # must parse as a PEM CA cert
curl -s http://127.0.0.1:3000/api/v1/log/publicKey # must parse as a PKIX key
```

Bytes that parse, not a status code. A TCP dial or an unexamined 200 passes
against any listening socket, including a proxy in front of a dead Fulcio.

`docker compose -f deploy/compose/sigstore.yml up` **before** the SPIRE stack
exists fails naming the missing `innsegl-oidc-frontend` network. That is the
correct failure: `spire.yml` declares and owns that network, and it is the whole
of the wiring between the two stacks.

## The issuer is the one value that must agree in three places

Fulcio accepts a JWT-SVID only if it can fetch the discovery document and JWKS
of the issuer named in the token's `iss` claim. Three files must name the same
string:

| file | what it sets |
|---|---|
| `../spire/server.conf` | `jwt_issuer` — the `iss` claim SPIRE stamps |
| `../spire/oidc-discovery-provider.conf` | the `issuer` in the discovery document |
| `fulcio-config.yaml` | the `oidc-issuers` key Fulcio will believe |

All three read `INNSEGL_SPIRE_JWT_ISSUER`. SPIRE expands it natively
(`-expandEnv`); Fulcio has no expansion of its own, so `bootstrap.sh` renders
`fulcio-config.yaml` into the CA volume with the value substituted, on every
run.

The compose value is `http://spire-oidc:8080` — the service name on the shared
network, already on the provider's `domains` allowlist. **Note that
`spire.yml`'s own default is `https://oidc.innsegl.dev`, which ADR-0010 decided
is never stood up.** A stack brought up on that default mints tokens Fulcio
cannot validate. `sigstore.yml` therefore requires the variable
(`${INNSEGL_SPIRE_JWT_ISSUER:?...}`) rather than defaulting it, and `verify.sh`
asserts the minted token's `iss` matches what Fulcio was configured for —
because Fulcio's own error for this is `invalid identity token`, which names
nothing.

Correcting `spire.yml`'s default belongs to RM-014's file, not to this one.

## Prove it issues a certificate

```sh
make sigstore-verify   # or: deploy/compose/sigstore/verify.sh
```

Exit status is the verdict. It registers a run in SPIRE the way
`register_agent` does, with the one selector `innsegl:run:<run_id>` that no
workload can match (ADR-0053), mints a JWT-SVID for audience `sigstore`
through the server's `MintJWTSVID` the way `get_credential` does,
exchanges it at Fulcio with a proof of possession, and asserts that the
certificate's **URI SAN is exactly the run's SPIFFE ID** and that it chains to
the root Fulcio publishes. That URI SAN is what makes a commit attributable to
one agent run rather than to a machine or a workflow — the whole of I1 and half
of I5.

It then submits a `hashedrekord` entry and **polls for an inclusion proof**.
That poll is not padding: it is RM-012's most expensive finding made
executable. Without `trillian-log-signer`, leaves are queued and never
integrated, the entry is accepted and the proof never arrives — a failure that
presents as slowness. The deadline turns it back into a failure with a name.

This is not TC-SIG and must not become it. SIG-001 is a signed *commit* verified
through the shipped tooling; it belongs to E5's Go tests against this stack.
This script is the infrastructure check that has to pass before those tests have
anything to run against.

## Network shape

Doc 05 §1: "Compose is where the least-privilege shape is first proven, not
first ignored." Six networks; membership is the access-control list and is
written at each declaration in `../sigstore.yml`.

```
                    ┌──────────────────────────────┐
   (spire.yml)      │  innsegl-oidc-frontend       │
   spire-oidc ──────┤  external; declared there    ├────── fulcio
                    └──────────────────────────────┘         │
                                                             │
   host ──▶ 127.0.0.1:5555 ┐                                 │
   host ──▶ 127.0.0.1:3000 ┴─ innsegl-sigstore-published ─── fulcio, rekor
                                                             │
   innsegl-mcp, sealer,  ─── innsegl-sigstore (internal) ──── fulcio, rekor
   reconciler, dashboard                                     │
   (when they land)                                          │
                                                             ├─ rekor-log ── trillian-log-server
                                                             └─ rekor-index ── trillian-db
                                                                               (rekor_index only)
              trillian-log-server ┐
              trillian-log-signer ┴── innsegl-sigstore-trillian-db ── trillian-db
```

Three properties worth reading off that picture rather than trusting a
sentence:

- **Fulcio has no route into SPIRE beyond the OIDC frontend.** It is on no
  network with `spire-server` and cannot open a socket to the Agent API or the
  admin API. What it does over that network is read two public documents.
- **Rekor cannot touch Trillian's tables.** The front end — the component a
  verifier talks to — is not a member of `innsegl-sigstore-trillian-db`. It
  reaches the MySQL server only over `innsegl-sigstore-rekor-index`, a network
  of two members, and only as the `rekor` user, whose grant is the
  `rekor_index` database (`rekor-index.sql`). Measured: that user is refused
  `SELECT` on Trillian's `Trees` table.

`innsegl-sigstore-published` is the one non-internal network and it exists for a
mechanical reason. MEASURED: a container attached only to `internal` networks
cannot have a port published — `docker port` prints the port with no host
binding and the host cannot connect, because an internal network has no gateway
to NAT through. Rather than un-internalling `innsegl-sigstore` and handing
egress to every service that later joins it, the two services that must be
reachable from outside get one narrow network of their own.

## What is deliberately absent

- **A Certificate Transparency log.** Doc 05 §1's table has no row for one, and
  `--ct-log-url=` (empty) turns Fulcio's submission off. This has a real
  consequence downstream: **certificates from this stack carry no SCT, so a
  verifier configured to require one will refuse them.** RM-032's gitsign
  wrapper and RM-037's `innsegl verify` must be configured against a trust root
  that lists no CT log. ADR-0029 decision 5.
- **`oidc.innsegl.dev`.** ADR-0010 decision 1: not stood up in v0.1. The
  discovery provider stays internal to the deployment, reachable by this Fulcio
  only.
- **Container healthchecks on the four distroless services.** Fulcio, Rekor and
  both Trillian services ship without a shell or an HTTP client, so there is
  nothing to probe with from inside. This is `spire-oidc`'s situation and takes
  its answer: probe from outside, the way a client does. Startup ordering is
  handled with `restart: on-failure`, which is how RM-012 handled it.
- **An ADR-0022 test overlay.** Nothing under `internal/` or `test/` drives this
  stack today; it is brought up by hand or by `make`. When a harness does drive
  it, it needs a per-process overlay — the external network name is already
  parameterised (`INNSEGL_SIGSTORE_OIDC_NETWORK`) so that is a rename, not a
  rework.
- **Postgres, the object store and the built `innsegl-*` services.** The rest of doc 05 §1,
  and other issues' files.

## Rekor's search index lives in trillian-db

The index is the map from artifact digest to entry UUID that a verifier asks
through `/api/v1/index/retrieve`. It is a table, `EntryIndex`, in the
`rekor_index` database on `trillian-db` (#451, ADR-0010's 2026-10-05
amendment). Rekor creates the table on first connect. `trillian-db` runs
`rekor-index.sql` with `--init-file` at every start, so the database and its
one user exist on a new volume and on one made before the index moved.

It used to be a Redis container on a volume of its own. `down -v` removed that
volume while the log kept every entry, and the log then answered "no such
entry" for good commits (OPS-036), so bring-up walked the whole log to rebuild
the index at every start. On the trust volume the log already lives on, the
index survives what the log survives, and start no longer rebuilds it.

Measured against the pinned images: Rekor starts with the MySQL index; a new
entry is found by hash at once; it is still found after rekor is recreated and
after trillian-db restarts.

### Upgrading a log that predates the move: automatic

Rekor indexes an entry only when it is written, so entries written while the
index was Redis are not in the new table, and until they are `innsegl verify`
reports their commits as never logged. Nothing has to be run by hand for
this. `make start` and `innsegl-update` bring the Sigstore project up, and
`make update` brings up the log's services (not Fulcio, which a key-custody
host runs under `sigstore.keycustody.yml`). Either way trillian-db and rekor
are recreated on the new shape, and both then run `rekor-index-ready`, which

1. removes the old `innsegl-sigstore-rekor-redis` container by name (not
   with `--remove-orphans`, which would also remove `innsegl-ca-store`, a
   service of the same project declared in `sigstore.keycustody.yml`);
2. pins the log (`rekor-tlog-id`), which waits for it to answer;
3. runs `scripts/rekor-reindex.sh --if-behind`: it counts this tree's entries
   in the index and, when that is fewer than the log's size, runs Rekor's own
   `backfill-index` tool (the same release as `rekor-server`) over the whole
   log. It does this before the core starts, and fails the bring-up if it
   cannot finish.

On every later start the index already holds the whole log and the step
reads one count and does nothing. Measured: 1,600 entries backfilled in about
3 seconds; the no-op check takes under a second.

The old Redis volume, `innsegl-sigstore_sigstore-rekor-search`, is NOT
removed. Nothing mounts
it any more, and what it holds (digests and identities that are in the public
log anyway) is not a secret. Remove it whenever convenient:
`docker volume rm innsegl-sigstore_sigstore-rekor-search`.

`make rekor-reindex` runs the backfill over the whole log unconditionally. It
is idempotent; use it to repair an index that was damaged some other way.

## Lifted from RM-012, not rebuilt

The five-container Rekor stack here is
`internal/segment/rekorharness_test.go`'s, which stood it up first to prove
SEG-003 against a real transparency log. Service list, image versions, flags and
ordering hazards are carried over; the two findings that cost real time to
discover are marked `RM-012 FINDING` at the settings that encode them:

- **`trillian-log-signer` is not optional.** Without it nothing is ever
  integrated and no inclusion proof exists. `verify.sh` polls for one.
- **The Trillian images are the Sigstore *scaffolding* ones.** Upstream's
  compose names `trillian-opensource-ci` images, which are amd64-only.
  `trillian-db` is the one image with no arm64 build and carries an explicit
  `platform: linux/amd64`; it runs under emulation, which is why its healthcheck
  has a long `start_period`.
- **`trillian-db`'s healthcheck is a `SELECT` over TCP.** The image boots twice
  and a unix-socket probe answers "ready" during the first boot, when nothing on
  the network can connect.

Two things differ from the harness, both deliberate and both in ADR-0029:

| | harness | here | why |
|---|---|---|---|
| images | tag only | tag **and** digest | a harness pulling a tag is fine; a shipped deployment is not |
| log signer | `memory` | a key on disk | ADR-0009 verifies an anchor under the log's key. A memory signer mints a new one per restart, silently invalidating every anchor issued before it |

When the Rekor version moves here, it moves in `rekorharness_test.go` in the
same change — or the stack and the test that proved it stop describing the same
log.
